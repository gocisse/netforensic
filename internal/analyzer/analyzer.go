// Package analyzer contains the pure analysis logic. It performs no file,
// CLI or network I/O and operates only on in-memory models.
package analyzer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const topTalkerCount = 5

// Analyze restricts packets to the given service filter ("all", "dns",
// "http", "tls", "https" or a port number) and returns the aggregated flows,
// top talkers and detected issues. An unrecognized service matches no
// packets. Analyze is pure: it performs no I/O.
func Analyze(packets []models.PacketInfo, service string) *models.AnalysisResult {
	return AnalyzeWithIssues(packets, service)
}

// AnalyzeWithIssues is Analyze with additional caller-supplied issues, such
// as problems with the capture itself (see TruncatedCaptureIssue). They are
// included in the result's issues, health score and timeline.
func AnalyzeWithIssues(packets []models.PacketInfo, service string, extra ...models.Issue) *models.AnalysisResult {
	start := time.Now()

	if port, matchAll, ok := parseService(service); !ok {
		packets = nil
	} else if !matchAll {
		packets = filterByPort(packets, port)
	}

	flows := aggregateFlows(packets)
	flows, perfIssues := applyPerformanceMetrics(packets, flows)
	issues := detectIssues(flows)
	issues = append(issues, analyzeDNS(packets)...)
	issues = append(issues, analyzeHTTP(packets)...)
	issues = append(issues, analyzeTLS(packets)...)
	issues = append(issues, analyzeICMP(packets)...)
	issues = append(issues, analyzeARP(packets)...)
	issues = append(issues, analyzeConnections(packets)...)
	issues = append(issues, perfIssues...)
	issues = append(issues, extra...)
	if issues == nil {
		issues = []models.Issue{} // serialize as [] rather than null
	}
	talkers := topTalkers(flows, topTalkerCount)
	if talkers == nil {
		talkers = []models.Flow{}
	}
	return &models.AnalysisResult{
		TotalPackets: len(packets),
		TotalFlows:   len(flows),
		AnalysisTime: start,
		Duration:     captureDuration(packets).String(),
		Issues:       issues,
		TopTalkers:   talkers,
		SlowFlows:    slowFlows(flows, topTalkerCount),
		Diagnosis:    correlate(packets, flows, issues),
	}
}

// parseService maps a service filter to a port. matchAll is true for "all";
// ok is false if the service is not recognized.
func parseService(service string) (port uint16, matchAll bool, ok bool) {
	switch strings.ToLower(service) {
	case "all", "":
		return 0, true, true
	case "dns":
		return 53, false, true
	case "http":
		return 80, false, true
	case "tls", "https":
		return 443, false, true
	}
	n, err := strconv.ParseUint(service, 10, 16)
	if err != nil {
		return 0, false, false
	}
	return uint16(n), false, true
}

// filterByPort keeps packets whose source or destination port equals port.
func filterByPort(packets []models.PacketInfo, port uint16) []models.PacketInfo {
	var out []models.PacketInfo
	for _, p := range packets {
		if p.SrcPort == port || p.DstPort == port {
			out = append(out, p)
		}
	}
	return out
}

// captureDuration returns the time between the earliest and latest packet.
func captureDuration(packets []models.PacketInfo) time.Duration {
	if len(packets) == 0 {
		return 0
	}
	first, last := packets[0].Timestamp, packets[0].Timestamp
	for _, p := range packets[1:] {
		if p.Timestamp.Before(first) {
			first = p.Timestamp
		}
		if p.Timestamp.After(last) {
			last = p.Timestamp
		}
	}
	return last.Sub(first)
}

type endpoint struct {
	ip   string
	port uint16
}

func (e endpoint) less(o endpoint) bool {
	if e.ip != o.ip {
		return e.ip < o.ip
	}
	return e.port < o.port
}

func (e endpoint) String() string { return fmt.Sprintf("%s:%d", e.ip, e.port) }

type flowKey struct {
	a, b  endpoint
	proto models.Protocol
}

// instKey identifies one connection: a flowKey plus the index of the TCP
// connection attempt on that 4-tuple (see models.ConnectionInstances).
type instKey struct {
	flowKey
	inst int
}

// id is the flow ID shown to users: "ip:port-ip:port", with "#N" appended
// from the second connection on a reused 4-tuple, e.g. "...#2".
func (k instKey) id() string {
	id := k.a.String() + "-" + k.b.String()
	if k.inst > 0 {
		id += "#" + strconv.Itoa(k.inst+1)
	}
	return id
}

// canonicalKey returns the direction-independent flow key of p and whether p
// travels from the canonical source endpoint to the canonical destination.
func canonicalKey(p models.PacketInfo) (key flowKey, forward bool) {
	src := endpoint{p.SrcIP, p.SrcPort}
	dst := endpoint{p.DstIP, p.DstPort}
	if dst.less(src) {
		return flowKey{dst, src, p.Protocol}, false
	}
	return flowKey{src, dst, p.Protocol}, true
}

// retransmitDetector flags TCP segments that reuse a sequence number already
// seen in the same direction of the same flow. It is fed packets in capture
// order.
type retransmitDetector struct {
	seen    map[retransSeqKey]struct{}
	nextSeq map[retransDirKey]uint32 // sequence number following the highest segment seen
}

type retransDirKey struct {
	flow    instKey
	forward bool
}

type retransSeqKey struct {
	dir retransDirKey
	seq uint32
}

// observe reports whether p is a retransmission. Only packets that consume
// sequence space (payload, SYN or FIN) are considered, since bare ACKs
// legitimately repeat sequence numbers, and keep-alive probes are ignored
// because they deliberately reuse the last sequence number.
func (d *retransmitDetector) observe(key instKey, forward bool, p models.PacketInfo) bool {
	if p.Protocol != models.ProtocolTCP || !consumesSeq(p) {
		return false
	}
	if d.seen == nil {
		d.seen = make(map[retransSeqKey]struct{})
		d.nextSeq = make(map[retransDirKey]uint32)
	}
	dk := retransDirKey{key, forward}
	next, haveNext := d.nextSeq[dk]
	if isKeepAlive(p, next, haveNext) {
		return false
	}
	sk := retransSeqKey{dk, p.TCPSeq}
	_, dup := d.seen[sk]
	d.seen[sk] = struct{}{}
	if end := p.TCPSeq + seqLen(p); !haveNext || int32(end-next) > 0 {
		d.nextSeq[dk] = end
	}
	return dup
}

// aggregateFlows groups packets into bidirectional flows. Packets A->B and
// B->A share one flow whose canonical source is the lesser (IP, port)
// endpoint. BytesSent counts bytes from the canonical source and BytesRecv
// bytes from the canonical destination.
//
// Retransmits counts TCP packets that reuse a sequence number already seen
// in the same direction of the same flow. To avoid false positives, only
// packets that consume sequence space (payload, SYN or FIN) are considered;
// bare ACKs legitimately repeat sequence numbers.
func aggregateFlows(packets []models.PacketInfo) []models.Flow {
	byKey := make(map[instKey]*models.Flow)
	var rd retransmitDetector
	insts := models.ConnectionInstances(packets)

	for i, p := range packets {
		fk, forward := canonicalKey(p)
		key := instKey{fk, insts[i]}
		a, b := key.a, key.b
		f, ok := byKey[key]
		if !ok {
			f = &models.Flow{
				ID:        key.id(),
				SrcIP:     a.ip,
				DstIP:     b.ip,
				SrcPort:   a.port,
				DstPort:   b.port,
				Protocol:  p.Protocol,
				StartTime: p.Timestamp,
				EndTime:   p.Timestamp,
			}
			byKey[key] = f
		}

		f.PacketCount++
		if forward {
			f.BytesSent += p.Size
		} else {
			f.BytesRecv += p.Size
		}
		if rd.observe(key, forward, p) {
			f.Retransmits++
		}
		if p.Timestamp.Before(f.StartTime) {
			f.StartTime = p.Timestamp
		}
		if p.Timestamp.After(f.EndTime) {
			f.EndTime = p.Timestamp
		}
	}

	flows := make([]models.Flow, 0, len(byKey))
	for _, f := range byKey {
		flows = append(flows, *f)
	}
	sort.Slice(flows, func(i, j int) bool {
		if !flows[i].StartTime.Equal(flows[j].StartTime) {
			return flows[i].StartTime.Before(flows[j].StartTime)
		}
		return flows[i].ID < flows[j].ID
	})
	return flows
}

// seqLen is the amount of sequence space a TCP packet occupies.
func seqLen(p models.PacketInfo) uint32 {
	n := uint32(p.PayloadSize)
	if hasTCPFlag(p.TCPFlags, "SYN") {
		n++
	}
	if hasTCPFlag(p.TCPFlags, "FIN") {
		n++
	}
	return n
}

// isKeepAlive reports whether p is a TCP keep-alive probe: one byte of
// data (or none) whose sequence number is the last acknowledged byte, one
// below the next expected sequence number.
func isKeepAlive(p models.PacketInfo, next uint32, haveNext bool) bool {
	return haveNext && p.PayloadSize == 1 &&
		!hasTCPFlag(p.TCPFlags, "SYN") && !hasTCPFlag(p.TCPFlags, "FIN") && !hasTCPFlag(p.TCPFlags, "RST") &&
		p.TCPSeq == next-1
}

// consumesSeq reports whether a TCP packet occupies sequence space, i.e. it
// carries payload or a SYN/FIN flag.
func consumesSeq(p models.PacketInfo) bool {
	if p.PayloadSize > 0 {
		return true
	}
	for _, f := range strings.Split(p.TCPFlags, ",") {
		if f == "SYN" || f == "FIN" {
			return true
		}
	}
	return false
}

// detectIssues inspects flows and returns any anomalies found.
func detectIssues(flows []models.Flow) []models.Issue {
	var issues []models.Issue
	for _, f := range flows {
		if f.Retransmits > 0 {
			issues = append(issues, models.Issue{
				ID:          "packetloss-" + f.ID,
				Severity:    models.SeverityWarning,
				Category:    "PacketLoss",
				Title:       "TCP Retransmissions detected",
				Description: fmt.Sprintf("flow %s had %d retransmitted packets", f.ID, f.Retransmits),
				Timestamp:   f.StartTime,
				FlowID:      f.ID,
			})
		}
	}
	return issues
}

// topTalkers returns up to n flows with the most total bytes, descending.
func topTalkers(flows []models.Flow, n int) []models.Flow {
	sorted := append([]models.Flow(nil), flows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].BytesSent+sorted[i].BytesRecv > sorted[j].BytesSent+sorted[j].BytesRecv
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}
