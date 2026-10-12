// Package analyzer contains the pure analysis logic. It performs no file,
// CLI or network I/O and operates only on in-memory models.
package analyzer

import (
	"net"
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
	return AnalyzeWithProgress(packets, service, nil, extra...)
}

// Analysis stages, as reported to the progress callback of AnalyzeWithProgress.
const (
	// StageClassifying is reported when packets are grouped into flows and classified.
	StageClassifying = "classifying"
	// StageDetecting is reported when the issue detectors start.
	StageDetecting = "detecting"
	// StageReporting is reported when the issues are annotated and the verdict is computed.
	StageReporting = "reporting"
)

// AnalyzeWithProgress is AnalyzeWithIssues that calls progress (if not nil)
// with the name of each stage as it starts: StageClassifying, StageDetecting
// and StageReporting. The callback runs on the calling goroutine; the
// analysis itself stays free of I/O.
func AnalyzeWithProgress(packets []models.PacketInfo, service string, progress func(stage string), extra ...models.Issue) *models.AnalysisResult {
	start := time.Now()
	stage := func(name string) {
		if progress != nil {
			progress(name)
		}
	}
	stage(StageClassifying)

	// Callers that print or follow packets should filter with FilterService
	// first and pass the result here, so that what they show is exactly what
	// is analyzed; filtering again is harmless.
	packets, _ = FilterService(packets, service)

	flows := aggregateFlows(packets)
	classes, perPacket := classifyFlows(packets)
	for i := range flows {
		if c := classes[flows[i].ID]; c != nil {
			flows[i].AppProtocol = string(c.app)
		}
	}
	flows, perfIssues := applyPerformanceMetrics(packets, flows)
	stage(StageDetecting)
	issues := detectIssues(flows)
	issues = append(issues, analyzeDNS(packets)...)
	issues = append(issues, analyzeHTTP(packets)...)
	issues = append(issues, analyzeTLS(packets)...)
	issues = append(issues, analyzeSIP(packets)...)
	issues = append(issues, analyzeDHCPv6(packets)...)
	issues = append(issues, analyzeQUIC(packets)...)
	issues = append(issues, analyzeICMP(packets)...)
	issues = append(issues, analyzeARP(packets)...)
	issues = append(issues, analyzeConnections(packets)...)
	issues = append(issues, perfIssues...)
	issues = append(issues, extra...)
	if note, ok := decapsulatedIssue(packets); ok {
		issues = append(issues, note)
	}
	if issues == nil {
		issues = []models.Issue{} // serialize as [] rather than null
	}
	stage(StageReporting)
	annotateProtocols(issues, classes)
	annotateGuidance(issues, flows)
	annotateFlowStatus(flows, issues)
	talkers := topTalkers(flows, topTalkerCount)
	if talkers == nil {
		talkers = []models.Flow{}
	}
	return &models.AnalysisResult{
		TotalPackets:  len(packets),
		TotalFlows:    len(flows),
		AnalysisTime:  start,
		Duration:      formatDuration(captureDuration(packets)),
		Issues:        issues,
		TopTalkers:    talkers,
		SlowFlows:     slowFlows(flows, topTalkerCount),
		ProtocolStats: protocolStats(packets, flows, classes, perPacket),
		Diagnosis:     correlate(packets, flows, issues),
		Flows:         flows,

		GoodTrafficFilter: GoodTrafficFilter(issues),
		HealthyFlows:      HealthyFlows(flows),
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

// FilterService keeps the packets that belong to service: "all" keeps
// everything, "dns" keeps packets to or from port 53 and any packet that
// carries a DNS message, "http" is port 80, "tls" and "https" are port 443,
// and a number is that port. It reports false, with no packets, if service
// is not recognized.
func FilterService(packets []models.PacketInfo, service string) ([]models.PacketInfo, bool) {
	port, matchAll, ok := parseService(service)
	switch {
	case !ok:
		return nil, false
	case matchAll:
		return packets, true
	case strings.EqualFold(service, "dns"):
		var out []models.PacketInfo
		for _, p := range packets {
			if p.SrcPort == port || p.DstPort == port || p.DNSQueryName != "" {
				out = append(out, p)
			}
		}
		return out, true
	}
	return filterByPort(packets, port), true
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

// maxShownDuration is the longest capture duration shown exactly. Longer
// ones usually mean that interfaces with unsynchronized clocks were merged
// into one file (the packets then span years), and a precise figure would
// only look broken.
const maxShownDuration = 24 * time.Hour

// formatDuration formats d, or "24h+" if it exceeds maxShownDuration.
func formatDuration(d time.Duration) string {
	if d > maxShownDuration {
		return "24h+"
	}
	return d.String()
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

// String formats the endpoint as ip:port, with IPv6 addresses in brackets
// ([2001:db8::1]:443) so the port cannot be mistaken for part of the address.
func (e endpoint) String() string { return net.JoinHostPort(e.ip, strconv.Itoa(int(e.port))) }

type flowKey struct {
	a, b  endpoint
	proto models.Protocol
	// tunnel is the direction-independent identity of the tunnel the packets
	// came out of (see models.TunnelKey), or "". Without it, the same inner
	// 4-tuple in two different tunnels would be taken for one flow.
	tunnel string
}

// instKey identifies one connection: a flowKey plus the index of the TCP
// connection attempt on that 4-tuple (see models.ConnectionInstances).
type instKey struct {
	flowKey
	inst int
}

// id is the flow ID shown to users: "ip:port-ip:port", with "#N" appended
// from the second connection on a reused 4-tuple, e.g. "...#2". A flow that
// came out of a tunnel ends with "@KIND:outer~outer", for example
// "...@GRE:192.0.2.1~192.0.2.2".
func (k instKey) id() string {
	id := k.a.String() + "-" + k.b.String()
	if k.inst > 0 {
		id += "#" + strconv.Itoa(k.inst+1)
	}
	if k.tunnel != "" {
		id += "@" + k.tunnel
	}
	return id
}

// canonicalKey returns the direction-independent flow key of p and whether p
// travels from the canonical source endpoint to the canonical destination.
func canonicalKey(p models.PacketInfo) (key flowKey, forward bool) {
	src := endpoint{p.SrcIP, p.SrcPort}
	dst := endpoint{p.DstIP, p.DstPort}
	tunnel := models.TunnelKey(p.Tunnel)
	if dst.less(src) {
		return flowKey{dst, src, p.Protocol, tunnel}, false
	}
	return flowKey{src, dst, p.Protocol, tunnel}, true
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
				Tunnel:    key.tunnel,
				StartTime: p.Timestamp,
				EndTime:   p.Timestamp,
			}
			if p.StreamKnown {
				stream := p.Stream
				f.TCPStream = &stream
			}
			byKey[key] = f
		}

		f.PacketCount++
		noteSIP(f, p)
		noteDHCPv6(f, p)
		noteQUIC(f, p)
		if forward {
			f.BytesSent += p.Size
		} else {
			f.BytesRecv += p.Size
		}
		if r := rd.observe(key, forward, p); r.retrans || r.dupAck {
			recordRetransmit(f, r, p)
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

// detectIssues inspects flows and returns any anomalies found: one issue
// per flow for each kind of retransmission it contains.
func detectIssues(flows []models.Flow) []models.Issue {
	var issues []models.Issue
	for _, f := range flows {
		if f.Retransmits == 0 {
			continue
		}
		for _, k := range []retransKind{retransTimeout, retransFast, retransOther} {
			if is, ok := retransmitIssue(f, k); ok {
				issues = append(issues, is)
			}
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

// noteSIP adds the SIP details of p, if it carries any, to flow f: each
// request method once, and the first Call-ID and User-Agent.
func noteSIP(f *models.Flow, p models.PacketInfo) {
	if p.SIPMethod == "" && p.SIPStatusCode == 0 {
		return
	}
	if m := p.SIPMethod; m != "" && !strings.Contains(","+f.SIPMethod+",", ","+m+",") {
		if f.SIPMethod != "" {
			f.SIPMethod += ","
		}
		f.SIPMethod += m
	}
	if f.SIPCallID == "" {
		f.SIPCallID = p.SIPCallID
	}
	if f.SIPUserAgent == "" {
		f.SIPUserAgent = p.SIPUserAgent
	}
}
