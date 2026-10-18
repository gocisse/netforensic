package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	slowSetupMs = 500.0
	slowTTFBMs  = 1000.0
	highRTTMs   = 200.0
	highJitter  = 500.0 // max RTT

	// latencyWarnMs is the worst average RTT from which the aggregated
	// latency issue becomes a warning instead of an info.
	latencyWarnMs = 1000.0
)

// applyPerformanceMetrics fills the timing metrics of every TCP flow and
// returns the updated flows (the input is not modified) with issues for
// metrics that exceed their thresholds:
//   - setup time over 500ms: slow TCP handshake (warning)
//   - TTFB over 1000ms: slow server response (warning)
//
// Per-flow issues are raised for the first two. Latency and jitter are
// common across many flows at once, so they are aggregated into at most one
// issue each (see aggregatePerformance):
//   - average RTT over 200ms: high network latency (info, or warning if the
//     worst flow averages over 1s)
//   - max RTT over 500ms: high jitter (warning)
//
// Setup time comes from the handshake timestamps on the packets, TTFB from
// those and the first payloads of the flow (see handshakeMetrics).
// RTT samples are the delays between a segment (data, SYN or FIN) and the
// first reverse-direction ACK covering it; retransmitted segments are
// skipped because their ACK is ambiguous.
func applyPerformanceMetrics(packets []models.PacketInfo, flows []models.Flow) ([]models.Flow, []models.Issue) {
	// The packets of each TCP flow, as indices into packets: copying the
	// packets themselves (about a kilobyte each) would hold every TCP packet
	// of the capture a second time. The flow ID is built once per connection,
	// not once per packet.
	byKey := make(map[instKey]*[]int32)
	byID := make(map[string]*[]int32)
	insts := models.ConnectionInstances(packets)
	for i := range packets {
		p := &packets[i]
		if p.Protocol != models.ProtocolTCP {
			continue
		}
		k, _ := canonicalKey(*p)
		ik := instKey{k, insts[i]}
		list := byKey[ik]
		if list == nil {
			list = new([]int32)
			byKey[ik] = list
			byID[ik.id()] = list
		}
		*list = append(*list, int32(i))
	}

	out := append([]models.Flow(nil), flows...)
	var issues []models.Issue
	var buf []models.PacketInfo

	for i := range out {
		f := &out[i]
		if f.Protocol != models.ProtocolTCP {
			continue
		}
		list := byID[f.ID]
		if list == nil || len(*list) == 0 {
			continue
		}
		// Only this flow's packets are copied, one flow at a time, into a
		// buffer that is reused for the next flow.
		pkts := buf[:0]
		for _, idx := range *list {
			pkts = append(pkts, packets[idx])
		}
		buf = pkts
		sort.SliceStable(pkts, func(a, b int) bool { return pkts[a].Timestamp.Before(pkts[b].Timestamp) })

		f.SetupTimeMs, f.TTFBMs = handshakeMetrics(pkts)
		f.AvgRTTMs, f.MaxRTTMs = rttMetrics(pkts)
		perf := performanceIssues(*f)
		if f.TTFBMs > slowTTFBMs {
			_, ack := flowHandshake(pkts)
			advice := slowResponseAdvice(*f, pkts, ack)
			for i := range perf {
				if perf[i].Title == "Slow Server Response" {
					perf[i].Recommendation = advice
				}
			}
		}
		issues = append(issues, perf...)
	}
	issues = append(issues, aggregatePerformance(out)...)
	return out, issues
}

// ms converts a duration to milliseconds rounded to two decimals.
func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Millisecond)*100) / 100 }

// handshakeMetrics derives setup time and TTFB from the handshake
// timestamps carried by the flow's packets, which must be sorted by time.
// Unobserved events yield 0.
//
// TTFB needs the handshake ACK. The anchor is the first payload at or after
// it: if that comes from the client, TTFB runs from that segment (a later or
// retransmitted client segment never moves it) to the first server payload
// after it, so the client's idle time before its request is not counted. If
// the server sends first (a greeting), TTFB runs from the ACK to that payload.
// The client is the sender of the connection's first SYN. Nothing looks into
// the payload: a one-byte keepalive probe counts as client data.
func handshakeMetrics(pkts []models.PacketInfo) (setupMs, ttfbMs float64) {
	syn, ack := flowHandshake(pkts)
	if !syn.IsZero() && !ack.IsZero() && !ack.Before(syn) {
		setupMs = ms(ack.Sub(syn))
	}
	if !ack.IsZero() {
		ttfbMs = ttfb(pkts, ack)
	}
	return setupMs, ttfbMs
}

// flowHandshake returns the time of the first SYN and of the final handshake
// ACK of the flow, from the handshake carried by its packets; a zero time
// means the event was not observed.
func flowHandshake(pkts []models.PacketInfo) (syn, ack time.Time) {
	for _, p := range pkts {
		if p.Handshake == nil {
			continue
		}
		if syn.IsZero() {
			syn = p.Handshake.TCPSynTime
		}
		if ack.IsZero() {
			ack = p.Handshake.TCPAckTime
		}
	}
	return syn, ack
}

// responseWindow is the interval TTFB measures: from the first client payload
// to the first server payload after it, as indices into the flow's packets.
type responseWindow struct {
	client endpoint
	anchor int       // the first client payload at or after the ACK; -1 if the server sent first
	end    int       // the first server payload at or after the ACK
	start  time.Time // the anchor's time, or the handshake ACK if the server sent first
}

// findResponseWindow locates the response window of the connection whose
// handshake ended at ack, in packets sorted by time. It reports false if the
// client is unknown or no server payload follows.
func findResponseWindow(pkts []models.PacketInfo, ack time.Time) (responseWindow, bool) {
	w := responseWindow{anchor: -1, start: ack}
	found := false
	for _, p := range pkts {
		if hasTCPFlag(p.TCPFlags, "SYN") && !hasTCPFlag(p.TCPFlags, "ACK") {
			w.client, found = endpoint{p.SrcIP, p.SrcPort}, true
			break
		}
	}
	if !found {
		return w, false
	}
	for i, p := range pkts {
		if p.PayloadSize == 0 || p.Timestamp.Before(ack) {
			continue
		}
		if (endpoint{p.SrcIP, p.SrcPort}) == w.client {
			if w.anchor < 0 {
				w.anchor, w.start = i, p.Timestamp // the first client payload; later ones do not move it
			}
			continue
		}
		w.end = i // the first server payload after the anchor
		return w, true
	}
	return w, false
}

// ttfb measures the time to first byte of the connection whose handshake ended
// at ack, or returns 0 if it cannot be measured.
func ttfb(pkts []models.PacketInfo, ack time.Time) float64 {
	w, ok := findResponseWindow(pkts, ack)
	if !ok {
		return 0
	}
	return ms(pkts[w.end].Timestamp.Sub(w.start))
}

// slowResponseAdvice says what the evidence in the response window of a slow
// flow supports. Loss evidence is a retransmission of either side inside the
// window, or a duplicate ACK (the detector's definition, see
// retransDir.trackAck) whose predecessor is also inside it, except an ACK that
// answers a keep-alive probe. Without it, the
// delay is placed after the request only if the server acknowledged the
// anchor's payload before its first data (the ACK on the first data itself
// does not count). A server-first flow and a one-byte client anchor, which
// may be a keep-alive probe, are not a request, so nothing is claimed for
// them. A truncated capture needs no case of its own: the window ends at a
// captured server payload, so it is always complete.
func slowResponseAdvice(f models.Flow, pkts []models.PacketInfo, ack time.Time) string {
	w, ok := findResponseWindow(pkts, ack)
	if !ok {
		return slowRespAmbiguous
	}
	end := pkts[w.end].Timestamp
	for _, ev := range f.RetransmitEvents {
		if !ev.Time.Before(w.start) && !ev.Time.After(end) {
			return slowRespLoss
		}
	}
	first := w.anchor
	if first < 0 {
		for first = 0; first < w.end && pkts[first].Timestamp.Before(ack); first++ {
		}
	}
	var client, server retransDir
	var next [2]uint32 // the end of the highest segment each side has sent, from the window's first packet
	var sent [2]bool
	probed := false // the previous packet was a keep-alive probe
	for i := first; i <= w.end; i++ {
		p := pkts[i]
		who, side := 1, &server
		if (endpoint{p.SrcIP, p.SrcPort}) == w.client {
			who, side = 0, &client
		}
		// A pure ACK that answers a keep-alive probe repeats the previous ACK
		// by design: it is not a duplicate ACK in the loss sense.
		if side.trackAck(p) && !probed {
			return slowRespLoss
		}
		probed = isKeepAlive(p, next[who], sent[who])
		if end := p.TCPSeq + seqLen(p); consumesSeq(p) && (!sent[who] || int32(end-next[who]) > 0) {
			next[who], sent[who] = end, true
		}
	}
	if w.anchor < 0 {
		return slowRespServerFirst
	}
	a := pkts[w.anchor]
	if a.PayloadSize == 1 {
		return slowRespAmbiguous
	}
	covered := a.TCPSeq + uint32(a.PayloadSize)
	for i := w.anchor + 1; i < w.end; i++ {
		p := pkts[i]
		if (endpoint{p.SrcIP, p.SrcPort}) != w.client && hasTCPFlag(p.TCPFlags, "ACK") && int32(p.TCPAck-covered) >= 0 {
			return slowRespRequestAcked
		}
	}
	return slowRespAmbiguous
}

type segment struct {
	end uint32 // sequence number just past the segment
	at  time.Time
}

// rttMetrics returns the average and maximum RTT in milliseconds over all
// samples in a flow's time-ordered packets, or zeros if there are none.
func rttMetrics(pkts []models.PacketInfo) (avgMs, maxMs float64) {
	if len(pkts) == 0 {
		return 0, 0
	}
	first, _ := canonicalKey(pkts[0])

	var pending [2][]segment
	var seen [2]map[uint32]bool
	seen[0], seen[1] = map[uint32]bool{}, map[uint32]bool{}

	var sum, max time.Duration
	var n int

	for _, p := range pkts {
		dir := 0
		if (endpoint{p.SrcIP, p.SrcPort}) != first.a {
			dir = 1
		}

		// An ACK from this side closes pending segments sent by the other side.
		if hasTCPFlag(p.TCPFlags, "ACK") {
			other := 1 - dir
			var latest segment
			found := false
			rest := pending[other][:0]
			for i := range pending[other] {
				s := pending[other][i]
				if int32(p.TCPAck-s.end) >= 0 {
					latest, found = s, true
				} else {
					rest = append(rest, s)
				}
			}
			if found {
				if d := p.Timestamp.Sub(latest.at); d >= 0 {
					sum += d
					n++
					if d > max {
						max = d
					}
				}
			}
			pending[other] = rest
		}

		// Register the segment this packet sends.
		length := uint32(p.PayloadSize)
		if hasTCPFlag(p.TCPFlags, "SYN") {
			length++
		}
		if hasTCPFlag(p.TCPFlags, "FIN") {
			length++
		}
		if length == 0 {
			continue
		}
		end := p.TCPSeq + length
		if seen[dir][p.TCPSeq] { // retransmission: its ACK is ambiguous (Karn)
			rest := pending[dir][:0]
			for _, s := range pending[dir] {
				if s.end != end {
					rest = append(rest, s)
				}
			}
			pending[dir] = rest
			continue
		}
		seen[dir][p.TCPSeq] = true
		pending[dir] = append(pending[dir], segment{end, p.Timestamp})
	}

	if n == 0 {
		return 0, 0
	}
	return ms(sum / time.Duration(n)), ms(max)
}

// hasTCPFlag reports whether the comma-separated flags string includes flag.
func hasTCPFlag(flags, flag string) bool {
	// Walks the comma-separated list without splitting it: this runs several
	// times per packet, and strings.Split allocated a slice every time.
	for len(flags) > 0 {
		f := flags
		if i := strings.IndexByte(flags, ','); i >= 0 {
			f, flags = flags[:i], flags[i+1:]
		} else {
			flags = ""
		}
		if f == flag {
			return true
		}
	}
	return false
}

// performanceIssues returns the per-flow threshold violations of one flow:
// a slow handshake and a slow first response.
func performanceIssues(f models.Flow) []models.Issue {
	var issues []models.Issue
	add := func(kind string, title, desc string) {
		issues = append(issues, models.Issue{
			ID:          "perf-" + kind + "-" + f.ID,
			Severity:    models.SeverityWarning,
			Category:    "Performance",
			Title:       title,
			Description: desc,
			Timestamp:   f.StartTime,
			FlowID:      f.ID,
		})
	}
	if f.SetupTimeMs > slowSetupMs {
		add("setup", "Slow TCP Handshake",
			fmt.Sprintf("flow %s took %.0fms to complete the TCP handshake (threshold %.0fms)", f.ID, f.SetupTimeMs, slowSetupMs))
	}
	if f.TTFBMs > slowTTFBMs {
		add("ttfb", "Slow Server Response",
			fmt.Sprintf("flow %s waited %.0fms for the first server data after the first client data, or after the handshake if the server sends first (threshold %.0fms)", f.ID, f.TTFBMs, slowTTFBMs))
	}
	return issues
}

// aggregatePerformance folds the latency and jitter violations of all flows
// into one issue each:
//   - High Network Latency: flows with an average RTT over 200ms
//   - High Jitter: flows with a maximum RTT over 500ms
//
// The issues name the number of flows, the worst value observed and the
// three worst flows; the full list is in Occurrences. The slowest flows are
// also shown by the TOP SLOW FLOWS table.
func aggregatePerformance(flows []models.Flow) []models.Issue {
	var issues []models.Issue
	if is, ok := aggregateFlowMetric(flows, "latency", "High Network Latency",
		func(f models.Flow) float64 { return f.AvgRTTMs }, highRTTMs, "average RTT"); ok {
		is.Severity = models.SeverityInfo
		if is.worstValue > latencyWarnMs {
			is.Severity = models.SeverityWarning
		}
		issues = append(issues, is.Issue)
	}
	if is, ok := aggregateFlowMetric(flows, "jitter", "High Jitter",
		func(f models.Flow) float64 { return f.MaxRTTMs }, highJitter, "max RTT"); ok {
		is.Severity = models.SeverityWarning
		issues = append(issues, is.Issue)
	}
	return issues
}

// aggregated is an aggregate issue plus the value that decides its severity.
type aggregated struct {
	models.Issue
	worstValue float64
}

func aggregateFlowMetric(flows []models.Flow, kind, title string, value func(models.Flow) float64, threshold float64, what string) (aggregated, bool) {
	var hit []models.Flow
	for _, f := range flows {
		if value(f) > threshold {
			hit = append(hit, f)
		}
	}
	if len(hit) == 0 {
		return aggregated{}, false
	}
	sort.SliceStable(hit, func(i, j int) bool { return value(hit[i]) > value(hit[j]) })

	first := hit[0].StartTime
	occ := make([]models.Occurrence, len(hit))
	for i, f := range hit {
		occ[i] = models.Occurrence{Time: f.StartTime, Subject: f.ID, Value: value(f), Unit: "ms"}
		if f.StartTime.Before(first) {
			first = f.StartTime
		}
	}
	worst := make([]string, 0, 3)
	for i, f := range hit {
		if i == 3 {
			break
		}
		worst = append(worst, fmt.Sprintf("%s (%.0fms)", f.ID, value(f)))
	}

	is := models.Issue{
		ID:          "perf-" + kind,
		Category:    "Performance",
		Title:       title,
		Timestamp:   first,
		Target:      hit[0].ID,
		Count:       len(hit),
		Occurrences: occ,
	}
	if len(hit) == 1 {
		is.FlowID = hit[0].ID
	}
	is.Description = fmt.Sprintf("%s experienced %s > %.0fms (Max observed: %.0fms). Worst: %s",
		count(len(hit), "flow", "flows"), what, threshold, value(hit[0]), strings.Join(worst, ", "))
	return aggregated{is, value(hit[0])}, true
}

// slowFlows returns up to n flows ordered by their worst timing metric. The
// result holds copies of just those flows: slicing a copy of all of them
// would keep every flow of the capture alive.
func slowFlows(flows []models.Flow, n int) []models.Flow {
	worst := func(f *models.Flow) float64 { return math.Max(math.Max(f.SetupTimeMs, f.TTFBMs), f.MaxRTTMs) }
	var idx []int
	for i := range flows {
		if worst(&flows[i]) > 0 {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return worst(&flows[idx[a]]) > worst(&flows[idx[b]]) })
	return pick(flows, idx, n)
}

// pick returns copies of the first n of the flows at idx (all of them if
// there are fewer), never nil.
func pick(flows []models.Flow, idx []int, n int) []models.Flow {
	if len(idx) > n {
		idx = idx[:n]
	}
	out := make([]models.Flow, len(idx))
	for i, j := range idx {
		out[i] = flows[j]
	}
	return out
}
