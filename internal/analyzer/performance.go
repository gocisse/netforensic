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
// Setup time and TTFB come from the handshake timestamps on the packets.
// RTT samples are the delays between a segment (data, SYN or FIN) and the
// first reverse-direction ACK covering it; retransmitted segments are
// skipped because their ACK is ambiguous.
func applyPerformanceMetrics(packets []models.PacketInfo, flows []models.Flow) ([]models.Flow, []models.Issue) {
	byID := make(map[string][]models.PacketInfo)
	insts := models.ConnectionInstances(packets)
	for i, p := range packets {
		if p.Protocol != models.ProtocolTCP {
			continue
		}
		k, _ := canonicalKey(p)
		id := instKey{k, insts[i]}.id()
		byID[id] = append(byID[id], p)
	}

	out := append([]models.Flow(nil), flows...)
	var issues []models.Issue

	for i := range out {
		f := &out[i]
		if f.Protocol != models.ProtocolTCP {
			continue
		}
		pkts := byID[f.ID]
		if len(pkts) == 0 {
			continue
		}
		sort.SliceStable(pkts, func(a, b int) bool { return pkts[a].Timestamp.Before(pkts[b].Timestamp) })

		f.SetupTimeMs, f.TTFBMs = handshakeMetrics(pkts)
		f.AvgRTTMs, f.MaxRTTMs = rttMetrics(pkts)
		issues = append(issues, performanceIssues(*f)...)
	}
	issues = append(issues, aggregatePerformance(out)...)
	return out, issues
}

// ms converts a duration to milliseconds rounded to two decimals.
func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Millisecond)*100) / 100 }

// handshakeMetrics derives setup time and TTFB from the handshake
// timestamps carried by the flow's packets. Unobserved events yield 0.
func handshakeMetrics(pkts []models.PacketInfo) (setupMs, ttfbMs float64) {
	var syn, ack, data time.Time
	for _, p := range pkts {
		if syn.IsZero() {
			syn = p.TCPSynTime
		}
		if ack.IsZero() {
			ack = p.TCPAckTime
		}
		if data.IsZero() {
			data = p.FirstDataTime
		}
	}
	if !syn.IsZero() && !ack.IsZero() && !ack.Before(syn) {
		setupMs = ms(ack.Sub(syn))
	}
	if !ack.IsZero() && !data.IsZero() && !data.Before(ack) {
		ttfbMs = ms(data.Sub(ack))
	}
	return setupMs, ttfbMs
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
	for _, f := range strings.Split(flags, ",") {
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
			fmt.Sprintf("flow %s waited %.0fms for the first server data after the handshake (threshold %.0fms)", f.ID, f.TTFBMs, slowTTFBMs))
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

// slowFlows returns up to n flows ordered by their worst timing metric.
func slowFlows(flows []models.Flow, n int) []models.Flow {
	worst := func(f models.Flow) float64 { return math.Max(math.Max(f.SetupTimeMs, f.TTFBMs), f.MaxRTTMs) }
	var out []models.Flow
	for _, f := range flows {
		if worst(f) > 0 {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return worst(out[i]) > worst(out[j]) })
	if len(out) > n {
		out = out[:n]
	}
	if out == nil {
		out = []models.Flow{}
	}
	return out
}
