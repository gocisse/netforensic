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
)

// applyPerformanceMetrics fills the timing metrics of every TCP flow and
// returns the updated flows (the input is not modified) with issues for
// metrics that exceed their thresholds:
//   - setup time over 500ms: slow TCP handshake (warning)
//   - TTFB over 1000ms: slow server response (warning)
//   - average RTT over 200ms: high network latency (info)
//   - max RTT over 500ms: high jitter (warning)
//
// Setup time and TTFB come from the handshake timestamps on the packets.
// RTT samples are the delays between a segment (data, SYN or FIN) and the
// first reverse-direction ACK covering it; retransmitted segments are
// skipped because their ACK is ambiguous.
func applyPerformanceMetrics(packets []models.PacketInfo, flows []models.Flow) ([]models.Flow, []models.Issue) {
	byKey := make(map[flowKey][]models.PacketInfo)
	for _, p := range packets {
		if p.Protocol != models.ProtocolTCP {
			continue
		}
		k, _ := canonicalKey(p)
		byKey[k] = append(byKey[k], p)
	}

	out := append([]models.Flow(nil), flows...)
	var issues []models.Issue

	for i := range out {
		f := &out[i]
		if f.Protocol != models.ProtocolTCP {
			continue
		}
		pkts := byKey[flowKey{endpoint{f.SrcIP, f.SrcPort}, endpoint{f.DstIP, f.DstPort}, f.Protocol}]
		if len(pkts) == 0 {
			continue
		}
		sort.SliceStable(pkts, func(a, b int) bool { return pkts[a].Timestamp.Before(pkts[b].Timestamp) })

		f.SetupTimeMs, f.TTFBMs = handshakeMetrics(pkts)
		f.AvgRTTMs, f.MaxRTTMs = rttMetrics(pkts)
		issues = append(issues, performanceIssues(*f)...)
	}
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

// performanceIssues returns the threshold violations of one flow.
func performanceIssues(f models.Flow) []models.Issue {
	var issues []models.Issue
	add := func(kind string, sev models.Severity, title, desc string) {
		issues = append(issues, models.Issue{
			ID:          "perf-" + kind + "-" + f.ID,
			Severity:    sev,
			Category:    "Performance",
			Title:       title,
			Description: desc,
			Timestamp:   f.StartTime,
			FlowID:      f.ID,
		})
	}
	if f.SetupTimeMs > slowSetupMs {
		add("setup", models.SeverityWarning, "Slow TCP Handshake",
			fmt.Sprintf("flow %s took %.0fms to complete the TCP handshake (threshold %.0fms)", f.ID, f.SetupTimeMs, slowSetupMs))
	}
	if f.TTFBMs > slowTTFBMs {
		add("ttfb", models.SeverityWarning, "Slow Server Response",
			fmt.Sprintf("flow %s waited %.0fms for the first server data after the handshake (threshold %.0fms)", f.ID, f.TTFBMs, slowTTFBMs))
	}
	if f.AvgRTTMs > highRTTMs {
		add("latency", models.SeverityInfo, "High Network Latency",
			fmt.Sprintf("flow %s has an average RTT of %.0fms (threshold %.0fms)", f.ID, f.AvgRTTMs, highRTTMs))
	}
	if f.MaxRTTMs > highJitter {
		add("jitter", models.SeverityWarning, "High Jitter",
			fmt.Sprintf("flow %s has a maximum RTT of %.0fms (average %.0fms, threshold %.0fms)", f.ID, f.MaxRTTMs, f.AvgRTTMs, highJitter))
	}
	return issues
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
