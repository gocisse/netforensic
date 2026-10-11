package analyzer

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

func issue(id string, sec float64, sev models.Severity, cat, title, domain string) models.Issue {
	return models.Issue{ID: id, Timestamp: at(sec), Severity: sev, Category: cat, Title: title, Description: "detail " + id, Domain: domain}
}

func servfail(id string, sec float64, domain string) models.Issue {
	return issue(id, sec, models.SeverityError, "DNS", "DNS SERVFAIL", domain)
}

func http5xx(id string, sec float64, domain string) models.Issue {
	return issue(id, sec, models.SeverityError, "HTTP", "HTTP Server Error", domain)
}

func roleOf(r models.RootCauseAnalysis, desc string) string {
	for _, e := range r.Timeline {
		if e.Description == desc {
			return e.EventType
		}
	}
	return "missing"
}

func TestCorrelateDNSToHTTP(t *testing.T) {
	tests := []struct {
		name         string
		issues       []models.Issue
		wantCause    string
		wantConf     string
		wantRoot     []string // issue titles+id expected as root_cause
		wantSymptoms []string
	}{
		{"same domain within 5s", []models.Issue{servfail("d", 10, "api.example.com"), http5xx("h", 12, "api.example.com")},
			"DNS resolution failure for api.example.com", "high", []string{"d"}, []string{"h"}},
		{"domain match ignores case", []models.Issue{servfail("d", 10, "API.example.com"), http5xx("h", 11, "api.EXAMPLE.com")},
			"DNS resolution failure for API.example.com", "high", []string{"d"}, []string{"h"}},
		{"exactly 5s still correlates", []models.Issue{servfail("d", 10, "x.com"), http5xx("h", 15, "x.com")},
			"DNS resolution failure for x.com", "high", []string{"d"}, []string{"h"}},
		{"unknown http host is a medium-confidence link", []models.Issue{servfail("d", 10, "x.com"), http5xx("h", 11, "")},
			"DNS resolution failure for x.com", "medium", []string{"d"}, []string{"h"}},
		{"unknown dns domain is a medium-confidence link", []models.Issue{servfail("d", 10, ""), http5xx("h", 11, "x.com")},
			"DNS resolution failure", "medium", []string{"d"}, []string{"h"}},
		{"several 5xx are all symptoms", []models.Issue{servfail("d", 10, "x.com"), http5xx("h1", 11, "x.com"), http5xx("h2", 13, "x.com")},
			"DNS resolution failure for x.com", "high", []string{"d"}, []string{"h1", "h2"}},
		{"timeline input order does not matter", []models.Issue{http5xx("h", 12, "x.com"), servfail("d", 10, "x.com")},
			"DNS resolution failure for x.com", "high", []string{"d"}, []string{"h"}},
		{"best of two servfails wins", []models.Issue{servfail("d1", 0, "a.com"), servfail("d2", 50, "b.com"),
			http5xx("h1", 51, "b.com"), http5xx("h2", 52, "b.com")},
			"DNS resolution failure for b.com", "high", []string{"d2"}, []string{"h1", "h2"}},
		{"matching domain beats unknown on a tie", []models.Issue{servfail("d1", 0, "a.com"), http5xx("h1", 1, ""),
			servfail("d2", 50, "b.com"), http5xx("h2", 51, "b.com")},
			"DNS resolution failure for b.com", "high", []string{"d2"}, []string{"h2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := correlate(nil, nil, tt.issues)
			assert.Equal(t, tt.wantCause, r.PrimaryCause)
			assert.Equal(t, tt.wantConf, r.Confidence)
			assert.Contains(t, r.Summary, "SERVFAIL")
			for _, id := range tt.wantRoot {
				assert.Equal(t, eventRootCause, roleOf(r, titleOf(tt.issues, id)), id)
			}
			for _, id := range tt.wantSymptoms {
				assert.Equal(t, eventSymptom, roleOf(r, titleOf(tt.issues, id)), id)
			}
			assert.GreaterOrEqual(t, len(r.Recommendations), 2)
			assert.LessOrEqual(t, len(r.Recommendations), 3)
		})
	}
}

// titleOf returns the timeline description the correlator generates for the issue with the given id.
func titleOf(issues []models.Issue, id string) string {
	for _, is := range issues {
		if is.ID == id {
			return is.Title + ": " + is.Description
		}
	}
	return ""
}

func TestCorrelateNoDNSHTTPLink(t *testing.T) {
	tests := []struct {
		name   string
		issues []models.Issue
	}{
		{"5xx more than 5s later", []models.Issue{servfail("d", 10, "x.com"), http5xx("h", 15.01, "x.com")}},
		{"5xx before the servfail", []models.Issue{http5xx("h", 9, "x.com"), servfail("d", 10, "x.com")}},
		{"5xx for a different domain", []models.Issue{servfail("d", 10, "x.com"), http5xx("h", 11, "y.com")}},
		{"servfail without http errors", []models.Issue{servfail("d", 10, "x.com")}},
		{"4xx is not a 5xx", []models.Issue{servfail("d", 10, "x.com"), issue("h", 11, models.SeverityWarning, "HTTP", "HTTP Client Error", "x.com")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := correlate(nil, nil, tt.issues)
			assert.NotContains(t, r.PrimaryCause, "DNS resolution failure")
			for _, e := range r.Timeline {
				assert.NotEqual(t, eventSymptom, e.EventType)
			}
		})
	}
}

func TestCorrelateCongestion(t *testing.T) {
	hot := func(id string) models.Flow { return models.Flow{ID: id, AvgRTTMs: 300, Retransmits: 2} }
	tests := []struct {
		name     string
		flows    []models.Flow
		wantConf string
		wantOK   bool
	}{
		{"high rtt and retransmits", []models.Flow{hot("f1")}, "medium", true},
		{"two flows raise confidence", []models.Flow{hot("f1"), hot("f2")}, "high", true},
		{"high rtt alone", []models.Flow{{ID: "f", AvgRTTMs: 300}}, "", false},
		{"retransmits alone", []models.Flow{{ID: "f", AvgRTTMs: 20, Retransmits: 5}}, "", false},
		{"rtt exactly at threshold", []models.Flow{{ID: "f", AvgRTTMs: 200, Retransmits: 5}}, "", false},
		{"no flows", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := []models.Issue{{ID: "p1", FlowID: "f1", Timestamp: at(1), Severity: models.SeverityWarning, Category: "PacketLoss", Title: "TCP Retransmissions detected", Description: "d"}}
			r := correlate(nil, tt.flows, issues)
			if !tt.wantOK {
				assert.NotEqual(t, "Network congestion", r.PrimaryCause)
				return
			}
			assert.Equal(t, "Network congestion", r.PrimaryCause)
			assert.Equal(t, tt.wantConf, r.Confidence)
			assert.Contains(t, r.Summary, "retransmit")
			assert.Equal(t, eventRootCause, roleOf(r, "TCP Retransmissions detected: d"), "issues on congested flows are root-cause events")
			assert.GreaterOrEqual(t, len(r.Recommendations), 2)
		})
	}

	t.Run("worst flow is named", func(t *testing.T) {
		flows := []models.Flow{{ID: "mild", AvgRTTMs: 250, Retransmits: 1}, {ID: "bad", AvgRTTMs: 900, Retransmits: 3}}
		assert.Contains(t, correlate(nil, flows, nil).Summary, "bad")
	})
}

func TestCorrelatePriority(t *testing.T) {
	congested := []models.Flow{{ID: "f", AvgRTTMs: 300, Retransmits: 2}}
	dup := issue("dup", 5, models.SeverityCritical, "ARP", "Duplicate IP Address", "")

	tests := []struct {
		name      string
		flows     []models.Flow
		issues    []models.Issue
		wantCause string
		wantConf  string
	}{
		{"dns link beats critical", nil, []models.Issue{dup, servfail("d", 10, "x.com"), http5xx("h", 11, "x.com")}, "DNS resolution failure for x.com", "high"},
		{"critical beats congestion", congested, []models.Issue{dup}, "Duplicate IP Address", "high"},
		{"congestion beats worst-issue fallback", congested, []models.Issue{http5xx("h", 1, "")}, "Network congestion", "medium"},
		{"retransmissions are reported as packet loss", nil, []models.Issue{issue("p", 1, models.SeverityWarning, "PacketLoss", "TCP Retransmissions detected", "")}, "Packet loss", "low"},
		{"error issue fallback", nil, []models.Issue{http5xx("h", 1, "x.com")}, "HTTP Server Error", "medium"},
		{"warning issue fallback", nil, []models.Issue{issue("w", 1, models.SeverityWarning, "TLS", "TLS Protocol Downgrade", "")}, "TLS Protocol Downgrade", "low"},
		{"info issue fallback", nil, []models.Issue{issue("i", 1, models.SeverityInfo, "ICMP", "ICMP Redirect", "")}, "ICMP Redirect", "low"},
		{"most severe issue wins", nil, []models.Issue{
			issue("i", 1, models.SeverityInfo, "ICMP", "ICMP Redirect", ""),
			issue("e", 2, models.SeverityError, "ICMP", "ICMP Destination Unreachable", ""),
			issue("w", 3, models.SeverityWarning, "TLS", "TLS Protocol Downgrade", "")}, "ICMP Destination Unreachable", "medium"},
		{"no issues", nil, nil, "No significant issues detected", "high"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := correlate([]models.PacketInfo{{Timestamp: at(0)}}, tt.flows, tt.issues)
			assert.Equal(t, tt.wantCause, r.PrimaryCause)
			assert.Equal(t, tt.wantConf, r.Confidence)
			assert.NotEmpty(t, r.Summary)
		})
	}
}

func TestHealthScore(t *testing.T) {
	mk := func(sevs ...models.Severity) []models.Issue {
		var out []models.Issue
		for _, s := range sevs {
			out = append(out, models.Issue{Severity: s})
		}
		return out
	}
	tests := []struct {
		name   string
		issues []models.Issue
		want   int
	}{
		{"none", nil, 100},
		{"info", mk(models.SeverityInfo), 98},
		{"warning", mk(models.SeverityWarning), 90},
		{"error", mk(models.SeverityError), 80},
		{"critical", mk(models.SeverityCritical), 70},
		{"one of each", mk(models.SeverityCritical, models.SeverityError, models.SeverityWarning, models.SeverityInfo), 38},
		{"capped at zero", mk(models.SeverityCritical, models.SeverityCritical, models.SeverityCritical, models.SeverityCritical), 0},
		{"unknown severity costs nothing", mk(models.Severity("WEIRD")), 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, healthScore(tt.issues))
			assert.Equal(t, tt.want, correlate(nil, nil, tt.issues).HealthScore)
		})
	}
}

func TestTimeline(t *testing.T) {
	packets := []models.PacketInfo{{Timestamp: at(5)}, {Timestamp: at(0)}, {Timestamp: at(20)}}
	issues := []models.Issue{
		issue("late", 15, models.SeverityWarning, "TLS", "TLS Protocol Downgrade", ""),
		issue("early", 2, models.SeverityInfo, "ICMP", "ICMP Redirect", ""),
		issue("atstart", 0, models.SeverityInfo, "ICMP", "ICMP Redirect", ""),
		issue("atend", 20, models.SeverityInfo, "ICMP", "ICMP Redirect", ""),
	}
	r := correlate(packets, nil, issues)
	require.Len(t, r.Timeline, 6)

	for i := 1; i < len(r.Timeline); i++ {
		assert.False(t, r.Timeline[i].Timestamp.Before(r.Timeline[i-1].Timestamp), "event %d out of order", i)
	}
	assert.Equal(t, eventCaptureStart, r.Timeline[0].EventType, "capture_start precedes issues at the same instant")
	assert.Equal(t, eventCaptureEnd, r.Timeline[5].EventType, "capture_end follows issues at the same instant")
	assert.Equal(t, at(0), r.Timeline[0].Timestamp)
	assert.Equal(t, at(20), r.Timeline[5].Timestamp)
	assert.Contains(t, r.Timeline[0].Description, "3 packets")
	assert.Contains(t, r.Timeline[5].Description, "20s")
	for _, e := range r.Timeline {
		assert.NotEmpty(t, e.Description)
		assert.NotEmpty(t, e.Severity)
	}
}

func TestTimelineWithoutPackets(t *testing.T) {
	r := correlate(nil, nil, []models.Issue{issue("i", 1, models.SeverityInfo, "ICMP", "ICMP Redirect", "")})
	require.Len(t, r.Timeline, 1)
	assert.Equal(t, eventRootCause, r.Timeline[0].EventType, "sole issue is the fallback root cause")
	assert.Empty(t, correlate(nil, nil, nil).Timeline)
}

func TestCorrelateDoesNotMutateInput(t *testing.T) {
	issues := []models.Issue{http5xx("h", 12, ""), servfail("d", 10, "")}
	correlate(nil, nil, issues)
	assert.Equal(t, "h", issues[0].ID)
}

func TestRecommendations(t *testing.T) {
	cats := []string{"DNS", "HTTP", "TLS", "PacketLoss", "Performance", "ICMP", "ARP", "Unheard-of"}
	for _, c := range cats {
		t.Run("issue/"+c, func(t *testing.T) {
			r := recommendations(causeIssue, "", c)
			assert.GreaterOrEqual(t, len(r), 2)
			assert.LessOrEqual(t, len(r), 3)
		})
	}
	for _, kind := range []string{causeDNSHTTP, causeCongestion, causeNone} {
		t.Run(kind, func(t *testing.T) {
			r := recommendations(kind, "x.com", "")
			assert.GreaterOrEqual(t, len(r), 2)
			assert.LessOrEqual(t, len(r), 3)
		})
	}
	assert.Contains(t, recommendations(causeDNSHTTP, "x.com", "")[0], "dig x.com")
	assert.Contains(t, recommendations(causeDNSHTTP, "", "")[0], "the failing domain")
}

func TestAnalyzeProducesDiagnosis(t *testing.T) {
	res := Analyze([]models.PacketInfo{
		icmpPkt(0, "10.0.0.254", "10.0.0.1", 3, 1, "Destination Unreachable: Host Unreachable"),
		arpPkt(1, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(2, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05"),
	}, "all")
	assert.Equal(t, 50, res.Diagnosis.HealthScore, "critical (30) + error (20)")
	assert.Equal(t, "Duplicate IP Address", res.Diagnosis.PrimaryCause)
	assert.NotEmpty(t, res.Diagnosis.Timeline)
	assert.NotNil(t, res.SlowFlows)
}

// The tests below run the whole pipeline on real captures from ../VendorTestFile.

func readReal(t *testing.T, name string) []models.PacketInfo {
	t.Helper()
	packets, err := pcap.ReadPackets(filepath.Join("..", "..", "testdata", name))
	require.NoError(t, err)
	require.NotEmpty(t, packets)
	return packets
}

func issueTitles(r *models.AnalysisResult) []string {
	var titles []string
	for _, is := range r.Issues {
		titles = append(titles, is.Title)
	}
	return titles
}

// Lab-3: one HTTP download in which Wireshark reports retransmissions
// (a fast retransmission, a retransmission and a spurious retransmission).
func TestCorrelateRealLab3TCPRetransmissions(t *testing.T) {
	packets := readReal(t, "Lab-3-TCP-Retrans.pcapng")
	res := Analyze(packets, "all")

	assert.Equal(t, 202, res.TotalPackets)
	require.Equal(t, 1, res.TotalFlows)
	flow := res.TopTalkers[0]
	assert.Equal(t, "10.0.0.145:54436-186.15.230.24:80", flow.ID)
	assert.Positive(t, flow.Retransmits, "retransmissions must be detected")

	// Wireshark finds three retransmissions: a fast retransmit after three
	// duplicate ACKs (frame 60), a follow-up hole fill (64) and a spurious
	// resend of data the receiver already had (87).
	assert.Equal(t, 3, flow.Retransmits)
	assert.Equal(t, 2, flow.FastRetransmits)
	assert.Zero(t, flow.TimeoutRetransmits)
	assert.Equal(t, 4, flow.DupAcks, "Wireshark counts four duplicate ACKs")
	assert.Equal(t, []string{titleFastRetransmit, titleRetransmissions}, packetLossTitles(res))
	assert.Equal(t, 80, res.Diagnosis.HealthScore, "two warnings")
	assert.Equal(t, "Fast Retransmit (isolated packet loss)", res.Diagnosis.PrimaryCause)
	assert.Equal(t, categoryRecommendations[titleFastRetransmit], res.Diagnosis.Recommendations)

	var rootCause bool
	for _, e := range res.Diagnosis.Timeline {
		rootCause = rootCause || e.EventType == eventRootCause
	}
	assert.True(t, rootCause, "timeline marks the root cause")

	// Healthy handshake and RTT: the diagnosis must not blame latency.
	assert.Less(t, flow.SetupTimeMs, 500.0)
	assert.Less(t, flow.AvgRTTMs, highRTTMs)
}

// Lab-5: a connection whose server takes ~108s to send its first data.
// Wireshark finds no retransmissions here; the capture contains TCP
// keep-alive probes, which must not be mistaken for retransmissions.
func TestPerformanceRealLab5SlowApplication(t *testing.T) {
	packets := readReal(t, "Lab-5-AnotherSlowApp.pcapng")
	res := Analyze(packets, "all")

	assert.Equal(t, 84, res.TotalPackets)
	require.Equal(t, 1, res.TotalFlows)
	flow := res.TopTalkers[0]
	assert.Equal(t, "10.0.0.1:80-192.168.1.1:61300", flow.ID)

	// Setup (SYN 0.000s -> ACK 0.104s) and TTFB (ACK -> first server data at 108.87s).
	assert.InDelta(t, 104, flow.SetupTimeMs, 5)
	assert.InDelta(t, 108768, flow.TTFBMs, 50)
	assert.Greater(t, flow.TTFBMs, slowTTFBMs)

	assert.Contains(t, issueTitles(res), "Slow Server Response")
	assert.Zero(t, flow.Retransmits, "keep-alive probes are not retransmissions")
	assert.NotContains(t, issueTitles(res), "TCP Retransmissions detected")
	// The capture ends with the server resetting the connection (frame 84),
	// 41s after the last data: an idle-timeout cleanup, reported as Info
	// so it cannot take over from the slow response.
	assert.Contains(t, issueTitles(res), titleIdle)
	assert.NotContains(t, issueTitles(res), titleAborted)
	assert.Equal(t, "Slow Server Response", res.Diagnosis.PrimaryCause)
	assert.Equal(t, 88, res.Diagnosis.HealthScore)

	var inTimeline, idleInTimeline bool
	for _, e := range res.Diagnosis.Timeline {
		inTimeline = inTimeline || (e.EventType == eventRootCause && strings.Contains(e.Description, "Slow Server Response"))
		idleInTimeline = idleInTimeline || (e.EventType == eventIssue && e.Severity == models.SeverityInfo && strings.Contains(e.Description, titleIdle))
	}
	assert.True(t, inTimeline, "slow response is the root-cause event in the timeline")
	assert.True(t, idleInTimeline, "the idle reset is an info note in the timeline")

	require.NotEmpty(t, res.SlowFlows)
	assert.Equal(t, flow.ID, res.SlowFlows[0].ID)
}

// ARP_Spoofing.pcap holds five ARP requests, each from a different sender
// IP and MAC, aimed at addresses in 192.168.7.0/24 from senders outside that
// subnet. No IP address is claimed by two MACs and the burst is far below
// the storm threshold, so the duplicate-IP and storm rules correctly stay
// quiet. This test pins that behavior and the ARP field extraction.
func TestCorrelateRealARPSpoofingCapture(t *testing.T) {
	packets := readReal(t, "ARP_Spoofing.pcap")
	require.Len(t, packets, 5)

	for _, p := range packets {
		assert.Equal(t, models.ProtocolARP, p.Protocol)
		assert.Equal(t, "request", p.ARPOperation)
		assert.NotEmpty(t, p.ARPSenderMAC)
	}
	assert.Equal(t, "192.169.223.59", packets[0].ARPSenderIP)
	assert.Equal(t, "00:01:01:02:df:3b", packets[0].ARPSenderMAC)
	assert.Equal(t, "192.168.7.111", packets[0].ARPTargetIP)

	assert.Empty(t, analyzeARP(packets))
	res := Analyze(packets, "all")
	assert.Equal(t, 100, res.Diagnosis.HealthScore)

	// The same traffic with one sender IP answering from a second MAC is the
	// duplicate-IP case, which must be Critical.
	spoofed := append([]models.PacketInfo(nil), packets...)
	dup := packets[0]
	dup.Timestamp = dup.Timestamp.Add(time.Millisecond)
	dup.ARPSenderMAC = "de:ad:be:ef:00:01"
	spoofed = append(spoofed, dup)
	issues := analyzeARP(spoofed)
	require.Len(t, issues, 1)
	assert.Equal(t, models.SeverityCritical, issues[0].Severity)
	assert.Equal(t, "Duplicate IP Address", issues[0].Title)
	assert.Contains(t, issues[0].Description, "192.169.223.59")
	assert.Equal(t, "Duplicate IP Address", Analyze(spoofed, "all").Diagnosis.PrimaryCause)
}

// DNS_Flood.pcap holds a single DNS query. It must parse as DNS and, being
// the last packet of the capture, must not be reported as a timeout.
func TestCorrelateRealDNSCapture(t *testing.T) {
	packets := readReal(t, "DNS_Flood.pcap")
	require.Len(t, packets, 1)

	p := packets[0]
	assert.Equal(t, "www.aha.com", p.DNSQueryName)
	assert.True(t, p.DNSIsQuery)
	assert.Equal(t, "A", p.DNSResponseType)
	assert.Equal(t, uint16(0xa9ca), p.DNSID)
	assert.Equal(t, "10.164.19.78", p.SrcIP)
	assert.Equal(t, uint16(53), p.DstPort)

	res := Analyze(packets, "dns")
	assert.Equal(t, 1, res.TotalPackets)
	assert.Empty(t, res.Issues)
	assert.Equal(t, 100, res.Diagnosis.HealthScore)
}

func packetLossTitles(res *models.AnalysisResult) []string {
	var out []string
	for _, is := range res.Issues {
		if is.Category == "PacketLoss" {
			out = append(out, is.Title)
		}
	}
	return out
}

// Lab-4: a lost SYN, a lost SYN-ACK and lost data, every one recovered only
// after a retransmission timeout. Wireshark flags six retransmissions.
func TestCorrelateRealLab4TimeoutRetransmits(t *testing.T) {
	res := Analyze(readReal(t, "Lab-4-NetworkCongestion.pcapng"), "all")
	require.Equal(t, 1, res.TotalFlows)
	flow := res.TopTalkers[0]
	assert.Equal(t, 6, flow.Retransmits)
	assert.Equal(t, 6, flow.TimeoutRetransmits)
	assert.Zero(t, flow.FastRetransmits)
	assert.Equal(t, 1, flow.DupAcks)
	assert.Equal(t, []string{titleTimeoutRetransmit}, packetLossTitles(res))
	assert.Equal(t, "Timeout Retransmit (severe congestion or blackhole)", res.Diagnosis.PrimaryCause)
	assert.Equal(t, categoryRecommendations[titleTimeoutRetransmit], res.Diagnosis.Recommendations)
	assert.Equal(t, 60, res.Diagnosis.HealthScore, "timeout error plus slow handshake and slow response")
}
