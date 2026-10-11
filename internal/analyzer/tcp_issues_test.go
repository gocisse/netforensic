package analyzer

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

var rstT0 = time.Unix(1700000000, 0)

// tcpEv builds a TCP packet between client 10.0.0.1:<port> and server
// 10.0.0.2:443. Payload is a length only.
func tcpEv(ms int, port uint16, fromClient bool, flags string, payload int) models.PacketInfo {
	p := models.PacketInfo{Timestamp: rstT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags, PayloadSize: payload, Size: 60 + payload, TCPSeq: uint32(ms) + 1, TCPWindow: 65535}
	if fromClient {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", port, "10.0.0.2", 443
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 443, "10.0.0.1", port
	}
	return p
}

func resetIssues(res *models.AnalysisResult) (refused, aborted []models.Issue) {
	for _, is := range res.Issues {
		switch is.Title {
		case titleRefused:
			refused = append(refused, is)
		case titleAborted:
			aborted = append(aborted, is)
		}
	}
	return refused, aborted
}

func TestConnectionRefused(t *testing.T) { // Test A
	res := Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0),
		tcpEv(1, 5000, false, "RST,ACK", 0),
	}, "all")
	refused, aborted := resetIssues(res)
	require.Len(t, refused, 1)
	assert.Empty(t, aborted)
	is := refused[0]
	assert.Equal(t, models.SeverityWarning, is.Severity)
	assert.Equal(t, "Connection", is.Category)
	assert.Equal(t, "10.0.0.2:443", is.Target)
	assert.Equal(t, 1, is.Count)
	assert.Equal(t, "10.0.0.1:5000-10.0.0.2:443", is.FlowID)
	assert.Contains(t, is.Description, "10.0.0.2:443 answered the SYN from 10.0.0.1:5000 with an RST")
	assert.Equal(t, rstT0.Add(time.Millisecond), is.Timestamp, "anchored at the RST")
	assert.Equal(t, 90, res.Diagnosis.HealthScore)
	assert.Equal(t, titleRefused, res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"Verify if the service is running on the target port, or if a firewall is actively rejecting connections with an RST instead of dropping them."},
		res.Diagnosis.Recommendations)
}

func TestConnectionAbruptlyClosed(t *testing.T) { // Test B
	res := Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0),
		tcpEv(10, 5000, false, "SYN,ACK", 0),
		tcpEv(11, 5000, true, "ACK", 0),
		tcpEv(12, 5000, true, "PSH,ACK", 300),
		tcpEv(30, 5000, false, "ACK", 1000),
		tcpEv(500, 5000, false, "RST,ACK", 0),
	}, "all")
	refused, aborted := resetIssues(res)
	assert.Empty(t, refused)
	require.Len(t, aborted, 1)
	is := aborted[0]
	assert.Equal(t, models.SeverityError, is.Severity)
	assert.Equal(t, "10.0.0.1:5000-10.0.0.2:443", is.FlowID)
	assert.Equal(t, rstT0.Add(500*time.Millisecond), is.Timestamp)
	assert.Contains(t, is.Description, "reset by the server (10.0.0.2)")
	assert.Contains(t, is.Description, "1300 payload bytes")
	assert.Contains(t, is.Description, "the last data was 470ms earlier")
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, titleAborted, res.Diagnosis.PrimaryCause)
	assert.Contains(t, res.Diagnosis.Recommendations[0], "firewall state-table evictions")
	assert.Equal(t, "root_cause", res.Diagnosis.Timeline[1].EventType)
}

func TestResetClassification(t *testing.T) {
	tests := []struct {
		name        string
		packets     []models.PacketInfo
		wantRefused int
		wantAborted int
		wantFrom    string // who sent the first RST, for aborted
	}{
		{"client abort after data", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "ACK", 0),
			tcpEv(3, 5000, false, "PSH,ACK", 50), tcpEv(4, 5000, true, "RST,ACK", 0)}, 0, 1, "client (10.0.0.1)"},
		{"reset right after the handshake, no data", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "ACK", 0),
			tcpEv(3, 5000, false, "RST", 0)}, 0, 1, "server (10.0.0.2)"},
		{"capture starts mid-connection, data then RST", []models.PacketInfo{
			tcpEv(0, 5000, true, "PSH,ACK", 10), tcpEv(1, 5000, false, "RST", 0)}, 0, 1, "server (10.0.0.2)"},
		{"normal close followed by a stray RST", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "ACK", 0),
			tcpEv(3, 5000, true, "PSH,ACK", 10), tcpEv(4, 5000, true, "FIN,ACK", 0), tcpEv(5, 5000, false, "FIN,ACK", 0),
			tcpEv(6, 5000, true, "RST", 0)}, 0, 0, ""},
		{"reset after only one FIN is still abrupt", []models.PacketInfo{
			tcpEv(0, 5000, true, "PSH,ACK", 10), tcpEv(1, 5000, true, "FIN,ACK", 0), tcpEv(2, 5000, false, "RST", 0)}, 0, 1, "server (10.0.0.2)"},
		{"SYN, SYN-ACK, then client RST: not refused, not established", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "RST", 0)}, 0, 0, ""},
		{"RST without a SYN and without data", []models.PacketInfo{
			tcpEv(0, 5000, true, "RST,ACK", 0)}, 0, 0, ""},
		{"SYN with no reply is not a refusal", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0)}, 0, 0, ""},
		{"client gives up (RST) with no server reply", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1000, 5000, true, "RST", 0)}, 0, 0, ""},
		{"retried SYNs before the RST: still one refusal", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1000, 5000, true, "SYN", 0), tcpEv(1001, 5000, false, "RST,ACK", 0)}, 1, 0, ""},
		{"no TCP at all", []models.PacketInfo{{Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2"}}, 0, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refused, aborted := resetIssues(Analyze(tt.packets, "all"))
			assert.Len(t, refused, tt.wantRefused)
			require.Len(t, aborted, tt.wantAborted)
			if tt.wantAborted > 0 {
				assert.Contains(t, aborted[0].Description, tt.wantFrom)
			}
		})
	}
}

func TestMultipleResetsInOneFlowAreOneIssue(t *testing.T) { // Lab-7 pattern
	res := Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "PSH,ACK", 100),
		tcpEv(0, 5000, true, "RST,ACK", 0),
		tcpEv(0, 5000, true, "RST", 0),
		tcpEv(0, 5000, false, "RST,ACK", 0),
	}, "all")
	_, aborted := resetIssues(res)
	require.Len(t, aborted, 1)
	assert.Contains(t, aborted[0].Description, "reset by the client")
	assert.Contains(t, aborted[0].Description, "3 RST packets in total")
	assert.Contains(t, aborted[0].Description, "immediately after the last data")
}

func TestRefusalsAreGroupedPerServerEndpointAndSurvivePortReuse(t *testing.T) {
	var packets []models.PacketInfo
	// the same source port retried four times (new connection each time), then another client
	for i := 0; i < 4; i++ {
		packets = append(packets, tcpEv(i*100, 5000, true, "SYN", 0), tcpEv(i*100+1, 5000, false, "RST,ACK", 0))
	}
	other := tcpEv(900, 6000, true, "SYN", 0)
	other.SrcIP = "10.0.0.9"
	reply := tcpEv(901, 6000, false, "RST,ACK", 0)
	reply.DstIP = "10.0.0.9"
	packets = append(packets, other, reply)

	refused, _ := resetIssues(Analyze(packets, "all"))
	require.Len(t, refused, 1, "one issue for the endpoint, not one per attempt")
	assert.Equal(t, 5, refused[0].Count)
	assert.Contains(t, refused[0].Description, "5 connection attempts from 2 client(s) to 10.0.0.2:443")
	assert.Empty(t, refused[0].FlowID)
}

func TestRefusedSpikeBecomesPrimaryCause(t *testing.T) {
	refusals := func(n int, server string) []models.PacketInfo {
		var out []models.PacketInfo
		for i := 0; i < n; i++ {
			syn := tcpEv(i*10, uint16(5000+i), true, "SYN", 0)
			syn.DstIP = server
			rst := tcpEv(i*10+1, uint16(5000+i), false, "RST,ACK", 0)
			rst.SrcIP = server
			out = append(out, syn, rst)
		}
		return out
	}
	servfail := models.PacketInfo{Timestamp: rstT0, Protocol: models.ProtocolUDP, SrcIP: "10.0.0.53", SrcPort: 53, DstIP: "10.0.0.1", DstPort: 4444,
		DNSQueryName: "x.example", DNSResponseCode: "SERVFAIL"}

	t.Run("spike beats an unrelated DNS error", func(t *testing.T) {
		packets := append(refusals(5, "10.0.0.2"), servfail)
		res := Analyze(packets, "all")
		assert.Equal(t, "Service Unavailable / Port Closed on 10.0.0.2:443", res.Diagnosis.PrimaryCause)
		assert.Equal(t, "high", res.Diagnosis.Confidence)
		assert.Contains(t, res.Diagnosis.Summary, "10.0.0.2:443 refused 5 connection attempt(s)")
		assert.Equal(t, titleRefused, res.Issues[len(res.Issues)-1].Title)
	})
	t.Run("the busiest endpoint is named, others are counted", func(t *testing.T) {
		packets := append(refusals(6, "10.0.0.2"), refusals(5, "10.0.0.3")...)
		res := Analyze(packets, "all")
		assert.Equal(t, "Service Unavailable / Port Closed on 10.0.0.2:443", res.Diagnosis.PrimaryCause)
		assert.Contains(t, res.Diagnosis.Summary, "11 attempts were refused in total across 2 server endpoints")
		for _, ev := range res.Diagnosis.Timeline {
			if ev.EventType != "capture_start" && ev.EventType != "capture_end" {
				assert.Equal(t, "root_cause", ev.EventType)
			}
		}
	})
	t.Run("below the threshold the DNS error stays primary", func(t *testing.T) {
		packets := append(refusals(refusedSpike-1, "10.0.0.2"), servfail)
		res := Analyze(packets, "all")
		assert.Equal(t, "DNS SERVFAIL", res.Diagnosis.PrimaryCause)
	})
	t.Run("a DNS-caused HTTP failure still wins", func(t *testing.T) {
		d := &diagnosis{roles: map[string]string{}}
		assert.False(t, d.refusedSpike(nil))
	})
	t.Run("health score keeps falling per endpoint", func(t *testing.T) {
		packets := append(refusals(5, "10.0.0.2"), refusals(5, "10.0.0.3")...)
		assert.Equal(t, 80, Analyze(packets, "all").Diagnosis.HealthScore)
	})
}

func TestResetIssueFallbackRecommendations(t *testing.T) {
	// a lone abrupt close goes through the generic fallback but must get its own advice
	res := Analyze([]models.PacketInfo{tcpEv(0, 5000, true, "PSH,ACK", 5), tcpEv(1, 5000, false, "RST", 0)}, "all")
	assert.Equal(t, categoryRecommendations[titleAborted], res.Diagnosis.Recommendations)
	assert.NotEqual(t, categoryRecommendations[titleRefused], res.Diagnosis.Recommendations)

	// the ID is stable and unique per connection
	res = Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "PSH,ACK", 5), tcpEv(1, 5000, false, "RST", 0),
		tcpEv(2, 5000, true, "SYN", 0), tcpEv(3, 5000, false, "SYN,ACK", 0), tcpEv(4, 5000, true, "PSH,ACK", 5), tcpEv(5, 5000, false, "RST", 0),
	}, "all")
	_, aborted := resetIssues(res)
	require.Len(t, aborted, 2)
	assert.NotEqual(t, aborted[0].ID, aborted[1].ID)
	assert.Equal(t, fmt.Sprintf("reset-%s", aborted[1].FlowID), aborted[1].ID)
	assert.Contains(t, aborted[1].FlowID, "#2")
}

func TestResetAfterIdleIsInfoNotFailure(t *testing.T) {
	flow := func(gapMs int) []models.PacketInfo {
		return []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "ACK", 0),
			tcpEv(3, 5000, true, "PSH,ACK", 100), tcpEv(4, 5000, false, "PSH,ACK", 200),
			tcpEv(4+gapMs, 5000, false, "RST,ACK", 0),
		}
	}
	tests := []struct {
		name      string
		gapMs     int
		wantTitle string
		wantSev   models.Severity
	}{
		{"immediately after data", 1, titleAborted, models.SeverityError},
		{"9.9s of silence", 9900, titleAborted, models.SeverityError},
		{"exactly 10s is not yet idle", 10000, titleAborted, models.SeverityError},
		{"10.001s of silence", 10001, titleIdle, models.SeverityInfo},
		{"41s of silence", 41000, titleIdle, models.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(flow(tt.gapMs), "all")
			var got []models.Issue
			for _, is := range res.Issues {
				if is.Category == "Connection" {
					got = append(got, is)
				}
			}
			require.Len(t, got, 1)
			assert.Equal(t, tt.wantTitle, got[0].Title)
			assert.Equal(t, tt.wantSev, got[0].Severity)
		})
	}

	res := Analyze(flow(41000), "all")
	assert.Contains(t, res.Issues[len(res.Issues)-1].Description, "idle timeout")
	assert.Equal(t, 98, res.Diagnosis.HealthScore)
	assert.Contains(t, res.Diagnosis.Recommendations[0], "idle-timeout settings of firewalls")

	t.Run("an idle reset does not hijack a real failure", func(t *testing.T) {
		packets := append(flow(41000), models.PacketInfo{Timestamp: rstT0, Protocol: models.ProtocolUDP, SrcIP: "10.0.0.53", SrcPort: 53, DstIP: "10.0.0.1", DstPort: 4444,
			DNSQueryName: "x.example", DNSResponseCode: "SERVFAIL"})
		assert.Equal(t, "DNS SERVFAIL", Analyze(packets, "all").Diagnosis.PrimaryCause)
	})
}

// zw returns a copy of p advertising window w.
func zw(p models.PacketInfo, w uint32) models.PacketInfo {
	p.TCPWindow = w
	return p
}

func connectionIssues(res *models.AnalysisResult) []models.Issue {
	var out []models.Issue
	for _, is := range res.Issues {
		if is.Category == "Connection" {
			out = append(out, is)
		}
	}
	return out
}

func established() []models.PacketInfo {
	return []models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "SYN,ACK", 0), tcpEv(2, 5000, true, "ACK", 0),
		tcpEv(3, 5000, false, "PSH,ACK", 1000),
	}
}

func TestZeroWindowWarning(t *testing.T) {
	packets := append(established(),
		zw(tcpEv(10, 5000, true, "ACK", 0), 0),
		zw(tcpEv(20, 5000, true, "ACK", 0), 0), // zero-window probe answer
		tcpEv(30, 5000, false, "PSH,ACK", 500),
	)
	res := Analyze(packets, "all")
	got := connectionIssues(res)
	require.Len(t, got, 1)
	is := got[0]
	assert.Equal(t, titleZeroWindow, is.Title)
	assert.Equal(t, models.SeverityWarning, is.Severity)
	assert.Equal(t, 2, is.Count)
	assert.Equal(t, rstT0.Add(10*time.Millisecond), is.Timestamp)
	assert.Contains(t, is.Description, "Receiver buffer full, sender stalled")
	assert.Contains(t, is.Description, "the client (10.0.0.1) advertised a zero window 2 time(s)")
	assert.Contains(t, is.Description, "it never reopened in the capture")
	assert.Equal(t, 90, res.Diagnosis.HealthScore)
	assert.Equal(t, categoryRecommendations[titleZeroWindow], res.Diagnosis.Recommendations)
}

func TestZeroWindowReopens(t *testing.T) {
	packets := append(established(),
		zw(tcpEv(10, 5000, false, "ACK", 0), 0), // the server's buffer fills
		tcpEv(25, 5000, true, "PSH,ACK", 10),    // the client's window is irrelevant
		zw(tcpEv(40, 5000, false, "ACK", 0), 8192),
	)
	got := connectionIssues(Analyze(packets, "all"))
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Description, "the server (10.0.0.2) advertised a zero window 1 time(s)")
	assert.Contains(t, got[0].Description, "the window reopened 30ms later")
}

func TestZeroWindowThenResetIsOneError(t *testing.T) { // Lab-7 pattern
	packets := append(established(),
		zw(tcpEv(10, 5000, true, "ACK", 0), 0),
		zw(tcpEv(900, 5000, true, "RST,ACK", 0), 0),
		zw(tcpEv(901, 5000, false, "RST,ACK", 0), 0),
	)
	res := Analyze(packets, "all")
	got := connectionIssues(res)
	require.Len(t, got, 1, "the zero window and the RST merge into one issue")
	is := got[0]
	assert.Equal(t, titleZeroWindowReset, is.Title)
	assert.Equal(t, models.SeverityError, is.Severity)
	assert.Equal(t, rstT0.Add(10*time.Millisecond), is.Timestamp, "anchored at the stall")
	assert.Contains(t, is.Description, "the client (10.0.0.1) advertised a zero window 1 time(s)")
	assert.Contains(t, is.Description, "the client (10.0.0.1) reset the connection 890ms later")
	assert.Contains(t, is.Description, "2 RST packets in total")
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, titleZeroWindowReset, res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"The receiver's buffer filled up, causing the sender to stall, and the connection was eventually reset. Investigate receiver application processing speed or buffer sizing."},
		res.Diagnosis.Recommendations)
}

func TestZeroWindowDetectionIgnoresNonStalls(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
	}{
		{"RST segments always carry window 0", append(established(), zw(tcpEv(10, 5000, false, "RST,ACK", 0), 0))},
		{"SYN window is not a stall", []models.PacketInfo{zw(tcpEv(0, 5000, true, "SYN", 0), 0)}},
		{"FIN segment", append(established(), zw(tcpEv(10, 5000, true, "FIN,ACK", 0), 0))},
		{"healthy windows", append(established(), zw(tcpEv(10, 5000, true, "ACK", 0), 512))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, is := range Analyze(tt.packets, "all").Issues {
				assert.NotContains(t, is.Title, "Zero", is.Description)
				assert.NotEqual(t, titleZeroWindow, is.Title)
			}
		})
	}
}

func TestZeroWindowAfterResetIsNotCorrelated(t *testing.T) {
	// the reset belongs to the first connection; the zero window to the next one
	packets := append(established(), tcpEv(10, 5000, false, "RST", 0))
	packets = append(packets,
		tcpEv(20, 5000, true, "SYN", 0), tcpEv(21, 5000, false, "SYN,ACK", 0), tcpEv(22, 5000, true, "ACK", 0),
		zw(tcpEv(23, 5000, true, "ACK", 0), 0))
	var titles []string
	for _, is := range connectionIssues(Analyze(packets, "all")) {
		titles = append(titles, is.Title)
	}
	assert.ElementsMatch(t, []string{titleAborted, titleZeroWindow}, titles)
}

func TestZeroWindowRealLab7(t *testing.T) {
	res := Analyze(readReal(t, "Lab-7-TCPIssues.pcapng"), "all")
	got := connectionIssues(res)
	require.Len(t, got, 1)
	assert.Equal(t, titleZeroWindowReset, got[0].Title)
	assert.Contains(t, got[0].Description, "the client (10.0.2.15) advertised a zero window 1 time(s)")
	assert.Contains(t, got[0].Description, "3 RST packets in total")
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, titleZeroWindowReset, res.Diagnosis.PrimaryCause)
}
