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

// tx builds a TCP packet of the 10.0.0.2:443 -> 10.0.0.1:5000 stream
// (fromServer) or the reverse. seq/ack are absolute.
func tx(ms int, fromServer bool, flags string, seq, ack uint32, payload int, win uint32) models.PacketInfo {
	p := models.PacketInfo{Timestamp: rstT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags,
		TCPSeq: seq, TCPAck: ack, PayloadSize: payload, Size: 60 + payload, TCPWindow: win}
	if fromServer {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 443, "10.0.0.1", 5000
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 5000, "10.0.0.2", 443
	}
	return p
}

func retransmitIssues(res *models.AnalysisResult) []models.Issue {
	var out []models.Issue
	for _, is := range res.Issues {
		if is.Category == "PacketLoss" {
			out = append(out, is)
		}
	}
	return out
}

func TestFastRetransmit(t *testing.T) { // Test A
	packets := []models.PacketInfo{
		tx(0, true, "PSH,ACK", 1000, 1, 100, 100),
		tx(1, false, "ACK", 1, 1100, 0, 5000), // ACK for the first segment
		tx(2, true, "PSH,ACK", 1100, 1, 100, 100),
		tx(3, true, "PSH,ACK", 1200, 1, 100, 100), // the segment at 1100 was lost
		tx(4, false, "ACK", 1, 1100, 0, 5000),     // dup ACK 1
		tx(5, true, "PSH,ACK", 1300, 1, 100, 100),
		tx(6, false, "ACK", 1, 1100, 0, 5000), // dup ACK 2
		tx(7, true, "PSH,ACK", 1400, 1, 100, 100),
		tx(8, false, "ACK", 1, 1100, 0, 5000),     // dup ACK 3
		tx(9, true, "PSH,ACK", 1100, 1, 100, 100), // retransmit
	}
	res := Analyze(packets, "all")
	flow := res.TopTalkers[0]
	assert.Equal(t, 3, flow.DupAcks)
	assert.Equal(t, 1, flow.Retransmits)
	assert.Equal(t, 1, flow.FastRetransmits)
	assert.Zero(t, flow.TimeoutRetransmits)

	got := retransmitIssues(res)
	require.Len(t, got, 1)
	assert.Equal(t, titleFastRetransmit, got[0].Title)
	assert.Equal(t, models.SeverityWarning, got[0].Severity)
	assert.Equal(t, rstT0.Add(9*time.Millisecond), got[0].Timestamp)
	assert.Contains(t, got[0].Description, "after 3 or more duplicate ACKs, first seq 1100")
	assert.Equal(t, "Fast Retransmit (isolated packet loss)", res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"Isolated packet loss detected. The sender recovered quickly via Fast Retransmit. Monitor for increasing frequency."},
		res.Diagnosis.Recommendations)
	assert.Equal(t, 90, res.Diagnosis.HealthScore)
}

func TestTimeoutRetransmit(t *testing.T) { // Test B
	packets := []models.PacketInfo{
		tx(0, true, "PSH,ACK", 1000, 1, 100, 100),
		tx(300, true, "PSH,ACK", 1000, 1, 100, 100), // same segment after 300ms of silence
	}
	res := Analyze(packets, "all")
	flow := res.TopTalkers[0]
	assert.Zero(t, flow.DupAcks)
	assert.Equal(t, 1, flow.TimeoutRetransmits)
	assert.Zero(t, flow.FastRetransmits)

	got := retransmitIssues(res)
	require.Len(t, got, 1)
	assert.Equal(t, titleTimeoutRetransmit, got[0].Title)
	assert.Equal(t, models.SeverityError, got[0].Severity)
	assert.Contains(t, got[0].Description, "went silent for over 200ms with no duplicate ACKs")
	assert.Equal(t, "Timeout Retransmit (severe congestion or blackhole)", res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"Severe congestion or blackhole detected. The sender waited for an RTO (Retransmission Timeout) before retrying. Investigate link quality or MTU issues."},
		res.Diagnosis.Recommendations)
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
}

func TestRetransmitClassification(t *testing.T) {
	data := func(ms int, seq uint32) models.PacketInfo { return tx(ms, true, "PSH,ACK", seq, 1, 100, 100) }
	ack := func(ms int, n uint32) models.PacketInfo { return tx(ms, false, "ACK", 1, n, 0, 5000) }

	tests := []struct {
		name    string
		packets []models.PacketInfo
		kinds   []string // kind of each retransmission, in order
		dupAcks int
	}{
		{"no retransmission", []models.PacketInfo{data(0, 1000), ack(1, 1100), data(2, 1100)}, nil, 0},
		{"exactly 200ms of silence is not an RTO", []models.PacketInfo{data(0, 1000), data(200, 1000)}, []string{"other"}, 0},
		{"just over 200ms is", []models.PacketInfo{data(0, 1000), data(201, 1000)}, []string{"timeout"}, 0},
		{"quick resend without evidence is unclassified", []models.PacketInfo{data(0, 1000), data(10, 1000)}, []string{"other"}, 0},
		{"two dup ACKs are not enough for fast retransmit", []models.PacketInfo{
			data(0, 1000), data(1, 1100), ack(2, 1100), ack(3, 1100), ack(4, 1100), data(5, 1100)}, []string{"other"}, 2},
		{"three dup ACKs make it fast, even after a pause", []models.PacketInfo{
			data(0, 1000), data(1, 1100), ack(2, 1100), ack(3, 1100), ack(4, 1100), ack(5, 1100), data(500, 1100)}, []string{"fast"}, 3},
		{"dup ACKs for a different byte do not count", []models.PacketInfo{
			data(0, 1000), data(1, 1100), data(2, 1200), ack(3, 1200), ack(4, 1200), ack(5, 1200), ack(6, 1200), data(7, 1100)}, []string{"other"}, 3},
		{"dup ACKs rule out the timeout reading", []models.PacketInfo{
			data(0, 1000), data(1, 1100), ack(2, 1100), ack(3, 1100), data(500, 1000)}, []string{"other"}, 1},
		{"an advancing ACK resets the dup count", []models.PacketInfo{
			data(0, 1000), data(1, 1100), ack(2, 1100), ack(3, 1100), ack(4, 1100), ack(5, 1200), ack(6, 1200), data(7, 1100)}, []string{"other"}, 3},
		{"later segments of a fast recovery inherit its kind", []models.PacketInfo{
			data(0, 1000), data(1, 1100), data(2, 1200), ack(3, 1000), ack(4, 1000), ack(5, 1000), ack(6, 1000), data(7, 1000), ack(8, 1100), data(9, 1100)},
			[]string{"fast", "fast"}, 3},
		{"a recovery stops inheriting after a second", []models.PacketInfo{
			data(0, 1000), data(1, 1100), ack(2, 1000), ack(3, 1000), ack(4, 1000), ack(5, 1000), data(6, 1000), data(1500, 1100)}, []string{"fast", "other"}, 3},
		{"data the receiver already acknowledged is spurious", []models.PacketInfo{
			data(0, 1000), ack(1, 1100), data(5, 1000)}, []string{"other"}, 0},
		{"keep-alive probe is not a retransmission", []models.PacketInfo{
			data(0, 1000), ack(1, 1100), tx(5000, false, "ACK", 0, 1100, 1, 5000)}, nil, 0},
		{"SYN resent after 1s is a timeout", []models.PacketInfo{
			tx(0, false, "SYN", 0, 0, 0, 65535), tx(1000, false, "SYN", 0, 0, 0, 65535)}, []string{"timeout"}, 0},
		{"window updates are not duplicate ACKs", []models.PacketInfo{
			data(0, 1000), ack(1, 1100), tx(2, false, "ACK", 1, 1100, 0, 9000), tx(3, false, "ACK", 1, 1100, 0, 9500), tx(4, false, "ACK", 1, 1100, 0, 9900)}, nil, 0},
		{"data segments carrying the same ACK are not duplicate ACKs", []models.PacketInfo{
			data(0, 1000), ack(1, 1100), tx(2, false, "PSH,ACK", 1, 1100, 10, 5000), tx(3, false, "PSH,ACK", 11, 1100, 10, 5000)}, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rd retransmitDetector
			var kinds []string
			dups := 0
			for _, p := range tt.packets {
				k, fwd := canonicalKey(p)
				r := rd.observe(instKey{k, 0}, fwd, p)
				if r.dupAck {
					dups++
				}
				if r.retrans {
					kinds = append(kinds, r.kind.String())
				}
			}
			assert.Equal(t, tt.kinds, kinds)
			assert.Equal(t, tt.dupAcks, dups)
		})
	}
}

// The receiver-side view of loss: the lost segment never appears, then shows
// up later as a hole fill (the Lab-3 and Lab-4 pattern).
func TestRetransmitHoleFill(t *testing.T) {
	data := func(ms int, seq uint32) models.PacketInfo { return tx(ms, true, "PSH,ACK", seq, 1, 100, 100) }
	ack := func(ms int, n uint32) models.PacketInfo { return tx(ms, false, "ACK", 1, n, 0, 5000) }
	run := func(packets []models.PacketInfo) (kinds []string) {
		var rd retransmitDetector
		for _, p := range packets {
			k, fwd := canonicalKey(p)
			if r := rd.observe(instKey{k, 0}, fwd, p); r.retrans {
				kinds = append(kinds, r.kind.String())
			}
		}
		return kinds
	}

	t.Run("segment the receiver asked for, after dup ACKs, is fast", func(t *testing.T) {
		// 1100 and 1200 were lost upstream of the capture point
		kinds := run([]models.PacketInfo{
			data(0, 1000), ack(1, 1100), data(2, 1300), ack(3, 1100), data(4, 1400), ack(5, 1100), data(6, 1500), ack(7, 1100),
			data(20, 1100), ack(21, 1200),
			data(30, 1200), // partial ACK, one dup ACK earlier: still part of the recovery
		})
		assert.Equal(t, []string{"fast"}, kinds[:1])
	})
	t.Run("a delayed original is reordering, not a retransmission", func(t *testing.T) {
		kinds := run([]models.PacketInfo{data(0, 1000), ack(1, 1100), data(2, 1200), data(3, 1100)})
		assert.Empty(t, kinds, "arrives within 3ms of the segment that jumped ahead")
	})
	t.Run("a late hole fill with no evidence is out-of-order", func(t *testing.T) {
		kinds := run([]models.PacketInfo{data(0, 1000), ack(1, 1100), data(2, 1200), data(50, 1100)})
		assert.Empty(t, kinds)
	})
	t.Run("a hole fill after silence is a timeout retransmit", func(t *testing.T) {
		kinds := run([]models.PacketInfo{data(0, 1000), ack(1, 1100), data(2, 1200), data(900, 1100)})
		assert.Equal(t, []string{"timeout"}, kinds)
	})
	t.Run("an RTO recovery resends the whole window back to back", func(t *testing.T) {
		kinds := run([]models.PacketInfo{
			data(0, 1000), ack(1, 1100), data(2, 1400), // 1100..1399 missing
			data(900, 1100), data(901, 1200), data(902, 1300),
		})
		assert.Equal(t, []string{"timeout", "timeout", "timeout"}, kinds)
	})
	t.Run("a bare ACK reveals data lost before the capture point", func(t *testing.T) {
		// the first thing seen is an ACK saying the sender is already at 1500
		kinds := run([]models.PacketInfo{
			ack(0, 1000), tx(1, true, "ACK", 1500, 1, 0, 100), data(900, 1000)})
		assert.Equal(t, []string{"timeout"}, kinds)
	})
}

func TestRetransmitFollowMarkerAndPortReuse(t *testing.T) {
	// the second connection reuses the first one's sequence numbers
	packets := []models.PacketInfo{
		tx(0, true, "PSH,ACK", 1000, 1, 100, 100), tx(1, true, "RST", 1100, 0, 0, 0),
		tx(5, false, "SYN", 7, 0, 0, 100), tx(6, true, "SYN,ACK", 55, 8, 0, 100), tx(7, false, "ACK", 8, 56, 0, 100),
		tx(8, true, "PSH,ACK", 1000, 8, 100, 100),
	}
	res := Analyze(packets, "all")
	assert.Empty(t, retransmitIssues(res), "reusing a sequence number on a new connection is not a retransmission")
}

// synTo builds a client SYN from 10.0.0.<src>:<port> to <dst>:443.
func synTo(ms int, src int, port uint16, dst string) models.PacketInfo {
	p := tcpEv(ms, port, true, "SYN", 0)
	p.SrcIP, p.DstIP = fmt.Sprintf("10.0.1.%d", src), dst
	return p
}

// tail is an unrelated packet that makes the capture run until ms.
func tail(ms int) models.PacketInfo {
	return models.PacketInfo{Timestamp: rstT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolUDP, SrcIP: "9.9.9.9", DstIP: "9.9.9.8", SrcPort: 1, DstPort: 2}
}

func synIssuesOf(res *models.AnalysisResult) (out []models.Issue) {
	for _, is := range res.Issues {
		switch is.Title {
		case titleUnansweredSYN, titleSYNFlood, titleSYNRetried:
			out = append(out, is)
		}
	}
	return out
}

func TestUnansweredSYN(t *testing.T) { // Test A
	res := Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0),
		tail(3000),
	}, "all")
	got := synIssuesOf(res)
	require.Len(t, got, 1)
	is := got[0]
	assert.Equal(t, titleUnansweredSYN, is.Title)
	assert.Equal(t, models.SeverityWarning, is.Severity)
	assert.Equal(t, "Connection", is.Category)
	assert.Equal(t, "10.0.0.2:443", is.Target)
	assert.Equal(t, 1, is.Count)
	assert.Equal(t, "10.0.0.1:5000-10.0.0.2:443", is.FlowID)
	assert.Equal(t, rstT0, is.Timestamp)
	assert.Contains(t, is.Description, "10.0.0.1:5000 sent a SYN to 10.0.0.2:443")
	assert.Contains(t, is.Description, "no SYN-ACK or RST")
	assert.Equal(t, titleUnansweredSYN, res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"Verify if a firewall is silently dropping packets, or if the server is down/unreachable."}, res.Diagnosis.Recommendations)
	assert.Equal(t, 90, res.Diagnosis.HealthScore)
}

func TestSYNFlood(t *testing.T) { // Test B
	var packets []models.PacketInfo
	for i := 0; i < 15; i++ {
		packets = append(packets, synTo(i*500, i, uint16(4000+i), "10.0.0.2"))
	}
	packets = append(packets, tail(20000))
	res := Analyze(packets, "all")

	got := synIssuesOf(res)
	require.Len(t, got, 1, "the flood replaces the plain warning")
	is := got[0]
	assert.Equal(t, titleSYNFlood, is.Title)
	assert.Equal(t, models.SeverityError, is.Severity)
	assert.Equal(t, "10.0.0.2:443", is.Target)
	assert.Equal(t, 15, is.Count)
	assert.Contains(t, is.Description, "15 connection attempts from 15 source(s) to 10.0.0.2:443")
	assert.Contains(t, is.Description, "15 of them within 10s")
	assert.Equal(t, titleSYNFlood, res.Diagnosis.PrimaryCause)
	assert.Contains(t, res.Diagnosis.Recommendations[0], "silently dropped")
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
}

func TestSYNFloodThresholdAndWindow(t *testing.T) {
	run := func(n, spacingMs int) []models.Issue {
		var packets []models.PacketInfo
		for i := 0; i < n; i++ {
			packets = append(packets, synTo(i*spacingMs, i, uint16(4000+i), "10.0.0.2"))
		}
		packets = append(packets, tail(n*spacingMs+5000))
		return synIssuesOf(Analyze(packets, "all"))
	}
	tests := []struct {
		name      string
		n, gap    int
		wantTitle string
	}{
		{"10 attempts is not more than 10", 10, 100, titleUnansweredSYN},
		{"11 attempts inside 10s", 11, 100, titleSYNFlood},
		{"11 attempts spread over 20s", 11, 2000, titleUnansweredSYN},
		{"11 attempts exactly 10s from first to last", 11, 1000, titleSYNFlood},
		{"11 attempts just over 10s from first to last", 11, 1001, titleUnansweredSYN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.n, tt.gap)
			require.Len(t, got, 1)
			assert.Equal(t, tt.wantTitle, got[0].Title)
			assert.Equal(t, tt.n, got[0].Count)
		})
	}
}

func TestSYNFloodIsPerDestinationAndRestIsFolded(t *testing.T) {
	var packets []models.PacketInfo
	for i := 0; i < 12; i++ { // flood against .2
		packets = append(packets, synTo(i*100, i, uint16(4000+i), "10.0.0.2"))
	}
	for i := 0; i < 4; i++ { // a sweep of single unanswered attempts elsewhere
		packets = append(packets, synTo(i*100, 50, uint16(6000+i), fmt.Sprintf("10.0.0.%d", 10+i)))
	}
	packets = append(packets, tail(5000))
	got := synIssuesOf(Analyze(packets, "all"))
	require.Len(t, got, 2)
	titles := []string{got[0].Title, got[1].Title}
	assert.ElementsMatch(t, []string{titleSYNFlood, titleUnansweredSYN}, titles)
	for _, is := range got {
		if is.Title == titleUnansweredSYN {
			assert.Equal(t, 4, is.Count)
			assert.Contains(t, is.Description, "4 connection attempts from 1 source(s) to 4 destination(s)")
			assert.Contains(t, is.Description, "most affected: 10.0.0.10:443 (1)")
		} else {
			assert.Equal(t, 12, is.Count)
		}
	}
}

func TestSYNHandshakeCases(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    []string
	}{
		{"answered by SYN-ACK", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(10, 5000, false, "SYN,ACK", 0), tcpEv(11, 5000, true, "ACK", 0), tail(5000)}, nil},
		{"refused is not unanswered", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "RST,ACK", 0), tail(5000)}, nil},
		{"any server reply counts as an answer", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(10, 5000, false, "ACK", 0), tail(5000)}, nil},
		{"capture ends right after the SYN", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tail(999)}, nil},
		{"capture ends one second after the SYN", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tail(1000)}, []string{titleUnansweredSYN}},
		{"a lone SYN with nothing else in the capture", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0)}, nil},
		{"SYN retried until the end, never answered", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1000, 5000, true, "SYN", 0), tcpEv(3000, 5000, true, "SYN", 0), tail(9000)}, []string{titleUnansweredSYN}},
		{"first SYN lost, retry answered", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1000, 5000, true, "SYN", 0), tcpEv(1030, 5000, false, "SYN,ACK", 0), tcpEv(1031, 5000, true, "ACK", 0)}, []string{titleSYNRetried}},
		{"a SYN after the SYN-ACK is not a retry", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(10, 5000, false, "SYN,ACK", 0), tcpEv(20, 5000, true, "SYN", 0), tail(5000)}, nil},
		{"client gives up with an RST after a second", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1500, 5000, true, "RST", 0)}, []string{titleUnansweredSYN}},
		{"midstream traffic has no SYN", []models.PacketInfo{
			tcpEv(0, 5000, true, "PSH,ACK", 10), tail(5000)}, nil},
		{"port reuse: refused then unanswered are separate attempts", []models.PacketInfo{
			tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "RST,ACK", 0), tcpEv(100, 5000, true, "SYN", 0), tail(5000)}, []string{titleUnansweredSYN}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, is := range synIssuesOf(Analyze(tt.packets, "all")) {
				got = append(got, is.Title)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSYNRetriedIsInfo(t *testing.T) {
	res := Analyze([]models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0), tcpEv(1000, 5000, true, "SYN", 0), tcpEv(1030, 5000, false, "SYN,ACK", 0), tcpEv(1031, 5000, true, "ACK", 0),
	}, "all")
	got := synIssuesOf(res)
	require.Len(t, got, 1)
	assert.Equal(t, models.SeverityInfo, got[0].Severity)
	assert.Contains(t, got[0].Description, "completed after 2 SYNs, with the SYN-ACK arriving 1.03s after the first one")
	assert.Equal(t, rstT0, got[0].Timestamp)

	// several: folded into one issue
	var packets []models.PacketInfo
	for i := 0; i < 3; i++ {
		port := uint16(5000 + i)
		packets = append(packets, tcpEv(0, port, true, "SYN", 0), tcpEv(1000, port, true, "SYN", 0), tcpEv(1020, port, false, "SYN,ACK", 0))
	}
	got = synIssuesOf(Analyze(packets, "all"))
	require.Len(t, got, 1)
	assert.Equal(t, 3, got[0].Count)
	assert.Contains(t, got[0].Description, "3 connections needed more than one SYN")
}

func TestSYNFloodSingleSYNCaptureIsQuiet(t *testing.T) {
	res := Analyze([]models.PacketInfo{tcpEv(0, 5000, true, "SYN", 0)}, "all")
	assert.Empty(t, res.Issues)
}

// SYN_Flood.pcap holds a single SYN: there is nothing to compare it with and
// no evidence about how the capture ended, so no handshake issue is raised.
func TestSYNFloodRealSingleSYNCapture(t *testing.T) {
	res := Analyze(readReal(t, "SYN_Flood.pcap"), "all")
	assert.Equal(t, 1, res.TotalPackets)
	assert.Empty(t, res.Issues)
	assert.Equal(t, 100, res.Diagnosis.HealthScore)
}
