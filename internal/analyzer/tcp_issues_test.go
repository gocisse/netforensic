package analyzer

import (
	"encoding/json"
	"fmt"
	"strings"
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
	assert.Contains(t, is.Description, "the window had not reopened when the client (10.0.0.1) reset the connection at 22:13:20.900, 890ms later")
	assert.Contains(t, is.Description, "2 RST packets in total")
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, titleZeroWindowReset, res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"The receiver's buffer filled up, causing the sender to stall, and the connection was eventually reset. Investigate receiver application processing speed or buffer sizing."},
		res.Diagnosis.Recommendations)
}

func TestZeroWindowReopenedBeforeResetIsSaid(t *testing.T) {
	packets := append(established(),
		zw(tcpEv(10, 5000, true, "ACK", 0), 0),
		zw(tcpEv(800, 5000, true, "ACK", 0), 62780), // window update from the same side
		zw(tcpEv(808, 5000, true, "RST,ACK", 0), 0),
	)
	got := connectionIssues(Analyze(packets, "all"))
	require.Len(t, got, 1)
	assert.Equal(t, titleZeroWindowReset, got[0].Title)
	assert.Contains(t, got[0].Description, "advertised a zero window 1 time(s), first at 22:13:20.010")
	assert.Contains(t, got[0].Description, "the window reopened at 22:13:20.800 (790ms later), but the client (10.0.0.1) reset the connection at 22:13:20.808, 8ms after it reopened")
	assert.NotContains(t, got[0].Description, "had not reopened")
}

func TestZeroWindowReopenedByTheOtherSideDoesNotCount(t *testing.T) {
	packets := append(established(),
		zw(tcpEv(10, 5000, true, "ACK", 0), 0), // the client's window closes
		tcpEv(20, 5000, false, "ACK", 0),       // the server has plenty of window: irrelevant
		zw(tcpEv(30, 5000, true, "RST", 0), 0),
	)
	got := connectionIssues(Analyze(packets, "all"))
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Description, "the window had not reopened when the client (10.0.0.1) reset the connection")
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
	assert.Contains(t, got[0].Description, "the window reopened at 23:50:29.649 (808ms later), but the client (10.0.2.15) reset the connection at 23:50:29.657, 9ms after it reopened",
		"Wireshark: zero window at frame 50, window update at frame 51 (+1.33344s), RST at frame 61 (+1.34206s)")
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
	assert.Equal(t, "TCP retransmission timeout observed", res.Diagnosis.PrimaryCause)
	assert.Equal(t, []string{"TCP data was retransmitted after a period without sufficient acknowledgment progress. This capture alone cannot determine whether the cause was packet loss, congestion, an endpoint problem, or a capture limitation. Compare captures at both ends and inspect network interface, queue, and endpoint behavior."},
		res.Diagnosis.Recommendations)
	assert.Equal(t, "A TCP segment was retransmitted after a period without sufficient acknowledgment progress. This does not by itself prove packet loss or a path-wide stall. Compare captures at both ends to identify where the delay or missing acknowledgment occurs.", got[0].Recommendation)
	for _, s := range append([]string{res.Diagnosis.PrimaryCause, got[0].Recommendation}, res.Diagnosis.Recommendations...) {
		assert.NotContains(t, strings.ToLower(s), "blackhole")
		assert.NotContains(t, strings.ToLower(s), "severe congestion")
		assert.NotContains(t, strings.ToLower(s), "stalled completely")
	}
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
		{"later segments of a fast recovery are counted as recovery, not as fast", []models.PacketInfo{
			data(0, 1000), data(1, 1100), data(2, 1200), ack(3, 1000), ack(4, 1000), ack(5, 1000), ack(6, 1000), data(7, 1000), ack(8, 1100), data(9, 1100)},
			[]string{"fast", "fast-recovery"}, 3},
		{"recovery segments keep the episode alive", []models.PacketInfo{
			data(0, 1000), data(1, 1100), data(2, 1200), data(3, 1300), ack(4, 1000), ack(5, 1000), ack(6, 1000), ack(7, 1000),
			data(8, 1000), data(600, 1100), data(1100, 1200)},
			[]string{"fast", "fast-recovery", "fast-recovery"}, 3},
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
		assert.Equal(t, []string{"timeout", "timeout-recovery", "timeout-recovery"}, kinds)
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
	assert.Equal(t, []string{"Verify if a firewall is silently dropping packets, or if the server is down/unreachable. Also check that the capture point sees traffic in both directions: a one-sided capture looks the same."}, res.Diagnosis.Recommendations)
	assert.Contains(t, is.Title, "may be firewall drop, server unreachable, or asymmetric capture")
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

// synEv is a client SYN from tcpEv's connection that keeps one initial
// sequence number: a retried SYN repeats it, whereas tcpEv numbers every packet
// by its time, which would make each retry a new connection attempt.
func synEv(ms int, port uint16) models.PacketInfo {
	p := tcpEv(ms, port, true, "SYN", 0)
	p.TCPSeq = 1
	return p
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
			synEv(0, 5000), synEv(1000, 5000), synEv(3000, 5000), tail(9000)}, []string{titleUnansweredSYN}},
		{"first SYN lost, retry answered", []models.PacketInfo{
			synEv(0, 5000), synEv(1000, 5000), tcpEv(1030, 5000, false, "SYN,ACK", 0), tcpEv(1031, 5000, true, "ACK", 0)}, []string{titleSYNRetried}},
		{"a SYN after the SYN-ACK is not a retry", []models.PacketInfo{
			synEv(0, 5000), tcpEv(10, 5000, false, "SYN,ACK", 0), synEv(20, 5000), tail(5000)}, nil},
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
		synEv(0, 5000), synEv(1000, 5000), tcpEv(1030, 5000, false, "SYN,ACK", 0), tcpEv(1031, 5000, true, "ACK", 0),
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
		packets = append(packets, synEv(0, port), synEv(1000, port), tcpEv(1020, port, false, "SYN,ACK", 0))
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

func strayIssues(res *models.AnalysisResult) (out []models.Issue) {
	for _, is := range res.Issues {
		if is.Title == titleStray {
			out = append(out, is)
		}
	}
	return out
}

func TestStrayRST(t *testing.T) {
	// lone RSTs: three sent to 10.0.1.1 (by two servers) and one to 10.0.1.2
	rst := func(ms int, port uint16, fromServer bool, dst string) models.PacketInfo {
		p := tcpEv(ms, port, !fromServer, "RST,ACK", 0)
		if dst != "" {
			p.DstIP = dst
		}
		return p
	}
	a := rst(0, 5000, true, "10.0.1.1")
	b := rst(10, 5001, true, "10.0.1.1")
	c := rst(20, 5002, true, "10.0.1.1")
	c.SrcIP = "10.0.0.9"
	d := rst(30, 5003, true, "10.0.1.2")
	res := Analyze([]models.PacketInfo{a, b, c, d}, "all")

	got := strayIssues(res)
	require.Len(t, got, 1, "all stray RSTs are folded into one issue")
	is := got[0]
	assert.Equal(t, models.SeverityInfo, is.Severity)
	assert.Equal(t, "Connection", is.Category)
	assert.Equal(t, 4, is.Count)
	assert.Equal(t, "10.0.1.1", is.Target, "the destination hit most often")
	assert.Equal(t, rstT0, is.Timestamp)
	assert.Equal(t, "4 RSTs with no handshake or data captured, sent by 2 hosts to 2 destinations. Destinations: 10.0.1.1 (3), 10.0.1.2 (1). "+
		"These are usually replies to port probes or to packets of connections the sender no longer knows.", is.Description)
	require.Len(t, is.Occurrences, 4)
	assert.Equal(t, "10.0.0.2:443-10.0.1.1:5000", is.Occurrences[0].Subject)
	assert.Equal(t, 98, res.Diagnosis.HealthScore, "an info costs 2")
	assert.Equal(t, titleStray, res.Diagnosis.PrimaryCause)
	assert.Contains(t, res.Diagnosis.Recommendations[0], "scanned")
}

func TestStrayRSTTopDestinations(t *testing.T) {
	var packets []models.PacketInfo
	for i, dst := range []string{"10.0.1.1", "10.0.1.1", "10.0.1.1", "10.0.1.2", "10.0.1.2", "10.0.1.3", "10.0.1.4"} {
		p := tcpEv(i*10, uint16(5000+i), false, "RST", 0)
		p.DstIP = dst
		packets = append(packets, p)
	}
	got := strayIssues(Analyze(packets, "all"))
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Description, "7 RSTs")
	assert.Contains(t, got[0].Description, "Top 3 destinations: 10.0.1.1 (3), 10.0.1.2 (2), 10.0.1.3 (1).")
	assert.NotContains(t, got[0].Description, "10.0.1.4")
}

func TestStrayRSTNeedsAnEmptyConnection(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		stray   bool
	}{
		{"lone RST", []models.PacketInfo{tcpEv(0, 5000, false, "RST", 0)}, true},
		{"lone RST,ACK from the client", []models.PacketInfo{tcpEv(0, 5000, true, "RST,ACK", 0)}, true},
		{"a few ACKs, then RST: still nothing but control packets", []models.PacketInfo{tcpEv(0, 5000, true, "ACK", 0), tcpEv(1, 5000, false, "RST", 0)}, true},
		{"after a SYN it is a refusal, not a stray", []models.PacketInfo{tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "RST,ACK", 0)}, false},
		{"after data it is an abrupt close", []models.PacketInfo{tcpEv(0, 5000, true, "PSH,ACK", 10), tcpEv(1, 5000, false, "RST", 0)}, false},
		{"after a SYN-ACK", []models.PacketInfo{tcpEv(0, 5000, false, "SYN,ACK", 0), tcpEv(1, 5000, true, "RST", 0)}, false},
		{"no RST at all", []models.PacketInfo{tcpEv(0, 5000, true, "ACK", 0)}, false},
		{"udp is not tcp", []models.PacketInfo{{Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", TCPFlags: "RST"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.stray, len(strayIssues(Analyze(tt.packets, "all"))) == 1)
		})
	}
}

func TestAggregatedIssuesSerializeTheirOccurrences(t *testing.T) {
	// every aggregated issue must carry its events into the JSON
	var packets []models.PacketInfo
	for i := 0; i < 6; i++ { // refused
		port := uint16(5000 + i)
		packets = append(packets, tcpEv(i*10, port, true, "SYN", 0), tcpEv(i*10+1, port, false, "RST,ACK", 0))
	}
	for i := 0; i < 3; i++ { // unanswered
		packets = append(packets, synTo(i*10, 40+i, uint16(6000+i), "10.0.9.9"))
	}
	packets = append(packets, tcpEv(500, 7000, false, "RST", 0), tail(9000)) // stray
	res := Analyze(packets, "all")

	raw, err := json.Marshal(res)
	require.NoError(t, err)
	var decoded struct {
		Issues []struct {
			Title       string `json:"title"`
			Count       int    `json:"count"`
			Occurrences []struct {
				Time    string  `json:"time"`
				Subject string  `json:"subject"`
				Value   float64 `json:"value"`
			} `json:"occurrences"`
		} `json:"issues"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	seen := map[string]int{}
	for _, is := range decoded.Issues {
		seen[is.Title] = len(is.Occurrences)
		assert.Equal(t, is.Count, len(is.Occurrences), is.Title+": one occurrence per counted event")
		for _, o := range is.Occurrences {
			assert.NotEmpty(t, o.Subject, is.Title)
			assert.NotEmpty(t, o.Time, is.Title)
		}
	}
	assert.Equal(t, 6, seen[titleRefused])
	assert.Equal(t, 3, seen[titleUnansweredSYN])
	assert.Equal(t, 1, seen[titleStray])
}

// onPort moves a tx() packet to another client port.
func onPort(p models.PacketInfo, port uint16) models.PacketInfo {
	if p.SrcPort == 5000 {
		p.SrcPort = port
	}
	if p.DstPort == 5000 {
		p.DstPort = port
	}
	return p
}

func titlesOf(res *models.AnalysisResult, prefix string) (out []models.Issue) {
	for _, is := range res.Issues {
		if strings.HasPrefix(is.Title, prefix) {
			out = append(out, is)
		}
	}
	return out
}

// Client SYN retries that get no reply are reported by Unanswered SYN, not as
// a Timeout Retransmit error.
func TestUnansweredSYNRetriesAreNotATimeoutRetransmitError(t *testing.T) {
	syn := func(ms int) models.PacketInfo { return tx(ms, false, "SYN", 7000, 0, 0, 65535) }
	tests := []struct {
		name          string
		packets       []models.PacketInfo
		wantUnanswer  int
		wantRetransIs []string // titles of the retransmission issues
		wantRetrans   int      // the flow's Retransmits counter, which never changes
	}{
		{"retries spanning 3s, capture ends 200ms after the last: unanswered by the retry span",
			[]models.PacketInfo{syn(0), syn(1000), syn(3000), tail(3200)}, 1, nil, 2},
		{"retries spanning 3s, the capture ends with the last SYN",
			[]models.PacketInfo{syn(0), syn(1000), syn(3000)}, 1, nil, 2},
		{"retries spanning exactly 1s",
			[]models.PacketInfo{syn(0), syn(1000), tail(1100)}, 1, nil, 1},
		{"retries spanning under 1s, capture ends under 1s later: nothing is unanswered yet, as before",
			[]models.PacketInfo{syn(0), syn(500), tail(700)}, 0, []string{titleTimeoutRetransmit}, 1},
		{"retries spanning under 1s but the capture runs 1s past the last SYN: unanswered by the existing rule",
			[]models.PacketInfo{syn(0), syn(300), tail(1300)}, 1, nil, 1},
		{"a single SYN is not unanswered by the retry-span rule",
			[]models.PacketInfo{syn(0), tail(500)}, 0, nil, 0},
		{"a single SYN with a second of capture left is still unanswered (existing rule)",
			[]models.PacketInfo{syn(0), tail(1000)}, 1, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(tt.packets, "all")
			un := titlesOf(res, "Unanswered SYN")
			require.Len(t, un, tt.wantUnanswer)
			if len(un) == 1 {
				assert.Equal(t, models.SeverityWarning, un[0].Severity)
			}
			var titles []string
			for _, is := range retransmitIssues(res) {
				titles = append(titles, is.Title)
			}
			assert.Equal(t, tt.wantRetransIs, titles)
			var flowRetrans int
			for _, f := range res.Flows {
				flowRetrans += f.Retransmits
			}
			assert.Equal(t, tt.wantRetrans, flowRetrans, "the counters keep counting the SYN retries")
		})
	}
}

func TestSYNRetriesThatGetAnAnswerKeepTheirRetransmissionIssue(t *testing.T) {
	t.Run("SYN-ACK after the retry", func(t *testing.T) {
		res := Analyze([]models.PacketInfo{
			tx(0, false, "SYN", 7000, 0, 0, 65535), tx(1000, false, "SYN", 7000, 0, 0, 65535),
			tx(1030, true, "SYN,ACK", 9000, 7001, 0, 65535), tx(1031, false, "ACK", 7001, 9001, 0, 65535)}, "all")
		got := retransmitIssues(res)
		require.Len(t, got, 1)
		assert.Equal(t, titleTimeoutRetransmit, got[0].Title)
		assert.Equal(t, models.SeverityError, got[0].Severity)
		assert.Contains(t, got[0].Description, "1 segment(s) retransmitted")
		assert.Empty(t, titlesOf(res, "Unanswered SYN"))
		assert.Len(t, titlesOf(res, titleSYNRetried), 1)
	})
	t.Run("a server RST after the retry", func(t *testing.T) {
		res := Analyze([]models.PacketInfo{
			tx(0, false, "SYN", 7000, 0, 0, 65535), tx(1000, false, "SYN", 7000, 0, 0, 65535),
			tx(1500, true, "RST,ACK", 0, 7001, 0, 0), tail(5000)}, "all")
		assert.Empty(t, titlesOf(res, "Unanswered SYN"))
		assert.Len(t, titlesOf(res, titleRefused), 1)
		got := retransmitIssues(res)
		require.Len(t, got, 1, "a refused connection keeps its retransmission issue, as before")
		assert.Equal(t, models.SeverityError, got[0].Severity)
	})
}

func TestDataRetransmissionsAreKeptWhereSYNRetriesAreUnanswered(t *testing.T) {
	t.Run("established connection", func(t *testing.T) {
		res := Analyze([]models.PacketInfo{
			tx(0, false, "SYN", 1000, 0, 0, 65535), tx(10, true, "SYN,ACK", 9000, 1001, 0, 65535), tx(11, false, "ACK", 1001, 9001, 0, 65535),
			tx(100, false, "PSH,ACK", 1001, 9001, 100, 65535), tx(400, false, "PSH,ACK", 1001, 9001, 100, 65535)}, "all")
		got := retransmitIssues(res)
		require.Len(t, got, 1)
		assert.Equal(t, titleTimeoutRetransmit, got[0].Title)
		assert.Equal(t, models.SeverityError, got[0].Severity)
		assert.Equal(t, 1, res.Flows[0].Retransmits)
		assert.Equal(t, 1, res.Flows[0].TimeoutRetransmits)
	})
	t.Run("one flow with data retransmissions and unanswered SYN retries", func(t *testing.T) {
		res := Analyze([]models.PacketInfo{
			tx(0, false, "PSH,ACK", 2000, 1, 100, 65535), tx(300, false, "PSH,ACK", 2000, 1, 100, 65535), // data resent after 300ms
			// the SYN of the same connection (ISN 1999, so its data starts at 2000): a SYN with an unrelated ISN would be another connection
			tx(1000, false, "SYN", 1999, 0, 0, 65535), tx(2200, false, "SYN", 1999, 0, 0, 65535), tail(2300)}, "all")
		require.Len(t, res.Flows, 2, "the TCP flow and the UDP packet that ends the capture")
		assert.Equal(t, 2, res.Flows[0].Retransmits, "both resent segments are counted")
		un := titlesOf(res, "Unanswered SYN")
		require.Len(t, un, 1)
		got := retransmitIssues(res)
		require.Len(t, got, 1, "the data retransmission is still reported")
		assert.Equal(t, models.SeverityError, got[0].Severity)
		assert.Contains(t, got[0].Description, "1 segment(s) retransmitted", "...and only the data segment is counted in it")
	})
	t.Run("several flows: only the unanswered ones lose the error, none is reported twice", func(t *testing.T) {
		var pk []models.PacketInfo
		for _, port := range []uint16{5001, 5002} {
			for _, ms := range []int{0, 1000, 3000} {
				pk = append(pk, onPort(tx(ms, false, "SYN", 7000, 0, 0, 65535), port))
			}
		}
		pk = append(pk, onPort(tx(100, false, "PSH,ACK", 2000, 1, 100, 65535), 5003), onPort(tx(400, false, "PSH,ACK", 2000, 1, 100, 65535), 5003), tail(3100))
		res := Analyze(pk, "all")
		un := titlesOf(res, "Unanswered SYN")
		require.Len(t, un, 1, "one aggregated issue for both")
		assert.Equal(t, 2, un[0].Count)
		got := retransmitIssues(res)
		require.Len(t, got, 1)
		assert.Equal(t, "10.0.0.1:5003-10.0.0.2:443", got[0].FlowID)
	})
}

// Keep-alive probes are not data: they must not restart the idle timer of a
// connection, so a reset that follows a long idle is an idle timeout even if
// probes went by every few seconds.

// kaOpen opens a connection (client 10.0.0.1:5000, sequence 1000; server
// sequence 9000), has the client send 100 bytes (next client byte 1101) and the
// server 200 bytes (next server byte 9201), all within 4 ms.
func kaOpen() []models.PacketInfo {
	return []models.PacketInfo{
		tx(0, false, "SYN", 1000, 0, 0, 65535), tx(1, true, "SYN,ACK", 9000, 1001, 0, 65535), tx(2, false, "ACK", 1001, 9001, 0, 65535),
		tx(3, false, "PSH,ACK", 1001, 9001, 100, 65535), tx(4, true, "PSH,ACK", 9001, 1101, 200, 65535),
	}
}

// kaProbe is a client keep-alive probe at ms (one byte of the last client byte)
// and the server's pure ACK in answer.
func kaProbe(ms int) []models.PacketInfo {
	return []models.PacketInfo{tx(ms, false, "ACK", 1100, 9201, 1, 65535), tx(ms+1, true, "ACK", 9201, 1101, 0, 65535)}
}

func kaReset(ms int) models.PacketInfo { return tx(ms, true, "RST,ACK", 9201, 1101, 0, 0) }

// kaResult returns the single Connection issue of the packets.
func kaResult(t *testing.T, packets []models.PacketInfo) (models.Issue, *models.AnalysisResult) {
	t.Helper()
	res := Analyze(packets, "all")
	got := connectionIssues(res)
	require.Len(t, got, 1)
	return got[0], res
}

func TestKeepAliveProbesDoNotRestartTheIdleTimer(t *testing.T) {
	t.Run("probes less than 10s apart: the reset is an idle timeout", func(t *testing.T) {
		pk := kaOpen()
		for _, ms := range []int{5003, 10003, 15003} {
			pk = append(pk, kaProbe(ms)...)
		}
		is, res := kaResult(t, append(pk, kaReset(20004)))
		assert.Equal(t, titleIdle, is.Title)
		assert.Equal(t, models.SeverityInfo, is.Severity)
		assert.Contains(t, is.Description, "20s after the last data")
		assert.Zero(t, res.Flows[0].Retransmits)
	})

	t.Run("a genuine one-byte write is data", func(t *testing.T) {
		pk := kaOpen()
		for _, ms := range []int{5003, 10003, 15003} {
			pk = append(pk, kaProbe(ms)...)
		}
		pk = append(pk, tx(19000, false, "PSH,ACK", 1101, 9201, 1, 65535), kaReset(20000)) // seq == next: new data
		is, _ := kaResult(t, pk)
		assert.Equal(t, titleAborted, is.Title)
		assert.Equal(t, models.SeverityError, is.Severity)
		assert.Contains(t, is.Description, "the last data was 1s earlier")
		assert.Contains(t, is.Description, "304 payload bytes", "100 + 200 + 3 probes + 1 byte: the probes still count as payload")
	})

	t.Run("zero-length probes and pure ACKs do not change the timer", func(t *testing.T) {
		pk := append(kaOpen(),
			tx(5003, false, "ACK", 1100, 9201, 0, 65535), tx(5004, true, "ACK", 9201, 1101, 0, 65535),
			tx(10003, false, "ACK", 1100, 9201, 0, 65535), tx(10004, true, "ACK", 9201, 1101, 0, 65535))
		is, _ := kaResult(t, append(pk, kaReset(15004)))
		assert.Equal(t, titleIdle, is.Title)
		assert.Contains(t, is.Description, "15s after the last data")
	})

	t.Run("sequence wraparound", func(t *testing.T) {
		isn := uint32(4294967200)
		pk := []models.PacketInfo{
			tx(0, false, "SYN", isn, 0, 0, 65535), tx(1, true, "SYN,ACK", 9000, isn+1, 0, 65535), tx(2, false, "ACK", isn+1, 9001, 0, 65535),
			tx(3, false, "PSH,ACK", isn+1, 9001, 100, 65535), // ends at 5 after wrapping: the next byte is 5
			tx(4, true, "PSH,ACK", 9001, isn+101, 200, 65535),
			tx(15003, false, "ACK", 4, 9201, 1, 65535), tx(15004, true, "ACK", 9201, 5, 0, 65535), // one probe, 5s before the reset
			tx(20004, true, "RST,ACK", 9201, 5, 0, 0)}
		is, _ := kaResult(t, pk)
		assert.Equal(t, titleIdle, is.Title)
	})

	t.Run("a late segment does not lower the tracked sequence", func(t *testing.T) {
		pk := []models.PacketInfo{
			tx(0, false, "SYN", 1000, 0, 0, 65535), tx(1, true, "SYN,ACK", 9000, 1001, 0, 65535), tx(2, false, "ACK", 1001, 9001, 0, 65535),
			tx(3, false, "PSH,ACK", 1001, 9001, 100, 65535),
			tx(4, false, "PSH,ACK", 1201, 9001, 100, 65535),                                             // a hole at 1101..1200
			tx(5, false, "PSH,ACK", 1101, 9001, 100, 65535),                                             // and the missing segment arrives late; the next byte is still 1301
			tx(15003, false, "ACK", 1300, 9001, 1, 65535), tx(15004, true, "ACK", 9001, 1301, 0, 65535), // one probe, 5s before the reset
			tx(20004, true, "RST,ACK", 9001, 1301, 0, 0)}
		is, _ := kaResult(t, pk)
		assert.Equal(t, titleIdle, is.Title)
		assert.Contains(t, is.Description, "after the last data")
	})

	t.Run("the client's and the server's sequence state are independent", func(t *testing.T) {
		// A server probe is judged by the server's next byte (9201) ...
		pk := append(kaOpen(), tx(15003, true, "ACK", 9200, 1101, 1, 65535), tx(15004, false, "ACK", 1101, 9201, 0, 65535))
		is, _ := kaResult(t, append(pk, kaReset(20004)))
		assert.Equal(t, titleIdle, is.Title)
		// ... and a client segment that has the server's probe number is data.
		pk = append(kaOpen(), tx(18000, false, "PSH,ACK", 9200, 9201, 1, 65535))
		is, _ = kaResult(t, append(pk, kaReset(20004)))
		assert.Equal(t, titleAborted, is.Title)
		assert.Contains(t, is.Description, "the last data was 2.004s earlier")
	})

	t.Run("a connection whose only payload is probes is an abrupt close", func(t *testing.T) {
		pk := []models.PacketInfo{
			tx(0, false, "SYN", 1000, 0, 0, 65535), tx(1, true, "SYN,ACK", 9000, 1001, 0, 65535), tx(2, false, "ACK", 1001, 9001, 0, 65535)}
		for _, ms := range []int{3000, 6000, 9000} {
			pk = append(pk, tx(ms, false, "ACK", 1000, 9001, 1, 65535), tx(ms+1, true, "ACK", 9001, 1001, 0, 65535))
		}
		is, _ := kaResult(t, append(pk, tx(20000, true, "RST,ACK", 9001, 1001, 0, 0)))
		assert.Equal(t, titleAborted, is.Title)
		assert.Equal(t, models.SeverityError, is.Severity)
		assert.NotContains(t, is.Description, "the last data")
		assert.Contains(t, is.Description, "3 payload bytes", "the probes still count as payload bytes")
	})

	t.Run("a capture that starts with a probe has no sequence state: it counts as data, as before", func(t *testing.T) {
		pk := []models.PacketInfo{tx(0, false, "ACK", 500, 1, 1, 65535), tx(1, true, "ACK", 1, 501, 0, 65535), tx(20000, true, "RST,ACK", 1, 501, 0, 0)}
		is, _ := kaResult(t, pk)
		assert.Equal(t, titleIdle, is.Title)
		assert.Contains(t, is.Description, "20s after the last data")
	})
}

// Lab-5: the client sent keep-alive probes at 45 s, 90 s, 238 s and 283 s; the
// last real data was at 193.6 s and the server reset the connection at 324.7 s.
func TestLab5IdleTimeIgnoresKeepAliveProbes(t *testing.T) {
	res := Analyze(readReal(t, "Lab-5-AnotherSlowApp.pcapng"), "all")
	var idle []models.Issue
	for _, is := range res.Issues {
		if is.Title == titleIdle {
			idle = append(idle, is)
		}
	}
	require.Len(t, idle, 1)
	assert.Equal(t, models.SeverityInfo, idle[0].Severity)
	assert.Contains(t, idle[0].Description, "2m11.065s after the last data", "131.065s, as a Go duration")
	assert.Equal(t, "Slow Server Response", res.Diagnosis.PrimaryCause)
	assert.Equal(t, 88, res.Diagnosis.HealthScore)
	assert.Zero(t, res.Flows[0].Retransmits)
}
