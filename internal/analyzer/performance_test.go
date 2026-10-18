package analyzer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// tcpPkt builds a packet on the flow 10.0.0.1:1000 (client) <-> 10.0.0.2:80 (server).
func tcpPkt(sec float64, fromClient bool, flags string, seq, ack uint32, payload int) models.PacketInfo {
	p := models.PacketInfo{Timestamp: at(sec), Protocol: models.ProtocolTCP, TCPFlags: flags, TCPSeq: seq, TCPAck: ack, PayloadSize: payload, Size: 60 + payload}
	if fromClient {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 1000, "10.0.0.2", 80
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 80, "10.0.0.1", 1000
	}
	return p
}

// withHandshake stamps the handshake timeline on every packet, as the reader does.
func withHandshake(pkts []models.PacketInfo, syn, synAck, ack, data float64) []models.PacketInfo {
	t := func(s float64) time.Time {
		if s < 0 {
			return time.Time{}
		}
		return at(s)
	}
	for i := range pkts {
		pkts[i].Handshake = &models.HandshakeTimes{TCPSynTime: t(syn), TCPSynAckTime: t(synAck), TCPAckTime: t(ack), FirstDataTime: t(data)}
	}
	return pkts
}

func TestHandshakeMetrics(t *testing.T) {
	tests := []struct {
		name                  string
		syn, synAck, ack, dat float64 // -1 = not observed
		wantSetup, wantTTFB   float64
	}{
		{"full handshake and data", 0, 0.05, 0.1, 0.6, 100, 500},
		{"no data yet", 0, 0.05, 0.1, -1, 100, 0},
		{"no syn (mid-connection capture)", -1, -1, -1, 2, 0, 0},
		{"syn but handshake never completed", 0, 0.05, -1, -1, 0, 0},
		{"data before ack is not a valid ttfb", 0, 0.05, 0.1, 0.09, 100, 0},
		{"fractional milliseconds are rounded to 2 places", 0, 0.0004, 0.00123456, 0.00223456, 1.23, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkts []models.PacketInfo
			if tt.syn >= 0 {
				pkts = append(pkts, tcpPkt(tt.syn, true, "SYN", 0, 0, 0))
			}
			if tt.dat >= 0 {
				pkts = append(pkts, tcpPkt(tt.dat, false, "PSH,ACK", 1, 1, 100)) // the first server payload
			}
			if len(pkts) == 0 {
				pkts = append(pkts, tcpPkt(0, true, "ACK", 1, 1, 0))
			}
			pkts = withHandshake(pkts, tt.syn, tt.synAck, tt.ack, tt.dat)
			setup, ttfb := handshakeMetrics(pkts)
			assert.InDelta(t, tt.wantSetup, setup, 0.001)
			assert.InDelta(t, tt.wantTTFB, ttfb, 0.001)
		})
	}
}

func TestRTTMetrics(t *testing.T) {
	tests := []struct {
		name         string
		pkts         []models.PacketInfo
		wantAvg, max float64
	}{
		{"no packets", nil, 0, 0},
		{"two data samples", []models.PacketInfo{
			tcpPkt(1, true, "PSH,ACK", 101, 501, 50), tcpPkt(1.1, false, "ACK", 501, 151, 0),
			tcpPkt(2, true, "PSH,ACK", 151, 501, 50), tcpPkt(2.3, false, "ACK", 501, 201, 0)}, 200, 300},
		{"syn to syn-ack is a sample", []models.PacketInfo{
			tcpPkt(0, true, "SYN", 100, 0, 0), tcpPkt(0.08, false, "SYN,ACK", 500, 101, 0)}, 80, 80},
		{"delayed ack covers two segments: measured from the latest", []models.PacketInfo{
			tcpPkt(1, true, "ACK", 101, 501, 50), tcpPkt(1.1, true, "ACK", 151, 501, 50), tcpPkt(1.3, false, "ACK", 501, 201, 0)}, 200, 200},
		{"ack that does not cover the segment", []models.PacketInfo{
			tcpPkt(1, true, "PSH,ACK", 101, 501, 50), tcpPkt(1.1, false, "ACK", 501, 101, 0)}, 0, 0},
		{"retransmitted segment is excluded (Karn)", []models.PacketInfo{
			tcpPkt(1, true, "PSH,ACK", 101, 501, 50), tcpPkt(1.5, true, "PSH,ACK", 101, 501, 50), tcpPkt(1.6, false, "ACK", 501, 151, 0)}, 0, 0},
		{"packet without ACK flag does not acknowledge", []models.PacketInfo{
			tcpPkt(1, true, "PSH,ACK", 101, 501, 50), tcpPkt(1.1, false, "RST", 501, 151, 0)}, 0, 0},
		{"pure acks are not timed", []models.PacketInfo{
			tcpPkt(1, true, "ACK", 101, 501, 0), tcpPkt(1.1, false, "ACK", 501, 101, 0)}, 0, 0},
		{"sequence wraparound", []models.PacketInfo{
			tcpPkt(1, true, "PSH,ACK", 0xFFFFFFF0, 1, 32), tcpPkt(1.25, false, "ACK", 1, 0x10, 0)}, 250, 250},
		{"fin consumes sequence space", []models.PacketInfo{
			tcpPkt(1, true, "FIN,ACK", 101, 501, 0), tcpPkt(1.05, false, "ACK", 501, 102, 0)}, 50, 50},
		{"server data acked by client", []models.PacketInfo{
			tcpPkt(1, false, "PSH,ACK", 501, 101, 100), tcpPkt(1.04, true, "ACK", 101, 601, 0)}, 40, 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avg, max := rttMetrics(tt.pkts)
			assert.InDelta(t, tt.wantAvg, avg, 0.001)
			assert.InDelta(t, tt.max, max, 0.001)
		})
	}
}

func TestApplyPerformanceMetrics(t *testing.T) {
	pkts := withHandshake([]models.PacketInfo{
		tcpPkt(0, true, "SYN", 100, 0, 0),
		tcpPkt(0.2, false, "SYN,ACK", 500, 101, 0),
		tcpPkt(0.6, true, "ACK", 101, 501, 0),
		tcpPkt(2.0, false, "PSH,ACK", 501, 101, 100), // TTFB 1.4s after the handshake ACK
		tcpPkt(2.3, true, "ACK", 101, 601, 0),        // RTT 300ms
	}, 0, 0.2, 0.6, 2.0)
	udp := models.PacketInfo{Timestamp: at(0), SrcIP: "1.1.1.1", SrcPort: 1, DstIP: "2.2.2.2", DstPort: 2, Protocol: models.ProtocolUDP, Size: 50}

	in := aggregateFlows(append(pkts, udp))
	flows, issues := applyPerformanceMetrics(append(pkts, udp), in)

	var tcp, udpFlow models.Flow
	for _, f := range flows {
		if f.Protocol == models.ProtocolTCP {
			tcp = f
		} else {
			udpFlow = f
		}
	}
	assert.InDelta(t, 600, tcp.SetupTimeMs, 0.01)
	assert.InDelta(t, 1400, tcp.TTFBMs, 0.01)
	// Samples: SYN->SYN-ACK 200ms, SYN-ACK->handshake ACK 400ms, data->ACK 300ms.
	assert.InDelta(t, 300, tcp.AvgRTTMs, 0.01)
	assert.InDelta(t, 400, tcp.MaxRTTMs, 0.01)
	assert.Zero(t, udpFlow.SetupTimeMs, "non-TCP flows are untouched")

	titles := map[string]models.Severity{}
	for _, is := range issues {
		titles[is.Title] = is.Severity
		assert.Equal(t, "Performance", is.Category)
		assert.Equal(t, tcp.ID, is.FlowID)
	}
	assert.Equal(t, map[string]models.Severity{
		"Slow TCP Handshake":   models.SeverityWarning,
		"Slow Server Response": models.SeverityWarning,
		"High Network Latency": models.SeverityInfo,
	}, titles, "avg RTT 300ms exceeds 200ms; max 400ms does not exceed 500ms")

	for _, f := range in {
		assert.Zero(t, f.SetupTimeMs, "input flows must not be modified")
	}
}

func TestApplyPerformanceMetricsFlowWithoutPackets(t *testing.T) {
	flows := []models.Flow{{ID: "x", SrcIP: "9.9.9.9", DstIP: "8.8.8.8", Protocol: models.ProtocolTCP}}
	out, issues := applyPerformanceMetrics(nil, flows)
	assert.Equal(t, flows, out)
	assert.Empty(t, issues)
}

func TestPerformanceIssues(t *testing.T) {
	tests := []struct {
		name string
		flow models.Flow
		want []string
	}{
		{"healthy", models.Flow{ID: "f", SetupTimeMs: 20, TTFBMs: 80, AvgRTTMs: 20, MaxRTTMs: 40}, nil},
		{"all thresholds exactly met are not exceeded", models.Flow{ID: "f", SetupTimeMs: 500, TTFBMs: 1000, AvgRTTMs: 200, MaxRTTMs: 500}, nil},
		{"slow handshake", models.Flow{ID: "f", SetupTimeMs: 500.01}, []string{"Slow TCP Handshake"}},
		{"slow ttfb", models.Flow{ID: "f", TTFBMs: 1000.01}, []string{"Slow Server Response"}},
		{"latency and jitter are aggregated elsewhere", models.Flow{ID: "f", AvgRTTMs: 900, MaxRTTMs: 900}, nil},
		{"both per-flow issues", models.Flow{ID: "f", SetupTimeMs: 900, TTFBMs: 2000, AvgRTTMs: 300, MaxRTTMs: 900},
			[]string{"Slow TCP Handshake", "Slow Server Response"}},
	}
	sev := map[string]models.Severity{
		"Slow TCP Handshake": models.SeverityWarning, "Slow Server Response": models.SeverityWarning,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var titles []string
			for _, is := range performanceIssues(tt.flow) {
				titles = append(titles, is.Title)
				assert.Equal(t, sev[is.Title], is.Severity)
				assert.Equal(t, "f", is.FlowID)
				assert.NotEmpty(t, is.Description)
			}
			assert.Equal(t, tt.want, titles)
		})
	}
}

func TestSlowFlows(t *testing.T) {
	flows := []models.Flow{
		{ID: "none"},
		{ID: "setup", SetupTimeMs: 300},
		{ID: "ttfb", TTFBMs: 900},
		{ID: "jitter", MaxRTTMs: 600, AvgRTTMs: 10},
		{ID: "a", SetupTimeMs: 1}, {ID: "b", SetupTimeMs: 2}, {ID: "c", SetupTimeMs: 3},
	}
	got := slowFlows(flows, 5)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	assert.Equal(t, []string{"ttfb", "jitter", "setup", "c", "b"}, ids)

	empty := slowFlows([]models.Flow{{ID: "none"}}, 5)
	assert.NotNil(t, empty, "empty result must serialize as []")
	assert.Empty(t, empty)
}

// Lab-5 timings cross-checked against Wireshark: the handshake completes at
// 0.104s and the server's first data arrives at 108.87s.
func TestPerformanceRealLab5Handshake(t *testing.T) {
	packets, err := pcap.ReadPackets(filepath.Join("..", "..", "testdata", "Lab-5-AnotherSlowApp.pcapng"))
	require.NoError(t, err)

	first := packets[0]
	require.NotNil(t, first.Handshake)
	assert.False(t, first.Handshake.TCPSynTime.IsZero())
	assert.False(t, first.Handshake.TCPSynAckTime.IsZero())
	assert.False(t, first.Handshake.TCPAckTime.IsZero())
	assert.False(t, first.Handshake.FirstDataTime.IsZero())
	assert.InDelta(t, 97, ms(first.Handshake.TCPSynAckTime.Sub(first.Handshake.TCPSynTime)), 2, "SYN to SYN-ACK")

	flows, issues := applyPerformanceMetrics(packets, aggregateFlows(packets))
	require.Len(t, flows, 1)
	assert.InDelta(t, 104, flows[0].SetupTimeMs, 5)
	assert.Greater(t, flows[0].MaxRTTMs, flows[0].AvgRTTMs/2)

	var titles []string
	for _, is := range issues {
		titles = append(titles, is.Title)
		assert.Equal(t, flows[0].ID, is.FlowID)
	}
	assert.Contains(t, titles, "Slow Server Response")
	assert.NotContains(t, titles, "Slow TCP Handshake", "104ms is under the 500ms threshold")

}

func slowRTTFlows(n int, avg, max float64) []models.Flow {
	flows := make([]models.Flow, n)
	for i := range flows {
		flows[i] = models.Flow{ID: fmt.Sprintf("10.0.0.%d:1000-10.0.1.1:443", i), Protocol: models.ProtocolTCP,
			StartTime: at(float64(i)), AvgRTTMs: avg + float64(i), MaxRTTMs: max + float64(i)}
	}
	return flows
}

func perfIssuesByTitle(issues []models.Issue) map[string][]models.Issue {
	out := map[string][]models.Issue{}
	for _, is := range issues {
		out[is.Title] = append(out[is.Title], is)
	}
	return out
}

func TestAggregatePerformance50Flows(t *testing.T) {
	// 50 flows, every one above the latency and the jitter threshold
	issues := aggregatePerformance(slowRTTFlows(50, 250, 600))
	by := perfIssuesByTitle(issues)
	require.Len(t, issues, 2, "two aggregated issues, not 100")

	lat := by["High Network Latency"]
	require.Len(t, lat, 1)
	assert.Equal(t, models.SeverityInfo, lat[0].Severity)
	assert.Equal(t, "Performance", lat[0].Category)
	assert.Equal(t, 50, lat[0].Count)
	assert.Len(t, lat[0].Occurrences, 50)
	assert.Empty(t, lat[0].FlowID)
	assert.Equal(t, "10.0.0.49:1000-10.0.1.1:443", lat[0].Target, "the worst flow")
	assert.Equal(t, at(0), lat[0].Timestamp)
	assert.Equal(t, "50 flows experienced average RTT > 200ms (Max observed: 299ms). Worst: "+
		"10.0.0.49:1000-10.0.1.1:443 (299ms), 10.0.0.48:1000-10.0.1.1:443 (298ms), 10.0.0.47:1000-10.0.1.1:443 (297ms)", lat[0].Description)

	jit := by["High Jitter"]
	require.Len(t, jit, 1)
	assert.Equal(t, models.SeverityWarning, jit[0].Severity)
	assert.Equal(t, 50, jit[0].Count)
	assert.Contains(t, jit[0].Description, "50 flows experienced max RTT > 500ms (Max observed: 649ms)")
}

func TestAggregatePerformanceViaAnalyze(t *testing.T) {
	// 50 TCP flows, each with a 300ms request/ACK round trip, through the full pipeline
	var packets []models.PacketInfo
	for i := 0; i < 50; i++ {
		port := uint16(2000 + i)
		c := func(sec float64, flags string, seq, ack uint32, payload int, fromClient bool) models.PacketInfo {
			p := models.PacketInfo{Timestamp: at(float64(i) + sec), Protocol: models.ProtocolTCP, TCPFlags: flags, TCPSeq: seq, TCPAck: ack,
				PayloadSize: payload, Size: 60 + payload, TCPWindow: 1000}
			if fromClient {
				p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", port, "10.0.0.2", 80
			} else {
				p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 80, "10.0.0.1", port
			}
			return p
		}
		packets = append(packets,
			c(0, "PSH,ACK", 100, 1, 50, true),
			c(0.3, "ACK", 1, 150, 0, false), // 300ms RTT
		)
	}
	res := Analyze(packets, "all")
	require.Equal(t, 50, res.TotalFlows)
	by := perfIssuesByTitle(res.Issues)
	require.Len(t, by["High Network Latency"], 1, "one latency issue for 50 flows")
	assert.Equal(t, 50, by["High Network Latency"][0].Count)
	assert.Len(t, res.SlowFlows, topTalkerCount, "the TOP SLOW FLOWS table still lists the worst offenders")
	assert.Equal(t, 98, res.Diagnosis.HealthScore, "one info issue, not fifty")
}

func TestAggregatePerformanceDetails(t *testing.T) {
	t.Run("nothing over the thresholds", func(t *testing.T) {
		assert.Empty(t, aggregatePerformance([]models.Flow{{ID: "a", AvgRTTMs: 200, MaxRTTMs: 500}, {ID: "b"}}))
		assert.Empty(t, aggregatePerformance(nil))
	})
	t.Run("a single flow keeps its flow ID", func(t *testing.T) {
		issues := aggregatePerformance([]models.Flow{{ID: "a", AvgRTTMs: 300, StartTime: at(5)}, {ID: "b", AvgRTTMs: 10}})
		require.Len(t, issues, 1)
		assert.Equal(t, "a", issues[0].FlowID)
		assert.Equal(t, "1 flow experienced average RTT > 200ms (Max observed: 300ms). Worst: a (300ms)", issues[0].Description)
	})
	t.Run("latency and jitter are independent", func(t *testing.T) {
		issues := perfIssuesByTitle(aggregatePerformance([]models.Flow{
			{ID: "lat", AvgRTTMs: 250, MaxRTTMs: 300}, {ID: "jit", AvgRTTMs: 50, MaxRTTMs: 800}}))
		assert.Equal(t, 1, issues["High Network Latency"][0].Count)
		assert.Equal(t, "lat", issues["High Network Latency"][0].FlowID)
		assert.Equal(t, 1, issues["High Jitter"][0].Count)
		assert.Equal(t, "jit", issues["High Jitter"][0].FlowID)
	})
	t.Run("extreme latency becomes a warning", func(t *testing.T) {
		issues := aggregatePerformance([]models.Flow{{ID: "a", AvgRTTMs: 1000}, {ID: "b", AvgRTTMs: 1000.5}})
		assert.Equal(t, models.SeverityWarning, issues[0].Severity)
		issues = aggregatePerformance([]models.Flow{{ID: "a", AvgRTTMs: 1000}})
		assert.Equal(t, models.SeverityInfo, issues[0].Severity, "exactly 1s is still info")
	})
	t.Run("only the three worst flows are named", func(t *testing.T) {
		is := aggregatePerformance(slowRTTFlows(4, 300, 0))[0]
		assert.NotContains(t, is.Description, "10.0.0.0:")
		assert.Len(t, is.Occurrences, 4)
	})
}

func TestCongestionMarksAggregatedLatencyAsRootCause(t *testing.T) {
	hot := models.Flow{ID: "hot", AvgRTTMs: 400, Retransmits: 2, StartTime: at(0)}
	lat := aggregatePerformance([]models.Flow{hot, {ID: "other", AvgRTTMs: 300, StartTime: at(1)}})
	require.Len(t, lat, 1)
	d := diagnosis{roles: map[string]string{}}
	require.True(t, d.congestion([]models.Flow{hot}, lat))
	assert.Equal(t, eventRootCause, d.roles[lat[0].ID])
}

func TestAggregatedPerformanceSerializesEveryFlow(t *testing.T) {
	issues := aggregatePerformance(slowRTTFlows(50, 250, 600))
	by := perfIssuesByTitle(issues)
	lat := by["High Network Latency"][0]

	raw, err := json.Marshal(lat)
	require.NoError(t, err)
	var decoded struct {
		Count       int `json:"count"`
		Occurrences []struct {
			Subject string  `json:"subject"`
			Value   float64 `json:"value"`
			Unit    string  `json:"unit"`
		} `json:"occurrences"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded.Occurrences, 50)
	assert.Equal(t, "10.0.0.49:1000-10.0.1.1:443", decoded.Occurrences[0].Subject, "worst first")
	assert.InDelta(t, 299, decoded.Occurrences[0].Value, 0.001)
	assert.Equal(t, "ms", decoded.Occurrences[0].Unit)

	jit := by["High Jitter"][0]
	assert.InDelta(t, 649, jit.Occurrences[0].Value, 0.001, "jitter lists the max RTT, not the average")
}

func TestHandshakeMetricsWithoutHandshakeObject(t *testing.T) {
	pkts := []models.PacketInfo{tcpPkt(0, true, "ACK", 1, 1, 0), tcpPkt(1, false, "PSH,ACK", 1, 1, 10)}
	setup, ttfb := handshakeMetrics(pkts)
	assert.Zero(t, setup)
	assert.Zero(t, ttfb)
}

// ttfbFlow is a connection whose handshake ends at 0.020s (SYN at 0, SYN-ACK at
// 0.010s), followed by the given packets, stamped with the handshake timeline
// the reader would give it (firstData is the first server payload after the ACK).
func ttfbFlow(firstData float64, rest ...models.PacketInfo) []models.PacketInfo {
	pkts := []models.PacketInfo{
		tcpPkt(0, true, "SYN", 0, 0, 0), tcpPkt(0.010, false, "SYN,ACK", 0, 1, 0), tcpPkt(0.020, true, "ACK", 1, 1, 0),
	}
	pkts = append(pkts, rest...)
	for i := range pkts {
		pkts[i].TCPWindow = 65535 // a zero window would be an issue of its own
	}
	return withHandshake(pkts, 0, 0.010, 0.020, firstData)
}

func TestHandshakeMetricsTTFBAnchor(t *testing.T) {
	cli := func(sec float64, n int) models.PacketInfo { return tcpPkt(sec, true, "PSH,ACK", 1, 1, n) }
	srv := func(sec float64, n int) models.PacketInfo { return tcpPkt(sec, false, "PSH,ACK", 1, 1, n) }
	tests := []struct {
		name string
		pkts []models.PacketInfo
		want float64
	}{
		// Necessary for D1.
		{"D1-1 client idle time is not server time", ttfbFlow(30.070, cli(30.020, 100), srv(30.070, 500)), 50},
		{"D1-2 normal request and response", ttfbFlow(0.075, cli(0.025, 100), srv(0.075, 500)), 50},
		{"D1-3 a genuinely slow response is still measured", ttfbFlow(2.025, cli(0.025, 100), srv(2.025, 500)), 2000},
		{"D1-4 server-first protocol: measured from the handshake ACK", ttfbFlow(1.520, srv(1.520, 40)), 1500},
		{"D1-5 a retransmitted client payload does not move the anchor",
			ttfbFlow(0.260, cli(0.025, 100), cli(0.225, 100), srv(0.260, 500)), 235},
		{"the anchor is the first client payload, not a later client segment",
			ttfbFlow(0.900, cli(0.025, 100), cli(0.500, 100), srv(0.900, 500)), 875},
		{"client payload on the final ACK itself is the anchor",
			ttfbFlow(0.070, tcpPkt(0.020, true, "PSH,ACK", 1, 1, 100), srv(0.070, 500)), 50},
		{"server payload before any client payload keeps the server-first anchor, even if the client talks later",
			ttfbFlow(0.500, srv(0.500, 40), cli(0.600, 100), srv(0.700, 500)), 480},
		// Unavailable: 0.
		{"client payload without a server response", ttfbFlow(-1, cli(0.025, 100)), 0},
		{"no payload at all after the handshake", ttfbFlow(-1), 0},
		{"server payload before the handshake ACK does not count",
			withHandshake([]models.PacketInfo{tcpPkt(0, true, "SYN", 0, 0, 0), tcpPkt(0.010, false, "SYN,ACK", 0, 1, 0), tcpPkt(0.015, false, "PSH,ACK", 1, 1, 40), tcpPkt(0.020, true, "ACK", 1, 1, 0)}, 0, 0.010, 0.020, -1), 0},
		{"client unknown without the SYN", withHandshake([]models.PacketInfo{tcpPkt(0.020, true, "ACK", 1, 1, 0), cli(0.025, 100), srv(0.075, 500)}, -1, -1, 0.020, 0.075), 0},
		{"handshake never completed", withHandshake([]models.PacketInfo{tcpPkt(0, true, "SYN", 0, 0, 0), cli(0.025, 100), srv(0.075, 500)}, 0, -1, -1, 0.075), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ttfb := handshakeMetrics(tt.pkts)
			assert.InDelta(t, tt.want, ttfb, 0.001)
		})
	}
}

func ttfbFlowOnPort(port uint16, pkts []models.PacketInfo) []models.PacketInfo {
	for i := range pkts {
		if pkts[i].SrcPort == 1000 {
			pkts[i].SrcPort = port
		}
		if pkts[i].DstPort == 1000 {
			pkts[i].DstPort = port
		}
	}
	return pkts
}

func TestTTFBFlowLevelConsistency(t *testing.T) {
	cli := func(sec float64, n int) models.PacketInfo { return tcpPkt(sec, true, "PSH,ACK", 1, 1, n) }
	srv := func(sec float64, n int) models.PacketInfo { return tcpPkt(sec, false, "PSH,ACK", 1, 1, n) }
	idle := ttfbFlowOnPort(1001, ttfbFlow(30.070, cli(30.020, 100), srv(30.070, 500)))
	slow := ttfbFlowOnPort(1002, ttfbFlow(2.025, cli(0.025, 100), srv(2.025, 500)))
	banner := ttfbFlowOnPort(1003, ttfbFlow(1.520, srv(1.520, 40)))

	res := Analyze(append(append(append([]models.PacketInfo{}, idle...), slow...), banner...), "all")
	byPort := map[string]models.Flow{}
	for _, f := range res.TopTalkers {
		byPort[f.ID[:strings.Index(f.ID, "-")]] = f
	}
	require.Len(t, byPort, 3)

	f := byPort["10.0.0.1:1001"]
	assert.InDelta(t, 50, f.TTFBMs, 0.01)
	assert.Equal(t, statusWorking, f.Status, "an idle client is not a slow flow")
	f = byPort["10.0.0.1:1002"]
	assert.InDelta(t, 2000, f.TTFBMs, 0.01)
	assert.Equal(t, statusSlow, f.Status)
	f = byPort["10.0.0.1:1003"]
	assert.InDelta(t, 1500, f.TTFBMs, 0.01)
	assert.Equal(t, statusSlow, f.Status)

	var slowIssueFlows []string
	for _, is := range res.Issues {
		if is.Title == "Slow Server Response" {
			slowIssueFlows = append(slowIssueFlows, is.FlowID)
		}
	}
	assert.ElementsMatch(t, []string{byPort["10.0.0.1:1002"].ID, byPort["10.0.0.1:1003"].ID}, slowIssueFlows,
		"only the genuinely slow server and the server-first greeting are reported")

	require.Len(t, res.SlowFlows, 3)
	assert.Equal(t, byPort["10.0.0.1:1002"].ID, res.SlowFlows[0].ID, "ranking follows the corrected value")
	assert.Equal(t, byPort["10.0.0.1:1003"].ID, res.SlowFlows[1].ID)
	assert.Equal(t, byPort["10.0.0.1:1001"].ID, res.SlowFlows[2].ID)
}
