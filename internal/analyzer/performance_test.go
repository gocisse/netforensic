package analyzer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
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

// The three recommendations of Slow Server Response, and that of HTTP Slow Response.
const (
	adviceRequestAcked = "The server's TCP stack acknowledged the request, but the first data came much later and no retransmission was captured in between. The delay is after the request arrived: look at the server (application processing, a slow backend or database, or an overloaded host), or at a proxy or load balancer in front of it."
	adviceLoss         = "Retransmissions or duplicate ACKs were captured while waiting, so packet loss may explain the delay rather than slow processing. Fix the loss first (check the path, MTU and middleboxes, and compare with a capture at the server to see when the request arrived), then measure again."
	adviceAmbiguous    = "The first server data came much later than the client's first data, but this capture cannot show whether the time went to the server or to the network (no acknowledgement of the request and no retransmission was captured). Capture at the server, or on both sides, to tell them apart."
	adviceServerFirst  = "The server took this long to send its first data after the handshake. This capture cannot show whether the time went to the server or to the network (no retransmission was captured). Capture at the server, or on both sides, to tell them apart."
	adviceHTTPSlow     = "The server took more than a second to answer this request. The capture alone does not show whether the time went to the application or to packet loss on the path: check this flow for retransmissions first; if there are none, look at application and database performance on the server side."
)

// slowResponseIssue runs the packets through the performance metrics and
// returns the Slow Server Response issue of the flow, which must exist.
func slowResponseIssue(t *testing.T, pkts []models.PacketInfo) models.Issue {
	t.Helper()
	for i := range pkts {
		pkts[i].TCPWindow = 65535
	}
	pkts = withHandshake(pkts, 0, 0.010, 0.020, -1)
	_, issues := applyPerformanceMetrics(pkts, aggregateFlows(pkts))
	for _, is := range issues {
		if is.Title == "Slow Server Response" {
			return is
		}
	}
	require.Failf(t, "no Slow Server Response", "issues: %v", issues)
	return models.Issue{}
}

func TestSlowServerResponseAdvice(t *testing.T) {
	syn := func() models.PacketInfo { return tcpPkt(0, true, "SYN", 0, 0, 0) }
	synAck := func(sec float64) models.PacketInfo { return tcpPkt(sec, false, "SYN,ACK", 0, 1, 0) }
	ack := func() models.PacketInfo { return tcpPkt(0.020, true, "ACK", 1, 1, 0) }
	req := func(sec float64, n int) models.PacketInfo { return tcpPkt(sec, true, "PSH,ACK", 1, 1, n) }
	srvAck := func(sec float64, ackNo uint32) models.PacketInfo { return tcpPkt(sec, false, "ACK", 1, ackNo, 0) }
	resp := func(sec float64) models.PacketInfo { return tcpPkt(sec, false, "PSH,ACK", 1, 101, 500) }
	hs := func(rest ...models.PacketInfo) []models.PacketInfo {
		return append([]models.PacketInfo{syn(), synAck(0.010), ack()}, rest...)
	}

	tests := []struct {
		name string
		pkts []models.PacketInfo
		want string
	}{
		{"request acknowledged, nothing lost", hs(req(0.025, 100), srvAck(0.030, 101), resp(2.025)), adviceRequestAcked},
		{"a retransmission inside the window beats the acknowledgement",
			hs(req(0.025, 100), req(0.225, 100), srvAck(0.230, 101), resp(2.025)), adviceLoss},
		{"two identical pure ACKs inside the window, no retransmission",
			hs(req(0.025, 100), srvAck(0.030, 101), srvAck(0.031, 101), resp(2.025)), adviceLoss},
		{"request never acknowledged before the response", hs(req(0.025, 100), resp(2.025)), adviceAmbiguous},
		{"the acknowledgement of the response itself is not an earlier one",
			hs(req(0.025, 100), resp(2.025)), adviceAmbiguous},
		{"server speaks first", hs(tcpPkt(1.520, false, "PSH,ACK", 1, 1, 40)), adviceServerFirst},
		{"a one-byte client segment is an uncertain anchor",
			hs(req(0.025, 1), srvAck(0.030, 2), tcpPkt(2.025, false, "PSH,ACK", 1, 2, 500)), adviceAmbiguous},
		{"a one-byte anchor does not hide loss evidence",
			hs(req(0.025, 1), srvAck(0.030, 2), synAck(0.100), tcpPkt(2.025, false, "PSH,ACK", 1, 2, 500)), adviceLoss},
		{"an ACK answering a keep-alive probe is not a duplicate ACK",
			hs(req(0.025, 100), srvAck(0.030, 101), tcpPkt(1.0, true, "ACK", 100, 1, 1), srvAck(1.001, 101), resp(2.025)), adviceRequestAcked},
		{"the same repeated ACK without a probe is",
			hs(req(0.025, 100), srvAck(0.030, 101), tcpPkt(1.0, true, "ACK", 101, 1, 0), srvAck(1.001, 101), resp(2.025)), adviceLoss},

		// Window boundaries.
		{"a retransmission before the anchor is not in the window",
			[]models.PacketInfo{syn(), synAck(0.010), synAck(0.015), ack(), req(0.025, 100), srvAck(0.030, 101), resp(2.025)}, adviceRequestAcked},
		{"a retransmission after the first server payload is not in the window",
			hs(req(0.025, 100), srvAck(0.030, 101), resp(2.025), resp(2.5)), adviceRequestAcked},
		{"a retransmission at the anchor's time is in the window",
			hs(synAck(0.025), req(0.025, 100), srvAck(0.030, 101), resp(2.025)), adviceLoss},
		{"a retransmission at the first server payload's time is in the window",
			hs(req(0.025, 100), srvAck(0.030, 101), synAck(2.025), resp(2.025)), adviceLoss},
		{"duplicate ACKs need both ACKs inside the window",
			hs(srvAck(0.022, 1), req(0.025, 100), srvAck(0.026, 1), srvAck(0.030, 101), resp(2.025)), adviceRequestAcked},
		{"an acknowledgement that does not cover the request does not count",
			hs(req(0.025, 100), srvAck(0.030, 50), resp(2.025)), adviceAmbiguous},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := slowResponseIssue(t, tt.pkts)
			assert.Equal(t, tt.want, is.Recommendation)
			assert.NotContains(t, is.Recommendation, "The network is fine")
		})
	}
}

func TestSlowServerResponseAdviceKeepsTheIssueUnchanged(t *testing.T) {
	pkts := []models.PacketInfo{tcpPkt(0, true, "SYN", 0, 0, 0), tcpPkt(0.010, false, "SYN,ACK", 0, 1, 0), tcpPkt(0.020, true, "ACK", 1, 1, 0),
		tcpPkt(0.025, true, "PSH,ACK", 1, 1, 100), tcpPkt(0.030, false, "ACK", 1, 101, 0), tcpPkt(2.025, false, "PSH,ACK", 1, 101, 500)}
	is := slowResponseIssue(t, pkts)
	assert.Equal(t, models.SeverityWarning, is.Severity)
	assert.Equal(t, "Performance", is.Category)
	assert.Contains(t, is.Description, "waited 2000ms for the first server data after the first client data, or after the handshake if the server sends first (threshold 1000ms)")
}

func TestSlowServerResponseAdviceOnRealCaptures(t *testing.T) {
	titles := func(name string) models.Issue {
		for _, is := range Analyze(readReal(t, name), "all").Issues {
			if is.Title == "Slow Server Response" {
				return is
			}
		}
		require.Failf(t, "no Slow Server Response", name)
		return models.Issue{}
	}
	assert.Equal(t, adviceLoss, titles("Lab-4-NetworkCongestion.pcapng").Recommendation, "two retransmissions while waiting")
	assert.Equal(t, adviceRequestAcked, titles("Lab-5-AnotherSlowApp.pcapng").Recommendation, "the request was acknowledged, nothing was lost")
}

func TestSlowResponseStaticRecommendations(t *testing.T) {
	assert.Equal(t, adviceAmbiguous, recommendationFor(models.Issue{Title: "Slow Server Response"}), "without evidence, the neutral text")
	assert.Equal(t, adviceHTTPSlow, recommendationFor(models.Issue{Title: "HTTP Slow Response"}))

	res := Analyze([]models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(2, 1000, 200)}, "all")
	var got []models.Issue
	for _, is := range res.Issues {
		if is.Title == "HTTP Slow Response" {
			got = append(got, is)
		}
	}
	require.Len(t, got, 1)
	assert.Equal(t, adviceHTTPSlow, got[0].Recommendation)
	assert.Equal(t, models.SeverityInfo, got[0].Severity)
}

// handshakeRun runs a connection through the whole analysis: the client SYN at
// every time in syns (seconds), the SYN-ACK at synAck, the final ACK at ack,
// stamped like the reader stamps it (the first SYN, the SYN-ACK, the ACK).
func handshakeRun(syns []float64, synAck, ack float64) *models.AnalysisResult {
	var pkts []models.PacketInfo
	for _, s := range syns {
		pkts = append(pkts, tcpPkt(s, true, "SYN", 0, 0, 0))
	}
	pkts = append(pkts, tcpPkt(synAck, false, "SYN,ACK", 0, 1, 0), tcpPkt(ack, true, "ACK", 1, 1, 0))
	for i := range pkts {
		pkts[i].TCPWindow = 65535
	}
	sort.SliceStable(pkts, func(a, b int) bool { return pkts[a].Timestamp.Before(pkts[b].Timestamp) })
	return Analyze(withHandshake(pkts, syns[0], synAck, ack, -1), "all")
}

func hasIssue(res *models.AnalysisResult, title string) bool {
	for _, is := range res.Issues {
		if is.Title == title {
			return true
		}
	}
	return false
}

// A slow handshake needs a SYN-ACK that is slow whichever SYN it answered: the
// time from the last SYN before it to the final ACK must exceed the threshold.
func TestSlowHandshakeNeedsEvenTheLastSYNToBeSlow(t *testing.T) {
	tests := []struct {
		name      string
		syns      []float64
		synAck    float64
		ack       float64
		wantSetup float64 // SYN to final ACK, which never changes
		wantSlow  bool
	}{
		{"D3-1 a retry answered quickly: the retry explains the wait", []float64{0, 1.0}, 1.015, 1.030, 1030, false},
		{"D3-2 a retry answered slowly", []float64{0, 1.0}, 1.700, 1.710, 1710, true},
		{"D3-3 no retry, slow", []float64{0}, 0.350, 0.700, 700, true},
		{"D3-4 no retry, fast", []float64{0}, 0.150, 0.300, 300, false},
		{"several retries: the last SYN before the SYN-ACK counts", []float64{0, 1.0, 3.0}, 3.150, 3.310, 3310, false},
		{"several retries, the last one answered slowly", []float64{0, 1.0, 3.0}, 3.800, 3.810, 3810, true},
		{"no retry, exactly at the threshold is not slow", []float64{0}, 0.250, 0.500, 500, false},
		{"a retry whose minimum is exactly the threshold is not slow", []float64{0, 1.0}, 1.250, 1.500, 1500, false},
		{"a retry whose minimum is just over the threshold is slow", []float64{0, 1.0}, 1.250, 1.501, 1501, true},
		{"a SYN after the SYN-ACK is not a retry before it", []float64{0, 0.6}, 0.250, 0.700, 700, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := handshakeRun(tt.syns, tt.synAck, tt.ack)
			require.Len(t, res.Flows, 1)
			assert.InDelta(t, tt.wantSetup, res.Flows[0].SetupTimeMs, 0.01, "the reported setup time is the real one")
			assert.Equal(t, tt.wantSlow, hasIssue(res, "Slow TCP Handshake"))
			assert.Equal(t, len(tt.syns) > 1 && tt.syns[len(tt.syns)-1] < tt.synAck, hasIssue(res, titleSYNRetried), "SYN Retried Before Answer is as before")
		})
	}
}

func TestSlowHandshakeWithoutAFullHandshake(t *testing.T) {
	// A retry and no SYN-ACK, and a stamped flow without a final ACK: nothing to measure, nothing raised.
	pkts := withHandshake([]models.PacketInfo{tcpPkt(0, true, "SYN", 0, 0, 0), tcpPkt(1, true, "SYN", 0, 0, 0)}, 0, -1, -1, -1)
	flows, issues := applyPerformanceMetrics(pkts, aggregateFlows(pkts))
	require.Len(t, flows, 1)
	assert.Zero(t, flows[0].SetupTimeMs)
	assert.Empty(t, issues)

	pkts = []models.PacketInfo{tcpPkt(0, true, "SYN", 0, 0, 0), tcpPkt(1, true, "SYN", 0, 0, 0), tcpPkt(1.02, false, "SYN,ACK", 0, 1, 0)} // no Handshake stamp at all
	_, issues = applyPerformanceMetrics(pkts, aggregateFlows(pkts))
	assert.Empty(t, issues)
}

// Lab-4: the first SYN was lost, the retry was answered in about 30 ms.
func TestLab4SlowHandshakeIsExplainedByTheSYNRetry(t *testing.T) {
	res := Analyze(readReal(t, "Lab-4-NetworkCongestion.pcapng"), "all")
	require.Equal(t, 1, res.TotalFlows)
	f := res.Flows[0]
	assert.InDelta(t, 1030.77, f.SetupTimeMs, 0.01, "the real SYN to ACK time is still reported")
	assert.False(t, hasIssue(res, "Slow TCP Handshake"))
	assert.True(t, hasIssue(res, titleSYNRetried))
	assert.True(t, hasIssue(res, titleTimeoutRetransmit))
	assert.True(t, hasIssue(res, "Slow Server Response"))
	assert.Equal(t, 6, f.Retransmits)
	assert.Equal(t, 4, f.TimeoutRetransmits)
	assert.Equal(t, 2, f.RecoveryRetransmits)
	assert.Equal(t, 68, res.Diagnosis.HealthScore, "58 with the slow-handshake warning, 10 points more without it")
}
