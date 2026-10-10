package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
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
		pkts[i].TCPSynTime, pkts[i].TCPSynAckTime, pkts[i].TCPAckTime, pkts[i].FirstDataTime = t(syn), t(synAck), t(ack), t(data)
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
			pkts := withHandshake([]models.PacketInfo{tcpPkt(0, true, "ACK", 1, 1, 0)}, tt.syn, tt.synAck, tt.ack, tt.dat)
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
		{"high latency", models.Flow{ID: "f", AvgRTTMs: 200.01}, []string{"High Network Latency"}},
		{"high jitter", models.Flow{ID: "f", MaxRTTMs: 500.01}, []string{"High Jitter"}},
		{"everything", models.Flow{ID: "f", SetupTimeMs: 900, TTFBMs: 2000, AvgRTTMs: 300, MaxRTTMs: 900},
			[]string{"Slow TCP Handshake", "Slow Server Response", "High Network Latency", "High Jitter"}},
	}
	sev := map[string]models.Severity{
		"Slow TCP Handshake": models.SeverityWarning, "Slow Server Response": models.SeverityWarning,
		"High Network Latency": models.SeverityInfo, "High Jitter": models.SeverityWarning,
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
