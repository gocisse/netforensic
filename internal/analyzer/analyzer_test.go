package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestAnalyze(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	packets := []models.PacketInfo{
		{Timestamp: t0, SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80, Protocol: models.ProtocolTCP, Size: 100, PayloadSize: 5, TCPSeq: 1000, TCPFlags: "PSH,ACK"},
		{Timestamp: t0.Add(time.Second), SrcIP: "192.168.1.10", SrcPort: 54321, DstIP: "8.8.8.8", DstPort: 53, Protocol: models.ProtocolUDP, Size: 60, PayloadSize: 3},
	}
	tests := []struct {
		name        string
		packets     []models.PacketInfo
		service     string
		wantPackets int
		wantFlows   int
		wantTop     string
	}{
		{"all", packets, "all", 2, 2, "10.0.0.1:12345-10.0.0.2:80"},
		{"dns", packets, "dns", 1, 1, "192.168.1.10:54321-8.8.8.8:53"},
		{"http", packets, "http", 1, 1, "10.0.0.1:12345-10.0.0.2:80"},
		{"tls matches nothing", packets, "tls", 0, 0, ""},
		{"numeric port", packets, "53", 1, 1, "192.168.1.10:54321-8.8.8.8:53"},
		{"unknown service", packets, "ftp", 0, 0, ""},
		{"nil packets", nil, "all", 0, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(tt.packets, tt.service)
			require.NotNil(t, res)
			assert.Equal(t, tt.wantPackets, res.TotalPackets)
			assert.Equal(t, tt.wantFlows, res.TotalFlows)
			assert.Len(t, res.TopTalkers, tt.wantFlows)
			if tt.wantTop != "" {
				assert.Equal(t, tt.wantTop, res.TopTalkers[0].ID)
			}
		})
	}

	assert.Equal(t, "1s", Analyze(packets, "all").Duration)
}

func TestAnalyzeRetransmitIssue(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	data := models.PacketInfo{Timestamp: t0, SrcIP: "10.0.0.1", SrcPort: 1000, DstIP: "10.0.0.2", DstPort: 80, Protocol: models.ProtocolTCP, Size: 100, PayloadSize: 10, TCPSeq: 500, TCPFlags: "PSH,ACK"}
	res := Analyze([]models.PacketInfo{data, data}, "all")
	require.Len(t, res.Issues, 1)
	assert.Equal(t, "PacketLoss", res.Issues[0].Category)
	assert.Equal(t, models.SeverityWarning, res.Issues[0].Severity)
	assert.Equal(t, 1, res.TopTalkers[0].Retransmits)
}

func TestAggregateFlows(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	pkt := func(sec int, src string, sp uint16, dst string, dp uint16, proto models.Protocol, size int) models.PacketInfo {
		return models.PacketInfo{Timestamp: t0.Add(time.Duration(sec) * time.Second), SrcIP: src, SrcPort: sp, DstIP: dst, DstPort: dp, Protocol: proto, Size: size}
	}

	flows := aggregateFlows([]models.PacketInfo{
		pkt(0, "10.0.0.1", 1000, "10.0.0.2", 80, models.ProtocolTCP, 100),
		pkt(1, "10.0.0.2", 80, "10.0.0.1", 1000, models.ProtocolTCP, 300),
		pkt(2, "10.0.0.1", 1000, "10.0.0.2", 80, models.ProtocolTCP, 50),
		pkt(3, "10.0.0.1", 1000, "10.0.0.2", 80, models.ProtocolUDP, 10),
	})

	require.Len(t, flows, 2)
	tcp := flows[0]
	assert.Equal(t, "10.0.0.1:1000-10.0.0.2:80", tcp.ID)
	assert.Equal(t, 3, tcp.PacketCount)
	assert.Equal(t, 150, tcp.BytesSent)
	assert.Equal(t, 300, tcp.BytesRecv)
	assert.Equal(t, t0, tcp.StartTime)
	assert.Equal(t, t0.Add(2*time.Second), tcp.EndTime)
	assert.Equal(t, models.ProtocolUDP, flows[1].Protocol)

	// Reversed first packet must still yield the same canonical flow.
	rev := aggregateFlows([]models.PacketInfo{pkt(0, "10.0.0.2", 80, "10.0.0.1", 1000, models.ProtocolTCP, 70)})
	require.Len(t, rev, 1)
	assert.Equal(t, tcp.ID, rev[0].ID)
	assert.Equal(t, 0, rev[0].BytesSent)
	assert.Equal(t, 70, rev[0].BytesRecv)
}

func TestAggregateFlowsRetransmits(t *testing.T) {
	pkt := func(src string, sp uint16, dst string, dp uint16, seq uint32, payload int, flags string) models.PacketInfo {
		return models.PacketInfo{SrcIP: src, SrcPort: sp, DstIP: dst, DstPort: dp, Protocol: models.ProtocolTCP, Size: 60, PayloadSize: payload, TCPSeq: seq, TCPFlags: flags}
	}
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    int
	}{
		{"same seq same direction", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"), pkt("a", 1, "b", 2, 100, 10, "ACK")}, 1},
		{"same seq opposite directions", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"), pkt("b", 2, "a", 1, 100, 10, "ACK")}, 0},
		{"repeated bare acks", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 0, "ACK"), pkt("a", 1, "b", 2, 100, 0, "ACK")}, 0},
		{"retransmitted syn", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 0, "SYN"), pkt("a", 1, "b", 2, 100, 0, "SYN")}, 1},
		{"distinct seqs", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"), pkt("a", 1, "b", 2, 110, 10, "ACK")}, 0},
		{"repeated keep-alive probes are not retransmissions", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"),
			pkt("a", 1, "b", 2, 109, 1, "ACK"), pkt("a", 1, "b", 2, 109, 1, "ACK"), pkt("a", 1, "b", 2, 109, 1, "ACK")}, 0},
		{"keep-alive does not hide a later retransmission", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"), pkt("a", 1, "b", 2, 109, 1, "ACK"),
			pkt("a", 1, "b", 2, 100, 10, "ACK")}, 1},
		{"one-byte retransmission that is not a probe", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 1, "PSH,ACK"), pkt("a", 1, "b", 2, 101, 1, "PSH,ACK"),
			pkt("a", 1, "b", 2, 100, 1, "PSH,ACK")}, 1},
		{"one-byte segment repeating the last byte is a keep-alive", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 1, "ACK"), pkt("a", 1, "b", 2, 100, 1, "ACK")}, 0},
		{"fin is never a keep-alive", []models.PacketInfo{
			pkt("a", 1, "b", 2, 100, 10, "ACK"), pkt("a", 1, "b", 2, 109, 1, "FIN,ACK"), pkt("a", 1, "b", 2, 109, 1, "FIN,ACK")}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := aggregateFlows(tt.packets)
			require.Len(t, flows, 1)
			assert.Equal(t, tt.want, flows[0].Retransmits)
		})
	}
}

func TestDetectIssues(t *testing.T) {
	tests := []struct {
		name  string
		flows []models.Flow
		want  int
	}{
		{"no flows", nil, 0},
		{"clean flow", []models.Flow{{ID: "a"}}, 0},
		{"retransmits", []models.Flow{{ID: "a", Retransmits: 2}, {ID: "b"}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := detectIssues(tt.flows)
			assert.Len(t, issues, tt.want)
			for _, is := range issues {
				assert.Equal(t, models.SeverityWarning, is.Severity)
				assert.Equal(t, "PacketLoss", is.Category)
				assert.Equal(t, "TCP Retransmissions detected", is.Title)
			}
		})
	}
}

func TestTopTalkers(t *testing.T) {
	flows := []models.Flow{
		{ID: "a", BytesSent: 10}, {ID: "b", BytesSent: 50, BytesRecv: 50}, {ID: "c", BytesRecv: 30},
		{ID: "d"}, {ID: "e", BytesSent: 5}, {ID: "f", BytesSent: 1},
	}
	got := topTalkers(flows, 5)
	require.Len(t, got, 5)
	assert.Equal(t, "b", got[0].ID)
	assert.Equal(t, "c", got[1].ID)
	assert.Len(t, flows, 6, "input must not be modified")
}

// TestPortReuseAfterRefusal is the Lab-6 pattern: a client SYN is refused
// with RST,ACK and the client retries from the same source port.
func TestPortReuseAfterRefusal(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	pkt := func(ms int, fromClient bool, flags string, seq uint32) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, Size: 66, TCPFlags: flags, TCPSeq: seq}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "192.168.1.1", 49979, "53.235.100.201", 443
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "53.235.100.201", 443, "192.168.1.1", 49979
		}
		return p
	}

	t.Run("refused SYN then new SYN is two flows", func(t *testing.T) {
		flows := aggregateFlows([]models.PacketInfo{
			pkt(0, true, "SYN", 1000),
			pkt(1, false, "RST,ACK", 2000),
			pkt(500, true, "SYN", 3000),
		})
		require.Len(t, flows, 2)
		assert.Equal(t, "192.168.1.1:49979-53.235.100.201:443", flows[0].ID)
		assert.Equal(t, "192.168.1.1:49979-53.235.100.201:443#2", flows[1].ID)
		assert.Equal(t, 2, flows[0].PacketCount)
		assert.Equal(t, 1, flows[1].PacketCount)
		assert.Zero(t, flows[0].Retransmits)
		assert.Zero(t, flows[1].Retransmits, "the second SYN is a new attempt, not a retransmission")
	})

	t.Run("same SYN sequence number after a reset is still a new flow", func(t *testing.T) {
		flows := aggregateFlows([]models.PacketInfo{
			pkt(0, true, "SYN", 1000),
			pkt(1, false, "RST,ACK", 0),
			pkt(500, true, "SYN", 1000),
		})
		require.Len(t, flows, 2)
		assert.Zero(t, flows[0].Retransmits+flows[1].Retransmits)
	})

	t.Run("a SYN repeated without a close is a retransmission", func(t *testing.T) {
		flows := aggregateFlows([]models.PacketInfo{
			pkt(0, true, "SYN", 1000),
			pkt(1000, true, "SYN", 1000),
			pkt(1030, false, "SYN,ACK", 5000),
		})
		require.Len(t, flows, 1)
		assert.Equal(t, 1, flows[0].Retransmits)
	})

	t.Run("full analysis reports no packet loss and per-attempt handshake timing", func(t *testing.T) {
		// attempt 1 refused; attempt 2 completes in 40ms, 1s after the first SYN
		packets := []models.PacketInfo{
			pkt(0, true, "SYN", 1000),
			pkt(1, false, "RST,ACK", 0),
			pkt(1000, true, "SYN", 3000),
			pkt(1020, false, "SYN,ACK", 5000),
			pkt(1040, true, "ACK", 3001),
		}
		// the reader stamps handshake times per connection; mimic that
		insts := models.ConnectionInstances(packets)
		for i := range packets {
			if insts[i] == 1 {
				packets[i].TCPSynTime = t0.Add(1000 * time.Millisecond)
				packets[i].TCPSynAckTime = t0.Add(1020 * time.Millisecond)
				packets[i].TCPAckTime = t0.Add(1040 * time.Millisecond)
			}
		}
		res := Analyze(packets, "all")
		assert.Equal(t, 2, res.TotalFlows)
		for _, is := range res.Issues {
			assert.NotEqual(t, "PacketLoss", is.Category, is.Description)
			assert.NotEqual(t, "Slow TCP Handshake", is.Title, is.Description)
		}
	})
}

func TestListFlowsAndFollowSeparateReusedPorts(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	mk := func(ms int, fromClient bool, flags string, payload string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags,
			PayloadSize: len(payload), Payload: []byte(payload)}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "1.1.1.1", 5000, "2.2.2.2", 80
			p.TCPSeq = 100
			if payload == "second" {
				p.TCPSeq = 101 // follows the SYN, which uses 100
			}
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "2.2.2.2", 80, "1.1.1.1", 5000
			p.TCPSeq = 900
		}
		return p
	}
	packets := []models.PacketInfo{
		mk(0, true, "PSH,ACK", "first"), mk(1, false, "RST,ACK", ""),
		mk(10, true, "SYN", ""), mk(11, true, "PSH,ACK", "second"),
	}

	var ids []string
	for _, f := range ListFlows(packets) {
		ids = append(ids, f.ID)
	}
	assert.ElementsMatch(t, []string{"1.1.1.1:5000-2.2.2.2:80", "1.1.1.1:5000-2.2.2.2:80#2"}, ids)

	conv, err := FollowStream(packets, "1.1.1.1:5000-2.2.2.2:80")
	require.NoError(t, err)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "first", string(conv.Messages[0].Data))
	assert.Equal(t, "1.1.1.1:5000-2.2.2.2:80", conv.FlowID)

	conv, err = FollowStream(packets, "1.1.1.1:5000-2.2.2.2:80#2")
	require.NoError(t, err)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "second", string(conv.Messages[0].Data))
	assert.Equal(t, "1.1.1.1:5000-2.2.2.2:80#2", conv.FlowID)
	assert.Zero(t, conv.Retransmits, "same sequence number as the first connection is not a retransmit")

	_, err = Follow(packets, "1.1.1.1:5000-2.2.2.2:80#3")
	assert.Error(t, err)
}
