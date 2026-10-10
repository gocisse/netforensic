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
