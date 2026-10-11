package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// inTunnel marks packets as having come out of a tunnel.
func inTunnel(tunnel string, pkts ...models.PacketInfo) []models.PacketInfo {
	for i := range pkts {
		pkts[i].Tunnel = tunnel
	}
	return pkts
}

// dataSegment is a data segment of the standard test connection.
func dataSegment(sec float64, fromClient bool, seq uint32) models.PacketInfo {
	return tcpPkt(sec, fromClient, "PSH,ACK", seq, 1, 100)
}

func TestFlowsInDifferentTunnelsDoNotMerge(t *testing.T) {
	// The same inner 4-tuple and sequence numbers inside two GRE tunnels
	// between different outer endpoints are two connections. Merged, the
	// second tunnel's segments would look like retransmissions of the first's.
	var pkts []models.PacketInfo
	pkts = append(pkts, inTunnel("192.0.2.1>192.0.2.2/GRE", dataSegment(0, true, 100), dataSegment(1, true, 200))...)
	pkts = append(pkts, inTunnel("198.51.100.1>198.51.100.2/GRE", dataSegment(2, true, 100), dataSegment(3, true, 200))...)

	flows := aggregateFlows(pkts)
	require.Len(t, flows, 2)

	ids := []string{flows[0].ID, flows[1].ID}
	assert.ElementsMatch(t, []string{
		"10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2",
		"10.0.0.1:1000-10.0.0.2:80@GRE:198.51.100.1~198.51.100.2",
	}, ids)
	for _, f := range flows {
		assert.Zero(t, f.Retransmits, f.ID)
		assert.Equal(t, 2, f.PacketCount, f.ID)
		assert.NotEmpty(t, f.Tunnel)
	}
}

func TestBothDirectionsOfOneTunnelShareAFlow(t *testing.T) {
	// The outer addresses swap with the direction of travel; the flow must
	// not split because of it.
	pkts := []models.PacketInfo{
		inTunnel("192.0.2.1>192.0.2.2/GRE", dataSegment(0, true, 100))[0],
		inTunnel("192.0.2.2>192.0.2.1/GRE", dataSegment(1, false, 500))[0],
	}
	flows := aggregateFlows(pkts)
	require.Len(t, flows, 1)
	assert.Equal(t, 2, flows[0].PacketCount)
	assert.Equal(t, "GRE:192.0.2.1~192.0.2.2", flows[0].Tunnel)
}

func TestTunnelledAndPlainFlowsStaySeparate(t *testing.T) {
	pkts := append([]models.PacketInfo{dataSegment(0, true, 100)},
		inTunnel("192.0.2.1>192.0.2.2/IP-in-IP", dataSegment(1, true, 100))...)
	flows := aggregateFlows(pkts)
	require.Len(t, flows, 2)
	for _, f := range flows {
		assert.Zero(t, f.Retransmits)
	}
}

func TestConnectionInstancesPerTunnel(t *testing.T) {
	// A new SYN after a RST is a new connection, but only within one tunnel.
	syn := func(sec float64, tunnel string) models.PacketInfo {
		return inTunnel(tunnel, tcpPkt(sec, true, "SYN", 1, 0, 0))[0]
	}
	rst := func(sec float64, tunnel string) models.PacketInfo {
		return inTunnel(tunnel, tcpPkt(sec, true, "RST", 2, 0, 0))[0]
	}
	pkts := []models.PacketInfo{
		syn(0, "192.0.2.1>192.0.2.2/GRE"),
		rst(1, "192.0.2.1>192.0.2.2/GRE"),
		syn(2, "198.51.100.1>198.51.100.2/GRE"), // first connection in the other tunnel
		syn(3, "192.0.2.1>192.0.2.2/GRE"),       // second connection in the first tunnel
	}
	assert.Equal(t, []int{0, 0, 0, 1}, models.ConnectionInstances(pkts))
}

func TestFollowTunnelledFlow(t *testing.T) {
	var pkts []models.PacketInfo
	pkts = append(pkts, inTunnel("192.0.2.1>192.0.2.2/GRE", dataSegment(0, true, 100), dataSegment(1, false, 500))...)
	pkts = append(pkts, inTunnel("198.51.100.1>198.51.100.2/GRE", dataSegment(2, true, 100))...)

	conv, err := Follow(pkts, "10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2", conv.FlowID)
	assert.Len(t, conv.Events, 2, "only the packets of that tunnel")

	// the tunnel's outer addresses may be given in either order
	conv, err = Follow(pkts, "10.0.0.1:1000-10.0.0.2:80@GRE:198.51.100.1~198.51.100.2")
	require.NoError(t, err)
	assert.Len(t, conv.Events, 1)

	// without the tunnel the flow is not found, and the listing shows how to name it
	_, err = Follow(pkts, "10.0.0.1:1000-10.0.0.2:80")
	var fe *FollowError
	require.ErrorAs(t, err, &fe)
	require.Len(t, fe.Available, 2)
	assert.Contains(t, fe.Available[0].ID, "@GRE:")
}

func TestTunnelKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.0.2.1>192.0.2.2/GRE", "GRE:192.0.2.1~192.0.2.2"},
		{"192.0.2.2>192.0.2.1/GRE", "GRE:192.0.2.1~192.0.2.2"},
		{"2001:db8::2>2001:db8::1/IPv6-in-IPv6", "IPv6-in-IPv6:2001:db8::1~2001:db8::2"},
		{"", ""},
		{"garbage", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, models.TunnelKey(tt.in), tt.in)
	}
}

func TestDecapsulatedNote(t *testing.T) {
	plain := dataSegment(0, true, 100)
	var pkts []models.PacketInfo
	pkts = append(pkts, plain)
	pkts = append(pkts, inTunnel("192.0.2.1>192.0.2.2/GRE", dataSegment(1, true, 200), dataSegment(2, false, 500))...)
	pkts = append(pkts, inTunnel("192.0.2.3>192.0.2.4/6in4", dataSegment(3, true, 300))...)

	res := Analyze(pkts, "all")
	var note *models.Issue
	for i := range res.Issues {
		if res.Issues[i].Title == titleDecapsulated {
			note = &res.Issues[i]
		}
	}
	require.NotNil(t, note, "a note says that packets were decapsulated")
	assert.Equal(t, models.SeverityInfo, note.Severity)
	assert.Equal(t, "Capture", note.Category)
	assert.Equal(t, 3, note.Count)
	assert.Equal(t, at(0), note.Timestamp, "anchored at the start of the capture")
	assert.Equal(t, "3 packets were decapsulated from tunnels (6in4: 1, GRE: 2) and analyzed by their inner addresses and ports. "+
		"Encrypted tunnels such as ESP cannot be decapsulated.", note.Description)

	// Like the skipped-frames note, it costs no health points.
	assert.True(t, isNote(*note))
	var without []models.Issue
	for _, is := range res.Issues {
		if is.Title != titleDecapsulated {
			without = append(without, is)
		}
	}
	assert.Equal(t, healthScore(without), res.Diagnosis.HealthScore)

	// And there is no note without tunnels.
	clean := Analyze(pkts[:1], "all")
	for _, is := range clean.Issues {
		assert.NotEqual(t, titleDecapsulated, is.Title)
	}
}
