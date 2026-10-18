package pcap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// hsOf returns the handshake times of p, or the zero value if it has none.
func hsOf(p models.PacketInfo) models.HandshakeTimes {
	if p.Handshake == nil {
		return models.HandshakeTimes{}
	}
	return *p.Handshake
}

func TestHandshakeObjectLifecycle(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	pk := func(ms int, port uint16, fromClient bool, flags string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", port, "10.0.0.2", 443
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 443, "10.0.0.1", port
		}
		return p
	}
	packets := []models.PacketInfo{
		pk(0, 5000, true, "SYN"), pk(1, 5000, false, "RST,ACK"), // refused, same 4-tuple as the next
		pk(1000, 5000, true, "SYN"), pk(1020, 5000, false, "SYN,ACK"), pk(1040, 5000, true, "ACK"),
		pk(10, 6000, true, "ACK"), pk(11, 6000, false, "ACK"), // captured mid-connection: no SYN
	}
	annotateHandshakes(packets)
	require.NotNil(t, packets[0].Handshake)
	assert.Same(t, packets[0].Handshake, packets[1].Handshake, "one object per connection")
	assert.Same(t, packets[2].Handshake, packets[4].Handshake)
	assert.NotSame(t, packets[0].Handshake, packets[2].Handshake, "a reused 4-tuple is another connection")
	assert.Equal(t, t0.Add(time.Second), packets[2].Handshake.TCPSynTime)
	assert.Nil(t, packets[5].Handshake, "no SYN, no timeline")
	assert.Nil(t, packets[6].Handshake)
}
