package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func connPkt(fromClient bool, flags string) PacketInfo {
	p := PacketInfo{Protocol: ProtocolTCP, TCPFlags: flags}
	if fromClient {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 5000, "10.0.0.2", 443
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 443, "10.0.0.1", 5000
	}
	return p
}

func TestConnectionInstances(t *testing.T) {
	tests := []struct {
		name  string
		steps []PacketInfo
		want  []int
	}{
		{"single connection", []PacketInfo{connPkt(true, "SYN"), connPkt(false, "SYN,ACK"), connPkt(true, "ACK"), connPkt(true, "FIN,ACK"), connPkt(false, "FIN,ACK"), connPkt(true, "ACK")},
			[]int{0, 0, 0, 0, 0, 0}},
		{"syn after rst starts a new connection", []PacketInfo{connPkt(true, "SYN"), connPkt(false, "RST,ACK"), connPkt(true, "SYN")},
			[]int{0, 0, 1}},
		{"syn after fin starts a new connection", []PacketInfo{connPkt(true, "FIN,ACK"), connPkt(true, "SYN"), connPkt(false, "SYN,ACK")},
			[]int{0, 1, 1}},
		{"repeated syn without a close is a retransmission", []PacketInfo{connPkt(true, "SYN"), connPkt(true, "SYN")},
			[]int{0, 0}},
		{"late packets of a closed connection stay with it", []PacketInfo{connPkt(true, "RST"), connPkt(false, "ACK"), connPkt(true, "SYN"), connPkt(true, "RST"), connPkt(false, "RST,ACK"), connPkt(true, "SYN")},
			[]int{0, 0, 1, 1, 1, 2}},
		{"syn-ack does not open a new connection", []PacketInfo{connPkt(true, "RST"), connPkt(false, "SYN,ACK")},
			[]int{0, 0}},
		{"non-tcp is always 0", []PacketInfo{{Protocol: ProtocolUDP}, {Protocol: ProtocolICMP}},
			[]int{0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConnectionInstances(tt.steps))
		})
	}

	t.Run("different 4-tuples are independent", func(t *testing.T) {
		other := connPkt(true, "SYN")
		other.SrcPort = 6000
		got := ConnectionInstances([]PacketInfo{connPkt(true, "RST"), other, connPkt(true, "SYN")})
		assert.Equal(t, []int{0, 0, 1}, got)
	})
	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, ConnectionInstances(nil))
	})
}

func TestAssignConnectionsSurvivesFiltering(t *testing.T) {
	all := []PacketInfo{connPkt(true, "SYN"), connPkt(false, "RST,ACK"), connPkt(true, "SYN"), connPkt(false, "SYN,ACK")}
	AssignConnections(all)
	assert.Equal(t, []int{0, 0, 1, 1}, []int{all[0].Conn, all[1].Conn, all[2].Conn, all[3].Conn})

	// keep only the client's packets: the RST that separated the attempts is gone
	var clientOnly []PacketInfo
	for _, p := range all {
		if p.SrcPort == 5000 {
			clientOnly = append(clientOnly, p)
		}
	}
	assert.Equal(t, []int{0, 1}, ConnectionInstances(clientOnly))

	// without the stamp the filtered list would merge the attempts
	for i := range clientOnly {
		clientOnly[i].ConnKnown = false
	}
	assert.Equal(t, []int{0, 0}, ConnectionInstances(clientOnly))

	// non-TCP packets are never stamped
	udp := []PacketInfo{{Protocol: ProtocolUDP}}
	AssignConnections(udp)
	assert.False(t, udp[0].ConnKnown)
}
