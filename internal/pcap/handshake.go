package pcap

import (
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

type hsEndpoint struct {
	ip   string
	port uint16
}

type hsKey struct {
	a, b   hsEndpoint
	tunnel string // the same inner 4-tuple in different tunnels is another connection
}

// hsFlowKey returns a direction-independent key for a TCP packet.
func hsFlowKey(p models.PacketInfo) hsKey {
	src, dst := hsEndpoint{p.SrcIP, p.SrcPort}, hsEndpoint{p.DstIP, p.DstPort}
	if dst.ip < src.ip || (dst.ip == src.ip && dst.port < src.port) {
		src, dst = dst, src
	}
	return hsKey{src, dst, models.TunnelKey(p.Tunnel)}
}

func hasFlag(flags, want string) bool {
	for _, f := range strings.Split(flags, ",") {
		if f == want {
			return true
		}
	}
	return false
}

// annotateHandshakes records, on every TCP packet of each flow, when the
// flow's handshake happened:
//
//   - TCPSynTime: the first SYN (without ACK); its sender is the client
//   - TCPSynAckTime: the first SYN-ACK from the server after that
//   - TCPAckTime: the first ACK from the client after the SYN-ACK (a reset is not one)
//   - FirstDataTime: the first packet with payload from the server after that ACK
//
// Events that were not captured stay zero. Packets are processed in capture
// order, so the capture must be in chronological order. A 4-tuple reused
// after a FIN or RST (see models.ConnectionInstances) is annotated as a
// separate connection per SYN.
func annotateHandshakes(packets []models.PacketInfo) {
	// Each connection attempt on a reused 4-tuple gets its own handshake.
	type connKey struct {
		hsKey
		inst int
	}
	flows := make(map[connKey][]int)
	insts := models.ConnectionInstances(packets)
	for i, p := range packets {
		if p.Protocol == models.ProtocolTCP {
			k := connKey{hsFlowKey(p), insts[i]}
			flows[k] = append(flows[k], i)
		}
	}

	for _, idx := range flows {
		syn := -1
		for _, i := range idx {
			if hasFlag(packets[i].TCPFlags, "SYN") && !hasFlag(packets[i].TCPFlags, "ACK") {
				syn = i
				break
			}
		}
		if syn < 0 {
			continue
		}
		client := hsEndpoint{packets[syn].SrcIP, packets[syn].SrcPort}
		fromClient := func(p models.PacketInfo) bool { return (hsEndpoint{p.SrcIP, p.SrcPort}) == client }

		synAck, ack, data := -1, -1, -1
		for _, i := range idx {
			if i <= syn {
				continue
			}
			p := packets[i]
			switch {
			case synAck < 0:
				if !fromClient(p) && hasFlag(p.TCPFlags, "SYN") && hasFlag(p.TCPFlags, "ACK") {
					synAck = i
				}
			case ack < 0:
				if fromClient(p) && hasFlag(p.TCPFlags, "ACK") && !hasFlag(p.TCPFlags, "SYN") && !hasFlag(p.TCPFlags, "RST") {
					ack = i
				}
			case data < 0:
				if !fromClient(p) && p.PayloadSize > 0 {
					data = i
				}
			}
		}

		hs := &models.HandshakeTimes{TCPSynTime: packets[syn].Timestamp}
		if synAck >= 0 {
			hs.TCPSynAckTime = packets[synAck].Timestamp
		}
		if ack >= 0 {
			hs.TCPAckTime = packets[ack].Timestamp
		}
		if data >= 0 {
			hs.FirstDataTime = packets[data].Timestamp
		}
		for _, i := range idx {
			packets[i].Handshake = hs // one object per connection instance
		}
	}
}
