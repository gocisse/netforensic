package models

import "strings"

// AssignConnections stamps every TCP packet in packets with its connection
// index (see ConnectionInstances) so the numbering survives later
// filtering of the packet list.
func AssignConnections(packets []PacketInfo) {
	for i, c := range ConnectionInstances(packets) {
		if packets[i].Protocol == ProtocolTCP {
			packets[i].Conn, packets[i].ConnKnown = c, true
		}
	}
}

// ConnectionInstances numbers the TCP connection attempts that share a
// 4-tuple, so that a reused source port is not mistaken for the same
// connection. It returns, for every packet in packets, the zero-based index
// of the connection it belongs to; non-TCP packets are always 0.
//
// A connection is closed once a FIN or RST has been seen on it. The next
// packet on that 4-tuple that carries SYN without ACK starts a new
// connection. Packets must be in capture order. Late packets of a closed
// connection (the final ACK of a FIN exchange, say) stay with it, and a SYN
// that arrives before any FIN or RST is an ordinary retransmission of the
// connection's SYN. Packets already stamped by AssignConnections keep their
// stamp.
func ConnectionInstances(packets []PacketInfo) []int {
	type endpoint struct {
		ip   string
		port uint16
	}
	type key struct {
		a, b   endpoint
		tunnel string // packets of one 4-tuple inside different tunnels are different connections
	}
	type state struct {
		n      int
		closed bool
	}

	out := make([]int, len(packets))
	states := make(map[key]*state)
	for i, p := range packets {
		if p.Protocol != ProtocolTCP {
			continue
		}
		if p.ConnKnown {
			out[i] = p.Conn
			continue
		}
		src, dst := endpoint{p.SrcIP, p.SrcPort}, endpoint{p.DstIP, p.DstPort}
		if dst.ip < src.ip || (dst.ip == src.ip && dst.port < src.port) {
			src, dst = dst, src
		}
		k := key{src, dst, TunnelKey(p.Tunnel)}
		s := states[k]
		if s == nil {
			s = &state{}
			states[k] = s
		}

		flags := strings.Split(p.TCPFlags, ",")
		has := func(f string) bool {
			for _, x := range flags {
				if x == f {
					return true
				}
			}
			return false
		}
		if s.closed && has("SYN") && !has("ACK") {
			s.n++
			s.closed = false
		}
		out[i] = s.n
		if has("FIN") || has("RST") {
			s.closed = true
		}
	}
	return out
}
