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
// connection. So does a SYN without ACK that cannot belong to the connection
// even though nothing closed it, because the ports are being reused: its
// sequence number differs from that of the connection's own SYN, or, if the
// capture holds no SYN of the connection from that side, earlier traffic from
// that side does not begin at the byte after the SYN. A retransmitted SYN has
// the same sequence number and stays. Packets must be in capture order. Late
// packets of a closed connection (the final ACK of a FIN exchange, say) stay
// with it. Packets already stamped by AssignConnections keep their stamp.
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
		isn    [2]uint32 // the sequence number of the first SYN without ACK in each direction
		hasISN [2]bool
		first  [2]uint32 // the first sequence number seen in each direction, from any packet
		seen   [2]bool
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
		dir := 0 // the direction of p: 0 from the first endpoint, 1 from the second
		if p.SrcIP != src.ip || p.SrcPort != src.port {
			dir = 1
		}
		syn := has("SYN") && !has("ACK")
		if syn && (s.closed ||
			s.hasISN[dir] && p.TCPSeq != s.isn[dir] ||
			!s.hasISN[dir] && s.seen[dir] && s.first[dir] != p.TCPSeq+1) {
			*s = state{n: s.n + 1}
		}
		if !s.seen[dir] {
			s.first[dir], s.seen[dir] = p.TCPSeq, true
		}
		if syn && !s.hasISN[dir] {
			s.isn[dir], s.hasISN[dir] = p.TCPSeq, true
		}
		out[i] = s.n
		if has("FIN") || has("RST") {
			s.closed = true
		}
	}
	return out
}

// AssignStreams stamps every TCP packet in packets with the index of its TCP
// conversation, numbered from 0 in order of first appearance, which is how
// Wireshark numbers tcp.stream. A conversation is the traffic between the same
// two endpoints (inside the same tunnel); like Wireshark, a SYN without ACK
// that follows a FIN or RST, or whose sequence number differs from the first
// one seen in its direction, starts a new conversation, because the port pair
// is being reused. Packets
// must be in capture order, and be the whole capture: a filtered list would
// number differently.
func AssignStreams(packets []PacketInfo) {
	type endpoint struct {
		ip   string
		port uint16
	}
	type pair struct {
		a, b   endpoint
		tunnel string
	}
	type conversation struct {
		stream int
		base   [2]uint32 // the first sequence number seen in each direction
		seen   [2]bool
		closed bool // a FIN or RST has been seen
	}
	current := make(map[pair]*conversation)
	next := 0

	// place puts a TCP segment, real or quoted, in its conversation and
	// returns the conversation's stream.
	place := func(sip string, sport uint16, dip string, dport uint16, tunnel, flags string, seq uint32) int {
		src, dst := endpoint{sip, sport}, endpoint{dip, dport}
		dir := 0
		if dst.ip < src.ip || (dst.ip == src.ip && dst.port < src.port) {
			src, dst = dst, src
			dir = 1
		}
		k := pair{src, dst, TunnelKey(tunnel)}
		c := current[k]
		syn := hasFlag(flags, "SYN") && !hasFlag(flags, "ACK")
		if c != nil && syn && (c.closed || (c.seen[dir] && seq != c.base[dir])) {
			c = nil // the ports are reused: a new conversation
		}
		if c == nil {
			c = &conversation{stream: next}
			next++
			current[k] = c
		}
		if !c.seen[dir] {
			c.base[dir], c.seen[dir] = seq, true
		}
		if hasFlag(flags, "FIN") || hasFlag(flags, "RST") {
			c.closed = true
		}
		return c.stream
	}

	for i, p := range packets {
		switch {
		case p.Protocol == ProtocolICMP && p.ICMPOrigFullTCP:
			// Wireshark also dissects the TCP header that an ICMP error quotes,
			// if the error quotes all of it (most routers send only the first
			// 8 bytes, which it leaves alone), and treats it like any segment:
			// it can start a conversation and take a number.
			place(p.ICMPOrigSrcIP, p.ICMPOrigSrcPort, p.ICMPOrigDstIP, p.ICMPOrigDstPort, p.Tunnel, p.ICMPOrigTCPFlags, p.ICMPOrigTCPSeq)
		case p.Protocol == ProtocolTCP:
			packets[i].Stream = place(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Tunnel, p.TCPFlags, p.TCPSeq)
			packets[i].StreamKnown = true
		}
	}
}

func hasFlag(flags, f string) bool {
	for _, x := range strings.Split(flags, ",") {
		if x == f {
			return true
		}
	}
	return false
}
