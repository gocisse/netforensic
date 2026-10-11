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
