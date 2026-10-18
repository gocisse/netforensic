package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestAssignStreams(t *testing.T) {
	pk := func(src string, sport uint16, dst string, dport uint16, flags string, seq uint32) PacketInfo {
		return PacketInfo{Protocol: ProtocolTCP, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport, TCPFlags: flags, TCPSeq: seq}
	}
	udp := PacketInfo{Protocol: ProtocolUDP, SrcIP: "10.0.0.1", SrcPort: 5, DstIP: "10.0.0.2", DstPort: 6}

	tests := []struct {
		name    string
		packets []PacketInfo
		want    []int // the stream of each packet; -1 for none
	}{
		{"streams are numbered in order of first appearance", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 1),
			pk("10.0.0.3", 2000, "10.0.0.2", 80, "SYN", 1),
			pk("10.0.0.1", 1000, "10.0.0.4", 443, "SYN", 1),
		}, []int{0, 1, 2}},
		{"both directions of a connection share a stream", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "SYN,ACK", 500),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "ACK", 101),
			pk("10.0.0.3", 2000, "10.0.0.2", 80, "SYN", 1),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "ACK", 501),
		}, []int{0, 0, 0, 1, 0}},
		{"a SYN retransmitted with the same sequence number stays in its stream", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
		}, []int{0, 0}},
		{"a SYN after a RST starts a new stream, even with the same sequence number", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "RST,ACK", 0),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "RST,ACK", 0),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
		}, []int{0, 0, 1, 1, 2}},
		{"a SYN after a FIN starts a new stream", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "FIN,ACK", 100),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 900),
		}, []int{0, 1}},
		{"a SYN with another sequence number is a new connection on a reused port, closed or not", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "ACK", 101),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 7777),
		}, []int{0, 0, 1}},
		{"a capture that starts mid-connection: the first data sets the base", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "PSH,ACK", 5000),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "ACK", 5100),
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 42), // a new connection
		}, []int{0, 0, 1}},
		{"a SYN-ACK does not start a stream of its own", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 100),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "SYN,ACK", 500),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "SYN,ACK", 500),
		}, []int{0, 0, 0}},
		{"other protocols are not streams, and do not take a number", []PacketInfo{
			udp,
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 1),
			udp,
		}, []int{-1, 0, -1}},
		{"the same ports inside different tunnels are different streams", []PacketInfo{
			{Protocol: ProtocolTCP, SrcIP: "10.0.0.1", SrcPort: 1, DstIP: "10.0.0.2", DstPort: 2, TCPFlags: "SYN", Tunnel: "192.0.2.1>192.0.2.2/GRE"},
			{Protocol: ProtocolTCP, SrcIP: "10.0.0.1", SrcPort: 1, DstIP: "10.0.0.2", DstPort: 2, TCPFlags: "SYN", Tunnel: "198.51.100.1>198.51.100.2/GRE"},
			{Protocol: ProtocolTCP, SrcIP: "10.0.0.2", SrcPort: 2, DstIP: "10.0.0.1", DstPort: 1, TCPFlags: "SYN,ACK", Tunnel: "192.0.2.2>192.0.2.1/GRE"}, // the other direction of the first
		}, []int{0, 1, 0}},
		{"an ICMP error that quotes a whole TCP header takes a number for a connection it has not seen", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 1),
			{Protocol: ProtocolICMP, ICMPOrigFullTCP: true, ICMPOrigSrcIP: "10.0.0.5", ICMPOrigSrcPort: 5000, ICMPOrigDstIP: "10.0.0.6", ICMPOrigDstPort: 443, ICMPOrigTCPFlags: "SYN", ICMPOrigTCPSeq: 77},
			pk("10.0.0.3", 3000, "10.0.0.2", 80, "SYN", 1),
		}, []int{0, -1, 2}},
		{"...and joins the conversation of one it has", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "PSH,ACK", 50),
			{Protocol: ProtocolICMP, ICMPOrigFullTCP: true, ICMPOrigSrcIP: "10.0.0.1", ICMPOrigSrcPort: 1000, ICMPOrigDstIP: "10.0.0.2", ICMPOrigDstPort: 80, ICMPOrigTCPFlags: "PSH,ACK", ICMPOrigTCPSeq: 50},
			pk("10.0.0.3", 3000, "10.0.0.2", 80, "SYN", 1),
		}, []int{0, -1, 1}},
		{"a quoted SYN after a RST starts a new conversation, like any SYN", []PacketInfo{
			pk("10.0.0.1", 1000, "10.0.0.2", 80, "SYN", 1),
			pk("10.0.0.2", 80, "10.0.0.1", 1000, "RST,ACK", 0),
			{Protocol: ProtocolICMP, ICMPOrigFullTCP: true, ICMPOrigSrcIP: "10.0.0.1", ICMPOrigSrcPort: 1000, ICMPOrigDstIP: "10.0.0.2", ICMPOrigDstPort: 80, ICMPOrigTCPFlags: "SYN", ICMPOrigTCPSeq: 1},
			pk("10.0.0.3", 3000, "10.0.0.2", 80, "SYN", 1),
		}, []int{0, 0, -1, 2}},
		{"an ICMP error that quotes only the ports is not a TCP segment", []PacketInfo{
			{Protocol: ProtocolICMP, ICMPOrigProto: "TCP", ICMPOrigSrcIP: "10.0.0.5", ICMPOrigSrcPort: 5000, ICMPOrigDstIP: "10.0.0.6", ICMPOrigDstPort: 443},
			pk("10.0.0.3", 3000, "10.0.0.2", 80, "SYN", 1),
		}, []int{-1, 0}},
		{"IPv6 endpoints", []PacketInfo{
			pk("2001:db8::1", 1, "2001:db8::2", 2, "SYN", 1),
			pk("2001:db8::2", 2, "2001:db8::1", 1, "SYN,ACK", 9),
		}, []int{0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkts := append([]PacketInfo(nil), tt.packets...)
			AssignStreams(pkts)
			for i, p := range pkts {
				if tt.want[i] < 0 {
					assert.False(t, p.StreamKnown, "packet %d", i)
					continue
				}
				assert.True(t, p.StreamKnown, "packet %d", i)
				assert.Equal(t, tt.want[i], p.Stream, "packet %d", i)
			}
		})
	}
}

// connSeq is connPkt with a sequence number.
func connSeq(fromClient bool, flags string, seq uint32) PacketInfo {
	p := connPkt(fromClient, flags)
	p.TCPSeq = seq
	return p
}

// A SYN without ACK that has another ISN than the connection's own is a new
// connection even if no FIN or RST closed the old one; a retransmitted SYN
// (same ISN), and anything with ACK, is not.
func TestConnectionInstancesSplitOnANewISN(t *testing.T) {
	data := func(fromClient bool, seq uint32) PacketInfo { return connSeq(fromClient, "PSH,ACK", seq) }
	tests := []struct {
		name  string
		steps []PacketInfo
		want  []int
	}{
		{"R1 reuse with a new ISN, no FIN or RST",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "ACK", 1001), data(true, 1001), data(false, 5001),
				connSeq(true, "SYN", 9000), connSeq(false, "SYN,ACK", 7000), connSeq(true, "ACK", 9001)},
			[]int{0, 0, 0, 0, 0, 1, 1, 1}},
		{"R2 a retransmitted SYN has the same ISN",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "ACK", 1001)},
			[]int{0, 0, 0, 0}},
		{"R3 a new ISN after the SYN-ACK of an established connection",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "ACK", 1001), connSeq(true, "SYN", 9000), connSeq(false, "SYN,ACK", 7000)},
			[]int{0, 0, 0, 1, 1}},
		{"R4 a SYN-ACK never starts a connection, whatever its ISN",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(false, "SYN,ACK", 6000)},
			[]int{0, 0, 0}},
		{"SYNs with changing ISNs and no answer are separate attempts",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(true, "SYN", 2000), connSeq(true, "SYN", 3000), connSeq(true, "ACK", 3001)},
			[]int{0, 1, 2, 2}},
		{"the SYN-ACK answers the second ISN",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(true, "SYN", 2000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "ACK", 2001)},
			[]int{0, 1, 1, 1}},
		{"R5 after a FIN, a new ISN splits (as always); late packets stay",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(true, "FIN,ACK", 1001), connSeq(false, "ACK", 5000), connSeq(true, "SYN", 9000)},
			[]int{0, 0, 0, 1}},
		{"R5 after a RST, the same ISN splits too (as always)",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "RST,ACK", 0), connSeq(true, "SYN", 1000)},
			[]int{0, 0, 1}},
		{"R7 the capture starts mid-session: a SYN with an unrelated ISN is a new connection",
			[]PacketInfo{data(true, 5000), data(false, 100), connSeq(true, "SYN", 9000), connSeq(false, "SYN,ACK", 7000)},
			[]int{0, 0, 1, 1}},
		{"R8 data recorded before its own SYN is the same connection",
			[]PacketInfo{data(true, 1001), connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "ACK", 1001), connSeq(true, "SYN", 1000)},
			[]int{0, 0, 0, 0, 0}},
		{"R9 the ISN+1 comparison wraps around",
			[]PacketInfo{data(true, 0), connSeq(true, "SYN", 0xFFFFFFFF)},
			[]int{0, 0}},
		{"R9 and so does the retransmission of a wrapped SYN",
			[]PacketInfo{connSeq(true, "SYN", 0xFFFFFFFF), connSeq(true, "SYN", 0xFFFFFFFF), connSeq(true, "ACK", 0)},
			[]int{0, 0, 0}},
		{"a SYN from the other side has its own history",
			[]PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "SYN", 4000), connSeq(true, "SYN", 1000), connSeq(false, "SYN", 4000)},
			[]int{0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConnectionInstances(tt.steps))
		})
	}

	t.Run("R6 the same ports in two tunnels are independent", func(t *testing.T) {
		a, b := connSeq(true, "SYN", 1000), connSeq(true, "SYN", 2000)
		a.Tunnel, b.Tunnel = "192.0.2.1>192.0.2.2/GRE", "198.51.100.1>198.51.100.2/GRE"
		assert.Equal(t, []int{0, 0}, ConnectionInstances([]PacketInfo{a, b}))
		b.Tunnel = a.Tunnel
		assert.Equal(t, []int{0, 1}, ConnectionInstances([]PacketInfo{a, b}), "the same tunnel: another ISN, another connection")
	})
	t.Run("R10 stamped packets keep their stamp", func(t *testing.T) {
		a, b := connSeq(true, "SYN", 1000), connSeq(true, "SYN", 2000)
		a.Conn, a.ConnKnown, b.Conn, b.ConnKnown = 3, true, 3, true
		assert.Equal(t, []int{3, 3}, ConnectionInstances([]PacketInfo{a, b}))
	})
	t.Run("R11 the numbering survives filtering", func(t *testing.T) {
		all := []PacketInfo{connSeq(true, "SYN", 1000), connSeq(false, "SYN,ACK", 5000), connSeq(true, "SYN", 9000), connSeq(false, "SYN,ACK", 7000), connSeq(true, "ACK", 9001)}
		AssignConnections(all)
		require.Equal(t, []int{0, 0, 1, 1, 1}, []int{all[0].Conn, all[1].Conn, all[2].Conn, all[3].Conn, all[4].Conn})
		second := all[2:] // the capture filtered to the second connection
		assert.Equal(t, []int{1, 1, 1}, ConnectionInstances(second), "unstamped recomputation would call it connection 0")
	})
}
