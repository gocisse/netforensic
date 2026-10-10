package pcap

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func arpFrame(t *testing.T, op uint16, senderMAC net.HardwareAddr, senderIP, targetIP net.IP) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: senderMAC, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: op, SourceHwAddress: senderMAC, SourceProtAddress: senderIP.To4(),
		DstHwAddress: make([]byte, 6), DstProtAddress: targetIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp))
	return buf.Bytes()
}

func TestReadPacketsICMPAndARP(t *testing.T) {
	icmp := func(typ, code uint8) []byte {
		return serialize(t, layers.IPProtocolICMPv4, net.IP{10, 0, 0, 254}, clientIP,
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, code)}, []byte{0, 0, 0, 0})
	}
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	path := filepath.Join(t.TempDir(), "l2l3.pcap")
	writePCAP(t, path, [][]byte{
		icmp(3, 3),
		icmp(11, 0),
		icmp(5, 1),
		icmp(8, 0),
		icmp(42, 7),
		arpFrame(t, layers.ARPRequest, mac, net.IP{10, 0, 0, 5}, net.IP{10, 0, 0, 1}),
		arpFrame(t, layers.ARPReply, mac, net.IP{10, 0, 0, 5}, net.IP{10, 0, 0, 1}),
	})

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 7)

	icmpTests := []struct {
		idx       int
		typ, code uint8
		msg       string
	}{
		{0, 3, 3, "Destination Unreachable: Port Unreachable"},
		{1, 11, 0, "Time Exceeded: TTL Exceeded in Transit"},
		{2, 5, 1, "Redirect: Redirect for Host"},
		{3, 8, 0, "Echo Request"},
		{4, 42, 7, "Type 42 Code 7"},
	}
	for _, tt := range icmpTests {
		p := got[tt.idx]
		assert.Equal(t, models.ProtocolICMP, p.Protocol)
		assert.Equal(t, tt.typ, p.ICMPType)
		assert.Equal(t, tt.code, p.ICMPCode)
		assert.Equal(t, tt.msg, p.ICMPMessage)
		assert.Equal(t, "10.0.0.254", p.SrcIP)
	}

	for i, op := range map[int]string{5: "request", 6: "reply"} {
		p := got[i]
		assert.Equal(t, models.ProtocolARP, p.Protocol)
		assert.Equal(t, op, p.ARPOperation)
		assert.Equal(t, "10.0.0.5", p.ARPSenderIP)
		assert.Equal(t, "10.0.0.1", p.ARPTargetIP)
		assert.Equal(t, "de:ad:be:ef:00:01", p.ARPSenderMAC)
		assert.Equal(t, "10.0.0.5", p.SrcIP)
		assert.Equal(t, "10.0.0.1", p.DstIP)
	}
}

func TestIcmpMessage(t *testing.T) {
	tests := []struct {
		typ, code uint8
		want      string
	}{
		{0, 0, "Echo Reply"},
		{3, 1, "Destination Unreachable: Host Unreachable"},
		{3, 200, "Destination Unreachable: Code 200"},
		{11, 1, "Time Exceeded: Fragment Reassembly Time Exceeded"},
		{8, 5, "Echo Request: Code 5"},
		{99, 0, "Type 99 Code 0"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, icmpMessage(tt.typ, tt.code))
	}
}

func tcpInfo(sec float64, fromClient bool, flags string, payload int) models.PacketInfo {
	p := models.PacketInfo{Timestamp: time.Unix(1700000000, 0).Add(time.Duration(sec * float64(time.Second))),
		Protocol: models.ProtocolTCP, TCPFlags: flags, PayloadSize: payload}
	if fromClient {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 40000, "10.0.0.2", 80
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 80, "10.0.0.1", 40000
	}
	return p
}

func TestAnnotateHandshakes(t *testing.T) {
	ts := func(sec float64) time.Time {
		return time.Unix(1700000000, 0).Add(time.Duration(sec * float64(time.Second)))
	}
	tests := []struct {
		name                         string
		pkts                         []models.PacketInfo
		wantSyn, wantSA, wantAck, wD time.Time
	}{
		{"full handshake then request and response",
			[]models.PacketInfo{
				tcpInfo(0, true, "SYN", 0), tcpInfo(0.1, false, "SYN,ACK", 0), tcpInfo(0.2, true, "ACK", 0),
				tcpInfo(0.3, true, "PSH,ACK", 100), tcpInfo(0.9, false, "PSH,ACK", 500)},
			ts(0), ts(0.1), ts(0.2), ts(0.9)},
		{"handshake only",
			[]models.PacketInfo{tcpInfo(0, true, "SYN", 0), tcpInfo(0.1, false, "SYN,ACK", 0), tcpInfo(0.2, true, "ACK", 0)},
			ts(0), ts(0.1), ts(0.2), time.Time{}},
		{"syn retransmit: first syn is used",
			[]models.PacketInfo{tcpInfo(0, true, "SYN", 0), tcpInfo(1, true, "SYN", 0), tcpInfo(1.1, false, "SYN,ACK", 0), tcpInfo(1.2, true, "ACK", 0)},
			ts(0), ts(1.1), ts(1.2), time.Time{}},
		{"unanswered syn",
			[]models.PacketInfo{tcpInfo(0, true, "SYN", 0)},
			ts(0), time.Time{}, time.Time{}, time.Time{}},
		{"capture began mid-connection: nothing annotated",
			[]models.PacketInfo{tcpInfo(0, true, "PSH,ACK", 100), tcpInfo(0.1, false, "ACK", 0)},
			time.Time{}, time.Time{}, time.Time{}, time.Time{}},
		{"server data before the final ack is not first data",
			[]models.PacketInfo{tcpInfo(0, true, "SYN", 0), tcpInfo(0.1, false, "SYN,ACK", 0), tcpInfo(0.15, false, "PSH,ACK", 50), tcpInfo(0.2, true, "ACK", 0), tcpInfo(0.5, false, "PSH,ACK", 50)},
			ts(0), ts(0.1), ts(0.2), ts(0.5)},
		{"client data alone is not first data",
			[]models.PacketInfo{tcpInfo(0, true, "SYN", 0), tcpInfo(0.1, false, "SYN,ACK", 0), tcpInfo(0.2, true, "ACK", 0), tcpInfo(0.3, true, "PSH,ACK", 100)},
			ts(0), ts(0.1), ts(0.2), time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			annotateHandshakes(tt.pkts)
			for i, p := range tt.pkts {
				assert.True(t, tt.wantSyn.Equal(p.TCPSynTime), "packet %d syn", i)
				assert.True(t, tt.wantSA.Equal(p.TCPSynAckTime), "packet %d syn-ack", i)
				assert.True(t, tt.wantAck.Equal(p.TCPAckTime), "packet %d ack", i)
				assert.True(t, tt.wD.Equal(p.FirstDataTime), "packet %d first data", i)
			}
		})
	}
}

func TestAnnotateHandshakesSeparatesFlowsAndSkipsNonTCP(t *testing.T) {
	other := tcpInfo(5, true, "SYN", 0)
	other.SrcPort = 40001 // a second connection
	udp := models.PacketInfo{Timestamp: time.Unix(1700000000, 0), Protocol: models.ProtocolUDP, SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80}
	pkts := []models.PacketInfo{tcpInfo(0, true, "SYN", 0), other, udp}
	annotateHandshakes(pkts)
	assert.Equal(t, pkts[0].Timestamp, pkts[0].TCPSynTime)
	assert.Equal(t, pkts[1].Timestamp, pkts[1].TCPSynTime, "second flow has its own SYN")
	assert.NotEqual(t, pkts[0].TCPSynTime, pkts[1].TCPSynTime)
	assert.True(t, pkts[2].TCPSynTime.IsZero(), "UDP untouched")
}

func TestReadPacketsHandshakeEndToEnd(t *testing.T) {
	tcp := func(fromClient bool, flags layers.TCP, payload []byte) []byte {
		src, dst, sp, dp := clientIP, serverIP, layers.TCPPort(40000), layers.TCPPort(80)
		if !fromClient {
			src, dst, sp, dp = dst, src, dp, sp
		}
		flags.SrcPort, flags.DstPort = sp, dp
		return serialize(t, layers.IPProtocolTCP, src, dst, &flags, payload)
	}
	path := filepath.Join(t.TempDir(), "hs.pcap")
	writePCAP(t, path, [][]byte{
		tcp(true, layers.TCP{SYN: true, Seq: 100}, nil),
		tcp(false, layers.TCP{SYN: true, ACK: true, Seq: 500, Ack: 101}, nil),
		tcp(true, layers.TCP{ACK: true, Seq: 101, Ack: 501}, nil),
		tcp(true, layers.TCP{ACK: true, PSH: true, Seq: 101, Ack: 501}, []byte("GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n")),
		tcp(false, layers.TCP{ACK: true, PSH: true, Seq: 501, Ack: 138}, []byte("HTTP/1.1 200 OK\r\n\r\n")),
	})

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 5)

	base := time.Unix(1700000000, 0)
	for i, p := range got {
		assert.True(t, base.Equal(p.TCPSynTime), "packet %d", i)
		assert.True(t, base.Add(1*time.Second).Equal(p.TCPSynAckTime), "packet %d", i)
		assert.True(t, base.Add(2*time.Second).Equal(p.TCPAckTime), "packet %d", i)
		assert.True(t, base.Add(4*time.Second).Equal(p.FirstDataTime), "packet %d", i)
	}
	assert.Equal(t, uint32(501), got[2].TCPAck)
	assert.Equal(t, "Example.COM", got[3].HTTPHost)
	assert.Equal(t, 200, got[4].HTTPStatusCode)
}

func TestHTTPHost(t *testing.T) {
	tests := []struct {
		name, payload, want string
	}{
		{"simple", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com"},
		{"case-insensitive name and port", "GET / HTTP/1.1\r\nUser-Agent: x\r\nhOsT:  example.com:8080 \r\n\r\n", "example.com:8080"},
		{"lf only", "GET / HTTP/1.1\nHost: a.b\n\n", "a.b"},
		{"no host header", "GET / HTTP/1.0\r\nAccept: */*\r\n\r\n", ""},
		{"host in body is ignored", "POST / HTTP/1.1\r\n\r\nHost: evil.com", ""},
		{"malformed header line", "GET / HTTP/1.1\r\nnocolon\r\nHost: ok.com\r\n\r\n", "ok.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httpHost([]byte(tt.payload)))
		})
	}
}

func TestDNSAnswer(t *testing.T) {
	tests := []struct {
		name string
		rr   layers.DNSResourceRecord
		want string
	}{
		{"A", layers.DNSResourceRecord{Type: layers.DNSTypeA, IP: net.IP{1, 2, 3, 4}}, "A 1.2.3.4"},
		{"AAAA", layers.DNSResourceRecord{Type: layers.DNSTypeAAAA, IP: net.ParseIP("2001:db8::1")}, "AAAA 2001:db8::1"},
		{"CNAME", layers.DNSResourceRecord{Type: layers.DNSTypeCNAME, CNAME: []byte("real.example.org")}, "CNAME real.example.org"},
		{"NS", layers.DNSResourceRecord{Type: layers.DNSTypeNS, NS: []byte("ns1.example.org")}, "NS ns1.example.org"},
		{"PTR", layers.DNSResourceRecord{Type: layers.DNSTypePTR, PTR: []byte("host.example.org")}, "PTR host.example.org"},
		{"MX", layers.DNSResourceRecord{Type: layers.DNSTypeMX, MX: layers.DNSMX{Preference: 10, Name: []byte("mail.example.org")}}, "MX 10 mail.example.org"},
		{"TXT", layers.DNSResourceRecord{Type: layers.DNSTypeTXT, TXTs: [][]byte{[]byte("v=spf1"), []byte("-all")}}, "TXT v=spf1 -all"},
		{"other types show only the type", layers.DNSResourceRecord{Type: layers.DNSTypeSOA}, "SOA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dnsAnswer(tt.rr))
		})
	}
}

func TestPreviewPayload(t *testing.T) {
	assert.Nil(t, previewPayload(nil))

	short := []byte("abc")
	got := previewPayload(short)
	assert.Equal(t, short, got)
	short[0] = 'X'
	assert.Equal(t, byte('a'), got[0], "preview must be a copy")

	assert.Len(t, previewPayload(make([]byte, 2000)), maxPayloadPreview)
}

func TestReadPacketsKeepsDNSAnswersAndPreview(t *testing.T) {
	resp := dnsResponse(7, layers.DNSResponseCodeNoErr, true)
	path := filepath.Join(t.TempDir(), "ans.pcap")
	writePCAP(t, path, [][]byte{
		serialize(t, layers.IPProtocolUDP, serverIP, clientIP, &layers.UDP{SrcPort: 53, DstPort: 54321}, dnsPayload(t, resp)),
	})
	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, []string{"A 93.184.216.34"}, got[0].DNSAnswers)
	assert.Equal(t, got[0].PayloadSize, len(got[0].PayloadPreview))
}

func TestReadPacketsPcapng(t *testing.T) {
	packets, err := ReadPackets(filepath.Join("..", "..", "testdata", "Lab-5-AnotherSlowApp.pcapng"))
	require.NoError(t, err)
	require.Len(t, packets, 84)

	syn := packets[0]
	assert.Equal(t, models.ProtocolTCP, syn.Protocol)
	assert.Equal(t, "192.168.1.1", syn.SrcIP)
	assert.Equal(t, uint16(61300), syn.SrcPort)
	assert.Equal(t, "10.0.0.1", syn.DstIP)
	assert.Equal(t, uint16(80), syn.DstPort)
	assert.Equal(t, "SYN", syn.TCPFlags)

	// Frame 4 is a 1460-byte segment captured with a snaplen that cut the
	// payload short; the real length must still be reported.
	assert.Equal(t, 1460, packets[3].PayloadSize)
	assert.Less(t, len(packets[3].PayloadPreview), 1460)
}

func TestReadPacketsRejectsTinyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tiny.pcap")
	require.NoError(t, os.WriteFile(path, []byte{1, 2}, 0o644))
	_, err := ReadPackets(path)
	assert.ErrorContains(t, err, "capture header")
}

func TestReadPacketsTruncatedCapture(t *testing.T) {
	full := serialize(t, layers.IPProtocolTCP, clientIP, serverIP,
		&layers.TCP{SrcPort: 1000, DstPort: 80, ACK: true, Seq: 1}, make([]byte, 1000))
	const snaplen = 80

	path := filepath.Join(t.TempDir(), "trunc.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(snaplen, layers.LinkTypeEthernet))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), CaptureLength: snaplen, Length: len(full)}, full[:snaplen]))
	require.NoError(t, f.Close())

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1000, got[0].PayloadSize, "real segment length, not the captured bytes")
	assert.Equal(t, len(full), got[0].Size)
	assert.Less(t, len(got[0].PayloadPreview), 1000)
}

func TestTCPPayloadLen(t *testing.T) {
	build := func(t *testing.T, v6 bool, zeroLength bool) (gopacket.Packet, *layers.TCP) {
		t.Helper()
		var network gopacket.SerializableLayer
		var eth layers.EthernetType
		tcp := &layers.TCP{SrcPort: 1, DstPort: 2, ACK: true}
		if v6 {
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolTCP, HopLimit: 64, SrcIP: net.ParseIP("fe80::1"), DstIP: net.ParseIP("fe80::2")}
			require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
			network, eth = ip, layers.EthernetTypeIPv6
		} else {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: clientIP, DstIP: serverIP}
			require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
			network, eth = ip, layers.EthernetTypeIPv4
		}
		buf := gopacket.NewSerializeBuffer()
		ethL := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: eth}
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethL, network, tcp, gopacket.Payload(make([]byte, 77))))
		data := buf.Bytes()
		if zeroLength { // as written by NICs that segment in hardware
			if v6 {
				data[18], data[19] = 0, 0 // IPv6 payload length
			} else {
				data[16], data[17] = 0, 0 // IPv4 total length
			}
		}
		pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		return pkt, pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	}

	tests := []struct {
		name       string
		v6         bool
		zeroLength bool
		want       int
	}{
		{"ipv4", false, false, 77},
		{"ipv6", true, false, 77},
		{"ipv4 with zero length (segmentation offload) falls back to captured bytes", false, true, 77},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, tcp := build(t, tt.v6, tt.zeroLength)
			assert.Equal(t, tt.want, tcpPayloadLen(pkt, tcp))
		})
	}

	// Without an IP layer the captured length is all there is.
	assert.Equal(t, 3, tcpPayloadLen(gopacket.NewPacket(nil, layers.LayerTypeTCP, gopacket.Default), &layers.TCP{BaseLayer: layers.BaseLayer{Payload: []byte("abc")}}))
}
