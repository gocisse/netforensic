package pcap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

// serialize builds an Ethernet/IPv4 packet around the given transport layer.
func serialize(t *testing.T, proto layers.IPProtocol, src, dst net.IP, transport gopacket.SerializableLayer, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: src, DstIP: dst}
	switch l := transport.(type) {
	case *layers.TCP:
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
	case *layers.UDP:
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, transport, gopacket.Payload(payload)))
	return buf.Bytes()
}

// dnsPayload serializes a DNS message for use as a UDP payload.
func dnsPayload(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}))
	return buf.Bytes()
}

// writePCAP writes packets, one second apart, to a new pcap file at path.
func writePCAP(t *testing.T, path string, packets [][]byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))

	// Write to a temporary file and rename it into place: other packages'
	// tests read testdata/sample.pcap concurrently and must never see a
	// partially written file.
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*.pcap")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	ts := time.Unix(1700000000, 0)
	for i, data := range packets {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second), CaptureLength: len(data), Length: len(data)}
		require.NoError(t, w.WritePacket(ci, data))
	}
	require.NoError(t, f.Close())
	require.NoError(t, os.Rename(f.Name(), path))
}

var (
	clientIP = net.IP{192, 168, 1, 10}
	serverIP = net.IP{8, 8, 8, 8}
)

func dnsQuery(id uint16) *layers.DNS {
	return &layers.DNS{
		ID:        id,
		Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
}

// dnsResponse builds a response to dnsQuery(id) with the given RCODE and optional A answer.
func dnsResponse(id uint16, rcode layers.DNSResponseCode, withAnswer bool) *layers.DNS {
	d := dnsQuery(id)
	d.QR = true
	d.ResponseCode = rcode
	if withAnswer {
		d.Answers = []layers.DNSResourceRecord{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IP{93, 184, 216, 34}}}
	}
	return d
}

func TestReadPackets(t *testing.T) {
	path := filepath.Join("testdata", "sample.pcap")

	query := dnsPayload(t, dnsQuery(0x1234))
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	writePCAP(t, path, [][]byte{
		serialize(t, layers.IPProtocolTCP, net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2},
			&layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 1000, PSH: true, ACK: true, Window: 1024}, httpReq),
		serialize(t, layers.IPProtocolUDP, clientIP, serverIP,
			&layers.UDP{SrcPort: 54321, DstPort: 53}, query),
	})

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 2)

	tests := []struct {
		name        string
		idx         int
		srcIP       string
		dstIP       string
		srcPort     uint16
		dstPort     uint16
		proto       models.Protocol
		payloadSize int
		tcpSeq      uint32
		tcpFlags    string
		dnsName     string
	}{
		{"tcp", 0, "10.0.0.1", "10.0.0.2", 12345, 80, models.ProtocolTCP, len(httpReq), 1000, "PSH,ACK", ""},
		{"udp dns query", 1, "192.168.1.10", "8.8.8.8", 54321, 53, models.ProtocolUDP, len(query), 0, "", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := got[tt.idx]
			assert.Equal(t, tt.srcIP, p.SrcIP)
			assert.Equal(t, tt.dstIP, p.DstIP)
			assert.Equal(t, tt.srcPort, p.SrcPort)
			assert.Equal(t, tt.dstPort, p.DstPort)
			assert.Equal(t, tt.proto, p.Protocol)
			assert.Equal(t, tt.payloadSize, p.PayloadSize)
			assert.Equal(t, tt.tcpSeq, p.TCPSeq)
			assert.Equal(t, tt.tcpFlags, p.TCPFlags)
			assert.Equal(t, tt.dnsName, p.DNSQueryName)
			assert.Positive(t, p.Size)
		})
	}
}

func TestSampleHTTPRequest(t *testing.T) {
	got, err := ReadPackets(filepath.Join("testdata", "sample.pcap"))
	require.NoError(t, err)
	require.NotEmpty(t, got)
	assert.Equal(t, "GET", got[0].HTTPMethod)
	assert.Equal(t, "/index.html", got[0].HTTPURI)
}

func TestReadPacketsHTTPAndTLS(t *testing.T) {
	tcp := func(srcPort, dstPort uint16, payload []byte) []byte {
		return serialize(t, layers.IPProtocolTCP, clientIP, serverIP,
			&layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), ACK: true, PSH: true}, payload)
	}
	path := filepath.Join(t.TempDir(), "app.pcap")
	writePCAP(t, path, [][]byte{
		tcp(50000, 80, []byte("GET /a HTTP/1.1\r\n\r\n")),
		tcp(80, 50000, []byte("HTTP/1.1 404 Not Found\r\n\r\n")),
		tcp(50001, 443, record(22, 0x0301, hello(false, 0x0303))),
		tcp(443, 50001, record(21, 0x0303, []byte{2, 40})),
		tcp(50002, 9000, []byte("opaque")),
	})

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 5)

	assert.Equal(t, "GET", got[0].HTTPMethod)
	assert.Equal(t, "/a", got[0].HTTPURI)
	assert.Equal(t, 404, got[1].HTTPStatusCode)
	assert.Equal(t, "ClientHello", got[2].TLSHandshakeType)
	assert.Equal(t, "TLS 1.2", got[2].TLSVersion)
	assert.Equal(t, "Alert", got[3].TLSHandshakeType)
	assert.Equal(t, "fatal", got[3].TLSAlertLevel)
	assert.Equal(t, "handshake_failure", got[3].TLSAlertDescription)
	assert.Empty(t, got[4].HTTPMethod)
	assert.Empty(t, got[4].TLSHandshakeType)
}

func TestReadPacketsDNS(t *testing.T) {
	udp := func(srcPort, dstPort uint16, src, dst net.IP, d *layers.DNS) []byte {
		return serialize(t, layers.IPProtocolUDP, src, dst, &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}, dnsPayload(t, d))
	}
	path := filepath.Join(t.TempDir(), "dns.pcap")
	writePCAP(t, path, [][]byte{
		udp(54321, 53, clientIP, serverIP, dnsQuery(1)),
		udp(53, 54321, serverIP, clientIP, dnsResponse(1, layers.DNSResponseCodeNoErr, true)),
		udp(53, 54321, serverIP, clientIP, dnsResponse(2, layers.DNSResponseCodeNXDomain, false)),
		udp(53, 54321, serverIP, clientIP, dnsResponse(3, layers.DNSResponseCodeServFail, false)),
		udp(53, 54321, serverIP, clientIP, dnsResponse(4, layers.DNSResponseCodeRefused, false)),
		udp(53, 54321, serverIP, clientIP, dnsResponse(5, layers.DNSResponseCode(9), false)),
	})

	got, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, got, 6)

	tests := []struct {
		name     string
		idx      int
		id       uint16
		isQuery  bool
		respType string
		rcode    string
	}{
		{"query", 0, 1, true, "A", ""},
		{"noerror with answer", 1, 1, false, "A", "NOERROR"},
		{"nxdomain falls back to question type", 2, 2, false, "A", "NXDOMAIN"},
		{"servfail", 3, 3, false, "A", "SERVFAIL"},
		{"refused", 4, 4, false, "A", "REFUSED"},
		{"unknown rcode", 5, 5, false, "A", "RCODE9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := got[tt.idx]
			assert.Equal(t, "example.com", p.DNSQueryName)
			assert.Equal(t, tt.id, p.DNSID)
			assert.Equal(t, tt.isQuery, p.DNSIsQuery)
			assert.Equal(t, tt.respType, p.DNSResponseType)
			assert.Equal(t, tt.rcode, p.DNSResponseCode)
		})
	}
}

func TestReadPacketsErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pcap")
	require.NoError(t, os.WriteFile(bad, []byte("not a pcap"), 0o644))

	tests := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(t.TempDir(), "nope.pcap")},
		{"invalid header", bad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadPackets(tt.path)
			assert.Error(t, err)
		})
	}
}

func TestReadPacketsTruncatedFile(t *testing.T) {
	// Six DNS packets, so there are several record boundaries to cut at.
	udp := func(src, dst net.IP, sp, dp uint16, d *layers.DNS) []byte {
		return serialize(t, layers.IPProtocolUDP, src, dst, &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}, dnsPayload(t, d))
	}
	var frames [][]byte
	for id := uint16(1); id <= 6; id++ {
		frames = append(frames, udp(clientIP, serverIP, 54321, 53, dnsQuery(id)))
	}
	full := filepath.Join(t.TempDir(), "full.pcap")
	writePCAP(t, full, frames)
	data, err := os.ReadFile(full)
	require.NoError(t, err)

	// recordEnd[i] is the file offset just after packet i.
	const fileHeader, recordHeader = 24, 16
	offset := fileHeader
	var recordEnd []int
	for _, f := range frames {
		offset += recordHeader + len(f)
		recordEnd = append(recordEnd, offset)
	}
	require.Equal(t, len(data), recordEnd[len(recordEnd)-1])

	tests := []struct {
		name         string
		cut          int
		wantPackets  int
		wantTruncErr bool
		wantErr      bool
	}{
		{"complete file", len(data), 6, false, false},
		{"cut exactly between records is a clean end", recordEnd[2], 3, false, false},
		{"cut in the middle of a packet's data", recordEnd[2] + recordHeader + 10, 3, true, false},
		{"cut one byte short of the last packet", len(data) - 1, 5, true, false},
		{"cut in the middle of a record header", recordEnd[3] + 5, 4, true, false},
		{"cut in the first packet", fileHeader + recordHeader + 3, 0, true, false},
		{"only the file header", fileHeader, 0, false, false},
		{"cut inside the file header", 10, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cut.pcap")
			require.NoError(t, os.WriteFile(path, data[:tt.cut], 0o644))

			got, err := ReadPackets(path)
			var trunc *TruncatedError
			switch {
			case tt.wantErr:
				require.Error(t, err)
				assert.False(t, errors.As(err, &trunc))
				assert.Nil(t, got)
				return
			case tt.wantTruncErr:
				require.ErrorAs(t, err, &trunc)
				assert.Equal(t, tt.wantPackets, trunc.Packets)
				assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
				assert.Contains(t, err.Error(), fmt.Sprintf("after %d packets", tt.wantPackets))
			default:
				require.NoError(t, err)
			}
			require.Len(t, got, tt.wantPackets)
			for i, p := range got { // the surviving packets are intact
				assert.Equal(t, "example.com", p.DNSQueryName)
				assert.Equal(t, uint16(i+1), p.DNSID)
			}
		})
	}
}

func TestReadPacketsTruncatedPcapng(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "Lab-5-AnotherSlowApp.pcapng"))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "cut.pcapng")
	require.NoError(t, os.WriteFile(path, data[:5000], 0o644))

	got, err := ReadPackets(path)
	var trunc *TruncatedError
	require.ErrorAs(t, err, &trunc)
	assert.Equal(t, len(got), trunc.Packets)
	assert.Greater(t, len(got), 30, "most of the capture survives")
	assert.Less(t, len(got), 84)
	assert.Equal(t, "SYN", got[0].TCPFlags)
	assert.False(t, got[0].TCPSynAckTime.IsZero(), "handshake annotation still runs on the partial capture")
}

func TestReadPacketsWithOptionsFullPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.pcap")
	payload := bytes.Repeat([]byte("x"), maxPayloadPreview+100)
	writeBigTCP(t, path, payload)

	preview, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, preview, 1)
	assert.Len(t, preview[0].PayloadPreview, maxPayloadPreview)
	assert.Nil(t, preview[0].Payload)

	full, err := ReadPacketsWithOptions(path, ReadOptions{FullPayload: true})
	require.NoError(t, err)
	require.Len(t, full, 1)
	assert.Equal(t, payload, full[0].Payload)
	assert.Len(t, full[0].PayloadPreview, maxPayloadPreview)
}

// writeBigTCP writes a one-packet pcap holding a TCP segment with payload.
func writeBigTCP(t *testing.T, path string, payload []byte) {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		ip, tcp, gopacket.Payload(payload)))

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()))
}

func TestAnnotateHandshakesPerConnection(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	pk := func(ms int, fromClient bool, flags string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 5000, "10.0.0.2", 443
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 443, "10.0.0.1", 5000
		}
		return p
	}
	packets := []models.PacketInfo{
		pk(0, true, "SYN"), pk(1, false, "RST,ACK"), // refused
		pk(1000, true, "SYN"), pk(1020, false, "SYN,ACK"), pk(1040, true, "ACK"), // accepted
	}
	annotateHandshakes(packets)

	assert.Equal(t, t0, packets[0].TCPSynTime)
	assert.True(t, packets[0].TCPSynAckTime.IsZero(), "the refused attempt never got a SYN-ACK")
	assert.True(t, packets[1].TCPAckTime.IsZero())
	for _, p := range packets[2:] {
		assert.Equal(t, t0.Add(time.Second), p.TCPSynTime)
		assert.Equal(t, t0.Add(1020*time.Millisecond), p.TCPSynAckTime)
		assert.Equal(t, t0.Add(1040*time.Millisecond), p.TCPAckTime)
	}
}

func TestReadPacketsTCPWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "win.pcap")
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	require.NoError(t, (&layers.TCP{}).SetNetworkLayerForChecksum(ip))
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, win := range []uint16{0, 29200} {
		buf.Clear()
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1, ACK: true, Window: win}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(i+1), 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()))
	}
	require.NoError(t, f.Close())

	packets, err := ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, packets, 2)
	assert.Equal(t, uint32(0), packets[0].TCPWindow)
	assert.Equal(t, uint32(29200), packets[1].TCPWindow)
}

func TestReadPacketsStatsAccountsForEveryFrame(t *testing.T) {
	ip := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, []byte("x"))
	lldp := append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc}, make([]byte, 30)...) // layer-2 control frame
	stp := append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0, 1, 2, 3, 4, 5, 0x00, 0x26, 0x42, 0x42, 0x03}, make([]byte, 30)...)
	arp := func() []byte {
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, SourceProtAddress: []byte{10, 0, 0, 1}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{10, 0, 0, 2}}))
		return buf.Bytes()
	}()

	path := filepath.Join(t.TempDir(), "mixed.pcap")
	writePCAP(t, path, [][]byte{ip, lldp, arp, stp, ip})

	packets, stats, err := ReadPacketsStats(path, ReadOptions{})
	require.NoError(t, err)
	assert.Len(t, packets, 3, "two IP packets and the ARP request")
	assert.Equal(t, 5, stats.Frames)
	assert.Equal(t, 2, stats.SkippedNonIP, "LLDP and spanning tree")
	assert.Zero(t, stats.SkippedUnsupportedLink)
	assert.Equal(t, 2, stats.Skipped())
	assert.Empty(t, stats.UnsupportedLinkTypes)
	assert.Equal(t, stats.Frames, len(packets)+stats.Skipped(), "every frame is accounted for")

	// the plain reader returns the same packets
	plain, err := ReadPackets(path)
	require.NoError(t, err)
	assert.Equal(t, len(packets), len(plain))
}

func TestReadPacketsStatsUnsupportedLinkType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "weird.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkType(250))) // not a link type gopacket decodes
	for i := 0; i < 4; i++ {
		data := make([]byte, 60)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(i), 0), CaptureLength: 60, Length: 60}, data))
	}
	require.NoError(t, f.Close())

	packets, stats, err := ReadPacketsStats(path, ReadOptions{})
	require.NoError(t, err)
	assert.Empty(t, packets)
	assert.Equal(t, 4, stats.Frames)
	assert.Equal(t, 4, stats.SkippedUnsupportedLink)
	assert.Zero(t, stats.SkippedNonIP)
	assert.Equal(t, map[int]int{250: 4}, stats.UnsupportedLinkTypes)
}

func TestReadPacketsStatsOnTruncatedFile(t *testing.T) {
	ip := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, []byte("x"))
	lldp := append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc}, make([]byte, 30)...)
	path := filepath.Join(t.TempDir(), "cut.pcap")
	writePCAP(t, path, [][]byte{ip, lldp, ip})
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data[:len(data)-10], 0o644))

	packets, stats, err := ReadPacketsStats(path, ReadOptions{})
	var trunc *TruncatedError
	require.ErrorAs(t, err, &trunc)
	assert.Len(t, packets, 1)
	assert.Equal(t, 2, stats.Frames, "the cut frame is not counted")
	assert.Equal(t, 1, stats.SkippedNonIP)

	_, _, err = ReadPacketsStats(filepath.Join(t.TempDir(), "missing.pcap"), ReadOptions{})
	assert.Error(t, err)
}

func TestLinkTypeSupported(t *testing.T) {
	for lt, want := range map[layers.LinkType]bool{
		layers.LinkTypeEthernet: true, layers.LinkTypeRaw: true, layers.LinkTypeLinuxSLL: true, layers.LinkTypeNull: true,
		layers.LinkType(250): false, layers.LinkType(18): false,
	} {
		assert.Equal(t, want, linkTypeSupported(lt), lt)
	}
}

func TestReadStatsDescribe(t *testing.T) {
	assert.Equal(t, "", ReadStats{}.Describe())
	assert.Equal(t, "7 non-IP frames", ReadStats{SkippedNonIP: 7}.Describe())
	assert.Equal(t, "5 frames of unsupported link type 18; 2 frames of unsupported link type 250; 7 non-IP frames",
		ReadStats{SkippedNonIP: 7, SkippedUnsupportedLink: 7, UnsupportedLinkTypes: map[int]int{250: 2, 18: 5}}.Describe())
	assert.Equal(t, 9, ReadStats{SkippedNonIP: 7, SkippedUnsupportedLink: 2}.Skipped())
}
