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

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	ts := time.Unix(1700000000, 0)
	for i, data := range packets {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second), CaptureLength: len(data), Length: len(data)}
		require.NoError(t, w.WritePacket(ci, data))
	}
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
	writePCAP(t, path, [][]byte{
		serialize(t, layers.IPProtocolTCP, net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2},
			&layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 1000, SYN: true, PSH: true, Window: 1024}, []byte("hello")),
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
		{"tcp", 0, "10.0.0.1", "10.0.0.2", 12345, 80, models.ProtocolTCP, 5, 1000, "SYN,PSH", ""},
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
