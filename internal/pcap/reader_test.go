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

// createSamplePCAP writes a pcap file at path containing one TCP and one UDP packet.
func createSamplePCAP(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))

	tcpData := serialize(t, layers.IPProtocolTCP, net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2},
		&layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 1000, SYN: true, PSH: true, Window: 1024}, []byte("hello"))
	udpData := serialize(t, layers.IPProtocolUDP, net.IP{192, 168, 1, 10}, net.IP{8, 8, 8, 8},
		&layers.UDP{SrcPort: 54321, DstPort: 53}, []byte("dns"))

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	ts := time.Unix(1700000000, 0)
	for i, data := range [][]byte{tcpData, udpData} {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second), CaptureLength: len(data), Length: len(data)}
		require.NoError(t, w.WritePacket(ci, data))
	}
}

func TestReadPackets(t *testing.T) {
	path := filepath.Join("testdata", "sample.pcap")
	createSamplePCAP(t, path)

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
	}{
		{"tcp", 0, "10.0.0.1", "10.0.0.2", 12345, 80, models.ProtocolTCP, 5, 1000, "SYN,PSH"},
		{"udp", 1, "192.168.1.10", "8.8.8.8", 54321, 53, models.ProtocolUDP, 3, 0, ""},
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
			assert.Positive(t, p.Size)
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
