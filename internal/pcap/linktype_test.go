package pcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// ngFile builds a little-endian pcapng file with one interface per entry of
// linkTypes and one enhanced packet block per entry of frames, where
// frames[i] belongs to interface ifaces[i].
func ngFile(linkTypes []uint16, ifaces []uint32, frames [][]byte) []byte {
	le := binary.LittleEndian
	block := func(typ uint32, body []byte) []byte {
		total := uint32(12 + len(body))
		b := make([]byte, 0, total)
		b = le.AppendUint32(b, typ)
		b = le.AppendUint32(b, total)
		b = append(b, body...)
		return le.AppendUint32(b, total)
	}
	var out []byte
	shb := le.AppendUint32(nil, ngByteOrderMagic)
	shb = le.AppendUint16(shb, 1)
	shb = le.AppendUint16(shb, 0)
	shb = le.AppendUint64(shb, ^uint64(0)) // section length unknown
	out = append(out, block(ngSectionHeaderType, shb)...)
	for _, lt := range linkTypes {
		idb := le.AppendUint16(nil, lt)
		idb = le.AppendUint16(idb, 0)
		idb = le.AppendUint32(idb, 65535)
		out = append(out, block(ngInterfaceDescType, idb)...)
	}
	for i, data := range frames {
		epb := le.AppendUint32(nil, ifaces[i])
		epb = le.AppendUint32(epb, 0)
		epb = le.AppendUint32(epb, uint32(i)) // timestamp, microseconds
		epb = le.AppendUint32(epb, uint32(len(data)))
		epb = le.AppendUint32(epb, uint32(len(data)))
		epb = append(epb, data...)
		for len(epb)%4 != 0 {
			epb = append(epb, 0)
		}
		out = append(out, block(6, epb)...)
	}
	return out
}

func TestReadPacketsStatsRealLinkTypeNumber(t *testing.T) {
	ip := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, []byte("x"))
	junk := make([]byte, 60)

	// A classic pcap whose header declares link type 274 (Ethernet mPacket),
	// which gopacket would see as 18.
	classic := func() string {
		path := filepath.Join(t.TempDir(), "mpacket.pcap")
		var buf bytes.Buffer
		w := pcapgo.NewWriter(&buf)
		require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for i := 0; i < 3; i++ {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{CaptureLength: 60, Length: 60}, junk))
		}
		data := buf.Bytes()
		binary.LittleEndian.PutUint32(data[20:24], 274)
		require.NoError(t, os.WriteFile(path, data, 0o644))
		return path
	}

	pcapng := func(linkTypes []uint16, ifaces []uint32, frames [][]byte) string {
		path := filepath.Join(t.TempDir(), "mpacket.pcapng")
		require.NoError(t, os.WriteFile(path, ngFile(linkTypes, ifaces, frames), 0o644))
		return path
	}

	tests := []struct {
		name        string
		path        string
		wantPackets int
		wantTypes   map[int]int
		wantDescr   string
	}{
		{
			name:      "classic pcap with link type 274",
			path:      classic(),
			wantTypes: map[int]int{274: 3},
			wantDescr: "3 frames of unsupported link type 274 (Ethernet mPacket)",
		},
		{
			name:      "pcapng with link type 274",
			path:      pcapng([]uint16{274}, []uint32{0, 0}, [][]byte{junk, junk}),
			wantTypes: map[int]int{274: 2},
			wantDescr: "2 frames of unsupported link type 274 (Ethernet mPacket)",
		},
		{
			name:        "pcapng mixing Ethernet and 274",
			path:        pcapng([]uint16{1, 274}, []uint32{0, 1, 1, 0}, [][]byte{ip, junk, junk, ip}),
			wantPackets: 2,
			wantTypes:   map[int]int{274: 2},
			wantDescr:   "2 frames of unsupported link type 274 (Ethernet mPacket)",
		},
		{
			name:      "an unnamed type keeps its number",
			path:      pcapng([]uint16{250}, []uint32{0}, [][]byte{junk}),
			wantTypes: map[int]int{250: 1},
			wantDescr: "1 frames of unsupported link type 250",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets, stats, err := ReadPacketsStats(tt.path, ReadOptions{})
			require.NoError(t, err)
			assert.Len(t, packets, tt.wantPackets)
			assert.Equal(t, tt.wantTypes, stats.UnsupportedLinkTypes)
			assert.Equal(t, tt.wantDescr, stats.Describe())
		})
	}
}

func TestBlockTrackerRealLinkType(t *testing.T) {
	tests := []struct {
		name      string
		linkTypes []uint16
		truncated uint8
		want      int
		wantOK    bool
	}{
		{"one match", []uint16{1, 274}, 18, 274, true},
		{"same type twice", []uint16{274, 274}, 18, 274, true},
		{"ambiguous", []uint16{274, 18}, 18, 0, false},
		{"no match", []uint16{1}, 18, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// feed the file one byte at a time: the link type may be split
			// across reads
			tr := &blockTracker{r: iotestChunks(ngFile(tt.linkTypes, nil, nil), 1)}
			_, err := bytes.NewBuffer(nil).ReadFrom(tr)
			require.NoError(t, err)
			assert.Equal(t, tt.linkTypes, tr.linkTypes)

			got, ok := tr.realLinkType(tt.truncated)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestStreamsReliable(t *testing.T) {
	tests := []struct {
		name  string
		stats ReadStats
		want  bool
	}{
		{"nothing skipped", ReadStats{Frames: 10}, true},
		{"layer-2 control traffic that never carries TCP", ReadStats{SkippedNonIP: 5, NonIPTypes: map[string]int{"STP": 3, "LLDP": 1, "CDP": 1}}, true},
		{"every safe kind", ReadStats{SkippedNonIP: 11, NonIPTypes: map[string]int{"STP": 1, "LLDP": 1, "CDP": 1, "UDLD": 1, "VTP": 1, "DTP": 1, "EAPOL": 1, "PTP": 1, "CFM": 1, "Slow Protocols": 1, "Loopback": 1}}, true},
		{"frames of an unsupported link type", ReadStats{SkippedUnsupportedLink: 1, UnsupportedLinkTypes: map[int]int{274: 1}}, false},
		{"PPPoE may carry TCP", ReadStats{SkippedNonIP: 1, NonIPTypes: map[string]int{"PPPoE": 1}}, false},
		{"an unknown kind may carry TCP", ReadStats{SkippedNonIP: 1, NonIPTypes: map[string]int{"Other": 1}}, false},
		{"a tagged frame whose inner type is not understood", ReadStats{SkippedNonIP: 1, NonIPTypes: map[string]int{"VLAN": 1}}, false},
		{"MPLS", ReadStats{SkippedNonIP: 1, NonIPTypes: map[string]int{"MPLS": 1}}, false},
		{"one unsafe kind among safe ones", ReadStats{SkippedNonIP: 2, NonIPTypes: map[string]int{"STP": 1, "ERSPAN": 1}}, false},
		{"fragmented TCP segments", ReadStats{TCPFragments: 1}, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.stats.streamsReliable(), tt.name)
	}
}

func TestReadPacketsStampsStreamsOnlyWhenTheyCanBeTrusted(t *testing.T) {
	syn := func(sport uint16) []byte {
		return serialize(t, layers.IPProtocolTCP, clientIP, serverIP, &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: 80, SYN: true, Seq: 1, Window: 100}, nil)
	}
	lldp := append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc}, make([]byte, 30)...)
	pppoe := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x88, 0x64}, make([]byte, 30)...)
	// the first fragment of a TCP segment: IPv4 with More Fragments set and no TCP header decoded
	fragment := func() []byte {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: clientIP, DstIP: serverIP, Flags: layers.IPv4MoreFragments}
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, ip, gopacket.Payload(make([]byte, 40))))
		return buf.Bytes()
	}()

	tests := []struct {
		name         string
		frames       [][]byte
		wantStreams  bool
		wantFragment int
	}{
		{"plain TCP", [][]byte{syn(1000), syn(1001)}, true, 0},
		{"with spanning-tree-like control traffic", [][]byte{syn(1000), lldp, syn(1001)}, true, 0},
		{"with a PPPoE frame the tool cannot look into", [][]byte{syn(1000), pppoe, syn(1001)}, false, 0},
		{"with a fragmented TCP segment", [][]byte{syn(1000), fragment, syn(1001)}, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "streams.pcap")
			writePCAP(t, path, tt.frames)
			packets, stats, err := ReadPacketsStats(path, ReadOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.wantFragment, stats.TCPFragments)
			var tcp []models.PacketInfo
			for _, p := range packets {
				if p.Protocol == models.ProtocolTCP {
					tcp = append(tcp, p)
				}
			}
			require.Len(t, tcp, 2)
			for i, p := range tcp {
				assert.Equal(t, tt.wantStreams, p.StreamKnown)
				if tt.wantStreams {
					assert.Equal(t, i, p.Stream)
				}
			}
		})
	}
}
