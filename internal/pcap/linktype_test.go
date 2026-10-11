package pcap

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
