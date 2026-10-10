package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ngBlock builds a pcapng block with the given type and body length.
func ngBlock(order binary.ByteOrder, typ uint32, bodyLen int) []byte {
	total := 12 + bodyLen
	b := make([]byte, total)
	order.PutUint32(b[0:], typ)
	order.PutUint32(b[4:], uint32(total))
	order.PutUint32(b[total-4:], uint32(total))
	return b
}

// ngSectionHeader builds a section header block (body: magic, version, section length).
func ngSectionHeader(order binary.ByteOrder) []byte {
	b := ngBlock(order, ngSectionHeaderType, 16)
	order.PutUint32(b[8:], ngByteOrderMagic)
	order.PutUint16(b[12:], 1)
	return b
}

func TestBlockTracker(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		name := "little-endian"
		if order == binary.BigEndian {
			name = "big-endian"
		}
		t.Run(name, func(t *testing.T) {
			var stream []byte
			stream = append(stream, ngSectionHeader(order)...)
			stream = append(stream, ngBlock(order, 1, 16)...)
			stream = append(stream, ngBlock(order, 6, 100)...)
			stream = append(stream, ngBlock(order, 6, 40)...)

			tests := []struct {
				name string
				cut  int
				want bool
			}{
				{"empty", 0, false},
				{"whole stream", len(stream), false},
				{"one byte in", 1, true},
				{"inside the section header", 20, true},
				{"just after the section header", 28, false},
				{"inside a block header", 28 + 5, true},
				{"inside a block body", 28 + 12 + 16 + 10, true},
				{"one byte short", len(stream) - 1, true},
				{"block boundary", 28 + 28, false},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					// Feed in awkward chunk sizes to exercise state carried across reads.
					for _, chunk := range []int{1, 3, 7, 4096} {
						tr := &blockTracker{r: iotestChunks(stream[:tt.cut], chunk)}
						_, err := io.Copy(io.Discard, tr)
						require.NoError(t, err)
						assert.Equal(t, tt.want, tr.midBlock(), "chunk=%d", chunk)
					}
				})
			}
		})
	}
}

// iotestChunks returns a reader that yields b in pieces of at most n bytes.
func iotestChunks(b []byte, n int) io.Reader { return &chunkReader{b: b, n: n} }

type chunkReader struct {
	b []byte
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	k := min(len(p), c.n, len(c.b))
	copy(p, c.b[:k])
	c.b = c.b[k:]
	return k, nil
}

func TestBlockTrackerInvalidFraming(t *testing.T) {
	shortBlock := make([]byte, 8) // claims a total length below its own header size
	binary.LittleEndian.PutUint32(shortBlock[0:], 6)
	binary.LittleEndian.PutUint32(shortBlock[4:], 4)

	badMagic := ngSectionHeader(binary.LittleEndian)
	binary.LittleEndian.PutUint32(badMagic[8:], 0xdeadbeef)

	tests := []struct {
		name   string
		stream []byte
	}{
		{"not pcapng at all", bytes.Repeat([]byte{0xff}, 40)},
		{"bad byte-order magic", badMagic},
		{"first block is not a section header", ngBlock(binary.LittleEndian, 6, 8)},
		{"block shorter than its header", append(ngSectionHeader(binary.LittleEndian), shortBlock...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &blockTracker{r: bytes.NewReader(tt.stream)}
			_, err := io.Copy(io.Discard, tr)
			require.NoError(t, err)
			assert.False(t, tr.midBlock(), "unrecognized framing must never be reported as truncation")
		})
	}
}

// writeNg writes a pcapng file of n packets with NgWriter and returns its
// bytes together with the file offset just after each packet block.
func writeNg(t *testing.T, n int) (data []byte, packetEnds []int) {
	t.Helper()
	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
	require.NoError(t, err)
	require.NoError(t, w.Flush())

	for id := 1; id <= n; id++ {
		frame := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 54321, DstPort: 53}, dnsPayload(t, dnsQuery(uint16(id))))
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(id), 0), CaptureLength: len(frame), Length: len(frame)}
		require.NoError(t, w.WritePacket(ci, frame))
		require.NoError(t, w.Flush())
		packetEnds = append(packetEnds, buf.Len())
	}
	return buf.Bytes(), packetEnds
}

func TestReadPacketsTruncatedPcapngBoundaries(t *testing.T) {
	data, ends := writeNg(t, 5)
	headerEnd := ends[0] - (ends[1] - ends[0]) // offset after SHB+IDB

	tests := []struct {
		name        string
		cut         int
		wantPackets int
		wantTrunc   bool
		wantErr     bool
	}{
		{"complete", len(data), 5, false, false},
		{"clean end between blocks", ends[2], 3, false, false},
		{"cut inside a packet block", ends[2] + 20, 3, true, false},
		{"cut one byte short", len(data) - 1, 4, true, false},
		{"cut inside a block header", ends[3] + 3, 4, true, false},
		{"only the file header blocks", headerEnd, 0, false, false},
		{"cut inside the first packet", headerEnd + 30, 0, true, false},
		{"cut inside the interface block", 40, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cut.pcapng")
			require.NoError(t, os.WriteFile(path, data[:tt.cut], 0o644))

			got, err := ReadPackets(path)
			var trunc *TruncatedError
			switch {
			case tt.wantErr:
				require.Error(t, err)
				assert.False(t, errors.As(err, &trunc))
				return
			case tt.wantTrunc:
				require.ErrorAs(t, err, &trunc)
				assert.Equal(t, tt.wantPackets, trunc.Packets)
			default:
				require.NoError(t, err)
			}
			require.Len(t, got, tt.wantPackets)
			for i, p := range got {
				assert.Equal(t, uint16(i+1), p.DNSID)
			}
		})
	}
}
