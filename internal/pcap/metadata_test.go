package pcap

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// pcapng option codes used by the tests.
const (
	optComment    = 1
	optName       = 2 // if_name; shb_hardware is also 2
	optDesc       = 3 // if_description; shb_os is also 3
	optApp        = 4 // shb_userappl
	optFilter     = 11
	optTsResol    = 9
	optInterfaceN = 2
)

type ngOpt struct {
	code uint16
	val  []byte
}

func ngOptions(opts []ngOpt) []byte {
	le := binary.LittleEndian
	var b []byte
	for _, o := range opts {
		b = le.AppendUint16(b, o.code)
		b = le.AppendUint16(b, uint16(len(o.val)))
		b = append(b, o.val...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	if len(opts) > 0 {
		b = le.AppendUint32(b, 0) // opt_endofopt
	}
	return b
}

type ngIface struct {
	linkType uint16
	snapLen  uint32
	opts     []ngOpt
}

// ngMeta builds a little-endian pcapng file: a section header with the given
// options, the interfaces, and one packet per entry of packets (the value is
// the interface it was captured on).
func ngMeta(shb []ngOpt, ifaces []ngIface, packets []uint32, frame []byte) []byte {
	le := binary.LittleEndian
	block := func(typ uint32, body []byte) []byte {
		total := uint32(12 + len(body))
		b := le.AppendUint32(nil, typ)
		b = le.AppendUint32(b, total)
		b = append(b, body...)
		return le.AppendUint32(b, total)
	}
	body := le.AppendUint32(nil, ngByteOrderMagic)
	body = le.AppendUint16(body, 1)
	body = le.AppendUint16(body, 0)
	body = le.AppendUint64(body, ^uint64(0))
	body = append(body, ngOptions(shb)...)
	out := block(ngSectionHeaderType, body)
	for _, ifc := range ifaces {
		b := le.AppendUint16(nil, ifc.linkType)
		b = le.AppendUint16(b, 0)
		b = le.AppendUint32(b, ifc.snapLen)
		b = append(b, ngOptions(ifc.opts)...)
		out = append(out, block(ngInterfaceDescType, b)...)
	}
	for i, ifc := range packets {
		b := le.AppendUint32(nil, ifc)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, uint32(i))
		b = le.AppendUint32(b, uint32(len(frame)))
		b = le.AppendUint32(b, uint32(len(frame)))
		b = append(b, frame...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		out = append(out, block(6, b)...)
	}
	return out
}

func readMeta(t *testing.T, data []byte) (*models.CaptureMetadata, ReadStats) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meta.pcapng")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	_, stats, err := ReadPacketsStats(path, ReadOptions{})
	require.NoError(t, err)
	return stats.Metadata, stats
}

func TestReadPacketsStatsPcapngMetadata(t *testing.T) {
	udp := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, []byte("x"))
	shb := []ngOpt{
		{optName, []byte("Intel(R) Core(TM) i7")},
		{optDesc, []byte("Linux 5.10.0")},
		{optApp, []byte("Dumpcap (Wireshark) 3.4.9")},
		{optComment, []byte("a comment that is not shown")},
	}
	eth0 := ngIface{1, 262144, []ngOpt{{optInterfaceN, []byte("eth0")}, {optDesc, []byte("Uplink")}, {optTsResol, []byte{9}}, {optFilter, append([]byte{0}, "port 80"...)}}}
	wlan := ngIface{101, 0, []ngOpt{{optInterfaceN, []byte("tun0")}}} // raw IP, no snaplen limit, default microseconds

	tests := []struct {
		name    string
		data    []byte
		want    *models.CaptureMetadata
		wantNil bool
	}{
		{
			name: "section header and two interfaces",
			data: ngMeta(shb, []ngIface{eth0, wlan}, []uint32{0, 1, 0}, udp),
			want: &models.CaptureMetadata{
				CaptureTool: "Dumpcap (Wireshark) 3.4.9",
				OS:          "Linux 5.10.0",
				Hardware:    "Intel(R) Core(TM) i7",
				Interfaces: []models.InterfaceInfo{
					{Name: "eth0", Description: "Uplink", LinkType: "Ethernet", SnapLen: 262144, Resolution: "nanosecond", Filter: "port 80"},
					{Name: "tun0", LinkType: "Raw", SnapLen: 0, Resolution: "microsecond"},
				},
			},
		},
		{
			name: "identical interfaces are listed once",
			data: ngMeta(nil, []ngIface{eth0, eth0, eth0}, []uint32{0, 1, 2, 1}, udp),
			want: &models.CaptureMetadata{Interfaces: []models.InterfaceInfo{
				{Name: "eth0", Description: "Uplink", LinkType: "Ethernet", SnapLen: 262144, Resolution: "nanosecond", Filter: "port 80"},
			}},
		},
		{
			name: "an interface no packet used is still listed",
			data: ngMeta(nil, []ngIface{eth0, wlan}, []uint32{0}, udp),
			want: &models.CaptureMetadata{Interfaces: []models.InterfaceInfo{
				{Name: "eth0", Description: "Uplink", LinkType: "Ethernet", SnapLen: 262144, Resolution: "nanosecond", Filter: "port 80"},
				{Name: "tun0", LinkType: "Raw", Resolution: "microsecond"},
			}},
		},
		{
			name: "a file with no packets still has its metadata",
			data: ngMeta(shb, []ngIface{eth0}, nil, nil),
			want: &models.CaptureMetadata{
				CaptureTool: "Dumpcap (Wireshark) 3.4.9", OS: "Linux 5.10.0", Hardware: "Intel(R) Core(TM) i7",
				Interfaces: []models.InterfaceInfo{{Name: "eth0", Description: "Uplink", LinkType: "Ethernet", SnapLen: 262144, Resolution: "nanosecond", Filter: "port 80"}},
			},
		},
		{
			name: "an interface without options",
			data: ngMeta(nil, []ngIface{{1, 65535, nil}}, []uint32{0}, udp),
			want: &models.CaptureMetadata{Interfaces: []models.InterfaceInfo{{LinkType: "Ethernet", SnapLen: 65535, Resolution: "microsecond"}}},
		},
		{
			name: "an Ethernet mPacket interface is named by its real number",
			data: ngMeta(nil, []ngIface{{274, 0, []ngOpt{{optInterfaceN, []byte("mp0")}}}}, nil, nil),
			want: &models.CaptureMetadata{Interfaces: []models.InterfaceInfo{{Name: "mp0", LinkType: "Ethernet mPacket", Resolution: "microsecond"}}},
		},
		{
			name: "an unnamed link type shows its number",
			data: ngMeta(nil, []ngIface{{250, 0, nil}}, nil, nil),
			want: &models.CaptureMetadata{Interfaces: []models.InterfaceInfo{{LinkType: "type 250", Resolution: "microsecond"}}},
		},
		{
			name:    "the section header comment is not metadata",
			data:    ngMeta([]ngOpt{{optComment, []byte("only a comment")}}, nil, nil, nil),
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := readMeta(t, tt.data)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMetadataStringsAreSanitized(t *testing.T) {
	long := strings.Repeat("x", 500)
	got, _ := readMeta(t, ngMeta(
		[]ngOpt{{optApp, []byte("tool\x1b[2J\x1b]0;pwned\x07 1.0")}, {optDesc, []byte(long)}},
		[]ngIface{{1, 0, []ngOpt{{optInterfaceN, []byte("eth0\r\nspoof")}}}}, nil, nil))
	require.NotNil(t, got)

	assert.Equal(t, "tool [2J ]0;pwned  1.0", got.CaptureTool, "no escape sequence reaches the terminal")
	assert.Equal(t, strings.Repeat("x", maxMetaLen)+"…", got.OS, "a long value is cut")
	assert.Equal(t, "eth0  spoof", got.Interfaces[0].Name)
	for _, s := range []string{got.CaptureTool, got.OS, got.Interfaces[0].Name} {
		assert.NotRegexp(t, "[\x00-\x1f\x7f]", s)
	}
}

func TestMetadataClassicPcapHasNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classic.pcap")
	writePCAP(t, path, [][]byte{serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, nil)})
	_, stats, err := ReadPacketsStats(path, ReadOptions{})
	require.NoError(t, err)
	assert.Nil(t, stats.Metadata)
}

func TestMetadataSurvivesTruncation(t *testing.T) {
	udp := serialize(t, layers.IPProtocolUDP, clientIP, serverIP, &layers.UDP{SrcPort: 1, DstPort: 2}, []byte("x"))
	data := ngMeta([]ngOpt{{optApp, []byte("tool 1")}}, []ngIface{{1, 0, nil}}, []uint32{0, 0, 0}, udp)
	path := filepath.Join(t.TempDir(), "cut.pcapng")
	require.NoError(t, os.WriteFile(path, data[:len(data)-10], 0o644))

	packets, stats, err := ReadPacketsStats(path, ReadOptions{})
	var trunc *TruncatedError
	require.ErrorAs(t, err, &trunc)
	assert.Len(t, packets, 2)
	require.NotNil(t, stats.Metadata)
	assert.Equal(t, "tool 1", stats.Metadata.CaptureTool)
}

func TestMetadataFromRealCapture(t *testing.T) {
	_, stats, err := ReadPacketsStats(filepath.Join("..", "..", "testdata", "Lab-7-TCPIssues.pcapng"), ReadOptions{})
	require.NoError(t, err)
	require.NotNil(t, stats.Metadata)
	assert.Equal(t, "Dumpcap (Wireshark) 3.4.9 (Git v3.4.9 packaged as 3.4.9-1)", stats.Metadata.CaptureTool)
	assert.Equal(t, "Linux 5.10.0-kali3-amd64", stats.Metadata.OS)
	assert.Equal(t, "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (with SSE4.2)", stats.Metadata.Hardware)
	assert.Equal(t, []models.InterfaceInfo{{Name: "eth0", LinkType: "Ethernet", SnapLen: 262144, Resolution: "nanosecond"}}, stats.Metadata.Interfaces)
}
