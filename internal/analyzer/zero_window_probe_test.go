package analyzer

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
	"github.com/gocisse/netforensic/internal/pcap"
)

// A sender whose receiver advertised a zero window sends one-byte probes of the
// next unsent byte. The receiver does not accept the probe byte (its ACK stays
// where it was), so the full segment that follows once the window reopens
// carries that byte for the first time: it is new data, not a retransmission.
// Wireshark labels the probes ZeroWindowProbe and reports no retransmission.
//
// The sender is the client 10.0.0.1:5000, the receiver the server 10.0.0.2:443
// (see tx). The client's initial sequence number is 1000, the server's 5000;
// the client has sent 4380 bytes, all acknowledged (ack 5381) with window 0.
const probeNext = 5381

// zeroWindowPrefix is the handshake, three full segments and the receiver's
// acknowledgment that closes its window.
func zeroWindowPrefix() []models.PacketInfo {
	return []models.PacketInfo{
		tx(0, false, "SYN", 1000, 0, 0, 65535),
		tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
		tx(2, false, "ACK", 1001, 5001, 0, 65535),
		tx(10, false, "PSH,ACK", 1001, 5001, 1460, 65535),
		tx(11, false, "PSH,ACK", 2461, 5001, 1460, 65535),
		tx(12, false, "PSH,ACK", 3921, 5001, 1460, 65535),
		tx(20, true, "ACK", 5001, probeNext, 0, 0),
	}
}

func probe(ms int) models.PacketInfo { return tx(ms, false, "ACK", probeNext, 5001, 1, 65535) }

func probeAck(ms int, ack uint32) models.PacketInfo { return tx(ms, true, "ACK", 5001, ack, 0, 0) }

func windowUpdate(ms int, ack uint32) models.PacketInfo {
	return tx(ms, true, "ACK", 5001, ack, 0, 16384)
}

func fullSegment(ms int, seq uint32) models.PacketInfo {
	return tx(ms, false, "PSH,ACK", seq, 5001, 1460, 65535)
}

func TestZeroWindowProbeIsNotRetransmitted(t *testing.T) {
	tests := []struct {
		name         string
		packets      []models.PacketInfo
		wantRetrans  int
		wantTimeouts int
		wantZeroWin  bool
	}{
		{"R1: one probe, unchanged ACK, window update, full segment at the probe's sequence number",
			append(zeroWindowPrefix(),
				probe(1000), probeAck(1001, probeNext),
				windowUpdate(2000, probeNext),
				fullSegment(2001, probeNext), tx(2002, true, "ACK", 5001, probeNext+1460, 0, 16384)),
			0, 0, true},
		{"R2: three probes, then the full segment",
			append(zeroWindowPrefix(),
				probe(1000), probeAck(1001, probeNext),
				probe(2000), probeAck(2001, probeNext),
				probe(4000), probeAck(4001, probeNext),
				windowUpdate(5000, probeNext),
				fullSegment(5001, probeNext), tx(5002, true, "ACK", 5001, probeNext+1460, 0, 16384)),
			0, 0, true},
		{"R3 control: a genuine timeout retransmission without a zero window",
			[]models.PacketInfo{
				tx(0, false, "SYN", 1000, 0, 0, 65535),
				tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
				tx(2, false, "ACK", 1001, 5001, 0, 65535),
				fullSegment(10, 1001),
				fullSegment(510, 1001),
				tx(520, true, "ACK", 5001, 1001+1460, 0, 8192)},
			1, 1, false},
		{"R4 control: the probe byte is acknowledged, the next data follows it",
			append(zeroWindowPrefix(),
				probe(1000), probeAck(1001, probeNext+1),
				windowUpdate(2000, probeNext+1),
				fullSegment(2001, probeNext+1), tx(2002, true, "ACK", 5001, probeNext+1461, 0, 16384)),
			0, 0, true},
		{"R5 control: the full segment is genuinely sent again after a second of silence",
			append(zeroWindowPrefix(),
				probe(1000), probeAck(1001, probeNext),
				windowUpdate(2000, probeNext),
				fullSegment(2001, probeNext),
				fullSegment(3200, probeNext), tx(3210, true, "ACK", 5001, probeNext+1460, 0, 16384)),
			1, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(tt.packets, "all")
			require.Len(t, res.TopTalkers, 1)
			flow := res.TopTalkers[0]
			assert.Equal(t, tt.wantRetrans, flow.Retransmits, "retransmitted segments")
			assert.Equal(t, tt.wantTimeouts, flow.TimeoutRetransmits, "timeout retransmissions")
			assert.Zero(t, flow.FastRetransmits)
			var titles []string
			for _, is := range retransmitIssues(res) {
				titles = append(titles, is.Title)
			}
			if tt.wantRetrans == 0 {
				assert.Empty(t, titles, "no retransmission issue")
			} else {
				assert.Equal(t, []string{titleTimeoutRetransmit}, titles)
			}
			var zero bool
			for _, is := range connectionIssues(res) {
				zero = zero || is.Title == titleZeroWindow
			}
			assert.Equal(t, tt.wantZeroWin, zero, "the zero window itself is still reported")
		})
	}
}

// writeProbePcap writes packets (built for tx: client 10.0.0.1:5000, server
// 10.0.0.2:443) to a pcap file, keeping every advertised window.
func writeProbePcap(t *testing.T, path string, packets []models.PacketInfo) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, p := range packets {
		src, dst := net.ParseIP(p.SrcIP).To4(), net.ParseIP(p.DstIP).To4()
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.SrcPort), DstPort: layers.TCPPort(p.DstPort), Seq: p.TCPSeq, Ack: p.TCPAck, Window: uint16(p.TCPWindow),
			SYN: hasTCPFlag(p.TCPFlags, "SYN"), ACK: hasTCPFlag(p.TCPFlags, "ACK"), PSH: hasTCPFlag(p.TCPFlags, "PSH")}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload(make([]byte, p.PayloadSize))))
		fr := buf.Bytes()
		ts := time.Unix(1700000000, 0).Add(p.Timestamp.Sub(rstT0))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(fr), Length: len(fr)}, fr))
	}
}

// T2: the same capture through the real reader. The zero window must survive
// the reader (it is what identifies the probe), and the probe-following
// segment must not be reported as a retransmission.
func TestZeroWindowProbeThroughTheReader(t *testing.T) {
	packets := append(zeroWindowPrefix(),
		probe(1000), probeAck(1001, probeNext),
		probe(2000), probeAck(2001, probeNext),
		windowUpdate(3000, probeNext),
		fullSegment(3001, probeNext), tx(3002, true, "ACK", 5001, probeNext+1460, 0, 16384))
	path := filepath.Join(t.TempDir(), "zero-window-probe.pcap")
	writeProbePcap(t, path, packets)

	read, stats, err := pcap.ReadPacketsStats(path, pcap.ReadOptions{SkipPreview: true})
	require.NoError(t, err)
	require.Len(t, read, len(packets))
	assert.Zero(t, stats.Skipped())
	var zeros int
	for _, p := range read {
		if p.TCPWindow == 0 && hasTCPFlag(p.TCPFlags, "ACK") && !hasTCPFlag(p.TCPFlags, "SYN") {
			zeros++
		}
	}
	assert.Equal(t, 3, zeros, "the receiver's three zero-window ACKs keep their window through the reader")

	res := Analyze(read, "all")
	require.Len(t, res.TopTalkers, 1)
	assert.Zero(t, res.TopTalkers[0].Retransmits)
	assert.Empty(t, retransmitIssues(res))
	var zero bool
	for _, is := range connectionIssues(res) {
		zero = zero || is.Title == titleZeroWindow
	}
	assert.True(t, zero)
}
