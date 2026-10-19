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

// After its FIN a sender may keep sending one byte at the sequence number of
// the last data byte, about once a second. When the receiver has already
// acknowledged that byte, the segment cannot be a retransmission: nothing but
// the FIN is outstanding. Wireshark labels these Spurious Retransmission. The
// FIN itself is retransmitted with a growing gap, and those are real.
//
// Client 10.0.0.1:5000 (the sender, see tx), server 10.0.0.2:443. The client
// sends a 430-byte request (bytes 1001-1430, the last byte at 1430), the server
// acknowledges it (ack 1431), the server sends its FIN, and the client answers
// with an ACK and its own FIN at 1431, which is never acknowledged.
const (
	lastByte = 1430
	finSeq   = 1431
)

// finSession is the connection up to and including both FINs.
func finSession() []models.PacketInfo {
	return []models.PacketInfo{
		tx(0, false, "SYN", 1000, 0, 0, 65535),
		tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
		tx(2, false, "ACK", 1001, 5001, 0, 65535),
		tx(10, false, "PSH,ACK", 1001, 5001, 430, 65535),
		tx(11, true, "ACK", 5001, finSeq, 0, 924),
		tx(20000, true, "FIN,ACK", 5001, finSeq, 0, 924),
		tx(20001, false, "ACK", finSeq, 5002, 0, 65535),
		tx(20002, false, "FIN,ACK", finSeq, 5002, 0, 65535),
	}
}

func finRetransmissions(ms ...int) []models.PacketInfo {
	var out []models.PacketInfo
	for _, m := range ms {
		out = append(out, tx(m, false, "FIN,ACK", finSeq, 5002, 0, 65535))
	}
	return out
}

// oneByte is n one-byte ACK segments, one second apart from ms on, at seq.
func oneByte(ms, n int, seq uint32, flags string) []models.PacketInfo {
	var out []models.PacketInfo
	for i := 0; i < n; i++ {
		out = append(out, tx(ms+i*1000, false, flags, seq, 5002, 1, 65535))
	}
	return out
}

func retransCounts(t *testing.T, res *models.AnalysisResult) (retrans, timeouts int) {
	t.Helper()
	require.Len(t, res.TopTalkers, 1)
	return res.TopTalkers[0].Retransmits, res.TopTalkers[0].TimeoutRetransmits
}

func TestPostFINProbes(t *testing.T) {
	tests := []struct {
		name         string
		packets      []models.PacketInfo
		wantRetrans  int
		wantTimeouts int
	}{
		{"P2: the FIN is retransmitted three times; the four acknowledged one-byte segments after it are not retransmissions",
			concat(finSession(), finRetransmissions(20300, 20900, 22100), oneByte(23000, 4, lastByte, "ACK")),
			3, 3},
		{"P6a: the capture starts at the server FIN, whose ACK number acknowledges the data",
			concat([]models.PacketInfo{
				tx(0, true, "FIN,ACK", 5001, finSeq, 0, 924),
				tx(1, false, "ACK", finSeq, 5002, 0, 65535),
				tx(2, false, "FIN,ACK", finSeq, 5002, 0, 65535)},
				finRetransmissions(300, 900, 2100), oneByte(3000, 4, lastByte, "ACK")),
			3, 3},
		{"P1 control: an ordinary keep-alive before the FIN is not a retransmission",
			concat(finSession()[:5], []models.PacketInfo{
				tx(10000, false, "ACK", lastByte, 5001, 1, 65535), tx(10030, true, "ACK", 5001, finSeq, 0, 924)}),
			0, 0},
		{"P4 control: FIN retransmissions alone are all detected",
			concat(finSession(), finRetransmissions(20300, 20900, 22100, 24500)),
			4, 4},
		{"P5a control: a one-byte segment at FIN-2 is not covered by the rule",
			concat(finSession(), oneByte(23000, 3, lastByte-1, "ACK")),
			3, 3},
		{"P5c control: a two-byte segment at FIN-1 is not covered by the rule",
			concat(finSession(), []models.PacketInfo{
				tx(23000, false, "ACK", lastByte, 5002, 2, 65535),
				tx(24000, false, "ACK", lastByte, 5002, 2, 65535),
				tx(25000, false, "ACK", lastByte, 5002, 2, 65535)}),
			2, 2},
		{"P6b control: with no server packet captured there is no acknowledgment history, so the segments stay as before",
			concat([]models.PacketInfo{tx(0, false, "FIN,ACK", finSeq, 5002, 0, 65535)},
				finRetransmissions(300, 900, 2100), oneByte(3000, 4, lastByte, "ACK")),
			6, 6},
		{"P3c control: a genuine one-byte retransmission is still found once the server has sent a pure ACK with a window",
			[]models.PacketInfo{
				tx(0, false, "SYN", 1000, 0, 0, 65535),
				tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
				tx(2, false, "ACK", 1001, 5001, 0, 65535),
				tx(50, true, "ACK", 5001, 1001, 0, 924),
				tx(100, false, "PSH,ACK", 1001, 5001, 1, 65535),
				tx(110, false, "PSH,ACK", 1002, 5001, 400, 65535),
				tx(1300, false, "PSH,ACK", 1001, 5001, 1, 65535),
				tx(1330, true, "ACK", 5001, 1402, 0, 924)},
			1, 1},
		{"P7 control: the byte before the FIN was never acknowledged, so its resend after the FIN is a retransmission",
			[]models.PacketInfo{
				tx(0, false, "SYN", 1000, 0, 0, 65535),
				tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
				tx(2, false, "ACK", 1001, 5001, 0, 65535),
				tx(50, true, "ACK", 5001, 1001, 0, 924), // acknowledges nothing beyond the handshake
				tx(100, false, "PSH,ACK", 1001, 5001, 1, 65535),
				tx(110, false, "FIN,ACK", 1002, 5001, 0, 65535),
				tx(1200, false, "PSH,ACK", 1001, 5001, 1, 65535), // the byte again, still unacknowledged
				tx(1250, true, "ACK", 5001, 1003, 0, 924)},
			1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrans, timeouts := retransCounts(t, Analyze(tt.packets, "all"))
			assert.Equal(t, tt.wantRetrans, retrans, "retransmitted segments")
			assert.Equal(t, tt.wantTimeouts, timeouts, "timeout retransmissions")
		})
	}
}

func concat(parts ...[]models.PacketInfo) []models.PacketInfo {
	var out []models.PacketInfo
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// writeFINPcap writes packets (built for tx) to a pcap file with every flag
// and window kept; unlike the other test writers it keeps FIN.
func writeFINPcap(t *testing.T, path string, packets []models.PacketInfo) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, p := range packets {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(p.SrcIP).To4(), DstIP: net.ParseIP(p.DstIP).To4()}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.SrcPort), DstPort: layers.TCPPort(p.DstPort), Seq: p.TCPSeq, Ack: p.TCPAck, Window: uint16(p.TCPWindow),
			SYN: hasTCPFlag(p.TCPFlags, "SYN"), ACK: hasTCPFlag(p.TCPFlags, "ACK"), PSH: hasTCPFlag(p.TCPFlags, "PSH"), FIN: hasTCPFlag(p.TCPFlags, "FIN")}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload(make([]byte, p.PayloadSize))))
		fr := buf.Bytes()
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0).Add(p.Timestamp.Sub(rstT0)), CaptureLength: len(fr), Length: len(fr)}, fr))
	}
}

// The P2 capture through the real reader: the FINs and the acknowledgment
// numbers survive it, the three FIN retransmissions are the only ones.
func TestPostFINProbesThroughTheReader(t *testing.T) {
	packets := concat(finSession(), finRetransmissions(20300, 20900, 22100), oneByte(23000, 4, lastByte, "ACK"))
	path := filepath.Join(t.TempDir(), "post-fin-probes.pcap")
	writeFINPcap(t, path, packets)

	read, stats, err := pcap.ReadPacketsStats(path, pcap.ReadOptions{SkipPreview: true})
	require.NoError(t, err)
	require.Len(t, read, len(packets))
	assert.Zero(t, stats.Skipped())
	var fins int
	for _, p := range read {
		if hasTCPFlag(p.TCPFlags, "FIN") && p.SrcPort == 5000 {
			fins++
		}
	}
	assert.Equal(t, 4, fins, "the client's FIN and its three retransmissions")

	retrans, timeouts := retransCounts(t, Analyze(read, "all"))
	assert.Equal(t, 3, retrans)
	assert.Equal(t, 3, timeouts)
}
