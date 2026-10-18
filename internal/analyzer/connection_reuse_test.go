package analyzer

import (
	"net"
	"path/filepath"
	"strings"
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

// Connections that reuse a 4-tuple without a FIN or RST in between, written to
// a pcap file and read back by the real reader, so that the connection
// numbering, the handshake annotation and the analysis are tested together.
// Client 10.0.0.1:41000, server 10.0.0.2:80. The tshark stream counts quoted
// in the cases are those of the same packets in Wireshark.

// seg is one TCP segment of such a capture.
type seg struct {
	at         time.Duration // since the start of the capture
	fromClient bool
	flags      string // SYN, ACK, PSH, FIN, RST joined by commas
	seq, ack   uint32
	payload    int
}

func hasFlagStr(flags, f string) bool {
	for _, x := range strings.Split(flags, ",") {
		if x == f {
			return true
		}
	}
	return false
}

// writeSegments serializes segs into a pcap file at path.
func writeSegments(t *testing.T, path string, segs []seg) {
	t.Helper()
	f, err := createFile(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	start := time.Unix(1700000000, 0)
	for _, s := range segs {
		srcIP, dstIP, sport, dport := net.ParseIP(server).To4(), net.ParseIP(client).To4(), layers.TCPPort(80), layers.TCPPort(41000)
		if s.fromClient {
			srcIP, dstIP, sport, dport = dstIP, srcIP, dport, sport
		}
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
		tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: s.seq, Ack: s.ack, Window: 65535,
			SYN: hasFlagStr(s.flags, "SYN"), ACK: hasFlagStr(s.flags, "ACK"), PSH: hasFlagStr(s.flags, "PSH"),
			FIN: hasFlagStr(s.flags, "FIN"), RST: hasFlagStr(s.flags, "RST")}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, gopacket.Payload(make([]byte, s.payload))))
		fr := buf.Bytes()
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: start.Add(s.at), CaptureLength: len(fr), Length: len(fr)}, fr))
	}
	require.NoError(t, f.Close())
}

// connAt is a complete connection starting at t0: the handshake takes hs, the
// server answers a 100-byte request after resp.
func connAt(t0 time.Duration, isn, ssn uint32, hs, resp time.Duration) []seg {
	ms := time.Millisecond
	return []seg{
		{t0, true, "SYN", isn, 0, 0},
		{t0 + hs/2, false, "SYN,ACK", ssn, isn + 1, 0},
		{t0 + hs, true, "ACK", isn + 1, ssn + 1, 0},
		{t0 + hs + 5*ms, true, "PSH,ACK", isn + 1, ssn + 1, 100},
		{t0 + hs + 5*ms + resp, false, "PSH,ACK", ssn + 1, isn + 101, 200},
		{t0 + hs + 10*ms + resp, true, "ACK", isn + 101, ssn + 201, 0},
	}
}

func analyzeSegments(t *testing.T, segs []seg) *models.AnalysisResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reuse.pcap")
	writeSegments(t, path, segs)
	packets, err := pcap.ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, packets, len(segs))
	return Analyze(packets, "all")
}

func flowByID(t *testing.T, res *models.AnalysisResult, suffix string) models.Flow {
	t.Helper()
	for _, f := range res.Flows {
		if strings.HasSuffix(f.ID, suffix) {
			return f
		}
	}
	require.Failf(t, "no such flow", "suffix %q in %v", suffix, res.Flows)
	return models.Flow{}
}

func issuesWithPrefix(res *models.AnalysisResult, prefix string) []models.Issue {
	var out []models.Issue
	for _, is := range res.Issues {
		if strings.HasPrefix(is.Title, prefix) {
			out = append(out, is)
		}
	}
	return out
}

const baseFlow = "10.0.0.1:41000-10.0.0.2:80"

func TestReusedTupleWithoutFINOrRSTIsTwoFlows(t *testing.T) {
	ms := time.Millisecond
	// The second connection reuses the ports with another ISN and has a 700 ms
	// handshake. tshark: 2 streams.
	segs := append(connAt(0, 1000, 5000, 30*ms, 50*ms), connAt(5*time.Second, 9000, 7000, 700*ms, 50*ms)...)
	res := analyzeSegments(t, segs)

	require.Equal(t, 2, res.TotalFlows)
	first, second := flowByID(t, res, baseFlow), flowByID(t, res, baseFlow+"#2")
	assert.Equal(t, 6, first.PacketCount)
	assert.Equal(t, 6, second.PacketCount)
	assert.InDelta(t, 30, first.SetupTimeMs, 0.01)
	assert.InDelta(t, 700, second.SetupTimeMs, 0.01, "the second connection has its own handshake times")
	require.NotNil(t, first.TCPStream)
	require.NotNil(t, second.TCPStream)
	assert.NotEqual(t, *first.TCPStream, *second.TCPStream, "each flow is one Wireshark stream")

	slow := issuesWithPrefix(res, "Slow TCP Handshake")
	require.Len(t, slow, 1, "the slow handshake of the second connection is no longer hidden")
	assert.Equal(t, second.ID, slow[0].FlowID)
}

func TestReusedTupleAfterARSTIsStillTwoFlows(t *testing.T) {
	ms := time.Millisecond
	segs := append(connAt(0, 1000, 5000, 30*ms, 50*ms), seg{time.Second, false, "RST,ACK", 5201, 1101, 0})
	res := analyzeSegments(t, append(segs, connAt(5*time.Second, 9000, 7000, 700*ms, 50*ms)...))
	require.Equal(t, 2, res.TotalFlows)
	assert.InDelta(t, 700, flowByID(t, res, baseFlow+"#2").SetupTimeMs, 0.01)
	assert.Len(t, issuesWithPrefix(res, "Slow TCP Handshake"), 1)
}

func TestSYNsWithChangingISNsAreSeparateAttemptsButARetryIsNot(t *testing.T) {
	s := time.Second
	last := seg{6 * s, true, "ACK", 3001, 1, 0} // keeps the capture running after the last SYN

	t.Run("changing ISNs: three attempts (tshark: 3 streams)", func(t *testing.T) {
		res := analyzeSegments(t, []seg{{0, true, "SYN", 1000, 0, 0}, {1200 * time.Millisecond, true, "SYN", 2000, 0, 0}, {2400 * time.Millisecond, true, "SYN", 3000, 0, 0}, last})
		assert.Equal(t, 3, res.TotalFlows)
		un := issuesWithPrefix(res, "Unanswered SYN")
		require.Len(t, un, 1, "folded into one issue")
		assert.Equal(t, 3, un[0].Count)
		assert.Equal(t, models.SeverityWarning, un[0].Severity)
		assert.Empty(t, retransmitIssues(res))
	})
	t.Run("the same ISN: one connection retried three times (tshark: 1 stream)", func(t *testing.T) {
		res := analyzeSegments(t, []seg{{0, true, "SYN", 1000, 0, 0}, {1200 * time.Millisecond, true, "SYN", 1000, 0, 0}, {2400 * time.Millisecond, true, "SYN", 1000, 0, 0}, {6 * s, true, "ACK", 1001, 1, 0}})
		assert.Equal(t, 1, res.TotalFlows)
		un := issuesWithPrefix(res, "Unanswered SYN")
		require.Len(t, un, 1)
		assert.Equal(t, 1, un[0].Count)
		assert.Contains(t, un[0].Description, "in 3 tries")
		assert.Empty(t, retransmitIssues(res), "Step 6.6: the SYN retries of an unanswered connection are not a retransmission issue")
	})
	t.Run("the SYN-ACK acknowledges the second ISN (tshark: 2 streams)", func(t *testing.T) {
		res := analyzeSegments(t, []seg{{0, true, "SYN", 1000, 0, 0}, {time.Second, true, "SYN", 2000, 0, 0},
			{1030 * time.Millisecond, false, "SYN,ACK", 5000, 2001, 0}, {1060 * time.Millisecond, true, "ACK", 2001, 5001, 0}})
		require.Equal(t, 2, res.TotalFlows)
		assert.InDelta(t, 60, flowByID(t, res, baseFlow+"#2").SetupTimeMs, 0.01, "the answered attempt took 60 ms, not 1060 ms")
		un := issuesWithPrefix(res, "Unanswered SYN")
		require.Len(t, un, 1)
		assert.Equal(t, baseFlow, un[0].FlowID, "the first ISN was never answered")
		assert.Empty(t, issuesWithPrefix(res, titleSYNRetried))
	})
}

func TestThreeReusesWithASYNRetryInTheLast(t *testing.T) {
	ms := time.Millisecond
	segs := append(connAt(0, 1000, 5000, 30*ms, 50*ms), connAt(5*time.Second, 9000, 7000, 700*ms, 50*ms)...)
	segs = append(segs,
		seg{10 * time.Second, true, "SYN", 20000, 0, 0}, seg{11 * time.Second, true, "SYN", 20000, 0, 0}, // the same ISN: a retry
		seg{11*time.Second + 30*ms, false, "SYN,ACK", 8000, 20001, 0}, seg{11*time.Second + 60*ms, true, "ACK", 20001, 8001, 0})
	res := analyzeSegments(t, segs) // tshark: 3 streams

	require.Equal(t, 3, res.TotalFlows)
	third := flowByID(t, res, baseFlow+"#3")
	assert.Equal(t, 4, third.PacketCount)
	retried := issuesWithPrefix(res, titleSYNRetried)
	require.Len(t, retried, 1)
	assert.Equal(t, third.ID, retried[0].FlowID, "the retry belongs to the third connection only")
	slow := issuesWithPrefix(res, "Slow TCP Handshake")
	require.Len(t, slow, 1)
	assert.Equal(t, baseFlow+"#2", slow[0].FlowID)
}
