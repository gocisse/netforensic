package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
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

func TestPrintPacketTable(t *testing.T) {
	ts := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	tests := []struct {
		name   string
		packet models.PacketInfo
		want   []string
	}{
		{"tcp", models.PacketInfo{Timestamp: ts, SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80,
			Protocol: models.ProtocolTCP, Size: 100, TCPFlags: "SYN,ACK", TCPSeq: 1000},
			[]string{"2023-11-14 22:13:20.000", "10.0.0.1:12345", "10.0.0.2:80", "TCP", "100", "SYN,ACK", "1000"}},
		{"udp has no flags or seq", models.PacketInfo{Timestamp: ts, SrcIP: "1.1.1.1", SrcPort: 5, DstIP: "8.8.8.8", DstPort: 53,
			Protocol: models.ProtocolUDP, Size: 60},
			[]string{"1.1.1.1:5", "8.8.8.8:53", "UDP", "60", "-"}},
		{"icmp without ports", models.PacketInfo{Timestamp: ts, SrcIP: "1.1.1.1", DstIP: "8.8.8.8",
			Protocol: models.ProtocolICMP, Size: 84},
			[]string{"1.1.1.1  ", "8.8.8.8  ", "ICMP"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, printPacketTable(&buf, []models.PacketInfo{tt.packet}))
			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			require.Len(t, lines, 3)
			assert.Contains(t, lines[0], "SOURCE")
			for _, w := range tt.want {
				assert.Contains(t, lines[2], w)
			}
		})
	}
}

func TestGroupIssues(t *testing.T) {
	mk := func(sev models.Severity, cat, title string, n int) []models.Issue {
		out := make([]models.Issue, n)
		for i := range out {
			out[i] = models.Issue{Severity: sev, Category: cat, Title: title}
		}
		return out
	}
	var issues []models.Issue
	issues = append(issues, mk(models.SeverityInfo, "HTTP", "HTTP Slow Response", 1)...)
	issues = append(issues, mk(models.SeverityWarning, "DNS", "DNS NXDOMAIN", 22)...)
	issues = append(issues, mk(models.SeverityWarning, "DNS", "DNS Timeout", 19)...)
	issues = append(issues, mk(models.SeverityError, "ICMP", "ICMP Destination Unreachable", 4)...)
	issues = append(issues, mk(models.SeverityWarning, "ICMP", "ICMP Time Exceeded", 12)...)
	issues = append(issues, mk(models.SeverityCritical, "X", "Meltdown", 1)...)
	issues = append(issues, mk(models.SeverityWarning, "Connection", "Alpha", 1)...)
	issues = append(issues, mk(models.SeverityWarning, "Connection", "Beta", 1)...)
	issues = append(issues, mk(models.SeverityWarning, "Another", "Zeta", 1)...)
	issues = append(issues, mk(models.SeverityError, "ICMP", "ICMP Destination Unreachable", 0)...)
	// the same title at another severity is a different group
	issues = append(issues, mk(models.SeverityInfo, "DNS", "DNS NXDOMAIN", 2)...)

	var got []string
	for _, g := range groupIssues(issues) {
		got = append(got, fmt.Sprintf("%d %s %s", g.count, g.severity, g.title))
	}
	assert.Equal(t, []string{
		"1 CRITICAL Meltdown",
		"4 ERROR ICMP Destination Unreachable",
		"22 WARNING DNS NXDOMAIN",
		"19 WARNING DNS Timeout",
		"12 WARNING ICMP Time Exceeded",
		"1 WARNING Zeta",
		"1 WARNING Alpha",
		"1 WARNING Beta",
		"2 INFO DNS NXDOMAIN",
		"1 INFO HTTP Slow Response",
	}, got, "severity first, then count, then category and title")
	assert.Empty(t, groupIssues(nil))
}

func TestPrintIssueSummary(t *testing.T) {
	var issues []models.Issue
	for i := 0; i < 22; i++ {
		issues = append(issues, models.Issue{Severity: models.SeverityWarning, Category: "DNS", Title: "DNS NXDOMAIN"})
	}
	issues = append(issues, models.Issue{Severity: models.SeverityError, Category: "ICMP", Title: "ICMP Destination Unreachable"})

	var buf bytes.Buffer
	printIssueSummary(&buf, issues)
	assert.Equal(t, "   1x [ERROR] ICMP: ICMP Destination Unreachable\n"+
		"  22x [WARNING] DNS: DNS NXDOMAIN\n", buf.String(), "counts are right-aligned")

	buf.Reset()
	printIssueSummary(&buf, nil)
	assert.Empty(t, buf.String())
}

func TestRootCmdCollapsesIssueListButNotJSON(t *testing.T) {
	// 30 resolvers each answer NXDOMAIN: 30 issues of one kind
	dir := t.TempDir()
	path := filepath.Join(dir, "many.pcap")
	writeManyDNSFailures(t, path, 30)

	run := func(args ...string) string {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append(args, path))
		require.NoError(t, cmd.Execute())
		return out.String()
	}

	text := run()
	assert.Contains(t, text, "found 30 issues")
	assert.Equal(t, 1, strings.Count(text, "x [WARNING] DNS: DNS NXDOMAIN"))
	assert.Contains(t, text, " 30x [WARNING] DNS: DNS NXDOMAIN")

	var res models.AnalysisResult
	require.NoError(t, json.Unmarshal([]byte(run("-o", "json")), &res))
	assert.Len(t, res.Issues, 30, "JSON keeps every issue")
}

// writeManyDNSFailures writes a pcap in which n different resolvers each
// answer one query with NXDOMAIN, which yields n DNS NXDOMAIN issues.
func writeManyDNSFailures(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))

	client := net.IPv4(10, 0, 0, 1)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	write := func(at time.Time, src, dst net.IP, sport, dport layers.UDPPort, dns *layers.DNS) {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
		udp := &layers.UDP{SrcPort: sport, DstPort: dport}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dns))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()))
	}
	t0 := time.Unix(1700000000, 0)
	for i := 0; i < n; i++ {
		resolver := net.IPv4(192, 168, 1, byte(i+1))
		q := layers.DNSQuestion{Name: []byte(fmt.Sprintf("missing%d.example", i)), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
		at := t0.Add(time.Duration(i) * time.Second)
		write(at, client, resolver, 40000, 53, &layers.DNS{ID: uint16(i + 1), RD: true, QDCount: 1, Questions: []layers.DNSQuestion{q}})
		write(at.Add(10*time.Millisecond), resolver, client, 53, 40000,
			&layers.DNS{ID: uint16(i + 1), QR: true, RD: true, RA: true, ResponseCode: layers.DNSResponseCodeNXDomain, QDCount: 1, Questions: []layers.DNSQuestion{q}})
	}
}

// writeFrames writes raw Ethernet frames, one second apart, to a pcap file.
func writeFrames(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, data := range frames {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(data), Length: len(data)}, data))
	}
}

func udpFrame(t *testing.T) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
	udp := &layers.UDP{SrcPort: 1000, DstPort: 2000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		ip, udp, gopacket.Payload([]byte("hi"))))
	return buf.Bytes()
}

// lldpFrame is a layer-2 control frame: not IP, not ARP.
func lldpFrame() []byte {
	return append([]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc}, make([]byte, 30)...)
}

func TestRootCmdWarnsAboutSkippedFrames(t *testing.T) {
	dir := t.TempDir()
	mixed := filepath.Join(dir, "mixed.pcap")
	writeFrames(t, mixed, [][]byte{udpFrame(t), lldpFrame(), udpFrame(t), lldpFrame(), lldpFrame()})
	only := filepath.Join(dir, "only-l2.pcap")
	writeFrames(t, only, [][]byte{lldpFrame(), lldpFrame()})
	clean := filepath.Join(dir, "clean.pcap")
	writeFrames(t, clean, [][]byte{udpFrame(t), udpFrame(t)})

	run := func(args ...string) (string, string) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		require.NoError(t, cmd.Execute())
		return out.String(), errOut.String()
	}

	t.Run("text: warning in the timeline and on stderr", func(t *testing.T) {
		out, errOut := run(mixed)
		assert.Contains(t, out, "[INFO]     issue         Skipped Frames: 3 frames were skipped due to unsupported link-layer types or non-IP traffic. Analysis is based on the remaining 2 packets. (3 non-IP frames: 3 LLDP)")
		assert.Contains(t, out, "Health Score: 100/100 (HEALTHY)", "an informational note costs nothing")
		assert.Contains(t, out, "No significant issues detected", "and is not a root cause")
		assert.Contains(t, out, "1x [INFO] Capture: Skipped Frames")
		assert.Contains(t, errOut, "warning: 3 of 5 frames were skipped")
	})
	t.Run("json: the issue carries the count", func(t *testing.T) {
		out, errOut := run("-o", "json", mixed)
		var res struct {
			TotalPackets int `json:"total_packets"`
			Issues       []struct {
				Title string `json:"title"`
				Count int    `json:"count"`
			} `json:"issues"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &res))
		assert.Equal(t, 2, res.TotalPackets)
		require.Len(t, res.Issues, 1)
		assert.Equal(t, "Skipped Frames", res.Issues[0].Title)
		assert.Equal(t, 3, res.Issues[0].Count)
		assert.Empty(t, errOut, "stderr stays quiet in JSON mode")
	})
	t.Run("a capture of only layer-2 frames explains itself", func(t *testing.T) {
		out, _ := run(only)
		assert.Contains(t, out, "The capture contains no analyzable packets. Nothing to analyze.")
		assert.Contains(t, out, "Skipped Frames: 2 frames were skipped")
		assert.NotContains(t, out, "Health Score")

		out, _ = run("-o", "json", only)
		assert.Contains(t, out, `"title": "Skipped Frames"`)
		assert.Contains(t, out, `"message": "The capture contains no analyzable packets"`)
	})
	t.Run("a clean capture has no warning", func(t *testing.T) {
		out, errOut := run(clean)
		assert.NotContains(t, out, "Skipped Frames")
		assert.Empty(t, errOut)
		assert.Contains(t, out, "Health Score: 100/100")
	})
	t.Run("follow does not print the warning noise", func(t *testing.T) {
		_, errOut := run("--follow-packets", "10.0.0.1:1000-10.0.0.2:2000", mixed)
		assert.Empty(t, errOut)
	})
}

func TestDescribeSkipped(t *testing.T) {
	assert.Equal(t, "", describeSkipped(pcap.ReadStats{}))
	assert.Equal(t, "7 non-IP frames", describeSkipped(pcap.ReadStats{SkippedNonIP: 7}))
	assert.Equal(t, "5 frames of unsupported link type 18; 2 frames of unsupported link type 250; 7 non-IP frames",
		describeSkipped(pcap.ReadStats{SkippedNonIP: 7, UnsupportedLinkTypes: map[int]int{250: 2, 18: 5}}))
}

func TestPacketTableBracketsIPv6(t *testing.T) {
	assert.Equal(t, "[2001:db8::1]:443", formatEndpoint("2001:db8::1", 443))
	assert.Equal(t, "10.0.0.1:443", formatEndpoint("10.0.0.1", 443))
	assert.Equal(t, "2001:db8::1", formatEndpoint("2001:db8::1", 0), "portless protocols show the bare address")
}
