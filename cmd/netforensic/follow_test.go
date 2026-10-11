package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/models"
)

func synthetic() []models.PacketInfo {
	t0 := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	tcp := func(ms int, fromClient bool, flags string, seq uint32, payload string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP,
			TCPFlags: flags, TCPSeq: seq, PayloadSize: len(payload), PayloadPreview: []byte(payload)}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.1.50", 43210, "10.0.2.10", 443
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.2.10", 443, "10.0.1.50", 43210
		}
		return p
	}
	hello := tcp(300, true, "PSH,ACK", 101, "\x16\x03\x01")
	hello.TLSHandshakeType, hello.TLSVersion = "ClientHello", "TLS 1.2"
	alert := tcp(400, false, "PSH,ACK", 501, "\x15\x03\x03")
	alert.TLSHandshakeType, alert.TLSAlertLevel, alert.TLSAlertDescription = "Alert", "fatal", "handshake_failure"

	dnsQ := models.PacketInfo{Timestamp: t0, Protocol: models.ProtocolUDP, SrcIP: "10.0.1.50", SrcPort: 5353, DstIP: "10.0.0.53", DstPort: 53,
		DNSQueryName: "example.com", DNSIsQuery: true, DNSResponseType: "A"}
	dnsR := models.PacketInfo{Timestamp: t0.Add(20 * time.Millisecond), Protocol: models.ProtocolUDP, SrcIP: "10.0.0.53", SrcPort: 53, DstIP: "10.0.1.50", DstPort: 5353,
		DNSQueryName: "example.com", DNSResponseCode: "NOERROR", DNSAnswers: []string{"A 93.184.216.34"}}

	return []models.PacketInfo{
		dnsQ, dnsR,
		tcp(0, true, "SYN", 100, ""),
		tcp(100, false, "SYN,ACK", 500, ""),
		tcp(200, true, "ACK", 101, ""),
		hello, alert,
		tcp(500, true, "PSH,ACK", 104, "GET /secret HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
}

func TestFollowPacketsOutput(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, followPackets(&buf, synthetic(), "10.0.1.50:43210-10.0.2.10:443"))
	out := buf.String()

	assert.Contains(t, out, "Following flow 10.0.1.50:43210-10.0.2.10:443")
	assert.Contains(t, out, "client 10.0.1.50:43210  →  server 10.0.2.10:443, 6 packet(s)")
	assert.Contains(t, out, "22:13:20.000  →  TCP   [SYN] seq=100 len=0")
	assert.Contains(t, out, "22:13:20.100  ←  TCP   [SYN,ACK] seq=500 len=0")
	assert.Contains(t, out, "→  TLS   [PSH,ACK] seq=101 len=3  ClientHello (TLS 1.2)")
	assert.Contains(t, out, "←  TLS   [PSH,ACK] seq=501 len=3  Alert fatal handshake_failure")
	// generic payload is hex+ASCII dumped
	assert.Contains(t, out, "0000  47 45 54 20 2f 73 65 63")
	assert.Contains(t, out, "|GET /secret HTTP|")
	// the follow view omits the triage report and summary, and other flows
	assert.NotContains(t, out, "TRIAGE")
	assert.NotContains(t, out, "Analyzed")
	assert.NotContains(t, out, "example.com")
}

func TestFollowPacketsDNS(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, followPackets(&buf, synthetic(), "10.0.1.50:5353-10.0.0.53:53/udp"))
	out := buf.String()
	assert.Contains(t, out, "→  DNS")
	assert.Contains(t, out, "query example.com (A)")
	assert.Contains(t, out, "←  DNS")
	assert.Contains(t, out, "response example.com NOERROR: A 93.184.216.34")
}

func TestFollowPacketsHTTPDetail(t *testing.T) {
	req := models.PacketInfo{Timestamp: time.Unix(0, 0), Protocol: models.ProtocolTCP, SrcIP: "1.1.1.1", SrcPort: 1, DstIP: "2.2.2.2", DstPort: 80,
		HTTPMethod: "GET", HTTPURI: "/a", PayloadSize: 40, PayloadPreview: []byte("GET /a HTTP/1.1\r\nHost: h.com\r\n\r\n")}
	var buf bytes.Buffer
	require.NoError(t, followPackets(&buf, []models.PacketInfo{req}, "1.1.1.1:1-2.2.2.2:80"))
	assert.Contains(t, buf.String(), "HTTP  [none] seq=0 len=40  GET /a")
	assert.Contains(t, buf.String(), "      Host: h.com")
}

func TestFollowErrors(t *testing.T) {
	tests := []struct {
		name, id string
		want     []string
	}{
		{"invalid", "invalid-flow-id", []string{"invalid flow ID", "available flows:", "10.0.1.50:43210-10.0.2.10:443/TCP  (6 packets)", "10.0.0.53:53-10.0.1.50:5353/UDP  (2 packets)"}},
		{"not found", "1.2.3.4:1-5.6.7.8:2", []string{"not found", "available flows:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := followPackets(&buf, synthetic(), tt.id)
			require.Error(t, err)
			assert.Empty(t, buf.String())
			for _, w := range tt.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}

	err := followPackets(&bytes.Buffer{}, nil, "1.2.3.4:1-5.6.7.8:2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no flows are available")
}

func TestFormatFollowErrorTruncatesLongLists(t *testing.T) {
	fe := &analyzer.FollowError{Reason: "nope"}
	for i := 0; i < maxListedFlows+7; i++ {
		fe.Available = append(fe.Available, analyzer.FlowSummary{ID: "x", Protocol: models.ProtocolTCP, Packets: 1})
	}
	out := formatFollowError(fe)
	assert.Equal(t, maxListedFlows+3, len(strings.Split(out, "\n")))
	assert.Contains(t, out, "... and 7 more")
}

func TestPrintConversationPayloadTruncationNote(t *testing.T) {
	c := &analyzer.Conversation{FlowID: "f", Client: "a", Server: "b", Events: []analyzer.StreamEvent{{
		Timestamp: time.Unix(0, 0), ToServer: true, Kind: "UDP",
		Packet:  models.PacketInfo{Protocol: models.ProtocolUDP, PayloadSize: 250},
		Payload: bytes.Repeat([]byte{'a'}, 100),
	}}}
	var buf bytes.Buffer
	printConversation(&buf, c)
	assert.Contains(t, buf.String(), "... 150 more byte(s)")
	assert.Contains(t, buf.String(), "0060  61 61 61 61")
}

func TestHexDump(t *testing.T) {
	rows := hexDump([]byte("ABCDEFGHIJKLMNOPQR\x00\xff"))
	require.Len(t, rows, 2)
	assert.Equal(t, "0000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|", rows[0])
	assert.Equal(t, "0010  51 52 00 ff                                       |QR..|", rows[1])
	assert.Empty(t, hexDump(nil))
}

func TestRootCmdFilters(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"
	run := func(args ...string) (stdout, stderr string, err error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append(args, sample))
		err = cmd.Execute()
		return out.String(), errOut.String(), err
	}

	t.Run("src-ip limits analysis and packet table", func(t *testing.T) {
		out, _, err := run("--src-ip", "10.0.0.1", "-v")
		require.NoError(t, err)
		assert.Contains(t, out, "Analyzed 1 packets in 1 flows")
		assert.Contains(t, out, "10.0.0.1:12345")
		assert.NotContains(t, out, "8.8.8.8")
		assert.Contains(t, out, "No anomalies were found in 1 packets")
	})
	t.Run("combined filters use AND", func(t *testing.T) {
		out, _, err := run("--src-ip", "10.0.0.1", "--dst-port", "80", "--src-port", "12345", "--dst-ip", "10.0.0.2")
		require.NoError(t, err)
		assert.Contains(t, out, "Analyzed 1 packets")

		out, errOut, err := run("--src-ip", "10.0.0.1", "--dst-port", "53")
		require.NoError(t, err)
		assert.Contains(t, out, "No packets matched the specified filters. Nothing to analyze.")
		assert.Contains(t, errOut, "no packets match the filters")
	})
	t.Run("dst-port zero is a real filter", func(t *testing.T) {
		out, _, err := run("--dst-port", "0")
		require.NoError(t, err)
		assert.Contains(t, out, "No packets matched the specified filters")
	})
	t.Run("filters apply to json output", func(t *testing.T) {
		out, _, err := run("--dst-port", "53", "-o", "json")
		require.NoError(t, err)
		assert.Contains(t, out, `"total_packets": 1`)
	})
	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, args := range [][]string{{"--src-ip", "nope"}, {"--dst-ip", "1.2.3"}, {"--src-port", "70000"}, {"--dst-port", "-5"}} {
			_, _, err := run(args...)
			assert.Error(t, err, args)
		}
	})
}

func TestRootCmdFollow(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(append(args, sample))
		err := cmd.Execute()
		return out.String(), err
	}

	out, err := run("--follow", "10.0.0.1:12345-10.0.0.2:80")
	require.NoError(t, err)
	assert.Contains(t, out, "Following stream 10.0.0.1:12345-10.0.0.2:80")
	assert.Contains(t, out, "GET /index.html")
	assert.Contains(t, out, "Host: example.com")
	assert.NotContains(t, out, "seq=")
	assert.NotContains(t, out, "TRIAGE")

	out, err = run("--follow-packets", "10.0.0.1:12345-10.0.0.2:80")
	require.NoError(t, err)
	assert.Contains(t, out, "Following flow 10.0.0.1:12345-10.0.0.2:80")
	assert.Contains(t, out, "seq=")

	_, err = run("--follow", "10.0.0.1:12345-10.0.0.2:80", "--follow-packets", "10.0.0.1:12345-10.0.0.2:80")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")

	_, err = run("--follow-packets", "10.0.0.1:12345-10.0.0.2:80", "-o", "json")
	assert.Error(t, err)
	assert.NotContains(t, out, "Analyzed")

	out, err = run("--follow", "invalid-flow-id")
	require.Error(t, err)
	assert.Empty(t, out)
	assert.Contains(t, err.Error(), "available flows:")
	assert.Contains(t, err.Error(), "10.0.0.1:12345-10.0.0.2:80/TCP")

	_, err = run("--follow", "10.0.0.1:12345-10.0.0.2:80", "-o", "json")
	assert.Error(t, err)

	// a filter that excludes the flow leaves nothing to follow
	_, err = run("--follow", "10.0.0.1:12345-10.0.0.2:80", "--src-ip", "8.8.8.8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRootCmdTruncatedCapture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/Lab-5-AnotherSlowApp.pcapng")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cut.pcapng")
	require.NoError(t, os.WriteFile(path, data[:5000], 0o644))

	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append(args, path))
		err := cmd.Execute()
		return out.String(), errOut.String(), err
	}

	t.Run("text", func(t *testing.T) {
		out, errOut, err := run()
		require.NoError(t, err)
		assert.Contains(t, errOut, "is truncated; analyzing the 38 packets read before the cut")
		assert.Contains(t, out, "Truncated Capture")
		assert.Contains(t, out, "Analyzed 38 packets before truncation")
		assert.Contains(t, out, "Analyzed 38 packets in 1 flows")
	})
	t.Run("json", func(t *testing.T) {
		out, errOut, err := run("-o", "json")
		require.NoError(t, err)
		assert.Contains(t, errOut, "truncated")
		assert.Contains(t, out, `"title": "Truncated Capture"`)
		assert.Contains(t, out, `"category": "Capture"`)
		assert.Contains(t, out, `"total_packets": 38`)
	})
	t.Run("filters do not change the packet count in the warning", func(t *testing.T) {
		out, _, err := run("--dst-port", "80", "-o", "json")
		require.NoError(t, err)
		assert.Contains(t, out, "Analyzed 38 packets before truncation")
	})
	t.Run("follow still works on the partial capture", func(t *testing.T) {
		out, errOut, err := run("--follow", "10.0.0.1:80-192.168.1.1:61300")
		require.NoError(t, err)
		assert.Contains(t, errOut, "truncated")
		assert.Contains(t, out, "Following stream")
	})
}

func TestPrintConversationMarksRetransmits(t *testing.T) {
	p := models.PacketInfo{Timestamp: time.Unix(0, 0), Protocol: models.ProtocolTCP, TCPFlags: "ACK", TCPSeq: 7, PayloadSize: 4}
	c := &analyzer.Conversation{FlowID: "f", Client: "a", Server: "b", Events: []analyzer.StreamEvent{
		{Timestamp: time.Unix(0, 0), Kind: "TCP", Packet: p},
		{Timestamp: time.Unix(1, 0), Kind: "TCP", Packet: p, Retransmit: true},
	}}
	var buf bytes.Buffer
	printConversation(&buf, c)
	assert.Equal(t, 1, strings.Count(buf.String(), "[RETRANS]"))
	assert.Contains(t, buf.String(), "seq=7 len=4  [RETRANS]")
}

func TestFollowStreamReconstructed(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, followStream(&buf, synthetic(), "10.0.1.50:43210-10.0.2.10:443"))
	out := buf.String()

	assert.Contains(t, out, "Following stream 10.0.1.50:43210-10.0.2.10:443")
	assert.Contains(t, out, "→  TLS  ClientHello (TLS 1.2)")
	assert.Contains(t, out, "←  TLS  Alert fatal handshake_failure")
	assert.Contains(t, out, "[3 bytes of binary data]")
	assert.Contains(t, out, "GET /secret HTTP/1.1\n    Host: x")
	// handshake packets and sequence numbers are packet-level detail
	assert.NotContains(t, out, "SYN")
	assert.NotContains(t, out, "seq=")
	assert.NotContains(t, out, "example.com")
}

func TestFollowStreamDNSText(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, followStream(&buf, synthetic(), "10.0.1.50:5353-10.0.0.53:53/udp"))
	out := buf.String()
	assert.Contains(t, out, "→  DNS  query example.com (A)")
	assert.Contains(t, out, "←  DNS  response example.com NOERROR: A 93.184.216.34")
}

func TestFollowStreamStitchesHTTP(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	seg := func(ms int, fromClient bool, seq uint32, payload string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: "PSH,ACK",
			TCPSeq: seq, PayloadSize: len(payload), Payload: []byte(payload)}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "1.1.1.1", 1000, "2.2.2.2", 80
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "2.2.2.2", 80, "1.1.1.1", 1000
		}
		return p
	}
	req := seg(0, true, 10, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
	req.HTTPMethod = "GET"
	resp := seg(100, false, 50, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello ")
	resp.HTTPStatusCode = 200
	packets := []models.PacketInfo{
		req,
		resp,
		seg(110, false, 50+uint32(len(resp.Payload)), "world"),
		seg(120, false, 50, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello "), // retransmission
		{Timestamp: t0.Add(130 * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: "ACK", TCPSeq: 55, SrcIP: "1.1.1.1", SrcPort: 1000, DstIP: "2.2.2.2", DstPort: 80},
	}
	var buf bytes.Buffer
	require.NoError(t, followStream(&buf, packets, "1.1.1.1:1000-2.2.2.2:80"))
	out := buf.String()

	assert.Contains(t, out, "GET /x HTTP/1.1")
	assert.Contains(t, out, "HTTP/1.1 200 OK\n    Content-Length: 11\n\n    hello world")
	assert.Equal(t, 1, strings.Count(out, "HTTP/1.1 200 OK"), "retransmission must not repeat the response")
	assert.Contains(t, out, "1 retransmitted segment(s)")
}

func TestRenderPayload(t *testing.T) {
	tests := []struct {
		name string
		kind string
		data string
		want []string
	}{
		{"empty", "TCP", "", nil},
		{"text", "TCP", "hello\r\nworld\r\n", []string{"hello", "world"}},
		{"binary", "TCP", "\x16\x03\x01\x00\x00", []string{"[5 bytes of binary data]"}},
		{"invalid utf8", "TCP", "ab\xff\xfecd", []string{"[6 bytes of binary data]"}},
		{"http with binary body", "HTTP", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b\x08\x00", []string{"HTTP/1.1 200 OK", "Content-Encoding: gzip", "", "[4 bytes of binary data]"}},
		{"http headers only", "HTTP", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", []string{"GET / HTTP/1.1", "Host: a"}},
		{"http continuation without headers", "HTTP", "just body text", []string{"just body text"}},
		{"long text is truncated", "TCP", strings.Repeat("a", maxShownBytes+10), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderPayload(tt.kind, []byte(tt.data))
			if tt.want == nil && tt.data != "" {
				require.Len(t, got, 2)
				assert.Equal(t, "... 10 more byte(s)", got[1])
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTextLinesDoesNotSplitRunes(t *testing.T) {
	data := []byte(strings.Repeat("a", maxShownBytes-1) + "é" + "tail")
	lines := textLines(data)
	require.Len(t, lines, 2)
	assert.True(t, utf8.ValidString(lines[0]))
	assert.Contains(t, lines[1], "more byte(s)")
}

func TestPrintStreamGapsAndEmpty(t *testing.T) {
	c := &analyzer.Conversation{FlowID: "f", Client: "a", Server: "b", Messages: []analyzer.StreamMessage{
		{Timestamp: time.Unix(0, 0), Kind: "TCP", Missing: 1424},
	}}
	var buf bytes.Buffer
	printStream(&buf, c)
	assert.Contains(t, buf.String(), "[1424 bytes not captured]")

	buf.Reset()
	printStream(&buf, &analyzer.Conversation{FlowID: "f", Client: "a", Server: "b"})
	assert.Contains(t, buf.String(), "no application data")
}
