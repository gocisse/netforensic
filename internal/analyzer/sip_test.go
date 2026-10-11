package analyzer

import (
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

// A synthetic SIP capture: messages are serialized with gopacket into a pcap
// file, which is read back by the real reader, so the decoder and the
// analysis are tested together.

type sipMsg struct {
	from, to       string // IP addresses
	srcPort, dport uint16
	tcp            bool
	text           string
}

// sipCapture writes msgs, 100 ms apart, to a pcap file and reads it back.
func sipCapture(t *testing.T, msgs []sipMsg) []models.PacketInfo {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sip.pcap")
	writeSIPCapture(t, path, msgs)
	packets, err := pcap.ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, packets, len(msgs))
	return packets
}

// writeSIPCapture serializes msgs, 100 ms apart, into a pcap file at path.
func writeSIPCapture(t *testing.T, path string, msgs []sipMsg) {
	t.Helper()
	var frames [][]byte
	for _, m := range msgs {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP(m.from).To4(), DstIP: net.ParseIP(m.to).To4()}
		var transport gopacket.SerializableLayer
		if m.tcp {
			ip.Protocol = layers.IPProtocolTCP
			tcp := &layers.TCP{SrcPort: layers.TCPPort(m.srcPort), DstPort: layers.TCPPort(m.dport), ACK: true, PSH: true, Window: 1000}
			require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
			transport = tcp
		} else {
			ip.Protocol = layers.IPProtocolUDP
			udp := &layers.UDP{SrcPort: layers.UDPPort(m.srcPort), DstPort: layers.UDPPort(m.dport)}
			require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
			transport = udp
		}
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport, gopacket.Payload([]byte(m.text))))
		frames = append(frames, buf.Bytes())
	}

	f, err := createFile(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	start := time.Unix(1700000000, 0)
	for i, fr := range frames {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: start.Add(time.Duration(i) * 100 * time.Millisecond), CaptureLength: len(fr), Length: len(fr)}, fr))
	}
	require.NoError(t, f.Close())
}

const (
	client = "10.0.0.1"
	server = "10.0.0.2"
)

// req builds a SIP request from the client to the server on port 5060.
func req(method, callID string, cseq int, ua string) sipMsg {
	text := fmt.Sprintf("%s sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s%d\r\nFrom: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\nCall-ID: %s\r\nCSeq: %d %s\r\n", method, client, callID, cseq, callID, cseq, method)
	if ua != "" {
		text += "User-Agent: " + ua + "\r\n"
	}
	text += "Contact: <sip:alice@" + client + ">\r\nContent-Length: 0\r\n\r\n"
	return sipMsg{from: client, to: server, srcPort: 5060, dport: 5060, text: text}
}

// resp builds the server's response to a request.
func resp(code int, reason, callID string, cseq int, method string) sipMsg {
	text := fmt.Sprintf("SIP/2.0 %d %s\r\nFrom: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>;tag=2\r\nCall-ID: %s\r\nCSeq: %d %s\r\nServer: TestPBX 1.0\r\nContent-Length: 0\r\n\r\n", code, reason, callID, cseq, method)
	return sipMsg{from: server, to: client, srcPort: 5060, dport: 5060, text: text}
}

func join(parts ...[]sipMsg) []sipMsg {
	var all []sipMsg
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}

func one(m sipMsg) []sipMsg { return []sipMsg{m} }

// exchange is a request and its final response.
func exchange(method, callID string, cseq int, ua string, code int, reason string) []sipMsg {
	return []sipMsg{req(method, callID, cseq, ua), resp(code, reason, callID, cseq, method)}
}

func sipIssues(t *testing.T, msgs []sipMsg) []models.Issue {
	t.Helper()
	var out []models.Issue
	for _, is := range Analyze(sipCapture(t, msgs), "all").Issues {
		if is.Category == "SIP" {
			out = append(out, is)
		}
	}
	return out
}

func TestSIPDetection(t *testing.T) {
	garbage := func(port uint16, tcp bool) sipMsg {
		return sipMsg{from: client, to: server, srcPort: 40000, dport: port, tcp: tcp, text: "not a sip message at all"}
	}
	onPort := func(m sipMsg, port uint16) sipMsg { m.srcPort, m.dport = 40000, port; return m }

	tests := []struct {
		name    string
		msgs    []sipMsg
		wantApp string // application protocol of the one flow
	}{
		{"UDP 5060 with a SIP message", exchange("OPTIONS", "c1", 1, "ua", 200, "OK"), "SIP"},
		{"SIP recognized by content on another port", one(onPort(req("INVITE", "c1", 1, ""), 5070)), "SIP"},
		{"a response alone is recognized", one(onPort(resp(200, "OK", "c1", 1, "INVITE"), 7000)), "SIP"},
		{"UDP 5060 with unreadable content is SIP by port", one(garbage(5060, false)), "SIP"},
		{"TCP 5060 segments with no message are SIP by port", one(garbage(5060, true)), "SIP"},
		{"port 5061 with no recognized protocol is SIP by port", one(garbage(5061, true)), "SIP"},
		{"another port with unreadable content is not SIP", one(garbage(5062, false)), ""},
		{"an HTTP request is not SIP", one(sipMsg{from: client, to: server, srcPort: 40000, dport: 80, tcp: true, text: "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"}), "HTTP"},
		{"a request line with a wrong version is not SIP", one(sipMsg{from: client, to: server, srcPort: 40000, dport: 7000, text: "INVITE sip:bob@example.com SIP/3.0\r\n\r\n"}), ""},
		{"an unknown method is not SIP", one(sipMsg{from: client, to: server, srcPort: 40000, dport: 7000, text: "FETCH sip:bob@example.com SIP/2.0\r\n\r\n"}), ""},
		{"a lowercase method is not SIP", one(sipMsg{from: client, to: server, srcPort: 40000, dport: 7000, text: "invite sip:bob@example.com SIP/2.0\r\n\r\n"}), ""},
		{"a status code outside 100-699 is not SIP", one(sipMsg{from: client, to: server, srcPort: 40000, dport: 7000, text: "SIP/2.0 099 Odd\r\n\r\n"}), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(sipCapture(t, tt.msgs), "all")
			require.NotEmpty(t, res.Flows)
			assert.Equal(t, tt.wantApp, res.Flows[0].AppProtocol)

			var sipStat *models.ProtocolStat
			for i, s := range res.ProtocolStats {
				if s.Protocol == "SIP" {
					sipStat = &res.ProtocolStats[i]
				}
			}
			if tt.wantApp == "SIP" {
				require.NotNil(t, sipStat, "SIP is in the protocol distribution")
				assert.Equal(t, "application", sipStat.Layer)
				assert.Equal(t, len(tt.msgs), sipStat.Packets)
			} else {
				assert.Nil(t, sipStat)
			}
		})
	}
}

func TestSIPOverTLSIsTLS(t *testing.T) {
	// Port 5061 carries SIP over TLS: the flow shows a TLS handshake, which wins.
	hello := models.PacketInfo{Timestamp: at(0), Protocol: models.ProtocolTCP, TCPFlags: "PSH,ACK", TCPWindow: 100,
		SrcIP: client, SrcPort: 40000, DstIP: server, DstPort: 5061, TLSHandshakeType: "ClientHello"}
	res := Analyze([]models.PacketInfo{hello}, "all")
	require.Len(t, res.Flows, 1)
	assert.Equal(t, "TLS", res.Flows[0].AppProtocol)
}

func TestSIPFlowMetadata(t *testing.T) {
	msgs := join(
		one(req("INVITE", "call-1", 1, "SoftPhone 2.1")),
		one(resp(100, "Trying", "call-1", 1, "INVITE")),
		one(resp(200, "OK", "call-1", 1, "INVITE")),
		one(req("ACK", "call-1", 1, "SoftPhone 2.1")),
		one(req("BYE", "call-1", 2, "SoftPhone 2.1")),
		one(resp(200, "OK", "call-1", 2, "BYE")),
		exchange("INVITE", "call-2", 1, "SoftPhone 2.1", 200, "OK"),
	)
	res := Analyze(sipCapture(t, msgs), "all")
	require.Len(t, res.Flows, 1)
	f := res.Flows[0]
	assert.Equal(t, "SIP", f.AppProtocol)
	assert.Equal(t, "INVITE,ACK,BYE", f.SIPMethod, "each request method once, in order")
	assert.Equal(t, "call-1", f.SIPCallID, "the first call")
	assert.Equal(t, "SoftPhone 2.1", f.SIPUserAgent)
	assert.Empty(t, sipIssues(t, msgs), "a healthy conversation raises nothing")
}

func TestSIPRegistrationFailures(t *testing.T) {
	tests := []struct {
		name      string
		msgs      []sipMsg
		wantCount int // failed registrations; 0 means no issue
		wantDesc  string
	}{
		{
			name:      "403 Forbidden",
			msgs:      exchange("REGISTER", "r1", 1, "Yealink SIP-T46 1.2", 403, "Forbidden"),
			wantCount: 1,
			wantDesc:  "Yealink SIP-T46 1.2 received 403 Forbidden for REGISTER (sent to 10.0.0.2:5060)",
		},
		{
			name:      "5xx and 6xx count",
			msgs:      join(exchange("REGISTER", "r1", 1, "ua", 503, "Service Unavailable"), exchange("REGISTER", "r2", 1, "ua", 603, "Decline")),
			wantCount: 2,
			wantDesc:  "ua received 503 Service Unavailable (1x), 603 Decline (1x) for REGISTER (2 failed requests to 10.0.0.2:5060)",
		},
		{
			name: "the authentication challenge is not a failure when the retry succeeds",
			msgs: join(exchange("REGISTER", "r1", 1, "ua", 401, "Unauthorized"), exchange("REGISTER", "r1", 2, "ua", 200, "OK")),
		},
		{
			name: "407 is a challenge too",
			msgs: exchange("REGISTER", "r1", 1, "ua", 407, "Proxy Authentication Required"),
		},
		{
			name:      "a failure after the challenge is reported, not the challenge",
			msgs:      join(exchange("REGISTER", "r1", 1, "ua", 401, "Unauthorized"), exchange("REGISTER", "r1", 2, "ua", 403, "Forbidden")),
			wantCount: 1,
			wantDesc:  "ua received 403 Forbidden for REGISTER (sent to 10.0.0.2:5060)",
		},
		{
			name: "success",
			msgs: exchange("REGISTER", "r1", 1, "ua", 200, "OK"),
		},
		{
			name: "a redirect is not an error",
			msgs: exchange("REGISTER", "r1", 1, "ua", 302, "Moved Temporarily"),
		},
		{
			name: "no response captured",
			msgs: one(req("REGISTER", "r1", 1, "ua")),
		},
		{
			name: "only a provisional response",
			msgs: join(one(req("REGISTER", "r1", 1, "ua")), one(resp(100, "Trying", "r1", 1, "REGISTER"))),
		},
		{
			name:      "a client with no User-Agent is named by its address",
			msgs:      exchange("REGISTER", "r1", 1, "", 404, "Not Found"),
			wantCount: 1,
			wantDesc:  "client 10.0.0.1 received 404 Not Found for REGISTER (sent to 10.0.0.2:5060)",
		},
		{
			name:      "a retransmitted request counts once",
			msgs:      join(one(req("REGISTER", "r1", 1, "ua")), one(req("REGISTER", "r1", 1, "ua")), one(resp(403, "Forbidden", "r1", 1, "REGISTER"))),
			wantCount: 1,
			wantDesc:  "ua received 403 Forbidden for REGISTER (sent to 10.0.0.2:5060)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var regs []models.Issue
			for _, is := range sipIssues(t, tt.msgs) {
				if is.Title == titleSIPRegistration {
					regs = append(regs, is)
				}
			}
			if tt.wantCount == 0 {
				assert.Empty(t, regs)
				return
			}
			require.Len(t, regs, 1)
			assert.Equal(t, models.SeverityWarning, regs[0].Severity)
			assert.Equal(t, "SIP", regs[0].Category)
			assert.Equal(t, tt.wantCount, regs[0].Count)
			assert.Equal(t, tt.wantDesc, regs[0].Description)
			assert.Len(t, regs[0].Occurrences, tt.wantCount)
			assert.Equal(t, "10.0.0.2:5060", regs[0].Target)
			assert.Contains(t, regs[0].Protocols, "SIP")
		})
	}
}

func TestSIPCallSetupFailures(t *testing.T) {
	tests := []struct {
		name      string
		msgs      []sipMsg
		wantCount int
		wantDesc  string
	}{
		{
			name:      "486 Busy Here names the Call-ID",
			msgs:      exchange("INVITE", "call-9", 1, "ua", 486, "Busy Here"),
			wantCount: 1,
			wantDesc:  "call-9 received 486 Busy Here for INVITE (sent to 10.0.0.2:5060)",
		},
		{
			name: "several failures to one server are folded into one issue",
			msgs: join(
				exchange("INVITE", "a", 1, "ua", 404, "Not Found"),
				exchange("INVITE", "b", 1, "ua", 404, "Not Found"),
				exchange("INVITE", "c", 1, "ua", 603, "Decline")),
			wantCount: 3,
			wantDesc:  "3 INVITE requests to 10.0.0.2:5060 got error responses: 404 Not Found (2x), 603 Decline (1x) (first Call-ID: a)",
		},
		{
			name: "487 after a CANCEL is a caller hanging up",
			msgs: join(one(req("INVITE", "x", 1, "ua")), one(req("CANCEL", "x", 1, "ua")), one(resp(487, "Request Terminated", "x", 1, "INVITE")), one(resp(200, "OK", "x", 1, "CANCEL"))),
		},
		{
			name:      "487 with no CANCEL is a failure",
			msgs:      exchange("INVITE", "x", 1, "ua", 487, "Request Terminated"),
			wantCount: 1,
			wantDesc:  "x received 487 Request Terminated for INVITE (sent to 10.0.0.2:5060)",
		},
		{
			name: "an answered call",
			msgs: join(one(req("INVITE", "ok", 1, "ua")), one(resp(100, "Trying", "ok", 1, "INVITE")), one(resp(180, "Ringing", "ok", 1, "INVITE")), one(resp(200, "OK", "ok", 1, "INVITE"))),
		},
		{
			name: "the response is matched by CSeq: a late 200 to a re-INVITE does not hide the first failure",
			msgs: join(exchange("INVITE", "m", 1, "ua", 500, "Server Internal Error"), exchange("INVITE", "m", 2, "ua", 200, "OK")),
			// the first INVITE failed even though the call continued
			wantCount: 1,
			wantDesc:  "m received 500 Server Internal Error for INVITE (sent to 10.0.0.2:5060)",
		},
		{
			name: "a failed BYE is not a call setup failure",
			msgs: exchange("BYE", "z", 2, "ua", 481, "Call/Transaction Does Not Exist"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []models.Issue
			for _, is := range sipIssues(t, tt.msgs) {
				if is.Title == titleSIPCallSetup {
					calls = append(calls, is)
				}
			}
			if tt.wantCount == 0 {
				assert.Empty(t, calls)
				return
			}
			require.Len(t, calls, 1)
			assert.Equal(t, models.SeverityWarning, calls[0].Severity)
			assert.Equal(t, tt.wantCount, calls[0].Count)
			assert.Equal(t, tt.wantDesc, calls[0].Description)
			assert.Len(t, calls[0].Occurrences, tt.wantCount)
		})
	}
}

func TestSIPErrorRate(t *testing.T) {
	// n OPTIONS requests on one flow, of which the first `failed` get a 500.
	options := func(n, failed int) []sipMsg {
		var m []sipMsg
		for i := 0; i < n; i++ {
			code, reason := 200, "OK"
			if i < failed {
				code, reason = 500, "Server Internal Error"
			}
			m = append(m, exchange("OPTIONS", fmt.Sprintf("o%d", i), 1, "ua", code, reason)...)
		}
		return m
	}
	tests := []struct {
		name     string
		msgs     []sipMsg
		wantDesc string // "" means no issue
	}{
		{"15% of 20", options(20, 3), "15% of requests failed (3 of 20 answered requests on flow 10.0.0.1:5060-10.0.0.2:5060)"},
		{"exactly 10% is not more than 10%", options(20, 2), ""},
		{"5%", options(20, 1), ""},
		{"none", options(20, 0), ""},
		{"11 requests, 2 failed", options(11, 2), "18% of requests failed (2 of 11 answered requests on flow 10.0.0.1:5060-10.0.0.2:5060)"},
		{"all failed", options(10, 10), "100% of requests failed (10 of 10 answered requests on flow 10.0.0.1:5060-10.0.0.2:5060)"},
		{"too few requests to call it a rate: 3 of 5", options(5, 3), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rates []models.Issue
			for _, is := range sipIssues(t, tt.msgs) {
				if is.Title == titleSIPErrorRate {
					rates = append(rates, is)
				}
			}
			if tt.wantDesc == "" {
				assert.Empty(t, rates)
				return
			}
			require.Len(t, rates, 1)
			assert.Equal(t, models.SeverityWarning, rates[0].Severity)
			assert.Equal(t, tt.wantDesc, rates[0].Description)
			assert.Equal(t, "10.0.0.1:5060-10.0.0.2:5060", rates[0].FlowID)
		})
	}

	t.Run("flows are judged separately and folded into one issue", func(t *testing.T) {
		other := func(m sipMsg) sipMsg { // a second client on its own flow
			if m.from == client {
				m.from, m.srcPort = "10.0.0.9", 5060
			} else {
				m.to = "10.0.0.9"
			}
			return m
		}
		var bad2 []sipMsg
		for _, m := range options(20, 8) {
			bad2 = append(bad2, other(m))
		}
		msgs := join(options(20, 3), bad2, options(0, 0))
		var rates []models.Issue
		for _, is := range sipIssues(t, msgs) {
			if is.Title == titleSIPErrorRate {
				rates = append(rates, is)
			}
		}
		require.Len(t, rates, 1)
		assert.Equal(t, 2, rates[0].Count)
		require.Len(t, rates[0].Occurrences, 2)
		assert.Equal(t, 40.0, rates[0].Occurrences[0].Value, "the worst flow first")
		assert.Contains(t, rates[0].Description, "2 SIP flows have more than 10% of requests failing")
		assert.Contains(t, rates[0].Description, "40% (8 of 20 answered requests)")
	})
}

func TestSIPFailuresAggregateByUserAgent(t *testing.T) {
	var msgs []sipMsg
	for i := 0; i < 5; i++ {
		msgs = append(msgs, exchange("REGISTER", fmt.Sprintf("a%d", i), 1, "PhoneA 1.0", 403, "Forbidden")...)
	}
	for i := 0; i < 2; i++ {
		msgs = append(msgs, exchange("REGISTER", fmt.Sprintf("b%d", i), 1, "PhoneB 2.0", 408, "Request Timeout")...)
	}
	var regs []models.Issue
	for _, is := range sipIssues(t, msgs) {
		if is.Title == titleSIPRegistration {
			regs = append(regs, is)
		}
	}
	require.Len(t, regs, 2, "one issue per User-Agent, not one per failure")
	byUA := map[string]models.Issue{}
	for _, r := range regs {
		byUA[strings.SplitN(r.Description, " received", 2)[0]] = r
	}
	require.Contains(t, byUA, "PhoneA 1.0")
	require.Contains(t, byUA, "PhoneB 2.0")
	assert.Equal(t, 5, byUA["PhoneA 1.0"].Count)
	assert.Equal(t, "PhoneA 1.0 received 403 Forbidden (5x) for REGISTER (5 failed requests to 10.0.0.2:5060)", byUA["PhoneA 1.0"].Description)
	assert.Equal(t, 2, byUA["PhoneB 2.0"].Count)
	assert.Len(t, byUA["PhoneA 1.0"].Occurrences, 5, "the individual failures stay available for drill-down")
	assert.Equal(t, "a0", byUA["PhoneA 1.0"].Occurrences[0].Subject, "by Call-ID")
	assert.Equal(t, 403.0, byUA["PhoneA 1.0"].Occurrences[0].Value)
}

func TestSIPCallFailuresAggregateByServer(t *testing.T) {
	to := func(msgs []sipMsg, dst string) []sipMsg { // send the requests to another server
		out := append([]sipMsg(nil), msgs...)
		for i := range out {
			if out[i].from == client {
				out[i].to = dst
			} else {
				out[i].from = dst
			}
		}
		return out
	}
	msgs := join(
		to(exchange("INVITE", "a", 1, "ua", 404, "Not Found"), "10.0.0.2"),
		to(exchange("INVITE", "b", 1, "ua", 404, "Not Found"), "10.0.0.2"),
		to(exchange("INVITE", "c", 1, "ua", 480, "Temporarily Unavailable"), "10.0.0.3"),
	)
	var calls []models.Issue
	for _, is := range sipIssues(t, msgs) {
		if is.Title == titleSIPCallSetup {
			calls = append(calls, is)
		}
	}
	require.Len(t, calls, 2)
	targets := map[string]int{}
	for _, c := range calls {
		targets[c.Target] = c.Count
	}
	assert.Equal(t, map[string]int{"10.0.0.2:5060": 2, "10.0.0.3:5060": 1}, targets)
}

func TestSIPIssuesOverTCPAndOddPorts(t *testing.T) {
	// SIP over TCP, to a server on a non-standard port: recognized by content.
	r := req("INVITE", "t1", 1, "ua")
	r.tcp, r.dport = true, 5080
	p := resp(486, "Busy Here", "t1", 1, "INVITE")
	p.tcp, p.srcPort = true, 5080
	issues := sipIssues(t, []sipMsg{r, p})
	require.Len(t, issues, 1)
	assert.Equal(t, titleSIPCallSetup, issues[0].Title)
	assert.Equal(t, "10.0.0.2:5080", issues[0].Target)
}

func TestSIPDescriptionsAreNotInjectable(t *testing.T) {
	// User-Agent text comes from the network: control characters never reach a terminal.
	msgs := exchange("REGISTER", "r1", 1, "evil\x1b[2Jagent", 403, "Forbidden")
	issues := sipIssues(t, msgs)
	require.Len(t, issues, 1)
	assert.NotContains(t, issues[0].Description, "\x1b")
}

// createFile creates the capture file for sipCapture.
func createFile(path string) (*os.File, error) { return os.Create(path) }

func TestSIPProxyLegsAreSeparateTransactions(t *testing.T) {
	// A proxy forwards the INVITE with the same Call-ID and CSeq. Seen from a
	// capture point that has both legs, the first leg succeeds and the second
	// fails; neither may hide the other.
	leg2 := func(m sipMsg) sipMsg {
		if m.from == client {
			m.from, m.to = server, "10.0.0.3"
		} else {
			m.from, m.to = "10.0.0.3", server
		}
		return m
	}
	ok := exchange("INVITE", "same", 1, "ua", 200, "OK")
	bad := exchange("INVITE", "same", 1, "ua", 503, "Service Unavailable")
	msgs := join(ok, []sipMsg{leg2(bad[0]), leg2(bad[1])})

	calls := sipIssues(t, msgs)
	require.Len(t, calls, 1)
	assert.Equal(t, titleSIPCallSetup, calls[0].Title)
	assert.Equal(t, "10.0.0.3:5060", calls[0].Target)
}
