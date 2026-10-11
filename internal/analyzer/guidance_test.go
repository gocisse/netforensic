package analyzer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func intp(n int) *int { return &n }

// guided runs the guidance step on one issue, with the given flows.
func guided(is models.Issue, flows ...models.Flow) models.Issue {
	issues := []models.Issue{is}
	annotateGuidance(issues, flows)
	return issues[0]
}

func tcpFlow(id string, stream *int) models.Flow {
	return models.Flow{ID: id, Protocol: models.ProtocolTCP, TCPStream: stream}
}

func TestWiresharkFilters(t *testing.T) {
	const flowA = "10.0.0.1:50000-10.0.0.2:80"
	const flowB = "10.0.0.3:51000-10.0.0.2:80"
	const flowV6 = "[2001:db8::1]:50000-[2001:db8::2]:443"
	flows := []models.Flow{
		tcpFlow(flowA, intp(7)),
		tcpFlow(flowB, intp(12)),
		tcpFlow(flowV6, nil), // the capture's streams cannot be numbered
		{ID: "10.0.0.5:5060-10.0.0.6:5060", Protocol: models.ProtocolUDP},
	}
	occ := func(subjects ...string) []models.Occurrence {
		var o []models.Occurrence
		for _, s := range subjects {
			o = append(o, models.Occurrence{Subject: s})
		}
		return o
	}
	valued := func(vs ...float64) []models.Occurrence {
		var o []models.Occurrence
		for _, v := range vs {
			o = append(o, models.Occurrence{Subject: "x", Value: v})
		}
		return o
	}

	tests := []struct {
		name  string
		issue models.Issue
		want  string
	}{
		// TCP
		{"retransmission, one flow", models.Issue{Category: "PacketLoss", Title: titleRetransmissions, FlowID: flowA},
			"tcp.stream eq 7 && tcp.analysis.retransmission"},
		{"timeout retransmit", models.Issue{Category: "PacketLoss", Title: titleTimeoutRetransmit, FlowID: flowB},
			"tcp.stream eq 12 && tcp.analysis.retransmission"},
		{"fast retransmit", models.Issue{Category: "PacketLoss", Title: titleFastRetransmit, FlowID: flowA},
			"tcp.stream eq 7 && tcp.analysis.fast_retransmission"},
		{"retransmission when the streams cannot be numbered: by address and port", models.Issue{Category: "PacketLoss", Title: titleRetransmissions, FlowID: flowV6},
			"(ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2 && tcp.port == 50000 && tcp.port == 443) && tcp.analysis.retransmission"},
		{"zero window", models.Issue{Category: "Connection", Title: titleZeroWindow, FlowID: flowA},
			"tcp.stream eq 7 && tcp.analysis.zero_window"},
		{"reset after a zero window", models.Issue{Category: "Connection", Title: titleZeroWindowReset, FlowID: flowA},
			"tcp.stream eq 7 && (tcp.analysis.zero_window || tcp.flags.reset == 1)"},
		{"abruptly closed", models.Issue{Category: "Connection", Title: titleAborted, FlowID: flowA},
			"tcp.stream eq 7 && tcp.flags.reset == 1"},
		{"refused, several connections", models.Issue{Category: "Connection", Title: titleRefused, Target: "10.0.0.2:80", Occurrences: occ(flowA, flowB)},
			"(tcp.stream eq 7 || tcp.stream eq 12) && tcp.flags.reset == 1"},
		{"slow handshake", models.Issue{Category: "Performance", Title: "Slow TCP Handshake", FlowID: flowA},
			"tcp.stream eq 7 && tcp.analysis.initial_rtt"},
		{"slow server response", models.Issue{Category: "Performance", Title: "Slow Server Response", FlowID: flowB},
			"tcp.stream eq 12 && tcp.len > 0"},
		{"high latency across flows", models.Issue{Category: "Performance", Title: "High Network Latency", Target: flowA, Occurrences: occ(flowA, flowB)},
			"(tcp.stream eq 7 || tcp.stream eq 12) && tcp.analysis.ack_rtt > 0.2"},
		{"jitter", models.Issue{Category: "Performance", Title: "High Jitter", FlowID: flowA},
			"tcp.stream eq 7 && tcp.analysis.ack_rtt > 0.5"},
		{"a SYN flood names the target", models.Issue{Category: "Connection", Title: titleSYNFlood, Target: "10.0.0.2:80"},
			"tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 10.0.0.2 && tcp.dstport == 80"},
		{"unanswered SYNs", models.Issue{Category: "Connection", Title: titleUnansweredSYN, Target: "10.0.0.2:80", Occurrences: occ(flowA)},
			"tcp.stream eq 7 && tcp.flags.syn == 1 && tcp.flags.ack == 0"},
		{"refused with too many connections to list: every RST from the server", models.Issue{Category: "Connection", Title: titleRefused, Target: "10.0.0.2:80", Occurrences: manyFlows(maxFilterTerms + 1)},
			"tcp.flags.reset == 1 && ip.src == 10.0.0.2 && tcp.srcport == 80"},

		// DNS
		{"NXDOMAIN, one domain", models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: "bad.example.com", Target: "8.8.8.8", Occurrences: occ("bad.example.com")},
			`dns.flags.rcode == 3 && dns.qry.name == "bad.example.com"`},
		{"NXDOMAIN, every domain of an aggregated issue", models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: "a.example", Target: "8.8.8.8", Occurrences: occ("a.example", "b.example", "a.example", "c.example")},
			`dns.flags.rcode == 3 && (dns.qry.name == "a.example" || dns.qry.name == "b.example" || dns.qry.name == "c.example")`},
		{"NXDOMAIN, too many domains: the resolver's answers", models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: "d0.example", Target: "8.8.8.8", Occurrences: manyDomains(maxFilterTerms + 1)},
			"dns.flags.rcode == 3 && ip.src == 8.8.8.8"},
		{"SERVFAIL", models.Issue{Category: "DNS", Title: "DNS SERVFAIL", Domain: "x.example", Target: "2001:db8::53", Occurrences: occ("x.example")},
			`dns.flags.rcode == 2 && dns.qry.name == "x.example"`},
		{"timeout: queries with no response", models.Issue{Category: "DNS", Title: "DNS Timeout", Domain: "slow.example", Target: "8.8.8.8", Occurrences: occ("slow.example")},
			`dns.flags.response == 0 && !dns.response_in && dns.qry.name == "slow.example"`},
		{"timeout, too many names: the queries to the resolver", models.Issue{Category: "DNS", Title: "DNS Timeout", Domain: "d0.example", Target: "2001:db8::53", Occurrences: manyDomains(maxFilterTerms + 1)},
			"dns.flags.response == 0 && !dns.response_in && ipv6.dst == 2001:db8::53"},
		{"slow response", models.Issue{Category: "DNS", Title: "DNS Slow Response", Domain: "s.example", Target: "8.8.8.8", Occurrences: occ("s.example")},
			`dns.flags.response == 1 && dns.time > 1 && dns.qry.name == "s.example"`},
		{"a domain with a quote and a backslash is escaped", models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: `a"b\c`, Occurrences: occ(`a"b\c`)},
			`dns.flags.rcode == 3 && dns.qry.name == "a\"b\\c"`},
		{"a domain with control characters loses them", models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: "a\x1b[2Jb\n", Occurrences: occ("a\x1b[2Jb\n")},
			`dns.flags.rcode == 3 && dns.qry.name == "a[2Jb"`},

		// SIP
		{"SIP registration failure with one code", models.Issue{Category: "SIP", Title: titleSIPRegistration, Occurrences: valued(403, 403)},
			`sip.CSeq.method == "REGISTER" && sip.Status-Code == 403`},
		{"SIP call setup failures with several codes", models.Issue{Category: "SIP", Title: titleSIPCallSetup, Occurrences: valued(486, 404, 486)},
			`sip.CSeq.method == "INVITE" && (sip.Status-Code == 404 || sip.Status-Code == 486)`},
		{"SIP error rate", models.Issue{Category: "SIP", Title: titleSIPErrorRate, FlowID: "10.0.0.5:5060-10.0.0.6:5060"},
			"(ip.addr == 10.0.0.5 && ip.addr == 10.0.0.6 && udp.port == 5060) && sip.Status-Code >= 400"},

		// DHCPv6
		{"DHCPv6 no addresses", models.Issue{Category: "DHCPv6", Title: titleDHCPv6NoAddrs, Occurrences: valued(2, 3)},
			"(dhcpv6.msgtype == 2 || dhcpv6.msgtype == 7) && (dhcpv6.status_code == 2 || dhcpv6.status_code == 3)"},
		{"DHCPv6 configuration error", models.Issue{Category: "DHCPv6", Title: titleDHCPv6Config, Occurrences: valued(4)},
			"(dhcpv6.msgtype == 2 || dhcpv6.msgtype == 7) && dhcpv6.status_code == 4"},
		{"DHCPv6 failure rate", models.Issue{Category: "DHCPv6", Title: titleDHCPv6FailRate},
			"(dhcpv6.msgtype == 2 || dhcpv6.msgtype == 7) && dhcpv6.status_code > 0"},
		{"DHCPv6 timeout", models.Issue{Category: "DHCPv6", Title: titleDHCPv6Timeout, Target: "ff02::1:2"},
			"(dhcpv6.msgtype == 1 || dhcpv6.msgtype == 3) && ipv6.dst == ff02::1:2"},

		// QUIC
		{"QUIC handshake timeout", models.Issue{Category: "QUIC", Title: titleQUICTimeout, Target: "192.0.2.10:443"},
			"quic.long.packet_type == 0 && ip.dst == 192.0.2.10 && udp.dstport == 443"},
		{"QUIC retry", models.Issue{Category: "QUIC", Title: titleQUICRetry, Target: "[2a10:50c0::ad1:ff]:853"},
			"quic.long.packet_type == 3 && ipv6.src == 2a10:50c0::ad1:ff && udp.srcport == 853"},
		{"QUIC version negotiation", models.Issue{Category: "QUIC", Title: titleQUICVersionNeg, Target: "192.0.2.10:443"},
			"quic.version == 0x00000000 && ip.src == 192.0.2.10 && udp.srcport == 443"},
		{"QUIC drafts", models.Issue{Category: "QUIC", Title: titleQUICDraft}, "quic.version >= 0xff000000 && quic.version <= 0xff0000ff"},

		// no filter
		{"a capture note gets none", models.Issue{Category: "Capture", Title: "Skipped Frames"}, ""},
		{"an unknown kind of issue gets none", models.Issue{Category: "Whatever", Title: "Something", FlowID: flowA}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := guided(tt.issue, flows...)
			assert.Equal(t, tt.want, got.WiresharkFilter)
		})
	}
}

func manyFlows(n int) []models.Occurrence {
	var o []models.Occurrence
	for i := 0; i < n; i++ {
		o = append(o, models.Occurrence{Subject: fmt.Sprintf("10.9.%d.1:50000-10.0.0.2:80", i)})
	}
	return o
}

func manyDomains(n int) []models.Occurrence {
	var o []models.Occurrence
	for i := 0; i < n; i++ {
		o = append(o, models.Occurrence{Subject: fmt.Sprintf("d%d.example", i)})
	}
	return o
}

func TestHTTPAndTLSAndICMPAndARPFiltersAreSetWhereThePacketsAreAtHand(t *testing.T) {
	req := func(sec float64) models.PacketInfo {
		p := tcpPkt(sec, true, "PSH,ACK", 1, 1, 100)
		p.DstPort, p.StreamKnown, p.Stream = 80, true, 3
		p.HTTPMethod, p.HTTPURI, p.HTTPHost = "GET", "/slow", "example.com"
		return p
	}
	resp := func(sec float64, code int) models.PacketInfo {
		p := tcpPkt(sec, false, "PSH,ACK", 1, 1, 100)
		p.SrcPort, p.StreamKnown, p.Stream = 80, true, 3
		p.HTTPStatusCode = code
		return p
	}
	byTitle := func(issues []models.Issue) map[string]string {
		m := map[string]string{}
		for _, is := range issues {
			m[is.Title] = is.WiresharkFilter
		}
		return m
	}

	got := byTitle(analyzeHTTP([]models.PacketInfo{req(0), resp(2, 404), req(3), resp(3.1, 503)}))
	assert.Equal(t, "tcp.stream eq 3 && http.response.code == 404", got["HTTP Client Error"])
	assert.Equal(t, "tcp.stream eq 3 && http.response.code == 503", got["HTTP Server Error"])
	assert.Equal(t, "tcp.stream eq 3 && (http.request || http.response)", got["HTTP Slow Response"])

	// without stream numbers: addresses and ports
	r := resp(0.5, 404)
	r.StreamKnown = false
	q := req(0)
	q.StreamKnown = false
	got = byTitle(analyzeHTTP([]models.PacketInfo{q, r}))
	assert.Equal(t, "(ip.addr == 10.0.0.2 && ip.addr == 10.0.0.1 && tcp.port == 80 && tcp.port == 1000) && http.response.code == 404", got["HTTP Client Error"])

	arp := analyzeARP([]models.PacketInfo{
		{Timestamp: at(0), Protocol: models.ProtocolARP, ARPOperation: "reply", ARPSenderIP: "10.0.0.5", ARPSenderMAC: "aa:aa:aa:aa:aa:aa", SrcIP: "10.0.0.5", DstIP: "10.0.0.1"},
		{Timestamp: at(1), Protocol: models.ProtocolARP, ARPOperation: "reply", ARPSenderIP: "10.0.0.5", ARPSenderMAC: "bb:bb:bb:bb:bb:bb", SrcIP: "10.0.0.5", DstIP: "10.0.0.1"},
	})
	require.Len(t, arp, 1)
	assert.Equal(t, "arp.src.proto_ipv4 == 10.0.0.5", arp[0].WiresharkFilter)

	assert.Equal(t, "(icmp.type == 3 || icmpv6.type == 1) && ip.src == 10.0.0.254", icmpFilter(icmpDestUnreachable, "10.0.0.254"))
	assert.Equal(t, "(icmp.type == 11 || icmpv6.type == 3) && ipv6.src == fe80::1", icmpFilter(icmpTimeExceeded, "fe80::1"))
	assert.Equal(t, "icmp.type == 5 && ip.src == 10.0.0.254", icmpFilter(icmpRedirect, "10.0.0.254"))
}

func TestExistingFiltersAreKept(t *testing.T) {
	is := guided(models.Issue{Category: "HTTP", Title: "HTTP Client Error", WiresharkFilter: "http.response.code == 404"})
	assert.Equal(t, "http.response.code == 404", is.WiresharkFilter)
	assert.Equal(t, issueRecommendations["HTTP Client Error"], is.Recommendation, "the recommendation is still added")
}

func TestEveryIssueTitleHasARecommendation(t *testing.T) {
	titles := []string{
		titleFastRetransmit, titleTimeoutRetransmit, titleRetransmissions, titleZeroWindow, titleZeroWindowReset, titleRefused, titleAborted,
		titleIdle, titleStray, titleUnansweredSYN, titleSYNFlood, titleSYNRetried, "Slow TCP Handshake", "Slow Server Response",
		"High Network Latency", "High Jitter", "DNS NXDOMAIN", "DNS SERVFAIL", "DNS Timeout", "DNS Slow Response", "HTTP Client Error",
		"HTTP Server Error", "HTTP Slow Response", "TLS Handshake Failure", "TLS Protocol Downgrade", "ICMP Destination Unreachable",
		"ICMP Time Exceeded", "ICMP Redirect", "ARP Storm", "Duplicate IP Address", titleSIPRegistration, titleSIPCallSetup, titleSIPErrorRate,
		titleDHCPv6NoAddrs, titleDHCPv6Config, titleDHCPv6FailRate, titleDHCPv6Timeout, titleQUICTimeout, titleQUICRetry, titleQUICVersionNeg, titleQUICDraft,
	}
	for _, title := range titles {
		got := recommendationFor(models.Issue{Title: title})
		assert.NotEmpty(t, got, title)
		assert.True(t, strings.HasSuffix(got, "."), "a sentence: %s", title)
	}
	assert.NotEmpty(t, recommendationFor(models.Issue{Title: "Unanswered SYN (something new)"}))
	assert.Empty(t, recommendationFor(models.Issue{Title: "Unheard Of"}))
}

func TestWsString(t *testing.T) {
	assert.Equal(t, `"plain.example"`, wsString("plain.example"))
	assert.Equal(t, `"a\"b"`, wsString(`a"b`))
	assert.Equal(t, `"a\\b"`, wsString(`a\b`))
	assert.Equal(t, `"ab"`, wsString("a\x00\x1b\nb\x7f"))
	assert.Equal(t, `"日本語"`, wsString("日本語"))
	assert.Equal(t, `""`, wsString(""))
}

func TestFiltersAreWhatAFilterBarAccepts(t *testing.T) {
	// No filter may contain a character that would end or break a display
	// filter, or a newline, whatever the capture put in a name.
	for _, name := range []string{"x\"; drop", "a\nb", "a\tb", "x||y", "'quoted'", "%25"} {
		f := guided(models.Issue{Category: "DNS", Title: "DNS NXDOMAIN", Domain: name, Occurrences: []models.Occurrence{{Subject: name}}}).WiresharkFilter
		require.NotEmpty(t, f)
		assert.NotContains(t, f, "\n")
		assert.NotContains(t, f, "\t")
		// inside the quotes, every quote is escaped
		inner := strings.TrimPrefix(f, "dns.flags.rcode == 3 && dns.qry.name == ")
		require.True(t, strings.HasPrefix(inner, `"`) && strings.HasSuffix(inner, `"`), f)
		body := inner[1 : len(inner)-1]
		assert.NotRegexp(t, `(^|[^\\])"`, body, f)
	}
}

func TestFlowsCarryTheirWiresharkStream(t *testing.T) {
	a := tcpPkt(0, true, "SYN", 1, 0, 0)
	a.Stream, a.StreamKnown = 4, true
	b := tcpPkt(1, false, "SYN,ACK", 9, 2, 0)
	b.Stream, b.StreamKnown = 4, true
	udp := models.PacketInfo{Timestamp: at(2), Protocol: models.ProtocolUDP, SrcIP: "10.0.0.1", SrcPort: 5, DstIP: "10.0.0.2", DstPort: 6}

	flows := aggregateFlows([]models.PacketInfo{a, b, udp})
	require.Len(t, flows, 2)
	for _, f := range flows {
		if f.Protocol == models.ProtocolTCP {
			require.NotNil(t, f.TCPStream)
			assert.Equal(t, 4, *f.TCPStream)
		} else {
			assert.Nil(t, f.TCPStream, "only TCP flows have a stream")
		}
	}

	// without stream numbers (a capture whose numbering cannot be trusted) there is no stream
	a.StreamKnown, b.StreamKnown = false, false
	for _, f := range aggregateFlows([]models.PacketInfo{a, b}) {
		assert.Nil(t, f.TCPStream)
	}
}
