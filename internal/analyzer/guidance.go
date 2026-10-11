package analyzer

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/gocisse/netforensic/internal/filter"
	"github.com/gocisse/netforensic/internal/models"
)

// maxFilterTerms is how many alternatives (flows, domains, status codes) an
// aggregated issue's Wireshark filter lists. Past that the filter drops the
// list and matches the whole kind of packet instead, so that it stays
// something a person can read and paste.
const maxFilterTerms = 20

// annotateGuidance gives every issue a Wireshark display filter that shows the
// packets it is about, and a recommendation. Issues that already have a filter
// (set where the packets were at hand) keep it.
func annotateGuidance(issues []models.Issue, flows []models.Flow) {
	byID := make(map[string]models.Flow, len(flows))
	for _, f := range flows {
		byID[f.ID] = f
	}
	g := guide{flows: byID}
	for i := range issues {
		is := &issues[i]
		if is.Category == "Capture" {
			continue
		}
		if is.WiresharkFilter == "" {
			is.WiresharkFilter = g.filterFor(*is)
		}
		if is.Recommendation == "" {
			is.Recommendation = recommendationFor(*is)
		}
	}
}

type guide struct {
	flows map[string]models.Flow
}

// wsString quotes s as a Wireshark string literal. Control characters, which
// the filter language cannot hold, are dropped.
func wsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// addrField is the Wireshark field for an address: ip.addr or ipv6.addr.
func addrField(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	return "ip"
}

// ipLiteral writes an address as a Wireshark filter literal.
func ipLiteral(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.Unmap().String()
	}
	return ip
}

// addressTerm filters on the two endpoints of a flow by address and port,
// which is exact for every flow (a reused port pair shows both connections).
// proto is "tcp", "udp" or "" for a portless protocol.
func addressTerm(eps []filter.Endpoint, proto string) string {
	if len(eps) != 2 {
		return ""
	}
	var parts []string
	for _, e := range eps {
		parts = append(parts, fmt.Sprintf("%s.addr == %s", addrField(e.IP), ipLiteral(e.IP)))
	}
	if proto != "" {
		seen := make(map[uint16]bool) // a port both ends share is named once
		for _, e := range eps {
			if e.Port != 0 && !seen[e.Port] {
				seen[e.Port] = true
				parts = append(parts, fmt.Sprintf("%s.port == %d", proto, e.Port))
			}
		}
	}
	return "(" + strings.Join(parts, " && ") + ")"
}

// flowTerm filters on one flow: its Wireshark stream if the numbering is
// known, else its addresses and ports. fallbackProto is used when the flow's
// own protocol is not known.
func (g guide) flowTerm(id, fallbackProto string) string {
	f, known := g.flows[id]
	proto := fallbackProto
	if known {
		switch f.Protocol {
		case models.ProtocolTCP:
			proto = "tcp"
			if f.TCPStream != nil {
				return fmt.Sprintf("tcp.stream eq %d", *f.TCPStream)
			}
		case models.ProtocolUDP:
			proto = "udp"
		default:
			proto = ""
		}
	}
	return addressTerm(filter.ParseRef(id), proto)
}

// flowIDs lists the flows an issue is about: its own, and those named by its
// events' subjects.
func flowIDs(is models.Issue) []string {
	var ids []string
	seen := make(map[string]bool)
	add := func(s string) {
		if s != "" && !seen[s] && len(filter.ParseRef(s)) == 2 {
			seen[s] = true
			ids = append(ids, s)
		}
	}
	add(is.FlowID)
	for _, o := range is.Occurrences {
		add(o.Subject)
	}
	add(is.Target) // aggregated performance issues name their worst flow here
	return ids
}

// flowsTerm filters on all the flows of an issue, or returns "" if it has
// none or too many to list.
func (g guide) flowsTerm(is models.Issue, fallbackProto string) string {
	ids := flowIDs(is)
	if len(ids) == 0 || len(ids) > maxFilterTerms {
		return ""
	}
	return orTerms(mapStrings(ids, func(id string) string { return g.flowTerm(id, fallbackProto) }))
}

func mapStrings(in []string, f func(string) string) []string {
	var out []string
	for _, s := range in {
		if t := f(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// orTerms joins alternatives, parenthesized if there are several.
func orTerms(terms []string) string {
	switch len(terms) {
	case 0:
		return ""
	case 1:
		return terms[0]
	}
	return "(" + strings.Join(terms, " || ") + ")"
}

// and joins the non-empty conditions.
func and(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " && ")
}

// hostPort splits "ip:port" or "[ip6]:port" as endpoint names are written.
func hostPort(s string) (ip string, port uint16, ok bool) {
	eps := filter.ParseRef(s)
	if len(eps) != 1 {
		return "", 0, false
	}
	return eps[0].IP, eps[0].Port, true
}

// uniqueSubjects lists the distinct non-flow event subjects of an issue (for
// DNS issues the queried domains), the issue's own Domain first.
func uniqueSubjects(is models.Issue) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(is.Domain)
	for _, o := range is.Occurrences {
		add(o.Subject)
	}
	return out
}

// codesOf lists the distinct numeric values of an issue's events, such as the
// status codes of failed SIP requests, in ascending order.
func codesOf(is models.Issue) []int {
	seen := make(map[int]bool)
	var out []int
	for _, o := range is.Occurrences {
		if c := int(o.Value); c > 0 && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Ints(out)
	return out
}

// eqAny matches field against any of the values: "(f == 1 || f == 2)".
func eqAny(field string, values []int) string {
	terms := make([]string, len(values))
	for i, v := range values {
		terms[i] = fmt.Sprintf("%s == %d", field, v)
	}
	return orTerms(terms)
}

// filterFor builds the Wireshark filter of an issue, or "" if there is none
// worth giving.
func (g guide) filterFor(is models.Issue) string {
	switch is.Category {
	case "PacketLoss":
		field := "tcp.analysis.retransmission"
		if is.Title == titleFastRetransmit {
			field = "tcp.analysis.fast_retransmission"
		}
		return and(g.flowsTerm(is, "tcp"), field)
	case "Connection":
		return g.connectionFilter(is)
	case "Performance":
		return g.performanceFilter(is)
	case "DNS":
		return g.dnsFilter(is)
	case "SIP":
		return g.sipFilter(is)
	case "DHCPv6":
		return g.dhcpv6Filter(is)
	case "QUIC":
		return g.quicFilter(is)
	}
	return ""
}

func (g guide) connectionFilter(is models.Issue) string {
	flows := g.flowsTerm(is, "tcp")
	switch is.Title {
	case titleZeroWindow:
		return and(flows, "tcp.analysis.zero_window")
	case titleZeroWindowReset:
		return and(flows, "(tcp.analysis.zero_window || tcp.flags.reset == 1)")
	case titleRefused:
		if flows == "" {
			// too many connections to list: every RST from the refusing server
			if ip, port, ok := hostPort(is.Target); ok {
				return and("tcp.flags.reset == 1", fmt.Sprintf("%s.src == %s", addrField(ip), ipLiteral(ip)), portTerm("tcp.srcport", port))
			}
		}
		return and(flows, "tcp.flags.reset == 1")
	case titleAborted, titleIdle, titleStray:
		return and(flows, "tcp.flags.reset == 1")
	case titleUnansweredSYN, titleSYNFlood:
		if is.Title == titleSYNFlood {
			if ip, port, ok := hostPort(is.Target); ok {
				return and("tcp.flags.syn == 1", "tcp.flags.ack == 0", fmt.Sprintf("%s.dst == %s", addrField(ip), ipLiteral(ip)), portTerm("tcp.dstport", port))
			}
		}
		return and(flows, "tcp.flags.syn == 1", "tcp.flags.ack == 0")
	case titleSYNRetried:
		return and(flows, "tcp.flags.syn == 1", "tcp.flags.ack == 0", "tcp.analysis.retransmission")
	}
	return ""
}

func portTerm(field string, port uint16) string {
	if port == 0 {
		return ""
	}
	return fmt.Sprintf("%s == %d", field, port)
}

func (g guide) performanceFilter(is models.Issue) string {
	flows := g.flowsTerm(is, "tcp")
	switch is.Title {
	case "Slow TCP Handshake":
		return and(flows, "tcp.analysis.initial_rtt")
	case "Slow Server Response":
		return and(flows, "tcp.len > 0")
	case "High Network Latency":
		return and(flows, "tcp.analysis.ack_rtt > 0.2")
	case "High Jitter":
		return and(flows, "tcp.analysis.ack_rtt > 0.5")
	}
	return flows
}

func (g guide) dnsFilter(is models.Issue) string {
	var rcode string
	var timeout bool
	var slow bool
	switch is.Title {
	case "DNS NXDOMAIN":
		rcode = "dns.flags.rcode == 3"
	case "DNS SERVFAIL":
		rcode = "dns.flags.rcode == 2"
	case "DNS Timeout":
		timeout = true
	case "DNS Slow Response":
		slow = true
	default:
		return ""
	}

	// the queried names, if few enough to list; else the resolver
	names := uniqueSubjects(is)
	var nameTerm string
	if len(names) > 0 && len(names) <= maxFilterTerms {
		nameTerm = orTerms(mapStrings(names, func(n string) string { return "dns.qry.name == " + wsString(n) }))
	}
	resolver := ""
	if nameTerm == "" && is.Target != "" {
		if ip, _, ok := hostPort(is.Target); ok {
			side := "src"
			if timeout {
				side = "dst" // the queries went to it
			}
			resolver = fmt.Sprintf("%s.%s == %s", addrField(ip), side, ipLiteral(ip))
		}
	}
	switch {
	case timeout:
		return and("dns.flags.response == 0", "!dns.response_in", nameTerm, resolver)
	case slow:
		return and("dns.flags.response == 1", "dns.time > 1", nameTerm, resolver)
	}
	return and(rcode, nameTerm, resolver)
}

func (g guide) sipFilter(is models.Issue) string {
	codes := codesOf(is)
	switch is.Title {
	case titleSIPRegistration, titleSIPCallSetup:
		method := "REGISTER"
		if is.Title == titleSIPCallSetup {
			method = "INVITE"
		}
		return and(fmt.Sprintf("sip.CSeq.method == %s", wsString(method)), eqAny("sip.Status-Code", codes))
	case titleSIPErrorRate:
		return and(g.flowsTerm(is, "udp"), "sip.Status-Code >= 400")
	}
	return ""
}

func (g guide) dhcpv6Filter(is models.Issue) string {
	answers := "(dhcpv6.msgtype == 2 || dhcpv6.msgtype == 7)"
	switch is.Title {
	case titleDHCPv6NoAddrs, titleDHCPv6Config:
		return and(answers, eqAny("dhcpv6.status_code", codesOf(is)))
	case titleDHCPv6FailRate:
		return and(answers, "dhcpv6.status_code > 0")
	case titleDHCPv6Timeout:
		dst := ""
		if ip, _, ok := hostPort(is.Target); ok {
			dst = fmt.Sprintf("ipv6.dst == %s", ipLiteral(ip))
		}
		return and("(dhcpv6.msgtype == 1 || dhcpv6.msgtype == 3)", dst)
	}
	return ""
}

func (g guide) quicFilter(is models.Issue) string {
	switch is.Title {
	case titleQUICTimeout:
		if ip, port, ok := hostPort(is.Target); ok {
			return and("quic.long.packet_type == 0", fmt.Sprintf("%s.dst == %s", addrField(ip), ipLiteral(ip)), portTerm("udp.dstport", port))
		}
		return "quic.long.packet_type == 0"
	case titleQUICRetry:
		return and("quic.long.packet_type == 3", srcOf(is.Target))
	case titleQUICVersionNeg:
		return and("quic.version == 0x00000000", srcOf(is.Target))
	case titleQUICDraft:
		return "quic.version >= 0xff000000 && quic.version <= 0xff0000ff"
	}
	return ""
}

// srcOf filters on the sender named by an ip:port target.
func srcOf(target string) string {
	ip, port, ok := hostPort(target)
	if !ok {
		return ""
	}
	return and(fmt.Sprintf("%s.src == %s", addrField(ip), ipLiteral(ip)), portTerm("udp.srcport", port))
}

// packetStreamTerm filters on the TCP conversation of packet p: its stream if
// the numbering is known, else its addresses and ports.
func packetStreamTerm(p models.PacketInfo) string {
	if p.Protocol == models.ProtocolTCP && p.StreamKnown {
		return fmt.Sprintf("tcp.stream eq %d", p.Stream)
	}
	proto := ""
	switch p.Protocol {
	case models.ProtocolTCP:
		proto = "tcp"
	case models.ProtocolUDP:
		proto = "udp"
	}
	return addressTerm([]filter.Endpoint{{IP: p.SrcIP, Port: p.SrcPort}, {IP: p.DstIP, Port: p.DstPort}}, proto)
}
