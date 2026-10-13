package analyzer

import (
	"math"
	"sort"

	"github.com/gocisse/netforensic/internal/models"
)

// otherProtocol names packets whose IP protocol this tool does not decode.
const otherProtocol = "Other"

// topFlowsPerProtocol is how many of the busiest flows each ProtocolStat lists.
const topFlowsPerProtocol = 5

// flowClass is what is known about the protocols of one flow.
type flowClass struct {
	transport models.Protocol // TCP, UDP, ICMP, ARP, or "" for other IP protocols
	app       models.Protocol // DNS, HTTP, TLS or SIP if recognized in the flow, else ""
	sipPort   bool            // a packet used a well-known SIP port (5060, 5061)
	dhcpPort  bool            // a UDP packet used a DHCPv6 port (546, 547)
	dhcp4Port bool            // a UDP packet used a DHCP port (67, 68)
}

// transportName is the transport protocol as shown to users.
func (c *flowClass) transportName() string {
	if c.transport == "" {
		return otherProtocol
	}
	return string(c.transport)
}

// primary is the most specific protocol: the application protocol if there is
// one, else the transport protocol.
func (c *flowClass) primary() string {
	if c.app != "" {
		return string(c.app)
	}
	return c.transportName()
}

// classifyFlows works out the transport and application protocol of every
// flow, keyed by flow ID, and returns the flow class of each packet.
//
// The application protocol comes from the content: a flow is DNS if any of
// its packets carries a DNS message, TLS if any carries a TLS record, HTTP if
// any carries an HTTP request or response, SIP if any carries a SIP request,
// DHCPv6 if any carries a DHCPv6 message, QUIC if any carries a QUIC long header
// or response. If several apply, DNS beats TLS beats HTTP (a CONNECT tunnel
// starts as HTTP and carries TLS). A flow that never showed a SIP message but
// uses a well-known SIP port (5060, 5061) and was recognized as nothing else
// is taken for SIP too: a TCP flow's ACKs and segment fragments carry no
// message, and port 5061 usually carries TLS, which wins.
func classifyFlows(packets []models.PacketInfo) (map[string]*flowClass, []*flowClass) {
	classes := make(map[string]*flowClass)
	perPacket := make([]*flowClass, len(packets))
	insts := models.ConnectionInstances(packets)

	for i, p := range packets {
		fk, _ := canonicalKey(p)
		id := instKey{fk, insts[i]}.id()
		c := classes[id]
		if c == nil {
			c = &flowClass{transport: p.Protocol}
			classes[id] = c
		}
		perPacket[i] = c

		switch {
		case p.DNSQueryName != "":
			c.app = models.ProtocolDNS
		case p.TLSHandshakeType != "" && c.app != models.ProtocolDNS:
			c.app = models.ProtocolTLS
		case (p.HTTPMethod != "" || p.HTTPStatusCode != 0) && c.app == "":
			c.app = models.ProtocolHTTP
		case (p.SIPMethod != "" || p.SIPStatusCode != 0) && c.app != models.ProtocolDNS:
			c.app = models.ProtocolSIP
		case p.DHCP != nil && c.app != models.ProtocolDNS:
			c.app = models.ProtocolDHCP
		case p.DHCPv6MsgType != 0 && c.app != models.ProtocolDNS:
			c.app = models.ProtocolDHCPv6
		case p.QUICLongHeader && c.app != models.ProtocolDNS:
			c.app = models.ProtocolQUIC
		}
		if isSIPPort(p) {
			c.sipPort = true
		}
		if isDHCPv6Port(p) {
			c.dhcpPort = true
		}
		if isDHCPPort(p) {
			c.dhcp4Port = true
		}
	}
	for _, c := range classes {
		switch {
		case c.app != "":
		case c.sipPort:
			c.app = models.ProtocolSIP
		case c.dhcpPort:
			c.app = models.ProtocolDHCPv6
		case c.dhcp4Port:
			c.app = models.ProtocolDHCP
		}
	}
	return classes, perPacket
}

// sipPorts are the well-known SIP ports: 5060 (plain) and 5061 (TLS).
const (
	sipPort    = 5060
	sipTLSPort = 5061
)

// isSIPPort reports whether p is TCP or UDP traffic to or from a SIP port.
func isSIPPort(p models.PacketInfo) bool {
	if p.Protocol != models.ProtocolTCP && p.Protocol != models.ProtocolUDP {
		return false
	}
	return p.SrcPort == sipPort || p.DstPort == sipPort || p.SrcPort == sipTLSPort || p.DstPort == sipTLSPort
}

// isDHCPPort reports whether p is UDP traffic to or from a DHCP (IPv4) port: 67
// (servers and relay agents) or 68 (clients).
func isDHCPPort(p models.PacketInfo) bool {
	return p.Protocol == models.ProtocolUDP && (p.SrcPort == 67 || p.SrcPort == 68 || p.DstPort == 67 || p.DstPort == 68)
}

// isDHCPv6Port reports whether p is UDP traffic to or from a DHCPv6 port: 546
// (clients) or 547 (servers and relay agents).
func isDHCPv6Port(p models.PacketInfo) bool {
	return p.Protocol == models.ProtocolUDP && (p.SrcPort == 546 || p.SrcPort == 547 || p.DstPort == 546 || p.DstPort == 547)
}

// protocolStats computes the traffic composition: packets, flows and share of
// all packets per protocol, most packets first. Every packet counts towards
// its transport protocol, and also towards the application protocol of its
// flow, so application protocols overlap with transport ones.
func protocolStats(packets []models.PacketInfo, flows []models.Flow, classes map[string]*flowClass, perPacket []*flowClass) []models.ProtocolStat {
	if len(packets) == 0 {
		return []models.ProtocolStat{}
	}

	type acc struct {
		layer         string
		packets, flow int
	}
	byName := make(map[string]*acc)
	add := func(name, layer string, packets, flows int) {
		a := byName[name]
		if a == nil {
			a = &acc{layer: layer}
			byName[name] = a
		}
		a.packets += packets
		a.flow += flows
	}

	for _, c := range perPacket {
		add(c.transportName(), "transport", 1, 0)
		if c.app != "" {
			add(string(c.app), "application", 1, 0)
		}
	}
	for _, c := range classes {
		add(c.transportName(), "transport", 0, 1)
		if c.app != "" {
			add(string(c.app), "application", 0, 1)
		}
	}

	stats := make([]models.ProtocolStat, 0, len(byName))
	for name, a := range byName {
		stats = append(stats, models.ProtocolStat{
			Protocol: name,
			Layer:    a.layer,
			Packets:  a.packets,
			Flows:    a.flow,
			Percent:  math.Round(float64(a.packets)*1000/float64(len(packets))) / 10,
			TopFlows: topFlowsOf(flows, name),
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Packets != stats[j].Packets {
			return stats[i].Packets > stats[j].Packets
		}
		return stats[i].Protocol < stats[j].Protocol
	})
	return stats
}

// topFlowsOf returns the busiest flows (by bytes) that belong to protocol,
// as their transport or application protocol.
func topFlowsOf(flows []models.Flow, protocol string) []models.Flow {
	var idx []int
	for i := range flows {
		f := &flows[i]
		transport := string(f.Protocol)
		if transport == "" {
			transport = otherProtocol
		}
		if transport == protocol || f.AppProtocol == protocol {
			idx = append(idx, i)
		}
	}
	return topByBytes(flows, idx, topFlowsPerProtocol)
}

// annotateProtocols fills in the protocols of issues and of their
// occurrences, so that a UI can filter by protocol and show the protocol of
// every event. Protocols already set on an issue are kept.
//
// An event whose subject is a flow ID takes the protocols of that flow. DNS,
// ICMP and ARP issues are about their own protocol, and HTTP and TLS issues
// about that protocol over TCP. Issues about the capture itself involve no
// protocol.
func annotateProtocols(issues []models.Issue, classes map[string]*flowClass) {
	for i := range issues {
		is := &issues[i]
		set := make(map[string]struct{})
		for _, p := range is.Protocols {
			set[p] = struct{}{}
		}

		for j := range is.Occurrences {
			o := &is.Occurrences[j]
			primary, all := protocolsOf(is, o.Subject, classes)
			if o.Protocol == "" {
				o.Protocol = primary
			}
			for _, p := range all {
				set[p] = struct{}{}
			}
		}
		if is.FlowID != "" {
			_, all := protocolsOf(is, is.FlowID, classes)
			for _, p := range all {
				set[p] = struct{}{}
			}
		}
		if len(is.Occurrences) == 0 && is.FlowID == "" {
			_, all := protocolsOf(is, "", classes)
			for _, p := range all {
				set[p] = struct{}{}
			}
		}

		if len(set) == 0 {
			continue
		}
		is.Protocols = is.Protocols[:0]
		for p := range set {
			is.Protocols = append(is.Protocols, p)
		}
		sort.Strings(is.Protocols)
	}
}

// protocolsOf returns the most specific protocol and all protocols involved
// for an event of issue is about subject (a flow ID, or something else).
func protocolsOf(is *models.Issue, subject string, classes map[string]*flowClass) (string, []string) {
	if c, ok := classes[subject]; ok {
		all := []string{c.transportName()}
		if c.app != "" {
			all = append(all, string(c.app))
		}
		return c.primary(), all
	}
	switch is.Category {
	case "DNS":
		return string(models.ProtocolDNS), []string{string(models.ProtocolDNS)}
	case "ICMP":
		return string(models.ProtocolICMP), []string{string(models.ProtocolICMP)}
	case "ARP":
		return string(models.ProtocolARP), []string{string(models.ProtocolARP)}
	case "HTTP":
		return string(models.ProtocolHTTP), []string{string(models.ProtocolHTTP), string(models.ProtocolTCP)}
	case "TLS":
		return string(models.ProtocolTLS), []string{string(models.ProtocolTLS), string(models.ProtocolTCP)}
	case "SIP":
		return string(models.ProtocolSIP), []string{string(models.ProtocolSIP)}
	case "DHCP":
		return string(models.ProtocolDHCP), []string{string(models.ProtocolDHCP), string(models.ProtocolUDP)}
	case "DHCPv6":
		return string(models.ProtocolDHCPv6), []string{string(models.ProtocolDHCPv6), string(models.ProtocolUDP)}
	case "QUIC":
		return string(models.ProtocolQUIC), []string{string(models.ProtocolQUIC), string(models.ProtocolUDP)}
	}
	return "", nil
}
