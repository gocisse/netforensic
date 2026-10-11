package analyzer

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

var protoT0 = time.Unix(1700000000, 0)

func tcpFlowPkt(ms int, srcPort uint16, dstIP string, dstPort uint16, flags string, size int) models.PacketInfo {
	return models.PacketInfo{Timestamp: protoT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags, TCPWindow: 1000,
		SrcIP: "10.0.0.1", SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort, Size: size}
}

func udpFlowPkt(ms int, srcPort uint16, dstIP string, dstPort uint16, size int) models.PacketInfo {
	return models.PacketInfo{Timestamp: protoT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolUDP,
		SrcIP: "10.0.0.1", SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort, Size: size}
}

// mixedTraffic: 1 HTTP flow (4 packets), 1 TLS flow (3), 1 plain TCP flow (2),
// 1 DNS flow (2 UDP), 1 plain UDP flow (1), 1 ICMP packet, 1 ARP packet, and
// 1 packet of an IP protocol this tool does not decode: 15 packets, 8 flows.
func mixedTraffic() []models.PacketInfo {
	var pk []models.PacketInfo
	// HTTP: only the request carries a parsed header; the rest of the flow counts too
	pk = append(pk, tcpFlowPkt(0, 1000, "10.0.1.1", 80, "SYN", 60), tcpFlowPkt(1, 1000, "10.0.1.1", 80, "ACK", 60))
	req := tcpFlowPkt(2, 1000, "10.0.1.1", 80, "PSH,ACK", 400)
	req.HTTPMethod, req.HTTPURI, req.PayloadSize = "GET", "/", 300
	pk = append(pk, req, tcpFlowPkt(3, 1000, "10.0.1.1", 80, "FIN,ACK", 60))
	// TLS
	hello := tcpFlowPkt(10, 2000, "10.0.1.2", 443, "PSH,ACK", 500)
	hello.TLSHandshakeType = "ClientHello"
	pk = append(pk, tcpFlowPkt(9, 2000, "10.0.1.2", 443, "SYN", 60), hello, tcpFlowPkt(11, 2000, "10.0.1.2", 443, "ACK", 60))
	// plain TCP
	pk = append(pk, tcpFlowPkt(20, 3000, "10.0.1.3", 9999, "SYN", 60), tcpFlowPkt(21, 3000, "10.0.1.3", 9999, "ACK", 60))
	// DNS over UDP
	q := udpFlowPkt(30, 4000, "10.0.1.4", 53, 80)
	q.DNSQueryName, q.DNSIsQuery = "a.example", true
	r := udpFlowPkt(31, 4000, "10.0.1.4", 53, 120)
	r.DNSQueryName = "a.example"
	pk = append(pk, q, r)
	// plain UDP
	pk = append(pk, udpFlowPkt(40, 5000, "10.0.1.5", 5000, 100))
	// ICMP, ARP, other
	pk = append(pk, models.PacketInfo{Timestamp: protoT0.Add(50 * time.Millisecond), Protocol: models.ProtocolICMP, SrcIP: "10.0.0.254", DstIP: "10.0.0.1", Size: 70})
	pk = append(pk, models.PacketInfo{Timestamp: protoT0.Add(51 * time.Millisecond), Protocol: models.ProtocolARP, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Size: 42})
	pk = append(pk, models.PacketInfo{Timestamp: protoT0.Add(52 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.9.9", Size: 90})
	return pk
}

func statByName(stats []models.ProtocolStat, name string) (models.ProtocolStat, bool) {
	for _, s := range stats {
		if s.Protocol == name {
			return s, true
		}
	}
	return models.ProtocolStat{}, false
}

func TestProtocolStats(t *testing.T) {
	res := Analyze(mixedTraffic(), "all")
	require.Equal(t, 15, res.TotalPackets)
	require.Equal(t, 8, res.TotalFlows)

	want := map[string]struct {
		layer          string
		packets, flows int
		percent        float64
	}{
		"TCP":   {"transport", 9, 3, 60.0},
		"UDP":   {"transport", 3, 2, 20.0},
		"ICMP":  {"transport", 1, 1, 6.7},
		"ARP":   {"transport", 1, 1, 6.7},
		"Other": {"transport", 1, 1, 6.7},
		"HTTP":  {"application", 4, 1, 26.7},
		"TLS":   {"application", 3, 1, 20.0},
		"DNS":   {"application", 2, 1, 13.3},
	}
	assert.Len(t, res.ProtocolStats, len(want))
	for name, w := range want {
		s, ok := statByName(res.ProtocolStats, name)
		require.True(t, ok, name)
		assert.Equal(t, w.layer, s.Layer, name)
		assert.Equal(t, w.packets, s.Packets, name+" packets")
		assert.Equal(t, w.flows, s.Flows, name+" flows")
		assert.InDelta(t, w.percent, s.Percent, 0.0001, name+" percent")
	}

	// transport protocols partition the capture
	var sumPackets, sumFlows int
	var sumPct float64
	for _, s := range res.ProtocolStats {
		if s.Layer == "transport" {
			sumPackets += s.Packets
			sumFlows += s.Flows
			sumPct += s.Percent
		}
	}
	assert.Equal(t, res.TotalPackets, sumPackets)
	assert.Equal(t, res.TotalFlows, sumFlows)
	assert.InDelta(t, 100, sumPct, 0.5, "rounded percentages add up to about 100")
}

func TestProtocolStatsOrderedByPackets(t *testing.T) {
	res := Analyze(mixedTraffic(), "all")
	for i := 1; i < len(res.ProtocolStats); i++ {
		a, b := res.ProtocolStats[i-1], res.ProtocolStats[i]
		assert.True(t, a.Packets > b.Packets || (a.Packets == b.Packets && a.Protocol < b.Protocol), "%s before %s", a.Protocol, b.Protocol)
	}
	assert.Equal(t, "TCP", res.ProtocolStats[0].Protocol)
	// equal counts are ordered by name: ARP, ICMP and Other have one packet each
	var tail []string
	for _, s := range res.ProtocolStats {
		if s.Packets == 1 {
			tail = append(tail, s.Protocol)
		}
	}
	assert.Equal(t, []string{"ARP", "ICMP", "Other"}, tail)
}

func TestProtocolStatsFlowsCarryTheirApplicationProtocol(t *testing.T) {
	res := Analyze(mixedTraffic(), "all")
	apps := map[string]string{}
	for _, s := range res.ProtocolStats {
		for _, f := range s.TopFlows {
			apps[f.ID] = f.AppProtocol
		}
	}
	assert.Equal(t, "HTTP", apps["10.0.0.1:1000-10.0.1.1:80"])
	assert.Equal(t, "TLS", apps["10.0.0.1:2000-10.0.1.2:443"])
	assert.Equal(t, "DNS", apps["10.0.0.1:4000-10.0.1.4:53"])
	assert.Equal(t, "", apps["10.0.0.1:3000-10.0.1.3:9999"])
}

func TestProtocolStatsTopFlows(t *testing.T) {
	var pk []models.PacketInfo
	// seven TCP flows of increasing size
	for i := 0; i < 7; i++ {
		pk = append(pk, tcpFlowPkt(i, uint16(1000+i), "10.0.1.1", 80, "ACK", 100*(i+1)))
	}
	pk = append(pk, udpFlowPkt(10, 5000, "10.0.1.5", 5000, 5000))
	res := Analyze(pk, "all")

	tcp, _ := statByName(res.ProtocolStats, "TCP")
	require.Len(t, tcp.TopFlows, 5, "at most five")
	assert.Equal(t, "10.0.0.1:1006-10.0.1.1:80", tcp.TopFlows[0].ID, "busiest first")
	assert.Equal(t, "10.0.0.1:1002-10.0.1.1:80", tcp.TopFlows[4].ID)
	for _, f := range tcp.TopFlows {
		assert.Equal(t, models.ProtocolTCP, f.Protocol, "only flows of the protocol")
	}
	udp, _ := statByName(res.ProtocolStats, "UDP")
	require.Len(t, udp.TopFlows, 1)
	assert.Equal(t, 5000, udp.TopFlows[0].BytesSent)
}

func TestProtocolStatsJSON(t *testing.T) {
	raw, err := json.Marshal(Analyze(mixedTraffic(), "all"))
	require.NoError(t, err)
	var decoded struct {
		ProtocolStats []struct {
			Protocol string  `json:"protocol"`
			Layer    string  `json:"layer"`
			Packets  int     `json:"packets"`
			Flows    int     `json:"flows"`
			Percent  float64 `json:"percent"`
			TopFlows []struct {
				ID          string `json:"id"`
				AppProtocol string `json:"app_protocol"`
			} `json:"top_flows"`
		} `json:"protocol_stats"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.NotEmpty(t, decoded.ProtocolStats)
	assert.Equal(t, "TCP", decoded.ProtocolStats[0].Protocol)
	assert.Equal(t, 9, decoded.ProtocolStats[0].Packets)
	assert.Equal(t, 60.0, decoded.ProtocolStats[0].Percent)
	assert.NotEmpty(t, decoded.ProtocolStats[0].TopFlows)
}

func TestProtocolStatsEmpty(t *testing.T) {
	assert.Equal(t, []models.ProtocolStat{}, Analyze(nil, "all").ProtocolStats, "an empty array, never null")
	raw, err := json.Marshal(Analyze(nil, "all"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"protocol_stats":[]`)
}

func TestProtocolStatsRespectTheServiceFilter(t *testing.T) {
	res := Analyze(mixedTraffic(), "dns")
	require.Equal(t, 2, res.TotalPackets)
	dns, _ := statByName(res.ProtocolStats, "DNS")
	udp, _ := statByName(res.ProtocolStats, "UDP")
	assert.Equal(t, 2, dns.Packets)
	assert.Equal(t, 100.0, dns.Percent)
	assert.Equal(t, 2, udp.Packets)
	_, hasTCP := statByName(res.ProtocolStats, "TCP")
	assert.False(t, hasTCP)
}

func TestClassifyFlowsPrecedence(t *testing.T) {
	mk := func(set func(*models.PacketInfo)) []models.PacketInfo {
		a := tcpFlowPkt(0, 1000, "10.0.1.1", 80, "PSH,ACK", 100)
		b := tcpFlowPkt(1, 1000, "10.0.1.1", 80, "PSH,ACK", 100)
		a.HTTPMethod = "CONNECT"
		set(&b)
		return []models.PacketInfo{a, b}
	}
	app := func(pk []models.PacketInfo) models.Protocol {
		classes, _ := classifyFlows(pk)
		for _, c := range classes {
			return c.app
		}
		return ""
	}
	assert.Equal(t, models.ProtocolHTTP, app(mk(func(*models.PacketInfo) {})))
	assert.Equal(t, models.ProtocolTLS, app(mk(func(p *models.PacketInfo) { p.TLSHandshakeType = "ClientHello" })), "a CONNECT tunnel that carries TLS is TLS")
	assert.Equal(t, models.ProtocolDNS, app(mk(func(p *models.PacketInfo) { p.DNSQueryName = "x" })))
	// a response parsed later does not turn TLS back into HTTP
	pk := mk(func(p *models.PacketInfo) { p.TLSHandshakeType = "ServerHello" })
	pk = append(pk, tcpFlowPkt(2, 1000, "10.0.1.1", 80, "PSH,ACK", 100))
	pk[2].HTTPStatusCode = 200
	assert.Equal(t, models.ProtocolTLS, app(pk))
}

func TestProtocolStatsSeparatePortReuse(t *testing.T) {
	pk := []models.PacketInfo{
		tcpFlowPkt(0, 1000, "10.0.1.1", 80, "SYN", 60), tcpFlowPkt(1, 1000, "10.0.1.1", 80, "RST", 60),
		tcpFlowPkt(10, 1000, "10.0.1.1", 80, "SYN", 60), tcpFlowPkt(11, 1000, "10.0.1.1", 80, "ACK", 60),
	}
	res := Analyze(pk, "all")
	tcp, _ := statByName(res.ProtocolStats, "TCP")
	assert.Equal(t, 2, tcp.Flows, "the reused port is a second connection")
	assert.Equal(t, res.TotalFlows, tcp.Flows)
}

func TestIssueAndOccurrenceProtocols(t *testing.T) {
	classes := map[string]*flowClass{
		"f-tcp":  {transport: models.ProtocolTCP},
		"f-http": {transport: models.ProtocolTCP, app: models.ProtocolHTTP},
		"f-dns":  {transport: models.ProtocolUDP, app: models.ProtocolDNS},
		"f-oth":  {},
	}
	issues := []models.Issue{
		{ID: "a", Category: "Performance", Occurrences: []models.Occurrence{{Subject: "f-tcp"}, {Subject: "f-http"}, {Subject: "f-dns"}}},
		{ID: "b", Category: "PacketLoss", FlowID: "f-http"},
		{ID: "c", Category: "DNS", Occurrences: []models.Occurrence{{Subject: "x.example"}}, Protocols: []string{"DNS", "UDP"}},
		{ID: "d", Category: "DNS", Occurrences: []models.Occurrence{{Subject: "y.example"}}},
		{ID: "e", Category: "ICMP", Occurrences: []models.Occurrence{{Subject: "10.0.0.1:80"}}},
		{ID: "f", Category: "ARP"},
		{ID: "g", Category: "HTTP"},
		{ID: "h", Category: "TLS"},
		{ID: "i", Category: "Capture"}, // about the file, not about traffic
		{ID: "j", Category: "Performance", FlowID: "f-oth"},
		{ID: "k", Category: "Connection", Occurrences: []models.Occurrence{{Subject: "unknown-flow"}}},
		{ID: "l", Category: "Performance", Occurrences: []models.Occurrence{{Subject: "f-tcp", Protocol: "preset"}}},
	}
	annotateProtocols(issues, classes)

	byID := map[string]models.Issue{}
	for _, is := range issues {
		byID[is.ID] = is
	}
	assert.Equal(t, []string{"DNS", "HTTP", "TCP", "UDP"}, byID["a"].Protocols)
	assert.Equal(t, []string{"TCP", "HTTP", "DNS"}, []string{byID["a"].Occurrences[0].Protocol, byID["a"].Occurrences[1].Protocol, byID["a"].Occurrences[2].Protocol},
		"each event shows its most specific protocol")
	assert.Equal(t, []string{"HTTP", "TCP"}, byID["b"].Protocols, "a flow issue takes the protocols of its flow")
	assert.Equal(t, []string{"DNS", "UDP"}, byID["c"].Protocols, "preset protocols are kept")
	assert.Equal(t, "DNS", byID["c"].Occurrences[0].Protocol)
	assert.Equal(t, []string{"DNS"}, byID["d"].Protocols)
	assert.Equal(t, []string{"ICMP"}, byID["e"].Protocols)
	assert.Equal(t, "ICMP", byID["e"].Occurrences[0].Protocol)
	assert.Equal(t, []string{"ARP"}, byID["f"].Protocols)
	assert.Equal(t, []string{"HTTP", "TCP"}, byID["g"].Protocols)
	assert.Equal(t, []string{"TCP", "TLS"}, byID["h"].Protocols)
	assert.Empty(t, byID["i"].Protocols, "capture notes involve no protocol")
	assert.Equal(t, []string{"Other"}, byID["j"].Protocols)
	assert.Empty(t, byID["k"].Protocols)
	assert.Equal(t, "", byID["k"].Occurrences[0].Protocol)
	assert.Equal(t, "preset", byID["l"].Occurrences[0].Protocol, "an event protocol that is already set is kept")
}

func TestAnalyzeAnnotatesRealIssues(t *testing.T) {
	// DNS failures over UDP plus a refused TCP connection
	var pk []models.PacketInfo
	pk = append(pk, dnsQ(0, 1, "x.example"), dnsR(0.1, 1, "x.example", "NXDOMAIN"))
	pk = append(pk, tcpEv(0, 5000, true, "SYN", 0), tcpEv(1, 5000, false, "RST,ACK", 0))
	res := Analyze(pk, "all")

	protocols := map[string][]string{}
	for _, is := range res.Issues {
		protocols[is.Title] = is.Protocols
		for _, o := range is.Occurrences {
			assert.NotEmpty(t, o.Protocol, is.Title)
		}
	}
	assert.Equal(t, []string{"DNS", "UDP"}, protocols["DNS NXDOMAIN"])
	assert.Equal(t, []string{"TCP"}, protocols[titleRefused])
}

func TestProtocolStatsNamedIPProtocols(t *testing.T) {
	ip := func(ms int, proto models.Protocol, dst string) models.PacketInfo {
		return models.PacketInfo{Timestamp: protoT0.Add(time.Duration(ms) * time.Millisecond), Protocol: proto, SrcIP: "10.0.0.1", DstIP: dst, Size: 80}
	}
	pk := []models.PacketInfo{
		ip(0, "OSPF", "224.0.0.5"), ip(1, "OSPF", "224.0.0.5"),
		ip(2, "VRRP", "224.0.0.18"),
		ip(3, "", "10.0.9.9"), // an IP protocol with no known name
	}
	res := Analyze(pk, "all")

	tests := []struct {
		name           string
		packets, flows int
	}{
		{"OSPF", 2, 1},
		{"VRRP", 1, 1},
		{"Other", 1, 1},
	}
	for _, tt := range tests {
		s, ok := statByName(res.ProtocolStats, tt.name)
		require.True(t, ok, tt.name)
		assert.Equal(t, "transport", s.Layer, tt.name)
		assert.Equal(t, tt.packets, s.Packets, tt.name)
		assert.Equal(t, tt.flows, s.Flows, tt.name)
	}
}
