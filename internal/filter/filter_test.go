package filter

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func mustParse(t *testing.T, query string) Spec {
	t.Helper()
	q, err := url.ParseQuery(query)
	require.NoError(t, err)
	s, err := Parse(q)
	require.NoError(t, err, query)
	return s
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    Spec
		wantErr string // "" means valid
	}{
		{name: "nothing", query: "", want: Spec{}},
		{name: "every filter", query: "source_ip=10.0.0.1&dest_ip=2001:DB8::1&port=80,443,8000-9000&protocol=DNS&severity=error,warning&category=DNS,Connection",
			want: Spec{SourceIP: "10.0.0.1", DestIP: "2001:0db8:0000:0000:0000:0000:0000:0001", Ports: []PortRange{{80, 80}, {443, 443}, {8000, 9000}},
				Protocol: "DNS", Severities: []string{"ERROR", "WARNING"}, Categories: []string{"DNS", "Connection"}}},
		{name: "All is no protocol filter", query: "protocol=All", want: Spec{}},
		{name: "all, in any case", query: "protocol=ALL", want: Spec{}},
		{name: "spaces are trimmed", query: "source_ip=%2010.0.0.1%20&port=%2080%20,%20443%20", want: Spec{SourceIP: "10.0.0.1", Ports: []PortRange{{80, 80}, {443, 443}}}},
		{name: "an IPv4-mapped address is the IPv4 address", query: "source_ip=::ffff:10.0.0.1", want: Spec{SourceIP: "10.0.0.1"}},
		{name: "empty list entries are skipped", query: "severity=ERROR,,INFO,", want: Spec{Severities: []string{"ERROR", "INFO"}}},

		{name: "not an IP", query: "source_ip=999.1.1.1", wantErr: "source_ip"},
		{name: "a hostname", query: "dest_ip=example.com", wantErr: "dest_ip"},
		{name: "an IPv6 zone", query: "source_ip=fe80::1%25eth0", wantErr: "source_ip"},
		{name: "a CIDR", query: "source_ip=10.0.0.0/8", wantErr: "source_ip"},
		{name: "port 0", query: "port=0", wantErr: "port"},
		{name: "port 65536", query: "port=65536", wantErr: "port"},
		{name: "a word", query: "port=http", wantErr: "port"},
		{name: "a backwards range", query: "port=9000-8000", wantErr: "runs backwards"},
		{name: "an empty entry", query: "port=80,,443", wantErr: "port"},
		{name: "a negative port", query: "port=-80", wantErr: "port"},
		{name: "an open range", query: "port=80-", wantErr: "port"},
		{name: "an unknown severity", query: "severity=FATAL", wantErr: "severity"},
		{name: "a protocol with a comma", query: "protocol=TCP,UDP", wantErr: "protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := url.ParseQuery(tt.query)
			require.NoError(t, err)
			got, err := Parse(q)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want.Active(), got.Active())
		})
	}
}

func TestParseLimits(t *testing.T) {
	ports := ""
	for i := 1; i <= maxPortRanges+1; i++ {
		ports += "," + string(rune('0'+i%10)) + "1"
	}
	q := url.Values{ParamPort: {ports[1:]}}
	_, err := Parse(q)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than")
}

func TestActive(t *testing.T) {
	assert.False(t, Spec{}.Active())
	assert.True(t, mustParse(t, "protocol=TCP").Active())
	assert.True(t, mustParse(t, "severity=ERROR").Active())
	assert.False(t, mustParse(t, "protocol=All").Active())
}

func flow(src string, sport uint16, dst string, dport uint16, proto, app string, packets int) models.Flow {
	return models.Flow{ID: src + ":" + "x", SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport, Protocol: models.Protocol(proto), AppProtocol: app, PacketCount: packets}
}

func TestMatchFlow(t *testing.T) {
	web := flow("10.0.0.1", 50000, "93.184.216.34", 443, "TCP", "TLS", 10)
	dns := flow("10.0.0.1", 53000, "8.8.8.8", 53, "UDP", "DNS", 4)
	v6 := flow("2001:db8::1", 4000, "2001:db8::2", 80, "TCP", "HTTP", 6)
	icmp := flow("10.0.0.5", 0, "10.0.0.6", 0, "ICMP", "", 2)
	ospf := flow("10.0.0.7", 0, "224.0.0.5", 0, "OSPF", "", 3)
	other := flow("10.0.0.8", 0, "10.0.0.9", 0, "", "", 1)

	tests := []struct {
		name  string
		query string
		flow  models.Flow
		want  bool
	}{
		{"no filter", "", web, true},
		{"source IP is either endpoint: the source", "source_ip=10.0.0.1", web, true},
		{"source IP is either endpoint: the destination", "source_ip=93.184.216.34", web, true},
		{"another IP", "source_ip=10.9.9.9", web, false},
		{"source and destination, in order", "source_ip=10.0.0.1&dest_ip=93.184.216.34", web, true},
		{"source and destination, reversed", "source_ip=93.184.216.34&dest_ip=10.0.0.1", web, true},
		{"source and destination, one of them wrong", "source_ip=10.0.0.1&dest_ip=8.8.8.8", web, false},
		{"IPv6 in another spelling", "source_ip=2001:0DB8:0:0:0:0:0:1", v6, true},
		{"IPv6, the other address", "dest_ip=2001:db8::2", v6, true},
		{"IPv6 does not match IPv4", "source_ip=10.0.0.1", v6, false},
		{"a port, the destination's", "port=443", web, true},
		{"a port, the source's", "port=50000", web, true},
		{"another port", "port=80", web, false},
		{"a range", "port=8000-9000,40000-60000", web, true},
		{"the range's ends are inside it", "port=443-443", web, true},
		{"just outside the range", "port=444-500", web, false},
		{"a list", "port=22,80,443", web, true},
		{"ports and IP together", "port=443&source_ip=10.0.0.1", web, true},
		{"ports and IP together, the IP wrong", "port=443&source_ip=10.0.0.2", web, false},
		{"portless flows never match a port filter", "port=1-65535", icmp, false},
		{"protocol: transport", "protocol=TCP", web, true},
		{"protocol: application", "protocol=TLS", web, true},
		{"protocol: wrong", "protocol=UDP", web, false},
		{"protocol: case-insensitive", "protocol=tls", web, true},
		{"protocol: a named IP protocol", "protocol=OSPF", ospf, true},
		{"protocol: Other is a flow with no name", "protocol=Other", other, true},
		{"protocol: Other is not a TCP flow", "protocol=Other", web, false},
		{"protocol and IP", "protocol=DNS&source_ip=10.0.0.1", dns, true},
		{"protocol right, IP wrong", "protocol=DNS&source_ip=10.0.0.2", dns, false},
		{"severity and category do not apply to flows", "severity=ERROR&category=DNS", web, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mustParse(t, tt.query).MatchFlow(tt.flow))
		})
	}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		ref  string
		want []endpoint
	}{
		{"10.0.0.1", []endpoint{{"10.0.0.1", 0}}},
		{"10.0.0.1:443", []endpoint{{"10.0.0.1", 443}}},
		{"[2001:db8::1]:443", []endpoint{{"2001:0db8:0000:0000:0000:0000:0000:0001", 443}}},
		{"2001:db8::1", []endpoint{{"2001:0db8:0000:0000:0000:0000:0000:0001", 0}}},
		{"[2001:db8::1]", []endpoint{{"2001:0db8:0000:0000:0000:0000:0000:0001", 0}}},
		{"10.0.0.1:1000-10.0.0.2:80", []endpoint{{"10.0.0.1", 1000}, {"10.0.0.2", 80}}},
		{"10.0.0.1:1000-10.0.0.2:80#2", []endpoint{{"10.0.0.1", 1000}, {"10.0.0.2", 80}}},
		{"10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2", []endpoint{{"10.0.0.1", 1000}, {"10.0.0.2", 80}}},
		{"10.0.0.1:1000-10.0.0.2:80#3@IP-in-IP:192.0.2.1~192.0.2.2", []endpoint{{"10.0.0.1", 1000}, {"10.0.0.2", 80}}},
		{"[2001:db8::1]:5-[2001:db8::2]:6", []endpoint{{"2001:0db8:0000:0000:0000:0000:0000:0001", 5}, {"2001:0db8:0000:0000:0000:0000:0000:0002", 6}}},
		{"10.0.0.1:0-10.0.0.2:0", []endpoint{{"10.0.0.1", 0}, {"10.0.0.2", 0}}},
		{"::ffff:10.0.0.1", []endpoint{{"10.0.0.1", 0}}},

		{"", nil},
		{"download.windowsupdate.com", nil},
		{"my-host.example.com", nil},
		{"132.146.114.52.in-addr.arpa.na.loreal.intra", nil},
		{"p65557t1573829978m943109c168405915s2", nil},
		{"00030001aabbccddeeff", nil},
		{"10.0.0.1:99999", nil},
		{"10.0.0.1:http", nil},
		{"10.0.0.1:80-", nil},
		{"-10.0.0.1:80", nil},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, parseRef(tt.ref), tt.ref)
	}
}

func TestMatchIssue(t *testing.T) {
	flowIssue := models.Issue{ID: "1", Severity: models.SeverityError, Category: "Connection", Title: "Connection Abruptly Closed",
		FlowID: "10.0.0.1:50000-10.0.0.2:80", Target: "10.0.0.2:80", Protocols: []string{"TCP", "HTTP"}}
	dnsIssue := models.Issue{ID: "2", Severity: models.SeverityWarning, Category: "DNS", Title: "DNS NXDOMAIN", Target: "8.8.8.8",
		Domain: "x.example.com", Occurrences: []models.Occurrence{{Subject: "x.example.com"}}, Protocols: []string{"UDP", "DNS"}}
	aggregated := models.Issue{ID: "3", Severity: models.SeverityWarning, Category: "Performance", Title: "High Network Latency", Target: "10.1.1.1:5985-10.2.2.2:59393",
		Occurrences: []models.Occurrence{{Subject: "10.1.1.1:5985-10.2.2.2:59393"}, {Subject: "10.3.3.3:443-10.4.4.4:50000"}}, Protocols: []string{"TCP"}}
	http := models.Issue{ID: "4", Severity: models.SeverityInfo, Category: "HTTP", Title: "HTTP Slow Response", Domain: "download.example.com", Protocols: []string{"HTTP", "TCP"}}
	note := models.Issue{ID: "5", Severity: models.SeverityInfo, Category: "Capture", Title: "Skipped Frames"}
	critical := models.Issue{ID: "6", Severity: models.SeverityCritical, Category: "ARP", Title: "ARP Spoofing", Target: "10.0.0.50", Protocols: []string{"ARP"}}
	v6 := models.Issue{ID: "7", Severity: models.SeverityWarning, Category: "ICMP", Title: "ICMP Time Exceeded", Target: "[2001:db8::9]:443", Protocols: []string{"ICMP"}}

	tests := []struct {
		name  string
		query string
		issue models.Issue
		want  bool
	}{
		{"no filter", "", flowIssue, true},
		{"no filter still drops the capture note", "severity=ERROR,INFO", note, false},
		{"severity", "severity=ERROR", flowIssue, true},
		{"severity, another", "severity=ERROR", dnsIssue, false},
		{"several severities", "severity=ERROR,WARNING", dnsIssue, true},
		{"CRITICAL is its own severity", "severity=ERROR", critical, false},
		{"CRITICAL", "severity=CRITICAL", critical, true},
		{"category", "category=DNS", dnsIssue, true},
		{"category, case-insensitive", "category=dns", dnsIssue, true},
		{"category, another", "category=DNS", flowIssue, false},
		{"several categories", "category=DNS,Connection", flowIssue, true},
		{"protocol of the issue", "protocol=HTTP", flowIssue, true},
		{"protocol it does not involve", "protocol=UDP", flowIssue, false},
		{"severity and category", "severity=ERROR&category=Connection", flowIssue, true},
		{"severity right, category wrong", "severity=ERROR&category=DNS", flowIssue, false},
		{"an IP in the flow ID", "source_ip=10.0.0.1", flowIssue, true},
		{"the other IP in the flow ID", "dest_ip=10.0.0.2", flowIssue, true},
		{"both, whichever way round", "source_ip=10.0.0.2&dest_ip=10.0.0.1", flowIssue, true},
		{"an IP in the target", "source_ip=8.8.8.8", dnsIssue, true},
		{"an IP the issue does not mention", "source_ip=10.0.0.9", flowIssue, false},
		{"an IP in a later event", "source_ip=10.3.3.3", aggregated, true},
		{"an IP in the target of an aggregated issue", "source_ip=10.2.2.2", aggregated, true},
		{"one IP in one event, the other in another", "source_ip=10.1.1.1&dest_ip=10.4.4.4", aggregated, true},
		{"a port in the flow ID", "port=50000", flowIssue, true},
		{"a port in the target", "port=80", flowIssue, true},
		{"a port range", "port=8000-9000", flowIssue, false},
		{"a port on an event subject", "port=443", aggregated, true},
		{"an IP-only target never matches a port", "port=53", dnsIssue, false},
		{"a domain-only issue does not match an IP filter", "source_ip=10.0.0.1", http, false},
		{"a domain-only issue does not match a port filter", "port=80", http, false},
		{"a domain-only issue still matches the other filters", "category=HTTP&severity=INFO", http, true},
		{"a bare IPv4 target", "source_ip=10.0.0.50", critical, true},
		{"an IPv6 target, spelled differently", "source_ip=2001:DB8:0:0:0:0:0:9", v6, true},
		{"an IPv6 target's port", "port=443", v6, true},
		{"everything at once", "source_ip=10.0.0.1&dest_ip=10.0.0.2&port=80&protocol=TCP&severity=ERROR&category=Connection", flowIssue, true},
		{"everything at once, one thing wrong", "source_ip=10.0.0.1&dest_ip=10.0.0.2&port=80&protocol=TCP&severity=WARNING&category=Connection", flowIssue, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mustParse(t, tt.query).MatchIssue(tt.issue))
		})
	}
}

func sampleResult() *models.AnalysisResult {
	return &models.AnalysisResult{
		FileName: "x.pcap", TotalPackets: 24, TotalFlows: 4,
		Flows: []models.Flow{
			flow("10.0.0.1", 50000, "93.184.216.34", 443, "TCP", "TLS", 10),
			flow("10.0.0.1", 53000, "8.8.8.8", 53, "UDP", "DNS", 4),
			flow("10.0.0.2", 40000, "10.0.0.3", 22, "TCP", "", 8),
			flow("10.0.0.5", 0, "10.0.0.6", 0, "ICMP", "", 2),
		},
		Issues: []models.Issue{
			{ID: "a", Severity: models.SeverityError, Category: "Connection", FlowID: "10.0.0.1:50000-93.184.216.34:443", Protocols: []string{"TCP", "TLS"}},
			{ID: "b", Severity: models.SeverityWarning, Category: "DNS", Target: "8.8.8.8", Protocols: []string{"UDP", "DNS"}},
			{ID: "c", Severity: models.SeverityWarning, Category: "Connection", FlowID: "10.0.0.2:40000-10.0.0.3:22", Protocols: []string{"TCP"}},
			{ID: "n", Severity: models.SeverityInfo, Category: "Capture", Title: "Skipped Frames"},
		},
		ProtocolStats: []models.ProtocolStat{{Protocol: "TCP", Packets: 18}},
		Diagnosis:     models.RootCauseAnalysis{HealthScore: 42, PrimaryCause: "cause"},
	}
}

func TestApply(t *testing.T) {
	res := sampleResult()

	t.Run("an inactive spec changes nothing", func(t *testing.T) {
		assert.Same(t, res, Spec{}.Apply(res))
	})

	t.Run("by IP: flows, issues and the protocol distribution", func(t *testing.T) {
		got := mustParse(t, "source_ip=10.0.0.1").Apply(res)
		require.Len(t, got.Flows, 2)
		assert.Equal(t, 2, got.TotalFlows)
		require.Len(t, got.Issues, 1, "only the issues that mention the address: not the DNS issue about 8.8.8.8, not the capture note")
		assert.Equal(t, "a", got.Issues[0].ID)

		byName := map[string]models.ProtocolStat{}
		for _, p := range got.ProtocolStats {
			byName[p.Protocol] = p
		}
		assert.Equal(t, 10, byName["TCP"].Packets)
		assert.Equal(t, 4, byName["UDP"].Packets)
		assert.Equal(t, 10, byName["TLS"].Packets)
		assert.Equal(t, "application", byName["TLS"].Layer)
		assert.Equal(t, 71.4, byName["TCP"].Percent, "10 of the 14 packets that are left")
		assert.Equal(t, 28.6, byName["UDP"].Percent)
	})

	t.Run("the capture-wide results are untouched", func(t *testing.T) {
		got := mustParse(t, "severity=ERROR").Apply(res)
		assert.Equal(t, 42, got.Diagnosis.HealthScore)
		assert.Equal(t, "cause", got.Diagnosis.PrimaryCause)
		assert.Equal(t, 24, got.TotalPackets)
		assert.Equal(t, "x.pcap", got.FileName)
		require.Len(t, got.Issues, 1)
		assert.Len(t, got.Flows, 4, "severity does not apply to flows")
	})

	t.Run("the original is not modified", func(t *testing.T) {
		_ = mustParse(t, "protocol=UDP").Apply(res)
		assert.Len(t, res.Flows, 4)
		assert.Len(t, res.Issues, 4)
		assert.Equal(t, 4, res.TotalFlows)
	})

	t.Run("nothing matches", func(t *testing.T) {
		got := mustParse(t, "source_ip=192.0.2.1").Apply(res)
		assert.Empty(t, got.Flows)
		assert.NotNil(t, got.Issues, "an empty list, not null")
		assert.Empty(t, got.Issues)
		assert.Empty(t, got.ProtocolStats)
		assert.Zero(t, got.TotalFlows)
	})

	t.Run("by port and protocol", func(t *testing.T) {
		got := mustParse(t, "port=22&protocol=TCP").Apply(res)
		require.Len(t, got.Flows, 1)
		assert.Equal(t, "10.0.0.2", got.Flows[0].SrcIP)
		require.Len(t, got.Issues, 1)
		assert.Equal(t, "c", got.Issues[0].ID)
	})
}

func TestProtocolStats(t *testing.T) {
	stats := ProtocolStats([]models.Flow{
		flow("1.1.1.1", 1, "2.2.2.2", 2, "TCP", "TLS", 6),
		flow("1.1.1.1", 3, "2.2.2.2", 4, "TCP", "", 3),
		flow("1.1.1.1", 5, "2.2.2.2", 6, "UDP", "DNS", 1),
		flow("1.1.1.1", 0, "2.2.2.2", 0, "", "", 0),
	})
	var got []string
	for _, s := range stats {
		got = append(got, s.Protocol+"/"+s.Layer)
	}
	assert.Equal(t, []string{"TCP/transport", "TLS/application", "DNS/application", "UDP/transport", "Other/transport"}, got,
		"most packets first, ties by name")
	assert.Equal(t, 9, stats[0].Packets)
	assert.Equal(t, 2, stats[0].Flows)
	assert.Equal(t, 90.0, stats[0].Percent)
	assert.Equal(t, 60.0, stats[1].Percent, "application protocols overlap the transport ones")
	assert.Empty(t, ProtocolStats(nil))
}
