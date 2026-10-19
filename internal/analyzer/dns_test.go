package analyzer

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

var dnsT0 = time.Unix(1700000000, 0)

func dnsQ(sec float64, id uint16, name string) models.PacketInfo {
	return models.PacketInfo{
		Timestamp: dnsT0.Add(time.Duration(sec * float64(time.Second))),
		SrcIP:     "192.168.1.10", SrcPort: 54321, DstIP: "8.8.8.8", DstPort: 53,
		Protocol: models.ProtocolUDP, DNSID: id, DNSQueryName: name, DNSResponseType: "A", DNSIsQuery: true,
	}
}

func dnsR(sec float64, id uint16, name, rcode string) models.PacketInfo {
	return models.PacketInfo{
		Timestamp: dnsT0.Add(time.Duration(sec * float64(time.Second))),
		SrcIP:     "8.8.8.8", SrcPort: 53, DstIP: "192.168.1.10", DstPort: 54321,
		Protocol: models.ProtocolUDP, DNSID: id, DNSQueryName: name, DNSResponseType: "A", DNSResponseCode: rcode,
	}
}

// other is a non-DNS packet used to extend the capture past a given time.
func other(sec float64) models.PacketInfo {
	return models.PacketInfo{Timestamp: dnsT0.Add(time.Duration(sec * float64(time.Second))), Protocol: models.ProtocolTCP}
}

func TestAnalyzeDNS(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    []string // issue titles, in order
		wantSev []models.Severity
	}{
		{"no packets", nil, nil, nil},
		{"healthy fast response", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsR(0.05, 1, "a.com", "NOERROR")}, nil, nil},
		{"nxdomain", []models.PacketInfo{dnsQ(0, 1, "x.com"), dnsR(0.1, 1, "x.com", "NXDOMAIN")},
			[]string{"DNS NXDOMAIN"}, []models.Severity{models.SeverityWarning}},
		{"servfail", []models.PacketInfo{dnsQ(0, 1, "x.com"), dnsR(0.1, 1, "x.com", "SERVFAIL")},
			[]string{"DNS SERVFAIL"}, []models.Severity{models.SeverityError}},
		{"unsolicited nxdomain response", []models.PacketInfo{dnsR(0.1, 9, "x.com", "NXDOMAIN")},
			[]string{"DNS NXDOMAIN"}, []models.Severity{models.SeverityWarning}},
		{"slow response", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsR(1.5, 1, "a.com", "NOERROR")},
			[]string{"DNS Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"exactly 1s is not slow", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsR(1, 1, "a.com", "NOERROR")}, nil, nil},
		{"unanswered query with later traffic", []models.PacketInfo{dnsQ(0, 1, "a.com"), other(6)},
			[]string{"DNS Timeout"}, []models.Severity{models.SeverityWarning}},
		{"unanswered query at end of capture", []models.PacketInfo{dnsQ(0, 1, "a.com"), other(4)}, nil, nil},
		{"response after more than 5s is a timeout", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsR(6, 1, "a.com", "NOERROR")},
			[]string{"DNS Timeout"}, []models.Severity{models.SeverityWarning}},
		{"response id mismatch leaves query unanswered", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsR(0.1, 2, "a.com", "NOERROR"), other(7)},
			[]string{"DNS Timeout"}, []models.Severity{models.SeverityWarning}},
		{"name match is case-insensitive", []models.PacketInfo{dnsQ(0, 1, "A.com"), dnsR(2, 1, "a.COM", "NOERROR")},
			[]string{"DNS Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"client retry keeps the first query", []models.PacketInfo{dnsQ(0, 1, "a.com"), dnsQ(1, 1, "a.com"), dnsR(1.2, 1, "a.com", "NOERROR")},
			[]string{"DNS Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"out-of-order input is sorted", []models.PacketInfo{dnsR(2, 1, "a.com", "NOERROR"), dnsQ(0, 1, "a.com")},
			[]string{"DNS Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"nxdomain after slow wait reports both", []models.PacketInfo{dnsQ(0, 1, "x.com"), dnsR(2, 1, "x.com", "NXDOMAIN")},
			[]string{"DNS NXDOMAIN", "DNS Slow Response"}, []models.Severity{models.SeverityWarning, models.SeverityInfo}},
		{"non-dns packets ignored", []models.PacketInfo{other(0), other(10)}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeDNS(tt.packets)
			var titles []string
			var sevs []models.Severity
			for _, is := range issues {
				titles = append(titles, is.Title)
				sevs = append(sevs, is.Severity)
				assert.Equal(t, "DNS", is.Category)
				assert.NotEmpty(t, is.ID)
				assert.NotEmpty(t, is.Description)
			}
			assert.Equal(t, tt.want, titles)
			assert.Equal(t, tt.wantSev, sevs)
		})
	}
}

func TestAnalyzeIncludesDNSIssues(t *testing.T) {
	res := Analyze([]models.PacketInfo{dnsQ(0, 1, "x.com"), dnsR(0.1, 1, "x.com", "NXDOMAIN")}, "dns")
	require.Len(t, res.Issues, 1)
	assert.Equal(t, "DNS NXDOMAIN", res.Issues[0].Title)

	// A non-DNS service filter drops DNS packets, so no DNS issues.
	res = Analyze([]models.PacketInfo{dnsQ(0, 1, "x.com"), dnsR(0.1, 1, "x.com", "NXDOMAIN")}, "http")
	assert.Empty(t, res.Issues)
}

func nxPair(sec float64, id uint16, name string) []models.PacketInfo {
	return []models.PacketInfo{dnsQ(sec, id, name), dnsR(sec+0.01, id, name, "NXDOMAIN")}
}

func TestDNSAggregationNXDOMAIN(t *testing.T) { // Test A
	var packets []models.PacketInfo
	id := uint16(0)
	// 50 NXDOMAIN answers for 5 domains: 20, 14, 8, 5 and 3 queries
	for _, d := range []struct {
		name string
		n    int
	}{{"wpad.corp.example", 20}, {"printer.corp.example", 14}, {"old-host.corp.example", 8}, {"typo.example", 5}, {"nothing.example", 3}} {
		for i := 0; i < d.n; i++ {
			id++
			packets = append(packets, nxPair(float64(id), id, d.name)...)
		}
	}
	issues := analyzeDNS(packets)
	require.Len(t, issues, 1, "50 failures, one resolver: one issue")
	is := issues[0]
	assert.Equal(t, "DNS NXDOMAIN", is.Title)
	assert.Equal(t, models.SeverityWarning, is.Severity)
	assert.Equal(t, 50, is.Count)
	assert.Equal(t, "8.8.8.8", is.Target)
	assert.Equal(t, "wpad.corp.example", is.Domain)
	assert.Equal(t, "Resolver 8.8.8.8 returned NXDOMAIN for 50 queries (5 unique domains). "+
		"Top 3 domains: wpad.corp.example (20), printer.corp.example (14), old-host.corp.example (8).", is.Description)
	assert.NotContains(t, is.Description, "typo.example")
	assert.Len(t, is.Occurrences, 50)
	assert.Equal(t, dnsT0.Add(1010*time.Millisecond), is.Timestamp, "anchored at the first failure")
}

func TestDNSAggregationPerResolverAndKind(t *testing.T) {
	r2 := func(p models.PacketInfo) models.PacketInfo { // the same traffic via a second resolver
		if p.DNSIsQuery {
			p.DstIP = "1.1.1.1"
		} else {
			p.SrcIP = "1.1.1.1"
		}
		return p
	}
	var packets []models.PacketInfo
	packets = append(packets, nxPair(0, 1, "a.example")...)
	packets = append(packets, nxPair(1, 2, "a.example")...)
	for _, p := range nxPair(2, 3, "b.example") {
		packets = append(packets, r2(p))
	}
	packets = append(packets, dnsQ(3, 4, "c.example"), dnsR(3.1, 4, "c.example", "SERVFAIL"))
	issues := analyzeDNS(packets)

	var got []string
	for _, is := range issues {
		got = append(got, is.Title+"@"+is.Target)
	}
	assert.Equal(t, []string{"DNS NXDOMAIN@8.8.8.8", "DNS NXDOMAIN@1.1.1.1", "DNS SERVFAIL@8.8.8.8"}, got)
	assert.Equal(t, "Resolver 8.8.8.8 returned NXDOMAIN for 2 queries (1 unique domain). Domains: a.example (2).", issues[0].Description)
	assert.Equal(t, "Resolver 1.1.1.1 returned NXDOMAIN for 1 query (1 unique domain). Domains: b.example (1).", issues[1].Description)
	assert.Equal(t, models.SeverityError, issues[2].Severity)
	assert.Equal(t, "Resolver 8.8.8.8 returned SERVFAIL for 1 query (1 unique domain). Domains: c.example (1).", issues[2].Description)
}

func TestDNSAggregationTimeouts(t *testing.T) {
	var packets []models.PacketInfo
	for i := 0; i < 6; i++ { // six unanswered queries to the default resolver
		packets = append(packets, dnsQ(float64(i), uint16(i+1), fmt.Sprintf("h%d.example", i%2)))
	}
	late := dnsQ(1, 50, "late.example") // answered after 7s
	packets = append(packets, late, dnsR(8, 50, "late.example", "NOERROR"), other(30))
	// a second resolver that does answer, slowly
	q := dnsQ(2, 60, "slow.example")
	q.DstIP = "9.9.9.9"
	r := dnsR(3.5, 60, "slow.example", "NOERROR")
	r.SrcIP = "9.9.9.9"
	packets = append(packets, q, r)

	issues := analyzeDNS(packets)
	require.Len(t, issues, 2)
	to := issues[0]
	assert.Equal(t, "DNS Timeout", to.Title)
	assert.Equal(t, 7, to.Count)
	assert.Equal(t, "8.8.8.8", to.Target)
	assert.Contains(t, to.Description, "Resolver 8.8.8.8 failed to respond to 7 queries within 5s (1 answered only later).")
	assert.Contains(t, to.Description, "Domains: h0.example (3), h1.example (3), late.example (1).")

	slow := issues[1]
	assert.Equal(t, "DNS Slow Response", slow.Title)
	assert.Equal(t, models.SeverityInfo, slow.Severity)
	assert.Equal(t, "Resolver 9.9.9.9 took more than 1s to answer 1 query; the slowest, \"slow.example\", took 1.5s. Domains: slow.example (1).", slow.Description)
}

func TestDNSAggregationKeepsServfailCorrelation(t *testing.T) {
	// One aggregated SERVFAIL issue covers two domains; the HTTP 5xx belongs to the second.
	var packets []models.PacketInfo
	packets = append(packets, dnsQ(0, 1, "first.example"), dnsR(0.1, 1, "first.example", "SERVFAIL"))
	packets = append(packets, dnsQ(30, 2, "shop.example"), dnsR(30.1, 2, "shop.example", "SERVFAIL"))
	req := httpReq(31, 1000, "GET", "/")
	req.HTTPHost = "shop.example"
	resp := httpResp(31.5, 1000, 503)
	resp.HTTPHost = "shop.example"
	packets = append(packets, req, resp)

	res := Analyze(packets, "all")
	var servfails int
	for _, is := range res.Issues {
		if is.Title == "DNS SERVFAIL" {
			servfails++
			assert.Equal(t, 2, is.Count)
		}
	}
	assert.Equal(t, 1, servfails)
	assert.Equal(t, "DNS resolution failure for shop.example", res.Diagnosis.PrimaryCause)
	assert.Equal(t, "high", res.Diagnosis.Confidence)
	assert.Contains(t, res.Diagnosis.Summary, "DNS SERVFAIL at")
}

func TestPluralCount(t *testing.T) {
	assert.Equal(t, "1 query", count(1, "query", "queries"))
	assert.Equal(t, "0 queries", count(0, "query", "queries"))
	assert.Equal(t, "7 queries", count(7, "query", "queries"))
}

func TestDNSIssuesSerializeEveryQuery(t *testing.T) {
	var packets []models.PacketInfo
	for i := 0; i < 205; i++ {
		packets = append(packets, nxPair(float64(i), uint16(i+1), fmt.Sprintf("host%03d.example", i%40))...)
	}
	issues := analyzeDNS(packets)
	require.Len(t, issues, 1)

	raw, err := json.Marshal(issues[0])
	require.NoError(t, err)
	var decoded struct {
		Count       int `json:"count"`
		Occurrences []struct {
			Time    time.Time `json:"time"`
			Subject string    `json:"subject"`
		} `json:"occurrences"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, 205, decoded.Count)
	require.Len(t, decoded.Occurrences, 205, "every NXDOMAIN, not just the top three domains")
	assert.Equal(t, "host000.example", decoded.Occurrences[0].Subject)
	assert.True(t, dnsT0.Add(10*time.Millisecond).Equal(decoded.Occurrences[0].Time))

	// timeouts carry how long the answer took, when there was one
	late := dnsQ(0, 9, "late.example")
	to := analyzeDNS([]models.PacketInfo{late, dnsR(7, 9, "late.example", "NOERROR")})
	require.Len(t, to, 1)
	assert.InDelta(t, 7000, to[0].Occurrences[0].Value, 0.01)
	assert.Equal(t, "ms", to[0].Occurrences[0].Unit)
}
