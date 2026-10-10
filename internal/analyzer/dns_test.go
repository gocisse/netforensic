package analyzer

import (
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
