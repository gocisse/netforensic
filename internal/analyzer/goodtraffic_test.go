package analyzer

import (
	"testing"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestGoodTrafficFilter(t *testing.T) {
	is := func(cat, f string) models.Issue { return models.Issue{Category: cat, WiresharkFilter: f} }
	tests := []struct {
		name   string
		issues []models.Issue
		want   string
	}{
		{"no issues", nil, ""},
		{"issues without filters", []models.Issue{is("DNS", "")}, ""},
		{"one filter", []models.Issue{is("TCP", "tcp.analysis.retransmission")}, "!(tcp.analysis.retransmission)"},
		{"several filters are joined with ||", []models.Issue{
			is("TCP", "tcp.analysis.retransmission"), is("TCP", "tcp.flags.reset == 1"), is("DNS", "dns.flags.rcode > 0"),
		}, "!(tcp.analysis.retransmission || tcp.flags.reset == 1 || dns.flags.rcode > 0)"},
		{"repeated filters are used once", []models.Issue{is("TCP", "tcp.flags.reset == 1"), is("TCP", "tcp.flags.reset == 1"), is("DNS", "dns")},
			"!(tcp.flags.reset == 1 || dns)"},
		{"filters with operators get parentheses", []models.Issue{is("TCP", "ip.addr == 1.1.1.1 && tcp.port == 80"), is("DNS", "dns")},
			"!((ip.addr == 1.1.1.1 && tcp.port == 80) || dns)"},
		{"an operator inside a quoted name needs none", []models.Issue{is("DNS", `dns.qry.name == "a||b.example"`), is("TCP", "tcp")},
			`!(dns.qry.name == "a||b.example" || tcp)`},
		{"capture notes are left out", []models.Issue{is("Capture", "frame.number < 5"), is("TCP", "tcp")}, "!(tcp)"},
		{"filters that are not well formed are left out", []models.Issue{is("TCP", "(tcp"), is("TCP", `dns.qry.name == "x`), is("TCP", "tcp) || (udp"), is("DNS", "dns")}, "!(dns)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GoodTrafficFilter(tt.issues))
		})
	}
}

func TestHealthyFlows(t *testing.T) {
	flows := []models.Flow{{ID: "a"}, {ID: "b", IssueCount: 2}, {ID: "c", IssueCount: 0}}
	got := HealthyFlows(flows)
	assert.Equal(t, []string{"a", "c"}, []string{got[0].ID, got[1].ID})
	assert.NotNil(t, HealthyFlows(nil))
	assert.Empty(t, HealthyFlows([]models.Flow{{IssueCount: 1}}))
}
