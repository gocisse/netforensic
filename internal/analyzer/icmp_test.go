package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func icmpPkt(sec float64, src, dst string, typ, code uint8, msg string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: src, DstIP: dst, Protocol: models.ProtocolICMP,
		ICMPType: typ, ICMPCode: code, ICMPMessage: msg}
}

func TestAnalyzeICMP(t *testing.T) {
	tests := []struct {
		name      string
		packets   []models.PacketInfo
		wantTitle []string
		wantSev   []models.Severity
	}{
		{"no packets", nil, nil, nil},
		{"echo request and reply ignored", []models.PacketInfo{
			icmpPkt(0, "10.0.0.1", "10.0.0.2", 8, 0, "Echo Request"), icmpPkt(1, "10.0.0.2", "10.0.0.1", 0, 0, "Echo Reply")}, nil, nil},
		{"destination unreachable", []models.PacketInfo{icmpPkt(0, "10.0.0.254", "10.0.0.1", 3, 3, "Destination Unreachable: Port Unreachable")},
			[]string{"ICMP Destination Unreachable"}, []models.Severity{models.SeverityError}},
		{"time exceeded", []models.PacketInfo{icmpPkt(0, "10.0.0.254", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit")},
			[]string{"ICMP Time Exceeded"}, []models.Severity{models.SeverityWarning}},
		{"redirect", []models.PacketInfo{icmpPkt(0, "10.0.0.254", "10.0.0.1", 5, 1, "Redirect: Redirect for Host")},
			[]string{"ICMP Redirect"}, []models.Severity{models.SeverityInfo}},
		{"empty message falls back to type and code", []models.PacketInfo{icmpPkt(0, "10.0.0.254", "10.0.0.1", 3, 1, "")},
			[]string{"ICMP Destination Unreachable"}, []models.Severity{models.SeverityError}},
		{"non-icmp packet with icmp-looking fields ignored", []models.PacketInfo{
			{Timestamp: at(0), Protocol: models.ProtocolTCP, ICMPType: 3}}, nil, nil},
		{"results are in chronological order", []models.PacketInfo{
			icmpPkt(5, "10.0.0.254", "10.0.0.1", 5, 0, ""), icmpPkt(1, "10.0.0.254", "10.0.0.1", 11, 0, "")},
			[]string{"ICMP Time Exceeded", "ICMP Redirect"}, []models.Severity{models.SeverityWarning, models.SeverityInfo}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeICMP(tt.packets)
			var titles []string
			var sevs []models.Severity
			for _, is := range issues {
				titles = append(titles, is.Title)
				sevs = append(sevs, is.Severity)
				assert.Equal(t, "ICMP", is.Category)
				assert.NotEmpty(t, is.ID)
				assert.NotEmpty(t, is.Description)
			}
			assert.Equal(t, tt.wantTitle, titles)
			assert.Equal(t, tt.wantSev, sevs)
		})
	}
}

func TestAnalyzeICMPAggregatesRepeats(t *testing.T) {
	packets := []models.PacketInfo{
		icmpPkt(3, "10.0.0.254", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit"),
		icmpPkt(1, "10.0.0.254", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit"),
		icmpPkt(2, "10.0.0.254", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit"),
		icmpPkt(2, "10.0.0.253", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit"), // other router
	}
	issues := analyzeICMP(packets)
	require.Len(t, issues, 2)
	assert.Contains(t, issues[0].Description, "3 times")
	assert.Contains(t, issues[0].Description, "routing loop")
	assert.Equal(t, at(1), issues[0].Timestamp, "anchored at the earliest occurrence")
	assert.NotContains(t, issues[1].Description, "times")
}
