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
	assert.Contains(t, issues[0].Description, "Router 10.0.0.254 sent 3 Time Exceeded messages to 1 host")
	assert.Contains(t, issues[0].Description, "routing loop")
	assert.Equal(t, 3, issues[0].Count)
	assert.Equal(t, at(1), issues[0].Timestamp, "anchored at the earliest occurrence")
	assert.Contains(t, issues[1].Description, "Router 10.0.0.253 sent 1 Time Exceeded message to 1 host.")
}

// icmpErr is a Destination Unreachable from router about a packet that
// 10.0.0.1 sent to dst:port.
func icmpErr(sec float64, router, dst string, port uint16, msg string) models.PacketInfo {
	p := icmpPkt(sec, router, "10.0.0.1", 3, 1, msg)
	p.ICMPOrigSrcIP, p.ICMPOrigDstIP, p.ICMPOrigDstPort, p.ICMPOrigSrcPort, p.ICMPOrigProto = "10.0.0.1", dst, port, 40000, "TCP"
	return p
}

func TestICMPAggregationByRouter(t *testing.T) { // Test B
	var packets []models.PacketInfo
	// 30 errors from one router: 12 about .10:80, 9 about .11:443, 6 about .12:22, 3 about .13:25
	for i, spec := range []struct {
		dst  string
		port uint16
		n    int
	}{{"192.168.9.10", 80, 12}, {"192.168.9.11", 443, 9}, {"192.168.9.12", 22, 6}, {"192.168.9.13", 25, 3}} {
		for j := 0; j < spec.n; j++ {
			packets = append(packets, icmpErr(float64(i*100+j), "10.0.0.254", spec.dst, spec.port, "Destination Unreachable: Host Unreachable"))
		}
	}
	// another router, a different type, must not be mixed in
	packets = append(packets, icmpErr(500, "10.0.0.253", "192.168.9.10", 80, "Destination Unreachable: Host Unreachable"))

	issues := analyzeICMP(packets)
	require.Len(t, issues, 2)
	is := issues[0]
	assert.Equal(t, "ICMP Destination Unreachable", is.Title)
	assert.Equal(t, models.SeverityError, is.Severity)
	assert.Equal(t, 30, is.Count)
	assert.Equal(t, "192.168.9.10:80", is.Target)
	assert.Contains(t, is.Description, "Router 10.0.0.254 sent 30 Destination Unreachable messages to 1 host.")
	assert.Contains(t, is.Description, "Top 3 targets: 192.168.9.10:80 (12), 192.168.9.11:443 (9), 192.168.9.12:22 (6).")
	assert.NotContains(t, is.Description, "192.168.9.13", "only the top three are listed")
	assert.Contains(t, is.Description, "Reasons: Host Unreachable (30).")
	assert.Len(t, is.Occurrences, 30)
	assert.Contains(t, issues[1].Description, "Router 10.0.0.253 sent 1 Destination Unreachable message to 1 host.")
}

func TestICMPAggregationDetails(t *testing.T) {
	t.Run("different message types from one router stay separate", func(t *testing.T) {
		te := icmpPkt(1, "10.0.0.254", "10.0.0.1", 11, 0, "Time Exceeded: TTL Exceeded in Transit")
		du := icmpErr(2, "10.0.0.254", "192.168.9.10", 80, "Destination Unreachable: Port Unreachable")
		issues := analyzeICMP([]models.PacketInfo{te, du})
		require.Len(t, issues, 2)
		assert.Equal(t, "ICMP Time Exceeded", issues[0].Title)
		assert.Equal(t, "ICMP Destination Unreachable", issues[1].Title)
	})
	t.Run("several reasons are listed", func(t *testing.T) {
		a := icmpErr(1, "10.0.0.254", "192.168.9.10", 80, "Destination Unreachable: Host Unreachable")
		b := icmpErr(2, "10.0.0.254", "192.168.9.10", 80, "Destination Unreachable: Port Unreachable")
		c := icmpErr(3, "10.0.0.254", "192.168.9.10", 80, "Destination Unreachable: Port Unreachable")
		issues := analyzeICMP([]models.PacketInfo{a, b, c})
		require.Len(t, issues, 1)
		assert.Contains(t, issues[0].Description, "Reasons: Port Unreachable (2), Host Unreachable (1).")
		assert.Contains(t, issues[0].Description, "Targets: 192.168.9.10:80 (3).")
	})
	t.Run("targets without a port and without quoted data", func(t *testing.T) {
		ping := icmpErr(1, "10.0.0.254", "192.168.9.10", 0, "Destination Unreachable: Host Unreachable")
		ping.ICMPOrigProto = "ICMP"
		bare := icmpPkt(2, "10.0.0.254", "10.0.0.1", 3, 1, "Destination Unreachable: Host Unreachable")
		issues := analyzeICMP([]models.PacketInfo{ping, bare})
		require.Len(t, issues, 1)
		assert.Contains(t, issues[0].Description, "Targets: 192.168.9.10 (1), unknown (1).")
	})
	t.Run("messages from several hosts are counted", func(t *testing.T) {
		a := icmpErr(1, "10.0.0.254", "192.168.9.10", 80, "")
		b := icmpErr(2, "10.0.0.254", "192.168.9.10", 80, "")
		b.DstIP = "10.0.0.2"
		issues := analyzeICMP([]models.PacketInfo{a, b})
		assert.Contains(t, issues[0].Description, "to 2 hosts.")
		assert.Contains(t, issues[0].Description, "Reasons: type 3 code 1 (2).")
	})
	t.Run("redirect", func(t *testing.T) {
		issues := analyzeICMP([]models.PacketInfo{icmpPkt(1, "10.0.0.254", "10.0.0.1", 5, 1, "Redirect: Redirect for Host")})
		assert.Contains(t, issues[0].Description, "Router 10.0.0.254 sent 1 Redirect message to 1 host.")
	})
}
