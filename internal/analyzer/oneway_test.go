package analyzer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func connPacket(sec float64, srcIP string, srcPort uint16, dstIP string, dstPort uint16, flags string, seq uint32) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), Protocol: models.ProtocolTCP, TCPFlags: flags, TCPSeq: seq, TCPWindow: 1000, Size: 60,
		SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
}

// twoWayFlows returns n completed handshakes, seen in both directions.
func twoWayFlows(n int) []models.PacketInfo {
	var pk []models.PacketInfo
	for i := 0; i < n; i++ {
		port, ip := uint16(2000+i), fmt.Sprintf("10.1.0.%d", i+1)
		pk = append(pk,
			connPacket(0, ip, port, "10.9.0.1", 443, "SYN", 1),
			connPacket(0.01, "10.9.0.1", 443, ip, port, "SYN,ACK", 100),
			connPacket(0.02, ip, port, "10.9.0.1", 443, "ACK", 2))
	}
	return pk
}

// oneWayFlows returns n connections of which only the client's side was captured.
func oneWayFlows(n int) []models.PacketInfo {
	var pk []models.PacketInfo
	for i := 0; i < n; i++ {
		port, ip := uint16(3000+i), fmt.Sprintf("10.2.0.%d", i+1)
		pk = append(pk,
			connPacket(0, ip, port, "10.9.0.2", 443, "ACK", 5),
			connPacket(0.1, ip, port, "10.9.0.2", 443, "PSH,ACK", 6))
	}
	return pk
}

// unansweredSYNs returns n SYNs to n different servers that never got a reply.
func unansweredSYNs(n int) []models.PacketInfo {
	var pk []models.PacketInfo
	for i := 0; i < n; i++ {
		pk = append(pk, connPacket(1, "10.3.0.1", uint16(4000+i), fmt.Sprintf("10.9.1.%d", i+1), 80, "SYN", 1))
	}
	return pk
}

// floodSYNs returns n SYNs from different clients to one server and port.
func floodSYNs(n int) []models.PacketInfo {
	var pk []models.PacketInfo
	for i := 0; i < n; i++ {
		pk = append(pk, connPacket(1+float64(i)*0.1, fmt.Sprintf("10.4.0.%d", i+1), uint16(5000+i), "10.9.2.1", 80, "SYN", 1))
	}
	return pk
}

// lateEnd extends the capture by 5 seconds with a UDP packet, so unanswered
// SYNs have had time to be answered; it adds no TCP flow.
func lateEnd() models.PacketInfo {
	return models.PacketInfo{Timestamp: at(6), Protocol: models.ProtocolUDP, SrcIP: "10.5.0.1", SrcPort: 53, DstIP: "10.9.3.1", DstPort: 53, Size: 80}
}

func unansweredIssuesOf(pk []models.PacketInfo) map[string]string {
	out := make(map[string]string)
	for _, is := range analyzeConnections(pk) {
		if is.Title == titleUnansweredSYN || is.Title == titleSYNFlood {
			out[is.Title] = is.Description
		}
	}
	return out
}

func TestAsymmetricCaptureEvidence(t *testing.T) {
	concat := func(parts ...[]models.PacketInfo) []models.PacketInfo {
		var all []models.PacketInfo
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}
	tests := []struct {
		name        string
		packets     []models.PacketInfo
		wantTitles  []string
		wantPercent string // "" if no note is expected
	}{
		{
			name:        "mostly one-sided: 20 of 25 flows",
			packets:     concat(oneWayFlows(20), twoWayFlows(5), unansweredSYNs(3)),
			wantTitles:  []string{titleUnansweredSYN},
			wantPercent: "80%",
		},
		{
			name:       "fully bidirectional capture",
			packets:    concat(twoWayFlows(25), unansweredSYNs(3)),
			wantTitles: []string{titleUnansweredSYN},
		},
		{
			name:       "a few one-way flows stay under the threshold",
			packets:    concat(oneWayFlows(5), twoWayFlows(20), unansweredSYNs(3)),
			wantTitles: []string{titleUnansweredSYN},
		},
		{
			name:       "exactly at the threshold is not above it: 10 of 25",
			packets:    concat(oneWayFlows(10), twoWayFlows(15), unansweredSYNs(3)),
			wantTitles: []string{titleUnansweredSYN},
		},
		{
			name:        "just above the threshold: 11 of 26",
			packets:     concat(oneWayFlows(11), twoWayFlows(15), unansweredSYNs(3)),
			wantTitles:  []string{titleUnansweredSYN},
			wantPercent: "42%",
		},
		{
			name:       "one flow short of the minimum: 9 of 9",
			packets:    concat(oneWayFlows(9), unansweredSYNs(3)),
			wantTitles: []string{titleUnansweredSYN},
		},
		{
			name:        "exactly the minimum: 10 of 10",
			packets:     concat(oneWayFlows(10), unansweredSYNs(3)),
			wantTitles:  []string{titleUnansweredSYN},
			wantPercent: "100%",
		},
		{
			name:       "too few other flows to say anything: 3 of 3",
			packets:    concat(oneWayFlows(3), unansweredSYNs(3)),
			wantTitles: []string{titleUnansweredSYN},
		},
		{
			name:        "a SYN flood is annotated too",
			packets:     concat(oneWayFlows(20), twoWayFlows(5), floodSYNs(12)),
			wantTitles:  []string{titleSYNFlood},
			wantPercent: "80%",
		},
		{
			name:        "flood and other unanswered SYNs both get it",
			packets:     concat(oneWayFlows(20), twoWayFlows(5), floodSYNs(12), unansweredSYNs(2)),
			wantTitles:  []string{titleSYNFlood, titleUnansweredSYN},
			wantPercent: "80%",
		},
		{
			name:       "the unanswered SYNs themselves do not make a capture look one-sided",
			packets:    concat(twoWayFlows(15), floodSYNs(12), unansweredSYNs(5)),
			wantTitles: []string{titleSYNFlood, titleUnansweredSYN},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := append([]models.PacketInfo{}, tt.packets...)
			pk = append(pk, lateEnd())
			got := unansweredIssuesOf(pk)

			titles := make([]string, 0, len(got))
			for title := range got {
				titles = append(titles, title)
			}
			require.ElementsMatch(t, tt.wantTitles, titles)

			for title, desc := range got {
				if tt.wantPercent == "" {
					assert.NotContains(t, desc, "Note:", title)
					continue
				}
				want := fmt.Sprintf(". Note: %s of the other TCP flows in this capture are seen in one direction only, so missing replies may simply have taken another path.", tt.wantPercent)
				assert.True(t, strings.HasSuffix(desc, want), "%s: %q", title, desc)
			}
		})
	}
}

func TestAsymmetricNoteOnlyOnSYNIssues(t *testing.T) {
	// A one-sided capture with other connection problems: only the
	// unanswered-SYN issues carry the note.
	pk := append(oneWayFlows(20), twoWayFlows(5)...)
	pk = append(pk, unansweredSYNs(3)...)
	pk = append(pk, lateEnd(),
		connPacket(2, "10.6.0.1", 7000, "10.9.4.1", 80, "RST,ACK", 9)) // a stray RST
	for _, is := range analyzeConnections(pk) {
		if is.Title != titleUnansweredSYN {
			assert.NotContains(t, is.Description, "Note:", is.Title)
		}
	}
}
