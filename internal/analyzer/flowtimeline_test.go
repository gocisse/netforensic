package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

const tlFlowID = "10.0.0.1:5000-10.0.0.2:443"

// withSeq and withWindow adjust a packet built by tcpEv.
func withSeq(p models.PacketInfo, seq uint32) models.PacketInfo { p.TCPSeq = seq; return p }
func withWindow(p models.PacketInfo, w uint32) models.PacketInfo {
	p.TCPWindow = w
	return p
}

// handshake is a complete three-way handshake ending at 12 ms, then a request.
func handshake() []models.PacketInfo {
	return []models.PacketInfo{
		tcpEv(0, 5000, true, "SYN", 0),
		tcpEv(10, 5000, false, "SYN,ACK", 0),
		tcpEv(12, 5000, true, "ACK", 0),
		withSeq(tcpEv(20, 5000, true, "PSH,ACK", 300), 1000),
	}
}

func timelineOf(t *testing.T, res *models.AnalysisResult, id string) []models.FlowEvent {
	t.Helper()
	for _, f := range res.Flows {
		if f.ID == id {
			return f.Timeline
		}
	}
	t.Fatalf("flow %s not found", id)
	return nil
}

func names(tl []models.FlowEvent) []string {
	out := make([]string, len(tl))
	for i, e := range tl {
		out[i] = e.Event
	}
	return out
}

func firstIssues(tl []models.FlowEvent) []string {
	var out []string
	for _, e := range tl {
		if e.FirstIssue {
			out = append(out, e.Event)
		}
	}
	return out
}

func TestFlowTimeline(t *testing.T) {
	tests := []struct {
		name       string
		packets    []models.PacketInfo
		want       []string // event names, in order
		first      string   // the event marked as the first issue
		firstSev   models.Severity
		wantDescIn map[string]string // event name -> text its description holds
	}{
		{
			name: "zero window, never reopened, then reset",
			packets: append(handshake(),
				withWindow(tcpEv(50, 5000, false, "ACK", 0), 0),
				withWindow(tcpEv(80, 5000, false, "ACK", 0), 0),
				tcpEv(400, 5000, false, "RST,ACK", 0),
			),
			want:       []string{evStart, evHandshake, evFirstData, evZeroWindow, evReset},
			first:      evZeroWindow,
			firstSev:   models.SeverityWarning,
			wantDescIn: map[string]string{evZeroWindow: "never reopened", evReset: "zero-window stall had lasted 350ms and was still open"},
		},
		{
			name: "zero window that reopens before the reset",
			packets: append(handshake(),
				withWindow(tcpEv(50, 5000, false, "ACK", 0), 0),
				tcpEv(300, 5000, false, "ACK", 0),
				tcpEv(310, 5000, false, "RST,ACK", 0),
			),
			want:       []string{evStart, evHandshake, evFirstData, evZeroWindow, evWindowOpen, evReset},
			first:      evZeroWindow,
			firstSev:   models.SeverityWarning,
			wantDescIn: map[string]string{evWindowOpen: "250ms after closing it"},
		},
		{
			name: "timeout retransmit after silence",
			packets: append(handshake(),
				withSeq(tcpEv(1500, 5000, true, "PSH,ACK", 300), 1000),
				tcpEv(1600, 5000, false, "ACK", 0),
			),
			want:       []string{evStart, evHandshake, evFirstData, titleTimeoutRetransmit},
			first:      titleTimeoutRetransmit,
			firstSev:   models.SeverityError,
			wantDescIn: map[string]string{titleTimeoutRetransmit: "waited for the retransmission timeout, then resent seq 1000"},
		},
		{
			name: "reset ends an established connection",
			packets: append(handshake(),
				tcpEv(30, 5000, false, "ACK", 1000),
				tcpEv(40, 5000, false, "RST,ACK", 0),
			),
			want:     []string{evStart, evHandshake, evFirstData, evReset},
			first:    evReset,
			firstSev: models.SeverityError,
		},
		{
			name: "unanswered SYN is retried",
			packets: []models.PacketInfo{
				withSeq(tcpEv(0, 5000, true, "SYN", 0), 77),
				withSeq(tcpEv(1000, 5000, true, "SYN", 0), 77),
				withSeq(tcpEv(3000, 5000, true, "SYN", 0), 77),
			},
			want:       []string{evStart, evSynRetry, evSynRetry},
			first:      evSynRetry,
			firstSev:   models.SeverityWarning,
			wantDescIn: map[string]string{evSynRetry: "attempt 2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tl := timelineOf(t, Analyze(tt.packets, "all"), tlFlowID)
			require.Equal(t, tt.want, names(tl))
			assert.Equal(t, []string{tt.first}, firstIssues(tl), "exactly one first issue")
			for _, e := range tl {
				if e.FirstIssue {
					assert.Equal(t, tt.firstSev, e.Severity)
				}
			}
			for name, text := range tt.wantDescIn {
				found := false
				for _, e := range tl {
					if e.Event == name && strings.Contains(e.Description, text) {
						found = true
					}
				}
				assert.True(t, found, "%s should mention %q", name, text)
			}
			for i := 1; i < len(tl); i++ {
				assert.False(t, tl[i].Timestamp.Before(tl[i-1].Timestamp), "events are in time order")
			}
		})
	}
}

func TestFlowTimelineOnlyForTCPFlowsWithIssues(t *testing.T) {
	healthy := []models.PacketInfo{
		tcpEv(0, 6000, true, "SYN", 0),
		tcpEv(10, 6000, false, "SYN,ACK", 0),
		tcpEv(12, 6000, true, "ACK", 0),
		tcpEv(20, 6000, true, "PSH,ACK", 100),
		tcpEv(30, 6000, false, "ACK", 0),
	}
	udp := models.PacketInfo{Timestamp: rstT0, Protocol: models.ProtocolUDP, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 5353, DstPort: 5353, Size: 80}
	pk := append(append([]models.PacketInfo{}, handshake()...), tcpEv(40, 5000, false, "RST,ACK", 0))
	pk = append(append(pk, healthy...), udp)
	res := Analyze(pk, "all")

	var withTimeline int
	for _, f := range res.Flows {
		if len(f.Timeline) > 0 {
			withTimeline++
			assert.Equal(t, tlFlowID, f.ID)
		}
	}
	assert.Equal(t, 1, withTimeline, "only the broken TCP flow gets a timeline")
	for _, f := range append(res.TopTalkers, res.SlowFlows...) {
		assert.Empty(t, f.Timeline, "summary lists do not carry timelines")
	}
}

func TestFlowTimelineTrimsRetransmissions(t *testing.T) {
	pk := handshake()
	// Twenty resends of the same segment, each after a pause.
	for i := 0; i < 20; i++ {
		pk = append(pk, withSeq(tcpEv(1000+i*500, 5000, true, "PSH,ACK", 300), 1000))
	}
	tl := timelineOf(t, Analyze(pk, "all"), tlFlowID)

	retrans, more := 0, 0
	for _, e := range tl {
		switch e.Event {
		case titleTimeoutRetransmit, "Retransmission", "Retransmit (recovery)":
			retrans++
		case evMore:
			more++
			assert.Contains(t, e.Description, "10 more retransmissions")
		}
	}
	assert.Equal(t, maxTimelineRetransmits, retrans)
	assert.Equal(t, 1, more)
	assert.Equal(t, evMore, tl[len(tl)-1].Event, "the summary closes the timeline")
}

func TestFlowTimelineFallsBackToIssues(t *testing.T) {
	flows := []models.Flow{{ID: tlFlowID, Protocol: models.ProtocolTCP, IssueCount: 1}}
	issues := []models.Issue{{Title: "Slow Response", Severity: models.SeverityWarning, FlowID: tlFlowID,
		Timestamp: rstT0.Add(time.Second), Occurrences: []models.Occurrence{{Subject: tlFlowID, Time: rstT0.Add(2 * time.Second)}}}}
	annotateTimelines([]models.PacketInfo{tcpEv(0, 5000, true, "SYN", 0)}, flows, issues)

	tl := flows[0].Timeline
	require.Equal(t, []string{evStart, "Slow Response"}, names(tl))
	assert.Equal(t, rstT0.Add(2*time.Second), tl[1].Timestamp, "the flow's own occurrence time is used")
	assert.Equal(t, []string{"Slow Response"}, firstIssues(tl))
}
