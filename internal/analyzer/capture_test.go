package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestTruncatedCaptureIssue(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		wantMsg string
	}{
		{"several packets", []models.PacketInfo{{Timestamp: at(2)}, {Timestamp: at(9)}, {Timestamp: at(5)}},
			"The capture file ended unexpectedly. Analyzed 3 packets before truncation."},
		{"no packets", nil, "The capture file ended unexpectedly. Analyzed 0 packets before truncation."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := TruncatedCaptureIssue(tt.packets)
			assert.Equal(t, models.SeverityWarning, is.Severity)
			assert.Equal(t, "Capture", is.Category)
			assert.Equal(t, "Truncated Capture", is.Title)
			assert.Equal(t, tt.wantMsg, is.Description)
			assert.NotEmpty(t, is.ID)
		})
	}
	assert.Equal(t, at(9), TruncatedCaptureIssue([]models.PacketInfo{{Timestamp: at(2)}, {Timestamp: at(9)}, {Timestamp: at(5)}}).Timestamp,
		"anchored at the latest packet")
}

func TestAnalyzeWithIssues(t *testing.T) {
	packets := []models.PacketInfo{{Timestamp: at(0), Protocol: models.ProtocolTCP, TCPWindow: 1}, {Timestamp: at(3), Protocol: models.ProtocolTCP, TCPWindow: 1}}

	plain := Analyze(packets, "all")
	assert.Empty(t, plain.Issues)

	res := AnalyzeWithIssues(packets, "all", TruncatedCaptureIssue(packets))
	require.Len(t, res.Issues, 1)
	assert.Equal(t, "Truncated Capture", res.Issues[0].Title)
	assert.Equal(t, 90, res.Diagnosis.HealthScore, "the warning costs 10 points")
	assert.Equal(t, "Truncated Capture", res.Diagnosis.PrimaryCause)
	assert.GreaterOrEqual(t, len(res.Diagnosis.Recommendations), 2)
	assert.Len(t, res.Diagnosis.Timeline, 3, "capture start, the warning, capture end")
	assert.Equal(t, 2, res.TotalPackets, "extra issues do not change packet counts")
}

func TestSkippedFramesIssue(t *testing.T) {
	packets := []models.PacketInfo{{Timestamp: at(5)}, {Timestamp: at(2)}, {Timestamp: at(9)}}
	is := SkippedFramesIssue(13664, "10667 frames of unsupported link type 18; 2997 non-IP frames", packets)
	assert.Equal(t, "Skipped Frames", is.Title)
	assert.Equal(t, models.SeverityInfo, is.Severity, "layer-2 background traffic is normal")
	assert.Equal(t, "Capture", is.Category)
	assert.Equal(t, 13664, is.Count)
	assert.Equal(t, at(2), is.Timestamp, "anchored at the start of the capture")
	assert.Equal(t, "13664 frames were skipped due to unsupported link-layer types or non-IP traffic. Analysis is based on the remaining 3 packets. "+
		"(10667 frames of unsupported link type 18; 2997 non-IP frames)", is.Description)

	one := SkippedFramesIssue(1, "", nil)
	assert.Equal(t, "1 frame was skipped due to unsupported link-layer types or non-IP traffic. Analysis is based on the remaining 0 packets.", one.Description)
	assert.True(t, one.Timestamp.IsZero())

	res := AnalyzeWithIssues(packets, "all", is)
	assert.Equal(t, 100, res.Diagnosis.HealthScore, "costs no health points")
	assert.Equal(t, "No significant issues detected", res.Diagnosis.PrimaryCause, "and explains nothing about the traffic")
	var inTimeline bool
	for _, e := range res.Diagnosis.Timeline {
		if strings.Contains(e.Description, "Skipped Frames: 13664 frames were skipped") {
			inTimeline = true
			assert.Equal(t, models.SeverityInfo, e.Severity)
			assert.Equal(t, "issue", e.EventType)
		}
	}
	assert.True(t, inTimeline, "the engineer still sees it in the timeline")
	assert.Len(t, res.Issues, 1, "and in the issue list")

	// it never hides a real problem or lowers its score
	real := models.Issue{ID: "x", Severity: models.SeverityError, Category: "DNS", Title: "DNS SERVFAIL", Timestamp: at(3)}
	res = AnalyzeWithIssues(packets, "all", is, real)
	assert.Equal(t, 80, res.Diagnosis.HealthScore)
	assert.Equal(t, "DNS SERVFAIL", res.Diagnosis.PrimaryCause)
}

func TestIsNote(t *testing.T) {
	assert.True(t, isNote(models.Issue{Category: "Capture", Severity: models.SeverityInfo}))
	assert.False(t, isNote(models.Issue{Category: "Capture", Severity: models.SeverityWarning}), "a truncated capture is a warning, not a note")
	assert.False(t, isNote(models.Issue{Category: "DNS", Severity: models.SeverityInfo}))
	assert.Equal(t, 98, healthScore([]models.Issue{{Category: "DNS", Severity: models.SeverityInfo}}), "other infos still cost 2")
	assert.Equal(t, 100, healthScore([]models.Issue{{Category: "Capture", Severity: models.SeverityInfo}}))
}

func TestFormatDuration(t *testing.T) {
	assert.Equal(t, "0s", formatDuration(0))
	assert.Equal(t, "587.22ms", formatDuration(587220*time.Microsecond))
	assert.Equal(t, "5m24.673387s", formatDuration(5*time.Minute+24*time.Second+673387*time.Microsecond))
	assert.Equal(t, "24h0m0s", formatDuration(24*time.Hour), "exactly a day is still exact")
	assert.Equal(t, "24h+", formatDuration(24*time.Hour+time.Nanosecond))
	assert.Equal(t, "24h+", formatDuration(118508*time.Hour))
}

func TestAnalyzeCapsAbsurdDurations(t *testing.T) {
	// two interfaces whose clocks are years apart end up in one capture
	pkts := []models.PacketInfo{
		{Timestamp: time.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC), Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2},
		{Timestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2},
		{Timestamp: time.Date(2014, 3, 1, 0, 0, 0, 0, time.UTC), Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2}, // out of order
	}
	res := Analyze(pkts, "all")
	assert.Equal(t, "24h+", res.Duration)
	for _, e := range res.Diagnosis.Timeline {
		assert.NotContains(t, e.Description, "h0m", "no multi-year duration in the timeline")
	}
	var ends string
	for _, e := range res.Diagnosis.Timeline {
		if e.EventType == "capture_end" {
			ends = e.Description
		}
	}
	assert.Equal(t, "Capture ends (24h+ later)", ends)

	// a normal capture is unchanged, whatever the packet order
	ok := Analyze([]models.PacketInfo{pkts[0], {Timestamp: pkts[0].Timestamp.Add(90 * time.Minute), Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2}, {Timestamp: pkts[0].Timestamp.Add(time.Minute), Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2}}, "all")
	assert.Equal(t, "1h30m0s", ok.Duration)
}
