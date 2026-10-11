package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestPrintTriageReport(t *testing.T) {
	ts := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	res := &models.AnalysisResult{
		SlowFlows: []models.Flow{{ID: "10.0.0.1:1000-10.0.0.2:80", SetupTimeMs: 612.5, TTFBMs: 1450, AvgRTTMs: 210.25}},
		Diagnosis: models.RootCauseAnalysis{
			HealthScore:  62,
			PrimaryCause: "DNS resolution failure for x.com",
			Confidence:   "high",
			Summary:      "SERVFAIL then 5xx.",
			Timeline: []models.TimelineEvent{
				{Timestamp: ts, EventType: "root_cause", Severity: models.SeverityError, Description: "DNS SERVFAIL: bad"},
				{Timestamp: ts.Add(time.Second), EventType: "symptom", Severity: models.SeverityError, Description: "HTTP Server Error: 503"},
			},
			Recommendations: []string{"Check the resolver.", "Re-test HTTP."},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, printTriageReport(&buf, res))
	out := buf.String()

	for _, want := range []string{
		"TRIAGE REPORT", "Health Score: 62/100 (UNHEALTHY)",
		"ROOT CAUSE", "DNS resolution failure for x.com (confidence: high)", "SERVFAIL then 5xx.",
		"TIMELINE (UTC)", "22:13:20.000  [ERROR]", "root_cause", "symptom", "HTTP Server Error: 503",
		"TOP SLOW FLOWS", "FLOW", "SETUP", "TTFB", "AVG RTT", "MAX RTT", "10.0.0.1:1000-10.0.0.2:80", "612.5ms", "1450.0ms", "210.2ms",
		"RECOMMENDATIONS", "1. Check the resolver.", "2. Re-test HTTP.",
	} {
		assert.Contains(t, out, want)
	}
	// unmeasured metric shows a dash
	assert.Regexp(t, `210\.\dms\s+-\n`, out)

	// sections appear in the required order
	last := -1
	for _, section := range []string{"TRIAGE REPORT", "ROOT CAUSE", "TIMELINE", "TOP SLOW FLOWS", "RECOMMENDATIONS"} {
		i := strings.Index(out, section)
		assert.Greater(t, i, last, section)
		last = i
	}
}

func TestPrintTriageReportEmptyAndTruncated(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printTriageReport(&buf, &models.AnalysisResult{}))
	assert.Contains(t, buf.String(), "no events")
	assert.Contains(t, buf.String(), "no flows with measurable timing metrics")

	var events []models.TimelineEvent
	for i := 0; i < maxTimelineEvents+4; i++ {
		events = append(events, models.TimelineEvent{Timestamp: time.Unix(int64(i), 0), EventType: "issue", Severity: models.SeverityInfo, Description: fmt.Sprintf("event-%d", i)})
	}
	buf.Reset()
	require.NoError(t, printTriageReport(&buf, &models.AnalysisResult{Diagnosis: models.RootCauseAnalysis{Timeline: events}}))
	assert.Contains(t, buf.String(), "event-14")
	assert.NotContains(t, buf.String(), "event-15")
	assert.Contains(t, buf.String(), "4 more event(s)")
}

func TestHealthLabel(t *testing.T) {
	tests := map[int]string{100: "HEALTHY", 90: "HEALTHY", 89: "DEGRADED", 70: "DEGRADED", 69: "UNHEALTHY", 40: "UNHEALTHY", 39: "CRITICAL", 0: "CRITICAL", -1: "CATASTROPHIC", -50: "CATASTROPHIC"}
	for score, want := range tests {
		assert.Equal(t, want, healthLabel(score), score)
	}
}

func TestFmtMs(t *testing.T) {
	assert.Equal(t, "-", fmtMs(0))
	assert.Equal(t, "-", fmtMs(-1))
	assert.Equal(t, "12.5ms", fmtMs(12.5))
}

func TestRootCmdTriageOnlyInTextMode(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"

	var text bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&text)
	cmd.SetArgs([]string{"-v", sample})
	require.NoError(t, cmd.Execute())
	out := text.String()
	assert.Contains(t, out, "TRIAGE REPORT")
	assert.Contains(t, out, "Health Score: 100/100")
	assert.Less(t, strings.Index(out, "TRIAGE REPORT"), strings.Index(out, "SOURCE"), "triage precedes the packet table")
	assert.Less(t, strings.Index(out, "SOURCE"), strings.Index(out, "Analyzed 2 packets"), "packet table precedes the summary")

	var js bytes.Buffer
	cmd = newRootCmd()
	cmd.SetOut(&js)
	cmd.SetArgs([]string{"-o", "json", sample})
	require.NoError(t, cmd.Execute())
	assert.NotContains(t, js.String(), "TRIAGE REPORT")
	assert.Contains(t, js.String(), `"diagnosis"`)
	assert.Contains(t, js.String(), `"health_score": 100`)
}

func TestPrintTriageReportNegativeHealth(t *testing.T) {
	for score, want := range map[int]string{-1: "Health Score: -1/100 (CATASTROPHIC)", -50: "Health Score: -50/100 (CATASTROPHIC)", 0: "Health Score: 0/100 (CRITICAL)"} {
		var buf bytes.Buffer
		res := &models.AnalysisResult{Diagnosis: models.RootCauseAnalysis{HealthScore: score, PrimaryCause: "x", Confidence: "low"}}
		require.NoError(t, printTriageReport(&buf, res))
		assert.Contains(t, buf.String(), want)
	}
}
