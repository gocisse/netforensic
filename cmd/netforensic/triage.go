package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	maxTimelineEvents = 15
	reportWidth       = 72
)

// printTriageReport prints the diagnosis, timeline, slowest flows and
// recommendations of res.
func printTriageReport(w io.Writer, res *models.AnalysisResult) error {
	d := res.Diagnosis
	rule := strings.Repeat("=", reportWidth)

	fmt.Fprintln(w, rule)
	fmt.Fprintf(w, " TRIAGE REPORT  |  Health Score: %d/100 (%s)\n", d.HealthScore, healthLabel(d.HealthScore))
	fmt.Fprintln(w, rule)

	fmt.Fprintln(w, "\nROOT CAUSE")
	fmt.Fprintf(w, "  %s (confidence: %s)\n", d.PrimaryCause, d.Confidence)
	if d.Summary != "" {
		fmt.Fprintf(w, "  %s\n", d.Summary)
	}

	fmt.Fprintln(w, "\nTIMELINE (UTC)")
	if len(d.Timeline) == 0 {
		fmt.Fprintln(w, "  no events")
	}
	for i, e := range d.Timeline {
		if i == maxTimelineEvents {
			fmt.Fprintf(w, "  ... %d more event(s); see the issue list below\n", len(d.Timeline)-maxTimelineEvents)
			break
		}
		fmt.Fprintf(w, "  %s  %-10s %-13s %s\n", e.Timestamp.UTC().Format("15:04:05.000"), "["+string(e.Severity)+"]", e.EventType, e.Description)
	}

	fmt.Fprintln(w, "\nTOP SLOW FLOWS")
	if len(res.SlowFlows) == 0 {
		fmt.Fprintln(w, "  no flows with measurable timing metrics")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  FLOW\tSETUP\tTTFB\tAVG RTT\tMAX RTT")
		for _, f := range res.SlowFlows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", f.ID, fmtMs(f.SetupTimeMs), fmtMs(f.TTFBMs), fmtMs(f.AvgRTTMs), fmtMs(f.MaxRTTMs))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintln(w, "\nRECOMMENDATIONS")
	for i, r := range d.Recommendations {
		fmt.Fprintf(w, "  %d. %s\n", i+1, r)
	}
	fmt.Fprintln(w)
	return nil
}

// healthLabel names a health score band.
func healthLabel(score int) string {
	switch {
	case score >= 90:
		return "HEALTHY"
	case score >= 70:
		return "DEGRADED"
	case score >= 40:
		return "UNHEALTHY"
	case score >= 0:
		return "CRITICAL"
	}
	return "CATASTROPHIC"
}

// fmtMs formats a millisecond metric, using "-" when it was not measured.
func fmtMs(v float64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fms", v)
}
