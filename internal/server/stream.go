package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Batch sizes of the chunked answer: an issue is a few hundred bytes to a few
// kilobytes, a flow a few hundred bytes.
const (
	issuesPerChunk = 100
	flowsPerChunk  = 500
)

// Names of the chunks of a chunked analysis (GET /api/analysis/{id}?chunked=1).
const (
	chunkSummary  = "summary"
	chunkOverview = "overview"
	chunkIssues   = "issues"
	chunkFlows    = "flows"
	chunkDone     = "done"
)

// chunkEvent is one line of the chunked answer.
//
// The chunks come in this order: "summary" (the verdict, ready as soon as the
// analysis is), "overview" (protocol mix, top talkers, slowest flows), then
// "issues" in batches of 100, worst first, and "flows" in batches of 500, and
// at last "done". A batch carries the number of items before it as Offset.
type chunkEvent struct {
	Chunk  string `json:"chunk"`
	Offset int    `json:"offset"`
	Data   any    `json:"data,omitempty"`
}

// chunkCounts says how much is coming, so that a page can show progress and
// the size of its tabs before the data is there.
type chunkCounts struct {
	Issues           int `json:"issues"`
	ReportableIssues int `json:"reportable_issues"` // without the notes about the capture file itself
	Flows            int `json:"flows"`
	HealthyFlows     int `json:"healthy_flows"`
}

// summaryChunk is the first chunk: the analysis without its lists. The
// diagnosis lacks its timeline, which holds an entry for every issue and which
// the page does not show.
type summaryChunk struct {
	FileName          string                   `json:"file_name"`
	TotalPackets      int                      `json:"total_packets"`
	TotalFlows        int                      `json:"total_flows"`
	AnalysisTime      time.Time                `json:"analysis_time"`
	Duration          string                   `json:"duration"`
	Diagnosis         models.RootCauseAnalysis `json:"diagnosis"`
	Metadata          *models.CaptureMetadata  `json:"metadata,omitempty"`
	AnalysisID        string                   `json:"analysis_id"`
	GoodTrafficFilter string                   `json:"good_traffic_filter"`
	Counts            chunkCounts              `json:"counts"`
}

// overviewChunk is the second chunk: what the overview shows before the flows
// are there.
type overviewChunk struct {
	ProtocolStats []models.ProtocolStat `json:"protocol_stats"`
	TopTalkers    []models.Flow         `json:"top_talkers"`
	SlowFlows     []models.Flow         `json:"slow_flows"`
}

var severityOrder = map[models.Severity]int{
	models.SeverityCritical: 3, models.SeverityError: 2, models.SeverityWarning: 1, models.SeverityInfo: 0,
}

// displayOrder returns the indices of issues in the order the page lists
// them: the worst severity first, within a severity the issue with the most
// events first, then by title. Sent in this order, the first batches hold what
// matters most.
func displayOrder(issues []models.Issue) []int {
	idx := make([]int, len(issues))
	for i := range idx {
		idx[i] = i
	}
	count := func(i int) int {
		if c := issues[i].Count; c > 0 {
			return c
		}
		return 1
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := idx[a], idx[b]
		if sx, sy := severityOrder[issues[x].Severity], severityOrder[issues[y].Severity]; sx != sy {
			return sx > sy
		}
		if cx, cy := count(x), count(y); cx != cy {
			return cx > cy
		}
		return issues[x].Title < issues[y].Title
	})
	return idx
}

// streamAnalysis writes res to w as a chunked analysis (see chunkEvent): one
// JSON object per line, flushed as each is written, so the page can show the
// verdict at once and the lists as they arrive. It stops if the client goes
// away (cancelled returns true).
func streamAnalysis(w http.ResponseWriter, res *models.AnalysisResult, cancelled func() bool) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	send := func(ev chunkEvent) bool {
		if cancelled() {
			return false
		}
		if err := enc.Encode(ev); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	reportable := 0
	for _, is := range res.Issues {
		if is.Category != "Capture" {
			reportable++
		}
	}
	diag := res.Diagnosis
	diag.Timeline = []models.TimelineEvent{}
	healthy := 0
	for i := range res.Flows {
		if res.Flows[i].IssueCount == 0 {
			healthy++
		}
	}
	if !send(chunkEvent{Chunk: chunkSummary, Data: summaryChunk{
		FileName: res.FileName, TotalPackets: res.TotalPackets, TotalFlows: res.TotalFlows, AnalysisTime: res.AnalysisTime,
		Duration: res.Duration, Diagnosis: diag, Metadata: res.Metadata, AnalysisID: res.AnalysisID, GoodTrafficFilter: res.GoodTrafficFilter,
		Counts: chunkCounts{Issues: len(res.Issues), ReportableIssues: reportable, Flows: len(res.Flows), HealthyFlows: healthy},
	}}) {
		return
	}
	if !send(chunkEvent{Chunk: chunkOverview, Data: overviewChunk{ProtocolStats: res.ProtocolStats, TopTalkers: res.TopTalkers, SlowFlows: res.SlowFlows}}) {
		return
	}

	order := displayOrder(res.Issues)
	for off := 0; off < len(order); off += issuesPerChunk {
		end := min(off+issuesPerChunk, len(order))
		batch := make([]models.Issue, 0, end-off)
		for _, i := range order[off:end] {
			batch = append(batch, res.Issues[i])
		}
		if !send(chunkEvent{Chunk: chunkIssues, Offset: off, Data: batch}) {
			return
		}
	}
	for off := 0; off < len(res.Flows); off += flowsPerChunk {
		end := min(off+flowsPerChunk, len(res.Flows))
		if !send(chunkEvent{Chunk: chunkFlows, Offset: off, Data: res.Flows[off:end]}) {
			return
		}
	}
	send(chunkEvent{Chunk: chunkDone})
}
