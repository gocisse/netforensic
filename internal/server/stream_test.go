package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// chunkLine is a line of the chunked answer with its data left raw.
type chunkLine struct {
	Chunk  string          `json:"chunk"`
	Offset int             `json:"offset"`
	Data   json.RawMessage `json:"data"`
}

func readChunks(t *testing.T, body []byte) []chunkLine {
	t.Helper()
	var out []chunkLine
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var l chunkLine
		require.NoError(t, json.Unmarshal(sc.Bytes(), &l), sc.Text())
		out = append(out, l)
	}
	require.NoError(t, sc.Err())
	return out
}

func TestDisplayOrder(t *testing.T) {
	issues := []models.Issue{
		{Title: "b", Severity: models.SeverityWarning, Count: 9},
		{Title: "a", Severity: models.SeverityError},
		{Title: "c", Severity: models.SeverityError, Count: 5},
		{Title: "a", Severity: models.SeverityInfo, Count: 50},
		{Title: "z", Severity: models.SeverityCritical},
		{Title: "b", Severity: models.SeverityError}, // ties with "a": by title
	}
	var titles []string
	for _, i := range displayOrder(issues) {
		titles = append(titles, fmt.Sprintf("%s/%s", issues[i].Severity, issues[i].Title))
	}
	assert.Equal(t, []string{"CRITICAL/z", "ERROR/c", "ERROR/a", "ERROR/b", "WARNING/b", "INFO/a"}, titles)
	assert.Empty(t, displayOrder(nil))
}

// syntheticResult is an analysis with n issues and m flows, half of the flows healthy.
func syntheticResult(n, m int) *models.AnalysisResult {
	res := &models.AnalysisResult{FileName: "x.pcap", TotalPackets: 1000, TotalFlows: m, AnalysisID: "abc", AnalysisTime: time.Unix(1700000000, 0).UTC(), Duration: "1s",
		Diagnosis: models.RootCauseAnalysis{HealthScore: 42, PrimaryCause: "cause", Timeline: make([]models.TimelineEvent, n)}}
	for i := 0; i < n; i++ {
		is := models.Issue{ID: fmt.Sprint("i", i), Title: fmt.Sprintf("t%04d", i), Severity: models.SeverityWarning, Category: "TCP", Count: 1}
		if i%10 == 0 {
			is.Severity = models.SeverityError
		}
		if i == 0 {
			is.Category = "Capture" // a note about the file, not reportable
		}
		res.Issues = append(res.Issues, is)
	}
	for i := 0; i < m; i++ {
		f := models.Flow{ID: fmt.Sprint("f", i)}
		if i%2 == 0 {
			f.IssueCount = 1
		}
		res.Flows = append(res.Flows, f)
	}
	return res
}

func TestStreamAnalysisBatches(t *testing.T) {
	res := syntheticResult(250, 1200)
	rec := httptest.NewRecorder()
	streamAnalysis(rec, res, func() bool { return false })
	assert.Equal(t, "application/x-ndjson", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	lines := readChunks(t, rec.Body.Bytes())
	var order []string
	for _, l := range lines {
		order = append(order, l.Chunk)
	}
	assert.Equal(t, []string{"summary", "overview", "issues", "issues", "issues", "flows", "flows", "flows", "done"}, order, "the verdict first, then the issues, then the flows")

	var sum struct {
		FileName  string `json:"file_name"`
		Diagnosis struct {
			HealthScore int               `json:"health_score"`
			Timeline    []json.RawMessage `json:"timeline"`
		} `json:"diagnosis"`
		AnalysisID string      `json:"analysis_id"`
		Counts     chunkCounts `json:"counts"`
	}
	require.NoError(t, json.Unmarshal(lines[0].Data, &sum))
	assert.Equal(t, "x.pcap", sum.FileName)
	assert.Equal(t, "abc", sum.AnalysisID)
	assert.Equal(t, 42, sum.Diagnosis.HealthScore)
	assert.NotNil(t, sum.Diagnosis.Timeline)
	assert.Empty(t, sum.Diagnosis.Timeline, "the 250-entry timeline stays out of the summary")
	assert.Equal(t, chunkCounts{Issues: 250, ReportableIssues: 249, Flows: 1200, HealthyFlows: 600}, sum.Counts)

	size := func(l chunkLine) int {
		var a []json.RawMessage
		require.NoError(t, json.Unmarshal(l.Data, &a))
		return len(a)
	}
	assert.Equal(t, []int{100, 100, 50}, []int{size(lines[2]), size(lines[3]), size(lines[4])})
	assert.Equal(t, []int{0, 100, 200}, []int{lines[2].Offset, lines[3].Offset, lines[4].Offset})
	assert.Equal(t, []int{500, 500, 200}, []int{size(lines[5]), size(lines[6]), size(lines[7])})
	assert.Equal(t, []int{0, 500, 1000}, []int{lines[5].Offset, lines[6].Offset, lines[7].Offset})

	var first []models.Issue
	require.NoError(t, json.Unmarshal(lines[2].Data, &first))
	assert.Equal(t, models.SeverityError, first[0].Severity, "the worst issues come first")
	var all []models.Issue
	for _, l := range lines[2:5] {
		var b []models.Issue
		require.NoError(t, json.Unmarshal(l.Data, &b))
		all = append(all, b...)
	}
	assert.Len(t, all, 250)
}

func TestStreamAnalysisEmptyListsAndCancel(t *testing.T) {
	rec := httptest.NewRecorder()
	streamAnalysis(rec, syntheticResult(0, 0), func() bool { return false })
	var order []string
	for _, l := range readChunks(t, rec.Body.Bytes()) {
		order = append(order, l.Chunk)
	}
	assert.Equal(t, []string{"summary", "overview", "done"}, order, "no empty batches")

	calls := 0
	rec = httptest.NewRecorder()
	streamAnalysis(rec, syntheticResult(250, 10), func() bool { calls++; return calls > 3 })
	var got []string
	for _, l := range readChunks(t, rec.Body.Bytes()) {
		got = append(got, l.Chunk)
	}
	assert.Equal(t, []string{"summary", "overview", "issues"}, got, "a client that went away gets nothing more")
}

func TestChunkedAnalysisThroughTheAPI(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)

	// the upload answers with the stages and the analysis ID, not with the result
	body, ct := upload(t, "file", "Lab-7.pcapng", readFile(t, lab7))
	req := httptest.NewRequest(http.MethodPost, "/api/analyze?progress=1&chunked=1", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var id string
	var stages []string
	for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
		var ev struct {
			Stage      string `json:"stage"`
			Result     any    `json:"result"`
			AnalysisID string `json:"analysis_id"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &ev))
		assert.Nil(t, ev.Result, "no result in a chunked upload")
		if ev.Stage != "" {
			stages = append(stages, ev.Stage)
		}
		if ev.AnalysisID != "" {
			id = ev.AnalysisID
		}
	}
	assert.Equal(t, []string{"reading", "classifying", "detecting", "reporting"}, stages)
	require.Len(t, id, 32)

	// the chunks hold exactly what the plain answer holds
	chunked := get(h, "/api/analysis/"+id, map[string][]string{"chunked": {"1"}})
	require.Equal(t, http.StatusOK, chunked.Code)
	lines := readChunks(t, chunked.Body.Bytes())
	require.GreaterOrEqual(t, len(lines), 4)
	assert.Equal(t, "summary", lines[0].Chunk)
	assert.Equal(t, "done", lines[len(lines)-1].Chunk)

	var plain analysisAnswer
	require.NoError(t, json.Unmarshal(get(h, "/api/analysis/"+id, nil).Body.Bytes(), &plain))
	var issues []models.Issue
	var flows []models.Flow
	for _, l := range lines {
		switch l.Chunk {
		case "issues":
			var b []models.Issue
			require.NoError(t, json.Unmarshal(l.Data, &b))
			issues = append(issues, b...)
		case "flows":
			var b []models.Flow
			require.NoError(t, json.Unmarshal(l.Data, &b))
			flows = append(flows, b...)
		}
	}
	assert.ElementsMatch(t, plain.Issues, issues)
	assert.Equal(t, plain.Flows, flows)
	var sum summaryChunk
	require.NoError(t, json.Unmarshal(lines[0].Data, &sum))
	assert.Equal(t, plain.Diagnosis.HealthScore, sum.Diagnosis.HealthScore)
	assert.Equal(t, plain.Diagnosis.PrimaryCause, sum.Diagnosis.PrimaryCause)
	assert.Equal(t, id, sum.AnalysisID)
	assert.Len(t, plain.Healthy, sum.Counts.HealthyFlows)

	// an unknown analysis is a 404, chunked or not
	missing := get(h, "/api/analysis/nope", map[string][]string{"chunked": {"1"}})
	assert.Equal(t, http.StatusNotFound, missing.Code)

	// the plain upload still answers with the result
	plainUp := uploadLab(t, h, lab7, "Lab-7.pcapng")
	assert.NotEmpty(t, plainUp.Issues)
}

func TestChunkedUploadOfACaptureWithNothingToAnalyzeEndsWithTheExplanation(t *testing.T) {
	h := authed(t, testAssets, maxUploadBytes)
	body, ct := upload(t, "file", "l2.pcap", pcapBytes(t, lldpFrame()))
	req := httptest.NewRequest(http.MethodPost, "/api/analyze?progress=1&chunked=1", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	var last struct {
		Result struct {
			Message string `json:"message"`
		} `json:"result"`
		AnalysisID string `json:"analysis_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &last))
	assert.Equal(t, "The capture contains no analyzable packets", last.Result.Message)
	assert.Empty(t, last.AnalysisID, "nothing is stored, so there is nothing to fetch")
}
