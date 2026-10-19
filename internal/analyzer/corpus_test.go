package analyzer

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// corpusEnv names the environment variable that points the smoke test at a
// directory of captures that are not part of the repository. See
// docs/external-corpus.md.
const corpusEnv = "NETFORENSIC_CORPUS"

// TestExternalCorpusSmoke reads and analyzes every .pcap and .pcapng file
// under $NETFORENSIC_CORPUS and checks that the pipeline completes with a
// well-formed result. It does not check what the analysis found: a capture
// that opens and analyzes cleanly says nothing about whether the diagnosis is
// right. The test is skipped when the variable is unset or the directory is
// missing, so it never runs in CI or on a machine without the corpus.
func TestExternalCorpusSmoke(t *testing.T) {
	dir := os.Getenv(corpusEnv)
	if dir == "" {
		t.Skipf("%s is not set; see docs/external-corpus.md", corpusEnv)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Skipf("%s=%q is not an existing directory", corpusEnv, dir)
	}

	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".pcap", ".pcapng":
				files = append(files, path)
			}
		}
		return nil
	})
	require.NoError(t, err, "walk %s", dir)
	require.NotEmpty(t, files, "no .pcap or .pcapng files under %s", dir)
	sort.Strings(files)

	for _, path := range files {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		t.Run(rel, func(t *testing.T) { smokeCapture(t, path, rel) })
	}
}

// smokeCapture reads one capture the way the CLI does and checks the
// invariants of the result.
func smokeCapture(t *testing.T, path, rel string) {
	t.Helper()
	packets, stats, err := pcap.ReadPacketsStats(path, pcap.ReadOptions{SkipPreview: true})
	var truncated *pcap.TruncatedError
	switch {
	case errors.As(err, &truncated):
		// A file cut off mid-record is analyzed up to the cut; the CLI warns.
		require.Equal(t, len(packets), truncated.Packets, "%s: truncated after %d packets but %d were returned", rel, truncated.Packets, len(packets))
	case err != nil:
		t.Fatalf("%s: read failed: %v", rel, err)
	}
	require.GreaterOrEqual(t, stats.Frames, 0, "%s: frame count", rel)
	require.GreaterOrEqual(t, stats.Skipped(), 0, "%s: skipped frame count", rel)
	require.LessOrEqual(t, len(packets), stats.Frames, "%s: more packets than frames", rel)

	if len(packets) == 0 {
		// Like the CLI, do not analyze a capture that holds nothing to analyze.
		t.Logf("%s: frames=%d packets=0 (nothing to analyze)", rel, stats.Frames)
		return
	}

	res := AnalyzeWithIssues(packets, "all")
	require.NotNil(t, res, "%s: nil result", rel)
	require.Equal(t, len(packets), res.TotalPackets, "%s: total packets", rel)
	require.GreaterOrEqual(t, res.TotalFlows, 0, "%s: total flows", rel)
	require.GreaterOrEqual(t, res.Diagnosis.HealthScore, -50, "%s: health score below the documented floor", rel)
	require.LessOrEqual(t, res.Diagnosis.HealthScore, 100, "%s: health score above 100", rel)
	require.Contains(t, []string{"high", "medium", "low"}, res.Diagnosis.Confidence, "%s: confidence", rel)
	require.NotEmpty(t, res.Diagnosis.PrimaryCause, "%s: empty primary cause", rel)
	for _, is := range res.Issues {
		require.Contains(t, []models.Severity{models.SeverityInfo, models.SeverityWarning, models.SeverityError, models.SeverityCritical}, is.Severity, "%s: issue %q severity", rel, is.Title)
		require.NotEmpty(t, is.Title, "%s: issue without a title", rel)
		require.GreaterOrEqual(t, is.Count, 0, "%s: issue %q count", rel, is.Title)
	}
	_, err = json.Marshal(res)
	require.NoError(t, err, "%s: result does not serialize", rel)

	t.Logf("%s: frames=%d packets=%d flows=%d issues=%d truncated=%t", rel, stats.Frames, res.TotalPackets, res.TotalFlows, len(res.Issues), truncated != nil)
}
