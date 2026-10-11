package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	require.NoError(t, err, "valid CSV: %s", path)
	return rows
}

func TestExportCSVContentAndEscaping(t *testing.T) {
	ts := time.Date(2024, 3, 1, 12, 30, 0, 500_000_000, time.UTC)
	res := &models.AnalysisResult{
		Flows: []models.Flow{
			{ID: "10.0.0.1:1000-10.0.0.2:80", Protocol: models.ProtocolTCP, PacketCount: 10, BytesSent: 100, BytesRecv: 200, SetupTimeMs: 12.5, TTFBMs: 30, AvgRTTMs: 5.123, MaxRTTMs: 40},
			{ID: "10.0.0.3:2000-10.0.0.4:53", Protocol: models.ProtocolUDP, PacketCount: 2, BytesSent: 5000, BytesRecv: 5000},
			{ID: "[2001:db8::1]:5-[2001:db8::2]:6", Protocol: "OSPF", PacketCount: 1, BytesSent: 10},
		},
		Issues: []models.Issue{
			{
				ID: "a", Severity: models.SeverityError, Category: "Connection", Title: "Title, with comma",
				Description: "He said \"hi\",\nthen left. Größe → 5 µs; 日本語", FlowID: "10.0.0.1:1000-10.0.0.2:80",
				Target: "10.0.0.2:80", Count: 3, Timestamp: ts,
			},
			{
				ID: "b", Severity: models.SeverityWarning, Category: "DNS", Title: "DNS NXDOMAIN", Description: "=HYPERLINK(\"http://evil\")",
				Occurrences: []models.Occurrence{{Subject: "10.0.0.3:2000-10.0.0.4:53"}, {Subject: "10.0.0.3:2000-10.0.0.4:53"}},
			},
			{ID: "c", Severity: models.SeverityInfo, Category: "Capture", Title: "Skipped Frames", Description: "+1 frame", FlowID: "10.0.0.1:1000-10.0.0.2:80"},
		},
		ProtocolStats: []models.ProtocolStat{
			{Protocol: "TCP", Layer: "transport", Packets: 10, Flows: 1, Percent: 76.9},
			{Protocol: "TLS", Layer: "application", Packets: 3, Flows: 1, Percent: 23.1},
		},
	}
	prefix := filepath.Join(t.TempDir(), "out")
	written, err := exportCSV(prefix, res)
	require.NoError(t, err)
	assert.Equal(t, []string{prefix + "_flows.csv", prefix + "_issues.csv", prefix + "_protocols.csv"}, written)

	t.Run("flows", func(t *testing.T) {
		rows := readCSV(t, prefix+"_flows.csv")
		assert.Equal(t, []string{"flow_id", "packets", "bytes", "setup_time_ms", "ttfb_ms", "avg_rtt_ms", "max_rtt_ms", "protocol", "issues"}, rows[0])
		require.Len(t, rows, 4, "a header and every flow")
		// the busiest flow first
		assert.Equal(t, []string{"10.0.0.3:2000-10.0.0.4:53", "2", "10000", "", "", "", "", "UDP", "1"}, rows[1])
		assert.Equal(t, []string{"10.0.0.1:1000-10.0.0.2:80", "10", "300", "12.50", "30.00", "5.12", "40.00", "TCP", "2"}, rows[2])
		assert.Equal(t, []string{"[2001:db8::1]:5-[2001:db8::2]:6", "1", "10", "", "", "", "", "OSPF", "0"}, rows[3])
	})

	t.Run("issues", func(t *testing.T) {
		rows := readCSV(t, prefix+"_issues.csv")
		assert.Equal(t, []string{"id", "severity", "category", "title", "description", "flow_id", "target", "count", "timestamp"}, rows[0])
		require.Len(t, rows, 4)
		assert.Equal(t, []string{"a", "ERROR", "Connection", "Title, with comma",
			"He said \"hi\",\nthen left. Größe → 5 µs; 日本語", "10.0.0.1:1000-10.0.0.2:80", "10.0.0.2:80", "3", "2024-03-01T12:30:00.5Z"}, rows[1],
			"commas, quotes, newlines and non-ASCII text survive a round trip")
		assert.Equal(t, "'=HYPERLINK(\"http://evil\")", rows[2][4], "a formula is neutralized")
		assert.Equal(t, "'+1 frame", rows[3][4])
		assert.Equal(t, "", rows[2][8], "no timestamp, no value")
	})

	t.Run("protocols", func(t *testing.T) {
		rows := readCSV(t, prefix+"_protocols.csv")
		assert.Equal(t, [][]string{
			{"protocol", "layer", "packets", "flows", "percent"},
			{"TCP", "transport", "10", "1", "76.9"},
			{"TLS", "application", "3", "1", "23.1"},
		}, rows)
	})
}

func TestExportCSVEmptyResultStillWritesHeaders(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "empty")
	_, err := exportCSV(prefix, &models.AnalysisResult{})
	require.NoError(t, err)
	for _, suffix := range csvSuffixes {
		rows := readCSV(t, prefix+suffix)
		assert.Len(t, rows, 1, suffix)
	}
}

func TestExportCSVBadDirectory(t *testing.T) {
	_, err := exportCSV(filepath.Join(t.TempDir(), "no-such-dir", "x"), &models.AnalysisResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "export csv")
}

func TestRootCmdExportCSV(t *testing.T) {
	const lab3 = "../../testdata/Lab-3-TCP-Retrans.pcapng"
	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), errOut.String(), err
	}

	t.Run("writes the three files and still prints the report", func(t *testing.T) {
		prefix := filepath.Join(t.TempDir(), "lab3")
		out, errOut, err := run("--export-csv", prefix, lab3)
		require.NoError(t, err)
		assert.Contains(t, out, "TRIAGE REPORT", "the normal report is still printed")
		assert.Contains(t, errOut, "lab3_flows.csv", "the files are announced on stderr")

		flows := readCSV(t, prefix+"_flows.csv")
		issues := readCSV(t, prefix+"_issues.csv")
		protocols := readCSV(t, prefix+"_protocols.csv")
		require.Greater(t, len(flows), 1)
		require.Greater(t, len(issues), 1)
		require.Greater(t, len(protocols), 1)

		// the CSV agrees with the JSON output
		jsonOut, _, err := run("-o", "json", lab3)
		require.NoError(t, err)
		assert.Contains(t, jsonOut, `"total_flows": `+strconv.Itoa(len(flows)-1))
		for _, row := range flows[1:] {
			assert.Len(t, row, len(flows[0]))
		}
	})

	t.Run("works with json output, whose stdout stays valid", func(t *testing.T) {
		prefix := filepath.Join(t.TempDir(), "j")
		out, _, err := run("-o", "json", "--export-csv", prefix, lab3)
		require.NoError(t, err)
		assert.True(t, len(out) > 0 && out[0] == '{')
		_, statErr := os.Stat(prefix + "_issues.csv")
		assert.NoError(t, statErr)
	})

	t.Run("no prefix is a helpful error", func(t *testing.T) {
		for _, args := range [][]string{{lab3, "--export-csv"}, {"--export-csv", "", lab3}, {"--export-csv=  ", lab3}} {
			_, _, err := run(args...)
			require.Error(t, err, "%v", args)
			assert.Contains(t, err.Error(), "--export-csv needs a file name prefix")
			assert.Contains(t, err.Error(), "report_flows.csv")
		}
	})

	t.Run("cannot be combined with follow or the web UI", func(t *testing.T) {
		_, _, err := run("--export-csv", "x", "--follow", "10.0.0.1:1-10.0.0.2:2", lab3)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--export-csv")
		_, _, err = run("--web", ":0", "--export-csv", "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--export-csv")
	})

	t.Run("a directory that does not exist is an error", func(t *testing.T) {
		_, _, err := run("--export-csv", filepath.Join(t.TempDir(), "missing", "x"), lab3)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "export csv")
	})

	t.Run("nothing to analyze writes no files and says so", func(t *testing.T) {
		dir := t.TempDir()
		only := filepath.Join(dir, "l2.pcap")
		writeFrames(t, only, [][]byte{lldpFrame()})
		prefix := filepath.Join(dir, "none")
		_, errOut, err := run("--export-csv", prefix, only)
		require.NoError(t, err)
		assert.Contains(t, errOut, "no CSV files were written")
		_, statErr := os.Stat(prefix + "_flows.csv")
		assert.True(t, os.IsNotExist(statErr))
	})
}
