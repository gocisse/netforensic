package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// csvSuffixes are the names, after the prefix, of the files --export-csv writes.
var csvSuffixes = []string{"_flows.csv", "_issues.csv", "_protocols.csv"}

// exportCSV writes the analysis as CSV files for spreadsheets and data
// tools: <prefix>_flows.csv (every flow), <prefix>_issues.csv and
// <prefix>_protocols.csv. It returns the paths written. The files are UTF-8;
// quotes, commas and newlines in fields are escaped by encoding/csv.
func exportCSV(prefix string, res *models.AnalysisResult) ([]string, error) {
	tables := []struct {
		suffix string
		header []string
		rows   [][]string
	}{
		{csvSuffixes[0], flowsHeader, flowRows(res)},
		{csvSuffixes[1], issuesHeader, issueRows(res.Issues)},
		{csvSuffixes[2], protocolsHeader, protocolRows(res.ProtocolStats)},
	}
	var written []string
	for _, t := range tables {
		path := prefix + t.suffix
		if err := writeCSV(path, t.header, t.rows); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func writeCSV(path string, header []string, rows [][]string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("export csv: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("export csv: %w", cerr)
		}
	}()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return fmt.Errorf("export csv: write %s: %w", path, err)
	}
	if err := w.WriteAll(rows); err != nil { // WriteAll flushes
		return fmt.Errorf("export csv: write %s: %w", path, err)
	}
	return nil
}

var (
	flowsHeader     = []string{"flow_id", "packets", "bytes", "setup_time_ms", "ttfb_ms", "avg_rtt_ms", "max_rtt_ms", "protocol", "issues"}
	issuesHeader    = []string{"id", "severity", "category", "title", "description", "flow_id", "target", "count", "timestamp"}
	protocolsHeader = []string{"protocol", "layer", "packets", "flows", "percent"}
)

// flowRows lists every flow, the one with the most bytes first. The issues
// column is the number of issues that involve the flow.
func flowRows(res *models.AnalysisResult) [][]string {
	involved := make(map[string]int)
	for _, is := range res.Issues {
		seen := make(map[string]struct{})
		if is.FlowID != "" {
			seen[is.FlowID] = struct{}{}
		}
		for _, o := range is.Occurrences {
			seen[o.Subject] = struct{}{}
		}
		for id := range seen {
			involved[id]++
		}
	}

	flows := append([]models.Flow(nil), res.Flows...)
	sort.SliceStable(flows, func(i, j int) bool {
		bi, bj := flows[i].BytesSent+flows[i].BytesRecv, flows[j].BytesSent+flows[j].BytesRecv
		if bi != bj {
			return bi > bj
		}
		return flows[i].ID < flows[j].ID
	})
	rows := make([][]string, 0, len(flows))
	for _, f := range flows {
		rows = append(rows, []string{
			safeCell(f.ID),
			strconv.Itoa(f.PacketCount),
			strconv.Itoa(f.BytesSent + f.BytesRecv),
			ms(f.SetupTimeMs), ms(f.TTFBMs), ms(f.AvgRTTMs), ms(f.MaxRTTMs),
			safeCell(string(f.Protocol)),
			strconv.Itoa(involved[f.ID]),
		})
	}
	return rows
}

func issueRows(issues []models.Issue) [][]string {
	rows := make([][]string, 0, len(issues))
	for _, is := range issues {
		ts := ""
		if !is.Timestamp.IsZero() {
			ts = is.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, []string{
			safeCell(is.ID), string(is.Severity), safeCell(is.Category), safeCell(is.Title), safeCell(is.Description),
			safeCell(is.FlowID), safeCell(is.Target), strconv.Itoa(is.Count), ts,
		})
	}
	return rows
}

func protocolRows(stats []models.ProtocolStat) [][]string {
	rows := make([][]string, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, []string{
			safeCell(s.Protocol), s.Layer, strconv.Itoa(s.Packets), strconv.Itoa(s.Flows),
			strconv.FormatFloat(s.Percent, 'f', 1, 64),
		})
	}
	return rows
}

// ms formats a millisecond measurement; 0 means it could not be measured, and
// is left empty rather than reported as an instant.
func ms(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// safeCell keeps a spreadsheet from running a text field as a formula: a
// value that starts with =, +, -, @, a tab or a carriage return gets a
// leading apostrophe, as OWASP recommends for CSV exports. Descriptions can
// contain text from the capture (domain names, URLs).
func safeCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
