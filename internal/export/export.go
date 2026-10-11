// Package export turns an analysis into CSV tables for spreadsheets and data
// tools. The CLI's --export-csv flag and the web API's /api/export-csv share
// it, so both produce the same files.
package export

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Table is one CSV file: the suffix of its name (after the prefix), the header
// row and the data rows.
type Table struct {
	Suffix string
	Header []string
	Rows   [][]string
}

// Suffixes are the file name endings of the tables, in the order Tables
// returns them.
var Suffixes = []string{"_flows.csv", "_issues.csv", "_protocols.csv"}

// Tables returns the flows, issues and protocol distribution of res as CSV
// tables: <prefix>_flows.csv (every flow in res.Flows), <prefix>_issues.csv and
// <prefix>_protocols.csv.
func Tables(res *models.AnalysisResult) []Table {
	return []Table{
		{Suffixes[0], flowsHeader, flowRows(res)},
		{Suffixes[1], issuesHeader, issueRows(res.Issues)},
		{Suffixes[2], protocolsHeader, protocolRows(res.ProtocolStats)},
	}
}

// Write writes the table as CSV: UTF-8, with quotes, commas and newlines in
// fields escaped as encoding/csv does.
func (t Table) Write(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(t.Header); err != nil {
		return err
	}
	return cw.WriteAll(t.Rows) // WriteAll flushes
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
