package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// printPacketTable prints packets as an aligned table.
func printPacketTable(w io.Writer, packets []models.PacketInfo) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tTIME (UTC)\tSOURCE\tDESTINATION\tPROTO\tSIZE\tFLAGS\tSEQ")
	fmt.Fprintln(tw, "-\t----------\t------\t-----------\t-----\t----\t-----\t---")
	for i, p := range packets {
		flags, seq := "-", "-"
		if p.Protocol == models.ProtocolTCP {
			flags = p.TCPFlags
			if flags == "" {
				flags = "none"
			}
			seq = strconv.FormatUint(uint64(p.TCPSeq), 10)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			i+1,
			p.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			formatEndpoint(p.SrcIP, p.SrcPort),
			formatEndpoint(p.DstIP, p.DstPort),
			p.Protocol, p.Size, flags, seq)
	}
	return tw.Flush()
}

// formatEndpoint renders ip:port, or just the IP for portless protocols.
func formatEndpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

// issueGroup is a set of issues sharing severity, category and title.
type issueGroup struct {
	severity models.Severity
	category string
	title    string
	count    int
}

// groupIssues folds issues into groups, most severe first, then most
// numerous, then alphabetically.
func groupIssues(issues []models.Issue) []issueGroup {
	type key struct {
		sev        models.Severity
		cat, title string
	}
	index := make(map[key]int)
	var groups []issueGroup
	for _, is := range issues {
		k := key{is.Severity, is.Category, is.Title}
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, issueGroup{is.Severity, is.Category, is.Title, 0})
		}
		groups[i].count++
	}
	rank := map[models.Severity]int{models.SeverityCritical: 3, models.SeverityError: 2, models.SeverityWarning: 1}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		switch {
		case rank[a.severity] != rank[b.severity]:
			return rank[a.severity] > rank[b.severity]
		case a.count != b.count:
			return a.count > b.count
		case a.category != b.category:
			return a.category < b.category
		}
		return a.title < b.title
	})
	return groups
}

// printIssueSummary prints issues compactly, one line per kind of issue:
// "22x [WARNING] DNS: DNS NXDOMAIN". The full detail is in the triage
// report's timeline and in the JSON output.
func printIssueSummary(w io.Writer, issues []models.Issue) {
	groups := groupIssues(issues)
	width := 0
	for _, g := range groups {
		if n := len(strconv.Itoa(g.count)); n > width {
			width = n
		}
	}
	for _, g := range groups {
		fmt.Fprintf(w, "  %*dx [%s] %s: %s\n", width, g.count, g.severity, g.category, g.title)
	}
}

// printVerbose prints the packet table followed by a blank line.
func printVerbose(w io.Writer, packets []models.PacketInfo) error {
	if err := printPacketTable(w, packets); err != nil {
		return err
	}
	fmt.Fprintln(w)
	return nil
}

// nothingToAnalyze is the JSON result when no packets were left to analyze.
type nothingToAnalyze struct {
	FileName     string         `json:"file_name"`
	TotalPackets int            `json:"total_packets"`
	TotalFlows   int            `json:"total_flows"`
	Issues       []models.Issue `json:"issues"`
	Message      string         `json:"message"`
}

// printNothingToAnalyze reports that no packets remain to analyze, in place
// of a triage report: when filters removed them all, or the capture holds
// none. It is not an error.
func printNothingToAnalyze(w io.Writer, file string, asJSON, filtersActive bool, notes []models.Issue) error {
	msg := "The capture contains no analyzable packets"
	if filtersActive {
		msg = "No packets matched the specified filters"
	}
	if !asJSON {
		if _, err := fmt.Fprintf(w, "%s. Nothing to analyze.\n", msg); err != nil {
			return err
		}
		for _, n := range notes {
			if n.Title == "Skipped Frames" { // explains why a non-empty file has nothing to analyze
				_, err := fmt.Fprintf(w, "%s: %s\n", n.Title, n.Description)
				return err
			}
		}
		return nil
	}
	if notes == nil {
		notes = []models.Issue{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(nothingToAnalyze{FileName: file, Issues: notes, Message: msg})
}

// describeSkipped says which frames were skipped, for example
// "10667 frames of unsupported link type 18; 3 non-IP frames".
func describeSkipped(s pcap.ReadStats) string { return s.Describe() }
