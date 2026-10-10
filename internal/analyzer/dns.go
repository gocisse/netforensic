package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	dnsTimeout      = 5 * time.Second
	dnsSlowResponse = time.Second
)

// dnsTxn identifies a DNS transaction: the client and server endpoints, the
// transaction ID and the queried name.
type dnsTxn struct {
	client, server endpoint
	id             uint16
	name           string
}

// analyzeDNS inspects DNS packets and reports:
//   - NXDOMAIN responses (warning)
//   - SERVFAIL responses (error)
//   - queries with no response within 5 seconds (warning)
//   - responses that took longer than 1 second (info)
//
// A query counts as unanswered only if the capture continues for more than
// 5 seconds after it, so a query at the very end of a capture is not flagged.
// A response arriving after more than 5 seconds is reported as a timeout.
func analyzeDNS(packets []models.PacketInfo) []models.Issue {
	var dns []models.PacketInfo
	var captureEnd time.Time
	for _, p := range packets {
		if p.Timestamp.After(captureEnd) {
			captureEnd = p.Timestamp
		}
		if p.DNSQueryName != "" {
			dns = append(dns, p)
		}
	}
	sort.SliceStable(dns, func(i, j int) bool { return dns[i].Timestamp.Before(dns[j].Timestamp) })

	var issues []models.Issue
	pending := make(map[dnsTxn]models.PacketInfo)
	var order []dnsTxn // keeps unanswered-query reporting deterministic

	for _, p := range dns {
		name := strings.ToLower(p.DNSQueryName)
		if p.DNSIsQuery {
			txn := dnsTxn{endpoint{p.SrcIP, p.SrcPort}, endpoint{p.DstIP, p.DstPort}, p.DNSID, name}
			if _, dup := pending[txn]; !dup { // keep the first of any client retries
				pending[txn] = p
				order = append(order, txn)
			}
			continue
		}

		switch p.DNSResponseCode {
		case "NXDOMAIN":
			issues = append(issues, dnsIssue("nxdomain", models.SeverityWarning, "DNS NXDOMAIN", p,
				fmt.Sprintf("domain %q does not exist (queried by %s)", p.DNSQueryName, p.DstIP)))
		case "SERVFAIL":
			issues = append(issues, dnsIssue("servfail", models.SeverityError, "DNS SERVFAIL", p,
				fmt.Sprintf("server %s failed to resolve %q", p.SrcIP, p.DNSQueryName)))
		}

		txn := dnsTxn{endpoint{p.DstIP, p.DstPort}, endpoint{p.SrcIP, p.SrcPort}, p.DNSID, name}
		q, ok := pending[txn]
		if !ok {
			continue
		}
		delete(pending, txn)
		rtt := p.Timestamp.Sub(q.Timestamp)
		switch {
		case rtt > dnsTimeout:
			issues = append(issues, dnsIssue("timeout", models.SeverityWarning, "DNS Timeout", q,
				fmt.Sprintf("query for %q to %s was answered only after %s", q.DNSQueryName, q.DstIP, rtt)))
		case rtt > dnsSlowResponse:
			issues = append(issues, dnsIssue("slow", models.SeverityInfo, "DNS Slow Response", q,
				fmt.Sprintf("query for %q to %s took %s to answer", q.DNSQueryName, q.DstIP, rtt)))
		}
	}

	for _, txn := range order {
		q, unanswered := pending[txn]
		if unanswered && captureEnd.Sub(q.Timestamp) > dnsTimeout {
			issues = append(issues, dnsIssue("timeout", models.SeverityWarning, "DNS Timeout", q,
				fmt.Sprintf("query for %q to %s received no response within %s", q.DNSQueryName, q.DstIP, dnsTimeout)))
		}
	}
	return issues
}

// dnsIssue builds a DNS issue anchored at packet p.
func dnsIssue(kind string, sev models.Severity, title string, p models.PacketInfo, desc string) models.Issue {
	return models.Issue{
		ID:          fmt.Sprintf("dns-%s-%d-%s", kind, p.Timestamp.UnixNano(), p.DNSQueryName),
		Severity:    sev,
		Category:    "DNS",
		Title:       title,
		Description: desc,
		Timestamp:   p.Timestamp,
	}
}
