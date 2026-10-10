package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const httpSlowResponse = time.Second

// connKey identifies a client-to-server connection direction.
type connKey struct{ client, server endpoint }

// analyzeHTTP inspects HTTP requests and responses and reports:
//   - 5xx responses (error)
//   - 4xx responses (warning)
//   - responses that arrive more than 1 second after their request (info)
//
// Responses are matched to the oldest unanswered request on the same
// connection, which is correct for HTTP/1.x including pipelining.
func analyzeHTTP(packets []models.PacketInfo) []models.Issue {
	var msgs []models.PacketInfo
	for _, p := range packets {
		if p.HTTPMethod != "" || p.HTTPStatusCode != 0 {
			msgs = append(msgs, p)
		}
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].Timestamp.Before(msgs[j].Timestamp) })

	var issues []models.Issue
	pending := make(map[connKey][]models.PacketInfo)

	for _, p := range msgs {
		if p.HTTPMethod != "" {
			k := connKey{endpoint{p.SrcIP, p.SrcPort}, endpoint{p.DstIP, p.DstPort}}
			pending[k] = append(pending[k], p)
			continue
		}

		k := connKey{endpoint{p.DstIP, p.DstPort}, endpoint{p.SrcIP, p.SrcPort}}
		var req *models.PacketInfo
		if q := pending[k]; len(q) > 0 {
			req = &q[0]
			pending[k] = q[1:]
		}

		what, host := fmt.Sprintf("response from %s", p.SrcIP), ""
		if req != nil {
			what = fmt.Sprintf("%s %s to %s", req.HTTPMethod, req.HTTPURI, req.DstIP)
			host = req.HTTPHost
		}
		switch {
		case p.HTTPStatusCode >= 500:
			issues = append(issues, httpIssue("server-error", models.SeverityError, "HTTP Server Error", p, host,
				fmt.Sprintf("%s returned status %d", what, p.HTTPStatusCode)))
		case p.HTTPStatusCode >= 400:
			issues = append(issues, httpIssue("client-error", models.SeverityWarning, "HTTP Client Error", p, host,
				fmt.Sprintf("%s returned status %d", what, p.HTTPStatusCode)))
		}
		if req != nil {
			if rtt := p.Timestamp.Sub(req.Timestamp); rtt > httpSlowResponse {
				issues = append(issues, httpIssue("slow", models.SeverityInfo, "HTTP Slow Response", *req, host,
					fmt.Sprintf("%s took %s to answer (status %d)", what, rtt, p.HTTPStatusCode)))
			}
		}
	}
	return issues
}

// httpIssue builds an HTTP issue anchored at packet p.
func httpIssue(kind string, sev models.Severity, title string, p models.PacketInfo, domain, desc string) models.Issue {
	return models.Issue{
		ID:          fmt.Sprintf("http-%s-%d-%s:%d", kind, p.Timestamp.UnixNano(), p.SrcIP, p.SrcPort),
		Severity:    sev,
		Category:    "HTTP",
		Title:       title,
		Description: desc,
		Timestamp:   p.Timestamp,
		Domain:      domain,
	}
}
