package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// tlsRank orders TLS versions; unknown versions are not ranked.
var tlsRank = map[string]int{"SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}

// analyzeTLS inspects TLS handshakes and alerts and reports:
//   - handshake_failure / bad_certificate alerts (error)
//   - a ServerHello below TLS 1.2 answering a ClientHello that offered
//     TLS 1.2 or higher (warning)
func analyzeTLS(packets []models.PacketInfo) []models.Issue {
	var msgs []models.PacketInfo
	for _, p := range packets {
		if p.TLSHandshakeType != "" {
			msgs = append(msgs, p)
		}
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].Timestamp.Before(msgs[j].Timestamp) })

	var issues []models.Issue
	pending := make(map[connKey]models.PacketInfo) // latest ClientHello per connection

	for _, p := range msgs {
		switch p.TLSHandshakeType {
		case "ClientHello":
			pending[connKey{endpoint{p.SrcIP, p.SrcPort}, endpoint{p.DstIP, p.DstPort}}] = p

		case "ServerHello":
			k := connKey{endpoint{p.DstIP, p.DstPort}, endpoint{p.SrcIP, p.SrcPort}}
			ch, ok := pending[k]
			if !ok {
				continue
			}
			delete(pending, k)
			offered, okO := tlsRank[ch.TLSVersion]
			chosen, okC := tlsRank[p.TLSVersion]
			if okO && okC && offered >= tlsRank["TLS 1.2"] && chosen < tlsRank["TLS 1.2"] {
				issues = append(issues, tlsIssue("downgrade", models.SeverityWarning, "TLS Protocol Downgrade", p,
					fmt.Sprintf("client %s offered %s but server %s selected %s", ch.SrcIP, ch.TLSVersion, p.SrcIP, p.TLSVersion)))
			}

		case "Alert":
			d := p.TLSAlertDescription
			if strings.Contains(d, "handshake_failure") || strings.Contains(d, "bad_certificate") {
				issues = append(issues, tlsIssue("handshake-failure", models.SeverityError, "TLS Handshake Failure", p,
					fmt.Sprintf("%s alert (%s) sent by %s to %s", d, p.TLSAlertLevel, p.SrcIP, p.DstIP)))
			}
		}
	}
	return issues
}

// tlsIssue builds a TLS issue anchored at packet p.
func tlsIssue(kind string, sev models.Severity, title string, p models.PacketInfo, desc string) models.Issue {
	return models.Issue{
		ID:          fmt.Sprintf("tls-%s-%d-%s:%d", kind, p.Timestamp.UnixNano(), p.SrcIP, p.SrcPort),
		Severity:    sev,
		Category:    "TLS",
		Title:       title,
		Description: desc,
		Timestamp:   p.Timestamp,
	}
}
