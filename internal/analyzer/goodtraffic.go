package analyzer

import (
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// HealthyFlows returns the flows no issue names, in their order. It never
// returns nil, so that it serializes as [].
func HealthyFlows(flows []models.Flow) []models.Flow {
	out := []models.Flow{}
	for _, f := range flows {
		if f.IssueCount == 0 {
			out = append(out, f)
		}
	}
	return out
}

// GoodTrafficFilter builds a Wireshark display filter that hides everything
// the issues point at: the filter of every issue, negated and joined, as in
// !(tcp.analysis.retransmission || tcp.flags.reset == 1). What is left is the
// traffic no issue is about. Capture notes (which describe the file, not the
// traffic), issues without a filter and filters that are not well formed
// (unbalanced quotes or parentheses) are left out, and repeated filters are
// used once. It returns "" if no filter is left.
func GoodTrafficFilter(issues []models.Issue) string {
	seen := make(map[string]bool)
	var terms []string
	for _, is := range issues {
		f := strings.TrimSpace(is.WiresharkFilter)
		if is.Category == "Capture" || f == "" || seen[f] || !wellFormed(f) {
			continue
		}
		seen[f] = true
		terms = append(terms, f)
	}
	switch len(terms) {
	case 0:
		return ""
	case 1:
		return "!(" + terms[0] + ")"
	}
	for i, t := range terms {
		if hasOperator(t) {
			terms[i] = "(" + t + ")"
		}
	}
	return "!(" + strings.Join(terms, " || ") + ")"
}

// wellFormed reports whether f has balanced parentheses and closed quotes, so
// that wrapping it in parentheses cannot change the meaning of its neighbours.
func wellFormed(f string) bool {
	depth := 0
	inQuote := false
	for i := 0; i < len(f); i++ {
		c := f[i]
		switch {
		case c == '\\' && inQuote:
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !inQuote
}

// hasOperator reports whether f contains a logical operator outside quotes,
// in which case it needs parentheses of its own when joined with others.
func hasOperator(f string) bool {
	inQuote := false
	for i := 0; i < len(f); i++ {
		c := f[i]
		switch {
		case c == '\\' && inQuote:
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case strings.HasPrefix(f[i:], "||"), strings.HasPrefix(f[i:], "&&"), strings.HasPrefix(f[i:], "^^"),
			strings.HasPrefix(f[i:], " or "), strings.HasPrefix(f[i:], " and "), strings.HasPrefix(f[i:], " xor "):
			return true
		}
	}
	return false
}
