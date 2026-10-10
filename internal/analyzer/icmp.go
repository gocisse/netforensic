package analyzer

import (
	"fmt"
	"sort"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	icmpDestUnreachable = 3
	icmpRedirect        = 5
	icmpTimeExceeded    = 11
)

type icmpKey struct {
	typ, code uint8
	src, dst  string
}

// analyzeICMP reports ICMP error messages:
//   - Destination Unreachable, type 3 (error)
//   - Time Exceeded, type 11 (warning): possible routing loop
//   - Redirect, type 5 (info)
//
// Repeats of the same message between the same hosts are folded into one
// issue that carries the count.
func analyzeICMP(packets []models.PacketInfo) []models.Issue {
	type group struct {
		first models.PacketInfo
		count int
	}
	groups := make(map[icmpKey]*group)
	var order []icmpKey

	for _, p := range packets {
		if p.Protocol != models.ProtocolICMP {
			continue
		}
		switch p.ICMPType {
		case icmpDestUnreachable, icmpTimeExceeded, icmpRedirect:
		default:
			continue
		}
		k := icmpKey{p.ICMPType, p.ICMPCode, p.SrcIP, p.DstIP}
		g, ok := groups[k]
		if !ok {
			g = &group{first: p}
			groups[k] = g
			order = append(order, k)
		}
		g.count++
		if p.Timestamp.Before(g.first.Timestamp) {
			g.first = p
		}
	}

	issues := make([]models.Issue, 0, len(order))
	for _, k := range order {
		g := groups[k]
		p := g.first
		msg := p.ICMPMessage
		if msg == "" {
			msg = fmt.Sprintf("type %d code %d", p.ICMPType, p.ICMPCode)
		}
		times := ""
		if g.count > 1 {
			times = fmt.Sprintf(" (%d times)", g.count)
		}

		var sev models.Severity
		var title, desc string
		switch p.ICMPType {
		case icmpDestUnreachable:
			sev, title = models.SeverityError, "ICMP Destination Unreachable"
			desc = fmt.Sprintf("%s reported %s for traffic from %s%s", p.SrcIP, msg, p.DstIP, times)
		case icmpTimeExceeded:
			sev, title = models.SeverityWarning, "ICMP Time Exceeded"
			desc = fmt.Sprintf("%s reported %s for traffic from %s%s; possible routing loop or too-low TTL", p.SrcIP, msg, p.DstIP, times)
		default:
			sev, title = models.SeverityInfo, "ICMP Redirect"
			desc = fmt.Sprintf("%s redirected %s to a better route (%s)%s", p.SrcIP, p.DstIP, msg, times)
		}
		issues = append(issues, models.Issue{
			ID:          fmt.Sprintf("icmp-%d-%d-%d-%s-%s", p.ICMPType, p.ICMPCode, p.Timestamp.UnixNano(), p.SrcIP, p.DstIP),
			Severity:    sev,
			Category:    "ICMP",
			Title:       title,
			Description: desc,
			Timestamp:   p.Timestamp,
		})
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Timestamp.Before(issues[j].Timestamp) })
	return issues
}
