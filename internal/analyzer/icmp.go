package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	icmpDestUnreachable = 3
	icmpRedirect        = 5
	icmpTimeExceeded    = 11
)

type icmpKey struct {
	typ    uint8
	router string
}

// analyzeICMP reports ICMP error messages, folded per sending router and
// message type:
//   - Destination Unreachable, type 3 (error)
//   - Time Exceeded, type 11 (warning): possible routing loop
//   - Redirect, type 5 (info)
//
// Each issue names the router, how many messages it sent and the three
// targets (the original destination quoted in the error) hit most often.
func analyzeICMP(packets []models.PacketInfo) []models.Issue {
	type group struct {
		first   models.PacketInfo
		count   int
		targets map[string]int
		codes   map[string]int
		victims map[string]struct{} // hosts that received the errors
		occ     []models.Occurrence
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
		k := icmpKey{p.ICMPType, p.SrcIP}
		g, ok := groups[k]
		if !ok {
			g = &group{first: p, targets: map[string]int{}, codes: map[string]int{}, victims: map[string]struct{}{}}
			groups[k] = g
			order = append(order, k)
		}
		g.count++
		target := icmpTarget(p)
		g.targets[target]++
		msg := p.ICMPMessage
		if msg == "" {
			msg = fmt.Sprintf("type %d code %d", p.ICMPType, p.ICMPCode)
		}
		g.codes[msg]++
		g.victims[p.DstIP] = struct{}{}
		g.occ = append(g.occ, models.Occurrence{Time: p.Timestamp, Subject: target})
		if p.Timestamp.Before(g.first.Timestamp) {
			g.first = p
		}
	}

	issues := make([]models.Issue, 0, len(order))
	for _, k := range order {
		g := groups[k]
		top := topCounts(g.targets, 3)
		parts := make([]string, len(top))
		for i, t := range top {
			parts[i] = fmt.Sprintf("%s (%d)", t.name, t.n)
		}
		label := "Top 3 targets"
		if len(g.targets) <= 3 {
			label = "Targets"
		}

		var sev models.Severity
		var title, kind, hint string
		switch k.typ {
		case icmpDestUnreachable:
			sev, title, kind = models.SeverityError, "ICMP Destination Unreachable", "Destination Unreachable"
		case icmpTimeExceeded:
			sev, title, kind = models.SeverityWarning, "ICMP Time Exceeded", "Time Exceeded"
			hint = " Possible routing loop or too-low TTL."
		default:
			sev, title, kind = models.SeverityInfo, "ICMP Redirect", "Redirect"
		}
		desc := fmt.Sprintf("Router %s sent %s to %s. %s: %s.", k.router, count(g.count, kind+" message", kind+" messages"), count(len(g.victims), "host", "hosts"), label, strings.Join(parts, ", "))
		reasons := topCounts(g.codes, 3)
		rp := make([]string, len(reasons))
		for i, r := range reasons {
			name := r.name
			if _, after, ok := strings.Cut(name, ": "); ok {
				name = after
			}
			rp[i] = fmt.Sprintf("%s (%d)", name, r.n)
		}
		desc += " Reasons: " + strings.Join(rp, ", ") + "."
		issues = append(issues, models.Issue{
			ID:          fmt.Sprintf("icmp-%d-%s", k.typ, k.router),
			Severity:    sev,
			Category:    "ICMP",
			Title:       title,
			Description: desc + hint,
			Timestamp:   g.first.Timestamp,
			Target:      top[0].name,
			Count:       g.count,
			Occurrences: g.occ,
		})
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Timestamp.Before(issues[j].Timestamp) })
	return issues
}

// icmpTarget names what an ICMP error was about: the original destination
// as ip:port when the quoted packet was TCP or UDP, else just the IP.
func icmpTarget(p models.PacketInfo) string {
	switch {
	case p.ICMPOrigDstIP == "":
		return "unknown"
	case p.ICMPOrigDstPort != 0:
		return fmt.Sprintf("%s:%d", p.ICMPOrigDstIP, p.ICMPOrigDstPort)
	}
	return p.ICMPOrigDstIP
}
