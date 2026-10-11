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

// analyzeDNS inspects DNS packets and reports, folded per resolver:
//   - NXDOMAIN responses (warning), with the most queried domains
//   - SERVFAIL responses (error), likewise
//   - queries with no response within 5 seconds, or answered only after
//     that (warning), one issue per resolver
//   - responses that took longer than 1 second (info), one per resolver
//
// A query counts as unanswered only if the capture continues for more than
// 5 seconds after it, so a query at the very end of a capture is not flagged.
// Each issue keeps the individual events as Occurrences.
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

	nx, servfail, timeout, slow := newDNSGroup(), newDNSGroup(), newDNSGroup(), newDNSGroup()
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
			nx.add(p.SrcIP, dnsEvent{at: p.Timestamp, domain: name})
		case "SERVFAIL":
			servfail.add(p.SrcIP, dnsEvent{at: p.Timestamp, domain: name})
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
			timeout.add(q.DstIP, dnsEvent{at: q.Timestamp, domain: name, late: true, rtt: rtt})
		case rtt > dnsSlowResponse:
			slow.add(q.DstIP, dnsEvent{at: q.Timestamp, domain: name, rtt: rtt})
		}
	}
	for _, txn := range order {
		if q, unanswered := pending[txn]; unanswered && captureEnd.Sub(q.Timestamp) > dnsTimeout {
			timeout.add(q.DstIP, dnsEvent{at: q.Timestamp, domain: strings.ToLower(q.DNSQueryName)})
		}
	}

	var issues []models.Issue
	for _, r := range nx.resolvers {
		issues = append(issues, nx.issue(r, "nxdomain", models.SeverityWarning, "DNS NXDOMAIN",
			func(g []dnsEvent, domains string) string {
				return fmt.Sprintf("Resolver %s returned NXDOMAIN for %s (%s). %s.", r, count(len(g), "query", "queries"), count(uniqueDomains(g), "unique domain", "unique domains"), domains)
			}))
	}
	for _, r := range servfail.resolvers {
		issues = append(issues, servfail.issue(r, "servfail", models.SeverityError, "DNS SERVFAIL",
			func(g []dnsEvent, domains string) string {
				return fmt.Sprintf("Resolver %s returned SERVFAIL for %s (%s). %s.", r, count(len(g), "query", "queries"), count(uniqueDomains(g), "unique domain", "unique domains"), domains)
			}))
	}
	for _, r := range timeout.resolvers {
		issues = append(issues, timeout.issue(r, "timeout", models.SeverityWarning, "DNS Timeout",
			func(g []dnsEvent, domains string) string {
				late := 0
				for _, e := range g {
					if e.late {
						late++
					}
				}
				desc := fmt.Sprintf("Resolver %s failed to respond to %s within %s", r, count(len(g), "query", "queries"), dnsTimeout)
				if late > 0 {
					desc += fmt.Sprintf(" (%d answered only later)", late)
				}
				return desc + ". " + domains + "."
			}))
	}
	for _, r := range slow.resolvers {
		issues = append(issues, slow.issue(r, "slow", models.SeverityInfo, "DNS Slow Response",
			func(g []dnsEvent, domains string) string {
				worst := g[0]
				for _, e := range g[1:] {
					if e.rtt > worst.rtt {
						worst = e
					}
				}
				return fmt.Sprintf("Resolver %s took more than %s to answer %s; the slowest, %q, took %s. %s.",
					r, dnsSlowResponse, count(len(g), "query", "queries"), worst.domain, worst.rtt.Round(time.Millisecond), domains)
			}))
	}
	return issues
}

// dnsEvent is one failed or slow query.
type dnsEvent struct {
	at     time.Time
	domain string
	late   bool          // answered, but after the timeout
	rtt    time.Duration // time to the answer, when there was one
}

// dnsGroup collects events per resolver IP, keeping first-seen order.
type dnsGroup struct {
	resolvers []string
	events    map[string][]dnsEvent
}

func newDNSGroup() *dnsGroup { return &dnsGroup{events: make(map[string][]dnsEvent)} }

func (g *dnsGroup) add(resolver string, e dnsEvent) {
	if _, ok := g.events[resolver]; !ok {
		g.resolvers = append(g.resolvers, resolver)
	}
	g.events[resolver] = append(g.events[resolver], e)
}

// issue builds the aggregated issue for one resolver. describe receives the
// events and the "Top 3 domains: ..." sentence fragment.
func (g *dnsGroup) issue(resolver, kind string, sev models.Severity, title string, describe func([]dnsEvent, string) string) models.Issue {
	evs := g.events[resolver]
	counts := make(map[string]int)
	occ := make([]models.Occurrence, len(evs))
	first := evs[0].at
	for i, e := range evs {
		counts[e.domain]++
		occ[i] = models.Occurrence{Time: e.at, Subject: e.domain}
		if e.at.Before(first) {
			first = e.at
		}
	}
	top := topCounts(counts, 3)
	label := "Top 3 domains"
	if len(counts) <= 3 {
		label = "Domains"
	}
	parts := make([]string, len(top))
	for i, t := range top {
		parts[i] = fmt.Sprintf("%s (%d)", t.name, t.n)
	}
	return models.Issue{
		ID:          fmt.Sprintf("dns-%s-%s", kind, resolver),
		Severity:    sev,
		Category:    "DNS",
		Title:       title,
		Description: describe(evs, label+": "+strings.Join(parts, ", ")),
		Timestamp:   first,
		Domain:      top[0].name,
		Target:      resolver,
		Count:       len(evs),
		Occurrences: occ,
	}
}

func uniqueDomains(evs []dnsEvent) int {
	seen := make(map[string]struct{})
	for _, e := range evs {
		seen[e.domain] = struct{}{}
	}
	return len(seen)
}

type nameCount struct {
	name string
	n    int
}

// topCounts returns the k highest counts, ties broken alphabetically.
func topCounts(counts map[string]int, k int) []nameCount {
	out := make([]nameCount, 0, len(counts))
	for name, n := range counts {
		out = append(out, nameCount{name, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// count formats n with the matching singular or plural noun, "1 query".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
