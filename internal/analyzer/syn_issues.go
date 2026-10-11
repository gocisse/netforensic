package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the handshake-failure issues.
const (
	titleUnansweredSYN = "Unanswered SYN (No reply captured: may be firewall drop, server unreachable, or asymmetric capture)"
	titleSYNFlood      = "Possible SYN Flood (multiple unanswered SYNs)"
	titleSYNRetried    = "SYN Retried Before Answer"

	// synAnswerGrace is how long the capture must keep running after a
	// connection's last SYN before silence counts as "unanswered"; a first
	// retransmission would only come after about a second.
	synAnswerGrace = time.Second

	// synFloodWindow and synFloodThreshold: more than this many unanswered
	// SYNs to one ip:port within the window is a possible flood.
	synFloodWindow    = 10 * time.Second
	synFloodThreshold = 10
)

// synIssues reports handshakes that did not complete cleanly:
//   - Possible SYN Flood (error): more than 10 connection attempts to one
//     ip:port inside a 10-second window got no SYN-ACK and no RST. One issue
//     per such destination.
//   - Unanswered SYN (warning): the client sent a SYN and neither a SYN-ACK
//     nor an RST was captured, although the capture ran on for at least a
//     second. The title stays neutral about why, since a capture that sees
//     only one direction looks the same as a firewall drop. All remaining unanswered attempts are folded into one issue
//     that names the most affected destinations, so a port sweep does not
//     bury the report.
//   - SYN Retried Before Answer (info): the handshake did complete, but only
//     after the first SYN went unanswered and was sent again. Also one issue.
//
// Connections that were refused with an RST are not unanswered; they are
// reported by the refusal rule.
func synIssues(conns map[instKey]*connState, order []instKey, captureEnd time.Time) []models.Issue {
	unanswered := make(map[string][]*connState)
	var targets []string // first-seen order
	var retried []*connState

	for _, k := range order {
		c := conns[k]
		if !c.sawSyn {
			continue
		}
		switch {
		case c.sawSynAck && c.synTries > 1:
			retried = append(retried, c)
		case !c.sawSynAck && !c.firstReply && captureEnd.Sub(c.synLast) >= synAnswerGrace:
			t := c.server.String()
			if _, ok := unanswered[t]; !ok {
				targets = append(targets, t)
			}
			unanswered[t] = append(unanswered[t], c)
		}
	}

	var issues []models.Issue
	var rest []*connState
	for _, t := range targets {
		conns := unanswered[t]
		if is, flood := synFloodIssue(t, conns); flood {
			issues = append(issues, is)
		} else {
			rest = append(rest, conns...)
		}
	}
	if len(rest) > 0 {
		issues = append(issues, unansweredIssue(rest))
	}
	if len(retried) > 0 {
		issues = append(issues, retriedIssue(retried))
	}
	return issues
}

// peakWindow returns the largest number of times that fit in any window,
// and the start of that busiest window. times must be sorted.
func peakWindow(times []time.Time, window time.Duration) (int, time.Time) {
	best, start, lo := 0, time.Time{}, 0
	for hi := range times {
		for times[hi].Sub(times[lo]) > window {
			lo++
		}
		if n := hi - lo + 1; n > best {
			best, start = n, times[lo]
		}
	}
	return best, start
}

// synFloodIssue reports whether the unanswered connections to target form a
// possible SYN flood.
func synFloodIssue(target string, conns []*connState) (models.Issue, bool) {
	times := make([]time.Time, len(conns))
	sources := make(map[string]struct{})
	for i, c := range conns {
		times[i] = c.synFirst
		sources[c.client.ip] = struct{}{}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	peak, at := peakWindow(times, synFloodWindow)
	if peak <= synFloodThreshold {
		return models.Issue{}, false
	}
	return models.Issue{
		ID:        "syn-flood-" + target,
		Severity:  models.SeverityError,
		Category:  "Connection",
		Title:     titleSYNFlood,
		Timestamp: at,
		Target:    target,
		Count:     len(conns),
		Description: fmt.Sprintf("%d connection attempts from %d source(s) to %s got no SYN-ACK and no RST, %d of them within %s starting at %s",
			len(conns), len(sources), target, peak, synFloodWindow, at.UTC().Format("15:04:05.000")),
	}, true
}

// topTargets lists the destinations of conns by number of connections, as
// "ip:port (n)", at most three, busiest first.
func topTargets(conns []*connState) (list string, busiest string, n int) {
	count := make(map[string]int)
	for _, c := range conns {
		count[c.server.String()]++
	}
	names := make([]string, 0, len(count))
	for t := range count {
		names = append(names, t)
	}
	sort.Slice(names, func(i, j int) bool {
		if count[names[i]] != count[names[j]] {
			return count[names[i]] > count[names[j]]
		}
		return names[i] < names[j]
	})
	var parts []string
	for i, t := range names {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("%d more", len(names)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", t, count[t]))
	}
	return strings.Join(parts, ", "), names[0], len(names)
}

func unansweredIssue(conns []*connState) models.Issue {
	first, last := conns[0].synFirst, conns[0].synFirst
	sources := make(map[string]struct{})
	for _, c := range conns {
		if c.synFirst.Before(first) {
			first = c.synFirst
		}
		if c.synFirst.After(last) {
			last = c.synFirst
		}
		sources[c.client.ip] = struct{}{}
	}
	list, busiest, nTargets := topTargets(conns)

	is := models.Issue{
		ID:        "unanswered-syn",
		Severity:  models.SeverityWarning,
		Category:  "Connection",
		Title:     titleUnansweredSYN,
		Timestamp: first,
		Target:    busiest,
		Count:     len(conns),
	}
	if len(conns) == 1 {
		c := conns[0]
		is.FlowID = c.id
		is.Description = fmt.Sprintf("%s sent a SYN to %s at %s and got no SYN-ACK or RST", c.client, c.server, first.UTC().Format("15:04:05.000"))
		if c.synTries > 1 {
			is.Description += fmt.Sprintf(" in %d tries", c.synTries)
		}
		return is
	}
	is.Description = fmt.Sprintf("%d connection attempts from %d source(s) to %d destination(s) got no SYN-ACK or RST (first %s, last %s); most affected: %s",
		len(conns), len(sources), nTargets, first.UTC().Format("15:04:05.000"), last.UTC().Format("15:04:05.000"), list)
	return is
}

func retriedIssue(conns []*connState) models.Issue {
	first := conns[0]
	for _, c := range conns[1:] {
		if c.synFirst.Before(first.synFirst) {
			first = c
		}
	}
	waited := first.synAckAt.Sub(first.synFirst).Round(time.Millisecond)
	_, busiest, _ := topTargets(conns)
	is := models.Issue{
		ID:        "syn-retried",
		Severity:  models.SeverityInfo,
		Category:  "Connection",
		Title:     titleSYNRetried,
		Timestamp: first.synFirst,
		Target:    busiest,
		Count:     len(conns),
	}
	if len(conns) == 1 {
		is.FlowID = first.id
		is.Description = fmt.Sprintf("flow %s: the first SYN got no answer; the handshake only completed after %d SYNs, with the SYN-ACK arriving %s after the first one",
			first.id, first.synTries, waited)
		return is
	}
	list, _, _ := topTargets(conns)
	is.Description = fmt.Sprintf("%d connections needed more than one SYN before the SYN-ACK came; most affected: %s (earliest: %s, %d SYNs, answered after %s)",
		len(conns), list, first.id, first.synTries, waited)
	return is
}
