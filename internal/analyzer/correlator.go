package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	dnsHTTPWindow = 5 * time.Second

	// refusedSpike is the number of refused connections to one ip:port that
	// makes "service unavailable" the primary cause.
	refusedSpike = 5
)

// Health score deductions per issue severity.
var severityPenalty = map[models.Severity]int{
	models.SeverityCritical: 30,
	models.SeverityError:    20,
	models.SeverityWarning:  10,
	models.SeverityInfo:     2,
}

// Event types used in the timeline.
const (
	eventRootCause    = "root_cause"
	eventSymptom      = "symptom"
	eventIssue        = "issue"
	eventCaptureStart = "capture_start"
	eventCaptureEnd   = "capture_end"
)

// Kinds of primary cause, which select the recommendations.
const (
	causeNone       = ""
	causeDNSHTTP    = "dns-http"
	causeCongestion = "congestion"
	causeRefused    = "refused"
	causeIssue      = "issue"
)

// correlate links issues causally and produces a diagnosis. It looks for:
//   - a DNS SERVFAIL followed within 5 seconds by HTTP 5xx errors for the same
//     domain (or, when the HTTP host is unknown, any HTTP 5xx): the DNS issue
//     is the primary cause and the HTTP errors are symptoms
//   - high RTT together with TCP retransmits on a flow: network congestion
//   - five or more connections refused (RST in reply to SYN) by one ip:port:
//     the service is down or a firewall rejects it
//
// A DNS-to-HTTP link takes priority, then a Critical issue, then a spike of
// refused connections to one service, then congestion,
// then the most severe remaining issue. correlate is pure.
func correlate(packets []models.PacketInfo, flows []models.Flow, issues []models.Issue) models.RootCauseAnalysis {
	sorted := append([]models.Issue(nil), issues...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	d := diagnosis{roles: make(map[string]string)}
	switch {
	case d.dnsHTTP(sorted):
	case d.critical(sorted):
	case d.refusedSpike(sorted):
	case d.congestion(flows, sorted):
	case d.worst(sorted):
	default:
		d.cause, d.confidence = "No significant issues detected", "high"
		d.summary = fmt.Sprintf("No anomalies were found in %d packets.", len(packets))
		d.kind = causeNone
	}

	return models.RootCauseAnalysis{
		HealthScore:     healthScore(sorted),
		PrimaryCause:    d.cause,
		Confidence:      d.confidence,
		Summary:         d.summary,
		Timeline:        buildTimeline(packets, sorted, d.roles),
		Recommendations: recommendations(d.kind, d.domain, d.category),
	}
}

type diagnosis struct {
	cause, confidence, summary string
	kind                       string
	domain, category           string
	roles                      map[string]string // issue ID -> timeline event type
}

// dnsHTTP applies the DNS SERVFAIL to HTTP 5xx rule. A SERVFAIL issue may
// aggregate many queries; each one is tried as the cause, using its own time
// and domain.
func (d *diagnosis) dnsHTTP(issues []models.Issue) bool {
	var best *models.Issue
	var bestAt time.Time
	var bestDomain string
	var bestSymptoms []models.Issue
	bestHigh := false

	for i := range issues {
		s := &issues[i]
		if s.Category != "DNS" || s.Title != "DNS SERVFAIL" {
			continue
		}
		occs := s.Occurrences
		if len(occs) == 0 {
			occs = []models.Occurrence{{Time: s.Timestamp, Subject: s.Domain}}
		}
		for _, o := range occs {
			var symptoms []models.Issue
			matched := false
			for _, h := range issues {
				if h.Category != "HTTP" || h.Title != "HTTP Server Error" {
					continue
				}
				if dt := h.Timestamp.Sub(o.Time); dt < 0 || dt > dnsHTTPWindow {
					continue
				}
				switch {
				case h.Domain != "" && o.Subject != "" && strings.EqualFold(h.Domain, o.Subject):
					matched = true
				case h.Domain != "" && o.Subject != "":
					continue // a different domain: unrelated
				}
				symptoms = append(symptoms, h)
			}
			if len(symptoms) > len(bestSymptoms) || (len(symptoms) > 0 && len(symptoms) == len(bestSymptoms) && matched && !bestHigh) {
				best, bestAt, bestDomain, bestSymptoms, bestHigh = s, o.Time, o.Subject, symptoms, matched
			}
		}
	}
	if best == nil {
		return false
	}

	d.kind, d.domain, d.category = causeDNSHTTP, bestDomain, "DNS"
	d.cause = "DNS resolution failure"
	if bestDomain != "" {
		d.cause += " for " + bestDomain
	}
	d.confidence = "medium"
	if bestHigh {
		d.confidence = "high"
	}
	d.summary = fmt.Sprintf("DNS SERVFAIL at %s was followed by %d HTTP 5xx error(s) within %s; the HTTP failures are most likely a consequence of the failed name resolution.",
		bestAt.UTC().Format("15:04:05.000"), len(bestSymptoms), dnsHTTPWindow)
	d.roles[best.ID] = eventRootCause
	for _, h := range bestSymptoms {
		d.roles[h.ID] = eventSymptom
	}
	return true
}

// critical makes the earliest Critical issue the primary cause.
func (d *diagnosis) critical(issues []models.Issue) bool {
	for _, is := range issues {
		if is.Severity == models.SeverityCritical {
			d.fromIssue(is, "high")
			return true
		}
	}
	return false
}

// refusedSpike makes a service that refused many connections the primary
// cause. The server endpoint with the most refusals wins, provided it
// reached refusedSpike.
func (d *diagnosis) refusedSpike(issues []models.Issue) bool {
	var worst models.Issue
	total, targets := 0, 0
	for _, is := range issues {
		if is.Title != titleRefused {
			continue
		}
		total += is.Count
		targets++
		if is.Count > worst.Count {
			worst = is
		}
	}
	if worst.Count < refusedSpike {
		return false
	}

	d.kind, d.category = causeRefused, "Connection"
	d.cause = "Service Unavailable / Port Closed on " + worst.Target
	d.confidence = "high"
	d.summary = fmt.Sprintf("%s refused %d connection attempt(s) with an RST instead of a SYN-ACK", worst.Target, worst.Count)
	if targets > 1 {
		d.summary += fmt.Sprintf("; %d attempts were refused in total across %d server endpoints", total, targets)
	}
	d.summary += ". The service is not listening, or a firewall actively rejects it."
	for _, is := range issues {
		if is.Title == titleRefused {
			d.roles[is.ID] = eventRootCause
		}
	}
	return true
}

// congestion detects flows with both high average RTT and retransmits.
func (d *diagnosis) congestion(flows []models.Flow, issues []models.Issue) bool {
	hot := make(map[string]models.Flow)
	for _, f := range flows {
		if f.AvgRTTMs > highRTTMs && f.Retransmits > 0 {
			hot[f.ID] = f
		}
	}
	if len(hot) == 0 {
		return false
	}

	ids := make([]string, 0, len(hot))
	for id := range hot {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	worst := hot[ids[0]]
	for _, id := range ids[1:] {
		if hot[id].AvgRTTMs > worst.AvgRTTMs {
			worst = hot[id]
		}
	}

	d.kind, d.category = causeCongestion, "Performance"
	d.cause = "Network congestion"
	d.confidence = "medium"
	if len(hot) > 1 {
		d.confidence = "high"
	}
	d.summary = fmt.Sprintf("%d flow(s) combine high latency with TCP retransmissions; worst is %s with an average RTT of %.0fms and %d retransmit(s). That pattern points to queueing or packet loss on the path.",
		len(hot), worst.ID, worst.AvgRTTMs, worst.Retransmits)
	for _, is := range issues {
		if _, ok := hot[is.FlowID]; ok {
			d.roles[is.ID] = eventRootCause
		}
		for _, o := range is.Occurrences { // aggregated latency and jitter issues
			if _, ok := hot[o.Subject]; ok && is.Category == "Performance" {
				d.roles[is.ID] = eventRootCause
			}
		}
	}
	return true
}

// worst makes the most severe issue (earliest on ties) the primary cause.
func (d *diagnosis) worst(issues []models.Issue) bool {
	var best models.Issue
	found := false
	for _, is := range issues {
		if isNote(is) {
			continue // a note about the capture explains nothing about the traffic
		}
		if !found || severityRank(is.Severity) > severityRank(best.Severity) {
			best, found = is, true
		}
	}
	if !found {
		return false
	}
	conf := "low"
	if severityRank(best.Severity) >= severityRank(models.SeverityError) {
		conf = "medium"
	}
	d.fromIssue(best, conf)
	return true
}

func (d *diagnosis) fromIssue(is models.Issue, confidence string) {
	d.kind, d.category, d.domain = causeIssue, is.Category, is.Domain
	if _, ok := categoryRecommendations[is.Title]; ok {
		d.category = is.Title // some issues need advice of their own, not their category's
	}
	d.cause, d.confidence, d.summary = is.Title, confidence, is.Description
	if c, ok := categoryCause[is.Category]; ok {
		d.cause = c
	}
	if c, ok := titleCause[is.Title]; ok {
		d.cause = c
	}
	d.roles[is.ID] = eventRootCause
}

func severityRank(s models.Severity) int { return severityPenalty[s] }

// isNote reports whether is is an informational note about the capture
// itself, such as skipped frames. Notes are shown in the timeline but do not
// lower the health score or become the primary cause.
func isNote(is models.Issue) bool {
	return is.Category == "Capture" && is.Severity == models.SeverityInfo
}

// minHealthScore is the floor of the health score. A capture can score
// below 0 so that "very bad" and "catastrophic" stay distinguishable.
const minHealthScore = -50

// healthScore starts at 100 and subtracts a penalty per issue, never going
// below minHealthScore.
func healthScore(issues []models.Issue) int {
	score := 100
	for _, is := range issues {
		if isNote(is) {
			continue
		}
		score -= severityPenalty[is.Severity]
	}
	if score < minHealthScore {
		return minHealthScore
	}
	return score
}

// buildTimeline merges issues and capture bookends in chronological order.
// roles maps issue IDs to "root_cause" or "symptom"; other issues are "issue".
func buildTimeline(packets []models.PacketInfo, issues []models.Issue, roles map[string]string) []models.TimelineEvent {
	events := make([]models.TimelineEvent, 0, len(issues)+2)

	if len(packets) > 0 {
		first, last := packets[0].Timestamp, packets[0].Timestamp
		for _, p := range packets[1:] {
			if p.Timestamp.Before(first) {
				first = p.Timestamp
			}
			if p.Timestamp.After(last) {
				last = p.Timestamp
			}
		}
		events = append(events,
			models.TimelineEvent{Timestamp: first, EventType: eventCaptureStart, Severity: models.SeverityInfo,
				Description: fmt.Sprintf("Capture starts (%d packets)", len(packets))},
			models.TimelineEvent{Timestamp: last, EventType: eventCaptureEnd, Severity: models.SeverityInfo,
				Description: fmt.Sprintf("Capture ends (%s later)", formatDuration(last.Sub(first)))},
		)
	}

	for _, is := range issues {
		typ := eventIssue
		if r, ok := roles[is.ID]; ok {
			typ = r
		}
		events = append(events, models.TimelineEvent{
			Timestamp: is.Timestamp, EventType: typ, Severity: is.Severity,
			Description: is.Title + ": " + is.Description,
		})
	}

	// Stable, with capture_start ordered before and capture_end after events
	// that share its timestamp.
	rank := func(e models.TimelineEvent) int {
		switch e.EventType {
		case eventCaptureStart:
			return 0
		case eventCaptureEnd:
			return 2
		}
		return 1
	}
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.Before(events[j].Timestamp)
		}
		return rank(events[i]) < rank(events[j])
	})
	return events
}

// recommendations returns 2-3 concrete next steps for the primary cause.
func recommendations(kind, domain, category string) []string {
	switch kind {
	case causeDNSHTTP:
		target := "the failing domain"
		if domain != "" {
			target = domain
		}
		return []string{
			fmt.Sprintf("Query the resolver directly (dig %s @<resolver>) and compare with an alternate resolver to confirm the SERVFAIL.", target),
			"Check the resolver's upstream reachability and DNSSEC validation; SERVFAIL usually means unreachable authoritative servers or a broken signature chain.",
			"Re-test the HTTP service once DNS resolves; the 5xx errors should clear without any web server change.",
		}
	case causeRefused:
		return categoryRecommendations[titleRefused]
	case causeCongestion:
		return []string{
			"Inspect interface error, drop and queue counters on the devices along the path, starting nearest the high-RTT flows.",
			"Check link utilisation and QoS policy for saturation or bufferbloat during the capture window.",
			"Run a traceroute/MTR to the affected hosts to locate the hop where latency or loss begins.",
		}
	case causeIssue:
		if r := categoryRecommendations[category]; r != nil {
			return r
		}
	}
	if kind == causeNone {
		return []string{
			"No action required; the capture shows no anomalies.",
			"Keep this capture as a baseline to compare against when a problem is reported.",
		}
	}
	return []string{
		"Review the detailed issue list below, starting with the highest severity items.",
		"Capture again closer to the affected client and server to confirm where the problem originates.",
	}
}

// categoryCause names the primary cause for categories where the issue title
// describes a symptom rather than the underlying problem.
var categoryCause = map[string]string{
	"PacketLoss": "TCP retransmissions observed",
}

// titleCause overrides the cause name for specific issues.
var titleCause = map[string]string{
	titleFastRetransmit:    "TCP fast retransmission observed",
	titleTimeoutRetransmit: "TCP retransmission timeout observed",
}

var categoryRecommendations = map[string][]string{
	titleFastRetransmit: {
		"TCP data was retransmitted after 3 or more duplicate acknowledgments for the same byte. This capture alone cannot determine whether a segment was lost, reordered or delayed, or where. Compare captures at both ends and inspect network interface, queue, and endpoint behavior.",
	},
	titleTimeoutRetransmit: {
		"TCP data was retransmitted after a period without sufficient acknowledgment progress. This capture alone cannot determine whether the cause was packet loss, congestion, an endpoint problem, or a capture limitation. Compare captures at both ends and inspect network interface, queue, and endpoint behavior.",
	},
	titleStray: {
		"Check whether the destinations are being scanned, or whether a firewall or NAT dropped the connection state so that later packets are answered with RSTs. If the capture is one-sided, the handshake may simply be on the other path.",
	},
	titleUnansweredSYN: {
		"Verify if a firewall is silently dropping packets, or if the server is down/unreachable. Also check that the capture point sees traffic in both directions: a one-sided capture looks the same.",
	},
	titleSYNFlood: {
		"Multiple connection attempts are being silently dropped. This may indicate a firewall blocking the source, a server overload, or a SYN flood attack.",
	},
	titleSYNRetried: {
		"The first SYN was lost or ignored and only a retry got through. Check for packet loss on the path, and whether a firewall or an overloaded server drops initial SYNs.",
	},
	titleRefused: {
		"Verify if the service is running on the target port, or if a firewall is actively rejecting connections with an RST instead of dropping them.",
	},
	titleZeroWindowReset: {
		"A TCP receive window of 0 was advertised on this flow. This capture alone cannot show why, or whether it affected the rest of the exchange. Compare captures at both ends and inspect the receiving application and its buffer behavior.",
	},
	titleZeroWindow: {
		"A TCP receive window of 0 was advertised on this flow. This capture alone cannot show why, or whether it affected the rest of the exchange. Compare captures at both ends and inspect the receiving application and its buffer behavior.",
	},
	titleIdle: {
		"Check the idle-timeout settings of firewalls, NAT gateways and load balancers on the path, and enable TCP keep-alives if long-idle connections are expected.",
	},
	titleAborted: {
		"Investigate application-level crashes, firewall state-table evictions, or middleboxes forcefully tearing down the connection.",
	},
	"DNS": {
		"Query the affected names against another resolver to see whether the failure is specific to the configured one.",
		"Check resolver health, upstream forwarders and DNSSEC validation.",
	},
	"HTTP": {
		"Check the application server and reverse proxy logs for the failing requests around the reported time.",
		"Verify upstream dependencies (databases, APIs) of the failing endpoints.",
	},
	"TLS": {
		"Verify the certificate chain, expiry and hostname match on the server; test with openssl s_client.",
		"Compare the TLS versions and cipher suites offered by the client with those allowed by the server.",
	},
	"PacketLoss": {
		"Retransmissions were observed, but this capture alone cannot show whether packets were lost, delayed or reordered. Compare captures at both ends.",
		"Check interface error and drop counters and queue behavior on the path.",
	},
	"Performance": {
		"Compare handshake and response timings against a baseline capture taken at a quiet time.",
		"Check server load and network path latency (traceroute/MTR) for the slow flows.",
	},
	"ICMP": {
		"Trace the path to the destination to find the router generating the ICMP errors.",
		"Check routing tables and ACLs on that router, and look for routing loops if TTL expiry is reported.",
	},
	"Capture": {
		"Re-capture the traffic, or retrieve the complete file; this analysis only covers the packets before the cut.",
		"Check disk space, ring-buffer settings and whether the capture process was stopped or crashed.",
	},
	"ARP": {
		"Find the devices owning the conflicting MAC addresses with the switch's MAC address table and remove the duplicate address.",
		"Check for misconfigured static IPs, DHCP conflicts or hosts flooding ARP requests, and enable port security or dynamic ARP inspection.",
	},
}
