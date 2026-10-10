package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const dnsHTTPWindow = 5 * time.Second

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
	causeIssue      = "issue"
)

// correlate links issues causally and produces a diagnosis. It looks for:
//   - a DNS SERVFAIL followed within 5 seconds by HTTP 5xx errors for the same
//     domain (or, when the HTTP host is unknown, any HTTP 5xx): the DNS issue
//     is the primary cause and the HTTP errors are symptoms
//   - high RTT together with TCP retransmits on a flow: network congestion
//
// A DNS-to-HTTP link takes priority, then a Critical issue, then congestion,
// then the most severe remaining issue. correlate is pure.
func correlate(packets []models.PacketInfo, flows []models.Flow, issues []models.Issue) models.RootCauseAnalysis {
	sorted := append([]models.Issue(nil), issues...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	d := diagnosis{roles: make(map[string]string)}
	switch {
	case d.dnsHTTP(sorted):
	case d.critical(sorted):
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

// dnsHTTP applies the DNS SERVFAIL to HTTP 5xx rule.
func (d *diagnosis) dnsHTTP(issues []models.Issue) bool {
	var best *models.Issue
	var bestSymptoms []models.Issue
	bestHigh := false

	for i := range issues {
		s := &issues[i]
		if s.Category != "DNS" || s.Title != "DNS SERVFAIL" {
			continue
		}
		var symptoms []models.Issue
		matched := false
		for _, h := range issues {
			if h.Category != "HTTP" || h.Title != "HTTP Server Error" {
				continue
			}
			if dt := h.Timestamp.Sub(s.Timestamp); dt < 0 || dt > dnsHTTPWindow {
				continue
			}
			switch {
			case h.Domain != "" && s.Domain != "" && strings.EqualFold(h.Domain, s.Domain):
				matched = true
			case h.Domain != "" && s.Domain != "":
				continue // a different domain: unrelated
			}
			symptoms = append(symptoms, h)
		}
		if len(symptoms) > len(bestSymptoms) || (len(symptoms) > 0 && len(symptoms) == len(bestSymptoms) && matched && !bestHigh) {
			best, bestSymptoms, bestHigh = s, symptoms, matched
		}
	}
	if best == nil {
		return false
	}

	d.kind, d.domain, d.category = causeDNSHTTP, best.Domain, "DNS"
	d.cause = "DNS resolution failure"
	if best.Domain != "" {
		d.cause += " for " + best.Domain
	}
	d.confidence = "medium"
	if bestHigh {
		d.confidence = "high"
	}
	d.summary = fmt.Sprintf("DNS SERVFAIL at %s was followed by %d HTTP 5xx error(s) within %s; the HTTP failures are most likely a consequence of the failed name resolution.",
		best.Timestamp.UTC().Format("15:04:05.000"), len(bestSymptoms), dnsHTTPWindow)
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
	}
	return true
}

// worst makes the most severe issue (earliest on ties) the primary cause.
func (d *diagnosis) worst(issues []models.Issue) bool {
	if len(issues) == 0 {
		return false
	}
	best := issues[0]
	for _, is := range issues[1:] {
		if severityRank(is.Severity) > severityRank(best.Severity) {
			best = is
		}
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
	d.cause, d.confidence, d.summary = is.Title, confidence, is.Description
	d.roles[is.ID] = eventRootCause
}

func severityRank(s models.Severity) int { return severityPenalty[s] }

// healthScore starts at 100 and subtracts a penalty per issue, never going
// below 0.
func healthScore(issues []models.Issue) int {
	score := 100
	for _, is := range issues {
		score -= severityPenalty[is.Severity]
	}
	if score < 0 {
		return 0
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
				Description: fmt.Sprintf("Capture ends (%s later)", last.Sub(first))},
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

var categoryRecommendations = map[string][]string{
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
		"Check interface error and drop counters on the path between the two hosts.",
		"Look for duplex mismatches, faulty cabling or congested links; run a sustained ping or iperf test.",
	},
	"Performance": {
		"Compare handshake and response timings against a baseline capture taken at a quiet time.",
		"Check server load and network path latency (traceroute/MTR) for the slow flows.",
	},
	"ICMP": {
		"Trace the path to the destination to find the router generating the ICMP errors.",
		"Check routing tables and ACLs on that router, and look for routing loops if TTL expiry is reported.",
	},
	"ARP": {
		"Find the devices owning the conflicting MAC addresses with the switch's MAC address table and remove the duplicate address.",
		"Check for misconfigured static IPs, DHCP conflicts or hosts flooding ARP requests, and enable port security or dynamic ARP inspection.",
	},
}
