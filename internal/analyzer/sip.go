package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the SIP issues.
const (
	titleSIPRegistration = "SIP Registration Failed"
	titleSIPCallSetup    = "SIP Call Setup Failed"
	titleSIPErrorRate    = "High SIP Error Rate"

	// sipErrorRatePercent and sipMinRequests: a flow whose answered requests
	// failed more often than this share, out of at least this many, has a
	// high error rate. The minimum keeps one failure among a handful of
	// requests from looking like a trend; that failure is reported by itself.
	sipErrorRatePercent = 10
	sipMinRequests      = 10
)

// sipTxn is one SIP request and its first final response. Requests are
// matched to responses by Call-ID and CSeq, which every response repeats.
type sipTxn struct {
	callID string
	method string
	req    models.PacketInfo
	flow   string // ID of the flow the request travelled on
	client string // IP address of the sender of the request
	server string // ip:port of its destination
	final  *models.PacketInfo
}

func (t *sipTxn) code() int { return t.final.SIPStatusCode }

// sipKey identifies a transaction. The flow is part of it: a proxy forwards a
// request with the same Call-ID and CSeq, and a capture that sees both legs
// holds two transactions.
func sipKey(flow, callID string, cseq int, method string) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s", flow, callID, cseq, method)
}

// failed reports whether the transaction ended in an error. 4xx, 5xx and 6xx
// responses are errors, except
//   - 401 and 407, which are the authentication challenge of an ordinary
//     registration or call: the client answers with credentials and the
//     request repeats (a failure after that is its own transaction);
//   - 487 Request Terminated after the call was cancelled, which is what a
//     caller hanging up before the answer looks like.
func (t *sipTxn) failed(cancelled map[string]bool) bool {
	c := t.code()
	switch {
	case c < 400:
		return false
	case c == 401 || c == 407:
		return false
	case c == 487 && cancelled[t.callID]:
		return false
	}
	return true
}

// analyzeSIP reports SIP requests that were answered with an error:
//   - SIP Registration Failed (warning): REGISTER requests that got an error
//     response, one issue per User-Agent (per client address if the request
//     names none), with the status codes received.
//   - SIP Call Setup Failed (warning): INVITE requests that got an error
//     response, one issue per server.
//   - High SIP Error Rate (warning): flows on which more than 10% of the
//     answered requests (at least 10 of them) failed, folded into one issue.
//
// Retransmitted requests count once. ACK needs no answer and is ignored; a
// request that was never answered in the capture is not counted either way.
func analyzeSIP(packets []models.PacketInfo) []models.Issue {
	insts := models.ConnectionInstances(packets)
	txns := make(map[string]*sipTxn)
	var order []*sipTxn
	cancelled := make(map[string]bool)

	for i, p := range packets {
		fk, _ := canonicalKey(p)
		flow := instKey{fk, insts[i]}.id()
		switch {
		case p.SIPMethod != "":
			if p.SIPCallID == "" {
				continue
			}
			if p.SIPMethod == "CANCEL" {
				cancelled[p.SIPCallID] = true
			}
			if p.SIPMethod == "ACK" {
				continue
			}
			cseq := p.SIPCSeq
			k := sipKey(flow, p.SIPCallID, cseq, p.SIPMethod)
			if _, seen := txns[k]; seen {
				continue // a retransmission
			}
			t := &sipTxn{callID: p.SIPCallID, method: p.SIPMethod, req: p,
				flow: flow, client: p.SrcIP, server: endpoint{p.DstIP, p.DstPort}.String()}
			txns[k] = t
			order = append(order, t)
		case p.SIPStatusCode >= 200:
			if t := txns[sipKey(flow, p.SIPCallID, p.SIPCSeq, p.SIPCSeqMethod)]; t != nil && t.final == nil {
				resp := p
				t.final = &resp
			}
		}
	}

	var registers, invites []*sipTxn
	rates := make(map[string]*flowRate)
	var flowOrder []*flowRate
	for _, t := range order {
		if t.final == nil {
			continue
		}
		r := rates[t.flow]
		if r == nil {
			r = &flowRate{flow: t.flow, first: t.req.Timestamp}
			rates[t.flow] = r
			flowOrder = append(flowOrder, r)
		}
		r.answered++
		if !t.failed(cancelled) {
			continue
		}
		r.failed++
		switch t.method {
		case "REGISTER":
			registers = append(registers, t)
		case "INVITE":
			invites = append(invites, t)
		}
	}

	var issues []models.Issue
	issues = append(issues, sipRegistrationIssues(registers)...)
	issues = append(issues, sipCallSetupIssues(invites)...)
	if is, ok := sipErrorRateIssue(flowOrder); ok {
		issues = append(issues, is)
	}
	return issues
}

// flowRate is the outcome of the answered requests on one flow.
type flowRate struct {
	flow             string
	first            time.Time // the first answered request
	answered, failed int
}

// sipCodes lists the status codes of failed transactions, most frequent
// first, as "403 Forbidden (3x), 404 Not Found". A code is shown with the
// reason phrase of its first response.
func sipCodes(txns []*sipTxn) string {
	count := make(map[int]int)
	reason := make(map[int]string)
	for _, t := range txns {
		c := t.code()
		count[c]++
		if _, ok := reason[c]; !ok {
			reason[c] = t.final.SIPReason
		}
	}
	codes := make([]int, 0, len(count))
	for c := range count {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool {
		if count[codes[i]] != count[codes[j]] {
			return count[codes[i]] > count[codes[j]]
		}
		return codes[i] < codes[j]
	})
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = strings.TrimSpace(fmt.Sprintf("%d %s", c, reason[c]))
		if len(codes) > 1 || count[c] > 1 {
			parts[i] += fmt.Sprintf(" (%dx)", count[c])
		}
	}
	return strings.Join(parts, ", ")
}

// sipOccurrences lists the failed transactions, one event each: the Call-ID
// as subject and the status code as value.
func sipOccurrences(txns []*sipTxn) []models.Occurrence {
	occ := make([]models.Occurrence, len(txns))
	for i, t := range txns {
		occ[i] = models.Occurrence{Time: t.req.Timestamp, Subject: t.callID, Value: float64(t.code())}
	}
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].Time.Before(occ[j].Time) })
	return occ
}

// sipServers names the destinations of txns: the busiest, and how many.
func sipServers(txns []*sipTxn) (list string, busiest string) {
	count := make(map[string]int)
	for _, t := range txns {
		count[t.server]++
	}
	names := make([]string, 0, len(count))
	for s := range count {
		names = append(names, s)
	}
	sort.Slice(names, func(i, j int) bool {
		if count[names[i]] != count[names[j]] {
			return count[names[i]] > count[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + fmt.Sprintf(" and %d more", len(names)-3), names[0]
	}
	return strings.Join(names, ", "), names[0]
}

func firstRequestTime(txns []*sipTxn) time.Time {
	first := txns[0].req.Timestamp
	for _, t := range txns[1:] {
		if t.req.Timestamp.Before(first) {
			first = t.req.Timestamp
		}
	}
	return first
}

// sipRegistrationIssues folds failed REGISTERs into one issue per client,
// identified by its User-Agent (or its address if it sends none).
func sipRegistrationIssues(txns []*sipTxn) []models.Issue {
	groups := make(map[string][]*sipTxn)
	var order []string
	for _, t := range txns {
		who := t.req.SIPUserAgent
		if who == "" {
			who = "client " + t.client
		}
		if _, ok := groups[who]; !ok {
			order = append(order, who)
		}
		groups[who] = append(groups[who], t)
	}
	var issues []models.Issue
	for _, who := range order {
		g := groups[who]
		servers, busiest := sipServers(g)
		desc := fmt.Sprintf("%s received %s for REGISTER", who, sipCodes(g))
		if len(g) > 1 {
			desc += fmt.Sprintf(" (%d failed requests to %s)", len(g), servers)
		} else {
			desc += fmt.Sprintf(" (sent to %s)", servers)
		}
		issues = append(issues, models.Issue{
			ID:          "sip-register-" + who,
			Severity:    models.SeverityWarning,
			Category:    "SIP",
			Title:       titleSIPRegistration,
			Description: desc,
			Timestamp:   firstRequestTime(g),
			Target:      busiest,
			Count:       len(g),
			Occurrences: sipOccurrences(g),
		})
	}
	return issues
}

// sipCallSetupIssues folds failed INVITEs into one issue per server.
func sipCallSetupIssues(txns []*sipTxn) []models.Issue {
	groups := make(map[string][]*sipTxn)
	var order []string
	for _, t := range txns {
		if _, ok := groups[t.server]; !ok {
			order = append(order, t.server)
		}
		groups[t.server] = append(groups[t.server], t)
	}
	var issues []models.Issue
	for _, server := range order {
		g := groups[server]
		is := models.Issue{
			ID:          "sip-invite-" + server,
			Severity:    models.SeverityWarning,
			Category:    "SIP",
			Title:       titleSIPCallSetup,
			Timestamp:   firstRequestTime(g),
			Target:      server,
			Count:       len(g),
			Occurrences: sipOccurrences(g),
		}
		if len(g) == 1 {
			is.FlowID = g[0].flow
			is.Description = fmt.Sprintf("%s received %s for INVITE (sent to %s)", g[0].callID, sipCodes(g), server)
		} else {
			first := g[0]
			for _, t := range g[1:] {
				if t.req.Timestamp.Before(first.req.Timestamp) {
					first = t
				}
			}
			is.Description = fmt.Sprintf("%d INVITE requests to %s got error responses: %s (first Call-ID: %s)",
				len(g), server, sipCodes(g), first.callID)
		}
		issues = append(issues, is)
	}
	return issues
}

// sipErrorRateIssue folds the flows on which more than sipErrorRatePercent
// percent of at least sipMinRequests answered requests failed into one issue.
func sipErrorRateIssue(rates []*flowRate) (models.Issue, bool) {
	var high []*flowRate
	for _, r := range rates {
		if r.answered >= sipMinRequests && r.failed*100 > sipErrorRatePercent*r.answered {
			high = append(high, r)
		}
	}
	if len(high) == 0 {
		return models.Issue{}, false
	}
	pct := func(r *flowRate) int { return (r.failed*100 + r.answered/2) / r.answered }
	sort.SliceStable(high, func(i, j int) bool {
		if high[i].failed*high[j].answered != high[j].failed*high[i].answered {
			return high[i].failed*high[j].answered > high[j].failed*high[i].answered // highest rate first
		}
		return high[i].flow < high[j].flow
	})

	is := models.Issue{
		ID:       "sip-error-rate",
		Severity: models.SeverityWarning,
		Category: "SIP",
		Title:    titleSIPErrorRate,
		Count:    len(high),
	}
	for _, r := range high {
		is.Occurrences = append(is.Occurrences, models.Occurrence{Time: r.first, Subject: r.flow, Value: float64(pct(r)), Unit: "%"})
		if is.Timestamp.IsZero() || r.first.Before(is.Timestamp) {
			is.Timestamp = r.first
		}
	}
	worst := high[0]
	if len(high) == 1 {
		is.FlowID = worst.flow
		is.Description = fmt.Sprintf("%d%% of requests failed (%d of %d answered requests on flow %s)", pct(worst), worst.failed, worst.answered, worst.flow)
	} else {
		is.Description = fmt.Sprintf("%s have more than %d%% of requests failing; the worst, %s, has %d%% (%d of %d answered requests)",
			count(len(high), "SIP flow", "SIP flows"), sipErrorRatePercent, worst.flow, pct(worst), worst.failed, worst.answered)
	}
	return is, true
}
