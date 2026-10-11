package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the DHCPv6 issues.
const (
	titleDHCPv6NoAddrs  = "DHCPv6 No Addresses Available"
	titleDHCPv6Config   = "DHCPv6 Configuration Error"
	titleDHCPv6FailRate = "High DHCPv6 Failure Rate"
	titleDHCPv6Timeout  = "DHCPv6 Timeout"

	// dhcpv6Timeout is how long a Solicit or Request may wait for its reply.
	dhcpv6Timeout = 30 * time.Second

	// dhcpv6FailPercent and dhcpv6MinResponses: a server whose responses
	// carried an error status more often than this share, out of at least
	// this many, has a high failure rate.
	dhcpv6FailPercent  = 20
	dhcpv6MinResponses = 10
)

// DHCPv6 message types.
const (
	dhcpSolicit     = 1
	dhcpAdvertise   = 2
	dhcpRequest     = 3
	dhcpConfirm     = 4
	dhcpRenew       = 5
	dhcpRebind      = 6
	dhcpReply       = 7
	dhcpRelease     = 8
	dhcpDecline     = 9
	dhcpInfoRequest = 11
)

var dhcpv6MsgNames = map[int]string{
	1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply",
	8: "Release", 9: "Decline", 10: "Reconfigure", 11: "Information-request", 12: "Relay-forward", 13: "Relay-reply",
}

// dhcpv6StatusNames are the status codes of RFC 8415 and its successors.
var dhcpv6StatusNames = map[int]string{
	1: "UnspecFail", 2: "NoAddrsAvail", 3: "NoBinding", 4: "NotOnLink", 5: "UseMulticast", 6: "NoPrefixAvail",
	7: "UnknownQueryType", 8: "MalformedQuery", 9: "NotConfigured", 10: "NotAllowed", 11: "QueryTerminated",
	12: "DataMissing", 13: "CatchUpComplete", 14: "NotSupported",
}

func dhcpv6MsgName(t int) string {
	if n, ok := dhcpv6MsgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

func dhcpv6StatusName(c int) string {
	if n, ok := dhcpv6StatusNames[c]; ok {
		return fmt.Sprintf("%s (%d)", n, c)
	}
	return fmt.Sprintf("status %d", c)
}

// dhcpv6Error reports whether a status code means that the request failed.
// 13 (CatchUpComplete) ends a leasequery successfully.
func dhcpv6Error(c int) bool { return c != 0 && c != 13 }

// The status codes that get their own issue. RFC 8415: 2 NoAddrsAvail, 3
// NoBinding and 6 NoPrefixAvail mean the server has nothing to give or no
// record of the client; 4 NotOnLink, 5 UseMulticast, 9 NotConfigured and 10
// NotAllowed mean that the client's request does not fit the configuration.
func dhcpv6NoAddrs(c int) bool { return c == 2 || c == 3 || c == 6 }
func dhcpv6Config(c int) bool  { return c == 4 || c == 5 || c == 9 || c == 10 }

// noteDHCPv6 adds the DHCPv6 details of p, if it carries any, to flow f.
func noteDHCPv6(f *models.Flow, p models.PacketInfo) {
	if p.DHCPv6MsgType == 0 {
		return
	}
	add := func(t int) {
		n := dhcpv6MsgName(t)
		if !strings.Contains(","+f.DHCPv6MessageTypes+",", ","+n+",") {
			if f.DHCPv6MessageTypes != "" {
				f.DHCPv6MessageTypes += ","
			}
			f.DHCPv6MessageTypes += n
		}
	}
	add(p.DHCPv6MsgType)
	if p.DHCPv6InnerType != p.DHCPv6MsgType && p.DHCPv6InnerType != 0 {
		add(p.DHCPv6InnerType)
	}
	if f.DHCPv6ClientID == "" {
		f.DHCPv6ClientID = p.DHCPv6ClientID
	}
	if f.DHCPv6ServerID == "" {
		f.DHCPv6ServerID = p.DHCPv6ServerID
	}
}

// dhcpv6Txn is a client message that expects an answer, with the first
// server message that answered it. A client repeats the transaction ID when it
// retransmits, and a server repeats it in its answer, together with the
// client's identifier; a relay agent passes both on unchanged.
type dhcpv6Txn struct {
	req      models.PacketInfo
	reqType  int
	client   string
	answered bool
	answerAt time.Time
	session  time.Time // the end of the capture session the request is in
}

// dhcpv6Response is one Advertise or Reply from a server.
type dhcpv6Response struct {
	p       models.PacketInfo
	server  string
	client  string
	forType string // the request it answers, by name
}

func dhcpv6Key(p models.PacketInfo) string {
	return fmt.Sprintf("%06x|%s", p.DHCPv6XID, p.DHCPv6ClientID)
}

// analyzeDHCPv6 reports problems getting IPv6 addresses and prefixes:
//   - DHCPv6 No Addresses Available (warning): an Advertise or Reply with
//     status NoAddrsAvail, NoBinding or NoPrefixAvail, in a Status Code option
//     of the message or of one of its IA options, one issue per server.
//   - DHCPv6 Configuration Error (warning): status NotOnLink, UseMulticast,
//     NotConfigured or NotAllowed, one issue per server.
//   - High DHCPv6 Failure Rate (warning): servers whose responses carried an
//     error status in more than 20% of cases (at least 10 responses), folded
//     into one issue.
//   - DHCPv6 Timeout (warning): a Solicit or Request that got no Advertise or
//     Reply within 30 seconds, one issue per destination.
//
// Requests and answers are matched by transaction ID and client identifier,
// not by flow: a client sends to a multicast address and the server answers
// from its own. A request is only called unanswered if the capture session it
// is in lasted 30 seconds beyond it.
func analyzeDHCPv6(packets []models.PacketInfo) []models.Issue {
	session := sessionEnds(packets)

	txns := make(map[string]*dhcpv6Txn)
	var order []*dhcpv6Txn
	var responses []dhcpv6Response

	for i, p := range packets {
		if p.DHCPv6MsgType == 0 {
			continue
		}
		key := dhcpv6Key(p)
		switch t := p.DHCPv6InnerType; t {
		case dhcpSolicit, dhcpRequest, dhcpConfirm, dhcpRenew, dhcpRebind, dhcpRelease, dhcpDecline, dhcpInfoRequest:
			if _, seen := txns[key]; seen {
				continue // a retransmission, or the same message seen on two legs of a relay
			}
			tx := &dhcpv6Txn{req: p, reqType: t, client: dhcpv6Client(p), session: session[i]}
			txns[key] = tx
			order = append(order, tx)
		case dhcpAdvertise, dhcpReply:
			r := dhcpv6Response{p: p, server: dhcpv6Server(p), client: dhcpv6Client(p), forType: dhcpv6MsgName(t)}
			if tx := txns[key]; tx != nil {
				r.forType = dhcpv6MsgName(tx.reqType)
				if !tx.answered {
					tx.answered, tx.answerAt = true, p.Timestamp
				}
			}
			responses = append(responses, r)
		}
	}

	var issues []models.Issue
	issues = append(issues, dhcpv6StatusIssues(responses, dhcpv6NoAddrs, titleDHCPv6NoAddrs, "dhcpv6-noaddrs-")...)
	issues = append(issues, dhcpv6StatusIssues(responses, dhcpv6Config, titleDHCPv6Config, "dhcpv6-config-")...)
	if is, ok := dhcpv6FailureRateIssue(responses); ok {
		issues = append(issues, is)
	}
	issues = append(issues, dhcpv6TimeoutIssues(order)...)
	return issues
}

// dhcpv6Client names the client of a message: its DUID, else the address it
// came from (or went to, in an answer).
func dhcpv6Client(p models.PacketInfo) string {
	if p.DHCPv6ClientID != "" {
		return p.DHCPv6ClientID
	}
	switch p.DHCPv6InnerType {
	case dhcpAdvertise, dhcpReply:
		return p.DstIP
	}
	return p.SrcIP
}

// dhcpv6Server names the server of an answer: its DUID, else its address.
func dhcpv6Server(p models.PacketInfo) string {
	if p.DHCPv6ServerID != "" {
		return p.DHCPv6ServerID
	}
	return p.SrcIP
}

// countedList renders counts as "a (2x), b" for the keys in order of
// frequency; a single entry seen once has no count.
func countedList(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k
		if len(keys) > 1 || counts[k] > 1 {
			parts[i] += fmt.Sprintf(" (%dx)", counts[k])
		}
	}
	return strings.Join(parts, ", ")
}

// dhcpv6StatusIssues builds one issue per server from the responses whose
// status code satisfies match.
func dhcpv6StatusIssues(responses []dhcpv6Response, match func(int) bool, title, idPrefix string) []models.Issue {
	groups := make(map[string][]dhcpv6Response)
	var order []string
	for _, r := range responses {
		if !match(r.p.DHCPv6StatusCode) {
			continue
		}
		if _, ok := groups[r.server]; !ok {
			order = append(order, r.server)
		}
		groups[r.server] = append(groups[r.server], r)
	}

	var issues []models.Issue
	for _, server := range order {
		g := groups[server]
		statuses, forTypes := make(map[string]int), make(map[string]int)
		first := g[0]
		for _, r := range g {
			statuses[dhcpv6StatusName(r.p.DHCPv6StatusCode)]++
			forTypes[r.forType]++
			if r.p.Timestamp.Before(first.p.Timestamp) {
				first = r
			}
		}
		desc := fmt.Sprintf("server %s returned %s for %s", server, countedList(statuses), countedList(forTypes))
		if len(g) == 1 && g[0].p.DHCPv6StatusMsg != "" {
			desc += fmt.Sprintf(": %q", g[0].p.DHCPv6StatusMsg)
		} else if len(g) > 1 {
			desc += fmt.Sprintf(" (%s)", count(len(g), "response", "responses"))
		}

		is := models.Issue{
			ID:          idPrefix + server,
			Severity:    models.SeverityWarning,
			Category:    "DHCPv6",
			Title:       title,
			Description: desc,
			Timestamp:   first.p.Timestamp,
			Target:      first.p.SrcIP,
			Count:       len(g),
		}
		for _, r := range g {
			is.Occurrences = append(is.Occurrences, models.Occurrence{Time: r.p.Timestamp, Subject: r.client, Value: float64(r.p.DHCPv6StatusCode)})
		}
		sort.SliceStable(is.Occurrences, func(i, j int) bool { return is.Occurrences[i].Time.Before(is.Occurrences[j].Time) })
		issues = append(issues, is)
	}
	return issues
}

// dhcpv6FailureRateIssue folds the servers whose responses failed too often
// into one issue.
func dhcpv6FailureRateIssue(responses []dhcpv6Response) (models.Issue, bool) {
	type rate struct {
		server        string
		first         time.Time
		total, failed int
	}
	byServer := make(map[string]*rate)
	var order []*rate
	for _, r := range responses {
		x := byServer[r.server]
		if x == nil {
			x = &rate{server: r.server, first: r.p.Timestamp}
			byServer[r.server] = x
			order = append(order, x)
		}
		x.total++
		if dhcpv6Error(r.p.DHCPv6StatusCode) {
			x.failed++
		}
	}
	var high []*rate
	for _, x := range order {
		if x.total >= dhcpv6MinResponses && x.failed*100 > dhcpv6FailPercent*x.total {
			high = append(high, x)
		}
	}
	if len(high) == 0 {
		return models.Issue{}, false
	}
	pct := func(x *rate) int { return (x.failed*100 + x.total/2) / x.total }
	sort.SliceStable(high, func(i, j int) bool {
		if a, b := high[i].failed*high[j].total, high[j].failed*high[i].total; a != b {
			return a > b // highest rate first
		}
		return high[i].server < high[j].server
	})

	is := models.Issue{ID: "dhcpv6-failure-rate", Severity: models.SeverityWarning, Category: "DHCPv6", Title: titleDHCPv6FailRate, Count: len(high)}
	for _, x := range high {
		is.Occurrences = append(is.Occurrences, models.Occurrence{Time: x.first, Subject: x.server, Value: float64(pct(x)), Unit: "%"})
		if is.Timestamp.IsZero() || x.first.Before(is.Timestamp) {
			is.Timestamp = x.first
		}
	}
	w := high[0]
	if len(high) == 1 {
		is.Target = w.server
		is.Description = fmt.Sprintf("%d%% of requests failed (%d of %d responses from server %s carried an error status)", pct(w), w.failed, w.total, w.server)
	} else {
		is.Description = fmt.Sprintf("%s fail more than %d%% of requests; the worst, %s, fails %d%% (%d of %d responses)",
			count(len(high), "DHCPv6 server", "DHCPv6 servers"), dhcpv6FailPercent, w.server, pct(w), w.failed, w.total)
	}
	return is, true
}

// dhcpv6TimeoutIssues folds the Solicits and Requests that were not answered
// in time into one issue per destination.
func dhcpv6TimeoutIssues(txns []*dhcpv6Txn) []models.Issue {
	groups := make(map[string][]*dhcpv6Txn)
	var order []string
	for _, tx := range txns {
		if tx.reqType != dhcpSolicit && tx.reqType != dhcpRequest {
			continue
		}
		late := tx.answered && tx.answerAt.Sub(tx.req.Timestamp) > dhcpv6Timeout
		unanswered := !tx.answered && tx.session.Sub(tx.req.Timestamp) >= dhcpv6Timeout
		if !late && !unanswered {
			continue
		}
		dst := tx.req.DstIP
		if _, ok := groups[dst]; !ok {
			order = append(order, dst)
		}
		groups[dst] = append(groups[dst], tx)
	}

	var issues []models.Issue
	for _, dst := range order {
		g := groups[dst]
		first := g[0]
		kinds := make(map[string]int)
		for _, tx := range g {
			kinds[dhcpv6MsgName(tx.reqType)]++
			if tx.req.Timestamp.Before(first.req.Timestamp) {
				first = tx
			}
		}
		is := models.Issue{
			ID:        "dhcpv6-timeout-" + dst,
			Severity:  models.SeverityWarning,
			Category:  "DHCPv6",
			Title:     titleDHCPv6Timeout,
			Timestamp: first.req.Timestamp,
			Target:    dst,
			Count:     len(g),
		}
		one := fmt.Sprintf("no reply to %s from client %s", dhcpv6MsgName(first.reqType), first.client)
		if first.answered {
			one = fmt.Sprintf("the reply to %s from client %s came only after %s", dhcpv6MsgName(first.reqType), first.client,
				first.answerAt.Sub(first.req.Timestamp).Round(time.Second))
		}
		if len(g) == 1 {
			is.Description = fmt.Sprintf("%s (sent to %s, waited %s)", one, dst, dhcpv6Timeout)
		} else {
			is.Description = fmt.Sprintf("%d requests to %s got no reply within %s: %s; first: %s", len(g), dst, dhcpv6Timeout, countedList(kinds), one)
		}
		for _, tx := range g {
			is.Occurrences = append(is.Occurrences, models.Occurrence{Time: tx.req.Timestamp, Subject: tx.client})
		}
		sort.SliceStable(is.Occurrences, func(i, j int) bool { return is.Occurrences[i].Time.Before(is.Occurrences[j].Time) })
		issues = append(issues, is)
	}
	return issues
}

// sessionGap is the longest silence inside one capture session. A larger gap,
// or time running backwards, means that captures were merged, and what follows
// says nothing about whether an earlier request was answered.
const sessionGap = time.Hour

// sessionEnds returns, for every packet, the time at which the capture session
// it is in ends: the timestamp of the last packet of the run that starts at
// it, in capture order, without a gap of more than sessionGap or a step back
// in time. Analyses that call a request unanswered use it to know whether the
// capture lasted long enough after the request to say so.
func sessionEnds(packets []models.PacketInfo) []time.Time {
	end := make([]time.Time, len(packets))
	for i := len(packets) - 1; i >= 0; i-- {
		end[i] = packets[i].Timestamp
		if i+1 < len(packets) {
			gap := packets[i+1].Timestamp.Sub(packets[i].Timestamp)
			if gap >= 0 && gap <= sessionGap {
				end[i] = end[i+1]
			}
		}
	}
	return end
}
