package analyzer

import (
	"fmt"
	"sort"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Event names of a flow timeline.
const (
	evStart       = "Connection start (SYN)"
	evHandshake   = "Handshake complete"
	evFirstData   = "First data transfer"
	evZeroWindow  = "Zero Window"
	evWindowOpen  = "Window reopened"
	evReset       = "Connection reset (RST)"
	evResetClosed = "Reset after close (RST)"
	evClosed      = "Connection closed (FIN)"
	evSynRetry    = "SYN retransmitted"
	evMore        = "More retransmissions"

	// maxTimelineRetransmits is how many retransmissions a flow timeline
	// lists one by one; a flow can have thousands, and the rest are
	// summarized in one entry.
	maxTimelineRetransmits = 10

	// maxFallbackIssues is how many issues a flow whose timeline has no
	// problem of its own (a slow response, say) is given entries for.
	maxFallbackIssues = 5
)

// tlEvent is a timeline entry under construction.
type tlEvent struct {
	models.FlowEvent
	problem   bool // something went wrong here: a candidate for the first issue
	trimmable bool // may be left out when there are very many (retransmissions)
}

// retryKey identifies a retransmitted SYN among the flow's retransmissions.
type retryKey struct {
	at  time.Time
	seq uint32
}

// tlConn follows one TCP connection to build its timeline.
type tlConn struct {
	client            endpoint
	events            []tlEvent
	sawSyn, sawSynAck bool
	sawAck, data      bool
	fin               [2]bool
	finSeen           bool
	synAt             time.Time
	synTries          int
	synRetries        map[retryKey]int // SYN retransmissions -> attempt number
	packets           int
	stall             int // index+1 of the open zero-window event, or 0
	stallStart        time.Time
	stallPackets      int
	stallClient       bool
	rst               int // index+1 of the reset event, or 0
	rstPackets        int
}

// annotateTimelines gives every TCP flow that has issues a Timeline: the
// connection start, the first data, what went wrong (retransmissions, zero
// windows, resets) and how the connection ended, in time order, with the
// first problem marked. Flows are matched to packets the way aggregateFlows
// does. Flows whose packets show no problem of their own get entries for the
// issues that name them.
func annotateTimelines(packets []models.PacketInfo, flows []models.Flow, issues []models.Issue) {
	wanted := make(map[string]int)
	for i := range flows {
		f := &flows[i]
		if f.Protocol == models.ProtocolTCP && (f.IssueCount > 0 || f.Retransmits > 0) {
			wanted[f.ID] = i
		}
	}
	if len(wanted) == 0 {
		return
	}

	conns := make(map[instKey]*tlConn)
	byFlow := make(map[int]*tlConn)
	insts := models.ConnectionInstances(packets)
	for i, p := range packets {
		if p.Protocol != models.ProtocolTCP {
			continue
		}
		fk, _ := canonicalKey(p)
		k := instKey{fk, insts[i]}
		c, seen := conns[k]
		if !seen {
			if idx, ok := wanted[k.id()]; ok {
				c = &tlConn{client: endpoint{p.SrcIP, p.SrcPort}}
				byFlow[idx] = c
			}
			conns[k] = c
		}
		if c != nil {
			c.observe(p)
		}
	}

	byIssueFlow := make(map[string][]models.Issue)
	for _, is := range issues {
		if is.Category == "Capture" {
			continue
		}
		for _, id := range flowIDs(is) {
			byIssueFlow[id] = append(byIssueFlow[id], is)
		}
	}
	for idx, c := range byFlow {
		f := &flows[idx]
		f.Timeline = c.finish(*f, byIssueFlow[f.ID])
	}
}

// role names an endpoint as "client (ip)" or "server (ip)".
func (c *tlConn) role(e endpoint) string {
	if e == c.client {
		return "client (" + e.ip + ")"
	}
	return "server (" + e.ip + ")"
}

func (c *tlConn) add(ts time.Time, name string, sev models.Severity, desc string) int {
	c.events = append(c.events, tlEvent{FlowEvent: models.FlowEvent{Timestamp: ts, Event: name, Severity: sev, Description: desc}})
	return len(c.events)
}

// observe folds one packet of the connection into the timeline.
func (c *tlConn) observe(p models.PacketInfo) {
	c.packets++
	src, dst := endpoint{p.SrcIP, p.SrcPort}, endpoint{p.DstIP, p.DstPort}
	fromClient := src == c.client
	has := func(f string) bool { return hasTCPFlag(p.TCPFlags, f) }

	switch {
	case has("SYN") && !has("ACK"):
		if !c.sawSyn {
			c.sawSyn = true
			c.client, fromClient = src, true
			c.synAt, c.synTries = p.Timestamp, 1
			c.add(p.Timestamp, evStart, models.SeverityInfo, fmt.Sprintf("client %s sent a SYN to %s", src, dst))
		} else if fromClient && !c.sawSynAck {
			c.synTries++
			if c.synRetries == nil {
				c.synRetries = make(map[retryKey]int)
			}
			c.synRetries[retryKey{p.Timestamp, p.TCPSeq}] = c.synTries
		}
	case has("SYN") && has("ACK") && !fromClient:
		c.sawSynAck = true
	case has("ACK") && fromClient && c.sawSynAck && !c.sawAck && !has("RST"):
		c.sawAck = true
		c.add(p.Timestamp, evHandshake, models.SeverityInfo,
			fmt.Sprintf("three-way handshake finished %s after the first SYN", p.Timestamp.Sub(c.synAt).Round(time.Microsecond)))
	}

	if p.PayloadSize > 0 && !c.data {
		c.data = true
		c.add(p.Timestamp, evFirstData, models.SeverityInfo,
			fmt.Sprintf("%s sent %d bytes of data to %s", c.role(src), p.PayloadSize, dst))
	}

	// Window: SYN, FIN and RST segments carry no meaningful window.
	if !has("SYN") && !has("FIN") && !has("RST") {
		switch {
		case p.TCPWindow == 0 && c.stall == 0:
			c.stallStart, c.stallPackets, c.stallClient = p.Timestamp, 1, fromClient
			c.stall = c.add(p.Timestamp, evZeroWindow, models.SeverityWarning,
				fmt.Sprintf("%s advertised a receive window of 0: it asked the sender to pause sending new data", c.role(src)))
			c.events[c.stall-1].problem = true
		case p.TCPWindow == 0 && fromClient == c.stallClient:
			c.stallPackets++
		case p.TCPWindow > 0 && c.stall != 0 && fromClient == c.stallClient:
			if c.stallPackets > 1 {
				c.events[c.stall-1].Description += fmt.Sprintf(" (%d zero-window packets in this stall)", c.stallPackets)
			}
			c.add(p.Timestamp, evWindowOpen, models.SeverityInfo,
				fmt.Sprintf("%s reopened its window %s after closing it", c.role(src), p.Timestamp.Sub(c.stallStart).Round(time.Millisecond)))
			c.stall = 0
		}
	}

	if has("FIN") {
		if fromClient {
			c.fin[0] = true
		} else {
			c.fin[1] = true
		}
		if !c.finSeen {
			c.finSeen = true
			c.add(p.Timestamp, evClosed, models.SeverityInfo, fmt.Sprintf("%s sent a FIN to close the connection", c.role(src)))
		}
	}

	if has("RST") {
		c.rstPackets++
		if c.rst == 0 {
			if c.fin[0] && c.fin[1] {
				c.rst = c.add(p.Timestamp, evResetClosed, models.SeverityInfo,
					fmt.Sprintf("%s sent an RST after both sides had closed the connection", c.role(src)))
			} else {
				desc := fmt.Sprintf("%s reset the connection after %d packets", c.role(src), c.packets-1)
				if c.stall != 0 {
					desc += fmt.Sprintf("; its zero-window stall had lasted %s and was still open", p.Timestamp.Sub(c.stallStart).Round(time.Millisecond))
				}
				c.rst = c.add(p.Timestamp, evReset, models.SeverityError, desc)
				c.events[c.rst-1].problem = true
			}
		}
	}
}

// finish adds the retransmissions of f, orders the events, trims the
// retransmissions and marks the first problem. issues are the issues that
// name the flow.
func (c *tlConn) finish(f models.Flow, issues []models.Issue) []models.FlowEvent {
	if c.rst != 0 && c.rstPackets > 1 {
		c.events[c.rst-1].Description += fmt.Sprintf("; %d RST packets in total", c.rstPackets)
	}
	if c.stall != 0 && c.stallPackets > 1 {
		c.events[c.stall-1].Description += fmt.Sprintf(" (%d zero-window packets, the window never reopened in the capture)", c.stallPackets)
	} else if c.stall != 0 {
		c.events[c.stall-1].Description += " (it never reopened in the capture)"
	}

	for _, r := range f.RetransmitEvents {
		ev := tlEvent{problem: true, trimmable: true}
		ev.Timestamp = r.Time
		switch {
		case c.synRetries[retryKey{r.Time, r.Seq}] > 0:
			ev.Event, ev.Severity = evSynRetry, models.SeverityWarning
			ev.Description = fmt.Sprintf("no SYN-ACK yet: the SYN was sent again (attempt %d)", c.synRetries[retryKey{r.Time, r.Seq}])
		case r.Kind == retransTimeout.String():
			ev.Event, ev.Severity = titleTimeoutRetransmit, models.SeverityError
			ev.Description = fmt.Sprintf("seq %d resent after the flow had been silent for over %s with no duplicate ACKs", r.Seq, rtoSilence)
		case r.Kind == retransFast.String():
			ev.Event, ev.Severity = titleFastRetransmit, models.SeverityWarning
			ev.Description = fmt.Sprintf("seq %d resent after %d or more duplicate ACKs for the same byte", r.Seq, fastRetransmitDupAcks)
		case r.Kind == retransFast.String()+"-recovery" || r.Kind == retransTimeout.String()+"-recovery":
			ev.Event, ev.Severity = "Retransmit (recovery)", models.SeverityWarning
			ev.Description = fmt.Sprintf("seq %d resent as part of an ongoing %s recovery", r.Seq, r.Kind[:len(r.Kind)-len("-recovery")])
		default:
			ev.Event, ev.Severity = "Retransmission", models.SeverityWarning
			ev.Description = fmt.Sprintf("seq %d was sent again", r.Seq)
		}
		c.events = append(c.events, ev)
	}

	// No problem seen in the packets (for example a slow response): fall back
	// to the issues that name the flow, so the timeline still says what is wrong.
	hasProblem := false
	for _, e := range c.events {
		hasProblem = hasProblem || e.problem
	}
	if !hasProblem {
		for i, is := range issues {
			if i == maxFallbackIssues {
				break
			}
			ev := tlEvent{problem: is.Severity != models.SeverityInfo}
			ev.Timestamp, ev.Event, ev.Severity = issueTimeFor(is, f.ID), is.Title, is.Severity
			ev.Description = "reported as an issue; see the issue card below"
			c.events = append(c.events, ev)
		}
	}

	sort.SliceStable(c.events, func(i, j int) bool { return c.events[i].Timestamp.Before(c.events[j].Timestamp) })

	var kept []tlEvent
	retrans, omitted := 0, 0
	var lastOmitted time.Time
	worst := models.SeverityWarning
	for _, e := range c.events {
		if e.trimmable {
			retrans++
			if retrans > maxTimelineRetransmits {
				omitted++
				lastOmitted = e.Timestamp
				if severityRank(e.Severity) > severityRank(worst) {
					worst = e.Severity
				}
				continue
			}
		}
		kept = append(kept, e)
	}
	if omitted > 0 {
		kept = append(kept, tlEvent{FlowEvent: models.FlowEvent{
			Timestamp: lastOmitted, Event: evMore, Severity: worst,
			Description: fmt.Sprintf("%d more retransmissions up to this time are not listed; the Wireshark filter shows them all", omitted),
		}})
		sort.SliceStable(kept, func(i, j int) bool { return kept[i].Timestamp.Before(kept[j].Timestamp) })
	}

	// The first problem is the earliest event that is one; events that are
	// only informational (the start, the data, a FIN) are never marked.
	out := make([]models.FlowEvent, len(kept))
	marked := false
	for i, e := range kept {
		out[i] = e.FlowEvent
		if e.problem && !marked {
			out[i].FirstIssue, marked = true, true
		}
	}
	return out
}

// issueTimeFor returns when issue is about flow id: the time of the matching
// occurrence of an aggregated issue, else the issue's own time.
func issueTimeFor(is models.Issue, id string) time.Time {
	for _, o := range is.Occurrences {
		if o.Subject == id {
			return o.Time
		}
	}
	return is.Timestamp
}
