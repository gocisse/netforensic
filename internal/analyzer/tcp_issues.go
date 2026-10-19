package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the connection-reset issues.
const (
	titleRefused = "Connection Refused (Port Closed)"
	titleAborted = "Connection Abruptly Closed"
	titleIdle    = "Connection Idle Timeout"
	titleStray   = "Stray RST / Port Probe"

	titleZeroWindow      = "TCP Zero Window"
	titleZeroWindowReset = "Connection reset after zero-window stall"

	// idleResetGap is how long a connection must have been silent before an
	// RST is read as an idle-timeout cleanup rather than a failure.
	idleResetGap = 10 * time.Second
)

// connState follows one TCP connection (see models.ConnectionInstances).
type connState struct {
	id         string
	client     endpoint // sender of the first SYN; first sender if no SYN was captured
	server     endpoint
	sawSyn     bool
	sawSynAck  bool
	anySYN     bool // a SYN or SYN-ACK was seen, from either side
	fromServer bool // at least one packet travelled from the server to the client
	sawAck     bool // client ACK after the SYN-ACK: the handshake completed
	data       bool // payload seen in either direction
	fin        [2]bool
	// next is the end of the highest segment each side has sent (0 client,
	// 1 server) and haveNext that it is known; they tell keep-alive probes
	// from data. Only segments that occupy sequence space advance it.
	next       [2]uint32
	haveNext   [2]bool
	packets    int
	dataBytes  int
	lastData   time.Time // the last payload that is not a keep-alive probe
	rsts       int
	firstRST   models.PacketInfo
	rstFromCli bool

	zeroWindows    int // packets advertising a zero receive window
	firstZero      models.PacketInfo
	zeroFromClient bool      // the client was the receiver that ran out of buffer
	zeroReopened   time.Time // first window > 0 from the same receiver afterwards

	synFirst, synLast time.Time // first and last SYN from the client
	synTries          int       // SYNs sent before the SYN-ACK (or in total, if none came)
	synAckAt          time.Time

	firstReply    bool // the server's first packet after the SYN has been seen
	refusedByRST  bool // ...and it was an RST
	refusedAt     time.Time
	refusedPacket models.PacketInfo
}

// analyzeConnections classifies connections that saw a TCP RST or a zero
// receive window:
//   - Connection Refused (warning): the client sent a SYN and the server's
//     first reply was an RST, so no SYN-ACK was ever sent. Refusals are
//     folded into one issue per server ip:port, since a closed port or a
//     rejecting firewall refuses every attempt the same way.
//   - Connection Abruptly Closed (error): the connection had completed its
//     handshake or exchanged data and was then torn down by an RST, unless
//     both sides had already sent a FIN (a normal close followed by a stray
//     RST). One issue per connection.
//   - Connection Idle Timeout (info): the same, but the RST came more than
//     10 seconds after the last payload in either direction, which looks
//     like an idle-timeout cleanup rather than a failure.
//   - Stray RST / Port Probe (info): an RST on a connection whose SYN,
//     SYN-ACK and data were never captured, typically a reply to a port
//     probe or to a segment of a connection the sender no longer knows.
//     All of them are folded into one issue that names the destinations
//     (the hosts the RSTs were sent to) most often hit.
//   - TCP Zero Window (warning): a receiver advertised a window of 0, so the
//     sender had to stall until its buffer drained.
//   - Connection reset after zero-window stall (error): a zero window
//     followed by an RST on the same connection. It replaces the two issues
//     above, whichever RST classification would have applied.
func analyzeConnections(packets []models.PacketInfo) []models.Issue {
	conns := make(map[instKey]*connState)
	var order []instKey
	insts := models.ConnectionInstances(packets)

	for i, p := range packets {
		if p.Protocol != models.ProtocolTCP {
			continue
		}
		fk, _ := canonicalKey(p)
		k := instKey{fk, insts[i]}
		c := conns[k]
		if c == nil {
			c = &connState{id: k.id(), client: endpoint{p.SrcIP, p.SrcPort}, server: endpoint{p.DstIP, p.DstPort}}
			conns[k] = c
			order = append(order, k)
		}
		c.observe(p)
	}

	var captureEnd time.Time
	for _, p := range packets {
		if p.Timestamp.After(captureEnd) {
			captureEnd = p.Timestamp
		}
	}

	var issues []models.Issue
	var stray []*connState                   // RST with no handshake and no data captured
	refused := make(map[string][]*connState) // server ip:port -> refused connections
	var refusedOrder []string

	for _, k := range order {
		c := conns[k]
		stalledThenReset := c.zeroWindows > 0 && c.rsts > 0 && !c.firstRST.Timestamp.Before(c.firstZero.Timestamp)
		switch {
		case stalledThenReset:
			issues = append(issues, c.zeroWindowResetIssue())
		case c.refusedByRST:
			t := c.server.String()
			if _, ok := refused[t]; !ok {
				refusedOrder = append(refusedOrder, t)
			}
			refused[t] = append(refused[t], c)
		case c.rsts > 0 && !c.anySYN && !c.data:
			stray = append(stray, c)
		case c.rsts > 0 && c.established() && !(c.fin[0] && c.fin[1]):
			issues = append(issues, c.abortedIssue())
		}
		if c.zeroWindows > 0 && !stalledThenReset {
			issues = append(issues, c.zeroWindowIssue())
		}
	}
	for _, t := range refusedOrder {
		issues = append(issues, refusedIssue(t, refused[t]))
	}
	if len(stray) > 0 {
		issues = append(issues, strayRSTIssue(stray))
	}
	issues = append(issues, synIssues(conns, order, captureEnd)...)
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Timestamp.Before(issues[j].Timestamp) })
	return issues
}

// observe folds p into the connection state.
func (c *connState) observe(p models.PacketInfo) {
	c.packets++
	src := endpoint{p.SrcIP, p.SrcPort}
	fromClient := src == c.client
	if !fromClient {
		c.fromServer = true
	}
	flags := p.TCPFlags
	has := func(f string) bool { return hasTCPFlag(flags, f) }
	if has("SYN") {
		c.anySYN = true
	}

	switch {
	case has("SYN") && !has("ACK") && !c.sawSyn:
		c.sawSyn = true
		c.client, c.server = src, endpoint{p.DstIP, p.DstPort}
		fromClient = true
		c.synFirst, c.synLast, c.synTries = p.Timestamp, p.Timestamp, 1
	case has("SYN") && !has("ACK") && fromClient && !c.sawSynAck:
		c.synLast = p.Timestamp
		c.synTries++
	case has("SYN") && has("ACK") && !fromClient:
		if !c.sawSynAck {
			c.synAckAt = p.Timestamp
		}
		c.sawSynAck = true
	case has("ACK") && fromClient && c.sawSynAck && !c.sawAck && !has("RST"):
		c.sawAck = true
	}
	if has("FIN") {
		if fromClient {
			c.fin[0] = true
		} else {
			c.fin[1] = true
		}
	}
	// A zero window announces that the sender's buffer is full. SYN, FIN
	// and RST segments carry no meaningful window.
	if !has("SYN") && !has("FIN") && !has("RST") {
		switch {
		case p.TCPWindow == 0:
			c.zeroWindows++
			if c.zeroWindows == 1 {
				c.firstZero, c.zeroFromClient = p, fromClient
			}
		case c.zeroWindows > 0 && c.zeroReopened.IsZero() && fromClient == c.zeroFromClient:
			c.zeroReopened = p.Timestamp
		}
	}
	side := 1
	if fromClient {
		side = 0
	}
	if p.PayloadSize > 0 {
		c.data = true
		c.dataBytes += p.PayloadSize
		if !isKeepAlive(p, c.next[side], c.haveNext[side]) {
			c.lastData = p.Timestamp
		}
	}
	if consumesSeq(p) && !isKeepAlive(p, c.next[side], c.haveNext[side]) {
		if end := p.TCPSeq + seqLen(p); !c.haveNext[side] || int32(end-c.next[side]) > 0 {
			c.next[side], c.haveNext[side] = end, true
		}
	}

	if !fromClient && c.sawSyn && !c.firstReply && !c.sawSynAck {
		c.firstReply = true
		if has("RST") {
			c.refusedByRST, c.refusedAt, c.refusedPacket = true, p.Timestamp, p
		}
	}
	if has("RST") {
		c.rsts++
		if c.rsts == 1 {
			c.firstRST, c.rstFromCli = p, fromClient
		}
	}
}

// established reports whether the connection got past the handshake: all
// three steps were seen, or data flowed (which also covers captures that
// start mid-connection).
func (c *connState) established() bool {
	return (c.sawSynAck && c.sawAck) || c.data
}

// idleFor returns how long the connection had been silent when the first RST
// arrived, and whether any data had been exchanged at all.
func (c *connState) idleFor() (time.Duration, bool) {
	if c.lastData.IsZero() {
		return 0, false
	}
	return c.firstRST.Timestamp.Sub(c.lastData), true
}

func (c *connState) abortedIssue() models.Issue {
	who := c.server
	role := "server"
	if c.rstFromCli {
		who, role = c.client, "client"
	}
	p := c.firstRST
	desc := fmt.Sprintf("flow %s was reset by the %s (%s) at %s after %d packets and %d payload bytes",
		c.id, role, who.ip, p.Timestamp.UTC().Format("15:04:05.000"), c.packets-c.rsts, c.dataBytes)
	if !c.lastData.IsZero() {
		if gap := p.Timestamp.Sub(c.lastData); gap < time.Millisecond {
			desc += "; it came immediately after the last data"
		} else {
			desc += fmt.Sprintf("; the last data was %s earlier", gap.Round(time.Millisecond))
		}
	}
	if c.rsts > 1 {
		desc += fmt.Sprintf("; %d RST packets in total", c.rsts)
	}
	sev, title := models.SeverityError, titleAborted
	if idle, ok := c.idleFor(); ok && idle > idleResetGap {
		sev, title = models.SeverityInfo, titleIdle
		desc = fmt.Sprintf("flow %s was reset by the %s (%s) at %s, %s after the last data; likely a firewall, NAT or load-balancer idle timeout cleaning up an idle connection",
			c.id, role, who.ip, p.Timestamp.UTC().Format("15:04:05.000"), idle.Round(time.Millisecond))
	}
	return models.Issue{
		ID:          "reset-" + c.id,
		Severity:    sev,
		Category:    "Connection",
		Title:       title,
		Description: desc,
		Timestamp:   p.Timestamp,
		FlowID:      c.id,
		Target:      c.server.String(),
		Count:       1,
	}
}

// refusedIssue folds the refused connections to one server endpoint into a
// single issue.
func refusedIssue(target string, conns []*connState) models.Issue {
	first, last := conns[0].refusedAt, conns[0].refusedAt
	clients := make(map[string]struct{})
	for _, c := range conns {
		if c.refusedAt.Before(first) {
			first = c.refusedAt
		}
		if c.refusedAt.After(last) {
			last = c.refusedAt
		}
		clients[c.client.ip] = struct{}{}
	}

	var b strings.Builder
	n := len(conns)
	if n == 1 {
		fmt.Fprintf(&b, "%s answered the SYN from %s with an RST instead of a SYN-ACK", target, conns[0].client)
	} else {
		fmt.Fprintf(&b, "%d connection attempts from %d client(s) to %s were answered with an RST instead of a SYN-ACK (first %s, last %s)",
			n, len(clients), target, first.UTC().Format("15:04:05.000"), last.UTC().Format("15:04:05.000"))
	}
	is := models.Issue{
		Occurrences: connOccurrences(conns, func(c *connState) time.Time { return c.refusedAt }),
		ID:          "refused-" + target,
		Severity:    models.SeverityWarning,
		Category:    "Connection",
		Title:       titleRefused,
		Description: b.String(),
		Timestamp:   first,
		Target:      target,
		Count:       n,
	}
	if n == 1 {
		is.FlowID = conns[0].id
	}
	return is
}

// receiverSide names who ran out of buffer.
func (c *connState) receiverSide() (endpoint, string) {
	if c.zeroFromClient {
		return c.client, "client"
	}
	return c.server, "server"
}

// zeroWindowIssue reports a zero-window stall that did not end in a reset.
func (c *connState) zeroWindowIssue() models.Issue {
	rx, role := c.receiverSide()
	desc := fmt.Sprintf("Receiver buffer full, sender stalled: the %s (%s) advertised a zero window %d time(s) in flow %s, first at %s",
		role, rx.ip, c.zeroWindows, c.id, c.firstZero.Timestamp.UTC().Format("15:04:05.000"))
	if !c.zeroReopened.IsZero() {
		desc += fmt.Sprintf("; the window reopened %s later", c.zeroReopened.Sub(c.firstZero.Timestamp).Round(time.Millisecond))
	} else {
		desc += "; it never reopened in the capture"
	}
	return models.Issue{
		ID:          "zerowindow-" + c.id,
		Severity:    models.SeverityWarning,
		Category:    "Connection",
		Title:       titleZeroWindow,
		Description: desc,
		Timestamp:   c.firstZero.Timestamp,
		FlowID:      c.id,
		Target:      c.server.String(),
		Count:       c.zeroWindows,
	}
}

// zeroWindowResetIssue reports a connection that was reset after its
// receiver advertised a zero window.
func (c *connState) zeroWindowResetIssue() models.Issue {
	rx, role := c.receiverSide()
	by, byRole := c.server, "server"
	if c.rstFromCli {
		by, byRole = c.client, "client"
	}
	zero, rst := c.firstZero.Timestamp, c.firstRST.Timestamp
	desc := fmt.Sprintf("flow %s: the %s (%s) advertised a zero window %d time(s), first at %s",
		c.id, role, rx.ip, c.zeroWindows, zero.UTC().Format("15:04:05.000"))
	if !c.zeroReopened.IsZero() && c.zeroReopened.Before(rst) {
		// The stall had already ended when the reset came; saying only
		// "reset after the stall" would make the stall look like the cause.
		desc += fmt.Sprintf("; the window reopened at %s (%s later), but the %s (%s) reset the connection at %s, %s after it reopened",
			c.zeroReopened.UTC().Format("15:04:05.000"), c.zeroReopened.Sub(zero).Round(time.Millisecond),
			byRole, by.ip, rst.UTC().Format("15:04:05.000"), rst.Sub(c.zeroReopened).Round(time.Millisecond))
	} else {
		desc += fmt.Sprintf("; the window had not reopened when the %s (%s) reset the connection at %s, %s later",
			byRole, by.ip, rst.UTC().Format("15:04:05.000"), rst.Sub(zero).Round(time.Millisecond))
	}
	if c.rsts > 1 {
		desc += fmt.Sprintf("; %d RST packets in total", c.rsts)
	}
	return models.Issue{
		ID:          "zerowindow-reset-" + c.id,
		Severity:    models.SeverityError,
		Category:    "Connection",
		Title:       titleZeroWindowReset,
		Description: desc,
		Timestamp:   c.firstZero.Timestamp,
		FlowID:      c.id,
		Target:      c.server.String(),
		Count:       c.zeroWindows,
	}
}

// connOccurrences lists conns as occurrences: the connection's flow ID at the
// time at() gives, in capture order.
func connOccurrences(conns []*connState, at func(*connState) time.Time) []models.Occurrence {
	occ := make([]models.Occurrence, len(conns))
	for i, c := range conns {
		occ[i] = models.Occurrence{Time: at(c), Subject: c.id}
	}
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].Time.Before(occ[j].Time) })
	return occ
}

// strayRSTIssue folds connections that show nothing but an RST into one
// issue, grouped by the destination of the RST.
func strayRSTIssue(conns []*connState) models.Issue {
	byDst := make(map[string]int)
	srcs := make(map[string]struct{})
	occ := make([]models.Occurrence, len(conns))
	first := conns[0].firstRST.Timestamp
	for i, c := range conns {
		byDst[c.firstRST.DstIP]++
		srcs[c.firstRST.SrcIP] = struct{}{}
		occ[i] = models.Occurrence{Time: c.firstRST.Timestamp, Subject: c.id}
		if c.firstRST.Timestamp.Before(first) {
			first = c.firstRST.Timestamp
		}
	}
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].Time.Before(occ[j].Time) })
	top := topCounts(byDst, 3)
	parts := make([]string, len(top))
	for i, t := range top {
		parts[i] = fmt.Sprintf("%s (%d)", t.name, t.n)
	}
	label := "Top 3 destinations"
	if len(byDst) <= 3 {
		label = "Destinations"
	}
	return models.Issue{
		ID:        "stray-rst",
		Severity:  models.SeverityInfo,
		Category:  "Connection",
		Title:     titleStray,
		Timestamp: first,
		Target:    top[0].name,
		Count:     len(conns),
		Description: fmt.Sprintf("%s with no handshake or data captured, sent by %s to %s. %s. These are usually replies to port probes or to packets of connections the sender no longer knows.",
			count(len(conns), "RST", "RSTs"), count(len(srcs), "host", "hosts"), count(len(byDst), "destination", "destinations"), label+": "+strings.Join(parts, ", ")),
		Occurrences: occ,
	}
}
