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
	sawAck     bool // client ACK after the SYN-ACK: the handshake completed
	data       bool // payload seen in either direction
	fin        [2]bool
	packets    int
	dataBytes  int
	lastData   time.Time
	rsts       int
	firstRST   models.PacketInfo
	rstFromCli bool

	firstReply    bool // the server's first packet after the SYN has been seen
	refusedByRST  bool // ...and it was an RST
	refusedAt     time.Time
	refusedPacket models.PacketInfo
}

// analyzeResets classifies connections that saw a TCP RST:
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
func analyzeResets(packets []models.PacketInfo) []models.Issue {
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

	var issues []models.Issue
	refused := make(map[string][]*connState) // server ip:port -> refused connections
	var refusedOrder []string

	for _, k := range order {
		c := conns[k]
		switch {
		case c.refusedByRST:
			t := c.server.String()
			if _, ok := refused[t]; !ok {
				refusedOrder = append(refusedOrder, t)
			}
			refused[t] = append(refused[t], c)
		case c.rsts > 0 && c.established() && !(c.fin[0] && c.fin[1]):
			issues = append(issues, c.abortedIssue())
		}
	}
	for _, t := range refusedOrder {
		issues = append(issues, refusedIssue(t, refused[t]))
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Timestamp.Before(issues[j].Timestamp) })
	return issues
}

// observe folds p into the connection state.
func (c *connState) observe(p models.PacketInfo) {
	c.packets++
	src := endpoint{p.SrcIP, p.SrcPort}
	fromClient := src == c.client
	flags := p.TCPFlags
	has := func(f string) bool { return hasTCPFlag(flags, f) }

	switch {
	case has("SYN") && !has("ACK") && !c.sawSyn:
		c.sawSyn = true
		c.client, c.server = src, endpoint{p.DstIP, p.DstPort}
		fromClient = true
	case has("SYN") && has("ACK") && !fromClient:
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
	if p.PayloadSize > 0 {
		c.data = true
		c.dataBytes += p.PayloadSize
		c.lastData = p.Timestamp
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
