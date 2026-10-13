package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the DHCP (IPv4) issues.
const (
	titleDHCPNak         = "DHCP NAK"
	titleDHCPTimeout     = "DHCP Timeout"
	titleDHCPFailRate    = "High DHCP Failure Rate"
	titleDHCPExhaustion  = "Possible DHCP Address Exhaustion"
	dhcpOfferTimeout     = 10 * time.Second // how long a Discover may wait for an Offer
	dhcpMinRequests      = 5                // fewest requests for a failure rate to mean anything
	dhcpFailPercent      = 20               // a share of NAK'd requests above this is a high failure rate
	dhcpExhaustionNaks   = 3                // NAKs from one server that suggest an exhausted pool
	dhcpDiscover         = 1
	dhcpOffer            = 2
	dhcp4Request         = 3
	dhcpAck              = 5
	dhcpNak              = 6
	dhcpClientNameFormat = "xid %#x" // names a client whose hardware address is not known
)

var dhcpMsgNames = map[int]string{
	1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "Ack", 6: "Nak", 7: "Release", 8: "Inform",
}

func dhcpMsgName(t int) string {
	if n, ok := dhcpMsgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

// dhcpFromServer reports whether a DHCP message type is one that a server sends.
func dhcpFromServer(t int) bool { return t == dhcpOffer || t == dhcpAck || t == dhcpNak }

// noteDHCP adds the DHCP details of p, if it carries any, to flow f.
func noteDHCP(f *models.Flow, p models.PacketInfo) {
	d := p.DHCP
	if d == nil {
		return
	}
	if n := dhcpMsgName(d.MsgType); !strings.Contains(","+f.DHCPMessageTypes+",", ","+n+",") {
		if f.DHCPMessageTypes != "" {
			f.DHCPMessageTypes += ","
		}
		f.DHCPMessageTypes += n
	}
	if f.DHCPClientMAC == "" {
		f.DHCPClientMAC = d.ClientMAC
	}
	if f.DHCPServerIP == "" {
		if d.ServerID != "" {
			f.DHCPServerIP = d.ServerID
		} else if dhcpFromServer(d.MsgType) {
			f.DHCPServerIP = p.SrcIP
		}
	}
}

// dhcpKey identifies a DHCP transaction: a client repeats its transaction ID
// when it retransmits, and a server answers with it.
func dhcpKey(d *models.DHCPInfo) string {
	return fmt.Sprintf("%08x|%s", d.XID, d.ClientMAC)
}

// dhcpClient names the client of a message: its hardware address, else its
// transaction ID.
func dhcpClient(d *models.DHCPInfo) string {
	if d.ClientMAC != "" {
		return d.ClientMAC
	}
	return fmt.Sprintf(dhcpClientNameFormat, d.XID)
}

// dhcpServer names the server of a message: its Server Identifier option, else
// the address that sent it.
func dhcpServer(p models.PacketInfo) string {
	if p.DHCP.ServerID != "" {
		return p.DHCP.ServerID
	}
	return p.SrcIP
}

type dhcpDiscoverTxn struct {
	req      models.PacketInfo
	client   string
	answered bool
	answerAt time.Time
	session  time.Time // the end of the capture session the Discover is in
}

type dhcpNakMsg struct {
	p      models.PacketInfo
	server string
	client string
}

// analyzeDHCP reports problems getting IPv4 addresses:
//   - DHCP NAK (warning): a server refused a client's request with a NAK, one
//     issue per server, with the reason the server gave.
//   - Possible DHCP Address Exhaustion (warning): a server sent at least 3
//     NAKs, one issue per server.
//   - High DHCP Failure Rate (warning): more than 20% of the requests were
//     NAK'd (out of at least 5), one issue for the capture.
//   - DHCP Timeout (warning): a Discover that got no Offer within 10 seconds,
//     one issue per destination.
//
// Requests and answers are matched by transaction ID and client hardware
// address, not by flow: a client broadcasts and the server answers from its
// own address. A Discover is only called unanswered if the capture session it
// is in lasted 10 seconds beyond it.
func analyzeDHCP(packets []models.PacketInfo) []models.Issue {
	var session []time.Time // computed only if the capture has a Discover

	discovers := make(map[string]*dhcpDiscoverTxn)
	var order []*dhcpDiscoverTxn
	requests := make(map[string]struct{})
	nakSeen := make(map[string]struct{})
	nakKeys := make(map[string]struct{})
	var naks []dhcpNakMsg

	for i, p := range packets {
		d := p.DHCP
		if d == nil {
			continue
		}
		key := dhcpKey(d)
		switch d.MsgType {
		case dhcpDiscover:
			if _, seen := discovers[key]; seen {
				continue // a retransmission, or the same message seen on two legs of a relay
			}
			if session == nil {
				session = sessionEnds(packets)
			}
			tx := &dhcpDiscoverTxn{req: p, client: dhcpClient(d), session: session[i]}
			discovers[key] = tx
			order = append(order, tx)
		case dhcpOffer:
			if tx := discovers[key]; tx != nil && !tx.answered {
				tx.answered, tx.answerAt = true, p.Timestamp
			}
		case dhcp4Request:
			requests[key] = struct{}{}
		case dhcpNak:
			server := dhcpServer(p)
			nk := key + "|" + server
			if _, seen := nakSeen[nk]; seen {
				continue
			}
			nakSeen[nk] = struct{}{}
			nakKeys[key] = struct{}{}
			naks = append(naks, dhcpNakMsg{p: p, server: server, client: dhcpClient(d)})
		}
	}

	var issues []models.Issue
	byServer, servers := groupNaks(naks)
	issues = append(issues, dhcpNakIssues(byServer, servers)...)
	issues = append(issues, dhcpExhaustionIssues(byServer, servers)...)
	if is, ok := dhcpFailureRateIssue(requests, nakKeys, byServer, servers); ok {
		issues = append(issues, is)
	}
	issues = append(issues, dhcpTimeoutIssues(order)...)
	return issues
}

// groupNaks groups NAKs by the server that sent them, the servers in the order
// of their first NAK.
func groupNaks(naks []dhcpNakMsg) (map[string][]dhcpNakMsg, []string) {
	byServer := make(map[string][]dhcpNakMsg)
	var servers []string
	for _, n := range naks {
		if _, ok := byServer[n.server]; !ok {
			servers = append(servers, n.server)
		}
		byServer[n.server] = append(byServer[n.server], n)
	}
	return byServer, servers
}

// dhcpNakOccurrences lists the NAKs of a server, by time, each naming its client.
func dhcpNakOccurrences(g []dhcpNakMsg) []models.Occurrence {
	occ := make([]models.Occurrence, len(g))
	for i, n := range g {
		occ[i] = models.Occurrence{Time: n.p.Timestamp, Subject: n.client}
	}
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].Time.Before(occ[j].Time) })
	return occ
}

func firstNak(g []dhcpNakMsg) dhcpNakMsg {
	first := g[0]
	for _, n := range g {
		if n.p.Timestamp.Before(first.p.Timestamp) {
			first = n
		}
	}
	return first
}

// dhcpNakIssues builds one issue per server that sent a NAK.
func dhcpNakIssues(byServer map[string][]dhcpNakMsg, servers []string) []models.Issue {
	var issues []models.Issue
	for _, server := range servers {
		g := byServer[server]
		first := firstNak(g)
		is := models.Issue{
			ID:          "dhcp-nak-" + server,
			Severity:    models.SeverityWarning,
			Category:    "DHCP",
			Title:       titleDHCPNak,
			Timestamp:   first.p.Timestamp,
			Target:      server,
			Count:       len(g),
			Occurrences: dhcpNakOccurrences(g),
		}
		if len(g) == 1 {
			is.Description = fmt.Sprintf("server %s refused address request from %s", server, first.client)
			if m := first.p.DHCP.Message; m != "" {
				is.Description += ": " + m
			}
		} else {
			clients, reasons := make(map[string]struct{}), make(map[string]int)
			for _, n := range g {
				clients[n.client] = struct{}{}
				if m := n.p.DHCP.Message; m != "" {
					reasons[m]++
				}
			}
			is.Description = fmt.Sprintf("server %s refused %d address requests from %s", server, len(g), count(len(clients), "client", "clients"))
			if len(reasons) > 0 {
				is.Description += ": " + countedList(reasons)
			}
		}
		issues = append(issues, is)
	}
	return issues
}

// dhcpExhaustionIssues builds one issue per server that sent several NAKs.
func dhcpExhaustionIssues(byServer map[string][]dhcpNakMsg, servers []string) []models.Issue {
	var issues []models.Issue
	for _, server := range servers {
		g := byServer[server]
		if len(g) < dhcpExhaustionNaks {
			continue
		}
		clients := make(map[string]struct{})
		for _, n := range g {
			clients[n.client] = struct{}{}
		}
		issues = append(issues, models.Issue{
			ID:          "dhcp-exhaustion-" + server,
			Severity:    models.SeverityWarning,
			Category:    "DHCP",
			Title:       titleDHCPExhaustion,
			Description: fmt.Sprintf("server %s sent %d NAKs to %s", server, len(g), count(len(clients), "client", "clients")),
			Timestamp:   firstNak(g).p.Timestamp,
			Target:      server,
			Count:       len(g),
			Occurrences: dhcpNakOccurrences(g),
		})
	}
	return issues
}

// dhcpFailureRateIssue reports a high share of NAK'd requests. A NAK whose
// request was not captured counts as a request too.
func dhcpFailureRateIssue(requests, nakKeys map[string]struct{}, byServer map[string][]dhcpNakMsg, servers []string) (models.Issue, bool) {
	total := len(requests)
	for k := range nakKeys {
		if _, ok := requests[k]; !ok {
			total++
		}
	}
	failed := len(nakKeys)
	if total < dhcpMinRequests || failed*100 <= dhcpFailPercent*total {
		return models.Issue{}, false
	}
	pct := (failed*100 + total/2) / total
	is := models.Issue{
		ID:          "dhcp-failure-rate",
		Severity:    models.SeverityWarning,
		Category:    "DHCP",
		Title:       titleDHCPFailRate,
		Description: fmt.Sprintf("%d%% of requests were NAK'd (%d of %d requests)", pct, failed, total),
		Count:       failed,
	}
	for _, server := range servers {
		g := byServer[server]
		first := firstNak(g)
		is.Occurrences = append(is.Occurrences, models.Occurrence{Time: first.p.Timestamp, Subject: server, Value: float64(len(g)), Unit: "NAKs"})
		if is.Timestamp.IsZero() || first.p.Timestamp.Before(is.Timestamp) {
			is.Timestamp = first.p.Timestamp
		}
	}
	if len(servers) == 1 {
		is.Target = servers[0]
	}
	return is, true
}

// dhcpTimeoutIssues folds the Discovers that got no Offer in time into one
// issue per destination.
func dhcpTimeoutIssues(txns []*dhcpDiscoverTxn) []models.Issue {
	groups := make(map[string][]*dhcpDiscoverTxn)
	var order []string
	for _, tx := range txns {
		late := tx.answered && tx.answerAt.Sub(tx.req.Timestamp) > dhcpOfferTimeout
		unanswered := !tx.answered && tx.session.Sub(tx.req.Timestamp) >= dhcpOfferTimeout
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
		for _, tx := range g {
			if tx.req.Timestamp.Before(first.req.Timestamp) {
				first = tx
			}
		}
		is := models.Issue{
			ID:        "dhcp-timeout-" + dst,
			Severity:  models.SeverityWarning,
			Category:  "DHCP",
			Title:     titleDHCPTimeout,
			Timestamp: first.req.Timestamp,
			Target:    dst,
			Count:     len(g),
		}
		one := fmt.Sprintf("no offer to discover from %s", first.client)
		if first.answered {
			one = fmt.Sprintf("the offer to discover from %s came only after %s", first.client, first.answerAt.Sub(first.req.Timestamp).Round(time.Second))
		}
		if len(g) == 1 {
			is.Description = fmt.Sprintf("%s (sent to %s, waited %s)", one, dst, dhcpOfferTimeout)
		} else {
			is.Description = fmt.Sprintf("%d discovers to %s got no offer within %s; first: %s", len(g), dst, dhcpOfferTimeout, one)
		}
		for _, tx := range g {
			is.Occurrences = append(is.Occurrences, models.Occurrence{Time: tx.req.Timestamp, Subject: tx.client})
		}
		sort.SliceStable(is.Occurrences, func(i, j int) bool { return is.Occurrences[i].Time.Before(is.Occurrences[j].Time) })
		issues = append(issues, is)
	}
	return issues
}
