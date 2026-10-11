package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// Titles of the QUIC issues.
const (
	titleQUICVersionNeg = "QUIC Version Negotiation"
	titleQUICRetry      = "QUIC Retry"
	titleQUICTimeout    = "QUIC Handshake Timeout"
	titleQUICDraft      = "QUIC Draft Version"

	// quicHandshakeTimeout is how long a client Initial may wait for any
	// answer from the server.
	quicHandshakeTimeout = 10 * time.Second
)

const (
	quicTypeInitial = "Initial"
	quicTypeRetry   = "Retry"
	quicTypeVerNeg  = "Version Negotiation"
)

// noteQUIC adds the QUIC details of p, if it carries any, to flow f: the
// version of the first packet that names one, and each long-header packet
// type seen, in order.
func noteQUIC(f *models.Flow, p models.PacketInfo) {
	if !p.QUICLongHeader {
		return
	}
	// A Version Negotiation packet has no version of its own; it only
	// describes the flow until a packet with a real version turns up.
	if p.QUICVersion != models.QUICVersionNegotiation {
		if f.QUICVersion == "" || f.QUICVersion == quicTypeVerNeg {
			f.QUICVersion = models.QUICVersionName(p.QUICVersion)
		}
	} else if f.QUICVersion == "" {
		f.QUICVersion = quicTypeVerNeg
	}
	for _, t := range strings.Split(p.QUICPacketTypes, ",") {
		if t != "" && !strings.Contains(","+f.QUICPacketTypes+",", ","+t+",") {
			if f.QUICPacketTypes != "" {
				f.QUICPacketTypes += ","
			}
			f.QUICPacketTypes += t
		}
	}
}

func hasQUICType(p models.PacketInfo, typ string) bool {
	for _, t := range strings.Split(p.QUICPacketTypes, ",") {
		if t == typ {
			return true
		}
	}
	return false
}

// quicFlow is what is known about the handshake on one UDP flow.
type quicFlow struct {
	id        string
	client    string // ip:port of the sender of the first client Initial
	server    string
	firstInit models.PacketInfo
	initIdx   int
	initials  int       // client Initial packets sent
	answered  bool      // the server sent anything back
	answerAt  time.Time // when it first did
	version   uint32    // version of the client's first Initial
}

// analyzeQUIC reports handshake problems that show in the long headers of
// QUIC, whose payloads are encrypted:
//   - QUIC Version Negotiation (info): a server answered a client's version
//     with a list of its own, one issue per server.
//   - QUIC Retry (info): a server asked a client to prove its address, one
//     issue per server.
//   - QUIC Handshake Timeout (warning): a client Initial that got no packet at
//     all from the server within 10 seconds, one issue per server.
//   - QUIC Draft Version (info): a client using a draft version, one issue per
//     draft.
//
// The client of a flow is the sender of its first Initial packet, unless that
// came from port 443, in which case the capture started after the handshake
// began and the other side is the client. A client Initial counts as answered
// by any packet back from the server on the flow, a Version Negotiation or
// Retry included. It is only called unanswered if the capture session it is in
// lasted 10 seconds beyond it (see sessionEnds).
func analyzeQUIC(packets []models.PacketInfo) []models.Issue {
	anyQUIC := false
	for _, p := range packets {
		if p.QUICLongHeader {
			anyQUIC = true
			break
		}
	}
	if !anyQUIC {
		return nil
	}

	insts := models.ConnectionInstances(packets)
	session := sessionEnds(packets)
	flows := make(map[string]*quicFlow)
	var order []*quicFlow
	initialVersion := make(map[string]uint32) // "scid|dcid" of a client Initial -> its version

	var verNegs, retries []quicEvent
	drafts := make(map[int]map[string]quicEvent) // draft number -> flow -> first event

	for i, p := range packets {
		if p.Protocol != models.ProtocolUDP {
			continue
		}
		fk, _ := canonicalKey(p)
		id := instKey{fk, insts[i]}.id()
		src, dst := endpoint{p.SrcIP, p.SrcPort}.String(), endpoint{p.DstIP, p.DstPort}.String()
		fl := flows[id]

		if p.QUICLongHeader && hasQUICType(p, quicTypeInitial) && (fl == nil || fl.client == "") {
			fromServerPort := p.SrcPort == 443 && p.DstPort != 443
			if !fromServerPort {
				if fl == nil {
					fl = &quicFlow{id: id}
					flows[id] = fl
					order = append(order, fl)
				}
				fl.client, fl.server = src, dst
				fl.firstInit, fl.initIdx, fl.version = p, i, p.QUICVersion
			}
		}
		// Version Negotiation and Retry come from servers, and are reported
		// even if the client's Initial was not captured.
		if p.QUICLongHeader && (hasQUICType(p, quicTypeVerNeg) || hasQUICType(p, quicTypeRetry)) && quicFromServer(fl, p, src) {
			e := quicEvent{p: p, flow: id, client: dst, server: src}
			if hasQUICType(p, quicTypeVerNeg) {
				// the version the client asked for is that of the Initial
				// whose connection IDs the packet echoes, else of the first
				// Initial on the flow
				if v, ok := initialVersion[p.QUICDCID+"|"+p.QUICSCID]; ok {
					e.requested, e.haveRequested = v, true
				} else if fl != nil && fl.initials > 0 {
					e.requested, e.haveRequested = fl.version, true
				}
				verNegs = append(verNegs, e)
			} else {
				retries = append(retries, e)
			}
		}
		if fl == nil {
			continue
		}
		if p.QUICLongHeader && src == fl.client {
			if hasQUICType(p, quicTypeInitial) {
				fl.initials++
				initialVersion[p.QUICSCID+"|"+p.QUICDCID] = p.QUICVersion
			}
			if d, isDraft := models.QUICDraft(p.QUICVersion); isDraft {
				if drafts[d] == nil {
					drafts[d] = make(map[string]quicEvent)
				}
				if _, seen := drafts[d][id]; !seen {
					drafts[d][id] = quicEvent{p: p, flow: id, client: src, server: dst}
				}
			}
		}
		if src == fl.server && !fl.answered {
			fl.answered, fl.answerAt = true, p.Timestamp
		}
	}

	var issues []models.Issue
	issues = append(issues, quicVersionNegIssues(verNegs)...)
	issues = append(issues, quicRetryIssues(retries)...)
	issues = append(issues, quicTimeoutIssues(order, session)...)
	issues = append(issues, quicDraftIssues(drafts)...)
	return issues
}

// quicEvent is one packet of interest, with the endpoints of its flow.
type quicEvent struct {
	p              models.PacketInfo
	flow           string
	client, server string

	// For Version Negotiation: the version the client asked for, if known.
	requested     uint32
	haveRequested bool
}

// quicFromServer reports whether p, sent from src, came from the server of its
// flow. Where the flow's client is not known (its Initial was not captured),
// the side that uses port 443 is the server, and a packet to port 443 is the
// client's.
func quicFromServer(fl *quicFlow, p models.PacketInfo, src string) bool {
	if fl != nil && fl.client != "" {
		return src == fl.server
	}
	return !(p.DstPort == 443 && p.SrcPort != 443)
}

// byServer groups events by server endpoint, in order of first appearance.
func byServer(events []quicEvent) (map[string][]quicEvent, []string) {
	groups := make(map[string][]quicEvent)
	var order []string
	for _, e := range events {
		if _, ok := groups[e.server]; !ok {
			order = append(order, e.server)
		}
		groups[e.server] = append(groups[e.server], e)
	}
	return groups, order
}

func quicOccurrences(events []quicEvent) []models.Occurrence {
	occ := make([]models.Occurrence, len(events))
	for i, e := range events {
		occ[i] = models.Occurrence{Time: e.p.Timestamp, Subject: e.flow}
	}
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].Time.Before(occ[j].Time) })
	return occ
}

func firstEvent(events []quicEvent) quicEvent {
	first := events[0]
	for _, e := range events[1:] {
		if e.p.Timestamp.Before(first.p.Timestamp) {
			first = e
		}
	}
	return first
}

func versionNames(vs []uint32) string {
	names := make([]string, len(vs))
	for i, v := range vs {
		names[i] = models.QUICVersionName(v)
	}
	return strings.Join(names, ", ")
}

// quicVersionNegIssues builds one issue per server that sent Version
// Negotiation. The version the client asked for was worked out when the packet
// was seen: that of the Initial whose connection IDs it echoes (its destination
// ID is the client's source ID and the reverse), or of the first Initial on
// the flow.
func quicVersionNegIssues(events []quicEvent) []models.Issue {
	groups, order := byServer(events)
	var issues []models.Issue
	for _, server := range order {
		g := groups[server]
		requested := make(map[string]int)
		var offered []uint32
		seen := make(map[uint32]bool)
		for _, e := range g {
			name := "an unknown version"
			if e.haveRequested {
				name = models.QUICVersionName(e.requested)
			}
			requested[name]++
			for _, v := range e.p.QUICOfferedVersions {
				if !seen[v] {
					seen[v] = true
					offered = append(offered, v)
				}
			}
		}
		offer := versionNames(offered)
		if offer == "" {
			offer = "no version"
		}
		desc := fmt.Sprintf("client requested %s, server offered %s (server %s)", countedList(requested), offer, server)
		if len(g) > 1 {
			desc = fmt.Sprintf("%d Version Negotiation packets from server %s: client requested %s; server offered %s", len(g), server, countedList(requested), offer)
		}
		issues = append(issues, models.Issue{
			ID: "quic-version-negotiation-" + server, Severity: models.SeverityInfo, Category: "QUIC", Title: titleQUICVersionNeg,
			Description: desc, Timestamp: firstEvent(g).p.Timestamp, Target: server, Count: len(g), Occurrences: quicOccurrences(g),
		})
	}
	return issues
}

// quicRetryIssues builds one issue per server that sent Retry packets.
func quicRetryIssues(events []quicEvent) []models.Issue {
	groups, order := byServer(events)
	var issues []models.Issue
	for _, server := range order {
		g := groups[server]
		desc := fmt.Sprintf("server requested address validation (Retry from server %s to client %s)", server, g[0].client)
		if len(g) > 1 {
			desc = fmt.Sprintf("server requested address validation (%d Retry packets from server %s)", len(g), server)
		}
		issues = append(issues, models.Issue{
			ID: "quic-retry-" + server, Severity: models.SeverityInfo, Category: "QUIC", Title: titleQUICRetry,
			Description: desc, Timestamp: firstEvent(g).p.Timestamp, Target: server, Count: len(g), Occurrences: quicOccurrences(g),
		})
	}
	return issues
}

// quicTimeoutIssues builds one issue per server whose clients' Initial
// packets went unanswered (or were answered only after the timeout).
func quicTimeoutIssues(flows []*quicFlow, session []time.Time) []models.Issue {
	groups := make(map[string][]*quicFlow)
	var order []string
	for _, fl := range flows {
		if fl.initials == 0 {
			continue
		}
		start := fl.firstInit.Timestamp
		late := fl.answered && fl.answerAt.Sub(start) > quicHandshakeTimeout
		silent := !fl.answered && session[fl.initIdx].Sub(start) >= quicHandshakeTimeout
		if !late && !silent {
			continue
		}
		if _, ok := groups[fl.server]; !ok {
			order = append(order, fl.server)
		}
		groups[fl.server] = append(groups[fl.server], fl)
	}

	var issues []models.Issue
	for _, server := range order {
		g := groups[server]
		first := g[0]
		sent := 0
		for _, fl := range g {
			sent += fl.initials
			if fl.firstInit.Timestamp.Before(first.firstInit.Timestamp) {
				first = fl
			}
		}
		what := "no server response to Client Initial"
		if first.answered {
			what = fmt.Sprintf("the server answered the Client Initial only after %s", first.answerAt.Sub(first.firstInit.Timestamp).Round(time.Second))
		}
		is := models.Issue{
			ID: "quic-timeout-" + server, Severity: models.SeverityWarning, Category: "QUIC", Title: titleQUICTimeout,
			Timestamp: first.firstInit.Timestamp, Target: server, Count: len(g),
		}
		if len(g) == 1 {
			is.FlowID = first.id
			is.Description = fmt.Sprintf("%s (from %s to %s, %s, waited %s)", what, first.client, server, count(sent, "Initial packet", "Initial packets"), quicHandshakeTimeout)
		} else {
			is.Description = fmt.Sprintf("%d client connections to %s got no server response within %s (%s sent); first: %s from %s",
				len(g), server, quicHandshakeTimeout, count(sent, "Initial packet", "Initial packets"), what, first.client)
		}
		for _, fl := range g {
			is.Occurrences = append(is.Occurrences, models.Occurrence{Time: fl.firstInit.Timestamp, Subject: fl.id})
		}
		sort.SliceStable(is.Occurrences, func(i, j int) bool { return is.Occurrences[i].Time.Before(is.Occurrences[j].Time) })
		issues = append(issues, is)
	}
	return issues
}

// quicDraftIssues builds one issue per draft version that clients used.
func quicDraftIssues(drafts map[int]map[string]quicEvent) []models.Issue {
	nums := make([]int, 0, len(drafts))
	for d := range drafts {
		nums = append(nums, d)
	}
	sort.Ints(nums)
	var issues []models.Issue
	for _, d := range nums {
		var events []quicEvent
		for _, e := range drafts[d] {
			events = append(events, e)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].flow < events[j].flow })
		first := firstEvent(events)
		clients := make(map[string]struct{})
		for _, e := range events {
			clients[e.p.SrcIP] = struct{}{}
		}
		desc := fmt.Sprintf("client using draft-%d (%s to %s)", d, first.client, first.server)
		if len(events) > 1 {
			desc = fmt.Sprintf("%s using draft-%d, an early version of QUIC that servers may drop (%d connections; first: %s to %s)",
				count(len(clients), "client", "clients"), d, len(events), first.client, first.server)
		}
		issues = append(issues, models.Issue{
			ID: fmt.Sprintf("quic-draft-%d", d), Severity: models.SeverityInfo, Category: "QUIC", Title: titleQUICDraft,
			Description: desc, Timestamp: first.p.Timestamp, Target: first.server, Count: len(events), Occurrences: quicOccurrences(events),
		})
	}
	return issues
}
