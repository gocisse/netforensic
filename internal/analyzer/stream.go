package analyzer

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	streamPayloadPreview = 100 // bytes of generic payload shown per packet
	maxStreamHeaderLines = 20
)

// FlowSummary describes one flow present in a capture.
type FlowSummary struct {
	ID       string
	Protocol models.Protocol
	Packets  int
}

// StreamEvent is one packet of a followed conversation, with its
// protocol-level interpretation.
type StreamEvent struct {
	Timestamp time.Time
	ToServer  bool   // true if sent by the client (the flow's first sender)
	Kind      string // "DNS", "HTTP", "TLS", or the transport/network protocol
	Packet    models.PacketInfo
	Summary   string   // one-line description
	Detail    []string // extra lines such as HTTP headers and body preview
	Payload   []byte   // first bytes of payload for generic TCP/UDP traffic

	Retransmit bool // TCP segment that repeats an already-seen sequence number
}

// Conversation is the reconstructed packet exchange of a single flow.
type Conversation struct {
	FlowID string
	Client string // "ip:port" of the first sender
	Server string
	Events []StreamEvent // packet-level view, filled by Follow

	// Messages is the reconstructed application-level view, filled by
	// FollowStream. Retransmits counts the duplicate segments it dropped.
	Messages    []StreamMessage
	Retransmits int
}

// FollowError reports why a flow could not be followed and lists the flows
// that are available.
type FollowError struct {
	Reason    string
	Available []FlowSummary
}

func (e *FollowError) Error() string { return e.Reason }

// ListFlows returns the distinct flows in packets, busiest first.
func ListFlows(packets []models.PacketInfo) []FlowSummary {
	counts := make(map[instKey]int)
	insts := models.ConnectionInstances(packets)
	for i, p := range packets {
		fk, _ := canonicalKey(p)
		counts[instKey{fk, insts[i]}]++
	}
	out := make([]FlowSummary, 0, len(counts))
	for key, n := range counts {
		out = append(out, FlowSummary{ID: key.id(), Protocol: key.proto, Packets: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

// parseFlowID parses "ip:port-ip:port" with optional "#N" and "/PROTO"
// suffixes (for example "10.0.0.1:1234-10.0.0.2:80#2/TCP"). "#N" selects
// the Nth connection (N >= 1) when the 4-tuple was reused; inst is the
// zero-based index, 0 if absent. The protocol is empty if the suffix is
// absent. Endpoints are returned in canonical order.
func parseFlowID(id string) (a, b endpoint, proto models.Protocol, inst int, err error) {
	bad := func(why string) error {
		return fmt.Errorf("invalid flow ID %q: %s (expected ip:port-ip:port[/proto], IPv6 as [ip]:port)", id, why)
	}

	rest := strings.TrimSpace(id)
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		proto = models.Protocol(strings.ToUpper(rest[i+1:]))
		rest = rest[:i]
		switch proto {
		case models.ProtocolTCP, models.ProtocolUDP, models.ProtocolICMP, models.ProtocolARP:
		default:
			return a, b, "", 0, bad("unknown protocol " + strconv.Quote(string(proto)))
		}
	}

	if i := strings.LastIndex(rest, "#"); i >= 0 {
		n, convErr := strconv.Atoi(rest[i+1:])
		if convErr != nil || n < 1 {
			return a, b, "", 0, bad(strconv.Quote(rest[i+1:]) + " is not a valid connection number")
		}
		inst = n - 1
		rest = rest[:i]
	}

	parts := strings.Split(rest, "-")
	if len(parts) != 2 {
		return a, b, "", 0, bad("need exactly one '-' between the two endpoints")
	}
	var eps [2]endpoint
	for i, part := range parts {
		var ip, portStr string
		if strings.HasPrefix(part, "[") { // [ipv6]:port
			end := strings.Index(part, "]")
			if end < 0 || end+1 >= len(part) || part[end+1] != ':' {
				return a, b, "", 0, bad(strconv.Quote(part) + " has no port after the closing bracket")
			}
			ip, portStr = part[1:end], part[end+2:]
		} else {
			c := strings.LastIndex(part, ":")
			if c < 0 {
				return a, b, "", 0, bad(strconv.Quote(part) + " has no port")
			}
			ip, portStr = part[:c], part[c+1:] // also accepts an unbracketed IPv6 address
		}
		if net.ParseIP(ip) == nil {
			return a, b, "", 0, bad(strconv.Quote(ip) + " is not an IP address")
		}
		port, convErr := strconv.ParseUint(portStr, 10, 16)
		if convErr != nil {
			return a, b, "", 0, bad(strconv.Quote(portStr) + " is not a valid port")
		}
		eps[i] = endpoint{ip, uint16(port)}
	}
	if eps[1].less(eps[0]) {
		eps[0], eps[1] = eps[1], eps[0]
	}
	return eps[0], eps[1], proto, inst, nil
}

// matchFlow returns the packets of the flow named by flowID, in either
// direction and in chronological order, together with its conversation
// header. The returned error is a *FollowError listing the available flows
// if flowID is malformed or matches nothing.
func matchFlow(packets []models.PacketInfo, flowID string) ([]models.PacketInfo, *Conversation, error) {
	a, b, proto, inst, err := parseFlowID(flowID)
	if err != nil {
		return nil, nil, &FollowError{Reason: err.Error(), Available: ListFlows(packets)}
	}

	var matched []models.PacketInfo
	insts := models.ConnectionInstances(packets)
	for i, p := range packets {
		key, _ := canonicalKey(p)
		if key.a == a && key.b == b && (proto == "" || key.proto == proto) && insts[i] == inst {
			matched = append(matched, p)
		}
	}
	if len(matched) == 0 {
		return nil, nil, &FollowError{Reason: fmt.Sprintf("flow %q not found in the capture", flowID), Available: ListFlows(packets)}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Timestamp.Before(matched[j].Timestamp) })

	client := endpoint{matched[0].SrcIP, matched[0].SrcPort}
	server := endpoint{matched[0].DstIP, matched[0].DstPort}
	return matched, &Conversation{FlowID: instKey{flowKey{a, b, matched[0].Protocol}, inst}.id(), Client: client.String(), Server: server.String()}, nil
}

// isFromClient reports whether p was sent by the conversation's client.
func (c *Conversation) isFromClient(p models.PacketInfo) bool {
	return (endpoint{p.SrcIP, p.SrcPort}).String() == c.Client
}

// Follow returns the packet-by-packet conversation of the flow named by
// flowID, with retransmitted segments marked. The returned error is a
// *FollowError listing the available flows if flowID is malformed or
// matches nothing.
func Follow(packets []models.PacketInfo, flowID string) (*Conversation, error) {
	matched, conv, err := matchFlow(packets, flowID)
	if err != nil {
		return nil, err
	}
	var rd retransmitDetector
	for _, p := range matched {
		ev := describePacket(p)
		ev.ToServer = conv.isFromClient(p)
		key, forward := canonicalKey(p)
		ev.Retransmit = rd.observe(instKey{key, 0}, forward, p).retrans
		conv.Events = append(conv.Events, ev)
	}
	return conv, nil
}

// describePacket interprets p at the application level.
func describePacket(p models.PacketInfo) StreamEvent {
	ev := StreamEvent{Timestamp: p.Timestamp, Packet: p, Kind: string(p.Protocol)}

	switch {
	case p.DNSQueryName != "":
		ev.Kind = "DNS"
		if p.DNSIsQuery {
			ev.Summary = fmt.Sprintf("query %s (%s)", p.DNSQueryName, p.DNSResponseType)
		} else {
			ev.Summary = fmt.Sprintf("response %s %s", p.DNSQueryName, p.DNSResponseCode)
			if len(p.DNSAnswers) > 0 {
				ev.Summary += ": " + strings.Join(p.DNSAnswers, ", ")
			} else {
				ev.Summary += ": no answers"
			}
		}

	case p.HTTPMethod != "" || p.HTTPStatusCode != 0:
		ev.Kind = "HTTP"
		if p.HTTPMethod != "" {
			ev.Summary = p.HTTPMethod + " " + p.HTTPURI
		} else {
			ev.Summary = fmt.Sprintf("status %d", p.HTTPStatusCode)
		}
		ev.Detail = httpDetail(p.PayloadPreview)

	case p.TLSHandshakeType != "":
		ev.Kind = "TLS"
		ev.Summary = p.TLSHandshakeType
		switch {
		case p.TLSHandshakeType == "Alert":
			ev.Summary = fmt.Sprintf("Alert %s %s", p.TLSAlertLevel, p.TLSAlertDescription)
		case p.TLSVersion != "":
			ev.Summary += " (" + p.TLSVersion + ")"
		}

	case p.Protocol == models.ProtocolICMP:
		ev.Summary = p.ICMPMessage

	case p.Protocol == models.ProtocolARP:
		if p.ARPOperation == "request" {
			ev.Summary = fmt.Sprintf("who has %s? tell %s", p.ARPTargetIP, p.ARPSenderIP)
		} else {
			ev.Summary = fmt.Sprintf("%s is at %s", p.ARPSenderIP, p.ARPSenderMAC)
		}

	default:
		if p.PayloadSize > 0 {
			ev.Payload = p.PayloadPreview
			if len(ev.Payload) > streamPayloadPreview {
				ev.Payload = ev.Payload[:streamPayloadPreview]
			}
		}
	}
	return ev
}

// httpDetail returns the header lines of an HTTP message preview followed by
// a printable preview of the body, if any.
func httpDetail(payload []byte) []string {
	text := string(payload)
	head, body, hasBody := strings.Cut(text, "\r\n\r\n")
	if !hasBody {
		head, body, hasBody = strings.Cut(text, "\n\n")
	}

	lines := strings.Split(strings.ReplaceAll(head, "\r", ""), "\n")
	var out []string
	if len(lines) > 1 {
		for _, l := range lines[1:] { // lines[0] is the request or status line
			if len(out) == maxStreamHeaderLines {
				out = append(out, "...")
				break
			}
			out = append(out, l)
		}
	}
	if hasBody && body != "" {
		if len(body) > streamPayloadPreview {
			body = body[:streamPayloadPreview]
		}
		out = append(out, "body: "+printable(body))
	}
	return out
}

// printable replaces non-printable bytes with '.'.
func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '.'
		}
	}
	return string(b)
}
