// Package filter narrows an analysis to the flows and issues an engineer is
// looking at: by IP address, port, protocol, severity and category. The web UI
// applies the same rules in the browser (web/src/filters), and the web API's
// /api/export-csv applies them here, so a filtered export contains exactly what
// the page shows.
//
// Flows are bidirectional, so an IP filter matches either endpoint. An issue
// is tied to addresses and ports through what it refers to: its flow, its
// target and the subjects of its events, which are flow IDs or ip:port pairs
// for most issues. An issue that refers to no address (a slow HTTP response
// named by its domain, say) does not match an IP or port filter.
package filter

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// Limits on what a query may ask for.
const (
	maxPortRanges = 64
	maxListItems  = 32
)

// PortRange is an inclusive range of ports.
type PortRange struct{ Lo, Hi uint16 }

// Spec is a set of filters. A zero field filters nothing.
type Spec struct {
	SourceIP   string // normalized; "" for none
	DestIP     string
	Ports      []PortRange
	Protocol   string   // TCP, UDP, DNS, ...; "" or "All" for none
	Severities []string // empty for all
	Categories []string
}

// Query parameter names, shared with the web UI's URL.
const (
	ParamSourceIP = "source_ip"
	ParamDestIP   = "dest_ip"
	ParamPort     = "port"
	ParamProtocol = "protocol"
	ParamSeverity = "severity"
	ParamCategory = "category"
)

var validSeverities = map[string]bool{"CRITICAL": true, "ERROR": true, "WARNING": true, "INFO": true}

// Parse reads a Spec from query parameters. It returns an error naming the
// parameter if one is malformed.
func Parse(q url.Values) (Spec, error) {
	var s Spec
	var err error
	if s.SourceIP, err = parseIP(q.Get(ParamSourceIP)); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", ParamSourceIP, err)
	}
	if s.DestIP, err = parseIP(q.Get(ParamDestIP)); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", ParamDestIP, err)
	}
	if s.Ports, err = ParsePorts(q.Get(ParamPort)); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", ParamPort, err)
	}
	if p := strings.TrimSpace(q.Get(ParamProtocol)); p != "" && !strings.EqualFold(p, "all") {
		if len(p) > 32 || strings.ContainsAny(p, ",;\x00") {
			return Spec{}, fmt.Errorf("%s: not a protocol name", ParamProtocol)
		}
		s.Protocol = p
	}
	if s.Severities, err = parseList(q.Get(ParamSeverity), strings.ToUpper); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", ParamSeverity, err)
	}
	for _, sev := range s.Severities {
		if !validSeverities[sev] {
			return Spec{}, fmt.Errorf("%s: %q is not CRITICAL, ERROR, WARNING or INFO", ParamSeverity, sev)
		}
	}
	if s.Categories, err = parseList(q.Get(ParamCategory), nil); err != nil {
		return Spec{}, fmt.Errorf("%s: %w", ParamCategory, err)
	}
	return s, nil
}

// parseIP validates an IPv4 or IPv6 address and returns it in the form flows
// use. Empty is allowed and means no filter.
func parseIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", fmt.Errorf("%q is not an IPv4 or IPv6 address", s)
	}
	return ipKey(a), nil
}

// ipKey is the form in which addresses are compared: IPv4 (or IPv4-mapped
// IPv6) as dotted decimal, IPv6 fully expanded.
func ipKey(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	return a.StringExpanded()
}

// ParsePorts reads a comma-separated list of ports and ranges, such as
// "80,443,8000-9000". Empty means no filter.
func ParsePorts(s string) ([]PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty entry in %q", s)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		l, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		h := l
		if isRange {
			if h, err = parsePort(hi); err != nil {
				return nil, err
			}
			if h < l {
				return nil, fmt.Errorf("the range %q runs backwards", part)
			}
		}
		out = append(out, PortRange{l, h})
		if len(out) > maxPortRanges {
			return nil, fmt.Errorf("more than %d ports or ranges", maxPortRanges)
		}
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%q is not a port from 1 to 65535", s)
	}
	return uint16(n), nil
}

func parseList(s string, norm func(string) string) ([]string, error) {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if norm != nil {
			item = norm(item)
		}
		out = append(out, item)
		if len(out) > maxListItems {
			return nil, fmt.Errorf("more than %d values", maxListItems)
		}
	}
	return out, nil
}

// Active reports whether the spec filters anything.
func (s Spec) Active() bool {
	return s.SourceIP != "" || s.DestIP != "" || len(s.Ports) > 0 || s.Protocol != "" || len(s.Severities) > 0 || len(s.Categories) > 0
}

func (s Spec) portIn(p uint16) bool {
	for _, r := range s.Ports {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

// endpoint is an address with an optional port (0 if none).
type endpoint struct {
	ip   string // normalized
	port uint16
}

// involves reports whether eps satisfy the IP and port filters: every IP
// filter names an address in eps, and, if there is a port filter, some
// endpoint's port is in it.
func (s Spec) involves(eps []endpoint) bool {
	has := func(ip string) bool {
		for _, e := range eps {
			if e.ip == ip {
				return true
			}
		}
		return false
	}
	if s.SourceIP != "" && !has(s.SourceIP) {
		return false
	}
	if s.DestIP != "" && !has(s.DestIP) {
		return false
	}
	if len(s.Ports) > 0 {
		ok := false
		for _, e := range eps {
			if e.port != 0 && s.portIn(e.port) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (s Spec) hasEndpointFilter() bool {
	return s.SourceIP != "" || s.DestIP != "" || len(s.Ports) > 0
}

// MatchFlow reports whether f passes the IP, port and protocol filters. A
// protocol filter matches the flow's transport or application protocol.
func (s Spec) MatchFlow(f models.Flow) bool {
	if s.Protocol != "" && !strings.EqualFold(string(f.Protocol), s.Protocol) && !strings.EqualFold(f.AppProtocol, s.Protocol) &&
		!(f.Protocol == "" && strings.EqualFold(s.Protocol, "Other")) {
		return false
	}
	if !s.hasEndpointFilter() {
		return true
	}
	var eps []endpoint
	for _, e := range []struct {
		ip   string
		port uint16
	}{{f.SrcIP, f.SrcPort}, {f.DstIP, f.DstPort}} {
		if a, err := netip.ParseAddr(e.ip); err == nil {
			eps = append(eps, endpoint{ipKey(a), e.port})
		}
	}
	return s.involves(eps)
}

// MatchIssue reports whether is passes all the filters. Capture notes, which
// describe the file and not the traffic, never do.
func (s Spec) MatchIssue(is models.Issue) bool {
	if is.Category == "Capture" && is.Severity == models.SeverityInfo {
		return false
	}
	if len(s.Severities) > 0 && !contains(s.Severities, string(is.Severity)) {
		return false
	}
	if len(s.Categories) > 0 && !containsFold(s.Categories, is.Category) {
		return false
	}
	if s.Protocol != "" && !containsFold(is.Protocols, s.Protocol) {
		return false
	}
	if !s.hasEndpointFilter() {
		return true
	}
	return s.involves(issueEndpoints(is))
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// issueEndpoints collects the addresses an issue refers to: its flow ID, its
// target and the subjects of its events.
func issueEndpoints(is models.Issue) []endpoint {
	refs := []string{is.FlowID, is.Target}
	for _, o := range is.Occurrences {
		refs = append(refs, o.Subject)
	}
	var eps []endpoint
	for _, r := range refs {
		eps = append(eps, parseRef(r)...)
	}
	return eps
}

// parseRef reads the addresses out of a reference to a flow ("ip:port-ip:port",
// with an optional "#N" and "@tunnel" suffix) or to an endpoint ("ip:port",
// "[ip6]:port" or just "ip"). It returns nothing for anything else, such as a
// domain name or a Call-ID.
func parseRef(ref string) []endpoint {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if e, ok := parseEndpoint(ref); ok {
		return []endpoint{e}
	}
	// a flow ID: drop the tunnel and connection number, then split the two
	// endpoints at a dash that leaves a valid endpoint on each side
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "#"); i >= 0 {
		ref = ref[:i]
	}
	for i := 0; i < len(ref); i++ {
		if ref[i] != '-' {
			continue
		}
		a, okA := parseEndpoint(ref[:i])
		b, okB := parseEndpoint(ref[i+1:])
		if okA && okB {
			return []endpoint{a, b}
		}
	}
	return nil
}

func parseEndpoint(s string) (endpoint, bool) {
	var host, port string
	switch {
	case strings.HasPrefix(s, "["): // [ip6] or [ip6]:port
		end := strings.Index(s, "]")
		if end < 0 {
			return endpoint{}, false
		}
		host = s[1:end]
		if rest := s[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return endpoint{}, false
			}
			port = rest[1:]
		}
	case strings.Count(s, ":") == 1: // ip4:port
		host, port, _ = strings.Cut(s, ":")
	default: // ip4, or a bare ip6
		host = s
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return endpoint{}, false
	}
	e := endpoint{ip: ipKey(a)}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return endpoint{}, false
		}
		e.port = uint16(n)
	}
	return e, true
}

// Apply returns a copy of res narrowed to what passes the filters: the flows
// that match, the issues that match, and the protocol distribution of those
// flows. The health score, root cause and everything else describe the whole
// capture and stay as they are. An inactive spec returns res itself.
func (s Spec) Apply(res *models.AnalysisResult) *models.AnalysisResult {
	if !s.Active() {
		return res
	}
	out := *res
	out.Flows = nil
	for _, f := range res.Flows {
		if s.MatchFlow(f) {
			out.Flows = append(out.Flows, f)
		}
	}
	out.Issues = []models.Issue{}
	for _, is := range res.Issues {
		if s.MatchIssue(is) {
			out.Issues = append(out.Issues, is)
		}
	}
	out.TotalFlows = len(out.Flows)
	out.ProtocolStats = ProtocolStats(out.Flows)
	return &out
}

// ProtocolStats computes the protocol distribution of flows: packets, flows
// and share of the packets per protocol, most packets first. Every flow counts
// towards its transport protocol (an unnamed one is "Other") and also towards
// its application protocol, so the application protocols overlap the transport
// ones, as in the analysis itself. The busiest flows are not filled in.
func ProtocolStats(flows []models.Flow) []models.ProtocolStat {
	type acc struct {
		layer         string
		packets, flow int
	}
	by := make(map[string]*acc)
	total := 0
	add := func(name, layer string, packets int) {
		a := by[name]
		if a == nil {
			a = &acc{layer: layer}
			by[name] = a
		}
		a.packets += packets
		a.flow++
	}
	for _, f := range flows {
		total += f.PacketCount
		name := string(f.Protocol)
		if name == "" {
			name = "Other"
		}
		add(name, "transport", f.PacketCount)
		if f.AppProtocol != "" {
			add(f.AppProtocol, "application", f.PacketCount)
		}
	}
	stats := make([]models.ProtocolStat, 0, len(by))
	for name, a := range by {
		pct := 0.0
		if total > 0 {
			pct = float64(int(float64(a.packets)*1000/float64(total)+0.5)) / 10
		}
		stats = append(stats, models.ProtocolStat{Protocol: name, Layer: a.layer, Packets: a.packets, Flows: a.flow, Percent: pct, TopFlows: []models.Flow{}})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Packets != stats[j].Packets {
			return stats[i].Packets > stats[j].Packets
		}
		return stats[i].Protocol < stats[j].Protocol
	})
	return stats
}
