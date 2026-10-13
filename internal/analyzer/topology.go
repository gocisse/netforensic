package analyzer

import (
	"net/netip"
	"sort"

	"github.com/gocisse/netforensic/internal/filter"
	"github.com/gocisse/netforensic/internal/models"
)

// Limits of BuildTopology: a graph of more nodes than a person can read, or a
// browser can lay out, helps nobody.
const (
	// DefaultTopologyNodes is how many nodes a topology keeps unless told otherwise.
	DefaultTopologyNodes = 500
	// MaxTopologyNodes is the most nodes a topology may keep.
	MaxTopologyNodes = 2000
	// topologyEdgesPerNode bounds the edges to this many per kept node.
	topologyEdgesPerNode = 4
)

// topologyAddr writes an address in one form, so that flows and the references
// issues make to them agree; anything that is not an address is returned as is.
func topologyAddr(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

// serverSide says which end of a flow is the server and which the client, or
// returns "" if it cannot tell. A DNS flow's server has port 53 and a DHCP
// flow's port 67; otherwise it is the end with a well-known port (below 1024)
// when the other end has none. A flow lists its lesser endpoint first, so its
// order says nothing.
func serverSide(f models.Flow) (server, client string) {
	src, dst := topologyAddr(f.SrcIP), topologyAddr(f.DstIP)
	isServerPort := wellKnownPort
	switch f.AppProtocol {
	case string(models.ProtocolDNS):
		isServerPort = func(p uint16) bool { return p == 53 }
	case string(models.ProtocolDHCP):
		isServerPort = func(p uint16) bool { return p == 67 }
	}
	s, d := isServerPort(f.SrcPort), isServerPort(f.DstPort)
	switch {
	case s && !d:
		return src, dst
	case d && !s:
		return dst, src
	}
	return "", ""
}

// wellKnownPort reports whether a port is one a server listens on.
func wellKnownPort(p uint16) bool { return p > 0 && p < 1024 }

type topoPair struct{ a, b string } // a < b

func pairOf(x, y string) topoPair {
	if y < x {
		x, y = y, x
	}
	return topoPair{x, y}
}

type topoNode struct {
	models.TopologyNode
	protocols map[string]int
	dns, dhcp bool // seen as the server of such a flow
	servers   int  // flows in which it is the well-known-port side
	clients   int
}

type topoEdge struct {
	a, b       string
	sent, recv int64 // bytes from a to b, and from b to a
	packets    int
	protocols  map[string]int
	issues     int
	worst      models.Severity
}

// issueRefs maps what the issues name, per issue, to the addresses and the
// address pairs of the capture.
func issueRefs(issues []models.Issue, node func(string) *topoNode, edge func(x, y string) *topoEdge) {
	for _, is := range issues {
		if isNote(is) {
			continue
		}
		seenNode := make(map[string]struct{})
		seenEdge := make(map[topoPair]struct{})
		visit := func(ref string) {
			eps := filter.ParseRef(ref)
			var ips []string
			for _, e := range eps {
				ips = append(ips, topologyAddr(e.IP))
			}
			for _, ip := range ips {
				if _, ok := seenNode[ip]; ok {
					continue
				}
				seenNode[ip] = struct{}{}
				if n := node(ip); n != nil {
					n.IssueCount++
					n.WorstSeverity = worseSeverity(n.WorstSeverity, is.Severity)
				}
			}
			if len(ips) == 2 {
				p := pairOf(ips[0], ips[1])
				if _, ok := seenEdge[p]; ok {
					return
				}
				seenEdge[p] = struct{}{}
				if e := edge(ips[0], ips[1]); e != nil {
					e.issues++
					e.worst = worseSeverity(e.worst, is.Severity)
				}
			}
		}
		visit(is.FlowID)
		visit(is.Target)
		for _, o := range is.Occurrences {
			visit(o.Subject)
		}
	}
}

// worseSeverity returns the more severe of two severities ("" is the least).
func worseSeverity(a, b models.Severity) models.Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// BuildTopology turns the flows and issues of a capture into a graph: a node
// per address with its role, traffic, protocols and the issues that name it,
// and an edge per pair of addresses with the traffic between them (pointing the
// way most of the bytes go) and the issues on it. At most maxNodes nodes are
// kept (DefaultTopologyNodes if it is not positive, never more than
// MaxTopologyNodes): the busiest half, then the ones with the worst issues,
// then the rest by traffic. Only edges between kept nodes are returned.
func BuildTopology(flows []models.Flow, issues []models.Issue, maxNodes int) models.Topology {
	if maxNodes <= 0 {
		maxNodes = DefaultTopologyNodes
	}
	if maxNodes > MaxTopologyNodes {
		maxNodes = MaxTopologyNodes
	}

	nodes := make(map[string]*topoNode)
	edges := make(map[topoPair]*topoEdge)
	getNode := func(ip string) *topoNode {
		n := nodes[ip]
		if n == nil {
			n = &topoNode{TopologyNode: models.TopologyNode{IP: ip}, protocols: make(map[string]int)}
			nodes[ip] = n
		}
		return n
	}

	for _, f := range flows {
		src, dst := topologyAddr(f.SrcIP), topologyAddr(f.DstIP)
		if src == "" || dst == "" || src == dst {
			continue
		}
		proto := f.AppProtocol
		if proto == "" {
			proto = string(f.Protocol)
		}
		bytes := int64(f.BytesSent + f.BytesRecv)
		for _, ip := range []string{src, dst} {
			n := getNode(ip)
			n.TrafficVolume += bytes
			n.Packets += f.PacketCount
			if proto != "" {
				n.protocols[proto] += f.PacketCount
			}
		}
		if srv, cli := serverSide(f); srv != "" {
			nodes[srv].servers++
			nodes[cli].clients++
			switch f.AppProtocol {
			case string(models.ProtocolDNS):
				nodes[srv].dns = true
			case string(models.ProtocolDHCP):
				nodes[srv].dhcp = true
			}
		}

		p := pairOf(src, dst)
		e := edges[p]
		if e == nil {
			e = &topoEdge{a: p.a, b: p.b, protocols: make(map[string]int)}
			edges[p] = e
		}
		e.packets += f.PacketCount
		if proto != "" {
			e.protocols[proto] += f.PacketCount
		}
		// BytesSent runs from the flow's first endpoint to its second.
		if src == p.a {
			e.sent, e.recv = e.sent+int64(f.BytesSent), e.recv+int64(f.BytesRecv)
		} else {
			e.sent, e.recv = e.sent+int64(f.BytesRecv), e.recv+int64(f.BytesSent)
		}
	}

	issueRefs(issues,
		func(ip string) *topoNode { return nodes[ip] },
		func(x, y string) *topoEdge { return edges[pairOf(x, y)] })

	all := make([]*topoNode, 0, len(nodes))
	for _, n := range nodes {
		n.IsProblematic = n.IssueCount > 0
		switch {
		case n.dns:
			n.Type = "dns_server"
		case n.dhcp:
			n.Type = "dhcp_server"
		case n.servers > n.clients || (n.servers > 0 && n.clients == 0):
			n.Type = "server"
		default:
			n.Type = "client"
		}
		n.Protocols = topKeys(n.protocols, 6)
		all = append(all, n)
	}
	kept := pickNodes(all, maxNodes)

	keep := make(map[string]struct{}, len(kept))
	out := models.Topology{TotalNodes: len(all), TotalEdges: len(edges), Nodes: make([]models.TopologyNode, 0, len(kept)), Edges: []models.TopologyEdge{}}
	for _, n := range kept {
		keep[n.IP] = struct{}{}
		out.Nodes = append(out.Nodes, n.TopologyNode)
	}
	var shown []*topoEdge
	for _, e := range edges {
		_, okA := keep[e.a]
		_, okB := keep[e.b]
		if okA && okB {
			shown = append(shown, e)
		}
	}
	sort.Slice(shown, func(i, j int) bool {
		if bi, bj := shown[i].sent+shown[i].recv, shown[j].sent+shown[j].recv; bi != bj {
			return bi > bj
		}
		return shown[i].a+shown[i].b < shown[j].a+shown[j].b
	})
	if limit := topologyEdgesPerNode * maxNodes; len(shown) > limit {
		shown = shown[:limit]
	}
	for _, e := range shown {
		te := models.TopologyEdge{Source: e.a, Target: e.b, Packets: e.packets, Bytes: e.sent + e.recv, Issues: e.issues, WorstSeverity: e.worst, Protocol: firstOf(topKeys(e.protocols, 1))}
		if e.recv > e.sent {
			te.Source, te.Target = e.b, e.a
		}
		out.Edges = append(out.Edges, te)
	}
	out.Truncated = len(kept) < len(all) || len(out.Edges) < len(edges)
	return out
}

// pickNodes keeps n of the nodes: the busiest half, then those with the worst
// issues (then the most issues, then the most traffic), then the busiest of
// the rest. The result is ordered by traffic, then address.
func pickNodes(all []*topoNode, n int) []*topoNode {
	if len(all) <= n {
		sort.Slice(all, func(i, j int) bool { return busier(all[i], all[j]) })
		return all
	}
	sort.Slice(all, func(i, j int) bool { return busier(all[i], all[j]) })
	chosen := make(map[*topoNode]struct{}, n)
	for _, x := range all[:n/2] {
		chosen[x] = struct{}{}
	}
	var troubled []*topoNode
	for _, x := range all[n/2:] {
		if x.IsProblematic {
			troubled = append(troubled, x)
		}
	}
	sort.SliceStable(troubled, func(i, j int) bool {
		a, b := troubled[i], troubled[j]
		if ra, rb := severityRank(a.WorstSeverity), severityRank(b.WorstSeverity); ra != rb {
			return ra > rb
		}
		return a.IssueCount > b.IssueCount
	})
	for _, x := range troubled {
		if len(chosen) >= n {
			break
		}
		chosen[x] = struct{}{}
	}
	for _, x := range all[n/2:] {
		if len(chosen) >= n {
			break
		}
		chosen[x] = struct{}{}
	}
	kept := make([]*topoNode, 0, len(chosen))
	for _, x := range all {
		if _, ok := chosen[x]; ok {
			kept = append(kept, x)
		}
	}
	return kept
}

func busier(a, b *topoNode) bool {
	if a.TrafficVolume != b.TrafficVolume {
		return a.TrafficVolume > b.TrafficVolume
	}
	return a.IP < b.IP
}

// topKeys returns the keys of counts, the most frequent first (ties by name),
// at most n of them.
func topKeys(counts map[string]int, n int) []string {
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
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
