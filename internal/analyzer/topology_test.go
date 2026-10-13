package analyzer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// tflow builds a flow between two endpoints; BytesSent runs from the first to the second.
func tflow(src string, sport uint16, dst string, dport uint16, proto, app string, packets, sent, recv int) models.Flow {
	return models.Flow{
		ID:    fmt.Sprintf("%s:%d-%s:%d", src, sport, dst, dport),
		SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: dport,
		Protocol: models.Protocol(proto), AppProtocol: app, PacketCount: packets, BytesSent: sent, BytesRecv: recv,
	}
}

func nodeOf(t *testing.T, topo models.Topology, ip string) models.TopologyNode {
	t.Helper()
	for _, n := range topo.Nodes {
		if n.IP == ip {
			return n
		}
	}
	t.Fatalf("no node %s in %v", ip, topo.Nodes)
	return models.TopologyNode{}
}

func TestBuildTopologyNodesAndEdges(t *testing.T) {
	flows := []models.Flow{
		tflow("10.0.0.1", 40000, "10.0.0.53", 53, "UDP", "DNS", 20, 1000, 4000),
		tflow("10.0.0.2", 40001, "10.0.0.53", 53, "UDP", "DNS", 10, 500, 2000),
		tflow("10.0.0.1", 40002, "10.0.0.80", 443, "TCP", "TLS", 100, 5000, 90000),
		tflow("10.0.0.1", 40003, "10.0.0.80", 443, "TCP", "TLS", 50, 1000, 49000), // a second flow of the same pair
		tflow("0.0.0.0", 68, "10.0.0.67", 67, "UDP", "DHCP", 2, 600, 700),
	}
	topo := BuildTopology(flows, nil, 0)

	assert.Equal(t, 6, topo.TotalNodes)
	assert.Equal(t, 4, topo.TotalEdges)
	assert.False(t, topo.Truncated)
	require.Len(t, topo.Nodes, 6)

	tests := []struct {
		ip        string
		wantType  string
		wantBytes int64
		wantPkts  int
		wantProto []string
	}{
		{"10.0.0.53", "dns_server", 7500, 30, []string{"DNS"}},
		{"10.0.0.80", "server", 145000, 150, []string{"TLS"}},
		{"10.0.0.67", "dhcp_server", 1300, 2, []string{"DHCP"}},
		{"10.0.0.1", "client", 150000, 170, []string{"TLS", "DNS"}},
		{"10.0.0.2", "client", 2500, 10, []string{"DNS"}},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			n := nodeOf(t, topo, tt.ip)
			assert.Equal(t, tt.wantType, n.Type)
			assert.Equal(t, tt.wantBytes, n.TrafficVolume)
			assert.Equal(t, tt.wantPkts, n.Packets)
			assert.Equal(t, tt.wantProto, n.Protocols)
			assert.False(t, n.IsProblematic)
			assert.Zero(t, n.IssueCount)
		})
	}

	t.Run("nodes are ordered by traffic", func(t *testing.T) {
		for i := 1; i < len(topo.Nodes); i++ {
			assert.GreaterOrEqual(t, topo.Nodes[i-1].TrafficVolume, topo.Nodes[i].TrafficVolume)
		}
	})

	t.Run("the flows of a pair are one edge, pointing the way most bytes go", func(t *testing.T) {
		var got *models.TopologyEdge
		for i, e := range topo.Edges {
			if e.Source == "10.0.0.80" || e.Target == "10.0.0.80" {
				got = &topo.Edges[i]
			}
		}
		require.NotNil(t, got)
		assert.Equal(t, "10.0.0.80", got.Source, "the server sends most of the bytes")
		assert.Equal(t, "10.0.0.1", got.Target)
		assert.Equal(t, 150, got.Packets)
		assert.Equal(t, int64(145000), got.Bytes)
		assert.Equal(t, "TLS", got.Protocol)
	})

	t.Run("the other direction", func(t *testing.T) {
		for _, e := range topo.Edges {
			if e.Source == "10.0.0.1" && e.Target == "10.0.0.53" {
				t.Fatalf("the resolver answers more than it is asked: %v", e)
			}
		}
		assert.Contains(t, topo.Edges, models.TopologyEdge{Source: "10.0.0.53", Target: "10.0.0.1", Packets: 20, Bytes: 5000, Protocol: "DNS"})
	})
}

func TestBuildTopologyIssues(t *testing.T) {
	flows := []models.Flow{
		tflow("10.0.0.1", 40000, "10.0.0.80", 80, "TCP", "HTTP", 10, 100, 100),
		tflow("10.0.0.2", 40000, "10.0.0.80", 80, "TCP", "HTTP", 10, 100, 100),
		tflow("10.0.0.3", 40000, "10.0.0.80", 80, "TCP", "HTTP", 10, 100, 100),
	}
	issues := []models.Issue{
		{ID: "1", Severity: models.SeverityError, Category: "PacketLoss", Title: "t1", FlowID: "10.0.0.1:40000-10.0.0.80:80"},
		{ID: "2", Severity: models.SeverityWarning, Category: "Performance", Title: "t2", FlowID: "10.0.0.1:40000-10.0.0.80:80"},
		// an aggregated issue names a target and the flows of its events
		{ID: "3", Severity: models.SeverityWarning, Category: "Connection", Title: "t3", Target: "10.0.0.80:80", Occurrences: []models.Occurrence{
			{Subject: "10.0.0.2:40000-10.0.0.80:80"}, {Subject: "10.0.0.2:40000-10.0.0.80:80"}, {Subject: "10.0.0.3:40000-10.0.0.80:80"}}},
		// a note about the capture names nobody
		{ID: "4", Severity: models.SeverityInfo, Category: "Capture", Title: "Skipped Frames", Description: "from 10.0.0.9"},
	}
	topo := BuildTopology(flows, issues, 0)

	tests := []struct {
		ip       string
		want     int
		severity models.Severity
	}{
		{"10.0.0.1", 2, models.SeverityError},
		{"10.0.0.2", 1, models.SeverityWarning},
		{"10.0.0.3", 1, models.SeverityWarning},
		{"10.0.0.80", 3, models.SeverityError}, // each issue counts once, however often it names the address
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			n := nodeOf(t, topo, tt.ip)
			assert.Equal(t, tt.want, n.IssueCount)
			assert.True(t, n.IsProblematic)
			assert.Equal(t, tt.severity, n.WorstSeverity)
		})
	}
	edges := map[string]models.TopologyEdge{}
	for _, e := range topo.Edges {
		other := e.Source
		if other == "10.0.0.80" {
			other = e.Target
		}
		edges[other] = e
	}
	assert.Equal(t, 2, edges["10.0.0.1"].Issues)
	assert.Equal(t, models.SeverityError, edges["10.0.0.1"].WorstSeverity)
	assert.Equal(t, 1, edges["10.0.0.2"].Issues, "an issue counts once per pair")
	assert.Equal(t, 1, edges["10.0.0.3"].Issues)
}

func TestBuildTopologyIPv6AndSpellings(t *testing.T) {
	flows := []models.Flow{tflow("2001:db8::1", 40000, "2001:DB8:0:0:0:0:0:2", 443, "TCP", "TLS", 5, 10, 10)}
	issues := []models.Issue{{ID: "1", Severity: models.SeverityError, Title: "t", FlowID: "[2001:db8::1]:40000-[2001:db8::2]:443"}}
	topo := BuildTopology(flows, issues, 0)
	require.Len(t, topo.Nodes, 2)
	assert.Equal(t, 1, nodeOf(t, topo, "2001:db8::1").IssueCount)
	assert.Equal(t, 1, nodeOf(t, topo, "2001:db8::2").IssueCount, "an address is one node however it is written")
}

func TestBuildTopologyDegenerateFlows(t *testing.T) {
	tests := []struct {
		name      string
		flows     []models.Flow
		wantNodes int
	}{
		{"no flows", nil, 0},
		{"a flow to itself", []models.Flow{tflow("10.0.0.1", 1, "10.0.0.1", 2, "TCP", "", 1, 1, 1)}, 0},
		{"a flow without addresses", []models.Flow{{ID: "x", Protocol: "ARP"}}, 0},
		{"two well-known ports: neither is the server", []models.Flow{tflow("10.0.0.1", 53, "10.0.0.2", 80, "TCP", "", 1, 1, 1)}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topo := BuildTopology(tt.flows, nil, 0)
			assert.Len(t, topo.Nodes, tt.wantNodes)
			assert.NotNil(t, topo.Nodes, "an empty list, not null")
			assert.NotNil(t, topo.Edges)
			if tt.name == "two well-known ports: neither is the server" {
				assert.Equal(t, "client", topo.Nodes[0].Type)
			}
		})
	}
}

func TestBuildTopologyTruncation(t *testing.T) {
	// 40 clients; client 1 is the busiest, clients 30 to 40 have the worst issues but little traffic.
	var flows []models.Flow
	var issues []models.Issue
	for i := 1; i <= 40; i++ {
		ip := fmt.Sprintf("10.0.1.%d", i)
		flows = append(flows, tflow(ip, 40000, "10.0.0.1", 80, "TCP", "HTTP", 10, 1000*(41-i), 10))
		if i >= 30 {
			issues = append(issues, models.Issue{ID: ip, Severity: models.SeverityError, Title: "t", FlowID: ip + ":40000-10.0.0.1:80"})
		}
	}
	topo := BuildTopology(flows, issues, 12)

	assert.Equal(t, 41, topo.TotalNodes)
	assert.Equal(t, 40, topo.TotalEdges)
	assert.True(t, topo.Truncated)
	require.Len(t, topo.Nodes, 12)

	have := map[string]bool{}
	for _, n := range topo.Nodes {
		have[n.IP] = true
	}
	assert.True(t, have["10.0.0.1"], "the server, the busiest node, stays")
	assert.True(t, have["10.0.1.1"], "the busiest clients stay")
	troubled := 0
	for ip := range have {
		if nodeOf(t, topo, ip).IsProblematic {
			troubled++
		}
	}
	assert.Equal(t, 7, troubled, "half the room goes to nodes with issues (and the server, which has them too)")
	for _, e := range topo.Edges {
		assert.True(t, have[e.Source] && have[e.Target], "edges join kept nodes: %v", e)
	}
	assert.Len(t, topo.Edges, 11, "the edges between the kept nodes")
}

func TestBuildTopologyLimits(t *testing.T) {
	var flows []models.Flow
	for i := 0; i < 3000; i++ {
		flows = append(flows, tflow(fmt.Sprintf("10.%d.%d.1", i/250, i%250), 40000, "10.200.0.1", 80, "TCP", "", 1, 100, 100))
	}
	assert.Len(t, BuildTopology(flows, nil, 0).Nodes, DefaultTopologyNodes, "the default")
	assert.Len(t, BuildTopology(flows, nil, -5).Nodes, DefaultTopologyNodes, "a bad limit means the default")
	assert.Len(t, BuildTopology(flows, nil, 100000).Nodes, MaxTopologyNodes, "never more than the maximum")
	assert.Len(t, BuildTopology(flows, nil, 7).Nodes, 7)
}

func TestBuildTopologyOnRealCapture(t *testing.T) {
	packets, err := pcap.ReadPackets("../../testdata/Lab-7-TCPIssues.pcapng")
	require.NoError(t, err)
	res := Analyze(packets, "all")
	topo := BuildTopology(res.Flows, res.Issues, 0)
	require.Len(t, topo.Nodes, 2)
	require.Len(t, topo.Edges, 1)
	client, server := nodeOf(t, topo, "10.0.2.15"), nodeOf(t, topo, "157.240.11.22")
	assert.Equal(t, "client", client.Type)
	assert.Equal(t, "server", server.Type)
	for _, n := range []models.TopologyNode{client, server} {
		assert.True(t, n.IsProblematic, n.IP)
		assert.Equal(t, 1, n.IssueCount)
		assert.Equal(t, models.SeverityError, n.WorstSeverity)
	}
	assert.Equal(t, 1, topo.Edges[0].Issues)
	assert.Equal(t, "TLS", topo.Edges[0].Protocol)
}
