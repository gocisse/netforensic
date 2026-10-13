package analyzer

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// DHCP (IPv4) message encoding: the BOOTP header, the magic cookie and options.

func d4opt(code byte, val ...byte) []byte { return append([]byte{code, byte(len(val))}, val...) }

func d4ip(s string) []byte {
	var a, b, c, d byte
	fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	return []byte{a, b, c, d}
}

// d4mac is the hardware address of client n.
func d4mac(n byte) [6]byte { return [6]byte{2, 0, 0, 0, 0, n} }
func d4macStr(n byte) string {
	m := d4mac(n)
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// d4msg builds a DHCP message of a type for client n with a transaction ID.
func d4msg(op byte, n byte, xid uint32, typ byte, opts ...[]byte) []byte {
	b := make([]byte, 236)
	b[0], b[1], b[2] = op, 1, 6
	b[4], b[5], b[6], b[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)
	m := d4mac(n)
	copy(b[28:], m[:])
	b = append(b, 0x63, 0x82, 0x53, 0x63)
	b = append(b, d4opt(53, typ)...)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, 255)
}

const dhcpServerNet = "192.168.0."

func serverIP(n int) string { return fmt.Sprintf("%s%d", dhcpServerNet, n) }

func fromClient(at time.Duration, msg []byte) udpPkt {
	return udpPkt{at: at, from: "0.0.0.0", to: "255.255.255.255", srcPort: 68, dport: 67, payload: msg}
}

func fromDHCPServer(at time.Duration, n int, msg []byte) udpPkt {
	return udpPkt{at: at, from: serverIP(n), to: "255.255.255.255", srcPort: 67, dport: 68, payload: msg}
}

func discoverPkt(at time.Duration, client byte, xid uint32) udpPkt {
	return fromClient(at, d4msg(1, client, xid, 1))
}
func offerPkt(at time.Duration, server int, client byte, xid uint32) udpPkt {
	return fromDHCPServer(at, server, d4msg(2, client, xid, 2, d4opt(54, d4ip(serverIP(server))...)))
}
func requestPkt(at time.Duration, client byte, xid uint32) udpPkt {
	return fromClient(at, d4msg(1, client, xid, 3))
}
func nakPkt(at time.Duration, server int, client byte, xid uint32, reason string) udpPkt {
	opts := [][]byte{d4opt(54, d4ip(serverIP(server))...)}
	if reason != "" {
		opts = append(opts, d4opt(56, []byte(reason)...))
	}
	return fromDHCPServer(at, server, d4msg(2, client, xid, 6, opts...))
}

// laterPkt is an unrelated packet, so that the capture lasts until at.
func laterPkt(at time.Duration) udpPkt {
	return udpPkt{at: at, from: "10.9.9.1", to: "10.9.9.2", srcPort: 5000, dport: 5001, payload: []byte("x")}
}

func dhcp4Issues(t *testing.T, pkts []udpPkt) []models.Issue {
	t.Helper()
	var out []models.Issue
	for _, is := range Analyze(udpCapture(t, pkts), "all").Issues {
		if is.Category == "DHCP" {
			out = append(out, is)
		}
	}
	return out
}

func TestDHCPDetection(t *testing.T) {
	cookie := []byte{0x63, 0x82, 0x53, 0x63}
	bootp := append(append(make([]byte, 236), cookie...), 255) // no message type option
	noCookie := append(make([]byte, 240), 255)
	noCookie[0] = 1
	tests := []struct {
		name         string
		pkt          udpPkt
		wantApp      string
		wantMessages string
	}{
		{"a Discover to port 67", discoverPkt(0, 1, 1), "DHCP", "Discover"},
		{"an Offer from port 67", offerPkt(0, 1, 1, 1), "DHCP", "Offer"},
		{"a Request", requestPkt(0, 1, 1), "DHCP", "Request"},
		{"a NAK", nakPkt(0, 1, 1, 1, ""), "DHCP", "Nak"},
		{"BOOTP without a message type is DHCP by port only", fromClient(0, bootp), "DHCP", ""},
		{"no magic cookie is DHCP by port only", fromClient(0, noCookie), "DHCP", ""},
		{"a message type out of range is DHCP by port only", fromClient(0, d4msg(1, 1, 1, 9)), "DHCP", ""},
		{"the same bytes on another port are not DHCP", udpPkt{from: "10.0.0.1", to: "10.0.0.2", srcPort: 40000, dport: 40001, payload: d4msg(1, 1, 1, 1)}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(udpCapture(t, []udpPkt{tt.pkt}), "all")
			require.NotEmpty(t, res.Flows)
			assert.Equal(t, tt.wantApp, res.Flows[0].AppProtocol)
			assert.Equal(t, tt.wantMessages, res.Flows[0].DHCPMessageTypes)

			var stat *models.ProtocolStat
			for i, s := range res.ProtocolStats {
				if s.Protocol == "DHCP" {
					stat = &res.ProtocolStats[i]
				}
			}
			if tt.wantApp == "" {
				assert.Nil(t, stat)
				return
			}
			require.NotNil(t, stat, "DHCP is in the protocol distribution")
			assert.Equal(t, "application", stat.Layer)
		})
	}
}

func TestDHCPFlowMetadata(t *testing.T) {
	res := Analyze(udpCapture(t, []udpPkt{
		discoverPkt(0, 7, 1),
		offerPkt(time.Second, 3, 7, 1),
		fromClient(2*time.Second, d4msg(1, 7, 2, 3, d4opt(54, d4ip(serverIP(3))...))),
		fromDHCPServer(3*time.Second, 3, d4msg(2, 7, 2, 5, d4opt(54, d4ip(serverIP(3))...), d4opt(51, 0, 0, 0x0e, 0x10))),
		discoverPkt(4*time.Second, 7, 3), // Discover again: listed once
	}), "all")
	require.Len(t, res.Flows, 2, "the client's flow and the server's")
	byTypes := map[string]models.Flow{}
	for _, f := range res.Flows {
		byTypes[f.DHCPMessageTypes] = f
	}
	client := byTypes["Discover,Request"]
	require.NotEmpty(t, client.ID, "%v", byTypes)
	assert.Equal(t, d4macStr(7), client.DHCPClientMAC)
	assert.Equal(t, serverIP(3), client.DHCPServerIP, "taken from the Request, which names the chosen server")
	server := byTypes["Offer,Ack"]
	assert.Equal(t, serverIP(3), server.DHCPServerIP)
	assert.Equal(t, d4macStr(7), server.DHCPClientMAC)
}

func TestDHCPNak(t *testing.T) {
	tests := []struct {
		name     string
		pkts     []udpPkt
		wantDesc string
		wantNone bool
	}{
		{"a NAK with its reason",
			[]udpPkt{requestPkt(0, 1, 1), nakPkt(time.Second, 1, 1, 1, "requested address not available")},
			fmt.Sprintf("server %s refused address request from %s: requested address not available", serverIP(1), d4macStr(1)), false},
		{"a NAK without a reason",
			[]udpPkt{requestPkt(0, 1, 1), nakPkt(time.Second, 1, 1, 1, "")},
			fmt.Sprintf("server %s refused address request from %s", serverIP(1), d4macStr(1)), false},
		{"an Ack is not refused", []udpPkt{requestPkt(0, 1, 1), fromDHCPServer(time.Second, 1, d4msg(2, 1, 1, 5))}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issuesTitled(dhcp4Issues(t, tt.pkts), titleDHCPNak)
			if tt.wantNone {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			assert.Equal(t, models.SeverityWarning, got[0].Severity)
			assert.Equal(t, tt.wantDesc, got[0].Description)
			assert.Equal(t, serverIP(1), got[0].Target)
			assert.Equal(t, 1, got[0].Count)
		})
	}

	t.Run("the server is its Server Identifier, else the address it sent from", func(t *testing.T) {
		nak := d4msg(2, 1, 1, 6) // no option 54
		got := issuesTitled(dhcp4Issues(t, []udpPkt{requestPkt(0, 1, 1), fromDHCPServer(time.Second, 5, nak)}), titleDHCPNak)
		require.Len(t, got, 1)
		assert.Equal(t, serverIP(5), got[0].Target)

		relayed := fromDHCPServer(time.Second, 5, d4msg(2, 1, 1, 6, d4opt(54, d4ip("10.1.1.1")...)))
		got = issuesTitled(dhcp4Issues(t, []udpPkt{requestPkt(0, 1, 1), relayed}), titleDHCPNak)
		require.Len(t, got, 1)
		assert.Equal(t, "10.1.1.1", got[0].Target)
	})
}

func TestDHCPIssuesAggregateByServer(t *testing.T) {
	pkts := []udpPkt{
		requestPkt(0, 1, 1), nakPkt(time.Second, 1, 1, 1, "no free leases"),
		requestPkt(2*time.Second, 2, 2), nakPkt(3*time.Second, 1, 2, 2, "no free leases"),
		requestPkt(4*time.Second, 3, 3), nakPkt(5*time.Second, 2, 3, 3, "wrong network"),
		nakPkt(6*time.Second, 1, 1, 1, "no free leases"), // the same NAK again (seen twice): counted once
	}
	got := issuesTitled(dhcp4Issues(t, pkts), titleDHCPNak)
	require.Len(t, got, 2, "one issue per server, not per NAK")
	byTarget := map[string]models.Issue{}
	for _, is := range got {
		byTarget[is.Target] = is
	}
	a := byTarget[serverIP(1)]
	assert.Equal(t, 2, a.Count)
	assert.Equal(t, fmt.Sprintf("server %s refused 2 address requests from 2 clients: no free leases (2x)", serverIP(1)), a.Description)
	require.Len(t, a.Occurrences, 2)
	assert.Equal(t, []string{d4macStr(1), d4macStr(2)}, []string{a.Occurrences[0].Subject, a.Occurrences[1].Subject})
	b := byTarget[serverIP(2)]
	assert.Equal(t, 1, b.Count)
	assert.Contains(t, b.Description, "wrong network")
}

func TestDHCPAddressExhaustion(t *testing.T) {
	naks := func(server, n int) []udpPkt {
		var p []udpPkt
		for i := 1; i <= n; i++ {
			p = append(p, requestPkt(time.Duration(i)*time.Second, byte(i), uint32(i)), nakPkt(time.Duration(i)*time.Second+time.Millisecond, server, byte(i), uint32(i), ""))
		}
		return p
	}
	tests := []struct {
		name    string
		pkts    []udpPkt
		want    map[string]int // server -> NAKs, for the exhaustion issues expected
		wantMsg string
	}{
		{"two NAKs are not enough", naks(1, 2), map[string]int{}, ""},
		{"three NAKs from one server", naks(1, 3), map[string]int{serverIP(1): 3}, fmt.Sprintf("server %s sent 3 NAKs to 3 clients", serverIP(1))},
		{"NAKs from different servers do not add up", append(naks(1, 2), naks(2, 2)...), map[string]int{}, ""},
		{"a retransmitted NAK counts once", append(naks(1, 2), nakPkt(10*time.Second, 1, 2, 2, "")), map[string]int{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issuesTitled(dhcp4Issues(t, tt.pkts), titleDHCPExhaustion)
			have := map[string]int{}
			for _, is := range got {
				have[is.Target] = is.Count
				assert.Equal(t, models.SeverityWarning, is.Severity)
				if tt.wantMsg != "" {
					assert.Equal(t, tt.wantMsg, is.Description)
				}
			}
			assert.Equal(t, tt.want, have)
		})
	}
}

func TestDHCPFailureRate(t *testing.T) {
	// requests clients ask, of which the first naks get a NAK (from server 1), the rest an Ack.
	exchange := func(requests, naks int) []udpPkt {
		var p []udpPkt
		for i := 1; i <= requests; i++ {
			at := time.Duration(i) * time.Second
			p = append(p, requestPkt(at, byte(i), uint32(i)))
			if i <= naks {
				p = append(p, nakPkt(at+time.Millisecond, 1, byte(i), uint32(i), ""))
			} else {
				p = append(p, fromDHCPServer(at+time.Millisecond, 1, d4msg(2, byte(i), uint32(i), 5)))
			}
		}
		return p
	}
	tests := []struct {
		name    string
		pkts    []udpPkt
		wantMsg string // "" if no issue is expected
	}{
		{"10% is fine", exchange(10, 1), ""},
		{"exactly 20% is not above it", exchange(10, 2), ""},
		{"30% is high", exchange(10, 3), "30% of requests were NAK'd (3 of 10 requests)"},
		{"all of them", exchange(5, 5), "100% of requests were NAK'd (5 of 5 requests)"},
		{"too few requests to say: 4 of 4", exchange(4, 4), ""},
		{"a NAK whose request was not captured counts as a request",
			append(exchange(4, 0), nakPkt(20*time.Second, 1, 9, 9, ""), nakPkt(21*time.Second, 1, 10, 10, "")), "33% of requests were NAK'd (2 of 6 requests)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issuesTitled(dhcp4Issues(t, tt.pkts), titleDHCPFailRate)
			if tt.wantMsg == "" {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			assert.Equal(t, models.SeverityWarning, got[0].Severity)
			assert.Equal(t, tt.wantMsg, got[0].Description)
			assert.Equal(t, serverIP(1), got[0].Target, "a single server is the target")
		})
	}
}

func TestDHCPTimeouts(t *testing.T) {
	tests := []struct {
		name      string
		pkts      []udpPkt
		wantCount int // the Discovers in the issue; 0 if there is none
		wantDesc  string
	}{
		{"no offer in 10 seconds", []udpPkt{discoverPkt(0, 1, 1), laterPkt(11 * time.Second)}, 1,
			fmt.Sprintf("no offer to discover from %s (sent to 255.255.255.255, waited 10s)", d4macStr(1))},
		{"the capture ends too soon to say", []udpPkt{discoverPkt(0, 1, 1), laterPkt(9 * time.Second)}, 0, ""},
		{"an offer in time", []udpPkt{discoverPkt(0, 1, 1), offerPkt(time.Second, 1, 1, 1), laterPkt(30 * time.Second)}, 0, ""},
		{"an offer to another transaction does not answer it", []udpPkt{discoverPkt(0, 1, 1), offerPkt(time.Second, 1, 1, 2), laterPkt(30 * time.Second)}, 1, ""},
		{"an offer to another client does not answer it", []udpPkt{discoverPkt(0, 1, 1), offerPkt(time.Second, 1, 2, 1), laterPkt(30 * time.Second)}, 1, ""},
		{"an offer after 10 seconds is late", []udpPkt{discoverPkt(0, 1, 1), offerPkt(15*time.Second, 1, 1, 1), laterPkt(20 * time.Second)}, 1,
			fmt.Sprintf("the offer to discover from %s came only after 15s (sent to 255.255.255.255, waited 10s)", d4macStr(1))},
		{"a retransmitted Discover counts once", []udpPkt{discoverPkt(0, 1, 1), discoverPkt(4*time.Second, 1, 1), laterPkt(30 * time.Second)}, 1, ""},
		{"Discovers to one destination are one issue", []udpPkt{discoverPkt(0, 1, 1), discoverPkt(time.Second, 2, 2), discoverPkt(2*time.Second, 3, 3), laterPkt(30 * time.Second)}, 3,
			fmt.Sprintf("3 discovers to 255.255.255.255 got no offer within 10s; first: no offer to discover from %s", d4macStr(1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issuesTitled(dhcp4Issues(t, tt.pkts), titleDHCPTimeout)
			if tt.wantCount == 0 {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			assert.Equal(t, models.SeverityWarning, got[0].Severity)
			assert.Equal(t, tt.wantCount, got[0].Count)
			assert.Equal(t, "255.255.255.255", got[0].Target)
			if tt.wantDesc != "" {
				assert.Equal(t, tt.wantDesc, got[0].Description)
			}
		})
	}

	t.Run("Discovers to different servers are different issues", func(t *testing.T) {
		relay := func(at time.Duration, n byte, dst string) udpPkt {
			p := discoverPkt(at, n, uint32(n))
			p.from, p.to, p.srcPort = "10.0.0.5", dst, 67
			return p
		}
		got := issuesTitled(dhcp4Issues(t, []udpPkt{relay(0, 1, "10.1.0.1"), relay(time.Second, 2, "10.1.0.2"), relay(2*time.Second, 3, "10.1.0.1"), laterPkt(30 * time.Second)}), titleDHCPTimeout)
		require.Len(t, got, 2)
		counts := map[string]int{}
		for _, is := range got {
			counts[is.Target] = is.Count
		}
		assert.Equal(t, map[string]int{"10.1.0.1": 2, "10.1.0.2": 1}, counts)
	})
}

func TestDHCPIssueGuidance(t *testing.T) {
	// Each DHCP issue carries a recommendation and a Wireshark filter.
	pkts := []udpPkt{discoverPkt(0, 9, 99)}
	for i := 1; i <= 5; i++ {
		pkts = append(pkts, requestPkt(time.Duration(i)*time.Second, byte(i), uint32(i)), nakPkt(time.Duration(i)*time.Second+time.Millisecond, 1, byte(i), uint32(i), "no free leases"))
	}
	pkts = append(pkts, laterPkt(30*time.Second))
	issues := dhcp4Issues(t, pkts)
	titles := map[string]models.Issue{}
	for _, is := range issues {
		titles[is.Title] = is
		assert.NotEmpty(t, is.Recommendation, is.Title)
		assert.NotEmpty(t, is.WiresharkFilter, is.Title)
		assert.Equal(t, []string{"DHCP", "UDP"}, is.Protocols, is.Title)
	}
	assert.Len(t, titles, 4, "NAK, exhaustion, failure rate and timeout")
	assert.Equal(t, "dhcp.option.dhcp == 6 && dhcp.option.dhcp_server_id == "+serverIP(1), titles[titleDHCPNak].WiresharkFilter)
	assert.Equal(t, "dhcp.option.dhcp == 1 && ip.dst == 255.255.255.255", titles[titleDHCPTimeout].WiresharkFilter)
}

func TestDHCPRealCapture(t *testing.T) {
	packets, err := pcap.ReadPackets("../../testdata/IPv4-DHCP-Sequence.pcap")
	require.NoError(t, err)
	res := Analyze(packets, "all")
	require.Len(t, res.Flows, 2)
	for _, f := range res.Flows {
		assert.Equal(t, "DHCP", f.AppProtocol)
	}
	assert.Equal(t, "Discover,Request", res.Flows[0].DHCPMessageTypes+"")
	assert.Equal(t, "00:0b:82:01:fc:42", res.Flows[0].DHCPClientMAC)
	assert.Equal(t, "192.168.0.1", res.Flows[0].DHCPServerIP)
	for _, is := range res.Issues {
		assert.NotEqual(t, "DHCP", is.Category, "a clean exchange has no DHCP issue: %s", is.Title)
	}
	found := false
	for _, s := range res.ProtocolStats {
		if s.Protocol == "DHCP" {
			found = true
			assert.Equal(t, 4, s.Packets)
		}
	}
	assert.True(t, found, "DHCP is in the protocol distribution")
}
