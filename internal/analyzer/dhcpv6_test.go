package analyzer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

// A synthetic DHCPv6 capture: messages are serialized with gopacket into a
// pcap file and read back by the real reader.

type d6Pkt struct {
	at             time.Duration // since the start of the capture
	from, to       string
	srcPort, dport uint16
	payload        []byte
}

func writeD6Capture(t *testing.T, path string, pkts []d6Pkt) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	start := time.Unix(1700000000, 0)
	for _, p := range pkts {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0x33, 0x33, 0, 1, 0, 2}, EthernetType: layers.EthernetTypeIPv6}
		ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP(p.from), DstIP: net.ParseIP(p.to)}
		udp := &layers.UDP{SrcPort: layers.UDPPort(p.srcPort), DstPort: layers.UDPPort(p.dport)}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(p.payload)))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: start.Add(p.at), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()))
	}
	require.NoError(t, f.Close())
}

func d6Capture(t *testing.T, pkts []d6Pkt) []models.PacketInfo {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dhcpv6.pcap")
	writeD6Capture(t, path, pkts)
	packets, err := pcap.ReadPackets(path)
	require.NoError(t, err)
	require.Len(t, packets, len(pkts))
	return packets
}

// DHCPv6 message encoding.

func d6opt(code uint16, val ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, code)
	b = binary.BigEndian.AppendUint16(b, uint16(len(val)))
	return append(b, val...)
}

func d6cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func d6status(code uint16, msg string) []byte {
	return d6opt(13, append(binary.BigEndian.AppendUint16(nil, code), msg...)...)
}

func d6ianaWith(nested ...[]byte) []byte {
	return d6opt(3, append([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, d6cat(nested...)...)...)
}

func d6msg(typ byte, xid uint32, opts ...[]byte) []byte {
	return append([]byte{typ, byte(xid >> 16), byte(xid >> 8), byte(xid)}, d6cat(opts...)...)
}

func d6relay(typ byte, inner []byte) []byte {
	return append(append([]byte{typ, 0}, make([]byte, 32)...), d6opt(9, inner...)...)
}

// duid builds a DUID-LL for a client or server number, and its hex form.
func duid(n byte) []byte    { return []byte{0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, n} }
func hexOf(b []byte) string { return hex.EncodeToString(b) }

func cidOpt(n byte) []byte { return d6opt(1, duid(n)...) }
func sidOpt(n byte) []byte { return d6opt(2, append([]byte{0, 1, 0, 1, 9, 9, 9, 9, 9}, n)...) }
func sidHex(n byte) string { return hexOf(append([]byte{0, 1, 0, 1, 9, 9, 9, 9, 9}, n)) }

const (
	clientAddr = "fe80::1"
	serverAddr = "fe80::2"
	multicast  = "ff02::1:2"
)

// toServer is a client message to the All_DHCP_Relay_Agents_and_Servers address.
func toServer(at time.Duration, msg []byte) d6Pkt {
	return d6Pkt{at: at, from: clientAddr, to: multicast, srcPort: 546, dport: 547, payload: msg}
}

// fromServer is a server's message to the client.
func fromServer(at time.Duration, msg []byte) d6Pkt {
	return d6Pkt{at: at, from: serverAddr, to: clientAddr, srcPort: 547, dport: 546, payload: msg}
}

// fromServerN is fromServer from one of several servers, by number.
func fromServerN(at time.Duration, n int, msg []byte) d6Pkt {
	p := fromServer(at, msg)
	p.from = fmt.Sprintf("fe80::20%d", n)
	return p
}

// later is an unrelated packet, so that the capture lasts until at.
func later(at time.Duration) d6Pkt {
	return d6Pkt{at: at, from: "2001:db8::1", to: "2001:db8::2", srcPort: 5000, dport: 5001, payload: []byte("x")}
}

func dhcpIssues(t *testing.T, pkts []d6Pkt) []models.Issue {
	t.Helper()
	var out []models.Issue
	for _, is := range Analyze(d6Capture(t, pkts), "all").Issues {
		if is.Category == "DHCPv6" {
			out = append(out, is)
		}
	}
	return out
}

func issuesTitled(issues []models.Issue, title string) []models.Issue {
	var out []models.Issue
	for _, is := range issues {
		if is.Title == title {
			out = append(out, is)
		}
	}
	return out
}

func TestDHCPv6Detection(t *testing.T) {
	garbage := []byte{99, 1, 2, 3, 4, 5, 6, 7}
	tests := []struct {
		name         string
		pkts         []d6Pkt
		wantApp      string
		wantMessages string
	}{
		{"a Solicit to port 547", []d6Pkt{toServer(0, d6msg(1, 1, cidOpt(1)))}, "DHCPv6", "Solicit"},
		{"an Advertise from port 547", []d6Pkt{fromServer(0, d6msg(2, 1, cidOpt(1), sidOpt(1)))}, "DHCPv6", "Advertise"},
		{"a full exchange",
			[]d6Pkt{toServer(0, d6msg(1, 1, cidOpt(1))), fromServer(time.Second, d6msg(2, 1, cidOpt(1), sidOpt(1))),
				toServer(2*time.Second, d6msg(3, 2, cidOpt(1), sidOpt(1))), fromServer(3*time.Second, d6msg(7, 2, cidOpt(1), sidOpt(1)))},
			"DHCPv6", "Solicit,Request"}, // the client's flow; the server's is another
		{"detected by the message on another port",
			[]d6Pkt{{from: clientAddr, to: serverAddr, srcPort: 40000, dport: 40001, payload: d6msg(3, 5, cidOpt(2), sidOpt(1))}},
			"DHCPv6", "Request"},
		{"a port-547 packet that is no readable message is DHCPv6 by port",
			[]d6Pkt{{from: clientAddr, to: serverAddr, srcPort: 546, dport: 547, payload: garbage}}, "DHCPv6", ""},
		{"another port with the same bytes is not",
			[]d6Pkt{{from: clientAddr, to: serverAddr, srcPort: 40000, dport: 40001, payload: garbage}}, "", ""},
		{"a message type in range but no client ID, on another port, is not",
			[]d6Pkt{{from: clientAddr, to: serverAddr, srcPort: 40000, dport: 40001, payload: d6msg(1, 1)}}, "", ""},
		{"a relayed message", []d6Pkt{{from: "2001:db8::1", to: "2001:db8::2", srcPort: 547, dport: 547, payload: d6relay(12, d6msg(1, 7, cidOpt(1)))}},
			"DHCPv6", "Relay-forward,Solicit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(d6Capture(t, tt.pkts), "all")
			require.NotEmpty(t, res.Flows)
			assert.Equal(t, tt.wantApp, res.Flows[0].AppProtocol)
			assert.Equal(t, tt.wantMessages, res.Flows[0].DHCPv6MessageTypes)

			var stat *models.ProtocolStat
			for i, s := range res.ProtocolStats {
				if s.Protocol == "DHCPv6" {
					stat = &res.ProtocolStats[i]
				}
			}
			if tt.wantApp == "" {
				assert.Nil(t, stat)
				return
			}
			require.NotNil(t, stat, "DHCPv6 is in the protocol distribution")
			assert.Equal(t, "application", stat.Layer)
		})
	}
}

func TestDHCPv6FlowMetadata(t *testing.T) {
	res := Analyze(d6Capture(t, []d6Pkt{
		toServer(0, d6msg(1, 1, cidOpt(7))),
		fromServer(time.Second, d6msg(2, 1, cidOpt(7), sidOpt(3))),
		toServer(2*time.Second, d6msg(3, 2, cidOpt(7), sidOpt(3))),
		fromServer(3*time.Second, d6msg(7, 2, cidOpt(7), sidOpt(3))),
		toServer(4*time.Second, d6msg(3, 3, cidOpt(7), sidOpt(3))), // Request again: listed once
	}), "all")
	require.Len(t, res.Flows, 2, "the client's flow and the server's")
	byID := map[string]models.Flow{}
	for _, f := range res.Flows {
		byID[f.DHCPv6MessageTypes] = f
	}
	client := byID["Solicit,Request"]
	require.NotEmpty(t, client.ID, "%v", byID)
	assert.Equal(t, hexOf(duid(7)), client.DHCPv6ClientID)
	assert.Equal(t, sidHex(3), client.DHCPv6ServerID, "taken from the Request, which names the chosen server")
	server := byID["Advertise,Reply"]
	assert.Equal(t, sidHex(3), server.DHCPv6ServerID)
}

func TestDHCPv6NoAddressesAndConfigErrors(t *testing.T) {
	// Each case: a request, then a Reply (or Advertise) with the status.
	reply := func(status []byte, reqType byte, replyType byte) []d6Pkt {
		return []d6Pkt{
			toServer(0, d6msg(reqType, 1, cidOpt(1))),
			fromServer(time.Second, d6msg(replyType, 1, cidOpt(1), sidOpt(1), status)),
		}
	}
	tests := []struct {
		name      string
		pkts      []d6Pkt
		wantTitle string // "" means no issue
		wantDesc  string
	}{
		{"NoAddrsAvail at the top level", reply(d6status(2, "No addresses available"), 3, 7),
			titleDHCPv6NoAddrs, fmt.Sprintf(`server %s returned NoAddrsAvail (2) for Request: "No addresses available"`, sidHex(1))},
		{"NoAddrsAvail inside the IA_NA, as servers send it", reply(d6ianaWith(d6status(2, "")), 3, 7),
			titleDHCPv6NoAddrs, fmt.Sprintf("server %s returned NoAddrsAvail (2) for Request", sidHex(1))},
		{"NoAddrsAvail in an Advertise answers a Solicit", reply(d6ianaWith(d6status(2, "")), 1, 2),
			titleDHCPv6NoAddrs, fmt.Sprintf("server %s returned NoAddrsAvail (2) for Solicit", sidHex(1))},
		{"NoBinding after a Renew", reply(d6status(3, "no binding"), 5, 7),
			titleDHCPv6NoAddrs, fmt.Sprintf(`server %s returned NoBinding (3) for Renew: "no binding"`, sidHex(1))},
		{"NoPrefixAvail", reply(d6status(6, ""), 3, 7),
			titleDHCPv6NoAddrs, fmt.Sprintf("server %s returned NoPrefixAvail (6) for Request", sidHex(1))},
		{"NotOnLink after a Confirm", reply(d6status(4, "wrong link"), 4, 7),
			titleDHCPv6Config, fmt.Sprintf(`server %s returned NotOnLink (4) for Confirm: "wrong link"`, sidHex(1))},
		{"UseMulticast", reply(d6status(5, ""), 3, 7),
			titleDHCPv6Config, fmt.Sprintf("server %s returned UseMulticast (5) for Request", sidHex(1))},
		{"NotConfigured", reply(d6status(9, ""), 11, 7),
			titleDHCPv6Config, fmt.Sprintf("server %s returned NotConfigured (9) for Information-request", sidHex(1))},
		{"NotAllowed", reply(d6status(10, ""), 3, 7),
			titleDHCPv6Config, fmt.Sprintf("server %s returned NotAllowed (10) for Request", sidHex(1))},
		{"UnspecFail has no issue of its own", reply(d6status(1, "oops"), 3, 7), "", ""},
		{"Success", reply(d6status(0, "ok"), 3, 7), "", ""},
		{"no status at all", reply(nil, 3, 7), "", ""},
		{"CatchUpComplete is not an error", reply(d6status(13, ""), 3, 7), "", ""},
		{"a reply with no matching request is still reported",
			[]d6Pkt{fromServer(0, d6msg(7, 1, cidOpt(1), sidOpt(1), d6status(2, "")))},
			titleDHCPv6NoAddrs, fmt.Sprintf("server %s returned NoAddrsAvail (2) for Reply", sidHex(1))},
		{"a server with no identifier is named by its address",
			[]d6Pkt{fromServer(0, d6msg(7, 1, cidOpt(1), d6status(2, "")))},
			titleDHCPv6NoAddrs, "server fe80::2 returned NoAddrsAvail (2) for Reply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := dhcpIssues(t, tt.pkts)
			var relevant []models.Issue
			for _, is := range issues {
				if is.Title == titleDHCPv6NoAddrs || is.Title == titleDHCPv6Config {
					relevant = append(relevant, is)
				}
			}
			if tt.wantTitle == "" {
				assert.Empty(t, relevant)
				return
			}
			require.Len(t, relevant, 1)
			assert.Equal(t, tt.wantTitle, relevant[0].Title)
			assert.Equal(t, models.SeverityWarning, relevant[0].Severity)
			assert.Equal(t, "DHCPv6", relevant[0].Category)
			assert.Equal(t, tt.wantDesc, relevant[0].Description)
			assert.Equal(t, 1, relevant[0].Count)
			require.Len(t, relevant[0].Occurrences, 1)
			assert.Equal(t, hexOf(duid(1)), relevant[0].Occurrences[0].Subject, "the client")
			assert.Contains(t, relevant[0].Protocols, "DHCPv6")
		})
	}
}

func TestDHCPv6IssuesAggregateByServer(t *testing.T) {
	var pkts []d6Pkt
	// server 1 fails three requests, with two different statuses; server 2 fails two.
	add := func(i int, srv byte, status []byte) {
		xid := uint32(100 + i)
		pkts = append(pkts,
			toServer(time.Duration(i)*time.Second, d6msg(3, xid, cidOpt(byte(i)))),
			fromServerN(time.Duration(i)*time.Second+time.Millisecond, int(srv), d6msg(7, xid, cidOpt(byte(i)), sidOpt(srv), status)))
	}
	add(0, 1, d6status(2, ""))
	add(1, 1, d6status(2, ""))
	add(2, 1, d6status(3, ""))
	add(3, 2, d6status(2, ""))
	add(4, 2, d6status(2, ""))

	issues := issuesTitled(dhcpIssues(t, pkts), titleDHCPv6NoAddrs)
	require.Len(t, issues, 2, "one issue per server, not one per failure")
	bySrv := map[string]models.Issue{}
	for _, is := range issues {
		bySrv[is.Description[:len("server ")+len(sidHex(1))]] = is
	}
	s1, s2 := bySrv["server "+sidHex(1)], bySrv["server "+sidHex(2)]
	require.NotEmpty(t, s1.ID)
	require.NotEmpty(t, s2.ID)
	assert.Equal(t, 3, s1.Count)
	assert.Equal(t, fmt.Sprintf("server %s returned NoAddrsAvail (2) (2x), NoBinding (3) (1x) for Request (3x) (3 responses)", sidHex(1)), s1.Description)
	assert.Len(t, s1.Occurrences, 3, "each failure stays available for drill-down")
	assert.Equal(t, 2, s2.Count)
	assert.Equal(t, "fe80::201", s1.Target)
}

func TestDHCPv6FailureRate(t *testing.T) {
	// n Replies from one server, of which the first `failed` carry an error status.
	replies := func(n, failed int, status uint16) []d6Pkt {
		var pkts []d6Pkt
		for i := 0; i < n; i++ {
			xid := uint32(i + 1)
			var st []byte
			if i < failed {
				st = d6status(status, "")
			}
			pkts = append(pkts,
				toServer(time.Duration(i)*time.Second, d6msg(3, xid, cidOpt(1))),
				fromServer(time.Duration(i)*time.Second+time.Millisecond, d6msg(7, xid, cidOpt(1), sidOpt(1), st)))
		}
		return pkts
	}
	tests := []struct {
		name     string
		pkts     []d6Pkt
		wantDesc string
	}{
		{"25% of 12", replies(12, 3, 1), fmt.Sprintf("25%% of requests failed (3 of 12 responses from server %s carried an error status)", sidHex(1))},
		{"30% of 10", replies(10, 3, 2), fmt.Sprintf("30%% of requests failed (3 of 10 responses from server %s carried an error status)", sidHex(1))},
		{"exactly 20% is not more than 20%", replies(10, 2, 1), ""},
		{"10%", replies(20, 2, 1), ""},
		{"none", replies(20, 0, 1), ""},
		{"all of 10", replies(10, 10, 1), fmt.Sprintf("100%% of requests failed (10 of 10 responses from server %s carried an error status)", sidHex(1))},
		{"too few responses to call it a rate: 5 of 5", replies(5, 5, 1), ""},
		{"UnspecFail counts here, though it has no issue of its own", replies(10, 5, 1), fmt.Sprintf("50%% of requests failed (5 of 10 responses from server %s carried an error status)", sidHex(1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rates := issuesTitled(dhcpIssues(t, tt.pkts), titleDHCPv6FailRate)
			if tt.wantDesc == "" {
				assert.Empty(t, rates)
				return
			}
			require.Len(t, rates, 1)
			assert.Equal(t, models.SeverityWarning, rates[0].Severity)
			assert.Equal(t, tt.wantDesc, rates[0].Description)
			assert.Equal(t, "%", rates[0].Occurrences[0].Unit)
		})
	}

	t.Run("servers are judged separately and folded into one issue", func(t *testing.T) {
		var pkts []d6Pkt
		for srv := 1; srv <= 3; srv++ {
			failed := []int{0, 3, 8}[srv-1] // 0%, 30%, 80% of 10
			for i := 0; i < 10; i++ {
				xid := uint32(srv*100 + i)
				var st []byte
				if i < failed {
					st = d6status(1, "")
				}
				at := time.Duration(srv*100+i) * time.Second
				pkts = append(pkts, toServer(at, d6msg(3, xid, cidOpt(byte(srv)))), fromServerN(at+time.Millisecond, srv, d6msg(7, xid, cidOpt(byte(srv)), sidOpt(byte(srv)), st)))
			}
		}
		rates := issuesTitled(dhcpIssues(t, pkts), titleDHCPv6FailRate)
		require.Len(t, rates, 1)
		assert.Equal(t, 2, rates[0].Count)
		assert.Equal(t, 80.0, rates[0].Occurrences[0].Value, "the worst first")
		assert.Contains(t, rates[0].Description, "2 DHCPv6 servers fail more than 20% of requests")
		assert.Contains(t, rates[0].Description, "80% (8 of 10 responses)")
	})
}

func TestDHCPv6Timeouts(t *testing.T) {
	solicit := func(at time.Duration, xid uint32) d6Pkt { return toServer(at, d6msg(1, xid, cidOpt(1))) }
	request := func(at time.Duration, xid uint32) d6Pkt { return toServer(at, d6msg(3, xid, cidOpt(1), sidOpt(1))) }
	advertise := func(at time.Duration, xid uint32) d6Pkt { return fromServer(at, d6msg(2, xid, cidOpt(1), sidOpt(1))) }
	replyTo := func(at time.Duration, xid uint32) d6Pkt { return fromServer(at, d6msg(7, xid, cidOpt(1), sidOpt(1))) }
	cid := hexOf(duid(1))

	tests := []struct {
		name      string
		pkts      []d6Pkt
		wantDesc  string // "" means no issue
		wantCount int
	}{
		{"a Solicit with no reply, the capture running on", []d6Pkt{solicit(0, 1), later(40 * time.Second)},
			fmt.Sprintf("no reply to Solicit from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"a Request with no reply", []d6Pkt{request(0, 1), later(31 * time.Second)},
			fmt.Sprintf("no reply to Request from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"exactly 30 seconds of capture is enough to judge", []d6Pkt{solicit(0, 1), later(30 * time.Second)},
			fmt.Sprintf("no reply to Solicit from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"the capture ended too soon to tell", []d6Pkt{solicit(0, 1), later(10 * time.Second)}, "", 0},
		{"a Solicit that was the last packet", []d6Pkt{solicit(0, 1)}, "", 0},
		{"answered by an Advertise", []d6Pkt{solicit(0, 1), advertise(time.Second, 1), later(60 * time.Second)}, "", 0},
		{"answered by a Reply (rapid commit)", []d6Pkt{solicit(0, 1), replyTo(time.Second, 1), later(60 * time.Second)}, "", 0},
		{"answered in time, at 29 seconds", []d6Pkt{request(0, 1), replyTo(29*time.Second, 1), later(60 * time.Second)}, "", 0},
		{"answered late, after 45 seconds", []d6Pkt{request(0, 1), replyTo(45*time.Second, 1)},
			fmt.Sprintf("the reply to Request from client %s came only after 45s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"a Renew with no reply is not judged", []d6Pkt{toServer(0, d6msg(5, 1, cidOpt(1), sidOpt(1))), later(60 * time.Second)}, "", 0},
		{"a Confirm with no reply is not judged", []d6Pkt{toServer(0, d6msg(4, 1, cidOpt(1))), later(60 * time.Second)}, "", 0},
		{"a retransmitted Solicit counts once", []d6Pkt{solicit(0, 1), solicit(1*time.Second, 1), solicit(3*time.Second, 1), later(60 * time.Second)},
			fmt.Sprintf("no reply to Solicit from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"a reply to another client's transaction does not answer it",
			[]d6Pkt{solicit(0, 1), fromServer(time.Second, d6msg(2, 1, cidOpt(2), sidOpt(1))), later(60 * time.Second)},
			fmt.Sprintf("no reply to Solicit from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"a reply to another transaction ID does not answer it",
			[]d6Pkt{solicit(0, 1), advertise(time.Second, 2), later(60 * time.Second)},
			fmt.Sprintf("no reply to Solicit from client %s (sent to ff02::1:2, waited 30s)", cid), 1},
		{"three Solicits to one destination are folded into one issue",
			[]d6Pkt{solicit(0, 1), solicit(time.Second, 2), solicit(2*time.Second, 3), later(60 * time.Second)},
			fmt.Sprintf("3 requests to ff02::1:2 got no reply within 30s: Solicit (3x); first: no reply to Solicit from client %s", cid), 3},
		{"a Solicit and a Request",
			[]d6Pkt{solicit(0, 1), request(time.Second, 2), later(60 * time.Second)},
			fmt.Sprintf("2 requests to ff02::1:2 got no reply within 30s: Request (1x), Solicit (1x); first: no reply to Solicit from client %s", cid), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeouts := issuesTitled(dhcpIssues(t, tt.pkts), titleDHCPv6Timeout)
			if tt.wantCount == 0 {
				assert.Empty(t, timeouts)
				return
			}
			require.Len(t, timeouts, 1)
			is := timeouts[0]
			assert.Equal(t, models.SeverityWarning, is.Severity)
			assert.Equal(t, tt.wantCount, is.Count)
			assert.Len(t, is.Occurrences, tt.wantCount)
			assert.Equal(t, multicast, is.Target)
			if tt.wantDesc != "" {
				assert.Equal(t, tt.wantDesc, is.Description)
			}
		})
	}

	t.Run("a Solicit relayed to a server is answered through the relay", func(t *testing.T) {
		relayed := func(at time.Duration, typ byte, inner []byte, from, to string) d6Pkt {
			return d6Pkt{at: at, from: from, to: to, srcPort: 547, dport: 547, payload: d6relay(typ, inner)}
		}
		pkts := []d6Pkt{
			relayed(0, 12, d6msg(1, 9, cidOpt(1)), "2001:db8::1", "2001:db8::53"),
			relayed(time.Second, 13, d6msg(2, 9, cidOpt(1), sidOpt(1)), "2001:db8::53", "2001:db8::1"),
			later(60 * time.Second),
		}
		assert.Empty(t, issuesTitled(dhcpIssues(t, pkts), titleDHCPv6Timeout))
	})

	t.Run("a relayed Solicit nobody answered", func(t *testing.T) {
		pkts := []d6Pkt{
			{at: 0, from: "2001:db8::1", to: "2001:db8::53", srcPort: 547, dport: 547, payload: d6relay(12, d6msg(1, 9, cidOpt(1)))},
			later(60 * time.Second),
		}
		timeouts := issuesTitled(dhcpIssues(t, pkts), titleDHCPv6Timeout)
		require.Len(t, timeouts, 1)
		assert.Equal(t, "2001:db8::53", timeouts[0].Target, "the server the relay sent it to")
	})

	t.Run("a merged capture does not make every request look unanswered", func(t *testing.T) {
		// The next packet is from a different capture, years later: it says
		// nothing about whether the Solicit was answered.
		pkts := []d6Pkt{solicit(0, 1), later(24 * 365 * 3 * time.Hour)}
		assert.Empty(t, issuesTitled(dhcpIssues(t, pkts), titleDHCPv6Timeout))
		// and neither does one that jumps back in time
		pkts = []d6Pkt{later(500 * time.Second), solicit(400*time.Second, 1), later(100 * time.Second)}
		assert.Empty(t, issuesTitled(dhcpIssues(t, pkts), titleDHCPv6Timeout))
	})

	t.Run("timeouts are aggregated by destination", func(t *testing.T) {
		to := func(p d6Pkt, dst string) d6Pkt { p.to = dst; return p }
		pkts := []d6Pkt{
			solicit(0, 1), to(solicit(time.Second, 2), "ff02::1:3"), to(request(2*time.Second, 3), "fe80::53"),
			to(solicit(3*time.Second, 4), "fe80::53"), later(60 * time.Second),
		}
		timeouts := issuesTitled(dhcpIssues(t, pkts), titleDHCPv6Timeout)
		require.Len(t, timeouts, 3)
		counts := map[string]int{}
		for _, is := range timeouts {
			counts[is.Target] = is.Count
		}
		assert.Equal(t, map[string]int{"ff02::1:2": 1, "ff02::1:3": 1, "fe80::53": 2}, counts)
	})
}
