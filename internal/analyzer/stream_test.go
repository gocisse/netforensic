package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func tcpAt(sec float64, fromClient bool, flags string, seq uint32, payload []byte) models.PacketInfo {
	p := tcpPkt(sec, fromClient, flags, seq, 0, len(payload))
	p.PayloadPreview = payload
	return p
}

func conversation() []models.PacketInfo {
	return []models.PacketInfo{
		tcpAt(0, true, "SYN", 100, nil),
		tcpAt(0.1, false, "SYN,ACK", 500, nil),
		tcpAt(0.2, true, "ACK", 101, nil),
		withHTTP(tcpAt(0.3, true, "PSH,ACK", 101, []byte("GET /x HTTP/1.1\r\nHost: a.com\r\nAccept: */*\r\n\r\n")), "GET", "/x", 0),
		withHTTP(tcpAt(0.5, false, "PSH,ACK", 501, []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi\x00\x01!")), "", "", 200),
	}
}

func withHTTP(p models.PacketInfo, method, uri string, status int) models.PacketInfo {
	p.HTTPMethod, p.HTTPURI, p.HTTPStatusCode = method, uri, status
	return p
}

func TestParseFlowID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		wantA     endpoint
		wantB     endpoint
		wantProto models.Protocol
		wantErr   string
		wantInst  int
	}{
		{"ipv4", "10.0.0.1:1234-10.0.0.2:80", endpoint{"10.0.0.1", 1234}, endpoint{"10.0.0.2", 80}, "", "", 0},
		{"endpoints are canonicalized", "10.0.0.2:80-10.0.0.1:1234", endpoint{"10.0.0.1", 1234}, endpoint{"10.0.0.2", 80}, "", "", 0},
		{"protocol suffix", "10.0.0.1:1234-10.0.0.2:80/tcp", endpoint{"10.0.0.1", 1234}, endpoint{"10.0.0.2", 80}, models.ProtocolTCP, "", 0},
		{"udp suffix", "1.1.1.1:5-8.8.8.8:53/UDP", endpoint{"1.1.1.1", 5}, endpoint{"8.8.8.8", 53}, models.ProtocolUDP, "", 0},
		{"ipv6", "fe80::1:1234-fe80::2:80", endpoint{"fe80::1", 1234}, endpoint{"fe80::2", 80}, "", "", 0},
		{"surrounding whitespace", "  10.0.0.1:1-10.0.0.2:2 ", endpoint{"10.0.0.1", 1}, endpoint{"10.0.0.2", 2}, "", "", 0},
		{"connection number", "10.0.0.1:1234-10.0.0.2:80#3/tcp", endpoint{"10.0.0.1", 1234}, endpoint{"10.0.0.2", 80}, models.ProtocolTCP, "", 2},
		{"connection number zero", "10.0.0.1:1-10.0.0.2:2#0", endpoint{}, endpoint{}, "", "not a valid connection number", 0},
		{"connection number junk", "10.0.0.1:1-10.0.0.2:2#x", endpoint{}, endpoint{}, "", "not a valid connection number", 0},
		{"no dash", "10.0.0.1:1", endpoint{}, endpoint{}, "", "exactly one '-'", 0},
		{"too many dashes", "invalid-flow-id", endpoint{}, endpoint{}, "", "exactly one '-'", 0},
		{"missing port", "10.0.0.1-10.0.0.2:80", endpoint{}, endpoint{}, "", "has no port", 0},
		{"bad ip", "nope:1-10.0.0.2:80", endpoint{}, endpoint{}, "", "not an IP address", 0},
		{"bad port", "10.0.0.1:abc-10.0.0.2:80", endpoint{}, endpoint{}, "", "not a valid port", 0},
		{"port out of range", "10.0.0.1:70000-10.0.0.2:80", endpoint{}, endpoint{}, "", "not a valid port", 0},
		{"unknown protocol", "10.0.0.1:1-10.0.0.2:80/xyz", endpoint{}, endpoint{}, "", "unknown protocol", 0},
		{"empty", "", endpoint{}, endpoint{}, "", "exactly one '-'", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b, proto, inst, err := parseFlowID(tt.id)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantA, a)
			assert.Equal(t, tt.wantB, b)
			assert.Equal(t, tt.wantProto, proto)
			assert.Equal(t, tt.wantInst, inst)
		})
	}
}

func TestFollow(t *testing.T) {
	conv, err := Follow(conversation(), "10.0.0.2:80-10.0.0.1:1000") // reversed order is fine
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1:1000-10.0.0.2:80", conv.FlowID)
	assert.Equal(t, "10.0.0.1:1000", conv.Client)
	assert.Equal(t, "10.0.0.2:80", conv.Server)
	require.Len(t, conv.Events, 5)

	wantToServer := []bool{true, false, true, true, false}
	for i, ev := range conv.Events {
		assert.Equal(t, wantToServer[i], ev.ToServer, "event %d direction", i)
	}
	assert.Equal(t, "TCP", conv.Events[0].Kind)
	assert.Equal(t, "HTTP", conv.Events[3].Kind)
	assert.Equal(t, "GET /x", conv.Events[3].Summary)
	assert.Equal(t, []string{"Host: a.com", "Accept: */*"}, conv.Events[3].Detail)
	assert.Equal(t, "status 200", conv.Events[4].Summary)
	assert.Equal(t, []string{"Content-Length: 5", "body: hi..!"}, conv.Events[4].Detail)
}

func TestFollowFiltersAndOrders(t *testing.T) {
	other := tcpAt(0.05, true, "SYN", 1, nil)
	other.SrcPort = 2000 // different connection
	udp := models.PacketInfo{Timestamp: at(0.01), Protocol: models.ProtocolUDP, SrcIP: "10.0.0.1", SrcPort: 1000, DstIP: "10.0.0.2", DstPort: 80}
	pkts := append(conversation(), other, udp)
	pkts[0], pkts[4] = pkts[4], pkts[0] // out of order input

	t.Run("without protocol, same endpoints of any protocol match", func(t *testing.T) {
		conv, err := Follow(pkts, "10.0.0.1:1000-10.0.0.2:80")
		require.NoError(t, err)
		assert.Len(t, conv.Events, 6)
		for i := 1; i < len(conv.Events); i++ {
			assert.False(t, conv.Events[i].Timestamp.Before(conv.Events[i-1].Timestamp))
		}
	})
	t.Run("protocol suffix narrows", func(t *testing.T) {
		conv, err := Follow(pkts, "10.0.0.1:1000-10.0.0.2:80/udp")
		require.NoError(t, err)
		require.Len(t, conv.Events, 1)
		assert.Equal(t, "UDP", conv.Events[0].Kind)
	})
	t.Run("client is the first sender in time, not in input order", func(t *testing.T) {
		conv, err := Follow(pkts, "10.0.0.1:1000-10.0.0.2:80/tcp")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1:1000", conv.Client)
		assert.Len(t, conv.Events, 5)
	})
}

func TestFollowErrors(t *testing.T) {
	pkts := append(conversation(), models.PacketInfo{Protocol: models.ProtocolUDP, SrcIP: "1.1.1.1", SrcPort: 5, DstIP: "8.8.8.8", DstPort: 53})

	tests := []struct {
		name   string
		id     string
		reason string
	}{
		{"malformed", "invalid-flow-id", "invalid flow ID"},
		{"not found", "9.9.9.9:1-8.8.8.8:2", "not found"},
		{"wrong protocol", "10.0.0.1:1000-10.0.0.2:80/udp", "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conv, err := Follow(pkts, tt.id)
			assert.Nil(t, conv)
			var fe *FollowError
			require.ErrorAs(t, err, &fe)
			assert.Contains(t, fe.Error(), tt.reason)
			require.Len(t, fe.Available, 2)
			assert.Equal(t, FlowSummary{ID: "10.0.0.1:1000-10.0.0.2:80", Protocol: models.ProtocolTCP, Packets: 5}, fe.Available[0], "busiest first")
			assert.Equal(t, "1.1.1.1:5-8.8.8.8:53", fe.Available[1].ID)
		})
	}

	_, err := Follow(nil, "1.1.1.1:1-2.2.2.2:2")
	var fe *FollowError
	require.ErrorAs(t, err, &fe)
	assert.Empty(t, fe.Available)
}

func TestListFlowsOrdering(t *testing.T) {
	mk := func(src string, sp uint16, proto models.Protocol) models.PacketInfo {
		return models.PacketInfo{Protocol: proto, SrcIP: src, SrcPort: sp, DstIP: "9.9.9.9", DstPort: 1}
	}
	got := ListFlows([]models.PacketInfo{mk("b", 1, "TCP"), mk("a", 1, "UDP"), mk("a", 1, "TCP"), mk("c", 1, "TCP"), mk("c", 1, "TCP")})
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID+"/"+string(f.Protocol))
	}
	assert.Equal(t, []string{"9.9.9.9:1-c:1/TCP", "9.9.9.9:1-a:1/TCP", "9.9.9.9:1-a:1/UDP", "9.9.9.9:1-b:1/TCP"}, ids)
}

func TestDescribePacket(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	tests := []struct {
		name        string
		p           models.PacketInfo
		wantKind    string
		wantSummary string
		wantPayload int
	}{
		{"dns query", models.PacketInfo{Protocol: models.ProtocolUDP, DNSQueryName: "a.com", DNSIsQuery: true, DNSResponseType: "A"}, "DNS", "query a.com (A)", 0},
		{"dns response with answers", models.PacketInfo{Protocol: models.ProtocolUDP, DNSQueryName: "a.com", DNSResponseCode: "NOERROR", DNSAnswers: []string{"A 1.2.3.4", "A 5.6.7.8"}}, "DNS", "response a.com NOERROR: A 1.2.3.4, A 5.6.7.8", 0},
		{"dns nxdomain", models.PacketInfo{Protocol: models.ProtocolUDP, DNSQueryName: "a.com", DNSResponseCode: "NXDOMAIN"}, "DNS", "response a.com NXDOMAIN: no answers", 0},
		{"http request", models.PacketInfo{Protocol: models.ProtocolTCP, HTTPMethod: "POST", HTTPURI: "/api", PayloadPreview: []byte("POST /api HTTP/1.1\r\n\r\n")}, "HTTP", "POST /api", 0},
		{"tls client hello", models.PacketInfo{Protocol: models.ProtocolTCP, TLSHandshakeType: "ClientHello", TLSVersion: "TLS 1.3"}, "TLS", "ClientHello (TLS 1.3)", 0},
		{"tls hello without version", models.PacketInfo{Protocol: models.ProtocolTCP, TLSHandshakeType: "Certificate"}, "TLS", "Certificate", 0},
		{"tls alert", models.PacketInfo{Protocol: models.ProtocolTCP, TLSHandshakeType: "Alert", TLSAlertLevel: "fatal", TLSAlertDescription: "handshake_failure"}, "TLS", "Alert fatal handshake_failure", 0},
		{"icmp", models.PacketInfo{Protocol: models.ProtocolICMP, ICMPMessage: "Echo Request"}, "ICMP", "Echo Request", 0},
		{"arp request", models.PacketInfo{Protocol: models.ProtocolARP, ARPOperation: "request", ARPTargetIP: "10.0.0.1", ARPSenderIP: "10.0.0.5"}, "ARP", "who has 10.0.0.1? tell 10.0.0.5", 0},
		{"arp reply", models.PacketInfo{Protocol: models.ProtocolARP, ARPOperation: "reply", ARPSenderIP: "10.0.0.5", ARPSenderMAC: "aa:bb:cc:dd:ee:ff"}, "ARP", "10.0.0.5 is at aa:bb:cc:dd:ee:ff", 0},
		{"generic tcp payload is previewed", models.PacketInfo{Protocol: models.ProtocolTCP, PayloadSize: 5, PayloadPreview: []byte("hello")}, "TCP", "", 5},
		{"generic payload is capped at 100 bytes", models.PacketInfo{Protocol: models.ProtocolTCP, PayloadSize: 300, PayloadPreview: long}, "TCP", "", 100},
		{"bare ack has no payload", models.PacketInfo{Protocol: models.ProtocolTCP}, "TCP", "", 0},
		{"udp payload", models.PacketInfo{Protocol: models.ProtocolUDP, PayloadSize: 3, PayloadPreview: []byte("abc")}, "UDP", "", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := describePacket(tt.p)
			assert.Equal(t, tt.wantKind, ev.Kind)
			assert.Equal(t, tt.wantSummary, ev.Summary)
			assert.Len(t, ev.Payload, tt.wantPayload)
		})
	}
}

func TestHTTPDetail(t *testing.T) {
	manyHeaders := "GET / HTTP/1.1\r\n"
	for i := 0; i < 25; i++ {
		manyHeaders += "H: v\r\n"
	}
	longBody := "HTTP/1.1 200 OK\r\n\r\n"
	for i := 0; i < 150; i++ {
		longBody += "x"
	}
	tests := []struct {
		name    string
		payload string
		want    []string
	}{
		{"request line only", "GET / HTTP/1.1\r\n\r\n", nil},
		{"headers", "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n", []string{"A: 1", "B: 2"}},
		{"lf-only separators", "GET / HTTP/1.1\nA: 1\n\nbody", []string{"A: 1", "body: body"}},
		{"truncated headers have no body", "GET / HTTP/1.1\r\nA: 1\r\nB: ", []string{"A: 1", "B: "}},
		{"non-printable body bytes", "HTTP/1.1 200 OK\r\n\r\n\x00\x01ok", []string{"body: ..ok"}},
		{"header lines are capped", manyHeaders, append(repeat("H: v", maxStreamHeaderLines), "...")},
		{"body is capped at 100 bytes", longBody, []string{"body: " + string(make100x())}},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, httpDetail([]byte(tt.payload)))
		})
	}
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func make100x() []byte {
	b := make([]byte, 100)
	for i := range b {
		b[i] = 'x'
	}
	return b
}

func TestEndpointStringBracketsIPv6(t *testing.T) {
	assert.Equal(t, "10.0.0.1:80", endpoint{"10.0.0.1", 80}.String())
	assert.Equal(t, "[2001:db8::1]:80", endpoint{"2001:db8::1", 80}.String())
	assert.Equal(t, "[fe80::1:1234]:0", endpoint{"fe80::1:1234", 0}.String())
}

func TestParseFlowIDBracketedIPv6(t *testing.T) {
	a, b, proto, inst, err := parseFlowID("[2001:db8::2]:443-[2001:db8::1]:80#2/tcp")
	require.NoError(t, err)
	assert.Equal(t, endpoint{"2001:db8::1", 80}, a, "canonical order")
	assert.Equal(t, endpoint{"2001:db8::2", 443}, b)
	assert.Equal(t, models.ProtocolTCP, proto)
	assert.Equal(t, 1, inst)

	// mixed families and the legacy unbracketed spelling both still parse
	a, b, _, _, err = parseFlowID("10.0.0.1:5-[::1]:6")
	require.NoError(t, err)
	assert.Equal(t, endpoint{"10.0.0.1", 5}, a)
	assert.Equal(t, endpoint{"::1", 6}, b)
	a, _, _, _, err = parseFlowID("fe80::1:1234-fe80::2:80")
	require.NoError(t, err)
	assert.Equal(t, endpoint{"fe80::1", 1234}, a)

	for _, bad := range []string{"[2001:db8::1-10.0.0.1:80", "[2001:db8::1]-10.0.0.1:80", "[2001:db8::1]80-10.0.0.1:80", "[nope]:80-10.0.0.1:80", "[::1]:99999-10.0.0.1:80"} {
		_, _, _, _, err := parseFlowID(bad)
		assert.Error(t, err, bad)
	}
}

func TestIPv6FlowIDsRoundTrip(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	mk := func(ms int, fromClient bool, payload string) models.PacketInfo {
		p := models.PacketInfo{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: "PSH,ACK", TCPWindow: 100,
			PayloadSize: len(payload), Payload: []byte(payload)}
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "2001:db8::1", 50000, "2001:db8::f02:443", 179
			p.TCPSeq = 1
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "2001:db8::f02:443", 179, "2001:db8::1", 50000
			p.TCPSeq = 100
		}
		return p
	}
	packets := []models.PacketInfo{mk(0, true, "hello"), mk(5, false, "world")}

	flows := ListFlows(packets)
	require.Len(t, flows, 1)
	assert.Equal(t, "[2001:db8::1]:50000-[2001:db8::f02:443]:179", flows[0].ID, "unambiguous: the second host is ...::f02:443, port 179")

	res := Analyze(packets, "all")
	assert.Equal(t, flows[0].ID, res.TopTalkers[0].ID)

	conv, err := FollowStream(packets, flows[0].ID)
	require.NoError(t, err)
	assert.Equal(t, flows[0].ID, conv.FlowID)
	assert.Equal(t, "[2001:db8::1]:50000", conv.Client)
	require.Len(t, conv.Messages, 2)
	assert.Equal(t, "hello", string(conv.Messages[0].Data))

	conv, err = Follow(packets, "[2001:db8::f02:443]:179-[2001:db8::1]:50000/tcp")
	require.NoError(t, err)
	assert.Len(t, conv.Events, 2)

	// the error for an unknown flow lists the bracketed IDs
	_, err = Follow(packets, "[2001:db8::9]:1-[2001:db8::8]:2")
	var fe *FollowError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, flows[0].ID, fe.Available[0].ID)
}

func TestICMPTargetBracketsIPv6(t *testing.T) {
	p := models.PacketInfo{ICMPOrigDstIP: "2001:db8::9", ICMPOrigDstPort: 53}
	assert.Equal(t, "[2001:db8::9]:53", icmpTarget(p))
	p.ICMPOrigDstPort = 0
	assert.Equal(t, "2001:db8::9", icmpTarget(p), "no port: the bare address")
}
