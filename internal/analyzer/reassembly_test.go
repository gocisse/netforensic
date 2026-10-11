package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func dataSeg(ms int, fromClient bool, seq uint32, payload string) models.PacketInfo {
	p := models.PacketInfo{Timestamp: time.Unix(1700000000, 0).Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolTCP,
		TCPFlags: "PSH,ACK", TCPSeq: seq, PayloadSize: len(payload), Payload: []byte(payload)}
	if fromClient {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.1", 5000, "10.0.0.2", 80
	} else {
		p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.0.0.2", 80, "10.0.0.1", 5000
	}
	return p
}

const streamFlow = "10.0.0.1:5000-10.0.0.2:80"

func TestFollowStreamReassembly(t *testing.T) {
	ack := models.PacketInfo{Timestamp: time.Unix(1700000000, 0), Protocol: models.ProtocolTCP, TCPFlags: "ACK", SrcIP: "10.0.0.1", SrcPort: 5000, DstIP: "10.0.0.2", DstPort: 80}
	truncated := dataSeg(0, false, 100, "abcdef")
	truncated.Payload = []byte("abc") // snaplen kept 3 of 6 bytes
	partial := dataSeg(10, false, 106, "ghi")

	tests := []struct {
		name        string
		packets     []models.PacketInfo
		wantData    []string // Data of each message ("" for gaps)
		wantMissing []int
		retrans     int
	}{
		{"consecutive segments are stitched", []models.PacketInfo{
			dataSeg(0, false, 100, "ab"), dataSeg(1, false, 102, "cd")},
			[]string{"abcd"}, []int{0}, 0},
		{"pure acks are dropped", []models.PacketInfo{dataSeg(0, true, 1, "q"), ack, dataSeg(5, false, 9, "r")},
			[]string{"q", "r"}, []int{0, 0}, 0},
		{"directions alternate in time order", []models.PacketInfo{
			dataSeg(0, true, 1, "req"), dataSeg(10, false, 50, "resp1"), dataSeg(20, false, 55, "resp2"), dataSeg(30, true, 4, "req2")},
			[]string{"req", "resp1resp2", "req2"}, []int{0, 0, 0}, 0},
		{"retransmission is deduplicated", []models.PacketInfo{
			dataSeg(0, false, 100, "ab"), dataSeg(1, false, 102, "cd"), dataSeg(50, false, 100, "ab")},
			[]string{"abcd"}, []int{0}, 1},
		{"out-of-order segment is placed by sequence", []models.PacketInfo{
			dataSeg(0, false, 100, "ab"), dataSeg(1, false, 104, "ef"), dataSeg(50, false, 102, "cd")},
			[]string{"abcdef"}, []int{0}, 0},
		{"overlapping segment is trimmed", []models.PacketInfo{
			dataSeg(0, false, 100, "abc"), dataSeg(1, false, 102, "cde")},
			[]string{"abcde"}, []int{0}, 0},
		{"gap is reported", []models.PacketInfo{
			dataSeg(0, false, 100, "ab"), dataSeg(1, false, 110, "yz")},
			[]string{"ab", "", "yz"}, []int{0, 8, 0}, 0},
		{"snaplen tail is reported as missing", []models.PacketInfo{truncated, partial},
			[]string{"abc", "", "ghi"}, []int{0, 3, 0}, 0},
		{"sequence number wrap", []models.PacketInfo{
			dataSeg(0, false, 0xfffffffe, "ab"), dataSeg(1, false, 0, "cd")},
			[]string{"abcd"}, []int{0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conv, err := FollowStream(tt.packets, streamFlow)
			require.NoError(t, err)
			require.Len(t, conv.Messages, len(tt.wantData))
			for i, m := range conv.Messages {
				assert.Equal(t, tt.wantData[i], string(m.Data), "message %d", i)
				assert.Equal(t, tt.wantMissing[i], m.Missing, "message %d", i)
			}
			assert.Equal(t, tt.retrans, conv.Retransmits)
		})
	}
}

func TestFollowStreamLateRetransmissionKeepsStreamOrder(t *testing.T) {
	// The client's request is interleaved with a hole-filling retransmission
	// of the server's response; the response must stay contiguous.
	conv, err := FollowStream([]models.PacketInfo{
		dataSeg(0, false, 100, "AA"),
		dataSeg(1, false, 104, "CC"),
		dataSeg(5, true, 1, "next-request"),
		dataSeg(9, false, 102, "BB"),
	}, streamFlow)
	require.NoError(t, err)
	var resp string
	for _, m := range conv.Messages {
		if m.ToServer { // the first sender, here the "server" side of dataSeg, is the client
			resp += string(m.Data)
		}
	}
	assert.Equal(t, "AABBCC", resp)
}

func TestFollowStreamKinds(t *testing.T) {
	req := dataSeg(0, true, 1, "GET / HTTP/1.1\r\n\r\n")
	req.HTTPMethod, req.HTTPURI = "GET", "/"
	cut := dataSeg(10, false, 9, "HTTP/1.1 200 OK\r\n\r\n") // fields unparsed
	hello := dataSeg(20, true, 19, "\x16\x03\x01")
	hello.TLSHandshakeType = "ClientHello"
	udp := models.PacketInfo{Timestamp: time.Unix(1700000001, 0), Protocol: models.ProtocolUDP, SrcIP: "10.0.0.1", SrcPort: 5000, DstIP: "10.0.0.2", DstPort: 80,
		PayloadSize: 4, Payload: []byte("ping")}
	empty := udp
	empty.PayloadSize, empty.Payload = 0, nil
	icmp := models.PacketInfo{Timestamp: time.Unix(1700000002, 0), Protocol: models.ProtocolICMP, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", ICMPMessage: "echo"}

	conv, err := FollowStream([]models.PacketInfo{req, cut, hello}, streamFlow)
	require.NoError(t, err)
	require.Len(t, conv.Messages, 3)
	assert.Equal(t, "HTTP", conv.Messages[0].Kind)
	assert.Equal(t, "GET /", conv.Messages[0].Summary)
	assert.Equal(t, "HTTP", conv.Messages[1].Kind)
	assert.Equal(t, "TLS", conv.Messages[2].Kind)
	assert.Equal(t, "ClientHello", conv.Messages[2].Summary)
	assert.Equal(t, "\x16\x03\x01", string(conv.Messages[2].Data))

	conv, err = FollowStream([]models.PacketInfo{udp, empty}, "10.0.0.1:5000-10.0.0.2:80/udp")
	require.NoError(t, err)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "ping", string(conv.Messages[0].Data))

	conv, err = FollowStream([]models.PacketInfo{icmp}, "10.0.0.1:0-10.0.0.2:0/icmp")
	require.NoError(t, err)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "echo", conv.Messages[0].Summary)
	assert.Nil(t, conv.Messages[0].Data)
}

func TestFollowStreamFallsBackToPreview(t *testing.T) {
	p := dataSeg(0, true, 1, "hi")
	p.Payload, p.PayloadPreview = nil, []byte("hi")
	conv, err := FollowStream([]models.PacketInfo{p}, streamFlow)
	require.NoError(t, err)
	require.Len(t, conv.Messages, 1)
	assert.Equal(t, "hi", string(conv.Messages[0].Data))
}

func TestFollowStreamErrors(t *testing.T) {
	_, err := FollowStream([]models.PacketInfo{dataSeg(0, true, 1, "x")}, "bogus")
	var fe *FollowError
	require.ErrorAs(t, err, &fe)
	assert.Len(t, fe.Available, 1)

	_, err = FollowStream(nil, streamFlow)
	require.ErrorAs(t, err, &fe)
}

func TestFollowMarksRetransmits(t *testing.T) {
	conv, err := Follow([]models.PacketInfo{
		dataSeg(0, false, 100, "ab"),
		dataSeg(1, false, 102, "cd"),
		dataSeg(50, false, 100, "ab"),
		dataSeg(60, true, 100, "ab"), // other direction, same number: not a retransmit
	}, streamFlow)
	require.NoError(t, err)
	var got []bool
	for _, ev := range conv.Events {
		got = append(got, ev.Retransmit)
	}
	assert.Equal(t, []bool{false, false, true, false}, got)
}
