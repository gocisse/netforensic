package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// A duplicate ACK is evidence that the receiver is missing data. The reply to
// a keep-alive probe or to a zero-window probe repeats the previous ACK number
// and window by design: it answers the probe and says nothing about loss, so
// it must neither be counted as a duplicate ACK nor feed the fast-retransmit
// trigger. Wireshark labels these Keep-Alive ACK and ZeroWindowProbeAck.
//
// The sender is the client 10.0.0.1:5000, the receiver the server 10.0.0.2:443
// (see tx); the client's first data segment (100 bytes at 1001) is
// acknowledged (ack 1101), the sequence number after it is dataNext.
const dataNext = 1101

// sentData is a handshake and one acknowledged 100-byte segment.
func sentData() []models.PacketInfo {
	return []models.PacketInfo{
		tx(0, false, "SYN", 1000, 0, 0, 65535),
		tx(1, true, "SYN,ACK", 5000, 1001, 0, 8192),
		tx(2, false, "ACK", 1001, 5001, 0, 65535),
		tx(10, false, "PSH,ACK", 1001, 5001, 100, 65535),
		tx(11, true, "ACK", 5001, dataNext, 0, 8192),
	}
}

func receiverAck(ms int, ack uint32) models.PacketInfo {
	return tx(ms, true, "ACK", 5001, ack, 0, 8192)
}

// keepAlives is three keep-alive probes 10 s apart, each acknowledged
// unchanged. A one-byte probe repeats the last byte sent (seq dataNext-1); a
// zero-length one (the Linux style) is a bare ACK at that sequence number.
func keepAlives(payload int) []models.PacketInfo {
	var out []models.PacketInfo
	for _, ms := range []int{10000, 20000, 30000} {
		out = append(out, tx(ms, false, "ACK", dataNext-1, 5001, payload, 65535), receiverAck(ms+1, dataNext))
	}
	return out
}

func TestDuplicateACKsAreLossEvidence(t *testing.T) {
	tests := []struct {
		name        string
		packets     []models.PacketInfo
		wantDupAcks int
	}{
		{"D2: replies to one-byte keep-alive probes", append(sentData(), keepAlives(1)...), 0},
		{"D7: zero-length keep-alive probes and their replies", append(sentData(), keepAlives(0)...), 0},
		{"D4: replies to zero-window probes",
			append(zeroWindowPrefix(),
				probe(1000), probeAck(1001, probeNext),
				probe(2000), probeAck(2001, probeNext),
				probe(4000), probeAck(4001, probeNext)),
			0},
		{"D5 control: advancing ACKs and a window update are not duplicates",
			append(sentData(),
				tx(20, false, "PSH,ACK", dataNext, 5001, 100, 65535), receiverAck(21, dataNext+100),
				tx(30, true, "ACK", 5001, dataNext+100, 0, 16384),
				tx(40, false, "PSH,ACK", dataNext+100, 5001, 100, 65535), tx(41, true, "ACK", 5001, dataNext+200, 0, 16384)),
			0},
		{"D6 control: a pure ACK repeated twice is two duplicate ACKs, as Wireshark counts it",
			append(sentData(),
				receiverAck(20, dataNext),
				tx(30, false, "PSH,ACK", dataNext, 5001, 100, 65535),
				receiverAck(40, dataNext),
				receiverAck(50, dataNext+100)),
			2},
		{"D1 control: three duplicate ACKs after a lost segment",
			append(sentData(), lossRecovery()...),
			3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(tt.packets, "all")
			require.Len(t, res.TopTalkers, 1)
			assert.Equal(t, tt.wantDupAcks, res.TopTalkers[0].DupAcks)
		})
	}
}

// lossRecovery is three data segments after a missing one, each answered by an
// ACK for the missing byte, then the fast retransmit.
func lossRecovery() []models.PacketInfo {
	return []models.PacketInfo{
		tx(20, false, "PSH,ACK", dataNext+100, 5001, 100, 65535), receiverAck(21, dataNext),
		tx(30, false, "PSH,ACK", dataNext+200, 5001, 100, 65535), receiverAck(31, dataNext),
		tx(40, false, "PSH,ACK", dataNext+300, 5001, 100, 65535), receiverAck(41, dataNext),
		tx(50, false, "PSH,ACK", dataNext, 5001, 100, 65535), receiverAck(51, dataNext+400),
	}
}

func TestRetransmitAfterKeepAlivesKeepsItsKind(t *testing.T) {
	// D3: after three keep-alive exchanges new data is sent, never acknowledged,
	// and sent again 1.2 s later. Nothing is a duplicate ACK, so this is a
	// timeout retransmission (Wireshark: a plain Retransmission), not a fast one.
	d3 := append(sentData(), keepAlives(1)...)
	d3 = append(d3,
		tx(40000, false, "PSH,ACK", dataNext, 5001, 100, 65535),
		tx(41200, false, "PSH,ACK", dataNext, 5001, 100, 65535),
		receiverAck(41210, dataNext+100))
	res := Analyze(d3, "all")
	require.Len(t, res.TopTalkers, 1)
	flow := res.TopTalkers[0]
	assert.Equal(t, 1, flow.Retransmits)
	assert.Equal(t, 1, flow.TimeoutRetransmits)
	assert.Zero(t, flow.FastRetransmits)
	assert.Zero(t, flow.DupAcks)
	var titles []string
	for _, is := range retransmitIssues(res) {
		titles = append(titles, is.Title)
		assert.NotContains(t, is.Description, "3 or more duplicate ACKs")
	}
	assert.Equal(t, []string{titleTimeoutRetransmit}, titles)

	// D1 control: the same retransmission after three genuine duplicate ACKs is fast.
	res = Analyze(append(sentData(), lossRecovery()...), "all")
	require.Len(t, res.TopTalkers, 1)
	assert.Equal(t, 1, res.TopTalkers[0].FastRetransmits)
	assert.Zero(t, res.TopTalkers[0].TimeoutRetransmits)
	var fast []string
	for _, is := range retransmitIssues(res) {
		fast = append(fast, is.Title)
	}
	assert.Equal(t, []string{titleFastRetransmit}, fast)
}
