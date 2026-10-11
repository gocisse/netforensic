package analyzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// QUIC long header encoding (RFC 9000, section 17.2) for the tests; the
// datagrams are sent over UDP/IPv4 and read back by the real reader.

func qvarint(v uint64) []byte {
	if v < 1<<6 {
		return []byte{byte(v)}
	}
	return binary.BigEndian.AppendUint16(nil, uint16(v)|0x4000)
}

func qlong(version uint32, typeBits byte, dcid, scid []byte, rest ...[]byte) []byte {
	b := binary.BigEndian.AppendUint32([]byte{0xc0 | typeBits<<4}, version)
	b = append(append(append(append(b, byte(len(dcid))), dcid...), byte(len(scid))), scid...)
	return append(b, bytes.Join(rest, nil)...)
}

// qinit is a client or server Initial of the given version.
func qinit(version uint32, dcid, scid []byte) []byte {
	bits := byte(0)
	if version == models.QUICVersion2 {
		bits = 1
	}
	return qlong(version, bits, dcid, scid, qvarint(0), qvarint(30), bytes.Repeat([]byte{0xaa}, 30))
}

// qhand is a Handshake packet.
func qhand(version uint32, dcid, scid []byte) []byte {
	bits := byte(2)
	if version == models.QUICVersion2 {
		bits = 3
	}
	return qlong(version, bits, dcid, scid, qvarint(20), bytes.Repeat([]byte{0xbb}, 20))
}

func qretry(version uint32, dcid, scid []byte) []byte {
	bits := byte(3)
	if version == models.QUICVersion2 {
		bits = 0
	}
	return qlong(version, bits, dcid, scid, bytes.Repeat([]byte{0xcc}, 40))
}

func qvneg(dcid, scid []byte, offered ...uint32) []byte {
	b := binary.BigEndian.AppendUint32([]byte{0x80 | 0x15}, 0)
	b = append(append(append(append(b, byte(len(dcid))), dcid...), byte(len(scid))), scid...)
	for _, v := range offered {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

// qshort is a short header packet, whose connection ID is the server's.
func qshort(dcid []byte) []byte {
	return append(append([]byte{0x41}, dcid...), bytes.Repeat([]byte{0xdd}, 40)...)
}

const (
	qClient = "192.0.2.1"
	qServer = "192.0.2.10"
	draft29 = 0xff00001d
	draft27 = 0xff00001b
)

var (
	cDCID = []byte{1, 1, 1, 1, 1, 1, 1, 1} // the connection ID the client picks for the server
	cSCID = []byte{2, 2, 2, 2}             // the client's own
	sSCID = []byte{3, 3, 3, 3}             // the server's own
)

// toQServer is a datagram from the client (port 50000+n) to the server's port 443.
func toQServer(at time.Duration, n int, payload []byte) udpPkt {
	return udpPkt{at: at, from: qClient, to: qServer, srcPort: uint16(50000 + n), dport: 443, payload: payload}
}

// fromQServer is the server's datagram to the client's port 50000+n.
func fromQServer(at time.Duration, n int, payload []byte) udpPkt {
	return udpPkt{at: at, from: qServer, to: qClient, srcPort: 443, dport: uint16(50000 + n), payload: payload}
}

func quicIssues(t *testing.T, pkts []udpPkt) []models.Issue {
	t.Helper()
	var out []models.Issue
	for _, is := range Analyze(udpCapture(t, pkts), "all").Issues {
		if is.Category == "QUIC" {
			out = append(out, is)
		}
	}
	return out
}

func TestQUICDetectionAndMetadata(t *testing.T) {
	tests := []struct {
		name         string
		pkts         []udpPkt
		wantApp      string
		wantVersion  string
		wantPackets  string
		wantFlowSize int // packets of the first flow
	}{
		{"a client Initial to port 443", []udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID))}, "QUIC", "QUIC v1", "Initial", 1},
		{"Initial and Handshake coalesced", []udpPkt{toQServer(0, 0, append(qinit(1, cDCID, cSCID), qhand(1, cDCID, cSCID)...))}, "QUIC", "QUIC v1", "Initial,Handshake", 1},
		{"a whole flow is QUIC once a long header shows, short headers included",
			[]udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), fromQServer(time.Second, 0, qinit(1, cSCID, sSCID)),
				toQServer(2*time.Second, 0, qshort(sSCID)), fromQServer(3*time.Second, 0, qshort(cSCID))},
			"QUIC", "QUIC v1", "Initial", 4},
		{"QUIC v2", []udpPkt{toQServer(0, 0, qinit(models.QUICVersion2, cDCID, cSCID))}, "QUIC", "QUIC v2", "Initial", 1},
		{"a draft", []udpPkt{toQServer(0, 0, qinit(draft29, cDCID, cSCID))}, "QUIC", "draft-29", "Initial", 1},
		{"another draft", []udpPkt{toQServer(0, 0, qinit(draft27, cDCID, cSCID))}, "QUIC", "draft-27", "Initial", 1},
		{"a greased version", []udpPkt{toQServer(0, 0, qinit(0x2a3a4a5a, cDCID, cSCID))}, "QUIC", "reserved (0x2a3a4a5a)", "Initial", 1},
		{"an unknown version on port 443", []udpPkt{toQServer(0, 0, qinit(0xdeadbeef, cDCID, cSCID))}, "QUIC", "unknown (0xdeadbeef)", "Initial", 1},
		{"every packet type in a conversation",
			[]udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), fromQServer(time.Second, 0, qretry(1, cSCID, sSCID)),
				toQServer(2*time.Second, 0, qinit(1, cDCID, cSCID)), fromQServer(3*time.Second, 0, append(qinit(1, cSCID, sSCID), qhand(1, cSCID, sSCID)...))},
			"QUIC", "QUIC v1", "Initial,Retry,Handshake", 4},
		{"only a Version Negotiation packet", []udpPkt{fromQServer(0, 0, qvneg(cSCID, cDCID, 1))}, "QUIC", "Version Negotiation", "Version Negotiation", 1},
		{"a Version Negotiation, then a real version",
			[]udpPkt{toQServer(0, 0, qinit(draft29, cDCID, cSCID)), fromQServer(time.Second, 0, qvneg(cSCID, cDCID, 1)), toQServer(2*time.Second, 0, qinit(1, cDCID, cSCID))},
			"QUIC", "draft-29", "Initial,Version Negotiation", 3},
		{"DNS over QUIC on port 853", []udpPkt{{from: qClient, to: qServer, srcPort: 40000, dport: 853, payload: qinit(1, cDCID, cSCID)}}, "QUIC", "QUIC v1", "Initial", 1},
		{"short headers alone are not recognized", []udpPkt{toQServer(0, 0, qshort(sSCID)), fromQServer(time.Second, 0, qshort(cSCID))}, "", "", "", 2},
		{"DTLS on port 443 is not QUIC", []udpPkt{toQServer(0, 0, []byte{0x17, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4, 5})}, "", "", "", 1},
		{"an unknown version on a port that is not 443 is not QUIC", []udpPkt{{from: qClient, to: qServer, srcPort: 40000, dport: 9000, payload: qinit(0xdeadbeef, cDCID, cSCID)}}, "", "", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(udpCapture(t, tt.pkts), "all")
			require.NotEmpty(t, res.Flows)
			f := res.Flows[0]
			assert.Equal(t, tt.wantApp, f.AppProtocol)
			assert.Equal(t, tt.wantVersion, f.QUICVersion)
			assert.Equal(t, tt.wantPackets, f.QUICPacketTypes)
			assert.Equal(t, tt.wantFlowSize, f.PacketCount)

			var stat *models.ProtocolStat
			for i, s := range res.ProtocolStats {
				if s.Protocol == "QUIC" {
					stat = &res.ProtocolStats[i]
				}
			}
			if tt.wantApp == "" {
				assert.Nil(t, stat)
				return
			}
			require.NotNil(t, stat, "QUIC is in the protocol distribution")
			assert.Equal(t, "application", stat.Layer)
		})
	}
}

func TestQUICVersionNames(t *testing.T) {
	tests := []struct {
		v    uint32
		want string
	}{
		{0x00000001, "QUIC v1"},
		{0x6b3343cf, "QUIC v2"},
		{0xff00001d, "draft-29"},
		{0xff000020, "draft-32"},
		{0xff000001, "draft-1"},
		{0x00000000, "Version Negotiation"},
		{0x0a0a0a0a, "reserved (0x0a0a0a0a)"},
		{0xfa7a1a9a, "reserved (0xfa7a1a9a)"},
		{0xdeadbeef, "unknown (0xdeadbeef)"},
		{0xfe00001d, "unknown (0xfe00001d)"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, models.QUICVersionName(tt.v), fmt.Sprintf("%#x", tt.v))
	}
	d, ok := models.QUICDraft(0xff00001d)
	assert.True(t, ok)
	assert.Equal(t, 29, d)
	_, ok = models.QUICDraft(1)
	assert.False(t, ok)
}

func TestQUICVersionNegotiation(t *testing.T) {
	t.Run("the client's version comes from the Initial the packet echoes", func(t *testing.T) {
		issues := quicIssues(t, []udpPkt{
			toQServer(0, 0, qinit(draft29, cDCID, cSCID)),
			fromQServer(100*time.Millisecond, 0, qvneg(cSCID, cDCID, 1, models.QUICVersion2)),
			toQServer(200*time.Millisecond, 0, qinit(1, cDCID, cSCID)),
			fromQServer(300*time.Millisecond, 0, qinit(1, cSCID, sSCID)),
		})
		vn := issuesTitled(issues, titleQUICVersionNeg)
		require.Len(t, vn, 1)
		assert.Equal(t, models.SeverityInfo, vn[0].Severity)
		assert.Equal(t, "client requested draft-29, server offered QUIC v1, QUIC v2 (server 192.0.2.10:443)", vn[0].Description)
		assert.Equal(t, "192.0.2.10:443", vn[0].Target)
		assert.Equal(t, 1, vn[0].Count)
	})
	t.Run("a packet that echoes nothing we saw", func(t *testing.T) {
		vn := issuesTitled(quicIssues(t, []udpPkt{fromQServer(0, 0, qvneg([]byte{9, 9}, []byte{8, 8}, 1))}), titleQUICVersionNeg)
		require.Len(t, vn, 1)
		assert.Equal(t, "client requested an unknown version, server offered QUIC v1 (server 192.0.2.10:443)", vn[0].Description)
	})
	t.Run("a greased version provokes it", func(t *testing.T) {
		vn := issuesTitled(quicIssues(t, []udpPkt{
			toQServer(0, 0, qinit(0x1a2a3a4a, cDCID, cSCID)),
			fromQServer(time.Millisecond, 0, qvneg(cSCID, cDCID, 1, draft29)),
		}), titleQUICVersionNeg)
		require.Len(t, vn, 1)
		assert.Equal(t, "client requested reserved (0x1a2a3a4a), server offered QUIC v1, draft-29 (server 192.0.2.10:443)", vn[0].Description)
	})
	t.Run("several from one server are folded into one issue", func(t *testing.T) {
		var pkts []udpPkt
		for n := 0; n < 3; n++ {
			cid := []byte{byte(n + 1), 7, 7, 7}
			pkts = append(pkts, toQServer(time.Duration(n)*time.Second, n, qinit(draft29, cDCID, cid)),
				fromQServer(time.Duration(n)*time.Second+time.Millisecond, n, qvneg(cid, cDCID, 1)))
		}
		vn := issuesTitled(quicIssues(t, pkts), titleQUICVersionNeg)
		require.Len(t, vn, 1)
		assert.Equal(t, 3, vn[0].Count)
		assert.Len(t, vn[0].Occurrences, 3)
		assert.Equal(t, "3 Version Negotiation packets from server 192.0.2.10:443: client requested draft-29 (3x); server offered QUIC v1", vn[0].Description)
	})
	t.Run("two servers, two issues", func(t *testing.T) {
		other := fromQServer(0, 1, qvneg(cSCID, cDCID, 1))
		other.from = "192.0.2.20"
		issues := issuesTitled(quicIssues(t, []udpPkt{fromQServer(0, 0, qvneg(cSCID, cDCID, 1)), other}), titleQUICVersionNeg)
		assert.Len(t, issues, 2)
	})
	t.Run("a client's own Version Negotiation-looking packet is not reported", func(t *testing.T) {
		// only the server's side counts
		assert.Empty(t, issuesTitled(quicIssues(t, []udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), toQServer(time.Second, 0, qvneg(cSCID, cDCID, 1))}), titleQUICVersionNeg))
	})
}

func TestQUICRetry(t *testing.T) {
	t.Run("one Retry names the client", func(t *testing.T) {
		issues := quicIssues(t, []udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), fromQServer(time.Millisecond, 0, qretry(1, cSCID, sSCID))})
		retry := issuesTitled(issues, titleQUICRetry)
		require.Len(t, retry, 1)
		assert.Equal(t, models.SeverityInfo, retry[0].Severity)
		assert.Equal(t, "server requested address validation (Retry from server 192.0.2.10:443 to client 192.0.2.1:50000)", retry[0].Description)
		assert.Empty(t, issuesTitled(issues, titleQUICTimeout), "a Retry is an answer")
	})
	t.Run("a v2 Retry", func(t *testing.T) {
		retry := issuesTitled(quicIssues(t, []udpPkt{
			toQServer(0, 0, qinit(models.QUICVersion2, cDCID, cSCID)), fromQServer(time.Millisecond, 0, qretry(models.QUICVersion2, cSCID, sSCID))}), titleQUICRetry)
		require.Len(t, retry, 1)
	})
	t.Run("several Retries from one server are folded", func(t *testing.T) {
		var pkts []udpPkt
		for n := 0; n < 4; n++ {
			pkts = append(pkts, toQServer(time.Duration(n)*time.Second, n, qinit(1, cDCID, cSCID)), fromQServer(time.Duration(n)*time.Second+time.Millisecond, n, qretry(1, cSCID, sSCID)))
		}
		retry := issuesTitled(quicIssues(t, pkts), titleQUICRetry)
		require.Len(t, retry, 1)
		assert.Equal(t, 4, retry[0].Count)
		assert.Equal(t, "server requested address validation (4 Retry packets from server 192.0.2.10:443)", retry[0].Description)
		assert.Len(t, retry[0].Occurrences, 4)
	})
	t.Run("a normal handshake raises nothing", func(t *testing.T) {
		assert.Empty(t, quicIssues(t, []udpPkt{
			toQServer(0, 0, qinit(1, cDCID, cSCID)),
			fromQServer(50*time.Millisecond, 0, append(qinit(1, cSCID, sSCID), qhand(1, cSCID, sSCID)...)),
			toQServer(100*time.Millisecond, 0, qhand(1, sSCID, cSCID)),
			toQServer(time.Minute, 0, qshort(sSCID)),
		}))
	})
}

func TestQUICHandshakeTimeout(t *testing.T) {
	cl := func(at time.Duration, n int) udpPkt { return toQServer(at, n, qinit(1, cDCID, cSCID)) }
	srvInit := func(at time.Duration, n int) udpPkt { return fromQServer(at, n, qinit(1, cSCID, sSCID)) }

	tests := []struct {
		name      string
		pkts      []udpPkt
		wantDesc  string // "" means no issue
		wantCount int
	}{
		{"no answer, the capture running on", []udpPkt{cl(0, 0), later(30 * time.Second)},
			"no server response to Client Initial (from 192.0.2.1:50000 to 192.0.2.10:443, 1 Initial packet, waited 10s)", 1},
		{"exactly 10 seconds of capture is enough to judge", []udpPkt{cl(0, 0), later(10 * time.Second)},
			"no server response to Client Initial (from 192.0.2.1:50000 to 192.0.2.10:443, 1 Initial packet, waited 10s)", 1},
		{"retransmitted Initials count as one connection", []udpPkt{cl(0, 0), cl(time.Second, 0), cl(3*time.Second, 0), later(30 * time.Second)},
			"no server response to Client Initial (from 192.0.2.1:50000 to 192.0.2.10:443, 3 Initial packets, waited 10s)", 1},
		{"the capture ended too soon to tell", []udpPkt{cl(0, 0), later(5 * time.Second)}, "", 0},
		{"the Initial was the last packet", []udpPkt{cl(0, 0)}, "", 0},
		{"answered by a server Initial", []udpPkt{cl(0, 0), srvInit(time.Second, 0), later(60 * time.Second)}, "", 0},
		{"answered by Version Negotiation", []udpPkt{cl(0, 0), fromQServer(time.Second, 0, qvneg(cSCID, cDCID, 1)), later(60 * time.Second)}, "", 0},
		{"answered by anything the server sends back", []udpPkt{cl(0, 0), fromQServer(time.Second, 0, qshort(cSCID)), later(60 * time.Second)}, "", 0},
		{"answered just in time", []udpPkt{cl(0, 0), srvInit(10*time.Second, 0), later(60 * time.Second)}, "", 0},
		{"answered late, after 12 seconds", []udpPkt{cl(0, 0), srvInit(12*time.Second, 0)},
			"the server answered the Client Initial only after 12s (from 192.0.2.1:50000 to 192.0.2.10:443, 1 Initial packet, waited 10s)", 1},
		{"a packet from another client's port does not answer", []udpPkt{cl(0, 0), srvInit(time.Second, 1), later(30 * time.Second)},
			"no server response to Client Initial (from 192.0.2.1:50000 to 192.0.2.10:443, 1 Initial packet, waited 10s)", 1},
		{"two clients to one server are folded into one issue", []udpPkt{cl(0, 0), cl(time.Second, 1), later(30 * time.Second)},
			"2 client connections to 192.0.2.10:443 got no server response within 10s (2 Initial packets sent); first: no server response to Client Initial from 192.0.2.1:50000", 2},
		{"capture started after the handshake: the server's Initial is not a client's",
			[]udpPkt{srvInit(0, 0), later(30 * time.Second)}, "", 0},
		{"the capture started mid-handshake and the client never answered: not our business",
			[]udpPkt{srvInit(0, 0), toQServer(time.Second, 0, qhand(1, sSCID, cSCID)), later(30 * time.Second)}, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeouts := issuesTitled(quicIssues(t, tt.pkts), titleQUICTimeout)
			if tt.wantCount == 0 {
				assert.Empty(t, timeouts)
				return
			}
			require.Len(t, timeouts, 1)
			is := timeouts[0]
			assert.Equal(t, models.SeverityWarning, is.Severity)
			assert.Equal(t, tt.wantDesc, is.Description)
			assert.Equal(t, tt.wantCount, is.Count)
			assert.Len(t, is.Occurrences, tt.wantCount)
			assert.Equal(t, "192.0.2.10:443", is.Target)
			assert.Contains(t, is.Protocols, "QUIC")
		})
	}

	t.Run("a merged capture does not make every client Initial look unanswered", func(t *testing.T) {
		assert.Empty(t, issuesTitled(quicIssues(t, []udpPkt{cl(0, 0), later(24 * 365 * 3 * time.Hour)}), titleQUICTimeout))
		assert.Empty(t, issuesTitled(quicIssues(t, []udpPkt{later(500 * time.Second), cl(400*time.Second, 0), later(100 * time.Second)}), titleQUICTimeout))
	})
	t.Run("servers are judged separately", func(t *testing.T) {
		other := cl(time.Second, 1)
		other.to = "192.0.2.20"
		timeouts := issuesTitled(quicIssues(t, []udpPkt{cl(0, 0), other, later(30 * time.Second)}), titleQUICTimeout)
		require.Len(t, timeouts, 2)
		targets := []string{timeouts[0].Target, timeouts[1].Target}
		assert.ElementsMatch(t, []string{"192.0.2.10:443", "192.0.2.20:443"}, targets)
	})
}

func TestQUICDraftVersions(t *testing.T) {
	t.Run("a client using draft-29", func(t *testing.T) {
		drafts := issuesTitled(quicIssues(t, []udpPkt{toQServer(0, 0, qinit(draft29, cDCID, cSCID)), fromQServer(time.Millisecond, 0, qinit(draft29, cSCID, sSCID))}), titleQUICDraft)
		require.Len(t, drafts, 1)
		assert.Equal(t, models.SeverityInfo, drafts[0].Severity)
		assert.Equal(t, "client using draft-29 (192.0.2.1:50000 to 192.0.2.10:443)", drafts[0].Description)
		assert.Equal(t, 1, drafts[0].Count)
	})
	t.Run("one issue per draft, folding the connections", func(t *testing.T) {
		pkts := []udpPkt{
			toQServer(0, 0, qinit(draft29, cDCID, cSCID)), toQServer(time.Second, 1, qinit(draft29, cDCID, cSCID)), toQServer(2*time.Second, 2, qinit(draft27, cDCID, cSCID)),
		}
		drafts := issuesTitled(quicIssues(t, pkts), titleQUICDraft)
		require.Len(t, drafts, 2)
		byTitle := map[string]models.Issue{}
		for _, d := range drafts {
			byTitle[d.ID] = d
		}
		assert.Equal(t, 2, byTitle["quic-draft-29"].Count)
		assert.Equal(t, "1 client using draft-29, an early version of QUIC that servers may drop (2 connections; first: 192.0.2.1:50000 to 192.0.2.10:443)", byTitle["quic-draft-29"].Description)
		assert.Equal(t, 1, byTitle["quic-draft-27"].Count)
		assert.Equal(t, "client using draft-27 (192.0.2.1:50002 to 192.0.2.10:443)", byTitle["quic-draft-27"].Description)
	})
	t.Run("a draft the server spoke is not the client's", func(t *testing.T) {
		assert.Empty(t, issuesTitled(quicIssues(t, []udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), fromQServer(time.Millisecond, 0, qinit(draft29, cSCID, sSCID))}), titleQUICDraft))
	})
	t.Run("v1 and v2 are not drafts", func(t *testing.T) {
		assert.Empty(t, issuesTitled(quicIssues(t, []udpPkt{toQServer(0, 0, qinit(1, cDCID, cSCID)), toQServer(time.Second, 1, qinit(models.QUICVersion2, cDCID, cSCID))}), titleQUICDraft))
	})
}
