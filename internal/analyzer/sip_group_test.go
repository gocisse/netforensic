package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

var groupT0 = time.Unix(1700000000, 0)

// groupUDP is a UDP packet between two fixed endpoints on port 7000, so that
// only its content, not a well-known SIP port, can make it SIP.
func groupUDP(ms int, fromClient bool) models.PacketInfo {
	p := models.PacketInfo{Timestamp: groupT0.Add(time.Duration(ms) * time.Millisecond), Protocol: models.ProtocolUDP, Size: 100,
		SrcIP: "10.0.0.1", SrcPort: 7000, DstIP: "10.0.0.2", DstPort: 7000}
	if !fromClient {
		p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
	}
	return p
}

func TestClassifyFlowsSIPGroup(t *testing.T) {
	tests := []struct {
		name string
		sip  *models.SIPInfo
		want models.Protocol
	}{
		{"no SIP group", nil, ""},
		{"an empty SIP group", &models.SIPInfo{}, ""},
		{"a request", &models.SIPInfo{SIPMethod: "INVITE"}, models.ProtocolSIP},
		{"a response", &models.SIPInfo{SIPStatusCode: 200}, models.ProtocolSIP},
		{"a group with no method or status", &models.SIPInfo{SIPCallID: "c"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := groupUDP(0, true)
			p.SIPInfo = tt.sip
			classes, _ := classifyFlows([]models.PacketInfo{p, groupUDP(10, false)})
			require.Len(t, classes, 1)
			for _, c := range classes {
				assert.Equal(t, tt.want, c.app)
			}
		})
	}
}

func TestNoteSIPGroup(t *testing.T) {
	tests := []struct {
		name string
		sip  []*models.SIPInfo
		want models.Flow
	}{
		{"nil group leaves the flow alone", []*models.SIPInfo{nil}, models.Flow{}},
		{"empty group leaves the flow alone", []*models.SIPInfo{{}}, models.Flow{}},
		{"a request sets method, call and agent", []*models.SIPInfo{{SIPMethod: "INVITE", SIPCallID: "c1", SIPUserAgent: "UA"}},
			models.Flow{SIPMethod: "INVITE", SIPCallID: "c1", SIPUserAgent: "UA"}},
		{"a response sets call and agent only", []*models.SIPInfo{{SIPStatusCode: 200, SIPCallID: "c1", SIPUserAgent: "S"}},
			models.Flow{SIPCallID: "c1", SIPUserAgent: "S"}},
		{"each method once, first call and agent kept", []*models.SIPInfo{
			{SIPMethod: "INVITE", SIPCallID: "c1", SIPUserAgent: "A"}, nil, {SIPMethod: "INVITE", SIPCallID: "c2", SIPUserAgent: "B"},
			{SIPMethod: "BYE", SIPCallID: "c3"}},
			models.Flow{SIPMethod: "INVITE,BYE", SIPCallID: "c1", SIPUserAgent: "A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f models.Flow
			for _, s := range tt.sip {
				p := groupUDP(0, true)
				p.SIPInfo = s
				noteSIP(&f, p)
			}
			assert.Equal(t, tt.want, f)
		})
	}
}

func TestAnalyzeSIPGroupWithNonSIPPackets(t *testing.T) {
	var pk []models.PacketInfo
	at := 0
	add := func(fromClient bool, s *models.SIPInfo) {
		p := groupUDP(at, fromClient)
		p.SIPInfo = s
		pk = append(pk, p)
		at += 10
	}
	add(true, nil) // non-SIP traffic before, between and after the messages
	add(true, &models.SIPInfo{SIPMethod: "REGISTER", SIPCallID: "r1", SIPCSeq: 1, SIPCSeqMethod: "REGISTER", SIPUserAgent: "Phone/1"})
	add(false, nil)
	add(false, &models.SIPInfo{SIPStatusCode: 403, SIPReason: "Forbidden", SIPCallID: "r1", SIPCSeq: 1, SIPCSeqMethod: "REGISTER"})
	add(true, &models.SIPInfo{}) // an empty group is not a message
	add(true, nil)

	issues := analyzeSIP(pk)
	require.Len(t, issues, 1)
	assert.Equal(t, "SIP Registration Failed", issues[0].Title)
	assert.Contains(t, issues[0].Description, "403 Forbidden")

	assert.Empty(t, analyzeSIP([]models.PacketInfo{groupUDP(0, true), groupUDP(1, false)}), "no SIP at all")
	assert.Empty(t, analyzeSIP(nil))
}
