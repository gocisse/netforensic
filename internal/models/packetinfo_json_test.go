package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenJSON is the encoding of goldenPackets() as produced by the code from
// before the SIP fields moved into SIPInfo, when they were fields of
// PacketInfo. The SIP members must stay flat, at the same position, with the
// same omission rules.
var goldenJSON = map[string]string{
	"non_sip":         `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":5060,"dst_port":5060,"protocol":"UDP","size":100,"payload_size":58,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET","tls_version":"TLS 1.2","dhcpv6_msg_type":1}`,
	"sip_empty_group": `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":5060,"dst_port":5060,"protocol":"UDP","size":100,"payload_size":58,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET","tls_version":"TLS 1.2","dhcpv6_msg_type":1}`,
	"sip_only_status": `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":5060,"dst_port":5060,"protocol":"UDP","size":100,"payload_size":58,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET","tls_version":"TLS 1.2","sip_status_code":200,"dhcpv6_msg_type":1}`,
	"sip_request":     `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":5060,"dst_port":5060,"protocol":"UDP","size":100,"payload_size":58,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET","tls_version":"TLS 1.2","sip_version":"SIP/2.0","sip_method":"INVITE","sip_uri":"sip:bob@example.com;user=phone","sip_call_id":"a84b@10.0.0.1","sip_from":"\"Alice\" \u003csip:a@x\u003e;tag=1","sip_to":"\u003csip:bob@x\u003e","sip_contact":"\u003csip:a@10.0.0.1:5060\u003e","sip_user_agent":"Linphone/4.1 \u003c\u0026\u003e","sip_cseq":314159,"sip_cseq_method":"INVITE","dhcpv6_msg_type":1}`,
	"sip_response":    `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":5060,"dst_port":5060,"protocol":"UDP","size":100,"payload_size":58,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET","tls_version":"TLS 1.2","sip_version":"SIP/2.0","sip_status_code":486,"sip_reason":"Busy Here","sip_call_id":"c1","sip_user_agent":"PBX","sip_cseq":1,"sip_cseq_method":"INVITE","dhcpv6_msg_type":1}`,
	"zero":            `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"","size":0,"payload_size":0,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z"}`,
}

func goldenPackets() map[string]PacketInfo {
	base := PacketInfo{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 5060, DstPort: 5060, Protocol: ProtocolUDP, Size: 100, PayloadSize: 58,
		HTTPMethod: "GET", TLSVersion: "TLS 1.2", DHCPv6MsgType: 1}
	m := map[string]PacketInfo{}
	m["non_sip"] = base
	p := base
	p.SIPInfo = &SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPURI: "sip:bob@example.com;user=phone",
		SIPCallID: "a84b@10.0.0.1", SIPFrom: "\"Alice\" <sip:a@x>;tag=1", SIPTo: "<sip:bob@x>", SIPContact: "<sip:a@10.0.0.1:5060>",
		SIPUserAgent: "Linphone/4.1 <&>", SIPCSeq: 314159, SIPCSeqMethod: "INVITE"}
	m["sip_request"] = p
	p = base
	p.SIPInfo = &SIPInfo{SIPVersion: "SIP/2.0", SIPStatusCode: 486, SIPReason: "Busy Here", SIPCallID: "c1", SIPCSeq: 1, SIPCSeqMethod: "INVITE", SIPUserAgent: "PBX"}
	m["sip_response"] = p
	p = base
	p.SIPInfo = &SIPInfo{}
	m["sip_empty_group"] = p
	p = base
	p.SIPInfo = &SIPInfo{SIPStatusCode: 200}
	m["sip_only_status"] = p
	m["zero"] = PacketInfo{}
	return m
}

func TestPacketInfoJSONKeepsSIPFlat(t *testing.T) {
	for name, p := range goldenPackets() {
		t.Run(name, func(t *testing.T) {
			got, err := json.Marshal(p)
			require.NoError(t, err)
			assert.Equal(t, goldenJSON[name], string(got))
		})
	}
}

func TestPacketInfoJSONInASlice(t *testing.T) {
	pk := goldenPackets()
	got, err := json.Marshal([]PacketInfo{pk["non_sip"], pk["sip_request"], pk["sip_empty_group"]})
	require.NoError(t, err)
	want := "[" + goldenJSON["non_sip"] + "," + goldenJSON["sip_request"] + "," + goldenJSON["sip_empty_group"] + "]"
	assert.Equal(t, want, string(got))
}

func TestPacketInfoJSONNeverLeaksTheReservedKey(t *testing.T) {
	for name, p := range goldenPackets() {
		b, err := json.Marshal(p)
		require.NoError(t, err)
		assert.NotContains(t, string(b), sipInlineKey, name)
		assert.NotContains(t, string(b), `"SIPInfo"`, name)
	}
	var m map[string]any
	b, err := json.Marshal(goldenPackets()["sip_request"])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, "INVITE", m["sip_method"])
}

func TestPacketInfoJSONReservedKeyMatchesTheTag(t *testing.T) {
	f, ok := reflect.TypeOf(PacketInfo{}).FieldByName("SIPInfo")
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(f.Tag.Get("json"), sipInlineKey+","), f.Tag.Get("json"))
}

func TestPacketInfoJSONRoundTrip(t *testing.T) {
	for name, p := range goldenPackets() {
		t.Run(name, func(t *testing.T) {
			if p.SIPInfo != nil && *p.SIPInfo == (SIPInfo{}) {
				p.SIPInfo = nil // an empty group is not told apart from none
			}
			b, err := json.Marshal(p)
			require.NoError(t, err)
			var again PacketInfo
			require.NoError(t, json.Unmarshal(b, &again))
			assert.Equal(t, p, again)

			var legacy PacketInfo // the encoding from before the change
			require.NoError(t, json.Unmarshal([]byte(goldenJSON[name]), &legacy))
			assert.Equal(t, p, legacy)
		})
	}
}

func TestPacketInfoUnmarshalSIPMembers(t *testing.T) {
	var many []PacketInfo
	in := `[{"src_ip":"1.1.1.1","sip_status_code":486,"sip_reason":"Busy Here","http_method":"GET"},{"src_ip":"2.2.2.2"},{"sip_method":""}]`
	require.NoError(t, json.Unmarshal([]byte(in), &many))
	require.Len(t, many, 3)
	assert.Equal(t, &SIPInfo{SIPStatusCode: 486, SIPReason: "Busy Here"}, many[0].SIPInfo)
	assert.Equal(t, "GET", many[0].HTTPMethod)
	assert.Nil(t, many[1].SIPInfo)
	assert.Nil(t, many[2].SIPInfo, "empty members make no group")
	assert.Error(t, json.Unmarshal([]byte(`{"sip_status_code":"x"}`), new(PacketInfo)))
}

func TestPacketInfoUnmarshalKeepsFieldsTheInputOmits(t *testing.T) {
	p := PacketInfo{SrcIP: "10.0.0.1", HTTPMethod: "GET", Size: 7}
	require.NoError(t, json.Unmarshal([]byte(`{"dst_ip":"10.0.0.2","size":9}`), &p))
	assert.Equal(t, PacketInfo{SrcIP: "10.0.0.1", HTTPMethod: "GET", Size: 9, DstIP: "10.0.0.2"}, p)

	var rest []PacketInfo = []PacketInfo{{SrcIP: "a"}, {SrcIP: "b", SIPInfo: &SIPInfo{SIPMethod: "BYE"}}}
	require.NoError(t, json.Unmarshal([]byte(`[{"dst_ip":"x"},{"dst_ip":"y"}]`), &rest))
	assert.Equal(t, "a", rest[0].SrcIP, "slice elements are reused")
	assert.Equal(t, &SIPInfo{SIPMethod: "BYE"}, rest[1].SIPInfo)
}

func TestPacketInfoUnmarshalNullLeavesTheValueUnchanged(t *testing.T) {
	want := PacketInfo{SrcIP: "10.0.0.1", SIPInfo: &SIPInfo{SIPMethod: "INVITE", SIPCallID: "c1"}}
	p := want
	require.NoError(t, json.Unmarshal([]byte(`null`), &p))
	assert.Equal(t, want, p)
	require.NoError(t, json.Unmarshal([]byte(" null\n"), &p))
	assert.Equal(t, want, p)

	var zero PacketInfo
	require.NoError(t, json.Unmarshal([]byte(`null`), &zero))
	assert.Equal(t, PacketInfo{}, zero)
}

func TestPacketInfoUnmarshalMergesSIPMembersIntoTheExistingGroup(t *testing.T) {
	shared := &SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPCallID: "c1", SIPUserAgent: "UA"}
	p := PacketInfo{SrcIP: "10.0.0.1", SIPInfo: shared}
	other := p // a copy shares the group

	require.NoError(t, json.Unmarshal([]byte(`{"sip_call_id":"c2","sip_cseq":5}`), &p))
	assert.Equal(t, &SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPCallID: "c2", SIPUserAgent: "UA", SIPCSeq: 5}, p.SIPInfo,
		"mentioned members change, the others stay")
	assert.Equal(t, "10.0.0.1", p.SrcIP)
	assert.Equal(t, &SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPCallID: "c1", SIPUserAgent: "UA"}, other.SIPInfo,
		"the group other copies share is not modified")

	t.Run("input without SIP members keeps the group as it is", func(t *testing.T) {
		q := PacketInfo{SIPInfo: shared}
		require.NoError(t, json.Unmarshal([]byte(`{"dst_ip":"x"}`), &q))
		assert.Same(t, shared, q.SIPInfo, "no new group is allocated")
	})
	t.Run("a mentioned empty member clears that member", func(t *testing.T) {
		q := PacketInfo{SIPInfo: &SIPInfo{SIPMethod: "INVITE", SIPCallID: "c1"}}
		require.NoError(t, json.Unmarshal([]byte(`{"sip_method":""}`), &q))
		assert.Equal(t, &SIPInfo{SIPCallID: "c1"}, q.SIPInfo)
	})
	t.Run("clearing every member leaves no group", func(t *testing.T) {
		q := PacketInfo{SIPInfo: &SIPInfo{SIPMethod: "INVITE"}}
		require.NoError(t, json.Unmarshal([]byte(`{"sip_method":""}`), &q))
		assert.Nil(t, q.SIPInfo)
	})
	t.Run("no group is made for input without SIP members", func(t *testing.T) {
		var q PacketInfo
		require.NoError(t, json.Unmarshal([]byte(`{"dst_ip":"x"}`), &q))
		assert.Nil(t, q.SIPInfo)
	})
}
