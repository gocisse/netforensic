package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

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

// Golden encodings of packets with handshake times, produced by the code from
// before the times moved into Handshake, when they were four fields of PacketInfo.
var (
	hsT0 = time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)

	goldenHandshakeAll     = `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":40000,"dst_port":443,"protocol":"TCP","size":60,"payload_size":0,"tcp_flags":"SYN","tcp_syn_time":"2024-01-02T03:04:05.123456789Z","tcp_syn_ack_time":"2024-01-02T03:04:05.143456789Z","tcp_ack_time":"2024-01-02T03:04:05.163456789Z","first_data_time":"2024-01-02T03:04:05.213456789Z","tls_version":"TLS 1.2"}`
	goldenHandshakePartial = `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"10.0.0.1","dst_ip":"","src_port":0,"dst_port":0,"protocol":"TCP","size":0,"payload_size":0,"tcp_syn_time":"2024-01-02T03:04:05.123456789Z","tcp_syn_ack_time":"2024-01-02T03:04:05.143456789Z","tcp_ack_time":"0001-01-01T00:00:00Z","first_data_time":"0001-01-01T00:00:00Z","http_method":"GET"}`
	goldenHandshakeWithSIP = `{"timestamp":"0001-01-01T00:00:00Z","src_ip":"","dst_ip":"","src_port":0,"dst_port":0,"protocol":"UDP","size":0,"payload_size":0,"tcp_syn_time":"0001-01-01T00:00:00Z","tcp_syn_ack_time":"0001-01-01T00:00:00Z","tcp_ack_time":"2024-01-02T04:04:05.123456789+01:00","first_data_time":"0001-01-01T00:00:00Z","sip_method":"INVITE"}`
)

func hsAllPacket() PacketInfo {
	return PacketInfo{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 443, Protocol: ProtocolTCP, Size: 60, TCPFlags: "SYN", TLSVersion: "TLS 1.2",
		Handshake: &HandshakeTimes{TCPSynTime: hsT0, TCPSynAckTime: hsT0.Add(20 * time.Millisecond), TCPAckTime: hsT0.Add(40 * time.Millisecond), FirstDataTime: hsT0.Add(90 * time.Millisecond)}}
}

func TestPacketInfoJSONHandshakeIsFlatAndMatchesTheOldEncoding(t *testing.T) {
	partial := PacketInfo{SrcIP: "10.0.0.1", Protocol: ProtocolTCP, HTTPMethod: "GET",
		Handshake: &HandshakeTimes{TCPSynTime: hsT0, TCPSynAckTime: hsT0.Add(20 * time.Millisecond)}}
	withSIP := PacketInfo{Protocol: ProtocolUDP, SIPInfo: &SIPInfo{SIPMethod: "INVITE"},
		Handshake: &HandshakeTimes{TCPAckTime: hsT0.In(time.FixedZone("x", 3600))}}
	for name, c := range map[string]struct {
		p    PacketInfo
		want string
	}{"all": {hsAllPacket(), goldenHandshakeAll}, "partial": {partial, goldenHandshakePartial}, "with_sip": {withSIP, goldenHandshakeWithSIP}} {
		t.Run(name, func(t *testing.T) {
			got, err := json.Marshal(c.p)
			require.NoError(t, err)
			assert.Equal(t, c.want, string(got))
			assert.NotContains(t, string(got), "handshake")
		})
	}
}

func TestPacketInfoJSONZeroHandshakeTimesAreStillWritten(t *testing.T) {
	zero := "0001-01-01T00:00:00Z"
	for name, p := range map[string]PacketInfo{
		"nil handshake":   {SrcIP: "a"},
		"empty handshake": {SrcIP: "a", Handshake: &HandshakeTimes{}},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(p)
			require.NoError(t, err)
			var m map[string]any
			require.NoError(t, json.Unmarshal(b, &m))
			for _, k := range []string{"tcp_syn_time", "tcp_syn_ack_time", "tcp_ack_time", "first_data_time"} {
				assert.Equal(t, zero, m[k], k)
			}
			s := string(b)
			order := []string{`"payload_size"`, `"tcp_syn_time"`, `"tcp_syn_ack_time"`, `"tcp_ack_time"`, `"first_data_time"`}
			for i := 1; i < len(order); i++ {
				assert.Less(t, strings.Index(s, order[i-1]), strings.Index(s, order[i]), "%s before %s", order[i-1], order[i])
			}
		})
	}
	// With only zero times set after the ICMP-free fields, the next field follows directly.
	b, err := json.Marshal(PacketInfo{ICMPType: 3})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"first_data_time":"0001-01-01T00:00:00Z","icmp_type":3`)
}

func TestPacketInfoJSONHandshakeInASlice(t *testing.T) {
	got, err := json.Marshal([]PacketInfo{hsAllPacket(), {}, hsAllPacket()})
	require.NoError(t, err)
	want := "[" + goldenHandshakeAll + "," + goldenJSON["zero"] + "," + goldenHandshakeAll + "]"
	assert.Equal(t, want, string(got))

	var back []PacketInfo
	require.NoError(t, json.Unmarshal(got, &back))
	require.Len(t, back, 3)
	assert.Nil(t, back[1].Handshake, "four zero times are no handshake")
	assert.True(t, hsT0.Equal(back[2].Handshake.TCPSynTime))
	assert.NotSame(t, back[0].Handshake, back[2].Handshake, "decoded packets do not share a group")
}

func TestPacketInfoJSONHandshakeRoundTripAndLegacy(t *testing.T) {
	p := hsAllPacket()
	b, err := json.Marshal(p)
	require.NoError(t, err)
	var again PacketInfo
	require.NoError(t, json.Unmarshal(b, &again))
	assert.Equal(t, p, again)

	var legacy PacketInfo // the flat encoding from before the change
	require.NoError(t, json.Unmarshal([]byte(goldenHandshakeAll), &legacy))
	assert.Equal(t, p, legacy)

	var partial PacketInfo
	require.NoError(t, json.Unmarshal([]byte(goldenHandshakePartial), &partial))
	require.NotNil(t, partial.Handshake)
	assert.True(t, hsT0.Equal(partial.Handshake.TCPSynTime))
	assert.True(t, hsT0.Add(20*time.Millisecond).Equal(partial.Handshake.TCPSynAckTime))
	assert.True(t, partial.Handshake.TCPAckTime.IsZero())
	assert.True(t, partial.Handshake.FirstDataTime.IsZero())
}

func TestPacketInfoUnmarshalMergesHandshakeTimes(t *testing.T) {
	existing := HandshakeTimes{TCPSynTime: hsT0, TCPSynAckTime: hsT0.Add(time.Second), TCPAckTime: hsT0.Add(2 * time.Second), FirstDataTime: hsT0.Add(3 * time.Second)}
	zero := `"0001-01-01T00:00:00Z"`
	t.Run("omitted keys keep the existing times", func(t *testing.T) {
		h := existing
		p := PacketInfo{SrcIP: "a", Handshake: &h}
		require.NoError(t, json.Unmarshal([]byte(`{"dst_ip":"b"}`), &p))
		assert.Same(t, &h, p.Handshake, "no new object when nothing is mentioned")
		assert.Equal(t, existing, *p.Handshake)
	})
	t.Run("a mentioned time replaces just that time", func(t *testing.T) {
		h := existing
		p := PacketInfo{Handshake: &h}
		require.NoError(t, json.Unmarshal([]byte(`{"tcp_ack_time":"2030-05-06T07:08:09Z"}`), &p))
		want := existing
		want.TCPAckTime = time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
		assert.Equal(t, want, *p.Handshake)
	})
	t.Run("an explicit zero time clears that time", func(t *testing.T) {
		h := existing
		p := PacketInfo{Handshake: &h}
		require.NoError(t, json.Unmarshal([]byte(`{"first_data_time":`+zero+`}`), &p))
		want := existing
		want.FirstDataTime = time.Time{}
		assert.Equal(t, want, *p.Handshake)
	})
	t.Run("clearing every time leaves no handshake", func(t *testing.T) {
		h := existing
		p := PacketInfo{Handshake: &h}
		in := `{"tcp_syn_time":` + zero + `,"tcp_syn_ack_time":` + zero + `,"tcp_ack_time":` + zero + `,"first_data_time":` + zero + `}`
		require.NoError(t, json.Unmarshal([]byte(in), &p))
		assert.Nil(t, p.Handshake)
	})
	t.Run("explicit zero times make no handshake", func(t *testing.T) {
		var p PacketInfo
		require.NoError(t, json.Unmarshal([]byte(goldenJSON["zero"]), &p))
		assert.Nil(t, p.Handshake)
	})
	t.Run("a null time is no change", func(t *testing.T) {
		h := existing
		p := PacketInfo{Handshake: &h}
		require.NoError(t, json.Unmarshal([]byte(`{"tcp_syn_time":null}`), &p))
		assert.Same(t, &h, p.Handshake)
		assert.Equal(t, existing, *p.Handshake)
	})
	t.Run("null leaves the packet and its handshake unchanged", func(t *testing.T) {
		h := existing
		p := PacketInfo{SrcIP: "a", Handshake: &h}
		require.NoError(t, json.Unmarshal([]byte(`null`), &p))
		assert.Equal(t, PacketInfo{SrcIP: "a", Handshake: &existing}, p)
		assert.Same(t, &h, p.Handshake)
	})
	t.Run("ordinary and SIP fields survive a handshake-only input", func(t *testing.T) {
		p := PacketInfo{SrcIP: "a", HTTPMethod: "GET", SIPInfo: &SIPInfo{SIPMethod: "BYE"}}
		require.NoError(t, json.Unmarshal([]byte(`{"tcp_syn_time":"2030-05-06T07:08:09Z"}`), &p))
		assert.Equal(t, "a", p.SrcIP)
		assert.Equal(t, "GET", p.HTTPMethod)
		assert.Equal(t, &SIPInfo{SIPMethod: "BYE"}, p.SIPInfo)
		require.NotNil(t, p.Handshake)
		assert.Equal(t, time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC), p.Handshake.TCPSynTime)
	})
	t.Run("a bad time is an error", func(t *testing.T) {
		assert.Error(t, json.Unmarshal([]byte(`{"tcp_syn_time":"yesterday"}`), new(PacketInfo)))
		p := PacketInfo{Handshake: &HandshakeTimes{TCPSynTime: hsT0}}
		assert.Error(t, json.Unmarshal([]byte(`{"tcp_ack_time":5}`), &p))
		require.NotNil(t, p.Handshake)
		assert.Equal(t, hsT0, p.Handshake.TCPSynTime, "the existing group survives a failed decode")
	})
}

func TestPacketInfoUnmarshalDoesNotModifyASharedHandshake(t *testing.T) {
	shared := &HandshakeTimes{TCPSynTime: hsT0, TCPAckTime: hsT0.Add(time.Second)}
	before := *shared
	a := PacketInfo{SrcIP: "a", Handshake: shared}
	b := a // a copy shares the group, as the packets of one connection do

	require.NoError(t, json.Unmarshal([]byte(`{"tcp_ack_time":"2030-05-06T07:08:09Z","first_data_time":"2030-05-06T07:08:10Z"}`), &a))
	assert.Equal(t, before, *shared, "the shared group is not modified")
	assert.Same(t, shared, b.Handshake)
	assert.NotSame(t, shared, a.Handshake)
	assert.Equal(t, hsT0, a.Handshake.TCPSynTime, "unmentioned times are copied over")

	// The reserved key is not input: it neither fills nor changes a group.
	c := PacketInfo{Handshake: shared}
	require.NoError(t, json.Unmarshal([]byte(`{"`+handshakeInlineKey+`":{"tcp_syn_time":"2030-01-01T00:00:00Z"}}`), &c))
	assert.Equal(t, before, *shared)
	assert.Same(t, shared, c.Handshake)
	var d PacketInfo
	require.NoError(t, json.Unmarshal([]byte(`{"`+handshakeInlineKey+`":{"tcp_syn_time":"2030-01-01T00:00:00Z"}}`), &d))
	assert.Nil(t, d.Handshake)
}

func TestPacketInfoJSONReservedHandshakeKeyIsNeverWritten(t *testing.T) {
	for _, p := range []PacketInfo{{}, hsAllPacket()} {
		b, err := json.Marshal(p)
		require.NoError(t, err)
		assert.NotContains(t, string(b), handshakeInlineKey)
	}
	f, ok := reflect.TypeOf(PacketInfo{}).FieldByName("Handshake")
	require.True(t, ok)
	assert.Equal(t, handshakeInlineKey, f.Tag.Get("json"))
}
