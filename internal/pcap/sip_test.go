package pcap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

func TestFillSIP(t *testing.T) {
	crlf := func(lines ...string) []byte { return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n") }

	tests := []struct {
		name    string
		payload []byte
		want    models.PacketInfo
	}{
		{
			name: "request with the headers the analysis uses",
			payload: crlf(
				"INVITE sip:bob@example.com;user=phone SIP/2.0",
				"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1",
				"From: \"Alice\" <sip:alice@example.com>;tag=abc",
				"To: <sip:bob@example.com>",
				"Call-ID: a84b4c76e66710@10.0.0.1",
				"CSeq: 314159 INVITE",
				"Contact: <sip:alice@10.0.0.1:5060>",
				"User-Agent: Linphone/4.1",
				"Content-Length: 0"),
			want: models.PacketInfo{SIPInfo: &models.SIPInfo{
				SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPURI: "sip:bob@example.com;user=phone",
				SIPCallID: "a84b4c76e66710@10.0.0.1", SIPFrom: "\"Alice\" <sip:alice@example.com>;tag=abc", SIPTo: "<sip:bob@example.com>",
				SIPContact: "<sip:alice@10.0.0.1:5060>", SIPUserAgent: "Linphone/4.1", SIPCSeq: 314159, SIPCSeqMethod: "INVITE",
			}},
		},
		{
			name:    "response: status code and reason phrase",
			payload: crlf("SIP/2.0 486 Busy Here", "Call-ID: c1", "CSeq: 1 INVITE", "Server: Asterisk PBX 18"),
			want: models.PacketInfo{SIPInfo: &models.SIPInfo{
				SIPVersion: "SIP/2.0", SIPStatusCode: 486, SIPReason: "Busy Here", SIPCallID: "c1",
				SIPCSeq: 1, SIPCSeqMethod: "INVITE", SIPUserAgent: "Asterisk PBX 18",
			}},
		},
		{
			name:    "a response without a reason phrase",
			payload: crlf("SIP/2.0 200", "Call-ID: c1"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPStatusCode: 200, SIPCallID: "c1"}},
		},
		{
			name:    "a reason phrase with several words",
			payload: crlf("SIP/2.0 407 Proxy Authentication Required", "Call-ID: c1"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPStatusCode: 407, SIPReason: "Proxy Authentication Required", SIPCallID: "c1"}},
		},
		{
			name:    "User-Agent wins over Server",
			payload: crlf("SIP/2.0 200 OK", "Server: S", "User-Agent: U"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPStatusCode: 200, SIPReason: "OK", SIPUserAgent: "U"}},
		},
		{
			name:    "compact header names and any letter case",
			payload: crlf("OPTIONS sip:x@y SIP/2.0", "i: compact-id", "f: <sip:a@b>", "t: <sip:c@d>", "m: <sip:e@f>", "cSeQ: 7 options", "USER-agent: UA"),
			want: models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "OPTIONS", SIPURI: "sip:x@y", SIPCallID: "compact-id", SIPFrom: "<sip:a@b>",
				SIPTo: "<sip:c@d>", SIPContact: "<sip:e@f>", SIPCSeq: 7, SIPCSeqMethod: "OPTIONS", SIPUserAgent: "UA"}},
		},
		{
			name:    "a folded header line",
			payload: crlf("REGISTER sip:example.com SIP/2.0", "Call-ID: abc", "User-Agent: Very", "  Long Agent", "CSeq: 2 REGISTER"),
			want: models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "REGISTER", SIPURI: "sip:example.com", SIPCallID: "abc",
				SIPUserAgent: "Very Long Agent", SIPCSeq: 2, SIPCSeqMethod: "REGISTER"}},
		},
		{
			name:    "bare line feeds instead of CRLF",
			payload: []byte("BYE sip:x@y SIP/2.0\nCall-ID: lf\nCSeq: 3 BYE\n\nbody: not a header\n"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "BYE", SIPURI: "sip:x@y", SIPCallID: "lf", SIPCSeq: 3, SIPCSeqMethod: "BYE"}},
		},
		{
			name:    "the first occurrence of a header is used, and the body is not read",
			payload: []byte("INVITE sip:x@y SIP/2.0\r\nCall-ID: first\r\nCall-ID: second\r\n\r\nCall-ID: in-the-body\r\nUser-Agent: body\r\n"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPURI: "sip:x@y", SIPCallID: "first"}},
		},
		{
			name:    "control characters from the network are removed",
			payload: crlf("INVITE sip:x@y SIP/2.0", "User-Agent: evil\x1b[2J\x07agent"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPURI: "sip:x@y", SIPUserAgent: "evil [2J agent"}},
		},
		{
			name:    "a CSeq with no number is ignored",
			payload: crlf("INVITE sip:x@y SIP/2.0", "CSeq: abc INVITE"),
			want:    models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "INVITE", SIPURI: "sip:x@y"}},
		},
		{name: "every method is recognized: SUBSCRIBE", payload: crlf("SUBSCRIBE sip:x@y SIP/2.0"), want: models.PacketInfo{SIPInfo: &models.SIPInfo{SIPVersion: "SIP/2.0", SIPMethod: "SUBSCRIBE", SIPURI: "sip:x@y"}}},

		// not SIP
		{name: "an HTTP request", payload: crlf("OPTIONS * HTTP/1.1", "Host: x")},
		{name: "an HTTP response", payload: crlf("HTTP/1.1 200 OK")},
		{name: "a different SIP version", payload: crlf("INVITE sip:x@y SIP/1.0")},
		{name: "an unknown method", payload: crlf("FETCH sip:x@y SIP/2.0")},
		{name: "a lowercase method", payload: crlf("invite sip:x@y SIP/2.0")},
		{name: "too many words in the request line", payload: crlf("INVITE sip:x@y extra SIP/2.0")},
		{name: "a status code that is not three digits", payload: crlf("SIP/2.0 20 OK")},
		{name: "a status code below 100", payload: crlf("SIP/2.0 099 Odd")},
		{name: "a status code above 699", payload: crlf("SIP/2.0 700 Odd")},
		{name: "a status code that is not a number", payload: crlf("SIP/2.0 abc OK")},
		{name: "empty", payload: nil},
		{name: "too short", payload: []byte("SIP/2.0")},
		{name: "binary data", payload: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got models.PacketInfo
			fillSIP(&got, tt.payload)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFillSIPBoundsWhatItReads(t *testing.T) {
	// A huge payload is not read past the header limit, and long values are cut.
	big := "INVITE sip:x@y SIP/2.0\r\nUser-Agent: " + strings.Repeat("a", 5000) + "\r\nCall-ID: late\r\n" + strings.Repeat("X-Pad: y\r\n", 5000) + "\r\n"
	var got models.PacketInfo
	fillSIP(&got, []byte(big))
	assert.Equal(t, "INVITE", got.SIPInfo.SIPMethod)
	assert.Len(t, []rune(got.SIPInfo.SIPUserAgent), maxMetaLen+1, "cut, with an ellipsis")
	assert.Equal(t, "late", got.SIPInfo.SIPCallID)
}
