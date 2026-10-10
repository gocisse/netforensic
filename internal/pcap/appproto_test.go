package pcap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

func be16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

// ext encodes a TLS extension.
func ext(typ int, data ...byte) []byte {
	return append(append(be16(typ), be16(len(data))...), data...)
}

// supportedVersionsClient encodes a ClientHello supported_versions extension.
func supportedVersionsClient(versions ...int) []byte {
	var list []byte
	for _, v := range versions {
		list = append(list, be16(v)...)
	}
	return ext(43, append([]byte{byte(len(list))}, list...)...)
}

// hello builds a ClientHello (server=false) or ServerHello (server=true) handshake message.
func hello(server bool, legacy int, exts ...[]byte) []byte {
	body := append(be16(legacy), make([]byte, 32)...) // version + random
	body = append(body, 0)                            // empty session id
	if server {
		body = append(body, be16(0x1301)...) // cipher suite
		body = append(body, 0)               // compression method
	} else {
		body = append(body, be16(2)...)
		body = append(body, be16(0x1301)...) // one cipher suite
		body = append(body, 1, 0)            // null compression
	}
	var all []byte
	for _, e := range exts {
		all = append(all, e...)
	}
	body = append(body, be16(len(all))...)
	body = append(body, all...)

	typ := byte(1)
	if server {
		typ = 2
	}
	return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// record wraps body in a TLS record.
func record(recType byte, version int, body []byte) []byte {
	return append(append([]byte{recType}, append(be16(version), be16(len(body))...)...), body...)
}

func TestFillHTTP(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantMethod string
		wantURI    string
		wantStatus int
	}{
		{"get", "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", "GET", "/index.html", 0},
		{"post", "POST /api HTTP/1.0\r\n", "POST", "/api", 0},
		{"request line without newline", "GET / HTTP/1.1", "GET", "/", 0},
		{"response 200", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "", "", 200},
		{"response 503", "HTTP/1.1 503 Service Unavailable\r\n", "", "", 503},
		{"response bad code", "HTTP/1.1 abc OK\r\n", "", "", 0},
		{"response out of range code", "HTTP/1.1 999 Nope\r\n", "", "", 0},
		{"unknown method", "BREW /pot HTTP/1.1\r\n", "", "", 0},
		{"not http", "hello world", "", "", 0},
		{"binary", "\x16\x03\x01\x00\x05", "", "", 0},
		{"empty", "", "", "", 0},
		{"overlong first line is bounded", "GET /" + string(make([]byte, 5000)) + " HTTP/1.1", "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var info models.PacketInfo
			fillHTTP(&info, []byte(tt.payload))
			assert.Equal(t, tt.wantMethod, info.HTTPMethod)
			assert.Equal(t, tt.wantURI, info.HTTPURI)
			assert.Equal(t, tt.wantStatus, info.HTTPStatusCode)
		})
	}
}

func TestFillTLS(t *testing.T) {
	grease := supportedVersionsClient(0x0a0a, 0x0304, 0x0303)
	tests := []struct {
		name        string
		payload     []byte
		wantType    string
		wantVersion string
		wantLevel   string
		wantDesc    string
	}{
		{"client hello 1.2 legacy only", record(22, 0x0301, hello(false, 0x0303)), "ClientHello", "TLS 1.2", "", ""},
		{"client hello 1.0", record(22, 0x0301, hello(false, 0x0301)), "ClientHello", "TLS 1.0", "", ""},
		{"client hello 1.3 via supported_versions", record(22, 0x0301, hello(false, 0x0303, grease)), "ClientHello", "TLS 1.3", "", ""},
		{"client hello skips unrelated extension", record(22, 0x0301, hello(false, 0x0303, ext(0, 1, 2, 3), supportedVersionsClient(0x0303))), "ClientHello", "TLS 1.2", "", ""},
		{"server hello 1.2", record(22, 0x0303, hello(true, 0x0303)), "ServerHello", "TLS 1.2", "", ""},
		{"server hello 1.0", record(22, 0x0301, hello(true, 0x0301)), "ServerHello", "TLS 1.0", "", ""},
		{"server hello 1.3 via supported_versions", record(22, 0x0303, hello(true, 0x0303, ext(43, 0x03, 0x04))), "ServerHello", "TLS 1.3", "", ""},
		{"server hello unknown version", record(22, 0x0303, hello(true, 0x0305)), "ServerHello", "0x0305", "", ""},
		{"ssl 3.0 and 1.1 names", record(22, 0x0301, hello(true, 0x0300)), "ServerHello", "SSL 3.0", "", ""},
		{"server hello 1.1", record(22, 0x0301, hello(true, 0x0302)), "ServerHello", "TLS 1.1", "", ""},
		{"truncated client hello", record(22, 0x0301, hello(false, 0x0303)[:20]), "ClientHello", "TLS 1.2", "", ""},
		{"client hello too short for version", record(22, 0x0301, []byte{1, 0, 0, 1, 3}), "ClientHello", "", "", ""},
		{"server hello too short for version", record(22, 0x0303, []byte{2, 0, 0, 1, 3}), "ServerHello", "", "", ""},
		{"truncated extensions", record(22, 0x0301, hello(false, 0x0303, supportedVersionsClient(0x0304))[:52]), "ClientHello", "TLS 1.2", "", ""},
		{"certificate message", record(22, 0x0303, []byte{11, 0, 0, 0}), "Certificate", "", "", ""},
		{"unknown handshake message", record(22, 0x0303, []byte{99, 0, 0, 0}), "Handshake(99)", "", "", ""},
		{"fatal handshake_failure alert", record(21, 0x0303, []byte{2, 40}), "Alert", "", "fatal", "handshake_failure"},
		{"warning close_notify alert", record(21, 0x0303, []byte{1, 0}), "Alert", "", "warning", "close_notify"},
		{"unknown alert", record(21, 0x0303, []byte{2, 250}), "Alert", "", "fatal", "alert_250"},
		{"encrypted alert ignored", record(21, 0x0303, make([]byte, 19)), "", "", "", ""},
		{"app data ignored", record(23, 0x0303, []byte{1, 2, 3}), "", "", "", ""},
		{"multiple records, first handshake wins",
			append(record(22, 0x0303, hello(true, 0x0303)), record(21, 0x0303, []byte{2, 40})...), "ServerHello", "TLS 1.2", "", ""},
		{"server hello then certificate in one record", record(22, 0x0303, append(hello(true, 0x0303), 11, 0, 0, 0)), "ServerHello", "TLS 1.2", "", ""},
		{"not tls", []byte("GET / HTTP/1.1"), "", "", "", ""},
		{"empty", nil, "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var info models.PacketInfo
			fillTLS(&info, tt.payload)
			assert.Equal(t, tt.wantType, info.TLSHandshakeType)
			assert.Equal(t, tt.wantVersion, info.TLSVersion)
			assert.Equal(t, tt.wantLevel, info.TLSAlertLevel)
			assert.Equal(t, tt.wantDesc, info.TLSAlertDescription)
		})
	}
}
