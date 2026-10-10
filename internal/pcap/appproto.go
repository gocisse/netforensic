package pcap

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// gopacket has no HTTP layer, and its TLS layer does not expose handshake
// message types or hello versions, so both protocols are parsed from the TCP
// payload here.

var httpMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

// fillHTTP sets the HTTP fields on info if payload begins with an HTTP/1.x
// request line or status line.
func fillHTTP(info *models.PacketInfo, payload []byte) {
	if len(payload) == 0 {
		return
	}
	line := payload
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 4096 {
		line = line[:4096]
	}
	parts := strings.Fields(string(line))

	// Status line: HTTP/1.1 200 OK
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/") {
		if code, err := strconv.Atoi(parts[1]); err == nil && code >= 100 && code <= 599 {
			info.HTTPStatusCode = code
		}
		return
	}

	// Request line: GET /path HTTP/1.1
	if len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/") {
		for _, m := range httpMethods {
			if parts[0] == m {
				info.HTTPMethod = m
				info.HTTPURI = parts[1]
				return
			}
		}
	}
}

const (
	tlsRecordAlert     = 21
	tlsRecordHandshake = 22

	tlsHandshakeClientHello = 1
	tlsHandshakeServerHello = 2

	tlsExtSupportedVersions = 43
)

var tlsHandshakeNames = map[byte]string{
	0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
	8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
	13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
	16: "ClientKeyExchange", 20: "Finished",
}

var tlsAlertNames = map[byte]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
	22: "record_overflow", 30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate",
	42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
	45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
	49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
	71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
	90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
	110: "unsupported_extension", 112: "unrecognized_name", 116: "certificate_required",
	120: "no_application_protocol",
}

// fillTLS sets the TLS fields on info if payload begins with a TLS record.
// Only plaintext handshake and alert records are decoded; a segment holding
// part of a fragmented hello yields whatever fields are present.
func fillTLS(info *models.PacketInfo, payload []byte) {
	if !looksLikeTLS(payload) {
		return
	}
	for len(payload) >= 5 && looksLikeTLS(payload) {
		recType := payload[0]
		n := int(payload[3])<<8 | int(payload[4])
		body := payload[5:]
		if len(body) > n {
			body = body[:n]
		}
		switch recType {
		case tlsRecordHandshake:
			fillTLSHandshake(info, body)
		case tlsRecordAlert:
			if n == 2 && len(body) == 2 && info.TLSHandshakeType == "" { // longer alerts are encrypted
				info.TLSHandshakeType = "Alert"
				info.TLSAlertLevel = "warning"
				if body[0] == 2 {
					info.TLSAlertLevel = "fatal"
				}
				info.TLSAlertDescription = tlsAlertNames[body[1]]
				if info.TLSAlertDescription == "" {
					info.TLSAlertDescription = fmt.Sprintf("alert_%d", body[1])
				}
			}
		}
		if len(payload) < 5+n {
			break
		}
		payload = payload[5+n:]
	}
}

// looksLikeTLS reports whether b starts with a plausible TLS record header.
func looksLikeTLS(b []byte) bool {
	return len(b) >= 5 && b[0] >= 20 && b[0] <= 23 && b[1] == 3 && b[2] <= 4
}

// fillTLSHandshake decodes the handshake messages in a handshake record body.
func fillTLSHandshake(info *models.PacketInfo, body []byte) {
	for len(body) >= 4 {
		msgType := body[0]
		n := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		msg := body[4:]
		if len(msg) > n {
			msg = msg[:n]
		}
		if info.TLSHandshakeType == "" {
			name := tlsHandshakeNames[msgType]
			if name == "" {
				name = fmt.Sprintf("Handshake(%d)", msgType)
			}
			info.TLSHandshakeType = name
		}
		switch msgType {
		case tlsHandshakeClientHello:
			info.TLSVersion = clientHelloVersion(msg)
		case tlsHandshakeServerHello:
			info.TLSVersion = serverHelloVersion(msg)
		}
		if len(body) < 4+n {
			return
		}
		body = body[4+n:]
	}
}

// cursor is a bounds-checked reader over a byte slice.
type cursor struct {
	b  []byte
	ok bool
}

func newCursor(b []byte) *cursor { return &cursor{b: b, ok: true} }

func (c *cursor) take(n int) []byte {
	if !c.ok || n < 0 || len(c.b) < n {
		c.ok = false
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() int {
	if b := c.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (c *cursor) u16() int {
	if b := c.take(2); b != nil {
		return int(b[0])<<8 | int(b[1])
	}
	return 0
}

// clientHelloVersion returns the highest TLS version a ClientHello offers,
// preferring the supported_versions extension over the legacy version field.
func clientHelloVersion(msg []byte) string {
	c := newCursor(msg)
	legacy := c.u16()
	if !c.ok {
		return ""
	}
	best := legacy
	c.take(32)                         // random
	c.take(c.u8())                     // session id
	c.take(c.u16())                    // cipher suites
	c.take(c.u8())                     // compression methods
	exts := newCursor(c.take(c.u16())) // extensions
	for exts.ok && len(exts.b) > 0 {
		typ := exts.u16()
		data := newCursor(exts.take(exts.u16()))
		if !exts.ok || typ != tlsExtSupportedVersions {
			continue
		}
		list := newCursor(data.take(data.u8()))
		for list.ok && len(list.b) > 0 {
			v := list.u16()
			if list.ok && !isGREASE(v) && v > best {
				best = v
			}
		}
	}
	return tlsVersionName(best)
}

// serverHelloVersion returns the version a ServerHello selected, preferring
// the supported_versions extension (TLS 1.3) over the legacy version field.
func serverHelloVersion(msg []byte) string {
	c := newCursor(msg)
	version := c.u16()
	if !c.ok {
		return ""
	}
	c.take(32)     // random
	c.take(c.u8()) // session id
	c.take(2)      // cipher suite
	c.take(1)      // compression method
	exts := newCursor(c.take(c.u16()))
	for exts.ok && len(exts.b) > 0 {
		typ := exts.u16()
		data := newCursor(exts.take(exts.u16()))
		if exts.ok && typ == tlsExtSupportedVersions {
			if v := data.u16(); data.ok {
				version = v
			}
		}
	}
	return tlsVersionName(version)
}

// isGREASE reports whether v is a reserved GREASE value (0x0a0a, 0x1a1a, ...).
func isGREASE(v int) bool { return v&0x0f0f == 0x0a0a }

// tlsVersionName renders a wire version such as 0x0303 as "TLS 1.2".
func tlsVersionName(v int) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}
