package pcap

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// sipVersion is the only SIP version in use.
const sipVersion = "SIP/2.0"

// sipMaxHeader is how much of a message is searched for headers.
const sipMaxHeader = 8192

// sipMethods are the request methods (RFC 3261 and its common extensions).
var sipMethods = map[string]bool{
	"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true, "REGISTER": true, "OPTIONS": true,
	"PRACK": true, "SUBSCRIBE": true, "NOTIFY": true, "PUBLISH": true, "INFO": true,
	"REFER": true, "MESSAGE": true, "UPDATE": true,
}

// sipCompact maps the one-letter header names to their full names.
var sipCompact = map[string]string{"i": "call-id", "f": "from", "t": "to", "m": "contact"}

// fillSIP sets the SIP fields on info if payload begins with a SIP request
// line ("INVITE sip:bob@example.com SIP/2.0") or status line ("SIP/2.0 200
// OK"), and reads the headers the analysis uses. Only the first message of a
// payload is read. Text from the capture is cleaned of control characters
// and cut to a sane length, since it is shown on terminals.
func fillSIP(info *models.PacketInfo, payload []byte) {
	if len(payload) < len(sipVersion)+4 {
		return
	}
	if len(payload) > sipMaxHeader {
		payload = payload[:sipMaxHeader]
	}
	head := payload
	if i := bytes.Index(head, []byte("\r\n\r\n")); i >= 0 {
		head = head[:i]
	} else if i := bytes.Index(head, []byte("\n\n")); i >= 0 {
		head = head[:i]
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")

	first := lines[0]
	switch {
	case strings.HasPrefix(first, sipVersion+" "): // status line: SIP/2.0 486 Busy Here
		rest := strings.TrimSpace(first[len(sipVersion)+1:])
		codeStr, reason, _ := strings.Cut(rest, " ")
		code, err := strconv.Atoi(codeStr)
		if err != nil || len(codeStr) != 3 || code < 100 || code > 699 {
			return
		}
		info.SIPStatusCode, info.SIPReason = code, cleanMeta(strings.TrimSpace(reason))
	default: // request line: INVITE sip:bob@example.com SIP/2.0
		parts := strings.Fields(first)
		if len(parts) != 3 || parts[2] != sipVersion || !sipMethods[parts[0]] {
			return
		}
		info.SIPMethod, info.SIPURI = parts[0], cleanMeta(parts[1])
	}
	info.SIPVersion = sipVersion

	// Headers, with folded (continued) lines joined to the one before.
	var server string
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		for i+1 < len(lines) && len(lines[i+1]) > 0 && (lines[i+1][0] == ' ' || lines[i+1][0] == '\t') {
			line += " " + strings.TrimSpace(lines[i+1])
			i++
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if full, ok := sipCompact[name]; ok {
			name = full
		}
		value = cleanMeta(value)
		switch name {
		case "call-id":
			if info.SIPCallID == "" {
				info.SIPCallID = value
			}
		case "from":
			if info.SIPFrom == "" {
				info.SIPFrom = value
			}
		case "to":
			if info.SIPTo == "" {
				info.SIPTo = value
			}
		case "contact":
			if info.SIPContact == "" {
				info.SIPContact = value
			}
		case "user-agent":
			if info.SIPUserAgent == "" {
				info.SIPUserAgent = value
			}
		case "server":
			if server == "" {
				server = value
			}
		case "cseq":
			num, method, _ := strings.Cut(value, " ")
			if n, err := strconv.Atoi(num); err == nil && info.SIPCSeq == 0 {
				info.SIPCSeq, info.SIPCSeqMethod = n, strings.ToUpper(strings.TrimSpace(method))
			}
		}
	}
	if info.SIPUserAgent == "" {
		info.SIPUserAgent = server
	}
}
