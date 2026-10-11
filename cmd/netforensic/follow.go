package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/models"
)

const (
	maxListedFlows = 20
	maxShownBytes  = 2048 // text shown per stream message before truncating
)

// followStream prints the reconstructed application-layer conversation of
// flowID. On failure it returns an error that lists the available flows.
func followStream(w io.Writer, packets []models.PacketInfo, flowID string) error {
	conv, err := analyzer.FollowStream(packets, flowID)
	if err != nil {
		return followError(err)
	}
	printStream(w, conv)
	return nil
}

// followPackets prints the packet-by-packet view of flowID, including pure
// ACKs, sequence numbers, payload dumps and retransmit markers.
func followPackets(w io.Writer, packets []models.PacketInfo, flowID string) error {
	conv, err := analyzer.Follow(packets, flowID)
	if err != nil {
		return followError(err)
	}
	printConversation(w, conv)
	return nil
}

// followError turns a *analyzer.FollowError into an error that lists the
// available flows.
func followError(err error) error {
	var fe *analyzer.FollowError
	if errors.As(err, &fe) {
		return errors.New(formatFollowError(fe))
	}
	return err
}

// printStream prints a reconstructed conversation: payloads stitched in
// order, empty segments left out, binary data summarized.
func printStream(w io.Writer, c *analyzer.Conversation) {
	fmt.Fprintf(w, "Following stream %s\n", c.FlowID)
	fmt.Fprintf(w, "client %s  →  server %s\n", c.Client, c.Server)
	if len(c.Messages) == 0 {
		fmt.Fprintln(w, "\n(no application data in this flow)")
	}

	for _, m := range c.Messages {
		arrow := "←"
		if m.ToServer {
			arrow = "→"
		}
		line := fmt.Sprintf("\n%s  %s  %s", m.Timestamp.UTC().Format("15:04:05.000"), arrow, m.Kind)
		if m.Missing > 0 {
			fmt.Fprintf(w, "%s  [%d bytes not captured]\n", line, m.Missing)
			continue
		}
		if m.Summary != "" && m.Kind != "HTTP" {
			line += "  " + m.Summary
		}
		fmt.Fprintln(w, line)
		for _, l := range renderPayload(m.Kind, m.Data) {
			if l == "" {
				fmt.Fprintln(w)
				continue
			}
			fmt.Fprintf(w, "    %s\n", l)
		}
	}
	if c.Retransmits > 0 {
		fmt.Fprintf(w, "\n(%d retransmitted segment(s) not repeated above; use --follow-packets to see them)\n", c.Retransmits)
	}
}

// renderPayload renders reassembled payload as text lines. HTTP messages
// are split into headers and body; anything that is not text becomes a
// one-line size summary.
func renderPayload(kind string, data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	if kind == "HTTP" {
		if head, body, ok := splitHTTP(data); ok {
			lines := textLines(head)
			if len(body) > 0 {
				lines = append(lines, "")
				lines = append(lines, bodyLines(body)...)
			}
			return lines
		}
	}
	return bodyLines(data)
}

// splitHTTP separates an HTTP message into its header block and body.
func splitHTTP(data []byte) (head, body []byte, ok bool) {
	i := bytes.Index(data, []byte("\r\n\r\n"))
	sep := 4
	if i < 0 {
		i, sep = bytes.Index(data, []byte("\n\n")), 2
	}
	if i < 0 || !isText(data[:i]) {
		return nil, nil, false
	}
	return data[:i], data[i+sep:], true
}

// bodyLines shows data as text, or as a size summary if it is binary.
func bodyLines(data []byte) []string {
	if !isText(data) {
		return []string{fmt.Sprintf("[%d bytes of binary data]", len(data))}
	}
	return textLines(data)
}

// textLines splits text into lines, truncating after maxShownBytes.
func textLines(data []byte) []string {
	more := 0
	if len(data) > maxShownBytes {
		more = len(data) - maxShownBytes
		data = data[:maxShownBytes]
		for !utf8.Valid(data) && len(data) > 0 { // do not cut a rune in half
			data = data[:len(data)-1]
			more++
		}
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), "\n")
	if more > 0 {
		lines = append(lines, fmt.Sprintf("... %d more byte(s)", more))
	}
	return lines
}

// isText reports whether data is valid UTF-8 made up almost entirely of
// printable characters and ordinary whitespace.
func isText(data []byte) bool {
	if !utf8.Valid(data) {
		// Tolerate a multi-byte character cut by a missing tail.
		trimmed := data
		for i := 0; i < 3 && len(trimmed) > 0 && !utf8.Valid(trimmed); i++ {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if !utf8.Valid(trimmed) {
			return false
		}
		data = trimmed
	}
	bad := 0
	for _, r := range string(data) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			bad++
		}
	}
	return bad == 0
}

// formatFollowError renders the reason and the available flow IDs.
func formatFollowError(fe *analyzer.FollowError) string {
	var b strings.Builder
	b.WriteString(fe.Reason)
	if len(fe.Available) == 0 {
		b.WriteString("\nno flows are available")
		return b.String()
	}
	b.WriteString("\navailable flows:")
	for i, f := range fe.Available {
		if i == maxListedFlows {
			fmt.Fprintf(&b, "\n  ... and %d more", len(fe.Available)-maxListedFlows)
			break
		}
		fmt.Fprintf(&b, "\n  %s/%s  (%d packets)", f.ID, f.Protocol, f.Packets)
	}
	return b.String()
}

// printConversation prints a reconstructed conversation, one block per packet.
func printConversation(w io.Writer, c *analyzer.Conversation) {
	fmt.Fprintf(w, "Following flow %s\n", c.FlowID)
	fmt.Fprintf(w, "client %s  →  server %s, %d packet(s)\n\n", c.Client, c.Server, len(c.Events))

	for _, ev := range c.Events {
		arrow := "←"
		if ev.ToServer {
			arrow = "→"
		}
		p := ev.Packet

		line := fmt.Sprintf("%s  %s  %-5s", ev.Timestamp.UTC().Format("15:04:05.000"), arrow, ev.Kind)
		if p.Protocol == models.ProtocolTCP {
			flags := p.TCPFlags
			if flags == "" {
				flags = "none"
			}
			line += fmt.Sprintf(" [%s] seq=%d len=%d", flags, p.TCPSeq, p.PayloadSize)
		}

		if ev.Summary != "" {
			line += "  " + ev.Summary
		}
		if ev.Retransmit {
			line += "  [RETRANS]"
		}
		fmt.Fprintln(w, line)

		for _, d := range ev.Detail {
			fmt.Fprintf(w, "      %s\n", d)
		}
		if len(ev.Payload) > 0 {
			for _, l := range hexDump(ev.Payload) {
				fmt.Fprintf(w, "      %s\n", l)
			}
			if p.PayloadSize > len(ev.Payload) {
				fmt.Fprintf(w, "      ... %d more byte(s)\n", p.PayloadSize-len(ev.Payload))
			}
		}
	}
}

// hexDump formats b as rows of 16 bytes: offset, hex and ASCII.
func hexDump(b []byte) []string {
	var rows []string
	for off := 0; off < len(b); off += 16 {
		end := off + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[off:end]

		var hex, ascii strings.Builder
		for i := 0; i < 16; i++ {
			if i < len(chunk) {
				fmt.Fprintf(&hex, "%02x ", chunk[i])
				c := chunk[i]
				if c < 0x20 || c > 0x7e {
					c = '.'
				}
				ascii.WriteByte(c)
			} else {
				hex.WriteString("   ")
			}
			if i == 7 {
				hex.WriteByte(' ')
			}
		}
		rows = append(rows, fmt.Sprintf("%04x  %s |%s|", off, hex.String(), ascii.String()))
	}
	return rows
}
