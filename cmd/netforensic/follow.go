package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/models"
)

const maxListedFlows = 20

// followStream prints the conversation of flowID. On failure it returns an
// error that lists the available flows.
func followStream(w io.Writer, packets []models.PacketInfo, flowID string) error {
	conv, err := analyzer.Follow(packets, flowID)
	if err != nil {
		var fe *analyzer.FollowError
		if errors.As(err, &fe) {
			return errors.New(formatFollowError(fe))
		}
		return err
	}
	printConversation(w, conv)
	return nil
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
