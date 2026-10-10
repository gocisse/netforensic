package main

import (
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/gocisse/netforensic/internal/models"
)

// printPacketTable prints packets as an aligned table.
func printPacketTable(w io.Writer, packets []models.PacketInfo) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tTIME (UTC)\tSOURCE\tDESTINATION\tPROTO\tSIZE\tFLAGS\tSEQ")
	fmt.Fprintln(tw, "-\t----------\t------\t-----------\t-----\t----\t-----\t---")
	for i, p := range packets {
		flags, seq := "-", "-"
		if p.Protocol == models.ProtocolTCP {
			flags = p.TCPFlags
			if flags == "" {
				flags = "none"
			}
			seq = strconv.FormatUint(uint64(p.TCPSeq), 10)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			i+1,
			p.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			formatEndpoint(p.SrcIP, p.SrcPort),
			formatEndpoint(p.DstIP, p.DstPort),
			p.Protocol, p.Size, flags, seq)
	}
	return tw.Flush()
}

// formatEndpoint renders ip:port, or just the IP for portless protocols.
func formatEndpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
