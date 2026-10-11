package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	maxTimelineEvents = 15
	reportWidth       = 72
)

// printTriageReport prints the diagnosis, timeline, slowest flows and
// recommendations of res.
func printTriageReport(w io.Writer, res *models.AnalysisResult) error {
	d := res.Diagnosis
	rule := strings.Repeat("=", reportWidth)

	fmt.Fprintln(w, rule)
	fmt.Fprintf(w, " TRIAGE REPORT  |  Health Score: %d/100 (%s)\n", d.HealthScore, healthLabel(d.HealthScore))
	fmt.Fprintln(w, rule)
	printCaptureMetadata(w, res.Metadata)

	fmt.Fprintln(w, "\nROOT CAUSE")
	fmt.Fprintf(w, "  %s (confidence: %s)\n", d.PrimaryCause, d.Confidence)
	if d.Summary != "" {
		fmt.Fprintf(w, "  %s\n", d.Summary)
	}

	fmt.Fprintln(w, "\nTIMELINE (UTC)")
	if len(d.Timeline) == 0 {
		fmt.Fprintln(w, "  no events")
	}
	for i, e := range d.Timeline {
		if i == maxTimelineEvents {
			fmt.Fprintf(w, "  ... %d more event(s); see the issue list below\n", len(d.Timeline)-maxTimelineEvents)
			break
		}
		fmt.Fprintf(w, "  %s  %-10s %-13s %s\n", e.Timestamp.UTC().Format("15:04:05.000"), "["+string(e.Severity)+"]", e.EventType, e.Description)
	}

	fmt.Fprintln(w, "\nTOP SLOW FLOWS")
	if len(res.SlowFlows) == 0 {
		fmt.Fprintln(w, "  no flows with measurable timing metrics")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  FLOW\tSETUP\tTTFB\tAVG RTT\tMAX RTT")
		for _, f := range res.SlowFlows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", f.ID, fmtMs(f.SetupTimeMs), fmtMs(f.TTFBMs), fmtMs(f.AvgRTTMs), fmtMs(f.MaxRTTMs))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if err := printSIPFlows(w, res.Flows); err != nil {
		return err
	}
	if err := printDHCPv6Flows(w, res.Flows); err != nil {
		return err
	}
	if err := printQUICFlows(w, res.Flows); err != nil {
		return err
	}

	fmt.Fprintln(w, "\nRECOMMENDATIONS")
	for i, r := range d.Recommendations {
		fmt.Fprintf(w, "  %d. %s\n", i+1, r)
	}
	fmt.Fprintln(w)
	return nil
}

// healthLabel names a health score band.
func healthLabel(score int) string {
	switch {
	case score >= 90:
		return "HEALTHY"
	case score >= 70:
		return "DEGRADED"
	case score >= 40:
		return "UNHEALTHY"
	case score >= 0:
		return "CRITICAL"
	}
	return "CATASTROPHIC"
}

// fmtMs formats a millisecond metric, using "-" when it was not measured.
func fmtMs(v float64) string {
	if v <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fms", v)
}

// maxInterfacesShown is how many interface descriptions the report header
// lists; a merged capture can hold hundreds.
const maxInterfacesShown = 3

// printCaptureMetadata prints what the capture file says about its creation,
// as lines under the report title: the tool and operating system, the
// hardware, and the interfaces. It prints nothing if md is nil.
func printCaptureMetadata(w io.Writer, md *models.CaptureMetadata) {
	if md == nil {
		return
	}
	var capture []string
	if md.CaptureTool != "" {
		capture = append(capture, md.CaptureTool)
	}
	if md.OS != "" {
		capture = append(capture, "on "+md.OS)
	}
	if len(capture) > 0 {
		fmt.Fprintf(w, " Captured with: %s\n", strings.Join(capture, " "))
	}
	if md.Hardware != "" {
		fmt.Fprintf(w, " Hardware:      %s\n", md.Hardware)
	}
	for i, ifc := range md.Interfaces {
		label := " Interfaces:    "
		if i > 0 {
			label = strings.Repeat(" ", len(label))
		}
		if i == maxInterfacesShown {
			fmt.Fprintf(w, "%s... and %d more\n", label, len(md.Interfaces)-maxInterfacesShown)
			break
		}
		fmt.Fprintf(w, "%s%s\n", label, describeInterface(ifc))
	}
}

// describeInterface summarizes an interface, for example
// "eth0 (Ethernet, snaplen 262144, nanosecond timestamps)".
func describeInterface(ifc models.InterfaceInfo) string {
	name := ifc.Name
	if name == "" {
		name = "(unnamed)"
	}
	if ifc.Description != "" {
		name += " - " + ifc.Description
	}
	details := []string{ifc.LinkType}
	if ifc.SnapLen > 0 {
		details = append(details, fmt.Sprintf("snaplen %d", ifc.SnapLen))
	}
	if ifc.Resolution != "" {
		details = append(details, ifc.Resolution+" timestamps")
	}
	if ifc.Filter != "" {
		details = append(details, "filter: "+ifc.Filter)
	}
	return fmt.Sprintf("%s (%s)", name, strings.Join(details, ", "))
}

// maxAppFlowsShown is how many flows of one application protocol the report lists.
const maxAppFlowsShown = 5

// appFlowTable describes the table of an application protocol's flows.
type appFlowTable struct {
	app     models.Protocol
	heading string
	columns []string // after FLOW and PACKETS
	row     func(models.Flow) []string
}

var sipFlowTable = appFlowTable{
	app: models.ProtocolSIP, heading: "SIP FLOWS",
	columns: []string{"METHODS", "USER-AGENT", "CALL-ID"},
	row: func(f models.Flow) []string {
		return []string{dash(f.SIPMethod), dash(f.SIPUserAgent), dash(f.SIPCallID)}
	},
}

var dhcpv6FlowTable = appFlowTable{
	app: models.ProtocolDHCPv6, heading: "DHCPV6 FLOWS",
	columns: []string{"MESSAGES", "CLIENT-ID", "SERVER-ID"},
	row: func(f models.Flow) []string {
		return []string{dash(f.DHCPv6MessageTypes), dash(f.DHCPv6ClientID), dash(f.DHCPv6ServerID)}
	},
}

var quicFlowTable = appFlowTable{
	app: models.ProtocolQUIC, heading: "QUIC FLOWS",
	columns: []string{"VERSION", "PACKET TYPES"},
	row: func(f models.Flow) []string {
		return []string{dash(f.QUICVersion), dash(f.QUICPacketTypes)}
	},
}

// printSIPFlows lists the busiest flows that carry SIP, with the request
// methods, the User-Agent and the Call-ID of their first message.
func printSIPFlows(w io.Writer, flows []models.Flow) error {
	return printAppFlows(w, flows, sipFlowTable)
}

// printDHCPv6Flows lists the busiest flows that carry DHCPv6, with the
// message types and the client and server identifiers.
func printDHCPv6Flows(w io.Writer, flows []models.Flow) error {
	return printAppFlows(w, flows, dhcpv6FlowTable)
}

// printQUICFlows lists the busiest flows that carry QUIC, with the version and
// the long-header packet types seen. The payloads are encrypted, so nothing
// more can be told.
func printQUICFlows(w io.Writer, flows []models.Flow) error {
	return printAppFlows(w, flows, quicFlowTable)
}

// printAppFlows lists the busiest flows of one application protocol. It
// prints nothing if there are none.
func printAppFlows(w io.Writer, flows []models.Flow, t appFlowTable) error {
	var matching []models.Flow
	for _, f := range flows {
		if f.AppProtocol == string(t.app) {
			matching = append(matching, f)
		}
	}
	if len(matching) == 0 {
		return nil
	}
	sort.SliceStable(matching, func(i, j int) bool {
		if matching[i].PacketCount != matching[j].PacketCount {
			return matching[i].PacketCount > matching[j].PacketCount
		}
		return matching[i].ID < matching[j].ID
	})
	fmt.Fprintf(w, "\n%s (%d)\n", t.heading, len(matching))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  FLOW\tPACKETS\t%s\n", strings.Join(t.columns, "\t"))
	for i, f := range matching {
		if i == maxAppFlowsShown {
			break
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\n", f.ID, f.PacketCount, strings.Join(t.row(f), "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(matching) > maxAppFlowsShown {
		fmt.Fprintf(w, "  ... and %d more\n", len(matching)-maxAppFlowsShown)
	}
	return nil
}

// dash returns s, or "-" if it is empty.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
