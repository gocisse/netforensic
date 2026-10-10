// Command netforensic analyzes pcap files for network problems.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/pcap"
)

var validServices = []string{"all", "dns", "http", "tls", "https", "<port>"}

func main() {
	cmd := newRootCmd()
	cmd.SetArgs(normalizeArgs(os.Args[1:]))
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// normalizeArgs accepts the single-dash "-service" spelling; pflag would
// otherwise parse it as the shorthand "-s" with value "ervice".
func normalizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "-service" || strings.HasPrefix(a, "-service=") {
			a = "-" + a
		}
		out[i] = a
	}
	return out
}

// newRootCmd builds the netforensic root command.
func newRootCmd() *cobra.Command {
	var (
		service string
		verbose bool
		output  string
		follow  string

		srcIP, dstIP string
		srcPort      int
		dstPort      int
	)

	cmd := &cobra.Command{
		Use:           "netforensic [flags] file.pcap",
		Short:         "Analyze a pcap file for network issues",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			service = strings.ToLower(service)
			if err := validateService(service); err != nil {
				return err
			}
			output = strings.ToLower(output)
			if output != "text" && output != "json" {
				return fmt.Errorf("invalid output format %q (valid: text, json)", output)
			}
			if err := validateFile(args[0]); err != nil {
				return err
			}
			var srcPortP, dstPortP *int
			if cmd.Flags().Changed("src-port") {
				srcPortP = &srcPort
			}
			if cmd.Flags().Changed("dst-port") {
				dstPortP = &dstPort
			}
			filter, err := newPacketFilter(srcIP, dstIP, srcPortP, dstPortP)
			if err != nil {
				return err
			}
			if follow != "" && output != "text" {
				return fmt.Errorf("--follow only supports text output")
			}

			packets, err := pcap.ReadPackets(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			total := len(packets)
			packets = filter.apply(packets)
			if filter.active() && len(packets) == 0 && total > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: no packets match the filters (%d packets in the capture)\n", total)
			}

			if follow != "" {
				return followStream(cmd.OutOrStdout(), packets, follow)
			}

			res := analyzer.Analyze(packets, service)
			res.FileName = args[0]

			if output == "json" {
				if verbose { // keep stdout valid JSON
					if err := printPacketTable(cmd.ErrOrStderr(), packets); err != nil {
						return fmt.Errorf("write packet table: %w", err)
					}
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return fmt.Errorf("encode json: %w", err)
				}
				return nil
			}

			if err := printTriageReport(cmd.OutOrStdout(), res); err != nil {
				return fmt.Errorf("write triage report: %w", err)
			}
			if verbose {
				if err := printPacketTable(cmd.OutOrStdout(), packets); err != nil {
					return fmt.Errorf("write packet table: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Analyzed %d packets in %d flows, found %d issues in %s\n",
				res.TotalPackets, res.TotalFlows, len(res.Issues), res.Duration)
			for _, is := range res.Issues {
				fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s: %s\n", is.Severity, is.Category, is.Title)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&service, "service", "s", "all", "service to analyze: "+strings.Join(validServices, ", "))

	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text, json")
	cmd.Flags().StringVar(&srcIP, "src-ip", "", "only analyze packets from this source IP")
	cmd.Flags().StringVar(&dstIP, "dst-ip", "", "only analyze packets to this destination IP")
	cmd.Flags().IntVar(&srcPort, "src-port", 0, "only analyze packets from this source port")
	cmd.Flags().IntVar(&dstPort, "dst-port", 0, "only analyze packets to this destination port")
	cmd.Flags().StringVar(&follow, "follow", "", "show the full conversation of a flow, e.g. 10.0.0.1:43210-10.0.0.2:443[/tcp]")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print every packet read before the summary")

	return cmd
}

// validateService checks that service is a supported filter.
func validateService(service string) error {
	for _, s := range validServices {
		if s == service {
			return nil
		}
	}
	if _, err := strconv.ParseUint(service, 10, 16); err == nil {
		return nil
	}
	return fmt.Errorf("invalid service %q (valid: %s)", service, strings.Join(validServices, ", "))
}

// validateFile checks that path exists, is a regular file and has a pcap extension.
func validateFile(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap", ".pcapng":
	default:
		return fmt.Errorf("unsupported file extension %q (want .pcap or .pcapng)", filepath.Ext(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}
