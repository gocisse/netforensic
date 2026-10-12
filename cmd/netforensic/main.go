// Command netforensic analyzes pcap files for network problems.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gocisse/netforensic/internal/analyzer"
	"github.com/gocisse/netforensic/internal/auth"
	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
	"github.com/gocisse/netforensic/internal/server"
)

// errExportCSVPrefix is the error for --export-csv without a prefix.
var errExportCSVPrefix = errors.New("--export-csv needs a file name prefix, for example --export-csv report (writes report_flows.csv, report_issues.csv and report_protocols.csv)")

var validServices = []string{"all", "dns", "http", "tls", "https", "<port>"}

// bigCaptureBytes is the file size from which the garbage collector is
// tightened (see the use in the root command).
const bigCaptureBytes = 32 << 20

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
func newRootCmd() *cobra.Command { return newRootCmdWith(server.StartServer) }

// newRootCmdWith builds the root command with startServer as the function
// behind --web, so that tests do not have to run a real server.
func newRootCmdWith(startServer func(addr string, a *auth.Service) error) *cobra.Command {
	var (
		web         string
		credentials string
		service     string
		verbose     bool
		output      string
		follow      string
		followPkts  string
		csvPrefix   string

		srcIP, dstIP string
		srcPort      int
		dstPort      int
	)

	cmd := &cobra.Command{
		Use:           "netforensic [flags] file.pcap | netforensic --web addr",
		Short:         "Analyze a pcap file for network issues",
		Args:          cobra.ArbitraryArgs, // checked below: one file, or none with --web
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if web != "" {
				return runWeb(cmd, web, credentials, args, startServer)
			}
			if cmd.Flags().Changed("credentials") {
				return fmt.Errorf("--credentials only applies together with --web")
			}
			if len(args) != 1 {
				return fmt.Errorf("accepts 1 arg(s), received %d (give a capture file, or --web <addr> to start the web UI)", len(args))
			}
			service = strings.ToLower(service)
			if err := validateService(service); err != nil {
				return err
			}
			output = strings.ToLower(output)
			if output != "text" && output != "json" {
				return fmt.Errorf("invalid output format %q (valid: text, json)", output)
			}
			if cmd.Flags().Changed("export-csv") && strings.TrimSpace(csvPrefix) == "" {
				return errExportCSVPrefix
			}
			if cmd.Flags().Changed("export-csv") && (follow != "" || followPkts != "") {
				return fmt.Errorf("--export-csv exports the analysis and cannot be combined with --follow or --follow-packets")
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
			if follow != "" && followPkts != "" {
				return fmt.Errorf("--follow and --follow-packets are mutually exclusive")
			}
			if (follow != "" || followPkts != "") && output != "text" {
				return fmt.Errorf("--follow and --follow-packets only support text output")
			}

			// A big capture holds gigabytes of packets: collect garbage sooner
			// (50% instead of 100% over the live data) to lower the peak.
			if fi, serr := os.Stat(args[0]); serr == nil && fi.Size() >= bigCaptureBytes {
				debug.SetGCPercent(50)
			}
			// Stream reconstruction needs whole payloads, not previews, and
			// nothing else looks at the previews.
			packets, stats, err := pcap.ReadPacketsStats(args[0], pcap.ReadOptions{FullPayload: follow != "", SkipPreview: follow == "" && followPkts == ""})
			var truncated *pcap.TruncatedError
			if errors.As(err, &truncated) {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is truncated; analyzing the %d packets read before the cut\n", args[0], len(packets))
				err = nil
			}
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			var notes []models.Issue
			if truncated != nil {
				notes = append(notes, analyzer.TruncatedCaptureIssue(packets))
			}
			if stats.Skipped() > 0 {
				notes = append(notes, analyzer.SkippedFramesIssue(stats.Skipped(), describeSkipped(stats), packets))
				if output == "text" && follow == "" && followPkts == "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: %d of %d frames were skipped (unsupported link-layer types or non-IP traffic)\n", stats.Skipped(), stats.Frames)
				}
			}

			// Every filter is applied here, once. The result is the only
			// packet list that the table, the follow views and the analysis
			// ever see, so none of them can show traffic the others dropped.
			total := len(packets)
			filtered := filter.apply(packets)
			filtered, _ = analyzer.FilterService(filtered, service) // service was validated above
			packets = filtered
			filtersActive := filter.active() || service != "all"
			if filtersActive && len(packets) == 0 && total > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: no packets match the filters (%d packets in the capture)\n", total)
			}

			if follow != "" {
				return followStream(cmd.OutOrStdout(), packets, follow)
			}
			if followPkts != "" {
				return followPackets(cmd.OutOrStdout(), packets, followPkts)
			}

			if len(packets) == 0 {
				// Nothing to analyze: a health score would claim a clean bill
				// of health for traffic that was never looked at.
				if csvPrefix != "" {
					fmt.Fprintln(cmd.ErrOrStderr(), "warning: nothing to analyze, so no CSV files were written")
				}
				return printNothingToAnalyze(cmd.OutOrStdout(), args[0], output == "json", filtersActive, notes)
			}

			res := analyzer.AnalyzeWithIssues(packets, "all", notes...) // already filtered
			res.FileName = args[0]
			res.Metadata = stats.Metadata

			if csvPrefix != "" {
				written, err := exportCSV(csvPrefix, res)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "exported %s\n", strings.Join(written, ", "))
			}

			if output == "json" {
				if verbose { // keep stdout valid JSON
					if err := printVerbose(cmd.ErrOrStderr(), packets); err != nil {
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
				if err := printVerbose(cmd.OutOrStdout(), packets); err != nil {
					return fmt.Errorf("write packet table: %w", err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Analyzed %d packets in %d flows, found %d issues in %s\n",
				res.TotalPackets, res.TotalFlows, len(res.Issues), res.Duration)
			printIssueSummary(cmd.OutOrStdout(), res.Issues)
			return nil
		},
	}
	cmd.Flags().StringVar(&credentials, "credentials", "", "with --web: the credentials file (default: "+auth.CredentialsFileName+" in your home directory)")
	cmd.Flags().StringVar(&web, "web", "", "serve the web UI and API on this address, for example :8080, instead of analyzing a file")
	cmd.Flags().StringVarP(&service, "service", "s", "all", "service to analyze: "+strings.Join(validServices, ", "))

	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text, json")
	cmd.Flags().StringVar(&srcIP, "src-ip", "", "only analyze packets from this source IP")
	cmd.Flags().StringVar(&dstIP, "dst-ip", "", "only analyze packets to this destination IP")
	cmd.Flags().IntVar(&srcPort, "src-port", 0, "only analyze packets from this source port")
	cmd.Flags().IntVar(&dstPort, "dst-port", 0, "only analyze packets to this destination port")
	cmd.Flags().StringVar(&follow, "follow", "", "show the reconstructed application-layer conversation of a flow, e.g. 10.0.0.1:43210-10.0.0.2:443[/tcp]")
	cmd.Flags().StringVar(&followPkts, "follow-packets", "", "show a flow packet by packet (flags, seq, payload dump, [RETRANS] markers)")
	cmd.Flags().StringVar(&csvPrefix, "export-csv", "", "also write the analysis as CSV files: <prefix>_flows.csv, <prefix>_issues.csv and <prefix>_protocols.csv")
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		if strings.Contains(err.Error(), "--export-csv") {
			return errExportCSVPrefix
		}
		return err
	})
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print every packet read before the summary")

	return cmd
}

// runWeb starts the web server on addr. It takes no capture file and no
// analysis flags: uploads are analyzed with the defaults.
func runWeb(cmd *cobra.Command, addr, credentials string, args []string, startServer func(string, *auth.Service) error) error {
	if len(args) > 0 {
		return fmt.Errorf("--web serves uploads and does not take a capture file (got %q)", args[0])
	}
	var conflicting []string
	for _, name := range []string{"service", "output", "verbose", "src-ip", "dst-ip", "src-port", "dst-port", "follow", "follow-packets", "export-csv"} {
		if cmd.Flags().Changed(name) {
			conflicting = append(conflicting, "--"+name)
		}
	}
	if len(conflicting) > 0 {
		return fmt.Errorf("--web cannot be combined with %s", strings.Join(conflicting, ", "))
	}
	if credentials == "" {
		credentials = auth.DefaultPath()
	}
	authSvc, err := auth.Open(credentials)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Web UI available at %s (press Ctrl-C to stop)\n", webURL(addr))
	fmt.Fprintf(out, "Credentials file: %s\n", authSvc.Path())
	if authSvc.MustChangePassword() {
		fmt.Fprintf(out, "warning: the default login %s/%s is active. Sign in and change the password; until then anyone who can reach %s can use the analyzer.\n",
			auth.DefaultUsername, auth.DefaultPassword, addr)
	}
	return startServer(addr, authSvc)
}

// webURL turns a listen address such as ":8080" into a URL to open.
func webURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
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
