// Command netforensic analyzes pcap files for network problems.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gocisse/netforensic/internal/analyzer"
)

var validServices = []string{"all", "dns", "http", "tls", "https", "<port>"}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// newRootCmd builds the netforensic root command.
func newRootCmd() *cobra.Command {
	var service string

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
			if err := validateFile(args[0]); err != nil {
				return err
			}
			res, err := analyzer.AnalyzeFile(args[0], service)
			if err != nil {
				return fmt.Errorf("analyze file: %w", err)
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

	// Accept the single-dash "-service" spelling; pflag would otherwise
	// parse it as the shorthand "-s" with value "ervice".
	args := os.Args[1:]
	for i, a := range args {
		if a == "-service" || strings.HasPrefix(a, "-service=") {
			args[i] = "-" + a
		}
	}
	cmd.SetArgs(args)
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
