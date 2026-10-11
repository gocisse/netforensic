package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestValidateFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		assert.NoError(t, os.WriteFile(p, nil, 0o644))
		return p
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"pcap", write("a.pcap"), false},
		{"pcapng uppercase", write("b.PCAPNG"), false},
		{"bad extension", write("c.txt"), true},
		{"missing", filepath.Join(dir, "missing.pcap"), true},
		{"directory", dir, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFile(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateService(t *testing.T) {
	tests := []struct {
		service string
		wantErr bool
	}{
		{"all", false}, {"dns", false}, {"http", false}, {"tls", false}, {"https", false}, {"443", false}, {"70000", true}, {"ftp", true}, {"", true},
	}
	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			assert.Equal(t, tt.wantErr, validateService(tt.service) != nil)
		})
	}
}

func TestRootCmdVerbose(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"
	tests := []struct {
		name        string
		args        []string
		wantTable   bool
		wantSummary string
	}{
		{"default", []string{sample}, false, "Analyzed 2 packets in 2 flows"},
		{"short flag", []string{"-v", sample}, true, "Analyzed 2 packets in 2 flows"},
		{"long flag with single-dash service", normalizeArgs([]string{"--verbose", "-service", "dns", sample}), true, "Analyzed 1 packets in 1 flows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&out)
			cmd.SetArgs(tt.args)
			require.NoError(t, cmd.Execute())
			assert.Equal(t, tt.wantTable, strings.Contains(out.String(), "SOURCE"))
			assert.Contains(t, out.String(), tt.wantSummary)
		})
	}
}

func TestRootCmdJSON(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"

	t.Run("valid json on stdout", func(t *testing.T) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"-o", "json", "-v", sample})
		require.NoError(t, cmd.Execute())

		var res models.AnalysisResult
		require.NoError(t, json.Unmarshal(out.Bytes(), &res), "stdout must be pure JSON, got: %s", out.String())
		assert.Equal(t, sample, res.FileName)
		assert.Equal(t, 2, res.TotalPackets)
		assert.Equal(t, 2, res.TotalFlows)
		assert.Len(t, res.TopTalkers, 2)
		assert.Contains(t, out.String(), "\n  \"total_packets\": 2", "output should be indented")
		assert.NotContains(t, out.String(), "Analyzed")
		assert.Contains(t, errOut.String(), "SOURCE", "verbose table goes to stderr")
	})

	t.Run("empty issues is an array", func(t *testing.T) {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--output", "json", "-s", "tls", sample})
		require.NoError(t, cmd.Execute())
		assert.Contains(t, out.String(), `"issues": []`)
		assert.Contains(t, out.String(), `"top_talkers": []`)
	})

	t.Run("invalid format", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"-o", "xml", sample})
		assert.Error(t, cmd.Execute())
	})
}

// The service filter used to run only inside the analyzer, so -v printed
// every packet of the capture next to a report that said "0 packets".
func TestRootCmdServiceFilterAppliesToTableAndAnalysis(t *testing.T) {
	const lab3 = "../../testdata/Lab-3-TCP-Retrans.pcapng" // 202 packets, all to or from port 80
	run := func(args ...string) (stdout, stderr string, err error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append(args, lab3))
		err = cmd.Execute()
		return out.String(), errOut.String(), err
	}

	for _, svc := range []string{"443", "https", "tls", "dns", "53", "8080"} {
		t.Run("-s "+svc+" matches nothing", func(t *testing.T) {
			out, errOut, err := run("-v", "-s", svc)
			require.NoError(t, err)
			assert.Contains(t, out, "Analyzed 0 packets in 0 flows, found 0 issues")
			assert.Contains(t, out, "0 packets matched the specified filters")
			assert.NotContains(t, out, "186.15.230.24:80", "no port 80 traffic may be shown")
			assert.NotContains(t, out, "SOURCE", "no table header for an empty selection")
			assert.Contains(t, errOut, "no packets match the filters (202 packets in the capture)")
		})
	}

	for _, svc := range []string{"80", "http", "all"} {
		t.Run("-s "+svc+" keeps everything", func(t *testing.T) {
			out, errOut, err := run("-v", "-s", svc)
			require.NoError(t, err)
			assert.Contains(t, out, "Analyzed 202 packets in 1 flows")
			assert.Contains(t, out, "186.15.230.24:80")
			assert.NotContains(t, out, "matched the specified filters")
			assert.NotContains(t, errOut, "no packets match")
			assert.Equal(t, 202, strings.Count(out, "TCP  "), "one table row per analyzed packet")
		})
	}

	t.Run("table rows always equal analyzed packets", func(t *testing.T) {
		out, _, err := run("-v", "-s", "80", "--src-ip", "10.0.0.145")
		require.NoError(t, err)
		rows := len(regexp.MustCompile(`(?m)^\d+\s+\d{4}-\d\d-\d\d `).FindAllString(out, -1)) // table rows only
		var analyzed int
		_, scanErr := fmt.Sscanf(out[strings.Index(out, "Analyzed "):], "Analyzed %d packets", &analyzed)
		require.NoError(t, scanErr)
		assert.Less(t, analyzed, 202)
		assert.Equal(t, analyzed, rows)
		assert.NotContains(t, out, "186.15.230.24:80 ->", "server-to-client packets were filtered out")
	})

	t.Run("service and ip filters combine", func(t *testing.T) {
		out, _, err := run("-v", "-s", "443", "--src-ip", "10.0.0.145")
		require.NoError(t, err)
		assert.Contains(t, out, "Analyzed 0 packets")
		assert.NotContains(t, out, "10.0.0.145:54436")
	})

	t.Run("json with -v writes the filtered table to stderr", func(t *testing.T) {
		out, errOut, err := run("-v", "-o", "json", "-s", "443")
		require.NoError(t, err)
		assert.Contains(t, out, `"total_packets": 0`)
		assert.Contains(t, errOut, "0 packets matched the specified filters")
		assert.NotContains(t, errOut, "186.15.230.24:80")
	})

	t.Run("follow honors the service filter", func(t *testing.T) {
		_, _, err := run("-s", "443", "--follow", "10.0.0.145:54436-186.15.230.24:80")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		out, _, err := run("-s", "80", "--follow", "10.0.0.145:54436-186.15.230.24:80")
		require.NoError(t, err)
		assert.Contains(t, out, "Following stream")
	})
}
