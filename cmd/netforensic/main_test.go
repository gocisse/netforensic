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

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
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
		assert.Contains(t, out.String(), `"issues": []`, "an empty selection still has an issues array, never null")
		assert.Contains(t, out.String(), `"message": "No packets matched the specified filters"`)
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
			assert.Equal(t, "No packets matched the specified filters. Nothing to analyze.\n", out)
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
		assert.Contains(t, out, "No packets matched the specified filters")
		assert.NotContains(t, out, "10.0.0.145:54436")
	})

	t.Run("json with -v writes the filtered table to stderr", func(t *testing.T) {
		out, errOut, err := run("-v", "-o", "json", "-s", "443")
		require.NoError(t, err)
		assert.Contains(t, out, `"total_packets": 0`)
		assert.Empty(t, errOut[strings.Index(errOut, "\n")+1:], "no table either: only the warning line")
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

func TestRootCmdNothingToAnalyze(t *testing.T) {
	const lab3 = "../../testdata/Lab-3-TCP-Retrans.pcapng" // port 80 only
	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append(args, lab3))
		err := cmd.Execute()
		return out.String(), errOut.String(), err
	}

	t.Run("text: no health score, clean exit", func(t *testing.T) {
		out, errOut, err := run("-s", "443")
		require.NoError(t, err, "an empty selection is not an error")
		assert.Equal(t, "No packets matched the specified filters. Nothing to analyze.\n", out)
		assert.NotContains(t, out, "Health Score")
		assert.NotContains(t, out, "100/100")
		assert.NotContains(t, out, "HEALTHY")
		assert.NotContains(t, out, "TRIAGE REPORT")
		assert.Contains(t, errOut, "warning: no packets match the filters (202 packets in the capture)")
	})
	t.Run("text with -v prints no table", func(t *testing.T) {
		out, _, err := run("-v", "-s", "443")
		require.NoError(t, err)
		assert.NotContains(t, out, "SOURCE")
		assert.NotContains(t, out, "Health Score")
	})
	t.Run("ip and port filters too", func(t *testing.T) {
		for _, args := range [][]string{{"--src-ip", "9.9.9.9"}, {"--dst-port", "443"}, {"--src-port", "1"}} {
			out, _, err := run(args...)
			require.NoError(t, err, args)
			assert.Contains(t, out, "No packets matched the specified filters. Nothing to analyze.", args)
			assert.NotContains(t, out, "Health Score", args)
		}
	})
	t.Run("json: minimal object", func(t *testing.T) {
		out, _, err := run("-o", "json", "-s", "443")
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &got))
		assert.Equal(t, map[string]any{
			"file_name":     lab3,
			"total_packets": float64(0),
			"total_flows":   float64(0),
			"issues":        []any{},
			"message":       "No packets matched the specified filters",
		}, got)
		assert.NotContains(t, out, "health_score")
		assert.NotContains(t, out, "diagnosis")
	})
	t.Run("matching traffic still gets a full report", func(t *testing.T) {
		out, _, err := run("-s", "80")
		require.NoError(t, err)
		assert.Contains(t, out, "Health Score: 80/100")
		assert.NotContains(t, out, "Nothing to analyze")
	})
	t.Run("a capture with no packets at all", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.pcap")
		f, err := os.Create(path)
		require.NoError(t, err)
		require.NoError(t, pcapgo.NewWriter(f).WriteFileHeader(65535, layers.LinkTypeEthernet))
		require.NoError(t, f.Close())

		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{path})
		require.NoError(t, cmd.Execute())
		assert.Equal(t, "The capture contains no analyzable packets. Nothing to analyze.\n", out.String(), "no filter was involved, so it does not blame one")

		out.Reset()
		cmd = newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"-o", "json", path})
		require.NoError(t, cmd.Execute())
		assert.Contains(t, out.String(), `"message": "The capture contains no analyzable packets"`)
	})
}

func TestRootCmdWeb(t *testing.T) {
	const sample = "../../internal/pcap/testdata/sample.pcap"
	run := func(startServer func(string) error, args ...string) (string, error) {
		var out, errOut bytes.Buffer
		cmd := newRootCmdWith(startServer)
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	notCalled := func(string) error {
		t.Error("the server must not start")
		return nil
	}

	t.Run("starts the server and says where", func(t *testing.T) {
		var gotAddr string
		out, err := run(func(addr string) error { gotAddr = addr; return nil }, "--web", ":8080")
		require.NoError(t, err)
		assert.Equal(t, ":8080", gotAddr)
		assert.Equal(t, "Web UI available at http://localhost:8080 (press Ctrl-C to stop)\n", out)
		assert.NotContains(t, out, "TRIAGE", "no analysis runs")
	})
	t.Run("server errors are returned", func(t *testing.T) {
		_, err := run(func(string) error { return fmt.Errorf("listen on \":8080\": address already in use") }, "--web", ":8080")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "address already in use")
	})
	t.Run("an equals sign works too", func(t *testing.T) {
		var gotAddr string
		_, err := run(func(addr string) error { gotAddr = addr; return nil }, "--web=127.0.0.1:9000")
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:9000", gotAddr)
	})
	t.Run("a capture file is not allowed", func(t *testing.T) {
		_, err := run(notCalled, "--web", ":8080", sample)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not take a capture file")
	})
	t.Run("analysis flags are not allowed", func(t *testing.T) {
		_, err := run(notCalled, "--web", ":8080", "-v", "-s", "dns", "--follow", "a")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--web cannot be combined with --service, --verbose, --follow")
	})
	t.Run("without --web a file is still required", func(t *testing.T) {
		_, err := run(notCalled)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s), received 0")
		_, err = run(notCalled, sample, sample)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "received 2")
	})
	t.Run("an empty --web runs the normal analysis", func(t *testing.T) {
		out, err := run(notCalled, "--web", "", sample)
		require.NoError(t, err)
		assert.Contains(t, out, "Analyzed 2 packets in 2 flows")
	})
	t.Run("the real command rejects an unusable address", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--web", "not an address"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "listen on")
	})
}

func TestWebURL(t *testing.T) {
	for addr, want := range map[string]string{
		":8080":          "http://localhost:8080",
		"localhost:3000": "http://localhost:3000",
		"127.0.0.1:9000": "http://127.0.0.1:9000",
		"0.0.0.0:80":     "http://0.0.0.0:80",
		"[::1]:8080":     "http://[::1]:8080",
		"[::]:8080":      "http://[::]:8080",
		"weird":          "http://weird",
		"host.example:1": "http://host.example:1",
	} {
		assert.Equal(t, want, webURL(addr), addr)
	}
}

func TestDescribeSkippedDelegates(t *testing.T) {
	s := pcap.ReadStats{SkippedNonIP: 2, UnsupportedLinkTypes: map[int]int{18: 5}}
	assert.Equal(t, s.Describe(), describeSkipped(s))
}
