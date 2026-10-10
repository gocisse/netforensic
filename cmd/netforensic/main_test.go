package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
