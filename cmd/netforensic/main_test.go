package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"all", false}, {"dns", false}, {"http", false}, {"tls", false}, {"ftp", true}, {"", true},
	}
	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			assert.Equal(t, tt.wantErr, validateService(tt.service) != nil)
		})
	}
}
