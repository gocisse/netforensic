package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPProtocolName(t *testing.T) {
	tests := []struct {
		n    uint8
		want Protocol
	}{
		{2, "IGMP"},
		{4, "IP-in-IP"},
		{47, "GRE"},
		{50, "ESP"},
		{51, "AH"},
		{88, "EIGRP"},
		{89, "OSPF"},
		{103, "PIM"},
		{112, "VRRP"},
		{115, "L2TP"},
		{132, "SCTP"},
		{6, ""},   // TCP is decoded, not named here
		{253, ""}, // unknown
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, IPProtocolName(tt.n), "protocol %d", tt.n)
	}
}
