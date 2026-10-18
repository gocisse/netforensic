package analyzer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// Only a client SYN retransmission is marked as one; the marker is not part of
// any serialized form.
func TestRetransmitEventMarksClientSYNRetries(t *testing.T) {
	res := Analyze([]models.PacketInfo{
		tx(0, false, "SYN", 7000, 0, 0, 65535), tx(1000, false, "SYN", 7000, 0, 0, 65535),
		tx(1030, true, "SYN,ACK", 9000, 7001, 0, 65535), tx(1330, true, "SYN,ACK", 9000, 7001, 0, 65535), // the server resends its SYN-ACK
		tx(1331, false, "ACK", 7001, 9001, 0, 65535),
		tx(1500, false, "PSH,ACK", 7001, 9001, 100, 65535), tx(1800, false, "PSH,ACK", 7001, 9001, 100, 65535)}, "all")
	require.Len(t, res.Flows, 1)
	ev := res.Flows[0].RetransmitEvents
	require.Len(t, ev, 3)
	assert.True(t, ev[0].SYN, "the client's repeated SYN")
	assert.False(t, ev[1].SYN, "the server's repeated SYN-ACK")
	assert.False(t, ev[2].SYN, "repeated data")
	assert.Equal(t, 3, res.Flows[0].Retransmits)
	assert.Equal(t, 3, res.Flows[0].TimeoutRetransmits, "kinds and counters are as before")
	for _, e := range ev {
		assert.Equal(t, "timeout", e.Kind)
	}
}

func TestRetransmitEventMarkerIsNotSerialized(t *testing.T) {
	b, err := json.Marshal(models.RetransmitEvent{Seq: 7, Kind: "timeout", SYN: true})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.NotContains(t, m, "SYN")
	assert.NotContains(t, m, "syn")
	assert.Len(t, m, 3, "Time, Seq and Kind, as before")

	res := Analyze([]models.PacketInfo{tx(0, false, "SYN", 7000, 0, 0, 65535), tx(1000, false, "SYN", 7000, 0, 0, 65535), tail(3000)}, "all")
	out, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "RetransmitEvent")
	assert.NotContains(t, string(out), `"SYN"`)
}
