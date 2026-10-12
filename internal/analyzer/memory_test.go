package analyzer

import (
	"fmt"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestHasTCPFlag(t *testing.T) {
	tests := []struct {
		flags, flag string
		want        bool
	}{
		{"SYN", "SYN", true},
		{"SYN,ACK", "SYN", true},
		{"SYN,ACK", "ACK", true},
		{"PSH,ACK,FIN", "ACK", true},
		{"PSH,ACK", "SYN", false},
		{"", "ACK", false},
		{"ACK", "", false},
		{"SYNACK", "SYN", false}, // a prefix is not a flag
		{"RST,ACK", "RST", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q has %q", tt.flags, tt.flag), func(t *testing.T) {
			assert.Equal(t, tt.want, hasTCPFlag(tt.flags, tt.flag))
		})
	}
	assert.Zero(t, testing.AllocsPerRun(100, func() { hasTCPFlag("PSH,ACK,FIN", "RST") }), "must not allocate")
}

// syntheticFlows builds n TCP flows, each with a handshake, a request and its answer.
func syntheticFlows(n int) []models.PacketInfo {
	t0 := time.Unix(1700000000, 0)
	pk := make([]models.PacketInfo, 0, n*5)
	add := func(i, ms int, fromClient bool, flags string, payload int, seq, ack uint32) {
		p := models.PacketInfo{
			Timestamp: t0.Add(time.Duration(i*10+ms) * time.Millisecond), Protocol: models.ProtocolTCP, TCPFlags: flags,
			PayloadSize: payload, Size: 60 + payload, TCPSeq: seq, TCPAck: ack, TCPWindow: 65535,
		}
		client := fmt.Sprintf("10.%d.%d.1", i/250%250, i%250)
		if fromClient {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = client, 40000, "10.9.9.9", 443
		} else {
			p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = "10.9.9.9", 443, client, 40000
		}
		pk = append(pk, p)
	}
	for i := 0; i < n; i++ {
		add(i, 0, true, "SYN", 0, 100, 0)
		add(i, 1, false, "SYN,ACK", 0, 500, 101)
		add(i, 2, true, "ACK", 0, 101, 501)
		add(i, 3, true, "PSH,ACK", 200, 101, 501)
		add(i, 4, false, "ACK", 0, 501, 301)
	}
	return pk
}

// Giving each flow its packets used to copy every TCP packet of the capture,
// about a kilobyte each, and hold all the copies at once. Now one flow's
// packets are copied at a time into a reused buffer, so the metrics cost a
// small fraction of a copy of the capture even in total allocation.
func TestApplyPerformanceMetricsDoesNotCopyThePackets(t *testing.T) {
	packets := syntheticFlows(6000)
	flows := aggregateFlows(packets)
	require.Len(t, flows, 6000)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, _ := applyPerformanceMetrics(packets, flows)
	runtime.ReadMemStats(&after)

	copyOfAll := uint64(len(packets)) * uint64(unsafe.Sizeof(models.PacketInfo{}))
	allocated := after.TotalAlloc - before.TotalAlloc
	assert.Less(t, allocated, copyOfAll*3/4, "applyPerformanceMetrics allocated %d bytes; copying the packets would take %d", allocated, copyOfAll)
	assert.Positive(t, out[0].AvgRTTMs, "the metrics are still filled in")
}

// The top lists must hold copies of just their flows: a slice of a copy of
// all the flows would keep every flow of the capture alive.
func TestTopListsDoNotRetainAllFlows(t *testing.T) {
	flows := make([]models.Flow, 1000)
	for i := range flows {
		flows[i] = models.Flow{ID: fmt.Sprint(i), Protocol: models.ProtocolTCP, BytesSent: i, MaxRTTMs: float64(i + 1)}
	}
	for name, got := range map[string][]models.Flow{
		"topTalkers":  topTalkers(flows, 5),
		"slowFlows":   slowFlows(flows, 5),
		"topFlowsOf":  topFlowsOf(flows, "TCP"),
		"no matching": topFlowsOf(flows, "UDP"),
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotNil(t, got)
			assert.LessOrEqual(t, cap(got), topFlowsPerProtocol, "the backing array holds only the flows that are kept")
		})
	}
	assert.Equal(t, []string{"999", "998", "997", "996", "995"}, ids(topTalkers(flows, 5)))
	assert.Equal(t, []string{"999", "998", "997"}, ids(slowFlows(flows, 3)))
	assert.Empty(t, topFlowsOf(flows, "UDP"))
}

func ids(flows []models.Flow) []string {
	out := make([]string, len(flows))
	for i, f := range flows {
		out[i] = f.ID
	}
	return out
}
