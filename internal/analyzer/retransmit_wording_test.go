package analyzer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRetransmissionWordingClaimsNoLoss pins the general retransmission
// advice and the wording of the other retransmission texts: a retransmission
// shows that data was sent again, not that a packet was lost.
func TestRetransmissionWordingClaimsNoLoss(t *testing.T) {
	assert.Equal(t, "TCP retransmissions observed", categoryCause["PacketLoss"])
	assert.Equal(t, "Segments were sent again on this flow without a duplicate-ACK or silence trigger that NetForensic could identify. A retransmission does not by itself prove packet loss. Open the filter in Wireshark and compare the timing of the resent frames with their originals; compare with a capture at the other end.",
		issueRecommendations[titleRetransmissions])
	assert.Equal(t, []string{
		"Retransmissions were observed, but this capture alone cannot show whether packets were lost, delayed or reordered. Compare captures at both ends.",
		"Check interface error and drop counters and queue behavior on the path.",
	}, categoryRecommendations["PacketLoss"])

	texts := []string{categoryCause["PacketLoss"], titleCause[titleFastRetransmit], titleCause[titleTimeoutRetransmit]}
	for _, title := range []string{titleFastRetransmit, titleTimeoutRetransmit, titleRetransmissions} {
		texts = append(texts, issueRecommendations[title])
		texts = append(texts, categoryRecommendations[title]...)
	}
	texts = append(texts, categoryRecommendations["PacketLoss"]...)
	for _, s := range texts {
		l := strings.ToLower(s)
		for _, bad := range []string{"isolated packet loss", "missing segment", "the losses", "duplex mismatch", "faulty cabling", "recovered quickly"} {
			assert.NotContains(t, l, bad, s)
		}
	}
}
