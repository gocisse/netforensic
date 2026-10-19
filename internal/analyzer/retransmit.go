package analyzer

import (
	"fmt"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	// fastRetransmitDupAcks is the number of duplicate ACKs that triggers a
	// fast retransmit (RFC 5681).
	fastRetransmitDupAcks = 3

	// rtoSilence is how long a connection must have been silent before a
	// retransmission is read as the result of a retransmission timeout.
	rtoSilence = 200 * time.Millisecond

	// reorderWindow is the time after a segment that advanced the stream
	// within which a late hole-filling segment is taken for reordering.
	reorderWindow = 3 * time.Millisecond

	// episodeWindow is how long after a fast or timeout retransmit further
	// retransmissions in the same direction count as part of the same
	// recovery and inherit its kind.
	episodeWindow = time.Second
)

// retransKind says what triggered a retransmission.
type retransKind int

const (
	retransNone    retransKind = iota
	retransFast                // after three or more duplicate ACKs
	retransTimeout             // after silence, with no duplicate ACKs
	retransOther               // neither trigger, or data that was already acknowledged

	// Later segments resent during the recovery that a fast or timeout
	// retransmission started. They did not trigger it themselves, so they are
	// counted apart and never inflate the fast or timeout counts.
	retransFastRecovery
	retransTimeoutRecovery
)

// family maps the recovery kinds to the kind that started the recovery.
func (k retransKind) family() retransKind {
	switch k {
	case retransFastRecovery:
		return retransFast
	case retransTimeoutRecovery:
		return retransTimeout
	}
	return k
}

func (k retransKind) String() string {
	switch k {
	case retransFast:
		return "fast"
	case retransTimeout:
		return "timeout"
	case retransOther:
		return "other"
	case retransFastRecovery:
		return "fast-recovery"
	case retransTimeoutRecovery:
		return "timeout-recovery"
	}
	return ""
}

// segmentResult is what the detector concluded about one packet.
type segmentResult struct {
	retrans bool
	kind    retransKind
	dupAck  bool
}

type retransDirKey struct {
	flow    instKey
	forward bool
}

// retransDir is the state of one direction of one connection: the segments
// it sent and the ACKs it sent back.
type retransDir struct {
	seen        map[uint32]struct{}
	nextSeq     uint32 // sequence number following the highest segment sent
	haveNext    bool
	advancedAt  time.Time // when nextSeq last moved forward
	lastRetrans time.Time
	lastKind    retransKind

	// ACKs sent by this side
	haveAck bool
	lastAck uint32
	lastWin uint32
	dupAcks int // consecutive duplicate ACKs for lastAck
}

// retransmitDetector finds retransmitted TCP segments and classifies them.
// It is fed packets in capture order.
//
// A segment is a retransmission when it carries data, a SYN or a FIN and
//   - its sequence number was already sent in the same direction, or
//   - it starts below the highest sequence sent and exactly at the byte the
//     receiver last asked for (a hole being filled), at least a few
//     milliseconds after the segment that last advanced the stream
//     (otherwise it is reordering), and either the receiver has sent
//     duplicate ACKs for it, or the connection had been silent. Once such an
//     RTO retransmission has happened, further hole fills that follow within a
//     second are part of the same recovery and count too. Later hole fills that the receiver never asked
//     for again are delayed originals, which Wireshark also calls
//     out-of-order rather than retransmissions; or
//   - everything in it was already acknowledged.
//
// Keep-alive probes, which deliberately reuse the last sequence number, are
// not retransmissions. A duplicate ACK is a pure ACK repeating the previous
// ACK number and window of the same side.
type retransmitDetector struct {
	dirs     map[retransDirKey]*retransDir
	lastSeen map[instKey]time.Time // last packet of either direction
}

func (d *retransmitDetector) dir(k retransDirKey) *retransDir {
	if d.dirs == nil {
		d.dirs = make(map[retransDirKey]*retransDir)
		d.lastSeen = make(map[instKey]time.Time)
	}
	r := d.dirs[k]
	if r == nil {
		r = &retransDir{seen: make(map[uint32]struct{})}
		d.dirs[k] = r
	}
	return r
}

// observe examines p, which travels in the given direction of connection key.
func (d *retransmitDetector) observe(key instKey, forward bool, p models.PacketInfo) segmentResult {
	var res segmentResult
	if p.Protocol != models.ProtocolTCP {
		return res
	}
	me, peer := d.dir(retransDirKey{key, forward}), d.dir(retransDirKey{key, !forward})
	prevPacket, hadPrev := d.lastSeen[key]
	d.lastSeen[key] = p.Timestamp

	res.dupAck = me.trackAck(p)

	if !consumesSeq(p) {
		// A bare ACK still reveals how far the sender has got: its sequence
		// number is the next byte it will send, even if the data segments
		// before it were lost before the capture point.
		if !hasTCPFlag(p.TCPFlags, "RST") && (!me.haveNext || int32(p.TCPSeq-me.nextSeq) > 0) {
			me.nextSeq, me.haveNext, me.advancedAt = p.TCPSeq, true, p.Timestamp
		}
		return res
	}
	if isKeepAlive(p, me.nextSeq, me.haveNext) {
		return res
	}

	end := p.TCPSeq + seqLen(p)
	_, dupStart := me.seen[p.TCPSeq]
	me.seen[p.TCPSeq] = struct{}{}
	below := me.haveNext && int32(p.TCPSeq-me.nextSeq) < 0 // starts inside already-sent space
	acked := peer.haveAck && int32(end-peer.lastAck) <= 0  // the receiver already has all of it
	asked := peer.haveAck && p.TCPSeq == peer.lastAck      // the receiver is waiting for this byte

	silent := hadPrev && p.Timestamp.Sub(prevPacket) > rtoSilence
	inTimeoutRecovery := me.lastKind == retransTimeout && p.Timestamp.Sub(me.lastRetrans) <= episodeWindow
	switch {
	case dupStart:
		res.retrans = true
	case below && acked:
		res.retrans = true
	case below && inTimeoutRecovery && peer.haveAck && int32(p.TCPSeq-peer.lastAck) >= 0:
		// After an RTO the sender resends the whole missing window back to
		// back, so these segments need not start at the last ACK number.
		res.retrans = true
	case below && asked && p.Timestamp.Sub(me.advancedAt) >= reorderWindow &&
		(peer.dupAcks > 0 || silent):
		// A hole is being filled and the receiver, the silence or the
		// ongoing recovery says this is not just late delivery.
		res.retrans = true
	}
	if !me.haveNext || int32(end-me.nextSeq) > 0 {
		me.nextSeq, me.haveNext = end, true
		if !below {
			me.advancedAt = p.Timestamp
		}
	}
	if !res.retrans {
		return res
	}

	switch {
	case asked && peer.dupAcks >= fastRetransmitDupAcks:
		res.kind = retransFast
	case peer.dupAcks == 0 && silent:
		res.kind = retransTimeout
	case acked:
		res.kind = retransOther // the receiver had it already: a spurious resend
	case (me.lastKind == retransFast || me.lastKind == retransTimeout) && p.Timestamp.Sub(me.lastRetrans) <= episodeWindow:
		// A later segment of the same recovery: it did not trigger anything
		// itself, so it must not be counted as a fast or timeout retransmit.
		if me.lastKind == retransFast {
			res.kind = retransFastRecovery
		} else {
			res.kind = retransTimeoutRecovery
		}
	default:
		res.kind = retransOther
	}
	me.lastRetrans, me.lastKind = p.Timestamp, res.kind.family()
	return res
}

// trackAck updates the ACKs sent by this side and reports whether p is a
// duplicate ACK.
func (r *retransDir) trackAck(p models.PacketInfo) bool {
	if !hasTCPFlag(p.TCPFlags, "ACK") {
		return false
	}
	pure := p.PayloadSize == 0 && !hasTCPFlag(p.TCPFlags, "SYN") && !hasTCPFlag(p.TCPFlags, "FIN") && !hasTCPFlag(p.TCPFlags, "RST")
	dup := false
	switch {
	case !r.haveAck, int32(p.TCPAck-r.lastAck) > 0:
		r.dupAcks = 0
	case p.TCPAck == r.lastAck && pure && p.TCPWindow == r.lastWin:
		r.dupAcks++
		dup = true
	case p.TCPAck == r.lastAck && pure:
		r.dupAcks = 0 // a window update, not a duplicate
	}
	if !r.haveAck || int32(p.TCPAck-r.lastAck) >= 0 {
		r.lastAck = p.TCPAck
		r.haveAck = true
		if pure {
			r.lastWin = p.TCPWindow
		}
	}
	return dup
}

// record adds the detector's verdict on p to the flow's counters.
func recordRetransmit(f *models.Flow, r segmentResult, p models.PacketInfo) {
	if r.dupAck {
		f.DupAcks++
	}
	if !r.retrans {
		return
	}
	f.Retransmits++
	switch r.kind {
	case retransFast:
		f.FastRetransmits++
	case retransTimeout:
		f.TimeoutRetransmits++
	case retransFastRecovery, retransTimeoutRecovery:
		f.RecoveryRetransmits++
	}
	f.RetransmitEvents = append(f.RetransmitEvents, models.RetransmitEvent{Time: p.Timestamp, Seq: p.TCPSeq, Kind: r.kind.String(),
		SYN: hasTCPFlag(p.TCPFlags, "SYN") && !hasTCPFlag(p.TCPFlags, "ACK")})
}

// Titles of the retransmission issues.
const (
	titleFastRetransmit    = "Fast Retransmit"
	titleTimeoutRetransmit = "Timeout Retransmit"
	titleRetransmissions   = "TCP Retransmissions detected"
)

// retransmitIssue builds the issue for the retransmissions of kind k in f,
// reporting false if there are none.
func retransmitIssue(f models.Flow, k retransKind) (models.Issue, bool) {
	var first, last time.Time
	var firstSeq uint32
	n, recovery := 0, 0 // segments that triggered / segments resent in the same recovery
	recoveryKind := ""
	if k == retransFast || k == retransTimeout {
		recoveryKind = k.String() + "-recovery"
	}
	for _, ev := range f.RetransmitEvents {
		isRecovery := recoveryKind != "" && ev.Kind == recoveryKind
		if ev.Kind != k.String() && !isRecovery {
			continue
		}
		if n+recovery == 0 {
			first, firstSeq = ev.Time, ev.Seq
		}
		last = ev.Time
		if isRecovery {
			recovery++
		} else {
			n++
		}
	}
	if n+recovery == 0 {
		return models.Issue{}, false
	}
	total := n + recovery
	also := ""
	if recovery > 0 {
		also = fmt.Sprintf(", plus %d more resent during the same recovery", recovery)
	}

	is := models.Issue{
		ID:        fmt.Sprintf("packetloss-%s-%s", k, f.ID),
		Category:  "PacketLoss",
		Timestamp: first,
		FlowID:    f.ID,
		Count:     total,
	}
	span := ""
	if total > 1 {
		span = fmt.Sprintf(" (last at %s)", last.UTC().Format("15:04:05.000"))
	}
	switch k {
	case retransFast:
		is.Severity, is.Title = models.SeverityWarning, titleFastRetransmit
		is.Description = fmt.Sprintf("flow %s had %d segment(s) retransmitted after %d or more duplicate ACKs%s, first seq %d at %s%s; the receiver kept asking for a missing segment",
			f.ID, n, fastRetransmitDupAcks, also, firstSeq, first.UTC().Format("15:04:05.000"), span)
	case retransTimeout:
		is.Severity, is.Title = models.SeverityError, titleTimeoutRetransmit
		is.Description = fmt.Sprintf("flow %s had %d segment(s) retransmitted after the connection went silent for over %s with no duplicate ACKs%s, first seq %d at %s%s; the sender waited for a retransmission timeout",
			f.ID, n, rtoSilence, also, firstSeq, first.UTC().Format("15:04:05.000"), span)
	default:
		is.Severity, is.Title = models.SeverityWarning, titleRetransmissions
		is.Description = fmt.Sprintf("flow %s had %d retransmitted packets", f.ID, total)
	}
	return is, true
}
