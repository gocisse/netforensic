package analyzer

import (
	"bytes"
	"sort"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// StreamMessage is one contiguous piece of application-layer conversation:
// the stitched payload of consecutive same-direction TCP segments, a single
// UDP datagram, or a non-transport event such as an ICMP message.
type StreamMessage struct {
	Timestamp time.Time // arrival of the first segment
	ToServer  bool
	Kind      string // "DNS", "HTTP", "TLS", or the transport/network protocol
	Summary   string // protocol-level description, for example "GET /index.html"
	Data      []byte // reassembled payload; nil for DNS, ICMP, ARP and gaps
	Missing   int    // bytes that were never captured (a gap in the stream)
	Segments  int    // packets stitched into Data
}

// streamChunk is a piece of one direction of a TCP byte stream.
type streamChunk struct {
	toServer bool
	off      int64 // stream offset relative to the first segment seen
	ts       time.Time
	data     []byte // nil for a gap
	missing  int    // gap length when data is nil
	pkt      models.PacketInfo
}

func (c streamChunk) length() int64 {
	if c.data == nil {
		return int64(c.missing)
	}
	return int64(len(c.data))
}

// FollowStream reconstructs the application-layer conversation of the flow
// named by flowID. TCP segments are reassembled by sequence number per
// direction, so retransmitted and out-of-order segments land where they
// belong and duplicates are dropped; pure ACKs and other empty segments do
// not appear. Bytes that were never captured show up as Missing gaps.
//
// Payloads come from PacketInfo.Payload, falling back to PayloadPreview
// when the full payload was not kept. The returned error is a *FollowError
// listing the available flows if flowID is malformed or matches nothing.
func FollowStream(packets []models.PacketInfo, flowID string) (*Conversation, error) {
	matched, conv, err := matchFlow(packets, flowID)
	if err != nil {
		return nil, err
	}

	var (
		rd       retransmitDetector
		segments = map[bool][]streamChunk{}
		other    []streamChunk // UDP, ICMP and ARP events, one per packet
	)
	for _, p := range matched {
		toServer := conv.isFromClient(p)
		key, forward := canonicalKey(p)
		if rd.observe(instKey{key, 0}, forward, p).retrans {
			conv.Retransmits++
		}

		src := p.Payload
		if src == nil {
			src = p.PayloadPreview
		}
		switch {
		case p.Protocol == models.ProtocolTCP:
			span := p.PayloadSize
			if span < len(src) {
				span = len(src)
			}
			if span == 0 {
				continue // pure ACK, SYN, FIN or RST
			}
			c := streamChunk{toServer: toServer, ts: p.Timestamp, pkt: p, off: int64(int32(p.TCPSeq))}
			if len(src) > 0 {
				c.data = src
			}
			c.missing = span - len(src)
			segments[toServer] = append(segments[toServer], c)
		case p.Protocol == models.ProtocolUDP && p.PayloadSize == 0 && p.DNSQueryName == "":
		default:
			other = append(other, streamChunk{toServer: toServer, ts: p.Timestamp, pkt: p, data: src})
		}
	}

	var chunks []streamChunk
	for _, dir := range []bool{true, false} {
		chunks = append(chunks, orderDirection(segments[dir])...)
	}
	chunks = append(chunks, other...)
	sort.SliceStable(chunks, func(i, j int) bool { return chunks[i].ts.Before(chunks[j].ts) })

	for _, c := range chunks {
		conv.Messages = appendChunk(conv.Messages, c)
	}
	return conv, nil
}

// orderDirection turns the TCP segments of one direction into a gap-aware,
// duplicate-free, offset-ordered chunk list. Each chunk's timestamp is the
// earliest arrival among itself and everything after it, so a late
// retransmission that fills a hole is shown in stream order rather than
// arrival order.
func orderDirection(segs []streamChunk) []streamChunk {
	if len(segs) == 0 {
		return nil
	}
	base := segs[0].off
	for i := range segs {
		segs[i].off = int64(int32(uint32(segs[i].off) - uint32(base)))
	}
	sort.SliceStable(segs, func(i, j int) bool { return segs[i].off < segs[j].off })

	// Split each segment into its captured bytes and the tail cut off by the
	// snaplen, so both take part in overlap handling.
	var parts []streamChunk
	for _, s := range segs {
		if s.data != nil {
			parts = append(parts, streamChunk{toServer: s.toServer, off: s.off, ts: s.ts, data: s.data, pkt: s.pkt})
		}
		if s.missing > 0 {
			parts = append(parts, streamChunk{toServer: s.toServer, off: s.off + int64(len(s.data)), ts: s.ts, missing: s.missing, pkt: s.pkt})
		}
	}

	covered := parts[0].off
	var out []streamChunk
	for _, c := range parts {
		end := c.off + c.length()
		if end <= covered {
			continue // duplicate of bytes already placed
		}
		if c.off > covered { // bytes between segments were never captured
			out = append(out, streamChunk{toServer: c.toServer, off: covered, ts: c.ts, missing: int(c.off - covered), pkt: c.pkt})
			covered = c.off
		}
		if skip := covered - c.off; skip > 0 { // partial overlap
			if c.data != nil {
				c.data = c.data[skip:]
			} else {
				c.missing -= int(skip)
			}
			c.off = covered
		}
		out = append(out, c)
		covered = end
	}

	for i := len(out) - 2; i >= 0; i-- {
		if out[i+1].ts.Before(out[i].ts) {
			out[i].ts = out[i+1].ts
		}
	}
	return out
}

// appendChunk adds c to msgs, stitching it onto the previous message when
// both are consecutive data from the same TCP direction.
func appendChunk(msgs []StreamMessage, c streamChunk) []StreamMessage {
	if c.pkt.Protocol == models.ProtocolTCP {
		if c.data == nil {
			return append(msgs, StreamMessage{Timestamp: c.ts, ToServer: c.toServer, Kind: string(models.ProtocolTCP), Missing: c.missing})
		}
		if n := len(msgs); n > 0 {
			last := &msgs[n-1]
			if last.ToServer == c.toServer && last.Missing == 0 && last.Segments > 0 {
				last.Data = append(last.Data, c.data...)
				last.Segments++
				return msgs
			}
		}
	}

	ev := describePacket(c.pkt)
	m := StreamMessage{Timestamp: c.ts, ToServer: c.toServer, Kind: ev.Kind, Summary: ev.Summary, Segments: 1}
	if m.Kind == string(models.ProtocolTCP) && looksLikeHTTP(c.data) {
		m.Kind = "HTTP" // headline packet was cut short by the snaplen
	}
	if ev.Kind != "DNS" && c.pkt.Protocol != models.ProtocolICMP && c.pkt.Protocol != models.ProtocolARP {
		m.Data = append([]byte(nil), c.data...)
	}
	return append(msgs, m)
}

// looksLikeHTTP reports whether data starts like an HTTP request or response.
func looksLikeHTTP(data []byte) bool {
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1.", "HTTP/2"} {
		if bytes.HasPrefix(data, []byte(prefix)) {
			return true
		}
	}
	return false
}
