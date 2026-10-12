// Command gencap writes a large synthetic capture for load-testing netforensic:
// mixed TCP conversations (with handshakes, data, retransmissions, resets and
// unanswered SYNs), DNS lookups (some failing), HTTP requests with error
// responses and ICMP errors, interleaved the way real traffic is. The output is
// deterministic for a given -seed. It is a development tool and is not part of
// the netforensic binary.
//
//	go run ./cmd/gencap -packets 1500000 -out /tmp/big.pcap
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// event is one packet of a scripted conversation.
type event struct {
	udp      bool
	fromCli  bool
	flags    byte // TCP flags: 1 FIN, 2 SYN, 4 RST, 8 PSH, 16 ACK
	seq, ack uint32
	payload  []byte
	icmp     bool
	dns      *layers.DNS
	delay    time.Duration // time since the previous event of the conversation
}

type conversation struct {
	cli, srv     net.IP
	cport, sport uint16
	events       []event
	next         int
	nextAt       time.Time
}

type generator struct {
	rng     *rand.Rand
	clients []net.IP
	servers []net.IP
}

func newGenerator(seed int64) *generator {
	g := &generator{rng: rand.New(rand.NewSource(seed))}
	for i := 0; i < 20000; i++ {
		g.clients = append(g.clients, net.IP{10, byte(i >> 8), byte(i), byte(1 + i%250)})
	}
	for i := 0; i < 600; i++ {
		g.servers = append(g.servers, net.IP{100, 64, byte(i >> 8), byte(1 + i%250)})
	}
	return g
}

var httpPorts = []uint16{80, 443, 443, 443, 8080, 22, 445, 3389, 5432}

func (g *generator) tcpConversation() *conversation {
	r := g.rng
	c := &conversation{
		cli: g.clients[r.Intn(len(g.clients))], srv: g.servers[r.Intn(len(g.servers))],
		cport: uint16(1024 + r.Intn(60000)), sport: httpPorts[r.Intn(len(httpPorts))],
	}
	cseq, sseq := r.Uint32(), r.Uint32()
	rtt := time.Duration(200+r.Intn(3000)) * time.Microsecond
	if r.Intn(40) == 0 { // a slow path
		rtt = time.Duration(150+r.Intn(400)) * time.Millisecond
	}
	add := func(e event) { c.events = append(c.events, e) }

	if r.Intn(60) == 0 { // a SYN nobody answers
		add(event{fromCli: true, flags: 2, seq: cseq})
		add(event{fromCli: true, flags: 2, seq: cseq, delay: time.Second})
		return c
	}
	if r.Intn(50) == 0 { // refused
		add(event{fromCli: true, flags: 2, seq: cseq})
		add(event{flags: 4 | 16, seq: 0, ack: cseq + 1, delay: rtt})
		return c
	}
	add(event{fromCli: true, flags: 2, seq: cseq})
	add(event{flags: 2 | 16, seq: sseq, ack: cseq + 1, delay: rtt})
	cseq++
	sseq++
	add(event{fromCli: true, flags: 16, seq: cseq, ack: sseq, delay: rtt})

	rounds := 1 + r.Intn(6)
	for i := 0; i < rounds; i++ {
		n := 80 + r.Intn(400)
		var req []byte
		if c.sport == 80 || c.sport == 8080 {
			req = []byte(fmt.Sprintf("GET /item/%d HTTP/1.1\r\nHost: web%d.example.com\r\n\r\n", r.Intn(100000), r.Intn(500)))
		} else {
			req = make([]byte, n)
		}
		add(event{fromCli: true, flags: 8 | 16, seq: cseq, ack: sseq, payload: req, delay: time.Duration(r.Intn(2000)) * time.Microsecond})
		if r.Intn(150) == 0 { // a retransmission
			add(event{fromCli: true, flags: 8 | 16, seq: cseq, ack: sseq, payload: req, delay: 220 * time.Millisecond})
		}
		cseq += uint32(len(req))
		var resp []byte
		if c.sport == 80 || c.sport == 8080 {
			status := "200 OK"
			switch x := r.Intn(100); {
			case x < 3:
				status = "404 Not Found"
			case x < 4:
				status = "500 Internal Server Error"
			}
			resp = []byte("HTTP/1.1 " + status + "\r\nContent-Length: 600\r\n\r\n" + string(make([]byte, 600)))
		} else {
			resp = make([]byte, 80+r.Intn(500))
		}
		add(event{flags: 8 | 16, seq: sseq, ack: cseq, payload: resp, delay: rtt})
		sseq += uint32(len(resp))
		add(event{fromCli: true, flags: 16, seq: cseq, ack: sseq, delay: rtt / 2})
	}
	switch x := r.Intn(100); {
	case x < 4: // a reset
		add(event{flags: 4 | 16, seq: sseq, ack: cseq, delay: rtt})
	case x < 5: // no close at all
	default:
		add(event{fromCli: true, flags: 1 | 16, seq: cseq, ack: sseq, delay: rtt})
		add(event{flags: 1 | 16, seq: sseq, ack: cseq + 1, delay: rtt})
		add(event{fromCli: true, flags: 16, seq: cseq + 1, ack: sseq + 1, delay: rtt})
	}
	return c
}

func (g *generator) dnsConversation() *conversation {
	r := g.rng
	c := &conversation{cli: g.clients[r.Intn(len(g.clients))], srv: g.servers[r.Intn(8)], cport: uint16(1024 + r.Intn(60000)), sport: 53}
	id := uint16(r.Intn(65536))
	name := fmt.Sprintf("host%d.corp%d.example.com", r.Intn(5000), r.Intn(30))
	q := &layers.DNS{ID: id, RD: true, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	c.events = append(c.events, event{udp: true, fromCli: true, dns: q})
	switch x := r.Intn(100); {
	case x < 3: // no answer
	default:
		resp := &layers.DNS{ID: id, QR: true, RD: true, RA: true, Questions: q.Questions}
		switch {
		case x < 9:
			resp.ResponseCode = layers.DNSResponseCodeNXDomain
		case x < 10:
			resp.ResponseCode = layers.DNSResponseCodeServFail
		default:
			resp.Answers = []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.IP{93, 184, 216, byte(r.Intn(250))}}}
		}
		c.events = append(c.events, event{udp: true, dns: resp, delay: time.Duration(500+r.Intn(20000)) * time.Microsecond})
	}
	return c
}

func (g *generator) icmpConversation() *conversation {
	r := g.rng
	c := &conversation{cli: g.servers[r.Intn(len(g.servers))], srv: g.clients[r.Intn(len(g.clients))]}
	c.events = []event{{icmp: true}}
	return c
}

// gap is the time between two packets: 20 to 180 microseconds, or, if
// duration is set, 20% to 180% of the mean gap that spreads total packets over
// duration (conversation delays come on top, so the capture runs a little longer).
func gap(r *rand.Rand, duration time.Duration, total int) time.Duration {
	if duration <= 0 || total <= 0 {
		return time.Duration(20+r.Intn(160)) * time.Microsecond
	}
	mean := duration / time.Duration(total)
	return mean/5 + time.Duration(r.Int63n(int64(mean)*8/5+1))
}

func main() {
	packets := flag.Int("packets", 1_500_000, "number of packets to write")
	out := flag.String("out", "", "output pcap file (required)")
	seed := flag.Int64("seed", 1, "random seed")
	duration := flag.Duration("duration", 0, "spread the packets over about this long, for example 5m (default: about 100 microseconds apart)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "gencap: -out is required")
		os.Exit(2)
	}
	if err := run(*out, *packets, *seed, *duration); err != nil {
		fmt.Fprintln(os.Stderr, "gencap:", err)
		os.Exit(1)
	}
}

func run(path string, total int, seed int64, duration time.Duration) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	w := pcapgo.NewWriter(bw)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	g := newGenerator(seed)
	r := g.rng
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	var active []*conversation
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}

	spawn := func() *conversation {
		var c *conversation
		switch x := r.Intn(100); {
		case x < 18:
			c = g.dnsConversation()
		case x < 19:
			c = g.icmpConversation()
		default:
			c = g.tcpConversation()
		}
		c.nextAt = now
		return c
	}
	for len(active) < 3000 {
		active = append(active, spawn())
	}

	written := 0
	for written < total {
		// the conversation due next: pick among a few random ones the earliest
		i := r.Intn(len(active))
		for k := 0; k < 3; k++ {
			if j := r.Intn(len(active)); active[j].nextAt.Before(active[i].nextAt) {
				i = j
			}
		}
		c := active[i]
		e := c.events[c.next]
		if c.nextAt.After(now) {
			now = c.nextAt
		}
		now = now.Add(gap(r, duration, total))

		src, dst := c.cli, c.srv
		sp, dp := c.cport, c.sport
		if !e.fromCli {
			src, dst, sp, dp = dst, src, dp, sp
		}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: src, DstIP: dst}
		var serial []gopacket.SerializableLayer
		switch {
		case e.icmp:
			ip.Protocol = layers.IPProtocolICMPv4
			serial = []gopacket.SerializableLayer{eth, ip,
				&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, 0)},
				gopacket.Payload(append([]byte{0x45, 0, 0, 40, 0, 1, 0, 0, 1, 6, 0, 0, 10, 1, 1, 1, 100, 64, 1, 1}, make([]byte, 8)...))}
		case e.udp:
			ip.Protocol = layers.IPProtocolUDP
			udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				return err
			}
			serial = []gopacket.SerializableLayer{eth, ip, udp, e.dns}
		default:
			ip.Protocol = layers.IPProtocolTCP
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: e.seq, Ack: e.ack, Window: 29200,
				FIN: e.flags&1 != 0, SYN: e.flags&2 != 0, RST: e.flags&4 != 0, PSH: e.flags&8 != 0, ACK: e.flags&16 != 0,
			}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				return err
			}
			serial = []gopacket.SerializableLayer{eth, ip, tcp, gopacket.Payload(e.payload)}
		}
		if err := buf.Clear(); err != nil {
			return err
		}
		if err := gopacket.SerializeLayers(buf, opts, serial...); err != nil {
			return err
		}
		data := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: now, CaptureLength: len(data), Length: len(data)}, data); err != nil {
			return err
		}
		written++

		c.next++
		if c.next >= len(c.events) {
			active[i] = spawn()
		} else {
			c.nextAt = now.Add(c.events[c.next].delay)
		}
	}
	return bw.Flush()
}
