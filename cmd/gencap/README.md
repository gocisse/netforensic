# gencap

A development tool that writes a large, deterministic synthetic capture for
load-testing netforensic. It is not part of the `netforensic` binary.

## Usage

```bash
go run ./cmd/gencap -packets 1500000 -out /tmp/big.pcap
./netforensic /tmp/big.pcap
```

| Flag | Default | Meaning |
|---|---|---|
| `-out` | (required) | classic pcap file to write (Ethernet, microsecond timestamps) |
| `-packets` | `1500000` | number of packets to write |
| `-seed` | `1` | random seed; the same seed and size give a byte-identical file |

## What it generates

About 3000 conversations are kept in flight and their packets interleaved, the
way real traffic is. Roughly 80% are TCP, 18% DNS and 1% ICMP errors; the rest
is spread out over those:

- **TCP:** handshakes, 1 to 6 request/response rounds (HTTP on ports 80 and
  8080, opaque payloads on 443, 22, 445, 3389 and 5432), normal FIN closes,
  resets, connections that are never closed, refused connections (RST to a
  SYN), SYNs nobody answers, occasional retransmissions after about 220 ms, and
  a slow path (150 to 550 ms round trips) for about 1 in 40 flows.
- **HTTP:** about 3% 404 and 1% 500 responses.
- **DNS:** 6% NXDOMAIN, 1% SERVFAIL and 3% unanswered queries.
- **ICMP:** time-exceeded errors.

It uses 20,000 client and 600 server addresses, so a 1.5 million packet file
holds tens of thousands of flows and a few thousand issues (about 300 MB on
disk).
