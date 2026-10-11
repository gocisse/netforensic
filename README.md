# netforensic

A single-binary Go forensic tool that analyzes `.pcap` and `.pcapng` captures
and provides actionable network diagnostics. It reads a capture, follows every
flow, and tells you what went wrong and why: retransmissions (fast or timeout),
connection resets and refusals, zero-window stalls, unanswered SYNs and SYN
floods, DNS failures, ICMP errors, slow handshakes and server responses. It
ends with a health score, a root-cause summary, a timeline and recommendations.

It runs in two modes from the same binary:

- **CLI mode:** `netforensic [flags] capture.pcap` prints a triage report.
- **Web UI mode:** `netforensic --web :8181` serves an embedded web page where
  you upload a capture and see the same analysis in your browser.

## Prerequisites

- **Go 1.22 or newer** to build the binary.
- **Node.js and npm** (Node 20+ recommended) to build the web UI that is
  embedded into the binary. Not needed to run the CLI from a binary that was
  already built with the UI.
- `tshark` is *not* required; it is only useful for cross-checking results.

## Installation

```bash
git clone https://github.com/gocisse/netforensic.git
cd netforensic
go mod tidy

# build the web UI (it is embedded into the Go binary)
cd web
npm install
npm run build
cd ..

go build -o netforensic ./cmd/netforensic
```

The result is a single self-contained `netforensic` executable. If you skip the
`npm` steps the binary still builds and the CLI works; the web server then
answers `503` at `/` with a reminder to build the UI, while `/api/analyze`
keeps working.

Run the tests with `go test ./...`.

## Usage: CLI mode

```bash
./netforensic capture.pcapng                 # triage report
./netforensic -o json capture.pcapng         # the same analysis as JSON
```

The triage report shows the health score, the root cause, a timeline, the
slowest flows, recommendations and a compact count of issues by kind. The JSON
output holds every issue in full, including the individual events behind
aggregated issues (`occurrences`).

For pcapng files, the header of the report also shows what the file says about
its creation: the capturing application and operating system, the hardware and
the interfaces (name, link type, snap length, timestamp resolution), for
example:

```
 TRIAGE REPORT  |  Health Score: 80/100 (DEGRADED)
========================================================================
 Captured with: Dumpcap (Wireshark) 3.4.9 on Linux 5.10.0-kali3-amd64
 Hardware:      Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (with SSE4.2)
 Interfaces:    eth0 (Ethernet, snaplen 262144, nanosecond timestamps)
```

Interfaces with identical settings are listed once, and at most three are
shown (a merged capture can hold hundreds; the rest are counted). The JSON
output, the web UI's API answer and the report all carry the same information
under `metadata` (`capture_tool`, `os`, `hardware`, `interfaces`); classic pcap
files have none, and fields the file leaves out are omitted. The text comes
from the file, so control characters are replaced and long values are cut.

**SIP (VoIP)**: SIP over UDP or TCP is recognized by its content (a request
line such as `INVITE sip:bob@example.com SIP/2.0`, or a `SIP/2.0 200 OK` status
line, on any port) and by the well-known ports 5060 and 5061, and appears as an
application protocol next to DNS, HTTP and TLS in the protocol distribution
(a TLS handshake on 5061 is still TLS). Requests are matched to their responses
by Call-ID and CSeq, and the report points out:

| Issue | Meaning |
|---|---|
| `SIP Registration Failed` (warning) | `REGISTER` requests that got a 4xx, 5xx or 6xx response, one issue per User-Agent (or per client address if it sends none), with the status codes received. |
| `SIP Call Setup Failed` (warning) | `INVITE` requests that got an error response, one issue per server, naming the Call-ID of a single failure. |
| `High SIP Error Rate` (warning) | A flow on which more than 10% of the answered requests failed (at least 10 requests), folded into one issue. |

401 and 407 are the ordinary authentication challenge and are not counted as
failures (a failure after the retry is), nor is 487 after the caller cancelled,
nor are 3xx redirects. Retransmitted requests count once, `ACK` is ignored, and
a request with no response in the capture is not counted. A SIP flow carries
its request methods, first Call-ID and User-Agent (`sip_method`, `sip_call_id`,
`sip_user_agent` in the JSON; a "SIP FLOWS" table in the report). Only the first
message of a packet is read, and a message that IP fragmentation split across
packets (a large INVITE with SDP can exceed the MTU) is not reassembled, so
that request is not seen.

**DHCPv6**: DHCPv6 messages (UDP ports 546 and 547, or any port if the
payload is a well-formed message with a Client Identifier) are decoded:
message type, transaction ID, client and server identifiers, the identity
associations asked for (IA_NA, IA_TA, IA_PD), the Elapsed Time and any Status
Code, including one inside an IA option, where servers usually put it. Relayed
messages (Relay-forward, Relay-reply) are unwrapped to the message inside. DHCPv6
appears as an application protocol in the protocol distribution, and its flows
carry `dhcpv6_message_types`, `dhcpv6_client_id` and `dhcpv6_server_id` (a
"DHCPV6 FLOWS" table in the report). Requests and answers are matched by
transaction ID and client identifier, not by flow, since a client sends to a
multicast address and the server answers from its own.

| Issue | Meaning |
|---|---|
| `DHCPv6 No Addresses Available` (warning) | A server answered with `NoAddrsAvail` (2), `NoBinding` (3) or `NoPrefixAvail` (6). One issue per server. |
| `DHCPv6 Configuration Error` (warning) | `NotOnLink` (4), `UseMulticast` (5), `NotConfigured` (9) or `NotAllowed` (10). One issue per server. |
| `High DHCPv6 Failure Rate` (warning) | Servers whose responses (Advertise and Reply) carried an error status more than 20% of the time, out of at least 10 responses; any status except Success and `CatchUpComplete` counts, `UnspecFail` included. |
| `DHCPv6 Timeout` (warning) | A Solicit or Request that got no Advertise or Reply within 30 seconds (or only a later one), one issue per destination address. |

The status code numbers are those of RFC 8415. A request is only called
unanswered if the capture session it is in lasted 30 seconds beyond it; a
silence of more than an hour, or time running backwards, ends a session, so a
merged capture does not make every request look unanswered. Retransmitted
requests (same transaction ID) count once. Other messages (Renew, Rebind,
Confirm, ...) are not checked for timeouts.

**QUIC**: QUIC is encrypted (TLS 1.3 runs inside it), so its payloads cannot
be decoded, but its long headers are readable and the tool identifies QUIC
connections by them: the header form bit set and, except in Version Negotiation,
the fixed bit (RFC 9000, section 17.2), on UDP port 443 with any version, or on
another port (such as 853 for DNS over QUIC) with a known one. QUIC appears as
an application protocol in the protocol distribution, and its flows carry
`quic_version` (`QUIC v1`, `QUIC v2`, `draft-29`, `reserved`, `unknown`) and
`quic_packet_types` (Initial, 0-RTT, Handshake, Retry, Version Negotiation; a
"QUIC FLOWS" table in the report). Datagrams that coalesce several packets list
all of them.

| Issue | Meaning |
|---|---|
| `QUIC Version Negotiation` (info) | A server answered with a list of versions: the one the client asked for, matched by the connection IDs the packet echoes, and what the server offered. One issue per server. |
| `QUIC Retry` (info) | A server asked a client to prove its address with a Retry packet. One issue per server. |
| `QUIC Handshake Timeout` (warning) | A client Initial that got no packet at all from the server within 10 seconds (or only a later one). A Version Negotiation or Retry counts as an answer. One issue per server. |
| `QUIC Draft Version` (info) | A client using a draft version (`0xff0000XX`), one issue per draft. |

A Version Negotiation packet has no fixed bit and a version field of just zero,
so it is only accepted on port 443 and only if it offers at least one known
version (a real server always offers v1 or a draft); without that, RTP and
other protocols that start with a high bit would be mistaken for it.

Limits: only long headers are recognized. Short-header packets carry no
version or connection ID and cannot be told from other UDP traffic without
connection state, so a flow is QUIC if any of its packets has a long header
(its short-header packets then count with it), and a capture that only has
the tail of a connection is not recognized. Since the payload is encrypted,
nothing inside it (HTTP/3 requests, TLS alerts, transport errors, later
packet loss) is visible, and a handshake that fails after the first answer
cannot be told from one that succeeds. The client of a flow is the sender of
its first Initial (the side that uses port 443 is the server when that is
ambiguous), and a flow is one UDP 4-tuple, so a connection that migrates to
another address is two flows. An Initial is called unanswered only if the
capture session lasted 10 seconds beyond it. QUIC's v2 packet type numbers
(RFC 9369) differ from v1's and are handled. Google's older QUIC and
vendor-specific versions are shown as `unknown` (on port 443) or not
recognized.

**Verbose packet table** (`-v`): print every packet that is analyzed before the
summary.

```bash
./netforensic -v capture.pcap
```

**Service filter** (`-s`): analyze only one service. Accepted values are `all`
(default), `dns`, `http` (port 80), `tls` or `https` (port 443), or any port
number. The filter applies to the analysis and to `-v` alike.

```bash
./netforensic -s dns capture.pcap
./netforensic -v -s 443 capture.pcap
./netforensic -s 8080 capture.pcap
```

**IP and port filters:** `--src-ip`, `--dst-ip`, `--src-port` and `--dst-port`
combine with each other and with `-s`.

```bash
./netforensic --src-ip 10.0.0.145 capture.pcap
./netforensic --dst-ip 8.8.8.8 --dst-port 53 capture.pcap
```

If nothing matches the filters, the tool says "No packets matched the specified
filters. Nothing to analyze." instead of printing a health score.

**CSV export** (`--export-csv <prefix>`): also write the analysis as CSV files
for Excel, pandas or other tools. The report on stdout is unchanged, so it
combines with `-o json`, `-s` and the filters.

```bash
./netforensic --export-csv report capture.pcapng
# writes report_flows.csv, report_issues.csv and report_protocols.csv

./netforensic -s dns --export-csv out/dns capture.pcap   # the directory must exist
```

| File | Columns |
|---|---|
| `<prefix>_flows.csv` | `flow_id, packets, bytes, setup_time_ms, ttfb_ms, avg_rtt_ms, max_rtt_ms, protocol, issues` |
| `<prefix>_issues.csv` | `id, severity, category, title, description, flow_id, target, count, timestamp` |
| `<prefix>_protocols.csv` | `protocol, layer, packets, flows, percent` |

The flows file lists *every* flow (the JSON output lists only the top ones),
busiest first; `bytes` is both directions together, `issues` is the number of
issues that involve the flow, and a timing that could not be measured is left
empty. Timestamps are UTC (RFC 3339). Files are UTF-8, with commas, quotes and
newlines in fields escaped as CSV requires. A text field that starts with
`=`, `+`, `-` or `@` gets a leading apostrophe so that a spreadsheet does not
run it as a formula. Existing files are overwritten. `--export-csv` needs a
prefix and cannot be combined with `--follow`, `--follow-packets` or `--web`;
when there is nothing to analyze, no files are written.

**Follow a flow** (`--follow`): reconstruct the application-layer conversation
of one flow, much like Wireshark's "Follow TCP Stream": HTTP requests and
responses and DNS queries as text, binary data summarized by size, retransmitted
segments left out. Flow IDs look like `ip:port-ip:port`, with IPv6 addresses in
brackets (`[2001:db8::1]:443-[2001:db8::2]:50000`); add `/udp` or `/tcp` to pick
a protocol, and `#2` for the second connection when a port was reused. A wrong
or unknown ID lists the flows that exist.

```bash
./netforensic --follow "10.0.0.145:54436-186.15.230.24:80" capture.pcapng
```

`--follow-packets` shows the same flow packet by packet instead, with flags,
sequence numbers, payload dumps and a `[RETRANS]` mark on retransmitted
segments:

```bash
./netforensic --follow-packets "10.0.0.145:54436-186.15.230.24:80" capture.pcapng
```

## Usage: Web UI mode

```bash
./netforensic --web :8181
```

This prints `Web UI available at http://localhost:8181` and keeps running until
you press Ctrl-C. Open that address in a browser and sign in. On a fresh
installation the login is `admin` / `admin`, and the page makes you choose a new
password before anything else; the user menu (top right) has **Change Password**
and **Logout**. Then choose or drop a `.pcap` or `.pcapng` file and press
**Analyze**. The page shows the health score (green
from 80, yellow from 40, red below that), the primary cause and confidence, the
top issues, and the recommendations. Truncated captures and skipped frames are
called out in notices, and a capture with nothing to analyze says so instead of
showing a score.

At the top of the results, **Protocol distribution** shows the traffic
composition: a bar and badges for TCP, UDP, ICMP and ARP, which add up to all
packets, and for the application protocols recognized inside the flows (DNS,
HTTP, TLS). Application protocols are detected from content (a DNS message, an
HTTP header, a TLS handshake), so a flow whose handshake or header was not
captured counts only as TCP or UDP. The **Protocol filter** (or a click on a
badge) limits the issue list and the flow tables to one protocol, and every
issue's details table shows the protocol of each event. The same data is in the
JSON as `protocol_stats`, with `protocols` on issues and `protocol` on their
occurrences.

`--web` takes an address such as `:8181` or `127.0.0.1:8181`, cannot be
combined with a capture file or with the analysis flags, and refuses to start if
the port is taken. Pick a port that is free on your machine.

The same analysis is available over HTTP, behind a login. A fresh installation
has the user `admin` with the password `admin`; change it right away. The
server prints a warning while the default password is in use.

```bash
TOKEN=$(curl -s -X POST http://localhost:8181/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r .token)

curl -X POST http://localhost:8181/api/change-password \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"old_password":"admin","new_password":"something-longer"}'
# the answer holds a fresh token: the change ends every older session

curl -F "file=@capture.pcapng" -H "Authorization: Bearer $TOKEN" http://localhost:8181/api/analyze
```

`POST /api/login` returns a signed JWT that is valid for 24 hours;
`POST /api/analyze` and `POST /api/change-password` need it in an
`Authorization: Bearer` header, and answer 401 without one. `POST /api/analyze`
takes a multipart upload in the field `file` (`.pcap` or `.pcapng`, up to
512 MiB) and answers with the JSON of `-o json`; errors come back as
`{"error": "..."}` with status 400, 401, 413 or 500. New passwords need 6 to 72
characters. Signing out is the client discarding its token (`/api/logout`
exists for symmetry and revokes nothing).

The password hash and the secret that signs the tokens are kept in
`~/.netforensic-credentials.json` (mode 0600; created on first start; pick
another place with `--credentials`). Delete the file to go back to the default
login. The server listens on all interfaces for an address like `:8181`; use
`127.0.0.1:8181` to keep it on your machine.

Uploads are kept in a private temporary file that is deleted as soon as the
analysis is done.

### Developing the UI

Run the server (`./netforensic --web :8181`) and, in `web/`, `npm run dev`. The
Vite dev server proxies `/api` to `localhost:8181`. After changing the UI, run
`npm run build` and rebuild the Go binary to embed the new files.

## Known limitations

- **Tunnels.** GRE, IP-in-IP and IPv6-in-IPv4 (6in4) tunnels are decapsulated:
  a tunnelled packet is analyzed by its inner addresses and ports, and a
  "Decapsulated Tunnels" note says how many packets were treated that way
  (it costs no health points). Flows from different tunnels stay separate; the
  ID of a tunnelled flow ends with the tunnel, for example
  `10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2`, and `--follow` takes the
  same form. Only the outermost tunnel is recorded for nested tunnels. Tunnels
  the tool cannot look into stay opaque: encrypted ones (ESP, AH), L2TP, and
  UDP-based ones (VXLAN, Teredo, ...) are analyzed as the outer flow they
  appear as. HTTP, TLS and DNS matching still pairs requests and responses by
  addresses and ports alone, so two tunnels carrying an identical inner
  4-tuple could be paired with each other.
  IP packets with protocols the tool does not decode are not analyzed for
  issues. Well-known ones (OSPF, VRRP, PIM, IGMP, SCTP, ESP, GRE, ...) are
  listed under their own name in the protocol distribution; any other IP
  protocol is counted as "Other".
- **One-sided (asymmetric) captures.** A capture point that sees only one
  direction of a conversation (asymmetric routing, a SPAN port on one link)
  cannot show replies. Such SYNs are reported as "Unanswered SYN (No reply
  captured ...)" without claiming a cause, and other findings that depend on
  both directions may be missing.

  When many unanswered SYNs target the same destination (a SYN flood pattern),
  the tool reports them as a separate "Possible SYN Flood" issue instead. That
  issue does not include the asymmetric-capture caveat, but the same
  explanation can apply: on a one-sided capture, many SYNs with no captured
  reply can simply mean that the replies took another path
  (`cisco-example-lan.pcap` is such a capture, and is flagged this way).

  To help judge that, both issues carry statistical evidence when the capture
  looks one-sided: if more than 40% of its other TCP flows (at least 10; the
  connections with unanswered SYNs are left out) are seen in one direction
  only, the description ends with "Note: X% of the other TCP flows in this
  capture are seen in one direction only, so missing replies may simply have
  taken another path." It is a hint, not a verdict: the tool still cannot know
  what happened on the missing path.
- **Unsupported frames.** Frames with a link-layer type this tool cannot decode
  (for example Ethernet mPackets) and non-IP traffic (spanning tree, LLDP, ...)
  are skipped. A "Skipped Frames" note says how many, names the link type
  (for example "link type 274 (Ethernet mPacket)") and breaks the non-IP
  frames down by what they carry, for example "2997 non-IP frames: 2373 STP,
  169 Loopback, 455 Other" (the three most common kinds; the rest is counted
  as "Other"). It costs no health points.
- **Truncated files** are analyzed up to the cut and flagged; a file cut inside
  its first header cannot be read at all.
- **Health score.** It starts at 100 and drops with every issue. It goes below 0
  for badly troubled captures and stops at -50 (CATASTROPHIC).
- **Capture durations** over 24 hours are shown as "24h+", since they usually
  mean that interfaces with unsynchronized clocks were merged into one file.
