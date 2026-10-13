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

**DHCP (IPv4)**: DHCP messages are decoded on UDP ports 67 and 68 when they
carry the BOOTP header, the magic cookie and a DHCP Message Type option (53):
Discover, Offer, Request, Decline, Ack, Nak, Release and Inform, with the
transaction ID, the client hardware address (`chaddr`), the client, your and
server addresses (`ciaddr`, `yiaddr`, `siaddr`) and the options subnet mask (1),
router (3), DNS servers (6), lease time (51), Server Identifier (54) and message
(56, the reason of a NAK). DHCP appears as an application protocol in the
protocol distribution, and its flows carry `dhcp_message_types`,
`dhcp_client_mac` and `dhcp_server_ip` (a "DHCP FLOWS" table in the report;
traffic on the DHCP ports that is not a readable DHCP message is still labelled
DHCP by its port). Requests and answers are matched by transaction ID and client
hardware address, not by flow, since a client broadcasts and the server answers
from its own address. The server of a NAK is its Server Identifier, else the
address it came from.

| Issue | Meaning |
|---|---|
| `DHCP NAK` (warning) | A server refused a request with a NAK, with the reason it gave. One issue per server. |
| `Possible DHCP Address Exhaustion` (warning) | A server sent at least 3 NAKs. One issue per server. |
| `High DHCP Failure Rate` (warning) | More than 20% of the requests were NAK'd, out of at least 5 requests (a NAK whose request was not captured counts as one). One issue for the capture. |
| `DHCP Timeout` (warning) | A Discover that got no Offer within 10 seconds (or only a later one), one issue per destination address. A Discover is only called unanswered if the capture lasted 10 seconds beyond it. |

Frames in skipped link types (such as Ethernet mPackets) are not seen, so a
capture that carries DHCP in them shows less of it than Wireshark does.

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

**Bad Traffic / Good Traffic.** A summary bar ("Total: X packets · Y flows ·
Z issues · Health: N/100") sits above two tabs. **Bad Traffic** lists the issues
grouped by severity (errors first), each as a card with *What* is wrong, its
*Impact* (events and flows), the *Fix*, the Wireshark filter in a code block and
the buttons **Copy Filter**, **Show N packets** (copies `tshark -r capture.pcap
-Y '<filter>' | head -N`) and **View Details** (the affected flows and events).
**Good Traffic** lists the flows no issue names (`healthy_flows`) in a sortable
table (busiest first) with a search box, and a **master Wireshark filter**
(`good_traffic_filter`) that hides everything the issues point at, as
`!(<filter 1> || <filter 2> || …)`, with buttons to copy it or a tshark command
for it. The master filter drops the packets the issue filters match, which is
not always whole flows; issue filters that are not well formed are left out of
it. A capture with issues opens on Bad Traffic, a clean one on Good Traffic.

**Issues table.** Bad Traffic lists the issues as a table like the one of the
flows with issues: severity, title, number of events (×39), the addresses
involved (`10.0.0.145:54436 → 186.15.230.24:80`, or the first two and "+37 more"
for an aggregated issue) and the protocol, the worst first. Click a column to
sort, type in the search box to find an issue by title, address or description
("Showing X of Y issues"), and click a row (or press Enter on it) for the
details in a dialog: what is wrong, the impact, every affected address (click
one to filter the page to it), the fix, the Wireshark filter, and buttons to
copy the filter or a tshark command, to copy a command that lists the first N
matching packets, and to open the events of an aggregated issue.

**Long lists.** The issue table, the issue lists of the protocol pages, the Good
Traffic table and the events of an issue are virtual: only the rows in view
(plus a few more on each side) are in the page, so a capture with hundreds of
thousands of issues scrolls as smoothly as one with a few. Rows and cards may be any
height. A button at the corner takes
you back to the top once you have scrolled down. A list longer than 5,000 rows
shows the first 5,000, the worst first, with a button for 5,000 more (up to 50,000):
browsers cannot scroll a page taller than about 33 million pixels, and the filters
and the CSV export are the way to the rest. The list uses `@tanstack/react-virtual` (MIT).

**TCP stream timeline.** Below the issues, Bad Traffic lists the flows that have
issues (worst first); the flow tables there are clickable (**View Details**) and
open a dialog with the flow's TCP stream number (`tcp.stream`), packet count and
duration, buttons to copy its Wireshark filter (`tcp.stream eq N`) or a `tshark`
command, a **timeline** and the issue cards that are about this flow. The
timeline (`timeline` in the flow JSON of `/api/analyze`, TCP flows with issues
only) lists the connection start (SYN), the handshake, the first data, what went
wrong (timeout and fast retransmits, repeated SYNs, zero windows and their
reopening, RSTs) and how it ended (FIN), in time order, with the **first
problem** marked. Normal events are green, warnings yellow, errors red. A flow
with very many retransmissions lists the first ten and summarizes the rest. A
flow whose packets show no problem of their own (for example a slow response)
shows the issues that name it instead.

**Pages.** The upload page is at `/`. When the analysis is ready the page
moves to `/analysis/<id>` (which opens `/analysis/<id>/bad` or `/good`, see
above), and beneath Bad Traffic a navigation bar offers one page
per protocol with its number of issues: TCP, UDP, DNS, HTTP, TLS, SIP, DHCPv6
and QUIC (`/analysis/<id>/tcp`, `/udp`, `/dns`, `/http`, `/tls`, `/sip`,
`/dhcpv6`, `/quic`). A protocol page lists every issue that involves the
protocol (TCP's includes those of HTTP and TLS, UDP's those of DNS, SIP, DHCP, DHCPv6
and QUIC), worst first, each with its description, the flows and names it
affects (click a flow to filter the page to it), what to do about it, and a
Wireshark display filter. Severity checkboxes, a search box and the IP and port
filters narrow a page; the filters follow you from tab to tab, and every page can
be reloaded or shared by its address. The server serves the page for these paths
and the page fetches the analysis by its ID.

**Wireshark filters.** Every issue carries a display filter (`wireshark_filter`
in the JSON) that shows the packets it is about, and a `recommendation`. Paste the
filter into Wireshark's filter bar with the capture open, or use **Copy
Wireshark command** (`wireshark -r capture.pcap -Y '<filter>'`) or **Copy tshark
command**; Wireshark has no link that opens a capture with a filter, so there is
no "open" button. Examples:

| Issue | Filter |
|---|---|
| TCP Retransmissions, Timeout Retransmit | `tcp.stream eq 7 && tcp.analysis.retransmission` |
| TCP Zero Window | `tcp.stream eq 7 && tcp.analysis.zero_window` |
| Connection reset after zero-window stall | `tcp.stream eq 0 && (tcp.analysis.zero_window \|\| tcp.flags.reset == 1)` |
| Connection Abruptly Closed, Refused | `tcp.stream eq 7 && tcp.flags.reset == 1` |
| Slow TCP Handshake | `tcp.stream eq 7 && tcp.analysis.initial_rtt` |
| Possible SYN Flood | `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 10.0.0.2 && tcp.dstport == 80` |
| DNS NXDOMAIN, SERVFAIL | `dns.flags.rcode == 3 && (dns.qry.name == "a.example" \|\| dns.qry.name == "b.example")` |
| DNS Timeout | `dns.flags.response == 0 && !dns.response_in && dns.qry.name == "a.example"` |
| HTTP errors | `tcp.stream eq 7 && http.response.code == 404` |
| SIP Registration / Call Setup Failed | `sip.CSeq.method == "REGISTER" && sip.Status-Code == 403` |
| DHCP NAK | `dhcp.option.dhcp == 6 && dhcp.option.dhcp_server_id == 192.168.0.1` |
| DHCPv6 No Addresses Available | `(dhcpv6.msgtype == 2 \|\| dhcpv6.msgtype == 7) && dhcpv6.status_code == 2` |
| QUIC Handshake Timeout | `quic.long.packet_type == 0 && ip.dst == 192.0.2.10 && udp.dstport == 443` |

An aggregated issue's filter matches all its occurrences (every flow, domain or
status code, up to 20; beyond that it falls back to the whole kind of packet,
for example every NXDOMAIN answer from the resolver). Names from the capture are
quoted and escaped. `tcp.stream` is Wireshark's own index of the TCP
conversation, numbered in order of first appearance, with a new one when a SYN
follows a FIN or RST or arrives with a different sequence number, and
with a conversation of its own for the TCP header that an ICMP error quotes in
full (the tool reproduces this and was checked against `tshark` on the test
captures: every TCP flow of the captures it can number has the same stream
index as in Wireshark). It can only
be worked out when every frame that may carry TCP was decoded, so when frames
were skipped that Wireshark might decode (an unsupported link type such as
Ethernet mPackets, PPPoE or MPLS) or TCP segments were IP-fragmented, the
filters name the flow by addresses and ports instead, which is always right
(a reused port pair then shows both connections). A few filters differ from the
obvious one because Wireshark's fields behave differently: SIP uses
`sip.CSeq.method`, which both requests and responses carry (`sip.Method` is a
request-only field, so combined with a status code it would match nothing); an
HTTP slow response filters to the request and response of the stream rather than
on `http.time`, which Wireshark leaves empty on some responses; DHCPv6's status
field is `dhcpv6.status_code`, and a DHCPv6 timeout shows the Solicits and
Requests sent to the server, because Wireshark cannot filter for a packet that
has no reply.

**Filtering.** Under the headline numbers, the **Filters** panel narrows the
issues, flows and protocol distribution to what you are looking at:

- **Source IP** and **Destination IP** (IPv4 or IPv6, validated; any spelling of
  an IPv6 address works). Flows are bidirectional, so an IP matches either end
  of a flow, and with both set the two ends of one flow.
- **Port**: ports and ranges separated by commas, such as `80,443,8000-9000`;
  it matches either port of a flow.
- **Protocol**: any detected protocol, transport or application (TCP, DNS, QUIC,
  SIP, ...).
- **Severity** (ERROR, WARNING, INFO, and CRITICAL when the capture has any) and
  **Category** (Connection, DNS, PacketLoss, ... as found in the capture).

Nothing changes until you press **Apply Filters** (or Enter); **Reset** clears
everything. The **Quick filters** (All Errors, DNS Issues, Connection Issues,
Packet Loss) and a click on a **top talker** (the busiest addresses by bytes), a
protocol badge or a tag's x apply at once. Applied filters show as removable
tags, and counters read "Showing X of Y issues" and "Showing X of Y flows". The
health score and the root cause always describe the whole capture. An issue is
tied to addresses and ports through its flow, target and event subjects, so an
issue that names no address (a slow HTTP response known only by its domain) is
hidden while an IP or port filter is on. The filters are kept in the address
bar (`?source_ip=...&port=...&severity=ERROR,WARNING&category=DNS&protocol=TCP`),
together with the ID of the analysis, which the server keeps in memory (the last
8, for 2 hours): a refresh or a copied link shows the same view again, unless the
server has restarted or the analysis has expired, in which case the page says so
and keeps the filters.

**Export Filtered** downloads the flows, issues and protocol distribution that
pass the filters as CSV files in one zip, with the same tables as the CLI's
`--export-csv`. Over HTTP:

```bash
# the answer of /api/analyze carries "analysis_id"
curl -H "Authorization: Bearer $TOKEN" -o filtered.zip \
  "http://localhost:8181/api/export-csv?analysis=$ID&source_ip=10.0.0.1&port=80,443&severity=ERROR,WARNING"
# one table instead of the zip: add &file=flows, &file=issues or &file=protocols
curl -H "Authorization: Bearer $TOKEN" http://localhost:8181/api/analysis/$ID   # the analysis again
```

`GET /api/export-csv` takes `analysis` (required) and the optional filters
`source_ip`, `dest_ip`, `port`, `protocol`, `severity` and `category` (lists
separated by commas); a malformed filter is a 400, an analysis the server no
longer holds a 404. Without filters it exports everything, capture notes
included, like the CLI; with filters the capture notes are left out, and the
protocol table is worked out from the flows that are left. The web answer to
`POST /api/analyze` also lists every flow (`flows`, each TCP flow with its Wireshark `tcp_stream` when it can be worked out), which the page filters
itself; the CLI's JSON does not.

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
`POST /api/analyze`, `POST /api/change-password`, `GET /api/analysis/{id}` and
`GET /api/export-csv` need it in an `Authorization: Bearer` header, and answer 401 without one. `POST /api/analyze`
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

### Keyboard shortcuts, loading and notifications

| Key | What it does |
|---|---|
| `Ctrl+K` / `Cmd+K` | Command palette: search the issues of the open analysis, jump to a page, switch theme |
| `1` – `8` | Jump to the TCP, UDP, DNS, HTTP, TLS, SIP, DHCPv6 or QUIC tab (`0`: Bad Traffic, `9`: Good Traffic) |
| `Esc` | Close a dialog; otherwise clear the filters |
| `?` | List the shortcuts |

Number keys and `?` are ignored while you type in a field. While a capture uploads, the page shows the bytes sent and
the upload speed, then the four steps of the analysis (reading packets, classifying flows, detecting issues, generating
the report) as the server reaches them, with skeleton placeholders where the results will appear. Copying a filter,
exporting and an expired session show a toast in the bottom-right corner for three seconds. Animations (tab fades, the
health score counting up, expanding details) are off for people whose system asks for reduced motion.

`POST /api/analyze?progress=1` answers with JSON lines instead of one document: `{"stage":"reading"}`, then one line
for each later stage (`classifying`, `detecting`, `reporting`), then `{"result": {...}}` (the same document as without
the parameter), or `{"error": "...", "status": 400}` when the capture cannot be read.

**Chunked loading.** A large analysis is a large document (a capture of 1.5 million
packets has 170,000 issues and 115,000 flows), so the page does not wait for all of it.
`POST /api/analyze?progress=1&chunked=1` ends with `{"analysis_id": "..."}` in place of the
result, and `GET /api/analysis/{id}?chunked=1` then streams the stored analysis as JSON
lines, flushed one by one: `{"chunk":"summary","data":{...}}` (the diagnosis, the totals, the
Good Traffic filter and `counts` of what follows, without the per-issue diagnosis timeline),
`{"chunk":"overview",...}` (protocol mix, top talkers, slowest flows), `{"chunk":"issues","offset":N,"data":[...]}`
in batches of 100, worst severity first, `{"chunk":"flows",...}` in batches of 500, and `{"chunk":"done"}`.
The page shows the health score and root cause as soon as the first chunk is in, the
tab counts from `counts`, issue rows as batches arrive (a progress bar says "Loading issues: 400 / 1,600"),
and skeletons for the flow tables and Good Traffic until all flows are there. Without `chunked=1` both
endpoints answer as before.

`npm test` (in `web/`) runs the UI's unit tests, and `npm run check:spacing` checks that padding, margin and gap
utilities stay on the 4/8/12/16/24/32 px scale.

### Developing the UI

Run the server (`./netforensic --web :8181`) and, in `web/`, `npm run dev`. The
Vite dev server proxies `/api` to `localhost:8181`. After changing the UI, run
`npm run build` and rebuild the Go binary to embed the new files.

## Performance on large captures

`cmd/gencap` writes a deterministic synthetic capture of any size (see its README);
`go run ./cmd/gencap -packets 1500000 -duration 5m -out big.pcap` makes 1.5 million packets over five
minutes: 115,000 flows, 171,000 issues, 307 MB. `NETFORENSIC_PERF_PACKETS=1500000 go test -run
TestLargeCaptureStreamsProgressively -v ./internal/server` uploads it and checks that the analysis streams
to the page in chunks (the test is skipped with `-short` and defaults to 100,000 packets).

Measured on an Apple M-series laptop, the web UI in headless Chrome:

| | before | after |
|---|---|---|
| Analysis done, result starts to flow | 48 s | 36 s |
| Health score and root cause on screen | 82 s | 36.7 s |
| All issues and flows loaded | 82 s | 38.6 s |
| Longest block of the page's main thread | 11.5 s | 0.6 s |
| Blocked main-thread time in all | 32 s (123 blocks) | 1.2 s (4 blocks) |
| Server peak memory (RSS) | 2.6 GB | 2.25 GB |
| CLI run (read, analyze, report) | 42.8 s | 31.5 s |
| Analysis kept in memory | 443 MB | 284 MB |
| Page heap after loading | 383 MB | 381 MB |

"Before" is the code of commit `1d4b9c9`. The server takes 30 s of that for the analysis
itself (a million and a half packets are decoded and 171,000 issues found), which streaming does not shorten;
what it removes is the half minute that followed, when the page received, parsed and grouped one document of
170 MB. The memory the analysis needs is dominated by the packets themselves, about 1 KB each
(`models.PacketInfo`); see the comment on `analyzer.AnalyzeWithProgress` for where the rest went.

## Known limitations

- **Tunnels.** GRE, IP-in-IP and IPv6-in-IPv4 (6in4) tunnels are decapsulated:
  a tunnelled packet is analyzed by its inner addresses and ports, and a
  "Decapsulated Tunnels" note says how many packets were treated that way
  (it costs no health points; in JSON output it is an INFO entry in `issues`).
  Flows from different tunnels stay separate; the ID of a tunnelled flow ends
  with the tunnel, for example
  `10.0.0.1:1000-10.0.0.2:80@GRE:192.0.2.1~192.0.2.2`, and `--follow` takes the
  same form (the `@...` suffix may be left out). Only the outermost tunnel is
  recorded for nested tunnels. Tunnels the tool cannot look into stay opaque: encrypted ones (ESP, AH), L2TP, and
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
- **Truncated files** are analyzed up to the cut and flagged with a warning
  (the exit status stays 0); a file cut inside its first header cannot be read
  at all and ends with an error and exit status 1.
- **Health score.** It starts at 100 and drops with every issue. It goes below 0
  for badly troubled captures and stops at -50 (CATASTROPHIC). In JSON output
  it is `diagnosis.health_score`.
- **Capture durations** over 24 hours are shown as "24h+", since they usually
  mean that interfaces with unsynchronized clocks were merged into one file.
