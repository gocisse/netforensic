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
- **Unsupported frames.** Frames with a link-layer type this tool cannot decode
  (for example Ethernet mPackets) and non-IP traffic (spanning tree, LLDP, ...)
  are skipped. A "Skipped Frames" note says how many, and names the link type
  (for example "link type 274 (Ethernet mPacket)"); it costs no health points.
- **Truncated files** are analyzed up to the cut and flagged; a file cut inside
  its first header cannot be read at all.
- **Health score.** It starts at 100 and drops with every issue. It goes below 0
  for badly troubled captures and stops at -50 (CATASTROPHIC).
- **Capture durations** over 24 hours are shown as "24h+", since they usually
  mean that interfaces with unsynchronized clocks were merged into one file.
