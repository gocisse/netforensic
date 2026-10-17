# netforensic v0.1.0 — Architectural Review

*Principal-level review of the Go backend and React frontend, with a v0.2.0 roadmap. Figures below were measured from the repository (`go test -cover ./...`, `git ls-files`, README benchmark tables), not taken from marketing copy.*

---

## 1. Executive Summary

**netforensic** is a single-binary forensic analyzer for packet captures (`.pcap` / `.pcapng`). It answers the question an engineer asks at 3 a.m. — *"what is wrong in this capture, and where do I look?"* — by turning raw packets into a health score, a ranked list of issues with plain-language causes and fixes, and Wireshark display filters to verify each claim.

It runs in two modes from the same executable:

- **CLI** — `netforensic [flags] file.pcap`, with text/JSON output, CSV export, filters, triage and TCP stream following.
- **Web UI** — `netforensic --web :8181` serves an embedded React dashboard (JWT-authenticated) with upload, streamed results, a Good/Bad traffic split, per-protocol pages and a network topology diagram.

| Dimension | Snapshot |
|---|---|
| Version / maturity | v0.1.0 — feature-rich, unusually well tested for its age, not yet operationalized (no CI, no packaging beyond zip releases) |
| Size | ~13.1k lines Go (non-test), ~14.3k lines Go tests, ~8.9k lines TS/TSX; 74 commits |
| Coverage (measured) | analyzer 97.8%, pcap 96.1%, export 95.1%, cmd 95.0%, filter 97.7%, server 93.7%, models 91.6%, auth 90.5% |
| Dependencies | gopacket (`pcapgo`, pure Go, no cgo), cobra, testify, golang-jwt, x/crypto; React 19, react-router 7, @tanstack/react-virtual, Tailwind 3, Vite |
| Audience | Network engineers and SREs doing post-incident capture triage; junior on-call staff benefit from the guidance text |

**Verdict:** a credible, focused tool whose engineering discipline is ahead of its version number. The main gaps are not correctness but *operational*: memory per packet, CI, and getting evidence *out* of the tool (extracting packets back to a pcap).

---

## 2. Annotated Project Tree

```
netforensic/
├── cmd/
│   ├── netforensic/            # CLI entry point (cobra); formatting lives here, not in internal/
│   │   ├── main.go             #   flags, mode dispatch (CLI vs --web)
│   │   ├── output.go           #   text/JSON rendering of analysis results
│   │   ├── export.go           #   CSV export (flows, issues, protocols)
│   │   ├── filter.go           #   CLI filter flag parsing -> internal/filter
│   │   ├── follow.go           #   --follow: per-flow packet/stream view
│   │   └── triage.go           #   quick-triage summary
│   └── gencap/                 # dev-only synthetic pcap generator (deterministic, seeded)
│                               #   used for the 1.5M-packet load test; not in the shipped binary
├── internal/
│   ├── models/                 # shared types: PacketInfo, Flow, Issue, Analysis result
│   ├── pcap/                   # reading + decoding layer (pcapgo, pure Go)
│   │   ├── reader.go           #   pcap/pcapng readers, truncation detection, link types
│   │   ├── ngtrack.go          #   pcapng interface/metadata tracking
│   │   ├── handshake.go        #   TCP handshake extraction
│   │   ├── appproto.go         #   HTTP/TLS/DNS payload decoding
│   │   └── dhcp.go dhcpv6.go sip.go quic.go   # per-protocol decoders
│   ├── analyzer/               # PURE analysis: no files, CLI or HTTP
│   │   ├── analyzer.go         #   orchestrator, AnalyzeWithProgress
│   │   ├── tcp_issues.go syn_issues.go retransmit.go reassembly.go
│   │   ├── dns.go http.go tls.go sip.go dhcp.go dhcpv6.go quic.go arp.go icmp.go
│   │   ├── correlator.go       #   root-cause correlation across findings
│   │   ├── flowstatus.go flowtimeline.go goodtraffic.go   # Good/Bad split + stream timeline data
│   │   ├── topology.go         #   node/edge graph for the diagram
│   │   ├── guidance.go recommendations.go                 # plain-language causes and fixes
│   │   └── memory_test.go      #   allocation/RSS guard tests
│   ├── filter/                 # IP / port / protocol / severity filter engine (shared CLI + export)
│   ├── export/                 # CSV writers
│   ├── auth/                   # single-user store (bcrypt-hashed password in a small JSON file), JWT issue/verify, forced first-login password change
│   └── server/                 # HTTP layer
│       ├── server.go           #   routes, upload limit (512 MiB), graceful shutdown
│       ├── stream.go           #   chunked (NDJSON-style) progressive result stream
│       ├── store.go            #   in-memory analysis store (TTL 2h, capped count)
│       └── auth.go export.go gcgov.go                      # auth endpoints, CSV zip, GC-percent governor for big analyses
├── web/
│   ├── embed.go                # //go:embed of web/dist -> single binary
│   └── src/
│       ├── App.tsx             # route table (/analysis/:id/{bad,good,tcp,dns,http,tls,sip,dhcpv6,quic,topology})
│       ├── analysis/           # AnalysisProvider, chunk-stream parser, load progress, cache
│       ├── auth/               # AuthProvider, session/token holder
│       ├── filters/            # filter model, IP/port parsers, match engine, useFilters
│       ├── topology/           # pure graph model + force-directed layout (unit-tested)
│       ├── components/
│       │   ├── NetworkTopology.tsx   # custom Canvas renderer: pan/zoom/hover/culling
│       │   ├── analyzer/IssuesTable.tsx, IssueCard.tsx, UploadCard.tsx, HealthCard.tsx
│       │   ├── FlowDetailsModal.tsx  # TCP stream timeline modal
│       │   ├── IssueDetailsModal.tsx, NodeIssuesModal.tsx
│       │   └── ui/VirtualList.tsx, CappedVirtualList.tsx, Table, Card, Badge ...
│       ├── pages/              # route-level views (Overview=Bad, GoodTraffic, Topology, protocol/*)
│       ├── shortcuts/          # command palette + keyboard shortcuts
│       ├── wireshark.ts        # builds Wireshark display filters for "verify in Wireshark"
│       └── goodTraffic.ts flowTimeline.ts issueView.ts   # view-model logic with unit tests
├── testdata/                   # real, minimal .pcap fixtures (mandated by CLAUDE.md)
├── Makefile                    # build, test (race+cover), lint, release zips with checksums
└── CLAUDE.md                   # agent/contributor rules: layering, mandatory tests, dependency freeze
```

---

## 3. Backend Architecture Review (Go)

### 3.1 Layering and packet parsing

The layering rule from `CLAUDE.md` is actually honoured: `internal/analyzer` is pure (it consumes `[]models.PacketInfo`, not files), `internal/pcap` owns decoding, `cmd/` owns stdout. That is what makes 97.8% analyzer coverage achievable without fixtures for most cases, and what let the server reuse the analyzer unchanged.

Notable parsing decisions:

- **Pure-Go reading (`pcapgo`)** — no libpcap/cgo, so cross-compiled single-binary releases are real, not aspirational.
- **pcap and pcapng**, including mixed link types and pcapng metadata extraction.
- **Truncated files** are analyzed up to the cut and flagged with a warning; a file too short for a header fails with an explanatory error. Honest and user-friendly.
- **Unsupported link types / non-IP frames** are counted and named in a "Skipped Frames" note (with EtherType breakdown) rather than silently dropped.

### 3.2 Protocol decoders

| Protocol | Assessment |
|---|---|
| TCP | Strongest area: retransmission, SYN/unanswered-SYN, SYN-flood pattern, reassembly, handshake timing, stream numbering that mirrors Wireshark's `tcp.stream`. |
| DNS | Request/response pairing, NXDOMAIN/SERVFAIL, unanswered queries. |
| HTTP | Request/response matching, 4xx/5xx, latency. Cleartext only. |
| TLS | Handshake-level (hello, alerts, failures); no decryption, appropriately. |
| SIP | Registration/call failures; documented limitation: SIP messages split across segments are not reassembled. |
| DHCP / DHCPv6 | NAK, timeouts, address availability, RFC 8415 status codes. |
| QUIC | Version identification and handshake-timeout detection; documented caveat on connection migration (flow = UDP 4-tuple). |
| ARP / ICMP | Present. |

The pattern across decoders is consistent: decode in `internal/pcap`, judge in `internal/analyzer`. The cost is that adding a protocol touches two packages plus `guidance.go` and the frontend protocol page — a candidate for a registry/interface in v0.2.0.

### 3.3 Tunnel decapsulation

GRE, IP-in-IP and 6in4 are decapsulated so inner flows are analyzed by inner addresses; the tunnel is recorded in the flow ID (`...@GRE:a~b`) so separate tunnels do not merge. This fixes real bugs (flow merging, retransmit inflation) and the README states the residual limits precisely: only the outermost tunnel is recorded for nested tunnels; ESP/AH/L2TP/VXLAN/Teredo stay opaque; HTTP/TLS/DNS matching pairs by 4-tuple alone, so two tunnels with an identical inner 4-tuple could cross-pair. VXLAN/GENEVE are the obvious next ones for SRE audiences.

### 3.4 Memory and performance

Measured (README, 1.5M packets, 307 MB capture, 115k flows, 171k issues):

| Metric | Before | After |
|---|---|---|
| Health score on screen | 82 s | 36.7 s |
| Longest main-thread block | 11.5 s | 0.6 s |
| Analysis in memory | 443 MB | 284 MB |
| Server peak RSS | 2.6 GB | 2.25 GB |

What is good: the team *measured*, built `gencap` to make the workload reproducible, kept a 1.5M-packet streaming test (`NETFORENSIC_PERF_PACKETS`), and added allocation guards (`testing.AllocsPerRun` on hot helpers like `hasTCPFlag`).

What is honestly weak: **~1 KB retained per packet (`models.PacketInfo`) and a 2.25 GB server peak for a 300 MB file.** The README admits streaming "does not shorten" the 30 s of analysis; it only removes the post-analysis parse/render stall. The analyzer is not truly streaming — it holds all packets. Peak RSS of roughly 7× the file size will cap what an SRE can open on a laptop or a small container, and the 512 MiB upload limit sits close to that ceiling.

### 3.5 API design and concurrency

Routes (stdlib `ServeMux`): `POST /api/login`, `/api/logout`, `/api/change-password`, `/api/analyze`, `GET /api/analysis/{id}` (with `?chunked=1`), `/api/export-csv`, static assets at `/`.

Strengths:

- Auth middleware wraps every data route; request bodies bounded with `http.MaxBytesReader` (JSON bodies and the 512 MiB upload) with typed `MaxBytesError` handling.
- Graceful shutdown via `signal.NotifyContext` with a shutdown timeout.
- Analyses live in an in-memory store with a **2-hour TTL** and a **maximum count**, and a GC governor (`gcgov.go`) that lowers the Go GC percent while big analyses run (about a fifth less peak memory at no cost in speed) and restores it when the last one finishes — bounded, no unbounded growth.
- **Progressive delivery:** the chunked endpoint emits `summary → overview → issues → flows → done`, so the verdict renders before the 170 MB of detail is parsed.

Concurrency model: deliberately simple — request-per-goroutine, one analysis per upload, a mutex-guarded store. Appropriate for a single-user forensic tool. Risks to note: analyses are CPU- and memory-heavy and there is no admission control, so two concurrent 500 MB uploads can exhaust RAM; the analyzer itself is single-threaded per capture, leaving cores idle (flow-sharded parallel analysis is possible because flows are independent). State is in-process only, so a restart loses results (acceptable for v0.1.0, and arguably a feature for sensitive captures).

---

## 4. Frontend Architecture Review (React)

### 4.1 Structure, state and routing

- **Routing** is clean and URL-addressable: `/analysis/:id` is a layout route with children per view (`bad`, `good`, `tcp`, `udp`, `dns`, `http`, `tls`, `sip`, `dhcpv6`, `quic`, `topology`), with safe fallbacks (`Navigate`). Deep links survive reloads while the server-side analysis is alive.
- **State** uses React Context providers (`AnalysisProvider`, `AuthProvider`, `ToastProvider`) and focused hooks (`useFilters`, `useAnalysisCache`, `useLoadProgress`) — no heavyweight store. Sensible at this size; the one pressure point is that a large analysis in a single context re-renders consumers broadly (selector-based access, or splitting context per chunk, would help).
- **Logic/UI separation** is good: `goodTraffic.ts`, `flowTimeline.ts`, `issueView.ts`, `filters/*`, `topology/*` and `wireshark.ts` are plain TS modules with unit tests (14 test files), keeping components thin. Frontend test depth is lower than the backend's, and component/E2E tests are not in the repo (see §5).
- Tooling: Vite 8, TypeScript 6, oxlint, a custom spacing-scale check script, Tailwind 3.

### 4.2 UX choices

| Feature | Assessment |
|---|---|
| **Good / Bad traffic split** | Strong idea. Showing what is *healthy* builds trust in the verdict and lets an engineer rule things out quickly. |
| **Clickable issues table** | Replaced cards with a dense table (IP addresses, severity, count) + details modal — right call for scanning hundreds of issues. |
| **TCP stream timeline modal** | Shows *when* a problem started inside a flow; this is the feature that most closely mirrors how engineers reason in Wireshark. |
| **Advanced filtering** | IP/CIDR, port, protocol, severity, quick-troubleshooting shortcuts, active-filter chips, and filter export. Because filters produce Wireshark display filters (`wireshark.ts`), the tool is a *router into* Wireshark rather than a competitor — pragmatic. |
| **Command palette / shortcuts** | Power-user polish; low cost, high value. |
| **Dark/light, skeletons, toasts** | Table-stakes polish, done consistently. |

A removed "Junior/Senior" toggle shows healthy product judgment: one mode, well explained, beat two diverging ones.

### 4.3 Network topology (Canvas)

A custom Canvas renderer (`NetworkTopology.tsx`, 390 lines, plus `topology/layout.ts` and `topology/model.ts`) instead of a graph library. Reasons this is the right call: zero added dependencies (the project's rules forbid casual additions), and DOM/SVG would collapse at thousands of nodes.

- **Force-directed layout** is a separate pure module with its own tests, run incrementally on `requestAnimationFrame`.
- **Viewport culling** (`visible` / `drawn` flags per node) avoids drawing off-screen nodes; HiDPI handled via `devicePixelRatio`.
- **Interactivity:** wheel-zoom around the pointer (with a non-passive listener to stop page scroll), drag-pan, hit-testing, hover, filter matching, and node → issues modal. Edges encode direction; nodes encode role (e.g. DNS server), traffic volume and worst severity.
- The API returns `total_nodes`/`truncated`, so large graphs degrade explicitly rather than freezing.

The repulsion step already uses a spatial grid, so a tick costs roughly the number of neighbouring nodes rather than O(n²). Risks: very dense clusters can still degrade a grid, and Canvas is opaque to accessibility — a keyboard/table alternative for the same data is advisable.

### 4.4 Performance optimizations

- **Virtualization** via `@tanstack/react-virtual` (`VirtualList`) for issues and flows.
- **Capped lists** (`CappedVirtualList`): first 5,000 rows of very long lists, with the rest reachable via filters — a pragmatic guard.
- **Progressive chunked loading:** the summary/overview paints first; `useLoadProgress` and a progress bar show the remainder arriving.
- Result: blocked main-thread time fell from 32 s (123 blocks) to 1.2 s (4 blocks) in the 1.5M-packet benchmark. Page heap (~381 MB) did not improve — the browser still holds the full dataset, which is the next frontier (server-side pagination).

---

## 5. Why This Application Is Solid

1. **Test rigour that matches the stated policy.** `CLAUDE.md` makes tests mandatory per protocol, using real minimal pcap fixtures — and the numbers back it: analyzer 97.8%, pcap 96.1%, export 95.1%, cmd 95.0%, filter 97.7%, server 93.7% (all verified by running `go test -cover ./...`). Test code (~14.3k lines) exceeds production Go code (~13.1k). Tests run with the race detector via `make test-go`.
2. **Honest about limits.** The README's "Known limitations" is specific and testable, not defensive hand-waving. The standout is **asymmetric-capture handling**: unanswered SYNs are *not* declared firewall drops; when more than 40% of other TCP flows (≥10) are one-directional, the report says replies may simply have taken another path — "a hint, not a verdict." A forensic tool that refuses to over-claim is rare and valuable.
3. **Defensive programming.** Truncated captures analyzed to the cut with a warning; too-short files explained; unknown link types reported by real type number; unsupported frames counted and broken down; durations over 24 h shown as "24h+" (merged unsynchronized clocks); bounded uploads, bounded request bodies, TTL-bounded store, graceful shutdown.
4. **Architecture enforces itself.** Pure analyzer, thin `cmd/`, embedded UI → one binary; pure-Go pcap reading → painless cross-compilation; per-platform release zips with checksums.
5. **Performance work is evidence-based.** Reproducible generator, before/after tables tied to commit hashes, a regression test at 1.5M packets, allocation guards.
6. **Scope discipline.** Dependencies are few and approved; UI logic is extracted into tested modules; the topology diagram avoids a heavy library; features were removed when they didn't earn their keep.
7. **Verification is built into the UX.** Every finding links to a Wireshark filter, so users can check the tool rather than trust it.

---

## 6. Strategic Roadmap for v0.2.0

Ordered by impact-to-effort.

### 1. Packet extraction / "export evidence" (highest user value)
Let users export a filtered subset as a new `.pcap`/`.pcapng` — a single flow, an issue's packets, or everything matching the active filter — from both CLI (`--write-filtered out.pcap`) and the web UI. Today the tool tells you *what* is wrong and then you go find the packets elsewhere; closing that loop makes it a complete triage step and an attachable artifact for tickets and vendor cases. Needs packet offsets/indices retained during analysis (a few bytes per packet, far cheaper than the 1 KB of decoded state).

### 2. CI/CD and supply-chain basics
The Makefile already defines `make check` ("everything CI should run") but there is **no `.github/` workflow**. Add: GitHub Actions running `check` on Linux + macOS, Go matrix (1.22 and latest), `govulncheck`, `npm audit`, frontend build verified against the embedded `web/dist`, tagged releases that publish the existing zip+checksum artifacts (add SBOM and signing via cosign/goreleaser). Wire the perf test as a scheduled (nightly) job with a regression threshold. This is the cheapest way to protect the quality bar already achieved.

### 3. Cut memory per packet; make analysis truly streaming
Retaining ~1 KB `PacketInfo` per packet drives the 2.25 GB RSS. Options, in order of risk: (a) shrink the struct (interned strings for IPs/flags, `netip.Addr`, enums for protocol/flags, drop fields not needed after flow aggregation); (b) aggregate into flows incrementally and discard packets, keeping only per-flow state plus offsets for on-demand re-read (which also enables roadmap item 1); (c) shard flows across worker goroutines. Target: ≤ 3× file size at 1.5M packets and multi-core speedup of the 30 s analysis. Add server-side pagination for issues/flows so the browser heap stops mirroring the dataset, and an admission limit (max concurrent analyses / memory budget) on the server.

### 4. More protocol decoders via a registry
Add the protocols network engineers actually chase in captures: **BGP** (session flaps, NOTIFICATION codes, hold-timer expiry), **SNMP** (timeouts, auth failures, v1/v2c community exposure), **NTP/DNS-over-TLS**, **VXLAN/GENEVE** decapsulation (cloud and K8s overlays), and **TCP/TLS depth** (TLS 1.3 alert classification, certificate expiry from the handshake). To keep each addition cheap, introduce a small `Decoder`/`Detector` interface and registry so a protocol is one package plus a fixture and table test, not edits across `pcap`, `analyzer`, `guidance` and `web`.

### 5. Alerting and automation integrations
SREs want this in pipelines, not just a dashboard: a stable, versioned JSON schema (documented, with a JSON Schema file), exit codes keyed to severity thresholds (`--fail-on error`), SARIF/JUnit output for CI, and a webhook (Slack / PagerDuty / generic) on a health-score threshold. Pair with a watch mode (`--watch dir/`) for rotating captures. Lower priority but straightforward once the schema is fixed.

### Smaller items worth tracking
- Frontend: add component/E2E tests (Playwright) for the upload → stream → filter → timeline path that was currently verified by hand in the browser; add a keyboard-accessible table alternative to the Canvas topology.
- Security hardening for web mode: configurable bind address default of loopback, rate limiting on `/api/login`, optional TLS flags, and documenting the auth model in the README.
- Persistence option (SQLite or on-disk spill) for analyses, off by default given the sensitivity of captures.

---

*Method note: all counts and coverage figures come from running `go test -cover ./...` and inspecting the repo at commit `6f64c78`; performance numbers are quoted from the project README and were not re-run for this review. Items under "weak" and "risks" are my assessment from reading the code and docs, not observed failures.*
