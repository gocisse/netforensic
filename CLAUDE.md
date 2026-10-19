# CLAUDE.md — Agent Instructions for netforensic

## Project Overview
`netforensic` is a Go-based forensic tool for analyzing `.pcap` and `.pcapng` files. It provides:
- **CLI:** packet-capture analysis, filtering, triage, and text/JSON/CSV output.
- **Web UI:** an embedded React dashboard served by the same Go executable.

The intended release artifact is a single self-contained Go binary with the frontend embedded.

## Tech Stack (Do Not Change Without Approval)
- **Language:** Go 1.22+
- **Packet parsing:** `github.com/google/gopacket` and its pure-Go `pcapgo` readers; do not introduce cgo/libpcap requirements without approval.
- **CLI:** `github.com/spf13/cobra`
- **HTTP server:** Go standard library
- **Frontend:** React, TypeScript, Vite, Tailwind CSS
- **Embedding:** Go `embed` package (`//go:embed`)
- **Testing:** Go standard library `testing`, `testify` where already used, and Node's built-in test runner for frontend unit tests.

## Architecture Principles
1. Keep clear boundaries:
   - `cmd/netforensic/` — CLI entry point, flags, and output formatting.
   - `internal/pcap/` — packet-capture reading and packet decoding.
   - `internal/analyzer/` — analysis and detector logic; keep it independent of files, CLI, and HTTP.
   - `internal/models/` — shared domain data structures.
   - `internal/filter/` and `internal/export/` — reusable filtering and export logic.
   - `internal/server/` and `internal/auth/` — web API and authentication.
   - `web/src/` — frontend source; `web/dist/` — generated assets embedded in the binary.
2. Keep the analyzer testable in isolation and reuse it from both CLI and web modes.
3. Keep the shipped application deployable as a single binary. Do not commit generated build artifacts beyond those already required by the repository's release/build process.
4. Do not describe a finding as a confirmed root cause unless the captured evidence supports that conclusion. Preserve uncertainty and known capture limitations in findings and guidance.

## Coding Standards
- Run `gofmt` on every Go file you touch.
- Every exported Go function and type needs an appropriate doc comment.
- Error messages should be concise and actionable.
- Wrap errors with context using `fmt.Errorf("context: %w", err)` when appropriate.
- Prefer table-driven tests for protocol and analysis behavior.
- Avoid `init()` functions unless necessary.
- Avoid global mutable state.
- Keep changes focused; do not combine unrelated refactors with a bug fix or feature.

## Mandatory Testing Rules
- Every new protocol decoder, detector, or analysis feature must include tests.
- Use small, real `.pcap`/`.pcapng` fixtures from `testdata/` when validating packet-level behavior. Use synthetic model data for pure helper logic where appropriate.
- Add regression tests for every confirmed bug fix.
- Run the narrowest relevant tests first, then the broader checks when feasible.
- Aim for greater than 80% coverage in `internal/analyzer` and `internal/pcap`, without treating coverage alone as proof of correctness.
- Performance changes must include a reproducible workload and before/after measurements where practical.

## What You SHOULD Do
- Write tests alongside implementation.
- Keep commits atomic and clearly described.
- Ask before adding a dependency or changing a locked technology.
- Keep packet evidence, interpretation, and likely diagnosis distinct.
- Return domain data from `internal/` packages; keep CLI rendering in `cmd/` and HTTP concerns in `internal/server/`.

## What You MUST NOT Do
- Do not add a dependency without explicit approval.
- Do not modify `go.mod` or `go.sum` unless a dependency change is approved.
- Do not use `panic()` for expected errors; return errors instead.
- Do not hardcode local file paths; use flags or configuration.
- Do not skip relevant tests to save time.
- Do not refactor unrelated code in the same change as a feature or bug fix.
- Do not claim a test, benchmark, or manual verification passed unless it was actually run and its result was observed.

## Build, Test, and Quality Commands
```bash
go build -o netforensic ./cmd/netforensic
go build ./...
go test ./...
go test -race -cover ./...
go test -run TestName ./path/to/pkg
go vet ./...
make test
make check

# From web/
npm ci
npm test
npm run build
npm run lint
npm run check:spacing
```

## Environment
- Prefer repository scripts and documented project tooling.
- Do not modify generated files or dependencies unless the task requires it.
- If a command cannot run because a dependency or external service is unavailable, report the exact limitation rather than claiming success.
