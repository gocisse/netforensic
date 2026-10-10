Overwrite the existing CLAUDE.md file at the project root with the EXACT content below. Do not modify, summarize, or reorder it. Write it verbatim.

---BEGIN CLAUDE.md CONTENT---
# CLAUDE.md — Agent Instructions for netforensic

## Project Overview
`netforensic` is a Go-based forensic tool that analyzes `.pcap` files.
It has two modes:
  1. **CLI mode** (Phase 1 — current focus): `netforensic [flags] file.pcap`
  2. **Web mode** (Phase 2): embedded React+Tailwind UI served from the same binary

The final deliverable is a **single self-contained Go binary**.

## Tech Stack (Locked — Do Not Change Without Approval)
- **Language:** Go 1.22+
- **PCAP parsing:** `github.com/google/gopacket` + `github.com/google/gopacket/pcap`
- **CLI flags:** `github.com/spf13/cobra` (preferred) or stdlib `flag`
- **Frontend (Phase 2):** React + Vite + Tailwind CSS
- **Embedding:** Go `embed` package (`//go:embed`)
- **Testing:** stdlib `testing` + `testify` for assertions

## Architecture Principles
1. **Separation of concerns:**
   - `cmd/netforensic/` — CLI entry points and flag parsing
   - `internal/analyzer/` — pure analysis logic (NO I/O, NO CLI, NO HTTP)
   - `internal/pcap/` — pcap reading/parsing layer
   - `internal/models/` — shared data structures (Packet, Flow, Issue, etc.)
   - `internal/server/` — HTTP server (Phase 2)
   - `web/` — React frontend source (Phase 2)
   - `web/dist/` — built frontend assets (embedded)
2. **The analyzer must be testable in isolation** — no dependency on files, CLI, or HTTP.
3. **Single binary:** everything (including frontend) must be embeddable.

## Coding Standards
- Run `gofmt` / `goimports` on every file you touch.
- Every exported function needs a doc comment.
- Error messages: lowercase, no trailing punctuation (Go convention).
- Use `fmt.Errorf("context: %w", err)` for wrapping.
- Prefer table-driven tests.
- No `init()` functions unless absolutely necessary.
- No global mutable state.

## 🚨 MANDATORY TESTING RULES 🚨
- **Every new protocol detection or analysis feature (e.g., DNS, HTTP, HTTPS/TLS, packet loss) MUST be accompanied by unit tests.**
- Tests MUST use real, minimal `.pcap` fixture files stored in the `testdata/` directory.
- No protocol logic is considered "complete" or merged without corresponding table-driven tests proving it works.
- Aim for >80% coverage on `internal/analyzer` and `internal/pcap`.

## What You SHOULD Do
- Write tests alongside implementation.
- Keep commits atomic and well-described.
- Ask before adding a new dependency.
- Return data from `internal/` packages; let `cmd/` handle stdout formatting.

## What You MUST NOT Do
- ❌ Do NOT add a dependency without explicit approval.
- ❌ Do NOT modify `go.mod` / `go.sum` unless adding an approved dependency.
- ❌ Do NOT start Phase 2 (web server, React) until Phase 1 CLI is fully working and tested.
- ❌ Do NOT use `panic()` for expected errors — always return errors.
- ❌ Do NOT hardcode file paths — use flags or config.
- ❌ Do NOT skip tests "to save time." Testing is mandatory.
- ❌ Do NOT refactor unrelated code in the same commit as a feature.

## Build & Run
```bash
go build -o netforensic ./cmd/netforensic
go run ./cmd/netforensic   # run the program
go build ./...        # build
go test ./...         # run all tests
go test -run TestName ./path/to/pkg   # run a single test
go vet ./...          # static checks
go test -v ./internal/analyzer/...
go test -cover ./...
./netforensic file.pcap
./netforensic -service dns file.pcap
```
