# External capture corpus

NetForensic's tests use the small captures in `testdata/`. For broader checks there is a much larger set of real captures that lives **outside** this repository. This page says where it is, what it is for, and how to use it without drawing the wrong conclusions from it.

## Location

- Default: `~/tools/NetForensic-Corpus/` (a flat directory of `.pcap` and `.pcapng` files, about 280 captures and 1.7 GB when this page was written).
- Override with the `NETFORENSIC_CORPUS` environment variable:

  ```bash
  export NETFORENSIC_CORPUS="$HOME/tools/NetForensic-Corpus"
  ```

- The corpus is **local test data**. It is not part of the repository, is not downloaded by any build step, and may not exist on CI or on another developer's machine. Everything below must keep working (by skipping) when it is absent.
- Do **not** commit captures or copy them into the repository. Keep the corpus out of Git: it is large, some captures may carry data that should not be published, and their licenses were not reviewed.

## What it is for

Checking that the reader and the analyzer cope with realistic traffic: many protocols, odd link types, truncated files, very large files. It is **not** a set of golden files. The repository fixtures in `testdata/` remain the ones to use for assertions about findings.

## Parsing is not diagnosing

A capture that opens, analyzes and serializes without error shows only that the pipeline did not crash. It does not show that the findings are right, complete or well explained.

- Filenames are **not** evidence. A file called `tcp-spurious-retran` or `voip-extension` may or may not contain what its name suggests, and the analyzer may or may not report it. Verify a capture's contents with Wireshark, `tshark` or `capinfos` before asserting anything about it.
- A capture with no findings is not proof that it has no problems: the analyzer has no findings for several things Wireshark flags (for example out-of-order segments, "previous segment not captured" and spurious retransmissions).
- Do not call a detector validated because some corpus capture contains the protocol.

## Smoke test (Go)

`internal/analyzer/corpus_test.go` contains `TestExternalCorpusSmoke`. It walks the corpus (recursively, `.pcap` and `.pcapng`, case-insensitive), reads each file with the same reader the CLI uses, analyzes it, and checks basic invariants: the read succeeds (or reports the documented truncated-capture error), the packet count matches, the health score is in its documented range, confidence is one of `high`/`medium`/`low`, severities are valid, and the result serializes to JSON. It does not check which issues were found. It needs no external tool.

```bash
# Skipped (and says so) unless NETFORENSIC_CORPUS is set to an existing directory:
go test -run TestExternalCorpusSmoke -v ./internal/analyzer

# Against the corpus (about 15 seconds for the full set):
NETFORENSIC_CORPUS="$HOME/tools/NetForensic-Corpus" go test -count=1 -run TestExternalCorpusSmoke -v ./internal/analyzer
```

`go test ./...` and `make test` skip it when the variable is unset. Its log lines (`-v`) give per-file frame, packet, flow and issue counts.

## CLI sweep (script)

`scripts/corpus-sweep.sh` runs the built binary with `-o json` on every capture and writes a CSV (file, size, SHA-256, exit status, elapsed seconds, status, packets, flows, issue count, primary cause, first stderr line). It continues after a failure and exits 1 if any capture failed, 2 on a setup error.

```bash
make backend                      # builds ./netforensic; the script never builds
scripts/corpus-sweep.sh           # corpus from NETFORENSIC_CORPUS or the default, CSV in $TMPDIR
scripts/corpus-sweep.sh ./netforensic /tmp/sweeps
```

- The CSV goes to a timestamped file outside the repository (the script refuses an output directory inside it).
- The binary is `./netforensic` unless given as the first argument; the script warns if the Go sources are newer than it.
- `NETFORENSIC_SWEEP_TIMEOUT` (seconds per capture, default 600) bounds a single run.
- It needs `python3` (standard library only) for JSON, hashing and CSV quoting.
- `status` is `analyzed`, `no_analyzable_packets` (a successful run on a capture with nothing to analyze) or `failed`; a successful analysis with zero issues is `analyzed` with `issue_count` 0.

## Known limitations of the corpus and the tool

- **802.11 and USB captures** (and other captures without Ethernet/IP traffic, such as STP, LLDP, CDP, EAPOL) contain link types or frames NetForensic cannot decode. They are reported as "The capture contains no analyzable packets" with a `Skipped Frames` issue. That is expected, not a failure, and tells you nothing about the traffic inside them.
- **Truncated captures** (`Velocloud-Lan.pcap` and `Velocloud-Wan.pcap` at the time of writing) are analyzed up to the cut; the CLI prints a warning and the result carries a `Truncated Capture` issue.
- **File extension and format can differ**: the reader chooses the format by content. `smb3-aes-128-ccm.pcap` is a pcapng file.
- **Duplicates and near-duplicates** exist (the same capture under several names), so counts of files are not counts of independent scenarios.
- The corpus has no manifest or checksums; the sweep CSV records SHA-256 values so that two runs can be compared.
- The largest captures are about 170 MB. The web upload path and its size limit were not exercised with them.

## Reporting a run

When you report a corpus check, give the capture names, the exact command, the exit status and what was verified (parsed only, or compared with `tshark`), plus any capture that was skipped or failed.
