#!/usr/bin/env bash
# corpus-sweep.sh runs the netforensic binary on every .pcap and .pcapng file
# of an external capture corpus and writes one CSV row per capture.
#
# It checks that each capture reads and analyzes; it does not check that the
# diagnosis is right. See docs/external-corpus.md.
#
# Usage: scripts/corpus-sweep.sh [BINARY [OUTPUT_DIR]]
#
#   BINARY      the netforensic binary (default: ./netforensic in the repository
#               root, as built by `make backend`; it is never built here)
#   OUTPUT_DIR  where the CSV goes (default: $TMPDIR or /tmp; must be outside
#               the repository)
#
# Environment:
#   NETFORENSIC_CORPUS          the corpus directory (default: $HOME/tools/NetForensic-Corpus)
#   NETFORENSIC_SWEEP_TIMEOUT   seconds allowed per capture (default: 600)
#
# Exit status: 0 if every capture was analyzed (or reported as having nothing
# to analyze), 1 if any capture failed, 2 on a usage or setup error.
# Requires python3 (standard library only) for JSON, hashing and CSV quoting.

set -u

die() {
	echo "corpus-sweep: $*" >&2
	exit 2
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P) || die "cannot find the repository root"
corpus=${NETFORENSIC_CORPUS:-$HOME/tools/NetForensic-Corpus}
bin=${1:-$repo/netforensic}
outdir=${2:-${TMPDIR:-/tmp}}
timeout_s=${NETFORENSIC_SWEEP_TIMEOUT:-600}

[ -d "$corpus" ] || die "corpus directory not found: $corpus
Set NETFORENSIC_CORPUS to a directory of .pcap/.pcapng files."
if [ ! -x "$bin" ]; then
	die "binary not found or not executable: $bin
Build it first (make backend, or go build -o netforensic ./cmd/netforensic) or pass its path as the first argument."
fi
command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1 ||
	die "python3 is required (standard library only) and was not found"
mkdir -p "$outdir" || die "cannot create output directory: $outdir"
outdir=$(cd "$outdir" && pwd -P)
case "$outdir/" in
"$repo"/*) die "the output directory must be outside the repository: $outdir" ;;
esac
case "$timeout_s" in
'' | *[!0-9]*) die "NETFORENSIC_SWEEP_TIMEOUT must be a whole number of seconds" ;;
esac

csv="$outdir/corpus-sweep-$(date +%Y%m%d-%H%M%S).csv"

if [ -n "$(find "$repo/cmd" "$repo/internal" -name '*.go' -newer "$bin" -print -quit 2>/dev/null)" ]; then
	echo "corpus-sweep: warning: $bin is older than the Go sources; rebuild it to test the current code" >&2
fi
echo "corpus-sweep: corpus=$corpus" >&2
echo "corpus-sweep: binary=$bin" >&2
echo "corpus-sweep: csv=$csv" >&2

python3 -I - "$corpus" "$bin" "$csv" "$timeout_s" <<'PY'
import csv, hashlib, json, os, subprocess, sys, tempfile, time

corpus, binary, out, timeout_s = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

files = []
for root, _, names in os.walk(corpus):
    for n in names:
        p = os.path.join(root, n)
        if os.path.isfile(p) and n.lower().endswith((".pcap", ".pcapng")):
            files.append(p)
files.sort()
if not files:
    print("corpus-sweep: no .pcap or .pcapng files under " + corpus, file=sys.stderr)
    sys.exit(2)

cols = ["file", "size_bytes", "sha256", "exit_status", "elapsed_seconds", "status",
        "total_packets", "total_flows", "issue_count", "primary_cause", "note"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


failed = analyzed = empty = 0
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=cols)  # quotes fields that need it
    w.writeheader()
    for path in files:
        row = dict.fromkeys(cols, "")
        row["file"] = os.path.relpath(path, corpus)
        row["size_bytes"] = os.path.getsize(path)
        row["sha256"] = sha256(path)
        start = time.monotonic()
        with tempfile.TemporaryFile() as so:
            try:
                r = subprocess.run([binary, "-o", "json", path], stdout=so,
                                   stderr=subprocess.PIPE, timeout=timeout_s)
                row["exit_status"] = r.returncode
                err = r.stderr.decode("utf-8", "replace").strip().splitlines()
                row["note"] = (err[0] if err else "")[:200]
                row["elapsed_seconds"] = round(time.monotonic() - start, 3)
                if r.returncode != 0:
                    row["status"] = "failed"
                else:
                    so.seek(0)
                    try:
                        d = json.load(so)
                        row["total_packets"] = d["total_packets"]
                        row["total_flows"] = d["total_flows"]
                        row["issue_count"] = len(d.get("issues") or [])
                        if "diagnosis" in d:
                            row["primary_cause"] = d["diagnosis"]["primary_cause"]
                            row["status"] = "analyzed"
                        elif "message" in d:
                            row["status"] = "no_analyzable_packets"
                        else:
                            row["status"] = "failed"
                            row["note"] = "unrecognized JSON output"
                    except (ValueError, KeyError, TypeError) as e:
                        row["status"] = "failed"
                        row["note"] = "unreadable JSON output: %s" % e
            except subprocess.TimeoutExpired:
                row["exit_status"] = "timeout"
                row["elapsed_seconds"] = round(time.monotonic() - start, 3)
                row["status"] = "failed"
                row["note"] = "timed out after %ds" % timeout_s
        w.writerow(row)
        fh.flush()
        if row["status"] == "failed":
            failed += 1
            print("FAILED  %s: %s" % (row["file"], row["note"]), file=sys.stderr)
        elif row["status"] == "analyzed":
            analyzed += 1
        else:
            empty += 1

print("corpus-sweep: %d captures: %d analyzed, %d with nothing to analyze, %d failed"
      % (len(files), analyzed, empty, failed), file=sys.stderr)
sys.exit(1 if failed else 0)
PY
