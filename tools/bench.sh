#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run the 0.7 measurement harness and print a baseline block for the current
# build.zig.zon manifest version (release plan P0-1, wave W1-1).
#
# The harness itself (src/substrate/bench.zig) knows nothing about the machine it
# runs on beyond arch/OS/CPU-count. This wrapper adds the facts that make a
# baseline comparable later — CPU model, kernel, CPU governor, load average — and
# runs the harness TWICE, because the release plan's acceptance criterion is a
# baseline that reproduces across two consecutive runs. A baseline is
# machine-specific: report deltas only against a same-machine baseline.
#
# Usage:
#   tools/bench.sh                       # print a baseline block to stdout
#   tools/bench.sh -o docs/audit/x.md    # also write it to a file
#   tools/bench.sh --runs 3              # more consecutive runs
#   tools/bench.sh --quick               # fewer samples (a smoke, not a baseline)
#   tools/bench.sh --live                # throwaway daemon: TLS / shards / ring axes
#   tools/bench.sh --live --quick        # one plaintext live cell
#
# Offline mode (`zig build bench`) never starts the daemon. `--live` boots a
# throwaway `onyx-server` on 127.0.0.1 with kernel-assigned ports (never
# 6667/6680/6697, never `orochi.service`). See docs/dev/benchmarks.md.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUNS=2
OUT=""
LIVE=0
QUICK=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUT="${2:?--out needs a path}"; shift 2 ;;
    --runs) RUNS="${2:?--runs needs a count}"; shift 2 ;;
    --live) LIVE=1; shift ;;
    --quick) QUICK=1
             export ONYX_BENCH_SAMPLES="${ONYX_BENCH_SAMPLES:-5}"
             export ONYX_BENCH_ITERS="${ONYX_BENCH_ITERS:-1000}"
             export ONYX_BENCH_ACCEPT_ITERS="${ONYX_BENCH_ACCEPT_ITERS:-100}"
             RUNS=1; shift ;;
    -h|--help) sed -n '5,30p' "$0"; exit 0 ;;
    *) echo "bench.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

# The manifest is the single source of truth for the version this baseline
# belongs to (build.zig reads it the same way, via manifestVersion()).
MANIFEST_VERSION="$(sed -n 's/.*\.version = "\([^"]*\)".*/\1/p' build.zig.zon | head -1)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY=""
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
  DIRTY=" (dirty tree)"
fi

cpu_model() { sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1; }
governor() {
  local g
  g="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true)"
  [ -n "$g" ] && echo "$g" || echo "unknown"
}

emit() {
  echo "# Benchmark baseline — onyx-server ${MANIFEST_VERSION}"
  echo
  echo "Produced by \`tools/bench.sh\` (\`zig build bench\`, harness:"
  echo "\`src/substrate/bench.zig\`). Release plan P0-1 / wave W1-1."
  echo
  echo '## Provenance'
  echo
  echo "| field | value |"
  echo "| --- | --- |"
  echo "| manifest version | \`${MANIFEST_VERSION}\`${DIRTY} |"
  echo "| commit | \`${COMMIT}\` |"
  echo "| captured | $(date -Is) |"
  echo "| host | $(uname -n) |"
  echo "| kernel | $(uname -sr) |"
  echo "| cpu | $(cpu_model) |"
  echo "| cpu governor | $(governor) |"
  echo "| load avg at start | $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown) |"
  echo "| zig | $(zig version) |"
  echo "| runs | ${RUNS} consecutive |"
  echo
  echo 'Compare deltas ONLY against a baseline captured on this same machine,'
  echo 'kernel, and governor. If `min` and `p50` differ by more than ~1.5x in any'
  echo 'row, the box was contended during capture: trust `min` for code cost and'
  echo 're-capture on an idle machine before recording a baseline.'
  echo

  local i
  for i in $(seq 1 "$RUNS"); do
    echo "## Run ${i} of ${RUNS}"
    echo
    echo '```'
    # The harness prints its table to stderr (std.debug.print), so fold it in.
    zig build bench 2>&1
    echo '```'
    echo
  done

  echo '## Interpretation'
  echo
  echo 'See `docs/dev/benchmarks.md` for what each row measures, what it'
  echo 'deliberately does NOT measure (TLS/kTLS, RSS per connection, `num_shards`'
  echo 'scaling, end-to-end round-trip, io_uring submit cost), and how to read the'
  echo 'min/p50/p99 columns.'
}

if [ "$LIVE" -eq 1 ]; then
  echo "bench.sh: building the live-daemon image (ReleaseFast; the first build is slow)..." >&2
  LIVE_ARGS=()
  [ "$QUICK" -eq 1 ] && LIVE_ARGS+=(--quick)
  [ -n "$OUT" ] && LIVE_ARGS+=(-o "$OUT")
  if ! zig build bench-live -- "${LIVE_ARGS[@]+"${LIVE_ARGS[@]}"}"; then
    echo "bench.sh: 'zig build bench-live' failed; re-run it directly to see the error" >&2
    exit 1
  fi
  exit 0
fi

# Warm the build cache up front, at trivial sample counts, so the slow ReleaseFast
# compile is not attributed to run 1 — and so a compile failure aborts the script
# before any baseline output is emitted. The measured runs below then hit a warm
# cache and start immediately.
echo "bench.sh: building the harness (ReleaseFast; the first build is slow)..." >&2
if ! ONYX_BENCH_SAMPLES=3 ONYX_BENCH_ITERS=100 ONYX_BENCH_ACCEPT_ITERS=50 \
     zig build bench >/dev/null 2>&1; then
  echo "bench.sh: 'zig build bench' failed; re-run it directly to see the error" >&2
  exit 1
fi

if [ -n "$OUT" ]; then
  mkdir -p "$(dirname "$OUT")"
  emit | tee "$OUT"
  echo "bench.sh: wrote ${OUT}" >&2
else
  emit
fi
