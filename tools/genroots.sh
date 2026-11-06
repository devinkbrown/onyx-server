#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

# Regenerate the marker regions in each package root.zig from the files present.
# Modules = sibling *.zig (except root.zig/main.zig) + subdirs containing root.zig.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)/src"
gen() {
  local dir="$1" rootf="$1/root.zig"
  [ -f "$rootf" ] || return 0
  local entries=()
  for f in "$dir"/*.zig; do
    b=$(basename "$f"); [ "$b" = root.zig ] && continue; [ "$b" = main.zig ] && continue
    # src/substrate/bench.zig is a standalone executable root (`zig build bench`)
    # with its own `onyx_server` import, like src/cli below. Re-exporting it from
    # substrate/root.zig would put `@import("onyx_server")` INSIDE the onyx_server
    # module, where that name is not available — breaking `zig build test`.
    [ "$dir" = "$SRC/substrate" ] && [ "$b" = bench.zig ] && continue
    # These daemon leaves are compiled by hand-written guards that fail the
    # build if the name is exported. Keep them out of the generated block.
    if [ "$dir" = "$SRC/daemon" ]; then
      case "$b" in
        ocg2_authority_issuer.zig|ocg2_reconcile_schedule.zig|ocg2_reconcile_workset.zig|ocg2_transaction_dst.zig)
          continue
          ;;
      esac
    fi
    # The setup-wizard tree (src/setup*.zig) and session_retirement_cli.zig
    # are a closed, mutually-importing cluster reachable only from
    # `src/main.zig`'s own root module (directly or transitively through each
    # other). Re-exporting any one of them from src/root.zig (the
    # `onyx_server` library module) assigns that file to two modules, which
    # `zig build` rejects — the same hazard the src/cli and bench.zig
    # exclusions below guard against. Exclude the whole cluster, not just
    # main.zig's direct imports, since a transitively-reachable member (e.g.
    # setup_account.zig, only reached via setup_bundle.zig) trips the same
    # two-module error the moment genroots exports it on its own.
    if [ "$dir" = "$SRC" ]; then
      case "$b" in
        session_retirement_cli.zig | setup.zig | setup_*.zig)
          continue
          ;;
      esac
      # Top-level standalone build roots. build.zig compiles each of these as
      # its own module root (leaf test lanes, private acceptance fixtures) or
      # as the custom test_runner over the onyx_server test module (the
      # production Helix exec helpers). Exporting any of them from src/root.zig
      # places the file in two modules and breaks that build step. `_*.zig`
      # files are local scratch roots and must never become public API.
      case "$b" in
        _*.zig | *_tests.zig | *_fixture.zig | *_exec_helper.zig)
          continue
          ;;
      esac
    fi
    entries+=("${b%.zig}|$b")
  done
  for sub in "$dir"/*/; do
    [ -f "${sub}root.zig" ] || continue
    s=$(basename "$sub")
    # src/cli is an executable-root module with its own `onyx_server` import.
    # Re-exporting it from src/root.zig assigns the same files to both modules.
    [ "$dir" = "$SRC" ] && [ "$s" = cli ] && continue
    entries+=("$s|$s/root.zig")
  done
  IFS=$'\n' read -r -d '' -a entries < <(printf '%s\n' "${entries[@]}" | sort && printf '\0') || true
  # A pub const declared outside the generated block is the one export.
  # Emitting it again inside the block does not compile. The test reference
  # stays, so the manual declaration still pulls that module's tests.
  local outside
  outside="$(awk '
    /gen:mods:begin/{skip=1; next}
    /gen:mods:end/{skip=0; next}
    skip{next}
    /^pub const [A-Za-z0-9_]+ =/{print $3}
  ' "$rootf")"
  local imp="" tst=""
  for e in "${entries[@]}"; do
    n="${e%%|*}"; p="${e##*|}"
    if printf '%s\n' "$outside" | grep -qx "$n"; then
      tst+="    _ = $n;"$'\n'
      continue
    fi
    imp+="pub const $n = @import(\"$p\");"$'\n'
    tst+="    _ = $n;"$'\n'
  done
  awk -v imp="$imp" -v tst="$tst" '
    /gen:mods:begin/{print; printf "%s", imp; skip=1; next}
    /gen:mods:end/{skip=0; print; next}
    /gen:tests:begin/{print; printf "%s", tst; skip=1; next}
    /gen:tests:end/{skip=0; print; next}
    {if(!skip) print}
  ' "$rootf" > "$rootf.tmp" && mv "$rootf.tmp" "$rootf"
}
while IFS= read -r rf; do gen "$(dirname "$rf")"; done < <(find "$SRC" -name root.zig)
echo "genroots: regenerated $(find "$SRC" -name root.zig | wc -l) package roots"
