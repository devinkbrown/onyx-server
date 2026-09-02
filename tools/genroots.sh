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
  local imp="" tst=""
  for e in "${entries[@]}"; do
    n="${e%%|*}"; p="${e##*|}"
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
