#!/bin/sh
# Build a signed local Alpine apk3 artifact. No installation occurs here.
set -eu
[ "$#" = 8 ] || { echo 'usage: make-apk.sh BINARY SHA256 VERSION REPO IDENTITY_GUARD UPGRADE_GUARD SIGN_KEY OUTPUT' >&2; exit 2; }
binary=$1; expected=$2; version=$3; repo=$4; hook=$5; guard=$6; signkey=$7; output=$8
abort_phase() {
    printf 'ONYX_APK_PHASE %s %s %s\n' "$1" "$2" "$3" >&2
    exit 1
}
case "$expected" in *[!0-9a-f]*|'') exit 2;; esac
[ "${#expected}" = 64 ] || exit 2
case "$version" in *[!0-9a-zA-Z._+-]*|'') exit 2;; esac
[ -f "$binary" ] && [ ! -L "$binary" ] || abort_phase source invalid_file 1
[ "$(sha256sum "$binary" | awk '{print $1}')" = "$expected" ] || abort_phase source hash_mismatch 1
[ "$(id -u)" = 0 ] || { echo "build requires a disposable root Alpine guest" >&2; exit 1; }
[ -f "$signkey" ] && [ ! -L "$signkey" ] || exit 2
[ "$(stat -c %a "$signkey")" = 600 ] && [ "$(stat -c %u "$signkey")" = "$(id -u)" ] && [ "$(stat -c %h "$signkey")" = 1 ] || exit 2
command -v apk >/dev/null
work=$(mktemp -d "${TMPDIR:-/tmp}/onyx-apk.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
# Probe and package the same private, verified executable. The source is a
# read-only 0400 guest share and is never executed or chmodded.
mkdir -p "$work/root/usr/bin" "$work/root/etc/init.d" "$work/root/usr/share/onyx-server" "$work/root/usr/libexec/onyx-server" || abort_phase copy setup 1
if cp "$binary" "$work/root/usr/bin/onyx-server"; then :; else rc=$?; abort_phase copy copy_failed "$rc"; fi
if chmod 755 "$work/root/usr/bin/onyx-server"; then :; else rc=$?; abort_phase copy chmod_failed "$rc"; fi
[ "$(sha256sum "$work/root/usr/bin/onyx-server" | awk '{print $1}')" = "$expected" ] || abort_phase copy hash_mismatch 1
if (set -o pipefail; timeout 5 "$work/root/usr/bin/onyx-server" --helix-upgrade-capabilities-v1 2>&1 | head -c 4097 > "$work/capability"); then :
else rc=$?; abort_phase capability command_failed "$rc"; fi
[ "$(wc -c < "$work/capability")" -le 4096 ] || abort_phase capability oversized 1
if grep -Fx 'ONYX_HELIX_BOOT_POLICY=1' "$work/capability" >/dev/null; then :
else rc=$?; if [ "$rc" = 1 ]; then abort_phase capability missing_token 1; else abort_phase capability read_error "$rc"; fi; fi
cp "$repo/packaging/alpine/onyx-server.openrc" "$work/root/etc/init.d/onyx-server"
cp "$repo/etc/openrc/onyx-server.confd" "$work/root/usr/share/onyx-server/onyx-server.confd.example"
cp "$hook" "$work/root/usr/libexec/onyx-server/identity-guard"
cp "$guard" "$work/root/usr/libexec/onyx-server/upgrade"
cp "$repo/packaging/alpine/runtime-preflight" "$work/root/usr/libexec/onyx-server/runtime-preflight"
cp "$repo/packaging/alpine/guarded-start" "$work/root/usr/libexec/onyx-server/guarded-start"
chmod 755 "$work/root/usr/libexec/onyx-server/identity-guard" "$work/root/usr/libexec/onyx-server/upgrade" "$work/root/usr/libexec/onyx-server/guarded-start" "$work/root/usr/libexec/onyx-server/runtime-preflight"
chmod 755 "$work/root/usr/bin/onyx-server" "$work/root/etc/init.d/onyx-server"
chmod 644 "$work/root/usr/share/onyx-server/onyx-server.confd.example"
chmod 755 "$work/root" "$work/root/etc" "$work/root/etc/init.d" "$work/root/usr" "$work/root/usr/bin" "$work/root/usr/share" "$work/root/usr/share/onyx-server" "$work/root/usr/libexec" "$work/root/usr/libexec/onyx-server"
printf '%s\n' "$version" > "$work/root/usr/share/onyx-server/package-version"
chmod 644 "$work/root/usr/share/onyx-server/package-version"
[ "$(sha256sum "$work/root/usr/bin/onyx-server" | awk '{print $1}')" = "$expected" ] || exit 1
if apk mkpkg --files "$work/root" --info name:onyx-server --info "version:$version" --info arch:x86_64 --sign-key "$signkey" --output "$output"; then :
else rc=$?; printf 'ONYX_APK_EXIT %s\n' "$rc" >&2; exit "$rc"; fi
[ "$(sha256sum "$binary" | awk '{print $1}')" = "$expected" ] || abort_phase source hash_mismatch 1
