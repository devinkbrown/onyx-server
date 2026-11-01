#!/bin/sh
# Supported offline upgrade entry point. Checks identity before invoking apk.
set -eu
[ "$(id -u)" = 0 ] || exit 1
[ "$#" = 2 ] || exit 2
package=$1; expected=$2
case "$expected" in ''|*[!0-9a-f]*) exit 2;; esac
[ "${#expected}" = 64 ] || exit 2
[ -f "$package" ] && [ ! -L "$package" ] || exit 1
[ "$(sha256sum "$package" | awk '{print $1}')" = "$expected" ] || exit 1
/usr/libexec/onyx-server/identity-guard /etc/onyx-server/onyx-server.toml onyx-server || exit 1
env -u RC_SVCNAME start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server \
    --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml || exit 1
exec apk add --network=no "$package"
