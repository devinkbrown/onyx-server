#!/bin/sh
# Only in a disposable networkless Alpine guest; never exports private state.
set -eu
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
umask 077
fail() { code=$1; trap - EXIT; if command -v cleanup >/dev/null 2>&1; then cleanup; fi; printf 'ONYX_RESULT FAIL %s\n' "$code"; exit 1; }
mkdir -m 700 /tmp/onyx-service-diag || fail prereq
custody() {
    helper=unknown; supervisor_class=unknown; daemon_class=unknown
    registry=/run/openrc/daemons/onyx-server
    if [ -d "$registry" ] && [ ! -L "$registry" ]; then
        helper=absent; n=0
        for entry in "$registry"/*; do
            [ -e "$entry" ] || continue
            n=$((n + 1)); if [ "$n" -gt 16 ] || [ ! -f "$entry" ] || [ -L "$entry" ] || [ ! -r "$entry" ] || [ "$(wc -c < "$entry")" -gt 8192 ]; then helper=unknown; break; fi
            if grep -Fx 'exec=/usr/libexec/onyx-server/runtime-preflight' "$entry" >/dev/null 2>&1; then helper=present; fi
        done
    fi
    if [ ! -e /run/supervise-onyx-server.pid ]; then supervisor_class=absent; daemon_class=absent
    elif [ -f /run/supervise-onyx-server.pid ] && [ ! -L /run/supervise-onyx-server.pid ] && [ -r /run/supervise-onyx-server.pid ]; then
        spid=$(cat /run/supervise-onyx-server.pid)
        case "$spid" in ''|*[!0-9]*) supervisor_class=invalid;; *)
            supervisor_class=invalid
            sstart=$(sed 's/.*) //' "/proc/$spid/stat" 2>/dev/null | awk '{print $20}')
            case "$sstart" in ''|*[!0-9]*) :;; *)
                if [ "$(basename "$(readlink "/proc/$spid/exe" 2>/dev/null || :)")" = supervise-daemon ]; then
                    supervisor_class=valid; daemon_class=absent; count=0
                    for child in $(cat "/proc/$spid/task/$spid/children" 2>/dev/null || :); do
                        case "$child" in ''|*[!0-9]*) daemon_class=unknown; continue;; esac
                        if [ "$(readlink "/proc/$child/exe" 2>/dev/null || :)" = /usr/bin/onyx-server ]; then
                            count=$((count + 1)); daemon_class=invalid
                            dstart=$(sed 's/.*) //' "/proc/$child/stat" 2>/dev/null | awk '{print $20}')
                            if [ "$count" = 1 ] && [ -n "$dstart" ] && [ "$(stat -c %u "/proc/$child" 2>/dev/null || :)" = "$(id -u onyx-server)" ] && [ "$(readlink "/proc/$child/cwd" 2>/dev/null || :)" = /var/lib/onyx-server ] && [ "$(sed 's/.*) //' "/proc/$child/stat" 2>/dev/null | awk '{print $20}')" = "$dstart" ]; then daemon_class=valid; fi
                        fi
                    done
                    if [ "$(cat /run/supervise-onyx-server.pid 2>/dev/null || :)" != "$spid" ] || [ "$(sed 's/.*) //' "/proc/$spid/stat" 2>/dev/null | awk '{print $20}')" != "$sstart" ]; then supervisor_class=invalid; daemon_class=unknown; fi
                fi;; esac;; esac
    else supervisor_class=unknown; fi
    printf 'ONYX_DIAG custody %s %s %s %s %s\n' "$phase" "$operation" "$helper" "$supervisor_class" "$daemon_class"
}
service_op() {
    phase=$1; operation=$2; log=/tmp/onyx-service-diag/"$phase"-"$operation".log
    if (set -o pipefail; timeout 20 rc-service onyx-server "$operation" 2>&1 | head -c 65537 > "$log"); then op_rc=0
    else op_rc=$?; fi
    case "$op_rc" in ''|*[!0-9]*) op_rc=255;; esac
    [ "$op_rc" -le 255 ] || op_rc=255
    if timeout 10 /usr/libexec/onyx-server/identity-guard /etc/onyx-server/onyx-server.toml onyx-server >/dev/null 2>&1; then root_rc=0; else root_rc=$?; fi
    if timeout 10 env -u RC_SVCNAME start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml >/dev/null 2>&1; then runtime_rc=0; else runtime_rc=$?; fi
    if timeout 10 /usr/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml >/dev/null 2>&1; then config_rc=0; else config_rc=$?; fi
    if timeout 10 rc-service onyx-server status >/dev/null 2>&1; then service_state=started
    else status=$?; case "$status" in 3) service_state=stopped;; 4) service_state=stopping;; 8) service_state=starting;; 16) service_state=inactive;; 32) service_state=crashed;; *) service_state=unknown;; esac; fi
    if [ -e /run/openrc/failed/onyx-server ]; then failed_marker=present; else failed_marker=absent; fi
    reason=other
    if [ "$(wc -c < "$log")" -gt 65536 ]; then reason=truncated
    elif grep -qi 'permission denied' "$log"; then reason=permission
    elif grep -qi 'runtime-preflight' "$log"; then reason=runtime_preflight
    elif grep -qi 'identity-guard' "$log"; then reason=identity_guard
    elif grep -qi 'validating.*configuration' "$log"; then reason=config
    elif grep -qiE 'depend|need service' "$log"; then reason=dependency
    elif grep -qiE 'supervise-daemon|supervisor' "$log"; then reason=supervisor
    elif grep -qi 'already' "$log"; then reason=already; fi
    if [ "$reason" = truncated ]; then
        # A successful service action cannot turn a truncated capture into a
        # passing test; the host will reject the incomplete transfer as well.
        op_rc=125
    else
        case "$phase:$operation" in
            runtime_denied:start|initial:start|initial:status|initial:stop|missing_before:start|missing_after:start|postupgrade:start|postupgrade:status|postupgrade:stop|mode_file:start|mode_file:status|mode_file:stop|mode_inline:start|mode_inline:status|mode_inline:stop|mode_env:start|mode_env:status|mode_env:stop|mode_ref:start|mode_ref:status|mode_ref:stop|cleanup:stop) ;;
            *) op_rc=125; reason=truncated;;
        esac
        if [ "$reason" != truncated ]; then
            printf 'ONYX_PRIVATE_SERVICE %s %s ' "$phase" "$operation"
            if (set -o pipefail; base64 < "$log" | tr -d '\r\n'); then printf '\n'
            else printf '\n'; op_rc=125; reason=truncated; fi
        fi
    fi
    custody
    if [ "$operation" = status ] && { [ "$phase" = initial ] || [ "$phase" = postupgrade ]; } && [ "$op_rc" = 0 ]; then
        if [ "$helper" != absent ] || [ "$supervisor_class" != valid ] || [ "$daemon_class" != valid ]; then op_rc=125; fi
    fi
    printf 'ONYX_DIAG service %s %s %s %s %s %s %s %s %s\n' "$phase" "$operation" "$op_rc" "$root_rc" "$runtime_rc" "$config_rc" "$service_state" "$failed_marker" "$reason"
    return "$op_rc"
}
cleanup() {
    if [ -n "${client_pid:-}" ]; then kill "$client_pid" 2>/dev/null || :; wait "$client_pid" 2>/dev/null || :; client_pid=''; fi
    if command -v profile_capture >/dev/null 2>&1; then profile_capture || :; fi
    service_op cleanup stop || :
    if [ -n "${syslog_pid:-}" ]; then kill "$syslog_pid" 2>/dev/null || :; wait "$syslog_pid" 2>/dev/null || :; fi
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || fail prereq
for tool in apk adduser addgroup sha256sum stat su rc-service base64 nc mkfifo timeout tr grep cmp; do command -v "$tool" >/dev/null || fail prereq; done
# The pinned Alpine ISO supplies OpenSSL; install it only inside this guest
# and only if it is not already available, with normal signature validation.
if ! command -v openssl >/dev/null; then
    mkdir -p /media/onyx-iso
    mount -t iso9660 -o ro /dev/sr0 /media/onyx-iso >/dev/null 2>&1 || fail openssl_prereq
    apk add --force-non-repository --network=no /media/onyx-iso/apks/x86_64/openssl-3.5.9-r0.apk >/dev/null 2>&1 || fail openssl_prereq
fi
command -v openssl >/dev/null || fail openssl_prereq
# apk3 packages are built only inside this disposable guest. Kernel file-size
# limit bounds each output and staging file, including the transferred binary.
ulimit -f 1048576 || fail build_limit
expected=$(cat /fixture/expected.sha256)
case "$expected" in ''|*[!0-9a-f]*) fail build_input;; esac
[ "${#expected}" = 64 ] || fail build_input
mkdir -m 700 /tmp/onyx-package-build || fail build_input
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/onyx-package-build/sign.key >/dev/null 2>&1 || fail keygen
chmod 600 /tmp/onyx-package-build/sign.key
openssl pkey -in /tmp/onyx-package-build/sign.key -pubout -out /tmp/onyx-package-build/sign.pub >/dev/null 2>&1 || fail keygen
mkdir -p /etc/apk/keys
cp /tmp/onyx-package-build/sign.pub /etc/apk/keys/onyx-fixture.pub
chmod 644 /etc/apk/keys/onyx-fixture.pub
build_package() {
    stage=$1; version=$2; log=/tmp/onyx-package-build/"$stage".log
    # Drain at most 65537 bytes into a private file. A truncated stream fails
    # the build and is classified rather than exporting any underlying text.
    if (set -o pipefail; sh /fixture/make-apk.sh /fixture/onyx-server "$expected" "$version" /fixture /fixture/identity-guard /fixture/upgrade.sh /tmp/onyx-package-build/sign.key "/tmp/onyx-package-build/$stage.apk" 2>&1 | head -c 65537 > "$log"); then
        [ "$(wc -c < "$log")" -le 65536 ] && return 0
        rc=1
    else rc=$?; fi
    log_class=unknown; option=unknown; apk_exit=none
    if [ -f "$log" ] && [ ! -L "$log" ] && [ -r "$log" ]; then
        bytes=$(wc -c < "$log")
        if [ "$bytes" -gt 65536 ]; then log_class=truncated
        else
            log_class=complete
            if grep -Ei 'unrecognized option|unknown option|invalid info field|invalid argument for option' "$log" >/dev/null 2>&1; then option=reported
            else grep_rc=$?; if [ "$grep_rc" = 1 ]; then option=not_reported; fi; fi
            found=$(awk '/^ONYX_APK_EXIT [0-9]+$/ {n++; v=$2} END {if(n==1 && v>=1 && v<=255) print v}' "$log") || found=''
            case "$found" in ''|*[!0-9]*) ;; *) apk_exit=$found;; esac
        fi
    fi
    case "$rc" in ''|*[!0-9]*|0) rc=1;; esac
    [ "$rc" -le 255 ] || rc=1
    if [ "$log_class" = complete ]; then
        phase_info=$(awk '/^ONYX_APK_PHASE (source|copy|capability) (invalid_file|setup|copy_failed|chmod_failed|hash_mismatch|command_failed|oversized|missing_token|read_error) [0-9]+$/ { n++; if ($4 >= 1 && $4 <= 255) v=$2 " " $3 " " $4 } END { if (n==1 && v!="") print v }' "$log") || phase_info=''
        if [ -n "$phase_info" ]; then printf 'ONYX_DIAG apkphase %s %s\n' "$stage" "$phase_info"; fi
    fi
    printf 'ONYX_DIAG build %s %s %s %s %s\n' "$stage" "$rc" "$apk_exit" "$option" "$log_class"
    fail build
}
build_package old 0.8.1-r0
build_package new 0.8.1-r1
# Publish only complete, validated packages. apk's intermediate files never
# touch the host transfer share. Host independently checks ownership/size/hash.
for name in old new; do
    file=/tmp/onyx-package-build/$name.apk
    [ -f "$file" ] && [ ! -L "$file" ] || fail build_output
    [ "$(stat -c %u "$file")" = 0 ] && [ "$(stat -c %h "$file")" = 1 ] || fail build_output
    size=$(stat -c %s "$file")
    case "$size" in ''|*[!0-9]*) fail build_output;; esac
    [ "$size" -gt 0 ] && [ "$size" -le 536870912 ] || fail build_output
    [ ! -e "/output/$name.apk" ] && [ ! -L "/output/$name.apk" ] || fail build_output
    local_hash=$(sha256sum "$file" | awk '{print $1}')
    cp "$file" "/output/$name.apk" || fail build_output
    [ -f "/output/$name.apk" ] && [ ! -L "/output/$name.apk" ] || fail build_output
    [ "$(sha256sum "/output/$name.apk" | awk '{print $1}')" = "$local_hash" ] || fail build_output
    if [ "$name" = old ]; then old_hash=$local_hash; else new_hash=$local_hash; fi
done
cp /tmp/onyx-package-build/sign.pub /output/fixture.pub || fail build_output
pub_hash=$(sha256sum /output/fixture.pub | awk '{print $1}')
printf 'ONYX_ARTIFACT %s %s %s\n' "$old_hash" "$new_hash" "$pub_hash"
apk_local_add() { apk add --force-non-repository --network=no "$@"; }
# Negative proofs must observe the fixed apk cryptographic failure text, not
# merely any nonzero return (which could be an unrelated setup failure).
reject_crypto() {
    class=$1; shift
    log=/tmp/onyx-package-build/negative.log
    if (set -o pipefail; "$@" 2>&1 | head -c 65537 > "$log"); then fail "$class"; fi
    [ "$(wc -c < "$log")" -le 65536 ] || fail "$class"
    grep -Ei 'UNTRUSTED signature|BAD signature|ADB integrity error|file integrity error|v2 package integrity error' "$log" >/dev/null 2>&1 || fail "$class"
}
apk verify /output/old.apk /output/new.apk >/dev/null 2>&1 || fail signature_trusted
mkdir -m 700 /tmp/onyx-package-build/untrusted
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/onyx-package-build/other.key >/dev/null 2>&1 || fail keygen
chmod 600 /tmp/onyx-package-build/other.key
openssl pkey -in /tmp/onyx-package-build/other.key -pubout -out /tmp/onyx-package-build/untrusted/other.pub >/dev/null 2>&1 || fail keygen
reject_crypto signature_wrong_key apk verify --keys-dir /tmp/onyx-package-build/untrusted /output/old.apk
reject_crypto signature_wrong_key apk_local_add --keys-dir /tmp/onyx-package-build/untrusted /output/old.apk
cp /output/old.apk /tmp/onyx-package-build/unsigned.apk
apk adbsign --reset-signatures /tmp/onyx-package-build/unsigned.apk >/dev/null 2>&1 || fail signature_unsigned_setup
reject_crypto signature_unsigned apk verify /tmp/onyx-package-build/unsigned.apk
reject_crypto signature_unsigned apk_local_add /tmp/onyx-package-build/unsigned.apk
cp /output/old.apk /tmp/onyx-package-build/tampered.apk
size=$(stat -c %s /tmp/onyx-package-build/tampered.apk)
[ "$size" -gt 64 ] || fail signature_tamper_setup
offset=$((size-10))
byte=$(dd if=/tmp/onyx-package-build/tampered.apk bs=1 skip="$offset" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
case "$byte" in ''|*[!0-9]*) fail signature_tamper_setup;; esac
if [ "$byte" = 255 ]; then corrupt='\000'; else corrupt='\377'; fi
printf "$corrupt" | dd of=/tmp/onyx-package-build/tampered.apk bs=1 seek="$offset" conv=notrunc 2>/dev/null || fail signature_tamper_setup
reject_crypto signature_tampered apk verify /tmp/onyx-package-build/tampered.apk
reject_crypto signature_tampered apk_local_add /tmp/onyx-package-build/tampered.apk
if apk info -e onyx-server >/dev/null 2>&1; then fail signature_mutation; fi
stat -c '%u:%g:%a' / /etc /usr /etc/init.d /usr/bin > /tmp/onyx-package-build/system.before
addgroup -S onyx-server >/dev/null 2>&1 || fail account
adduser -S -D -H -G onyx-server onyx-server >/dev/null 2>&1 || fail account
if (set -o pipefail; apk_local_add /output/old.apk 2>&1 | head -c 65537 > /tmp/onyx-package-build/install.log); then :
else rc=$?; class=other
    if [ "$(wc -c < /tmp/onyx-package-build/install.log)" -gt 65536 ]; then class=truncated
    elif grep -qi 'non-repository' /tmp/onyx-package-build/install.log; then class=non_repository
    elif grep -qi 'untrusted\|signature' /tmp/onyx-package-build/install.log; then class=trust
    elif grep -qi 'unrecognized option\|unknown option\|invalid.*option' /tmp/onyx-package-build/install.log; then class=option
    elif grep -qi 'no such file\|not found' /tmp/onyx-package-build/install.log; then class=missing
    elif grep -qi 'permission denied' /tmp/onyx-package-build/install.log; then class=permission; fi
    printf 'ONYX_DIAG install %s %s\n' "$rc" "$class"; fail install
fi
stat -c '%u:%g:%a' / /etc /usr /etc/init.d /usr/bin > /tmp/onyx-package-build/system.after
cmp -s /tmp/onyx-package-build/system.before /tmp/onyx-package-build/system.after || fail system_layout
mkdir -p /etc/onyx-server /etc/conf.d /var/lib/onyx-server
chown root:onyx-server /etc/onyx-server
chmod 750 /etc/onyx-server
chown onyx-server:onyx-server /var/lib/onyx-server
chmod 700 /var/lib/onyx-server
cat > /etc/onyx-server/onyx-server.toml <<'CONFIG'
[node]
id = 1
[network]
server_name = "alpine.package.fixture"
[listen]
host = "127.0.0.1"
irc = 16680
ws = 0
[limits]
num_shards = 1
CONFIG
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > /etc/onyx-server/onyx-server-node.key
printf '\n' >> /etc/onyx-server/onyx-server-node.key
printf 'respawn_delay=8\nrespawn_max=2\nrespawn_period=75\n' > /etc/conf.d/onyx-server
printf 'operator-state-marker\n' > /var/lib/onyx-server/operator-state
chown onyx-server:onyx-server /etc/onyx-server/onyx-server.toml /etc/onyx-server/onyx-server-node.key /var/lib/onyx-server/operator-state
chmod 600 /etc/onyx-server/onyx-server.toml /etc/onyx-server/onyx-server-node.key /var/lib/onyx-server/operator-state
chmod 600 /etc/conf.d/onyx-server
snapshot() {
    for path in /etc/onyx-server/onyx-server.toml /etc/onyx-server/onyx-server-node.key /etc/conf.d/onyx-server /var/lib/onyx-server/operator-state; do
        [ -f "$path" ] && [ ! -L "$path" ] || return 1
        sha256sum "$path"; stat -c '%u:%g:%a' "$path"
    done
    stat -c '%u:%g:%a' /etc/onyx-server /var/lib/onyx-server
}
snapshot > /tmp/snapshot.before || fail snapshot
su -s /bin/sh onyx-server -c 'cd /var/lib/onyx-server && exec /usr/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml' >/dev/null 2>&1 || fail preflight
old_binary=$(sha256sum /usr/bin/onyx-server | awk '{print $1}')
[ "$(cat /usr/share/onyx-server/package-version)" = 0.8.1-r0 ] || fail install
# Direct package upgrade with absent key must never create one. The package
# service guard rejects startup before daemon execution until seed is restored.
# The live Alpine image may start its own OpenRC syslog. Retire only the
# identified service owning this exact socket; unknown ownership is failure.
if [ -e /dev/log ] || [ -L /dev/log ]; then
    [ -S /dev/log ] && [ ! -L /dev/log ] || fail boot_socket_type
    socket_identity=$(stat -c '%d:%i' /dev/log) || fail boot_stale_identity
    case "$socket_identity" in *[!0-9:]*|:*|*:*:*|*:|'') fail boot_stale_identity;; *:*) ;; *) fail boot_stale_identity;; esac
    rc-service syslog status >/dev/null 2>&1 || fail boot_syslog_status
    [ -r /run/syslogd.pid ] || fail boot_syslog_identity
    boot_pid=$(cat /run/syslogd.pid)
    case "$boot_pid" in ''|*[!0-9]*) fail boot_syslog_identity;; esac
    [ "$boot_pid" -gt 1 ] || fail boot_syslog_identity
    [ "$(readlink "/proc/$boot_pid/exe" 2>/dev/null || :)" = "$(readlink -f /bin/busybox)" ] || fail boot_syslog_identity
    boot_arg=$(tr '\000' '\n' < "/proc/$boot_pid/cmdline" | head -n 1)
    [ "$boot_arg" = /sbin/syslogd ] || fail boot_syslog_identity
    boot_start=$(sed 's/.*) //' "/proc/$boot_pid/stat" | awk '{print $20}')
    case "$boot_start" in ''|*[!0-9]*) fail boot_syslog_identity;; esac
    # Linux exposes the kernel socket inode in /proc/net/unix; bind it to a
    # descriptor held by the exact syslog process before stopping the service.
    inode=$(awk '$8=="/dev/log" {n++; v=$7} END {if(n==1 && v ~ /^[0-9]+$/) print v; else exit 1}' /proc/net/unix) || fail boot_socket_owner
    owner=0
    for fd in /proc/"$boot_pid"/fd/*; do
        [ "$(readlink "$fd" 2>/dev/null || :)" = "socket:[$inode]" ] && owner=1
    done
    [ "$owner" = 1 ] || fail boot_socket_owner
    [ "$(sed 's/.*) //' "/proc/$boot_pid/stat" 2>/dev/null | awk '{print $20}')" = "$boot_start" ] || fail boot_syslog_identity
    timeout 10 rc-service syslog stop >/dev/null 2>&1 || fail boot_syslog_stop
    i=0
    while :; do
        current=$(sed 's/.*) //' "/proc/$boot_pid/stat" 2>/dev/null | awk '{print $20}' || :)
        # Only absent PID or a readable, different numeric start time proves
        # the captured owner is gone. An unreadable existing PID is unknown.
        owner_gone=0
        if [ ! -e "/proc/$boot_pid" ]; then owner_gone=1
        elif [ -r "/proc/$boot_pid/stat" ]; then
            case "$current" in ''|*[!0-9]*) ;; *) [ "$current" = "$boot_start" ] || owner_gone=1;; esac
        fi
        if rc-service syslog status >/dev/null 2>&1; then status=0; else status=$?; fi
        if [ "$owner_gone" = 1 ] && [ "$status" = 3 ]; then
            if [ ! -e /dev/log ] && [ ! -L /dev/log ]; then break; fi
            [ -S /dev/log ] && [ ! -L /dev/log ] || fail boot_stale_identity
            [ "$(stat -c '%d:%i' /dev/log)" = "$socket_identity" ] || fail boot_stale_identity
            # A filesystem socket may remain after its owner closes it. Never
            # remove it while *any* kernel binding to this path still exists.
            [ -r /proc/net/unix ] || fail boot_socket_binding
            bindings=$(awk '$8=="/dev/log" {print "bound"}' /proc/net/unix) || fail boot_socket_binding
            [ -z "$bindings" ] || fail boot_socket_binding
            [ -S /dev/log ] && [ ! -L /dev/log ] &&
                [ "$(stat -c '%d:%i' /dev/log)" = "$socket_identity" ] || fail boot_stale_identity
            rm /dev/log || fail boot_stale_remove
            [ ! -e /dev/log ] && [ ! -L /dev/log ] || fail boot_stale_remove
            break
        fi
        i=$((i+1))
        if [ "$i" -gt 30 ]; then
            proc_class=unknown
            if [ ! -e "/proc/$boot_pid" ]; then
                proc_class=gone
            elif [ -r "/proc/$boot_pid/stat" ]; then
                fields=$(sed 's/.*) //' "/proc/$boot_pid/stat" 2>/dev/null || :)
                state=$(printf '%s\n' "$fields" | awk '{print $1}')
                stamp=$(printf '%s\n' "$fields" | awk '{print $20}')
                case "$stamp" in
                    ''|*[!0-9]*) ;;
                    *) case "$state" in
                           [A-Z]) if [ "$stamp" != "$boot_start" ]; then proc_class=changed
                                  elif [ "$state" = Z ]; then proc_class=zombie
                                  else proc_class=live; fi ;;
                       esac ;;
                esac
            fi
            if rc-service syslog status >/dev/null 2>&1; then service_class=started
            else status=$?; if [ "$status" = 3 ]; then service_class=stopped; else service_class=unknown; fi; fi
            if [ -L /dev/log ]; then socket_class=symlink
            elif [ -S /dev/log ]; then socket_class=socket
            elif [ -e /dev/log ]; then socket_class=other
            else socket_class=absent; fi
            printf 'ONYX_DIAG retirement %s %s %s\n' "$proc_class" "$service_class" "$socket_class"
            fail boot_syslog_retirement
        fi
        sleep 0.1
    done
fi
[ ! -e /dev/log ] && [ ! -L /dev/log ] || fail boot_syslog_retirement
mkdir -p /tmp/onyx-private /etc/onyx-server /var/lib/onyx-server /etc/network
chmod 700 /tmp/onyx-private
syslogd -n -O /tmp/onyx-private/syslog -s 1024 -b 1 >/dev/null 2>&1 &
syslog_pid=$!
i=0
while [ ! -S /dev/log ]; do i=$((i+1)); [ "$i" -le 30 ] || fail syslog_ready; kill -0 "$syslog_pid" 2>/dev/null || fail syslog_ready; sleep 0.1; done
logger -t onyx-logger-probe -p daemon.err ready
sleep 1
grep -q 'onyx-logger-probe.*ready' /tmp/onyx-private/syslog || fail syslog_ready
rc-update -u >/dev/null 2>&1 || fail service_setup
mkdir -p /etc/network
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
timeout 20 rc-service networking start >/dev/null 2>&1 || fail service_setup
# The root guard can read the file under a root-only parent, but the runtime
# account cannot. Prove the runtime wrapper refuses before binary execution.
chmod 700 /etc/onyx-server
[ -r /etc/onyx-server/onyx-server.toml ] && [ -r /etc/onyx-server/onyx-server-node.key ] || fail runtime_guard_setup
/usr/libexec/onyx-server/identity-guard /etc/onyx-server/onyx-server.toml onyx-server >/dev/null 2>&1 || fail runtime_guard_setup
seed_hash=$(sha256sum /etc/onyx-server/onyx-server-node.key | awk '{print $1}')
if service_op runtime_denied start; then fail runtime_guard; fi
[ ! -e /run/supervise-onyx-server.pid ] || fail runtime_guard
[ "$(sha256sum /etc/onyx-server/onyx-server-node.key | awk '{print $1}')" = "$seed_hash" ] || fail runtime_guard
for proc in /proc/[0-9]*/exe; do
    [ "$(readlink "$proc" 2>/dev/null || :)" != /usr/bin/onyx-server ] || fail runtime_guard
done
if timeout 5 su -s /bin/sh onyx-server -c 'exec /usr/libexec/onyx-server/guarded-start /etc/onyx-server/onyx-server.toml' >/dev/null 2>&1; then fail runtime_guard
else guard_status=$?; [ "$guard_status" = 1 ] || fail runtime_guard; fi
[ "$(sha256sum /etc/onyx-server/onyx-server-node.key | awk '{print $1}')" = "$seed_hash" ] || fail runtime_guard
for proc in /proc/[0-9]*/exe; do
    [ "$(readlink "$proc" 2>/dev/null || :)" != /usr/bin/onyx-server ] || fail runtime_guard
done
chmod 750 /etc/onyx-server
su -s /bin/sh onyx-server -c 'test -r /etc/onyx-server/onyx-server.toml && test -r /etc/onyx-server/onyx-server-node.key' >/dev/null 2>&1 || fail runtime_guard_setup
service_op initial start || fail service_start
service_op initial status || fail service_start
service_op initial stop || fail service_stop
mv /etc/onyx-server/onyx-server-node.key /etc/onyx-server/seed.saved
if env -u RC_SVCNAME start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml >/dev/null 2>&1; then fail missing_identity_start; fi
if service_op missing_before start; then fail missing_identity_start; fi
[ ! -e /run/supervise-onyx-server.pid ] || fail missing_identity_start
[ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity
apk_local_add /output/new.apk >/dev/null 2>&1 || fail upgrade
apk info -e 'onyx-server=0.8.1-r1' >/dev/null 2>&1 || fail upgrade
[ "$(cat /usr/share/onyx-server/package-version)" = 0.8.1-r1 ] || fail upgrade
[ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity
if service_op missing_after start; then fail missing_identity_start; fi
[ ! -e /run/supervise-onyx-server.pid ] || fail missing_identity_start
[ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity
# Install an independently signed unrelated package while the seed is absent.
mkdir -p /tmp/onyx-package-build/unrelated/usr/share/onyx-unrelated
chmod 755 /tmp/onyx-package-build/unrelated /tmp/onyx-package-build/unrelated/usr /tmp/onyx-package-build/unrelated/usr/share /tmp/onyx-package-build/unrelated/usr/share/onyx-unrelated
printf 'fixture\n' > /tmp/onyx-package-build/unrelated/usr/share/onyx-unrelated/value
chmod 644 /tmp/onyx-package-build/unrelated/usr/share/onyx-unrelated/value
apk mkpkg --files /tmp/onyx-package-build/unrelated --info name:onyx-fixture-unrelated --info version:1.0-r0 --info arch:x86_64 --sign-key /tmp/onyx-package-build/other.key --output /tmp/onyx-package-build/unrelated.apk >/dev/null 2>&1 || fail unrelated_maintenance
cp /tmp/onyx-package-build/untrusted/other.pub /etc/apk/keys/onyx-unrelated.pub
apk_local_add /tmp/onyx-package-build/unrelated.apk >/dev/null 2>&1 || fail unrelated_maintenance
apk info -e 'onyx-fixture-unrelated=1.0-r0' >/dev/null 2>&1 || fail unrelated_maintenance
mv /etc/onyx-server/seed.saved /etc/onyx-server/onyx-server-node.key
stat -c '%u:%g:%a' / /etc /usr /etc/init.d /usr/bin > /tmp/onyx-package-build/system.upgraded
cmp -s /tmp/onyx-package-build/system.before /tmp/onyx-package-build/system.upgraded || fail system_layout
snapshot > /tmp/snapshot.after || fail snapshot
cmp -s /tmp/snapshot.before /tmp/snapshot.after || fail preservation
su -s /bin/sh onyx-server -c 'cd /var/lib/onyx-server && exec /usr/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml' >/dev/null 2>&1 || fail preflight
service_op postupgrade start || fail service_start
service_op postupgrade status || fail service_start
service_op postupgrade stop || fail service_stop
# One native credential profile: no credential is inspected by shell policy.
# The fixture supplies known values; only the typed runtime checker decides.
profile_capture() {
    [ -n "${profile_log:-}" ] && [ -f "$profile_log" ] || return 0
    [ "${profile_sent:-0}" = 0 ] || return 0
    if [ "${profile_combined:-0}" = 0 ]; then
        tail -c 32768 /tmp/onyx-private/syslog >> "$profile_log" || return 1
        profile_combined=1
    fi
    profile_truncated=0
    profile_transfer=$profile_log
    if [ "$(wc -c < "$profile_log")" -gt 65536 ]; then
        profile_truncated=1
        profile_transfer=/tmp/onyx-profile/transfer-$mode.log
        head -c 65536 "$profile_log" > "$profile_transfer" || return 1
    fi
    printf 'ONYX_PRIVATE_PROFILE %s ' "$mode"
    if (set -o pipefail; base64 < "$profile_transfer" | tr -d '\r\n'); then printf '\n'; else printf '\n'; return 1; fi
    profile_sent=1
    [ "$profile_truncated" = 0 ]
}
check_runtime() {
    env -u RC_SVCNAME start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server \
        --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml >/dev/null 2>&1
}
profile_config() {
    kind=$1; value=$2
    {
        printf '[node]\nid=1\n'
        case "$kind" in
            inline) printf 'secret_key="%s"\n' "$value";;
            env) printf 'secret_key="env:%s"\n' "${3:-ONYX_A04_NODE_SECRET}";;
            ref) printf 'secret_key="@file:/etc/onyx-server/profile.key"\n';;
            file) :;; *) fail profile_source;;
        esac
        printf '[network]\nserver_name="alpine.package.fixture"\n[listen]\nhost="127.0.0.1"\nirc=16680\nws=0\n[limits]\nnum_shards=1\n'
    } > /etc/onyx-server/onyx-server.toml
    chown onyx-server:onyx-server /etc/onyx-server/onyx-server.toml
    chmod 600 /etc/onyx-server/onyx-server.toml
}
source_snapshot() {
    for source_path in /etc/onyx-server/onyx-server.toml /etc/onyx-server/onyx-server-node.key /etc/onyx-server/profile.key /etc/conf.d/onyx-server /var/lib/onyx-server/operator-state; do
        if [ -e "$source_path" ]; then
            [ -f "$source_path" ] && [ ! -L "$source_path" ] || return 1
            sha256sum "$source_path"; stat -c '%u:%g:%a' "$source_path"
        else printf 'absent %s\n' "$source_path"; fi
    done
}
refusal_unchanged() {
    source_snapshot > /tmp/onyx-profile/refusal.before || fail profile_source
    if check_runtime; then fail profile_refusal; fi
    source_snapshot > /tmp/onyx-profile/refusal.after || fail profile_source
    cmp -s /tmp/onyx-profile/refusal.before /tmp/onyx-profile/refusal.after || fail preservation
    [ ! -e /run/supervise-onyx-server.pid ] || fail profile_refusal
    [ "$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')" = "$bad_config_hash" ] || fail profile_refusal
    if [ "$mode" != file ]; then [ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity; fi
}
wait_reply() {
    wanted=$1; i=0
    while ! grep -F "$wanted" "$profile_log" >/dev/null 2>&1; do
        i=$((i+1)); [ "$i" -le 100 ] || fail helix_client
        kill -0 "$client_pid" 2>/dev/null || fail helix_client
        [ "$(wc -c < "$profile_log")" -le 65536 ] || fail identity_capture
        sleep 0.1
    done
}
# Fixed counts only; no descriptors, addresses, paths or console payload.
socket_fail() {
    socket_stage=$1
    tcp4=unknown; tcp6=unknown; client_unreadable=0; server_unreadable=0
    if [ -r /proc/net/tcp ]; then tcp4=$(awk '$4=="01" && $2 ~ /:4128$/ {n++} END {print n+0}' /proc/net/tcp 2>/dev/null) || tcp4=unknown; fi
    if [ -r /proc/net/tcp6 ]; then tcp6=$(awk '$4=="01" && $2 ~ /:4128$/ {n++} END {print n+0}' /proc/net/tcp6 2>/dev/null) || tcp6=unknown; fi
    for fd in /proc/$client_pid/fd/*; do if readlink "$fd" >/dev/null 2>&1; then :; else client_unreadable=$((client_unreadable+1)); fi; done
    for fd in /proc/$daemon_pid/fd/*; do if readlink "$fd" >/dev/null 2>&1; then :; else server_unreadable=$((server_unreadable+1)); fi; done
    for number in "$tcp4" "$tcp6" "$client_unreadable" "$server_unreadable"; do
        case "$number" in unknown) ;; ''|*[!0-9]*) fail helix_socket;; *) [ "$number" -le 999 ] || fail helix_socket;; esac
    done
    printf 'ONYX_DIAG socket %s %s %s %s %s %s %s\n' "$mode" "$socket_stage" "$tcp4" "$tcp6" "$client_unreadable" "$server_unreadable" initial
    fail helix_socket
}
# One candidate inode per established fixture endpoint, from both kernel tables.
socket_table_inodes() {
    [ "$#" = 2 ] && [ -r "$1" ] && [ -r "$2" ] || return 1
    awk '$4=="01" && $2 ~ /:4128$/ {print $10}' "$1" "$2"
}
held_refusal() {
    refusal_class=$1
    case "$refusal_class" in
        key) expected_error=ChangedNodeIdentity;;
        realm) expected_error=ChangedNodeRealm;;
        env) expected_error=ChangedBootEnvironment;;
        *) fail helix_exec;;
    esac
    refusal_text="onyx-server: deferred UPGRADE failed: $expected_error"
    before_refusals=$(grep -Fc "$refusal_text" /tmp/onyx-private/syslog || :)
    kill -USR2 "$daemon_pid" || fail helix_exec
    i=0
    while :; do
        after_refusals=$(grep -Fc "$refusal_text" /tmp/onyx-private/syslog || :)
        [ "$after_refusals" -le "$before_refusals" ] || break
        i=$((i+1)); [ "$i" -le 100 ] || fail helix_exec
        kill -0 "$daemon_pid" 2>/dev/null || fail helix_exec
        sleep 0.1
    done
    [ "$(sed 's/.*) //' "/proc/$daemon_pid/stat" | awk '{print $20}')" = "$daemon_start" ] || fail helix_exec
    [ "$(stat -Lc '%d:%i' "/proc/$daemon_pid/exe")" = "$target_inode" ] || fail helix_exec
    if tr '\000' '\n' < "/proc/$daemon_pid/cmdline" | grep -Fx -- '--supervisor' >/dev/null; then fail helix_exec; fi
    found_client=0; found_server=0
    for fd in /proc/$client_pid/fd/*; do [ "$(readlink "$fd" 2>/dev/null || :)" != "$client_socket" ] || found_client=$((found_client+1)); done
    for fd in /proc/$daemon_pid/fd/*; do [ "$(readlink "$fd" 2>/dev/null || :)" != "$server_socket" ] || found_server=$((found_server+1)); done
    [ "$found_client" = 1 ] && [ "$found_server" = 1 ] || fail helix_socket
    printf 'PING :a04-refused-%s\r\n' "$refusal_class" >&3
    wait_reply "a04-refused-$refusal_class"
    grep " PONG .*a04-refused-$refusal_class" "$profile_log" >/dev/null || fail helix_client
    printf 'ONYX_REFUSAL %s %s retained socket pong\n' "$refusal_class" "$expected_error"
}
mkdir -m 700 /tmp/onyx-profile || fail profile_source
cp -p /etc/onyx-server/onyx-server.toml /tmp/onyx-profile/config.saved
cp -p /etc/conf.d/onyx-server /tmp/onyx-profile/confd.saved
cp -p /etc/onyx-server/onyx-server-node.key /tmp/onyx-profile/seed.saved
seed_value=$(tr -d '\n' < /tmp/onyx-profile/seed.saved)
for mode in file inline env ref; do
    profile_log=/tmp/onyx-profile/client-$mode.log; profile_sent=0; profile_combined=0
    : > "$profile_log"; chmod 600 "$profile_log"
    cp -p /tmp/onyx-profile/confd.saved /etc/conf.d/onyx-server
    unset ONYX_A04_NODE_SECRET
    rm -f /etc/onyx-server/onyx-server-node.key /etc/onyx-server/profile.key
    profile_config "$mode" "$seed_value"
    case "$mode" in
        file)
            cp -p /tmp/onyx-profile/seed.saved /etc/onyx-server/onyx-server-node.key
            mv /etc/onyx-server/onyx-server-node.key /tmp/onyx-profile/missing.key
            bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
            refusal_unchanged
            [ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity
            mv /tmp/onyx-profile/missing.key /etc/onyx-server/onyx-server-node.key
            printf 'malformed\n' > /etc/onyx-server/onyx-server-node.key
            refusal_unchanged
            cp -p /tmp/onyx-profile/seed.saved /etc/onyx-server/onyx-server-node.key
            chmod 644 /etc/onyx-server/onyx-server-node.key
            refusal_unchanged
            chmod 600 /etc/onyx-server/onyx-server-node.key
            ;;
        inline)
            profile_config inline ''
            bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
            refusal_unchanged
            profile_config inline malformed
            bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
            refusal_unchanged
            profile_config inline "$seed_value"
            ;;
        env)
            export ONYX_A04_NODE_SECRET="$seed_value"
            bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
            if env -u RC_SVCNAME -u ONYX_A04_NODE_SECRET start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml >/dev/null 2>&1; then fail profile_refusal; fi
            [ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity
            ONYX_A04_NODE_SECRET=malformed; export ONYX_A04_NODE_SECRET
            refusal_unchanged
            ONYX_A04_NODE_SECRET=$seed_value; export ONYX_A04_NODE_SECRET
            # Explicit fixture binding in the operator's private OpenRC config.
            printf "export ONYX_A04_NODE_SECRET='%s'\n" "$seed_value" >> /etc/conf.d/onyx-server
            # Deliberately present but unreferenced in the original config.
            # A later ref-only mutation must hit the exact snapshot guard, not
            # merely fail parsing an absent variable.
            printf "export ONYX_A04_ALTERNATE='%s'\n" "$seed_value" >> /etc/conf.d/onyx-server
            ;;
        ref)
            bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
            refusal_unchanged
            printf 'malformed' > /etc/onyx-server/profile.key
            chown onyx-server:onyx-server /etc/onyx-server/profile.key; chmod 600 /etc/onyx-server/profile.key
            refusal_unchanged
            printf '%s' "$seed_value" > /etc/onyx-server/profile.key
            chmod 644 /etc/onyx-server/profile.key
            refusal_unchanged
            chmod 600 /etc/onyx-server/profile.key
            ;;
    esac
    # The config itself is also a private source; reject permissive custody.
    bad_config_hash=$(sha256sum /etc/onyx-server/onyx-server.toml | awk '{print $1}')
    chmod 644 /etc/onyx-server/onyx-server.toml
    refusal_unchanged
    chmod 600 /etc/onyx-server/onyx-server.toml
    check_runtime || fail profile_source
    source_snapshot > /tmp/onyx-profile/active-$mode.before || fail profile_source
    [ "$(sha256sum /usr/bin/onyx-server | awk '{print $1}')" = "$expected" ] || fail build_input
    profile_seed_hash=absent
    if [ -e /etc/onyx-server/onyx-server-node.key ]; then profile_seed_hash=$(sha256sum /etc/onyx-server/onyx-server-node.key | awk '{print $1}'); fi
    service_op "mode_$mode" start || fail service_start
    service_op "mode_$mode" status || fail service_start
    spid=$(cat /run/supervise-onyx-server.pid)
    daemon_pid=''
    for child in $(cat "/proc/$spid/task/$spid/children"); do
        if [ "$(readlink "/proc/$child/exe" 2>/dev/null || :)" = /usr/bin/onyx-server ]; then
            [ -z "$daemon_pid" ] || fail custody; daemon_pid=$child
        fi
    done
    [ -n "$daemon_pid" ] || fail custody
    [ "$(stat -c %u "/proc/$daemon_pid")" = "$(id -u onyx-server)" ] || fail custody
    daemon_start=$(sed 's/.*) //' "/proc/$daemon_pid/stat" | awk '{print $20}')
    target_inode=$(stat -Lc '%d:%i' /usr/bin/onyx-server)
    [ "$(stat -Lc '%d:%i' "/proc/$daemon_pid/exe")" = "$target_inode" ] || fail helix_exec
    tr '\000' '\n' < "/proc/$daemon_pid/cmdline" | grep -Fx -- '--strict-existing-identity' >/dev/null || fail helix_carry
    if tr '\000' '\n' < "/proc/$daemon_pid/cmdline" | grep -Fx -- '--supervisor' >/dev/null; then fail helix_exec; fi
    fifo=/tmp/onyx-profile/client-$mode.fifo
    mkfifo -m 600 "$fifo" || fail helix_client
    exec 3<> "$fifo"
    nc -w 60 127.0.0.1 16680 < "$fifo" > "$profile_log" 2>&1 &
    client_pid=$!
    printf 'NICK A04Client\r\nUSER a04 0 * :A04 native participant\r\n' >&3
    wait_reply ' 001 A04Client '
    printf 'PING :a04-before\r\n' >&3
    wait_reply 'a04-before'
    grep ' PONG .*a04-before' "$profile_log" >/dev/null || fail helix_client
    client_socket=''
    for fd in /proc/$client_pid/fd/*; do
        link=$(readlink "$fd" 2>/dev/null || :)
        case "$link" in socket:\[*\]) [ -z "$client_socket" ] || socket_fail client_multiple; client_socket=$link;; esac
    done
    [ -n "$client_socket" ] || socket_fail client_absent
    server_socket=''
    # Only fixture TCP state/port is inspected; no credentials or TOML parsing.
    socket_inodes=$(socket_table_inodes /proc/net/tcp /proc/net/tcp6) || socket_fail table_unreadable
    for inode in $socket_inodes; do
        for fd in /proc/$daemon_pid/fd/*; do
            link=$(readlink "$fd" 2>/dev/null || :)
            if [ "$link" = "socket:[$inode]" ]; then [ -z "$server_socket" ] || socket_fail server_multiple; server_socket=$link; fi
        done
    done
    [ -n "$server_socket" ] || socket_fail server_absent
    case "$mode" in
        file)
            # Change only the actual persisted key, then restore exact bytes and
            # custody through ordinary fixture file repair, never live latches.
            cp -p /etc/onyx-server/onyx-server-node.key /tmp/onyx-profile/active-seed.saved
            [ "$seed_value" != 1111111111111111111111111111111111111111111111111111111111111111 ] || fail profile_source
            printf '%s\n' 1111111111111111111111111111111111111111111111111111111111111111 > /etc/onyx-server/onyx-server-node.key
            held_refusal key
            cp -p /tmp/onyx-profile/active-seed.saved /etc/onyx-server/onyx-server-node.key
            ;;
        env)
            cp -p /etc/onyx-server/onyx-server.toml /tmp/onyx-profile/active-config.saved
            # Both bindings exist in this original live process and resolve
            # the same valid identity. Only the actual reference name changes.
            alternate_before=$(tr '\000' '\n' < "/proc/$daemon_pid/environ" | grep -c '^ONYX_A04_ALTERNATE=' || :)
            [ "$alternate_before" = 1 ] || fail helix_carry
            profile_config env "$seed_value" ONYX_A04_ALTERNATE
            held_refusal env
            cp -p /tmp/onyx-profile/active-config.saved /etc/onyx-server/onyx-server.toml
            ;;
        ref)
            cp -p /etc/onyx-server/onyx-server.toml /tmp/onyx-profile/active-config.saved
            printf '[mesh]\nrealm="changed-refusal-realm"\n' >> /etc/onyx-server/onyx-server.toml
            held_refusal realm
            cp -p /tmp/onyx-profile/active-config.saved /etc/onyx-server/onyx-server.toml
            ;;
    esac
    kill -USR2 "$daemon_pid" || fail helix_exec
    i=0
    while ! tr '\000' '\n' < "/proc/$daemon_pid/cmdline" | grep -Fx -- '--supervisor' >/dev/null; do
        i=$((i+1)); [ "$i" -le 200 ] || fail helix_exec
        kill -0 "$daemon_pid" 2>/dev/null || fail helix_exec
        sleep 0.1
    done
    [ "$(sed 's/.*) //' "/proc/$daemon_pid/stat" | awk '{print $20}')" = "$daemon_start" ] || fail helix_exec
    [ "$(stat -Lc '%d:%i' "/proc/$daemon_pid/exe")" = "$target_inode" ] || fail helix_exec
    tr '\000' '\n' < "/proc/$daemon_pid/cmdline" | grep -Fx -- '--strict-existing-identity' >/dev/null || fail helix_carry
    carry_count=$(tr '\000' '\n' < "/proc/$daemon_pid/environ" | grep -c '^ONYX_A04_NODE_SECRET=' || :)
    if [ "$mode" = env ]; then [ "$carry_count" = 1 ] || fail helix_carry
    else [ "$carry_count" = 0 ] || fail helix_carry; fi
    alternate_after=$(tr '\000' '\n' < "/proc/$daemon_pid/environ" | grep -c '^ONYX_A04_ALTERNATE=' || :)
    [ "$alternate_after" = 0 ] || fail helix_carry
    found_client=0; found_server=0
    for fd in /proc/$client_pid/fd/*; do [ "$(readlink "$fd" 2>/dev/null || :)" != "$client_socket" ] || found_client=$((found_client+1)); done
    for fd in /proc/$daemon_pid/fd/*; do [ "$(readlink "$fd" 2>/dev/null || :)" != "$server_socket" ] || found_server=$((found_server+1)); done
    [ "$found_client" = 1 ] && [ "$found_server" = 1 ] || fail helix_socket
    printf 'PING :a04-after\r\n' >&3
    wait_reply 'a04-after'
    grep ' PONG .*a04-after' "$profile_log" >/dev/null || fail helix_client
    [ "$(grep -c ' 001 A04Client ' "$profile_log")" = 1 ] || fail helix_client
    source_snapshot > /tmp/onyx-profile/active-$mode.after || fail profile_source
    cmp -s /tmp/onyx-profile/active-$mode.before /tmp/onyx-profile/active-$mode.after || fail preservation
    if [ "$mode" = file ]; then
        [ "$(sha256sum /etc/onyx-server/onyx-server-node.key | awk '{print $1}')" = "$profile_seed_hash" ] || fail new_identity
    else [ ! -e /etc/onyx-server/onyx-server-node.key ] || fail new_identity; fi
    printf 'QUIT :profile complete\r\n' >&3
    exec 3>&-
    kill "$client_pid" 2>/dev/null || :; wait "$client_pid" 2>/dev/null || :; client_pid=''
    rm -f "$fifo"
    profile_capture || fail identity_capture
    service_op "mode_$mode" stop || fail service_stop
    client_inode=$(printf '%s' "$client_socket" | tr -dc '0-9')
    server_inode=$(printf '%s' "$server_socket" | tr -dc '0-9')
    printf 'ONYX_HELIX %s %s %s %s %s %s strict %s same\n' "$mode" "$daemon_pid" "$daemon_start" "$client_inode" "$server_inode" "$target_inode" "$carry_count"
    printf 'ONYX_PROFILE %s strict socket exe carry pass\n' "$mode"
    profile_log=''
done
unset ONYX_A04_NODE_SECRET seed_value
cp -p /tmp/onyx-profile/config.saved /etc/onyx-server/onyx-server.toml
cp -p /tmp/onyx-profile/confd.saved /etc/conf.d/onyx-server
cp -p /tmp/onyx-profile/seed.saved /etc/onyx-server/onyx-server-node.key
rm -f /etc/onyx-server/profile.key

# Real daemon under the runtime identity; an explicit bounded probe requires
# the identity-load line and proves the existing key, never a replacement, ran.
# /proc/uptime is monotonic boot time. Capture integer milliseconds, then
# require the 5-second watchdog interval with a bounded scheduling margin.
env -u RC_SVCNAME start-stop-daemon --start --user onyx-server:onyx-server --chdir /var/lib/onyx-server --exec /usr/libexec/onyx-server/runtime-preflight -- /etc/onyx-server/onyx-server.toml >/dev/null 2>&1 || fail identity_load
probe_start=$(awk '{printf "%.0f", $1 * 1000}' /proc/uptime 2>/dev/null || :)
if (set -o pipefail; timeout 5 su -s /bin/sh onyx-server -c 'cd /var/lib/onyx-server && exec /usr/bin/onyx-server --strict-existing-identity /etc/onyx-server/onyx-server.toml' 2>&1 | head -c 65537 > /tmp/daemon.private); then status=0; else status=$?; fi
probe_end=$(awk '{printf "%.0f", $1 * 1000}' /proc/uptime 2>/dev/null || :)
probe_window=unknown
case "$probe_start:$probe_end" in
    *[!0-9:]*|:*|*:|*:*:*) ;;
    *) if [ "$probe_end" -ge "$probe_start" ]; then
        probe_elapsed=$((probe_end - probe_start))
        if [ "$probe_elapsed" -ge 4000 ] && [ "$probe_elapsed" -le 10000 ]; then probe_window=within; else probe_window=outside; fi
    fi;;
esac
case "$status" in ''|*[!0-9]*) status=255;; esac
[ "$status" -le 255 ] || status=255
[ "$(wc -c < /tmp/daemon.private)" -le 65536 ] || fail identity_capture
identity_class=other
if grep -F 'node identity generated + persisted to ' /tmp/daemon.private >/dev/null 2>&1; then identity_class=generated
else
    grep_status=$?
    if [ "$grep_status" != 1 ]; then identity_class=read_error
    else
        if strict_lines=$(grep -Fxc 'onyx-server: strict service identity source: existing_keyfile' /tmp/daemon.private); then
            if [ "$strict_lines" = 1 ]; then identity_class=strict_validated; fi
        else
            grep_status=$?
            if [ "$grep_status" != 1 ]; then identity_class=read_error; fi
        fi
    fi
fi
remaining=absent
for proc in /proc/[0-9]*/exe; do
    if [ "$(readlink "$proc" 2>/dev/null || :)" = /usr/bin/onyx-server ]; then remaining=present; fi
done
printf 'ONYX_PRIVATE_SERVICE identity probe '
if (set -o pipefail; base64 < /tmp/daemon.private | tr -d '\r\n'); then printf '\n'; else printf '\n'; fail identity_capture; fi
printf 'ONYX_DIAG identity %s %s %s %s\n' "$status" "$identity_class" "$remaining" "$probe_window"
# BusyBox timeout signals the exec-replaced process, not a GNU 124 result.
# Only clean exit or SIGTERM within the measured watchdog window is accepted.
[ "$status" = 0 ] || [ "$status" = 143 ] || fail daemon
[ "$probe_window" = within ] || fail daemon
[ "$identity_class" = strict_validated ] || fail identity_load
[ "$remaining" = absent ] || fail cleanup_daemon
snapshot > /tmp/snapshot.final || fail snapshot
cmp -s /tmp/snapshot.before /tmp/snapshot.final || fail preservation
for proc in /proc/[0-9]*/exe; do
    [ "$(readlink "$proc" 2>/dev/null || :)" != /usr/bin/onyx-server ] || fail cleanup_daemon
done
kill "$syslog_pid" 2>/dev/null || fail cleanup_syslog
wait "$syslog_pid" 2>/dev/null || :
kill -0 "$syslog_pid" 2>/dev/null && fail cleanup_syslog
syslog_pid=''
trap - EXIT
printf 'ONYX_RESULT PASS package\n'
