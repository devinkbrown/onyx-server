#!/bin/sh
# Disposable VM only. Never print the captured syslog or private canary.
set -eu
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
umask 077
fail() { echo "ONYX_RESULT FAIL $1"; exit 1; }
cleanup() {
    rc-service onyx-server stop >/dev/null 2>&1 || :
    [ -z "${syslog_pid:-}" ] || kill "$syslog_pid" 2>/dev/null || :
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || fail prerequisites
for cmd in rc-service supervise-daemon syslogd logger nc timeout awk od sha256sum; do command -v "$cmd" >/dev/null || fail prerequisites; done
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
addgroup -S onyx-server >/dev/null 2>&1 || fail account
adduser -S -D -H -G onyx-server onyx-server >/dev/null 2>&1 || fail account
cp /fixture/onyx-server /usr/bin/onyx-server
cp /fixture/service /etc/init.d/onyx-server
cp /fixture/confd /etc/conf.d/onyx-server
chmod 755 /usr/bin/onyx-server /etc/init.d/onyx-server
rc-update -u >/dev/null 2>&1 || fail openrc
printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
timeout 20 rc-service networking start >/dev/null 2>&1 || fail networking
chmod 700 /var/lib/onyx-server
chown onyx-server:onyx-server /var/lib/onyx-server
chown root:onyx-server /etc/onyx-server
chmod 750 /etc/onyx-server
cat > /etc/onyx-server/onyx-server.toml <<'CONFIG'
[node]
id = 1
[network]
server_name = "alpine.fixture.local"
[listen]
host = "127.0.0.1"
irc = 16680
ws = 0
[limits]
num_shards = 1
[metrics]
bind = "127.0.0.1"
listen = 19130
CONFIG
chmod 600 /etc/onyx-server/onyx-server.toml
chown onyx-server:onyx-server /etc/onyx-server/onyx-server.toml
/usr/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml >/dev/null 2>&1 || fail config
su -s /bin/sh onyx-server -c 'cd /var/lib/onyx-server && exec /usr/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml' >/dev/null 2>&1 || fail service_user_config
boot_mark=$(cut -d. -f1 /proc/uptime 2>/dev/null || :)
timeout 20 rc-service onyx-server start >/dev/null 2>&1 || fail service_start
[ -r /run/supervise-onyx-server.pid ] || fail supervisor
supervisor=$(cat /run/supervise-onyx-server.pid)
case "$supervisor" in ''|*[!0-9]*) fail supervisor;; esac
[ "$(basename "$(readlink "/proc/$supervisor/exe")")" = supervise-daemon ] || fail supervisor
# Bind the real non-root daemon and the exact shipped stderr logger to the
# same supervisor and pipe, retaining process start times to reject PID reuse.
stat_fields() { sed 's/.*) //' "/proc/$1/stat"; }
start_time() { stat_fields "$1" | awk '{print $20}'; }
supervisor_start=$(start_time "$supervisor")
case "$supervisor_start" in ''|*[!0-9]*) fail supervisor;; esac
expected_uid=$(id -u onyx-server)
[ "$expected_uid" -gt 0 ] || fail daemon_identity
daemon=''; logger_pid=''; logger_pipe=''
for child in $(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null); do
    [ -r "/proc/$child/cmdline" ] || continue
    if [ "$(readlink "/proc/$child/exe" 2>/dev/null || :)" = /usr/bin/onyx-server ] &&
       [ "$(stat -c %u "/proc/$child" 2>/dev/null || :)" = "$expected_uid" ]; then
        tr '\000' '\n' < "/proc/$child/cmdline" > /tmp/onyx-private/argv
        if awk 'NR==1 && $0!="/usr/bin/onyx-server" {exit 1} NR==2 && $0!="/etc/onyx-server/onyx-server.toml" {exit 1} END {if (NR!=2) exit 1}' /tmp/onyx-private/argv; then
            [ -z "$daemon" ] || fail daemon_identity
            daemon=$child
        fi
    fi
done
[ -n "$daemon" ] || fail daemon_identity
daemon_start=$(start_time "$daemon")
daemon_pipe=$(readlink "/proc/$daemon/fd/2")
case "$daemon_pipe" in 'pipe:['*']') ;; *) fail pipe_identity;; esac
for child in $(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null); do
    for pid in "$child" $(cat "/proc/$child/task/$child/children" 2>/dev/null || :); do
        [ -r "/proc/$pid/cmdline" ] || continue
        tr '\000' '\n' < "/proc/$pid/cmdline" > /tmp/onyx-private/argv
        if awk 'NR==1 {sub(/^.*\//, ""); if ($0 != "logger") exit 1} NR==2 && $0!="-t" {exit 1} NR==3 && $0!="onyx-server" {exit 1} NR==4 && $0!="-p" {exit 1} NR==5 && $0!="daemon.err" {exit 1} END {if (NR!=5) exit 1}' /tmp/onyx-private/argv; then
            pipe=$(readlink "/proc/$pid/fd/0" 2>/dev/null || :)
            if [ "$pipe" = "$daemon_pipe" ]; then
                [ -z "$logger_pid" ] || fail logger_identity
                logger_pid=$pid; logger_pipe=$pipe
            fi
        fi
    done
done
[ -n "$logger_pid" ] || fail logger_identity
logger_start=$(start_time "$logger_pid")
[ -n "$daemon_start" ] && [ -n "$logger_start" ] || fail pipe_identity
metric() {
    if printf 'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n' | timeout 3 nc 127.0.0.1 19130 > /tmp/onyx-private/metrics; then nc_class=success
    else nc_status=$?; if [ "$nc_status" = 124 ]; then nc_class=timeout; else nc_class=other; fi; return 1; fi
    tr -d '\r' < /tmp/onyx-private/metrics > /tmp/onyx-private/metrics.clean
    a=$(awk '$1=="onyx_connection_diagnostics_total{event=\"accepted\"}" {n++; v=$2} END {if(n==1 && v ~ /^[0-9]+$/) print v; else exit 1}' /tmp/onyx-private/metrics.clean) || return 1
    s=$(awk '$1=="onyx_connection_diagnostics_sink_suppressed_total" {n++; v=$2} END {if(n==1 && v ~ /^[0-9]+$/) print v; else exit 1}' /tmp/onyx-private/metrics.clean) || return 1
}
i=0
until metric; do
    i=$((i+1))
    if [ "$i" -gt 30 ]; then
        daemon_class=unknown
        if [ ! -e "/proc/$daemon" ]; then daemon_class=gone
        elif [ -r "/proc/$daemon/stat" ]; then
            observed=$(start_time "$daemon" 2>/dev/null || :)
            case "$observed" in ''|*[!0-9]*) ;; *) if [ "$observed" = "$daemon_start" ]; then daemon_class=alive; else daemon_class=changed; fi;; esac
        fi
        if rc-service onyx-server status >/dev/null 2>&1; then service_class=started
        else status=$?; if [ "$status" = 3 ]; then service_class=stopped; else service_class=unknown; fi; fi
        http_class=absent
        if [ -r /tmp/onyx-private/metrics ]; then
            first=$(head -n 1 /tmp/onyx-private/metrics | tr -d '\r')
            case "$first" in 'HTTP/1.0 200 '*|'HTTP/1.1 200 '*) http_class=200;; HTTP/*) http_class=other;; esac
        fi
        # Report exactly the same cardinality and decimal rule as metric().
        metric_class() {
            awk -v wanted="$1" '
                { gsub(/\r/, ""); if ($1 == wanted) { n++; value=$2 } }
                END { if (n==0) print "missing"; else if (n>1) print "duplicate";
                      else if (value ~ /^[0-9]+$/) print "valid"; else print "malformed" }
            ' /tmp/onyx-private/metrics
        }
        accepted_class=$(metric_class 'onyx_connection_diagnostics_total{event="accepted"}') || accepted_class=missing
        suppressed_class=$(metric_class 'onyx_connection_diagnostics_sink_suppressed_total') || suppressed_class=missing
        if grep -F 'onyx-server: /metrics endpoint disabled (' /tmp/onyx-private/syslog >/dev/null 2>&1; then disabled_class=present
        else status=$?; if [ "$status" = 1 ]; then disabled_class=absent; else disabled_class=read_error; fi; fi
        printf 'ONYX_DIAG metrics %s %s %s %s %s %s %s\n' "$daemon_class" "$service_class" "$nc_class" "$http_class" "$accepted_class" "$suppressed_class" "$disabled_class"
        # Forensics are metadata only. Treat missing, rotated, oversized or
        # uncorrelated logs as unknown; the original failing oracle remains.
        supervisor_class=unknown; replacement_class=unknown
        if [ ! -e "/proc/$supervisor" ]; then supervisor_class=gone
        elif [ -r "/proc/$supervisor/stat" ]; then
            observed_supervisor=$(start_time "$supervisor" 2>/dev/null || :)
            case "$observed_supervisor" in ''|*[!0-9]*) ;; *)
                if [ "$observed_supervisor" = "$supervisor_start" ]; then supervisor_class=same; else supervisor_class=changed; fi;; esac
        fi
        if [ "$supervisor_class" = same ] && [ -r "/proc/$supervisor/task/$supervisor/children" ]; then
            replacement_class=none
            for candidate in $(cat "/proc/$supervisor/task/$supervisor/children" 2>/dev/null); do
                if [ "$candidate" != "$daemon" ] && [ "$(readlink "/proc/$candidate/exe" 2>/dev/null || :)" = /usr/bin/onyx-server ] &&
                   [ "$(stat -c %u "/proc/$candidate" 2>/dev/null || :)" = "$expected_uid" ]; then replacement_class=present; fi
            done
        fi
        outcome=unknown; outcome_code=0; marker=unknown
        if [ -r /tmp/onyx-private/syslog ] && [ ! -e /tmp/onyx-private/syslog.0 ] &&
           [ "$(wc -c < /tmp/onyx-private/syslog)" -lt 1048576 ]; then
            # Only pinned supervisor message shapes with exact original PID and
            # unique numeric value are accepted; never emit the matching line.
            exit_info=$(awk -v pid="$daemon" '
                /supervise-daemon/ {
                    exit_prefix="pid " pid ", exited with return code "
                    sig_prefix="pid " pid ", terminated by signal "
                    p=index($0,exit_prefix); q=index($0,sig_prefix)
                    if(p) {v=substr($0,p+length(exit_prefix)); if(v ~ /^[0-9]+$/ && v+0<=255) {n++; kind="exit"; code=v+0}}
                    if(q) {v=substr($0,q+length(sig_prefix)); if(v ~ /^[0-9]+$/ && v+0>=1 && v+0<=64) {n++; kind="signal"; code=v+0}}
                }
                END {if(n==1) print kind,code; else print "unknown 0"}
            ' /tmp/onyx-private/syslog) || exit_info='unknown 0'
            set -- $exit_info
            case "${1:-unknown}:${2:-0}" in exit:[0-9]*|signal:[0-9]*) outcome=$1; outcome_code=$2;; esac
            # This marker is deliberately labelled uncorrelated: the default
            # daemon logger does not include physical process identity.
            if grep -F 'panic:' /tmp/onyx-private/syslog >/dev/null 2>&1; then marker=panic
            elif grep -F 'error: OutOfMemory' /tmp/onyx-private/syslog >/dev/null 2>&1; then marker=out_of_memory
            elif grep -F 'error: AccessDenied' /tmp/onyx-private/syslog >/dev/null 2>&1; then marker=access_denied
            elif grep -F 'error: AddressInUse' /tmp/onyx-private/syslog >/dev/null 2>&1; then marker=address_in_use; fi
        fi
        oom=unknown
        # A positive fixed kernel message is PID-matched; lack of a message is
        # unknown because ring retention and read completeness are not proven.
        if (ulimit -f 2048; timeout 3 dmesg > /tmp/onyx-private/kmsg 2>/dev/null) &&
           [ "$(wc -c < /tmp/onyx-private/kmsg)" -lt 1048576 ]; then
            case "$boot_mark" in ''|*[!0-9]*) ;; *)
                oom_match=$(awk -v pid="$daemon" -v minimum="$boot_mark" '
                    { line=$0; if (match(line, /^\[[[:space:]]*[0-9]+(\.[0-9]+)?\]/)) {
                        stamp=substr(line, RSTART+1, RLENGTH-2); gsub(/[[:space:]]/, "", stamp)
                        killed="Killed process " pid "([[:space:]]|$)"
                        victim="oom-kill:.*pid=" pid "([,[:space:]]|$)"
                        if (stamp+0 >= minimum && (line ~ killed || line ~ victim)) found=1
                    }} END {if(found) print "yes"}
                ' /tmp/onyx-private/kmsg) || oom_match=''
                [ "$oom_match" = yes ] && oom=yes ;;
            esac
        fi
        printf 'ONYX_DIAG lifetime %s %s %s %s %s %s\n' "$outcome" "$outcome_code" "$supervisor_class" "$replacement_class" "$marker" "$oom"
        fail metrics_ready
    fi
    sleep 0.1
done
canary=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
[ "${#canary}" = 48 ] || fail canary
base_a=$a; base_s=$s; attempt=0
while :; do
    attempt=$((attempt+1)); [ "$attempt" -le 3 ] || fail burst
    # Exactly 200 bounded sequential real loopback connections. Counters,
    # rather than host timing assumptions, are the suppression oracle.
    start=$(cut -d. -f1 /proc/uptime)
    i=0
    while [ "$i" -lt 200 ]; do
        printf 'PRIVMSG nobody :%s\r\nQUIT :%s\r\n' "$canary" "$canary" | timeout 1 nc 127.0.0.1 16680 >/dev/null 2>&1 || :
        i=$((i+1))
        now=$(cut -d. -f1 /proc/uptime)
        [ $((now-start)) -le 2 ] || break
    done
    end=$(cut -d. -f1 /proc/uptime)
    sleep 1
    metric || fail metrics_read
    da=$((a-base_a)); ds=$((s-base_s))
    if [ $((end-start)) -le 1 ] && [ "$da" -gt 128 ] && [ "$ds" -gt 0 ]; then break; fi
    base_a=$a; base_s=$s
    sleep 1
done
# Capture byte offset after burst; only a later syslog record is a summary.
sleep 2
[ ! -e /tmp/onyx-private/syslog.0 ] || fail log_bound
before=$(wc -c < /tmp/onyx-private/syslog)
printf 'NICK logprobe\r\nUSER logprobe 0 * :probe\r\nQUIT :%s\r\n' "$canary" | timeout 2 nc 127.0.0.1 16680 >/dev/null 2>&1 || :
sleep 1
[ ! -e /tmp/onyx-private/syslog.0 ] || fail log_bound
[ "$(wc -c < /tmp/onyx-private/syslog)" -le 1048576 ] || fail log_bound
tail -c +$((before+1)) /tmp/onyx-private/syslog > /tmp/onyx-private/after
summary=$(awk '/daemon\.err.*onyx-server.*onyx-server: connection / && /suppressed=[1-9][0-9]*$/ {n++} END {print n+0}' /tmp/onyx-private/after)
[ "$summary" -gt 0 ] || fail summary
if grep -F "$canary" /tmp/onyx-private/syslog >/dev/null; then fail canary_leak; else rc=$?; [ "$rc" = 1 ] || fail canary_scan; fi
[ "$(start_time "$daemon" 2>/dev/null || :)" = "$daemon_start" ] &&
[ "$(start_time "$logger_pid" 2>/dev/null || :)" = "$logger_start" ] &&
[ "$(readlink "/proc/$daemon/fd/2" 2>/dev/null || :)" = "$daemon_pipe" ] &&
[ "$(readlink "/proc/$logger_pid/fd/0" 2>/dev/null || :)" = "$logger_pipe" ] || fail pipe_identity
kill -0 "$syslog_pid" 2>/dev/null || fail syslog_died
rc-service onyx-server stop >/dev/null 2>&1 || fail stop
[ ! -e /run/supervise-onyx-server.pid ] || fail stop
kill -0 "$supervisor" 2>/dev/null && fail stop
kill "$syslog_pid" 2>/dev/null || fail syslog_stop
wait "$syslog_pid" 2>/dev/null || :
syslog_pid=''
trap - EXIT
printf 'ONYX_RESULT PASS logger %s %s %s %s\n' "$da" "$ds" "$summary" "$attempt"
