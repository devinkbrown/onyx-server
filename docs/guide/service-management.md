# OpenRC and systemd service management

The Linux package stages both supervisor kits. Install one kit for the host's
actual init system. Staging or running the setup wizard does not enable a
service. The wizard describes these templates; it does not verify account,
filesystem, kernel, supervisor, listener or secured mesh readiness.

Both kits run the daemon in the foreground with a dedicated account, private
state and configuration preflight. OpenRC uses `supervise-daemon` with a
five-second respawn delay and three-respawn budget within 60 seconds. systemd
uses `Restart=on-failure` with two seconds between attempts and at most five
starts in 60 seconds. Exhausted budgets require investigation and explicit
recovery; do not automate a repeated reset of failed state. The 30-second
termination grace allows normal SIGTERM shutdown before forced termination.

On native POSIX builds, SIGTERM and SIGINT request orderly daemon cleanup,
including joined workers and recording finalization. A cold restart still drops
TCP attachments. Follow the [cold-restart custody contract](../RUNBOOK.md#cold-restart)
before stopping an active MESSAGE_V2 node; process exit alone does not establish
that every queued mesh event reached its recipient.

## Provisioning and paths

Create the system account and group `onyx-server` using the host's account
management tools, with no interactive login and home `/var/lib/onyx-server`.
Install the reviewed executable, preserve its previous artifact, and prepare
the node's actual TOML and keys before enabling a service. Defaults are:

| Setting | OpenRC | systemd |
| --- | --- | --- |
| Executable | `/usr/bin/onyx-server` | `/usr/local/bin/onyx-server` |
| Config | `/etc/onyx-server/onyx-server.toml` | same |
| Account/group | `onyx-server:onyx-server` | same |
| Working state | `/var/lib/onyx-server` mode `0700` | same |
| Runtime directory | OpenRC's supervisor-managed state | `/run/onyx-server` mode `0700` |
| Logs | syslog `daemon.info` / `daemon.err` | journal identifier `onyx-server` |

Keep executables, service definitions and config parent directories owned by
root. Keep config root-owned and group-readable by the service account
(`0640`); keys must be accessible only to that account and administrators.
Persistent state belongs to the service account. Both kits apply umask `0077`.
Relative data/key paths resolve from the working state directory. Resolve
`env:` secrets in the service environment and `@file:` secrets with the
service's actual read permissions. Avoid putting secrets in process arguments.
Never replace an existing node's config, cloak keys or identity with the
reference template during an upgrade.

An example first-install directory layout, run as root after creating the account:

```sh
install -d -m 0750 -o root -g onyx-server /etc/onyx-server
install -d -m 0700 -o onyx-server -g onyx-server /var/lib/onyx-server
# Install your reviewed node-specific TOML, not a default identity:
install -m 0640 -o root -g onyx-server candidate.toml /etc/onyx-server/onyx-server.toml
```

Validate as the service identity from the intended working directory before
first start. systemd automatically applies its configured identity and sandbox
to both startup and reload preflight. OpenRC uses util-linux `setpriv` to run its one-shot preflight with the selected
UID, explicit primary group and initialized supplementary groups, from the
daemon working directory. Install Alpine's `setpriv` package (`apk add setpriv`)
before starting the kit; a missing launcher fails closed before any upgrade
signal. The launcher preserves the configured service environment, including
secret references, and prevents new privileges. Avoid HOME-dependent secret
paths; configure explicit private paths.
Startup preflight does not create an io_uring reactor or prove port access.

## OpenRC installation and operations

Install `etc/openrc/onyx-server` executable at `/etc/init.d/onyx-server` and
its `.confd` template at `/etc/conf.d/onyx-server` only on first installation.
Preserve existing conf.d settings on upgrades. Set `command`, `config`,
`command_user` and `directory` there for custom hosts. These values are trusted
shell configuration; use absolute paths without shell metacharacters. Do not
copy systemd's home-directory deployment settings into the generic template.

```sh
rc-service onyx-server checkconfig
rc-service onyx-server start
rc-service onyx-server status
rc-update add onyx-server default
# SIGTERM with a bounded drain period, then forced termination if necessary:
rc-service onyx-server stop
```

`checkconfig` works while stopped or started; `reload` is available only while
started. Foreground supervision owns the daemon PID: do not add backgrounding,
`--make-pidfile`, a daemon PID file, or custom `start`/`stop` wrappers. The
supervisor's PID is distinct from the child PID. Retain syslog and configure
retention/rate limits. Preserve the respawn budget's relationship to its delay
when overriding the policy; an excessively short period can allow endless
restarts. See the [OpenRC supervisor guide](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md)
and [native options](https://github.com/OpenRC/openrc/blob/master/man/openrc-run.8).

When migrating an existing start-stop-daemon installation, first record the
actual PID, binary/config paths, UID/GID, working directory and logs. Stop that
instance through its existing kit, verify it exited, then install the reviewed
supervisor script and preserved conf.d settings and start it. OpenRC `zap`
only clears bookkeeping; it does not stop a daemon. A stale `starting` marker
requires process inspection before clearing it, so a second daemon cannot be
started on top of a surviving instance. Migrate one mesh node at a time.

## systemd installation and operations

Install the unit under `/etc/systemd/system/onyx-server.service` for a managed
local installation or the package's vendor unit directory. Use a drop-in for
host-specific paths and identities. When changing an executable/config, reset
and replace **all three** command lists to keep startup and reload aligned:

```ini
[Service]
ExecStartPre=
ExecStartPre=/srv/onyx/onyx-server --check-config /srv/onyx/node.toml
ExecStart=
ExecStart=/srv/onyx/onyx-server /srv/onyx/node.toml
ExecReload=
ExecReload=/srv/onyx/onyx-server --check-config /srv/onyx/node.toml
ExecReload=/bin/kill -USR2 $MAINPID
```

Review `User`, `Group` and `WorkingDirectory` together. A host running from
`/home/...` also needs an explicit `ProtectHome=false` override; default
`ProtectSystem=strict` permits writes to the managed state/runtime directories.
Grant only the additional writable paths that the actual deployment requires.
StateDirectory changes ownership of its managed directory: review ownership
before adapting an existing account or shared location.

```sh
systemd-analyze verify /etc/systemd/system/onyx-server.service
systemctl daemon-reload
systemctl enable --now onyx-server
systemctl status onyx-server
journalctl -u onyx-server -n 100 --no-pager
```

`Type=exec` catches executable/identity setup failure, but does not indicate IRC
or mesh readiness. Inspect logs and probe clients/secured links after startup.
After correcting a failed startup or crash loop, use `systemctl reset-failed
onyx-server` and then start it explicitly.

The unit grants no capabilities by default: IRC ports 6667/6697 are above 1023.
If configuring a port below 1024, review a drop-in adding
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. Review all required paths before
weakening filesystem restrictions. Keep io_uring, memfd, descriptor execution,
process creation and pidfd operations available for the pure-Zig reactor and
Helix. The unit explicitly adds required native calls to the system service
allowlist because syscall group membership varies by systemd release. Verify
actual daemon startup and upgrade on the target kernel/systemd; a parser check
alone does not exercise seccomp or kernel policy.

## Validated Helix requests and release acceptance

`rc-service onyx-server reload` and `systemctl reload onyx-server` first run
candidate `--check-config` and send USR2 only if validation succeeds. This
requests a Helix image upgrade. Config-only IRC REHASH is a different operation.
Preflight failure leaves the running instance unsignalled. The candidate binary
must already be staged atomically at the configured executable path, with its
previous artifact retained and compatibility reviewed under the
[release procedure](../RUNBOOK.md).

A successful reload command means the signal was delivered, not that Helix
completed. The daemon may reject an incompatible candidate transactionally.
Neither kit implements synchronous reload acknowledgement, and reload must not
be used as an ordering barrier for dependent services. See
[systemd's reload semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#ExecReload=).
Verify the resulting image/version, daemon upgrade outcome, existing-client
continuity, and secured mesh convergence before accepting the deployment.
Restart performs a cold boundary and disconnects attached clients. Use the
explicit release fallback decision when Helix refuses an incompatible target.

## Isolated kit checks

```sh
mkdir -p .zig-cache/cloak-tmp
TMPDIR="$PWD/.zig-cache/cloak-tmp" python3 -B tools/alpine_openrc_smoke.py
TMPDIR="$PWD/.zig-cache/cloak-tmp" python3 -B tools/systemd_service_smoke.py
```

The OpenRC checks exercise shell functions, native checkpath and the installed
supervisor adapter while intercepting process launch. systemd checks exercise
the unit's actual preflight/reload command lists against stub executables,
including failed/missing candidates, and run `systemd-analyze verify` when
available. No test controls production services or opens daemon listeners.
These checks establish kit behavior; actual account transitions, crash recovery,
kernel sandbox compatibility and Helix client preservation require runtime
acceptance on the intended host. See [Alpine operation](alpine.md) for native
process/recovery tests and their coverage limits.
