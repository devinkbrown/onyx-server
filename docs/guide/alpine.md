# Alpine Linux operation

Onyx Server supports a native Linux/musl build. The Linux `package` target also
stages an OpenRC service and configuration template alongside the systemd unit;
staging assets does not install, enable, or restart a service.

Use the source-compatible compiler recorded with your release. This checkout
has been exercised with native Zig 0.17.0, whose optimization arguments are
`debug`, `safe`, `fast`, and `small`. An older 0.17 development compiler may
reject language constructs accepted by the release compiler. Record the exact
compiler, CPU baseline, target, and source revision in release evidence.

```sh
zig version
zig build package -Dtarget=x86_64-linux-musl -Dcpu=x86_64 --prefix zig-out/alpine
```

The staged OpenRC files are `etc/init.d/onyx-server` and
`etc/conf.d/onyx-server`. The script expects `/usr/bin/onyx-server`, the service
account/group `onyx-server`, a private configuration at
`/etc/onyx-server/onyx-server.toml`, and writable state in
`/var/lib/onyx-server`. Installation must provision that account and config;
the service deliberately does not create a network identity or choose a cloak
secret on the operator's behalf. Files in `/etc/conf.d` are trusted root-owned
shell configuration, not an interface for untrusted input.

Use the reference TOML to prepare the actual configuration; never overwrite an
existing node's config or identity while installing updated assets. Keep the
configuration and keys readable only by the service account and authorized
administrators. Validate the candidate as the service user as well as checking
the intended directories and network permissions before first start.

The [OpenRC service](../../etc/openrc/onyx-server) uses `supervise-daemon` with
the daemon in the foreground. Startup validates configuration; unexpected
exit has a bounded respawn policy. State directories are private, and stdout
and stderr are sent through `logger` to the configured syslog service. Configure
syslog retention and rate limits for your installation. Review overrides in
`/etc/conf.d/onyx-server` before using nondefault paths or accounts.

Once the reviewed assets have been installed and the service provisioned,
normal OpenRC operations are `rc-service onyx-server start`, `status`, and
`stop`, with `rc-update add onyx-server default` for boot activation. This guide
does not perform those actions. See
[Alpine's init-script guidance](https://wiki.alpinelinux.org/wiki/Writing_Init_Scripts)
and the [OpenRC supervisor guide](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md).

Before installation, run the isolated service contract checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/alpine_openrc_smoke.py
```

The service checks source the repository's service and configuration template in a
temporary workspace. They assert foreground supervision settings, the default
five-second delay and three-respawn/60-second policy, operator overrides, private
state-directory arguments, and refusal after invalid/missing configuration or
state-directory failure, plus validated reload ordering, effective identity launcher arguments and daemon working-directory use. Configuration validation uses a stub daemon. When
installed, native OpenRC `checkpath` also creates and repairs temporary state
to mode `0700` with the invoking user's ownership, and the installed supervisor
shell adapter forwards the service arguments to an intercepted launcher. Native
checks are reported as skipped when those OpenRC components are unavailable.

This harness never invokes `rc-service`, launches `supervise-daemon`, changes
installed service files, or opens daemon listeners. It establishes the service
script's contract and native helper behavior. The cross-UID unreadable-config check runs only in an
isolated root test environment and is skipped by normal non-root runs. The
harness does not establish actual daemon configuration validation or
runtime crash/respawn limits. Complete A03 acceptance still requires an isolated
Alpine VM/container with the packaged daemon and provisioned account: confirm
invalid config prevents start, valid config runs in the foreground, and repeated
crashes exhaust the configured respawn budget before testing explicit recovery.
Capture native service status, child/supervisor identities, restart counts,
state ownership, and logs during that drill.

For an actual native process/recovery check, run the separate smoke as a
non-root user against an explicit freshly built local artifact:

```sh
mkdir -p .zig-cache/alpine-runtime-tmp
TMPDIR="$PWD/.zig-cache/alpine-runtime-tmp" PYTHONDONTWRITEBYTECODE=1 \
  python3 tools/alpine_runtime_smoke.py --binary zig-out/bin/onyx-server
```

The smoke copies the artifact before running it, records its digest/version and
native platform/UID, and uses private temporary state with an explicitly
allocated IPv4 loopback port. It runs real valid/invalid configuration preflight
and rejects actual invalid startup, registers an IRC client and checks PONG,
kills the fixture with SIGKILL, restarts it, and restores an offline state backup
into another private directory for a third boot. Each boot checks the generated
node identity's owner and `0600` mode and verifies its digest remains stable.
The config is mode `0400`; its contents and the copied binary must remain
unchanged. Fixture logs and keys are removed on completion and never printed.
Use a temporary directory with enough space for the copied binary; debug
artifacts may exceed a small `/tmp` filesystem.

This is real native daemon acceptance, with no OpenRC service or mocks. It
establishes IPv4 IRC and private identity/store recovery only. It does not prove
authenticated account mutations survive crashes, a container read-only root,
supervisor respawn behavior, DNS/TLS/IPv6/UDP/WebTransport, descriptor upgrades,
or multi-node session/media convergence. The port reservation must close before
the daemon binds; a collision fails the smoke. See the
[container instructions](../../packaging/README.md#quickstart-docker) for the
non-root image's writable `/data` and read-only config/secret mounts.

For native connection-diagnostic privacy acceptance, run this smaller fixture
against an explicit component artifact:

```sh
TMPDIR="$PWD/.zig-cache/alpine-runtime-tmp" PYTHONDONTWRITEBYTECODE=1 \
  python3 tools/alpine_diagnostics_smoke.py --binary zig-out/bin/onyx-server
PYTHONDONTWRITEBYTECODE=1 python3 tools/alpine_diagnostics_tests.py
```

One temporary non-root daemon registers a real loopback IRC client, answers
PING, and processes QUIT containing a private random marker. The fixture requires
accepted, registered, command-QUIT, and closed diagnostics with physical
connection metadata, verifies each observed diagnostic is shorter than the
1024-byte formatter buffer, and rejects the marker anywhere in captured daemon
output. QUIT diagnostics omit the caller's reason. Command and daemon logs are
private, kernel-limited to one MiB, never printed, and removed with the fixture;
the output contains only a fixed version token and numeric/provenance facts.
The separate four adversarial fixture tests mock child behavior to prove leaked
markers, absent diagnostics, exchange failures, and full logs fail with static
errors and cleanup. Those unit fixtures are not native acceptance.

This native check establishes one QUIT privacy boundary. It does not exhaust
the logging rate budget, test OpenRC `logger` delivery/retention, or establish
redaction for every command or secret. The current typed diagnostic sink has a
128-event-per-second admission budget; counters and bounded recent metadata
are retained independently of sink admission. Rotation and retention of all
other daemon output remain supervisor/operator responsibilities.

OpenRC process status establishes supervision, not mesh readiness. Check the
daemon's metrics/doctor output and established secured links. A TCP-only peer
is insufficient, and neither a successful package build nor a service status
is a multi-client media or session acceptance test.

The shipped `reload` validates the candidate before asking the supervisor to
signal its child with USR2. Success means a request was delivered; verify Helix
completion separately. See [service management](service-management.md) for
installation, migration, permissions and reload acceptance. Helix requires a
compatible verified target, complete mandatory state, rollback preparation, and
the authorized release procedure. The current policy-state handoff boundary
rejects older producers before exec; upgrading across it may require a
separately approved cold boundary.

For deployment on older CPUs, test the generated daemon natively at the chosen
baseline. Compiler emulation can help build tooling; it does not establish
native daemon, socket, or media behavior. Linux currently requires base
`io_uring`; denied or unavailable base support aborts startup with an explicit
reactor error. Optional setup-flag combinations retry on kernel `EINVAL`, and
some optional operations have narrower fallbacks. This is not an epoll/select
fallback for an unavailable base reactor. Configuration preflight alone does
not exercise kernel ring creation. Verify a real native startup under the
intended service/container restrictions without disabling security checks.


Source of truth: `build.zig`, `etc/openrc/onyx-server`, `etc/openrc/onyx-server.confd`, `tools/alpine_openrc_smoke.py`, `tools/alpine_runtime_smoke.py` and `tools/alpine_diagnostics_smoke.py`. Current installed fleet facts live in [production paths](../ops/onyx-server-paths.md); platform-specific tests retain their recorded scope.
