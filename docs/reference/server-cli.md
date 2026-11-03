# Onyx Server host command line

These commands run on the host, not on an IRC connection. The
[IRC command index](commands/_index.md) covers client verbs; the
[Armor CLI](armor-cli.md) is a separate executable. The active entry-point parser
is [src/main.zig](../../src/main.zig); `onyx-server --help` prints the built
revision's usage.

## Modes, side effects and detailed guides

| Invocation | Purpose and important boundary | Detailed documentation |
|---|---|---|
| `onyx-server CONFIG_PATH` | Boot the daemon with that explicit config. It opens configured listeners/stores and may connect to peers. Relative state paths use the applicable working-directory/config rules. Invalid explicit input is fatal. | [Quickstart](../guide/00-quickstart.md), [configuration](config.md) |
| `onyx-server` | Boot using the built-in/default selection. This can bind default ports; it is not a harmless version or syntax check. | [Runbook](../RUNBOOK.md) |
| `--help`, `-h` | Print top-level usage and exit. | This page |
| `--version`, `-v` | Print the embedded source-version stamp and exit. Test-only stamps do not identify production artifacts. | [Build](../guide/build.md) |
| `--check-config PATH [--against RUNNING_TOML]` | Parse/project/preflight explicit config without starting listeners or dialing mesh. Filesystem, identity and platform checks can still inspect/open configured resources. `--against` also compares configured listeners against the supplied baseline file; it does not interrogate arbitrary live state. | [Configuration](config.md), [runbook](../RUNBOOK.md#pre-deploy-config-validation) |
| `--check-service-identity PATH` | Service/startup identity preflight. It does not mean every listener, sandbox syscall or remote peer will work after launch. | [Service kits](../guide/service-management.md) |
| `--strict-existing-identity PATH` | Daemon-start variant that requires the expected existing identity instead of silently creating/replacing it. This starts a daemon; it is not an offline check. | [Service kits](../guide/service-management.md), [Windows](../guide/windows.md) |
| `--initialize-guest-issuer CONFIG` | Explicit offline initialization of the configured guest issuer material. This is a write operation with private-material validation, not an ordinary config preview. | [Guest/issuer configuration](config.md) |
| `--init-private-dir PATH` | Windows private-directory creation/validation helper. Platform-specific access-control handling is part of its contract. | [Windows](../guide/windows.md) |
| `setup CONFIG [--service auto\|openrc\|systemd\|foreground] [--json]` | Produce validated setup/service plans; preview does not automatically install the service. | [Setup](../guide/setup.md) |
| `setup --new [--profile private\|community\|media] [--interactive] [--export NEW_TOML \| --draft NEW_JSON]` | Build/review a proposed configuration, optionally saving a new private export or draft under explicit publication rules. | [Setup](../guide/setup.md) |
| `setup --resume PRIVATE_DRAFT [--interactive] [--export NEW_TOML]` | Resume a validated saved draft. Edits and exports have distinct persistence behavior; cancellation is not implicit publication. | [Setup](../guide/setup.md) |
| `doctor CONFIG [METRICS_URL \| --peer-config PATH] [--json]` | Redacted diagnostics from configuration and the selected live/offline peer source. A healthy-looking plan is not proof of public reachability or a completed deployment. | [Diagnostics](../guide/diagnostics.md) |
| `--restore-drill BACKUP_DIR --into SCRATCH_DIR` | Validate the backup set and reopen its account snapshot into a scratch restore. It writes scratch files without booting a serving daemon; exclusions are explicit. | [Persistence](../guide/persistence.md), [configuration](config.md#backup) |
| `session-fences export CONFIG --baseline OFFLINE_DIR --issuer KEY --output NEW_POLICY` | Export the bounded signed fence-policy material against explicit offline inputs. It does not complete mesh-wide retirement by itself. | [Retirement contract](../design/session-fence-retirement-v1.md), [credential domains](credential-domains.md) |
| `cloak-audit --kind KIND --input PRIVATE_CHECKPOINT --witness PRIVATE_JSON [--checkpoint-output NEW_FILE]` | Audit `access`, `saccess`, `akick`, `ward`, `world`, or supported record forms using explicit private witnesses. It does not recreate absent historical keys or prove unverifiable attribution. | [Host cloaking](host-cloaking.md) |
| `acme-issue ...` | Out-of-band certificate issuance; it can contact configured ACME infrastructure and write issued material. Use its actual option parser and the TLS guide; issuance is not a daemon restart. | [TLS](../guide/tls.md), [ACME runner](../../src/daemon/acme_runner.zig) |
| `delegated-credential inspect\|validate ...` | Inspect or validate the supplied delegated-credential material under its explicit certificate/time/signature inputs. Inspection alone is not trust validation. | [TLS](../guide/tls.md), [configuration](config.md#tls) |

`--supervisor` is a Helix handoff mechanism with authenticated carried state;
it is not a shortcut for ordinary startup. Do not hand-construct inherited state
or treat a missing mandatory relation as an optional feature. The
[upgrade architecture](../architecture/04-upgrade-wasm.md) defines its boundary.

## Validation example

```sh
./zig-out/bin/onyx-server --version
./zig-out/bin/onyx-server --check-config /etc/onyx-server/onyx-server.toml
./zig-out/bin/onyx-server --check-config /path/to/candidate.toml --against /path/to/running-baseline.toml
```

Run preflight under the service account and applicable working directory. A
configuration parser success does not exercise the eventual systemd seccomp
sandbox, certificate handshake, port ownership or mesh negotiation. Conversely,
`REHASH` may apply supported mutable fields while leaving startup-only listener
changes unapplied; use the documented dry/compatibility workflow rather than
assuming one all-or-nothing reload rule.

## Preview and diagnostic examples

```sh
./zig-out/bin/onyx-server setup packaging/onyx-server.quickstart.toml --service foreground --json
./zig-out/bin/onyx-server doctor /path/to/node.toml --json
./zig-out/bin/onyx-server doctor /path/to/node.toml --peer-config /path/to/peer.toml --json
```

The first command is a plan. The doctor commands report their input provenance
and uncertainty; the offline peer-file variant cannot establish a secured live
link. For an interactive new configuration, use `setup --new --interactive`,
review it, then deliberately export to a new file. Do not put secrets directly
in copied command examples or tracked drafts.

## Exit and signal behavior

Top-level usage errors normally exit `2`; an operation/preflight failure exits
nonzero, and successful offline commands exit without serving. Read the mode's
specific result rather than treating every non-daemon path as side-effect-free.
Ordinary foreground/interactive tools keep their documented signal behavior;
the Linux daemon owns a separate TERM/INT stop latch that is carried across
compatible Helix execution. Service supervision and restart behavior are in the
[service guide](../guide/service-management.md).
