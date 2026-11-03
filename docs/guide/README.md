# Operator and developer guides

Choose the guide for the action you are taking. Current configuration keys and
command syntax belong to the [reference](../reference/commands/_index.md) and
[reference TOML](../../etc/onyx-server.reference.toml); live hosts, versions and
hashes belong to [production paths](../ops/onyx-server-paths.md). Historical
pass counts and roadmap completion are evidence for their recorded source,
not a guarantee about a new checkout.

| Task | Guide | Result to verify |
| --- | --- | --- |
| Try one local node | [Quickstart](00-quickstart.md) | Explicit config, loopback/client registration and PONG |
| Build or cross-compile | [Build](build.md) | Exact compiler/target and intended artifacts; cross-build is not native acceptance |
| Create or assess a config | [Setup](setup.md) | Typed validation, private exported material and accurate preview scope |
| Diagnose a candidate | [Doctor](diagnostics.md) | Redacted checks with unknown/skipped observations preserved |
| Install Linux supervision | [OpenRC/systemd](service-management.md) | Effective account/CWD, validated start/reload and actual runtime sandbox |
| Operate on Alpine | [Alpine](alpine.md) | Native musl runtime, private state, bounded process/recovery evidence |
| Operate on Windows | [Windows](windows.md) | Native IOCP, private directories and platform-specific service/Helix acceptance |
| Configure public TLS | [TLS/STS](tls.md) | Trusted certificates, hostname checks, correct listener and optional kTLS attachment |
| Configure a mesh | [Mesh/S2S](mesh.md) | Identity/trust roots, durable guest presence and secured convergence |
| Administer policy | [Operators](operators.md) | Connection classes, permissions, events and current command reference |
| Preserve persistent state | [Persistence](persistence.md) | Coherent WAL/snapshot custody, declared backup scope and restore drill |
| Plan a compatible upgrade | [Helix](upgrade.md) | Exact capability/state relation and real physical-client preservation |
| Iterate and release | [Testing](testing.md) | Smallest useful gate, then exhaustive retained counts and release acceptance |

For a real deployment, enter through the [release runbook](../RUNBOOK.md), then
use the [mesh acceptance checklist](../ops/mesh-metrics-deploy-checklist.md).
Installing a service or passing static preflight does not establish public
TLS, secured mesh, reusable-session or media readiness. A cold restart drops
TCP connections and has different token/custody guarantees from Helix.

For candidate artifact generation, independent reproduction, checksums, optional
signing and container staging, use [packaging](../../packaging/README.md).
The [signed Alpine package profile](../../packaging/alpine/README.md) remains a
separate disposable-guest development boundary, with its own pending acceptance.

Source review: these guides track `build.zig`, `build.zig.zon`, the typed
configuration/parser/boot projection, daemon and CLI handlers, shipped service
kits and bounded acceptance tools. Source links identify current implementation;
[the dated release audit](../audit/release-and-test-speed-2026-11-03.md) identifies
what was actually tested and deployed.
