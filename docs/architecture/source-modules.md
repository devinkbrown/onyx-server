# Source-module ownership

The stable entry files below expose canonical types and functions through aliases.
Implementation files sit beside each entry in a same-named directory. A facade
owns no duplicate mutable state. Command dispatch and runtime module registration
are separate systems described in [World, dispatch and modules](02-world-dispatch-modules.md).

| Entry | Implementation boundaries | Ownership rule |
| --- | --- | --- |
| `src/daemon/server.zig` | Configuration values in `server_config.zig`; native upgrade value contracts in `native_upgrade_contracts.zig`; Linux keepalive values in `client_socket_policy.zig` | Runtime ownership and transaction bodies remain in the server. This is a partial extraction, with canonical aliases preserving callers. |
| `src/proto/dns.zig` | Wire/name validation, response interpretation, query deadlines and transport, configuration, result cache, confirmation | Results own their names and addresses; every socket and retry remains inside its absolute deadline. See [DNS](dns.md). |
| `src/proto/lotus.zig` | Retained-message store, canonical types, checkpoint codec, and history/exact-once tests | Keep wire definitions canonical and preserve protocol identities. |
| `src/proto/ircx_prop_store.zig` | Property contracts, storage operations, and codecs | Retain property authorization and canonical encoding at their existing boundaries. |
| `src/daemon/store.zig` | Storage owner, records, WAL/snapshot codecs, platform file custody, and focused tests | Prepare fallible state before durable writes; publish prepared mutations without allocation. |
| `src/daemon/services.zig` | One owner plus typed account, credential, channel, session, device, and operator domains | Domain contexts borrow original field addresses. They do not copy mutable fields before acquiring the original lock. |
| `src/daemon/relay_v2_event_log.zig` | Event-log owner, rows, checkpoint codec, and tests | Keep canonical event bytes and accepted custody together; decoding must not partially publish. |
| `src/daemon/attachment_delivery_spool.zig` | Spool owner, record model, policy, strict checkpoint codec, and tests | Prepared batches and attachment transfers remain with the owning spool and its no-fail commit boundary. |
| `src/daemon/mail_sender.zig` | One mail worker, message assembly, relay resolution, socket/TLS exchange, snapshots, and retained failure-journal checks | Accepted jobs and ambiguous failure receipts stay with the worker; private journal identity and publication order remain unchanged. |
| `src/daemon/http_fetch.zig` | Request policy, URL parsing, TLS exchange, DNS resolution, native sockets, and Windows resolver ABI | Preserve resolved-address pinning, TLS identity, native callback lifetime, and owned socket cleanup. |

## Choosing a home for a change

Use a leaf when the change concerns its existing responsibility. Keep ownership,
transaction boundaries, locks, and callback identity on the canonical owner. A
large function is not a reason to copy an owner into a generic context or move
its mutable state into a second object. For Services domains, an address-only
view of the required fields makes borrowing explicit while retaining the original
lock and publication order.

A type used by several leaves has one definition and aliases at its entry point.
Do not duplicate a struct merely because its fields currently match: Zig type
identity and callback signatures are part of the contract. Keep platform ABI
containers lazy where unsupported targets cannot analyze their declarations.

Sibling visibility is an implementation boundary. Keep additional helper names
off the facade unless callers need a supported API. Keep private owner methods
private; small white-box tests can remain beside them. Larger groups of tests
live in topical test modules and are explicitly imported by the facade's test
block. Production modules must not depend on test fixtures.

## Reviewing a split

Compare public names, canonical type layouts/defaults, function bodies, checkpoint
bytes, and ownership order before and after extraction. Check the local import
graph for new cycles rather than assuming that adding directories removes the
repository's existing dependency cycles. Preserve all named tests and confirm
their discovery through the project harness.

Use module-prefix test filters, such as `daemon.services`, instead of requiring
`.test.` immediately after the old facade name: moved tests acquire additional
namespace components. Run the gate selector on every changed path, including new
leaves. Anonymous facade registration blocks can increase the count; missing
named tests cannot be explained away by a higher total.

These boundaries cover the listed families. The remaining large server and
protocol files still require separate ownership and extraction work; this map
is not a claim that the entire repository has been decomposed.
