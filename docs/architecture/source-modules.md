# Source-module ownership

The live import graph determines ownership. Several entry files now delegate to
same-named directories; others still own their definitions despite adjacent
extraction candidates. The existence of a directory or a matching struct does
not establish that runtime callers use it. Command registry modules are a
separate system described in [the module system](MODULE-SYSTEM.md).

| Entry | Implementation boundaries | Ownership rule |
| --- | --- | --- |
| `src/daemon/server.zig` | Live daemon configuration, lifecycle and transaction bodies; imports individual typed contracts/helpers as needed | Integrator is the sole writer. Do not assume a nearby candidate configuration file replaces the live `Config` definition. |
| `src/daemon/config_format.zig` | Defines the actual live `Config`, defaults, resolver/error contracts, `parseToml` and tests | Its current implementation does not import `config_format/model.zig` or `projection.zig`. Those adjacent candidates can drift and are not the live configuration authority. |
| `src/proto/dns.zig` | Wire/name validation, response interpretation, query deadlines and transport, configuration, result cache, confirmation | Results own their names and addresses; every socket and retry remains inside its absolute deadline. See [DNS](dns.md). |
| `src/proto/lotus.zig` | Retained-message store, canonical types, checkpoint codec, and history/exact-once tests | Keep wire definitions canonical and preserve protocol identities. |
| `src/proto/ircx_prop_store.zig` | Property contracts, storage operations, and codecs | Retain property authorization and canonical encoding at their existing boundaries. |
| `src/daemon/store.zig` | Storage owner, records, WAL/snapshot codecs, platform file custody, and focused tests | Prepare fallible state before durable writes; publish prepared mutations without allocation. |
| `src/daemon/services.zig` | Live Services owner and account, credential, channel, session, device and operator implementation | Current entry still owns its definitions; the same-named extraction directory is not imported by it. Preserve the original lock and publication order. |
| `src/daemon/relay_v2_event_log.zig` | Event-log owner, rows, checkpoint codec, and tests | Keep canonical event bytes and accepted custody together; decoding must not partially publish. |
| `src/daemon/attachment_delivery_spool.zig` | Live spool owner, record model, policy, strict checkpoint codec and tests | The entry owns its current definitions. Prepared batches/transfers must remain with the same spool and no-fail commit boundary. |
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
