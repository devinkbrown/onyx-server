# DNS resolution

Onyx Server contains a bounded DNS stub client in `src/proto/dns/`, exposed
through the stable `src/proto/dns.zig` entry point. It asks configured recursive
nameservers for IN A, AAAA, and PTR data. It does not perform iterative recursion,
validate DNSSEC, expand search suffixes, consult the hosts file, or provide DoH,
DoT, EDNS negotiation, or a persistent TCP connection pool. TXT encoding and
legacy message decoding remain available in the wire API; the new lookup engine
does not resolve TXT records.

## Runtime use

`resolveForward`, `resolveReverse`, and `resolveConfirmed` use the new query engine.
The rDNS worker in `src/daemon/rdns.zig` uses a typed PTR-observation and
confirmation operation; the DNSBL worker in `src/daemon/dnsbl_resolver.zig` queries
the same engine directly. Both use its validation, alias traversal, scoped IPv6
transport, TCP fallback, and a whole-job budget capped at five seconds.

The detailed `resolve` API additionally returns the canonical name, addresses or
PTR name, outcome, alias count, and validated TTL. `CachedResolver` owns a bounded
cache and a configuration copy; it clears results when `setConfig` changes that
configuration. These additive interfaces are exercised by local transport tests.
The daemon's rDNS and DNSBL caches have **not** yet been migrated to them, and this
change does not replace those services' cache, expiry, or retry policies.

The POSIX ACME `SystemResolver` now uses `daemon/dns_address_lookup.zig` and
the same validated engine. Its complete A lookup shares a three-second deadline
across four ordered nameservers, CNAME traversal, and TCP fallback. Each endpoint
receives a share of the remaining time; negative answers and errors still permit
a later configured endpoint. It reads the caller-bounded configuration file and
has no public-resolver fallback. Literal addresses bypass that I/O. Windows keeps
its native resolver path. Web Push continues to screen and pin the returned
address before connecting.

POSIX HTTP lookups use that same adapter for A, AAAA, and dual-family resolution.
The caller's budget is clamped to 1–5,000 ms and shared across ordered endpoints,
aliases, and TCP fallback. A dual-family lookup performs A on the caller and AAAA
on one helper thread under the exact same deadline. The helper is always joined
before results are read or borrowed configuration/name storage can expire. Either
family can succeed independently. If the helper cannot start, the lookup performs
A only; it does not run a second sequential lookup. Windows retains its native
resolver policy. Missing or unusable HTTP nameserver configuration does not
silently select a public resolver.

HTTP and ACME read configuration before starting their socket deadline. Native
file reads, thread scheduling, and join scheduling are outside that I/O bound.
These calls still block their caller; this consolidation does not move existing
HTTP or mesh hostname callers off their reactors.

Lookup entry points wait for native socket readiness. New integrations should run
them on resolver workers; the deadline does not make synchronous DNS safe to call
on a server reactor. A
forward-confirmed lookup made through `resolveConfirmed` shares one budget across
PTR and forward confirmation. The daemon rDNS worker also shares one absolute
deadline across both operations and retains the owned PTR observation if forward
confirmation fails or times out. Only a matching forward result becomes a
confirmed hostname.

A complete DNSBL scan shares one deadline across all configured zones, preserving
zone order and the first listing. Each zone receives an equal share of the
remaining time; quick replies leave their unused time for later zones. The
existing fail-open result policy remains: this deadline change does not make
transient failures authoritative negative DNS answers. Scheduler delays are
outside the socket I/O deadline.

## Ownership and modules

| Module | Responsibility |
| --- | --- |
| `message_types.zig`, `wire.zig` | Existing public message types and 512-byte wire codec |
| `name_codec.zig` | Presentation-name validation, canonical keys, bounded compression decoding |
| `response.zig` | Exact question validation, complete section framing, answer ownership and TTL metadata |
| `query_engine.zig` | Attempts, nameserver order, cross-packet aliases, UDP-to-TCP transition |
| `deadline.zig`, `transport.zig` | Absolute monotonic budget and owned native sockets |
| `resolver_config.zig`, `windows_abi.zig` | Host policy discovery and native Windows ABI |
| `resolver.zig` | Existing resolver API and error compatibility |
| `confirmation.zig` | Owned PTR observation and forward confirmation under one deadline |
| `result_cache.zig`, `cached_resolver.zig` | Bounded owned results and a worker-owned cache integration API |
| `cache.zig` | Original forward/PTR cache API retained for existing users |

No lookup result borrows packet storage. Socket creation has close-on-error and
close-on-return ownership; Windows startup/cleanup calls are balanced. POSIX
sockets use close-on-exec, and new Windows transport sockets disable handle
inheritance. Cache storage is allocated during initialization. Cache lookups and
replacement do not allocate; callers serialize access to each cache instance.

## Validation and work limits

A UDP socket is connected to the selected nameserver address, scope, and port,
which constrains incoming datagrams to that peer. Every endpoint attempt uses a
fresh OS-random transaction ID. Replies must match that ID, QR/opcode/reserved-bit
rules, exactly one echoed question, its case-insensitive name, IN class, and query
type. AD/CD bits do not establish DNSSEC authenticity.

A TC reply must pass that envelope check before TCP fallback. Its resource-record
body may be partial. TCP uses the same endpoint and budget, sends the two-byte
length and query together, and handles fragmented prefixes and bodies. It rejects
short and oversized frames. Partial progress, rejected UDP packets, retries, and
CNAME follow-ups cannot renew the overall deadline.

Complete accepted replies are framed through all answer, authority, and additional
records with no trailing bytes. Only requested answer records owned by the final
canonical name produce data. All answer CNAMEs must form the query's unambiguous
chain; loops and unrelated aliases fail closed. Cross-packet traversal also checks
every intermediate target against earlier targets. Authority/additional data never
become address or PTR answers. Unknown record bodies are skipped after framing;
this is not semantic verification of DNSSEC or other unsupported record types.

| Bound | Value |
| --- | --- |
| Whole lookup budget | 1–5,000 ms; scheduler delay is outside this I/O budget |
| Per-attempt budget | Configured timeout, at least 1 ms, within remaining lookup budget |
| Attempts | 1–3 |
| Nameservers | At most 4, in configured order for each attempt |
| Rejected UDP datagrams per endpoint attempt | 16 |
| Complete response | 16 KiB, including TCP; larger replies fail closed |
| All resource records in one response | 128 |
| CNAME aliases over the whole lookup | 16 |
| Returned address/PTR records | At most 8; the first PTR is returned |
| Expanded name | 255 wire bytes / 253 presentation bytes |
| Compression pointer hops per name | 128, with repeated-offset detection |

Without an explicit detailed-API budget, the lookup budget is configured timeout
× bounded attempts × bounded nameservers, capped at five seconds. Arithmetic is
widened before multiplication. A zero configured timeout means one millisecond,
not an unbounded kernel wait. TCP socket I/O is nonblocking on Linux, OpenBSD,
and Windows; readiness waits always use the remaining absolute deadline.

## TTL and cache semantics

Positive lifetime is the minimum across the CNAME chain and terminal RRset.
Earlier aliases age while later packets are awaited. A TTL with its high bit set
is treated as zero, following [RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181#section-8).

NXDOMAIN and NODATA have a cacheable lifetime only when a relevant IN SOA occurs
in the authority section. The closest applicable zone supplies the minimum of
SOA TTL and SOA.MINIMUM, further limited by any alias chain. Missing SOA produces
zero cache lifetime. This follows the authoritative negative-answer model in
[RFC 2308 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc2308).

The new result cache supports 0–4,096 entries, canonicalizes case and terminal
dots, and separates query types. Unaliased NXDOMAIN applies across query types;
NODATA is specific to the query type. NXDOMAIN reached through a CNAME is retained
under that original query's type, because the original CNAME owner exists. Cache
entries expire at their exact monotonic deadline. Zero-TTL and incomplete alias
results are not stored. Positive storage is capped at one day and negative storage
at five minutes. At capacity, the earliest-expiring entry is evicted. Configuration
changes must clear the cache to avoid reusing split-horizon answers under another
nameserver policy. The wrapper conservatively measures cache lifetime from lookup
start, so resolution latency cannot extend it.

SERVFAIL, REFUSED, timeout, malformed replies, and transport errors remain errors;
they are never turned into authoritative negative entries. This stub does not yet
provide a separate transient-failure backoff cache. [RFC 9520](https://www.rfc-editor.org/rfc/rfc9520)
addresses failure caching in recursive resolvers; the authoritative-negative policy
here is not a claim to implement that full recursive-resolver specification.

## Host configuration and compatibility

`ResolverConfig` retains its original field types, order, and defaults:
`nameservers`, `nameserver_scope_ids`, `nameserver_count`, `port`, `timeout_ms`,
and `attempts`. The daemon's `onyx/companion/dns-config/v2` digest and existing
Helix schema are unchanged. The original `ResolveError` set is also unchanged;
legacy wrappers retain their historical timeout mapping for failed or invalid
endpoint replies. Detailed callers can distinguish the richer engine errors.

POSIX discovery reads at most 8 KiB of `/etc/resolv.conf`, retaining complete
lines if the buffer fills. It recognizes exact `nameserver` directives, IPv4 and
IPv6 literals, numeric IPv6 scope IDs, and native Linux/OpenBSD interface names.
Unscoped link-local IPv6 servers and malformed scopes are rejected. Duplicate
address/scope endpoints are removed. `options timeout:` is bounded to 1–5 seconds
and `attempts:` to 1–3. Search and other resolver options are ignored. The historical
POSIX fallback to 1.1.1.1 and 8.8.8.8 remains when no usable server is discovered;
operators requiring private-only DNS should supply explicit resolver settings.

Windows continues bounded native adapter discovery, choosing usable nameservers
across operational adapters while preserving adapter priority and backup order.
Link-local addresses retain or recover their adapter scope. Discovery failure has
no public-resolver fallback. Named scope parsing in resolv.conf is POSIX-only;
Windows adapter discovery already supplies numeric scopes.

## Verification and operational diagnosis

Tests use controlled loopback servers, not external DNS or production services.
They exercise IPv4/IPv6, peer/ID/question rejection, partial TC envelopes, TCP
fragmentation and size limits, alias cycles and aging TTLs, negative responses,
cache expiry/pressure/allocation failure, and shared deadlines across real retries.
The ordinary `dns` module filter also discovers rDNS, DNSBL, and relevant existing
codec/consumer tests. Real worker regressions also cover delayed PTR plus silent
confirmation, eight silent DNSBL zones, and a last-zone listing after earlier
silence. HTTP tests require both real A and AAAA questions before emitting either
answer, reject a deliberately serialized implementation, and check partial-family
results, helper-start failure, backup order, and the shared deadline. ACME tests
exercise its real resolver callback against incorrect IDs/questions and silent
endpoints. The UDP/TCP fixture retries at most eight exact port-collision failures,
closing both owned sockets between attempts; other setup errors remain failures.
Run Debug and safe-mode focused gates with the repository's
Zig compiler, plus supported-platform compile checks.

A failed legacy lookup commonly surfaces as `Timeout`; use the detailed API's
error/outcome when the caller needs to distinguish server failure, unsupported
response size, missing data, or invalid configuration. A successful reply can
have zero cache lifetime. Repeated misses with zero lifetime are expected for
zero-TTL records and negative replies lacking an applicable SOA. For TCP failures,
check that the configured resolver permits TCP on the same port as UDP. The TCP
framing policy follows [RFC 7766 section 8](https://www.rfc-editor.org/rfc/rfc7766#section-8).

## Accepted worker-job ownership

The rDNS and DNSBL workers reserve a cache row only after queue admission succeeds.
Queued and active jobs pin their rows against eviction, including a DNSBL row
whose synchronous remembered verdict becomes visible before its accepted probe
finishes. Completion releases that reservation under the resolver mutex.

Historical checkpoints can contain pending rows with no matching FIFO job.
Demand can re-admit such work, and a bounded worker scan repairs at most one row
per boundary. If a historical FIFO head has no row and every row is pending,
one unreserved orphan may run first to create a reclaimable row; the existing
FIFO bytes and relative order remain unchanged. Capture refuses an active job,
and restore reconstructs runtime reservations from the validated FIFO. These
repairs preserve the existing checkpoint layout and do not infer work ownership
from timestamps or change the legacy cache's thirty-minute lifetime policy.
