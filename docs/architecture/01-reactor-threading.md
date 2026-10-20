# Reactor and threading

_The live Ringlane io_uring reactor, per-reactor connection state, worker shards, cross-shard delivery, world locking, and the live multithreading status._

The production Linux ring is `src/daemon/ringlane.zig`. The daemon imports it at `src/daemon/server.zig:981`, and `src/daemon/reactor_backend.zig` selects `ringlane.Ring` on Linux. `src/substrate/io/ring.zig` is the same shape of prototype and is not the daemon backend. The production ring sizes the completion queue to at least 256 and requests cooperative task-work. Accept passes `SOCK_CLOEXEC`. It never requests `DEFER_TASKRUN` or `SINGLE_ISSUER`. On Linux each reactor installs one provided-buffer group and arms multishot recv. The completion is copied into the connection buffer before parse or a Helix snapshot, and the pool slice is replenished. Sends are zero-copy except kTLS TX, and the send buffer stays owned until the notification completion. Fixed files are implemented and are not registered for accepted sockets. `registerAll` stays pure bookkeeping. `src/substrate/reactor.zig` is the separate clock seam. Its header still treats submit, poll, accept, recv, and send as future work for that seam.

The socket path is unchanged: accept TCP, receive IRC bytes through the ring, feed complete LF-terminated lines into the command core, and send queued replies back through the ring.

## Ringlane reactor core

This section is the 2026-10-17 source contract. It is not a green full-suite result. A focused Debug compile of the Ringlane filters on that date failed before the later compile fixes, and no later full `zig build test` has been recorded.

| Behavior | Contract | Evidence |
| --- | --- | --- |
| Open | `Ring.init` probes multishot accept and multishot wake-poll, then opens the ring. A probe that cannot decide leaves that operation one-shot. A definitive yes or no is cached for the process. | `src/daemon/ringlane.zig:9`, `src/daemon/ringlane.zig:361` |
| Completion queue | At least 256 entries, four times the submission queue, capped at 32768, then rounded up to a power of two. The default submission queue is 32 and the default reap batch is 256, so the old kernel default of twice the submission queue was too small. | `src/daemon/ringlane.zig:22`, `src/daemon/ringlane.zig:301` |
| Cooperative task work | The first setup attempt requests `IORING_SETUP_COOP_TASKRUN`, `IORING_SETUP_TASKRUN_FLAG`, and `IORING_SETUP_CQSIZE`. Only `error.ArgumentsInvalid` walks a shorter ladder. | `src/daemon/ringlane.zig:321`, `src/daemon/ringlane.zig:332` |
| Closed setup bits | `IORING_SETUP_DEFER_TASKRUN` and `IORING_SETUP_SINGLE_ISSUER` are never passed to the kernel, including when `[io].defer_taskrun` is true. | `src/daemon/ringlane.zig:11`, `src/daemon/ringlane.zig:37` |
| SQPOLL | Opt-in through `[io].sqpoll`. The flag stays on every ladder attempt until the kernel returns `ArgumentsInvalid`. | `src/daemon/ringlane.zig:321` |
| Accept | Multishot accept with `SOCK_CLOEXEC` when the probe succeeded. The arm stays up while `IORING_CQE_F_MORE` is set and clears on the terminal completion. | `src/daemon/ringlane.zig:404` |
| Wake poll | Multishot poll on the reactor eventfd when the probe succeeded. `wake_armed` clears only when MORE is clear. Each completion drains the eventfd. | `src/daemon/ringlane.zig:465`, `src/daemon/server.zig:8375`, `src/daemon/server.zig:8415` |
| Recv and send | Linux with a provided-buffer group uses multishot recv. The bytes are copied into `recv_buf` and the pool slice is replenished before the latch drops. `recv_armed` stays set while `IORING_CQE_F_MORE` is set. `ENOBUFS` rearms instead of closing. Zero-copy send keeps `send_armed` until `IORING_CQE_F_NOTIF`. kTLS stays on one-shot copy recv and send. Fixed files are not on this path. | `src/daemon/ringlane.zig:12`, `src/daemon/server.zig:17125` |
| Overflow | Submit flushes `IORING_SQ_CQ_OVERFLOW` and retries once when the completion queue is overcommitted. | `src/daemon/ringlane.zig:380` |
| Listener adoption | Shard 0, when `s2s_port` is not 0, dups an inherited S2S listener and adopts that fd. The caller keeps the original. Port 0 still means no S2S listener. | `src/daemon/server.zig:2316`, `src/daemon/server.zig:5548`, `src/daemon/server.zig:124254` |
| World lock | Completions are handled under the shared world write lock. Reactors parallelize I/O and serialize command processing. | `src/daemon/server.zig:9907` |

`[io].defer_taskrun` remains a parsed key. `--check-config` still rejects it together with `sqpoll`. That rejection does not mean the live ring arms deferred task-run.

`src/substrate/io/buf_ring.zig` keeps pure provided-buffer bookkeeping. `registerAll` does not call the kernel. The production ring registers one group through `LiveBufRing` when Linux boot sets `buf_ring`. A kernel that rejects the group leaves that reactor on copy recv. The group is at least twice `max_clients`, rounded up to a power of two, and capped at 32768 entries of `default_recv_bytes`.

Line numbers in the sections below were taken against an older `server.zig`. Read the named symbol before trusting a citation there. The threading model those sections describe is still the model: one reactor owns its ring, clients, and listener fds; another reactor does not touch those fds.

## Per-reactor state and connection classes

`LinuxServer` stores a heap slice of `Reactor` structs. Each `Reactor` owns its ring, connection table, listener fds, timer/wake state, and shard id. Evidence: `src/daemon/server.zig:2504`, `src/daemon/server.zig:2510`, `src/daemon/server.zig:2511`, `src/daemon/server.zig:2515`, `src/daemon/server.zig:2518`, `src/daemon/server.zig:2520`, `src/daemon/server.zig:2533`, `src/daemon/server.zig:2537`, `src/daemon/server.zig:2814`, `src/daemon/server.zig:2818`.

Each connection is assigned a **connection class** by matching the connection's source IP (IPv4 and IPv6 CIDR), TLS status, SASL authentication, oper status, and ident/host glob patterns. The first matching class wins; S2S links resolve to the built-in `server` class and unmatched client links fall back to `user`. Evidence: `src/daemon/conn_class.zig:4`, `src/daemon/conn_class.zig:132`, `src/daemon/conn_class.zig:146`, `src/daemon/conn_class.zig:165`, `src/daemon/conn_class.zig:170`, `src/daemon/conn_class.zig:180`, `src/daemon/conn_class.zig:198`, `src/daemon/conn_class.zig:200`, `src/daemon/conn_class.zig:204`, `src/daemon/server.zig:9797`.

| Field | Ownership rule | Evidence |
| --- | --- | --- |
| `ring` | Owned by one reactor thread for accept/recv/send/poll/timeout completions. | `src/daemon/server.zig:2511` |
| `clients` | Connections are pinned to a reactor-local slab; another reactor must not touch their fd/send buffers directly. | `src/daemon/server.zig:2513`, `src/daemon/server.zig:2514`, `src/daemon/server.zig:6834`, `src/daemon/server.zig:6838` |
| `shard_id` | Stamped into `ClientId.shard`; always 0 in single-reactor configuration. | `src/daemon/server.zig:2516`, `src/daemon/server.zig:2517`, `src/daemon/server.zig:2518` |
| listener fds | Plaintext, optional S2S, optional implicit TLS, and optional secure-WebSocket listener fds live per reactor; S2S is reactor-0-only in sharded mode. | `src/daemon/server.zig:2520`, `src/daemon/server.zig:2522`, `src/daemon/server.zig:2524`, `src/daemon/server.zig:2526`, `src/daemon/server.zig:3295`, `src/daemon/server.zig:3298` |
| wake fd | A per-reactor eventfd may be polled so another thread can wake the loop and drain that shard's mailbox. | `src/daemon/server.zig:2537`, `src/daemon/server.zig:2540`, `src/daemon/server.zig:4383`, `src/daemon/server.zig:4388`, `src/daemon/server.zig:4422`, `src/daemon/server.zig:4430` |

The current reactor is held in `threadlocal var current_reactor`, and handlers call `self.rx()` to resolve the current thread's reactor or fall back to reactor 0 outside reactor threads. Evidence: `src/daemon/server.zig:2557`, `src/daemon/server.zig:2563`, `src/daemon/server.zig:3230`, `src/daemon/server.zig:3233`, `src/daemon/server.zig:3234`.

## SendQ and RecvQ

Every connection has a **SendQ** (outbound) and a **RecvQ** (inbound) bounded by the per-class policy, applied when `assignConnClass` runs.

| Buffer | Structure | Ceiling | Evidence |
| --- | --- | --- | --- |
| **SendQ** | Inline send buffer (`send_buf`) plus a heap-allocated overflow queue. The kernel reads only the fixed inline buffer; overflow refills the inline buffer on send completion. | Per-class `sendq` ceiling (default 1 MiB for user class, 8 MiB for server class). | `src/daemon/server.zig:2066`, `src/daemon/server.zig:2076`, `src/daemon/server.zig:2078`, `src/daemon/server.zig:2084`, `src/daemon/server.zig:30753`, `src/daemon/server.zig:30763`, `src/daemon/conn_class.zig:55`, `src/daemon/conn_class.zig:299` |
| **RecvQ** | Inline line buffer (`line_buf`) accumulates the current unterminated line; overflow spills to a heap queue. | Per-class `recvq` ceiling (`0` = physical line-buffer default). A line exceeding this ceiling closes the connection with `LineTooLong`. | `src/daemon/server.zig:2054`, `src/daemon/server.zig:2057`, `src/daemon/server.zig:2065`, `src/daemon/server.zig:30681`, `src/daemon/server.zig:30704`, `src/daemon/server.zig:30706`, `src/daemon/conn_class.zig:56`, `src/daemon/server.zig:9776` |

Both overflow queues share the connection's `overflow_allocator`; SendQ overflow is drained back into `send_buf`, and RecvQ overflow is released on reset after a completed line. Evidence: `src/daemon/server.zig:2059`, `src/daemon/server.zig:2094`, `src/daemon/server.zig:30716`, `src/daemon/server.zig:30729`, `src/daemon/server.zig:30767`, `src/daemon/server.zig:30773`.

## Initialization

| Step | Behavior | Evidence |
| --- | --- | --- |
| Shard count | `clampShards` converts zero to one, caps at `shard.max_shards`, and returns at least one. | `src/daemon/server.zig:3237`, `src/daemon/server.zig:3246`, `src/daemon/server.zig:3247`, `src/daemon/server.zig:3248`, `src/daemon/server.zig:3249` |
| Listener selection | The plaintext listener is created with SO_REUSEPORT even for one shard so a later 1-shard to N-shard upgrade can bind siblings. Sharded TLS and secure-WebSocket client listeners also use SO_REUSEPORT; the S2S listener is bound only by reactor 0. | `src/daemon/server.zig:3280`, `src/daemon/server.zig:3281`, `src/daemon/server.zig:3288`, `src/daemon/server.zig:3292`, `src/daemon/server.zig:3295`, `src/daemon/server.zig:3298`, `src/daemon/server.zig:3307`, `src/daemon/server.zig:3320` |
| Per-reactor ring | `initReactor` creates the listener fds, Ringlane ring, reserved client slab, shard-local client table, and wake handle. | `src/daemon/server.zig:3272`, `src/daemon/server.zig:3328`, `src/daemon/server.zig:3334`, `src/daemon/server.zig:3337`, `src/daemon/server.zig:3341`, `src/daemon/server.zig:3352` |
| Server reactor slice | `LinuxServer.init` allocates `reactors` with length `shard_count` and initializes each entry. | `src/daemon/server.zig:3378`, `src/daemon/server.zig:3384`, `src/daemon/server.zig:3388`, `src/daemon/server.zig:3389`, `src/daemon/server.zig:3514` |
| Shared world/stores | `LinuxServer` owns shared world and stores separately from per-reactor I/O; the worker pool is initialized alongside the server-level state. | `src/daemon/server.zig:3519`, `src/daemon/server.zig:3520`, `src/daemon/server.zig:3521`, `src/daemon/server.zig:3525`, `src/daemon/server.zig:3526` |

## Run loop

| Mode | Behavior | Evidence |
| --- | --- | --- |
| `runOnce` | Binds reactor 0 if no thread-local reactor is set, arms accept/wake/timer, waits for a completion, reaps CQEs, drains fabric if present, drains webhook posts, and submits pending SQEs. | `src/daemon/server.zig:5424`, `src/daemon/server.zig:5429`, `src/daemon/server.zig:5441`, `src/daemon/server.zig:5442`, `src/daemon/server.zig:5443`, `src/daemon/server.zig:5444`, `src/daemon/server.zig:5449`, `src/daemon/server.zig:5457`, `src/daemon/server.zig:5461`, `src/daemon/server.zig:5463` |
| Completion boundary | Each decoded completion is handled under one shared `world.lockWrite`; per-reactor clients, send buffers, and rings remain reactor-local. | `src/daemon/server.zig:30270`, `src/daemon/server.zig:30272`, `src/daemon/server.zig:30279`, `src/daemon/server.zig:30281`, `src/daemon/server.zig:30282`, `src/daemon/server.zig:30297` |
| Single reactor | `runThreaded` runs `runLoopResilient` inline when `self.reactors.len <= 1`; no pool and no fabric are used. | `src/daemon/server.zig:5474`, `src/daemon/server.zig:5479`, `src/daemon/server.zig:5480`, `src/daemon/server.zig:5481`, `src/daemon/server.zig:5482` |
| Multi reactor | For more than one reactor, `runThreaded` creates a cross-shard fabric, starts one worker thread per reactor, and joins the pool. If fabric or pool startup fails, it falls back to the single-reactor loop. | `src/daemon/server.zig:5485`, `src/daemon/server.zig:5490`, `src/daemon/server.zig:5495`, `src/daemon/server.zig:5501`, `src/daemon/server.zig:5506`, `src/daemon/server.zig:5514` |
| Worker | Each worker sets `current_reactor` to its shard and loops through `runLoopResilient`/`runOnce` while the run flag is true. | `src/daemon/server.zig:5517`, `src/daemon/server.zig:5521`, `src/daemon/server.zig:5522`, `src/daemon/server.zig:5532`, `src/daemon/server.zig:5534`, `src/daemon/reactor_pool.zig:61`, `src/daemon/reactor_pool.zig:94` |

## Cross-shard delivery

When a command needs to write to a connection, `enqueueDelivery` is the central shard-aware sink. Local writes append directly to the owning reactor's connection; cross-shard writes copy bytes into pooled buffers, enqueue them into the target shard mailbox, and wake the target reactor. Evidence: `src/daemon/server.zig:6828`, `src/daemon/server.zig:6832`, `src/daemon/server.zig:6834`, `src/daemon/server.zig:6839`, `src/daemon/server.zig:6891`, `src/daemon/server.zig:6916`, `src/daemon/server.zig:6928`, `src/daemon/server.zig:6939`, `src/daemon/server.zig:6962`.

`ReactorFabric` is runtime-sized by shard count and owns one MPMC inbox and one wake eventfd per shard plus a shared pooled-buffer allocator. The live daemon currently wakes the target reactor through `Reactor.wake`, not the fabric's own wake fds, because the reactor loop polls `Reactor.wake`. Evidence: `src/daemon/reactor_fabric.zig:4`, `src/daemon/reactor_fabric.zig:51`, `src/daemon/reactor_fabric.zig:65`, `src/daemon/reactor_fabric.zig:68`, `src/daemon/reactor_fabric.zig:70`, `src/daemon/reactor_fabric.zig:72`, `src/daemon/server.zig:6957`, `src/daemon/server.zig:6960`, `src/daemon/server.zig:6962`.

| Fabric operation | API | Evidence |
| --- | --- | --- |
| Copy bytes into pool | `acquire(bytes)` returns a `DeliverBuf` or null. | `src/daemon/reactor_fabric.zig:126`, `src/daemon/reactor_fabric.zig:129`, `src/daemon/reactor_fabric.zig:130` |
| Enqueue | `sendTo(target, msg)` pushes into the target shard inbox. | `src/daemon/reactor_fabric.zig:144`, `src/daemon/reactor_fabric.zig:148`, `src/daemon/reactor_fabric.zig:149` |
| Drain | `drain(target, out)` is called by the owning reactor. | `src/daemon/reactor_fabric.zig:152`, `src/daemon/reactor_fabric.zig:154`, `src/daemon/reactor_fabric.zig:155`, `src/daemon/server.zig:4441`, `src/daemon/server.zig:4446` |
| Wake | `wake(target)` pokes a fabric eventfd, while live cross-shard delivery wakes `self.reactors[id.shard].wake`. | `src/daemon/reactor_fabric.zig:158`, `src/daemon/reactor_fabric.zig:160`, `src/daemon/reactor_fabric.zig:161`, `src/daemon/server.zig:6957`, `src/daemon/server.zig:6962` |

## Worker pool

`ReactorPool` is the generic worker-thread harness for the sharded model. It spawns one thread per shard, passes each a distinct shard index, shares only a cooperative `RunFlag`, and joins every worker on shutdown. Evidence: `src/daemon/reactor_pool.zig:4`, `src/daemon/reactor_pool.zig:6`, `src/daemon/reactor_pool.zig:18`, `src/daemon/reactor_pool.zig:28`, `src/daemon/reactor_pool.zig:61`, `src/daemon/reactor_pool.zig:66`, `src/daemon/reactor_pool.zig:92`, `src/daemon/reactor_pool.zig:101`, `src/daemon/reactor_pool.zig:105`.

## World locking

The shared `World` owns an `RwLock`. Current comments say lookups take the read lock, mutations take the write lock, and every mutation/allocation happens under the exclusive lock. Evidence: `src/daemon/world.zig:328`, `src/daemon/world.zig:329`, `src/daemon/world.zig:336`, `src/daemon/world.zig:338`, `src/daemon/world.zig:344`.

The world also has lazily activated RCU mirrors for nick lookup and channel existence/membership. The RCU model is implemented in `world_rcu.zig`: readers pin EBR and traverse immutable HAMT snapshots without locks or allocation; writers serialize, copy-on-write, publish a new root, and retire old state. Evidence: `src/daemon/world.zig:314`, `src/daemon/world.zig:322`, `src/daemon/world_rcu.zig:7`, `src/daemon/world_rcu.zig:27`, `src/daemon/world_rcu.zig:29`, `src/daemon/world_rcu.zig:36`, `src/daemon/world_rcu.zig:40`.

## Is multithreading live?

Yes, conditionally. The default configuration is one shard, but the current source creates multiple reactors when `config.num_shards > 1`. In that case it initializes a reactor slice, starts a cross-shard fabric, and spawns one worker thread per reactor. Evidence: `src/daemon/server.zig:1640`, `src/daemon/server.zig:3378`, `src/daemon/server.zig:3384`, `src/daemon/server.zig:3389`, `src/daemon/server.zig:5485`, `src/daemon/server.zig:5490`, `src/daemon/server.zig:5501`.

The test suite contains threaded server coverage for multi-reactor startup and cross-shard behavior. It asserts `num_shards = 4` produces four reactors, and `num_shards = 2` cross-shard tests skip only when fewer than two reactors are available. Evidence: `src/daemon/server.zig:32437`, `src/daemon/server.zig:32439`, `src/daemon/server.zig:32445`, `src/daemon/server.zig:36850`, `src/daemon/server.zig:36860`, `src/daemon/server.zig:36869`, `src/daemon/server.zig:36942`, `src/daemon/server.zig:36954`, `src/daemon/server.zig:36960`.

## Planning notes and divergences

Current code diverges from older design intent in one important inline comment: `Config.num_shards` still says values greater than 1 are clamped to 1 at `runThreaded`, but the implementation starts the multi-reactor pool when `reactors.len > 1`. Evidence for the stale comment: `src/daemon/server.zig:1635`, `src/daemon/server.zig:1637`; evidence for current behavior: `src/daemon/server.zig:5479`, `src/daemon/server.zig:5485`, `src/daemon/server.zig:5501`.
