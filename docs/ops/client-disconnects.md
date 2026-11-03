# Client disconnect diagnosis

This page describes the current source policy. Use [production paths](onyx-server-paths.md) to
identify the accepted running image and [the release audit](../audit/release-and-test-speed-2026-11-03.md)
for deployment acceptance. A timeout diagnosis still requires the affected
connection's own evidence.

## Receive errors

The ordinary receive-error path keeps a previously selected close reason. If
none was selected, Unix `ETIMEDOUT` becomes `Connection timed out`, `ECONNRESET`
becomes `Connection reset by peer`, and other failures become `Read error`.
Windows currently collapses completion errors before this path and reports
`Read error`. The structured `recv_error` record includes the original result;
use it with the connection slot and generation to correlate the later close.
Explicit IRC QUIT text, orderly EOF, cancellation, and existing TLS fallback
paths retain their existing handling.

A timeout establishes that the kernel ended the connection without successful
progress. It does not identify which endpoint or network segment caused the
loss. A `Client quit` message from an older image is not proof that the client
sent an explicit IRC QUIT.

## Linux socket policy

`src/daemon/client_socket_policy.zig` owns the shared values: keepalive idle
30 seconds, probe interval 10 seconds, and three probes. The listener's
`TCP_USER_TIMEOUT` is derived from that whole window: 60,000 milliseconds.
Linux lets this timeout override the probe count once a probe is outstanding;
a 30,000-millisecond timeout could therefore abort after the first missed probe.
The longer value also changes the allowed unacknowledged-data stall to one
minute. Application-level deadlines remain independent and may close sooner.

The socket-policy regression checks real accepted-socket inheritance.
These timers bound failed transport progress; they do not identify the cause
of a particular client's packet loss. Correlate the actual connection's
diagnostics and network evidence before attributing responsibility.

Newly created listeners apply the new timeout, and accepted sockets inherit it.
The real accept-path regression checks inheritance and the client keepalive
options on the same descriptor. Helix does not update every inherited socket:
existing clients and S2S connections retain their previous settings, as do
inherited TLS, WebSocket, and S2S listeners. The inherited plain listener
explicitly reapplies listener options. Outbound dials do not gain a new
`TCP_USER_TIMEOUT` setting from this change. A cold start with fresh listeners
and connections is needed for complete adoption of this listener policy; follow
the runbook's custody requirements before restarting a live node.

Source of truth: `src/daemon/client_socket_policy.zig`, `server.zig` receive/accept
paths, and the connection diagnostics described in [Alpine operation](../guide/alpine.md).
