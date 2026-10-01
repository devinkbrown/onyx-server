**The source supports the proposed failure mechanism.** Collision resolution can retire a link before its peer receives the inner handshake reply needed to establish that link and transfer the outbound endpoint binding. This explains repeated losing dials without requiring an exec-specific fault; campaign causation remains unverified by this read-only review.

- **Plaintext loses the reply before staging.** [driveS2s](/home/kain/onyx-server/src/daemon/server.zig:10041) resolves collisions at line 10059 and returns for a loser before copying `link.outbound()` into ConnState at line 10062. The responder’s [recvHandshake](/home/kain/onyx-server/src/substrate/undertow/s2s_peer.zig:4201) queues its handshake reply, marks itself established, and queues a burst in the same feed. Local establishment therefore does not imply remote establishment.

- **Secured stages bytes, but does not wait for transmission.** [driveS2sSecured](/home/kain/onyx-server/src/daemon/server.zig:9796) flushes before collision resolution at line 9824. [flushMeshBurstStage](/home/kain/onyx-server/src/daemon/server.zig:15984) copies complete frames into SendQ and arms SEND; neither action establishes completion. [requestS2sClose](/home/kain/onyx-server/src/daemon/server.zig:52165) immediately calls `closeConn`, whose ownership branch executes [shutdown(RDWR)](/home/kain/onyx-server/src/daemon/server.zig:14367), even with SEND outstanding.

- **The critical secured reply is the inner handshake.** [processHandshake](/home/kain/onyx-server/src/daemon/secured_s2s_link.zig:1378) stages the Mooring reply before creating the inner link. [beginCrdt](/home/kain/onyx-server/src/daemon/secured_s2s_link.zig:1440) starts the inner handshake only for the initiator. The responder becomes daemon-visible as established after receiving that inner handshake, while its encrypted reply remains staged. Thus the failure need not involve losing M2.

For example, let A have the larger server name. B→A wins; A→B loses. If B already has its outbound winner, B’s inbound loser can establish locally and close before returning its inner reply. A’s outbound loser never establishes, so A never executes [transferMeshDialBinding](/home/kain/onyx-server/src/daemon/server.zig:52150). A retains an inbound winner with unknown endpoint and repeatedly probes its configured dial.

The delta against HEAD makes that missing transfer consequential: [meshPeerLinkedByDial](/home/kain/onyx-server/src/daemon/server.zig:52122) now requires a proven complete endpoint, replacing advertised-name/source-IP inference. Matching full secured keys is correct; restoring those old heuristics would conceal the ordering defect and reintroduce same-IP false matches. Snapshot capture/adoption preserves known bindings, but cannot create one that never transferred.

The smallest repair I recommend is **collision-specific close-on-drain**, preserving immediate abort for faults:

1. Stage plaintext handshake output before collision resolution.
2. Commit binding transfer and `s2s_dedup` immediately, excluding the loser from routing, but defer shutdown until all required output drains.
3. Preserve and retry any secured-link outbound suffix under SendQ pressure; `flushMeshBurstStage()` can return false without setting `closing`.
4. Ensure racing RECV completions cannot abort that drain. [handleRecv’s closing branch](/home/kain/onyx-server/src/daemon/server.zig:10467) currently calls `closeConn` immediately. Merely setting `closing` and arming SEND is insufficient.
5. Reuse [SEND completion/refill](/home/kain/onyx-server/src/daemon/server.zig:10559) and [SQ-pressure activation](/home/kain/onyx-server/src/daemon/server.zig:14178), retaining the pending activation signal until drain completion.

Risks to cover in the writer’s test: partial SENDs, overflow, SQ-full with no armed operation, retained link output, racing RECV/EOF, and bounded retirement of a blocked loser. SEND completion proves kernel acceptance, not peer processing. Preserve [CONNECT address ownership](/home/kain/onyx-server/src/daemon/server.zig:14150) and exact-generation storage latches. Also audit immediate finalization during a drive: plaintext can reach collision with its RECV latch already cleared and no SEND armed, allowing slot retirement before the caller resumes.

HEAD inspected: `d9991c00040a3c2623fb5fcf858f6e5127c62915`.

`src/daemon/server.zig` SHA-256, identical at start and end:
```text
725805d5dc8b87908f4acc6f7b1162c852c62dd539545aae2339a8b8bf99eace
```

No edits, tests, agents, credentials, or VM operations. This is a source diagnosis and repair recommendation, not final acceptance.
