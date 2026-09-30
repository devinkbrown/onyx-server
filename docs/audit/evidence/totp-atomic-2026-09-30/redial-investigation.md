# Carried-peer UPGRADE re-dial investigation

Read-only investigation of the named Linux Debug failure at server.zig:110427, expect(linked). No source edits, assertion changes, commits, push or deployment. Final source remains frozen:

- server.zig SHA-256: eb597455d267d8168dc6860e68336c18d1040f67d1024ee6bd031b36a679048c
- totp_auth.zig SHA-256: 2053019b7411fca8ba2c8d78bc68536b37b1d77972e2b17e37e9a82fb46b61aa
- Baseline HEAD: 95f75e0303eaf3f425b94833d4a227b9392b9d27.

Original failure receipt: .zig-cache/codex-resume/totp-atomic/named-linux-debug.log. It records 467 pass, 4 skip, 1 fail among 472 server tests; the failing test is `threaded server: UPGRADE resume arena re-dials a carried mesh peer`.

Focused command, executed unchanged against final source and clean baseline:

    zig build test-mod-verbose -Dtest-filter='UPGRADE resume arena re-dials a carried mesh peer' --summary all

Four final-source executions each exited 0: 72 passed, 0 skipped, 0 failed, 0 leaked, 0 log errors (one substantive test and 71 import-root wrappers). Actual substantive test durations were 225 ms, 84 ms, 85 ms and 93 ms. Logs:

- .zig-cache/codex-resume/totp-atomic/redial-focused-final-1.log
- .zig-cache/codex-resume/totp-atomic/redial-focused-final-2.log
- .zig-cache/codex-resume/totp-atomic/redial-focused-final-3.log
- .zig-cache/codex-resume/totp-atomic/redial-focused-final-4.log

Three clean-baseline executions each exited 0: 72 passed, 0 skipped, 0 failed, 0 leaked, 0 log errors; substantive test duration was 83 ms in each run. Baseline was checked out without edits in .zig-cache/codex-resume/totp-atomic/redial-baseline; its local build cache is separate from the main worktree. Baseline server.zig SHA-256 is b9dabd1970c0f3155c4ce814ae774129e4b717d23152095b0bbbc80f9da169db. Logs:

- .zig-cache/codex-resume/totp-atomic/redial-focused-baseline-1.log
- .zig-cache/codex-resume/totp-atomic/redial-focused-baseline-2.log
- .zig-cache/codex-resume/totp-atomic/redial-focused-baseline-3.log

Exact source-comparison receipt: .zig-cache/codex-resume/totp-atomic/redial-source-comparison.txt. These source slices are byte-identical versus baseline:

- Failing test: 5,056 bytes.
- activateInheritedMeshRedials: 1,487 bytes.
- initiateS2sConnectToAddr: 3,975 bytes.
- adoptInheritedSessions: 109,506 bytes.

Observed inherited readiness weakness: the outer test permits 120 LINKS probes without an elapsed-time deadline or pause between completed replies. recvUntil has a wall-clock timeout only while its requested marker is absent; it returns immediately on each 365 reply. Therefore 120 rapid LINKS replies can exhaust the outer count before a delayed handshake becomes visible, even though the connection may become established later. This is consistent with the isolated failure while full and named Debug/ReleaseSafe gates were running concurrently. The original failure was not reproduced in these focused runs, so contention remains an evidence-based inference, not a demonstrated root cause.

No TOTP-induced re-dial/adoption regression was found. Source and assertions remain unchanged. Parent owns the named Debug rerun after broad CPU contention drains; a failed original gate is not converted into release acceptance by focused reruns. Parent reports Services Debug 564/564 passed and test-server Debug retry session 26370 is running.
