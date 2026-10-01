# Read-only shared-session timestamp investigation

Final frozen server SHA-256:
`a08b0e8aa2089c5e09ce3501b72a618cff1af92c852e8bc4f07caffbca20ac1b`.

The earlier broad ReleaseSafe lifetime candidate reported a real failure in
`threaded server: one reusable session stays live and participatory across a secured mesh`:
expected `2026-10-01T01:06:34.632Z`, observed `.650Z`. Preserve
`named-final-release-safe-lifetime-candidate-interrupted.log` as RED evidence:
2325/2337 pass, 11 skipped, 1 failed. This was not merely an interrupted run.

The fixture is byte-identical to baseline d9991c00; fixture SHA-256
`9fb5411fdd95ce4f88dc8ba9c682cd176f073c8a8ceadfd00ed3e96670666723`.
No source edits or assertions changed during this investigation.

Exact final source focused repeats:

```
zig build test-mod -Dtest-filter='one reusable session stays live and participatory across a secured mesh' --summary all
zig build test-mod -Dtest-filter='one reusable session stays live and participatory across a secured mesh' -Doptimize=ReleaseSafe --summary all
```

`shared-session-final-debug.log`: exit 0, 72/72, compile 12s/run 2s.
`shared-session-final-release-safe.log`: exit 0, 72/72, compile 9m/run 1s.
Both retain the exact time/msgid/count/participation oracles.

Read-only hypothesis, not a proven cause: the older fixture extracts the first
`time=` and first `msgid=` from whole receive buffers, whereas newer fixtures use
`ircLineContaining` to bind both tags to the event being asserted. Timed control
lines without msgids can make those lookups refer to different records. The
observed failure log has no exact assertion or captured input-frame anchor, so
these two green repeats do not prove that hypothesis or discard the prior RED.
No reproduced regression is currently established; final broad acceptance stays
with the parent. All log paths above are within this directory.
