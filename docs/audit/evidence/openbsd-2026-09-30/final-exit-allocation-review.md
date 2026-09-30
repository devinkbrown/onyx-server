<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Rejected candidate exit allocation review

Fresh read-only reviewer: `/root/review_runtime_probe`, 2026-09-30.

The 16 SafeAllocator diagnostics in
[native-consolidated-final-rs-daemon.log](native-consolidated-final-rs-daemon.log)
are a real, pre-existing 694-byte allocation leak when the missing-key candidate
exits. They are not evidence of a growing live daemon leak or failed native
descriptor custody.

Baseline commit `15e09029`, `src/main.zig:583–586`, already constructs and globally
installs ISUPPORT tokens without freeing them. The final source retains that
lifetime at `src/main.zig:693–696`. The allocator creates 15 token strings and a
512-byte vector, matching all 16 records at raw log lines 27–73. The missing-key
error at `src/main.zig:747–749` returns before adoption.

Deferred native cleanup releases the incoming arena, received descriptors and
plaintext (`native_bootstrap.zig:133–142`). The predecessor aborts and kills/reaps
the uncommitted candidate (`server.zig:27595–27597`,
`native_process.zig:22–33`). The transport acceptance log confirms all 40 original
clients remain attached, followed by two successful upgrades.

This bounded failed-process exit leak remains a shared baseline issue outside
the operating-system port. Clearing the global ISUPPORT override and freeing
the tokens on exit would address it. This review changed no source and ran no
VM commands; the accepted source and artifact hashes remain unchanged.
