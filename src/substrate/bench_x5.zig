// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GAP-X5 hot-path bench.
//!
//! Names the bytes reserved for one connection and the microseconds to enqueue
//! one plaintext line per fan-out recipient. This run does not shrink
//! `ConnState` and does not bump the Helix clients capsule, so there is no
//! "after" number.
//!
//! Linux only. A non-Linux host exits 2 and records nothing: `ConnState` is the
//! Linux reactor connection, and a zero would be a fake measurement.

const std = @import("std");
const builtin = @import("builtin");

pub fn main(init: std.process.Init) !void {
    if (comptime builtin.os.tag != .linux) {
        std.debug.print(
            "GAP-X5 unmet on {s}: ConnState is the Linux reactor connection. No number was recorded.\n",
            .{@tagName(builtin.os.tag)},
        );
        std.process.exit(2);
    }
    return @import("bench_x5_linux.zig").main(init);
}
