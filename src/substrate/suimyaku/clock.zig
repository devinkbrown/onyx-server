// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SUIMYAKU logical clock substrate.
//!
//! HLC gives mesh events a near-wall total order while dotted version vectors
//! carry causal coverage for CRDT merge, repair, and conflict detection.
const std = @import("std");

/// A single causal dot emitted by one replica.
pub const Dot = struct {
    replica: u64,
    counter: u64,
};

/// Hybrid Logical Clock timestamp.
///
/// Physical time is supplied by the caller so tests and deterministic mesh
/// simulation never touch the system clock.
pub const Hlc = packed struct {
    wall_ms: u48 = 0,
    logical: u16 = 0,

    pub const Error = error{
        WallTimeOutOfRange,
        LogicalOverflow,
    };

    const max_wall_ms = std.math.maxInt(u48);

    /// Build a timestamp after validating the u48 wall-time bound.
    pub fn init(wall_ms: u64, logical: u16) Error!Hlc {
        return .{
            .wall_ms = try castWall(wall_ms),
            .logical = logical,
        };
    }

    /// Apply a local event at `physical_ms` and return the new timestamp.
    pub fn now(self: *Hlc, physical_ms: u64) Error!Hlc {
        const physical = try castWall(physical_ms);
        if (physical > self.wall_ms) {
            self.wall_ms = physical;
            self.logical = 0;
        } else {
            self.logical = try bump(self.logical);
        }
        return self.*;
    }

    /// Apply a send event.
    pub fn send(self: *Hlc, physical_ms: u64) Error!Hlc {
        return self.now(physical_ms);
    }

    /// Apply a receive event using local physical time and the remote HLC.
    pub fn recv(self: *Hlc, physical_ms: u64, remote: Hlc) Error!Hlc {
        const physical = try castWall(physical_ms);
        const local_wall = self.wall_ms;
        const remote_wall = remote.wall_ms;
        const next_wall = @max(physical, @max(local_wall, remote_wall));

        const next_logical = if (next_wall == local_wall and next_wall == remote_wall)
            try bump(@max(self.logical, remote.logical))
        else if (next_wall == local_wall)
            try bump(self.logical)
        else if (next_wall == remote_wall)
            try bump(remote.logical)
        else
            0;

        self.wall_ms = next_wall;
        self.logical = next_logical;
        return self.*;
    }

    /// Total order by wall time, then logical counter.
    pub fn compare(a: Hlc, b: Hlc) std.math.Order {
        if (a.wall_ms < b.wall_ms) return .lt;
        if (a.wall_ms > b.wall_ms) return .gt;
        if (a.logical < b.logical) return .lt;
        if (a.logical > b.logical) return .gt;
        return .eq;
    }

    /// Encode to the LWW timestamp key in the same order as `compare`.
    pub fn toU64(self: Hlc) u64 {
        comptime {
            std.debug.assert(@bitSizeOf(u48) == 48);
            std.debug.assert(@bitSizeOf(u16) == 16);
            std.debug.assert(@bitSizeOf(u48) + @bitSizeOf(u16) == @bitSizeOf(u64));
        }
        return (@as(u64, self.wall_ms) << @bitSizeOf(u16)) | @as(u64, self.logical);
    }

    fn castWall(physical_ms: u64) Error!u48 {
        if (physical_ms > max_wall_ms) return error.WallTimeOutOfRange;
        return @intCast(physical_ms);
    }

    fn bump(value: u16) Error!u16 {
        if (value == std.math.maxInt(u16)) return error.LogicalOverflow;
        return value + 1;
    }
};

/// Dotted version vector with a small inline replica table.
pub const VersionVector = struct {
    pub const max_entries = 64;

    pub const Error = error{
        CapacityExceeded,
        CounterOverflow,
    };

    const Entry = struct {
        replica: u64,
        counter: u64,
    };

    entries: [max_entries]Entry = @splat(.{ .replica = 0, .counter = 0 }),
    len: usize = 0,

    /// Empty vector.
    pub fn init() VersionVector {
        return .{};
    }

    /// Increment `replica` and return the emitted dot.
    pub fn increment(self: *VersionVector, replica: u64) Error!Dot {
        if (self.findIndex(replica)) |idx| {
            if (self.entries[idx].counter == std.math.maxInt(u64)) {
                return error.CounterOverflow;
            }
            self.entries[idx].counter += 1;
            return .{ .replica = replica, .counter = self.entries[idx].counter };
        }

        if (self.len == max_entries) return error.CapacityExceeded;
        self.entries[self.len] = .{ .replica = replica, .counter = 1 };
        self.len += 1;
        return .{ .replica = replica, .counter = 1 };
    }

    /// Merge another vector into this one by taking pointwise maxima.
    pub fn merge(self: *VersionVector, other: *const VersionVector) Error!void {
        for (other.entries[0..other.len]) |entry| {
            if (self.findIndex(entry.replica)) |idx| {
                self.entries[idx].counter = @max(self.entries[idx].counter, entry.counter);
            } else {
                if (self.len == max_entries) return error.CapacityExceeded;
                self.entries[self.len] = entry;
                self.len += 1;
            }
        }
    }

    /// Number of distinct replicas that would remain after merging `other`,
    /// computed WITHOUT mutating either vector. Lets a caller reject an
    /// over-capacity merge up front and stay all-or-nothing, since a partial
    /// `merge` that hit `max_entries` would leave the vector half-updated.
    pub fn mergedLen(self: *const VersionVector, other: *const VersionVector) usize {
        var total = self.len;
        for (other.entries[0..other.len]) |entry| {
            if (self.findIndex(entry.replica) == null) total += 1;
        }
        return total;
    }

    /// True when this vector causally covers every dot in `other`.
    pub fn dominates(self: *const VersionVector, other: *const VersionVector) bool {
        for (other.entries[0..other.len]) |entry| {
            if (self.counter(entry.replica) < entry.counter) return false;
        }
        return true;
    }

    /// True when neither vector dominates the other.
    pub fn concurrentWith(self: *const VersionVector, other: *const VersionVector) bool {
        return !self.dominates(other) and !other.dominates(self);
    }

    /// True when this vector contains the supplied dot.
    pub fn contains(self: *const VersionVector, dot: Dot) bool {
        return self.counter(dot.replica) >= dot.counter;
    }

    /// Return a replica counter, or zero when absent.
    pub fn counter(self: *const VersionVector, replica: u64) u64 {
        if (self.findIndex(replica)) |idx| return self.entries[idx].counter;
        return 0;
    }

    fn findIndex(self: *const VersionVector, replica: u64) ?usize {
        for (self.entries[0..self.len], 0..) |entry, idx| {
            if (entry.replica == replica) return idx;
        }
        return null;
    }
};

test "HLC local events are monotonic across stable and regressing physical time" {
    var clock = try Hlc.init(1000, 0);

    const a = try clock.now(1000);
    try std.testing.expectEqual(@as(u48, 1000), a.wall_ms);
    try std.testing.expectEqual(@as(u16, 1), a.logical);

    const b = try clock.send(999);
    try std.testing.expectEqual(@as(u48, 1000), b.wall_ms);
    try std.testing.expectEqual(@as(u16, 2), b.logical);
    try std.testing.expectEqual(std.math.Order.lt, Hlc.compare(a, b));

    const c = try clock.now(1001);
    try std.testing.expectEqual(@as(u48, 1001), c.wall_ms);
    try std.testing.expectEqual(@as(u16, 0), c.logical);
    try std.testing.expectEqual(std.math.Order.lt, Hlc.compare(b, c));
}

test "HLC receive merges local physical and remote observations" {
    var local = try Hlc.init(1000, 3);
    const remote = try Hlc.init(1200, 4);

    const merged = try local.recv(1100, remote);
    try std.testing.expectEqual(@as(u48, 1200), merged.wall_ms);
    try std.testing.expectEqual(@as(u16, 5), merged.logical);
    try std.testing.expectEqual(std.math.Order.gt, Hlc.compare(merged, remote));

    const physical_wins = try local.recv(1300, remote);
    try std.testing.expectEqual(@as(u48, 1300), physical_wins.wall_ms);
    try std.testing.expectEqual(@as(u16, 0), physical_wins.logical);
}

test "HLC receive tie-breaking bumps the maximum logical counter" {
    var local = try Hlc.init(42, 7);
    const remote = try Hlc.init(42, 11);

    const merged = try local.recv(40, remote);
    try std.testing.expectEqual(@as(u48, 42), merged.wall_ms);
    try std.testing.expectEqual(@as(u16, 12), merged.logical);
    try std.testing.expectEqual(std.math.Order.lt, Hlc.compare(remote, merged));
}

test "HLC guards logical and wall-time overflow" {
    var local = try Hlc.init(10, std.math.maxInt(u16));
    try std.testing.expectError(error.LogicalOverflow, local.now(10));

    var recv_local = try Hlc.init(10, 0);
    const remote = try Hlc.init(10, std.math.maxInt(u16));
    try std.testing.expectError(error.LogicalOverflow, recv_local.recv(9, remote));

    var wall = Hlc{};
    try std.testing.expectError(error.WallTimeOutOfRange, wall.now(@as(u64, std.math.maxInt(u48)) + 1));
}

test "version vector increment and contains dots" {
    var vv = VersionVector.init();

    const a1 = try vv.increment(7);
    const a2 = try vv.increment(7);
    const b1 = try vv.increment(9);

    try std.testing.expectEqual(Dot{ .replica = 7, .counter = 1 }, a1);
    try std.testing.expectEqual(Dot{ .replica = 7, .counter = 2 }, a2);
    try std.testing.expectEqual(Dot{ .replica = 9, .counter = 1 }, b1);
    try std.testing.expect(vv.contains(a1));
    try std.testing.expect(vv.contains(a2));
    try std.testing.expect(vv.contains(b1));
    try std.testing.expect(!vv.contains(.{ .replica = 9, .counter = 2 }));
}

test "version vector merge and dominance use pointwise maxima" {
    var left = VersionVector.init();
    _ = try left.increment(1);
    _ = try left.increment(1);
    _ = try left.increment(2);

    var right = VersionVector.init();
    _ = try right.increment(1);
    _ = try right.increment(3);
    _ = try right.increment(3);

    try std.testing.expect(!left.dominates(&right));
    try std.testing.expect(!right.dominates(&left));
    try std.testing.expect(left.concurrentWith(&right));

    try left.merge(&right);
    try std.testing.expectEqual(@as(u64, 2), left.counter(1));
    try std.testing.expectEqual(@as(u64, 1), left.counter(2));
    try std.testing.expectEqual(@as(u64, 2), left.counter(3));
    try std.testing.expect(left.dominates(&right));
    try std.testing.expect(!left.concurrentWith(&right));
}

test "version vector detects concurrency after divergent dots" {
    var base = VersionVector.init();
    _ = try base.increment(1);

    var a = base;
    var b = base;
    const a_dot = try a.increment(1);
    const b_dot = try b.increment(2);

    try std.testing.expect(a.contains(a_dot));
    try std.testing.expect(!a.contains(b_dot));
    try std.testing.expect(b.contains(b_dot));
    try std.testing.expect(!b.contains(a_dot));
    try std.testing.expect(a.concurrentWith(&b));

    try a.merge(&b);
    try std.testing.expect(a.dominates(&b));
    try std.testing.expect(a.contains(b_dot));
}

test "version vector mergedLen predicts merge capacity without mutating" {
    var left = VersionVector.init();
    _ = try left.increment(1);
    _ = try left.increment(2);

    var right = VersionVector.init();
    _ = try right.increment(2); // overlaps
    _ = try right.increment(3); // disjoint

    // Union of {1,2} and {2,3} is {1,2,3} = 3 distinct replicas.
    try std.testing.expectEqual(@as(usize, 3), left.mergedLen(&right));
    // Predicate is read-only: neither operand changed.
    try std.testing.expectEqual(@as(usize, 2), left.len);
    try std.testing.expectEqual(@as(usize, 2), right.len);

    // A merge that would exceed the cap is detectable up front.
    var full = VersionVector.init();
    for (0..VersionVector.max_entries) |replica| _ = try full.increment(@intCast(replica));
    var one_more = VersionVector.init();
    _ = try one_more.increment(VersionVector.max_entries); // a fresh replica
    try std.testing.expect(full.mergedLen(&one_more) > VersionVector.max_entries);
    try std.testing.expectEqual(@as(usize, VersionVector.max_entries), full.mergedLen(&full));
}

test "version vector reports capacity and counter overflow explicitly" {
    var full = VersionVector.init();
    for (0..VersionVector.max_entries) |replica| {
        _ = try full.increment(@intCast(replica));
    }
    try std.testing.expectError(error.CapacityExceeded, full.increment(VersionVector.max_entries));

    var overflow = VersionVector{
        .entries = @as([VersionVector.max_entries]VersionVector.Entry, @splat(.{ .replica = 0, .counter = 0 })),
        .len = 1,
    };
    overflow.entries[0] = .{ .replica = 1, .counter = std.math.maxInt(u64) };
    try std.testing.expectError(error.CounterOverflow, overflow.increment(1));
}
