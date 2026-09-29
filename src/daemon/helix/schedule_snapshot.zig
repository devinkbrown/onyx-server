// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deferred channel messages and oper actions carried across a Helix UPGRADE.
//!
//! The image is the due-record only: id, when, target, sender, and whether
//! reactor 0 has already fired it. The message body stays in the memo store
//! and, once fired, in history. Magic "SCHD" rides the existing
//! `.mesh_checkpoint` family at `min_supported = 2`. There is no new capsule
//! kind. A predecessor arena that lacks the piece still adopts. A present but
//! malformed or duplicate image rejects the whole handoff.
//!
//! The table is one heap allocation so `LinuxServer.init` does not put it on
//! the caller's stack.

const std = @import("std");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
    TooMany,
    InvalidSchedule,
};

pub const magic = [_]u8{ 'S', 'C', 'H', 'D' };
pub const version: u8 = 1;

/// Product bound for pending and already-fired jobs. Not a peer-capacity lock.
pub const max_jobs: usize = 256;
pub const max_target: usize = 64;
pub const max_sender: usize = 32;
pub const max_key: usize = 24;
pub const max_cron: usize = 48;

pub const kind_channel: u8 = 1;
pub const kind_oper: u8 = 2;
pub const when_timestamp: u8 = 1;
pub const when_cron: u8 = 2;

pub fn keyFromId(id: u64, out: *[max_key]u8) []const u8 {
    const hex = "0123456789abcdef";
    out[0] = 's';
    var i: usize = 16;
    var value = id;
    while (i > 0) {
        i -= 1;
        out[1 + i] = hex[@as(usize, @intCast(value & 0xf))];
        value >>= 4;
    }
    return out[0..17];
}

const Job = struct {
    used: bool = false,
    fired: bool = false,
    kind: u8 = 0,
    when_kind: u8 = 0,
    mode: u8 = 0,
    target_len: u8 = 0,
    sender_len: u8 = 0,
    key_len: u8 = 0,
    cron_len: u8 = 0,
    due_ms: i64 = 0,
    id: u64 = 0,
    target: [max_target]u8 = @splat(0),
    sender: [max_sender]u8 = @splat(0),
    key: [max_key]u8 = @splat(0),
    cron: [max_cron]u8 = @splat(0),

    fn targetSlice(self: *const Job) []const u8 {
        return self.target[0..self.target_len];
    }

    fn senderSlice(self: *const Job) []const u8 {
        return self.sender[0..self.sender_len];
    }

    fn keySlice(self: *const Job) []const u8 {
        return self.key[0..self.key_len];
    }

    fn cronSlice(self: *const Job) []const u8 {
        return self.cron[0..self.cron_len];
    }
};

const Storage = struct {
    next_id: u64 = 1,
    jobs: [max_jobs]Job = @splat(.{}),
};

pub const Fired = struct {
    id: u64,
    kind: u8,
    mode: u8,
    due_ms: i64,
    target: [max_target]u8,
    target_len: u8,
    sender: [max_sender]u8,
    sender_len: u8,
    key: [max_key]u8,
    key_len: u8,

    pub fn targetSlice(self: *const Fired) []const u8 {
        return self.target[0..self.target_len];
    }

    pub fn senderSlice(self: *const Fired) []const u8 {
        return self.sender[0..self.sender_len];
    }

    pub fn keySlice(self: *const Fired) []const u8 {
        return self.key[0..self.key_len];
    }
};

pub const NewJob = struct {
    id: u64,
    kind: u8,
    when_kind: u8,
    mode: u8 = 0,
    due_ms: i64,
    target: []const u8,
    sender: []const u8,
    key: []const u8,
    cron: []const u8 = "",
    fired: bool = false,
};

pub const Table = struct {
    allocator: std.mem.Allocator = undefined,
    storage: ?*Storage = null,

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!Table {
        const storage = try allocator.create(Storage);
        storage.* = .{};
        return .{ .allocator = allocator, .storage = storage };
    }

    pub fn deinit(self: *Table) void {
        if (self.storage) |storage| self.allocator.destroy(storage);
        self.storage = null;
    }

    pub fn clear(self: *Table) void {
        const storage = self.storage orelse return;
        storage.jobs = @splat(.{});
    }

    pub fn count(self: *const Table) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (storage.jobs) |job| {
            if (job.used) n += 1;
        }
        return n;
    }

    pub fn pendingCount(self: *const Table) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (storage.jobs) |job| {
            if (job.used and !job.fired) n += 1;
        }
        return n;
    }

    pub fn takeId(self: *Table) Error!u64 {
        const storage = self.storage orelse return error.InvalidSchedule;
        if (self.count() >= max_jobs) return error.TooMany;
        const id = storage.next_id;
        if (id == 0) return error.InvalidSchedule;
        storage.next_id += 1;
        return id;
    }

    pub fn insert(self: *Table, job: NewJob) Error!void {
        try self.insertExact(job, false);
    }

    pub fn find(self: *const Table, kind: u8, target: []const u8) ?usize {
        const storage = self.storage orelse return null;
        for (storage.jobs, 0..) |job, index| {
            if (!job.used or job.kind != kind) continue;
            if (std.mem.eql(u8, job.targetSlice(), target)) return index;
        }
        return null;
    }

    pub fn dueMsAt(self: *const Table, index: usize) i64 {
        const storage = self.storage orelse return 0;
        if (index >= storage.jobs.len or !storage.jobs[index].used) return 0;
        return storage.jobs[index].due_ms;
    }

    pub fn firedAt(self: *const Table, index: usize) bool {
        const storage = self.storage orelse return false;
        if (index >= storage.jobs.len or !storage.jobs[index].used) return false;
        return storage.jobs[index].fired;
    }

    pub fn memoKeyAt(self: *const Table, index: usize) []const u8 {
        const storage = self.storage orelse return "";
        if (index >= storage.jobs.len or !storage.jobs[index].used) return "";
        return storage.jobs[index].keySlice();
    }

    /// Mark every pending job whose due time has arrived, and copy it out.
    /// The fired bit is set before the caller sends, so a second pass cannot
    /// deliver the same job.
    pub fn claimDue(self: *Table, now_ms: i64, out: []Fired) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (&storage.jobs) |*job| {
            if (!job.used or job.fired) continue;
            if (job.due_ms > now_ms) continue;
            job.fired = true;
            if (n >= out.len) continue;
            out[n] = .{
                .id = job.id,
                .kind = job.kind,
                .mode = job.mode,
                .due_ms = job.due_ms,
                .target = job.target,
                .target_len = job.target_len,
                .sender = job.sender,
                .sender_len = job.sender_len,
                .key = job.key,
                .key_len = job.key_len,
            };
            n += 1;
        }
        return n;
    }

    pub fn replace(self: *Table, snap: Snapshot) usize {
        self.clear();
        const storage = self.storage orelse return snap.count;
        storage.next_id = snap.next_id;
        var dropped: usize = 0;
        var it = snap.iterator();
        while (it.next()) |job| {
            self.insertExact(job, job.fired) catch {
                dropped += 1;
                continue;
            };
        }
        return dropped;
    }

    fn insertExact(self: *Table, job: NewJob, fired: bool) Error!void {
        const storage = self.storage orelse return error.InvalidSchedule;
        if (job.id == 0 or job.id >= storage.next_id) return error.InvalidSchedule;
        if (job.kind != kind_channel and job.kind != kind_oper) return error.InvalidSchedule;
        if (job.when_kind != when_timestamp and job.when_kind != when_cron) return error.InvalidSchedule;
        if (job.target.len == 0 or job.target.len > max_target) return error.InvalidSchedule;
        if (job.sender.len == 0 or job.sender.len > max_sender) return error.InvalidSchedule;
        if (job.key.len == 0 or job.key.len > max_key) return error.InvalidSchedule;
        if (job.cron.len > max_cron) return error.InvalidSchedule;
        if (job.when_kind == when_cron and job.cron.len == 0) return error.InvalidSchedule;
        if (job.when_kind == when_timestamp and job.cron.len != 0) return error.InvalidSchedule;
        if (job.kind == kind_channel and job.mode != 0) return error.InvalidSchedule;
        if (job.kind == kind_oper and !isModeLetter(job.mode)) return error.InvalidSchedule;
        if (self.find(job.kind, job.target) != null) return error.InvalidSchedule;
        const slot = freeSlot(storage) orelse return error.TooMany;
        slot.* = .{};
        slot.id = job.id;
        slot.kind = job.kind;
        slot.when_kind = job.when_kind;
        slot.mode = job.mode;
        slot.due_ms = job.due_ms;
        slot.fired = fired;
        @memcpy(slot.target[0..job.target.len], job.target);
        slot.target_len = @intCast(job.target.len);
        @memcpy(slot.sender[0..job.sender.len], job.sender);
        slot.sender_len = @intCast(job.sender.len);
        @memcpy(slot.key[0..job.key.len], job.key);
        slot.key_len = @intCast(job.key.len);
        if (job.cron.len != 0) {
            @memcpy(slot.cron[0..job.cron.len], job.cron);
            slot.cron_len = @intCast(job.cron.len);
        }
        slot.used = true;
    }
};

fn isModeLetter(letter: u8) bool {
    return switch (letter) {
        'i', 'm', 'n', 't', 's', 'C', 'T', 'N', 'g', 'S', 'M' => true,
        else => false,
    };
}

fn freeSlot(storage: *Storage) ?*Job {
    for (&storage.jobs) |*slot| {
        if (!slot.used) return slot;
    }
    return null;
}

pub const Snapshot = struct {
    next_id: u64,
    count: usize,
    records: []const u8,

    pub fn iterator(self: Snapshot) Iterator {
        return .{ .buf = self.records, .left = self.count };
    }
};

pub const Iterator = struct {
    buf: []const u8,
    left: usize,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?NewJob {
        if (self.left == 0) return null;
        var reader = Reader{ .buf = self.buf, .pos = self.pos };
        const id = reader.int(u64) orelse return null;
        const kind = reader.byte() orelse return null;
        const when_kind = reader.byte() orelse return null;
        const fired_byte = reader.byte() orelse return null;
        const mode = reader.byte() orelse return null;
        const due_ms = reader.int(i64) orelse return null;
        const target = reader.shortSlice() orelse return null;
        const sender = reader.shortSlice() orelse return null;
        const key = reader.shortSlice() orelse return null;
        const cron_expr = reader.shortSlice() orelse return null;
        self.pos = reader.pos;
        self.left -= 1;
        return .{
            .id = id,
            .kind = kind,
            .when_kind = when_kind,
            .mode = mode,
            .due_ms = due_ms,
            .target = target,
            .sender = sender,
            .key = key,
            .cron = cron_expr,
            .fired = fired_byte != 0,
        };
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encodeFrom(allocator: std.mem.Allocator, table: *const Table) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &magic);
    try out.append(allocator, version);
    const storage = table.storage orelse return error.InvalidSchedule;
    try appendInt(&out, allocator, u64, storage.next_id);
    const count_off = out.items.len;
    try appendInt(&out, allocator, u32, 0);
    var job_count: u32 = 0;
    for (storage.jobs) |job| {
        if (!job.used) continue;
        if (job_count == max_jobs) return error.TooMany;
        try appendInt(&out, allocator, u64, job.id);
        try out.append(allocator, job.kind);
        try out.append(allocator, job.when_kind);
        try out.append(allocator, if (job.fired) 1 else 0);
        try out.append(allocator, job.mode);
        try appendInt(&out, allocator, i64, job.due_ms);
        try appendLenBytes(&out, allocator, job.targetSlice());
        try appendLenBytes(&out, allocator, job.senderSlice());
        try appendLenBytes(&out, allocator, job.keySlice());
        try appendLenBytes(&out, allocator, job.cronSlice());
        job_count += 1;
    }
    std.mem.writeInt(u32, out.items[count_off..][0..4], job_count, .little);
    _ = try decodeCurrent(out.items);
    return out.toOwnedSlice(allocator);
}

pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1 + 8 + 4) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    const next_id = std.mem.readInt(u64, bytes[magic.len + 1 ..][0..8], .little);
    const count = std.mem.readInt(u32, bytes[magic.len + 1 + 8 ..][0..4], .little);
    if (next_id == 0 or count > max_jobs) return error.InvalidSchedule;
    const records = bytes[magic.len + 1 + 8 + 4 ..];
    var reader = Reader{ .buf = records };
    var seen_ids: [max_jobs]u64 = undefined;
    var seen_channel: [max_jobs][]const u8 = undefined;
    var seen_oper: [max_jobs][]const u8 = undefined;
    var channel_n: usize = 0;
    var oper_n: usize = 0;
    var seen: usize = 0;
    var max_id: u64 = 0;
    while (seen < count) : (seen += 1) {
        const id = reader.int(u64) orelse return error.Truncated;
        const kind = reader.byte() orelse return error.Truncated;
        const when_kind = reader.byte() orelse return error.Truncated;
        const fired_byte = reader.byte() orelse return error.Truncated;
        const mode = reader.byte() orelse return error.Truncated;
        _ = reader.int(i64) orelse return error.Truncated;
        const target = reader.shortSlice() orelse return error.Truncated;
        const sender = reader.shortSlice() orelse return error.Truncated;
        const key = reader.shortSlice() orelse return error.Truncated;
        const cron_expr = reader.shortSlice() orelse return error.Truncated;
        if (id == 0 or id >= next_id) return error.InvalidSchedule;
        if (fired_byte > 1) return error.InvalidSchedule;
        if (kind != kind_channel and kind != kind_oper) return error.InvalidSchedule;
        if (when_kind != when_timestamp and when_kind != when_cron) return error.InvalidSchedule;
        if (target.len == 0 or target.len > max_target) return error.InvalidSchedule;
        if (sender.len == 0 or sender.len > max_sender) return error.InvalidSchedule;
        if (key.len == 0 or key.len > max_key) return error.InvalidSchedule;
        if (when_kind == when_cron and (cron_expr.len == 0 or cron_expr.len > max_cron)) return error.InvalidSchedule;
        if (when_kind == when_timestamp and cron_expr.len != 0) return error.InvalidSchedule;
        if (kind == kind_channel and mode != 0) return error.InvalidSchedule;
        if (kind == kind_oper and !isModeLetter(mode)) return error.InvalidSchedule;
        for (seen_ids[0..seen]) |prior| {
            if (prior == id) return error.InvalidSchedule;
        }
        if (kind == kind_channel) {
            for (seen_channel[0..channel_n]) |prior| {
                if (std.mem.eql(u8, prior, target)) return error.InvalidSchedule;
            }
            seen_channel[channel_n] = target;
            channel_n += 1;
        } else {
            for (seen_oper[0..oper_n]) |prior| {
                if (std.mem.eql(u8, prior, target)) return error.InvalidSchedule;
            }
            seen_oper[oper_n] = target;
            oper_n += 1;
        }
        seen_ids[seen] = id;
        if (id > max_id) max_id = id;
    }
    if (count != 0 and max_id >= next_id) return error.InvalidSchedule;
    if (reader.pos != records.len) return error.TrailingBytes;
    return .{ .next_id = next_id, .count = count, .records = records };
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    _ = try decodeCurrent(bytes);
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendLenBytes(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) (Error || std.mem.Allocator.Error)!void {
    if (bytes.len > 255) return error.InvalidSchedule;
    try out.append(allocator, @intCast(bytes.len));
    if (bytes.len != 0) try out.appendSlice(allocator, bytes);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *Reader) ?u8 {
        if (self.pos >= self.buf.len) return null;
        defer self.pos += 1;
        return self.buf[self.pos];
    }

    fn int(self: *Reader, comptime T: type) ?T {
        if (self.pos > self.buf.len or self.buf.len - self.pos < @sizeOf(T)) return null;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }

    fn shortSlice(self: *Reader) ?[]const u8 {
        if (self.pos >= self.buf.len) return null;
        const n: usize = self.buf[self.pos];
        if (self.buf.len - self.pos - 1 < n) return null;
        defer self.pos += 1 + n;
        return self.buf[self.pos + 1 ..][0..n];
    }
};

test "GAP-P3 schedule snapshot round trip keeps a fired job from firing again" {
    const allocator = std.testing.allocator;
    var table = try Table.init(allocator);
    defer table.deinit();
    const id = try table.takeId();
    var key_buf: [max_key]u8 = undefined;
    const key = keyFromId(id, &key_buf);
    try table.insert(.{
        .id = id,
        .kind = kind_channel,
        .when_kind = when_timestamp,
        .due_ms = 50,
        .target = "#room",
        .sender = "alice",
        .key = key,
    });
    var claimed: [4]Fired = undefined;
    try std.testing.expectEqual(@as(usize, 1), table.claimDue(50, &claimed));
    try std.testing.expectEqual(@as(usize, 0), table.claimDue(50, &claimed));
    try std.testing.expect(table.firedAt(table.find(kind_channel, "#room").?));

    const wire = try encodeFrom(allocator, &table);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    const snap = try decodeCurrent(wire);
    var restored = try Table.init(allocator);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), restored.replace(snap));
    const slot = restored.find(kind_channel, "#room") orelse return error.TestUnexpectedResult;
    try std.testing.expect(restored.firedAt(slot));
    try std.testing.expectEqual(@as(usize, 0), restored.claimDue(1_000, &claimed));
    try std.testing.expectEqualStrings(key, restored.memoKeyAt(slot));

    var bad = try allocator.dupe(u8, wire);
    defer allocator.free(bad);
    bad[magic.len] = 0xff;
    try std.testing.expectError(error.UnsupportedVersion, decodeCurrent(bad));
}
