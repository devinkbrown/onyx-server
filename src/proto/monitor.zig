// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 MONITOR state and reply emission.
//!
//! The module owns per-client monitor lists and a reverse index keyed by
//! normalized nick, so nick online/offline transitions can notify only the
//! clients watching that nick.
const std = @import("std");

pub const ClientId = u64;
pub const MAX_NICK_BYTES: usize = 64;
pub const MAX_REPLY_TARGET_BYTES: usize = 400;

/// IRCv3 MONITOR numeric replies.
pub const MonitorNumeric = enum(u16) {
    RPL_MONONLINE = 730,
    RPL_MONOFFLINE = 731,
    RPL_MONLIST = 732,
    RPL_ENDOFMONLIST = 733,
    ERR_MONLISTFULL = 734,

    pub fn code(self: MonitorNumeric) u16 {
        return @intFromEnum(self);
    }
};

pub const MonitorError = std.mem.Allocator.Error || error{
    InvalidSubcommand,
    MissingParameter,
    InvalidTarget,
    OutputTooSmall,
    TooManyReplies,
};

pub const MonitorSubcommand = enum {
    add,
    remove,
    clear,
    list,
    status,
};

/// One structured MONITOR numeric destined for `client`.
pub const MonitorReply = struct {
    numeric: MonitorNumeric,
    client: ClientId,
    targets: []const u8 = "",
    text: []const u8 = "",
};

/// Caller-provided storage for structured MONITOR replies.
pub const MonitorReplySink = struct {
    replies: []MonitorReply,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(
        self: *MonitorReplySink,
        numeric: MonitorNumeric,
        client: ClientId,
        targets: []const u8,
        text: []const u8,
    ) MonitorError!void {
        if (self.count >= self.replies.len) return error.TooManyReplies;
        const targets_copy = try self.copy(targets);
        const text_copy = try self.copy(text);
        self.replies[self.count] = .{
            .numeric = numeric,
            .client = client,
            .targets = targets_copy,
            .text = text_copy,
        };
        self.count += 1;
    }

    pub fn slice(self: *const MonitorReplySink) []const MonitorReply {
        return self.replies[0..self.count];
    }

    fn copy(self: *MonitorReplySink, bytes: []const u8) MonitorError![]const u8 {
        if (self.used + bytes.len > self.storage.len) return error.OutputTooSmall;
        const start = self.used;
        const end = start + bytes.len;
        @memcpy(self.storage[start..end], bytes);
        self.used = end;
        return self.storage[start..end];
    }
};

const NickKey = struct {
    bytes: [MAX_NICK_BYTES]u8 = @splat(0),
    len: u8 = 0,

    fn init(value: []const u8, normalize: bool) MonitorError!NickKey {
        if (!validTarget(value)) return error.InvalidTarget;

        var key = NickKey{ .len = @intCast(value.len) };
        for (value, 0..) |ch, index| {
            key.bytes[index] = if (normalize) asciiLower(ch) else ch;
        }
        return key;
    }

    fn slice(self: *const NickKey) []const u8 {
        return self.bytes[0..self.len];
    }
};

const ClientState = struct {
    targets: std.AutoHashMap(NickKey, NickKey),

    fn init(allocator: std.mem.Allocator) ClientState {
        return .{ .targets = std.AutoHashMap(NickKey, NickKey).init(allocator) };
    }

    fn deinit(self: *ClientState) void {
        self.targets.deinit();
    }
};

const WatcherSet = std.AutoHashMap(ClientId, void);

/// Server-side MONITOR state.
pub const MonitorStore = struct {
    allocator: std.mem.Allocator,
    max_monitor: usize,
    clients: std.AutoHashMap(ClientId, ClientState),
    reverse: std.AutoHashMap(NickKey, WatcherSet),
    online: std.AutoHashMap(NickKey, NickKey),

    pub fn init(allocator: std.mem.Allocator, max_monitor: usize) MonitorStore {
        return .{
            .allocator = allocator,
            .max_monitor = max_monitor,
            .clients = std.AutoHashMap(ClientId, ClientState).init(allocator),
            .reverse = std.AutoHashMap(NickKey, WatcherSet).init(allocator),
            .online = std.AutoHashMap(NickKey, NickKey).init(allocator),
        };
    }

    pub fn deinit(self: *MonitorStore) void {
        var client_it = self.clients.iterator();
        while (client_it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.clients.deinit();

        var reverse_it = self.reverse.iterator();
        while (reverse_it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.reverse.deinit();
        self.online.deinit();
    }

    /// Apply a parsed MONITOR command parameter list.
    pub fn handle(
        self: *MonitorStore,
        client: ClientId,
        params: []const []const u8,
        sink: *MonitorReplySink,
    ) MonitorError!void {
        return self.handleWithLimit(client, params, sink, null);
    }

    /// As `handle`, but `max_override` (when non-null) replaces the store-wide
    /// `max_monitor` for MONITOR + adds — the per-connection-class `monitor` cap.
    pub fn handleWithLimit(
        self: *MonitorStore,
        client: ClientId,
        params: []const []const u8,
        sink: *MonitorReplySink,
        max_override: ?usize,
    ) MonitorError!void {
        if (params.len == 0) return error.MissingParameter;
        const subcommand = try parseSubcommand(params[0]);
        switch (subcommand) {
            .add => {
                if (params.len < 2) return error.MissingParameter;
                try self.addTargetsWithLimit(client, params[1], sink, max_override);
            },
            .remove => {
                if (params.len < 2) return error.MissingParameter;
                try self.removeTargets(client, params[1]);
            },
            .clear => self.clearClient(client),
            .list => try self.emitList(client, sink),
            .status => try self.emitStatus(client, sink),
        }
    }

    /// Add comma-separated monitor targets for one client.
    pub fn addTargets(
        self: *MonitorStore,
        client: ClientId,
        target_list: []const u8,
        sink: *MonitorReplySink,
    ) MonitorError!void {
        return self.addTargetsWithLimit(client, target_list, sink, null);
    }

    /// As `addTargets`, but `max_override` (when non-null) replaces the store-wide
    /// `max_monitor` ceiling for this batch.
    pub fn addTargetsWithLimit(
        self: *MonitorStore,
        client: ClientId,
        target_list: []const u8,
        sink: *MonitorReplySink,
        max_override: ?usize,
    ) MonitorError!void {
        var cursor: usize = 0;
        while (cursor <= target_list.len) {
            const next = findByte(target_list, cursor, ',') orelse target_list.len;
            const target = target_list[cursor..next];
            try self.addOne(client, target, sink, max_override);
            if (next == target_list.len) break;
            cursor = next + 1;
        }
    }

    /// Remove comma-separated monitor targets for one client.
    pub fn removeTargets(
        self: *MonitorStore,
        client: ClientId,
        target_list: []const u8,
    ) MonitorError!void {
        var cursor: usize = 0;
        while (cursor <= target_list.len) {
            const next = findByte(target_list, cursor, ',') orelse target_list.len;
            const target = target_list[cursor..next];
            try self.removeOne(client, target);
            if (next == target_list.len) break;
            cursor = next + 1;
        }
    }

    /// Remove all monitor targets owned by `client`.
    pub fn clearClient(self: *MonitorStore, client: ClientId) void {
        const state = self.clients.getPtr(client) orelse return;
        var it = state.targets.iterator();
        while (it.next()) |entry| {
            self.removeWatcher(entry.key_ptr.*, client);
        }
        state.targets.clearRetainingCapacity();
    }

    /// Drop a disconnecting client from all indexes.
    pub fn removeClient(self: *MonitorStore, client: ClientId) void {
        const removed = self.clients.fetchRemove(client) orelse return;
        var state = removed.value;
        var it = state.targets.iterator();
        while (it.next()) |entry| {
            self.removeWatcher(entry.key_ptr.*, client);
        }
        state.deinit();
    }

    /// Mark `nick` online and notify clients watching it.
    pub fn setOnline(
        self: *MonitorStore,
        nick: []const u8,
        sink: *MonitorReplySink,
    ) MonitorError!void {
        const normalized = try NickKey.init(nick, true);
        if (self.online.contains(normalized)) return;

        const display = try NickKey.init(nick, false);
        try self.online.put(normalized, display);
        try self.notifyWatchers(.RPL_MONONLINE, normalized, display.slice(), sink);
    }

    /// Mark `nick` offline and notify clients watching it.
    pub fn setOffline(
        self: *MonitorStore,
        nick: []const u8,
        sink: *MonitorReplySink,
    ) MonitorError!void {
        const normalized = try NickKey.init(nick, true);
        const removed = self.online.fetchRemove(normalized) orelse return;
        try self.notifyWatchers(.RPL_MONOFFLINE, normalized, removed.value.slice(), sink);
    }

    /// Fill `out` with the clients currently monitoring `nick` (case-insensitive),
    /// returning how many were written (truncated to `out.len`). Used by the
    /// extended-monitor cap to fan a target's state changes to its watchers.
    pub fn watchersOf(self: *MonitorStore, nick: []const u8, out: []ClientId) usize {
        const key = NickKey.init(nick, true) catch return 0;
        const watchers = self.reverse.getPtr(key) orelse return 0;
        var n: usize = 0;
        var it = watchers.keyIterator();
        while (it.next()) |client| {
            if (n >= out.len) break;
            out[n] = client.*;
            n += 1;
        }
        return n;
    }

    pub fn watcherCount(self: *MonitorStore, nick: []const u8) usize {
        const key = NickKey.init(nick, true) catch return 0;
        const watchers = self.reverse.getPtr(key) orelse return 0;
        return watchers.count();
    }

    pub fn isMonitoring(self: *MonitorStore, client: ClientId, target: []const u8) MonitorError!bool {
        const normalized = try NickKey.init(target, true);
        const state = self.clients.getPtr(client) orelse return false;
        return state.targets.contains(normalized);
    }

    pub fn monitorCount(self: *MonitorStore, client: ClientId) usize {
        const state = self.clients.getPtr(client) orelse return 0;
        return state.targets.count();
    }

    /// Fill `out` with `client`'s monitored targets (display form), returning
    /// how many were written (truncated to `out.len`). Slices borrow the
    /// store's entry storage — valid until the store is next mutated. Used by
    /// the Helix upgrade seal to carry the watch list across a USR2.
    pub fn targetsInto(self: *MonitorStore, client: ClientId, out: [][]const u8) usize {
        const state = self.clients.getPtr(client) orelse return 0;
        var n: usize = 0;
        var it = state.targets.iterator();
        while (it.next()) |entry| {
            if (n >= out.len) break;
            out[n] = entry.value_ptr.slice();
            n += 1;
        }
        return n;
    }

    /// Silently re-insert one monitored target for `client` — the Helix
    /// upgrade restore path. Identical index bookkeeping to a `MONITOR +` add
    /// (forward + reverse) but emits NO replies and applies no per-add cap:
    /// the entries were legally added on the predecessor, and re-announcing
    /// an online/offline state the client already knows would be noise.
    pub fn restoreTarget(self: *MonitorStore, client: ClientId, target: []const u8) MonitorError!void {
        const normalized = try NickKey.init(target, true);
        const display = try NickKey.init(target, false);
        const state = try self.clientState(client);
        if (state.targets.contains(normalized)) return;
        try state.targets.put(normalized, display);
        errdefer _ = state.targets.remove(normalized);
        try self.addWatcher(normalized, client);
    }

    fn addOne(
        self: *MonitorStore,
        client: ClientId,
        target: []const u8,
        sink: *MonitorReplySink,
        max_override: ?usize,
    ) MonitorError!void {
        const normalized = try NickKey.init(target, true);
        const display = try NickKey.init(target, false);

        const state = try self.clientState(client);
        if (state.targets.contains(normalized)) return;

        // A per-connection-class cap (when set) overrides the store-wide
        // `max_monitor`; null falls back to the global advertised limit.
        const cap = max_override orelse self.max_monitor;
        if (state.targets.count() >= cap) {
            try sink.append(.ERR_MONLISTFULL, client, target, "Monitor list is full");
            return;
        }

        try state.targets.put(normalized, display);
        errdefer _ = state.targets.remove(normalized);
        try self.addWatcher(normalized, client);

        if (self.online.get(normalized)) |online_display| {
            try sink.append(.RPL_MONONLINE, client, online_display.slice(), "");
        } else {
            try sink.append(.RPL_MONOFFLINE, client, display.slice(), "");
        }
    }

    fn removeOne(
        self: *MonitorStore,
        client: ClientId,
        target: []const u8,
    ) MonitorError!void {
        const normalized = try NickKey.init(target, true);
        const state = self.clients.getPtr(client) orelse return;
        if (!state.targets.remove(normalized)) return;
        self.removeWatcher(normalized, client);
    }

    fn emitList(self: *MonitorStore, client: ClientId, sink: *MonitorReplySink) MonitorError!void {
        const state = self.clients.getPtr(client);
        if (state) |client_state| {
            var chunk = TargetChunk.init(.RPL_MONLIST, client, sink);
            var it = client_state.targets.iterator();
            while (it.next()) |entry| {
                try chunk.add(entry.value_ptr.slice());
            }
            try chunk.flush();
        }
        try sink.append(.RPL_ENDOFMONLIST, client, "", "End of MONITOR list");
    }

    fn emitStatus(self: *MonitorStore, client: ClientId, sink: *MonitorReplySink) MonitorError!void {
        const state = self.clients.getPtr(client) orelse return;
        var online_chunk = TargetChunk.init(.RPL_MONONLINE, client, sink);
        var offline_chunk = TargetChunk.init(.RPL_MONOFFLINE, client, sink);

        var it = state.targets.iterator();
        while (it.next()) |entry| {
            if (self.online.get(entry.key_ptr.*)) |display| {
                try online_chunk.add(display.slice());
            } else {
                try offline_chunk.add(entry.value_ptr.slice());
            }
        }

        try online_chunk.flush();
        try offline_chunk.flush();
    }

    fn clientState(self: *MonitorStore, client: ClientId) MonitorError!*ClientState {
        const gop = try self.clients.getOrPut(client);
        if (!gop.found_existing) {
            gop.value_ptr.* = ClientState.init(self.allocator);
        }
        return gop.value_ptr;
    }

    fn addWatcher(self: *MonitorStore, normalized: NickKey, client: ClientId) MonitorError!void {
        var gop = try self.reverse.getOrPut(normalized);
        if (!gop.found_existing) {
            gop.value_ptr.* = WatcherSet.init(self.allocator);
        }
        try gop.value_ptr.put(client, {});
    }

    fn removeWatcher(self: *MonitorStore, normalized: NickKey, client: ClientId) void {
        const watchers = self.reverse.getPtr(normalized) orelse return;
        _ = watchers.remove(client);
        if (watchers.count() == 0) {
            var removed = self.reverse.fetchRemove(normalized).?;
            removed.value.deinit();
        }
    }

    fn notifyWatchers(
        self: *MonitorStore,
        numeric: MonitorNumeric,
        normalized: NickKey,
        display: []const u8,
        sink: *MonitorReplySink,
    ) MonitorError!void {
        const watchers = self.reverse.getPtr(normalized) orelse return;
        var it = watchers.iterator();
        while (it.next()) |entry| {
            try sink.append(numeric, entry.key_ptr.*, display, "");
        }
    }
};

const TargetChunk = struct {
    numeric: MonitorNumeric,
    client: ClientId,
    sink: *MonitorReplySink,
    buf: [MAX_REPLY_TARGET_BYTES]u8 = undefined,
    len: usize = 0,

    fn init(numeric: MonitorNumeric, client: ClientId, sink: *MonitorReplySink) TargetChunk {
        return .{ .numeric = numeric, .client = client, .sink = sink };
    }

    fn add(self: *TargetChunk, target: []const u8) MonitorError!void {
        if (target.len > self.buf.len) return error.OutputTooSmall;
        const separator: usize = if (self.len == 0) 0 else 1;
        if (self.len != 0 and self.len + separator + target.len > self.buf.len) {
            try self.flush();
        }
        if (self.len != 0) {
            self.buf[self.len] = ',';
            self.len += 1;
        }
        @memcpy(self.buf[self.len .. self.len + target.len], target);
        self.len += target.len;
    }

    fn flush(self: *TargetChunk) MonitorError!void {
        if (self.len == 0) return;
        try self.sink.append(self.numeric, self.client, self.buf[0..self.len], "");
        self.len = 0;
    }
};

pub fn parseSubcommand(token: []const u8) MonitorError!MonitorSubcommand {
    if (token.len != 1) return error.InvalidSubcommand;
    return switch (token[0]) {
        '+' => .add,
        '-' => .remove,
        'C', 'c' => .clear,
        'L', 'l' => .list,
        'S', 's' => .status,
        else => error.InvalidSubcommand,
    };
}

fn validTarget(target: []const u8) bool {
    if (target.len == 0 or target.len > MAX_NICK_BYTES) return false;
    for (target) |ch| {
        switch (ch) {
            0, ',', ':', ' ', '\t', '\r', '\n' => return false,
            else => {},
        }
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn expectReply(
    reply: MonitorReply,
    numeric: MonitorNumeric,
    client: ClientId,
    targets: []const u8,
) !void {
    try std.testing.expectEqual(numeric, reply.numeric);
    try std.testing.expectEqual(client, reply.client);
    try std.testing.expectEqualStrings(targets, reply.targets);
}

test "add remove and list monitor targets" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.handle(1, &.{ "+", "Alice,Bob" }, &sink);
    try std.testing.expectEqual(@as(usize, 2), store.monitorCount(1));
    try expectReply(sink.replies[0], .RPL_MONOFFLINE, 1, "Alice");
    try expectReply(sink.replies[1], .RPL_MONOFFLINE, 1, "Bob");

    try store.removeTargets(1, "alice");
    try std.testing.expect(!try store.isMonitoring(1, "Alice"));
    try std.testing.expect(try store.isMonitoring(1, "Bob"));

    sink.count = 0;
    sink.used = 0;
    try store.handle(1, &.{"L"}, &sink);
    try std.testing.expectEqual(@as(usize, 2), sink.count);
    try expectReply(sink.replies[0], .RPL_MONLIST, 1, "Bob");
    try expectReply(sink.replies[1], .RPL_ENDOFMONLIST, 1, "");

    try store.handle(1, &.{"C"}, &sink);
    try std.testing.expectEqual(@as(usize, 0), store.monitorCount(1));
}

test "online transition notifies only watching clients" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.addTargets(1, "Alice", &sink);
    try store.addTargets(2, "Bob", &sink);
    try store.addTargets(3, "alice", &sink);

    sink.count = 0;
    sink.used = 0;
    try store.setOnline("ALICE", &sink);

    try std.testing.expectEqual(@as(usize, 2), sink.count);
    for (sink.slice()) |reply| {
        try std.testing.expect(reply.client == 1 or reply.client == 3);
        try expectReply(reply, .RPL_MONONLINE, reply.client, "ALICE");
    }
}

test "watchersOf lists the clients monitoring a nick (case-insensitive)" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();
    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.addTargets(1, "Alice", &sink);
    try store.addTargets(3, "alice", &sink);
    try store.addTargets(2, "Bob", &sink);

    var out: [8]ClientId = undefined;
    const n = store.watchersOf("ALICE", &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    var saw1 = false;
    var saw3 = false;
    for (out[0..n]) |c| {
        if (c == 1) saw1 = true;
        if (c == 3) saw3 = true;
    }
    try std.testing.expect(saw1 and saw3);
    try std.testing.expectEqual(@as(usize, 0), store.watchersOf("nobody", &out));
}

test "watchersOf can return more than the old fixed fanout buffer" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();
    var replies: [1]MonitorReply = undefined;
    var storage: [64]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    const watcher_count = 129;
    var client: ClientId = 1;
    while (client <= watcher_count) : (client += 1) {
        sink.count = 0;
        sink.used = 0;
        try store.addTargets(client, "Alice", &sink);
    }

    try std.testing.expectEqual(@as(usize, watcher_count), store.watcherCount("ALICE"));
    var out: [watcher_count]ClientId = undefined;
    const n = store.watchersOf("alice", &out);
    try std.testing.expectEqual(@as(usize, watcher_count), n);

    var saw = @as([watcher_count]bool, @splat(false));
    for (out[0..n]) |watcher| {
        try std.testing.expect(watcher >= 1 and watcher <= watcher_count);
        saw[@intCast(watcher - 1)] = true;
    }
    for (saw) |present| try std.testing.expect(present);
}

test "offline transition notifies watchers" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.addTargets(1, "Alice", &sink);
    sink.count = 0;
    sink.used = 0;

    try store.setOnline("Alice", &sink);
    sink.count = 0;
    sink.used = 0;

    try store.setOffline("alice", &sink);
    try std.testing.expectEqual(@as(usize, 1), sink.count);
    try expectReply(sink.replies[0], .RPL_MONOFFLINE, 1, "Alice");
}

test "list full emits ERR_MONLISTFULL without adding overflow target" {
    var store = MonitorStore.init(std.testing.allocator, 2);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.handle(7, &.{ "+", "a,b,c" }, &sink);
    try std.testing.expectEqual(@as(usize, 2), store.monitorCount(7));
    try std.testing.expect(!try store.isMonitoring(7, "c"));
    try expectReply(sink.replies[2], .ERR_MONLISTFULL, 7, "c");
    try std.testing.expectEqualStrings("Monitor list is full", sink.replies[2].text);
}

test "per-class override tightens the monitor cap below the store-wide limit" {
    // Store-wide limit is generous (8); a class override of 1 must win.
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.handleWithLimit(3, &.{ "+", "a,b" }, &sink, 1);
    try std.testing.expectEqual(@as(usize, 1), store.monitorCount(3));
    try std.testing.expect(try store.isMonitoring(3, "a"));
    try std.testing.expect(!try store.isMonitoring(3, "b"));
    try expectReply(sink.replies[1], .ERR_MONLISTFULL, 3, "b");
}

test "per-class override loosens the monitor cap above the store-wide limit" {
    // Store-wide limit is 1; a class override of 3 must allow all three.
    var store = MonitorStore.init(std.testing.allocator, 1);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };

    try store.handleWithLimit(4, &.{ "+", "a,b,c" }, &sink, 3);
    try std.testing.expectEqual(@as(usize, 3), store.monitorCount(4));
}

test "targetsInto enumerates and restoreTarget silently rebuilds a watch list (Helix)" {
    var store = MonitorStore.init(std.testing.allocator, 8);
    defer store.deinit();

    var replies: [16]MonitorReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = MonitorReplySink{ .replies = &replies, .storage = &storage };
    try store.handle(7, &.{ "+", "Alice,bob" }, &sink);

    // Enumerate: display forms come back, truncated to the out buffer.
    var out: [8][]const u8 = undefined;
    const n = store.targetsInto(7, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    var one: [1][]const u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), store.targetsInto(7, &one));
    // Unknown client enumerates empty.
    try std.testing.expectEqual(@as(usize, 0), store.targetsInto(99, &out));

    // Restore into a fresh store (the successor): silent — no sink involved —
    // and both forward + reverse indexes are rebuilt.
    var succ = MonitorStore.init(std.testing.allocator, 8);
    defer succ.deinit();
    for (out[0..n]) |t| try succ.restoreTarget(42, t);
    try std.testing.expectEqual(@as(usize, 2), succ.monitorCount(42));
    try std.testing.expect(try succ.isMonitoring(42, "alice")); // case-insensitive key
    try std.testing.expectEqual(@as(usize, 1), succ.watcherCount("BOB")); // reverse index live
    // Idempotent: restoring an existing target is a no-op.
    try succ.restoreTarget(42, "Alice");
    try std.testing.expectEqual(@as(usize, 2), succ.monitorCount(42));
}
