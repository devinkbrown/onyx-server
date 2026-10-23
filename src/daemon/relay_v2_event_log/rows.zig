// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned retained rows and sorted membership/cursor operations.
const std = @import("std");
const message_relay_v2 = @import("../../substrate/undertow/message_relay_v2.zig");
const RelayId = message_relay_v2.RelayId;

pub const Row = struct {
    relay_id: RelayId,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
    origin_node: u64,
    hlc: u64,
    wire: []u8,
    required_nodes: std.ArrayListUnmanaged(u64) = .empty,
    confirmed_nodes: std.ArrayListUnmanaged(u64) = .empty,
    excluded_once_nodes: std.ArrayListUnmanaged(u64) = .empty,

    pub fn deinit(self: *Row, allocator: std.mem.Allocator) void {
        allocator.free(self.wire);
        self.required_nodes.deinit(allocator);
        self.confirmed_nodes.deinit(allocator);
        self.excluded_once_nodes.deinit(allocator);
        self.* = undefined;
    }
};

pub const CursorEntry = struct {
    node: u64,
    /// The last origin considered for this target. The next page starts at the
    /// first lexicographically greater origin and wraps once, which provides
    /// fairness without ever stepping past that origin's lowest missing HLC.
    after_origin_pubkey: [message_relay_v2.pubkey_len]u8,
};

pub fn rowMissingForTarget(row: Row, target_node: u64) bool {
    return containsNode(row.required_nodes.items, target_node) and
        !containsNode(row.confirmed_nodes.items, target_node);
}

pub fn pubkeyLess(
    a: [message_relay_v2.pubkey_len]u8,
    b: [message_relay_v2.pubkey_len]u8,
) bool {
    return std.mem.lessThan(u8, &a, &b);
}

pub fn originEqual(
    a: [message_relay_v2.pubkey_len]u8,
    b: [message_relay_v2.pubkey_len]u8,
) bool {
    return std.mem.eql(u8, &a, &b);
}

pub fn headLess(a: Row, b: Row) bool {
    return a.hlc < b.hlc or
        (a.hlc == b.hlc and idLess(a.relay_id, b.relay_id));
}

/// Select the lowest-HLC missing row for the lexicographically first origin in
/// `(after, upper]`. A null bound is open-ended. Repeated calls walk distinct
/// origins, never multiple rows from one origin in the same page.
pub fn nextOriginHead(
    rows: []const Row,
    target_node: u64,
    after: ?[message_relay_v2.pubkey_len]u8,
    upper: ?[message_relay_v2.pubkey_len]u8,
) ?usize {
    var best: ?usize = null;
    for (rows, 0..) |row, index| {
        if (!rowMissingForTarget(row, target_node)) continue;
        if (after) |lower| if (!pubkeyLess(lower, row.origin_pubkey)) continue;
        if (upper) |limit| if (pubkeyLess(limit, row.origin_pubkey)) continue;
        if (best) |best_index| {
            const selected = rows[best_index];
            if (pubkeyLess(row.origin_pubkey, selected.origin_pubkey) or
                (originEqual(row.origin_pubkey, selected.origin_pubkey) and headLess(row, selected)))
            {
                best = index;
            }
        } else {
            best = index;
        }
    }
    return best;
}

pub fn greatestMissingOrigin(
    rows: []const Row,
    target_node: u64,
) ?[message_relay_v2.pubkey_len]u8 {
    var greatest: ?[message_relay_v2.pubkey_len]u8 = null;
    for (rows) |row| {
        if (!rowMissingForTarget(row, target_node)) continue;
        if (greatest == null or pubkeyLess(greatest.?, row.origin_pubkey))
            greatest = row.origin_pubkey;
    }
    return greatest;
}

pub fn greatestOrigin(rows: []const Row) ?[message_relay_v2.pubkey_len]u8 {
    var greatest: ?[message_relay_v2.pubkey_len]u8 = null;
    for (rows) |row| {
        if (greatest == null or pubkeyLess(greatest.?, row.origin_pubkey))
            greatest = row.origin_pubkey;
    }
    return greatest;
}

pub fn containsOrigin(
    rows: []const Row,
    origin_pubkey: [message_relay_v2.pubkey_len]u8,
) bool {
    for (rows) |row| if (originEqual(row.origin_pubkey, origin_pubkey)) return true;
    return false;
}

pub fn idsEqual(a: RelayId, b: RelayId) bool {
    return std.mem.eql(u8, &a, &b);
}

pub fn idLess(a: RelayId, b: RelayId) bool {
    return std.mem.lessThan(u8, &a, &b);
}

pub fn lowerBoundRows(rows: []const Row, relay_id: RelayId) usize {
    var lo: usize = 0;
    var hi = rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (idLess(rows[mid].relay_id, relay_id))
            lo = mid + 1
        else
            hi = mid;
    }
    return lo;
}

pub fn lowerBoundNodes(nodes: []const u64, node: u64) usize {
    var lo: usize = 0;
    var hi = nodes.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (nodes[mid] < node)
            lo = mid + 1
        else
            hi = mid;
    }
    return lo;
}

pub fn lowerBoundCursors(cursors: []const CursorEntry, node: u64) usize {
    var lo: usize = 0;
    var hi = cursors.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (cursors[mid].node < node) lo = mid + 1 else hi = mid;
    }
    return lo;
}

pub fn containsNode(nodes: []const u64, node: u64) bool {
    const index = lowerBoundNodes(nodes, node);
    return index < nodes.len and nodes[index] == node;
}

pub fn nodeIndex(nodes: []const u64, node: u64) ?usize {
    const index = lowerBoundNodes(nodes, node);
    return if (index < nodes.len and nodes[index] == node) index else null;
}

pub fn insertNodeAssumeCapacity(nodes: *std.ArrayListUnmanaged(u64), index: usize, node: u64) void {
    const old_len = nodes.items.len;
    nodes.appendAssumeCapacity(undefined);
    var cursor = old_len;
    while (cursor > index) : (cursor -= 1) nodes.items[cursor] = nodes.items[cursor - 1];
    nodes.items[index] = node;
}

pub fn insertCursorAssumeCapacity(cursors: *std.ArrayListUnmanaged(CursorEntry), index: usize, entry: CursorEntry) void {
    const old_len = cursors.items.len;
    cursors.appendAssumeCapacity(undefined);
    var cursor = old_len;
    while (cursor > index) : (cursor -= 1) cursors.items[cursor] = cursors.items[cursor - 1];
    cursors.items[index] = entry;
}

pub fn removeNodeAt(nodes: *std.ArrayListUnmanaged(u64), index: usize) void {
    var cursor = index;
    while (cursor + 1 < nodes.items.len) : (cursor += 1) nodes.items[cursor] = nodes.items[cursor + 1];
    nodes.items.len -= 1;
}

pub fn removeRowSlot(rows: *std.ArrayListUnmanaged(Row), index: usize) void {
    var cursor = index;
    while (cursor + 1 < rows.items.len) : (cursor += 1) rows.items[cursor] = rows.items[cursor + 1];
    rows.items.len -= 1;
}

pub fn removeCursorSlot(cursors: *std.ArrayListUnmanaged(CursorEntry), index: usize) void {
    var cursor = index;
    while (cursor + 1 < cursors.items.len) : (cursor += 1) cursors.items[cursor] = cursors.items[cursor + 1];
    cursors.items.len -= 1;
}
