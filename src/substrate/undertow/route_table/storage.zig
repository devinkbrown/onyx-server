// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned route-table storage records and their local mutation helpers.
const std = @import("std");
const membership_event = @import("../../../proto/membership_event.zig");
const contracts = @import("contracts.zig");
const NodeId = contracts.NodeId;
const Error = contracts.Error;
const ChannelListEntry = contracts.ChannelListEntry;
const ChannelListKind = contracts.ChannelListKind;
const Member = contracts.Member;

/// Allocation-free, owned key for the S2S protocol's bounded nick namespace.
/// Every byte is initialized so AutoHashMap equality/hash never observes padding
/// or stale stack contents. Route-table-only names beyond the wire bound bypass
/// the optional index and use the authoritative roster scan.
pub const NickKey = struct {
    bytes: [membership_event.max_nick_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn init(nick: []const u8) ?NickKey {
        if (nick.len == 0 or nick.len > membership_event.max_nick_len) return null;
        var key = NickKey{ .len = @intCast(nick.len) };
        _ = std.ascii.lowerString(key.bytes[0..nick.len], nick);
        return key;
    }
};

pub const NodeRef = struct {
    id: NodeId,
    members: u32 = 1,
};

pub const ChannelState = struct {
    nodes: []NodeRef,
    len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) Error!ChannelState {
        return .{ .nodes = try allocator.alloc(NodeRef, capacity) };
    }

    pub fn deinit(self: *ChannelState, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn addMember(self: *ChannelState, node: NodeId) Error!void {
        if (self.find(node)) |idx| {
            if (self.nodes[idx].members == std.math.maxInt(u32)) {
                return error.MemberCountOverflow;
            }
            self.nodes[idx].members += 1;
            return;
        }

        if (self.len == self.nodes.len) return error.ChannelFanoutFull;
        self.nodes[self.len] = .{ .id = node };
        self.len += 1;
    }

    pub fn removeMember(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        if (self.nodes[idx].members > 1) {
            self.nodes[idx].members -= 1;
            return;
        }
        self.swapRemove(idx);
    }

    pub fn removeNode(self: *ChannelState, node: NodeId) void {
        const idx = self.find(node) orelse return;
        self.swapRemove(idx);
    }

    pub fn copyNodes(self: *const ChannelState, out: []NodeId) Error!usize {
        if (out.len < self.len) return error.BufferTooSmall;
        for (self.nodes[0..self.len], 0..) |entry, idx| out[idx] = entry.id;
        return self.len;
    }

    pub fn find(self: *const ChannelState, node: NodeId) ?usize {
        for (self.nodes[0..self.len], 0..) |entry, idx| {
            if (entry.id == node) return idx;
        }
        return null;
    }

    pub fn swapRemove(self: *ChannelState, idx: usize) void {
        self.len -= 1;
        if (idx != self.len) self.nodes[idx] = self.nodes[self.len];
    }
};

pub const ChannelListState = struct {
    entries: std.ArrayListUnmanaged(ChannelListEntry) = .empty,

    pub fn deinit(self: *ChannelListState, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*entry| {
            allocator.free(entry.mask);
            allocator.free(entry.setter);
        }
        self.entries.deinit(allocator);
    }

    pub fn find(self: *const ChannelListState, kind: ChannelListKind, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (entry.kind == kind and std.mem.eql(u8, entry.mask, mask)) return i;
        }
        return null;
    }
};

/// Per-channel member roster (flat list — channels are bounded, and a flat list
/// keeps ownership trivial: owned nick + identity strings per entry).
pub const MemberList = struct {
    entries: std.ArrayListUnmanaged(Member) = .empty,

    pub fn deinit(self: *MemberList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |m| m.freeStrings(allocator);
        self.entries.deinit(allocator);
    }

    pub fn find(self: *const MemberList, nick: []const u8) ?usize {
        for (self.entries.items, 0..) |m, i| {
            if (std.mem.eql(u8, m.nick, nick)) return i;
        }
        return null;
    }
};

/// LWW PART tombstone for one (channel, nick, origin-node) triple.
///
/// Without these, a PART that arrives *before* a lower-HLC JOIN is discarded as
/// "unknown member", and the later JOIN resurrects a member the origin already
/// retracted — classic LWW-without-tombstone divergence under reordering. Channel
/// list masks already keep tombstones for the same reason (`ChannelListEntry.present`);
/// membership needs the same lattice so out-of-order gossip converges.
pub const PartTombstone = struct {
    nick: []u8,
    node: NodeId,
    hlc: u64,
    /// Receiver-local stamp for `pruneStale` GC (same clock domain as Member.last_refreshed_ms).
    stamped_ms: i64,

    pub fn free(self: *const PartTombstone, allocator: std.mem.Allocator) void {
        allocator.free(self.nick);
    }
};

pub const PartTombList = struct {
    entries: std.ArrayListUnmanaged(PartTombstone) = .empty,

    pub fn deinit(self: *PartTombList, allocator: std.mem.Allocator) void {
        for (self.entries.items) |t| t.free(allocator);
        self.entries.deinit(allocator);
    }

    pub fn find(self: *const PartTombList, nick: []const u8, node: NodeId) ?usize {
        for (self.entries.items, 0..) |t, i| {
            if (t.node == node and std.mem.eql(u8, t.nick, nick)) return i;
        }
        return null;
    }
};
