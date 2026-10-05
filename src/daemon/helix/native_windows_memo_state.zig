// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for RAM-only memo policy and accepted first
//! messages. Each decode creates a detached owner for a no-fail by-value swap.

const std = @import("std");
const forward = @import("../svc_memo_forward.zig");
const ignore = @import("../svc_memo_ignore.zig");
const first_hold = @import("../first_hold.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const forward_magic = [_]u8{ 'H', 'X', 'M', 'F' };
pub const ignore_magic = [_]u8{ 'H', 'X', 'M', 'I' };
pub const first_hold_magic = [_]u8{ 'H', 'X', 'F', 'H' };
pub const max_checkpoint_bytes = wire.max_checkpoint_bytes;
pub const Error = wire.Error;

const forward_domain = "onyx-windows-memo-forward-checkpoint-v1";
const ignore_domain = "onyx-windows-memo-ignore-checkpoint-v1";
const first_hold_domain = "onyx-windows-first-hold-checkpoint-v1";
const header_len: usize = 16;
const forward_limits = forward.Params{};

pub fn isForward(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, forward_magic);
}

pub fn isIgnore(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, ignore_magic);
}

pub fn isFirstHold(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, first_hold_magic);
}

/// Sorted account keys make duplicate validation allocation-free.
pub fn validateForward(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, forward_magic, header_len, forward_domain);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > forward_limits.max_accounts) return error.CheckpointTooLarge;
    if (count > body.len / 4) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var previous: ?[]const u8 = null;
    for (0..count) |_| {
        const account_len: usize = try reader.readByte();
        const target_len: usize = try reader.readByte();
        const account = try reader.take(account_len);
        const target = try reader.take(target_len);
        if (!validForwardAccount(account) or !validForwardAccount(target) or
            std.mem.eql(u8, account, target)) return error.InvalidField;
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, account)) return error.NonCanonicalOrder;
        }
        previous = account;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encodeForward(allocator: std.mem.Allocator, source: *const forward.MemoForwardStore) Error![]u8 {
    const count = source.forwards.count();
    if (count > forward_limits.max_accounts) return error.CheckpointTooLarge;
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    var size: usize = header_len + wire.checksum_len;
    var it = source.forwards.iterator();
    var index: usize = 0;
    while (it.next()) |entry| {
        const account = entry.key_ptr.*;
        const target = entry.value_ptr.target;
        if (!validForwardAccount(account) or !validForwardAccount(target) or
            std.mem.eql(u8, account, target)) return error.InvalidField;
        keys[index] = account;
        index += 1;
        try wire.addLen(&size, 2 + account.len + target.len);
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, keys, {}, lessText);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writeHeader(&writer, forward_magic, size, @intCast(count));
    for (keys) |account| {
        const target = source.forwards.get(account).?.target;
        writer.writeByte(@intCast(account.len));
        writer.writeByte(@intCast(target.len));
        writer.writeBytes(account);
        writer.writeBytes(target);
    }
    wire.finish(&writer, forward_domain);
    try validateForward(bytes);
    return bytes;
}

pub fn decodeForward(allocator: std.mem.Allocator, bytes: []const u8) Error!forward.MemoForwardStore {
    try validateForward(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result = forward.MemoForwardStore.init(allocator);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const account_len: usize = try reader.readByte();
        const target_len: usize = try reader.readByte();
        const account = try reader.take(account_len);
        const target = try reader.take(target_len);
        result.setForward(account, target) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
    }
    return result;
}

/// Recipient rows are sorted; senders remain in their original list order.
/// Empty rows are retained because a failed first append can leave one live.
pub fn validateIgnore(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, ignore_magic, header_len, ignore_domain);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    if (count > ignore.DEFAULT_MAX_ACCOUNTS) return error.CheckpointTooLarge;
    if (count > body.len / 3) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var previous: ?[]const u8 = null;
    for (0..count) |_| {
        const account_len: usize = try reader.readByte();
        const entry_count: usize = try reader.readByte();
        if (entry_count > ignore.DEFAULT_MAX_ENTRIES_PER_ACCOUNT) return error.InvalidField;
        const account = try reader.take(account_len);
        if (!validIgnoreAccount(account)) return error.InvalidField;
        if (previous) |prior| {
            if (!std.mem.lessThan(u8, prior, account)) return error.NonCanonicalOrder;
        }
        previous = account;
        var senders: [ignore.DEFAULT_MAX_ENTRIES_PER_ACCOUNT][]const u8 = undefined;
        for (0..entry_count) |index| {
            const sender_len: usize = try reader.readByte();
            const sender = try reader.take(sender_len);
            ignore.validateSender(sender) catch return error.InvalidField;
            for (senders[0..index]) |prior| {
                if (std.ascii.eqlIgnoreCase(prior, sender)) return error.DuplicateEntry;
            }
            senders[index] = sender;
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub fn encodeIgnore(allocator: std.mem.Allocator, source: *const ignore.MemoIgnoreList) Error![]u8 {
    const count = source.accounts.count();
    if (count > ignore.DEFAULT_MAX_ACCOUNTS) return error.CheckpointTooLarge;
    const keys = try allocator.alloc([]const u8, count);
    defer allocator.free(keys);
    var size: usize = header_len + wire.checksum_len;
    var it = source.accounts.iterator();
    var index: usize = 0;
    while (it.next()) |entry| {
        const account = entry.key_ptr.*;
        const senders = entry.value_ptr.items.items;
        if (!validIgnoreAccount(account) or senders.len > ignore.DEFAULT_MAX_ENTRIES_PER_ACCOUNT)
            return error.InvalidField;
        keys[index] = account;
        index += 1;
        try wire.addLen(&size, 2 + account.len);
        for (senders) |sender| {
            ignore.validateSender(sender.sender) catch return error.InvalidField;
            if (sender.kind != ignore.classifySender(sender.sender)) return error.InvalidField;
            try wire.addLen(&size, 1 + sender.sender.len);
        }
    }
    std.debug.assert(index == count);
    std.mem.sort([]const u8, keys, {}, lessText);
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writeHeader(&writer, ignore_magic, size, @intCast(count));
    for (keys) |account| {
        const senders = source.accounts.get(account).?.items.items;
        writer.writeByte(@intCast(account.len));
        writer.writeByte(@intCast(senders.len));
        writer.writeBytes(account);
        for (senders) |sender| {
            writer.writeByte(@intCast(sender.sender.len));
            writer.writeBytes(sender.sender);
        }
    }
    wire.finish(&writer, ignore_domain);
    try validateIgnore(bytes);
    return bytes;
}

pub fn decodeIgnore(allocator: std.mem.Allocator, bytes: []const u8) Error!ignore.MemoIgnoreList {
    try validateIgnore(bytes);
    const count: usize = std.mem.readInt(u32, bytes[12..16], .little);
    var result = ignore.MemoIgnoreList.init(allocator);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..count) |_| {
        const account_len: usize = try reader.readByte();
        const entry_count: usize = try reader.readByte();
        const account = try reader.take(account_len);
        result.checkpointEnsureRecipient(account) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidField,
        };
        for (0..entry_count) |_| {
            const sender = try reader.take(try reader.readByte());
            const added = result.add(account, sender) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidField,
            };
            std.debug.assert(added);
        }
    }
    return result;
}

/// Physical indexes preserve the first-held release order and counter slots.
/// Used rows are encoded; stale bytes in unused rows have no observable effect.
pub fn validateFirstHold(bytes: []const u8) Error!void {
    const body = try wire.parseFrame(bytes, first_hold_magic, header_len, first_hold_domain);
    const slot_count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const member_count: usize = std.mem.readInt(u16, bytes[14..16], .little);
    if (slot_count > first_hold.max_slots or member_count > first_hold.max_members)
        return error.CheckpointTooLarge;
    if (slot_count > body.len / 9 or member_count > body.len / 8) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var slots: [first_hold.max_slots]Identity = undefined;
    var previous_slot: ?usize = null;
    for (0..slot_count) |i| {
        const index: usize = try reader.readU16();
        const channel_len: usize = try reader.readByte();
        const nick_len: usize = try reader.readByte();
        const body_len: usize = try reader.readU16();
        if (index >= first_hold.max_slots or channel_len == 0 or channel_len > 64 or
            nick_len == 0 or nick_len > 32 or body_len == 0 or body_len > first_hold.max_body)
            return error.InvalidField;
        if (previous_slot) |prior| if (index <= prior) return error.NonCanonicalOrder;
        previous_slot = index;
        slots[i] = .{ .channel = try reader.take(channel_len), .nick = try reader.take(nick_len) };
        _ = try reader.take(body_len);
    }
    var members: [first_hold.max_members]Identity = undefined;
    var seen_counts: [first_hold.max_members]u16 = undefined;
    var previous_member: ?usize = null;
    for (0..member_count) |i| {
        const index: usize = try reader.readU16();
        const channel_len: usize = try reader.readByte();
        const nick_len: usize = try reader.readByte();
        const seen = try reader.readU16();
        if (index >= first_hold.max_members or channel_len == 0 or channel_len > 64 or
            nick_len == 0 or nick_len > 32 or seen == 0)
            return error.InvalidField;
        if (previous_member) |prior| if (index <= prior) return error.NonCanonicalOrder;
        previous_member = index;
        const identity = Identity{ .channel = try reader.take(channel_len), .nick = try reader.take(nick_len) };
        for (members[0..i]) |prior| if (sameIdentity(prior, identity)) return error.DuplicateEntry;
        members[i] = identity;
        seen_counts[i] = seen;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
    for (slots[0..slot_count]) |slot| {
        var found = false;
        for (members[0..member_count], 0..) |member, i| {
            if (!sameIdentity(slot, member)) continue;
            var held: u16 = 0;
            for (slots[0..slot_count]) |other| if (sameIdentity(other, member)) {
                held += 1;
            };
            if (held > seen_counts[i]) return error.InvalidField;
            found = true;
            break;
        }
        if (!found) return error.InvalidField;
    }
}

pub fn encodeFirstHold(allocator: std.mem.Allocator, source: *const first_hold.Table) Error![]u8 {
    if (source.slots.len != first_hold.max_slots or source.members.len != first_hold.max_members)
        return error.InvalidField;
    var slot_count: usize = 0;
    var member_count: usize = 0;
    var size: usize = header_len + wire.checksum_len;
    for (source.slots) |slot| {
        if (!slot.used) continue;
        if (slot.channel_len == 0 or slot.channel_len > 64 or slot.nick_len == 0 or
            slot.nick_len > 32 or slot.body_len == 0 or slot.body_len > first_hold.max_body)
            return error.InvalidField;
        slot_count += 1;
        try wire.addLen(&size, 6 + slot.channel_len + slot.nick_len + slot.body_len);
    }
    for (source.members) |member| {
        if (!member.used) continue;
        if (member.channel_len == 0 or member.channel_len > 64 or member.nick_len == 0 or
            member.nick_len > 32 or member.seen == 0)
            return error.InvalidField;
        member_count += 1;
        try wire.addLen(&size, 6 + member.channel_len + member.nick_len);
    }
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writer.writeBytes(&first_hold_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU16(@intCast(slot_count));
    writer.writeU16(@intCast(member_count));
    for (source.slots, 0..) |slot, index| {
        if (!slot.used) continue;
        writer.writeU16(@intCast(index));
        writer.writeByte(@intCast(slot.channel_len));
        writer.writeByte(@intCast(slot.nick_len));
        writer.writeU16(@intCast(slot.body_len));
        writer.writeBytes(slot.channel[0..slot.channel_len]);
        writer.writeBytes(slot.nick[0..slot.nick_len]);
        writer.writeBytes(slot.body[0..slot.body_len]);
    }
    for (source.members, 0..) |member, index| {
        if (!member.used) continue;
        writer.writeU16(@intCast(index));
        writer.writeByte(@intCast(member.channel_len));
        writer.writeByte(@intCast(member.nick_len));
        writer.writeU16(member.seen);
        writer.writeBytes(member.channel[0..member.channel_len]);
        writer.writeBytes(member.nick[0..member.nick_len]);
    }
    wire.finish(&writer, first_hold_domain);
    try validateFirstHold(bytes);
    return bytes;
}

pub fn decodeFirstHold(allocator: std.mem.Allocator, bytes: []const u8) Error!first_hold.Table {
    try validateFirstHold(bytes);
    const slot_count: usize = std.mem.readInt(u16, bytes[12..14], .little);
    const member_count: usize = std.mem.readInt(u16, bytes[14..16], .little);
    var result = try first_hold.Table.init(allocator);
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..slot_count) |_| {
        const index: usize = try reader.readU16();
        const channel_len: usize = try reader.readByte();
        const nick_len: usize = try reader.readByte();
        const body_len: usize = try reader.readU16();
        const slot = &result.slots[index];
        slot.channel_len = channel_len;
        slot.nick_len = nick_len;
        slot.body_len = body_len;
        @memcpy(slot.channel[0..channel_len], try reader.take(channel_len));
        @memcpy(slot.nick[0..nick_len], try reader.take(nick_len));
        @memcpy(slot.body[0..body_len], try reader.take(body_len));
        slot.used = true;
    }
    for (0..member_count) |_| {
        const index: usize = try reader.readU16();
        const channel_len: usize = try reader.readByte();
        const nick_len: usize = try reader.readByte();
        const seen = try reader.readU16();
        const member = &result.members[index];
        member.channel_len = channel_len;
        member.nick_len = nick_len;
        member.seen = seen;
        @memcpy(member.channel[0..channel_len], try reader.take(channel_len));
        @memcpy(member.nick[0..nick_len], try reader.take(nick_len));
        member.used = true;
    }
    return result;
}

const Identity = struct {
    channel: []const u8,
    nick: []const u8,
};

fn sameIdentity(a: Identity, b: Identity) bool {
    return std.ascii.eqlIgnoreCase(a.channel, b.channel) and std.ascii.eqlIgnoreCase(a.nick, b.nick);
}

fn validForwardAccount(account: []const u8) bool {
    forward.validateAccount(account) catch return false;
    return isLower(account);
}

fn validIgnoreAccount(account: []const u8) bool {
    ignore.validateAccount(account) catch return false;
    return isLower(account);
}

fn isLower(value: []const u8) bool {
    for (value) |byte| if (std.ascii.toLower(byte) != byte) return false;
    return true;
}

fn lessText(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn writeHeader(writer: *wire.Writer, magic: [4]u8, size: usize, count: u32) void {
    writer.writeBytes(&magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(size - header_len - wire.checksum_len));
    writer.writeU32(count);
}

fn rechecksum(bytes: []u8, domain: []const u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}

test "Windows memo forward checkpoint is deterministic and retains chains" {
    const alloc = std.testing.allocator;
    var a = forward.MemoForwardStore.init(alloc);
    defer a.deinit();
    var b = forward.MemoForwardStore.init(alloc);
    defer b.deinit();
    try a.setForward("Alice", "BOB");
    try a.setForward("bob", "Carol");
    try b.setForward("bob", "Carol");
    try b.setForward("Alice", "BOB");
    const encoded = try encodeForward(alloc, &a);
    defer alloc.free(encoded);
    const reordered = try encodeForward(alloc, &b);
    defer alloc.free(reordered);
    try std.testing.expectEqualSlices(u8, encoded, reordered);
    var restored = try decodeForward(alloc, encoded);
    defer restored.deinit();
    const resolved = try restored.resolveDelivery("ALICE");
    try std.testing.expectEqualStrings("carol", resolved.delivery_account);
    try std.testing.expectEqual(@as(usize, 2), resolved.hops);
    const again = try encodeForward(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, encoded, again);
}

test "Windows memo ignore checkpoint keeps list order spelling and empty rows" {
    const alloc = std.testing.allocator;
    var source = ignore.MemoIgnoreList.init(alloc);
    defer source.deinit();
    try source.checkpointEnsureRecipient("Empty");
    try std.testing.expect(try source.add("Alice", "B*b"));
    try std.testing.expect(try source.add("alice", "CAROL"));
    try std.testing.expect(try source.add("Zed", "dave"));
    const encoded = try encodeIgnore(alloc, &source);
    defer alloc.free(encoded);
    var restored = try decodeIgnore(alloc, encoded);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 3), restored.accounts.count());
    try std.testing.expectEqual(@as(usize, 0), try restored.count("empty"));
    var out: [ignore.DEFAULT_MAX_ENTRIES_PER_ACCOUNT]ignore.Entry = undefined;
    const entries = try restored.list("ALICE", &out);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("B*b", entries[0].sender);
    try std.testing.expectEqualStrings("CAROL", entries[1].sender);
    try std.testing.expect(!(try restored.shouldAccept("alice", "bob")));
    const again = try encodeIgnore(alloc, &restored);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, encoded, again);
}

test "Windows first-hold checkpoint retains body order and seen after release" {
    const alloc = std.testing.allocator;
    var source = try first_hold.Table.init(alloc);
    defer source.deinit();
    try source.hold("#Room", "Alice", "first", 2);
    try source.hold("#Room", "Alice", "second", 2);
    try source.hold("#Room", "Eve", "discard", 1);
    try std.testing.expectEqual(@as(usize, 1), source.drop("#Room", "Eve"));
    const encoded = try encodeFirstHold(alloc, &source);
    defer alloc.free(encoded);
    var restored = try decodeFirstHold(alloc, encoded);
    defer restored.deinit();
    var bodies: [first_hold.max_per_member][first_hold.max_body]u8 = undefined;
    var lengths: [first_hold.max_per_member]usize = undefined;
    try std.testing.expectEqual(@as(usize, 2), restored.copyOut("#room", "alice", &bodies, &lengths));
    try std.testing.expectEqualStrings("first", bodies[0][0..lengths[0]]);
    try std.testing.expectEqualStrings("second", bodies[1][0..lengths[1]]);
    try std.testing.expectEqual(@as(u16, 2), restored.seen("#room", "alice"));
    try std.testing.expectEqual(@as(u16, 1), restored.seen("#room", "eve"));
    try std.testing.expectError(error.Past, restored.hold("#room", "alice", "third", 2));
    var before_release = try decodeFirstHold(alloc, encoded);
    defer before_release.deinit();
    const again = try encodeFirstHold(alloc, &before_release);
    defer alloc.free(again);
    try std.testing.expectEqualSlices(u8, encoded, again);
}

test "Windows first-hold checkpoint carries counters above server policy cap" {
    const alloc = std.testing.allocator;
    var source = try first_hold.Table.init(alloc);
    defer source.deinit();
    for (0..9) |_| try source.hold("#room", "alice", "body", 9);
    const bytes = try encodeFirstHold(alloc, &source);
    defer alloc.free(bytes);
    var restored = try decodeFirstHold(alloc, bytes);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u16, 9), restored.seen("#room", "alice"));
    try std.testing.expectError(error.Past, restored.hold("#room", "alice", "extra", 9));
}

test "Windows memo capsules reject checksum tamper and canonical duplicates" {
    const alloc = std.testing.allocator;
    var f = forward.MemoForwardStore.init(alloc);
    defer f.deinit();
    try f.setForward("alice", "carol");
    try f.setForward("bobby", "david");
    const fw = try encodeForward(alloc, &f);
    defer alloc.free(fw);
    try std.testing.expectError(error.Truncated, validateForward(fw[0 .. fw.len - 1]));
    var bad_f = try alloc.dupe(u8, fw);
    defer alloc.free(bad_f);
    bad_f[header_len + 2] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateForward(bad_f));
    bad_f[header_len + 2] ^= 1;
    @memcpy(bad_f[header_len + 12 + 2 ..][0..5], "alice");
    rechecksum(bad_f, forward_domain);
    try std.testing.expectError(error.NonCanonicalOrder, validateForward(bad_f));

    var i = ignore.MemoIgnoreList.init(alloc);
    defer i.deinit();
    _ = try i.add("alice", "bob");
    _ = try i.add("alice", "eve");
    const iw = try encodeIgnore(alloc, &i);
    defer alloc.free(iw);
    var bad_i = try alloc.dupe(u8, iw);
    defer alloc.free(bad_i);
    @memcpy(bad_i[header_len + 2 + 5 + 1 + 3 + 1 ..][0..3], "BOB");
    rechecksum(bad_i, ignore_domain);
    try std.testing.expectError(error.DuplicateEntry, validateIgnore(bad_i));

    var held = try first_hold.Table.init(alloc);
    defer held.deinit();
    try held.hold("#r", "a", "x", 2);
    try held.hold("#r", "a", "y", 2);
    const hw = try encodeFirstHold(alloc, &held);
    defer alloc.free(hw);
    var bad_h = try alloc.dupe(u8, hw);
    defer alloc.free(bad_h);
    std.mem.writeInt(u16, bad_h[header_len + 10 ..][0..2], 0, .little);
    rechecksum(bad_h, first_hold_domain);
    try std.testing.expectError(error.NonCanonicalOrder, validateFirstHold(bad_h));
}

test "Windows memo capsules stage atomically through allocation failures" {
    const alloc = std.testing.allocator;
    var f = forward.MemoForwardStore.init(alloc);
    defer f.deinit();
    try f.setForward("alice", "bob");
    var i = ignore.MemoIgnoreList.init(alloc);
    defer i.deinit();
    _ = try i.add("alice", "B*b");
    var h = try first_hold.Table.init(alloc);
    defer h.deinit();
    try h.hold("#r", "alice", "held", 2);
    const Probe = struct {
        fn encodeF(a: std.mem.Allocator, source: *const forward.MemoForwardStore) !void {
            const bytes = try encodeForward(a, source);
            defer a.free(bytes);
        }
        fn decodeF(a: std.mem.Allocator, bytes: []const u8) !void {
            var staged = try decodeForward(a, bytes);
            defer staged.deinit();
        }
        fn encodeI(a: std.mem.Allocator, source: *const ignore.MemoIgnoreList) !void {
            const bytes = try encodeIgnore(a, source);
            defer a.free(bytes);
        }
        fn decodeI(a: std.mem.Allocator, bytes: []const u8) !void {
            var staged = try decodeIgnore(a, bytes);
            defer staged.deinit();
        }
        fn encodeH(a: std.mem.Allocator, source: *const first_hold.Table) !void {
            const bytes = try encodeFirstHold(a, source);
            defer a.free(bytes);
        }
        fn decodeH(a: std.mem.Allocator, bytes: []const u8) !void {
            var staged = try decodeFirstHold(a, bytes);
            defer staged.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, Probe.encodeF, .{&f});
    try std.testing.checkAllAllocationFailures(alloc, Probe.encodeI, .{&i});
    try std.testing.checkAllAllocationFailures(alloc, Probe.encodeH, .{&h});
    const fb = try encodeForward(alloc, &f);
    defer alloc.free(fb);
    const ib = try encodeIgnore(alloc, &i);
    defer alloc.free(ib);
    const hb = try encodeFirstHold(alloc, &h);
    defer alloc.free(hb);
    try std.testing.checkAllAllocationFailures(alloc, Probe.decodeF, .{fb});
    try std.testing.checkAllAllocationFailures(alloc, Probe.decodeI, .{ib});
    try std.testing.checkAllAllocationFailures(alloc, Probe.decodeH, .{hb});
    try std.testing.expectEqualStrings("bob", (try f.forwardTarget("alice")).?);
    try std.testing.expectEqual(@as(usize, 1), try i.count("alice"));
    try std.testing.expectEqual(@as(u16, 1), h.seen("#r", "alice"));
}
