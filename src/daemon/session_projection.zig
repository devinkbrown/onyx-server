// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-capacity, allocation-free local channel projection primitives.
//!
//! SessionStore owns when a projection is armed and published. This leaf owns
//! only the bounded projection image, canonical ordering, and work-item
//! comparisons so lifecycle code can reuse the same semantics without growing
//! the session registry module.

const std = @import("std");
const attachment_id_mod = @import("attachment_id.zig");

pub const token_len: usize = 16;
pub const local_channel_name_capacity: usize = 200;
pub const local_channel_projection_capacity: usize = 8;

pub const Token = [token_len]u8;
pub const AttachmentId = attachment_id_mod.AttachmentId;

/// One desired channel image within an exact reusable-token group.
///
/// Every local row bearing the token carries the same bounded set. That
/// deliberate duplication lets any sibling detach or disappear without taking
/// the retry source with it. A newer same-channel arm receives a generation, so
/// an older in-flight retry cannot clear the replacement.
pub const LocalChannelProjection = struct {
    generation: u64 = 0,
    channel_len: u8 = 0,
    channel_bytes: [local_channel_name_capacity]u8 = @splat(0),
    present: bool = false,
    member_mode_bits: u8 = 0,

    pub fn channel(self: *const LocalChannelProjection) []const u8 {
        return self.channel_bytes[0..self.channel_len];
    }
};

/// Canonically sorted, fixed-capacity pending work for one exact token group.
/// SessionStore arms the set only after staging all missing owned row copies;
/// reads, retries, and compare-and-clear stay allocation-free.
pub const LocalChannelProjectionSet = struct {
    revision: u64 = 0,
    len: u8 = 0,
    items: [local_channel_projection_capacity]LocalChannelProjection = @splat(.{}),

    pub fn slice(self: *const LocalChannelProjectionSet) []const LocalChannelProjection {
        return self.items[0..self.len];
    }

    pub fn isEmpty(self: *const LocalChannelProjectionSet) bool {
        return self.len == 0;
    }
};

pub const LocalChannelProjectionWork = struct {
    token: Token,
    projection: LocalChannelProjection,
};

pub const AttachmentReplicaWork = struct {
    token: Token,
    attachment_id: AttachmentId,
};

pub const AttachmentLocalChannelProjectionWork = struct {
    token: Token,
    attachment_id: AttachmentId,
    projection: LocalChannelProjection,
};

/// One accepted arm plus the exact same-channel intent it replaced.
pub const LocalChannelProjectionArm = struct {
    intent: LocalChannelProjection,
    previous: ?LocalChannelProjection,
};

pub const LocalProjectionArmError = std.mem.Allocator.Error || error{
    InvalidChannel,
    NoSuchToken,
    NoSuchAttachment,
    TooManyPendingChannels,
};

pub fn localProjectionSetRevision(set: ?*const LocalChannelProjectionSet) u64 {
    return if (set) |value| value.revision else 0;
}

pub fn localChannelOrder(a: []const u8, b: []const u8) std.math.Order {
    const shared = @min(a.len, b.len);
    for (a[0..shared], b[0..shared]) |a_byte, b_byte| {
        const a_folded = std.ascii.toLower(a_byte);
        const b_folded = std.ascii.toLower(b_byte);
        if (a_folded < b_folded) return .lt;
        if (a_folded > b_folded) return .gt;
    }
    return std.math.order(a.len, b.len);
}

pub fn localProjectionIndex(set: *const LocalChannelProjectionSet, channel: []const u8) ?usize {
    for (set.slice(), 0..) |projection, index| {
        if (std.ascii.eqlIgnoreCase(projection.channel(), channel)) return index;
    }
    return null;
}

pub fn localProjectionUpsert(
    set: *LocalChannelProjectionSet,
    projection: LocalChannelProjection,
) error{TooManyPendingChannels}!void {
    if (localProjectionIndex(set, projection.channel())) |index| {
        set.items[index] = projection;
        return;
    }
    if (set.len == local_channel_projection_capacity) return error.TooManyPendingChannels;

    var insert_at: usize = 0;
    while (insert_at < set.len and
        localChannelOrder(set.items[insert_at].channel(), projection.channel()) == .lt)
    {
        insert_at += 1;
    }
    var cursor: usize = set.len;
    while (cursor > insert_at) : (cursor -= 1)
        set.items[cursor] = set.items[cursor - 1];
    set.items[insert_at] = projection;
    set.len += 1;
}

pub fn localProjectionRemoveAt(set: *LocalChannelProjectionSet, index: usize) void {
    std.debug.assert(index < set.len);
    var cursor = index;
    while (cursor + 1 < set.len) : (cursor += 1)
        set.items[cursor] = set.items[cursor + 1];
    set.len -= 1;
    set.items[set.len] = .{};
}

pub fn mergeLocalProjectionSets(
    out: *LocalChannelProjectionSet,
    a: *const LocalChannelProjectionSet,
    b: *const LocalChannelProjectionSet,
) bool {
    out.* = .{};
    for (a.slice()) |projection|
        localProjectionUpsert(out, projection) catch return false;
    for (b.slice()) |projection| {
        if (localProjectionIndex(out, projection.channel())) |index| {
            if (projection.generation > out.items[index].generation)
                out.items[index] = projection;
            continue;
        }
        localProjectionUpsert(out, projection) catch return false;
    }
    out.revision = @max(a.revision, b.revision);
    return true;
}

pub fn localWorkOrder(a: LocalChannelProjectionWork, b: LocalChannelProjectionWork) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    return localChannelOrder(a.projection.channel(), b.projection.channel());
}

pub fn localWorkInSlice(
    work: []const LocalChannelProjectionWork,
    needle: LocalChannelProjectionWork,
) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            std.ascii.eqlIgnoreCase(candidate.projection.channel(), needle.projection.channel()))
        {
            return true;
        }
    }
    return false;
}

pub fn attachmentWorkOrder(a: AttachmentReplicaWork, b: AttachmentReplicaWork) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    return std.mem.order(u8, &a.attachment_id.raw, &b.attachment_id.raw);
}

pub fn attachmentWorkInSlice(work: []const AttachmentReplicaWork, needle: AttachmentReplicaWork) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            candidate.attachment_id.eql(needle.attachment_id))
        {
            return true;
        }
    }
    return false;
}

pub fn attachmentLocalWorkOrder(
    a: AttachmentLocalChannelProjectionWork,
    b: AttachmentLocalChannelProjectionWork,
) std.math.Order {
    const attachment_order = attachmentWorkOrder(
        .{ .token = a.token, .attachment_id = a.attachment_id },
        .{ .token = b.token, .attachment_id = b.attachment_id },
    );
    if (attachment_order != .eq) return attachment_order;
    return localChannelOrder(a.projection.channel(), b.projection.channel());
}

pub fn attachmentLocalWorkInSlice(
    work: []const AttachmentLocalChannelProjectionWork,
    needle: AttachmentLocalChannelProjectionWork,
) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            candidate.attachment_id.eql(needle.attachment_id) and
            std.ascii.eqlIgnoreCase(candidate.projection.channel(), needle.projection.channel()))
        {
            return true;
        }
    }
    return false;
}
