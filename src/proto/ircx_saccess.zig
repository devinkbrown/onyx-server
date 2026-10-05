// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX server-level ACCESS / SACCESS parsing and numeric builders.
//!
//! `ACCESS *` and `SACCESS` both address global IRCX access controls. This
//! module only parses borrowed command parameters and emits replies into
//! caller-owned buffers; storage and permission checks live above it.
const std = @import("std");
const listx = @import("listx.zig");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const RPL_ACCESSADD: u16 = 801;
pub const RPL_ACCESSDELETE: u16 = 802;
pub const RPL_ACCESSSTART: u16 = 803;
pub const RPL_ACCESSENTRY: u16 = 804;
pub const RPL_ACCESSEND: u16 = 805;

pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_REASON_BYTES: usize = 256;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_DURATION_DIGITS: usize = 20;

pub const SaccessError = error{
    MissingTarget,
    InvalidTarget,
    MissingSubcommand,
    InvalidSubcommand,
    MissingEntryType,
    InvalidEntryType,
    MissingMask,
    InvalidMask,
    MaskTooLong,
    InvalidDuration,
    DurationTooLong,
    InvalidReason,
    ReasonTooLong,
    InvalidServerName,
    InvalidRequester,
    TooManyParameters,
    TooManyEntries,
    LineTooLong,
    OutputTooSmall,
};

pub const StoreError = SaccessError || std.mem.Allocator.Error;

/// Compile-time limits used by parsers and line builders.
pub const Params = struct {
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_duration_digits: usize = DEFAULT_MAX_DURATION_DIGITS,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` is a wire budget and keeps its default.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_mask_bytes = limits.ircx_access_mask_len,
            .max_reason_bytes = limits.ircx_saccess_reason_len,
            .max_server_bytes = limits.server_name_len,
            .max_requester_bytes = limits.nick_len,
            .max_duration_digits = limits.ircx_duration_digits,
        };
    }
};

/// Server-level IRCX ACCESS entry kinds.
pub const EntryType = enum {
    deny,
    gag,
    grant,
    nochannel,
    nonick,
    // HOLDNICK reserves a nick glob: a matching nick is refused UNLESS the user is
    // GRANT-exempt (a trusted hostmask) or an operator. Unlike NONICK (a flat
    // forbid for everyone), a reservation holds the pattern for authorized use.
    holdnick,

    pub fn token(self: EntryType) []const u8 {
        return switch (self) {
            .deny => "DENY",
            .gag => "GAG",
            .grant => "GRANT",
            .nochannel => "NOCHANNEL",
            .nonick => "NONICK",
            .holdnick => "HOLDNICK",
        };
    }

    pub fn parse(raw: []const u8) ?EntryType {
        if (std.ascii.eqlIgnoreCase(raw, "DENY")) return .deny;
        if (std.ascii.eqlIgnoreCase(raw, "GAG")) return .gag;
        if (std.ascii.eqlIgnoreCase(raw, "GRANT")) return .grant;
        if (std.ascii.eqlIgnoreCase(raw, "NOCHANNEL")) return .nochannel;
        if (std.ascii.eqlIgnoreCase(raw, "NONICK")) return .nonick;
        if (std.ascii.eqlIgnoreCase(raw, "HOLDNICK")) return .holdnick;
        return null;
    }
};

/// Parsed ADD entry. Slices borrow from the caller's command parameter array.
pub const Entry = struct {
    entry_type: EntryType,
    mask: []const u8,
    duration: ?u64 = null,
    reason: ?[]const u8 = null,
};

/// Parsed DELETE selector.
pub const Delete = struct {
    entry_type: EntryType,
    mask: []const u8,
};

/// Parsed ACCESS * / SACCESS operation.
pub const Request = union(enum) {
    add: Entry,
    delete: Delete,
    list: ?EntryType,
    clear: ?EntryType,
};

/// Reply-level data shared by ACCESS numerics.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

const StoredEntry = struct {
    entry_type: EntryType,
    mask: []u8,
    duration: ?u64 = null,
    reason: ?[]u8 = null,

    fn view(self: *const StoredEntry) Entry {
        return .{
            .entry_type = self.entry_type,
            .mask = self.mask,
            .duration = self.duration,
            .reason = self.reason,
        };
    }

    fn deinit(self: StoredEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.mask);
        if (self.reason) |reason| allocator.free(reason);
    }
};

pub const ServerAccessStore = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(StoredEntry) = .empty,
    max_entries: usize = 256,

    pub fn init(allocator: std.mem.Allocator) ServerAccessStore {
        return .{ .allocator = allocator };
    }

    pub fn initWith(allocator: std.mem.Allocator, max_entries: usize) ServerAccessStore {
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    pub fn deinit(self: *ServerAccessStore) void {
        for (self.entries.items) |entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(self: *ServerAccessStore, entry: Entry) StoreError!void {
        try validateEntryWith(.{}, entry);

        if (self.findIndex(entry.entry_type, entry.mask)) |idx| {
            const reason_copy = if (entry.reason) |reason| try self.allocator.dupe(u8, reason) else null;
            errdefer if (reason_copy) |reason| self.allocator.free(reason);
            if (self.entries.items[idx].reason) |old| self.allocator.free(old);
            self.entries.items[idx].reason = reason_copy;
            self.entries.items[idx].duration = entry.duration;
            return;
        }

        if (self.entries.items.len >= self.max_entries) return error.TooManyEntries;

        const mask_copy = try self.allocator.dupe(u8, entry.mask);
        errdefer self.allocator.free(mask_copy);
        const reason_copy = if (entry.reason) |reason| try self.allocator.dupe(u8, reason) else null;
        errdefer if (reason_copy) |reason| self.allocator.free(reason);

        try self.entries.append(self.allocator, .{
            .entry_type = entry.entry_type,
            .mask = mask_copy,
            .duration = entry.duration,
            .reason = reason_copy,
        });
    }

    pub fn remove(self: *ServerAccessStore, entry_type: EntryType, mask: []const u8) SaccessError!bool {
        try validateMaskWith(.{}, entry_type, mask);
        const idx = self.findIndex(entry_type, mask) orelse return false;
        const removed = self.entries.swapRemove(idx);
        removed.deinit(self.allocator);
        return true;
    }

    pub fn clear(self: *ServerAccessStore, entry_type: ?EntryType) usize {
        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (entry_type == null or self.entries.items[idx].entry_type == entry_type.?) {
                const removed = self.entries.swapRemove(idx);
                removed.deinit(self.allocator);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        return removed_count;
    }

    pub fn list(self: *const ServerAccessStore, entry_type: ?EntryType, out: []Entry) SaccessError![]const Entry {
        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (entry_type != null and entry.entry_type != entry_type.?) continue;
            if (count >= out.len) return error.OutputTooSmall;
            out[count] = entry.view();
            count += 1;
        }
        return out[0..count];
    }

    /// Borrow one row in its physical match order for an exact Helix seal.
    pub fn snapshotAt(self: *const ServerAccessStore, index: usize) ?Entry {
        if (index >= self.entries.items.len) return null;
        return self.entries.items[index].view();
    }

    pub fn matchHostmask(self: *const ServerAccessStore, entry_type: EntryType, hostmask: []const u8) ?Entry {
        for (self.entries.items) |*entry| {
            if (entry.entry_type != entry_type) continue;
            if (listx.globMatch(entry.mask, hostmask)) return entry.view();
        }
        return null;
    }

    pub fn matchNick(self: *const ServerAccessStore, nick: []const u8) ?Entry {
        for (self.entries.items) |*entry| {
            if (entry.entry_type != .nonick) continue;
            if (listx.globMatch(entry.mask, nick)) return entry.view();
        }
        return null;
    }

    /// First HOLDNICK reservation whose glob matches `nick`, or null. The caller
    /// allows the nick anyway for GRANT-exempt / operator users (the reservation
    /// holds the pattern for authorized use, unlike the flat NONICK forbid).
    pub fn matchHoldNick(self: *const ServerAccessStore, nick: []const u8) ?Entry {
        for (self.entries.items) |*entry| {
            if (entry.entry_type != .holdnick) continue;
            if (listx.globMatch(entry.mask, nick)) return entry.view();
        }
        return null;
    }

    pub fn matchChannel(self: *const ServerAccessStore, channel: []const u8) ?Entry {
        for (self.entries.items) |*entry| {
            if (entry.entry_type != .nochannel) continue;
            if (listx.globMatch(entry.mask, channel)) return entry.view();
        }
        return null;
    }

    fn findIndex(self: *const ServerAccessStore, entry_type: EntryType, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.entry_type == entry_type and std.ascii.eqlIgnoreCase(entry.mask, mask)) return idx;
        }
        return null;
    }
};

const Subcommand = enum {
    add,
    delete,
    list,
    clear,

    fn parse(raw: []const u8) ?Subcommand {
        if (std.ascii.eqlIgnoreCase(raw, "ADD")) return .add;
        if (std.ascii.eqlIgnoreCase(raw, "DEL") or std.ascii.eqlIgnoreCase(raw, "DELETE")) return .delete;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        if (std.ascii.eqlIgnoreCase(raw, "CLEAR")) return .clear;
        return null;
    }
};

/// Parse parameters after `ACCESS`. Only `ACCESS * ...` is server-level.
pub fn parseAccess(params: []const []const u8) SaccessError!Request {
    return parseAccessWith(.{}, params);
}

/// Parse parameters after `ACCESS` with caller-selected validation limits.
pub fn parseAccessWith(comptime limits: Params, params: []const []const u8) SaccessError!Request {
    if (params.len == 0) return error.MissingTarget;
    if (!std.mem.eql(u8, params[0], "*")) return error.InvalidTarget;
    return parseSaccessWith(limits, params[1..]);
}

/// Parse parameters after `SACCESS`.
pub fn parseSaccess(params: []const []const u8) SaccessError!Request {
    return parseSaccessWith(.{}, params);
}

/// Parse parameters after `SACCESS` with caller-selected validation limits.
pub fn parseSaccessWith(comptime limits: Params, params: []const []const u8) SaccessError!Request {
    if (params.len == 0) return error.MissingSubcommand;

    const subcommand = Subcommand.parse(params[0]) orelse return error.InvalidSubcommand;
    return switch (subcommand) {
        .add => .{ .add = try parseAddWith(limits, params[1..]) },
        .delete => .{ .delete = try parseDeleteWith(limits, params[1..]) },
        .list => .{ .list = try parseOptionalEntryType(params[1..]) },
        .clear => .{ .clear = try parseOptionalEntryType(params[1..]) },
    };
}

/// Build RPL_ACCESSSTART (803).
pub fn buildAccessStart(out: []u8, ctx: ReplyContext) SaccessError![]const u8 {
    return buildAccessStartWith(.{}, out, ctx);
}

/// Build RPL_ACCESSSTART (803) with caller-selected limits.
pub fn buildAccessStartWith(comptime limits: Params, out: []u8, ctx: ReplyContext) SaccessError![]const u8 {
    try validateContextWith(limits, ctx);

    var b = LineBuilder.init(out, limits.max_line_bytes);
    try b.numericPrefix(RPL_ACCESSSTART, ctx.server_name, ctx.requester);
    try b.spaceParam("*");
    try b.spaceTrailing("ACCESS list begins");
    try b.crlf();
    return b.slice();
}

/// Build one RPL_ACCESSENTRY (804) line.
pub fn buildAccessEntry(out: []u8, ctx: ReplyContext, entry: Entry) SaccessError![]const u8 {
    return buildAccessEntryWith(.{}, out, ctx, entry);
}

/// Build one RPL_ACCESSENTRY (804) line with caller-selected limits.
pub fn buildAccessEntryWith(comptime limits: Params, out: []u8, ctx: ReplyContext, entry: Entry) SaccessError![]const u8 {
    try validateContextWith(limits, ctx);
    try validateEntryWith(limits, entry);

    var b = LineBuilder.init(out, limits.max_line_bytes);
    try b.numericPrefix(RPL_ACCESSENTRY, ctx.server_name, ctx.requester);
    try b.spaceParam("*");
    try appendEntryFields(&b, entry);
    try b.crlf();
    return b.slice();
}

/// Build RPL_ACCESSEND (805).
pub fn buildAccessEnd(out: []u8, ctx: ReplyContext) SaccessError![]const u8 {
    return buildAccessEndWith(.{}, out, ctx);
}

/// Build RPL_ACCESSEND (805) with caller-selected limits.
pub fn buildAccessEndWith(comptime limits: Params, out: []u8, ctx: ReplyContext) SaccessError![]const u8 {
    try validateContextWith(limits, ctx);

    var b = LineBuilder.init(out, limits.max_line_bytes);
    try b.numericPrefix(RPL_ACCESSEND, ctx.server_name, ctx.requester);
    try b.spaceParam("*");
    try b.spaceTrailing("End of ACCESS list");
    try b.crlf();
    return b.slice();
}

/// Build RPL_ACCESSADD (801).
pub fn buildAccessAdd(out: []u8, ctx: ReplyContext, entry: Entry) SaccessError![]const u8 {
    return buildAccessAddWith(.{}, out, ctx, entry);
}

/// Build RPL_ACCESSADD (801) with caller-selected limits.
pub fn buildAccessAddWith(comptime limits: Params, out: []u8, ctx: ReplyContext, entry: Entry) SaccessError![]const u8 {
    try validateContextWith(limits, ctx);
    try validateEntryWith(limits, entry);

    var b = LineBuilder.init(out, limits.max_line_bytes);
    try b.numericPrefix(RPL_ACCESSADD, ctx.server_name, ctx.requester);
    try b.spaceParam("*");
    try b.spaceParam(entry.entry_type.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry added");
    try b.crlf();
    return b.slice();
}

/// Build RPL_ACCESSDELETE (802).
pub fn buildAccessDelete(out: []u8, ctx: ReplyContext, entry: Delete) SaccessError![]const u8 {
    return buildAccessDeleteWith(.{}, out, ctx, entry);
}

/// Build RPL_ACCESSDELETE (802) with caller-selected limits.
pub fn buildAccessDeleteWith(comptime limits: Params, out: []u8, ctx: ReplyContext, entry: Delete) SaccessError![]const u8 {
    try validateContextWith(limits, ctx);
    try validateDeleteWith(limits, entry);

    var b = LineBuilder.init(out, limits.max_line_bytes);
    try b.numericPrefix(RPL_ACCESSDELETE, ctx.server_name, ctx.requester);
    try b.spaceParam("*");
    try b.spaceParam(entry.entry_type.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry deleted");
    try b.crlf();
    return b.slice();
}

fn parseAddWith(comptime limits: Params, params: []const []const u8) SaccessError!Entry {
    if (params.len == 0) return error.MissingEntryType;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 4) return error.TooManyParameters;

    const entry_type = EntryType.parse(params[0]) orelse return error.InvalidEntryType;
    const mask = params[1];
    try validateMaskWith(limits, entry_type, mask);

    var entry = Entry{
        .entry_type = entry_type,
        .mask = mask,
    };

    if (params.len >= 3) {
        if (params[2].len > 0 and params[2][0] == ':') {
            if (params.len > 3) return error.TooManyParameters;
            entry.reason = try parseReasonWith(limits, params[2]);
        } else {
            entry.duration = try parseDurationWith(limits, params[2]);
        }
    }

    if (params.len == 4) {
        entry.reason = try parseReasonWith(limits, params[3]);
    }

    return entry;
}

fn parseDeleteWith(comptime limits: Params, params: []const []const u8) SaccessError!Delete {
    if (params.len == 0) return error.MissingEntryType;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 2) return error.TooManyParameters;

    const entry_type = EntryType.parse(params[0]) orelse return error.InvalidEntryType;
    const mask = params[1];
    try validateMaskWith(limits, entry_type, mask);
    return .{ .entry_type = entry_type, .mask = mask };
}

fn parseOptionalEntryType(params: []const []const u8) SaccessError!?EntryType {
    if (params.len == 0) return null;
    if (params.len > 1) return error.TooManyParameters;
    return EntryType.parse(params[0]) orelse error.InvalidEntryType;
}

fn parseDurationWith(comptime limits: Params, raw: []const u8) SaccessError!u64 {
    if (raw.len == 0) return error.InvalidDuration;
    if (raw.len > limits.max_duration_digits) return error.DurationTooLong;

    var value: u64 = 0;
    for (raw) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDuration;
        const digit: u64 = byte - '0';
        if (value > (std.math.maxInt(u64) - digit) / 10) return error.InvalidDuration;
        value = value * 10 + digit;
    }
    return value;
}

fn parseReasonWith(comptime limits: Params, raw: []const u8) SaccessError![]const u8 {
    const reason = if (raw.len > 0 and raw[0] == ':') raw[1..] else raw;
    try validateReasonWith(limits, reason);
    return reason;
}

/// Apply the same invariants to a decoded checkpoint row as to `add`.
pub fn validateStoredEntry(entry: Entry) SaccessError!void {
    try validateEntryWith(.{}, entry);
}

fn validateEntryWith(comptime limits: Params, entry: Entry) SaccessError!void {
    try validateMaskWith(limits, entry.entry_type, entry.mask);
    if (entry.reason) |reason| try validateReasonWith(limits, reason);
}

fn validateDeleteWith(comptime limits: Params, entry: Delete) SaccessError!void {
    try validateMaskWith(limits, entry.entry_type, entry.mask);
}

fn validateContextWith(comptime limits: Params, ctx: ReplyContext) SaccessError!void {
    try validateParamBounded(ctx.server_name, limits.max_server_bytes, error.InvalidServerName);
    try validateParamBounded(ctx.requester, limits.max_requester_bytes, error.InvalidRequester);
}

fn validateParamBounded(param: []const u8, max_len: usize, err: SaccessError) SaccessError!void {
    if (param.len == 0 or param.len > max_len) return err;
    if (param[0] == ':') return err;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn validateMaskWith(comptime limits: Params, entry_type: EntryType, mask: []const u8) SaccessError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > limits.max_mask_bytes) return error.MaskTooLong;
    if (mask[0] == ':') return error.InvalidMask;

    for (mask) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n', 0x7f => return error.InvalidMask,
            else => {},
        }
    }

    switch (entry_type) {
        .nochannel => {
            if (!validChannelMaskPrefix(mask)) return error.InvalidMask;
        },
        .nonick, .holdnick => {
            if (mask[0] == '#') return error.InvalidMask;
            for (mask) |byte| {
                if (byte == '!' or byte == '@') return error.InvalidMask;
            }
        },
        .deny, .gag, .grant => {},
    }
}

fn validChannelMaskPrefix(mask: []const u8) bool {
    return switch (mask[0]) {
        '#', '&' => true,
        '%' => mask.len >= 2 and (mask[1] == '#' or mask[1] == '&'),
        else => false,
    };
}

fn validateReasonWith(comptime limits: Params, reason: []const u8) SaccessError!void {
    if (reason.len > limits.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidReason,
            else => {},
        }
    }
}

fn appendEntryFields(b: *LineBuilder, entry: Entry) SaccessError!void {
    try b.spaceParam(entry.entry_type.token());
    try b.spaceParam(entry.mask);
    if (entry.duration) |duration| try b.spaceUnsigned(duration);
    if (entry.reason) |reason| try b.spaceTrailing(reason);
}

fn formatCodeValue(value: u16, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{
            .out = out,
            .max_line_bytes = max_line_bytes,
        };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code_value: u16, server_name: []const u8, requester: []const u8) SaccessError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCodeValue(code_value, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) SaccessError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) SaccessError!void {
        try self.appendBytes(" :");
        try self.appendBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u64) SaccessError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) SaccessError!void {
        var buf: [20]u8 = undefined;
        var cursor: usize = buf.len;
        var current = value;

        while (true) {
            cursor -= 1;
            buf[cursor] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[cursor..]);
    }

    fn crlf(self: *LineBuilder) SaccessError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) SaccessError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) SaccessError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test {
    _ = numeric.numericTable;
}

test "parse ACCESS star and SACCESS add each server entry type" {
    const deny = try parseAccess(&.{ "*", "ADD", "DENY", "bad!*@*", "60", "abuse" });
    try std.testing.expectEqual(EntryType.deny, deny.add.entry_type);
    try std.testing.expectEqualStrings("bad!*@*", deny.add.mask);
    try std.testing.expectEqual(@as(?u64, 60), deny.add.duration);
    try std.testing.expectEqualStrings("abuse", deny.add.reason.?);

    const gag = try parseSaccess(&.{ "ADD", "GAG", "flooder!*@*" });
    try std.testing.expectEqual(EntryType.gag, gag.add.entry_type);
    try std.testing.expectEqualStrings("flooder!*@*", gag.add.mask);
    try std.testing.expectEqual(@as(?u64, null), gag.add.duration);
    try std.testing.expectEqual(@as(?[]const u8, null), gag.add.reason);

    const grant = try parseSaccess(&.{ "ADD", "GRANT", "trusted!*@*" });
    try std.testing.expectEqual(EntryType.grant, grant.add.entry_type);
    try std.testing.expectEqualStrings("trusted!*@*", grant.add.mask);

    const nochannel = try parseSaccess(&.{ "ADD", "NOCHANNEL", "#bad*" });
    try std.testing.expectEqual(EntryType.nochannel, nochannel.add.entry_type);
    try std.testing.expectEqualStrings("#bad*", nochannel.add.mask);

    const nonick = try parseSaccess(&.{ "ADD", "NONICK", "badnick*" });
    try std.testing.expectEqual(EntryType.nonick, nonick.add.entry_type);
    try std.testing.expectEqualStrings("badnick*", nonick.add.mask);
}

test "ServerAccessStore matches grant deny and gag masks independently" {
    var store = ServerAccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add(.{ .entry_type = .deny, .mask = "*!*@bad.test", .reason = "denied" });
    try store.add(.{ .entry_type = .grant, .mask = "good!*@bad.test" });
    try store.add(.{ .entry_type = .gag, .mask = "*!*@noisy.test" });

    // A trusted client matches BOTH the deny and the grant: the enforcement
    // layer consults grant first (GRANT overrides DENY). The store exposes each
    // independently so the caller can implement that precedence.
    try std.testing.expect(store.matchHostmask(.deny, "good!user@bad.test") != null);
    try std.testing.expect(store.matchHostmask(.grant, "good!user@bad.test") != null);
    // A non-trusted client on the same host matches deny but NOT grant.
    try std.testing.expect(store.matchHostmask(.deny, "evil!user@bad.test") != null);
    try std.testing.expect(store.matchHostmask(.grant, "evil!user@bad.test") == null);
    // Gag is its own axis.
    try std.testing.expect(store.matchHostmask(.gag, "any!user@noisy.test") != null);
    try std.testing.expect(store.matchHostmask(.grant, "any!user@noisy.test") == null);

    // Removing the grant leaves the deny in force.
    try std.testing.expect(try store.remove(.grant, "good!*@bad.test"));
    try std.testing.expect(store.matchHostmask(.grant, "good!user@bad.test") == null);
    try std.testing.expect(store.matchHostmask(.deny, "good!user@bad.test") != null);
}

test "parse delete list and clear subcommands" {
    const del = try parseSaccess(&.{ "DELETE", "GAG", "flooder!*@*" });
    try std.testing.expectEqual(EntryType.gag, del.delete.entry_type);
    try std.testing.expectEqualStrings("flooder!*@*", del.delete.mask);

    const list_all = try parseAccess(&.{ "*", "LIST" });
    try std.testing.expectEqual(@as(?EntryType, null), list_all.list);

    const list_typed = try parseSaccess(&.{ "LIST", "NONICK" });
    try std.testing.expectEqual(@as(?EntryType, EntryType.nonick), list_typed.list);

    const clear_all = try parseSaccess(&.{"CLEAR"});
    try std.testing.expectEqual(@as(?EntryType, null), clear_all.clear);

    const clear_typed = try parseAccess(&.{ "*", "CLEAR", "GAG" });
    try std.testing.expectEqual(@as(?EntryType, EntryType.gag), clear_typed.clear);
}

test "access list builders emit IRCX numerics" {
    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var buf: [256]u8 = undefined;

    try std.testing.expectEqualStrings(
        ":irc.example.test 803 dan * :ACCESS list begins\r\n",
        try buildAccessStart(&buf, ctx),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 804 dan * DENY bad!*@* 60 :abuse\r\n",
        try buildAccessEntry(&buf, ctx, .{
            .entry_type = .deny,
            .mask = "bad!*@*",
            .duration = 60,
            .reason = "abuse",
        }),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 804 dan * NONICK badnick*\r\n",
        try buildAccessEntry(&buf, ctx, .{
            .entry_type = .nonick,
            .mask = "badnick*",
        }),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 805 dan * :End of ACCESS list\r\n",
        try buildAccessEnd(&buf, ctx),
    );
}

test "add and delete acknowledgement builders emit IRCX numerics" {
    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var buf: [256]u8 = undefined;

    try std.testing.expectEqualStrings(
        ":irc.example.test 801 dan * GAG flooder!*@* :ACCESS entry added\r\n",
        try buildAccessAdd(&buf, ctx, .{
            .entry_type = .gag,
            .mask = "flooder!*@*",
        }),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 802 dan * GAG flooder!*@* :ACCESS entry deleted\r\n",
        try buildAccessDelete(&buf, ctx, .{
            .entry_type = .gag,
            .mask = "flooder!*@*",
        }),
    );
}

test "malformed access commands are rejected" {
    try std.testing.expectError(error.MissingTarget, parseAccess(&.{}));
    try std.testing.expectError(error.InvalidTarget, parseAccess(&.{ "#chan", "LIST" }));
    try std.testing.expectError(error.MissingSubcommand, parseSaccess(&.{}));
    try std.testing.expectError(error.InvalidSubcommand, parseSaccess(&.{"BOGUS"}));
    try std.testing.expectError(error.MissingEntryType, parseSaccess(&.{"ADD"}));
    try std.testing.expectError(error.MissingMask, parseSaccess(&.{ "ADD", "DENY" }));
    try std.testing.expectError(error.InvalidEntryType, parseSaccess(&.{ "ADD", "QUIET", "bad!*@*" }));
    try std.testing.expectError(error.InvalidMask, parseSaccess(&.{ "ADD", "DENY", "bad mask" }));
    try std.testing.expectError(error.InvalidMask, parseSaccess(&.{ "ADD", "NOCHANNEL", "bad*" }));
    try std.testing.expectError(error.InvalidMask, parseSaccess(&.{ "ADD", "NONICK", "bad!*@*" }));
    try std.testing.expectError(error.InvalidDuration, parseSaccess(&.{ "ADD", "DENY", "bad!*@*", "12x" }));
    try std.testing.expectError(error.InvalidReason, parseSaccess(&.{ "ADD", "DENY", "bad!*@*", "12", "bad\rreason" }));
    try std.testing.expectError(error.TooManyParameters, parseSaccess(&.{ "LIST", "DENY", "GAG" }));
    try std.testing.expectError(error.TooManyParameters, parseSaccess(&.{ "DELETE", "DENY", "bad!*@*", "extra" }));
}

test "builders validate bytes and caller-owned buffer bounds" {
    const good_ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    const bad_ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "bad nick" };
    var buf: [256]u8 = undefined;

    try std.testing.expectError(error.InvalidRequester, buildAccessEnd(&buf, bad_ctx));
    try std.testing.expectError(error.InvalidMask, buildAccessEntry(&buf, good_ctx, .{
        .entry_type = .nochannel,
        .mask = "not-a-channel",
    }));
    try std.testing.expectError(error.InvalidReason, buildAccessEntry(&buf, good_ctx, .{
        .entry_type = .deny,
        .mask = "bad!*@*",
        .reason = "bad\nreason",
    }));

    var short: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildAccessEnd(&short, good_ctx));

    var limited: [128]u8 = undefined;
    try std.testing.expectError(error.LineTooLong, buildAccessEndWith(.{ .max_line_bytes = 12 }, &limited, good_ctx));
}
