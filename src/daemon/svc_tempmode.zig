// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Timed channel mode scheduler for daemon-owned service commands.
//!
//! This module is intentionally pure data structure, parser, and command logic.
//! It does not model service pseudoclients: due entries become real IRC `MODE`
//! reverts such as `MODE #ops -m`.
const std = @import("std");

pub const COMMAND = "TEMPMODE";
pub const MAX_CHANNEL_BYTES: usize = 128;
pub const MAX_PARAM_BYTES: usize = 256;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_IRC_PARAMS: usize = 15;

/// The maximum legal queue fits under 2 MiB; this is also below the Helix
/// arena ceiling and rejects absurd lengths before allocation.
pub const max_checkpoint_bytes: usize = @min(@import("helix/live.zig").max_arena_bytes, 2 * 1024 * 1024);
pub const checkpoint_magic = [_]u8{ 'T', 'M', 'O', 'D' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4 + 8 + 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_row_min_len: usize = 8 + 1 + 2 + 1 + 1 + 8 + 8;
const checkpoint_domain = "onyx-service-tempmode-checkpoint-v1";

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    NonCanonicalOrder,
    DuplicateId,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Validate exact queue shape without allocating. The ID check is quadratic
/// over at most 4096 rows, so corrupt checkpoints cannot create unbounded work.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved_digest: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved_digest)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
    const next_id = try reader.readU64();
    if (next_id == 0) return error.InvalidField;
    const row_count: usize = try reader.readU32();
    if (row_count > MAX_ENTRIES) return error.CheckpointTooLarge;
    if (row_count > body_len / checkpoint_row_min_len) return error.Truncated;
    var seen_ids: [MAX_ENTRIES]EntryId = undefined;
    var previous: ?OrderKey = null;
    for (0..row_count) |index| {
        const id = try reader.readU64();
        if (id == 0 or id >= next_id) return error.InvalidField;
        for (seen_ids[0..index]) |prior_id| if (prior_id == id) return error.DuplicateId;
        seen_ids[index] = id;
        const channel_len: usize = try reader.readByte();
        if (channel_len < 2 or channel_len > MAX_CHANNEL_BYTES) return error.InvalidField;
        const channel = try reader.take(channel_len);
        validateChannel(channel) catch return error.InvalidField;
        const mode_letter = try reader.readByte();
        validateModeLetter(mode_letter) catch return error.InvalidField;
        const param_tag = try reader.readByte();
        switch (param_tag) {
            0 => {},
            1 => {
                const param_len: usize = try reader.readU16();
                if (param_len == 0 or param_len > MAX_PARAM_BYTES) return error.InvalidField;
                validateParam(try reader.take(param_len)) catch return error.InvalidField;
            },
            else => return error.InvalidField,
        }
        const set_at_ms = try reader.readI64();
        const revert_at_ms = try reader.readI64();
        if (revert_at_ms <= set_at_ms) return error.InvalidField;
        const order = OrderKey{ .revert_at_ms = revert_at_ms, .id = id };
        if (previous) |prior| {
            if (!orderLess(prior, order)) return error.NonCanonicalOrder;
        }
        previous = order;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

pub const EntryId = u64;
pub const TimestampMs = i64;

pub const TempModeError = std.mem.Allocator.Error || error{
    EmptyLine,
    EmbeddedNul,
    EmbeddedLineBreak,
    MissingCommand,
    UnknownCommand,
    MissingSubcommand,
    UnknownSubcommand,
    NeedMoreParams,
    TooManyParams,
    TooManyEntries,
    InvalidChannel,
    ChannelTooLong,
    InvalidMode,
    InvalidParam,
    ParamTooLong,
    InvalidDuration,
    InvalidTimeWindow,
    TimeOverflow,
    OutputTooSmall,
};

/// Numerics a daemon integration can use for TEMPMODE command failures.
pub const Numeric = enum(u16) {
    RPL_TEMPMODE = 778,
    ERR_NOSUCHCHANNEL = 403,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NEEDMOREPARAMS = 461,
    ERR_UNKNOWNMODE = 472,
    ERR_BADCHANMASK = 476,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED = 482,
};

pub const Entry = struct {
    id: EntryId,
    channel: []u8,
    mode_letter: u8,
    param: ?[]u8 = null,
    set_at_ms: TimestampMs,
    revert_at_ms: TimestampMs,
};

/// Borrowed action returned by `due`. Apply it as `MODE <channel> -<mode> [param]`.
pub const RevertAction = struct {
    id: EntryId,
    channel: []const u8,
    mode_letter: u8,
    param: ?[]const u8 = null,
    set_at_ms: TimestampMs,
    revert_at_ms: TimestampMs,

    pub fn modeString(self: RevertAction, out: *[2]u8) []const u8 {
        out.* = .{ '-', self.mode_letter };
        return out[0..2];
    }
};

pub const AddCommand = struct {
    channel: []const u8,
    mode_letter: u8,
    param: ?[]const u8 = null,
    set_at_ms: TimestampMs,
    revert_at_ms: TimestampMs,
};

pub const CancelCommand = struct {
    channel: []const u8,
    mode_letter: u8,
    param: ?[]const u8 = null,
};

pub const ParsedCommand = union(enum) {
    add: AddCommand,
    cancel: CancelCommand,
    sweep,
};

pub const TempModeQueue = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    next_id: EntryId = 1,

    pub fn init(allocator: std.mem.Allocator) TempModeQueue {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TempModeQueue) void {
        for (self.entries.items) |*entry| self.freeEntry(entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(
        self: *TempModeQueue,
        channel: []const u8,
        mode_letter: u8,
        param: ?[]const u8,
        set_at_ms: TimestampMs,
        revert_at_ms: TimestampMs,
    ) TempModeError!EntryId {
        try validateChannel(channel);
        try validateModeLetter(mode_letter);
        if (param) |value| try validateParam(value);
        if (revert_at_ms <= set_at_ms) return error.InvalidTimeWindow;
        if (self.entries.items.len >= MAX_ENTRIES) return error.TooManyEntries;

        var entry = Entry{
            .id = self.next_id,
            .channel = try self.allocator.dupe(u8, channel),
            .mode_letter = mode_letter,
            .param = null,
            .set_at_ms = set_at_ms,
            .revert_at_ms = revert_at_ms,
        };
        errdefer self.allocator.free(entry.channel);

        if (param) |value| {
            entry.param = try self.allocator.dupe(u8, value);
        }
        errdefer if (entry.param) |value| self.allocator.free(value);

        const index = self.insertIndex(revert_at_ms, entry.id);
        try self.entries.insert(self.allocator, index, entry);
        self.next_id += 1;
        return entry.id;
    }

    pub fn addParsed(self: *TempModeQueue, command: AddCommand) TempModeError!EntryId {
        return self.add(command.channel, command.mode_letter, command.param, command.set_at_ms, command.revert_at_ms);
    }

    pub fn cancelId(self: *TempModeQueue, id: EntryId) bool {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.id == id) {
                self.removeAt(index);
                return true;
            }
        }
        return false;
    }

    /// Cancel the first matching scheduled mode.
    pub fn cancel(self: *TempModeQueue, channel: []const u8, mode_letter: u8, param: ?[]const u8) bool {
        const normalized_mode = normalizeModeLetter(mode_letter) orelse return false;
        for (self.entries.items, 0..) |entry, index| {
            if (entry.mode_letter == normalized_mode and
                std.mem.eql(u8, entry.channel, channel) and
                optionalEql(entry.param, param))
            {
                self.removeAt(index);
                return true;
            }
        }
        return false;
    }

    /// Cancel every matching scheduled mode and return the number removed.
    pub fn cancelAll(self: *TempModeQueue, channel: []const u8, mode_letter: u8, param: ?[]const u8) usize {
        const normalized_mode = normalizeModeLetter(mode_letter) orelse return 0;
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (entry.mode_letter == normalized_mode and
                std.mem.eql(u8, entry.channel, channel) and
                optionalEql(entry.param, param))
            {
                self.removeAt(index);
                removed += 1;
            } else {
                index += 1;
            }
        }
        return removed;
    }

    pub fn dueCount(self: *const TempModeQueue, now_ms: TimestampMs) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.revert_at_ms > now_ms) break;
            count += 1;
        }
        return count;
    }

    /// Copy up to `out.len` due revert actions into `out`.
    ///
    /// Returned slices borrow from the queue and stay valid until `cancel`,
    /// `sweep`, `deinit`, or another mutating operation. Call `dueCount` first
    /// if the caller must guarantee a complete batch before `sweep`.
    pub fn due(self: *const TempModeQueue, now_ms: TimestampMs, out: []RevertAction) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.revert_at_ms > now_ms or count == out.len) break;
            out[count] = actionFromEntry(entry);
            count += 1;
        }
        return count;
    }

    /// Remove all expired entries after their returned MODE reverts have been applied.
    pub fn sweep(self: *TempModeQueue, now_ms: TimestampMs) usize {
        var removed: usize = 0;
        while (self.entries.items.len > 0 and self.entries.items[0].revert_at_ms <= now_ms) {
            self.removeAt(0);
            removed += 1;
        }
        return removed;
    }

    pub fn len(self: *const TempModeQueue) usize {
        return self.entries.items.len;
    }

    pub fn nextDueMs(self: *const TempModeQueue) ?TimestampMs {
        if (self.entries.items.len == 0) return null;
        return self.entries.items[0].revert_at_ms;
    }

    /// Serialize every pending action and the next ID. Already-due entries
    /// stay queued until the daemon has applied their MODE revert and swept.
    pub fn exportUpgradeCheckpoint(self: *const TempModeQueue, allocator: std.mem.Allocator) CheckpointError![]u8 {
        const row_count = self.entries.items.len;
        if (row_count > MAX_ENTRIES or self.next_id == 0) return error.InvalidField;
        var seen_ids: [MAX_ENTRIES]EntryId = undefined;
        var previous: ?OrderKey = null;
        var total_len: usize = checkpoint_header_len + checkpoint_checksum_len;
        for (self.entries.items, 0..) |entry, index| {
            if (entry.id == 0 or entry.id >= self.next_id or entry.revert_at_ms <= entry.set_at_ms)
                return error.InvalidField;
            for (seen_ids[0..index]) |prior_id| if (prior_id == entry.id) return error.DuplicateId;
            seen_ids[index] = entry.id;
            validateChannel(entry.channel) catch return error.InvalidField;
            validateModeLetter(entry.mode_letter) catch return error.InvalidField;
            const order = OrderKey{ .revert_at_ms = entry.revert_at_ms, .id = entry.id };
            if (previous) |prior| {
                if (!orderLess(prior, order)) return error.NonCanonicalOrder;
            }
            previous = order;
            try checkpointAddLen(&total_len, checkpoint_row_min_len - 2);
            try checkpointAddLen(&total_len, entry.channel.len);
            if (entry.param) |value| {
                validateParam(value) catch return error.InvalidField;
                try checkpointAddLen(&total_len, 2);
                try checkpointAddLen(&total_len, value.len);
            }
        }

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(total_len - checkpoint_header_len - checkpoint_checksum_len));
        writer.writeU64(self.next_id);
        writer.writeU32(@intCast(row_count));
        for (self.entries.items) |entry| {
            writer.writeU64(entry.id);
            writer.writeByte(@intCast(entry.channel.len));
            writer.writeBytes(entry.channel);
            writer.writeByte(entry.mode_letter);
            if (entry.param) |value| {
                writer.writeByte(1);
                writer.writeU16(@intCast(value.len));
                writer.writeBytes(value);
            } else {
                writer.writeByte(0);
            }
            writer.writeI64(entry.set_at_ms);
            writer.writeI64(entry.revert_at_ms);
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        return out;
    }

    /// Stage an independent exact queue before the upgrade commits.
    pub fn restoreUpgradeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) CheckpointError!TempModeQueue {
        try validateUpgradeCheckpoint(bytes);
        var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
        const next_id = try reader.readU64();
        const row_count: usize = try reader.readU32();
        var restored = TempModeQueue.init(allocator);
        errdefer restored.deinit();
        restored.next_id = next_id;
        try restored.entries.ensureTotalCapacityPrecise(allocator, row_count);
        for (0..row_count) |_| {
            const id = try reader.readU64();
            const channel_len: usize = try reader.readByte();
            const channel = try reader.take(channel_len);
            const mode_letter = try reader.readByte();
            const param_tag = try reader.readByte();
            const param: ?[]const u8 = if (param_tag == 1) blk: {
                const param_len: usize = try reader.readU16();
                break :blk try reader.take(param_len);
            } else null;
            const set_at_ms = try reader.readI64();
            const revert_at_ms = try reader.readI64();
            const owned_channel = try allocator.dupe(u8, channel);
            errdefer allocator.free(owned_channel);
            const owned_param: ?[]u8 = if (param) |value| try allocator.dupe(u8, value) else null;
            errdefer if (owned_param) |value| allocator.free(value);
            try restored.entries.append(allocator, .{
                .id = id,
                .channel = owned_channel,
                .mode_letter = mode_letter,
                .param = owned_param,
                .set_at_ms = set_at_ms,
                .revert_at_ms = revert_at_ms,
            });
        }
        std.debug.assert(reader.remaining() == 0);
        return restored;
    }

    pub fn replaceFromUpgradeCheckpoint(self: *TempModeQueue, bytes: []const u8) CheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, bytes);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }

    fn insertIndex(self: *const TempModeQueue, revert_at_ms: TimestampMs, id: EntryId) usize {
        for (self.entries.items, 0..) |entry, index| {
            if (revert_at_ms < entry.revert_at_ms) return index;
            if (revert_at_ms == entry.revert_at_ms and id < entry.id) return index;
        }
        return self.entries.items.len;
    }

    fn removeAt(self: *TempModeQueue, index: usize) void {
        var entry = self.entries.orderedRemove(index);
        self.freeEntry(&entry);
    }

    fn freeEntry(self: *TempModeQueue, entry: *Entry) void {
        self.allocator.free(entry.channel);
        if (entry.param) |value| self.allocator.free(value);
        entry.* = undefined;
    }
};

/// Parse a raw IRC line into a TEMPMODE command.
///
/// Supported real server command forms:
///   TEMPMODE ADD #chan +m <duration-ms>
///   TEMPMODE ADD #chan +b mask!*@* <duration-ms>
///   TEMPMODE CANCEL #chan m [param]
///   TEMPMODE SWEEP
pub fn parseCommand(line: []const u8, now_ms: TimestampMs) TempModeError!ParsedCommand {
    const parsed = try parseIrcLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, COMMAND)) return error.UnknownCommand;
    return parseParams(parsed.paramSlice(), now_ms);
}

/// Parse TEMPMODE parameters excluding the command name.
pub fn parseParams(params: []const []const u8, now_ms: TimestampMs) TempModeError!ParsedCommand {
    if (params.len == 0) return error.MissingSubcommand;

    if (std.ascii.eqlIgnoreCase(params[0], "ADD")) {
        if (params.len != 4 and params.len != 5) return error.NeedMoreParams;
        const channel = params[1];
        const mode_letter = try parseModeToken(params[2], true);
        const duration_text = params[params.len - 1];
        const duration_ms = parseDuration(duration_text) catch return error.InvalidDuration;
        const revert_at_ms = addDuration(now_ms, duration_ms) catch return error.TimeOverflow;
        const param = if (params.len == 5) params[3] else null;

        try validateChannel(channel);
        try validateModeLetter(mode_letter);
        if (param) |value| try validateParam(value);

        return .{ .add = .{
            .channel = channel,
            .mode_letter = mode_letter,
            .param = param,
            .set_at_ms = now_ms,
            .revert_at_ms = revert_at_ms,
        } };
    }

    if (std.ascii.eqlIgnoreCase(params[0], "CANCEL")) {
        if (params.len != 3 and params.len != 4) return error.NeedMoreParams;
        const channel = params[1];
        const mode_letter = try parseModeToken(params[2], false);
        const param = if (params.len == 4) params[3] else null;

        try validateChannel(channel);
        try validateModeLetter(mode_letter);
        if (param) |value| try validateParam(value);

        return .{ .cancel = .{
            .channel = channel,
            .mode_letter = mode_letter,
            .param = param,
        } };
    }

    if (std.ascii.eqlIgnoreCase(params[0], "SWEEP")) {
        if (params.len != 1) return error.NeedMoreParams;
        return .sweep;
    }

    return error.UnknownSubcommand;
}

/// Format the real IRC command that applies a due revert.
pub fn formatRevertMode(out: []u8, action: RevertAction) TempModeError![]const u8 {
    var writer = std.Io.Writer.fixed(out);
    writer.print("MODE {s} -{c}", .{ action.channel, action.mode_letter }) catch return error.OutputTooSmall;
    if (action.param) |value| {
        writer.print(" {s}", .{value}) catch return error.OutputTooSmall;
    }
    return writer.buffered();
}

pub fn numericForError(err: anyerror) Numeric {
    return switch (err) {
        error.UnknownCommand => .ERR_UNKNOWNCOMMAND,
        error.InvalidMode => .ERR_UNKNOWNMODE,
        error.InvalidChannel, error.ChannelTooLong => .ERR_BADCHANMASK,
        error.MissingSubcommand,
        error.UnknownSubcommand,
        error.NeedMoreParams,
        error.TooManyParams,
        error.InvalidParam,
        error.ParamTooLong,
        error.InvalidDuration,
        error.InvalidTimeWindow,
        error.TimeOverflow,
        => .ERR_NEEDMOREPARAMS,
        else => .ERR_NEEDMOREPARAMS,
    };
}

pub fn formatNumericCode(numeric: Numeric, out: *[3]u8) []const u8 {
    const value: u16 = @intFromEnum(numeric);
    out[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    out[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    out[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return out[0..3];
}

fn actionFromEntry(entry: Entry) RevertAction {
    return .{
        .id = entry.id,
        .channel = entry.channel,
        .mode_letter = entry.mode_letter,
        .param = entry.param,
        .set_at_ms = entry.set_at_ms,
        .revert_at_ms = entry.revert_at_ms,
    };
}

fn validateChannel(channel: []const u8) TempModeError!void {
    if (channel.len < 2) return error.InvalidChannel;
    if (channel.len > MAX_CHANNEL_BYTES) return error.ChannelTooLong;
    if (channel[0] != '#' and channel[0] != '&') return error.InvalidChannel;
    for (channel) |ch| {
        if (isControl(ch) or ch == ' ' or ch == ',' or ch == 7) return error.InvalidChannel;
    }
}

fn validateModeLetter(mode_letter: u8) TempModeError!void {
    if (normalizeModeLetter(mode_letter) == null) return error.InvalidMode;
}

fn normalizeModeLetter(mode_letter: u8) ?u8 {
    if (std.ascii.isAlphabetic(mode_letter)) return mode_letter;
    return null;
}

fn validateParam(param: []const u8) TempModeError!void {
    if (param.len == 0) return error.InvalidParam;
    if (param.len > MAX_PARAM_BYTES) return error.ParamTooLong;
    for (param) |ch| {
        if (isControl(ch) or ch == ' ') return error.InvalidParam;
    }
}

fn optionalEql(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) return true;
    if (left == null or right == null) return false;
    return std.mem.eql(u8, left.?, right.?);
}

fn parseModeToken(token: []const u8, require_plus: bool) TempModeError!u8 {
    if (token.len == 1) {
        if (require_plus) return error.InvalidMode;
        return token[0];
    }
    if (token.len == 2 and (token[0] == '+' or token[0] == '-')) {
        if (require_plus and token[0] != '+') return error.InvalidMode;
        return token[1];
    }
    return error.InvalidMode;
}

fn parseDuration(text: []const u8) TempModeError!TimestampMs {
    const value = std.fmt.parseInt(TimestampMs, text, 10) catch return error.InvalidDuration;
    if (value <= 0) return error.InvalidDuration;
    return value;
}

fn addDuration(now_ms: TimestampMs, duration_ms: TimestampMs) TempModeError!TimestampMs {
    if (duration_ms <= 0) return error.InvalidDuration;
    if (now_ms > std.math.maxInt(TimestampMs) - duration_ms) return error.TimeOverflow;
    return now_ms + duration_ms;
}

const IrcLine = struct {
    command: []const u8,
    params: [MAX_IRC_PARAMS][]const u8 = @splat(""),
    param_count: usize = 0,

    fn paramSlice(self: *const IrcLine) []const []const u8 {
        return self.params[0..self.param_count];
    }
};

fn parseIrcLine(input: []const u8) TempModeError!IrcLine {
    var body = input;
    if (body.len >= 2 and body[body.len - 2] == '\r' and body[body.len - 1] == '\n') {
        body = body[0 .. body.len - 2];
    } else if (body.len >= 1 and (body[body.len - 1] == '\r' or body[body.len - 1] == '\n')) {
        body = body[0 .. body.len - 1];
    }
    if (body.len == 0) return error.EmptyLine;
    for (body) |ch| {
        switch (ch) {
            0 => return error.EmbeddedNul,
            '\r', '\n' => return error.EmbeddedLineBreak,
            else => {},
        }
    }

    var cursor = skipSpaces(body, 0);
    if (cursor >= body.len) return error.MissingCommand;

    if (body[cursor] == '@') {
        const tags_end = findSpace(body, cursor) orelse return error.MissingCommand;
        cursor = skipSpaces(body, tags_end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    if (body[cursor] == ':') {
        const prefix_end = findSpace(body, cursor) orelse return error.MissingCommand;
        cursor = skipSpaces(body, prefix_end);
        if (cursor >= body.len) return error.MissingCommand;
    }

    const command_end = findSpace(body, cursor) orelse body.len;
    if (command_end == cursor) return error.MissingCommand;
    var line = IrcLine{ .command = body[cursor..command_end] };
    cursor = skipSpaces(body, command_end);

    while (cursor < body.len) {
        if (line.param_count == MAX_IRC_PARAMS) return error.TooManyParams;
        if (body[cursor] == ':') {
            line.params[line.param_count] = body[cursor + 1 ..];
            line.param_count += 1;
            break;
        }
        const end = findSpace(body, cursor) orelse body.len;
        line.params[line.param_count] = body[cursor..end];
        line.param_count += 1;
        cursor = skipSpaces(body, end);
    }

    return line;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var index = start;
    while (index < bytes.len and bytes[index] == ' ') : (index += 1) {}
    return index;
}

fn findSpace(bytes: []const u8, start: usize) ?usize {
    var index = start;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] == ' ') return index;
    }
    return null;
}

fn isControl(ch: u8) bool {
    return ch < 0x20 or ch == 0x7f;
}

const OrderKey = struct {
    revert_at_ms: TimestampMs,
    id: EntryId,
};

fn orderLess(a: OrderKey, b: OrderKey) bool {
    if (a.revert_at_ms != b.revert_at_ms) return a.revert_at_ms < b.revert_at_ms;
    return a.id < b.id;
}

fn checkpointAddLen(total: *usize, amount: usize) CheckpointError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU16(self: *CheckpointWriter, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .little);
        self.pos += 2;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeI64(self: *CheckpointWriter, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *CheckpointReader) CheckpointError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *CheckpointReader) CheckpointError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readI64(self: *CheckpointReader) CheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }
};

const testing = std.testing;

test "add stores owned entries sorted by revert time" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    const id_late = try queue.add("#ops", 'm', null, 1000, 5000);
    const id_early = try queue.add("#chat", 'i', null, 1000, 3000);

    try testing.expectEqual(@as(usize, 2), queue.len());
    try testing.expectEqual(id_early, queue.entries.items[0].id);
    try testing.expectEqual(id_late, queue.entries.items[1].id);
    try testing.expectEqual(@as(?TimestampMs, 3000), queue.nextDueMs());
}

test "queued strings are owned and independent from caller buffers" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    var channel_buf = [_]u8{ '#', 'o', 'p', 's' };
    var param_buf = [_]u8{ 'b', 'a', 'd', '!', '*', '@', '*' };
    _ = try queue.add(channel_buf[0..], 'b', param_buf[0..], 0, 10);

    channel_buf[1] = 'x';
    param_buf[0] = 'x';

    var out: [1]RevertAction = undefined;
    try testing.expectEqual(@as(usize, 1), queue.due(10, out[0..]));
    try testing.expectEqualStrings("#ops", out[0].channel);
    try testing.expectEqualStrings("bad!*@*", out[0].param.?);
}

test "due returns real MODE revert actions without removing entries" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.add("#ops", 'm', null, 1000, 2000);
    _ = try queue.add("#ops", 'b', "bad!*@*", 1000, 3000);

    var out: [2]RevertAction = undefined;
    try testing.expectEqual(@as(usize, 0), queue.due(1999, out[0..]));
    try testing.expectEqual(@as(usize, 1), queue.due(2000, out[0..]));
    try testing.expectEqualStrings("#ops", out[0].channel);
    try testing.expectEqual(@as(u8, 'm'), out[0].mode_letter);
    try testing.expectEqual(@as(?[]const u8, null), out[0].param);
    try testing.expectEqual(@as(usize, 2), queue.len());

    var mode_buf: [2]u8 = undefined;
    try testing.expectEqualStrings("-m", out[0].modeString(&mode_buf));
}

test "formatRevertMode emits server MODE command with optional parameter" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.add("#ops", 'b', "bad!*@*", 100, 200);
    var actions: [1]RevertAction = undefined;
    try testing.expectEqual(@as(usize, 1), queue.due(200, actions[0..]));

    var line_buf: [64]u8 = undefined;
    const line = try formatRevertMode(line_buf[0..], actions[0]);
    try testing.expectEqualStrings("MODE #ops -b bad!*@*", line);
}

test "sweep removes and frees only expired entries" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.add("#a", 'm', null, 0, 10);
    _ = try queue.add("#b", 'i', null, 0, 20);
    _ = try queue.add("#c", 's', null, 0, 30);

    try testing.expectEqual(@as(usize, 2), queue.sweep(20));
    try testing.expectEqual(@as(usize, 1), queue.len());
    try testing.expectEqualStrings("#c", queue.entries.items[0].channel);
    try testing.expectEqual(@as(usize, 1), queue.sweep(999));
    try testing.expectEqual(@as(usize, 0), queue.len());
}

test "cancel by id and by exact match remove scheduled entries" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    const first = try queue.add("#ops", 'm', null, 0, 100);
    _ = try queue.add("#ops", 'b', "bad!*@*", 0, 200);

    try testing.expect(queue.cancelId(first));
    try testing.expect(!queue.cancelId(first));
    try testing.expect(queue.cancel("#ops", '+', null) == false);
    try testing.expect(queue.cancel("#ops", 'b', "bad!*@*"));
    try testing.expectEqual(@as(usize, 0), queue.len());
}

test "cancelAll removes duplicate matching entries" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.add("#ops", 'm', null, 0, 100);
    _ = try queue.add("#ops", 'm', null, 0, 200);
    _ = try queue.add("#ops", 'i', null, 0, 300);

    try testing.expectEqual(@as(usize, 2), queue.cancelAll("#ops", 'm', null));
    try testing.expectEqual(@as(usize, 1), queue.len());
    try testing.expectEqual(@as(u8, 'i'), queue.entries.items[0].mode_letter);
}

test "due honors caller output capacity and dueCount reports total" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    _ = try queue.add("#a", 'm', null, 0, 10);
    _ = try queue.add("#b", 'i', null, 0, 20);
    _ = try queue.add("#c", 's', null, 0, 30);

    var out: [2]RevertAction = undefined;
    try testing.expectEqual(@as(usize, 3), queue.dueCount(30));
    try testing.expectEqual(@as(usize, 2), queue.due(30, out[0..]));
    try testing.expectEqualStrings("#a", out[0].channel);
    try testing.expectEqualStrings("#b", out[1].channel);
}

test "validation rejects bad channels modes params and time windows" {
    var queue = TempModeQueue.init(testing.allocator);
    defer queue.deinit();

    try testing.expectError(error.InvalidChannel, queue.add("ops", 'm', null, 0, 10));
    try testing.expectError(error.InvalidChannel, queue.add("#bad name", 'm', null, 0, 10));
    try testing.expectError(error.InvalidMode, queue.add("#ops", '1', null, 0, 10));
    try testing.expectError(error.InvalidParam, queue.add("#ops", 'b', "", 0, 10));
    try testing.expectError(error.InvalidParam, queue.add("#ops", 'b', "bad mask", 0, 10));
    try testing.expectError(error.InvalidTimeWindow, queue.add("#ops", 'm', null, 10, 10));
}

test "parse ADD command without parameter" {
    const parsed = try parseCommand("TEMPMODE ADD #ops +m 60000", 1000);
    switch (parsed) {
        .add => |cmd| {
            try testing.expectEqualStrings("#ops", cmd.channel);
            try testing.expectEqual(@as(u8, 'm'), cmd.mode_letter);
            try testing.expectEqual(@as(?[]const u8, null), cmd.param);
            try testing.expectEqual(@as(TimestampMs, 1000), cmd.set_at_ms);
            try testing.expectEqual(@as(TimestampMs, 61000), cmd.revert_at_ms);
        },
        else => return error.ExpectedAdd,
    }
}

test "parse ADD command with mode parameter and IRC prefix" {
    const parsed = try parseCommand("@label=123 :irc.example TEMPMODE ADD #ops +b bad!*@* 250\r\n", 50);
    switch (parsed) {
        .add => |cmd| {
            try testing.expectEqualStrings("#ops", cmd.channel);
            try testing.expectEqual(@as(u8, 'b'), cmd.mode_letter);
            try testing.expectEqualStrings("bad!*@*", cmd.param.?);
            try testing.expectEqual(@as(TimestampMs, 300), cmd.revert_at_ms);
        },
        else => return error.ExpectedAdd,
    }
}

test "parse CANCEL and SWEEP commands" {
    const cancel = try parseCommand("tempmode cancel #ops -b bad!*@*", 0);
    switch (cancel) {
        .cancel => |cmd| {
            try testing.expectEqualStrings("#ops", cmd.channel);
            try testing.expectEqual(@as(u8, 'b'), cmd.mode_letter);
            try testing.expectEqualStrings("bad!*@*", cmd.param.?);
        },
        else => return error.ExpectedCancel,
    }

    const sweep = try parseCommand("TEMPMODE SWEEP", 0);
    try testing.expect(sweep == .sweep);
}

test "parse rejects unknown commands malformed modes and invalid durations" {
    try testing.expectError(error.UnknownCommand, parseCommand("PRIVMSG #ops :hello", 0));
    try testing.expectError(error.InvalidMode, parseCommand("TEMPMODE ADD #ops -m 10", 0));
    try testing.expectError(error.InvalidDuration, parseCommand("TEMPMODE ADD #ops +m 0", 0));
    try testing.expectError(error.TimeOverflow, parseCommand("TEMPMODE ADD #ops +m 1", std.math.maxInt(TimestampMs)));
    try testing.expectError(error.NeedMoreParams, parseCommand("TEMPMODE ADD #ops +m", 0));
}

test "numeric mapping and formatting use IRC numerics" {
    try testing.expectEqual(Numeric.ERR_UNKNOWNCOMMAND, numericForError(error.UnknownCommand));
    try testing.expectEqual(Numeric.ERR_UNKNOWNMODE, numericForError(error.InvalidMode));
    try testing.expectEqual(Numeric.ERR_BADCHANMASK, numericForError(error.InvalidChannel));
    try testing.expectEqual(Numeric.ERR_NEEDMOREPARAMS, numericForError(error.InvalidDuration));

    var code_buf: [3]u8 = undefined;
    try testing.expectEqualStrings("472", formatNumericCode(.ERR_UNKNOWNMODE, &code_buf));
    try testing.expectEqualStrings("778", formatNumericCode(.RPL_TEMPMODE, &code_buf));
}

test "parse line rejects control bytes and too many params" {
    try testing.expectError(error.EmbeddedNul, parseCommand("TEMPMODE ADD #ops +m 1\x00", 0));

    const too_many = "TEMPMODE SWEEP a b c d e f g h i j k l m n o p";
    try testing.expectError(error.TooManyParams, parseCommand(too_many, 0));
}

test "formatRevertMode reports small output buffer" {
    const action = RevertAction{
        .id = 1,
        .channel = "#ops",
        .mode_letter = 'm',
        .set_at_ms = 0,
        .revert_at_ms = 1,
    };
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, formatRevertMode(tiny[0..], action));
}

test "tempmode checkpoint preserves due rows order and next id" {
    var source = TempModeQueue.init(testing.allocator);
    defer source.deinit();
    const cancelled = try source.add("#ops", 'm', null, 0, 100);
    const earliest = try source.add("#ops", 'b', "bad!*@*", -50, 50);
    const tied = try source.add("#chat", 'i', null, 0, 100);
    try testing.expect(source.cancelId(cancelled));
    try testing.expectEqual(@as(EntryId, 4), source.next_id);
    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    try validateUpgradeCheckpoint(wire);

    var restored = try TempModeQueue.restoreUpgradeCheckpoint(testing.allocator, wire);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.len());
    try testing.expectEqual(@as(EntryId, 4), restored.next_id);
    try testing.expectEqual(earliest, restored.entries.items[0].id);
    try testing.expectEqual(tied, restored.entries.items[1].id);
    try testing.expectEqual(@as(usize, 1), restored.dueCount(60));
    try testing.expectEqual(@as(?TimestampMs, 50), restored.nextDueMs());
    try testing.expectEqualStrings("bad!*@*", restored.entries.items[0].param.?);
    const reencoded = try restored.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, wire, reencoded);
    try testing.expectEqual(@as(EntryId, 4), try restored.add("#new", 's', null, 100, 200));

    // An empty queue still carries the ID high-water mark after cancellation.
    try testing.expect(source.cancelId(earliest));
    try testing.expect(source.cancelId(tied));
    const empty_wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(empty_wire);
    var empty_restored = try TempModeQueue.restoreUpgradeCheckpoint(testing.allocator, empty_wire);
    defer empty_restored.deinit();
    try testing.expectEqual(@as(usize, 0), empty_restored.len());
    try testing.expectEqual(@as(EntryId, 4), try empty_restored.add("#next", 'm', null, 0, 1));
}

test "tempmode checkpoint rejects malformed rows and ordering" {
    var source = TempModeQueue.init(testing.allocator);
    defer source.deinit();
    _ = try source.add("#a", 'm', null, 0, 100);
    _ = try source.add("#b", 'i', null, 0, 200);
    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    for (0..wire.len) |n| {
        try testing.expectError(error.Truncated, TempModeQueue.restoreUpgradeCheckpoint(testing.allocator, wire[0..n]));
    }

    var damaged = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(damaged);
    damaged[4] = 2;
    try testing.expectError(error.UnsupportedVersion, validateUpgradeCheckpoint(damaged));
    damaged[4] = checkpoint_version;
    damaged[checkpoint_header_len + 8 + 1] ^= 1;
    try testing.expectError(error.ChecksumMismatch, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u64, damaged[checkpoint_header_len + checkpoint_row_min_len ..][0..8], 1, .little);
    testRechecksum(damaged);
    try testing.expectError(error.DuplicateId, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(i64, damaged[checkpoint_header_len + checkpoint_row_min_len - 8 ..][0..8], 300, .little);
    testRechecksum(damaged);
    try testing.expectError(error.NonCanonicalOrder, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 8 + 1] = ' ';
    testRechecksum(damaged);
    try testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 8 + 1 + 2 + 1] = 2;
    testRechecksum(damaged);
    try testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(i64, damaged[checkpoint_header_len + checkpoint_row_min_len - 8 ..][0..8], 0, .little);
    testRechecksum(damaged);
    try testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, validateUpgradeCheckpoint(trailing));
}

test "tempmode checkpoint replacement is atomic across allocation failures" {
    var source = TempModeQueue.init(testing.allocator);
    defer source.deinit();
    _ = try source.add("#one", 'b', "bad!*@*", 1, 100);
    _ = try source.add("#two", 'm', null, 2, 200);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, queue: *const TempModeQueue) !void {
            const bytes = try queue.exportUpgradeCheckpoint(allocator);
            defer allocator.free(bytes);
            try testing.expectEqual(@as(usize, 2), queue.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});
    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var target = TempModeQueue.init(allocator);
            defer target.deinit();
            _ = try target.add("#keeper", 'i', null, 0, 999);
            target.replaceFromUpgradeCheckpoint(bytes) catch |err| {
                try testing.expectEqual(@as(usize, 1), target.len());
                try testing.expectEqualStrings("#keeper", target.entries.items[0].channel);
                return err;
            };
            try testing.expectEqual(@as(usize, 2), target.len());
            try testing.expectEqualStrings("#one", target.entries.items[0].channel);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RestoreSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
