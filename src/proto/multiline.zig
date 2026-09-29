// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 draft/multiline batch assembler.
//!
//! Multiline batches are assembled into caller-owned storage. The hot path is
//! allocation-free: the assembler stores only validated batch metadata, appends
//! message bytes directly to the output buffer, and rejects malformed content
//! before mutating counters.
const std = @import("std");
const irc_line = @import("irc_line.zig");

pub const draft_multiline_batch = "draft/multiline";
pub const draft_multiline_concat_tag = "draft/multiline-concat";
pub const batch_tag = "batch";

pub const default_max_bytes: usize = 40_000;
pub const default_max_lines: usize = 64;
pub const default_max_ref_len: usize = 64;
pub const default_max_target_len: usize = 128;

pub const MultilineError = irc_line.ParseError || error{
    OutputTooSmall,
    BatchAlreadyOpen,
    NoOpenBatch,
    InvalidBatchOpen,
    InvalidBatchClose,
    InvalidBatchReference,
    InvalidBatchType,
    InvalidTarget,
    MissingBatchTag,
    DuplicateBatchTag,
    BatchTagMismatch,
    DisallowedTag,
    InvalidConcatTag,
    ConcatWithoutPreviousLine,
    BlankConcatLine,
    DisallowedCommand,
    MixedCommands,
    MalformedMessageLine,
    MaxBytesExceeded,
    MaxLinesExceeded,
    EmptyBatch,
    BlankMessage,
};

/// Compile-time sizing for a multiline assembler instance.
pub const Config = struct {
    max_bytes: usize = default_max_bytes,
    max_lines: usize = default_max_lines,
    max_ref_len: usize = default_max_ref_len,
    max_target_len: usize = default_max_target_len,
};

/// The command shared by every message line in a valid multiline batch.
pub const PayloadCommand = enum {
    privmsg,
    notice,

    pub fn token(self: PayloadCommand) []const u8 {
        return switch (self) {
            .privmsg => "PRIVMSG",
            .notice => "NOTICE",
        };
    }
};

/// Final assembled multiline value.
pub const Message = struct {
    command: PayloadCommand,
    target: []const u8,
    value: []const u8,
    line_count: usize,
};

/// Assemble one complete `draft/multiline` batch from raw IRC protocol lines.
pub fn assemble(
    comptime config: Config,
    open_line: []const u8,
    body_lines: []const []const u8,
    close_line: []const u8,
    out: []u8,
) MultilineError!Message {
    var assembler = Assembler(config).init();
    try assembler.begin(open_line);
    for (body_lines) |line| {
        try assembler.append(line, out);
    }
    var msg = try assembler.finish(close_line, out);
    const needed = checkedAdd(msg.value.len, msg.target.len) orelse return error.OutputTooSmall;
    if (needed > out.len) return error.OutputTooSmall;
    const target_start = msg.value.len;
    const target_len = msg.target.len;
    @memcpy(out[target_start..][0..target_len], msg.target);
    msg.target = out[target_start..][0..target_len];
    return msg;
}

/// Stateful allocation-free multiline batch assembler.
pub fn Assembler(comptime config: Config) type {
    comptime {
        if (config.max_bytes == 0) @compileError("multiline max_bytes must be non-zero");
        if (config.max_lines == 0) @compileError("multiline max_lines must be non-zero");
        if (config.max_ref_len == 0) @compileError("multiline max_ref_len must be non-zero");
        if (config.max_target_len == 0) @compileError("multiline max_target_len must be non-zero");
    }

    return struct {
        const Self = @This();

        ref_bytes: [config.max_ref_len]u8 = @splat(0),
        ref_len: usize = 0,
        target_bytes: [config.max_target_len]u8 = @splat(0),
        target_len: usize = 0,
        command: ?PayloadCommand = null,
        line_count: usize = 0,
        byte_count: usize = 0,
        has_nonblank_line: bool = false,
        is_open: bool = false,

        pub fn init() Self {
            return .{};
        }

        pub fn isOpen(self: *const Self) bool {
            return self.is_open;
        }

        pub fn reference(self: *const Self) []const u8 {
            return self.ref_bytes[0..self.ref_len];
        }

        pub fn target(self: *const Self) []const u8 {
            return self.target_bytes[0..self.target_len];
        }

        /// Validate and open a `BATCH +ref draft/multiline target` line.
        pub fn begin(self: *Self, line: []const u8) MultilineError!void {
            if (self.is_open) return error.BatchAlreadyOpen;

            const parsed = try irc_line.parseLine(line);
            if (!commandEql(parsed.command, "BATCH")) return error.InvalidBatchOpen;
            if (hasTag(&parsed, batch_tag)) return error.InvalidBatchOpen;
            if (parsed.param_count != 3) return error.InvalidBatchOpen;

            const ref_param = parsed.params[0];
            const batch_type = parsed.params[1];
            const target_param = parsed.params[2];

            if (ref_param.len < 2 or ref_param[0] != '+') return error.InvalidBatchOpen;
            const ref = ref_param[1..];
            try validateReference(ref);
            if (ref.len > config.max_ref_len) return error.InvalidBatchReference;
            if (!std.mem.eql(u8, batch_type, draft_multiline_batch)) return error.InvalidBatchType;
            try validateTarget(target_param);
            if (target_param.len > config.max_target_len) return error.InvalidTarget;

            @memcpy(self.ref_bytes[0..ref.len], ref);
            @memcpy(self.target_bytes[0..target_param.len], target_param);
            self.ref_len = ref.len;
            self.target_len = target_param.len;
            self.command = null;
            self.line_count = 0;
            self.byte_count = 0;
            self.has_nonblank_line = false;
            self.is_open = true;
        }

        /// Append one tagged `PRIVMSG` or `NOTICE` line to `out`.
        pub fn append(self: *Self, line: []const u8, out: []u8) MultilineError!void {
            if (!self.is_open) return error.NoOpenBatch;

            const parsed = try irc_line.parseLine(line);
            const tags = try innerTags(&parsed, self.reference());
            if (tags.concat and self.line_count == 0) return error.ConcatWithoutPreviousLine;

            const payload_command = payloadCommand(parsed.command) orelse return error.DisallowedCommand;
            if (self.command) |known| {
                if (known != payload_command) return error.MixedCommands;
            }

            if (parsed.param_count != 2) return error.MalformedMessageLine;
            if (!std.mem.eql(u8, parsed.params[0], self.target())) return error.InvalidTarget;
            const text = parsed.params[1];
            if (tags.concat and text.len == 0) return error.BlankConcatLine;

            if (self.line_count >= config.max_lines) return error.MaxLinesExceeded;
            const separator_len: usize = if (self.line_count == 0 or tags.concat) 0 else 1;
            const added = checkedAdd(text.len, separator_len) orelse return error.MaxBytesExceeded;
            const next_bytes = checkedAdd(self.byte_count, added) orelse return error.MaxBytesExceeded;
            if (next_bytes > config.max_bytes) return error.MaxBytesExceeded;
            if (next_bytes > out.len) return error.OutputTooSmall;

            var cursor = self.byte_count;
            if (separator_len != 0) {
                out[cursor] = '\n';
                cursor += 1;
            }
            @memcpy(out[cursor .. cursor + text.len], text);

            self.command = payload_command;
            self.line_count += 1;
            self.byte_count = next_bytes;
            self.has_nonblank_line = self.has_nonblank_line or text.len != 0;
        }

        /// Validate the closing `BATCH -ref` line and return the assembled value.
        pub fn finish(self: *Self, line: []const u8, out: []u8) MultilineError!Message {
            if (!self.is_open) return error.NoOpenBatch;

            const parsed = try irc_line.parseLine(line);
            if (!commandEql(parsed.command, "BATCH")) return error.InvalidBatchClose;
            if (hasTag(&parsed, batch_tag)) return error.InvalidBatchClose;
            if (parsed.param_count != 1) return error.InvalidBatchClose;

            const ref_param = parsed.params[0];
            if (ref_param.len < 2 or ref_param[0] != '-') return error.InvalidBatchClose;
            if (!std.mem.eql(u8, ref_param[1..], self.reference())) return error.BatchTagMismatch;
            if (self.line_count == 0) return error.EmptyBatch;
            if (!self.has_nonblank_line) return error.BlankMessage;
            const command = self.command orelse return error.EmptyBatch;

            const msg = Message{
                .command = command,
                .target = self.target(),
                .value = out[0..self.byte_count],
                .line_count = self.line_count,
            };
            self.is_open = false;
            return msg;
        }
    };
}

const InnerTags = struct {
    batch_seen: bool = false,
    concat: bool = false,
};

fn innerTags(line: *const irc_line.LineView, expected_ref: []const u8) MultilineError!InnerTags {
    var tags = InnerTags{};

    for (line.tagSlice()) |tag| {
        if (std.mem.eql(u8, tag.key, batch_tag)) {
            if (tags.batch_seen) return error.DuplicateBatchTag;
            const value = tag.value_raw orelse return error.MissingBatchTag;
            if (!std.mem.eql(u8, value, expected_ref)) return error.BatchTagMismatch;
            tags.batch_seen = true;
        } else if (std.mem.eql(u8, tag.key, draft_multiline_concat_tag)) {
            if (tags.concat) return error.DisallowedTag;
            if (tag.value_raw != null) return error.InvalidConcatTag;
            tags.concat = true;
        } else {
            return error.DisallowedTag;
        }
    }

    if (!tags.batch_seen) return error.MissingBatchTag;
    return tags;
}

fn payloadCommand(command: []const u8) ?PayloadCommand {
    if (commandEql(command, "PRIVMSG")) return .privmsg;
    if (commandEql(command, "NOTICE")) return .notice;
    return null;
}

fn commandEql(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

fn hasTag(line: *const irc_line.LineView, key: []const u8) bool {
    for (line.tagSlice()) |tag| {
        if (std.mem.eql(u8, tag.key, key)) return true;
    }
    return false;
}

fn validateReference(ref: []const u8) MultilineError!void {
    if (ref.len == 0) return error.InvalidBatchReference;
    for (ref) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return error.InvalidBatchReference,
        }
    }
}

fn validateTarget(target: []const u8) MultilineError!void {
    if (target.len == 0) return error.InvalidTarget;
    for (target) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ' => return error.InvalidTarget,
            else => {},
        }
    }
}

fn checkedAdd(a: usize, b: usize) ?usize {
    const sum, const overflow = @addWithOverflow(a, b);
    return if (overflow != 0) null else sum;
}

test "GAP-P0c draft/multiline reassembles inbound and leaves the value as one message" {
    var out: [128]u8 = undefined;
    const body = [_][]const u8{
        "@batch=ref PRIVMSG #chan :alpha",
        "@batch=ref PRIVMSG #chan :beta",
    };
    const msg = try assemble(
        .{ .max_bytes = default_max_bytes, .max_lines = default_max_lines },
        "BATCH +ref draft/multiline #chan",
        &body,
        "BATCH -ref",
        &out,
    );
    try std.testing.expectEqual(.privmsg, msg.command);
    try std.testing.expectEqualStrings("#chan", msg.target);
    try std.testing.expectEqual(@as(usize, 2), msg.line_count);
    try std.testing.expectEqualStrings("alpha\nbeta", msg.value);
    try std.testing.expect(std.mem.indexOf(u8, msg.value, "BATCH") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg.value, "draft/multiline") == null);
    try std.testing.expectEqual(@as(usize, 40_000), default_max_bytes);
    try std.testing.expectEqual(@as(usize, 64), default_max_lines);
    std.debug.print("GAP-P0c branch=inbound multiline reassembles to one value and a server reply stays one line\n", .{});
}

test "assembles newline joins and concat joins" {
    var out: [128]u8 = undefined;
    const body = [_][]const u8{
        "@batch=abc PRIVMSG #onyx :hello",
        "@batch=abc PRIVMSG #onyx :",
        "@batch=abc PRIVMSG #onyx :how is ",
        "@batch=abc;draft/multiline-concat PRIVMSG #onyx :everyone?",
    };

    const msg = try assemble(
        .{ .max_bytes = 128, .max_lines = 8 },
        "BATCH +abc draft/multiline #onyx",
        &body,
        "BATCH -abc",
        &out,
    );

    try std.testing.expectEqual(.privmsg, msg.command);
    try std.testing.expectEqualStrings("#onyx", msg.target);
    try std.testing.expectEqual(@as(usize, 4), msg.line_count);
    try std.testing.expectEqualStrings("hello\n\nhow is everyone?", msg.value);
}

test "enforces max byte and max line limits" {
    var out: [64]u8 = undefined;

    const too_many_bytes = [_][]const u8{
        "@batch=lim PRIVMSG #c :12345",
        "@batch=lim PRIVMSG #c :67890",
    };
    try std.testing.expectError(
        error.MaxBytesExceeded,
        assemble(.{ .max_bytes = 10, .max_lines = 4 }, "BATCH +lim draft/multiline #c", &too_many_bytes, "BATCH -lim", &out),
    );

    const too_many_lines = [_][]const u8{
        "@batch=lim PRIVMSG #c :a",
        "@batch=lim PRIVMSG #c :b",
    };
    try std.testing.expectError(
        error.MaxLinesExceeded,
        assemble(.{ .max_bytes = 64, .max_lines = 1 }, "BATCH +lim draft/multiline #c", &too_many_lines, "BATCH -lim", &out),
    );
}

test "allows blank interior lines but rejects empty and blank-only batches" {
    var out: [64]u8 = undefined;

    const blank_interior = [_][]const u8{
        "@batch=blank NOTICE #c :top",
        "@batch=blank NOTICE #c :",
        "@batch=blank NOTICE #c :bottom",
    };
    const msg = try assemble(
        .{ .max_bytes = 64, .max_lines = 4 },
        "BATCH +blank draft/multiline #c",
        &blank_interior,
        "BATCH -blank",
        &out,
    );
    try std.testing.expectEqual(.notice, msg.command);
    try std.testing.expectEqualStrings("top\n\nbottom", msg.value);

    const empty_body = [_][]const u8{};
    try std.testing.expectError(
        error.EmptyBatch,
        assemble(.{ .max_bytes = 64, .max_lines = 4 }, "BATCH +empty draft/multiline #c", &empty_body, "BATCH -empty", &out),
    );

    const blank_only = [_][]const u8{
        "@batch=blank PRIVMSG #c :",
        "@batch=blank PRIVMSG #c :",
    };
    try std.testing.expectError(
        error.BlankMessage,
        assemble(.{ .max_bytes = 64, .max_lines = 4 }, "BATCH +blank draft/multiline #c", &blank_only, "BATCH -blank", &out),
    );
}

test "rejects malformed batches and disallowed inner commands" {
    var out: [128]u8 = undefined;

    const valid_body = [_][]const u8{"@batch=abc PRIVMSG #c :hello"};
    try std.testing.expectError(
        error.InvalidBatchOpen,
        assemble(.{}, "BATCH abc draft/multiline #c", &valid_body, "BATCH -abc", &out),
    );
    try std.testing.expectError(
        error.InvalidBatchType,
        assemble(.{}, "BATCH +abc chathistory #c", &valid_body, "BATCH -abc", &out),
    );
    try std.testing.expectError(
        error.BatchTagMismatch,
        assemble(.{}, "BATCH +abc draft/multiline #c", &valid_body, "BATCH -def", &out),
    );

    const disallowed_command = [_][]const u8{"@batch=abc JOIN #c"};
    try std.testing.expectError(
        error.DisallowedCommand,
        assemble(.{}, "BATCH +abc draft/multiline #c", &disallowed_command, "BATCH -abc", &out),
    );
}

test "rejects invalid tags and targets inside the batch" {
    var out: [128]u8 = undefined;

    const extra_tag = [_][]const u8{"@batch=abc;time=2026-06-02T00:00:00.000Z PRIVMSG #c :hello"};
    try std.testing.expectError(
        error.DisallowedTag,
        assemble(.{}, "BATCH +abc draft/multiline #c", &extra_tag, "BATCH -abc", &out),
    );

    const wrong_target = [_][]const u8{"@batch=abc PRIVMSG #other :hello"};
    try std.testing.expectError(
        error.InvalidTarget,
        assemble(.{}, "BATCH +abc draft/multiline #c", &wrong_target, "BATCH -abc", &out),
    );

    const mixed = [_][]const u8{
        "@batch=abc PRIVMSG #c :hello",
        "@batch=abc NOTICE #c :there",
    };
    try std.testing.expectError(
        error.MixedCommands,
        assemble(.{}, "BATCH +abc draft/multiline #c", &mixed, "BATCH -abc", &out),
    );

    const blank_concat = [_][]const u8{
        "@batch=abc PRIVMSG #c :hello",
        "@batch=abc;draft/multiline-concat PRIVMSG #c :",
    };
    try std.testing.expectError(
        error.BlankConcatLine,
        assemble(.{}, "BATCH +abc draft/multiline #c", &blank_concat, "BATCH -abc", &out),
    );
}
