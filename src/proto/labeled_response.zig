// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 labeled-response framing helpers.
//!
//! Callers pass already-rendered IRC response lines and a caller-owned sink.
//! This module performs no allocation in the framing path and keeps all scratch
//! storage bounded.
const std = @import("std");

pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_BATCH_REF_LEN: usize = 64;
pub const MAX_LINE_BODY: usize = 8191;
pub const MAX_ESCAPED_LABEL_LEN: usize = MAX_LABEL_LEN * 2;
pub const MAX_WIRE_LINE: usize = 1 + "label=".len + MAX_ESCAPED_LABEL_LEN + 1 + MAX_LINE_BODY + 2;

pub const LabeledError = error{
    DuplicateTag,
    InvalidBatchRef,
    InvalidLabel,
    InvalidLine,
    OutputTooSmall,
};

/// Prefix `@label=<id>` onto one response line.
///
/// When `label` is null, this is a byte-for-byte passthrough into `out`.
/// Tagged output is normalized to a CRLF-terminated wire line.
pub fn tagLine(label: ?[]const u8, line: []const u8, out: []u8) LabeledError![]const u8 {
    const id = label orelse {
        if (line.len > out.len) return error.OutputTooSmall;
        @memcpy(out[0..line.len], line);
        return out[0..line.len];
    };

    const body = try validateOutboundLine(line, "label");
    var writer = SliceWriter{ .buf = out };
    try writer.append("@label=");
    try writer.appendEscapedLabel(id);
    try appendTaggedBody(&writer, body);
    return writer.finishCrlf();
}

/// Build the labeled ACK used for commands that otherwise emit no response.
pub fn buildAck(label: []const u8, out: []u8) LabeledError![]const u8 {
    var writer = SliceWriter{ .buf = out };
    try writer.append("@label=");
    try writer.appendEscapedLabel(label);
    try writer.append(" ACK\r\n");
    return out[0..writer.len];
}

/// Emit labeled-response framing for a slice of complete response lines.
pub fn emitSlice(
    sink: anytype,
    label: ?[]const u8,
    batch_ref: []const u8,
    lines: []const []const u8,
) anyerror!void {
    var iterator = SliceIterator{ .lines = lines };
    try emitIterator(sink, label, batch_ref, &iterator);
}

/// Emit labeled-response framing from an iterator with `next() ?[]const u8`.
///
/// The implementation buffers at most two line slices to choose between ACK,
/// single-line, and batch framing.
pub fn emitIterator(
    sink: anytype,
    label: ?[]const u8,
    batch_ref: []const u8,
    iterator: anytype,
) anyerror!void {
    var it = iterator;
    const first = it.next() orelse {
        if (label) |id| {
            var out: [MAX_WIRE_LINE]u8 = undefined;
            try sink.appendLine(try buildAck(id, &out));
        }
        return;
    };

    const second = it.next() orelse {
        var out: [MAX_WIRE_LINE]u8 = undefined;
        try sink.appendLine(try tagLine(label, first, &out));
        return;
    };

    const id = label orelse {
        try sink.appendLine(first);
        try sink.appendLine(second);
        while (it.next()) |line| try sink.appendLine(line);
        return;
    };

    try validateBatchRef(batch_ref);

    var out: [MAX_WIRE_LINE]u8 = undefined;
    try sink.appendLine(try writeBatchOpen(id, batch_ref, &out));
    try sink.appendLine(try batchTagLine(batch_ref, first, &out));
    try sink.appendLine(try batchTagLine(batch_ref, second, &out));
    while (it.next()) |line| {
        try sink.appendLine(try batchTagLine(batch_ref, line, &out));
    }
    try sink.appendLine(try writeBatchClose(batch_ref, &out));
}

const SliceIterator = struct {
    lines: []const []const u8,
    index: usize = 0,

    fn next(self: *SliceIterator) ?[]const u8 {
        if (self.index >= self.lines.len) return null;
        defer self.index += 1;
        return self.lines[self.index];
    }
};

fn writeBatchOpen(label: []const u8, batch_ref: []const u8, out: []u8) LabeledError![]const u8 {
    var writer = SliceWriter{ .buf = out };
    try writer.append("@label=");
    try writer.appendEscapedLabel(label);
    try writer.append(" BATCH +");
    try writer.append(batch_ref);
    try writer.append(" labeled-response\r\n");
    return out[0..writer.len];
}

fn writeBatchClose(batch_ref: []const u8, out: []u8) LabeledError![]const u8 {
    var writer = SliceWriter{ .buf = out };
    try writer.append("BATCH -");
    try writer.append(batch_ref);
    try writer.append("\r\n");
    return out[0..writer.len];
}

fn batchTagLine(batch_ref: []const u8, line: []const u8, out: []u8) LabeledError![]const u8 {
    const body = try validateOutboundLine(line, "batch");
    var writer = SliceWriter{ .buf = out };
    try writer.append("@batch=");
    try writer.append(batch_ref);
    try appendTaggedBody(&writer, body);
    return writer.finishCrlf();
}

fn appendTaggedBody(writer: *SliceWriter, body: []const u8) LabeledError!void {
    if (body[0] == '@') {
        try writer.appendByte(';');
        try writer.append(body[1..]);
    } else {
        try writer.appendByte(' ');
        try writer.append(body);
    }
}

fn validateOutboundLine(line: []const u8, duplicate_key: []const u8) LabeledError![]const u8 {
    const body = stripLineEnding(line);
    if (body.len == 0 or body.len > MAX_LINE_BODY) return error.InvalidLine;

    for (body) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidLine,
            else => {},
        }
    }

    if (body[0] == '@') {
        const tag_end = std.mem.indexOfScalar(u8, body, ' ') orelse return error.InvalidLine;
        if (tag_end == 1) return error.InvalidLine;
        if (skipSpaces(body, tag_end) >= body.len) return error.InvalidLine;
        try validateTagsNoDuplicate(body[1..tag_end], duplicate_key);
    }

    return body;
}

fn validateTagsNoDuplicate(tags: []const u8, duplicate_key: []const u8) LabeledError!void {
    var cursor: usize = 0;
    while (cursor < tags.len) {
        const next = std.mem.indexOfScalar(u8, tags[cursor..], ';') orelse tags.len - cursor;
        const item = tags[cursor .. cursor + next];
        if (item.len == 0) return error.InvalidLine;

        const eq = std.mem.indexOfScalar(u8, item, '=') orelse item.len;
        const key = item[0..eq];
        if (!validTagKey(key)) return error.InvalidLine;
        if (std.mem.eql(u8, key, duplicate_key)) return error.DuplicateTag;

        cursor += next;
        if (cursor < tags.len) cursor += 1;
    }
}

fn validateBatchRef(batch_ref: []const u8) LabeledError!void {
    if (batch_ref.len == 0 or batch_ref.len > MAX_BATCH_REF_LEN) return error.InvalidBatchRef;
    for (batch_ref) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return error.InvalidBatchRef,
        }
    }
}

fn validateLabel(label: []const u8) LabeledError!void {
    if (label.len == 0 or label.len > MAX_LABEL_LEN) return error.InvalidLabel;
    for (label) |ch| {
        if (ch == 0) return error.InvalidLabel;
    }
}

fn validTagKey(key: []const u8) bool {
    if (key.len == 0) return false;
    const start: usize = if (key[0] == '+') 1 else 0;
    if (start == key.len) return false;
    for (key[start..]) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '/', '_' => {},
            else => return false,
        }
    }
    return true;
}

fn stripLineEnding(input: []const u8) []const u8 {
    if (input.len >= 2 and input[input.len - 2] == '\r' and input[input.len - 1] == '\n') {
        return input[0 .. input.len - 2];
    }
    if (input.len >= 1 and (input[input.len - 1] == '\r' or input[input.len - 1] == '\n')) {
        return input[0 .. input.len - 1];
    }
    return input;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) LabeledError!void {
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *SliceWriter, byte: u8) LabeledError!void {
        if (self.len >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    fn appendEscapedLabel(self: *SliceWriter, label: []const u8) LabeledError!void {
        try validateLabel(label);
        for (label) |ch| {
            switch (ch) {
                ';' => try self.append("\\:"),
                ' ' => try self.append("\\s"),
                '\r' => try self.append("\\r"),
                '\n' => try self.append("\\n"),
                '\\' => try self.append("\\\\"),
                else => try self.appendByte(ch),
            }
        }
    }

    fn finishCrlf(self: *SliceWriter) LabeledError![]const u8 {
        try self.append("\r\n");
        return self.buf[0..self.len];
    }
};

const AllocSink = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn appendLine(self: *AllocSink, line: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, line);
    }

    fn deinit(self: *AllocSink) void {
        self.bytes.deinit(self.allocator);
    }
};

test "single tagged line exact bytes" {
    var out: [128]u8 = undefined;
    const line = try tagLine("abc123", ":irc.example 401 me nick :No such nick\r\n", &out);
    try std.testing.expectEqualStrings(
        "@label=abc123 :irc.example 401 me nick :No such nick\r\n",
        line,
    );
}

test "multi-line response is wrapped in labeled-response batch" {
    const allocator = std.testing.allocator;
    var sink = AllocSink{ .allocator = allocator };
    defer sink.deinit();

    const lines = [_][]const u8{
        ":irc.example 311 me nick ~ident host * :Name\r\n",
        ":irc.example 318 me nick :End of /WHOIS list.\r\n",
    };
    try emitSlice(&sink, "whois-1", "ref42", &lines);

    try std.testing.expectEqualStrings(
        "@label=whois-1 BATCH +ref42 labeled-response\r\n" ++
            "@batch=ref42 :irc.example 311 me nick ~ident host * :Name\r\n" ++
            "@batch=ref42 :irc.example 318 me nick :End of /WHOIS list.\r\n" ++
            "BATCH -ref42\r\n",
        sink.bytes.items,
    );
}

test "empty labeled response emits ACK" {
    const allocator = std.testing.allocator;
    var sink = AllocSink{ .allocator = allocator };
    defer sink.deinit();

    try emitSlice(&sink, "pong", "unused", &.{});
    try std.testing.expectEqualStrings("@label=pong ACK\r\n", sink.bytes.items);

    var out: [64]u8 = undefined;
    const ack = try buildAck("pong", &out);
    try std.testing.expectEqualStrings("@label=pong ACK\r\n", ack);
}

test "no-label passthrough is exact" {
    const allocator = std.testing.allocator;
    var sink = AllocSink{ .allocator = allocator };
    defer sink.deinit();

    const lines = [_][]const u8{
        ":irc.example NOTICE me :one\r\n",
        "@time=2026-06-04T00:00:00.000Z :irc.example NOTICE me :two\r\n",
    };
    try emitSlice(&sink, null, "unused", &lines);

    try std.testing.expectEqualStrings(
        ":irc.example NOTICE me :one\r\n" ++
            "@time=2026-06-04T00:00:00.000Z :irc.example NOTICE me :two\r\n",
        sink.bytes.items,
    );

    var out: [64]u8 = undefined;
    const passthrough = try tagLine(null, "RAW\nBYTES", &out);
    try std.testing.expectEqualStrings("RAW\nBYTES", passthrough);
}

test "existing message tags are preserved after the label or batch tag" {
    var out: [160]u8 = undefined;
    const line = try tagLine("needs escaping; \\r\n", "@time=2026-06-04T00:00:00.000Z NOTICE me :ok", &out);
    try std.testing.expectEqualStrings(
        "@label=needs\\sescaping\\:\\s\\\\r\\n;time=2026-06-04T00:00:00.000Z NOTICE me :ok\r\n",
        line,
    );
}

test "client-only message tags remain valid when batch-tagged" {
    var out: [192]u8 = undefined;
    const line = try batchTagLine(
        "history",
        "@time=2026-06-04T00:00:00.000Z;+onyx/e2ee=mls :nick!u@h PRIVMSG #room :cipher\r\n",
        &out,
    );
    try std.testing.expectEqualStrings(
        "@batch=history;time=2026-06-04T00:00:00.000Z;+onyx/e2ee=mls :nick!u@h PRIVMSG #room :cipher\r\n",
        line,
    );
}
