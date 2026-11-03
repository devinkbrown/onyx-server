// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CTCP codec for IRC PRIVMSG and NOTICE bodies.
//!
//! CTCP frames are embedded in the trailing parameter as SOH-delimited spans:
//! `\x01COMMAND optional-argument\x01`. This module keeps parsing zero-copy and
//! allocation-free; dequoting and builders write into caller-provided buffers.
const std = @import("std");

pub const delimiter: u8 = 0x01;
pub const quote_byte: u8 = 0x10;

/// Conservative command bound for hot-path parsed views.
pub const default_max_command_len: usize = 32;

pub const ParseError = error{
    InvalidMessage,
    UnterminatedCtcp,
    EmptyCtcp,
    InvalidCommand,
    CommandTooLong,
    MalformedQuote,
};

pub const QuoteError = error{
    InvalidByte,
    MalformedQuote,
    OutputTooSmall,
};

pub const BuildError = error{
    InvalidCommand,
    InvalidTarget,
    InvalidByte,
    OutputTooSmall,
};

/// IRC command carrying the CTCP body.
pub const Carrier = enum {
    privmsg,
    notice,
};

/// Known CTCP commands. Unknown commands remain parseable and are preserved raw.
pub const CommandId = enum {
    version,
    ping,
    time,
    action,
    clientinfo,
    source,
    userinfo,
    finger,
    dcc,
    unknown,
};

/// Common DCC subcommands detected from a CTCP DCC argument.
pub const DccKind = enum {
    send,
    chat,
    accept,
    resume_file,
    unknown,
};

pub const ParseConfig = struct {
    max_command_len: usize = default_max_command_len,
    require_entire_message: bool = false,
};

/// Zero-copy parsed CTCP view. Slices point into the caller-owned message body.
pub const CtcpView = struct {
    carrier: Carrier,
    raw: []const u8,
    command: []const u8,
    arg_raw: ?[]const u8 = null,
    id: CommandId,
    dcc: ?DccKind = null,

    pub fn isReply(self: CtcpView) bool {
        return self.carrier == .notice;
    }

    pub fn argOrEmpty(self: CtcpView) []const u8 {
        return self.arg_raw orelse "";
    }

    /// Dequote the CTCP argument into caller storage.
    pub fn dequoteArg(self: CtcpView, out_buf: []u8) QuoteError![]const u8 {
        return dequote(self.argOrEmpty(), out_buf);
    }
};

/// Compile-time configurable parser and iterator.
pub fn Parser(comptime config: ParseConfig) type {
    comptime {
        if (config.max_command_len == 0) @compileError("max_command_len must be nonzero");
    }

    return struct {
        pub const Iterator = struct {
            carrier: Carrier,
            text: []const u8,
            cursor: usize = 0,

            pub fn next(self: *Iterator) ParseError!?CtcpView {
                validateMessageText(self.text) catch |err| return err;

                const start = findByte(self.text, self.cursor, delimiter) orelse {
                    self.cursor = self.text.len;
                    return null;
                };
                const end = findByte(self.text, start + 1, delimiter) orelse return error.UnterminatedCtcp;

                if (config.require_entire_message and (start != 0 or end + 1 != self.text.len)) {
                    return error.InvalidMessage;
                }

                self.cursor = end + 1;
                return try parseBody(self.carrier, self.text[start .. end + 1], self.text[start + 1 .. end]);
            }
        };

        pub fn iterator(carrier: Carrier, text: []const u8) Iterator {
            return .{ .carrier = carrier, .text = text };
        }

        pub fn parseFirst(carrier: Carrier, text: []const u8) ParseError!?CtcpView {
            var it = @This().iterator(carrier, text);
            return it.next();
        }

        fn parseBody(carrier: Carrier, raw: []const u8, body: []const u8) ParseError!CtcpView {
            if (body.len == 0) return error.EmptyCtcp;

            const command_end = findSpace(body, 0) orelse body.len;
            const command = body[0..command_end];
            if (command.len == 0) return error.InvalidCommand;
            if (command.len > config.max_command_len) return error.CommandTooLong;
            if (!validCommand(command)) return error.InvalidCommand;

            var arg_raw: ?[]const u8 = null;
            if (command_end < body.len) {
                const arg_start = skipSpaces(body, command_end);
                if (arg_start < body.len) {
                    arg_raw = body[arg_start..];
                    try validateQuoted(arg_raw.?);
                }
            }

            const id = classifyCommand(command);
            return .{
                .carrier = carrier,
                .raw = raw,
                .command = command,
                .arg_raw = arg_raw,
                .id = id,
                .dcc = if (id == .dcc) classifyDcc(arg_raw) else null,
            };
        }
    };
}

/// Return true when the text contains a CTCP delimiter byte.
pub fn hasCtcp(text: []const u8) bool {
    return findByte(text, 0, delimiter) != null;
}

/// Iterate over CTCP spans in a PRIVMSG/NOTICE trailing parameter.
pub fn iterator(carrier: Carrier, text: []const u8) Parser(.{}).Iterator {
    return Parser(.{}).iterator(carrier, text);
}

/// Parse the first CTCP span. Ordinary non-CTCP text returns null.
pub fn parseFirst(carrier: Carrier, text: []const u8) ParseError!?CtcpView {
    return Parser(.{}).parseFirst(carrier, text);
}

/// Write CTCP low-level quoted bytes into caller storage.
///
/// The CTCP delimiter itself has no low-level quote form, so it is rejected.
pub fn quote(input: []const u8, out_buf: []u8) QuoteError![]const u8 {
    var write: usize = 0;
    for (input) |ch| {
        switch (ch) {
            delimiter => return error.InvalidByte,
            0 => try appendEscaped(&write, out_buf, '0'),
            '\n' => try appendEscaped(&write, out_buf, 'n'),
            '\r' => try appendEscaped(&write, out_buf, 'r'),
            quote_byte => try appendEscaped(&write, out_buf, quote_byte),
            else => {
                if (write >= out_buf.len) return error.OutputTooSmall;
                out_buf[write] = ch;
                write += 1;
            },
        }
    }
    return out_buf[0..write];
}

/// Decode CTCP low-level quoted bytes into caller storage.
pub fn dequote(input: []const u8, out_buf: []u8) QuoteError![]const u8 {
    var read: usize = 0;
    var write: usize = 0;

    while (read < input.len) {
        var ch = input[read];
        read += 1;

        if (ch == quote_byte) {
            if (read >= input.len) return error.MalformedQuote;
            const esc = input[read];
            read += 1;
            ch = switch (esc) {
                '0' => 0,
                'n' => '\n',
                'r' => '\r',
                quote_byte => quote_byte,
                else => return error.MalformedQuote,
            };
        }

        if (write >= out_buf.len) return error.OutputTooSmall;
        out_buf[write] = ch;
        write += 1;
    }

    return out_buf[0..write];
}

/// Build only the SOH-delimited CTCP payload.
pub fn buildPayload(command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    if (!validCommand(command)) return error.InvalidCommand;

    var write: usize = 0;
    try appendByte(&write, out_buf, delimiter);
    try appendSlice(&write, out_buf, command);

    if (arg) |bytes| {
        if (bytes.len != 0) {
            try appendByte(&write, out_buf, ' ');
            const quoted = quote(bytes, out_buf[write..]) catch |err| return switch (err) {
                error.InvalidByte => error.InvalidByte,
                error.OutputTooSmall => error.OutputTooSmall,
                error.MalformedQuote => error.InvalidByte,
            };
            write += quoted.len;
        }
    }

    try appendByte(&write, out_buf, delimiter);
    return out_buf[0..write];
}

/// Build a complete IRC PRIVMSG CTCP request line without CRLF.
pub fn buildRequest(target: []const u8, command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    return buildLine(.privmsg, target, command, arg, out_buf);
}

/// Build a complete IRC NOTICE CTCP reply line without CRLF.
pub fn buildReply(target: []const u8, command: []const u8, arg: ?[]const u8, out_buf: []u8) BuildError![]const u8 {
    return buildLine(.notice, target, command, arg, out_buf);
}

/// Build a complete IRC CTCP carrier line without CRLF.
pub fn buildLine(
    carrier: Carrier,
    target: []const u8,
    command: []const u8,
    arg: ?[]const u8,
    out_buf: []u8,
) BuildError![]const u8 {
    if (!validTarget(target)) return error.InvalidTarget;

    var write: usize = 0;
    try appendSlice(&write, out_buf, carrierName(carrier));
    try appendByte(&write, out_buf, ' ');
    try appendSlice(&write, out_buf, target);
    try appendSlice(&write, out_buf, " :");

    const payload = try buildPayload(command, arg, out_buf[write..]);
    write += payload.len;
    return out_buf[0..write];
}

/// Canonical uppercase spelling for known CTCP commands.
pub fn commandName(id: CommandId) ?[]const u8 {
    return switch (id) {
        .version => "VERSION",
        .ping => "PING",
        .time => "TIME",
        .action => "ACTION",
        .clientinfo => "CLIENTINFO",
        .source => "SOURCE",
        .userinfo => "USERINFO",
        .finger => "FINGER",
        .dcc => "DCC",
        .unknown => null,
    };
}

fn carrierName(carrier: Carrier) []const u8 {
    return switch (carrier) {
        .privmsg => "PRIVMSG",
        .notice => "NOTICE",
    };
}

fn classifyCommand(command: []const u8) CommandId {
    if (asciiEqlIgnoreCase(command, "VERSION")) return .version;
    if (asciiEqlIgnoreCase(command, "PING")) return .ping;
    if (asciiEqlIgnoreCase(command, "TIME")) return .time;
    if (asciiEqlIgnoreCase(command, "ACTION")) return .action;
    if (asciiEqlIgnoreCase(command, "CLIENTINFO")) return .clientinfo;
    if (asciiEqlIgnoreCase(command, "SOURCE")) return .source;
    if (asciiEqlIgnoreCase(command, "USERINFO")) return .userinfo;
    if (asciiEqlIgnoreCase(command, "FINGER")) return .finger;
    if (asciiEqlIgnoreCase(command, "DCC")) return .dcc;
    return .unknown;
}

fn classifyDcc(arg_raw: ?[]const u8) DccKind {
    const arg = arg_raw orelse return .unknown;
    const token_end = findSpace(arg, 0) orelse arg.len;
    const token = arg[0..token_end];
    if (asciiEqlIgnoreCase(token, "SEND")) return .send;
    if (asciiEqlIgnoreCase(token, "CHAT")) return .chat;
    if (asciiEqlIgnoreCase(token, "ACCEPT")) return .accept;
    if (asciiEqlIgnoreCase(token, "RESUME")) return .resume_file;
    return .unknown;
}

fn validateMessageText(text: []const u8) ParseError!void {
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n' => return error.InvalidMessage,
            else => {},
        }
    }
}

fn validateQuoted(input: []const u8) ParseError!void {
    var read: usize = 0;
    while (read < input.len) {
        const ch = input[read];
        read += 1;
        if (ch != quote_byte) continue;

        if (read >= input.len) return error.MalformedQuote;
        const esc = input[read];
        read += 1;
        switch (esc) {
            '0', 'n', 'r', quote_byte => {},
            else => return error.MalformedQuote,
        }
    }
}

fn validCommand(command: []const u8) bool {
    if (command.len == 0) return false;
    for (command) |ch| {
        switch (ch) {
            'A'...'Z', 'a'...'z', '0'...'9', '-' => {},
            else => return false,
        }
    }
    return true;
}

fn validTarget(target: []const u8) bool {
    if (target.len == 0) return false;
    for (target) |ch| {
        switch (ch) {
            0, '\r', '\n', ' ', ':' => return false,
            else => {},
        }
    }
    return true;
}

fn appendEscaped(write: *usize, out_buf: []u8, esc: u8) QuoteError!void {
    if (write.* + 2 > out_buf.len) return error.OutputTooSmall;
    out_buf[write.*] = quote_byte;
    out_buf[write.* + 1] = esc;
    write.* += 2;
}

fn appendByte(write: *usize, out_buf: []u8, byte: u8) BuildError!void {
    if (write.* >= out_buf.len) return error.OutputTooSmall;
    out_buf[write.*] = byte;
    write.* += 1;
}

fn appendSlice(write: *usize, out_buf: []u8, bytes: []const u8) BuildError!void {
    if (write.* + bytes.len > out_buf.len) return error.OutputTooSmall;
    @memcpy(out_buf[write.* .. write.* + bytes.len], bytes);
    write.* += bytes.len;
}

fn skipSpaces(bytes: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < bytes.len and bytes[cursor] == ' ') {
        cursor += 1;
    }
    return cursor;
}

fn findSpace(bytes: []const u8, start: usize) ?usize {
    return findByte(bytes, start, ' ');
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ach, bch| {
        if (asciiUpper(ach) != asciiUpper(bch)) return false;
    }
    return true;
}

fn asciiUpper(ch: u8) u8 {
    return switch (ch) {
        'a'...'z' => ch - ('a' - 'A'),
        else => ch,
    };
}

/// Errors from the strict DCC offer parser. Shape only: whether an address,
/// port, or token is *trusted* is server policy, deliberately not modeled here.
pub const DccError = error{
    InvalidDcc,
    UnknownDccKind,
    MissingField,
    InvalidFilename,
    InvalidAddress,
    InvalidPort,
    InvalidNumber,
    TrailingGarbage,
};

/// DCC endpoint address in the three wire spellings seen in the wild.
pub const DccAddress = union(enum) {
    /// Dotted-quad IPv4, normalized to octets.
    ipv4: [4]u8,
    /// Legacy single-integer IPv4 (host-order u32 as sent by old clients).
    ipv4_u32: u32,
    /// IPv6 literal text (brackets stripped), borrowed from the input.
    ipv6: []const u8,
    /// Hostname token (some clients send one instead of a literal), borrowed.
    host: []const u8,
};

/// Zero-copy parsed DCC offer. All slices borrow the CTCP argument.
///
/// Grammar (de-facto DCC):
///   SEND   <filename> <addr> <port> [<size> [<token>]]
///   CHAT   chat <addr> <port> [<token>]
///   ACCEPT <filename> <port> <position> [<token>]
///   RESUME <filename> <port> <position> [<token>]
/// A filename containing spaces is double-quoted. Port 0 with a token is the
/// passive (reverse) form; a token on ACCEPT/RESUME marks the passive pair.
pub const DccOffer = struct {
    kind: DccKind,
    filename: ?[]const u8 = null,
    filename_quoted: bool = false,
    address: ?DccAddress = null,
    port: u16,
    file_size: ?u64 = null,
    position: ?u64 = null,
    token: ?[]const u8 = null,
    passive: bool = false,
};

const DccTokens = struct {
    text: []const u8,
    cursor: usize = 0,

    fn next(self: *DccTokens) ?[]const u8 {
        self.cursor = skipSpaces(self.text, self.cursor);
        if (self.cursor >= self.text.len) return null;
        const start = self.cursor;
        const end = findSpace(self.text, start) orelse self.text.len;
        self.cursor = end;
        return self.text[start..end];
    }

    fn required(self: *DccTokens) DccError![]const u8 {
        return self.next() orelse error.MissingField;
    }

    fn finish(self: *DccTokens) DccError!void {
        if (self.next() != null) return error.TrailingGarbage;
    }

    fn filename(self: *DccTokens, quoted: *bool) DccError![]const u8 {
        self.cursor = skipSpaces(self.text, self.cursor);
        if (self.cursor >= self.text.len) return error.MissingField;
        if (self.text[self.cursor] == '"') {
            const start = self.cursor + 1;
            const end = findByte(self.text, start, '"') orelse return error.InvalidFilename;
            if (end == start) return error.InvalidFilename;
            if (end + 1 < self.text.len and self.text[end + 1] != ' ') return error.InvalidFilename;
            self.cursor = end + 1;
            quoted.* = true;
            const name = self.text[start..end];
            try validateDccText(name, error.InvalidFilename);
            return name;
        }
        const name = try self.required();
        if (findByte(name, 0, '"') != null) return error.InvalidFilename;
        try validateDccText(name, error.InvalidFilename);
        return name;
    }
};

fn validateDccText(text: []const u8, err: DccError) DccError!void {
    if (text.len == 0) return err;
    for (text) |ch| {
        switch (ch) {
            0, '\r', '\n', delimiter, quote_byte => return err,
            else => {},
        }
    }
}

fn parseDccNumber(token: []const u8, comptime T: type) DccError!T {
    if (token.len == 0) return error.InvalidNumber;
    var value: T = 0;
    for (token) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidNumber;
        const digit: T = @intCast(ch - '0');
        value = std.math.mul(T, value, 10) catch return error.InvalidNumber;
        value = std.math.add(T, value, digit) catch return error.InvalidNumber;
    }
    return value;
}

fn parseDccPort(token: []const u8) DccError!u16 {
    const value = parseDccNumber(token, u32) catch return error.InvalidPort;
    if (value > std.math.maxInt(u16)) return error.InvalidPort;
    return @intCast(value);
}

fn parseDccAddress(token_raw: []const u8) DccError!DccAddress {
    var token = token_raw;
    var bracketed = false;
    if (token.len >= 2 and token[0] == '[' and token[token.len - 1] == ']') {
        token = token[1 .. token.len - 1];
        bracketed = true;
    } else if (findByte(token, 0, '[') != null or findByte(token, 0, ']') != null) {
        return error.InvalidAddress;
    }
    if (token.len == 0) return error.InvalidAddress;

    if (findByte(token, 0, ':') != null) {
        // IPv6 literal: hex groups, colons, and an optional embedded IPv4 tail.
        var colons: usize = 0;
        for (token) |ch| {
            switch (ch) {
                ':' => colons += 1,
                '0'...'9', 'a'...'f', 'A'...'F', '.' => {},
                else => return error.InvalidAddress,
            }
        }
        if (colons < 1) return error.InvalidAddress;
        return .{ .ipv6 = token };
    }
    if (bracketed) return error.InvalidAddress;

    if (findByte(token, 0, '.') != null) {
        // All digit/dot tokens must be strict dotted quads, never hostnames.
        var digits_dots = true;
        for (token) |ch| {
            if ((ch < '0' or ch > '9') and ch != '.') digits_dots = false;
        }
        if (digits_dots) {
            var octets: [4]u8 = undefined;
            var labels: usize = 0;
            var start: usize = 0;
            while (true) {
                const end = findByte(token, start, '.') orelse token.len;
                const label = token[start..end];
                if (label.len == 0 or label.len > 3 or labels >= 4) return error.InvalidAddress;
                const value = parseDccNumber(label, u32) catch return error.InvalidAddress;
                if (value > 255) return error.InvalidAddress;
                octets[labels] = @intCast(value);
                labels += 1;
                if (end == token.len) break;
                start = end + 1;
            }
            if (labels != 4) return error.InvalidAddress;
            return .{ .ipv4 = octets };
        }
        // Dotted quad when every label is numeric; otherwise a hostname.
        var octets: [4]u8 = undefined;
        var labels: usize = 0;
        var start: usize = 0;
        var numeric = true;
        while (true) {
            const end = findByte(token, start, '.') orelse token.len;
            const label = token[start..end];
            if (label.len == 0 or label.len > 3) {
                numeric = false;
            } else {
                const value = parseDccNumber(label, u32) catch {
                    numeric = false;
                    break;
                };
                if (labels < 4) {
                    if (value > 255) return error.InvalidAddress;
                    octets[labels] = @intCast(value);
                }
            }
            labels += 1;
            if (end == token.len) break;
            start = end + 1;
        }
        if (numeric) {
            if (labels != 4) return error.InvalidAddress;
            return .{ .ipv4 = octets };
        }
        try validateDccHost(token);
        return .{ .host = token };
    }

    // Bare integer is the legacy u32 IPv4 spelling; anything else is a host.
    if (parseDccNumber(token, u32)) |value| {
        return .{ .ipv4_u32 = value };
    } else |_| {}
    try validateDccHost(token);
    return .{ .host = token };
}

fn validateDccHost(token: []const u8) DccError!void {
    try validateDccText(token, error.InvalidAddress);
    for (token) |ch| {
        switch (ch) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_' => {},
            else => return error.InvalidAddress,
        }
    }
}

fn validDccToken(token: []const u8) DccError!void {
    try validateDccText(token, error.InvalidDcc);
    if (findByte(token, 0, '"') != null) return error.InvalidDcc;
}

/// Parse the argument of a CTCP DCC request (the text after `DCC `).
/// Strict and allocation-free; unknown subcommands return `UnknownDccKind`
/// so callers can still relay them opaquely under their own policy.
pub fn parseDcc(arg: []const u8) DccError!DccOffer {
    var tokens = DccTokens{ .text = arg };
    const kind_token = try tokens.required();
    const kind = classifyDcc(arg);
    _ = kind_token;

    switch (kind) {
        .send => {
            var quoted = false;
            const filename = try tokens.filename(&quoted);
            const address = try parseDccAddress(try tokens.required());
            const port = try parseDccPort(try tokens.required());
            var offer = DccOffer{
                .kind = .send,
                .filename = filename,
                .filename_quoted = quoted,
                .address = address,
                .port = port,
            };
            if (tokens.next()) |size_token| {
                offer.file_size = try parseDccNumber(size_token, u64);
                if (tokens.next()) |token| {
                    try validDccToken(token);
                    offer.token = token;
                }
            }
            try tokens.finish();
            if (port == 0) {
                // Passive SEND must carry the token the acceptor echoes back.
                if (offer.token == null) return error.MissingField;
                offer.passive = true;
            }
            return offer;
        },
        .chat => {
            const protocol = try tokens.required();
            if (!asciiEqlIgnoreCase(protocol, "chat")) return error.InvalidDcc;
            const address = try parseDccAddress(try tokens.required());
            const port = try parseDccPort(try tokens.required());
            var offer = DccOffer{ .kind = .chat, .address = address, .port = port };
            if (tokens.next()) |token| {
                try validDccToken(token);
                offer.token = token;
            }
            try tokens.finish();
            if (port == 0) {
                if (offer.token == null) return error.MissingField;
                offer.passive = true;
            }
            return offer;
        },
        .accept, .resume_file => {
            var quoted = false;
            const filename = try tokens.filename(&quoted);
            const port = try parseDccPort(try tokens.required());
            const position = try parseDccNumber(try tokens.required(), u64);
            var offer = DccOffer{
                .kind = kind,
                .filename = filename,
                .filename_quoted = quoted,
                .port = port,
                .position = position,
            };
            if (tokens.next()) |token| {
                try validDccToken(token);
                offer.token = token;
                offer.passive = true;
            }
            try tokens.finish();
            return offer;
        },
        .unknown => return error.UnknownDccKind,
    }
}

/// Parse a DCC offer directly from a parsed CTCP view.
pub fn parseDccView(view: CtcpView) DccError!DccOffer {
    if (view.id != .dcc) return error.InvalidDcc;
    return parseDcc(view.argOrEmpty());
}

test "parses ACTION from PRIVMSG body" {
    const view = (try parseFirst(.privmsg, "\x01ACTION waves hello\x01")).?;
    try std.testing.expectEqual(Carrier.privmsg, view.carrier);
    try std.testing.expect(!view.isReply());
    try std.testing.expectEqual(CommandId.action, view.id);
    try std.testing.expectEqualStrings("\x01ACTION waves hello\x01", view.raw);
    try std.testing.expectEqualStrings("ACTION", view.command);
    try std.testing.expectEqualStrings("waves hello", view.argOrEmpty());
}

test "parses embedded spans and keeps ACTIONGRAB distinct from ACTION" {
    const embedded = (try parseFirst(.privmsg, "hi \x01VERSION\x01 there")).?;
    try std.testing.expectEqual(CommandId.version, embedded.id);
    try std.testing.expectEqualStrings("\x01VERSION\x01", embedded.raw);

    const actiongrab = (try parseFirst(.privmsg, "\x01ACTIONGRAB x\x01")).?;
    try std.testing.expectEqual(CommandId.unknown, actiongrab.id);
    try std.testing.expectEqualStrings("ACTIONGRAB", actiongrab.command);
}

test "parses VERSION reply from NOTICE body" {
    const view = (try parseFirst(.notice, "prefix \x01VERSION onyx-server-0.1\x01 suffix")).?;
    try std.testing.expect(view.isReply());
    try std.testing.expectEqual(CommandId.version, view.id);
    try std.testing.expectEqualStrings("VERSION", view.command);
    try std.testing.expectEqualStrings("onyx-server-0.1", view.argOrEmpty());
}

test "parses and dequotes PING argument" {
    const view = (try parseFirst(.privmsg, "\x01PING token\x10n42\x01")).?;
    try std.testing.expectEqual(CommandId.ping, view.id);

    var out: [32]u8 = undefined;
    const arg = try view.dequoteArg(&out);
    try std.testing.expectEqualStrings("token\n42", arg);
}

test "detects DCC subcommands" {
    const view = (try parseFirst(.privmsg, "\x01DCC SEND file.txt 1 2 3\x01")).?;
    try std.testing.expectEqual(CommandId.dcc, view.id);
    try std.testing.expectEqual(@as(?DccKind, .send), view.dcc);
}

test "builds CTCP request and reply lines" {
    var request_buf: [128]u8 = undefined;
    const request = try buildRequest("nick", "PING", "12345", &request_buf);
    try std.testing.expectEqualStrings("PRIVMSG nick :\x01PING 12345\x01", request);

    var reply_buf: [128]u8 = undefined;
    const reply = try buildReply("nick", "VERSION", "onyx-server-0.1", &reply_buf);
    try std.testing.expectEqualStrings("NOTICE nick :\x01VERSION onyx-server-0.1\x01", reply);
}

test "low-level quoting round trip" {
    const input = [_]u8{ 'a', 0, 'b', '\n', 'c', '\r', 'd', quote_byte, 'e' };

    var quoted_buf: [32]u8 = undefined;
    const quoted = try quote(&input, &quoted_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        'a', quote_byte, '0', 'b', quote_byte, 'n', 'c', quote_byte, 'r', 'd', quote_byte, quote_byte, 'e',
    }, quoted);

    var dequoted_buf: [16]u8 = undefined;
    const dequoted = try dequote(quoted, &dequoted_buf);
    try std.testing.expectEqualSlices(u8, &input, dequoted);
}

test "rejects malformed and empty CTCP" {
    try std.testing.expectEqual(@as(?CtcpView, null), try parseFirst(.privmsg, "plain text"));
    try std.testing.expectError(error.EmptyCtcp, parseFirst(.privmsg, "\x01\x01"));
    try std.testing.expectError(error.UnterminatedCtcp, parseFirst(.privmsg, "\x01VERSION"));
    try std.testing.expectError(error.InvalidCommand, parseFirst(.privmsg, "\x01 ACTION\x01"));
    try std.testing.expectError(error.MalformedQuote, parseFirst(.privmsg, "\x01PING \x10x\x01"));
    try std.testing.expectError(error.InvalidMessage, parseFirst(.privmsg, "\x01PING raw\nline\x01"));
}

test "builders reject invalid bytes and small buffers" {
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildPayload("PING", "12345", &tiny));

    var buf: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidByte, buildPayload("PING", "\x01", &buf));
    try std.testing.expectError(error.InvalidCommand, buildPayload("BAD CMD", null, &buf));
    try std.testing.expectError(error.InvalidTarget, buildRequest("bad target", "PING", null, &buf));
}

test "DCC SEND parses legacy u32, dotted, quoted, and passive forms" {
    const legacy = try parseDcc("SEND file.txt 3232235777 1024 4096");
    try std.testing.expectEqual(DccKind.send, legacy.kind);
    try std.testing.expectEqualStrings("file.txt", legacy.filename.?);
    try std.testing.expectEqual(@as(u32, 3232235777), legacy.address.?.ipv4_u32);
    try std.testing.expectEqual(@as(u16, 1024), legacy.port);
    try std.testing.expectEqual(@as(?u64, 4096), legacy.file_size);
    try std.testing.expect(!legacy.passive);

    const quoted = try parseDcc("SEND \"my file.txt\" 192.168.0.1 5000 12");
    try std.testing.expectEqualStrings("my file.txt", quoted.filename.?);
    try std.testing.expect(quoted.filename_quoted);
    try std.testing.expectEqual([4]u8{ 192, 168, 0, 1 }, quoted.address.?.ipv4);

    const passive = try parseDcc("SEND file.txt 10.0.0.1 0 99 12345");
    try std.testing.expect(passive.passive);
    try std.testing.expectEqualStrings("12345", passive.token.?);
    try std.testing.expectError(error.MissingField, parseDcc("SEND file.txt 10.0.0.1 0 99"));
}

test "DCC CHAT, ACCEPT, RESUME, IPv6, and hostname forms parse" {
    const chat = try parseDcc("CHAT chat [2001:db8::1] 4096");
    try std.testing.expectEqual(DccKind.chat, chat.kind);
    try std.testing.expectEqualStrings("2001:db8::1", chat.address.?.ipv6);

    const chat6 = try parseDcc("CHAT chat 2001:db8::2 0 tok9");
    try std.testing.expect(chat6.passive);
    try std.testing.expectEqualStrings("tok9", chat6.token.?);

    const host = try parseDcc("SEND f dcc.example.org 1024");
    try std.testing.expectEqualStrings("dcc.example.org", host.address.?.host);

    const accept = try parseDcc("ACCEPT file.txt 1024 2048");
    try std.testing.expectEqual(DccKind.accept, accept.kind);
    try std.testing.expectEqual(@as(?u64, 2048), accept.position);
    try std.testing.expect(!accept.passive);

    const resume_passive = try parseDcc("RESUME \"a b.bin\" 0 7 token42");
    try std.testing.expectEqual(DccKind.resume_file, resume_passive.kind);
    try std.testing.expect(resume_passive.passive);
    try std.testing.expectEqualStrings("token42", resume_passive.token.?);
}

test "DCC parser rejects malformed offers fail-closed" {
    try std.testing.expectError(error.UnknownDccKind, parseDcc("GET f 1.2.3.4 1"));
    try std.testing.expectError(error.MissingField, parseDcc("SEND f 1.2.3.4"));
    try std.testing.expectError(error.InvalidPort, parseDcc("SEND f 1.2.3.4 65536"));
    try std.testing.expectError(error.InvalidPort, parseDcc("SEND f 1.2.3.4 -1"));
    try std.testing.expectError(error.InvalidNumber, parseDcc("SEND f 1.2.3.4 1 99999999999999999999999"));
    try std.testing.expectError(error.InvalidAddress, parseDcc("SEND f 999.1.1.1 1"));
    try std.testing.expectError(error.InvalidAddress, parseDcc("SEND f 1.2.3 1"));
    try std.testing.expectError(error.InvalidFilename, parseDcc("SEND \"unterminated 1.2.3.4 1"));
    try std.testing.expectError(error.TrailingGarbage, parseDcc("CHAT chat 1.2.3.4 1 tok extra"));
    try std.testing.expectError(error.InvalidDcc, parseDcc("CHAT schat 1.2.3.4 1"));
    try std.testing.expectError(error.InvalidDcc, parseDccView((try parseFirst(.privmsg, "\x01VERSION\x01")).?));

    const view = (try parseFirst(.privmsg, "\x01DCC SEND file.txt 1 2 3\x01")).?;
    const offer = try parseDccView(view);
    try std.testing.expectEqual(DccKind.send, offer.kind);
    try std.testing.expectEqual(@as(u32, 1), offer.address.?.ipv4_u32);
}
