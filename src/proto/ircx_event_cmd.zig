// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCX EVENT command parser and LIST reply builder.
//!
//! This module owns no command state. It parses EVENT requests into typed
//! `event_spine.CategoryMask` values and renders deterministic LIST bytes into
//! caller-provided buffers.
const std = @import("std");
const event_spine = event_spine_facade;

pub const EventCategory = event_spine.EventCategory;
pub const CategoryMask = event_spine.CategoryMask;

pub const ParseError = error{
    NeedMoreParams,
    UnknownCommand,
    InvalidSubcommand,
    UnknownCategory,
};

pub const BuildError = error{
    OutputTooSmall,
};

pub const Operation = enum {
    add,
    change,
    del,
    clear,
    list,
};

pub const Request = struct {
    operation: Operation,
    mask: CategoryMask,

    pub fn apply(self: Request, current: CategoryMask) CategoryMask {
        return applyRequest(current, self);
    }
};

/// Parse a raw `EVENT <ADD|DEL|LIST> [category...]` line.
pub fn parse(line: []const u8) ParseError!Request {
    const body = trimLineEnding(line);
    var it = std.mem.tokenizeScalar(u8, body, ' ');

    const command = it.next() orelse return error.NeedMoreParams;
    if (!std.ascii.eqlIgnoreCase(command, "EVENT")) return error.UnknownCommand;

    const subcommand = it.next() orelse return error.NeedMoreParams;
    const operation = try parseOperation(subcommand);

    var mask = CategoryMask.empty();
    while (it.next()) |token| {
        mask.add(try lookupCategory(token));
    }

    return .{ .operation = operation, .mask = mask };
}

/// Parse EVENT parameters excluding the command name.
pub fn parseParams(params: []const []const u8) ParseError!Request {
    if (params.len == 0) return error.NeedMoreParams;
    const operation = try parseOperation(params[0]);

    var mask = CategoryMask.empty();
    for (params[1..]) |token| {
        mask.add(try lookupCategory(token));
    }

    return .{ .operation = operation, .mask = mask };
}

pub fn parseOperation(token: []const u8) ParseError!Operation {
    if (std.ascii.eqlIgnoreCase(token, "ADD")) return .add;
    if (std.ascii.eqlIgnoreCase(token, "CHANGE")) return .change;
    if (std.ascii.eqlIgnoreCase(token, "DEL") or std.ascii.eqlIgnoreCase(token, "DELETE")) return .del;
    if (std.ascii.eqlIgnoreCase(token, "CLEAR")) return .clear;
    if (std.ascii.eqlIgnoreCase(token, "LIST") or std.ascii.eqlIgnoreCase(token, "STATUS")) return .list;
    return error.InvalidSubcommand;
}

/// Resolve category tokens using `EventCategory.code()`, `.token()`, and the
/// IRCX draft compatibility aliases.
pub fn lookupCategory(token: []const u8) ParseError!EventCategory {
    inline for (@typeInfo(EventCategory).@"enum".field_names) |field_name| {
        const category: EventCategory = @field(EventCategory, field_name);
        if (std.ascii.eqlIgnoreCase(token, category.code()) or
            std.ascii.eqlIgnoreCase(token, category.token()))
        {
            return category;
        }
    }
    return draftAlias(token) orelse error.UnknownCategory;
}

/// Map the six IRCX draft EVENT types (CHANNEL, MEMBER, SERVER, CONNECTION,
/// SOCKET, USER) onto Onyx Server's richer Event-Spine taxonomy so draft clients keep
/// working. Onyx Server intentionally diverges from the flat draft set (Event-Spine
/// path B in docs/planning/14-ircx-remainder.md); these aliases are the bridge.
pub fn draftAlias(token: []const u8) ?EventCategory {
    if (std.ascii.eqlIgnoreCase(token, "CHANNEL")) return .announce;
    if (std.ascii.eqlIgnoreCase(token, "MEMBER")) return .oper_action;
    if (std.ascii.eqlIgnoreCase(token, "SERVER")) return .server_link;
    if (std.ascii.eqlIgnoreCase(token, "CONNECTION")) return .connect;
    if (std.ascii.eqlIgnoreCase(token, "SOCKET")) return .disconnect;
    if (std.ascii.eqlIgnoreCase(token, "USER")) return .service;
    return null;
}

/// Apply an ADD/DEL request to an existing mask. LIST leaves the mask unchanged.
pub fn applyRequest(current: CategoryMask, request: Request) CategoryMask {
    return switch (request.operation) {
        .add => current.include(request.mask),
        .change => request.mask,
        .del => current.exclude(request.mask),
        .clear => CategoryMask.empty(),
        .list => current,
    };
}

pub const ListReplyBuilder = struct {
    writer: BufferWriter,

    pub fn init(out: []u8) ListReplyBuilder {
        return .{ .writer = BufferWriter.init(out) };
    }

    pub fn slice(self: *const ListReplyBuilder) []const u8 {
        return self.writer.slice();
    }

    /// Write one `EVENT LIST <CATEGORY>` line for each mask bit, then an end line.
    pub fn write(self: *ListReplyBuilder, mask: CategoryMask) BuildError![]const u8 {
        inline for (@typeInfo(EventCategory).@"enum".field_names) |field_name| {
            const category: EventCategory = @field(EventCategory, field_name);
            if (mask.contains(category)) {
                try self.writer.append("EVENT LIST ");
                try self.writer.append(category.code());
                try self.writer.crlf();
            }
        }
        try self.writer.append("EVENT LIST :End of event list");
        try self.writer.crlf();
        return self.slice();
    }
};

pub fn buildListReply(out: []u8, mask: CategoryMask) BuildError![]const u8 {
    var builder = ListReplyBuilder.init(out);
    return builder.write(mask);
}

fn trimLineEnding(line: []const u8) []const u8 {
    if (std.mem.endsWith(u8, line, "\r\n")) return line[0 .. line.len - 2];
    if (line.len != 0 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n')) {
        return line[0 .. line.len - 1];
    }
    return line;
}

const BufferWriter = struct {
    out: []u8,
    len: usize = 0,

    fn init(out: []u8) BufferWriter {
        return .{ .out = out };
    }

    fn slice(self: *const BufferWriter) []const u8 {
        return self.out[0..self.len];
    }

    fn append(self: *BufferWriter, bytes: []const u8) BuildError!void {
        if (self.len > self.out.len or bytes.len > self.out.len - self.len) return error.OutputTooSmall;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn crlf(self: *BufferWriter) BuildError!void {
        try self.append("\r\n");
    }
};

const event_spine_facade = struct {
    pub const Category = enum(u6) {
        connect,
        disconnect,
        server_link,
        flood,
        @"error",
        announce,
        oper_action,
        kill,
        spam,
        debug,
        policy,
        service,
        security,

        pub fn token(self: Category) []const u8 {
            return @tagName(self);
        }

        pub fn code(self: Category) []const u8 {
            return switch (self) {
                .connect => "CONNECT",
                .disconnect => "DISCONNECT",
                .server_link => "SERVER_LINK",
                .flood => "FLOOD",
                .@"error" => "ERROR",
                .announce => "ANNOUNCE",
                .oper_action => "OPER_ACTION",
                .kill => "KILL",
                .spam => "SPAM",
                .debug => "DEBUG",
                .policy => "POLICY",
                .service => "SERVICE",
                .security => "SECURITY",
            };
        }
    };

    pub const EventCategory = Category;

    pub const Mask = struct {
        bits: u64 = 0,

        pub fn empty() Mask {
            return .{};
        }

        pub fn only(category: Category) Mask {
            return .{ .bits = bit(category) };
        }

        pub fn fromCategories(categories: []const Category) Mask {
            var out = Mask.empty();
            for (categories) |category| out.add(category);
            return out;
        }

        pub fn add(self: *Mask, category: Category) void {
            self.bits |= bit(category);
        }

        pub fn include(self: Mask, other: Mask) Mask {
            return .{ .bits = self.bits | other.bits };
        }

        pub fn exclude(self: Mask, other: Mask) Mask {
            return .{ .bits = self.bits & ~other.bits };
        }

        pub fn contains(self: Mask, category: Category) bool {
            return (self.bits & bit(category)) != 0;
        }

        pub fn isEmpty(self: Mask) bool {
            return self.bits == 0;
        }

        fn bit(category: Category) u64 {
            return @as(u64, 1) << @backingInt(category);
        }
    };

    pub const CategoryMask = Mask;
};

test "parse ADD maps category code and token to mask" {
    const request = try parse("EVENT ADD CONNECT server_link error\r\n");

    try std.testing.expectEqual(Operation.add, request.operation);
    try std.testing.expect(request.mask.contains(.connect));
    try std.testing.expect(request.mask.contains(.server_link));
    try std.testing.expect(request.mask.contains(.@"error"));
    try std.testing.expect(!request.mask.contains(.debug));
}

test "parse DEL maps categories and applies removal" {
    const request = try parse("EVENT DEL FLOOD debug");
    const current = CategoryMask.fromCategories(&.{ .connect, .flood, .debug });
    const next = request.apply(current);

    try std.testing.expectEqual(Operation.del, request.operation);
    try std.testing.expect(next.contains(.connect));
    try std.testing.expect(!next.contains(.flood));
    try std.testing.expect(!next.contains(.debug));
}

test "parse LIST accepts optional category filter" {
    const all = try parse("EVENT LIST");
    try std.testing.expectEqual(Operation.list, all.operation);
    try std.testing.expect(all.mask.isEmpty());

    const filtered = try parseParams(&.{ "LIST", "SECURITY", "oper_action" });
    try std.testing.expectEqual(Operation.list, filtered.operation);
    try std.testing.expect(filtered.mask.contains(.security));
    try std.testing.expect(filtered.mask.contains(.oper_action));
}

test "draft EVENT category aliases map onto the Event-Spine taxonomy" {
    const channel = try parse("EVENT ADD CHANNEL MEMBER SERVER");
    try std.testing.expect(channel.mask.contains(.announce));
    try std.testing.expect(channel.mask.contains(.oper_action));
    try std.testing.expect(channel.mask.contains(.server_link));

    const transport = try parseParams(&.{ "ADD", "CONNECTION", "SOCKET", "USER" });
    try std.testing.expect(transport.mask.contains(.connect));
    try std.testing.expect(transport.mask.contains(.disconnect));
    try std.testing.expect(transport.mask.contains(.service));

    // Aliases are case-insensitive like the native tokens.
    try std.testing.expectEqual(EventCategory.connect, try lookupCategory("connection"));
}

test "unknown category handling" {
    try std.testing.expectError(error.UnknownCategory, parse("EVENT ADD NOT_A_CATEGORY"));
    try std.testing.expectError(error.InvalidSubcommand, parse("EVENT SHOW"));
    try std.testing.expectError(error.UnknownCommand, parse("PRIVMSG ADD CONNECT"));
    try std.testing.expectError(error.NeedMoreParams, parse("EVENT"));
}

test "list reply bytes" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 256);
    defer allocator.free(out);

    const mask = CategoryMask.fromCategories(&.{ .connect, .@"error", .security });
    const reply = try buildListReply(out, mask);

    try std.testing.expectEqualStrings(
        "EVENT LIST CONNECT\r\n" ++
            "EVENT LIST ERROR\r\n" ++
            "EVENT LIST SECURITY\r\n" ++
            "EVENT LIST :End of event list\r\n",
        reply,
    );
}

test "list reply reports output too small" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildListReply(&out, CategoryMask.only(.connect)));
}
