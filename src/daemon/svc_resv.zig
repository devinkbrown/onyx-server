// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Channel-name RESV registry for the Onyx Server IRC daemon.
//!
//! This module is intentionally standalone: it imports only `std`, owns all
//! reservation data it stores, and models real server command/numeric surfaces
//! (`RESV`, `UNRESV`, and `437 ERR_UNAVAILRESOURCE`) rather than service
//! pseudo-clients.

const std = @import("std");

/// IRC numeric replies needed by channel-name RESV enforcement.
pub const Numeric = enum(u16) {
    /// Returned when a user attempts to create or use a reserved channel name.
    ERR_UNAVAILRESOURCE = 437,
    /// Useful for command dispatchers that reject RESV from non-oper sessions.
    ERR_NOPRIVILEGES = 481,
    /// Useful for command dispatchers that reject malformed RESV commands.
    ERR_NEEDMOREPARAMS = 461,
};

/// One channel-name reservation.
pub const Reservation = struct {
    /// Channel glob pattern, for example `#help*` or `&staff`.
    pattern: []const u8,
    reason: []const u8,
    set_by: []const u8,
    created_ms: i64,
    /// Absolute epoch millisecond expiry. Zero means permanent.
    expires_ms: i64 = 0,

    /// Return whether this reservation has expired at `now_ms`.
    pub fn isExpired(self: Reservation, now_ms: i64) bool {
        return self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

/// Storage and validation limits for `ChannelResv`.
pub const Params = struct {
    max_resvs: usize = 1024,
    max_pattern: usize = 128,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

/// Errors returned while validating or storing channel RESV entries.
pub const ResvError = error{
    EmptyPattern,
    PatternTooLong,
    PatternIsNotChannel,
    InvalidPattern,
    ReasonTooLong,
    SetterTooLong,
    TooManyReservations,
};

/// Errors returned by RESV/UNRESV command parsers.
pub const ParseError = error{
    UnknownCommand,
    MissingParameter,
    InvalidDuration,
    DurationOverflow,
} || ResvError;

/// Parsed real server command intent. Slices borrow from parser input.
pub const Command = union(enum) {
    add: AddRequest,
    remove: []const u8,
    list,
    sweep,
};

/// Parsed `RESV ADD <pattern> <duration-ms> :<reason>` request.
pub const AddRequest = struct {
    pattern: []const u8,
    reason: []const u8,
    duration_ms: i64,
    expires_ms: i64,
};

/// Owning registry for channel-name RESV entries.
pub const ChannelResv = struct {
    allocator: std.mem.Allocator,
    params: Params,
    reservations: std.ArrayListUnmanaged(Reservation) = .empty,

    /// Initialize an empty registry with the supplied allocator and limits.
    pub fn init(allocator: std.mem.Allocator, params: Params) ChannelResv {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free all owned strings and backing storage.
    pub fn deinit(self: *ChannelResv) void {
        for (self.reservations.items) |*reservation| freeReservation(self.allocator, reservation);
        self.reservations.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add or replace a reservation, duplicating its strings. An existing entry
    /// with the same pattern under ASCII case-folding is replaced in place.
    pub fn add(self: *ChannelResv, reservation: Reservation) (ResvError || std.mem.Allocator.Error)!void {
        try self.validateReservation(reservation);

        const existing = self.indexOf(reservation.pattern);
        if (existing == null and self.reservations.items.len >= self.params.max_resvs) {
            return error.TooManyReservations;
        }

        var owned = try self.clone(reservation);
        errdefer freeReservation(self.allocator, &owned);

        if (existing) |idx| {
            freeReservation(self.allocator, &self.reservations.items[idx]);
            self.reservations.items[idx] = owned;
            return;
        }

        try self.reservations.append(self.allocator, owned);
    }

    /// Convenience helper for applying a parsed ADD request with a dispatcher
    /// supplied setter and creation time.
    pub fn addParsed(
        self: *ChannelResv,
        request: AddRequest,
        set_by: []const u8,
        created_ms: i64,
    ) (ResvError || std.mem.Allocator.Error)!void {
        try self.add(.{
            .pattern = request.pattern,
            .reason = request.reason,
            .set_by = set_by,
            .created_ms = created_ms,
            .expires_ms = request.expires_ms,
        });
    }

    /// Remove a reservation by pattern under ASCII case-folding. Returns true
    /// when an entry was present.
    pub fn remove(self: *ChannelResv, pattern: []const u8) bool {
        const idx = self.indexOf(pattern) orelse return false;
        var removed = self.reservations.orderedRemove(idx);
        freeReservation(self.allocator, &removed);
        return true;
    }

    /// Return whether `channel` matches any active channel-name RESV. Expired
    /// entries are swept as a side effect.
    pub fn isReserved(self: *ChannelResv, channel: []const u8, now_ms: i64) bool {
        return self.match(channel, now_ms) != null;
    }

    /// Return the first active reservation matching `channel`, or null. The
    /// returned pointer is valid until the registry is mutated again.
    pub fn match(self: *ChannelResv, channel: []const u8, now_ms: i64) ?*const Reservation {
        if (!isValidChannelName(channel)) return null;
        _ = self.sweep(now_ms);
        for (self.reservations.items) |*reservation| {
            if (globMatch(reservation.pattern, channel)) return reservation;
        }
        return null;
    }

    /// Copy stored reservations into `out` and return the filled prefix.
    /// Returned entries borrow owned strings from the registry.
    pub fn list(self: *const ChannelResv, out: []Reservation) []Reservation {
        const n = @min(out.len, self.reservations.items.len);
        @memcpy(out[0..n], self.reservations.items[0..n]);
        return out[0..n];
    }

    /// Return the number of stored reservations, including unswept expired ones.
    pub fn count(self: *const ChannelResv) usize {
        return self.reservations.items.len;
    }

    /// Remove every reservation whose expiry is at or before `now_ms`, returning
    /// the number of removed entries.
    pub fn sweep(self: *ChannelResv, now_ms: i64) usize {
        var removed_count: usize = 0;
        var i: usize = 0;
        while (i < self.reservations.items.len) {
            if (self.reservations.items[i].isExpired(now_ms)) {
                var removed = self.reservations.orderedRemove(i);
                freeReservation(self.allocator, &removed);
                removed_count += 1;
            } else {
                i += 1;
            }
        }
        return removed_count;
    }

    fn validateReservation(self: *const ChannelResv, reservation: Reservation) ResvError!void {
        try validateStoredEntry(self.params, reservation);
    }

    fn clone(self: *ChannelResv, reservation: Reservation) std.mem.Allocator.Error!Reservation {
        const pattern = try self.allocator.dupe(u8, reservation.pattern);
        errdefer self.allocator.free(pattern);
        const reason = try self.allocator.dupe(u8, reservation.reason);
        errdefer self.allocator.free(reason);
        const set_by = try self.allocator.dupe(u8, reservation.set_by);
        return .{
            .pattern = pattern,
            .reason = reason,
            .set_by = set_by,
            .created_ms = reservation.created_ms,
            .expires_ms = reservation.expires_ms,
        };
    }

    fn indexOf(self: *const ChannelResv, pattern: []const u8) ?usize {
        for (self.reservations.items, 0..) |reservation, idx| {
            if (eqlFoldSlice(reservation.pattern, pattern)) return idx;
        }
        return null;
    }
};

/// Validate a stored row against the exact limits of its owning registry.
/// Helix uses this before sealing and before allocating a detached replacement.
pub fn validateStoredEntry(params: Params, reservation: Reservation) ResvError!void {
    try validatePatternWithLimit(reservation.pattern, params.max_pattern);
    if (reservation.reason.len > params.max_reason) return error.ReasonTooLong;
    if (reservation.set_by.len > params.max_setter) return error.SetterTooLong;
}

/// Parse a real server command and its parameters. Use `RESV` for add/list/sweep
/// and `UNRESV` for removal. `duration-ms` is converted to absolute expiry with
/// `now_ms`; zero means permanent.
pub fn parseServerCommand(verb: []const u8, params: []const []const u8, now_ms: i64) ParseError!Command {
    if (eqlFoldSlice(verb, "RESV")) return parseResvParams(params, now_ms);
    if (eqlFoldSlice(verb, "UNRESV")) {
        if (params.len < 1) return error.MissingParameter;
        try validatePattern(params[0]);
        return .{ .remove = params[0] };
    }
    return error.UnknownCommand;
}

/// Parse parameters after a `RESV` verb.
///
/// Supported forms:
/// * `RESV ADD <pattern> <duration-ms> :<reason>`
/// * `RESV <pattern> <duration-ms> :<reason>`
/// * `RESV DEL <pattern>`
/// * `RESV LIST`
/// * `RESV SWEEP`
pub fn parseResvParams(params: []const []const u8, now_ms: i64) ParseError!Command {
    if (params.len < 1) return error.MissingParameter;

    if (eqlFoldSlice(params[0], "LIST")) return .list;
    if (eqlFoldSlice(params[0], "SWEEP")) return .sweep;

    if (eqlFoldSlice(params[0], "DEL") or eqlFoldSlice(params[0], "REMOVE")) {
        if (params.len < 2) return error.MissingParameter;
        try validatePattern(params[1]);
        return .{ .remove = params[1] };
    }

    const add_offset: usize = if (eqlFoldSlice(params[0], "ADD")) 1 else 0;
    if (params.len < add_offset + 3) return error.MissingParameter;

    const pattern = params[add_offset];
    const duration_ms = try parseDurationMs(params[add_offset + 1]);
    const expires_ms = try expiryFromDuration(now_ms, duration_ms);
    const reason = params[add_offset + 2];

    try validatePattern(pattern);
    return .{
        .add = .{
            .pattern = pattern,
            .reason = reason,
            .duration_ms = duration_ms,
            .expires_ms = expires_ms,
        },
    };
}

/// Build a real server numeric for attempts to create/use a reserved channel.
/// The reply prefix is the server name, never a pseudo-client.
pub fn buildUnavailableResourceNumeric(
    out: []u8,
    server_name: []const u8,
    nick: []const u8,
    channel: []const u8,
    reason: []const u8,
) error{ InvalidServerName, InvalidNick, InvalidChannel, InvalidReason, OutputTooSmall }![]const u8 {
    if (!isValidToken(server_name)) return error.InvalidServerName;
    if (!isValidToken(nick)) return error.InvalidNick;
    if (!isValidChannelName(channel)) return error.InvalidChannel;
    if (containsLineBreak(reason)) return error.InvalidReason;

    return std.fmt.bufPrint(
        out,
        ":{s} {d} {s} {s} :Channel is reserved: {s}",
        .{ server_name, @intFromEnum(Numeric.ERR_UNAVAILRESOURCE), nick, channel, reason },
    ) catch error.OutputTooSmall;
}

/// Return whether `channel` is a concrete IRC channel name this module may
/// enforce against.
pub fn isValidChannelName(channel: []const u8) bool {
    if (channel.len < 2) return false;
    if (!isChannelPrefix(channel[0])) return false;
    for (channel[1..]) |byte| {
        if (isInvalidChannelByte(byte)) return false;
    }
    return true;
}

/// Validate a channel-name RESV glob pattern with default limits.
pub fn validatePattern(pattern: []const u8) ResvError!void {
    return validatePatternWithLimit(pattern, (Params{}).max_pattern);
}

fn validatePatternWithLimit(pattern: []const u8, max_pattern: usize) ResvError!void {
    if (pattern.len == 0) return error.EmptyPattern;
    if (pattern.len > max_pattern) return error.PatternTooLong;
    if (!isChannelPrefix(pattern[0])) return error.PatternIsNotChannel;
    for (pattern[1..]) |byte| {
        if (isInvalidChannelByte(byte)) return error.InvalidPattern;
    }
}

fn parseDurationMs(raw: []const u8) ParseError!i64 {
    if (raw.len == 0) return error.InvalidDuration;
    const value = std.fmt.parseInt(i64, raw, 10) catch return error.InvalidDuration;
    if (value < 0) return error.InvalidDuration;
    return value;
}

fn expiryFromDuration(now_ms: i64, duration_ms: i64) ParseError!i64 {
    if (duration_ms == 0) return 0;
    return std.math.add(i64, now_ms, duration_ms) catch error.DurationOverflow;
}

fn freeReservation(allocator: std.mem.Allocator, reservation: *Reservation) void {
    allocator.free(reservation.pattern);
    allocator.free(reservation.reason);
    allocator.free(reservation.set_by);
    reservation.* = undefined;
}

fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or eqlFold(pattern[p], text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqlFold(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn eqlFoldSlice(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!eqlFold(left, right)) return false;
    }
    return true;
}

fn isChannelPrefix(byte: u8) bool {
    return byte == '#' or byte == '&' or byte == '+' or byte == '!';
}

fn isInvalidChannelByte(byte: u8) bool {
    return byte == 0 or byte == '\r' or byte == '\n' or byte == ' ' or byte == ',' or byte == 0x07;
}

fn containsLineBreak(text: []const u8) bool {
    for (text) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return true;
    }
    return false;
}

fn isValidToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n' or byte == ' ' or byte == ':') return false;
    }
    return true;
}

fn mkReservation(pattern: []const u8) Reservation {
    return .{
        .pattern = pattern,
        .reason = "reserved by policy",
        .set_by = "oper",
        .created_ms = 1000,
        .expires_ms = 0,
    };
}

const testing = std.testing;

test "add list remove and count preserve owned reservation data" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    try resv.add(mkReservation("#staff"));
    try resv.add(.{
        .pattern = "&local*",
        .reason = "local channels are staff-only",
        .set_by = "netadmin",
        .created_ms = 2000,
        .expires_ms = 9000,
    });

    var out: [4]Reservation = undefined;
    const listed = resv.list(&out);

    try testing.expectEqual(@as(usize, 2), resv.count());
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("#staff", listed[0].pattern);
    try testing.expectEqualStrings("reserved by policy", listed[0].reason);
    try testing.expectEqualStrings("&local*", listed[1].pattern);
    try testing.expectEqualStrings("netadmin", listed[1].set_by);
    try testing.expect(resv.remove("#staff"));
    try testing.expect(!resv.remove("#staff"));
    try testing.expectEqual(@as(usize, 1), resv.count());
}

test "isReserved matches channel glob patterns case-insensitively" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    try resv.add(mkReservation("#Bad*"));
    try resv.add(mkReservation("&staff-??"));

    try testing.expect(resv.isReserved("#badplace", 1000));
    try testing.expect(resv.isReserved("#BADPLACE", 1000));
    try testing.expect(resv.isReserved("&staff-ab", 1000));
    try testing.expect(!resv.isReserved("&staff-a", 1000));
    try testing.expect(!resv.isReserved("#good", 1000));
}

test "isReserved ignores invalid concrete channel names and stays distinct from nick reservation" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    try resv.add(mkReservation("#nick*"));

    try testing.expect(!resv.isReserved("nickserv", 1000));
    try testing.expect(!resv.isReserved("Nick*", 1000));
    try testing.expect(!resv.isReserved("#bad channel", 1000));
    try testing.expectError(error.PatternIsNotChannel, resv.add(mkReservation("Nick*")));
    try testing.expectError(error.PatternIsNotChannel, validatePattern("*Nick*"));
}

test "expired entries are swept before matching and sweep reports removals" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    var expired = mkReservation("#old*");
    expired.expires_ms = 5000;
    var active = mkReservation("#new*");
    active.expires_ms = 5001;
    var permanent = mkReservation("#perm*");
    permanent.expires_ms = 0;

    try resv.add(expired);
    try resv.add(active);
    try resv.add(permanent);

    try testing.expect(!resv.isReserved("#oldchan", 5000));
    try testing.expect(resv.isReserved("#newchan", 5000));
    try testing.expectEqual(@as(usize, 2), resv.count());
    try testing.expectEqual(@as(usize, 1), resv.sweep(5001));
    try testing.expect(resv.isReserved("#permchan", 9000));
    try testing.expectEqual(@as(usize, 1), resv.count());
}

test "add replaces existing pattern at capacity without leaking" {
    var resv = ChannelResv.init(testing.allocator, .{ .max_resvs = 1 });
    defer resv.deinit();

    var first = mkReservation("#dup*");
    first.reason = "first";
    first.set_by = "one";
    var second = mkReservation("#DUP*");
    second.reason = "second";
    second.set_by = "two";
    second.expires_ms = 7000;

    try resv.add(first);
    try resv.add(second);
    try testing.expectEqual(@as(usize, 1), resv.count());

    var out: [2]Reservation = undefined;
    const listed = resv.list(&out);
    try testing.expectEqualStrings("#DUP*", listed[0].pattern);
    try testing.expectEqualStrings("second", listed[0].reason);
    try testing.expectEqual(@as(i64, 7000), listed[0].expires_ms);

    try testing.expectError(error.TooManyReservations, resv.add(mkReservation("#other")));
}

test "validation limits reject malformed channel reservation records" {
    var resv = ChannelResv.init(testing.allocator, .{
        .max_resvs = 4,
        .max_pattern = 6,
        .max_reason = 4,
        .max_setter = 5,
    });
    defer resv.deinit();

    try testing.expectError(error.EmptyPattern, resv.add(mkReservation("")));
    try testing.expectError(error.PatternTooLong, resv.add(mkReservation("#abcdef")));
    try testing.expectError(error.PatternIsNotChannel, resv.add(mkReservation("nick*")));
    try testing.expectError(error.InvalidPattern, resv.add(mkReservation("#b ad")));

    var bad_reason = mkReservation("#ok");
    bad_reason.reason = "later";
    try testing.expectError(error.ReasonTooLong, resv.add(bad_reason));

    var bad_setter = mkReservation("#ok");
    bad_setter.reason = "ok";
    bad_setter.set_by = "longer";
    try testing.expectError(error.SetterTooLong, resv.add(bad_setter));
}

test "list truncates to caller buffer without mutating storage" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    try resv.add(mkReservation("#one"));
    try resv.add(mkReservation("#two"));

    var out: [1]Reservation = undefined;
    const listed = resv.list(&out);

    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqual(@as(usize, 2), resv.count());
    try testing.expectEqualStrings("#one", listed[0].pattern);
}

test "parse RESV add remove list sweep and UNRESV commands" {
    const add_args = [_][]const u8{ "ADD", "#bad*", "60000", "reserved namespace" };
    const add_cmd = try parseServerCommand("RESV", &add_args, 1000);
    try testing.expectEqualStrings("#bad*", add_cmd.add.pattern);
    try testing.expectEqualStrings("reserved namespace", add_cmd.add.reason);
    try testing.expectEqual(@as(i64, 60000), add_cmd.add.duration_ms);
    try testing.expectEqual(@as(i64, 61000), add_cmd.add.expires_ms);

    const bare_add_args = [_][]const u8{ "&ops", "0", "permanent local reserve" };
    const bare_add = try parseServerCommand("resv", &bare_add_args, 1000);
    try testing.expectEqualStrings("&ops", bare_add.add.pattern);
    try testing.expectEqual(@as(i64, 0), bare_add.add.expires_ms);

    const remove_args = [_][]const u8{ "DEL", "#bad*" };
    const remove_cmd = try parseServerCommand("RESV", &remove_args, 1000);
    try testing.expectEqualStrings("#bad*", remove_cmd.remove);

    const unresv_args = [_][]const u8{"#bad*"};
    const unresv_cmd = try parseServerCommand("UNRESV", &unresv_args, 1000);
    try testing.expectEqualStrings("#bad*", unresv_cmd.remove);

    const list_args = [_][]const u8{"LIST"};
    try testing.expectEqual(Command.list, try parseServerCommand("RESV", &list_args, 1000));
    const sweep_args = [_][]const u8{"SWEEP"};
    try testing.expectEqual(Command.sweep, try parseServerCommand("RESV", &sweep_args, 1000));
}

test "parse rejects bad command shape duration overflow and nick patterns" {
    const missing_args = [_][]const u8{"ADD"};
    try testing.expectError(error.MissingParameter, parseServerCommand("RESV", &missing_args, 1000));

    const bad_duration = [_][]const u8{ "ADD", "#bad*", "-1", "reason" };
    try testing.expectError(error.InvalidDuration, parseServerCommand("RESV", &bad_duration, 1000));

    const duration_overflow = [_][]const u8{ "ADD", "#bad*", "10", "reason" };
    try testing.expectError(error.DurationOverflow, parseServerCommand("RESV", &duration_overflow, std.math.maxInt(i64) - 5));

    const nick_pattern = [_][]const u8{ "ADD", "Nick*", "0", "reason" };
    try testing.expectError(error.PatternIsNotChannel, parseServerCommand("RESV", &nick_pattern, 1000));

    const unknown = [_][]const u8{"#bad*"};
    try testing.expectError(error.UnknownCommand, parseServerCommand("PRIVMSG", &unknown, 1000));
}

test "addParsed applies parsed ADD request with dispatcher supplied setter" {
    var resv = ChannelResv.init(testing.allocator, .{});
    defer resv.deinit();

    const args = [_][]const u8{ "ADD", "#quiet*", "250", "temporary reserve" };
    const cmd = try parseServerCommand("RESV", &args, 1000);
    try resv.addParsed(cmd.add, "ircop", 1000);

    var out: [1]Reservation = undefined;
    const listed = resv.list(&out);
    try testing.expectEqualStrings("#quiet*", listed[0].pattern);
    try testing.expectEqualStrings("ircop", listed[0].set_by);
    try testing.expectEqual(@as(i64, 1250), listed[0].expires_ms);
    try testing.expect(resv.isReserved("#quietroom", 1249));
    try testing.expect(!resv.isReserved("#quietroom", 1250));
}

test "unavailable resource numeric is server-prefixed and validates fields" {
    var buf: [256]u8 = undefined;
    const line = try buildUnavailableResourceNumeric(&buf, "irc.example.test", "alice", "#bad", "reserved by policy");

    try testing.expectEqualStrings(
        ":irc.example.test 437 alice #bad :Channel is reserved: reserved by policy",
        line,
    );
    try testing.expect(std.mem.indexOf(u8, line, "ChanServ") == null);
    try testing.expect(std.mem.indexOf(u8, line, "NickServ") == null);
    try testing.expect(std.mem.indexOf(u8, line, "OperServ") == null);

    try testing.expectError(error.InvalidServerName, buildUnavailableResourceNumeric(&buf, "irc example", "alice", "#bad", "reason"));
    try testing.expectError(error.InvalidNick, buildUnavailableResourceNumeric(&buf, "irc.example", "bad nick", "#bad", "reason"));
    try testing.expectError(error.InvalidChannel, buildUnavailableResourceNumeric(&buf, "irc.example", "alice", "Nick*", "reason"));
    try testing.expectError(error.InvalidReason, buildUnavailableResourceNumeric(&buf, "irc.example", "alice", "#bad", "bad\nreason"));

    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, buildUnavailableResourceNumeric(&tiny, "irc.example", "alice", "#bad", "reason"));
}

test "churn through add replace remove and sweep leaks no allocations" {
    var resv = ChannelResv.init(testing.allocator, .{ .max_resvs = 64 });
    defer resv.deinit();

    for (0..32) |idx| {
        var pattern_buf: [48]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "#chan{d}-*", .{idx});
        var reservation = mkReservation(pattern);
        reservation.expires_ms = @intCast(1000 + idx);
        try resv.add(reservation);
    }
    for (0..16) |idx| {
        var pattern_buf: [48]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "#chan{d}-*", .{idx});
        var replacement = mkReservation(pattern);
        replacement.reason = "swap";
        replacement.expires_ms = 900;
        try resv.add(replacement);
    }

    try testing.expectEqual(@as(usize, 16), resv.sweep(1000));
    for (16..32) |idx| {
        var pattern_buf: [48]u8 = undefined;
        const pattern = try std.fmt.bufPrint(&pattern_buf, "#chan{d}-*", .{idx});
        _ = resv.remove(pattern);
    }

    try testing.expectEqual(@as(usize, 0), resv.count());
}
