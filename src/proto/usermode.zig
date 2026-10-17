// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-room IRC user-mode codec.
//!
//! User modes are represented as stable enum bits and interpreted through a
//! comptime catalog. Parsing and serialization use caller-owned buffers only,
//! so MODE handling stays allocation-free on the hot path.
const std = @import("std");

pub const MAX_MODE_CHANGES: usize = mode_count;

/// Stable Onyx Server user-mode identifiers.
pub const UserMode = enum(u6) {
    invisible,
    bot,
    registered,
    secure_tls,
    deaf,
    callerid,
    no_ctcp,
    cloaked,
    regonly_pm, // R: reject PMs/notices from unauthenticated senders
    hide_chans, // p: suppress own channel list in WHOIS (opers still see it)
    no_forward, // Q: never be forwarded to another channel on a blocked JOIN
    hide_oper, // H: hide operator status from WHOIS/WHO for non-opers
    media_tx_deny, // M: server-managed media transmit/publish deny
    media_presence_private, // P: suppress automatic media presence broadcasts
    admin, // a: network administrator. Server-managed; derived from the
    // server_admin oper privilege on auto-elevation, never client-settable.
    override, // j: operator channel override plus SYSTEM kill attribution.
    // Appended modes keep the ordinals above stable in the u64 Helix tail.
    common_chan, // G: direct messages require a shared channel or ACCEPT
    tls_only_pm, // Z: direct messages require a TLS sender
    hide_idle, // I: hide WHOIS idle from other users
    no_invite, // V: refuse INVITE unless the inviter is oper or the same account
    whois_notify, // W: NOTICE this user when someone else runs WHOIS
    no_chan_notice, // T: drop channel NOTICE while still receiving channel PRIVMSG
};

const mode_count: usize = @typeInfo(UserMode).@"enum".field_names.len;

comptime {
    if (mode_count > 64) @compileError("UmodeSet stores bits in u64");
}

/// Bitset over known user modes.
pub const UmodeSet = struct {
    bits: u64 = 0,

    pub fn empty() UmodeSet {
        return .{};
    }

    pub fn one(mode: UserMode) UmodeSet {
        var set = UmodeSet.empty();
        set.add(mode);
        return set;
    }

    pub fn fromModes(modes: []const UserMode) UmodeSet {
        var set = UmodeSet.empty();
        for (modes) |mode| set.add(mode);
        return set;
    }

    pub fn add(self: *UmodeSet, mode: UserMode) void {
        self.bits |= bit(mode);
    }

    pub fn remove(self: *UmodeSet, mode: UserMode) void {
        self.bits &= ~bit(mode);
    }

    pub fn contains(self: UmodeSet, mode: UserMode) bool {
        return (self.bits & bit(mode)) != 0;
    }

    pub fn containsAll(self: UmodeSet, other: UmodeSet) bool {
        return (self.bits & other.bits) == other.bits;
    }

    pub fn isEmpty(self: UmodeSet) bool {
        return self.bits == 0;
    }

    pub fn eql(self: UmodeSet, other: UmodeSet) bool {
        return self.bits == other.bits;
    }

    pub fn unionWith(self: *UmodeSet, other: UmodeSet) void {
        self.bits |= other.bits;
    }

    pub fn subtract(self: *UmodeSet, other: UmodeSet) void {
        self.bits &= ~other.bits;
    }

    fn bit(mode: UserMode) u64 {
        return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(mode)));
    }
};

/// Whether a mode operation adds or removes a bit.
pub const ModeOp = enum {
    add,
    remove,
};

/// One parsed mode operation.
pub const ModeChange = struct {
    op: ModeOp,
    mode: UserMode,
};

/// Actor requesting a mode change.
pub const ApplySource = enum {
    client,
    server,
};

/// Client mutability policy for a mode.
pub const ModePolicy = enum {
    client_writable,
    server_managed,
};

/// One user-mode catalog entry.
pub const ModeSpec = struct {
    mode: UserMode,
    letter: u8,
    name: []const u8,
    policy: ModePolicy = .client_writable,
    ircv3: ?[]const u8 = null,
};

/// Summary of a successful apply operation.
pub const ApplySummary = struct {
    added: UmodeSet = .{},
    removed: UmodeSet = .{},
};

pub const UmodeError = error{
    EmptyModeString,
    MissingOperation,
    UnknownMode,
    TooManyChanges,
    ReadOnlyMode,
    ModeNotInCatalog,
    OutputTooSmall,
};

/// Default modern Onyx Server modes.
pub const default_specs = [_]ModeSpec{
    .{ .mode = .invisible, .letter = 'i', .name = "invisible" },
    .{ .mode = .bot, .letter = 'B', .name = "bot", .ircv3 = "bot" },
    .{ .mode = .registered, .letter = 'r', .name = "registered", .policy = .server_managed },
    .{ .mode = .secure_tls, .letter = 'z', .name = "secure-tls", .policy = .server_managed },
    .{ .mode = .deaf, .letter = 'D', .name = "deaf" },
    .{ .mode = .callerid, .letter = 'g', .name = "callerid" },
    .{ .mode = .no_ctcp, .letter = 'C', .name = "no-ctcp" },
    .{ .mode = .cloaked, .letter = 'x', .name = "cloaked", .policy = .server_managed },
    .{ .mode = .regonly_pm, .letter = 'R', .name = "regonly-pm" },
    .{ .mode = .hide_chans, .letter = 'p', .name = "hide-chans" },
    .{ .mode = .no_forward, .letter = 'Q', .name = "no-forward" },
    .{ .mode = .hide_oper, .letter = 'H', .name = "hide-oper" },
    .{ .mode = .media_tx_deny, .letter = 'M', .name = "media-tx-deny", .policy = .server_managed },
    .{ .mode = .media_presence_private, .letter = 'P', .name = "media-presence-private" },
    .{ .mode = .admin, .letter = 'a', .name = "admin", .policy = .server_managed },
    .{ .mode = .override, .letter = 'j', .name = "override" },
    .{ .mode = .common_chan, .letter = 'G', .name = "common-chan" },
    .{ .mode = .tls_only_pm, .letter = 'Z', .name = "tls-only-pm" },
    .{ .mode = .hide_idle, .letter = 'I', .name = "hide-idle" },
    .{ .mode = .no_invite, .letter = 'V', .name = "no-invite" },
    .{ .mode = .whois_notify, .letter = 'W', .name = "whois-notify" },
    .{ .mode = .no_chan_notice, .letter = 'T', .name = "no-chan-notice" },
};

pub const derived_operator_letter = 'o';
pub const default_mode_letters_storage = sortedLettersWithOperator(&default_specs);
pub const default_mode_letters: []const u8 = default_mode_letters_storage[0..];

pub const DefaultCatalog = Catalog(&default_specs);

fn sortedLettersWithOperator(comptime specs: []const ModeSpec) [specs.len + 1]u8 {
    comptime var out: [specs.len + 1]u8 = undefined;
    inline for (specs, 0..) |spec, i| out[i] = spec.letter;
    out[specs.len] = derived_operator_letter;
    sortLetters(&out);
    return out;
}

fn sortLetters(comptime letters: []u8) void {
    comptime var i: usize = 1;
    inline while (i < letters.len) : (i += 1) {
        const key = letters[i];
        comptime var j: usize = i;
        inline while (j > 0 and key < letters[j - 1]) : (j -= 1) {
            letters[j] = letters[j - 1];
        }
        letters[j] = key;
    }
}

/// Compile-time user-mode catalog with parser, policy, and serializer helpers.
pub fn Catalog(comptime specs: []const ModeSpec) type {
    comptime validateSpecs(specs);

    return struct {
        /// Parse a MODE mode-string such as `+iB-D` into caller-owned storage.
        pub fn parse(input: []const u8, out: []ModeChange) UmodeError![]const ModeChange {
            if (input.len == 0) return error.EmptyModeString;

            var op: ?ModeOp = null;
            var count: usize = 0;

            for (input) |ch| {
                switch (ch) {
                    '+' => op = .add,
                    '-' => op = .remove,
                    else => {
                        const active_op = op orelse return error.MissingOperation;
                        const mode = @This().modeFromLetter(ch) orelse return error.UnknownMode;
                        if (count >= out.len) return error.TooManyChanges;
                        out[count] = .{ .op = active_op, .mode = mode };
                        count += 1;
                    },
                }
            }

            return out[0..count];
        }

        /// Apply parsed mode operations. Client-originated updates cannot
        /// touch server-managed read-only modes.
        pub fn apply(set: *UmodeSet, changes: []const ModeChange, source: ApplySource) UmodeError!ApplySummary {
            for (changes) |change| {
                const spec = @This().specFor(change.mode) orelse return error.ModeNotInCatalog;
                if (source == .client and spec.policy == .server_managed) {
                    return error.ReadOnlyMode;
                }
            }

            var summary = ApplySummary{};
            for (changes) |change| {
                switch (change.op) {
                    .add => {
                        if (!set.contains(change.mode)) summary.added.add(change.mode);
                        set.add(change.mode);
                    },
                    .remove => {
                        if (set.contains(change.mode)) summary.removed.add(change.mode);
                        set.remove(change.mode);
                    },
                }
            }
            return summary;
        }

        /// Serialize the set as a canonical IRC mode-string, e.g. `+iB`.
        pub fn writeModeString(set: UmodeSet, out: []u8) UmodeError![]const u8 {
            if (out.len == 0) return error.OutputTooSmall;

            var n: usize = 0;
            out[n] = '+';
            n += 1;

            for (specs) |spec| {
                if (!set.contains(spec.mode)) continue;
                if (n >= out.len) return error.OutputTooSmall;
                out[n] = spec.letter;
                n += 1;
            }

            return out[0..n];
        }

        pub fn modeFromLetter(letter: u8) ?UserMode {
            for (specs) |spec| {
                if (spec.letter == letter) return spec.mode;
            }
            return null;
        }

        pub fn letterOf(mode: UserMode) ?u8 {
            const spec = @This().specFor(mode) orelse return null;
            return spec.letter;
        }

        pub fn specFor(mode: UserMode) ?ModeSpec {
            for (specs) |spec| {
                if (spec.mode == mode) return spec;
            }
            return null;
        }

        pub fn isClientWritable(mode: UserMode) bool {
            const spec = @This().specFor(mode) orelse return false;
            return spec.policy == .client_writable;
        }
    };
}

/// Parse with the default Onyx Server mode catalog.
pub fn parse(input: []const u8, out: []ModeChange) UmodeError![]const ModeChange {
    return DefaultCatalog.parse(input, out);
}

/// Apply with the default Onyx Server mode catalog.
pub fn apply(set: *UmodeSet, changes: []const ModeChange, source: ApplySource) UmodeError!ApplySummary {
    return DefaultCatalog.apply(set, changes, source);
}

/// Serialize with the default Onyx Server mode catalog.
pub fn writeModeString(set: UmodeSet, out: []u8) UmodeError![]const u8 {
    return DefaultCatalog.writeModeString(set, out);
}

pub fn modeFromLetter(letter: u8) ?UserMode {
    return DefaultCatalog.modeFromLetter(letter);
}

pub fn letterOf(mode: UserMode) ?u8 {
    return DefaultCatalog.letterOf(mode);
}

pub fn specFor(mode: UserMode) ?ModeSpec {
    return DefaultCatalog.specFor(mode);
}

fn validateSpecs(comptime specs: []const ModeSpec) void {
    if (specs.len == 0) @compileError("user-mode catalog must not be empty");
    if (specs.len > mode_count) @compileError("user-mode catalog has too many entries");

    var seen_modes: u64 = 0;
    var seen_letters: [256]bool = @splat(false);
    for (specs) |spec| {
        if (!validModeLetter(spec.letter)) @compileError("invalid user-mode letter");

        const mode_bit = UmodeSet.bit(spec.mode);
        if ((seen_modes & mode_bit) != 0) @compileError("duplicate user-mode id");
        seen_modes |= mode_bit;

        if (seen_letters[spec.letter]) @compileError("duplicate user-mode letter");
        seen_letters[spec.letter] = true;
    }
}

fn validModeLetter(ch: u8) bool {
    return (ch >= 'A' and ch <= 'Z') or (ch >= 'a' and ch <= 'z');
}

test "parse and apply mixed add remove mode string" {
    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+iB-D", &changes_buf);
    try std.testing.expectEqual(@as(usize, 3), changes.len);
    try std.testing.expectEqual(ModeChange{ .op = .add, .mode = .invisible }, changes[0]);
    try std.testing.expectEqual(ModeChange{ .op = .add, .mode = .bot }, changes[1]);
    try std.testing.expectEqual(ModeChange{ .op = .remove, .mode = .deaf }, changes[2]);

    var modes = UmodeSet.fromModes(&.{.deaf});
    const summary = try apply(&modes, changes, .client);
    try std.testing.expect(modes.contains(.invisible));
    try std.testing.expect(modes.contains(.bot));
    try std.testing.expect(!modes.contains(.deaf));
    try std.testing.expect(summary.added.containsAll(UmodeSet.fromModes(&.{ .invisible, .bot })));
    try std.testing.expect(summary.removed.contains(.deaf));
}

test "reject setting read-only modes from client" {
    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+rzx", &changes_buf);
    var modes = UmodeSet.empty();

    try std.testing.expectError(error.ReadOnlyMode, apply(&modes, changes, .client));
    try std.testing.expect(modes.isEmpty());

    _ = try apply(&modes, changes, .server);
    try std.testing.expect(modes.contains(.registered));
    try std.testing.expect(modes.contains(.secure_tls));
    try std.testing.expect(modes.contains(.cloaked));
}

test "serialize round-trip" {
    const initial = UmodeSet.fromModes(&.{ .invisible, .bot, .registered, .secure_tls, .callerid, .no_ctcp });
    var out: [MAX_MODE_CHANGES + 1]u8 = undefined;
    const text = try writeModeString(initial, &out);
    try std.testing.expectEqualStrings("+iBrzgC", text);

    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse(text, &changes_buf);
    var round_trip = UmodeSet.empty();
    _ = try apply(&round_trip, changes, .server);
    try std.testing.expect(initial.eql(round_trip));
}

test "bot mode reflected in set and serialized output" {
    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+B", &changes_buf);
    var modes = UmodeSet.empty();
    _ = try apply(&modes, changes, .client);

    try std.testing.expect(modes.contains(.bot));
    try std.testing.expectEqual(@as(?u8, 'B'), letterOf(.bot));
    try std.testing.expect((specFor(.bot) orelse return error.ModeNotInCatalog).ircv3 != null);

    var out: [2]u8 = undefined;
    try std.testing.expectEqualStrings("+B", try writeModeString(modes, &out));
}

test "no-forward umode (+Q) round-trips and is client-writable" {
    try std.testing.expectEqual(@as(?UserMode, .no_forward), modeFromLetter('Q'));
    try std.testing.expectEqual(@as(?u8, 'Q'), letterOf(.no_forward));
    try std.testing.expect(DefaultCatalog.isClientWritable(.no_forward));

    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+Q", &changes_buf);
    var modes = UmodeSet.empty();
    _ = try apply(&modes, changes, .client);
    try std.testing.expect(modes.contains(.no_forward));
}

test "media user modes expose server-managed transmit deny and client privacy" {
    try std.testing.expectEqual(@as(?UserMode, .media_tx_deny), modeFromLetter('M'));
    try std.testing.expectEqual(@as(?UserMode, .media_presence_private), modeFromLetter('P'));
    try std.testing.expect(!DefaultCatalog.isClientWritable(.media_tx_deny));
    try std.testing.expect(DefaultCatalog.isClientWritable(.media_presence_private));

    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const client_changes = try parse("+MP", &changes_buf);
    var modes = UmodeSet.empty();
    try std.testing.expectError(error.ReadOnlyMode, apply(&modes, client_changes, .client));
    try std.testing.expect(modes.isEmpty());

    _ = try apply(&modes, client_changes, .server);
    var out: [MAX_MODE_CHANGES + 1]u8 = undefined;
    try std.testing.expectEqualStrings("+MP", try writeModeString(modes, &out));
}

test "override user mode uses non-colliding +j catalog letter" {
    try std.testing.expectEqual(@as(?UserMode, .override), modeFromLetter('j'));
    try std.testing.expectEqual(@as(?u8, 'j'), letterOf(.override));
    try std.testing.expect(DefaultCatalog.isClientWritable(.override));
    try std.testing.expectEqualStrings("override", (specFor(.override) orelse return error.ModeNotInCatalog).name);

    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+j", &changes_buf);
    var modes = UmodeSet.empty();
    _ = try apply(&modes, changes, .client);
    try std.testing.expect(modes.contains(.override));
}

test "privacy user modes are client-writable and keep earlier ordinals" {
    try std.testing.expectEqual(@as(u6, 15), @intFromEnum(UserMode.override));
    try std.testing.expectEqual(@as(u6, 16), @intFromEnum(UserMode.common_chan));
    try std.testing.expectEqual(@as(?UserMode, .common_chan), modeFromLetter('G'));
    try std.testing.expectEqual(@as(?UserMode, .tls_only_pm), modeFromLetter('Z'));
    try std.testing.expectEqual(@as(?UserMode, .hide_idle), modeFromLetter('I'));
    try std.testing.expectEqual(@as(?UserMode, .no_invite), modeFromLetter('V'));
    try std.testing.expectEqual(@as(?UserMode, .whois_notify), modeFromLetter('W'));
    try std.testing.expectEqual(@as(?UserMode, .no_chan_notice), modeFromLetter('T'));
    inline for (.{ UserMode.common_chan, .tls_only_pm, .hide_idle, .no_invite, .whois_notify, .no_chan_notice, .deaf }) |mode| {
        try std.testing.expect(DefaultCatalog.isClientWritable(mode));
    }

    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    const changes = try parse("+GZIVWT", &changes_buf);
    var modes = UmodeSet.empty();
    _ = try apply(&modes, changes, .client);
    try std.testing.expect(modes.contains(.common_chan));
    try std.testing.expect(modes.contains(.tls_only_pm));
    try std.testing.expect(modes.contains(.hide_idle));
    try std.testing.expect(modes.contains(.no_invite));
    try std.testing.expect(modes.contains(.whois_notify));
    try std.testing.expect(modes.contains(.no_chan_notice));
}

test "unknown mode rejected" {
    var changes_buf: [MAX_MODE_CHANGES]ModeChange = undefined;
    try std.testing.expectError(error.UnknownMode, parse("+w", &changes_buf));
    try std.testing.expectError(error.MissingOperation, parse("i", &changes_buf));
}

test "output and change buffers are bounded" {
    _ = std.testing.allocator;

    var tiny_changes: [1]ModeChange = undefined;
    try std.testing.expectError(error.TooManyChanges, parse("+iB", &tiny_changes));

    const modes = UmodeSet.fromModes(&.{ .invisible, .bot });
    var tiny_out: [2]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, writeModeString(modes, &tiny_out));
}
