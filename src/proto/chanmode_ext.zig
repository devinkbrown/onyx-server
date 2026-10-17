// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure IRCX extended channel-mode data layer.
//!
//! This module intentionally owns no world state. It stores only IRCX channel
//! flag bits and translates between MODEX names and one-byte MODE letters.
const std = @import("std");

pub const ExtChannelModeError = error{
    MissingOperation,
    OutputTooSmall,
};

/// IRCX channel/visibility flag modes from `ircx_modex.mode_table`.
pub const ExtChannelFlag = enum(u5) {
    private,
    hidden,
    secret,
    moderated,
    topicop,
    inviteonly,
    noextern,
    knock,
    authonly,
    noformat,
    cloneable,
    clone,
    registered,
    service,
    auditorium,
    nowhisper,
    nocomicdata,
    opmoderate,
    freetarget,
    disforward,
    nocolor,
    nobot,
    founderkick,
};

pub const ModeSpec = struct {
    flag: ExtChannelFlag,
    letter: u8,
    name: []const u8,
    requires_oper: bool = false,
};

pub const ApplyModeStringResult = struct {
    flags: ExtChannelFlags,
    unknown_letters: []const u8,
};

pub const mode_specs = [_]ModeSpec{
    .{ .flag = .private, .letter = 'p', .name = "PRIVATE" },
    .{ .flag = .hidden, .letter = 'h', .name = "HIDDEN" },
    .{ .flag = .secret, .letter = 's', .name = "SECRET" },
    .{ .flag = .moderated, .letter = 'm', .name = "MODERATED" },
    .{ .flag = .topicop, .letter = 't', .name = "TOPICOP" },
    .{ .flag = .inviteonly, .letter = 'i', .name = "INVITEONLY" },
    .{ .flag = .noextern, .letter = 'n', .name = "NOEXTERN" },
    .{ .flag = .knock, .letter = 'u', .name = "KNOCK" },
    .{ .flag = .authonly, .letter = 'a', .name = "AUTHONLY" },
    .{ .flag = .noformat, .letter = 'f', .name = "NOFORMAT" },
    .{ .flag = .cloneable, .letter = 'd', .name = "CLONEABLE" },
    .{ .flag = .clone, .letter = 'E', .name = "CLONE", .requires_oper = true },
    .{ .flag = .registered, .letter = 'r', .name = "REGISTERED", .requires_oper = true },
    .{ .flag = .service, .letter = 'z', .name = "SERVICE", .requires_oper = true },
    .{ .flag = .auditorium, .letter = 'x', .name = "AUDITORIUM" },
    .{ .flag = .nowhisper, .letter = 'w', .name = "NOWHISPER" },
    .{ .flag = .nocomicdata, .letter = 'V', .name = "NOCOMICDATA" },
    .{ .flag = .opmoderate, .letter = 'U', .name = "OPMODERATE" },
    .{ .flag = .freetarget, .letter = 'F', .name = "FREETARGET" },
    .{ .flag = .disforward, .letter = 'D', .name = "DISFORWARD" },
    .{ .flag = .nocolor, .letter = 'c', .name = "NOCOLOR" },
    .{ .flag = .nobot, .letter = 'B', .name = "NOBOT" },
    .{ .flag = .founderkick, .letter = 'K', .name = "FOUNDERKICK" },
};

const render_specs = [_]ModeSpec{
    .{ .flag = .nobot, .letter = 'B', .name = "NOBOT" },
    .{ .flag = .disforward, .letter = 'D', .name = "DISFORWARD" },
    .{ .flag = .clone, .letter = 'E', .name = "CLONE", .requires_oper = true },
    .{ .flag = .freetarget, .letter = 'F', .name = "FREETARGET" },
    .{ .flag = .founderkick, .letter = 'K', .name = "FOUNDERKICK" },
    .{ .flag = .opmoderate, .letter = 'U', .name = "OPMODERATE" },
    .{ .flag = .nocomicdata, .letter = 'V', .name = "NOCOMICDATA" },
    .{ .flag = .authonly, .letter = 'a', .name = "AUTHONLY" },
    .{ .flag = .nocolor, .letter = 'c', .name = "NOCOLOR" },
    .{ .flag = .cloneable, .letter = 'd', .name = "CLONEABLE" },
    .{ .flag = .noformat, .letter = 'f', .name = "NOFORMAT" },
    .{ .flag = .hidden, .letter = 'h', .name = "HIDDEN" },
    .{ .flag = .inviteonly, .letter = 'i', .name = "INVITEONLY" },
    .{ .flag = .moderated, .letter = 'm', .name = "MODERATED" },
    .{ .flag = .noextern, .letter = 'n', .name = "NOEXTERN" },
    .{ .flag = .private, .letter = 'p', .name = "PRIVATE" },
    .{ .flag = .registered, .letter = 'r', .name = "REGISTERED", .requires_oper = true },
    .{ .flag = .secret, .letter = 's', .name = "SECRET" },
    .{ .flag = .topicop, .letter = 't', .name = "TOPICOP" },
    .{ .flag = .knock, .letter = 'u', .name = "KNOCK" },
    .{ .flag = .nowhisper, .letter = 'w', .name = "NOWHISPER" },
    .{ .flag = .auditorium, .letter = 'x', .name = "AUDITORIUM" },
    .{ .flag = .service, .letter = 'z', .name = "SERVICE", .requires_oper = true },
};

comptime {
    // The duplicate and sort checks nest a scan per flag. Three new flags
    // push that over Zig's default comptime branch quota.
    @setEvalBranchQuota(10_000);
    const flag_count = @typeInfo(ExtChannelFlag).@"enum".field_names.len;
    if (mode_specs.len != flag_count) @compileError("missing IRCX channel flag mode");
    if (render_specs.len != flag_count) @compileError("missing render spec");

    for (mode_specs, 0..) |left, left_index| {
        for (mode_specs[left_index + 1 ..]) |right| {
            if (left.flag == right.flag) @compileError("duplicate IRCX channel flag");
            if (left.letter == right.letter) @compileError("duplicate IRCX channel mode letter");
            if (asciiEqlComptime(left.name, right.name)) @compileError("duplicate IRCX channel mode name");
        }
    }
    for (render_specs, 0..) |left, left_index| {
        _ = specFor(left.flag) orelse @compileError("render spec has unknown flag");
        for (render_specs[left_index + 1 ..]) |right| {
            if (left.letter > right.letter) @compileError("render specs must be sorted by letter");
        }
    }
}

/// Packed bitset over IRCX extended channel flags.
pub const ExtChannelFlags = packed struct(u32) {
    private: bool = false,
    hidden: bool = false,
    secret: bool = false,
    moderated: bool = false,
    topicop: bool = false,
    inviteonly: bool = false,
    noextern: bool = false,
    knock: bool = false,
    authonly: bool = false,
    noformat: bool = false,
    cloneable: bool = false,
    clone: bool = false,
    registered: bool = false,
    service: bool = false,
    auditorium: bool = false,
    nowhisper: bool = false,
    nocomicdata: bool = false,
    opmoderate: bool = false,
    freetarget: bool = false,
    disforward: bool = false,
    nocolor: bool = false,
    nobot: bool = false,
    founderkick: bool = false,
    reserved: u9 = 0,

    pub fn empty() ExtChannelFlags {
        return .{};
    }

    pub fn one(flag: ExtChannelFlag) ExtChannelFlags {
        var flags = ExtChannelFlags.empty();
        flags.set(flag);
        return flags;
    }

    pub fn fromFlags(flags: []const ExtChannelFlag) ExtChannelFlags {
        var out = ExtChannelFlags.empty();
        for (flags) |flag| out.set(flag);
        return out;
    }

    pub fn set(self: *ExtChannelFlags, flag: ExtChannelFlag) void {
        switch (flag) {
            .private => self.private = true,
            .hidden => self.hidden = true,
            .secret => self.secret = true,
            .moderated => self.moderated = true,
            .topicop => self.topicop = true,
            .inviteonly => self.inviteonly = true,
            .noextern => self.noextern = true,
            .knock => self.knock = true,
            .authonly => self.authonly = true,
            .noformat => self.noformat = true,
            .cloneable => self.cloneable = true,
            .clone => self.clone = true,
            .registered => self.registered = true,
            .service => self.service = true,
            .auditorium => self.auditorium = true,
            .nowhisper => self.nowhisper = true,
            .nocomicdata => self.nocomicdata = true,
            .opmoderate => self.opmoderate = true,
            .freetarget => self.freetarget = true,
            .disforward => self.disforward = true,
            .nocolor => self.nocolor = true,
            .nobot => self.nobot = true,
            .founderkick => self.founderkick = true,
        }
    }

    pub fn clear(self: *ExtChannelFlags, flag: ExtChannelFlag) void {
        switch (flag) {
            .private => self.private = false,
            .hidden => self.hidden = false,
            .secret => self.secret = false,
            .moderated => self.moderated = false,
            .topicop => self.topicop = false,
            .inviteonly => self.inviteonly = false,
            .noextern => self.noextern = false,
            .knock => self.knock = false,
            .authonly => self.authonly = false,
            .noformat => self.noformat = false,
            .cloneable => self.cloneable = false,
            .clone => self.clone = false,
            .registered => self.registered = false,
            .service => self.service = false,
            .auditorium => self.auditorium = false,
            .nowhisper => self.nowhisper = false,
            .nocomicdata => self.nocomicdata = false,
            .opmoderate => self.opmoderate = false,
            .freetarget => self.freetarget = false,
            .disforward => self.disforward = false,
            .nocolor => self.nocolor = false,
            .nobot => self.nobot = false,
            .founderkick => self.founderkick = false,
        }
    }

    pub fn has(self: ExtChannelFlags, flag: ExtChannelFlag) bool {
        return switch (flag) {
            .private => self.private,
            .hidden => self.hidden,
            .secret => self.secret,
            .moderated => self.moderated,
            .topicop => self.topicop,
            .inviteonly => self.inviteonly,
            .noextern => self.noextern,
            .knock => self.knock,
            .authonly => self.authonly,
            .noformat => self.noformat,
            .cloneable => self.cloneable,
            .clone => self.clone,
            .registered => self.registered,
            .service => self.service,
            .auditorium => self.auditorium,
            .nowhisper => self.nowhisper,
            .nocomicdata => self.nocomicdata,
            .opmoderate => self.opmoderate,
            .freetarget => self.freetarget,
            .disforward => self.disforward,
            .nocolor => self.nocolor,
            .nobot => self.nobot,
            .founderkick => self.founderkick,
        };
    }

    pub fn eql(self: ExtChannelFlags, other: ExtChannelFlags) bool {
        return @as(u32, @bitCast(self)) == @as(u32, @bitCast(other));
    }
};

pub fn letterToFlag(letter: u8) ?ExtChannelFlag {
    for (mode_specs) |spec| {
        if (spec.letter == letter) return spec.flag;
    }
    return null;
}

pub fn flagToLetter(flag: ExtChannelFlag) u8 {
    return specFor(flag).?.letter;
}

pub fn nameToFlag(name: []const u8) ?ExtChannelFlag {
    for (mode_specs) |spec| {
        if (asciiEql(name, spec.name)) return spec.flag;
    }
    return null;
}

pub fn requiresOper(flag: ExtChannelFlag) bool {
    return specFor(flag).?.requires_oper;
}

/// Apply a simple flag-only MODE string and collect unknown letters.
pub fn applyModeString(
    initial: ExtChannelFlags,
    mode_string: []const u8,
    unknown_out: []u8,
) ExtChannelModeError!ApplyModeStringResult {
    var flags = initial;
    var unknown_len: usize = 0;
    var op: ?enum { add, remove } = null;

    for (mode_string) |ch| {
        switch (ch) {
            '+' => op = .add,
            '-' => op = .remove,
            else => {
                const active_op = op orelse return error.MissingOperation;
                const flag = letterToFlag(ch) orelse {
                    if (unknown_len >= unknown_out.len) return error.OutputTooSmall;
                    unknown_out[unknown_len] = ch;
                    unknown_len += 1;
                    continue;
                };
                switch (active_op) {
                    .add => flags.set(flag),
                    .remove => flags.clear(flag),
                }
            },
        }
    }

    return .{
        .flags = flags,
        .unknown_letters = unknown_out[0..unknown_len],
    };
}

/// Render active flags as `+` followed by mode letters sorted by letter.
pub fn renderModes(flags: ExtChannelFlags, out: []u8) ExtChannelModeError![]const u8 {
    var len: usize = 0;
    for (render_specs) |spec| {
        if (flags.has(spec.flag)) len += 1;
    }
    if (len == 0) return out[0..0];
    if (out.len < len + 1) return error.OutputTooSmall;

    out[0] = '+';
    var index: usize = 1;
    for (render_specs) |spec| {
        if (!flags.has(spec.flag)) continue;
        out[index] = spec.letter;
        index += 1;
    }
    return out[0..index];
}

fn specFor(flag: ExtChannelFlag) ?ModeSpec {
    for (mode_specs) |spec| {
        if (spec.flag == flag) return spec;
    }
    return null;
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiEqlComptime(comptime a: []const u8, comptime b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLowerComptime(left) != asciiLowerComptime(right)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn asciiLowerComptime(comptime byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

test "letter flag round-trip for every mode" {
    for (mode_specs) |spec| {
        const flag = letterToFlag(spec.letter) orelse return error.TestExpectedEqual;
        try std.testing.expectEqual(spec.flag, flag);
        try std.testing.expectEqual(spec.letter, flagToLetter(flag));
        try std.testing.expectEqual(spec.flag, nameToFlag(spec.name).?);
    }
}

test "applyModeString adds removes and collects unknown letters" {
    const allocator = std.testing.allocator;
    const unknown = try allocator.alloc(u8, 4);
    defer allocator.free(unknown);

    var initial = ExtChannelFlags.empty();
    initial.set(.auditorium);
    initial.set(.hidden);

    const applied = try applyModeString(initial, "+abE-x?", unknown);
    try std.testing.expect(applied.flags.has(.authonly));
    try std.testing.expect(applied.flags.has(.clone));
    try std.testing.expect(applied.flags.has(.hidden));
    try std.testing.expect(!applied.flags.has(.auditorium));
    try std.testing.expectEqualStrings("b?", applied.unknown_letters);
}

test "renderModes returns active letters sorted by letter" {
    const allocator = std.testing.allocator;
    const out = try allocator.alloc(u8, 32);
    defer allocator.free(out);

    const flags = ExtChannelFlags.fromFlags(&.{
        .service,
        .private,
        .clone,
        .authonly,
        .nocomicdata,
        .hidden,
    });

    try std.testing.expectEqualStrings("+EVahpz", try renderModes(flags, out));
}

test "NOCOLOR NOBOT and FOUNDERKICK use the spare extended bits" {
    try std.testing.expectEqual(ExtChannelFlag.nocolor, letterToFlag('c').?);
    try std.testing.expectEqual(ExtChannelFlag.nobot, letterToFlag('B').?);
    try std.testing.expectEqual(ExtChannelFlag.founderkick, letterToFlag('K').?);
    var flags = ExtChannelFlags.empty();
    flags.set(.nocolor);
    flags.set(.nobot);
    flags.set(.founderkick);
    try std.testing.expectEqual(@as(u32, (1 << 20) | (1 << 21) | (1 << 22)), @as(u32, @bitCast(flags)));
    try std.testing.expect(!requiresOper(.nocolor));
    try std.testing.expect(!requiresOper(.nobot));
    try std.testing.expect(!requiresOper(.founderkick));
}

test "requiresOper is true for CLONE REGISTERED SERVICE" {
    try std.testing.expect(requiresOper(.clone));
    try std.testing.expect(requiresOper(.registered));
    try std.testing.expect(requiresOper(.service));
    try std.testing.expect(!requiresOper(.authonly));
    try std.testing.expect(!requiresOper(.cloneable));
}
