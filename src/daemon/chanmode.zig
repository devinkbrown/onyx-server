// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-room channel MODE engine.
//!
//! Channel modes are stored in a compact struct while type-A list mode entries
//! live in caller-owned backing slices. Parsing, applying, and serialization do
//! not allocate and never panic on attacker-controlled MODE input.
const std = @import("std");

pub const DEFAULT_MAX_KEY_BYTES: usize = 64;
pub const DEFAULT_MAX_LIST_ENTRY_BYTES: usize = 256;
pub const MAX_SERIALIZED_MODES: usize = 256;

/// Known compact channel mode identifiers.
pub const ChannelMode = enum(u5) {
    ban,
    exempt,
    invex,
    key,
    limit,
    invite_only,
    moderated,
    no_external,
    topic_ops,
    secret,
    // Onyx Server Tier-1 boolean flags (see docs/mode_rearchitecture.md).
    no_ctcp, // C: block channel CTCP (except ACTION) from non-ops
    no_notice, // T: block channel NOTICE from non-ops
    no_nick, // N: block nick changes by non-ops while joined
    free_invite, // g: any member may INVITE while +i
    tls_only, // S: join only permitted over a TLS session
    mod_reg, // M: mute unauthenticated members (speak needs an account or +v)
    news_wire, // W: enable the in-channel !news/!localnews fantasy bot
    oper_only, // O: only server operators may join
    admin_only, // A: only server administrators may join
};

/// Channel MODE operation direction.
pub const ModeOp = enum {
    add,
    remove,
};

/// Protocol class for the compact channel mode set.
pub const ModeKind = enum {
    list_a,
    param_b,
    param_c,
    flag_d,
};

/// One channel mode catalog row.
pub const ModeSpec = struct {
    mode: ChannelMode,
    letter: u8,
    name: []const u8,
    kind: ModeKind,
};

/// One applied channel mode change, suitable for MODE echo serialization.
pub const AppliedChange = struct {
    op: ModeOp,
    mode: ChannelMode,
    param: ?[]const u8 = null,
};

/// Result returned by serializers.
pub const SerializedModes = struct {
    mode_string: []const u8,
    params: []const []const u8,
};

/// Parsed channel limit plus the original caller-owned bytes for echo/status.
pub const ChannelLimit = struct {
    value: u64,
    text: []const u8,
};

pub const ChanModeError = error{
    EmptyModeString,
    MissingOperation,
    UnknownMode,
    MissingParameter,
    InvalidModeLetter,
    InvalidListEntry,
    ListEntryTooLong,
    ListFull,
    InvalidKey,
    KeyTooLong,
    InvalidLimit,
    LimitOutOfRange,
    TooManyChanges,
    OutputTooSmall,
    TooManyParams,
};

pub const default_specs = [_]ModeSpec{
    .{ .mode = .ban, .letter = 'b', .name = "ban", .kind = .list_a },
    .{ .mode = .exempt, .letter = 'e', .name = "exempt", .kind = .list_a },
    .{ .mode = .invex, .letter = 'I', .name = "invite-exception", .kind = .list_a },
    .{ .mode = .key, .letter = 'k', .name = "key", .kind = .param_b },
    .{ .mode = .limit, .letter = 'l', .name = "limit", .kind = .param_c },
    .{ .mode = .invite_only, .letter = 'i', .name = "invite-only", .kind = .flag_d },
    .{ .mode = .moderated, .letter = 'm', .name = "moderated", .kind = .flag_d },
    .{ .mode = .no_external, .letter = 'n', .name = "no-external", .kind = .flag_d },
    .{ .mode = .topic_ops, .letter = 't', .name = "topic-ops", .kind = .flag_d },
    .{ .mode = .secret, .letter = 's', .name = "secret", .kind = .flag_d },
    .{ .mode = .no_ctcp, .letter = 'C', .name = "no-ctcp", .kind = .flag_d },
    .{ .mode = .no_notice, .letter = 'T', .name = "no-notice", .kind = .flag_d },
    .{ .mode = .no_nick, .letter = 'N', .name = "no-nick", .kind = .flag_d },
    .{ .mode = .free_invite, .letter = 'g', .name = "free-invite", .kind = .flag_d },
    .{ .mode = .tls_only, .letter = 'S', .name = "tls-only", .kind = .flag_d },
    .{ .mode = .mod_reg, .letter = 'M', .name = "moderate-unregistered", .kind = .flag_d },
    .{ .mode = .news_wire, .letter = 'W', .name = "news-wire", .kind = .flag_d },
    .{ .mode = .oper_only, .letter = 'O', .name = "oper-only", .kind = .flag_d },
    .{ .mode = .admin_only, .letter = 'A', .name = "admin-only", .kind = .flag_d },
};

pub const default_mode_letters_storage = sortedLetters(&default_specs);
pub const default_mode_letters: []const u8 = default_mode_letters_storage[0..];
pub const default_param_mode_letters_storage = sortedParamLetters(&default_specs);
pub const default_param_mode_letters: []const u8 = default_param_mode_letters_storage[0..];

fn sortedLetters(comptime specs: []const ModeSpec) [specs.len]u8 {
    comptime var out: [specs.len]u8 = undefined;
    inline for (specs, 0..) |spec, i| out[i] = spec.letter;
    sortLetters(&out);
    return out;
}

fn sortedParamLetters(comptime specs: []const ModeSpec) [paramModeCount(specs)]u8 {
    comptime var out: [paramModeCount(specs)]u8 = undefined;
    comptime var n: usize = 0;
    inline for (specs) |spec| {
        if (modeKindTakesParam(spec.kind)) {
            out[n] = spec.letter;
            n += 1;
        }
    }
    sortLetters(&out);
    return out;
}

fn paramModeCount(comptime specs: []const ModeSpec) usize {
    comptime var count: usize = 0;
    inline for (specs) |spec| {
        if (modeKindTakesParam(spec.kind)) count += 1;
    }
    return count;
}

fn modeKindTakesParam(kind: ModeKind) bool {
    return switch (kind) {
        .list_a, .param_b, .param_c => true,
        .flag_d => false,
    };
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

/// Caller-owned storage for one type-A channel mode list.
pub const ModeList = struct {
    entries: [][]const u8,
    count: usize = 0,

    pub fn init(storage: [][]const u8) ModeList {
        return .{ .entries = storage };
    }

    pub fn slice(self: *const ModeList) []const []const u8 {
        return self.entries[0..self.count];
    }

    pub fn contains(self: *const ModeList, entry: []const u8) bool {
        return self.indexOf(entry) != null;
    }

    fn add(self: *ModeList, entry: []const u8) ChanModeError!bool {
        if (self.contains(entry)) return false;
        if (self.count >= self.entries.len) return error.ListFull;
        self.entries[self.count] = entry;
        self.count += 1;
        return true;
    }

    fn remove(self: *ModeList, entry: []const u8) bool {
        const idx = self.indexOf(entry) orelse return false;
        if (idx + 1 < self.count) {
            std.mem.copyForwards([]const u8, self.entries[idx..], self.entries[idx + 1 .. self.count]);
        }
        self.count -= 1;
        return true;
    }

    fn indexOf(self: *const ModeList, entry: []const u8) ?usize {
        for (self.slice(), 0..) |candidate, idx| {
            if (std.mem.eql(u8, candidate, entry)) return idx;
        }
        return null;
    }
};

/// Compact channel mode state. List storage is supplied by the caller.
pub const ChannelModes = struct {
    bans: ModeList,
    exempts: ModeList,
    invexes: ModeList,
    key: ?[]const u8 = null,
    limit: ?ChannelLimit = null,
    invite_only: bool = false,
    moderated: bool = false,
    no_external: bool = false,
    topic_ops: bool = false,
    secret: bool = false,
    no_ctcp: bool = false,
    no_notice: bool = false,
    no_nick: bool = false,
    free_invite: bool = false,
    tls_only: bool = false,
    mod_reg: bool = false,
    news_wire: bool = false,
    oper_only: bool = false,
    admin_only: bool = false,

    pub fn init(
        ban_storage: [][]const u8,
        exempt_storage: [][]const u8,
        invex_storage: [][]const u8,
    ) ChannelModes {
        return .{
            .bans = ModeList.init(ban_storage),
            .exempts = ModeList.init(exempt_storage),
            .invexes = ModeList.init(invex_storage),
        };
    }

    pub fn empty() ChannelModes {
        return init(&.{}, &.{}, &.{});
    }

    pub fn containsFlag(self: *const ChannelModes, mode: ChannelMode) bool {
        return switch (mode) {
            .invite_only => self.invite_only,
            .moderated => self.moderated,
            .no_external => self.no_external,
            .topic_ops => self.topic_ops,
            .secret => self.secret,
            .no_ctcp => self.no_ctcp,
            .no_notice => self.no_notice,
            .no_nick => self.no_nick,
            .free_invite => self.free_invite,
            .tls_only => self.tls_only,
            .mod_reg => self.mod_reg,
            .news_wire => self.news_wire,
            .oper_only => self.oper_only,
            .admin_only => self.admin_only,
            else => false,
        };
    }

    fn listFor(self: *ChannelModes, mode: ChannelMode) ?*ModeList {
        return switch (mode) {
            .ban => &self.bans,
            .exempt => &self.exempts,
            .invex => &self.invexes,
            else => null,
        };
    }

    fn listForConst(self: *const ChannelModes, mode: ChannelMode) ?*const ModeList {
        return switch (mode) {
            .ban => &self.bans,
            .exempt => &self.exempts,
            .invex => &self.invexes,
            else => null,
        };
    }

    fn setFlag(self: *ChannelModes, mode: ChannelMode, enabled: bool) bool {
        const slot = switch (mode) {
            .invite_only => &self.invite_only,
            .moderated => &self.moderated,
            .no_external => &self.no_external,
            .topic_ops => &self.topic_ops,
            .secret => &self.secret,
            .no_ctcp => &self.no_ctcp,
            .no_notice => &self.no_notice,
            .no_nick => &self.no_nick,
            .free_invite => &self.free_invite,
            .tls_only => &self.tls_only,
            .mod_reg => &self.mod_reg,
            .news_wire => &self.news_wire,
            .oper_only => &self.oper_only,
            .admin_only => &self.admin_only,
            else => return false,
        };
        if (slot.* == enabled) return false;
        slot.* = enabled;
        return true;
    }
};

/// Stable member prefix mode identifiers. Builds on the IRCX draft and
/// adds an Onyx Server-native FOUNDER tier above owner:
///   founder +Q ('!') > owner +q ('.') > op +o ('@') > voice +v ('+')
/// → ISUPPORT PREFIX=(Qqov)!.@+. The channel creator is the founder (a single
/// top authority that ops/owners cannot strip). No halfop tier (IRCX `+h` is the
/// HIDDEN channel mode); IRCX ADMIN aliases OWNER (+q), not a separate wire mode.
pub const MemberMode = enum(u3) {
    voice,
    op,
    owner,
    founder,
};

/// Network-operator status prefix, shown above founder for an IRC operator who
/// holds the `oper_override` privilege. It is derived from oper status (not a
/// grantable channel mode), so it is never stored in the per-member status —
/// the render layer prepends it. Advertised in ISUPPORT PREFIX as `(Y…)*…`.
pub const oper_prefix: u8 = '*';
pub const oper_mode_letter: u8 = 'Y';

/// Inline prefix list returned by MemberModes.allPrefixes(). Sized for the four
/// grantable tiers (!.@+) plus a possible leading oper `*`.
pub const PrefixList = struct {
    bytes: [5]u8 = @splat(0),
    len: u8 = 0,

    pub fn asSlice(self: *const PrefixList) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Prepend the network-operator `*` as the new highest prefix (no-op if the
    /// member already shows it or the buffer is full).
    pub fn prependOper(self: *PrefixList) void {
        if (self.len >= self.bytes.len) return;
        if (self.len > 0 and self.bytes[0] == oper_prefix) return;
        var i: usize = self.len;
        while (i > 0) : (i -= 1) self.bytes[i] = self.bytes[i - 1];
        self.bytes[0] = oper_prefix;
        self.len += 1;
    }
};

/// Bitset for per-member channel prefix modes.
pub const MemberModes = struct {
    bits: u8 = 0,

    pub fn empty() MemberModes {
        return .{};
    }

    pub fn fromModes(modes: []const MemberMode) MemberModes {
        var set = MemberModes.empty();
        for (modes) |mode| set.add(mode);
        return set;
    }

    pub fn add(self: *MemberModes, mode: MemberMode) void {
        self.bits |= memberBit(mode);
    }

    pub fn remove(self: *MemberModes, mode: MemberMode) void {
        self.bits &= ~memberBit(mode);
    }

    pub fn contains(self: MemberModes, mode: MemberMode) bool {
        return (self.bits & memberBit(mode)) != 0;
    }

    pub fn highestPrefix(self: MemberModes) u8 {
        if (self.contains(.founder)) return '!';
        if (self.contains(.owner)) return '.';
        if (self.contains(.op)) return '@';
        if (self.contains(.voice)) return '+';
        return 0;
    }

    pub fn allPrefixes(self: MemberModes) PrefixList {
        var out = PrefixList{};
        if (self.contains(.founder)) appendPrefix(&out, '!');
        if (self.contains(.owner)) appendPrefix(&out, '.');
        if (self.contains(.op)) appendPrefix(&out, '@');
        if (self.contains(.voice)) appendPrefix(&out, '+');
        return out;
    }

    /// ISUPPORT PREFIX token: (YQqov)*!.@+ — network-operator (*) above Onyx Server
    /// founder (!), then the IRCX owner (.) / op (@) / voice (+) tiers. The `*`
    /// tier is server-derived from the oper_override privilege (never set by
    /// MODE); clients use it only to render the prefix in NAMES/WHO. This is the
    /// single source of truth for the advertised PREFIX (the daemon's ISUPPORT
    /// builder derives the 005 token from it — no duplicated copy elsewhere).
    pub const isupport_prefix = "(YQqov)*!.@+";

    /// ISUPPORT STATUSMSG symbols: the grantable status prefixes usable as
    /// message targets (founder ! / owner . / op @ / voice +), highest first.
    /// The derived oper `*` is intentionally excluded — it is not a message
    /// target. Derived once here so PREFIX and STATUSMSG never drift apart.
    pub const statusmsg_symbols = "!.@+";

    /// Operator authority: op or any higher tier (owner/founder).
    pub fn isOperator(self: MemberModes) bool {
        return self.contains(.op) or self.contains(.owner) or self.contains(.founder);
    }

    /// May speak in a +m moderated channel: voice or any operator tier.
    pub fn canSpeakModerated(self: MemberModes) bool {
        return self.contains(.voice) or self.isOperator();
    }

    /// Authority rank of the highest tier held: founder 4 > owner 3 > op 2 >
    /// voice 1 > none 0. Used to gate member-mode changes.
    pub fn rank(self: MemberModes) u8 {
        if (self.contains(.founder)) return 4;
        if (self.contains(.owner)) return 3;
        if (self.contains(.op)) return 2;
        if (self.contains(.voice)) return 1;
        return 0;
    }
};

/// Authority rank of a single member tier (founder 4 .. voice 1). A member may
/// only set/clear a tier whose rank is <= their own highest rank.
pub fn rankOfMode(mode: MemberMode) u8 {
    return switch (mode) {
        .founder => 4,
        .owner => 3,
        .op => 2,
        .voice => 1,
    };
}

/// One concrete tier change produced by `cascadeStatusOps`.
pub const TierOp = struct { mode: MemberMode, on: bool };

/// Expand a single named status MODE change into the ordered set of concrete
/// tier ops realizing a cumulative-authority tier hierarchy: the chain
/// founder > owner > op means a tier carries every authority below it, so a
/// member occupies exactly ONE chain level (Onyx Server stores the single highest
/// tier — the creator holds founder alone, `world.zig`). Voice is independent.
///
///   ADD `+X` (X ∈ owner/op; `+Q` is creation-only and rejected by the caller):
///     the member's chain level becomes exactly X — set X, clear any other chain
///     tier (promote a lower member, demote a higher one).
///   DEL `-X` (X ∈ founder/owner/op): clear X and every tier above it that is
///     held; then — unless a tier was stripped and X is the chain floor (op) —
///     set the tier directly below X so the member lands one rank down. So
///     `-Q` demotes founder→owner, `-q` demotes →op, and `-o` strips the chain
///     entirely. A `-X` that finds nothing at/above X is a no-op.
///
/// Ops are written high→low (founder, owner, op) so the wire echo reads
/// naturally. Returns the count written into `out` (0 = no change). The caller
/// still applies its own authority/rank checks against the highest tier touched.
pub fn cascadeStatusOps(current: MemberModes, named: MemberMode, adding: bool, out: *[3]TierOp) usize {
    // Voice sits outside the authority chain — a plain independent toggle.
    if (named == .voice) {
        if (current.contains(.voice) == adding) return 0;
        out[0] = .{ .mode = .voice, .on = adding };
        return 1;
    }
    const chain = [_]MemberMode{ .founder, .owner, .op };
    const named_rank = rankOfMode(named);
    var n: usize = 0;
    if (adding) {
        // Single-tier: the member's chain level becomes exactly `named`.
        for (chain) |t| {
            const desired = (t == named);
            if (current.contains(t) != desired) {
                out[n] = .{ .mode = t, .on = desired };
                n += 1;
            }
        }
    } else {
        // Clear the named tier and every tier above it that is currently held.
        var stripped = false;
        for (chain) |t| {
            if (rankOfMode(t) >= named_rank and current.contains(t)) {
                out[n] = .{ .mode = t, .on = false };
                n += 1;
                stripped = true;
            }
        }
        // Land one rank down: set the tier directly below `named` (founder→owner,
        // owner→op). `-o` is the chain floor and strips to nothing.
        if (stripped and named != .op) {
            const below: MemberMode = if (named == .founder) .owner else .op;
            if (!current.contains(below)) {
                out[n] = .{ .mode = below, .on = true };
                n += 1;
            }
        }
    }
    return n;
}

/// Apply a MODE change string plus parameter vector to channel state.
pub fn apply(
    modes: *ChannelModes,
    mode_string: []const u8,
    params: []const []const u8,
    out: []AppliedChange,
) ChanModeError![]const AppliedChange {
    const parsed = try parse(mode_string, params, out);
    return applyParsed(modes, parsed, out);
}

/// Parse a channel MODE change string into caller-owned storage.
pub fn parse(
    mode_string: []const u8,
    params: []const []const u8,
    out: []AppliedChange,
) ChanModeError![]const AppliedChange {
    if (mode_string.len == 0) return error.EmptyModeString;

    var op: ?ModeOp = null;
    var param_index: usize = 0;
    var count: usize = 0;

    for (mode_string) |ch| {
        switch (ch) {
            '+' => op = .add,
            '-' => op = .remove,
            else => {
                const active_op = op orelse return error.MissingOperation;
                const spec = specFromLetter(ch) orelse return error.UnknownMode;
                if (count >= out.len) return error.TooManyChanges;

                const param = try consumeParam(spec, active_op, params, &param_index);
                out[count] = .{ .op = active_op, .mode = spec.mode, .param = param };
                count += 1;
            },
        }
    }

    return out[0..count];
}

/// Apply already parsed changes and compact `out` to only state-changing echoes.
pub fn applyParsed(
    modes: *ChannelModes,
    changes: []const AppliedChange,
    out: []AppliedChange,
) ChanModeError![]const AppliedChange {
    var count: usize = 0;
    for (changes) |change| {
        if (try applyOne(modes, change)) {
            if (count >= out.len) return error.TooManyChanges;
            out[count] = change;
            count += 1;
        }
    }
    return out[0..count];
}

/// Serialize the current channel state in canonical catalog order.
pub fn writeModeString(
    modes: *const ChannelModes,
    mode_out: []u8,
    params_out: [][]const u8,
) ChanModeError!SerializedModes {
    var writer = ModeWriter.init(mode_out, params_out);

    for (default_specs) |spec| {
        switch (spec.kind) {
            .list_a => {
                const list = modes.listForConst(spec.mode).?;
                for (list.slice()) |entry| try writer.append(.add, spec.mode, entry);
            },
            .param_b => {
                if (modes.key) |key| try writer.append(.add, .key, key);
            },
            .param_c => {
                if (modes.limit) |limit| try writer.append(.add, .limit, limit.text);
            },
            .flag_d => {
                if (modes.containsFlag(spec.mode)) try writer.append(.add, spec.mode, null);
            },
        }
    }

    return writer.finish();
}

/// Serialize applied changes for a MODE echo, preserving operation order.
pub fn writeAppliedChanges(
    changes: []const AppliedChange,
    mode_out: []u8,
    params_out: [][]const u8,
) ChanModeError!SerializedModes {
    var writer = ModeWriter.init(mode_out, params_out);
    for (changes) |change| try writer.append(change.op, change.mode, change.param);
    return writer.finish();
}

pub fn specFromLetter(letter: u8) ?ModeSpec {
    for (default_specs) |spec| {
        if (spec.letter == letter) return spec;
    }
    return null;
}

pub fn letterOf(mode: ChannelMode) u8 {
    return switch (mode) {
        .ban => 'b',
        .exempt => 'e',
        .invex => 'I',
        .key => 'k',
        .limit => 'l',
        .invite_only => 'i',
        .moderated => 'm',
        .no_external => 'n',
        .topic_ops => 't',
        .secret => 's',
        .no_ctcp => 'C',
        .no_notice => 'T',
        .no_nick => 'N',
        .free_invite => 'g',
        .tls_only => 'S',
        .mod_reg => 'M',
        .news_wire => 'W',
        .oper_only => 'O',
        .admin_only => 'A',
    };
}

pub fn validateModeLetter(letter: u8) ChanModeError!void {
    if (specFromLetter(letter) == null) return error.InvalidModeLetter;
}

pub fn validateListEntry(entry: []const u8) ChanModeError!void {
    if (entry.len == 0) return error.InvalidListEntry;
    if (entry.len > DEFAULT_MAX_LIST_ENTRY_BYTES) return error.ListEntryTooLong;
    for (entry) |ch| {
        if (!validParamByte(ch)) return error.InvalidListEntry;
    }
}

pub fn validateKey(key: []const u8) ChanModeError!void {
    if (key.len == 0) return error.InvalidKey;
    if (key.len > DEFAULT_MAX_KEY_BYTES) return error.KeyTooLong;
    for (key) |ch| {
        if (!validParamByte(ch)) return error.InvalidKey;
    }
}

pub fn parseLimit(bytes: []const u8) ChanModeError!u64 {
    if (bytes.len == 0) return error.InvalidLimit;
    for (bytes) |ch| {
        if (ch < '0' or ch > '9') return error.InvalidLimit;
    }
    const value = std.fmt.parseUnsigned(u64, bytes, 10) catch return error.LimitOutOfRange;
    if (value == 0) return error.InvalidLimit;
    return value;
}

fn consumeParam(
    spec: ModeSpec,
    op: ModeOp,
    params: []const []const u8,
    param_index: *usize,
) ChanModeError!?[]const u8 {
    const needs_param = switch (spec.kind) {
        .list_a, .param_b => true,
        .param_c => op == .add,
        .flag_d => false,
    };
    if (!needs_param) return null;
    if (param_index.* >= params.len) return error.MissingParameter;

    const param = params[param_index.*];
    param_index.* += 1;

    switch (spec.kind) {
        .list_a => try validateListEntry(param),
        .param_b => try validateKey(param),
        .param_c => _ = try parseLimit(param),
        .flag_d => {},
    }
    return param;
}

fn applyOne(modes: *ChannelModes, change: AppliedChange) ChanModeError!bool {
    switch (change.mode) {
        .ban, .exempt, .invex => {
            const entry = change.param orelse return error.MissingParameter;
            const list = modes.listFor(change.mode).?;
            return switch (change.op) {
                .add => try list.add(entry),
                .remove => list.remove(entry),
            };
        },
        .key => {
            const key = change.param orelse return error.MissingParameter;
            switch (change.op) {
                .add => {
                    if (modes.key) |current| {
                        if (std.mem.eql(u8, current, key)) return false;
                    }
                    modes.key = key;
                    return true;
                },
                .remove => {
                    if (modes.key == null) return false;
                    modes.key = null;
                    return true;
                },
            }
        },
        .limit => switch (change.op) {
            .add => {
                const param = change.param orelse return error.MissingParameter;
                const limit = try parseLimit(param);
                if (modes.limit != null and modes.limit.?.value == limit) return false;
                modes.limit = .{ .value = limit, .text = param };
                return true;
            },
            .remove => {
                if (modes.limit == null) return false;
                modes.limit = null;
                return true;
            },
        },
        .invite_only, .moderated, .no_external, .topic_ops, .secret, .no_ctcp, .no_notice, .no_nick, .free_invite, .tls_only, .mod_reg, .news_wire, .oper_only, .admin_only => {
            return modes.setFlag(change.mode, change.op == .add);
        },
    }
}

const ModeWriter = struct {
    mode_out: []u8,
    params_out: [][]const u8,
    mode_len: usize = 0,
    param_len: usize = 0,
    op: ?ModeOp = null,

    fn init(mode_out: []u8, params_out: [][]const u8) ModeWriter {
        return .{ .mode_out = mode_out, .params_out = params_out };
    }

    fn append(self: *ModeWriter, op: ModeOp, mode: ChannelMode, param: ?[]const u8) ChanModeError!void {
        if (self.op == null or self.op.? != op) {
            try self.appendByte(switch (op) {
                .add => '+',
                .remove => '-',
            });
            self.op = op;
        }
        try self.appendByte(letterOf(mode));
        if (param) |value| {
            if (self.param_len >= self.params_out.len) return error.TooManyParams;
            self.params_out[self.param_len] = value;
            self.param_len += 1;
        }
    }

    fn finish(self: *ModeWriter) SerializedModes {
        return .{
            .mode_string = self.mode_out[0..self.mode_len],
            .params = self.params_out[0..self.param_len],
        };
    }

    fn appendByte(self: *ModeWriter, byte: u8) ChanModeError!void {
        if (self.mode_len >= self.mode_out.len) return error.OutputTooSmall;
        self.mode_out[self.mode_len] = byte;
        self.mode_len += 1;
    }
};

fn appendPrefix(out: *PrefixList, prefix: u8) void {
    if (out.len >= out.bytes.len) return;
    out.bytes[out.len] = prefix;
    out.len += 1;
}

fn memberBit(mode: MemberMode) u8 {
    return @as(u8, 1) << @as(u3, @intCast(@backingInt(mode)));
}

/// The channel-mode letter that grants `mode` (the `(YQqov)` set, minus the
/// derived oper `Y`). Used to render a MODE line for a member's prefix.
pub fn memberModeLetter(mode: MemberMode) u8 {
    return switch (mode) {
        .founder => 'Q',
        .owner => 'q',
        .op => 'o',
        .voice => 'v',
    };
}

fn validParamByte(ch: u8) bool {
    return switch (ch) {
        0, ' ', '\t', '\r', '\n' => false,
        else => true,
    };
}

test "parse apply and echo mixed channel modes" {
    var bans: [4][]const u8 = undefined;
    var exempts: [2][]const u8 = undefined;
    var invexes: [2][]const u8 = undefined;
    var modes = ChannelModes.init(&bans, &exempts, &invexes);

    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;
    const applied = try apply(&modes, "+ntk", &.{"sekret"}, &changes_buf);
    try std.testing.expectEqual(@as(usize, 3), applied.len);
    try std.testing.expect(modes.no_external);
    try std.testing.expect(modes.topic_ops);
    try std.testing.expectEqualStrings("sekret", modes.key.?);

    var mode_buf: [16]u8 = undefined;
    var param_buf: [4][]const u8 = undefined;
    const echo = try writeAppliedChanges(applied, &mode_buf, &param_buf);
    try std.testing.expectEqualStrings("+ntk", echo.mode_string);
    try std.testing.expectEqual(@as(usize, 1), echo.params.len);
    try std.testing.expectEqualStrings("sekret", echo.params[0]);
}

test "parse serialize round-trip with params and flags" {
    var bans: [4][]const u8 = undefined;
    var exempts: [2][]const u8 = undefined;
    var invexes: [2][]const u8 = undefined;
    var modes = ChannelModes.init(&bans, &exempts, &invexes);

    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;
    _ = try apply(&modes, "+ntkl", &.{ "sekret", "42" }, &changes_buf);

    var mode_buf: [32]u8 = undefined;
    var param_buf: [8][]const u8 = undefined;
    const serialized = try writeModeString(&modes, &mode_buf, &param_buf);
    try std.testing.expectEqualStrings("+klnt", serialized.mode_string);
    try std.testing.expectEqual(@as(usize, 2), serialized.params.len);
    try std.testing.expectEqualStrings("sekret", serialized.params[0]);
    try std.testing.expectEqualStrings("42", serialized.params[1]);

    var round_bans: [4][]const u8 = undefined;
    var round_exempts: [2][]const u8 = undefined;
    var round_invexes: [2][]const u8 = undefined;
    var round_trip = ChannelModes.init(&round_bans, &round_exempts, &round_invexes);
    _ = try apply(&round_trip, serialized.mode_string, serialized.params, &changes_buf);
    try std.testing.expect(round_trip.no_external);
    try std.testing.expect(round_trip.topic_ops);
    try std.testing.expectEqualStrings("sekret", round_trip.key.?);
    try std.testing.expectEqual(@as(u64, 42), round_trip.limit.?.value);
    try std.testing.expectEqualStrings("42", round_trip.limit.?.text);
}

test "list add remove and serializer include caller-owned entries" {
    var bans: [4][]const u8 = undefined;
    var exempts: [2][]const u8 = undefined;
    var invexes: [2][]const u8 = undefined;
    var modes = ChannelModes.init(&bans, &exempts, &invexes);

    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;
    const added = try apply(&modes, "+beI", &.{ "*!*@bad.example", "quiet!*@*", "invite!*@*" }, &changes_buf);
    try std.testing.expectEqual(@as(usize, 3), added.len);
    try std.testing.expect(modes.bans.contains("*!*@bad.example"));
    try std.testing.expect(modes.exempts.contains("quiet!*@*"));
    try std.testing.expect(modes.invexes.contains("invite!*@*"));

    const duplicate = try apply(&modes, "+b", &.{"*!*@bad.example"}, &changes_buf);
    try std.testing.expectEqual(@as(usize, 0), duplicate.len);

    const removed = try apply(&modes, "-e", &.{"quiet!*@*"}, &changes_buf);
    try std.testing.expectEqual(@as(usize, 1), removed.len);
    try std.testing.expect(!modes.exempts.contains("quiet!*@*"));

    var mode_buf: [32]u8 = undefined;
    var param_buf: [8][]const u8 = undefined;
    const serialized = try writeModeString(&modes, &mode_buf, &param_buf);
    try std.testing.expectEqualStrings("+bI", serialized.mode_string);
    try std.testing.expectEqualStrings("*!*@bad.example", serialized.params[0]);
    try std.testing.expectEqualStrings("invite!*@*", serialized.params[1]);
}

test "type b and c parameter removal semantics" {
    var modes = ChannelModes.empty();
    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;

    _ = try apply(&modes, "+kl", &.{ "sekret", "10" }, &changes_buf);
    try std.testing.expectEqualStrings("sekret", modes.key.?);
    try std.testing.expectEqual(@as(u64, 10), modes.limit.?.value);

    try std.testing.expectError(error.MissingParameter, parse("-k", &.{}, &changes_buf));
    const removed = try apply(&modes, "-kl", &.{"sekret"}, &changes_buf);
    try std.testing.expectEqual(@as(usize, 2), removed.len);
    try std.testing.expectEqual(@as(?[]const u8, null), modes.key);
    try std.testing.expectEqual(@as(?ChannelLimit, null), modes.limit);
}

test "member prefix ranking and multi-prefix list" {
    var member = MemberModes.empty();
    try std.testing.expectEqual(@as(u8, 0), member.highestPrefix());
    try std.testing.expectEqualStrings("", member.allPrefixes().asSlice());

    member.add(.voice);
    try std.testing.expectEqual(@as(u8, '+'), member.highestPrefix());
    try std.testing.expectEqualStrings("+", member.allPrefixes().asSlice());

    member.add(.op);
    try std.testing.expectEqual(@as(u8, '@'), member.highestPrefix());
    try std.testing.expectEqualStrings("@+", member.allPrefixes().asSlice());

    member.add(.owner);
    try std.testing.expectEqual(@as(u8, '.'), member.highestPrefix());
    try std.testing.expectEqualStrings(".@+", member.allPrefixes().asSlice());

    member.add(.founder);
    try std.testing.expectEqual(@as(u8, '!'), member.highestPrefix());
    try std.testing.expectEqualStrings("!.@+", member.allPrefixes().asSlice());

    member.remove(.op);
    try std.testing.expectEqual(@as(u8, '!'), member.highestPrefix());
    try std.testing.expectEqualStrings("!.+", member.allPrefixes().asSlice());
}

test "invalid input rejected before channel mutation" {
    var modes = ChannelModes.empty();
    modes.no_external = true;

    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;
    try std.testing.expectError(error.EmptyModeString, apply(&modes, "", &.{}, &changes_buf));
    try std.testing.expectError(error.MissingOperation, apply(&modes, "nt", &.{}, &changes_buf));
    try std.testing.expectError(error.UnknownMode, apply(&modes, "+w", &.{}, &changes_buf));
    try std.testing.expectError(error.MissingParameter, apply(&modes, "+k", &.{}, &changes_buf));
    try std.testing.expectError(error.InvalidKey, apply(&modes, "+k", &.{"bad key"}, &changes_buf));
    try std.testing.expectError(error.InvalidLimit, apply(&modes, "+l", &.{"0"}, &changes_buf));
    try std.testing.expectError(error.InvalidLimit, apply(&modes, "+l", &.{"12x"}, &changes_buf));
    try std.testing.expectError(error.InvalidListEntry, apply(&modes, "+b", &.{"bad mask"}, &changes_buf));
    try std.testing.expect(modes.no_external);
    try std.testing.expectEqual(@as(?[]const u8, null), modes.key);
    try std.testing.expectEqual(@as(?ChannelLimit, null), modes.limit);
}

test "bounded output and list storage" {
    var bans: [1][]const u8 = undefined;
    var modes = ChannelModes.init(&bans, &.{}, &.{});
    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;

    _ = try apply(&modes, "+b", &.{"a!*@*"}, &changes_buf);
    try std.testing.expectError(error.ListFull, apply(&modes, "+b", &.{"b!*@*"}, &changes_buf));

    var mode_buf: [1]u8 = undefined;
    var param_buf: [8][]const u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, writeModeString(&modes, &mode_buf, &param_buf));

    var enough_modes: [8]u8 = undefined;
    var no_params: [0][]const u8 = undefined;
    try std.testing.expectError(error.TooManyParams, writeModeString(&modes, &enough_modes, &no_params));

    var tiny_changes: [1]AppliedChange = undefined;
    try std.testing.expectError(error.TooManyChanges, parse("+nt", &.{}, &tiny_changes));
}

test "member tier rank ordering gates privilege (founder>owner>op>voice)" {
    try std.testing.expectEqual(@as(u8, 0), MemberModes.empty().rank());
    try std.testing.expectEqual(@as(u8, 1), MemberModes.fromModes(&.{.voice}).rank());
    try std.testing.expectEqual(@as(u8, 2), MemberModes.fromModes(&.{.op}).rank());
    try std.testing.expectEqual(@as(u8, 3), MemberModes.fromModes(&.{.owner}).rank());
    try std.testing.expectEqual(@as(u8, 4), MemberModes.fromModes(&.{.founder}).rank());
    // rankOfMode mirrors the tier ranks used to gate +Q/+q/+o/+v.
    try std.testing.expectEqual(rankOfMode(.founder), MemberModes.fromModes(&.{.founder}).rank());
    try std.testing.expectEqual(rankOfMode(.owner), MemberModes.fromModes(&.{.owner}).rank());
    // An op (rank 2) cannot reach owner(3)/founder(4); an owner cannot reach founder.
    try std.testing.expect(MemberModes.fromModes(&.{.op}).rank() < rankOfMode(.owner));
    try std.testing.expect(MemberModes.fromModes(&.{.owner}).rank() < rankOfMode(.founder));
}

test "oper-only and admin-only channel modes round-trip" {
    var modes = ChannelModes.empty();
    var changes_buf: [MAX_SERIALIZED_MODES]AppliedChange = undefined;

    const applied = try apply(&modes, "+OA", &.{}, &changes_buf);
    try std.testing.expectEqual(@as(usize, 2), applied.len);
    try std.testing.expect(modes.oper_only);
    try std.testing.expect(modes.admin_only);

    var mode_buf: [16]u8 = undefined;
    var param_buf: [1][]const u8 = undefined;
    const serialized = try writeModeString(&modes, &mode_buf, &param_buf);
    try std.testing.expectEqualStrings("+OA", serialized.mode_string);
}

// --- cascadeStatusOps: cumulative-authority tier hierarchy ---------------------

/// Render the ops `cascadeStatusOps` produces as a wire-style mode string
/// (e.g. "-q+o") so the cumulative cascade is easy to assert in tests.
fn renderCascade(current: MemberModes, named: MemberMode, adding: bool, buf: []u8) []const u8 {
    var ops: [3]TierOp = undefined;
    const n = cascadeStatusOps(current, named, adding, &ops);
    var len: usize = 0;
    var sign: u8 = 0;
    for (ops[0..n]) |op| {
        const want: u8 = if (op.on) '+' else '-';
        if (sign != want) {
            buf[len] = want;
            len += 1;
            sign = want;
        }
        buf[len] = memberModeLetter(op.mode);
        len += 1;
    }
    return buf[0..len];
}

test "cascade: deop strips the higher tiers it carries" {
    var buf: [8]u8 = undefined;
    const founder = MemberModes.fromModes(&.{.founder});
    const owner = MemberModes.fromModes(&.{.owner});
    const op = MemberModes.fromModes(&.{.op});
    // -o on a founder removes the founder tier (its authority includes op).
    try std.testing.expectEqualStrings("-Q", renderCascade(founder, .op, false, &buf));
    // -o on an owner removes ownership.
    try std.testing.expectEqualStrings("-q", renderCascade(owner, .op, false, &buf));
    // -o on a plain op just removes op.
    try std.testing.expectEqualStrings("-o", renderCascade(op, .op, false, &buf));
}

test "cascade: higher-tier removal demotes exactly one rank" {
    var buf: [8]u8 = undefined;
    const founder = MemberModes.fromModes(&.{.founder});
    const owner = MemberModes.fromModes(&.{.owner});
    // -Q on a founder lands them at owner.
    try std.testing.expectEqualStrings("-Q+q", renderCascade(founder, .founder, false, &buf));
    // -q on an owner lands them at op.
    try std.testing.expectEqualStrings("-q+o", renderCascade(owner, .owner, false, &buf));
    // -q on a founder strips owner-and-above, leaving op.
    try std.testing.expectEqualStrings("-Q+o", renderCascade(founder, .owner, false, &buf));
}

test "cascade: promotion moves the single tier" {
    var buf: [8]u8 = undefined;
    const none = MemberModes.empty();
    const op = MemberModes.fromModes(&.{.op});
    const owner = MemberModes.fromModes(&.{.owner});
    // +q on a plain member grants owner.
    try std.testing.expectEqualStrings("+q", renderCascade(none, .owner, true, &buf));
    // +q on an op promotes op→owner (clears the op tier).
    try std.testing.expectEqualStrings("+q-o", renderCascade(op, .owner, true, &buf));
    // +o on an owner demotes owner→op.
    try std.testing.expectEqualStrings("-q+o", renderCascade(owner, .op, true, &buf));
}

test "cascade: no-op and independent voice" {
    var buf: [8]u8 = undefined;
    const owner = MemberModes.fromModes(&.{.owner});
    const op = MemberModes.fromModes(&.{.op});
    // -Q on a non-founder changes nothing.
    try std.testing.expectEqualStrings("", renderCascade(op, .founder, false, &buf));
    // +q on someone already owner is a no-op.
    try std.testing.expectEqualStrings("", renderCascade(owner, .owner, true, &buf));
    // Voice is independent of the authority chain.
    try std.testing.expectEqualStrings("+v", renderCascade(owner, .voice, true, &buf));
    try std.testing.expectEqualStrings("-v", renderCascade(MemberModes.fromModes(&.{ .owner, .voice }), .voice, false, &buf));
}

test "cascade: required rank is the highest tier touched" {
    var ops: [3]TierOp = undefined;
    const founder = MemberModes.fromModes(&.{.founder});
    // -o on a founder must require founder-level authority, not op-level.
    const n = cascadeStatusOps(founder, .op, false, &ops);
    var required: u8 = 0;
    for (ops[0..n]) |op| required = @max(required, rankOfMode(op.mode));
    try std.testing.expectEqual(@as(u8, 4), required);
}

test "cascade: voice additions removals and redundant toggles emit only actual changes" {
    const chain_states = [_]MemberModes{
        MemberModes.empty(),
        MemberModes.fromModes(&.{.op}),
        MemberModes.fromModes(&.{.owner}),
        MemberModes.fromModes(&.{.founder}),
    };
    for (chain_states) |chain| {
        var voiced = chain;
        voiced.add(.voice);
        for ([_]bool{ false, true }) |adding| {
            for ([_]MemberModes{ chain, voiced }) |current| {
                const sentinel: TierOp = .{ .mode = .founder, .on = false };
                var out: [3]TierOp = @splat(sentinel);
                const expected: usize = if (current.contains(.voice) == adding) 0 else 1;
                try std.testing.expectEqual(expected, cascadeStatusOps(current, .voice, adding, &out));
                if (expected == 1) {
                    try std.testing.expectEqual(MemberMode.voice, out[0].mode);
                    try std.testing.expectEqual(adding, out[0].on);
                } else try std.testing.expectEqual(sentinel, out[0]);
                try std.testing.expectEqual(sentinel, out[1]);
                try std.testing.expectEqual(sentinel, out[2]);
            }
        }
    }
}
