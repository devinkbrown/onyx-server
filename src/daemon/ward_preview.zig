// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Warden impact preview — `WARD PREVIEW <match> <pattern> [scope] [action]
//! [secs] [:reason] [-- subject...]`.
//!
//! An operator checks a proposed Ward against representative subjects before
//! committing it. The preview applies exactly the rejections `WARD ADD` would
//! give, computes the expiry with the same formula, and evaluates each subject
//! with the registry's own per-ward predicate (`warden.matchesFacets`) and the
//! live enforcement effects (opers exempt, `require_auth` passes authenticated
//! subjects). It is strictly read-only: it never stores, relays, enforces, or
//! consumes a two-person approval.
//!
//! Subjects come from two places. Synthetic subjects follow `--` as
//! `facet=value[,facet=value...]` tokens. Live subjects come from an optional
//! server hook `wardPreviewLiveSubjects(self, *Accumulator)`, detected with
//! `@hasDecl`; without it the preview says live sampling is unavailable rather
//! than reporting a misleading zero. Pure and allocation-free: rows copy a
//! bounded, sanitized label, and totals count every subject even when rows are
//! truncated.
//!
//! Live sampling is a private-information read: it enumerates every live
//! client (including invisible ones) and tests facets only `oper_spy` may see
//! (real address, GeoIP country/ASN, certfp, cloak continuity). It therefore
//! runs only when the caller also holds `oper_spy`, and only after an
//! oper-audit record is written. Otherwise no live subject is evaluated or
//! counted, and the preview says why. Synthetic-only previews reveal nothing
//! beyond the operator's own input (like `WARD TEST`) and are not audited.

const std = @import("std");
const warden = @import("warden.zig");
const wildcard_limit = @import("../proto/wildcard_limit.zig");

/// Rows retained for display; totals still cover every evaluated subject.
pub const max_rows: usize = 16;
/// Synthetic subjects accepted after `--`. More is a parse error, not a cut.
pub const max_synthetic: usize = 16;
/// Display bytes kept per row label (truncated on a UTF-8 boundary).
pub const max_label: usize = 64;
/// Display bytes kept when echoing the proposed pattern.
pub const max_pattern_echo: usize = 256;

pub const Proposal = struct {
    match: warden.Match,
    pattern: []const u8,
    scope: warden.Scope = .node,
    action: warden.Action = .expel,
    secs: i64 = 0,
    reason: []const u8 = "No reason",
};

/// Every refusal `WARD ADD` can give for a proposal, in ADD's check order.
pub const Rejection = error{
    TooBroad,
    InvalidCidr,
    EmptyPattern,
    PatternTooLong,
    ReasonTooLong,
    RegistryFull,
};

/// The operator-facing text `WARD ADD` emits for the same refusal.
pub fn addMessage(err: Rejection) []const u8 {
    return switch (err) {
        error.TooBroad => "WARD: pattern too broad (needs more literal characters)",
        error.InvalidCidr => "WARD: invalid address CIDR (use e.g. 192.0.2.0/24 or 2001:db8::/32)",
        error.EmptyPattern, error.PatternTooLong, error.ReasonTooLong, error.RegistryFull => "WARD: could not add ward (limit or invalid input)",
    };
}

fn rejectionDetail(err: Rejection) []const u8 {
    return switch (err) {
        error.TooBroad => "too_broad",
        error.InvalidCidr => "invalid_cidr",
        error.EmptyPattern => "empty_pattern",
        error.PatternTooLong => "pattern_too_long",
        error.ReasonTooLong => "reason_too_long",
        error.RegistryFull => "registry_full",
    };
}

/// The proposal-only checks of `WARD ADD`, in its order: the over-broad glob
/// guard (non-address facets), the address CIDR create-time guard, then the
/// registry's string limits. Registry capacity is checked by `validateCapacity`.
pub fn validate(p: Proposal, params: warden.Params) Rejection!void {
    if (p.match != .address and wildcard_limit.isTooBroad(p.pattern, wildcard_limit.Policy.channel_ban)) return error.TooBroad;
    if (!warden.addressPatternValid(p.match, p.pattern)) return error.InvalidCidr;
    if (p.pattern.len == 0) return error.EmptyPattern;
    if (p.pattern.len > params.max_pattern) return error.PatternTooLong;
    if (p.reason.len > params.max_reason) return error.ReasonTooLong;
}

/// `Registry.add` replaces an existing (match, pattern) in place and only then
/// enforces `max_wards`; mirror that without pruning (ADD does not prune).
pub fn validateCapacity(registry: *const warden.Registry, p: Proposal) Rejection!void {
    if (registry.find(p.match, p.pattern) != null) return;
    if (registry.count() >= registry.params.max_wards) return error.RegistryFull;
}

pub const Expiry = struct {
    /// Absolute wall-clock expiry ADD would store; 0 is permanent.
    expires_ms: i64,
    permanent: bool,
    /// The ward would already be expired at creation and so never fire.
    expired: bool,
};

/// Expiry exactly as `WARD ADD` stamps it (`warden.expiryMs`) plus whether the
/// stored ward would already be expired at `now_ms`.
pub fn expiresMs(now_ms: i64, secs: i64) Expiry {
    const at = warden.expiryMs(now_ms, secs);
    const probe = warden.Ward{ .match = .host, .pattern = "", .expires_ms = at };
    return .{ .expires_ms = at, .permanent = at == 0, .expired = probe.isExpired(now_ms) };
}

pub const Source = enum {
    synthetic,
    live,

    pub fn token(self: Source) []const u8 {
        return switch (self) {
            .synthetic => "synthetic",
            .live => "live",
        };
    }
};

/// A subject presented to the preview. Facets borrow caller memory only for
/// the duration of `Accumulator.add`.
pub const Subject = struct {
    label: []const u8,
    facets: warden.Facets,
    source: Source = .synthetic,
    /// Opers are never warded off (registration checkpoint and live sweep).
    oper: bool = false,
    /// Set by the server when the previous-key or ban-cloak host continuity
    /// path would match this candidate. Honoured only for host/mask wards.
    continuity_hit: bool = false,
};

/// What adding the ward would do to one subject right now.
pub const Effect = enum {
    none,
    /// Pattern matches but the ward is expired at creation and never fires.
    inert,
    /// Pattern matches an oper, who is exempt.
    exempt,
    /// `require_auth` matches an authenticated subject, who passes.
    auth_pass,
    quarantine,
    /// refuse/expel, or `require_auth` on an unauthenticated subject.
    close,

    pub fn token(self: Effect) []const u8 {
        return switch (self) {
            .none => "none",
            .inert => "inert",
            .exempt => "exempt",
            .auth_pass => "auth_pass",
            .quarantine => "quarantine",
            .close => "close",
        };
    }
};

pub const Row = struct {
    label_buf: [max_label]u8 = undefined,
    label_len: usize = 0,
    source: Source = .synthetic,
    matches: bool = false,
    effect: Effect = .none,

    pub fn label(self: *const Row) []const u8 {
        return self.label_buf[0..self.label_len];
    }
};

pub const Counts = struct {
    total: usize = 0,
    matched: usize = 0,
    inert: usize = 0,
    exempt: usize = 0,
    auth_pass: usize = 0,
    quarantine: usize = 0,
    close: usize = 0,
};

pub const Preview = struct {
    expiry: Expiry,
    requires_two_person: bool,
    counts: Counts,
    rows: []const Row,

    pub fn hidden(self: Preview) usize {
        return self.counts.total - self.rows.len;
    }
};

/// Streams subjects against one validated proposal. Construction validates,
/// so an invalid rule can never be evaluated.
pub const Accumulator = struct {
    proposal: Proposal,
    expiry: Expiry,
    rows: []Row,
    shown: usize = 0,
    counts: Counts = .{},

    pub fn init(proposal: Proposal, params: warden.Params, now_ms: i64, rows: []Row) Rejection!Accumulator {
        try validate(proposal, params);
        return .{ .proposal = proposal, .expiry = expiresMs(now_ms, proposal.secs), .rows = rows };
    }

    pub fn add(self: *Accumulator, subject: Subject) Effect {
        const p = self.proposal;
        const continuity = subject.continuity_hit and (p.match == .host or p.match == .mask);
        const matches = continuity or warden.matchesFacets(p.match, p.pattern, subject.facets);
        const effect: Effect = if (!matches)
            .none
        else if (self.expiry.expired)
            .inert
        else if (subject.oper)
            .exempt
        else switch (p.action) {
            .quarantine => .quarantine,
            .require_auth => if (subject.facets.account != null) .auth_pass else .close,
            .refuse, .expel => .close,
        };
        self.counts.total +|= 1;
        if (matches) self.counts.matched +|= 1;
        switch (effect) {
            .none => {},
            .inert => self.counts.inert +|= 1,
            .exempt => self.counts.exempt +|= 1,
            .auth_pass => self.counts.auth_pass +|= 1,
            .quarantine => self.counts.quarantine +|= 1,
            .close => self.counts.close +|= 1,
        }
        if (self.shown < self.rows.len) {
            const row = &self.rows[self.shown];
            row.* = .{ .source = subject.source, .matches = matches, .effect = effect };
            row.label_len = sanitizeInto(&row.label_buf, subject.label).len;
            self.shown += 1;
        }
        return effect;
    }

    pub fn preview(self: *const Accumulator) Preview {
        return .{
            .expiry = self.expiry,
            .requires_two_person = self.proposal.scope == .mesh,
            .counts = self.counts,
            .rows = self.rows[0..self.shown],
        };
    }
};

/// Pure evaluation over a subject slice (rows truncated to `out.len`).
pub fn evaluate(proposal: Proposal, params: warden.Params, now_ms: i64, subjects: []const Subject, out: []Row) Rejection!Preview {
    var acc = try Accumulator.init(proposal, params, now_ms, out);
    for (subjects) |s| _ = acc.add(s);
    return acc.preview();
}

/// Copy `text` into `buf` for display: control bytes become `?` (so a NOTICE
/// is never dropped by the CR/LF guard) and truncation backs off to a UTF-8
/// boundary.
pub fn sanitizeInto(buf: []u8, text: []const u8) []const u8 {
    var n = @min(buf.len, text.len);
    if (n < text.len) {
        while (n > 0 and (text[n] & 0xC0) == 0x80) n -= 1;
    }
    for (text[0..n], 0..) |c, i| buf[i] = if (c < 0x20 or c == 0x7f) '?' else c;
    return buf[0..n];
}

pub const ParseError = error{
    MissingPattern,
    UnknownMatch,
    UnexpectedToken,
    TooManySubjects,
    BadSubject,
};

pub const Parsed = struct {
    proposal: Proposal,
    subjects: []const Subject,
};

/// Parse `<match> <pattern> [scope] [action] [secs] [reason] [-- subject...]`
/// (the arguments after `PREVIEW`). Axis tokens follow ADD: any order, last
/// wins; the first non-axis token is the reason, which may only be followed by
/// `--`. Synthetic subjects borrow `args`.
pub fn parseArgs(args: []const []const u8, subject_buf: []Subject) ParseError!Parsed {
    if (args.len < 2) return error.MissingPattern;
    var proposal = Proposal{
        .match = warden.Match.parse(args[0]) orelse return error.UnknownMatch,
        .pattern = args[1],
    };
    var i: usize = 2;
    var have_reason = false;
    while (i < args.len and !std.mem.eql(u8, args[i], "--")) : (i += 1) {
        if (have_reason) return error.UnexpectedToken;
        if (warden.Scope.parse(args[i])) |s| {
            proposal.scope = s;
        } else if (warden.Action.parse(args[i])) |a| {
            proposal.action = a;
        } else if (std.fmt.parseInt(i64, args[i], 10)) |n| {
            proposal.secs = n;
        } else |_| {
            proposal.reason = args[i];
            have_reason = true;
        }
    }
    var n: usize = 0;
    if (i < args.len) {
        const tokens = args[i + 1 ..];
        if (tokens.len > @min(subject_buf.len, max_synthetic)) return error.TooManySubjects;
        for (tokens) |tok| {
            subject_buf[n] = try parseSubject(tok);
            n += 1;
        }
    }
    return .{ .proposal = proposal, .subjects = subject_buf[0..n] };
}

/// `facet=value[,facet=value...]`. Unknown, duplicate, or empty facets and
/// control bytes are rejected; nothing is guessed.
pub fn parseSubject(token: []const u8) ParseError!Subject {
    if (token.len == 0) return error.BadSubject;
    for (token) |c| if (c < 0x20 or c == 0x7f) return error.BadSubject;
    var facets = warden.Facets{};
    var seen: std.EnumSet(warden.Match) = .empty;
    var it = std.mem.splitScalar(u8, token, ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return error.BadSubject;
        const m = warden.Match.parse(pair[0..eq]) orelse return error.BadSubject;
        const value = pair[eq + 1 ..];
        if (value.len == 0 or seen.contains(m)) return error.BadSubject;
        seen.insert(m);
        switch (m) {
            .address => facets.address = value,
            .host => facets.host = value,
            .mask => facets.mask = value,
            .account => facets.account = value,
            .realname => facets.realname = value,
            .certfp => facets.certfp = value,
            .country => facets.country = value,
            .asn => facets.asn = value,
        }
    }
    return .{ .label = token, .facets = facets };
}

fn parseErrorText(err: ParseError) []const u8 {
    return switch (err) {
        error.MissingPattern => "Usage: WARD PREVIEW <match> <pattern> [scope] [action] [secs] [:reason] [-- facet=value[,facet=value]...]",
        error.UnknownMatch => "WARD: unknown match facet (address|host|mask|account|realname|certfp|country|asn)",
        error.UnexpectedToken => "WARD PREVIEW: unexpected token after reason (subjects follow --)",
        error.TooManySubjects => "WARD PREVIEW: too many synthetic subjects (max 16)",
        error.BadSubject => "WARD PREVIEW: bad subject (use facet=value[,facet=value], known facets, no duplicates)",
    };
}

fn reject(self: anytype, conn: anytype, err: Rejection) !void {
    var rb: [160]u8 = undefined;
    const line = std.fmt.bufPrint(&rb, "WARD PREVIEW: ADD would reject ({s}): {s}", .{ rejectionDetail(err), addMessage(err) }) catch unreachable;
    try self.noticeTo(conn, line);
}

/// Audit reason for a live-sampling preview, e.g. `WARD PREVIEW address live`.
fn auditReason(buf: []u8, p: Proposal) []const u8 {
    return std.fmt.bufPrint(buf, "WARD PREVIEW {s} live", .{p.match.token()}) catch unreachable;
}

/// Command body for `WARD PREVIEW …`; `args` excludes the `PREVIEW` token.
/// Reads `self.warden` (params, capacity, existing entry) and never mutates
/// it. The server may expose `wardPreviewLiveSubjects(self, *Accumulator)`
/// to stream every eligible live connection through `Accumulator.add`; a
/// server exposing it must also expose `recordOperAudit` (compile error
/// otherwise), and the hook runs only for an `oper_spy` caller
/// (`conn.session.hasPriv`, checked silently so the preview still answers).
pub fn handle(self: anytype, conn: anytype, args: []const []const u8, now_ms: i64) !void {
    const Server = @TypeOf(self.*);
    if (!self.requirePriv(conn, .client_moderate)) return;
    var subject_buf: [max_synthetic]Subject = undefined;
    const parsed = parseArgs(args, &subject_buf) catch |err| {
        try self.noticeTo(conn, parseErrorText(err));
        return;
    };
    const p = parsed.proposal;
    var rows: [max_rows]Row = undefined;
    // Proposal checks first, capacity last: the order ADD reports them in.
    var acc = Accumulator.init(p, self.warden.params, now_ms, &rows) catch |err| return reject(self, conn, err);
    validateCapacity(&self.warden, p) catch |err| return reject(self, conn, err);

    var pat_buf: [max_pattern_echo]u8 = undefined;
    const pat = sanitizeInto(&pat_buf, p.pattern);
    const ellipsis: []const u8 = if (pat.len < p.pattern.len) "..." else "";
    var hb: [512]u8 = undefined;
    const head = if (acc.expiry.permanent)
        std.fmt.bufPrint(&hb, "WARD PREVIEW {s} {s}{s} {s}/{s} expires=permanent", .{ p.match.token(), pat, ellipsis, p.scope.token(), p.action.token() })
    else
        std.fmt.bufPrint(&hb, "WARD PREVIEW {s} {s}{s} {s}/{s} expires_ms={d}{s}", .{ p.match.token(), pat, ellipsis, p.scope.token(), p.action.token(), acc.expiry.expires_ms, if (acc.expiry.expired) " (already expired; would never fire)" else "" });
    try self.noticeTo(conn, head catch unreachable);
    if (self.warden.find(p.match, p.pattern)) |existing| {
        var eb: [128]u8 = undefined;
        try self.noticeTo(conn, std.fmt.bufPrint(&eb, "WARD PREVIEW: ADD would replace the existing {s}/{s} ward", .{ existing.scope.token(), existing.action.token() }) catch unreachable);
    }
    if (p.scope == .mesh) try self.noticeTo(conn, "WARD PREVIEW: mesh scope; ADD requires two-person approval before it is stored or relayed");

    for (parsed.subjects) |s| _ = acc.add(s);
    if (@hasDecl(Server, "wardPreviewLiveSubjects")) {
        if (conn.session.hasPriv(.oper_spy)) {
            // Audit before the private read, as the record of who looked.
            var ab: [48]u8 = undefined;
            _ = self.recordOperAudit(conn.session.displayName(), .other, p.pattern, auditReason(&ab, p));
            self.wardPreviewLiveSubjects(&acc);
        } else {
            try self.noticeTo(conn, "WARD PREVIEW: live sampling requires the 'oper_spy' operator privilege; only synthetic subjects were evaluated");
        }
    } else {
        try self.noticeTo(conn, "WARD PREVIEW: live subjects unavailable; only synthetic subjects were evaluated");
    }

    const result = acc.preview();
    for (result.rows) |*row| {
        var lb: [192]u8 = undefined;
        try self.noticeTo(conn, std.fmt.bufPrint(&lb, "WARD PREVIEW: {s} {s} match={s} effect={s}", .{ row.source.token(), row.label(), if (row.matches) "yes" else "no", row.effect.token() }) catch unreachable);
    }
    if (result.hidden() != 0) {
        var tb: [96]u8 = undefined;
        try self.noticeTo(conn, std.fmt.bufPrint(&tb, "WARD PREVIEW: {d} more subject(s) not shown", .{result.hidden()}) catch unreachable);
    }
    const c = result.counts;
    var sb: [256]u8 = undefined;
    try self.noticeTo(conn, std.fmt.bufPrint(&sb, "WARD PREVIEW: matched {d}/{d} subject(s); close={d} quarantine={d} auth_pass={d} exempt={d} inert={d}", .{ c.matched, c.total, c.close, c.quarantine, c.auth_pass, c.exempt, c.inert }) catch unreachable);
    try self.noticeTo(conn, "WARD PREVIEW: preview only; nothing was stored, relayed, or enforced");
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn subj(label: []const u8, facets: warden.Facets) Subject {
    return .{ .label = label, .facets = facets };
}

test "ward preview: proposed mask ward matches representative subjects in input order with matched/total counts" {
    const subjects = [_]Subject{
        subj("alice", .{ .mask = "alice!a@home.example" }),
        subj("bot1", .{ .mask = "bot1!b@x.evil.example" }),
        subj("bob", .{ .mask = "bob!b@work.example" }),
        subj("bot2", .{ .mask = "bot2!b@y.EVIL.example" }),
    };
    var rows: [8]Row = undefined;
    const pv = try evaluate(.{ .match = .mask, .pattern = "*!*@*.evil.example" }, .{}, 1_000, &subjects, &rows);
    try testing.expectEqual(@as(usize, 4), pv.counts.total);
    try testing.expectEqual(@as(usize, 2), pv.counts.matched);
    try testing.expectEqual(@as(usize, 2), pv.counts.close);
    try testing.expectEqual(@as(usize, 4), pv.rows.len);
    const want = [_]struct { []const u8, bool }{ .{ "alice", false }, .{ "bot1", true }, .{ "bob", false }, .{ "bot2", true } };
    for (want, pv.rows) |w, row| {
        try testing.expectEqualStrings(w[0], row.label());
        try testing.expectEqual(w[1], row.matches);
        try testing.expectEqual(if (w[1]) Effect.close else Effect.none, row.effect);
    }
    try testing.expect(!pv.requires_two_person);
}

test "ward preview: expiry equals addWardLive formula (now+secs*1000), secs<=0 is permanent, saturates on overflow" {
    const now: i64 = 1_700_000_000_000;
    const e = expiresMs(now, 3600);
    try testing.expectEqual(now + 3600 * 1000, e.expires_ms);
    try testing.expect(!e.permanent and !e.expired);
    for ([_]i64{ 0, -1, std.math.minInt(i64) }) |secs| {
        const p = expiresMs(now, secs);
        try testing.expectEqual(@as(i64, 0), p.expires_ms);
        try testing.expect(p.permanent and !p.expired);
    }
    const max = std.math.maxInt(i64);
    const sat = expiresMs(now, max);
    try testing.expectEqual(max, sat.expires_ms);
    try testing.expect(!sat.permanent and !sat.expired);
    // At the end of time the saturated expiry equals now: stored, but dead.
    const dead = expiresMs(max, 10);
    try testing.expect(dead.expired);
    var rows: [1]Row = undefined;
    const pv = try evaluate(.{ .match = .host, .pattern = "*.bad.example", .secs = 10 }, .{}, max, &.{subj("h", .{ .host = "x.bad.example" })}, &rows);
    try testing.expectEqual(Effect.inert, pv.rows[0].effect);
    try testing.expectEqual(@as(usize, 1), pv.counts.matched);
    try testing.expectEqual(@as(usize, 0), pv.counts.close);
}

test "ward preview: invalid address CIDR and over-broad mask rejected exactly like WARD ADD" {
    const params = warden.Params{ .max_pattern = 16, .max_reason = 10 };
    try testing.expectError(error.InvalidCidr, validate(.{ .match = .address, .pattern = "192.0.2.0/99" }, params));
    try testing.expectError(error.InvalidCidr, validate(.{ .match = .address, .pattern = "2001:db8::/129" }, params));
    try testing.expectError(error.TooBroad, validate(.{ .match = .mask, .pattern = "*!*@*" }, params));
    try testing.expectError(error.TooBroad, validate(.{ .match = .host, .pattern = "" }, params));
    // Address is exempt from the broadness guard, as in ADD.
    try validate(.{ .match = .address, .pattern = "*" }, params);
    try testing.expectError(error.EmptyPattern, validate(.{ .match = .address, .pattern = "" }, params));
    try testing.expectError(error.PatternTooLong, validate(.{ .match = .host, .pattern = "far.too.long.example" }, params));
    try testing.expectError(error.ReasonTooLong, validate(.{ .match = .host, .pattern = "a.example", .reason = "way too long" }, params));
    try validate(.{ .match = .host, .pattern = "a.example", .reason = "short" }, params);
    // Operator text is ADD's text, byte for byte.
    try testing.expectEqualStrings("WARD: invalid address CIDR (use e.g. 192.0.2.0/24 or 2001:db8::/32)", addMessage(error.InvalidCidr));
    try testing.expectEqualStrings("WARD: pattern too broad (needs more literal characters)", addMessage(error.TooBroad));
    var rows: [1]Row = undefined;
    try testing.expectError(error.TooBroad, evaluate(.{ .match = .mask, .pattern = "*!*@*" }, .{}, 0, &.{}, &rows));

    // Capacity mirrors Registry.add: replace is allowed when full, new is not.
    var reg = warden.Registry.init(testing.allocator, .{ .max_wards = 1 });
    defer reg.deinit();
    try reg.add(.{ .match = .host, .pattern = "a.example" });
    try validateCapacity(&reg, .{ .match = .host, .pattern = "a.example" });
    try testing.expectError(error.RegistryFull, validateCapacity(&reg, .{ .match = .host, .pattern = "b.example" }));
    try testing.expectError(error.TooManyWards, reg.add(.{ .match = .host, .pattern = "b.example" }));
}

test "ward preview: address CIDR ipv4/ipv6 family-distinct matching via warden.matchesFacets" {
    const subjects = [_]Subject{
        subj("v6-in", .{ .address = "2001:db8:dead::1" }),
        subj("v6-out", .{ .address = "2001:dead::1" }),
        subj("v4", .{ .address = "10.1.2.3" }),
        subj("mapped", .{ .address = "::ffff:10.1.2.3" }),
    };
    var rows: [4]Row = undefined;
    const v6 = try evaluate(.{ .match = .address, .pattern = "2001:db8::/32", .action = .refuse }, .{}, 0, &subjects, &rows);
    try testing.expectEqual(@as(usize, 1), v6.counts.matched);
    try testing.expect(v6.rows[0].matches and !v6.rows[1].matches and !v6.rows[2].matches);
    const v4 = try evaluate(.{ .match = .address, .pattern = "10.0.0.0/8" }, .{}, 0, &subjects, &rows);
    try testing.expect(!v4.rows[0].matches and !v4.rows[1].matches and v4.rows[2].matches);
    // Each row agrees with the live registry predicate.
    var reg = warden.Registry.init(testing.allocator, .{});
    defer reg.deinit();
    try reg.add(.{ .match = .address, .pattern = "10.0.0.0/8" });
    for (subjects, v4.rows) |s, row| try testing.expectEqual(reg.check(s.facets, 0) != null, row.matches);
}

test "ward preview: absent facet never matches (account ward vs unauthenticated subject)" {
    const subjects = [_]Subject{
        subj("anon", .{ .mask = "spammer1!u@h.example" }),
        subj("empty", .{ .account = "" }),
        subj("acct", .{ .account = "spammer42" }),
    };
    var rows: [3]Row = undefined;
    const pv = try evaluate(.{ .match = .account, .pattern = "spammer*", .action = .require_auth }, .{}, 0, &subjects, &rows);
    try testing.expectEqual(@as(usize, 1), pv.counts.matched);
    try testing.expectEqual(Effect.none, pv.rows[0].effect);
    try testing.expectEqual(Effect.none, pv.rows[1].effect);
    // require_auth matches an authenticated account, which passes.
    try testing.expectEqual(Effect.auth_pass, pv.rows[2].effect);
    try testing.expectEqual(@as(usize, 0), pv.counts.close);
}

test "ward preview: rows truncated to out.len while totals cover full subject list" {
    var subjects: [10]Subject = undefined;
    for (&subjects, 0..) |*s, i| s.* = subj(if (i % 2 == 0) "even" else "odd", .{ .host = if (i % 2 == 0) "a.bad.example" else "a.good.example" });
    var rows: [3]Row = undefined;
    const pv = try evaluate(.{ .match = .host, .pattern = "*.bad.example", .action = .quarantine }, .{}, 0, &subjects, &rows);
    try testing.expectEqual(@as(usize, 3), pv.rows.len);
    try testing.expectEqual(@as(usize, 10), pv.counts.total);
    try testing.expectEqual(@as(usize, 5), pv.counts.matched);
    try testing.expectEqual(@as(usize, 5), pv.counts.quarantine);
    try testing.expectEqual(@as(usize, 7), pv.hidden());
    var none: [0]Row = .{};
    const empty_rows = try evaluate(.{ .match = .host, .pattern = "*.bad.example" }, .{}, 0, &subjects, &none);
    try testing.expectEqual(@as(usize, 10), empty_rows.counts.total);
    try testing.expectEqual(@as(usize, 0), empty_rows.rows.len);
}

test "ward preview: effects mirror live enforcement (oper exempt, continuity only for host/mask)" {
    var rows: [4]Row = undefined;
    var acc = try Accumulator.init(.{ .match = .host, .pattern = "*.bad.example" }, .{}, 0, &rows);
    try testing.expectEqual(Effect.exempt, acc.add(.{ .label = "op", .facets = .{ .host = "x.bad.example" }, .oper = true, .source = .live }));
    try testing.expectEqual(Effect.close, acc.add(.{ .label = "rotated", .facets = .{ .host = "new.cloak" }, .continuity_hit = true, .source = .live }));
    try testing.expectEqual(Effect.none, acc.add(.{ .label = "clean", .facets = .{ .host = "new.cloak" }, .source = .live }));
    var acct_rows: [1]Row = undefined;
    var acct = try Accumulator.init(.{ .match = .account, .pattern = "evil*" }, .{}, 0, &acct_rows);
    // A misapplied continuity flag cannot widen a non-host/mask ward.
    try testing.expectEqual(Effect.none, acct.add(.{ .label = "x", .facets = .{}, .continuity_hit = true }));
    const pv = acc.preview();
    try testing.expectEqual(@as(usize, 2), pv.counts.matched);
    try testing.expectEqual(@as(usize, 1), pv.counts.exempt);
    try testing.expectEqual(Source.live, pv.rows[0].source);
}

test "ward preview: sanitize replaces control bytes and truncates on a UTF-8 boundary" {
    var buf: [6]u8 = undefined;
    try testing.expectEqualStrings("a?b", sanitizeInto(&buf, "a\x01b"));
    // "abcde" + 2-byte U+00E9 would split at byte 6; back off to 5.
    try testing.expectEqualStrings("abcde", sanitizeInto(&buf, "abcde\xc3\xa9"));
    try testing.expectEqualStrings("abc\xc3\xa9", sanitizeInto(&buf, "abc\xc3\xa9"));
}

test "ward preview: parseArgs splits scope/action/secs from subjects after -- and parses facet=value synthetic subjects" {
    var buf: [max_synthetic]Subject = undefined;
    const args = [_][]const u8{ "mask", "*!*@*.evil.example", "quarantine", "MESH", "600", "spam ring", "--", "mask=bot!b@x.evil.example", "address=192.0.2.9,account=bob" };
    const parsed = try parseArgs(&args, &buf);
    try testing.expectEqual(warden.Match.mask, parsed.proposal.match);
    try testing.expectEqual(warden.Scope.mesh, parsed.proposal.scope);
    try testing.expectEqual(warden.Action.quarantine, parsed.proposal.action);
    try testing.expectEqual(@as(i64, 600), parsed.proposal.secs);
    try testing.expectEqualStrings("spam ring", parsed.proposal.reason);
    try testing.expectEqual(@as(usize, 2), parsed.subjects.len);
    try testing.expectEqualStrings("bot!b@x.evil.example", parsed.subjects[0].facets.mask);
    try testing.expectEqualStrings("192.0.2.9", parsed.subjects[1].facets.address);
    try testing.expectEqualStrings("bob", parsed.subjects[1].facets.account.?);
    try testing.expect(parsed.subjects[1].facets.mask.len == 0);
    try testing.expectEqual(Source.synthetic, parsed.subjects[1].source);

    // No subjects and no axes: defaults match ADD.
    const bare = try parseArgs(&.{ "host", "*.x.example" }, &buf);
    try testing.expectEqual(warden.Scope.node, bare.proposal.scope);
    try testing.expectEqual(warden.Action.expel, bare.proposal.action);
    try testing.expectEqual(@as(usize, 0), bare.subjects.len);
    try testing.expectEqual(@as(usize, 0), (try parseArgs(&.{ "host", "*.x.example", "--" }, &buf)).subjects.len);

    // Hostile / malformed input fails closed.
    try testing.expectError(error.MissingPattern, parseArgs(&.{"mask"}, &buf));
    try testing.expectError(error.UnknownMatch, parseArgs(&.{ "kline", "x" }, &buf));
    try testing.expectError(error.UnexpectedToken, parseArgs(&.{ "host", "a.example", "why", "extra" }, &buf));
    for ([_][]const u8{ "", "mask", "nick=x", "mask=", "mask=a,mask=b", "account=a\x01b", "address=1.2.3.4,", "=x" }) |bad| {
        try testing.expectError(error.BadSubject, parseArgs(&.{ "host", "a.example", "--", bad }, &buf));
    }
    var many: [3 + max_synthetic + 1][]const u8 = undefined;
    many[0] = "host";
    many[1] = "a.example";
    many[2] = "--";
    for (many[3..]) |*t| t.* = "host=a.example";
    try testing.expectError(error.TooManySubjects, parseArgs(&many, &buf));
    try testing.expectEqual(@as(usize, max_synthetic), (try parseArgs(many[0 .. many.len - 1], &buf)).subjects.len);
}

const FakeConn = struct {
    session: Session = .{},

    const Session = struct {
        oper_spy: bool = true,

        pub fn hasPriv(self: *const Session, privilege: anytype) bool {
            return privilege == .oper_spy and self.oper_spy;
        }

        pub fn displayName(_: *const Session) []const u8 {
            return "op";
        }
    };
};

/// Without the hook: `handle` must report that live sampling is unavailable.
const BareServer = struct {
    warden: warden.Registry,
    notices: std.ArrayList([]const u8) = .empty,

    pub fn requirePriv(_: *BareServer, _: *FakeConn, _: anytype) bool {
        return true;
    }

    pub fn noticeTo(self: *BareServer, _: *FakeConn, text: []const u8) !void {
        try self.notices.append(testing.allocator, try testing.allocator.dupe(u8, text));
    }
};

const FakeServer = struct {
    const Self = @This();
    warden: warden.Registry,
    notices: std.ArrayList([]const u8) = .empty,
    allowed: bool = true,
    /// Event order: 'a' per audit record, 'l' per live-hook call.
    trace: [8]u8 = undefined,
    trace_len: usize = 0,
    audit_target: [64]u8 = undefined,
    audit_target_len: usize = 0,
    audit_reason: [64]u8 = undefined,
    audit_reason_len: usize = 0,

    fn init(params: warden.Params) Self {
        return .{ .warden = warden.Registry.init(testing.allocator, params) };
    }

    fn deinit(self: *Self) void {
        for (self.notices.items) |n| testing.allocator.free(n);
        self.notices.deinit(testing.allocator);
        self.warden.deinit();
    }

    pub fn requirePriv(self: *Self, conn: *FakeConn, privilege: anytype) bool {
        _ = conn;
        std.debug.assert(privilege == .client_moderate);
        return self.allowed;
    }

    pub fn noticeTo(self: *Self, conn: *FakeConn, text: []const u8) !void {
        _ = conn;
        try self.notices.append(testing.allocator, try testing.allocator.dupe(u8, text));
    }

    fn mark(self: *Self, c: u8) void {
        self.trace[self.trace_len] = c;
        self.trace_len += 1;
    }

    pub fn recordOperAudit(self: *Self, oper: []const u8, action: anytype, target: []const u8, reason: []const u8) ?[64]u8 {
        std.debug.assert(std.mem.eql(u8, oper, "op") and action == .other);
        self.mark('a');
        self.audit_target_len = sanitizeInto(&self.audit_target, target).len;
        self.audit_reason_len = sanitizeInto(&self.audit_reason, reason).len;
        return null;
    }

    pub fn wardPreviewLiveSubjects(self: *Self, acc: *Accumulator) void {
        self.mark('l');
        // A per-call scratch proves facets need only live through add().
        var mask_buf: [64]u8 = undefined;
        const mask = std.fmt.bufPrint(&mask_buf, "{s}!u@{s}", .{ "raider", "r.evil.example" }) catch unreachable;
        _ = acc.add(.{ .label = "raider", .facets = .{ .mask = mask }, .source = .live });
        _ = acc.add(.{ .label = "oper", .facets = .{ .mask = "oper!o@o.evil.example" }, .source = .live, .oper = true });
        // A cloaked client whose real address only oper_spy may see.
        _ = acc.add(.{ .label = "alice", .facets = .{ .address = "203.0.113.7", .host = "abc.cloak.onyx" }, .source = .live });
    }

    fn has(self: *const Self, needle: []const u8) bool {
        for (self.notices.items) |n| if (std.mem.indexOf(u8, n, needle) != null) return true;
        return false;
    }
};

test "ward preview: mesh scope reports requires_two_person and never mutates registry (count unchanged)" {
    var srv = FakeServer.init(.{});
    defer srv.deinit();
    try srv.warden.add(.{ .match = .mask, .pattern = "*!*@*.evil.example", .scope = .node, .action = .quarantine, .reason = "old" });
    var conn = FakeConn{};
    const args = [_][]const u8{ "mask", "*!*@*.evil.example", "mesh", "expel", "60", "--", "mask=bot!b@x.evil.example", "mask=ok!u@fine.example" };
    try handle(&srv, &conn, &args, 10_000);
    try testing.expectEqual(@as(usize, 1), srv.warden.count());
    const kept = srv.warden.find(.mask, "*!*@*.evil.example").?;
    try testing.expectEqual(warden.Scope.node, kept.scope);
    try testing.expectEqual(warden.Action.quarantine, kept.action);
    try testing.expectEqualStrings("old", kept.reason);
    try testing.expect(srv.has("WARD PREVIEW mask *!*@*.evil.example mesh/expel expires_ms=70000"));
    try testing.expect(srv.has("two-person approval"));
    try testing.expect(srv.has("ADD would replace the existing node/quarantine ward"));
    try testing.expect(srv.has("synthetic mask=bot!b@x.evil.example match=yes effect=close"));
    try testing.expect(srv.has("synthetic mask=ok!u@fine.example match=no effect=none"));
    try testing.expect(srv.has("live raider match=yes effect=close"));
    try testing.expect(srv.has("live oper match=yes effect=exempt"));
    try testing.expect(srv.has("live alice match=no effect=none"));
    try testing.expect(srv.has("matched 3/5 subject(s); close=2 quarantine=0 auth_pass=0 exempt=1 inert=0"));
    try testing.expect(srv.has("nothing was stored, relayed, or enforced"));
    // The proposal itself (mesh/expel) was never stored.
    try testing.expect(srv.warden.find(.mask, "*!*@*.evil.example").?.scope != .mesh);
}

test "ward preview: handle fails closed for unauthorized, invalid, full, and hookless servers" {
    var conn = FakeConn{};
    {
        var srv = FakeServer.init(.{});
        defer srv.deinit();
        srv.allowed = false;
        try handle(&srv, &conn, &.{ "host", "*.bad.example" }, 0);
        try testing.expectEqual(@as(usize, 0), srv.notices.items.len);
    }
    {
        var srv = FakeServer.init(.{});
        defer srv.deinit();
        try handle(&srv, &conn, &.{ "address", "192.0.2.0/99" }, 0);
        try testing.expectEqual(@as(usize, 1), srv.notices.items.len);
        try testing.expect(srv.has("ADD would reject (invalid_cidr): WARD: invalid address CIDR"));
        try handle(&srv, &conn, &.{ "mask", "*!*@*" }, 0);
        try testing.expect(srv.has("ADD would reject (too_broad): WARD: pattern too broad"));
        try handle(&srv, &conn, &.{"mask"}, 0);
        try testing.expect(srv.has("Usage: WARD PREVIEW"));
        try handle(&srv, &conn, &.{ "host", "*.bad.example", "--", "bogus=1" }, 0);
        try testing.expect(srv.has("WARD PREVIEW: bad subject"));
        try testing.expectEqual(@as(usize, 0), srv.warden.count());
    }
    {
        var srv = FakeServer.init(.{ .max_wards = 1 });
        defer srv.deinit();
        try srv.warden.add(.{ .match = .host, .pattern = "a.example" });
        try handle(&srv, &conn, &.{ "host", "b.example" }, 0);
        try testing.expect(srv.has("ADD would reject (registry_full)"));
        try testing.expectEqual(@as(usize, 1), srv.warden.count());
    }
    {
        var srv = BareServer{ .warden = warden.Registry.init(testing.allocator, .{}) };
        defer {
            for (srv.notices.items) |n| testing.allocator.free(n);
            srv.notices.deinit(testing.allocator);
            srv.warden.deinit();
        }
        try handle(&srv, &conn, &.{ "host", "*.bad.example", "--", "host=x.bad.example" }, 0);
        const lines = srv.notices.items;
        try testing.expectEqual(@as(usize, 5), lines.len);
        try testing.expectEqualStrings("WARD PREVIEW host *.bad.example node/expel expires=permanent", lines[0]);
        try testing.expectEqualStrings("WARD PREVIEW: live subjects unavailable; only synthetic subjects were evaluated", lines[1]);
        try testing.expectEqualStrings("WARD PREVIEW: synthetic host=x.bad.example match=yes effect=close", lines[2]);
        try testing.expectEqualStrings("WARD PREVIEW: matched 1/1 subject(s); close=1 quarantine=0 auth_pass=0 exempt=0 inert=0", lines[3]);
        try testing.expectEqualStrings("WARD PREVIEW: preview only; nothing was stored, relayed, or enforced", lines[4]);
    }
    {
        // A too-broad pattern on a full registry reports ADD's first refusal.
        var srv = FakeServer.init(.{ .max_wards = 0 });
        defer srv.deinit();
        try handle(&srv, &conn, &.{ "mask", "*!*@*" }, 0);
        try testing.expect(srv.has("(too_broad)") and !srv.has("(registry_full)"));
    }
}

test "ward preview: live sampling needs oper_spy and is audited before the read" {
    const args = [_][]const u8{ "address", "203.0.113.7" };
    {
        // client_moderate without oper_spy: no live row, no live count, no
        // hook call, no audit, and the reason is stated.
        var srv = FakeServer.init(.{});
        defer srv.deinit();
        var conn = FakeConn{ .session = .{ .oper_spy = false } };
        try handle(&srv, &conn, &args, 0);
        try testing.expectEqual(@as(usize, 0), srv.trace_len);
        for (srv.notices.items) |n| try testing.expect(std.mem.indexOf(u8, n, "live ") == null or std.mem.indexOf(u8, n, "match=") == null);
        try testing.expect(!srv.has("alice"));
        try testing.expect(srv.has("live sampling requires the 'oper_spy' operator privilege"));
        try testing.expect(srv.has("matched 0/0 subject(s)"));
        // Synthetic subjects still evaluate for the unprivileged caller.
        try handle(&srv, &conn, &.{ "address", "203.0.113.0/24", "--", "address=203.0.113.9" }, 0);
        try testing.expect(srv.has("synthetic address=203.0.113.9 match=yes effect=close"));
        try testing.expect(srv.has("matched 1/1 subject(s)"));
        try testing.expectEqual(@as(usize, 0), srv.trace_len);
    }
    {
        // oper_spy: one audit record strictly before the live read.
        var srv = FakeServer.init(.{});
        defer srv.deinit();
        var conn = FakeConn{};
        try handle(&srv, &conn, &args, 0);
        try testing.expectEqualStrings("al", srv.trace[0..srv.trace_len]);
        try testing.expectEqualStrings("203.0.113.7", srv.audit_target[0..srv.audit_target_len]);
        try testing.expectEqualStrings("WARD PREVIEW address live", srv.audit_reason[0..srv.audit_reason_len]);
        try testing.expect(srv.has("live alice match=yes effect=close"));
        try testing.expect(srv.has("matched 1/3 subject(s)"));
        try testing.expect(!srv.has("requires the 'oper_spy'"));
    }
    {
        // A rejected proposal never samples or audits, even for oper_spy.
        var srv = FakeServer.init(.{});
        defer srv.deinit();
        var conn = FakeConn{};
        try handle(&srv, &conn, &.{ "address", "203.0.113.0/99" }, 0);
        try testing.expectEqual(@as(usize, 0), srv.trace_len);
    }
}
