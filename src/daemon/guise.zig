// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guise — Onyx Server's reinvented virtual-host system.
//!
//! Legacy ircds treat a vhost as a single string an operator hangs on a user,
//! or a flat pool of literal offers a user can TAKE one at a time.
//! Guise generalizes that into an identity *wardrobe*:
//!
//!   * Each account holds MULTIPLE named personas and switches between them
//!     instantly with `VHOST USE <name>` — no re-request, no oper round trip.
//!   * Operators publish OFFER *templates* (globs like `*.users.eshmaki.me`),
//!     not just literal hosts; a user self-services any host matching a template
//!     via `VHOST CLAIM <host>` and it becomes a persona immediately.
//!   * Every persona records its PROVENANCE (how it was obtained): operator
//!     grant, self-claim from a template, domain-verified, or auto/cloak — so
//!     the trust origin of an apparent identity is always auditable.
//!
//! This module owns the persona + offer storage and the matching logic. The live
//! server applies the active persona to a session (CHGHOST) and gates who may
//! publish offers. Its one outward dependency is the stateless `cloak`
//! account-cloak encoder: `claim` binds a self-claimed host's identity labels to
//! the caller's collision-resistant `cloakAccount` identity,
//! so a user can only self-claim a host that spells their own account.

const std = @import("std");
const cloak = @import("../proto/cloak.zig");

/// How a persona's host was obtained — its trust provenance.
pub const Source = enum {
    granted, // an operator approved a VHOST REQUEST
    claimed, // self-claimed from an operator OFFER template
    verified, // bound to a domain the user proved control of (reserved seam)
    auto, // server-assigned (e.g. cloak-derived default)

    pub fn token(self: Source) []const u8 {
        return switch (self) {
            .granted => "granted",
            .claimed => "claimed",
            .verified => "verified",
            .auto => "auto",
        };
    }
};

/// One named apparent-host a user can wear.
pub const Persona = struct {
    name: []const u8,
    host: []const u8,
    source: Source,
    granted_ms: i64,
};

/// An operator-published vhost template. `template` is a glob (`*`/`?`) that a
/// claimed host must match; `label` is a human description.
pub const Offer = struct {
    template: []const u8,
    label: []const u8,
};

pub const Params = struct {
    max_accounts: usize = 65536,
    max_personas_per_account: usize = 16,
    max_offers: usize = 256,
    max_name: usize = 32,
    max_host: usize = 128,
    max_label: usize = 128,
    max_template: usize = 128,
};

pub const GuiseError = std.mem.Allocator.Error || error{
    NameTooLong,
    HostTooLong,
    LabelTooLong,
    TemplateTooLong,
    EmptyValue,
    TooManyPersonas,
    TooManyOffers,
    TooManyAccounts,
    NotOffered,
    NotYours,
    HostClaimedByOther,
    Duplicate,
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// account (lowercased, owned key) -> owned list of Personas (owned strings).
    accounts: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(Persona)) = .empty,
    offers: std.ArrayListUnmanaged(Offer) = .empty,

    pub fn init(allocator: std.mem.Allocator, params: Params) Registry {
        return .{ .allocator = allocator, .params = params };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.accounts.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.items) |*p| self.freePersona(p);
            e.value_ptr.deinit(self.allocator);
            self.allocator.free(e.key_ptr.*);
        }
        self.accounts.deinit(self.allocator);
        for (self.offers.items) |*o| self.freeOffer(o);
        self.offers.deinit(self.allocator);
        self.* = undefined;
    }

    // ── personas ──────────────────────────────────────────────────────────

    /// Grant a named persona to `account` (replacing one of the same name). The
    /// host's validity is the caller's concern; storage is owned here.
    pub fn grant(self: *Registry, account: []const u8, name: []const u8, host: []const u8, source: Source, now_ms: i64) GuiseError!void {
        if (name.len == 0 or host.len == 0) return error.EmptyValue;
        if (name.len > self.params.max_name) return error.NameTooLong;
        if (host.len > self.params.max_host) return error.HostTooLong;
        // Durable and Helix restore enter through grant, too. Validate before
        // account allocation or replacement so rejected historical claims leave
        // the existing registry byte-for-byte intact.
        if (source == .claimed) {
            if (!claimedHostBelongsToAccount(account, host)) return error.NotYours;
            if (self.hostOwnedByOther(account, host)) return error.HostClaimedByOther;
        }

        const list = try self.accountList(account);
        // Replace a same-named persona in place.
        for (list.items) |*p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) {
                const new_host = try self.allocator.dupe(u8, host);
                self.allocator.free(@constCast(p.host));
                p.host = new_host;
                p.source = source;
                p.granted_ms = now_ms;
                return;
            }
        }
        if (list.items.len >= self.params.max_personas_per_account) return error.TooManyPersonas;
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_host = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_host);
        try list.append(self.allocator, .{ .name = owned_name, .host = owned_host, .source = source, .granted_ms = now_ms });
    }

    /// Self-claim `host` if it matches an operator OFFER template. Stored as a
    /// `.claimed` persona named after the host's first label. Returns the offer.
    ///
    /// The claim is bound to `account`: the host's identity labels must equal
    /// the collision-resistant account cloak, and no *other* account may
    /// already wear the same host. Without
    /// this a logged-in user could self-claim `<someone-else>.users.<suffix>` off
    /// a wildcard community offer and wear another account's apparent identity.
    pub fn claim(self: *Registry, account: []const u8, host: []const u8, now_ms: i64) GuiseError!Offer {
        const offer = self.matchOffer(host) orelse return error.NotOffered;
        const name = firstLabel(host);
        try self.grant(account, name, host, .claimed, now_ms);
        return offer;
    }

    /// True when some account OTHER than `account` already wears `host` as a
    /// persona (case-insensitive). Blocks two accounts holding the identical
    /// apparent host.
    fn hostOwnedByOther(self: *const Registry, account: []const u8, host: []const u8) bool {
        var kbuf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&kbuf, account) orelse return false;
        var it = self.accounts.iterator();
        while (it.next()) |e| {
            if (std.mem.eql(u8, e.key_ptr.*, key)) continue; // same account
            for (e.value_ptr.items) |p| {
                if (std.ascii.eqlIgnoreCase(p.host, host)) return true;
            }
        }
        return false;
    }

    pub fn personas(self: *const Registry, account: []const u8) []const Persona {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return &.{};
        const list = self.accounts.getPtr(key) orelse return &.{};
        return list.items;
    }

    pub fn find(self: *const Registry, account: []const u8, name: []const u8) ?Persona {
        for (self.personas(account)) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) return p;
        }
        return null;
    }

    pub fn removePersona(self: *Registry, account: []const u8, name: []const u8) bool {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return false;
        const list = self.accounts.getPtr(key) orelse return false;
        for (list.items, 0..) |*p, i| {
            if (std.ascii.eqlIgnoreCase(p.name, name)) {
                self.freePersona(p);
                _ = list.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    // ── offers ────────────────────────────────────────────────────────────

    pub fn addOffer(self: *Registry, template: []const u8, label: []const u8) GuiseError!void {
        if (template.len == 0) return error.EmptyValue;
        if (template.len > self.params.max_template) return error.TemplateTooLong;
        if (label.len > self.params.max_label) return error.LabelTooLong;
        for (self.offers.items) |o| {
            if (std.ascii.eqlIgnoreCase(o.template, template)) return error.Duplicate;
        }
        if (self.offers.items.len >= self.params.max_offers) return error.TooManyOffers;
        const t = try self.allocator.dupe(u8, template);
        errdefer self.allocator.free(t);
        const l = try self.allocator.dupe(u8, label);
        try self.offers.append(self.allocator, .{ .template = t, .label = l });
    }

    pub fn removeOffer(self: *Registry, template: []const u8) bool {
        for (self.offers.items, 0..) |*o, i| {
            if (std.ascii.eqlIgnoreCase(o.template, template)) {
                self.freeOffer(o);
                _ = self.offers.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn offerList(self: *const Registry) []const Offer {
        return self.offers.items;
    }

    /// First offer whose template glob matches `host`, or null.
    pub fn matchOffer(self: *const Registry, host: []const u8) ?Offer {
        for (self.offers.items) |o| {
            if (globMatch(o.template, host)) return o;
        }
        return null;
    }

    // ── internals ─────────────────────────────────────────────────────────

    fn accountList(self: *Registry, account: []const u8) GuiseError!*std.ArrayListUnmanaged(Persona) {
        var buf: [Params_account_key_max]u8 = undefined;
        const key = lowerKey(&buf, account) orelse return error.NameTooLong;
        if (self.accounts.getPtr(key)) |list| return list;
        if (self.accounts.count() >= self.params.max_accounts) return error.TooManyAccounts;
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.accounts.put(self.allocator, owned_key, .empty);
        return self.accounts.getPtr(owned_key).?;
    }

    fn freePersona(self: *Registry, p: *Persona) void {
        self.allocator.free(@constCast(p.name));
        self.allocator.free(@constCast(p.host));
    }

    fn freeOffer(self: *Registry, o: *Offer) void {
        self.allocator.free(@constCast(o.template));
        self.allocator.free(@constCast(o.label));
    }
};

const Params_account_key_max = 128;

fn lowerKey(buf: []u8, account: []const u8) ?[]const u8 {
    if (account.len == 0 or account.len > buf.len) return null;
    return std.ascii.lowerString(buf[0..account.len], account);
}

/// The label before the first '.' of a host (used to auto-name a claimed persona).
fn firstLabel(host: []const u8) []const u8 {
    const dot = std.mem.indexOfScalar(u8, host, '.') orelse return host;
    return if (dot == 0) host else host[0..dot];
}

/// Iterative, case-insensitive `*`/`?` glob (no recursion, backtracking).
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
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
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// Use the cloak encoder as the single account-identity authority. Unsafe
/// account spellings require both their friendly and digest labels.
pub fn claimedHostBelongsToAccount(account: []const u8, host: []const u8) bool {
    var abuf: [cloak.max_cloak_len]u8 = undefined;
    const encoded = cloak.cloakAccount(&abuf, account, "claim") catch return false;
    const identity = encoded[0 .. encoded.len - ".users.claim".len];
    if (host.len <= identity.len or host[identity.len] != '.') return false;
    if (!std.ascii.eqlIgnoreCase(identity, host[0..identity.len])) return false;

    // A one-label canonical account must not borrow an unsafe account's
    // digest as its offered suffix and impersonate that account's auto host.
    // Other suffixes remain under the operator's OFFER policy.
    if (std.mem.indexOfScalar(u8, identity, '.') == null) {
        const suffix = host[identity.len + 1 ..];
        const digest_len = cloak.wide_token_hex_len;
        if (suffix.len > digest_len + ".users.".len and
            std.ascii.eqlIgnoreCase(suffix[digest_len..][0..".users.".len], ".users."))
        {
            for (suffix[0..digest_len]) |c| {
                if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) return true;
            }
            return false;
        }
    }
    return true;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "grant stores multiple named personas; find + remove" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.grant("alice", "work", "alice.staff.example", .granted, 1);
    try reg.grant("alice", "play", "alice.cool.example", .claimed, 2);
    try std.testing.expectEqual(@as(usize, 2), reg.personas("alice").len);
    try std.testing.expectEqualStrings("alice.cool.example", reg.find("alice", "PLAY").?.host);
    try std.testing.expect(reg.removePersona("alice", "work"));
    try std.testing.expectEqual(@as(usize, 1), reg.personas("alice").len);
}

test "grant replaces same-named persona without leaking" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.grant("bob", "main", "bob.v1.example", .granted, 1);
    try reg.grant("bob", "main", "bob.v2.example", .verified, 2);
    try std.testing.expectEqual(@as(usize, 1), reg.personas("bob").len);
    const p = reg.find("bob", "main").?;
    try std.testing.expectEqualStrings("bob.v2.example", p.host);
    try std.testing.expectEqual(Source.verified, p.source);
}

test "offers: add/list/match glob; claim self-services a matching host" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.eshmaki.me", "community vhosts");
    try std.testing.expect(reg.matchOffer("alice.users.eshmaki.me") != null);
    try std.testing.expect(reg.matchOffer("alice.staff.other.net") == null);

    const offer = try reg.claim("carol", "carol.users.eshmaki.me", 5);
    try std.testing.expectEqualStrings("community vhosts", offer.label);
    const p = reg.find("carol", "carol").?;
    try std.testing.expectEqual(Source.claimed, p.source);
    try std.testing.expectEqualStrings("carol.users.eshmaki.me", p.host);

    try std.testing.expectError(error.NotOffered, reg.claim("carol", "carol.notoffered.net", 6));
}

test "duplicate offer rejected; removeOffer works" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.a.example", "x");
    try std.testing.expectError(error.Duplicate, reg.addOffer("*.A.example", "y"));
    try std.testing.expect(reg.removeOffer("*.a.example"));
    try std.testing.expect(!reg.removeOffer("*.a.example"));
}

test "limits enforced" {
    var reg = Registry.init(std.testing.allocator, .{ .max_personas_per_account = 1, .max_offers = 1, .max_name = 4 });
    defer reg.deinit();
    try reg.grant("u", "main", "h.example", .granted, 0);
    try std.testing.expectError(error.TooManyPersonas, reg.grant("u", "alt", "h2.example", .granted, 0));
    try std.testing.expectError(error.NameTooLong, reg.grant("u", "toolong", "h.example", .granted, 0));
    try reg.addOffer("*.a", "x");
    try std.testing.expectError(error.TooManyOffers, reg.addOffer("*.b", "y"));
}

test "vhost claim binds host leading-label to the caller's account" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.eshmaki.me", "community vhosts");

    // Impersonation attempt: carol claiming bob's host is rejected, and nothing
    // is stored for carol.
    try std.testing.expectError(error.NotYours, reg.claim("carol", "bob.users.eshmaki.me", 1));
    try std.testing.expectEqual(@as(usize, 0), reg.personas("carol").len);

    // The account's own host succeeds (leading label == account).
    const offer = try reg.claim("carol", "carol.users.eshmaki.me", 2);
    try std.testing.expectEqualStrings("community vhosts", offer.label);
    try std.testing.expectEqualStrings("carol.users.eshmaki.me", reg.find("carol", "carol").?.host);
}

test "vhost claim rejects a host already worn by another account" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.eshmaki.me", "community vhosts");

    // Operator granted bob the host (a granted persona, any name/host).
    try reg.grant("bob", "main", "shared.users.eshmaki.me", .granted, 1);
    // Another account whose name sanitizes to the same leading label cannot claim
    // the identical host bob already wears.
    try std.testing.expectError(error.HostClaimedByOther, reg.claim("shared", "shared.users.eshmaki.me", 2));
    try std.testing.expectEqual(@as(usize, 0), reg.personas("shared").len);
}

test "vhost claim preserves collision-resistant account identity" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.eshmaki.me", "community vhosts");

    // The lossy spelling belongs to another valid account, not this account.
    try std.testing.expectError(error.NotYours, reg.claim("some_user", "some-user.users.eshmaki.me", 1));
    var buf: [cloak.max_cloak_len]u8 = undefined;
    const own = try cloak.cloakAccount(&buf, "some_user", "eshmaki.me");
    _ = try reg.claim("some_user", own, 1);
    try std.testing.expectEqualStrings(own, reg.find("some_user", "some-user").?.host);
    try std.testing.expectError(error.NotYours, reg.claim("some_user", "eve.users.eshmaki.me", 2));
}

test "vhost claim rejects punctuation collisions and encoded victim lookalikes" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.users.onyx", "account hosts");
    const aliases = [_][]const u8{ "alice_foo", "alice.foo", "-alice-foo", "alice-foo-" };
    for (aliases, 0..) |account, i| {
        try std.testing.expectError(error.NotYours, reg.claim(account, "alice-foo.users.onyx", 1));
        var buf: [cloak.max_cloak_len]u8 = undefined;
        const own = try cloak.cloakAccount(&buf, account, "onyx");
        // The canonical account cannot claim this encoded victim's host,
        // even before the victim has a registered persona.
        try std.testing.expectError(error.NotYours, reg.claim("alice-foo", own, 1));
        for (aliases[0..i]) |other| {
            try std.testing.expectError(error.NotYours, reg.claim(other, own, 1));
        }
        _ = try reg.claim(account, own, 2);
    }
    try std.testing.expectEqual(@as(usize, 0), reg.personas("alice-foo").len);
}

test "vhost claim keeps offered suffixes and rejects altered identity labels" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.addOffer("*.community.example", "custom suffix");
    _ = try reg.claim("ALICE", "alice.community.example", 1);
    try std.testing.expectError(error.NotYours, reg.claim("alice", "-alice.community.example", 1));
    try std.testing.expectError(error.NotYours, reg.claim("alice", "alice-.community.example", 1));
    var buf: [cloak.max_cloak_len]u8 = undefined;
    const encoded = try cloak.cloakAccount(&buf, "some_user", "claim");
    const identity = encoded[0 .. encoded.len - ".users.claim".len];
    var host_buf: [cloak.max_cloak_len]u8 = undefined;
    const own = try std.fmt.bufPrint(&host_buf, "{s}.community.example", .{identity});
    _ = try reg.claim("SOME_USER", own, 1);
    try std.testing.expectError(error.NotYours, reg.claim("some_user", "some-user.community.example", 1));
    host_buf[identity.len - 1] = if (host_buf[identity.len - 1] == '0') '1' else '0';
    try std.testing.expectError(error.NotYours, reg.claim("some_user", own, 1));
}

test "no leak under churn" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    for (0..50) |i| {
        var nb: [16]u8 = undefined;
        var hb: [48]u8 = undefined;
        const name = try std.fmt.bufPrint(&nb, "p{d}", .{i % 8});
        const host = try std.fmt.bufPrint(&hb, "h{d}.example", .{i});
        try reg.grant("churn", name, host, .granted, @intCast(i));
    }
    try std.testing.expect(reg.personas("churn").len <= 8);
}

test "claimed grant rejects historical identity collisions before registry mutation" {
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    try reg.grant("alice_foo", "prior", "oper-approved.example", .granted, 1);
    const accounts_before = reg.accounts.count();
    try std.testing.expectError(error.NotYours, reg.grant("alice_foo", "prior", "alice-foo.users.onyx", .claimed, 2));
    try std.testing.expectError(error.NotYours, reg.grant("other_foo", "new", "other-foo.users.onyx", .claimed, 2));
    try std.testing.expectEqual(accounts_before, reg.accounts.count());
    const unchanged = reg.find("alice_foo", "prior").?;
    try std.testing.expectEqualStrings("oper-approved.example", unchanged.host);
    try std.testing.expectEqual(Source.granted, unchanged.source);
    try std.testing.expectEqual(@as(i64, 1), unchanged.granted_ms);
    // Explicit operator authority can still assign arbitrary hostnames.
    try reg.grant("alice_foo", "operator", "alice-foo.users.onyx", .granted, 3);
    var host_buf: [cloak.max_cloak_len]u8 = undefined;
    const own_host = try cloak.cloakAccount(&host_buf, "other_foo", "onyx");
    try reg.grant("other_foo", "own", own_host, .claimed, 4);
    try std.testing.expectEqual(Source.claimed, reg.find("other_foo", "own").?.source);
}
