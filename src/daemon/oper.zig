// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SASL-account operator privilege grants.
//!
//! This module is intentionally pure and allocation-free. The daemon's SASL
//! layer verifies an account first, then asks this registry whether that
//! canonical account maps to an operator class and privilege set. Command
//! handlers render the typed outcomes as server notices or failures.
const std = @import("std");

pub const default_params = Params{};

/// Compile-time bounds for account and class identifiers.
pub const Params = struct {
    max_account_len: usize = 128,
    max_class_len: usize = 64,
};

/// The SASL mechanism that produced a verified account.
///
/// Elevation depends only on the account name; the mechanism is retained for
/// audit events and structured replies at higher layers.
pub const SaslMechanism = enum {
    external,
    scram_sha_256,
    scram_sha_512,
    other,
};

/// Account identity after SASL has already succeeded.
pub const VerifiedAccount = struct {
    name: []const u8,
    mechanism: SaslMechanism = .other,
};

/// Individual operator capabilities. Names are domain capabilities rather than
/// command names so the command layer can evolve without changing grants.
pub const Privilege = enum {
    // Server lifecycle.
    server_rehash,
    server_restart,
    server_shutdown,
    // Moderation.
    client_moderate, // WARD/SHUN/quarantine and similar client controls
    channel_moderate, // FORCE*/CLEAR and channel takeover
    client_kill, // KILL a client off the network
    // Network / mesh.
    mesh_admin, // CONNECT/SQUIT and mesh routing control
    // Services / administration.
    service_admin,
    server_admin, // network administrator (the admin tier)
    oper_grant, // grant/revoke operator status
    // Visibility / audit.
    oper_spy, // see private info (GEOIP, OPERSPY, real host/IP)
    event_subscribe,
    audit_read,
    // Catch-all override for force/sa-style actions.
    oper_override,
    // Connection limits. APPEND-ONLY: new members go at the END so `toBits`
    // ordinals stay stable for signed cross-mesh / persisted grants.
    limit_exempt, // bypass clone / per-class connection caps (and the +2 account bonus)
};

/// A compact flag set of operator capabilities.
pub const OperPrivileges = struct {
    set: std.EnumSet(Privilege) = .empty,

    pub const empty: OperPrivileges = .{};
    pub const full: OperPrivileges = .{ .set = std.EnumSet(Privilege).full };

    pub fn initMany(privileges: []const Privilege) OperPrivileges {
        return .{ .set = std.EnumSet(Privilege).initMany(privileges) };
    }

    pub fn fromNames(names: []const []const u8) RegistryError!OperPrivileges {
        var out = OperPrivileges.empty;
        for (names) |name| out.insert(try privilegeFromName(name));
        return out;
    }

    pub fn insert(self: *OperPrivileges, privilege: Privilege) void {
        self.set.insert(privilege);
    }

    /// Pack the privilege set into a portable u64 bitmask (one bit per Privilege,
    /// by enum ordinal). Used to carry privileges in signed cross-mesh oper
    /// grants. Stable as long as the Privilege enum only appends new members.
    pub fn toBits(self: OperPrivileges) u64 {
        var bits: u64 = 0;
        inline for (@typeInfo(Privilege).@"enum".field_names, @typeInfo(Privilege).@"enum".field_values) |f_name, f_value| {
            if (self.set.contains(@field(Privilege, f_name))) {
                bits |= @as(u64, 1) << @intCast(f_value);
            }
        }
        return bits;
    }

    /// Rebuild a privilege set from a u64 bitmask produced by `toBits`. Unknown
    /// bits (from a newer peer) are ignored.
    pub fn fromBits(bits: u64) OperPrivileges {
        var out = OperPrivileges.empty;
        inline for (@typeInfo(Privilege).@"enum".field_names, @typeInfo(Privilege).@"enum".field_values) |f_name, f_value| {
            if (bits & (@as(u64, 1) << @intCast(f_value)) != 0) {
                out.set.insert(@field(Privilege, f_name));
            }
        }
        return out;
    }

    pub fn has(self: OperPrivileges, privilege: Privilege) bool {
        return self.set.contains(privilege);
    }

    pub fn hasAny(self: OperPrivileges, needed: OperPrivileges) bool {
        var iter = needed.set.iterator();
        while (iter.next()) |privilege| {
            if (self.has(privilege)) return true;
        }
        return false;
    }

    pub fn hasAll(self: OperPrivileges, needed: OperPrivileges) bool {
        var iter = needed.set.iterator();
        while (iter.next()) |privilege| {
            if (!self.has(privilege)) return false;
        }
        return true;
    }

    pub fn require(self: OperPrivileges, privilege: Privilege) PrivilegeError!void {
        if (!self.has(privilege)) return error.MissingPrivilege;
    }

    pub fn count(self: OperPrivileges) usize {
        return self.set.count();
    }
};

/// OCG2 deliberately exports only moderation/continuity authority. Lifecycle,
/// mesh, services, grant-management, visibility, audit, and subscription bits
/// remain local to the authenticating node.
pub const ocg2_exportable_privileges = OperPrivileges.initMany(&.{
    .client_moderate,
    .channel_moderate,
    .client_kill,
    .oper_override,
    .limit_exempt,
});

pub const ocg2_exportable_bits = ocg2_exportable_privileges.toBits();

pub const Ocg2ExportError = error{NonExportablePrivilege};

/// Convert a typed local privilege set to the exact OCG2 subset. Refuse the
/// whole record if any local-only bit is present; silently narrowing a grant
/// would make the signed statement differ from operator intent.
pub fn ocg2ExportBits(privileges: OperPrivileges) Ocg2ExportError!u64 {
    const bits = privileges.toBits();
    if (bits & ~ocg2_exportable_bits != 0) return error.NonExportablePrivilege;
    return bits;
}

/// One account-to-operator-class binding. Slices are borrowed by the registry.
pub const OperBinding = struct {
    account_name: []const u8,
    class_name: []const u8,
    privileges: OperPrivileges,
    /// Optional custom WHOIS title (e.g. "Network Guardian"). Empty = generic.
    title: []const u8 = "",
    /// Event-Spine categories this oper is auto-subscribed to on elevation, as a
    /// raw `event_spine.CategoryMask.bits` value (stored as bits to keep this
    /// module dependency-free). 0 = subscribe to nothing; the oper must opt in
    /// per-category with `EVENT ADD`. Set from the `[[opers]]` `presubscribe`
    /// list at config load.
    presubscribe_bits: u64 = 0,
};

/// Successful operator elevation.
pub const OperGrant = struct {
    account_name: []const u8,
    class_name: []const u8,
    privileges: OperPrivileges,
    title: []const u8 = "",
    /// Event-Spine auto-subscription mask bits carried from the binding (see
    /// `OperBinding.presubscribe_bits`). A cross-mesh grant leaves this 0 — a
    /// remote oper subscribes explicitly.
    presubscribe_bits: u64 = 0,

    pub fn has(self: OperGrant, privilege: Privilege) bool {
        return self.privileges.has(privilege);
    }

    pub fn require(self: OperGrant, privilege: Privilege) PrivilegeError!void {
        return self.privileges.require(privilege);
    }
};

/// Structured reply concepts for the daemon command layer.
pub const ReplyKind = enum {
    fail,
    ok,
};

/// Stable names callers can map to daemon replies.
pub const ReplyCode = enum {
    account_required,
    account_not_oper,
    oper_granted,
    privilege_missing,
};

/// Typed reply metadata. It contains no rendered IRC text.
pub const Reply = struct {
    kind: ReplyKind,
    code: ReplyCode,
    account_name: ?[]const u8 = null,
    class_name: ?[]const u8 = null,
    privilege: ?Privilege = null,
};

pub const RegistryError = error{
    DuplicateAccount,
    EmptyPrivileges,
    InvalidAccountName,
    InvalidClassName,
    UnknownPrivilege,
};

pub const ElevationError = error{
    NotAuthenticated,
    NotAnOperator,
};

pub const PrivilegeError = error{
    MissingPrivilege,
};

/// Borrowed account registry. Construct with `init` to validate static data.
pub const OperRegistry = struct {
    bindings: []const OperBinding,

    pub fn init(bindings: []const OperBinding) RegistryError!OperRegistry {
        const registry = OperRegistry{ .bindings = bindings };
        try registry.validate(default_params);
        return registry;
    }

    pub fn initWithParams(comptime params: Params, bindings: []const OperBinding) RegistryError!OperRegistry {
        const registry = OperRegistry{ .bindings = bindings };
        try registry.validate(params);
        return registry;
    }

    pub fn validate(self: OperRegistry, comptime params: Params) RegistryError!void {
        for (self.bindings, 0..) |binding, index| {
            try validateAccountName(params, binding.account_name);
            try validateClassName(params, binding.class_name);
            if (binding.privileges.count() == 0) return error.EmptyPrivileges;

            for (self.bindings[0..index]) |previous| {
                if (accountNameEqual(previous.account_name, binding.account_name)) {
                    return error.DuplicateAccount;
                }
            }
        }
    }

    /// Elevate an optional verified account. Missing identity is distinct from
    /// a known account without an operator binding.
    pub fn elevate(self: OperRegistry, account: ?VerifiedAccount) ElevationError!OperGrant {
        const verified = account orelse return error.NotAuthenticated;
        return self.elevateAuthenticated(verified);
    }

    /// Elevate an already-authenticated account to its operator privileges.
    pub fn elevateAuthenticated(self: OperRegistry, account: VerifiedAccount) ElevationError!OperGrant {
        if (!isAccountName(default_params, account.name)) return error.NotAnOperator;
        const binding = self.lookup(account.name) orelse return error.NotAnOperator;
        return .{
            .account_name = binding.account_name,
            .class_name = binding.class_name,
            .privileges = binding.privileges,
            .title = binding.title,
            .presubscribe_bits = binding.presubscribe_bits,
        };
    }

    pub fn lookup(self: OperRegistry, account_name: []const u8) ?OperBinding {
        for (self.bindings) |binding| {
            if (accountNameEqual(binding.account_name, account_name)) return binding;
        }
        return null;
    }

    pub fn containsAccount(self: OperRegistry, account_name: []const u8) bool {
        return self.lookup(account_name) != null;
    }
};

/// Convenience entry point for command handlers that already hold a registry.
pub fn elevate(registry: OperRegistry, account: ?VerifiedAccount) ElevationError!OperGrant {
    return registry.elevate(account);
}

/// Check one privilege on a grant.
pub fn hasPrivilege(grant: OperGrant, privilege: Privilege) bool {
    return grant.has(privilege);
}

/// Require one privilege from a grant.
pub fn requirePrivilege(grant: OperGrant, privilege: Privilege) PrivilegeError!void {
    return grant.require(privilege);
}

/// Convert elevation errors into stable reply metadata.
pub fn replyForElevationError(err: ElevationError, account_name: ?[]const u8) Reply {
    return switch (err) {
        error.NotAuthenticated => .{
            .kind = .fail,
            .code = .account_required,
        },
        error.NotAnOperator => .{
            .kind = .fail,
            .code = .account_not_oper,
            .account_name = account_name,
        },
    };
}

/// Convert a successful grant into stable reply metadata.
pub fn replyForGrant(grant: OperGrant) Reply {
    return .{
        .kind = .ok,
        .code = .oper_granted,
        .account_name = grant.account_name,
        .class_name = grant.class_name,
    };
}

/// Convert a missing privilege into stable reply metadata.
pub fn replyForMissingPrivilege(grant: OperGrant, privilege: Privilege) Reply {
    return .{
        .kind = .fail,
        .code = .privilege_missing,
        .account_name = grant.account_name,
        .class_name = grant.class_name,
        .privilege = privilege,
    };
}

fn privilegeFromName(name: []const u8) RegistryError!Privilege {
    inline for (@typeInfo(Privilege).@"enum".field_names) |field_name| {
        if (std.mem.eql(u8, name, field_name)) return @field(Privilege, field_name);
    }
    return error.UnknownPrivilege;
}

fn validateAccountName(comptime params: Params, account_name: []const u8) RegistryError!void {
    if (!isBoundedAccountName(params, account_name)) return error.InvalidAccountName;
}

fn validateClassName(comptime params: Params, class_name: []const u8) RegistryError!void {
    if (class_name.len == 0 or class_name.len > params.max_class_len) return error.InvalidClassName;
    for (class_name) |ch| {
        const ok = (ch >= 'A' and ch <= 'Z') or
            (ch >= 'a' and ch <= 'z') or
            (ch >= '0' and ch <= '9') or
            ch == '_' or ch == '-' or ch == '.';
        if (!ok) return error.InvalidClassName;
    }
}

fn isAccountName(comptime params: Params, account_name: []const u8) bool {
    return isBoundedAccountName(params, account_name);
}

fn isBoundedAccountName(comptime params: Params, account_name: []const u8) bool {
    if (account_name.len == 0 or account_name.len > params.max_account_len) return false;
    for (account_name) |ch| {
        if (ch <= 0x20 or ch == 0x7f) return false;
    }
    return true;
}

fn accountNameEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "OCG2 export policy permits only frozen cross-mesh privileges" {
    const codec = @import("../proto/oper_cred_share.zig");
    const expected = OperPrivileges.initMany(&.{
        .client_moderate,
        .channel_moderate,
        .client_kill,
        .oper_override,
        .limit_exempt,
    });
    try std.testing.expectEqual(expected.toBits(), ocg2_exportable_bits);
    try std.testing.expectEqual(codec.ocg2_exportable_bits, ocg2_exportable_bits);
    try std.testing.expectEqual(ocg2_exportable_bits, try ocg2ExportBits(expected));
    try std.testing.expectEqual(@as(u64, 0), try ocg2ExportBits(.empty));
    inline for (.{
        Privilege.server_rehash,
        .server_restart,
        .server_shutdown,
        .mesh_admin,
        .service_admin,
        .server_admin,
        .oper_grant,
        .oper_spy,
        .event_subscribe,
        .audit_read,
    }) |local_only| {
        var mixed = expected;
        mixed.insert(local_only);
        try std.testing.expectError(error.NonExportablePrivilege, ocg2ExportBits(mixed));
    }
}

test "privilege bitmask round-trips through toBits/fromBits" {
    const orig = OperPrivileges.initMany(&.{ .client_kill, .server_admin, .oper_spy });
    const bits = orig.toBits();
    const back = OperPrivileges.fromBits(bits);
    try std.testing.expect(back.has(.client_kill));
    try std.testing.expect(back.has(.server_admin));
    try std.testing.expect(back.has(.oper_spy));
    try std.testing.expect(!back.has(.server_shutdown));
    // empty round-trips to empty; unknown high bits are ignored.
    try std.testing.expectEqual(@as(u64, 0), OperPrivileges.empty.toBits());
    try std.testing.expectEqual(@as(usize, 0), OperPrivileges.fromBits(1 << 63).count());
}

test "known SASL account elevates to configured operator class" {
    const admin_privileges = OperPrivileges.initMany(&.{
        .server_rehash,
        .client_moderate,
        .event_subscribe,
    });
    const bindings = [_]OperBinding{.{
        .account_name = "alice",
        .class_name = "netadmin",
        .privileges = admin_privileges,
    }};
    const registry = try OperRegistry.init(&bindings);

    const grant = try registry.elevate(.{ .name = "alice", .mechanism = .external });

    try std.testing.expectEqualStrings("alice", grant.account_name);
    try std.testing.expectEqualStrings("netadmin", grant.class_name);
    try std.testing.expect(grant.has(.server_rehash));
    try std.testing.expect(grant.has(.client_moderate));
    try std.testing.expect(grant.has(.event_subscribe));
    try std.testing.expect(!grant.has(.server_shutdown));

    const reply = replyForGrant(grant);
    try std.testing.expectEqual(ReplyKind.ok, reply.kind);
    try std.testing.expectEqual(ReplyCode.oper_granted, reply.code);
    try std.testing.expectEqualStrings("alice", reply.account_name.?);
}

test "unknown authenticated account is rejected as not an operator" {
    const bindings = [_]OperBinding{.{
        .account_name = "alice",
        .class_name = "netadmin",
        .privileges = OperPrivileges.initMany(&.{.server_rehash}),
    }};
    const registry = try OperRegistry.init(&bindings);

    const err: ElevationError = if (registry.elevate(.{ .name = "bob", .mechanism = .scram_sha_256 })) |_|
        return error.TestExpectedError
    else |e|
        e;
    try std.testing.expectEqual(error.NotAnOperator, err);

    const reply = replyForElevationError(err, "bob");
    try std.testing.expectEqual(ReplyKind.fail, reply.kind);
    try std.testing.expectEqual(ReplyCode.account_not_oper, reply.code);
    try std.testing.expectEqualStrings("bob", reply.account_name.?);
}

test "unauthenticated client is rejected before registry lookup" {
    const bindings = [_]OperBinding{.{
        .account_name = "alice",
        .class_name = "netadmin",
        .privileges = OperPrivileges.initMany(&.{.server_rehash}),
    }};
    const registry = try OperRegistry.init(&bindings);

    const err: ElevationError = if (registry.elevate(null)) |_|
        return error.TestExpectedError
    else |e|
        e;
    try std.testing.expectEqual(error.NotAuthenticated, err);

    const reply = replyForElevationError(err, null);
    try std.testing.expectEqual(ReplyKind.fail, reply.kind);
    try std.testing.expectEqual(ReplyCode.account_required, reply.code);
    try std.testing.expectEqual(@as(?[]const u8, null), reply.account_name);
}

test "privilege checks cover single, any, all, and missing privilege replies" {
    const grant = OperGrant{
        .account_name = "carol",
        .class_name = "services",
        .privileges = OperPrivileges.initMany(&.{
            .service_admin,
            .audit_read,
        }),
    };

    try std.testing.expect(hasPrivilege(grant, .service_admin));
    try requirePrivilege(grant, .audit_read);
    try std.testing.expectError(error.MissingPrivilege, requirePrivilege(grant, .server_shutdown));

    try std.testing.expect(grant.privileges.hasAny(OperPrivileges.initMany(&.{
        .server_shutdown,
        .service_admin,
    })));
    try std.testing.expect(!grant.privileges.hasAny(OperPrivileges.initMany(&.{
        .server_shutdown,
        .mesh_admin,
    })));
    try std.testing.expect(grant.privileges.hasAll(OperPrivileges.initMany(&.{
        .service_admin,
        .audit_read,
    })));
    try std.testing.expect(!grant.privileges.hasAll(OperPrivileges.initMany(&.{
        .service_admin,
        .mesh_admin,
    })));

    const reply = replyForMissingPrivilege(grant, .server_shutdown);
    try std.testing.expectEqual(ReplyKind.fail, reply.kind);
    try std.testing.expectEqual(ReplyCode.privilege_missing, reply.code);
    try std.testing.expectEqual(Privilege.server_shutdown, reply.privilege.?);
}

test "registry validation rejects duplicates, empty grants, and unknown flag names" {
    const duplicate_bindings = [_]OperBinding{
        .{
            .account_name = "alice",
            .class_name = "admin",
            .privileges = OperPrivileges.initMany(&.{.server_rehash}),
        },
        .{
            .account_name = "alice",
            .class_name = "admin2",
            .privileges = OperPrivileges.initMany(&.{.mesh_admin}),
        },
    };
    try std.testing.expectError(error.DuplicateAccount, OperRegistry.init(&duplicate_bindings));

    const empty_bindings = [_]OperBinding{.{
        .account_name = "dave",
        .class_name = "empty",
        .privileges = OperPrivileges.empty,
    }};
    try std.testing.expectError(error.EmptyPrivileges, OperRegistry.init(&empty_bindings));

    try std.testing.expectError(
        error.UnknownPrivilege,
        OperPrivileges.fromNames(&.{ "server_rehash", "not_a_privilege" }),
    );
}
