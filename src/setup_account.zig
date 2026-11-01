// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical staged account bootstrap. No password serialization or alternative
//! verifier format: Services, SCRAM, and OroStore own those contracts.
const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");
const services = onyx.daemon.services;
pub const wal_name = "accounts.wal";
pub const snapshot_name = "accounts.wal.snap";
pub const mechanisms: []const []const u8 = &.{ "PLAIN over TLS", "SCRAM-SHA-256", "SCRAM-SHA-512" };

pub const Intent = struct {
    account: []const u8 = "",
    privileges: []const u8 = "none",
    pub fn enabled(self: Intent) bool {
        return self.account.len != 0;
    }
    pub fn canonical(self: Intent) !services.AccountName {
        return services.canonicalAccount(self.account);
    }
    pub fn permissions(self: Intent) !onyx.daemon.oper.OperPrivileges {
        var result = onyx.daemon.oper.OperPrivileges.empty;
        if (std.mem.eql(u8, self.privileges, "none")) return result;
        var tokens = std.mem.splitScalar(u8, self.privileges, ',');
        while (tokens.next()) |token| {
            const privilege = std.meta.stringToEnum(onyx.daemon.oper.Privilege, token) orelse return error.InvalidBootstrapPrivilege;
            if (result.has(privilege)) return error.DuplicateBootstrapPrivilege;
            result.insert(privilege);
        }
        return result;
    }
    pub fn validate(self: Intent) !void {
        const permissions_value = try self.permissions();
        if (!self.enabled()) {
            if (permissions_value.count() != 0) return error.BootstrapAccountRequired;
            return;
        }
        _ = try self.canonical();
    }
};

pub fn appendConfig(allocator: std.mem.Allocator, original: []const u8, final_dir: []const u8, intent: Intent) ![]u8 {
    try intent.validate();
    const name = try intent.canonical();
    const account = try std.json.Stringify.valueAlloc(allocator, name.asSlice(), .{});
    defer allocator.free(account);
    const path = try std.fs.path.join(allocator, &.{ final_dir, wal_name });
    defer allocator.free(path);
    const encoded_path = try std.json.Stringify.valueAlloc(allocator, path, .{});
    defer allocator.free(encoded_path);
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    out.writer.print("{s}\n[sasl]\nenabled = true\naccount_db = {s}\n", .{ original, encoded_path }) catch return error.OutOfMemory;
    if ((try intent.permissions()).count() != 0) {
        out.writer.writeAll("[[oper_groups]]\nname = \"setup-bootstrap\"\nprivileges = [") catch return error.OutOfMemory;
        var tokens = std.mem.splitScalar(u8, intent.privileges, ',');
        var first = true;
        while (tokens.next()) |token| {
            if (!first) out.writer.writeAll(", ") catch return error.OutOfMemory;
            out.writer.print("\"{s}\"", .{token}) catch return error.OutOfMemory;
            first = false;
        }
        out.writer.print("]\n[[opers]]\naccount = {s}\nclass = \"setup-bootstrap\"\n", .{account}) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice();
}

/// Caller precreates an owner-private empty WAL inside its unpublished stage.
/// A failure at any point must discard the whole stage, since ordinary live
/// registration deliberately allows PLAIN to precede a best-effort SCRAM mirror.
pub fn provision(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, intent: Intent, password: []const u8, fault: ?onyx.daemon.store.PreparedIoFault) !void {
    return provisionWithPolicy(allocator, io, dir, intent, password, fault, .production);
}

/// This namespace has no callable declaration in a non-test build. Ordinary
/// provision calls retain the production default even when compiled as tests.
/// Both KDF factors are selected per call; production defaults stay unchanged.
pub const AllocationFailureSweep = if (builtin.is_test) struct {
    pub fn provision(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, intent: Intent, password: []const u8, fault: ?onyx.daemon.store.PreparedIoFault) !void {
        return provisionWithPolicy(allocator, io, dir, intent, password, fault, .allocation_failure_sweep);
    }
} else struct {};

const ProvisionPolicy = enum { production, allocation_failure_sweep };

fn provisionWithPolicy(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, intent: Intent, password: []const u8, fault: ?onyx.daemon.store.PreparedIoFault, comptime work_policy: ProvisionPolicy) !void {
    if (comptime !builtin.is_test and work_policy != .production) @compileError("reduced bootstrap work is test-only");
    const service_config: services.Config = .{ .pbkdf2_rounds = if (work_policy == .production) services.default_pbkdf2_rounds else 1 };
    try intent.validate();
    const account = try intent.canonical();
    {
        var store = try services.OroStore.openWithConfig(allocator, io, dir, wal_name, .{});
        defer store.deinit();
        if (fault) |value| store.setPreparedIoFault(value);
        var scram = services.ScramStore.init(allocator);
        defer scram.deinit();
        var service = services.Services.initWithConfig(&store, null, service_config);
        service.attachScramStore(&scram);
        var scratch: [768]u8 = undefined;
        defer std.crypto.secureZero(u8, &scratch);
        const result = if (comptime work_policy == .production)
            try service.registerAccount(account.asSlice(), password, &scratch)
        else
            try services.Services.AllocationFailureSweep.registerAccount(&service, account.asSlice(), password, &scratch);
        if (result != .registered_account or store.preparedWritesPoisoned()) return error.BootstrapRegistrationFailed;
    }
    // Reconstruct exactly the runtime backends from durable bytes. This catches
    // swallowed SCRAM mirror writes and verifies both mechanisms after restart.
    var cold = try services.OroStore.openReadOnlyWithConfig(allocator, io, dir, wal_name, .{});
    defer cold.deinit();
    var scram = services.ScramStore.init(allocator);
    defer scram.deinit();
    var service = services.Services.initWithConfig(&cold, null, service_config);
    service.attachScramStore(&scram);
    scram.setLoader(service.scramLoader());
    const verified = try service.identifyAccount(account.asSlice(), password);
    if (verified != .identified) return error.BootstrapAuthenticationFailed;
    if (scram.resolve(account.asSlice()) == null or scram.resolve512(account.asSlice()) == null) return error.BootstrapScramPersistenceFailed;
}
