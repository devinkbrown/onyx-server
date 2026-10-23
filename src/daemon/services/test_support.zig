// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test support.

const std = @import("std");
const sign = @import("../../crypto/sign.zig");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const oper_session_provenance = @import("../oper_session_provenance.zig");
const ocg2_reconcile_schedule = @import("../ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("../ocg2_reconcile_workset.zig");
const entity_prop_event = @import("../../proto/entity_prop_event.zig");
const oper_cred_share = @import("../../proto/oper_cred_share.zig");
const node_identity_mod = @import("../node_identity.zig");
const node_short_id_mod = @import("../../crypto/node_short_id.zig");
const webpush_mod = @import("../webpush.zig");
const OroStore = @import("records.zig").OroStore;
const account_max = @import("records.zig").account_max;
const record_max = @import("records.zig").record_max;
const Config = @import("records.zig").Config;
const SessionTokenIssue = @import("records.zig").SessionTokenIssue;
const AccessInfo = @import("records.zig").AccessInfo;
const AkickInfo = @import("records.zig").AkickInfo;
const DurableOperLookup = @import("contracts.zig").DurableOperLookup;
const DurableOperTransactionCopy = @import("contracts.zig").DurableOperTransactionCopy;
const DurableOperReconcileObservation = @import("contracts.zig").DurableOperReconcileObservation;
const DurableOperSecurityHorizonCopy = @import("contracts.zig").DurableOperSecurityHorizonCopy;
const webpush_key_max = @import("contracts.zig").webpush_key_max;
const totp_secret_max = @import("contracts.zig").totp_secret_max;
const AfterCopyHook = @import("oper_shared.zig").AfterCopyHook;
const Services = @import("core.zig").Services;
const Internal = @import("core.zig").Internal;

pub fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

pub const webpush_prune_accounts = [_][]const u8{ "alpha", "beta", "delta", "epsilon", "gamma", "zeta" };

pub const webpush_prune_dead = [_][]const u8{ "https://push.example.test/dead-one", "https://push.example.test/dead-two", "https://push.example.test/dead-one" };

pub const webpush_prune_live = "https://push.example.test/live";

pub fn webpushPruneTestBlob(allocator: std.mem.Allocator, endpoints: []const []const u8) ![]u8 {
    const ecdsa = @import("../../crypto/ecdsa_p256.zig");
    const pair = try ecdsa.KeyPair.fromSecretKey(try ecdsa.SecretKey.fromBytes(@splat(1)));
    var subs: [webpush_mod.max_subscriptions_per_account]webpush_mod.Subscription = undefined;
    for (endpoints, subs[0..endpoints.len]) |endpoint, *sub| sub.* = .{
        .endpoint = @constCast(endpoint),
        .ua_public = pair.public_key.toUncompressedSec1(),
        .auth = @splat(7),
    };
    return webpush_mod.encodeList(allocator, subs[0..endpoints.len]);
}

pub fn webpushPruneTestSeed(services: *Services) !void {
    var scratch: [record_max]u8 = undefined;
    for (webpush_prune_accounts, 0..) |account, index| {
        _ = try services.registerAccount(account, "test-password", &scratch);
        const endpoints: []const []const u8 = if (index == 0)
            &.{ webpush_prune_dead[0], webpush_prune_dead[1] }
        else
            &.{ webpush_prune_dead[0], webpush_prune_live, webpush_prune_dead[1] };
        const blob = try webpushPruneTestBlob(std.testing.allocator, endpoints);
        defer std.testing.allocator.free(blob);
        try services.webpushPut(account, blob);
    }
    _ = try services.registerAccount("untouched", "test-password", &scratch);
    const live = try webpushPruneTestBlob(std.testing.allocator, &.{webpush_prune_live});
    defer std.testing.allocator.free(live);
    try services.webpushPut("untouched", live);
    try services.store.family(.props).put("mda\x00alpha\x00ordinary", "keep unrelated property");
}

/// Every examined row must equal its exact predecessor or its exact pruned
/// successor. An atomic group's publication is all four rows or none.
pub fn webpushPruneTestProgress(services: *Services) !usize {
    const live = try webpushPruneTestBlob(std.testing.allocator, &.{webpush_prune_live});
    defer std.testing.allocator.free(live);
    var changed: usize = 0;
    for (webpush_prune_accounts, 0..) |account, index| {
        var key_buf: [Internal.webpush_key_max]u8 = undefined;
        const key = Internal.webpushKey(&key_buf, account).?;
        const current = services.store.family(.props).get(key);
        if (index == 0 and current == null) {
            changed += 1;
            continue;
        }
        const actual = current orelse return error.MissingWebpushSubscription;
        if (index != 0 and std.mem.eql(u8, actual, live)) {
            changed += 1;
            continue;
        }
        const expected = try webpushPruneTestBlob(std.testing.allocator, if (index == 0)
            &.{ webpush_prune_dead[0], webpush_prune_dead[1] }
        else
            &.{ webpush_prune_dead[0], webpush_prune_live, webpush_prune_dead[1] });
        defer std.testing.allocator.free(expected);
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expectEqualStrings(live, services.store.family(.props).get("wps\x00untouched") orelse return error.MissingWebpushSubscription);
    try std.testing.expectEqualStrings("keep unrelated property", services.store.family(.props).get("mda\x00alpha\x00ordinary") orelse return error.MissingUnrelatedProperty);
    return changed;
}

pub fn durableServicesEvent(seed_byte: u8, account: []const u8, key: []const u8, hlc: u64, present: bool, value: []const u8) !entity_prop_event.EntityPropEvent {
    return durableServicesEventWithOwner(seed_byte, account, account, key, hlc, present, value);
}

pub fn durableServicesEventWithOwner(seed_byte: u8, account: []const u8, owner: []const u8, key: []const u8, hlc: u64, present: bool, value: []const u8) !entity_prop_event.EntityPropEvent {
    var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
    defer kp.deinit();
    const public_key = kp.public_key;
    var event = entity_prop_event.EntityPropEvent{
        .present = present,
        .kind = .user,
        .origin_node = entity_prop_event.originShortId(public_key),
        .hlc = hlc,
        .entity = account,
        .key = key,
        .value = value,
        .owner = owner,
    };
    const transcript = try entity_prop_event.originTranscript(std.testing.allocator, event);
    defer std.testing.allocator.free(transcript);
    const signature = try kp.signCtx(entity_prop_event.sign_domain, transcript);
    event.origin_pubkey = try std.testing.allocator.dupe(u8, &public_key);
    errdefer std.testing.allocator.free(event.origin_pubkey);
    event.origin_sig = try std.testing.allocator.dupe(u8, &signature);
    return event;
}

pub fn freeDurableServicesEvent(event: entity_prop_event.EntityPropEvent) void {
    std.testing.allocator.free(event.origin_pubkey);
    std.testing.allocator.free(event.origin_sig);
}

pub const AuthAtomicTestOperation = enum { enable, disable, replace, revoke, rotate, reset };

pub const auth_atomic_old_secret = "JBSWY3DPEHPK3PXP";

pub const auth_atomic_new_secret = "MZXW6YTBOI======";

pub const auth_atomic_old_password = "correct horse battery staple";

pub const auth_atomic_new_password = "a replacement password value";

pub fn authAtomicTestApply(services: *Services, operation: AuthAtomicTestOperation) !?SessionTokenIssue {
    switch (operation) {
        .enable, .replace => try services.totpPolicyCommit("ALICE", auth_atomic_new_secret),
        .disable => try services.totpPolicyCommit("ALICE", null),
        .revoke => try services.revokeSessionTokens("ALICE"),
        .rotate => return try services.issueSessionToken("ALICE", 1001),
        .reset => {
            var scratch: [record_max]u8 = undefined;
            try services.setAccountPasswordForced("ALICE", auth_atomic_new_password, &scratch);
        },
    }
    return null;
}

pub fn authAtomicTestExpectSecret(services: *Services, expected: ?[]const u8) !void {
    var out: [Services.totp_secret_max]u8 = undefined;
    const actual = services.totpSecretGet("ALICE", &out);
    if (expected) |secret| {
        try std.testing.expectEqualStrings(secret, actual orelse return error.MissingTotpPolicy);
        try std.testing.expect(services.totpEnrolled("alice"));
    } else {
        try std.testing.expect(actual == null);
        try std.testing.expect(!services.totpEnrolled("alice"));
    }
}

pub fn authAtomicTestExpectApplied(services: *Services, operation: AuthAtomicTestOperation, old: SessionTokenIssue, replacement: ?SessionTokenIssue) !void {
    var out: [account_max]u8 = undefined;
    try std.testing.expect(services.authenticationAvailable());
    try std.testing.expect(services.validateSessionToken("alice", old.tokenSlice(), 1002, &out) == null);
    if (replacement) |token| try std.testing.expect(services.validateSessionToken("alice", token.tokenSlice(), 1002, &out) != null);
    const expected_secret: ?[]const u8 = switch (operation) {
        .enable, .replace => auth_atomic_new_secret,
        .disable => null,
        else => auth_atomic_old_secret,
    };
    try authAtomicTestExpectSecret(services, expected_secret);
    if (operation == .reset) {
        try std.testing.expectError(error.AuthFailed, services.identifyAccount("alice", auth_atomic_old_password));
        _ = try services.identifyAccount("alice", auth_atomic_new_password);
        try std.testing.expect(services.store.family(.props).get("scram:alice") == null);
    }
}

pub const ServicesMtCtx = struct {
    services: *Services,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    pub fn accountName(out: *[account_max]u8, writer_id: usize, i: usize) []const u8 {
        return std.fmt.bufPrint(out, "svc{d}_{d}", .{ writer_id, i }) catch unreachable;
    }

    pub fn writer(ctx: *ServicesMtCtx) void {
        var scratch: [record_max]u8 = undefined;
        var name_buf: [account_max]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const name = accountName(&name_buf, ctx.writer_id, i);
            _ = ctx.services.registerAccount(name, "correct horse battery staple", &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            _ = ctx.services.setAccount(name, "correct horse battery staple", .{ .email = "thread@example.test" }, &scratch) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }

    pub fn reader(ctx: *ServicesMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            _ = ctx.services.identifyAccount("seed", "correct horse battery staple") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            const info = ctx.services.accountInfo("seed") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, info.account_info.name.asSlice(), "seed")) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            _ = ctx.services.ghostAccount("seed", "correct horse battery staple", "SeedNick") catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }
};

pub const Ocg2ProvMtCtx = struct {
    services: *Services,
    successor_wire: []const u8,
    failures: *std.atomic.Value(u32),
    result: oper_session_provenance.DurableOperLookup = .absent,

    pub fn writer(ctx: *Ocg2ProvMtCtx) void {
        switch (ctx.services.commitDurableOperRecord(ctx.successor_wire, 2_001)) {
            .committed => {},
            else => _ = ctx.failures.fetchAdd(1, .monotonic),
        }
    }

    pub fn reader(ctx: *Ocg2ProvMtCtx) void {
        for (0..32) |_| {
            const lookup = ctx.services.inspectDurableOperAuthority("alice", 2_001);
            switch (lookup) {
                .active => |grant| {
                    if (!std.mem.eql(u8, grant.account(), "alice") or
                        !(std.mem.eql(u8, grant.title(), "Initial") or std.mem.eql(u8, grant.title(), "Successor")))
                        _ = ctx.failures.fetchAdd(1, .monotonic);
                },
                else => _ = ctx.failures.fetchAdd(1, .monotonic),
            }
            // Keep the last copied result in caller-owned inline storage.  The
            // writer may replace the durable record concurrently; no borrowed
            // state slice is allowed to escape inspectDurableOperAuthority.
            ctx.result = lookup;
        }
    }
};

pub fn markDurableOperUnavailableAfterCopy(ctx: *anyopaque) void {
    const services: *Services = @ptrCast(@alignCast(ctx));
    Internal.markDurableOperUnavailableForTest(services);
}

pub fn signOcg2RaceWire(kp: std.crypto.sign.Ed25519.KeyPair, authority: durable_oper_authority.Config, account: []const u8, revision: u64, kind: oper_cred_share.Ocg2Kind, title: []const u8, issued_ms: u64, expiry_ms: u64, out: []u8) ![]const u8 {
    return out[0..try oper_cred_share.signOcg2(kp, .{
        .kind = kind,
        .account = account,
        .revision = revision,
        .privilege_bits = if (kind == .grant) 1 << 3 else 0,
        .class = if (kind == .grant) "moderator" else "",
        .title = if (kind == .grant) title else "",
        .authority_node_id = authority.authority_node_id,
        .authority_pubkey = authority.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = if (kind == .grant) expiry_ms else 0,
    }, issued_ms, out)];
}

pub const Ocg2AfterCopyAction = enum {
    successor,
    tombstone,
    equivocation,
    unrelated_account,
    two_successors,
};

pub const Ocg2AfterCopyRaceCtx = struct {
    services: *Services,
    action: Ocg2AfterCopyAction,
    wires: [2][]const u8,
    calls: usize = 0,

    pub fn hook(ctx: *anyopaque) void {
        const self: *Ocg2AfterCopyRaceCtx = @ptrCast(@alignCast(ctx));
        defer self.calls += 1;
        switch (self.action) {
            .two_successors => if (self.calls < 2) {
                _ = self.services.commitDurableOperRecord(self.wires[self.calls], 1_000);
            },
            else => if (self.calls == 0) {
                _ = self.services.commitDurableOperRecord(self.wires[0], 1_000);
            },
        }
    }

    pub fn asHook(self: *Ocg2AfterCopyRaceCtx) AfterCopyHook {
        return .{ .callback = hook, .context = self };
    }
};

pub const S6c2Horizon = struct {
    kp: std.crypto.sign.Ed25519.KeyPair,
    config: durable_oper_authority.Config,

    pub fn init(seed: u8) !S6c2Horizon {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
        const public_key = kp.public_key.toBytes();
        return .{
            .kp = kp,
            .config = .{
                .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
                .authority_pubkey = public_key,
            },
        };
    }
};

pub fn expectHorizonCopy(copy: Services.DurableOperSecurityHorizonCopy, effective_ms: u64, floor_ms: u64, reserved_until_ms: u64) !void {
    try std.testing.expectEqual(effective_ms, copy.effective_now_ms);
    try std.testing.expectEqual(floor_ms, copy.security_floor_ms);
    try std.testing.expectEqual(reserved_until_ms, copy.reserved_until_ms);
    try std.testing.expectEqual(reserved_until_ms - effective_ms, copy.remaining_ms);
}

pub const S6c5Auth = struct {
    kp: std.crypto.sign.Ed25519.KeyPair,
    config: durable_oper_authority.Config,

    pub fn init(seed: u8) !S6c5Auth {
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
        const public_key = kp.public_key.toBytes();
        return .{
            .kp = kp,
            .config = .{
                .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
                .authority_pubkey = public_key,
            },
        };
    }
};

pub fn s6c5WorkFromCopy(copy: durable_oper_authority.TransactionCopy, now_ms: u64, cause: ocg2_reconcile_workset.Cause) !ocg2_reconcile_workset.WorkItem {
    var hints: [1]ocg2_reconcile_schedule.ReinspectHint = undefined;
    switch (ocg2_reconcile_schedule.build((&copy)[0..1], now_ms, &hints)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
    var expected = ocg2_reconcile_workset.BaselineEntry{
        .revision = hints[0].revision,
        .digest = hints[0].digest,
        .wire_sha256 = hints[0].wire_sha256,
        .phase = hints[0].phase,
        .next_transition_ms = hints[0].next_transition_ms,
        .account_len = hints[0].account_len,
    };
    @memcpy(expected.account_buf[0..hints[0].account_len], hints[0].account_buf[0..hints[0].account_len]);
    return .{ .cause = cause, .expected = expected };
}

pub fn s6c5Copied(services: *Services, out: []Services.DurableOperTransactionCopy) ![]Services.DurableOperTransactionCopy {
    switch (services.copyDurableOperTransactions(out)) {
        .copied => |n| return out[0..n],
        else => return error.TestUnexpectedResult,
    }
}

pub fn s6c5WorkForAccount(services: *Services, account: []const u8, now_ms: u64, cause: ocg2_reconcile_workset.Cause) !ocg2_reconcile_workset.WorkItem {
    var copies: [durable_oper_authority.max_records]Services.DurableOperTransactionCopy = undefined;
    const listed = try s6c5Copied(services, &copies);
    for (listed) |copy| {
        if (std.mem.eql(u8, copy.account(), account)) return s6c5WorkFromCopy(copy, now_ms, cause);
    }
    return error.TestUnexpectedResult;
}

pub fn s6c5XorConflictDigest(state: *durable_oper_authority.State, account: []const u8) void {
    for (state.records.items) |*record| {
        if (std.mem.eql(u8, record.account, account)) {
            record.conflict_digest = record.digest;
            return;
        }
    }
}

pub const S6c5MtCtx = struct {
    services: *Services,
    expected: ocg2_reconcile_workset.WorkItem,
    successor_wire: []const u8,
    failures: *std.atomic.Value(u32),
    published: *std.atomic.Value(bool),
    last: Services.DurableOperReconcileObservation = .disabled,
    saw_stale_after_publish: bool = false,

    pub fn writer(ctx: *S6c5MtCtx) void {
        switch (ctx.services.commitDurableOperRecord(ctx.successor_wire, 2_001)) {
            .committed => {},
            else => _ = ctx.failures.fetchAdd(1, .monotonic),
        }
        ctx.published.store(true, .release);
    }

    pub fn observeStale(ctx: *S6c5MtCtx, began_after_publish: bool) void {
        const observed = ctx.services.inspectDurableOperReconcileWork(ctx.expected, 2_001);
        if (began_after_publish) {
            switch (observed) {
                .superseded => {},
                else => _ = ctx.failures.fetchAdd(1, .monotonic),
            }
            ctx.saw_stale_after_publish = true;
        } else {
            switch (observed) {
                .matched_active => |grant| {
                    if (!std.mem.eql(u8, grant.account(), "alice") or
                        !std.mem.eql(u8, grant.title(), "Initial") or
                        grant.revision != 1)
                        _ = ctx.failures.fetchAdd(1, .monotonic);
                },
                .superseded => {},
                else => _ = ctx.failures.fetchAdd(1, .monotonic),
            }
        }
        ctx.last = observed;
    }

    pub fn reader(ctx: *S6c5MtCtx) void {
        for (0..32) |_| {
            ctx.observeStale(ctx.published.load(.acquire));
        }
        while (!ctx.published.load(.acquire)) {
            std.atomic.spinLoopHint();
        }
        ctx.observeStale(true);
    }
};

pub fn accessListsMatch(left: []const AccessInfo, right: []const AccessInfo) bool {
    if (left.len != right.len) return false;
    for (left) |row| {
        var found = false;
        for (right) |other| {
            if (row.level == other.level and
                std.mem.eql(u8, row.account.asSlice(), other.account.asSlice()) and
                std.mem.eql(u8, row.channel.asSlice(), other.channel.asSlice()))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

pub fn akickListsMatch(left: []const AkickInfo, right: []const AkickInfo) bool {
    if (left.len != right.len) return false;
    for (left) |row| {
        var found = false;
        for (right) |other| {
            if (std.mem.eql(u8, row.mask.asSlice(), other.mask.asSlice()) and
                std.mem.eql(u8, row.reason.asSlice(), other.reason.asSlice()) and
                std.mem.eql(u8, row.setter.asSlice(), other.setter.asSlice()) and
                std.mem.eql(u8, row.channel.asSlice(), other.channel.asSlice()))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}
