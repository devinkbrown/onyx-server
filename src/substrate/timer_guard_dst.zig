// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Seed-replayable ≥2-reactor timer-guard DST (0.7 P0-3).
//!
//! Models the contract in `docs/audit/timer-guard-0.7.md` §2.1: shared
//! maintenance work and its throttle counters advance only on the maintenance
//! reactor (reactor 0 with `current_reactor` set). A sibling tick that holds
//! no peer links must not steal a shared counter or wipe published peer
//! identity. `N == 1` is recorded as vacuous so the suite cannot green on
//! that coincidence.
const std = @import("std");

pub const shard_count_min = 2;
pub const site_count = 31;

pub const Site = enum(u8) {
    usr2_upgrade_poll,
    maybe_reload_acme_tls,
    maybe_swap_ocsp_staple,
    nick_delay_sweep,
    tick_ocg2_runtime,
    conn_throttle_prune,
    login_throttle_sweep,
    pending_migrations_sweep,
    sweep_session_replica_store,
    retry_deferred_relay_v2,
    retry_relay_v2_outbox,
    retry_e2ee_group_custody,
    access_prune_expired,
    sweep_mesh_auto_connect,
    maybe_probe_mesh_peer_rtt,
    publish_peer_count,
    oper_grant_refresh,
    refresh_portable_session_replicas,
    refresh_attached_session_leases,
    membership_resync,
    stale_member_reap,
    retry_dirty_session_replica_tokens,
    retry_dirty_session_replica_projections,
    retry_session_replica_store_stages,
    resume_session_replica_replays,
    retry_orphaned_local_session_revokes,
    retry_webhook_resume,
    save_event_history,
    event_collapse_flush,
    /// Grep-invisible internals (P0-TG-2).
    publish_peer_count_internal,
    maybe_probe_rtt_internal,
};

pub const Guard = enum { call_site, internal, both };

pub fn siteGuard(site: Site) Guard {
    return switch (site) {
        .tick_ocg2_runtime, .sweep_mesh_auto_connect, .retry_webhook_resume => .both,
        .maybe_probe_mesh_peer_rtt, .publish_peer_count => .call_site,
        .publish_peer_count_internal, .maybe_probe_rtt_internal => .internal,
        else => .call_site,
    };
}

pub const Model = struct {
    shard_count: u8,
    /// `null` models an off-reactor thread (`current_reactor` unset).
    current_reactor: ?u8 = 0,
    work: [site_count]u32 = @splat(0),
    counter: [site_count]u32 = @splat(0),
    peer_names: u32 = 0,
    last_peer_rtt_probe: u32 = 0,

    pub fn init(shards: u8) Model {
        std.debug.assert(shards >= 1);
        return .{ .shard_count = shards, .peer_names = 2 };
    }

    pub fn isMaintenanceReactor(self: *const Model) bool {
        return self.current_reactor != null and self.current_reactor.? == 0;
    }

    pub fn tick(self: *Model, site: Site) void {
        if (!self.isMaintenanceReactor()) return;
        const i = @intFromEnum(site);
        self.work[i] += 1;
        self.counter[i] += 1;
        if (site == .publish_peer_count or site == .publish_peer_count_internal) {
            self.peer_names = 2;
        }
        if (site == .maybe_probe_mesh_peer_rtt or site == .maybe_probe_rtt_internal) {
            self.last_peer_rtt_probe += 1;
        }
    }

    /// Buggy sibling path: advance the shared counter / wipe peers without work.
    pub fn stolenTick(self: *Model, site: Site) void {
        const i = @intFromEnum(site);
        self.counter[i] += 1;
        if (site == .publish_peer_count or site == .publish_peer_count_internal) {
            self.peer_names = 0;
        }
        if (site == .maybe_probe_mesh_peer_rtt or site == .maybe_probe_rtt_internal) {
            self.last_peer_rtt_probe += 1;
        }
    }
};

fn allSites() [site_count]Site {
    var out: [site_count]Site = undefined;
    for (&out, 0..) |*slot, i| slot.* = @enumFromInt(i);
    return out;
}

fn shuffleSites(prng: *std.Random.DefaultPrng, sites: *[site_count]Site) void {
    var i: usize = sites.len;
    while (i > 1) {
        i -= 1;
        const j = prng.random().uintLessThan(usize, i + 1);
        const tmp = sites.*[i];
        sites.*[i] = sites.*[j];
        sites.*[j] = tmp;
    }
}

fn runCampaign(seed: u64, shards: u8) Model {
    var prng = std.Random.DefaultPrng.init(seed);
    var model = Model.init(shards);
    var sites = allSites();
    shuffleSites(&prng, &sites);
    for (0..shards) |shard| {
        model.current_reactor = @intCast(shard);
        for (sites) |site| model.tick(site);
    }
    return model;
}

test "DST: timer-guard ≥2 shards refuses sibling counter theft" {
    const seed: u64 = 0x7e7e_0003;
    const model = runCampaign(seed, 2);
    for (0..site_count) |i| {
        if (model.work[i] != 1 or model.counter[i] != 1) {
            std.debug.print("DST timer-guard mismatch seed={d} site={s} work={d} counter={d}\n", .{
                seed,
                @tagName(@as(Site, @enumFromInt(i))),
                model.work[i],
                model.counter[i],
            });
            return error.TimerGuardTheft;
        }
    }
    try std.testing.expectEqual(@as(u32, 2), model.peer_names);
}

test "DST: timer-guard publishPeerCount sibling cannot wipe peer table" {
    var model = Model.init(2);
    model.current_reactor = 1;
    const before = model.peer_names;
    model.tick(.publish_peer_count);
    model.tick(.publish_peer_count_internal);
    try std.testing.expectEqual(before, model.peer_names);
    try std.testing.expectEqual(@as(u32, 0), model.work[@intFromEnum(Site.publish_peer_count)]);
}

test "DST: timer-guard maybeProbeMeshPeerRtt does not steal probe cadence" {
    var model = Model.init(2);
    model.current_reactor = 1;
    model.tick(.maybe_probe_mesh_peer_rtt);
    model.tick(.maybe_probe_rtt_internal);
    try std.testing.expectEqual(@as(u32, 0), model.last_peer_rtt_probe);
}

test "DST: timer-guard seed-replayable across shuffled ticks" {
    const seed: u64 = 0x5eed_0d57;
    const a = runCampaign(seed, 3);
    const b = runCampaign(seed, 3);
    try std.testing.expectEqualSlices(u32, &a.work, &b.work);
    try std.testing.expectEqualSlices(u32, &a.counter, &b.counter);
    try std.testing.expectEqual(a.peer_names, b.peer_names);
    try std.testing.expectEqual(a.last_peer_rtt_probe, b.last_peer_rtt_probe);
}

test "DST: timer-guard N=1 is vacuous for inverted guards" {
    var honest = Model.init(1);
    var inverted = Model.init(1);
    for (allSites()) |site| {
        honest.current_reactor = 0;
        honest.tick(site);
        inverted.current_reactor = 0;
        inverted.stolenTick(site);
    }
    try std.testing.expectEqual(@as(u32, site_count), sum(&honest.work));
    try std.testing.expectEqual(@as(u32, 0), sum(&inverted.work));
    try std.testing.expectEqual(sum(&honest.counter), sum(&inverted.counter));
}

test "DST: timer-guard unset current_reactor is not maintenance" {
    var model = Model.init(2);
    model.current_reactor = null;
    for (allSites()) |site| model.tick(site);
    try std.testing.expectEqual(@as(u32, 0), sum(&model.work));
    try std.testing.expectEqual(@as(u32, 0), sum(&model.counter));
    try std.testing.expectEqual(@as(u32, 2), model.peer_names);
}

test "DST: timer-guard stolen sibling path is the detectable counterexample" {
    var model = Model.init(2);
    model.current_reactor = 1;
    model.stolenTick(.publish_peer_count);
    model.stolenTick(.maybe_probe_mesh_peer_rtt);
    try std.testing.expectEqual(@as(u32, 0), model.peer_names);
    try std.testing.expectEqual(@as(u32, 1), model.last_peer_rtt_probe);
    try std.testing.expectEqual(@as(u32, 0), model.work[@intFromEnum(Site.publish_peer_count)]);
}

fn sum(values: []const u32) u32 {
    var total: u32 = 0;
    for (values) |v| total += v;
    return total;
}

test "timer-guard site table covers the audit 29 plus P0-TG-2 internals" {
    try std.testing.expectEqual(@as(usize, 31), site_count);
    try std.testing.expectEqual(Guard.call_site, siteGuard(.publish_peer_count));
    try std.testing.expectEqual(Guard.internal, siteGuard(.publish_peer_count_internal));
    try std.testing.expectEqual(Guard.both, siteGuard(.sweep_mesh_auto_connect));
}
