// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic Ocean simulation for the Design-C residence-trust gate (F1).
//!
//! A single receiver's `RouteTable` is driven over a seeded, virtual stream of
//! cross-node MEMBERSHIP claims for one contested nick ("kain") from two remote
//! nodes: a GENUINE multi-device node whose residence proof verifies during
//! seeded "proof-live" windows, and a BYZANTINE node that forges the same
//! account but can NEVER produce a valid proof (trusted is always false for it).
//! The seed derives the claim ordering, hlc jitter, partition drops, proof
//! expiry/refresh windows, and USR2 markers — so any failure replays
//! byte-for-byte from `0x...`.
//!
//! The load-bearing invariant is the STICKY-TRUST rule (blueprint §4.4 / R1):
//! a re-affirm from the node that ALREADY holds the nick is `.keep` — never a
//! UID re-gate — regardless of `trusted`. The residence proof gates the INITIAL
//! same-account coexist admission only; it must never continuously gate an
//! already-established member, so a proof that expires / is delayed by a
//! partition / is dropped across a USR2 / arrives reordered can NEVER rename a
//! live established member. Secondary invariants: an UNTRUSTED account never
//! unlocks any same-account short-circuit (F1 fail-closed), and a TRUSTED
//! genuine multi-device claim does coexist.
const std = @import("std");

const route_table = @import("route_table.zig");

const RouteTable = route_table.RouteTable;
const NickDecision = route_table.NickDecision;
const NodeId = route_table.NodeId;

/// Independent sub-stream derivation from one master seed (mirrors the sazanami
/// harness so both DST suites share the same replay discipline).
fn deriveSeed(master_seed: u64, stream: u64) u64 {
    var x = master_seed +% 0x9e37_79b9_7f4a_7c15 +% (stream << 1);
    x = (x ^ (x >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    x = (x ^ (x >> 27)) *% 0x94d0_49bb_1331_11eb;
    return x ^ (x >> 31);
}

const node_genuine: NodeId = 20; // real multi-device kain (proof can verify)
const node_byzantine: NodeId = 30; // forges account=kain, proof NEVER verifies
const contested_nick = "kain";
const contested_account = "kain";
const chan = "#room";

/// One seeded run. Returns an error (with the seed already logged by the caller)
/// on any invariant violation.
fn runOne(allocator: std.mem.Allocator, seed: u64) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    var table = try RouteTable.init(allocator, .{ .max_nicks = 32, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer table.deinit();

    // Whether the genuine node's proof is currently live (seeded window). The
    // Byzantine node's proof is NEVER live.
    var genuine_proof_live = false;
    var hlc: u64 = 100;

    const steps = 40 + rng.intRangeAtMost(usize, 0, 80);
    var i: usize = 0;
    while (i < steps) : (i += 1) {
        // Seeded environment transitions, each independent of the value clock.
        // Cases 2 and 3 (expiry / USR2) drop proof liveness: the sticky rule
        // must keep an established member alive through both.
        switch (rng.intRangeAtMost(u8, 0, 9)) {
            0, 1 => genuine_proof_live = true, // proof refreshed / converged
            2, 3 => genuine_proof_live = false, // proof expired / USR2 cache reset
            else => {},
        }

        // hlc jitter: usually advances, but sometimes a reordered/stale claim
        // arrives with an older clock (partition catch-up).
        if (rng.boolean()) {
            hlc += 1 + rng.intRangeAtMost(u64, 0, 5);
        } else if (hlc > 10) {
            hlc -= rng.intRangeAtMost(u64, 0, 10);
        }

        const from_genuine = rng.boolean();
        const node: NodeId = if (from_genuine) node_genuine else node_byzantine;
        if (rng.intRangeAtMost(u8, 0, 4) == 0) continue; // partition: claim dropped

        // The per-claim VERIFIED trust bool — exactly what s2s_peer computes.
        // Byzantine can never be trusted; genuine only while its proof is live.
        const trusted = from_genuine and genuine_proof_live;

        // Snapshot the incumbent BEFORE the decision: the sticky guarantee is
        // that a re-affirm from the CURRENT holder of the nick is `.keep`.
        const incumbent_before = table.nickNode(contested_nick);

        const decision = table.resolveIncomingNick(contested_nick, node, hlc, contested_account, trusted);

        // ---- Invariant 1: STICKY TRUST (R1). A re-affirm from the node that
        // already holds the real nick is ALWAYS `.keep` — never a UID re-gate —
        // regardless of `trusted` (expiry / partition / USR2 / reorder).
        if (incumbent_before) |holder| {
            if (holder == node and decision != .keep) {
                std.debug.print(
                    "STICKY VIOLATION: incumbent node {d} re-affirm re-gated: {s} (trusted={}, hlc={d})\n",
                    .{ node, @tagName(decision), trusted, hlc },
                );
                return error.StickyTrustViolated;
            }
        }

        // ---- Invariant 2: F1 fail-closed. An UNTRUSTED claim must never unlock
        // a same-account short-circuit (coexist / reclaim). It may only `.keep`
        // (same-node incumbent / uncontested) or `.rename_to_uid`.
        if (!trusted) {
            switch (decision) {
                .local_same_account, .remote_same_account, .reclaim_local => {
                    std.debug.print(
                        "F1 VIOLATION: untrusted node {d} unlocked {s} (hlc={d})\n",
                        .{ node, @tagName(decision), hlc },
                    );
                    return error.UntrustedShortCircuit;
                },
                .keep, .rename_to_uid => {},
            }
        }

        // Apply the claim the way s2s_peer would so the route-table state (and
        // thus the next step's incumbent) tracks reality: a UID rename applies
        // under the UID nick; every other outcome applies under the real nick.
        applyDecision(&table, decision, node, hlc);
    }

    // ---- Invariant 3: the trusted genuine path DOES restore coexistence. A
    // proof-live multi-device claim contesting a DIFFERENT-node incumbent must
    // coexist (remote_same_account), never UID.
    var t2 = try RouteTable.init(allocator, .{ .max_nicks = 32, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer t2.deinit();
    _ = try t2.applyMembership(chan, contested_nick, node_genuine, 0, 200, true, .{ .account = contested_account }, 0);
    const coexist = t2.resolveIncomingNick(contested_nick, node_byzantine, 100, contested_account, true);
    if (coexist != .remote_same_account) {
        std.debug.print("COEXIST VIOLATION: trusted multi-device claim did not coexist: {s}\n", .{@tagName(coexist)});
        return error.CoexistenceNotRestored;
    }

    // ---- Invariant 4: an UNTRUSTED same-account cross-node claim never
    // coexists — the same scenario as (3) but with the forged/unproven account.
    const forged = t2.resolveIncomingNick(contested_nick, node_byzantine, 100, contested_account, false);
    if (forged == .remote_same_account or forged == .reclaim_local or forged == .local_same_account) {
        std.debug.print("F1 VIOLATION (static): unproven cross-node claim coexisted: {s}\n", .{@tagName(forged)});
        return error.UntrustedShortCircuit;
    }

    // ---- Invariant 5 (mesh C1, the P2 store-side blank): a FORGED unproven
    // incumbent grants NO coexistence to a LATER genuinely-trusted newcomer. This
    // is the store half of F1: s2s_peer persists a forged (untrusted) claim
    // account-LESS (P2), so even a later newcomer whose OWN proof verifies cannot
    // `remote_same_account`-merge with the forged incumbent — the merge compares
    // against the STORED incumbent account, which is "". The forger thus never
    // draws a third node's same-account coexistence to itself.
    var t3 = try RouteTable.init(allocator, .{ .max_nicks = 32, .max_channels = 8, .max_nodes_per_channel = 8 });
    defer t3.deinit();
    // The Byzantine node's forged claim was UNTRUSTED, so s2s_peer stored it with
    // account="" (P2). Model exactly that: incumbent present under the real nick
    // but account-less.
    _ = try t3.applyMembership(chan, contested_nick, node_byzantine, 0, 100, true, .{ .account = "" }, 0);
    // A genuine multi-device newcomer from a different node arrives TRUSTED.
    const c1 = t3.resolveIncomingNick(contested_nick, node_genuine, 200, contested_account, true);
    if (c1 == .remote_same_account or c1 == .local_same_account or c1 == .reclaim_local) {
        std.debug.print("F1 VIOLATION (C1): forged account-less incumbent granted coexistence: {s}\n", .{@tagName(c1)});
        return error.UntrustedShortCircuit;
    }
}

fn applyDecision(table: *RouteTable, decision: NickDecision, node: NodeId, hlc: u64) void {
    const ident = route_table.MemberIdentity{ .account = contested_account };
    switch (decision) {
        .rename_to_uid => |uid| {
            _ = table.applyMembership(chan, uid[0..], node, 0, hlc, true, ident, 0) catch {};
        },
        .keep, .local_same_account, .remote_same_account, .reclaim_local => {
            _ = table.applyMembership(chan, contested_nick, node, 0, hlc, true, ident, 0) catch {};
        },
    }
}

test "Suimyaku mesh residence-trust DST: sticky trust + F1 fail-closed hold across a seeded fault campaign" {
    const allocator = std.testing.allocator;
    // A fixed campaign of master seeds — deterministic, replayable. Any failure
    // prints the exact seed so it reruns byte-for-byte.
    const campaign = [_]u64{ 0x1, 0x2, 0xF00D, 0xDEADBEEF, 0xA5A5_5A5A, 0x1234_5678_9ABC_DEF0, 0xC0FFEE, 0x0BADF00D };
    for (campaign) |master| {
        var s: u64 = 0;
        while (s < 64) : (s += 1) {
            const seed = deriveSeed(master, s);
            runOne(allocator, seed) catch |err| {
                std.debug.print("residence-trust DST FAILED at master=0x{x} sub={d} seed=0x{x}: {s}\n", .{ master, s, seed, @errorName(err) });
                return err;
            };
        }
    }
}
