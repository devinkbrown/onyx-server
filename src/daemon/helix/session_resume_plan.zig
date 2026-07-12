// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free post-Helix-upgrade session resume planner.
//!
//! After an in-place Helix upgrade, the successor process is handed back two
//! things: the decoded per-account session capsules (the durable bouncer /
//! multi-session registry, see `session_capsule.zig`) and the set of live
//! connections that were successfully migrated, identified by client id. This
//! planner reconstructs, for every session across every account, whether that
//! session is now ATTACHED (its underlying connection survived the migration
//! and appears in the live set) or DETACHED (the connection did not survive, so
//! a replay buffer must be drained when a client re-attaches).
//!
//! The planner is pure and std-only: it never allocates. It flattens all
//! sessions across the supplied capsules into a caller-provided `out` slice,
//! borrowing the account and token string slices from the input capsules, so
//! both the capsules and `out` must outlive the returned plan.
//!
//! Inconsistencies detected:
//!   - `error.TooMany`        when the flattened session count exceeds `out.len`
//!   - `error.DuplicateToken` when two sessions (anywhere in the set) share a
//!                            token; tokens are the registry's unique key, so a
//!                            collision means a corrupt or merged registry.

const std = @import("std");
const session_capsule = @import("session_capsule.zig");

/// Errors produced by the planner.
pub const Error = error{
    /// The flattened session count exceeded the caller-supplied `out` slice.
    TooMany,
    /// Two sessions in the set shared a token; tokens must be globally unique.
    DuplicateToken,
};

/// The resolved post-upgrade state of a single session.
///
/// `account` and `token` borrow the input capsules; `attached` reflects whether
/// the session's client id was present in the migrated live-client set.
pub const SessionState = struct {
    account: []const u8,
    token: []const u8,
    signon_unix: i64,
    attached: bool,
    /// The detached session's encoded restore snapshot (v2 capsules; empty when
    /// none). Passed through verbatim so a resumed bouncer session restores
    /// byte-identically instead of degrading to a bare reclaim token.
    snapshot: []const u8 = &.{},
};

/// Reconstruct the multi-session registry's attach/detach state after a Helix
/// upgrade.
///
/// For every session in every capsule, the session is `attached` iff its
/// `client` id appears in `live_client_ids` (the connections that successfully
/// migrated); otherwise it is detached and will need its replay buffer drained.
/// All sessions are flattened, in capsule-then-session order, into `out`.
///
/// Returns:
///   - `error.TooMany`        if the total session count exceeds `out.len`
///   - `error.DuplicateToken` if any two sessions share a token
///
/// On success returns the written prefix of `out`.
pub fn plan(
    capsules: []const session_capsule.SessionCapsule,
    live_client_ids: []const u64,
    out: []SessionState,
) Error![]SessionState {
    var n: usize = 0;

    for (capsules) |capsule| {
        for (capsule.sessions) |entry| {
            if (n >= out.len) return error.TooMany;

            // Bounded duplicate-token check against everything written so far.
            // O(n^2) but allocation-free and fine for realistic session counts.
            var i: usize = 0;
            while (i < n) : (i += 1) {
                if (std.mem.eql(u8, out[i].token, entry.token)) {
                    return error.DuplicateToken;
                }
            }

            out[n] = .{
                .account = capsule.account,
                .token = entry.token,
                .signon_unix = entry.signon_unix,
                .attached = containsClient(live_client_ids, entry.client),
                .snapshot = entry.snapshot,
            };
            n += 1;
        }
    }

    return out[0..n];
}

/// Count the sessions resolved to ATTACHED.
pub fn countAttached(states: []const SessionState) usize {
    var count: usize = 0;
    for (states) |s| {
        if (s.attached) count += 1;
    }
    return count;
}

/// Count the sessions resolved to DETACHED (replay buffer needed).
pub fn countDetached(states: []const SessionState) usize {
    var count: usize = 0;
    for (states) |s| {
        if (!s.attached) count += 1;
    }
    return count;
}

/// Linear membership test over the live-client id set.
fn containsClient(live_client_ids: []const u64, client: u64) bool {
    for (live_client_ids) |id| {
        if (id == client) return true;
    }
    return false;
}

// --- tests ------------------------------------------------------------------

const SessionEntry = session_capsule.SessionEntry;
const SessionCapsule = session_capsule.SessionCapsule;

test "plan attaches sessions whose client migrated and detaches the rest" {
    const alice_sessions = [_]SessionEntry{
        .{ .token = "alice-tok-1", .signon_unix = 1_700_000_001, .detached = false, .client = 10 },
        .{ .token = "alice-tok-2", .signon_unix = 1_700_000_002, .detached = true, .client = 20, .snapshot = "alice-restore-blob" },
    };
    const bob_sessions = [_]SessionEntry{
        .{ .token = "bob-tok-1", .signon_unix = 1_700_000_003, .detached = false, .client = 30 },
        .{ .token = "bob-tok-2", .signon_unix = 1_700_000_004, .detached = true, .client = 40 },
        .{ .token = "bob-tok-3", .signon_unix = 1_700_000_005, .detached = false, .client = 50 },
    };

    const capsules = [_]SessionCapsule{
        .{ .account = "alice", .sessions = &alice_sessions },
        .{ .account = "bob", .sessions = &bob_sessions },
    };

    // Clients 10, 30, 50 survived the migration; 20 and 40 did not.
    const live = [_]u64{ 10, 30, 50 };

    var out: [16]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 5), states.len);

    // alice-tok-1 (client 10) -> attached
    try std.testing.expectEqualStrings("alice", states[0].account);
    try std.testing.expectEqualStrings("alice-tok-1", states[0].token);
    try std.testing.expectEqual(@as(i64, 1_700_000_001), states[0].signon_unix);
    try std.testing.expectEqual(true, states[0].attached);

    // alice-tok-2 (client 20) -> detached; restore snapshot passes through verbatim.
    try std.testing.expectEqualStrings("alice-tok-2", states[1].token);
    try std.testing.expectEqual(false, states[1].attached);
    try std.testing.expectEqualSlices(u8, "alice-restore-blob", states[1].snapshot);

    // bob-tok-1 (client 30) -> attached
    try std.testing.expectEqualStrings("bob", states[2].account);
    try std.testing.expectEqualStrings("bob-tok-1", states[2].token);
    try std.testing.expectEqual(true, states[2].attached);

    // bob-tok-2 (client 40) -> detached
    try std.testing.expectEqualStrings("bob-tok-2", states[3].token);
    try std.testing.expectEqual(false, states[3].attached);

    // bob-tok-3 (client 50) -> attached
    try std.testing.expectEqualStrings("bob-tok-3", states[4].token);
    try std.testing.expectEqual(true, states[4].attached);

    try std.testing.expectEqual(@as(usize, 3), countAttached(states));
    try std.testing.expectEqual(@as(usize, 2), countDetached(states));
}

test "plan with empty live set detaches everything" {
    const sessions = [_]SessionEntry{
        .{ .token = "t1", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "t2", .signon_unix = 2, .detached = false, .client = 2 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "acct", .sessions = &sessions },
    };

    const live = [_]u64{};

    var out: [4]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 2), states.len);
    try std.testing.expectEqual(@as(usize, 0), countAttached(states));
    try std.testing.expectEqual(@as(usize, 2), countDetached(states));
}

test "plan returns DuplicateToken when two sessions share a token" {
    const alice_sessions = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 1, .detached = false, .client = 1 },
    };
    const bob_sessions = [_]SessionEntry{
        .{ .token = "shared-tok", .signon_unix = 2, .detached = true, .client = 2 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "alice", .sessions = &alice_sessions },
        .{ .account = "bob", .sessions = &bob_sessions },
    };

    const live = [_]u64{ 1, 2 };

    var out: [8]SessionState = undefined;
    try std.testing.expectError(error.DuplicateToken, plan(&capsules, &live, &out));
}

test "plan returns TooMany when out is too small" {
    const sessions = [_]SessionEntry{
        .{ .token = "a", .signon_unix = 1, .detached = false, .client = 1 },
        .{ .token = "b", .signon_unix = 2, .detached = false, .client = 2 },
        .{ .token = "c", .signon_unix = 3, .detached = false, .client = 3 },
    };
    const capsules = [_]SessionCapsule{
        .{ .account = "acct", .sessions = &sessions },
    };

    const live = [_]u64{1};

    var out: [2]SessionState = undefined; // too small for 3 sessions
    try std.testing.expectError(error.TooMany, plan(&capsules, &live, &out));
}

test "plan over zero capsules yields an empty plan" {
    const capsules = [_]SessionCapsule{};
    const live = [_]u64{ 1, 2, 3 };

    var out: [4]SessionState = undefined;
    const states = try plan(&capsules, &live, &out);

    try std.testing.expectEqual(@as(usize, 0), states.len);
    try std.testing.expectEqual(@as(usize, 0), countAttached(states));
    try std.testing.expectEqual(@as(usize, 0), countDetached(states));
}
