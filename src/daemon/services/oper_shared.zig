// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper shared.

const std = @import("std");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const ocg2_reconcile_schedule = @import("../ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("../ocg2_reconcile_workset.zig");

/// Private post-copy test hook. Production callers pass null; tests use it to
/// deterministically merge a successor between detached crypto and the exact
/// latest-tuple recheck without exposing a production race-control API.
pub const AfterCopyHook = struct {
    callback: *const fn (*anyopaque) void,
    context: *anyopaque,
};

pub fn ocg2ReconcileAccountCanonical(account: []const u8) bool {
    if (account.len == 0 or account.len > durable_oper_authority.max_account_len) return false;
    for (account) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '-';
        if (!ok) return false;
    }
    return true;
}

pub fn ocg2ReconcileExpectedValid(expected: ocg2_reconcile_workset.BaselineEntry, now_ms: u64) bool {
    if (expected.account_len == 0 or expected.account_len > expected.account_buf.len or
        expected.account_len > durable_oper_authority.max_account_len)
        return false;
    if (!ocg2ReconcileAccountCanonical(expected.account_buf[0..expected.account_len])) return false;
    if (expected.revision == 0) return false;
    const live = expected.phase == .not_yet_valid or expected.phase == .active;
    const terminal = expected.phase == .expired or expected.phase == .tombstone or expected.phase == .equivocation;
    if (live) {
        const deadline = expected.next_transition_ms orelse return false;
        return deadline > now_ms;
    }
    if (terminal) return expected.next_transition_ms == null;
    return false;
}

pub fn ocg2ReconcileIdentityMatches(
    expected: ocg2_reconcile_workset.BaselineEntry,
    hint: ocg2_reconcile_schedule.ReinspectHint,
) bool {
    if (expected.account_len != hint.account_len) return false;
    if (!std.mem.eql(
        u8,
        expected.account_buf[0..expected.account_len],
        hint.account_buf[0..hint.account_len],
    )) return false;
    if (expected.revision != hint.revision) return false;
    if (!std.mem.eql(u8, &expected.digest, &hint.digest)) return false;
    if (!std.mem.eql(u8, &expected.wire_sha256, &hint.wire_sha256)) return false;
    if (expected.phase != hint.phase) return false;
    if (expected.next_transition_ms) |left| {
        return if (hint.next_transition_ms) |right| left == right else false;
    }
    return hint.next_transition_ms == null;
}

pub fn ocg2ReconcileLiveMatchesCopy(
    state: *durable_oper_authority.State,
    availability_epoch: u64,
    current_epoch: u64,
    state_identity: *durable_oper_authority.State,
    account: []const u8,
    copy: *const durable_oper_authority.TransactionCopy,
) bool {
    if (state != state_identity or !state.servingAvailable() or current_epoch != availability_epoch)
        return false;
    const latest = state.latest(account) orelse return false;
    var live_sha: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(latest.wire, &live_sha, .{});
    const authority = state.authority();
    return latest.revision == copy.revision and
        latest.kind == copy.kind and
        latest.issued_ms == copy.issued_ms and
        latest.expiry_ms == copy.expiry_ms and
        latest.equivocation == copy.equivocation and
        std.mem.eql(u8, latest.account, copy.account()) and
        std.mem.eql(u8, &latest.digest, &copy.digest) and
        std.mem.eql(u8, &live_sha, &copy.wire_sha256) and
        std.mem.eql(u8, &latest.conflict_digest, &copy.conflict_digest) and
        authority.authority_node_id == copy.authority_node_id and
        std.mem.eql(u8, &authority.authority_pubkey, &copy.authority_pubkey) and
        std.mem.eql(u8, latest.wire, copy.signedWire());
}
