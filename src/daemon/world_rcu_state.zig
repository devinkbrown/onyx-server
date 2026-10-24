// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable state and reader-participant ownership for World RCU mirrors.
//!
//! The state records are heap allocated by `World` so each EBR `Domain` keeps
//! a stable address when the owning World is moved. Reader participants are
//! cached per thread and keyed by both that address and the state's generation;
//! teardown must unregister matching cached entries before the domain deinit.

const std = @import("std");
const ebr = @import("../substrate/ebr.zig");
const world_rcu = @import("world_rcu.zig");

/// Lazily-created RCU mirror of the nick registry (the lock-free read path).
/// Once active, it supplies nick -> client reads while `client_nicks` remains
/// the authoritative client -> nick reverse index. `World` heap-allocates this
/// state so `domain` has a stable address after the owner moves.
pub const RcuNickState = struct {
    domain: ebr.Domain,
    generation: usize,
    /// CoW writers only; reader threads use cached per-thread participants.
    writer_participant: *ebr.Participant,
    nicks: world_rcu.NickRegistry,
};

/// RCU channel existence and per-channel membership mirrors. `World` heap-
/// allocates each membership set because the map may rehash while the EBR
/// domain and writer participant remain stable.
pub const RcuChannelState = struct {
    domain: ebr.Domain,
    generation: usize,
    writer_participant: *ebr.Participant,
    /// Channel name -> OID witness; no pointer into the authoritative map.
    names: world_rcu.ChannelRegistry(u32),
    /// One membership set per live channel, keyed by folded channel name.
    members: std.StringHashMapUnmanaged(*world_rcu.MembershipSet) = .empty,
};

const RcuTlsEntry = struct {
    domain: ?*ebr.Domain = null,
    generation: usize = 0,
    participant: ?*ebr.Participant = null,
};

threadlocal var rcu_tls_entries: [ebr.max_participants]RcuTlsEntry = @splat(.{});
var rcu_generation = std.atomic.Value(usize).init(1);

/// Allocate a distinct identity for each newly-created mirror state. The
/// domain address alone can be reused after teardown, so readers match both.
pub fn nextRcuGeneration() usize {
    return rcu_generation.fetchAdd(1, .monotonic);
}

/// Get the participant cached for this exact domain generation, registering a
/// thread-local slot on first use. A stale generation must never reuse a
/// participant belonging to a prior heap state at the same address.
pub fn rcuReaderParticipant(domain: *ebr.Domain, generation: usize) ebr.RegisterError!*ebr.Participant {
    var free_slot: ?usize = null;
    for (&rcu_tls_entries, 0..) |*entry, i| {
        if (entry.participant) |participant| {
            if (entry.domain == domain and entry.generation == generation) return participant;
        } else if (free_slot == null) {
            free_slot = i;
        }
    }

    const index = free_slot orelse return error.TooManyParticipants;
    const participant = try domain.register();
    rcu_tls_entries[index] = .{
        .domain = domain,
        .generation = generation,
        .participant = participant,
    };
    return participant;
}

/// Unregister only this thread's cached reader slots for the retiring state.
/// Call after registries are deinitialized and the domain drained, but before
/// `Domain.deinit`; unrelated generations and domains remain cached.
pub fn rcuForgetThreadParticipants(domain: *ebr.Domain, generation: usize) void {
    for (&rcu_tls_entries) |*entry| {
        if (entry.participant) |participant| {
            if (entry.domain == domain and entry.generation == generation) {
                participant.unregister();
                entry.* = .{};
            }
        }
    }
}

test "World RCU reader participants are scoped by domain and generation" {
    var first_domain = ebr.Domain.init(std.testing.allocator);
    defer first_domain.deinit();
    var second_domain = ebr.Domain.init(std.testing.allocator);
    defer second_domain.deinit();

    const generation = nextRcuGeneration();
    const newer_generation = generation + 1;
    defer {
        rcuForgetThreadParticipants(&first_domain, generation);
        rcuForgetThreadParticipants(&first_domain, newer_generation);
        rcuForgetThreadParticipants(&second_domain, generation);
    }

    const first = try rcuReaderParticipant(&first_domain, generation);
    try std.testing.expect(first == try rcuReaderParticipant(&first_domain, generation));

    const newer = try rcuReaderParticipant(&first_domain, newer_generation);
    try std.testing.expect(first != newer);
    const other_domain = try rcuReaderParticipant(&second_domain, generation);
    try std.testing.expect(first != other_domain);

    rcuForgetThreadParticipants(&first_domain, generation);
    try std.testing.expect(!first.in_use.load(.acquire));
    try std.testing.expect(newer.in_use.load(.acquire));
    try std.testing.expect(other_domain.in_use.load(.acquire));

    const replacement = try rcuReaderParticipant(&first_domain, generation);
    try std.testing.expect(replacement != first);
    try std.testing.expect(replacement.in_use.load(.acquire));

    rcuForgetThreadParticipants(&first_domain, newer_generation);
    rcuForgetThreadParticipants(&first_domain, generation);
    rcuForgetThreadParticipants(&second_domain, generation);
    try std.testing.expect(!newer.in_use.load(.acquire));
    try std.testing.expect(!replacement.in_use.load(.acquire));
    try std.testing.expect(!other_domain.in_use.load(.acquire));
}
