// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helix Upgrade subsystem root.

const std = @import("std");

// Core upgrade transport + supervisor.
pub const attest = @import("attest.zig");
pub const capsule = @import("capsule.zig");
pub const handoff = @import("handoff.zig");
pub const live = @import("live.zig");
pub const handoff_manifest = @import("handoff_manifest.zig");
pub const handoff_relations = @import("handoff_relations.zig");
pub const supervisor = @import("supervisor.zig");
pub const conduit = @import("conduit.zig");

// State-migration capsules (one schema per resumable subsystem).
pub const conn_capsule = @import("conn_capsule.zig");
pub const world_capsule = @import("world_capsule.zig");
pub const world_checkpoint = @import("world_checkpoint.zig");
pub const history_checkpoint = @import("history_checkpoint.zig");
pub const account_capsule = @import("account_capsule.zig");
pub const listener_capsule = @import("listener_capsule.zig");
pub const session_capsule = @import("session_capsule.zig");
pub const session_snapshot = @import("session_snapshot.zig");
pub const tls_snapshot = @import("tls_snapshot.zig");
pub const ws_snapshot = @import("ws_snapshot.zig");
pub const ticket_key_capsule = @import("ticket_key_capsule.zig");
pub const s2s_snapshot = @import("s2s_snapshot.zig");
pub const mesh_redial = @import("mesh_redial.zig");
pub const mesh_clock_snapshot = @import("mesh_clock_snapshot.zig");
pub const oper_grant_snapshot = @import("oper_grant_snapshot.zig");
pub const thread_snapshot = @import("thread_snapshot.zig");
pub const session_migrate = @import("session_migrate.zig");
pub const session_replica = @import("session_replica.zig");
pub const session_replica_attachment = @import("session_replica_attachment.zig");
pub const migration_relay = @import("migration_relay.zig");
pub const prop_checkpoint = @import("prop_checkpoint.zig");
// S2S migration support modules (fsm + signed token + journal + policy + metrics).
pub const migration_fsm = @import("migration_fsm.zig");
pub const migration_token = @import("migration_token.zig");
pub const migration_journal = @import("migration_journal.zig");
pub const migration_policy = @import("migration_policy.zig");
pub const migration_metrics = @import("migration_metrics.zig");
pub const monitor_capsule = @import("monitor_capsule.zig");
pub const metadata_capsule = @import("metadata_capsule.zig");
pub const bouncer_buffer_capsule = @import("bouncer_buffer_capsule.zig");
pub const read_marker_capsule = @import("read_marker_capsule.zig");
pub const chathistory_cursor_capsule = @import("chathistory_cursor_capsule.zig");
pub const away_capsule = @import("away_capsule.zig");
pub const ban_capsule = @import("ban_capsule.zig");
pub const silence_capsule = @import("silence_capsule.zig");
pub const ratelimit_capsule = @import("ratelimit_capsule.zig");
pub const memo_capsule = @import("memo_capsule.zig");
pub const upgrade_manifest = @import("upgrade_manifest.zig");

// Successor-side planners + deterministic self-tests.
pub const resume_plan = @import("resume_plan.zig");
pub const session_resume_plan = @import("session_resume_plan.zig");
pub const upgrade_dst = @import("upgrade_dst.zig");
pub const session_migration_dst = @import("session_migration_dst.zig");
pub const world_migration_dst = @import("world_migration_dst.zig");
pub const s2s_adopt_dst = @import("s2s_adopt_dst.zig");
pub const session_adopt_dst = @import("session_adopt_dst.zig");
pub const multishard_upgrade_dst = @import("multishard_upgrade_dst.zig");

test {
    std.testing.refAllDecls(@This());
    _ = thread_snapshot;
}
