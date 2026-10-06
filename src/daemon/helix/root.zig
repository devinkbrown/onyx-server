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
pub const native_arena_envelope = @import("native_arena_envelope.zig");
pub const native_arena_file = @import("native_arena_file.zig");
pub const native_control = @import("native_control.zig");
pub const native_exchange = @import("native_exchange.zig");
pub const native_manifest = @import("native_manifest.zig");
pub const native_process = @import("native_process.zig");
pub const native_bootstrap = @import("native_bootstrap.zig");
pub const native_windows_socket = @import("native_windows_socket.zig");
pub const native_windows_metrics = @import("native_windows_metrics.zig");
pub const native_windows_webhook = @import("native_windows_webhook.zig");
pub const native_windows_history = @import("native_windows_history.zig");
pub const native_windows_rdns = @import("native_windows_rdns.zig");
pub const native_windows_dnsbl = @import("native_windows_dnsbl.zig");
pub const slowmode_checkpoint = @import("slowmode_checkpoint.zig");
pub const metadata_checkpoint = @import("metadata_checkpoint.zig");
pub const mlock_checkpoint = @import("mlock_checkpoint.zig");
pub const drain_checkpoint = @import("drain_checkpoint.zig");
pub const chanstats_checkpoint = @import("chanstats_checkpoint.zig");
pub const access_checkpoint = @import("access_checkpoint.zig");
pub const saccess_checkpoint = @import("saccess_checkpoint.zig");
pub const akick_checkpoint = @import("akick_checkpoint.zig");
pub const ward_checkpoint = @import("ward_checkpoint.zig");
pub const resv_jupe_checkpoint = @import("resv_jupe_checkpoint.zig");
pub const native_windows_webpush = @import("native_windows_webpush.zig");
pub const native_windows_geo = @import("native_windows_geo.zig");
pub const native_windows_mail = @import("native_windows_mail.zig");
pub const native_windows_acme = @import("native_windows_acme.zig");
pub const native_windows_ocsp = @import("native_windows_ocsp.zig");
pub const native_windows_ocsp_state = @import("native_windows_ocsp_state.zig");
pub const native_windows_tls_proof = @import("native_windows_tls_proof.zig");
pub const native_windows_tls_material = @import("native_windows_tls_material.zig");
pub const native_windows_wasm = @import("native_windows_wasm.zig");
pub const policy_checkpoint = @import("policy_checkpoint.zig");
pub const native_windows_operator_state = @import("native_windows_operator_state.zig");
pub const native_windows_account_flow = @import("native_windows_account_flow.zig");
pub const native_windows_memo_state = @import("native_windows_memo_state.zig");
pub const native_windows_user_settings = @import("native_windows_user_settings.zig");
pub const gag_checkpoint = @import("gag_checkpoint.zig");
pub const shun_checkpoint = @import("shun_checkpoint.zig");
pub const account_abuse_checkpoint = @import("account_abuse_checkpoint.zig");
pub const content_filter_checkpoint = @import("content_filter_checkpoint.zig");
pub const reputation_checkpoint = @import("reputation_checkpoint.zig");
pub const spamtrap_checkpoint = @import("spamtrap_checkpoint.zig");
pub const native_windows_arena = @import("native_windows_arena.zig");
pub const native_windows_control = @import("native_windows_control.zig");
pub const native_windows_process = @import("native_windows_process.zig");
pub const native_windows_bootstrap = @import("native_windows_bootstrap.zig");
pub const native_windows_driver = @import("native_windows_driver.zig");
pub const native_windows_config_proof = @import("native_windows_config_proof.zig");
pub const native_windows_runtime = @import("native_windows_runtime.zig");
pub const native_service_snapshot = @import("native_service_snapshot.zig");
pub const media_graph_checkpoint = @import("media_graph_checkpoint.zig");
pub const native_windows_active_media_snapshot = @import("native_windows_active_media_snapshot.zig");
pub const native_windows_media_custody = @import("native_windows_media_custody.zig");
pub const native_windows_active_webtransport_snapshot = @import("native_windows_active_webtransport_snapshot.zig");
pub const native_windows_active_webtransport_custody = @import("native_windows_active_webtransport_custody.zig");

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
pub const schedule_snapshot = @import("schedule_snapshot.zig");
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
pub const ban_capsule = @import("ban_capsule.zig");
pub const silence_capsule = @import("silence_capsule.zig");
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
    _ = native_arena_envelope;
    _ = native_arena_file;
    _ = native_control;
    _ = native_exchange;
    _ = native_manifest;
    _ = native_process;
    _ = native_bootstrap;
    _ = native_windows_socket;
    _ = native_windows_metrics;
    _ = native_windows_webhook;
    _ = native_windows_history;
    _ = native_windows_rdns;
    _ = native_windows_dnsbl;
    _ = slowmode_checkpoint;
    _ = metadata_checkpoint;
    _ = mlock_checkpoint;
    _ = drain_checkpoint;
    _ = chanstats_checkpoint;
    _ = access_checkpoint;
    _ = saccess_checkpoint;
    _ = akick_checkpoint;
    _ = ward_checkpoint;
    _ = resv_jupe_checkpoint;
    _ = native_windows_webpush;
    _ = native_windows_geo;
    _ = native_windows_mail;
    _ = native_windows_acme;
    _ = native_windows_ocsp;
    _ = native_windows_ocsp_state;
    _ = native_windows_tls_proof;
    _ = native_windows_tls_material;
    _ = native_windows_wasm;
    _ = policy_checkpoint;
    _ = native_windows_operator_state;
    _ = native_windows_account_flow;
    _ = native_windows_memo_state;
    _ = native_windows_user_settings;
    _ = gag_checkpoint;
    _ = shun_checkpoint;
    _ = account_abuse_checkpoint;
    _ = content_filter_checkpoint;
    _ = reputation_checkpoint;
    _ = spamtrap_checkpoint;
    _ = native_windows_arena;
    _ = native_windows_control;
    _ = native_windows_process;
    _ = native_windows_bootstrap;
    _ = native_windows_driver;
    _ = native_windows_config_proof;
    _ = native_windows_runtime;
    _ = native_service_snapshot;
    std.testing.refAllDecls(@This());
    _ = thread_snapshot;
    _ = schedule_snapshot;
}

test "section 10 drops unused memo away and ratelimit codecs" {
    try std.testing.expect(!@hasDecl(@This(), "memo_capsule"));
    try std.testing.expect(!@hasDecl(@This(), "away_capsule"));
    try std.testing.expect(!@hasDecl(@This(), "ratelimit_capsule"));
    try std.testing.expect(@hasDecl(@This(), "ban_capsule"));
    try std.testing.expect(@hasDecl(@This(), "silence_capsule"));

    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(capsule.CapsuleKind.clients));
    try std.testing.expectEqual(@as(u8, 17), @intFromEnum(capsule.CapsuleKind.handoff_manifest));
    try std.testing.expectEqual(capsule.CapsuleKind.handoff_manifest, try capsule.CapsuleKind.fromByte(17));
    try std.testing.expectEqual(@as(u8, 18), @intFromEnum(capsule.CapsuleKind.native_service));
    try std.testing.expectEqual(capsule.CapsuleKind.native_service, try capsule.CapsuleKind.fromByte(18));
    try std.testing.expectError(error.UnknownKind, capsule.CapsuleKind.fromByte(19));
    try std.testing.expectEqual(@as(usize, 18), @typeInfo(capsule.CapsuleKind).@"enum".field_names.len);

    std.debug.print(
        "section 10 branch=stop maintaining memo_capsule away_capsule and ratelimit_capsule; CapsuleKind 1 through 18 includes strict native service; ban_capsule stays\n",
        .{},
    );
}
