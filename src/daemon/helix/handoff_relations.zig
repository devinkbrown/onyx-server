// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free relational validation for a current Helix handoff.
//!
//! The whole-handoff manifest proves byte/order completeness. This pass proves
//! the cross-capsule graph before anything is published: each inherited socket
//! has exactly one owning client/S2S capsule, TLS and WebSocket sidecars match
//! the transport bits in that client, optional MONITOR/SILENCE rows are unique
//! and non-orphaned, and redial/S2S rows are current and canonical.

const std = @import("std");

const capsule = @import("capsule.zig");
const event_spine_replay_guard = @import("../event_spine_replay_guard.zig");
const attachment_delivery_spool = @import("../attachment_delivery_spool.zig");
const e2ee_group_mesh_authority = @import("../e2ee_group_mesh_authority.zig");
const relay_v2_event_log = @import("../relay_v2_event_log.zig");
const relay_v2_replay_guard = @import("../relay_v2_replay_guard.zig");
const relay_v2_outbox = @import("../relay_v2_outbox.zig");
const mesh_clock_snapshot = @import("mesh_clock_snapshot.zig");
const mesh_redial = @import("mesh_redial.zig");
const oper_grant_snapshot = @import("oper_grant_snapshot.zig");
const bot_grant_snapshot = @import("bot_grant_snapshot.zig");
const thread_snapshot = @import("thread_snapshot.zig");
const schedule_snapshot = @import("schedule_snapshot.zig");
const clone_detect = @import("../clone_detect.zig");
const mesh_clones = @import("../mesh_clones.zig");
const native_windows_rdns = @import("native_windows_rdns.zig");
const native_windows_dnsbl = @import("native_windows_dnsbl.zig");
const svc_login_throttle = @import("../svc_login_throttle.zig");
const nick_delay = @import("../nick_delay.zig");
const svc_tempmode = @import("../svc_tempmode.zig");
const raid_shield = @import("../raid_shield.zig");
const slowmode_checkpoint = @import("slowmode_checkpoint.zig");
const metadata_checkpoint = @import("metadata_checkpoint.zig");
const mlock_checkpoint = @import("mlock_checkpoint.zig");
const drain_checkpoint = @import("drain_checkpoint.zig");
const chanstats_checkpoint = @import("chanstats_checkpoint.zig");
const access_checkpoint = @import("access_checkpoint.zig");
const saccess_checkpoint = @import("saccess_checkpoint.zig");
const akick_checkpoint = @import("akick_checkpoint.zig");
const ward_checkpoint = @import("ward_checkpoint.zig");
const resv_jupe_checkpoint = @import("resv_jupe_checkpoint.zig");
const native_windows_webpush = @import("native_windows_webpush.zig");
const native_windows_geo = @import("native_windows_geo.zig");
const native_windows_mail = @import("native_windows_mail.zig");
const native_windows_acme = @import("native_windows_acme.zig");
const native_windows_ocsp = @import("native_windows_ocsp.zig");
const native_windows_ocsp_state = @import("native_windows_ocsp_state.zig");
const native_windows_tls_material = @import("native_windows_tls_material.zig");
const native_windows_wasm = @import("native_windows_wasm.zig");
const policy_checkpoint = @import("policy_checkpoint.zig");
const native_windows_operator_state = @import("native_windows_operator_state.zig");
const native_windows_account_flow = @import("native_windows_account_flow.zig");
const native_windows_memo_state = @import("native_windows_memo_state.zig");
const native_windows_user_settings = @import("native_windows_user_settings.zig");
const gag_checkpoint = @import("gag_checkpoint.zig");
const shun_checkpoint = @import("shun_checkpoint.zig");
const account_abuse_checkpoint = @import("account_abuse_checkpoint.zig");
const content_filter_checkpoint = @import("content_filter_checkpoint.zig");
const reputation_checkpoint = @import("reputation_checkpoint.zig");
const spamtrap_checkpoint = @import("spamtrap_checkpoint.zig");
const monitor_capsule = @import("monitor_capsule.zig");
const prop_checkpoint = @import("prop_checkpoint.zig");
const s2s_snapshot = @import("s2s_snapshot.zig");
const session_replica = @import("session_replica.zig");
const session_snapshot = @import("session_snapshot.zig");
const silence_capsule = @import("silence_capsule.zig");
const tls_snapshot = @import("tls_snapshot.zig");
const ws_snapshot = @import("ws_snapshot.zig");

/// These are the exact producer/adopter bounds in server.zig. Keeping them in
/// the validation API makes an oversized sidecar fatal before the restore pass
/// can silently skip it.
pub const max_monitor_targets = 512;
pub const max_silence_masks = 256;

pub const Error = error{
    InvalidStateFd,
    DuplicateStateFd,
    MissingStateFd,
    OrphanStateFd,
    InvalidClient,
    DuplicateClientFd,
    InvalidTls,
    OrphanTls,
    UnexpectedTls,
    DuplicateTls,
    MissingTls,
    InvalidWebSocket,
    OrphanWebSocket,
    UnexpectedWebSocket,
    DuplicateWebSocket,
    MissingWebSocket,
    InvalidMonitor,
    OrphanMonitor,
    DuplicateMonitor,
    MissingMonitor,
    InvalidSilence,
    OrphanSilence,
    DuplicateSilence,
    MissingSilence,
    InvalidS2s,
    DuplicateOwnerFd,
    DuplicateS2sPeer,
    InvalidRedial,
    DuplicateRedial,
    MissingEventSpineReplay,
    DuplicateEventSpineReplay,
    InvalidEventSpineReplay,
    MissingRelayV2Replay,
    DuplicateRelayV2Replay,
    InvalidRelayV2Replay,
    MissingRelayV2Outbox,
    DuplicateRelayV2Outbox,
    InvalidRelayV2Outbox,
    MissingRelayV2EventLog,
    DuplicateRelayV2EventLog,
    InvalidRelayV2EventLog,
    MissingAttachmentDeliverySpool,
    DuplicateAttachmentDeliverySpool,
    InvalidAttachmentDeliverySpool,
    MissingE2eeGroupMeshAuthority,
    DuplicateE2eeGroupMeshAuthority,
    InvalidE2eeGroupMeshAuthority,
    DuplicateMeshClock,
    MissingMeshClock,
    InvalidMeshClock,
    DuplicateOperGrants,
    InvalidOperGrants,
    DuplicateBotGrants,
    InvalidBotGrants,
    DuplicateThreads,
    InvalidThreads,
    DuplicateSchedules,
    InvalidSchedules,
    DuplicateCloneDetector,
    InvalidCloneDetector,
    DuplicateMeshClones,
    InvalidMeshClones,
    DuplicateRdns,
    InvalidRdns,
    DuplicateDnsbl,
    InvalidDnsbl,
    DuplicateLoginThrottle,
    InvalidLoginThrottle,
    DuplicateNickDelay,
    InvalidNickDelay,
    DuplicateTempMode,
    InvalidTempMode,
    DuplicateRaidShield,
    InvalidRaidShield,
    DuplicateSlowmode,
    InvalidSlowmode,
    DuplicateMetadata,
    InvalidMetadata,
    DuplicateMlock,
    InvalidMlock,
    DuplicateDrain,
    InvalidDrain,
    DuplicateChanstats,
    InvalidChanstats,
    DuplicateAccess,
    InvalidAccess,
    DuplicateSaccess,
    InvalidSaccess,
    DuplicateAkick,
    InvalidAkick,
    DuplicateWard,
    InvalidWard,
    DuplicateResv,
    InvalidResv,
    DuplicateJupe,
    InvalidJupe,
    DuplicateWebpush,
    InvalidWebpush,
    DuplicateGeo,
    InvalidGeo,
    DuplicateMail,
    InvalidMail,
    DuplicateAcme,
    InvalidAcme,
    DuplicateOcsp,
    InvalidOcsp,
    DuplicateOcspState,
    InvalidOcspState,
    DuplicateTlsMaterial,
    InvalidTlsMaterial,
    DuplicateWasm,
    InvalidWasm,
    DuplicatePolicy,
    InvalidPolicy,
    DuplicateOperatorState,
    InvalidOperatorState,
    DuplicateAccountFlow,
    InvalidAccountFlow,
    DuplicateMemoForward,
    InvalidMemoForward,
    DuplicateMemoIgnore,
    InvalidMemoIgnore,
    DuplicateFirstHold,
    InvalidFirstHold,
    DuplicateUserSettings,
    InvalidUserSettings,
    DuplicateGags,
    InvalidGags,
    DuplicateShuns,
    InvalidShuns,
    DuplicateAccountAbuse,
    InvalidAccountAbuse,
    DuplicateContentFilter,
    InvalidContentFilter,
    DuplicateReputation,
    InvalidReputation,
    DuplicateSpamtrap,
    InvalidSpamtrap,
    UnknownMeshCheckpoint,
};

pub const Summary = struct {
    clients: usize = 0,
    tls: usize = 0,
    websockets: usize = 0,
    monitors: usize = 0,
    silences: usize = 0,
    s2s_links: usize = 0,
    redials: usize = 0,
    event_spine_replay: usize = 0,
    relay_v2_replay: usize = 0,
    relay_v2_outbox: usize = 0,
    relay_v2_event_log: usize = 0,
    attachment_delivery_spool: usize = 0,
    e2ee_group_mesh_authority: usize = 0,
    mesh_clock: usize = 0,
    oper_grants: usize = 0,
    bot_grants: usize = 0,
    threads: usize = 0,
    schedules: usize = 0,
    clone_detector: usize = 0,
    mesh_clones: usize = 0,
    rdns: usize = 0,
    dnsbl: usize = 0,
    login_throttle: usize = 0,
    nick_delay: usize = 0,
    temp_mode: usize = 0,
    raid_shield: usize = 0,
    slowmode: usize = 0,
    metadata: usize = 0,
    mlock: usize = 0,
    drain: usize = 0,
    chanstats: usize = 0,
    access: usize = 0,
    saccess: usize = 0,
    akick: usize = 0,
    ward: usize = 0,
    resv: usize = 0,
    jupe: usize = 0,
    webpush: usize = 0,
    geo: usize = 0,
    mail: usize = 0,
    acme: usize = 0,
    ocsp: usize = 0,
    ocsp_state: usize = 0,
    tls_material: usize = 0,
    wasm: usize = 0,
    policy: usize = 0,
    operator_state: usize = 0,
    account_flow: usize = 0,
    memo_forward: usize = 0,
    memo_ignore: usize = 0,
    first_hold: usize = 0,
    user_settings: usize = 0,
    gags: usize = 0,
    shuns: usize = 0,
    account_abuse: usize = 0,
    content_filter: usize = 0,
    reputation: usize = 0,
    spamtrap: usize = 0,
};

/// Validate decoded capsules after `live.verifyHandoffManifest` and before any
/// successor state swap/adoption. `state_fds` is the authoritative environment
/// manifest; its set must equal the client+S2S owning-fd set exactly.
pub fn validateCurrent(capsules: []const capsule.Capsule, state_fds: []const i32) Error!Summary {
    var summary: Summary = .{};

    for (state_fds, 0..) |fd, i| {
        if (fd < 0) return error.InvalidStateFd;
        for (state_fds[0..i]) |prior| if (prior == fd) return error.DuplicateStateFd;
    }

    // Owning client rows are exact current snapshots with unique nonnegative
    // descriptors, each present in the authoritative inherited-fd set.
    for (capsules, 0..) |item, index| {
        if (item.header.kind != .clients) continue;
        const bytes = canonicalPayload(item, .clients) orelse return error.InvalidClient;
        const client = session_snapshot.decodeCurrent(bytes) catch return error.InvalidClient;
        if (client.fd < 0 or !containsFd(state_fds, client.fd)) return error.MissingStateFd;
        for (capsules[0..index]) |prior| {
            if (prior.header.kind != .clients) continue;
            const prior_client = session_snapshot.decodeCurrent(prior.fields[0].bytes) catch unreachable;
            if (prior_client.fd == client.fd) return error.DuplicateClientFd;
        }
        summary.clients += 1;
    }

    // Secured S2S links are the other owning family. They may neither alias a
    // client/another link fd nor duplicate one remote node authority.
    for (capsules, 0..) |item, index| {
        if (item.header.kind != .s2s_link) continue;
        const bytes = canonicalS2sPayload(item) orelse return error.InvalidS2s;
        const link = s2s_snapshot.decode(bytes, item.header.version) catch return error.InvalidS2s;
        if (link.fd < 0 or !containsFd(state_fds, link.fd)) return error.MissingStateFd;
        for (capsules) |candidate| {
            if (candidate.header.kind != .clients) continue;
            const client = session_snapshot.decodeCurrent(candidate.fields[0].bytes) catch unreachable;
            if (client.fd == link.fd) return error.DuplicateOwnerFd;
        }
        for (capsules[0..index]) |prior| {
            if (prior.header.kind != .s2s_link) continue;
            const prior_link = s2s_snapshot.decode(prior.fields[0].bytes, prior.header.version) catch unreachable;
            if (prior_link.fd == link.fd) return error.DuplicateOwnerFd;
            if (link.remote_node_id != 0 and prior_link.remote_node_id == link.remote_node_id)
                return error.DuplicateS2sPeer;
        }
        summary.s2s_links += 1;
    }

    // Every authoritative fd must be claimed by exactly one owner.
    for (state_fds) |fd| {
        var owners: usize = 0;
        for (capsules) |item| switch (item.header.kind) {
            .clients => {
                const client = session_snapshot.decodeCurrent(item.fields[0].bytes) catch unreachable;
                if (client.fd == fd) owners += 1;
            },
            .s2s_link => {
                const link = s2s_snapshot.decode(item.fields[0].bytes, item.header.version) catch unreachable;
                if (link.fd == fd) owners += 1;
            },
            else => {},
        };
        if (owners == 0) return error.OrphanStateFd;
        if (owners != 1) return error.DuplicateOwnerFd;
    }

    // Validate every sidecar, then validate every client's required transport
    // sidecars in the opposite direction. This catches both orphans/duplicates
    // and a missing secured/framed transport checkpoint.
    for (capsules, 0..) |item, index| switch (item.header.kind) {
        .tls_session => {
            // Mandatory exact TLS3 carries record policy, exporter, control
            // cursors and typed queue custody. No hot legacy normalization.
            const bytes = canonicalPayload(item, .tls_session) orelse return error.InvalidTls;
            const tls = tls_snapshot.decodeCurrent(bytes) catch return error.InvalidTls;
            const client = findClient(capsules, tls.fd) orelse return error.OrphanTls;
            if (!client.was_secured) return error.UnexpectedTls;
            for (capsules[0..index]) |prior| {
                if (prior.header.kind != .tls_session) continue;
                // The prior already decoded when it was `item`, so this is dead in
                // practice — but never assert `unreachable` on inherited bytes
                // (UB under ReleaseFast); fail the handoff closed instead.
                const prior_tls = tls_snapshot.decode(prior.fields[0].bytes, prior.header.version) catch return error.InvalidTls;
                if (prior_tls.fd == tls.fd) return error.DuplicateTls;
            }
            summary.tls += 1;
        },
        .ws_session => {
            // The selected application protocol is an enforcement boundary.
            // Current Helix adoption therefore requires the exact v3 shape;
            // legacy v1/v2 decoding exists only for explicit cold migration.
            const bytes = canonicalPayload(item, .ws_session) orelse return error.InvalidWebSocket;
            const websocket = ws_snapshot.decodeCurrent(bytes) catch return error.InvalidWebSocket;
            const client = findClient(capsules, websocket.fd) orelse return error.OrphanWebSocket;
            if (!client.was_websocket) return error.UnexpectedWebSocket;
            for (capsules[0..index]) |prior| {
                if (prior.header.kind != .ws_session) continue;
                // Dead in practice (prior already decoded as `item`) — but never
                // assert `unreachable` on inherited bytes; fail closed instead.
                const prior_ws = ws_snapshot.decodeCurrent(prior.fields[0].bytes) catch return error.InvalidWebSocket;
                if (prior_ws.fd == websocket.fd) return error.DuplicateWebSocket;
            }
            summary.websockets += 1;
        },
        .monitor_list => {
            const bytes = canonicalPayload(item, .monitor_list) orelse return error.InvalidMonitor;
            var targets: [max_monitor_targets][]const u8 = undefined;
            const monitor = monitor_capsule.MonitorCapsule.decode(bytes, &targets) catch return error.InvalidMonitor;
            const fd = std.math.cast(i32, monitor.client_id) orelse return error.OrphanMonitor;
            if (findClient(capsules, fd) == null) return error.OrphanMonitor;
            for (capsules[0..index]) |prior| {
                if (prior.header.kind != .monitor_list) continue;
                if (monitorOwnerFd(prior.fields[0].bytes) == fd) return error.DuplicateMonitor;
            }
            summary.monitors += 1;
        },
        .silence_list => {
            const bytes = canonicalPayload(item, .silence_list) orelse return error.InvalidSilence;
            var masks: [max_silence_masks][]const u8 = undefined;
            const silence = silence_capsule.SilenceCapsule.decode(bytes, &masks) catch return error.InvalidSilence;
            const fd = std.math.cast(i32, silence.client_id) orelse return error.OrphanSilence;
            if (findClient(capsules, fd) == null) return error.OrphanSilence;
            for (capsules[0..index]) |prior| {
                if (prior.header.kind != .silence_list) continue;
                if (silenceOwnerFd(prior.fields[0].bytes) == fd) return error.DuplicateSilence;
            }
            summary.silences += 1;
        },
        else => {},
    };

    for (capsules) |item| {
        if (item.header.kind != .clients) continue;
        const client = session_snapshot.decodeCurrent(item.fields[0].bytes) catch unreachable;
        const tls_count = countTlsForFd(capsules, client.fd);
        if (client.was_secured and tls_count == 0) return error.MissingTls;
        if (!client.was_secured and tls_count != 0) return error.UnexpectedTls;
        const ws_count = countWebSocketsForFd(capsules, client.fd);
        if (client.was_websocket and ws_count == 0) return error.MissingWebSocket;
        if (!client.was_websocket and ws_count != 0) return error.UnexpectedWebSocket;
        if (countMonitorsForFd(capsules, client.fd) == 0) return error.MissingMonitor;
        if (countSilencesForFd(capsules, client.fd) == 0) return error.MissingSilence;
    }

    // Current mesh state has four semantic inner families. The first three are
    // validated by their store decoders; this pass validates redial rows and
    // rejects unknown/broken discriminators so a corrupt hint cannot disappear.
    for (capsules, 0..) |item, index| {
        if (item.header.kind != .mesh_checkpoint) continue;
        const descriptor = capsule.descriptor(.mesh_checkpoint);
        if (item.header.schema_id != descriptor.schema_id or
            item.header.version != descriptor.current_version or
            item.header.max_supported != descriptor.max_supported or
            item.fields.len != 1 or item.fields[0].ordinal != 1)
            return error.UnknownMeshCheckpoint;
        const bytes = item.fields[0].bytes;
        if (event_spine_replay_guard.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = event_spine_replay_guard.validateCheckpoint(bytes) catch
                return error.InvalidEventSpineReplay;
            if (summary.event_spine_replay != 0) return error.DuplicateEventSpineReplay;
            summary.event_spine_replay = 1;
            continue;
        }
        if (relay_v2_replay_guard.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = relay_v2_replay_guard.validateCheckpoint(bytes) catch
                return error.InvalidRelayV2Replay;
            if (summary.relay_v2_replay != 0) return error.DuplicateRelayV2Replay;
            summary.relay_v2_replay = 1;
            continue;
        }
        if (relay_v2_outbox.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = relay_v2_outbox.validateCheckpoint(bytes) catch
                return error.InvalidRelayV2Outbox;
            if (summary.relay_v2_outbox != 0) return error.DuplicateRelayV2Outbox;
            summary.relay_v2_outbox = 1;
            continue;
        }
        if (relay_v2_event_log.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = relay_v2_event_log.validateCheckpoint(bytes) catch
                return error.InvalidRelayV2EventLog;
            if (summary.relay_v2_event_log != 0) return error.DuplicateRelayV2EventLog;
            summary.relay_v2_event_log = 1;
            continue;
        }
        if (attachment_delivery_spool.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = attachment_delivery_spool.validateCheckpoint(bytes) catch
                return error.InvalidAttachmentDeliverySpool;
            if (summary.attachment_delivery_spool != 0)
                return error.DuplicateAttachmentDeliverySpool;
            summary.attachment_delivery_spool = 1;
            continue;
        }
        // EGRG: guard metadata + exact accepted history (no completed receipts);
        // authority encode succeeds only with empty hop custody — payload and
        // live custody wires are never checkpointed.
        if (e2ee_group_mesh_authority.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            _ = e2ee_group_mesh_authority.validateCheckpoint(bytes) catch
                return error.InvalidE2eeGroupMeshAuthority;
            if (summary.e2ee_group_mesh_authority != 0)
                return error.DuplicateE2eeGroupMeshAuthority;
            summary.e2ee_group_mesh_authority = 1;
            continue;
        }
        if (prop_checkpoint.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.UnknownMeshCheckpoint;
            continue;
        }
        if (hasPrefix(bytes, &mesh_clock_snapshot.magic)) {
            if (item.header.min_supported != 2) return error.InvalidMeshClock;
            _ = mesh_clock_snapshot.decodeCurrent(bytes) catch return error.InvalidMeshClock;
            if (summary.mesh_clock != 0) return error.DuplicateMeshClock;
            summary.mesh_clock = 1;
            continue;
        }
        if (oper_grant_snapshot.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidOperGrants;
            oper_grant_snapshot.validateCheckpoint(bytes) catch return error.InvalidOperGrants;
            if (summary.oper_grants != 0) return error.DuplicateOperGrants;
            summary.oper_grants = 1;
            continue;
        }
        if (bot_grant_snapshot.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidBotGrants;
            bot_grant_snapshot.validateCheckpoint(bytes) catch return error.InvalidBotGrants;
            if (summary.bot_grants != 0) return error.DuplicateBotGrants;
            summary.bot_grants = 1;
            continue;
        }
        // THRD is at-most-once, like bot grants. A pre-thread arena has no
        // piece and must still adopt. Absence is not a missing-singleton error.
        if (thread_snapshot.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidThreads;
            thread_snapshot.validateCheckpoint(bytes) catch return error.InvalidThreads;
            if (summary.threads != 0) return error.DuplicateThreads;
            summary.threads = 1;
            continue;
        }
        // SCHD is at-most-once, like threads. A pre-schedule arena has no
        // piece and must still adopt. Absence is not a missing-singleton error.
        if (schedule_snapshot.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidSchedules;
            schedule_snapshot.validateCheckpoint(bytes) catch return error.InvalidSchedules;
            if (summary.schedules != 0) return error.DuplicateSchedules;
            summary.schedules = 1;
            continue;
        }
        if (clone_detect.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidCloneDetector;
            clone_detect.validateUpgradeCheckpoint(bytes) catch return error.InvalidCloneDetector;
            if (summary.clone_detector != 0) return error.DuplicateCloneDetector;
            summary.clone_detector = 1;
            continue;
        }
        if (mesh_clones.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMeshClones;
            mesh_clones.validateUpgradeCheckpoint(bytes) catch return error.InvalidMeshClones;
            if (summary.mesh_clones != 0) return error.DuplicateMeshClones;
            summary.mesh_clones = 1;
            continue;
        }
        if (native_windows_rdns.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidRdns;
            native_windows_rdns.validateCheckpoint(bytes) catch return error.InvalidRdns;
            if (summary.rdns != 0) return error.DuplicateRdns;
            summary.rdns = 1;
            continue;
        }
        if (native_windows_dnsbl.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidDnsbl;
            native_windows_dnsbl.validateCheckpoint(bytes) catch return error.InvalidDnsbl;
            if (summary.dnsbl != 0) return error.DuplicateDnsbl;
            summary.dnsbl = 1;
            continue;
        }
        if (svc_login_throttle.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidLoginThrottle;
            svc_login_throttle.validateUpgradeCheckpoint(bytes) catch return error.InvalidLoginThrottle;
            if (summary.login_throttle != 0) return error.DuplicateLoginThrottle;
            summary.login_throttle = 1;
            continue;
        }
        if (nick_delay.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidNickDelay;
            nick_delay.validateUpgradeCheckpoint(bytes) catch return error.InvalidNickDelay;
            if (summary.nick_delay != 0) return error.DuplicateNickDelay;
            summary.nick_delay = 1;
            continue;
        }
        if (svc_tempmode.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidTempMode;
            svc_tempmode.validateUpgradeCheckpoint(bytes) catch return error.InvalidTempMode;
            if (summary.temp_mode != 0) return error.DuplicateTempMode;
            summary.temp_mode = 1;
            continue;
        }
        if (raid_shield.isUpgradeCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidRaidShield;
            raid_shield.validateUpgradeCheckpoint(bytes) catch return error.InvalidRaidShield;
            if (summary.raid_shield != 0) return error.DuplicateRaidShield;
            summary.raid_shield = 1;
            continue;
        }
        if (slowmode_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidSlowmode;
            slowmode_checkpoint.validateCheckpoint(bytes) catch return error.InvalidSlowmode;
            if (summary.slowmode != 0) return error.DuplicateSlowmode;
            summary.slowmode = 1;
            continue;
        }
        if (metadata_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMetadata;
            metadata_checkpoint.validateCheckpoint(bytes) catch return error.InvalidMetadata;
            if (summary.metadata != 0) return error.DuplicateMetadata;
            summary.metadata = 1;
            continue;
        }
        if (mlock_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMlock;
            mlock_checkpoint.validateCheckpoint(bytes) catch return error.InvalidMlock;
            if (summary.mlock != 0) return error.DuplicateMlock;
            summary.mlock = 1;
            continue;
        }
        if (drain_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidDrain;
            drain_checkpoint.validateCheckpoint(bytes) catch return error.InvalidDrain;
            if (summary.drain != 0) return error.DuplicateDrain;
            summary.drain = 1;
            continue;
        }
        if (chanstats_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidChanstats;
            chanstats_checkpoint.validateCheckpoint(bytes) catch return error.InvalidChanstats;
            if (summary.chanstats != 0) return error.DuplicateChanstats;
            summary.chanstats = 1;
            continue;
        }
        if (access_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidAccess;
            access_checkpoint.validateCheckpoint(bytes) catch return error.InvalidAccess;
            if (summary.access != 0) return error.DuplicateAccess;
            summary.access = 1;
            continue;
        }
        if (saccess_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidSaccess;
            saccess_checkpoint.validateCheckpoint(bytes) catch return error.InvalidSaccess;
            if (summary.saccess != 0) return error.DuplicateSaccess;
            summary.saccess = 1;
            continue;
        }
        if (akick_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidAkick;
            akick_checkpoint.validateCheckpoint(bytes) catch return error.InvalidAkick;
            if (summary.akick != 0) return error.DuplicateAkick;
            summary.akick = 1;
            continue;
        }
        if (ward_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidWard;
            ward_checkpoint.validateCheckpoint(bytes) catch return error.InvalidWard;
            if (summary.ward != 0) return error.DuplicateWard;
            summary.ward = 1;
            continue;
        }
        if (resv_jupe_checkpoint.channel.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidResv;
            resv_jupe_checkpoint.channel.validateCheckpoint(bytes) catch return error.InvalidResv;
            if (summary.resv != 0) return error.DuplicateResv;
            summary.resv = 1;
            continue;
        }
        if (resv_jupe_checkpoint.server.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidJupe;
            resv_jupe_checkpoint.server.validateCheckpoint(bytes) catch return error.InvalidJupe;
            if (summary.jupe != 0) return error.DuplicateJupe;
            summary.jupe = 1;
            continue;
        }
        if (native_windows_webpush.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidWebpush;
            native_windows_webpush.validateCheckpoint(bytes) catch return error.InvalidWebpush;
            if (summary.webpush != 0) return error.DuplicateWebpush;
            summary.webpush = 1;
            continue;
        }
        if (native_windows_geo.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidGeo;
            native_windows_geo.validateCheckpoint(bytes) catch return error.InvalidGeo;
            if (summary.geo != 0) return error.DuplicateGeo;
            summary.geo = 1;
            continue;
        }
        if (native_windows_mail.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMail;
            native_windows_mail.validateCheckpoint(bytes) catch return error.InvalidMail;
            if (summary.mail != 0) return error.DuplicateMail;
            summary.mail = 1;
            continue;
        }
        if (native_windows_acme.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidAcme;
            native_windows_acme.validateCheckpoint(bytes) catch return error.InvalidAcme;
            if (summary.acme != 0) return error.DuplicateAcme;
            summary.acme = 1;
            continue;
        }
        if (native_windows_ocsp.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidOcsp;
            native_windows_ocsp.validateCheckpoint(bytes) catch return error.InvalidOcsp;
            if (summary.ocsp != 0) return error.DuplicateOcsp;
            summary.ocsp = 1;
            continue;
        }
        if (native_windows_ocsp_state.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidOcspState;
            native_windows_ocsp_state.validateCheckpoint(bytes) catch return error.InvalidOcspState;
            if (summary.ocsp_state != 0) return error.DuplicateOcspState;
            summary.ocsp_state = 1;
            continue;
        }
        if (native_windows_tls_material.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidTlsMaterial;
            native_windows_tls_material.validateCheckpoint(bytes) catch return error.InvalidTlsMaterial;
            if (summary.tls_material != 0) return error.DuplicateTlsMaterial;
            summary.tls_material = 1;
            continue;
        }
        if (native_windows_wasm.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidWasm;
            native_windows_wasm.validateCheckpoint(bytes) catch return error.InvalidWasm;
            if (summary.wasm != 0) return error.DuplicateWasm;
            summary.wasm = 1;
            continue;
        }
        if (policy_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidPolicy;
            policy_checkpoint.validateCheckpoint(bytes) catch return error.InvalidPolicy;
            if (summary.policy != 0) return error.DuplicatePolicy;
            summary.policy = 1;
            continue;
        }
        if (native_windows_operator_state.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidOperatorState;
            native_windows_operator_state.validateCheckpoint(bytes) catch return error.InvalidOperatorState;
            if (summary.operator_state != 0) return error.DuplicateOperatorState;
            summary.operator_state = 1;
            continue;
        }
        if (native_windows_account_flow.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidAccountFlow;
            native_windows_account_flow.validateCheckpoint(bytes) catch return error.InvalidAccountFlow;
            if (summary.account_flow != 0) return error.DuplicateAccountFlow;
            summary.account_flow = 1;
            continue;
        }
        if (native_windows_memo_state.isForward(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMemoForward;
            native_windows_memo_state.validateForward(bytes) catch return error.InvalidMemoForward;
            if (summary.memo_forward != 0) return error.DuplicateMemoForward;
            summary.memo_forward = 1;
            continue;
        }
        if (native_windows_memo_state.isIgnore(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidMemoIgnore;
            native_windows_memo_state.validateIgnore(bytes) catch return error.InvalidMemoIgnore;
            if (summary.memo_ignore != 0) return error.DuplicateMemoIgnore;
            summary.memo_ignore = 1;
            continue;
        }
        if (native_windows_memo_state.isFirstHold(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidFirstHold;
            native_windows_memo_state.validateFirstHold(bytes) catch return error.InvalidFirstHold;
            if (summary.first_hold != 0) return error.DuplicateFirstHold;
            summary.first_hold = 1;
            continue;
        }
        if (native_windows_user_settings.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidUserSettings;
            native_windows_user_settings.validateCheckpoint(bytes) catch return error.InvalidUserSettings;
            if (summary.user_settings != 0) return error.DuplicateUserSettings;
            summary.user_settings = 1;
            continue;
        }
        if (gag_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidGags;
            gag_checkpoint.validateCheckpoint(bytes) catch return error.InvalidGags;
            if (summary.gags != 0) return error.DuplicateGags;
            summary.gags = 1;
            continue;
        }
        if (shun_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidShuns;
            shun_checkpoint.validateCheckpoint(bytes) catch return error.InvalidShuns;
            if (summary.shuns != 0) return error.DuplicateShuns;
            summary.shuns = 1;
            continue;
        }
        if (account_abuse_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidAccountAbuse;
            account_abuse_checkpoint.validateCheckpoint(bytes) catch return error.InvalidAccountAbuse;
            if (summary.account_abuse != 0) return error.DuplicateAccountAbuse;
            summary.account_abuse = 1;
            continue;
        }
        if (content_filter_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidContentFilter;
            content_filter_checkpoint.validateCheckpoint(bytes) catch return error.InvalidContentFilter;
            if (summary.content_filter != 0) return error.DuplicateContentFilter;
            summary.content_filter = 1;
            continue;
        }
        if (reputation_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidReputation;
            reputation_checkpoint.validateCheckpoint(bytes) catch return error.InvalidReputation;
            if (summary.reputation != 0) return error.DuplicateReputation;
            summary.reputation = 1;
            continue;
        }
        if (spamtrap_checkpoint.isCheckpoint(bytes)) {
            if (item.header.min_supported != 2) return error.InvalidSpamtrap;
            spamtrap_checkpoint.validateCheckpoint(bytes) catch return error.InvalidSpamtrap;
            if (summary.spamtrap != 0) return error.DuplicateSpamtrap;
            summary.spamtrap = 1;
            continue;
        }
        if (item.header.min_supported != descriptor.min_supported)
            return error.UnknownMeshCheckpoint;
        if (session_replica.Store.isUpgradeCheckpoint(bytes)) continue;
        if (!mesh_redial.isCurrent(bytes)) return error.UnknownMeshCheckpoint;
        const redial = mesh_redial.decodeCurrent(bytes) catch return error.InvalidRedial;
        for (capsules[0..index]) |prior| {
            if (prior.header.kind != .mesh_checkpoint or prior.fields.len != 1) continue;
            if (!mesh_redial.isCurrent(prior.fields[0].bytes)) continue;
            const prior_redial = mesh_redial.decodeCurrent(prior.fields[0].bytes) catch return error.InvalidRedial;
            if (prior_redial.port == redial.port and std.mem.eql(u8, &prior_redial.addr, &redial.addr))
                return error.DuplicateRedial;
        }
        summary.redials += 1;
    }

    if (summary.event_spine_replay != 1) return error.MissingEventSpineReplay;
    if (summary.relay_v2_replay != 1) return error.MissingRelayV2Replay;
    if (summary.relay_v2_outbox != 1) return error.MissingRelayV2Outbox;
    if (summary.relay_v2_event_log != 1) return error.MissingRelayV2EventLog;
    if (summary.attachment_delivery_spool != 1) return error.MissingAttachmentDeliverySpool;
    if (summary.e2ee_group_mesh_authority != 1) return error.MissingE2eeGroupMeshAuthority;
    if (summary.mesh_clock != 1) return error.MissingMeshClock;
    // `oper_grants` is deliberately AT-MOST-once, not required: an arena sealed
    // by a pre-checkpoint predecessor simply lacks the piece and must still
    // adopt (empty registry = the exact pre-checkpoint behavior), mirroring how
    // a pre-v4 `.s2s_link` capsule adopts with an empty roster. Requiring it
    // would turn the FIRST post-introduction USR2 into a whole-handoff refusal
    // — dropping every preserved link/client, the regression class this piece
    // exists to prevent. Present-but-malformed/duplicate still fails closed
    // above, and a downgraded successor refuses the unknown discriminator.
    return summary;
}

fn canonicalPayload(item: capsule.Capsule, kind: capsule.CapsuleKind) ?[]const u8 {
    if (item.header.kind != kind) return null;
    const descriptor = capsule.descriptor(kind);
    if (item.header.schema_id != descriptor.schema_id or
        item.header.version != descriptor.current_version or
        item.header.min_supported != descriptor.min_supported or
        item.header.max_supported != descriptor.max_supported or
        item.fields.len != 1 or item.fields[0].ordinal != 1) return null;
    return item.fields[0].bytes;
}

/// S2S is the one ownership-bearing family intentionally rolling-compatible.
/// Require that the predecessor's own current payload version is the negotiated
/// overlap, then let the per-version canonical decoder validate the exact body.
fn canonicalS2sPayload(item: capsule.Capsule) ?[]const u8 {
    if (item.header.kind != .s2s_link or item.fields.len != 1 or
        item.fields[0].ordinal != 1) return null;
    const negotiated = capsule.negotiate(capsule.descriptor(.s2s_link), item.header) catch return null;
    if (negotiated != item.header.version) return null;
    return item.fields[0].bytes;
}

/// The rolling-compatible sidecar analogue of `canonicalS2sPayload` for the
/// TLS transport capsule: its descriptor advertises a `min_supported`
/// window (so a pre-bump predecessor's capsule still adopts instead of
/// netsplitting the next USR2). Require the predecessor's advertised current
/// version to be the negotiated overlap, then let the per-version decoder
/// validate the exact body. WebSocket and owning/exact families keep
/// `canonicalPayload`.
fn canonicalRollingPayload(item: capsule.Capsule, kind: capsule.CapsuleKind) ?[]const u8 {
    if (item.header.kind != kind or item.fields.len != 1 or
        item.fields[0].ordinal != 1) return null;
    const negotiated = capsule.negotiate(capsule.descriptor(kind), item.header) catch return null;
    if (negotiated != item.header.version) return null;
    return item.fields[0].bytes;
}

fn containsFd(fds: []const i32, fd: i32) bool {
    for (fds) |candidate| if (candidate == fd) return true;
    return false;
}

fn findClient(capsules: []const capsule.Capsule, fd: i32) ?session_snapshot.Snapshot {
    for (capsules) |item| {
        if (item.header.kind != .clients) continue;
        const client = session_snapshot.decodeCurrent(item.fields[0].bytes) catch return null;
        if (client.fd == fd) return client;
    }
    return null;
}

fn countTlsForFd(capsules: []const capsule.Capsule, fd: i32) usize {
    var count: usize = 0;
    for (capsules) |item| {
        if (item.header.kind != .tls_session) continue;
        const tls = tls_snapshot.decode(item.fields[0].bytes, item.header.version) catch continue;
        if (tls.fd == fd) count += 1;
    }
    return count;
}

fn countWebSocketsForFd(capsules: []const capsule.Capsule, fd: i32) usize {
    var count: usize = 0;
    for (capsules) |item| {
        if (item.header.kind != .ws_session) continue;
        const websocket = ws_snapshot.decodeCurrent(item.fields[0].bytes) catch continue;
        if (websocket.fd == fd) count += 1;
    }
    return count;
}

fn countMonitorsForFd(capsules: []const capsule.Capsule, fd: i32) usize {
    var count: usize = 0;
    for (capsules) |item| {
        if (item.header.kind != .monitor_list) continue;
        if (monitorOwnerFd(item.fields[0].bytes) == fd) count += 1;
    }
    return count;
}

fn countSilencesForFd(capsules: []const capsule.Capsule, fd: i32) usize {
    var count: usize = 0;
    for (capsules) |item| {
        if (item.header.kind != .silence_list) continue;
        if (silenceOwnerFd(item.fields[0].bytes) == fd) count += 1;
    }
    return count;
}

fn monitorOwnerFd(bytes: []const u8) ?i32 {
    if (bytes.len < monitor_capsule.magic.len + 1 + 8) return null;
    const raw = std.mem.readInt(u64, bytes[monitor_capsule.magic.len + 1 ..][0..8], .big);
    return std.math.cast(i32, raw);
}

fn silenceOwnerFd(bytes: []const u8) ?i32 {
    if (bytes.len < silence_capsule.magic.len + 1 + 8) return null;
    const raw = std.mem.readInt(u64, bytes[silence_capsule.magic.len + 1 ..][0..8], .big);
    return std.math.cast(i32, raw);
}

fn hasPrefix(bytes: []const u8, prefix: []const u8) bool {
    return bytes.len >= prefix.len and std.mem.eql(u8, bytes[0..prefix.len], prefix);
}

const TestPiece = struct { kind: capsule.CapsuleKind, bytes: []const u8 };

fn makeTestCaps(
    pieces: []const TestPiece,
    fields: [][1]capsule.Field,
    caps: []capsule.Capsule,
) []capsule.Capsule {
    std.debug.assert(pieces.len == fields.len and fields.len == caps.len);
    for (pieces, 0..) |piece, i| {
        fields[i][0] = .{ .ordinal = 1, .bytes = piece.bytes };
        caps[i] = capsule.make(piece.kind, fields[i][0..]);
    }
    return caps;
}

fn testEventSpineReplayCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var guard = try event_spine_replay_guard.Guard.init(allocator, .{});
    defer guard.deinit();
    return guard.encodeCheckpoint(allocator);
}

fn testRelayV2ReplayCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var guard = try relay_v2_replay_guard.Guard.init(allocator, .{});
    defer guard.deinit();
    return guard.encodeCheckpoint(allocator);
}

fn testRelayV2OutboxCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var outbox = try relay_v2_outbox.Outbox.init(allocator, relay_v2_outbox.default_max_entries);
    defer outbox.deinit();
    return outbox.encodeCheckpoint(allocator);
}

fn testRelayV2EventLogCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var event_log = try relay_v2_event_log.EventLog.init(allocator, .{});
    defer event_log.deinit();
    return event_log.encodeCheckpoint(allocator);
}

fn testAttachmentDeliveryCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var spool = try attachment_delivery_spool.Spool.init(allocator, .{});
    defer spool.deinit();
    return spool.encodeCheckpoint(allocator);
}

/// Canonical empty EGRG mesh authority (metadata + empty exact history; no custody).
fn testE2eeGroupMeshAuthorityCheckpoint(allocator: std.mem.Allocator) ![]u8 {
    var auth = try e2ee_group_mesh_authority.Authority.init(allocator, .{});
    defer auth.deinit();
    return auth.encodeCheckpoint(allocator);
}

fn testMeshClockCap(bytes: []const u8, field: *[1]capsule.Field) capsule.Capsule {
    field.* = .{.{ .ordinal = 1, .bytes = bytes }};
    var cap = capsule.make(.mesh_checkpoint, field);
    cap.header.min_supported = 2;
    return cap;
}

test "current handoff relations validate unique POLY HXOP HXTM HXAC and HXWM custody" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    const policy = try policy_checkpoint.encode(allocator, .{
        .generations = .{ .ward = 1, .filter = 1, .class = 1, .ban = 1, .proof = 1 },
    });
    defer allocator.free(policy);
    const operator_state = try native_windows_operator_state.encode(allocator, .{
        .method = .pow,
        .question = "",
        .answer = "",
        .issued = 7,
    });
    defer allocator.free(operator_state);
    const ed = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x45));
    var cert_buf: [4096]u8 = undefined;
    const cert = try @import("../../proto/x509_selfsign.zig").buildSelfSigned(&cert_buf, .{
        .common_name = "helix.test",
        .not_before = 1_700_000_000,
        .not_after = 1_900_000_000,
        .serial = &.{5},
        .key_pair = ed,
    });
    const chain = [_][]const u8{cert};
    const tls_material = try native_windows_tls_material.encodeSnapshot(allocator, .{
        .default = .{ .cert_chain = &chain, .signing_key = &ed },
        .tls12_mode = .disabled,
    });
    defer native_windows_tls_material.freeEncoded(allocator, tls_material);
    var unused_server: @import("../server.zig").Server = undefined;
    const tls_config: @import("../config_format.zig").Config.Tls = .{};
    var acme_owner = @import("../acme_renewal.zig").Service.init(allocator, std.testing.io, &unused_server, .{ .enabled = true }, &tls_config);
    const acme = try native_windows_acme.captureUnstartedEncoded(allocator, &acme_owner);
    defer allocator.free(acme);
    var wasm_bridge = @import("../../wasm/host/bridge.zig").Bridge.init(allocator);
    defer wasm_bridge.deinit();
    const wasm_state = try native_windows_wasm.encode(allocator, &wasm_bridge, "plugins");
    defer native_windows_wasm.freeEncoded(allocator, wasm_state);

    const pieces = [_]TestPiece{
        .{ .kind = .mesh_checkpoint, .bytes = event_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_outbox },
        .{ .kind = .mesh_checkpoint, .bytes = relay_event_log },
        .{ .kind = .mesh_checkpoint, .bytes = attachment_delivery },
        .{ .kind = .mesh_checkpoint, .bytes = e2ee_group },
        .{ .kind = .mesh_checkpoint, .bytes = &clock },
        .{ .kind = .mesh_checkpoint, .bytes = policy },
        .{ .kind = .mesh_checkpoint, .bytes = operator_state },
        .{ .kind = .mesh_checkpoint, .bytes = tls_material },
        .{ .kind = .mesh_checkpoint, .bytes = acme },
        .{ .kind = .mesh_checkpoint, .bytes = wasm_state },
    };
    var fields: [pieces.len][1]capsule.Field = undefined;
    var caps: [pieces.len]capsule.Capsule = undefined;
    _ = makeTestCaps(&pieces, &fields, &caps);
    for (&caps) |*cap| cap.header.min_supported = 2;
    const summary = try validateCurrent(&caps, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.policy);
    try std.testing.expectEqual(@as(usize, 1), summary.operator_state);
    try std.testing.expectEqual(@as(usize, 1), summary.tls_material);
    try std.testing.expectEqual(@as(usize, 1), summary.acme);
    try std.testing.expectEqual(@as(usize, 1), summary.wasm);
    try std.testing.expectError(error.DuplicatePolicy, validateCurrent(&.{ caps[7], caps[7] }, &.{}));
    try std.testing.expectError(error.DuplicateOperatorState, validateCurrent(&.{ caps[8], caps[8] }, &.{}));
    try std.testing.expectError(error.DuplicateTlsMaterial, validateCurrent(&.{ caps[9], caps[9] }, &.{}));
    try std.testing.expectError(error.DuplicateAcme, validateCurrent(&.{ caps[10], caps[10] }, &.{}));
    try std.testing.expectError(error.DuplicateWasm, validateCurrent(&.{ caps[11], caps[11] }, &.{}));

    const corrupt_policy = try allocator.dupe(u8, policy);
    defer allocator.free(corrupt_policy);
    corrupt_policy[corrupt_policy.len - 1] ^= 1;
    var corrupt_policy_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt_policy }};
    var corrupt_policy_cap = capsule.make(.mesh_checkpoint, &corrupt_policy_field);
    corrupt_policy_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidPolicy, validateCurrent(&.{corrupt_policy_cap}, &.{}));

    const corrupt_operator = try allocator.dupe(u8, operator_state);
    defer allocator.free(corrupt_operator);
    corrupt_operator[corrupt_operator.len - 1] ^= 1;
    var corrupt_operator_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt_operator }};
    var corrupt_operator_cap = capsule.make(.mesh_checkpoint, &corrupt_operator_field);
    corrupt_operator_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidOperatorState, validateCurrent(&.{corrupt_operator_cap}, &.{}));

    const corrupt_tls = try allocator.dupe(u8, tls_material);
    defer native_windows_tls_material.freeEncoded(allocator, corrupt_tls);
    corrupt_tls[corrupt_tls.len - 1] ^= 1;
    var corrupt_tls_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt_tls }};
    var corrupt_tls_cap = capsule.make(.mesh_checkpoint, &corrupt_tls_field);
    corrupt_tls_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidTlsMaterial, validateCurrent(&.{corrupt_tls_cap}, &.{}));

    const corrupt_acme = try allocator.dupe(u8, acme);
    defer allocator.free(corrupt_acme);
    corrupt_acme[corrupt_acme.len - 1] ^= 1;
    var corrupt_acme_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt_acme }};
    var corrupt_acme_cap = capsule.make(.mesh_checkpoint, &corrupt_acme_field);
    corrupt_acme_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidAcme, validateCurrent(&.{corrupt_acme_cap}, &.{}));

    const corrupt_wasm = try allocator.dupe(u8, wasm_state);
    defer native_windows_wasm.freeEncoded(allocator, corrupt_wasm);
    corrupt_wasm[corrupt_wasm.len - 1] ^= 1;
    var corrupt_wasm_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt_wasm }};
    var corrupt_wasm_cap = capsule.make(.mesh_checkpoint, &corrupt_wasm_field);
    corrupt_wasm_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidWasm, validateCurrent(&.{corrupt_wasm_cap}, &.{}));
}

test "current handoff relations accept exact mixed client sidecars S2S and redial" {
    const allocator = std.testing.allocator;
    const tls_server = @import("../../crypto/tls_server.zig");

    const client_a = try session_snapshot.encode(allocator, .{
        .nick = "alice",
        .fd = 10,
        .was_secured = true,
        .was_websocket = true,
    });
    defer allocator.free(client_a);
    const client_b = try session_snapshot.encode(allocator, .{ .nick = "bob", .fd = 11 });
    defer allocator.free(client_b);
    const tls = try tls_snapshot.encode(allocator, .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 10,
        .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 3, .app_write_seq = 4, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) } } },
    });
    defer allocator.free(tls);
    const websocket = try ws_snapshot.encode(allocator, .{ .fd = 10, .phase_open = true });
    defer allocator.free(websocket);
    var monitor_buf: [64]u8 = undefined;
    const monitor = try (monitor_capsule.MonitorCapsule{ .client_id = 10, .targets = &.{"bob"} }).encode(&monitor_buf);
    var empty_monitor_buf: [32]u8 = undefined;
    const empty_monitor = try (monitor_capsule.MonitorCapsule{ .client_id = 11, .targets = &.{} }).encode(&empty_monitor_buf);
    var silence_buf: [64]u8 = undefined;
    const silence = try (silence_capsule.SilenceCapsule{ .client_id = 10, .masks = &.{"bad!*@*"} }).encode(&silence_buf);
    var empty_silence_buf: [32]u8 = undefined;
    const empty_silence = try (silence_capsule.SilenceCapsule{ .client_id = 11, .masks = &.{} }).encode(&empty_silence_buf);
    const s2s = try s2s_snapshot.encode(allocator, .{ .fd = 20, .remote_node_id = 77 });
    defer allocator.free(s2s);
    const clock = try mesh_clock_snapshot.encode(.{ .last_stamp = 9 }, 0, .{});
    const redial = mesh_redial.encode(.{ .addr = @splat(0x11), .port = 6697 });
    var props = prop_checkpoint.DefaultStore.init(allocator);
    defer props.deinit();
    var channel_clocks: prop_checkpoint.ChannelClockMap = .empty;
    defer channel_clocks.deinit(allocator);
    var entity_clocks: prop_checkpoint.EntityClockMap = .empty;
    defer entity_clocks.deinit(allocator);
    const prop = try prop_checkpoint.encode(allocator, &props, &channel_clocks, &entity_clocks);
    defer allocator.free(prop);
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);

    const pieces = [_]TestPiece{
        .{ .kind = .clients, .bytes = client_a },
        .{ .kind = .clients, .bytes = client_b },
        .{ .kind = .tls_session, .bytes = tls },
        .{ .kind = .ws_session, .bytes = websocket },
        .{ .kind = .monitor_list, .bytes = monitor },
        .{ .kind = .monitor_list, .bytes = empty_monitor },
        .{ .kind = .silence_list, .bytes = silence },
        .{ .kind = .silence_list, .bytes = empty_silence },
        .{ .kind = .s2s_link, .bytes = s2s },
        .{ .kind = .mesh_checkpoint, .bytes = &clock },
        .{ .kind = .mesh_checkpoint, .bytes = &redial },
        .{ .kind = .mesh_checkpoint, .bytes = prop },
        .{ .kind = .mesh_checkpoint, .bytes = event_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_outbox },
        .{ .kind = .mesh_checkpoint, .bytes = relay_event_log },
        .{ .kind = .mesh_checkpoint, .bytes = attachment_delivery },
        .{ .kind = .mesh_checkpoint, .bytes = e2ee_group },
    };
    var fields: [pieces.len][1]capsule.Field = undefined;
    var caps: [pieces.len]capsule.Capsule = undefined;
    const current = makeTestCaps(&pieces, &fields, &caps);
    // The PROP checkpoint's v2 minimum is intentionally stricter than the
    // shared mesh-checkpoint descriptor's legacy-compatible v1 minimum.
    for (caps[caps.len - 7 ..]) |*cap| cap.header.min_supported = 2;
    for (&caps) |*cap| {
        if (cap.header.kind == .mesh_checkpoint and
            hasPrefix(cap.fields[0].bytes, &mesh_clock_snapshot.magic))
            cap.header.min_supported = 2;
    }
    const summary = try validateCurrent(current, &.{ 10, 11, 20 });
    try std.testing.expectEqual(@as(usize, 2), summary.clients);
    try std.testing.expectEqual(@as(usize, 1), summary.tls);
    try std.testing.expectEqual(@as(usize, 1), summary.websockets);
    try std.testing.expectEqual(@as(usize, 2), summary.monitors);
    try std.testing.expectEqual(@as(usize, 2), summary.silences);
    try std.testing.expectEqual(@as(usize, 1), summary.s2s_links);
    try std.testing.expectEqual(@as(usize, 1), summary.redials);
    try std.testing.expectEqual(@as(usize, 1), summary.event_spine_replay);
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_replay);
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_outbox);
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_event_log);
    try std.testing.expectEqual(@as(usize, 1), summary.attachment_delivery_spool);
    try std.testing.expectEqual(@as(usize, 1), summary.e2ee_group_mesh_authority);
    try std.testing.expectEqual(@as(usize, 1), summary.mesh_clock);

    // A v2 predecessor owns the same fd graph but predates the caps-extension
    // byte AND the v4 roster block. Its advertised current version must
    // negotiate and validate without weakening the exact ownership relation.
    const caps_ext_off = @sizeOf(i32) + 1 + 1 + s2s_snapshot.est_len +
        8 + 8 + 8 + 8 + 8 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 1;
    // Strip the trailing v4 roster block first (empty roster ⇒ 8 zero bytes).
    const s2s_v3 = s2s[0 .. s2s.len - 8];
    const s2s_v2 = try allocator.alloc(u8, s2s_v3.len - 1);
    defer allocator.free(s2s_v2);
    @memcpy(s2s_v2[0..caps_ext_off], s2s_v3[0..caps_ext_off]);
    @memcpy(s2s_v2[caps_ext_off..], s2s_v3[caps_ext_off + 1 ..]);
    fields[8][0].bytes = s2s_v2;
    caps[8].header.version = 2;
    caps[8].header.max_supported = 2;
    const rolling = try validateCurrent(current, &.{ 10, 11, 20 });
    try std.testing.expectEqual(@as(usize, 1), rolling.s2s_links);
}

test "current handoff relations accept a pre-bump v1 TLS sidecar (netsplit guard)" {
    const allocator = std.testing.allocator;
    const tls_server = @import("../../crypto/tls_server.zig");

    const client = try session_snapshot.encode(allocator, .{ .nick = "alice", .fd = 10, .was_secured = true });
    defer allocator.free(client);
    // The CURRENTLY-DEPLOYED predecessor seals the flag-bearing TLS blob while
    // still stamping capsule version 1. The relation preflight must negotiate and
    // decode it as v1 rather than pinning current, or the next USR2 netsplits.
    const tls = try tls_snapshot.encode(allocator, .{
        .kernel_tx_prefix_remaining = 0,
        .fd = 10,
        .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 3, .app_write_seq = 4, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) } } },
        .tx_offloaded = true,
    });
    defer allocator.free(tls);
    var monitor_buf: [32]u8 = undefined;
    const monitor = try (monitor_capsule.MonitorCapsule{ .client_id = 10, .targets = &.{} }).encode(&monitor_buf);
    var silence_buf: [32]u8 = undefined;
    const silence = try (silence_capsule.SilenceCapsule{ .client_id = 10, .masks = &.{} }).encode(&silence_buf);
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});

    const pieces = [_]TestPiece{
        .{ .kind = .clients, .bytes = client },
        .{ .kind = .tls_session, .bytes = tls },
        .{ .kind = .monitor_list, .bytes = monitor },
        .{ .kind = .silence_list, .bytes = silence },
        .{ .kind = .mesh_checkpoint, .bytes = event_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_outbox },
        .{ .kind = .mesh_checkpoint, .bytes = relay_event_log },
        .{ .kind = .mesh_checkpoint, .bytes = attachment_delivery },
        .{ .kind = .mesh_checkpoint, .bytes = e2ee_group },
        .{ .kind = .mesh_checkpoint, .bytes = &clock },
    };
    var fields: [pieces.len][1]capsule.Field = undefined;
    var caps: [pieces.len]capsule.Capsule = undefined;
    _ = makeTestCaps(&pieces, &fields, &caps);
    for (caps[caps.len - 7 ..]) |*cap| cap.header.min_supported = 2;
    // Stamp the TLS capsule as a legacy v1 image (what a pre-bump predecessor
    // produced), keeping the flag-bearing v2 blob bytes.
    caps[1].header.version = 1;
    caps[1].header.min_supported = 1;
    caps[1].header.max_supported = 1;
    try std.testing.expectError(error.InvalidTls, validateCurrent(&caps, &.{10}));
}

test "current handoff relations reject missing duplicate orphan and unexpected transport sidecars" {
    const allocator = std.testing.allocator;
    const tls_server = @import("../../crypto/tls_server.zig");
    const secured = try session_snapshot.encode(allocator, .{ .nick = "a", .fd = 10, .was_secured = true, .was_websocket = true });
    defer allocator.free(secured);
    const plain = try session_snapshot.encode(allocator, .{ .nick = "b", .fd = 11 });
    defer allocator.free(plain);
    const tls10 = try tls_snapshot.encode(allocator, .{ .kernel_tx_prefix_remaining = 0, .fd = 10, .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 0, .app_write_seq = 0, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) } } } });
    defer allocator.free(tls10);
    const tls11 = try tls_snapshot.encode(allocator, .{ .kernel_tx_prefix_remaining = 0, .fd = 11, .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 0, .app_write_seq = 0, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) } } } });
    defer allocator.free(tls11);
    const tls99 = try tls_snapshot.encode(allocator, .{ .kernel_tx_prefix_remaining = 0, .fd = 99, .state = .{ .barrier_phase = .none, .held_record_len = 0, .engine = .{ .tls13 = tls_server.Server.ResumeState{ .suite = 0x1302, .client_app_secret = @splat(1), .server_app_secret = @splat(2), .app_read_seq = 0, .app_write_seq = 0, .peer_record_size_limit_raw = 16385, .local_receive_policy = 16385, .record_size_limit_negotiated = false, .selected_alpn = &.{}, .exporter_master_secret = @splat(0), .exporter_master_secret_ready = true, .ku_prefix_len = 0, .ku_prefix = @splat(0) } } } });
    defer allocator.free(tls99);
    const ws10 = try ws_snapshot.encode(allocator, .{ .fd = 10 });
    defer allocator.free(ws10);
    const ws11 = try ws_snapshot.encode(allocator, .{ .fd = 11 });
    defer allocator.free(ws11);
    const ws99 = try ws_snapshot.encode(allocator, .{ .fd = 99 });
    defer allocator.free(ws99);
    var monitor10_buf: [32]u8 = undefined;
    const monitor10 = try (monitor_capsule.MonitorCapsule{ .client_id = 10, .targets = &.{} }).encode(&monitor10_buf);
    var monitor11_buf: [32]u8 = undefined;
    const monitor11 = try (monitor_capsule.MonitorCapsule{ .client_id = 11, .targets = &.{} }).encode(&monitor11_buf);
    var silence10_buf: [32]u8 = undefined;
    const silence10 = try (silence_capsule.SilenceCapsule{ .client_id = 10, .masks = &.{} }).encode(&silence10_buf);
    var silence11_buf: [32]u8 = undefined;
    const silence11 = try (silence_capsule.SilenceCapsule{ .client_id = 11, .masks = &.{} }).encode(&silence11_buf);
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});

    const base = [_]TestPiece{
        .{ .kind = .clients, .bytes = secured },
        .{ .kind = .clients, .bytes = plain },
        .{ .kind = .tls_session, .bytes = tls10 },
        .{ .kind = .ws_session, .bytes = ws10 },
        .{ .kind = .monitor_list, .bytes = monitor10 },
        .{ .kind = .monitor_list, .bytes = monitor11 },
        .{ .kind = .silence_list, .bytes = silence10 },
        .{ .kind = .silence_list, .bytes = silence11 },
        .{ .kind = .mesh_checkpoint, .bytes = event_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_outbox },
        .{ .kind = .mesh_checkpoint, .bytes = relay_event_log },
        .{ .kind = .mesh_checkpoint, .bytes = attachment_delivery },
        .{ .kind = .mesh_checkpoint, .bytes = e2ee_group },
        .{ .kind = .mesh_checkpoint, .bytes = &clock },
    };
    var base_fields: [base.len][1]capsule.Field = undefined;
    var base_caps: [base.len]capsule.Capsule = undefined;
    _ = makeTestCaps(&base, &base_fields, &base_caps);
    for (base_caps[base_caps.len - 7 ..]) |*cap| cap.header.min_supported = 2;
    _ = try validateCurrent(&base_caps, &.{ 10, 11 });

    try std.testing.expectError(error.MissingTls, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[3] }, &.{ 10, 11 }));
    try std.testing.expectError(error.DuplicateTls, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[2], base_caps[2], base_caps[3] }, &.{ 10, 11 }));
    var orphan_tls_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = tls99 }};
    const orphan_tls = capsule.make(.tls_session, &orphan_tls_field);
    try std.testing.expectError(error.OrphanTls, validateCurrent(&.{ base_caps[0], base_caps[1], orphan_tls, base_caps[3] }, &.{ 10, 11 }));
    var unexpected_tls_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = tls11 }};
    const unexpected_tls = capsule.make(.tls_session, &unexpected_tls_field);
    try std.testing.expectError(error.UnexpectedTls, validateCurrent(&.{ base_caps[0], base_caps[1], unexpected_tls, base_caps[3] }, &.{ 10, 11 }));

    try std.testing.expectError(error.MissingWebSocket, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[2] }, &.{ 10, 11 }));
    try std.testing.expectError(error.DuplicateWebSocket, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[2], base_caps[3], base_caps[3] }, &.{ 10, 11 }));
    var orphan_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = ws99 }};
    const orphan_ws = capsule.make(.ws_session, &orphan_ws_field);
    try std.testing.expectError(error.OrphanWebSocket, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[2], orphan_ws }, &.{ 10, 11 }));
    var unexpected_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = ws11 }};
    const unexpected_ws = capsule.make(.ws_session, &unexpected_ws_field);
    try std.testing.expectError(error.UnexpectedWebSocket, validateCurrent(&.{ base_caps[0], base_caps[1], base_caps[2], unexpected_ws }, &.{ 10, 11 }));

    const closed_ws = try ws_snapshot.encode(allocator, .{ .fd = 10, .phase_open = false });
    defer allocator.free(closed_ws);
    var closed_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = closed_ws }};
    var malformed_caps = base_caps;
    malformed_caps[3] = capsule.make(.ws_session, &closed_ws_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const retained_internal_cr_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .tx = "NOTICE Bob :one\rPRIVMSG Bob :two",
    });
    defer allocator.free(retained_internal_cr_ws);
    var retained_internal_cr_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = retained_internal_cr_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &retained_internal_cr_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const missing_binary_accumulator_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
    });
    defer allocator.free(missing_binary_accumulator_ws);
    var missing_binary_accumulator_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = missing_binary_accumulator_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &missing_binary_accumulator_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const stray_binary_accumulator_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .subprotocol = .onyx_irc_media,
        .binary_message = "stray",
    });
    defer allocator.free(stray_binary_accumulator_ws);
    var stray_binary_accumulator_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = stray_binary_accumulator_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &stray_binary_accumulator_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const oversized_binary = try allocator.alloc(u8, ws_snapshot.max_frame_payload + 1);
    defer allocator.free(oversized_binary);
    @memset(oversized_binary, 0xa5);
    const oversized_binary_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .fragmented = true,
        .msg_binary = true,
        .subprotocol = .onyx_irc_media,
        .binary_message_active = true,
        .binary_message = oversized_binary,
    });
    defer allocator.free(oversized_binary_ws);
    var oversized_binary_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = oversized_binary_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &oversized_binary_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const text_with_binary_state = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .msg_binary = true,
        .subprotocol = .ircv3_text,
    });
    defer allocator.free(text_with_binary_state);
    var text_with_binary_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = text_with_binary_state }};
    malformed_caps[3] = capsule.make(.ws_session, &text_with_binary_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    // A complete masked zero-payload text frame would already have been
    // drained by the predecessor. Carrying it as the "partial next frame" is
    // semantically impossible and must fail before any successor publication.
    const complete_frame = [_]u8{ 0x81, 0x80, 1, 2, 3, 4 };
    const complete_frame_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .deframer = &complete_frame,
    });
    defer allocator.free(complete_frame_ws);
    var complete_frame_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = complete_frame_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &complete_frame_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const retained_lf_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .tx = "NOTICE Bob :already-complete\r\npartial",
    });
    defer allocator.free(retained_lf_ws);
    var retained_lf_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = retained_lf_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &retained_lf_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const oversized_tx = try allocator.alloc(u8, ws_snapshot.max_tx_bytes + 1);
    defer allocator.free(oversized_tx);
    @memset(oversized_tx, 'x');
    const oversized_tx_ws = try ws_snapshot.encode(allocator, .{
        .fd = 10,
        .tx = oversized_tx,
    });
    defer allocator.free(oversized_tx_ws);
    var oversized_tx_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = oversized_tx_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &oversized_tx_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    // v2 has the exact partial-framing fields but no selected application
    // protocol. It remains cold-decodable by ws_snapshot and is deliberately
    // rejected by current Helix relation validation.
    const legacy_ws = ws10[0 .. ws10.len - 6];
    var legacy_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = legacy_ws }};
    var legacy_ws_cap = capsule.make(.ws_session, &legacy_ws_field);
    legacy_ws_cap.header.version = 2;
    legacy_ws_cap.header.min_supported = 1;
    legacy_ws_cap.header.max_supported = 2;
    malformed_caps[3] = legacy_ws_cap;
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const reserved_ws = try allocator.dupe(u8, ws10);
    defer allocator.free(reserved_ws);
    reserved_ws[4] |= 0x80;
    var reserved_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = reserved_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &reserved_ws_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );

    const trailing_ws = try allocator.alloc(u8, ws10.len + 1);
    defer allocator.free(trailing_ws);
    @memcpy(trailing_ws[0..ws10.len], ws10);
    trailing_ws[ws10.len] = 0;
    var trailing_ws_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = trailing_ws }};
    malformed_caps[3] = capsule.make(.ws_session, &trailing_ws_field);
    try std.testing.expectError(
        error.InvalidWebSocket,
        validateCurrent(&malformed_caps, &.{ 10, 11 }),
    );
}

test "current handoff relations reject optional sidecar owner and cardinality violations" {
    const allocator = std.testing.allocator;
    const client = try session_snapshot.encode(allocator, .{ .nick = "alice", .fd = 10 });
    defer allocator.free(client);
    var client_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = client }};
    const client_cap = capsule.make(.clients, &client_field);

    var monitor_buf: [64]u8 = undefined;
    const monitor = try (monitor_capsule.MonitorCapsule{ .client_id = 10, .targets = &.{"bob"} }).encode(&monitor_buf);
    var monitor_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = monitor }};
    const monitor_cap = capsule.make(.monitor_list, &monitor_field);
    try std.testing.expectError(error.DuplicateMonitor, validateCurrent(&.{ client_cap, monitor_cap, monitor_cap }, &.{10}));
    var orphan_monitor_buf: [64]u8 = undefined;
    const orphan_monitor_wire = try (monitor_capsule.MonitorCapsule{ .client_id = 99, .targets = &.{"bob"} }).encode(&orphan_monitor_buf);
    var orphan_monitor_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = orphan_monitor_wire }};
    try std.testing.expectError(error.OrphanMonitor, validateCurrent(&.{ client_cap, capsule.make(.monitor_list, &orphan_monitor_field) }, &.{10}));

    var silence_buf: [64]u8 = undefined;
    const silence = try (silence_capsule.SilenceCapsule{ .client_id = 10, .masks = &.{"bad!*@*"} }).encode(&silence_buf);
    var silence_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = silence }};
    const silence_cap = capsule.make(.silence_list, &silence_field);
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    var event_replay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_replay_cap = capsule.make(.mesh_checkpoint, &event_replay_field);
    event_replay_cap.header.min_supported = 2;
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    var relay_replay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var relay_replay_cap = capsule.make(.mesh_checkpoint, &relay_replay_field);
    relay_replay_cap.header.min_supported = 2;
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    var relay_outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_outbox }};
    var relay_outbox_cap = capsule.make(.mesh_checkpoint, &relay_outbox_field);
    relay_outbox_cap.header.min_supported = 2;
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    var relay_event_log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_event_log }};
    var relay_event_log_cap = capsule.make(.mesh_checkpoint, &relay_event_log_field);
    relay_event_log_cap.header.min_supported = 2;
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    var attachment_delivery_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment_delivery }};
    var attachment_delivery_cap = capsule.make(.mesh_checkpoint, &attachment_delivery_field);
    attachment_delivery_cap.header.min_supported = 2;
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    var e2ee_group_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_group_cap = capsule.make(.mesh_checkpoint, &e2ee_group_field);
    e2ee_group_cap.header.min_supported = 2;
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    _ = try validateCurrent(&.{ client_cap, monitor_cap, silence_cap, event_replay_cap, relay_replay_cap, relay_outbox_cap, relay_event_log_cap, attachment_delivery_cap, e2ee_group_cap, clock_cap }, &.{10});
    try std.testing.expectError(error.MissingMonitor, validateCurrent(&.{ client_cap, silence_cap }, &.{10}));
    try std.testing.expectError(error.MissingSilence, validateCurrent(&.{ client_cap, monitor_cap }, &.{10}));
    try std.testing.expectError(error.DuplicateSilence, validateCurrent(&.{ client_cap, silence_cap, silence_cap }, &.{10}));
    var orphan_silence_buf: [64]u8 = undefined;
    const orphan_silence_wire = try (silence_capsule.SilenceCapsule{ .client_id = 99, .masks = &.{"bad!*@*"} }).encode(&orphan_silence_buf);
    var orphan_silence_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = orphan_silence_wire }};
    try std.testing.expectError(error.OrphanSilence, validateCurrent(&.{ client_cap, capsule.make(.silence_list, &orphan_silence_field) }, &.{10}));
}

test "current handoff relations reject owner-fd S2S and redial violations" {
    const allocator = std.testing.allocator;
    const client = try session_snapshot.encode(allocator, .{ .nick = "alice", .fd = 10 });
    defer allocator.free(client);
    const s2s = try s2s_snapshot.encode(allocator, .{ .fd = 20, .remote_node_id = 77 });
    defer allocator.free(s2s);
    const redial = mesh_redial.encode(.{ .addr = @splat(0x22), .port = 6697 });
    var monitor_buf: [32]u8 = undefined;
    const monitor = try (monitor_capsule.MonitorCapsule{ .client_id = 10, .targets = &.{} }).encode(&monitor_buf);
    var silence_buf: [32]u8 = undefined;
    const silence = try (silence_capsule.SilenceCapsule{ .client_id = 10, .masks = &.{} }).encode(&silence_buf);
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    const pieces = [_]TestPiece{
        .{ .kind = .clients, .bytes = client },
        .{ .kind = .s2s_link, .bytes = s2s },
        .{ .kind = .mesh_checkpoint, .bytes = &redial },
        .{ .kind = .monitor_list, .bytes = monitor },
        .{ .kind = .silence_list, .bytes = silence },
        .{ .kind = .mesh_checkpoint, .bytes = event_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_replay },
        .{ .kind = .mesh_checkpoint, .bytes = relay_outbox },
        .{ .kind = .mesh_checkpoint, .bytes = relay_event_log },
        .{ .kind = .mesh_checkpoint, .bytes = attachment_delivery },
        .{ .kind = .mesh_checkpoint, .bytes = e2ee_group },
        .{ .kind = .mesh_checkpoint, .bytes = &clock },
    };
    var fields: [pieces.len][1]capsule.Field = undefined;
    var caps: [pieces.len]capsule.Capsule = undefined;
    _ = makeTestCaps(&pieces, &fields, &caps);
    for (caps[caps.len - 7 ..]) |*cap| cap.header.min_supported = 2;
    _ = try validateCurrent(&caps, &.{ 10, 20 });
    try std.testing.expectError(error.DuplicateStateFd, validateCurrent(&caps, &.{ 10, 20, 20 }));
    try std.testing.expectError(error.MissingStateFd, validateCurrent(&caps, &.{10}));
    try std.testing.expectError(error.OrphanStateFd, validateCurrent(&caps, &.{ 10, 20, 30 }));
    try std.testing.expectError(error.DuplicateRedial, validateCurrent(&.{ caps[0], caps[1], caps[2], caps[2], caps[3], caps[4] }, &.{ 10, 20 }));

    var trailing_redial: [mesh_redial.encoded_len + 1]u8 = undefined;
    @memcpy(trailing_redial[0..mesh_redial.encoded_len], &redial);
    trailing_redial[mesh_redial.encoded_len] = 0;
    var trailing_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = &trailing_redial }};
    try std.testing.expectError(error.InvalidRedial, validateCurrent(&.{ caps[0], caps[1], capsule.make(.mesh_checkpoint, &trailing_field), caps[3], caps[4] }, &.{ 10, 20 }));
    var unknown_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = "unknown-mesh" }};
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{ caps[0], caps[1], capsule.make(.mesh_checkpoint, &unknown_field), caps[3], caps[4] }, &.{ 10, 20 }));

    const trailing_s2s = try allocator.alloc(u8, s2s.len + 1);
    defer allocator.free(trailing_s2s);
    @memcpy(trailing_s2s[0..s2s.len], s2s);
    trailing_s2s[s2s.len] = 0;
    var trailing_s2s_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = trailing_s2s }};
    try std.testing.expectError(error.InvalidS2s, validateCurrent(&.{ caps[0], capsule.make(.s2s_link, &trailing_s2s_field), caps[2], caps[3], caps[4] }, &.{ 10, 20 }));
}

test "current handoff relations require exactly one canonical ESG2 authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    try std.testing.expect(event_spine_replay_guard.isCheckpoint(event_replay));
    var field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var current = capsule.make(.mesh_checkpoint, &field);
    current.header.min_supported = 2;
    var relay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var relay_cap = capsule.make(.mesh_checkpoint, &relay_field);
    relay_cap.header.min_supported = 2;
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    var event_log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_event_log }};
    var event_log_cap = capsule.make(.mesh_checkpoint, &event_log_field);
    event_log_cap.header.min_supported = 2;
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment_delivery }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;

    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ current, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.event_spine_replay);
    try std.testing.expectError(
        error.MissingMeshClock,
        validateCurrent(&.{ current, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    try std.testing.expectError(error.MissingEventSpineReplay, validateCurrent(&.{ relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}));
    try std.testing.expectError(error.DuplicateEventSpineReplay, validateCurrent(&.{ current, current, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}));

    var legacy_compatible = current;
    legacy_compatible.header.min_supported = 1;
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{legacy_compatible}, &.{}));

    const corrupt = try allocator.dupe(u8, event_replay);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidEventSpineReplay, validateCurrent(&.{corrupt_cap}, &.{}));

    const trailing = try allocator.alloc(u8, event_replay.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..event_replay.len], event_replay);
    trailing[event_replay.len] = 0;
    var trailing_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = trailing }};
    var trailing_cap = capsule.make(.mesh_checkpoint, &trailing_field);
    trailing_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidEventSpineReplay, validateCurrent(&.{trailing_cap}, &.{}));
}

test "current handoff relations require exactly one canonical RVG2 authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    try std.testing.expect(relay_v2_replay_guard.isCheckpoint(relay_replay));

    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    var field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var current = capsule.make(.mesh_checkpoint, &field);
    current.header.min_supported = 2;
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    var event_log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_event_log }};
    var event_log_cap = capsule.make(.mesh_checkpoint, &event_log_field);
    event_log_cap.header.min_supported = 2;
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment_delivery }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;

    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ event_cap, current, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_replay);
    try std.testing.expectError(error.MissingRelayV2Replay, validateCurrent(&.{ event_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}));
    try std.testing.expectError(error.DuplicateRelayV2Replay, validateCurrent(&.{ event_cap, current, current, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}));

    var legacy_compatible = current;
    legacy_compatible.header.min_supported = 1;
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{ event_cap, legacy_compatible }, &.{}));

    const invalid_config = try allocator.dupe(u8, relay_replay);
    defer allocator.free(invalid_config);
    invalid_config[5] = 0;
    invalid_config[6] = 0;
    var invalid_config_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = invalid_config }};
    var invalid_config_cap = capsule.make(.mesh_checkpoint, &invalid_config_field);
    invalid_config_cap.header.min_supported = 2;
    try std.testing.expectError(
        error.InvalidRelayV2Replay,
        validateCurrent(&.{ event_cap, invalid_config_cap }, &.{}),
    );

    const corrupt = try allocator.dupe(u8, relay_replay);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidRelayV2Replay, validateCurrent(&.{ event_cap, corrupt_cap }, &.{}));

    const trailing = try allocator.alloc(u8, relay_replay.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..relay_replay.len], relay_replay);
    trailing[relay_replay.len] = 0;
    var trailing_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = trailing }};
    var trailing_cap = capsule.make(.mesh_checkpoint, &trailing_field);
    trailing_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidRelayV2Replay, validateCurrent(&.{ event_cap, trailing_cap }, &.{}));
}

test "current handoff relations require exactly one canonical RVO2 authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(outbox);
    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    var relay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var relay_cap = capsule.make(.mesh_checkpoint, &relay_field);
    relay_cap.header.min_supported = 2;
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    var event_log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_event_log }};
    var event_log_cap = capsule.make(.mesh_checkpoint, &event_log_field);
    event_log_cap.header.min_supported = 2;
    const attachment_delivery = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment_delivery);
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment_delivery }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ event_cap, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_outbox);
    try std.testing.expectError(
        error.MissingRelayV2Outbox,
        validateCurrent(&.{ event_cap, relay_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    try std.testing.expectError(
        error.DuplicateRelayV2Outbox,
        validateCurrent(&.{ event_cap, relay_cap, outbox_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    const corrupt = try allocator.dupe(u8, outbox);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(
        error.InvalidRelayV2Outbox,
        validateCurrent(&.{ event_cap, relay_cap, corrupt_cap }, &.{}),
    );
}

test "current handoff relations require exactly one canonical RVL2 authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(outbox);
    const event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(event_log);
    const attachment = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);

    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    var replay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var replay_cap = capsule.make(.mesh_checkpoint, &replay_field);
    replay_cap.header.min_supported = 2;
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    var log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_log }};
    var log_cap = capsule.make(.mesh_checkpoint, &log_field);
    log_cap.header.min_supported = 2;
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;

    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.relay_v2_event_log);
    try std.testing.expectError(
        error.MissingRelayV2EventLog,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    try std.testing.expectError(
        error.DuplicateRelayV2EventLog,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, log_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    var legacy = log_cap;
    legacy.header.min_supported = 1;
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{legacy}, &.{}));

    const corrupt = try allocator.dupe(u8, event_log);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidRelayV2EventLog, validateCurrent(&.{corrupt_cap}, &.{}));
}

test "current handoff relations require exactly one canonical ADS1 authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(outbox);
    const event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(event_log);
    const attachment = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);

    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    var replay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var replay_cap = capsule.make(.mesh_checkpoint, &replay_field);
    replay_cap.header.min_supported = 2;
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    var log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_log }};
    var log_cap = capsule.make(.mesh_checkpoint, &log_field);
    log_cap.header.min_supported = 2;
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;

    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.attachment_delivery_spool);
    try std.testing.expectError(
        error.MissingAttachmentDeliverySpool,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, e2ee_cap }, &.{}),
    );
    try std.testing.expectError(
        error.DuplicateAttachmentDeliverySpool,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, attachment_cap, e2ee_cap }, &.{}),
    );
    var legacy = attachment_cap;
    legacy.header.min_supported = 1;
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{legacy}, &.{}));

    const corrupt = try allocator.dupe(u8, attachment);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidAttachmentDeliverySpool, validateCurrent(&.{corrupt_cap}, &.{}));
}

test "current handoff relations require exactly one canonical EGRG authority" {
    const allocator = std.testing.allocator;
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    const outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(outbox);
    const event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(event_log);
    const attachment = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment);
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    try std.testing.expect(e2ee_group_mesh_authority.isCheckpoint(e2ee_group));

    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    var replay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var replay_cap = capsule.make(.mesh_checkpoint, &replay_field);
    replay_cap.header.min_supported = 2;
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    var log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_log }};
    var log_cap = capsule.make(.mesh_checkpoint, &log_field);
    log_cap.header.min_supported = 2;
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;

    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);
    const summary = try validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, e2ee_cap, clock_cap }, &.{});
    try std.testing.expectEqual(@as(usize, 1), summary.e2ee_group_mesh_authority);
    try std.testing.expectError(
        error.MissingE2eeGroupMeshAuthority,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, clock_cap }, &.{}),
    );
    try std.testing.expectError(
        error.DuplicateE2eeGroupMeshAuthority,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, e2ee_cap, e2ee_cap, clock_cap }, &.{}),
    );
    var legacy = e2ee_cap;
    legacy.header.min_supported = 1;
    try std.testing.expectError(error.UnknownMeshCheckpoint, validateCurrent(&.{legacy}, &.{}));

    const corrupt = try allocator.dupe(u8, e2ee_group);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidE2eeGroupMeshAuthority, validateCurrent(&.{corrupt_cap}, &.{}));

    const trailing = try allocator.alloc(u8, e2ee_group.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..e2ee_group.len], e2ee_group);
    trailing[e2ee_group.len] = 0;
    var trailing_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = trailing }};
    var trailing_cap = capsule.make(.mesh_checkpoint, &trailing_field);
    trailing_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidE2eeGroupMeshAuthority, validateCurrent(&.{trailing_cap}, &.{}));

    // Zero the inner RVG2 window_size (RVG2 header bytes 5..7). EGRG body is
    // rvg2_len(4) || rvg2, so absolute offsets are egrg_header_len+4+5..6.
    // Recompute the inner RVG2 checksum (domain onyx-relay-v2-replay-checkpoint-v1)
    // then the outer EGRG v2 checksum so open succeeds and nested validation
    // reaches InvalidConfig (surfaced here as InvalidE2eeGroupMeshAuthority).
    const invalid_config = try allocator.dupe(u8, e2ee_group);
    defer allocator.free(invalid_config);
    const egrg_header_len: usize = 9;
    const rvg2_len_field_len: usize = 4;
    const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
    try std.testing.expect(invalid_config.len > egrg_header_len + rvg2_len_field_len + checksum_len + 7);
    const rvg2_off = egrg_header_len + rvg2_len_field_len;
    const rvg2_len: usize = std.mem.readInt(u32, invalid_config[egrg_header_len..][0..4], .big);
    try std.testing.expect(rvg2_len > checksum_len);
    try std.testing.expect(invalid_config.len >= rvg2_off + rvg2_len + checksum_len);
    invalid_config[rvg2_off + 5] = 0;
    invalid_config[rvg2_off + 6] = 0;
    const rvg2 = invalid_config[rvg2_off .. rvg2_off + rvg2_len];
    const rvg2_prefix_len = rvg2_len - checksum_len;
    var rvg2_hash = std.crypto.hash.Blake3.init(.{});
    rvg2_hash.update("onyx-relay-v2-replay-checkpoint-v1");
    rvg2_hash.update(rvg2[0..rvg2_prefix_len]);
    rvg2_hash.final(rvg2[rvg2_prefix_len..][0..checksum_len]);
    const prefix_len = invalid_config.len - checksum_len;
    var egrg_hash = std.crypto.hash.Blake3.init(.{});
    egrg_hash.update("onyx-e2ee-group-replay-checkpoint-v2");
    egrg_hash.update(invalid_config[0..prefix_len]);
    egrg_hash.final(invalid_config[prefix_len..][0..checksum_len]);
    const e2ee_group_replay_guard = @import("../e2ee_group_replay_guard.zig");
    try std.testing.expectError(error.InvalidConfig, e2ee_group_replay_guard.validateCheckpoint(invalid_config));
    var invalid_config_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = invalid_config }};
    var invalid_config_cap = capsule.make(.mesh_checkpoint, &invalid_config_field);
    invalid_config_cap.header.min_supported = 2;
    try std.testing.expectError(
        error.InvalidE2eeGroupMeshAuthority,
        validateCurrent(&.{ event_cap, replay_cap, outbox_cap, log_cap, attachment_cap, invalid_config_cap }, &.{}),
    );
}

test "current handoff relations validate the at-most-once oper-grant checkpoint" {
    const allocator = std.testing.allocator;
    const oper_cred_share = @import("../../proto/oper_cred_share.zig");

    // The six required singletons; the grants piece rides beside them.
    const event_replay = try testEventSpineReplayCheckpoint(allocator);
    defer allocator.free(event_replay);
    var event_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = event_replay }};
    var event_cap = capsule.make(.mesh_checkpoint, &event_field);
    event_cap.header.min_supported = 2;
    const relay_replay = try testRelayV2ReplayCheckpoint(allocator);
    defer allocator.free(relay_replay);
    var relay_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_replay }};
    var relay_cap = capsule.make(.mesh_checkpoint, &relay_field);
    relay_cap.header.min_supported = 2;
    const relay_outbox = try testRelayV2OutboxCheckpoint(allocator);
    defer allocator.free(relay_outbox);
    var outbox_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_outbox }};
    var outbox_cap = capsule.make(.mesh_checkpoint, &outbox_field);
    outbox_cap.header.min_supported = 2;
    const relay_event_log = try testRelayV2EventLogCheckpoint(allocator);
    defer allocator.free(relay_event_log);
    var event_log_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = relay_event_log }};
    var event_log_cap = capsule.make(.mesh_checkpoint, &event_log_field);
    event_log_cap.header.min_supported = 2;
    const attachment = try testAttachmentDeliveryCheckpoint(allocator);
    defer allocator.free(attachment);
    var attachment_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = attachment }};
    var attachment_cap = capsule.make(.mesh_checkpoint, &attachment_field);
    attachment_cap.header.min_supported = 2;
    const e2ee_group = try testE2eeGroupMeshAuthorityCheckpoint(allocator);
    defer allocator.free(e2ee_group);
    var e2ee_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = e2ee_group }};
    var e2ee_cap = capsule.make(.mesh_checkpoint, &e2ee_field);
    e2ee_cap.header.min_supported = 2;
    const clock = try mesh_clock_snapshot.encode(.{}, 0, .{});
    var clock_field: [1]capsule.Field = undefined;
    const clock_cap = testMeshClockCap(&clock, &clock_field);

    var reg = oper_cred_share.Registry.init();
    _ = reg.upsert(.{
        .account = "trev",
        .privilege_bits = 1,
        .class = "netadmin",
        .title = "",
        .issuer_node = "ircx.us",
        .incarnation = 7,
        .issued_ms = 1,
        .expiry_ms = 1_000,
    });
    const grants = try oper_grant_snapshot.encodeFromRegistry(allocator, &reg, 0, 9);
    defer allocator.free(grants);
    try std.testing.expect(oper_grant_snapshot.isCheckpoint(grants));
    var grants_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = grants }};
    var grants_cap = capsule.make(.mesh_checkpoint, &grants_field);
    grants_cap.header.min_supported = 2;

    // Present once: accepted and counted.
    const with = try validateCurrent(
        &.{ event_cap, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap, grants_cap },
        &.{},
    );
    try std.testing.expectEqual(@as(usize, 1), with.oper_grants);

    // ABSENT is legal: a pre-checkpoint predecessor's arena still adopts
    // (empty registry = pre-checkpoint behavior). No Missing error.
    const without = try validateCurrent(
        &.{ event_cap, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap },
        &.{},
    );
    try std.testing.expectEqual(@as(usize, 0), without.oper_grants);

    // Duplicate is ambiguous authority.
    try std.testing.expectError(error.DuplicateOperGrants, validateCurrent(
        &.{ event_cap, relay_cap, outbox_cap, event_log_cap, attachment_cap, e2ee_cap, clock_cap, grants_cap, grants_cap },
        &.{},
    ));

    // Malformed body with the right magic fails closed (declared count 2 with
    // only one record present walks off the end).
    const corrupt = try allocator.dupe(u8, grants);
    defer allocator.free(corrupt);
    std.mem.writeInt(u32, corrupt[oper_grant_snapshot.magic.len + 1 + 8 ..][0..4], 2, .little);
    var corrupt_field = [_]capsule.Field{.{ .ordinal = 1, .bytes = corrupt }};
    var corrupt_cap = capsule.make(.mesh_checkpoint, &corrupt_field);
    corrupt_cap.header.min_supported = 2;
    try std.testing.expectError(error.InvalidOperGrants, validateCurrent(&.{corrupt_cap}, &.{}));

    // A downgraded (min=1) header on this exact state piece fails closed.
    var weak_cap = grants_cap;
    weak_cap.header.min_supported = 1;
    try std.testing.expectError(error.InvalidOperGrants, validateCurrent(&.{weak_cap}, &.{}));
}
