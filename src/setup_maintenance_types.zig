// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared nonsecret maintenance interface. No authority is inferred from a
//! review: the daemon's upgrade cut still validates its actual live state.
const std = @import("std");

pub const Selection = struct {
    pid: i32,
    config: []const u8,
    target: []const u8,
    backup_dir: []const u8,
    restore_into: []const u8,
};

/// File/process identity retained by the Linux backend. No secrets or arbitrary
/// process environment values cross this boundary. Backend must reject drift.
pub const Binding = struct {
    pid: i32,
    uid: u32,
    start_ticks: u64,
    exe_device: u64,
    exe_inode: u64,
    current_sha256: [32]u8,
    config_sha256: [32]u8,
    target_sha256: [32]u8,
    backup_manifest_sha256: [32]u8,
};

pub const Check = enum { passed, unavailable, refused };
pub const StaticChecks = struct {
    current_capabilities: Check = .unavailable,
    target_capabilities: Check,
    candidate_config: Check,
    existing_identity: Check,
    /// Never substitute controller environment for the selected runtime's
    /// resolver. Environment-dependent checks may remain unavailable.
    environment_bound: bool = false,
};
pub const default_backup_max_age_seconds: u64 = 86400;
pub const BackupChecks = struct {
    generated_at_unix: ?i64 = null,
    observed_at_unix: ?i64 = null,
    max_age_seconds: u64 = default_backup_max_age_seconds,
    restore_drill: Check,
    coverage: []const u8 = "OroStore snapshot: accounts, nicks, channel registrations, bans, memos, vhosts, props and history",
    exclusions: []const u8 = "Channel statistics, search, webhook TSVs, event-history file, mail, live sockets, process memory and whole-install identity recovery are not established by this backup",

    /// Age is based on recorded manifest time, not a claim that a backup equals
    /// current live Store state. Backend must check again at the action cut.
    pub fn fresh(self: BackupChecks) bool {
        const generated = self.generated_at_unix orelse return false;
        const observed = self.observed_at_unix orelse return false;
        return generated >= 0 and observed >= generated and self.max_age_seconds > 0 and
            @as(u64, @intCast(observed - generated)) <= self.max_age_seconds;
    }
};
pub const RecoveryRefs = struct {
    runtime_executable: []const u8 = "",
    previous_artifact: []const u8 = "",
    journal: []const u8 = "",
    verified_backup: []const u8 = "",
    configuration_backup: []const u8 = "",
    restore_drill: []const u8 = "",

    pub fn complete(self: RecoveryRefs) bool {
        return self.runtime_executable.len != 0 and self.previous_artifact.len != 0 and self.journal.len != 0 and
            self.verified_backup.len != 0 and self.configuration_backup.len != 0 and self.restore_drill.len != 0;
    }
};

pub const Review = struct {
    binding: Binding,
    static_checks: StaticChecks,
    backup: BackupChecks,
    recovery_refs: RecoveryRefs = .{},
    live_config: []const u8 = "unknown until daemon final guard: in-memory config, realm, resolved environment policy and mandatory state are not attested by file preflight",
    client_impact: []const u8 = "Helix intends to preserve supported attachments; final daemon guards may refuse. Exec observation alone does not prove client, mesh or media readiness",
    recovery: []const u8 = "Retain previous executable and private configuration/identity sources. Refusal before exec leaves predecessor serving; cold recovery may disconnect clients. No full-install restore or safe hot downgrade is promised",

    pub fn applicable(self: Review) bool {
        return self.static_checks.current_capabilities == .passed and self.static_checks.target_capabilities == .passed and
            self.static_checks.candidate_config == .passed and
            self.static_checks.existing_identity == .passed and
            self.backup.restore_drill == .passed and self.backup.fresh() and self.recovery_refs.complete();
    }
};

pub const Outcome = enum { exec_observed, signal_sent_outcome_unknown, predecessor_exited, replacement_committed_signal_not_sent, signal_attempt_outcome_unknown };
pub const ActionResult = struct {
    outcome: Outcome,
    /// Artifact custody, not an assertion of successful rollback/adoption.
    previous_artifact_retained: bool,
    recovery_refs: RecoveryRefs,
    application_readiness: []const u8 = "unknown; validate real clients, mesh and media independently",
};

test "maintenance review never permits an explicit failed check or missing backup" {
    const b: Binding = .{ .pid = 1, .uid = 1, .start_ticks = 1, .exe_device = 1, .exe_inode = 1, .current_sha256 = @splat(1), .config_sha256 = @splat(2), .target_sha256 = @splat(3), .backup_manifest_sha256 = @splat(4) };
    var review: Review = .{ .binding = b, .static_checks = .{ .current_capabilities = .passed, .target_capabilities = .passed, .candidate_config = .passed, .existing_identity = .passed }, .backup = .{ .restore_drill = .passed, .generated_at_unix = 100, .observed_at_unix = 200 }, .recovery_refs = .{ .runtime_executable = "runtime", .previous_artifact = "previous", .journal = "journal", .verified_backup = "backup", .configuration_backup = "config", .restore_drill = "drill" } };
    try std.testing.expect(review.applicable());
    review.static_checks.candidate_config = .refused;
    try std.testing.expect(!review.applicable());
    review.static_checks.candidate_config = .unavailable;
    try std.testing.expect(!review.applicable());
    review.backup.restore_drill = .unavailable;
    try std.testing.expect(!review.applicable());
    review.backup.restore_drill = .passed;
    review.recovery_refs = .{};
    try std.testing.expect(!review.applicable());
}

test "maintenance backup recorded age refuses missing future stale and permits exact policy boundary" {
    var evidence: BackupChecks = .{ .restore_drill = .passed };
    try std.testing.expect(!evidence.fresh());
    evidence.generated_at_unix = 100;
    evidence.observed_at_unix = 99;
    try std.testing.expect(!evidence.fresh());
    evidence.observed_at_unix = 100 + @as(i64, @intCast(default_backup_max_age_seconds));
    try std.testing.expect(evidence.fresh());
    evidence.observed_at_unix.? += 1;
    try std.testing.expect(!evidence.fresh());
}
