// SPDX-License-Identifier: AGPL-3.0-or-later
//! Existing-local-runtime branch of the same setup wizard. UI owns review and
//! explicit intent; backend owns every process/file guard and pidfd operation.
const std = @import("std");
const builtin = @import("builtin");
const types = @import("setup_maintenance_types.zig");
const workflow = @import("setup_workflow.zig");
const review_ui = @import("setup_review.zig");

fn prepareReview(session: anytype) !types.Review {
    const binding = try session.bind();
    const static_checks = try session.checkStatic();
    const backup = try session.checkBackup();
    const recovery_refs = try session.recoveryReferences();
    try session.revalidate(binding);
    return .{ .binding = binding, .static_checks = static_checks, .backup = backup, .recovery_refs = recovery_refs };
}

fn message(init: std.process.Init, width: usize, text: []const u8) !void {
    const rendered = try review_ui.renderMessage(init.gpa, text, width);
    defer init.gpa.free(rendered);
    try std.Io.File.stdout().writeStreamingAll(init.io, rendered);
}

fn runLinux(init: std.process.Init, selection: types.Selection, linear: bool) !void {
    const backend = @import("setup_maintenance_linux.zig");
    const input = std.Io.File.stdin();
    const output = std.Io.File.stdout();
    if (!(try input.isTty(init.io)) or !(try output.isTty(init.io))) return error.InteractiveTerminalRequired;
    const width = review_ui.fallbackWidth(init.environ_map.get("COLUMNS"));
    const color = !linear and init.environ_map.get("NO_COLOR") == null;
    var selected = selection;
    var restore_override: ?[]u8 = null;
    defer if (restore_override) |path| init.gpa.free(path);
    var state: workflow.MaintenanceWizard = .{};
    var session: ?backend.Session = null;
    defer if (session) |*owned| owned.deinit();
    var current_review: ?types.Review = null;
    var buffer: [512]u8 = undefined;
    var reader = input.readerStreaming(init.io, &buffer);
    while (true) {
        const id: ?[]const u8 = if (state.review_id) |*value| value else null;
        const rendered = try review_ui.renderMaintenance(init.gpa, selected, current_review, id, color, width);
        defer init.gpa.free(rendered);
        try output.writeStreamingAll(init.io, rendered);
        try output.writeStreamingAll(init.io, if (current_review != null) "\nreview> " else "\nmaintenance> ");
        const line = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => {
                try message(init, width, "Maintenance cancelled at EOF; no executable staged or signal sent by this review.\n");
                return;
            },
            else => return err,
        };
        switch (state.command(line)) {
            .cancel => {
                try message(init, width, "Maintenance cancelled; no executable staged or signal sent by this review.\n");
                return;
            },
            .back => {
                if (session) |*owned| owned.deinit();
                session = null;
                current_review = null;
                try message(init, width, "Back to choices; previous review invalidated.\n");
            },
            .change_restore => {
                const path = workflow.maintenanceRestorePath(line) orelse return error.InvalidRestorePath;
                const copy = try init.gpa.dupe(u8, path);
                if (restore_override) |old| init.gpa.free(old);
                restore_override = copy;
                selected.restore_into = copy;
            },
            .review => {
                session = backend.Session.open(init.gpa, init.io, selected) catch |err| {
                    var diagnostic: [192]u8 = undefined;
                    try message(init, width, try std.fmt.bufPrint(&diagnostic, "Maintenance binding refused: {s}. No action performed.\n", .{@errorName(err)}));
                    continue;
                };
                current_review = prepareReview(&session.?) catch |err| {
                    session.?.deinit();
                    session = null;
                    var diagnostic: [192]u8 = undefined;
                    try message(init, width, try std.fmt.bufPrint(&diagnostic, "Maintenance review refused: {s}. No action performed.\n", .{@errorName(err)}));
                    continue;
                };
                var nonce: [16]u8 = undefined;
                init.io.random(&nonce);
                state.enterReview(std.fmt.bytesToHex(nonce, .lower));
                try message(init, width, "Review the compatibility, backup coverage, client impact and recovery boundary. Enter apply followed by the exact Review id, back, or cancel.\n");
            },
            .apply => {
                const reviewed = current_review orelse return error.MissingReview;
                if (!reviewed.applicable()) {
                    try message(init, width, "Apply unavailable: required checks have not passed. Enter back or cancel.\n");
                    continue;
                }
                const owned = &session.?;
                // Input drift invalidates the displayed intent. An error is
                // terminal: never replay stage/signal after an ambiguous result.
                try owned.revalidate(reviewed.binding);
                const result = try owned.apply(reviewed.binding);
                state.review_id = null;
                current_review = null;
                var diagnostic: [256]u8 = undefined;
                try message(init, width, try std.fmt.bufPrint(&diagnostic, "Maintenance action outcome: {s}; previous_artifact_retained={s}.\n", .{ @tagName(result.outcome), if (result.previous_artifact_retained) "yes" else "no" }));
                try message(init, width, "Recovery artifact/journal custody references from this action:\n");
                const receipt_view: types.Review = .{ .binding = reviewed.binding, .static_checks = reviewed.static_checks, .backup = reviewed.backup, .recovery_refs = result.recovery_refs };
                const receipt_text = try review_ui.renderMaintenance(init.gpa, selected, receipt_view, null, false, width);
                defer init.gpa.free(receipt_text);
                try output.writeStreamingAll(init.io, receipt_text);
                if (result.outcome == .replacement_committed_signal_not_sent) try message(init, width, "Replacement artifact committed, but no signal sent. The existing process may still run its old image; inspect the retained journal before any further operation. No automatic rollback was attempted.\n");
                try message(init, width, result.application_readiness);
                try message(init, width, "\nNo full-install restore, application readiness or safe hot-downgrade claim follows from this result.\n");
                return;
            },
            .invalid => try message(init, width, "Use review, back, cancel, or apply followed by the exact current Review id.\n"),
        }
    }
}

pub fn run(init: std.process.Init, selection: types.Selection, linear: bool) !void {
    if (comptime builtin.os.tag == .linux) return runLinux(init, selection, linear) else return error.UnsupportedMaintenancePlatform;
}

test "maintenance controller prepares checks in order and never applies during review" {
    const Fake = struct {
        stage: usize = 0,
        const binding: types.Binding = .{ .pid = 123, .uid = 1, .start_ticks = 2, .exe_device = 1, .exe_inode = 3, .current_sha256 = @splat(1), .config_sha256 = @splat(2), .target_sha256 = @splat(3), .backup_manifest_sha256 = @splat(4) };
        fn bind(self: *@This()) !types.Binding {
            try std.testing.expect(self.stage == 0);
            self.stage = 1;
            return binding;
        }
        fn checkStatic(self: *@This()) !types.StaticChecks {
            try std.testing.expect(self.stage == 1);
            self.stage = 2;
            return .{ .current_capabilities = .passed, .target_capabilities = .passed, .candidate_config = .passed, .existing_identity = .passed };
        }
        fn checkBackup(self: *@This()) !types.BackupChecks {
            try std.testing.expect(self.stage == 2);
            self.stage = 3;
            return .{ .restore_drill = .passed, .generated_at_unix = 100, .observed_at_unix = 200 };
        }
        fn recoveryReferences(self: *@This()) !types.RecoveryRefs {
            try std.testing.expect(self.stage == 3);
            return .{ .runtime_executable = "runtime", .previous_artifact = "previous", .journal = "journal", .verified_backup = "backup", .configuration_backup = "config", .restore_drill = "drill" };
        }
        fn revalidate(self: *@This(), supplied: types.Binding) !void {
            try std.testing.expect(self.stage == 3 and std.meta.eql(binding, supplied));
            self.stage = 4;
        }
    };
    var fake: Fake = .{};
    const prepared = try prepareReview(&fake);
    try std.testing.expect(prepared.applicable());
    try std.testing.expectEqual(@as(usize, 4), fake.stage);
}

test {
    _ = types;
    _ = workflow;
    _ = review_ui;
    if (builtin.os.tag == .linux) _ = @import("setup_maintenance_linux.zig");
}
