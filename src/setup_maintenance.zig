// SPDX-License-Identifier: AGPL-3.0-or-later
//! Existing-local-runtime branch of the same setup wizard. UI owns review and
//! explicit intent; backend owns every process/file guard and pidfd operation.
const std = @import("std");
const builtin = @import("builtin");
const types = @import("setup_maintenance_types.zig");
const workflow = @import("setup_workflow.zig");
const review_ui = @import("setup_review.zig");
const maintenance_config = @import("setup_maintenance_config.zig");

fn prepareReview(session: anytype) !types.Review {
    const binding = try session.bind();
    const static_checks = try session.checkStatic();
    const backup = try session.checkBackup();
    const recovery_refs = try session.recoveryReferences();
    try session.revalidate(binding);
    return .{ .binding = binding, .static_checks = static_checks, .backup = backup, .recovery_refs = recovery_refs };
}

/// Configuration edits for one maintenance run, through the new-install
/// wizard's typed Settings. The plan is bound to the exact live bytes read on
/// the first edit; nothing is written except an explicit new private
/// candidate. `env` supplies `loadLive(allocator)` and `save(path, bytes)`.
const ConfigEdits = struct {
    allocator: std.mem.Allocator,
    plan: ?maintenance_config.Plan = null,
    /// The private candidate file holding exactly the current pending edits.
    /// Cleared by any accepted edit, discard or live drift.
    saved: ?Saved = null,

    const Saved = struct { path: []u8, sha256: maintenance_config.Digest };

    fn deinit(self: *ConfigEdits) void {
        self.forgetSaved();
        if (self.plan) |*plan| plan.deinit();
        self.plan = null;
    }

    fn forgetSaved(self: *ConfigEdits) void {
        if (self.saved) |saved| self.allocator.free(saved.path);
        self.saved = null;
    }

    fn pending(self: *const ConfigEdits) bool {
        return if (self.plan) |*plan| plan.pending() else false;
    }

    /// Pending edits that exist only in this process: apply must not
    /// proceed as if they were captured anywhere.
    fn unsaved(self: *const ConfigEdits) bool {
        return self.pending() and self.saved == null;
    }

    /// Review-time check of the saved candidate by the target executable.
    /// `checker.checkCandidate(path, sha256)` returns a `types.Check`.
    /// Nothing here gates the executable action; it reports.
    fn reviewCandidate(self: *const ConfigEdits, checker: anytype, out: *std.Io.Writer) !void {
        const saved = self.saved orelse return;
        const result = checker.checkCandidate(saved.path, saved.sha256) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return out.print("Saved candidate check refused: {s}. Treat the candidate as unverified; nothing written.\n", .{@errorName(err)}),
        };
        try out.print("Saved candidate {s} (sha256 {s}): target executable --check-config against the live file: {s}.\n", .{ saved.path, std.fmt.bytesToHex(saved.sha256, .lower), @tagName(result) });
        try out.writeAll(switch (result) {
            .passed => "The target accepts it as a Helix successor configuration. This executable action does NOT publish it; the live configuration stays in force.\n",
            .refused => "The target refuses it as a Helix successor configuration (invalid, or a listener change that needs a cold restart). This executable action does NOT publish it.\n",
            .unavailable => "Not checked: environment-dependent static checks are unavailable. This executable action does NOT publish it.\n",
        });
    }

    /// Review binds the live file again. Any digest drift since the first
    /// edit discards the plan: edits are never rebased onto unseen bytes.
    fn bindingMatches(self: *ConfigEdits, config_sha256: [32]u8) bool {
        const plan = &(self.plan orelse return true);
        if (std.crypto.timing_safe.eql(maintenance_config.Digest, plan.original_sha256, config_sha256)) return true;
        self.deinit();
        return false;
    }

    fn handle(self: *ConfigEdits, action: workflow.MaintenanceWizard.Action, line: []const u8, env: anytype, out: *std.Io.Writer) !void {
        switch (action) {
            .edit_config => {
                const edit = workflow.maintenanceConfigEdit(line) orelse return out.writeAll("Use set <key> <value>.\n");
                if (self.plan == null) {
                    const live = env.loadLive(self.allocator) catch |err| return out.print("Configuration edit unavailable: {s}. Nothing recorded or written.\n", .{@errorName(err)});
                    defer {
                        std.crypto.secureZero(u8, live);
                        self.allocator.free(live);
                    }
                    self.plan = maintenance_config.Plan.init(self.allocator, live) catch |err| return out.print("Configuration edit unavailable: {s}. Nothing recorded or written.\n", .{@errorName(err)});
                }
                self.plan.?.edit(edit.key, edit.value) catch |err| return out.print("Configuration edit refused: {s}; previous choices kept.\n", .{@errorName(err)});
                self.forgetSaved();
                try out.writeAll("Configuration edit recorded for preview only; nothing written. Enter preview, discard, save-config <new-absolute-path>, or review.\n");
            },
            .preview_config, .save_config => {
                if (!self.pending()) return out.writeAll("No pending configuration edits.\n");
                var candidate = self.plan.?.candidate(self.allocator) catch |err| return out.print("Configuration preview refused: {s}. Nothing written.\n", .{@errorName(err)});
                defer candidate.deinit();
                const text = try maintenance_config.renderPreview(self.allocator, &candidate);
                defer self.allocator.free(text);
                try out.writeAll(text);
                if (action == .preview_config) return;
                const path = workflow.maintenanceSavePath(line) orelse return out.writeAll("Use save-config <new-absolute-path>.\n");
                // Own the record before the file exists: a save is never left unrecorded.
                const owned = try self.allocator.dupe(u8, path);
                env.save(path, candidate.bytes) catch |err| {
                    self.allocator.free(owned);
                    return out.print("Candidate save refused: {s}; no file replaced.\n", .{@errorName(err)});
                };
                self.forgetSaved();
                self.saved = .{ .path = owned, .sha256 = candidate.sha256 };
                try out.print("Candidate saved as a new private file: {s}. The live configuration is unchanged. Review checks it with the target executable (--check-config <candidate> --against <live>).\n", .{path});
            },
            .discard_config => {
                if (self.plan) |*plan| plan.discard();
                const kept = self.saved != null;
                self.forgetSaved();
                try out.writeAll(if (kept) "Pending configuration edits discarded; the saved candidate file is left untouched and no longer tracked.\n" else "Pending configuration edits discarded; nothing written.\n");
            },
            else => unreachable,
        }
    }
};

fn configMessage(init: std.process.Init, width: usize, edits: *ConfigEdits, action: workflow.MaintenanceWizard.Action, line: []const u8, env: anytype) !void {
    var text: std.Io.Writer.Allocating = .init(init.gpa);
    defer text.deinit();
    edits.handle(action, line, env, &text.writer) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => |e| return e,
    };
    try message(init, width, text.written());
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
    // Live configuration may hold inline secrets: wipe every plan allocation.
    var wipe: backend.WipingAllocator = .{ .parent = init.gpa };
    var edits: ConfigEdits = .{ .allocator = wipe.allocator() };
    defer edits.deinit();
    const env = struct {
        io: std.Io,
        config: []const u8,
        fn loadLive(self: @This(), allocator: std.mem.Allocator) ![]u8 {
            return backend.readLiveConfig(allocator, self.config);
        }
        fn save(self: @This(), path: []const u8, bytes: []const u8) !void {
            return backend.saveCandidate(self.io, path, bytes);
        }
    }{ .io = init.io, .config = selection.config };
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
                if (!edits.bindingMatches(current_review.?.binding.config_sha256)) {
                    try message(init, width, "Live configuration changed after the first configuration edit; pending edits discarded and nothing written.\n");
                } else if (edits.pending()) {
                    try configMessage(init, width, &edits, .preview_config, "preview", env);
                    if (edits.unsaved()) {
                        try message(init, width, "Pending configuration edits are NOT applied by this executable action and are not saved. Enter back, then save-config <new-absolute-path> or discard (a new review needs a fresh set restore-into) before apply.\n");
                    } else {
                        var text: std.Io.Writer.Allocating = .init(init.gpa);
                        defer text.deinit();
                        edits.reviewCandidate(&session.?, &text.writer) catch |err| switch (err) {
                            error.WriteFailed => return error.OutOfMemory,
                            else => |e| return e,
                        };
                        try message(init, width, text.written());
                    }
                }
                state.enterReview(std.fmt.bytesToHex(nonce, .lower));
                try message(init, width, "Review the compatibility, backup coverage, client impact and recovery boundary. Enter apply followed by the exact Review id, back, or cancel.\n");
            },
            .apply => {
                const reviewed = current_review orelse return error.MissingReview;
                if (edits.unsaved()) {
                    try message(init, width, "Apply refused: unsaved pending configuration edits would be lost and would not take effect. Enter back, then save-config <new-absolute-path> or discard.\n");
                    continue;
                }
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
            .edit_config, .preview_config, .discard_config, .save_config => |action| try configMessage(init, width, &edits, action, line, env),
            .invalid => try message(init, width, "Use review, back, cancel, set <key> <value>, preview, discard, save-config <new-path>, or apply followed by the exact current Review id.\n"),
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

test "maintenance config controller binds edits to live bytes previews saves and discards on drift" {
    const a = std.testing.allocator;
    const Env = struct {
        live: []const u8,
        loads: usize = 0,
        saved: ?[]u8 = null,
        fail_load: bool = false,
        fn loadLive(self: *@This(), allocator: std.mem.Allocator) ![]u8 {
            self.loads += 1;
            if (self.fail_load) return error.InsecureFile;
            return allocator.dupe(u8, self.live);
        }
        fn save(self: *@This(), _: []const u8, bytes: []const u8) !void {
            if (self.saved != null) return error.PathAlreadyExists;
            self.saved = try std.testing.allocator.dupe(u8, bytes);
        }
    };
    const live = "[listen]\nirc = 6680\n";
    var env: Env = .{ .live = live };
    defer if (env.saved) |bytes| a.free(bytes);
    var edits: ConfigEdits = .{ .allocator = a };
    defer edits.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();

    env.fail_load = true;
    try edits.handle(.edit_config, "set irc-port 7000", &env, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "unavailable: InsecureFile") != null);
    try std.testing.expect(edits.plan == null);
    env.fail_load = false;
    try edits.handle(.edit_config, "set node-id 9", &env, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "refused: ImmutableInMaintenance") != null);
    try std.testing.expect(!edits.pending());
    try edits.handle(.edit_config, "set irc-port 7000", &env, &out.writer);
    try std.testing.expect(edits.pending());
    try std.testing.expectEqual(@as(usize, 2), env.loads);
    out.clearRetainingCapacity();
    try edits.handle(.preview_config, "preview", &env, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "- listen.irc: 6680 -> 7000; restart_required") != null);
    try std.testing.expect(edits.unsaved());
    try edits.handle(.save_config, "save-config /private/candidate.toml", &env, &out.writer);
    try std.testing.expectEqualStrings("[listen]\nirc = 7000\n", env.saved.?);
    try std.testing.expect(edits.pending() and !edits.unsaved());
    try std.testing.expectEqualStrings("/private/candidate.toml", edits.saved.?.path);
    try std.testing.expectEqualSlices(u8, &maintenance_config.digest(env.saved.?), &edits.saved.?.sha256);
    out.clearRetainingCapacity();
    // A refused second save keeps the first record; nothing is replaced.
    try edits.handle(.save_config, "save-config /private/other.toml", &env, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "save refused: PathAlreadyExists") != null);
    try std.testing.expectEqualStrings("/private/candidate.toml", edits.saved.?.path);

    // Review-time target check reports every outcome and binds the saved digest.
    const Checker = struct {
        result: anyerror!types.Check,
        seen_path: []const u8 = "",
        seen_sha: maintenance_config.Digest = @splat(0),
        fn checkCandidate(self: *@This(), path: []const u8, sha256: maintenance_config.Digest) !types.Check {
            self.seen_path = path;
            self.seen_sha = sha256;
            const r = self.result catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.CandidateChanged,
            };
            return r;
        }
    };
    for ([_]struct { result: anyerror!types.Check, want: []const u8 }{
        .{ .result = .passed, .want = "against the live file: passed.\nThe target accepts it" },
        .{ .result = .refused, .want = "against the live file: refused.\nThe target refuses it" },
        .{ .result = .unavailable, .want = "against the live file: unavailable.\nNot checked" },
        .{ .result = error.CandidateChanged, .want = "Saved candidate check refused: CandidateChanged. Treat the candidate as unverified" },
    }) |case| {
        var checker: Checker = .{ .result = case.result };
        out.clearRetainingCapacity();
        try edits.reviewCandidate(&checker, &out.writer);
        try std.testing.expect(std.mem.indexOf(u8, out.written(), case.want) != null);
        try std.testing.expectEqualStrings("/private/candidate.toml", checker.seen_path);
        try std.testing.expectEqualSlices(u8, &edits.saved.?.sha256, &checker.seen_sha);
    }
    var oom: Checker = .{ .result = error.OutOfMemory };
    try std.testing.expectError(error.OutOfMemory, edits.reviewCandidate(&oom, &out.writer));

    // A refused edit keeps the saved record; an accepted edit invalidates it.
    try edits.handle(.edit_config, "set tls-port 7000", &env, &out.writer);
    try std.testing.expect(edits.saved != null);
    try edits.handle(.edit_config, "set media-port 5000", &env, &out.writer);
    try std.testing.expect(edits.saved == null and edits.unsaved());
    var unused: Checker = .{ .result = .passed };
    out.clearRetainingCapacity();
    try edits.reviewCandidate(&unused, &out.writer);
    try std.testing.expectEqualStrings("", out.written());

    // Review binding equal to the first-read bytes keeps the plan; drift drops it.
    try std.testing.expect(edits.bindingMatches(maintenance_config.digest(live)));
    try std.testing.expect(edits.pending());
    try std.testing.expect(!edits.bindingMatches(maintenance_config.digest("[listen]\nirc = 6681\n")));
    try std.testing.expect(edits.plan == null and !edits.pending() and edits.saved == null);
    try edits.handle(.edit_config, "set irc-port 7001", &env, &out.writer);
    a.free(env.saved.?);
    env.saved = null;
    try edits.handle(.save_config, "save-config /private/c2.toml", &env, &out.writer);
    try std.testing.expect(edits.saved != null);
    out.clearRetainingCapacity();
    try edits.handle(.discard_config, "discard", &env, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "saved candidate file is left untouched") != null);
    try std.testing.expect(!edits.pending() and edits.saved == null);
    out.clearRetainingCapacity();
    try edits.handle(.preview_config, "preview", &env, &out.writer);
    try std.testing.expectEqualStrings("No pending configuration edits.\n", out.written());
}

test {
    _ = types;
    _ = @import("setup_maintenance_config.zig");
    _ = workflow;
    _ = review_ui;
    if (builtin.os.tag == .linux) _ = @import("setup_maintenance_linux.zig");
}
