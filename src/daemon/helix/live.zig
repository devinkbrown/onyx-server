// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process Helix live-upgrade orchestration.
//!
//! This module joins the deterministic supervisor model with the Linux handoff
//! transport. It deliberately keeps process replacement outside `prepare` and
//! `handOff` so the worker/supervisor flow remains unit-testable.

const std = @import("std");
const builtin = @import("builtin");

const capsule = @import("capsule.zig");
const handoff = @import("handoff.zig");
const handoff_manifest = @import("handoff_manifest.zig");
const supervisor = @import("supervisor.zig");

const linux = std.os.linux;

/// Hard ceiling on the inherited state-arena size read by `readArena`, before the
/// capsule stream is even validated. The arena is produced by the prior binary
/// (the trust boundary), so a corrupt/buggy predecessor image — or a non-memfd fd
/// that never EOFs — must not be able to OOM the successor by claiming an
/// unbounded size. The bound comfortably exceeds the sum of the mandatory
/// checkpoint caps (prop 512 MiB + history 136 MiB + world/search 64 MiB each +
/// event 8 MiB) plus a very large per-client capsule population, so it never
/// rejects a legitimate handoff for Onyx Server's scale while still fail-closing an
/// absurd one.
pub const max_arena_bytes: usize = 2 * 1024 * 1024 * 1024;

/// One unit of state to carry across the upgrade, already serialized by the caller.
pub const StatePiece = struct {
    kind: capsule.CapsuleKind,
    bytes: []const u8,
    /// Raise the minimum decoder version for a representation that cannot be
    /// losslessly interpreted by an older binary. Most capsule families keep
    /// the registry default; exact state checkpoints use this to make rollback
    /// fail closed instead of being accepted and silently mis-decoded.
    min_supported: ?u16 = null,
};

/// Owned predecessor view containing the original state pieces followed by one
/// canonical whole-handoff manifest. The manifest bytes remain valid until
/// `deinit`; callers pass `pieces` directly to `prepare`.
pub const ManifestedPieces = struct {
    pieces: []StatePiece,
    manifest_bytes: []u8,

    pub fn deinit(self: *ManifestedPieces, allocator: std.mem.Allocator) void {
        allocator.free(self.pieces);
        allocator.free(self.manifest_bytes);
        self.* = .{ .pieces = &.{}, .manifest_bytes = &.{} };
    }
};

/// Commit to the exact ordered predecessor state and append one manifest as the
/// final piece. Existing manifest pieces are rejected so a caller cannot create
/// an ambiguous nested or duplicate commitment.
pub fn appendHandoffManifest(
    allocator: std.mem.Allocator,
    pieces: []const StatePiece,
) (std.mem.Allocator.Error || handoff_manifest.Error)!ManifestedPieces {
    var accumulator = handoff_manifest.Accumulator.init();
    for (pieces) |piece| {
        if (piece.kind == .handoff_manifest) return error.DuplicateManifest;
        const descriptor = capsule.descriptor(piece.kind);
        try accumulator.add(.{
            .header = .{
                .schema_id = descriptor.schema_id,
                .kind = @intFromEnum(piece.kind),
                .version = descriptor.current_version,
                .min_supported = piece.min_supported orelse descriptor.min_supported,
                .max_supported = descriptor.max_supported,
            },
            .bytes = piece.bytes,
        });
    }

    const manifest_bytes = try allocator.alloc(u8, handoff_manifest.encoded_len);
    errdefer allocator.free(manifest_bytes);
    _ = try accumulator.encode(manifest_bytes);

    const complete = try allocator.alloc(StatePiece, pieces.len + 1);
    errdefer allocator.free(complete);
    @memcpy(complete[0..pieces.len], pieces);
    complete[pieces.len] = .{ .kind = .handoff_manifest, .bytes = manifest_bytes };
    return .{ .pieces = complete, .manifest_bytes = manifest_bytes };
}

/// Allocation-free successor verification over already-decoded capsules. The
/// manifest must occur exactly once, as the canonical final v1 capsule, and all
/// preceding capsules must use the one-field StatePiece representation.
pub fn verifyHandoffManifest(capsules: []const capsule.Capsule) handoff_manifest.Error!void {
    if (capsules.len == 0) return error.MissingManifest;
    const last = capsules[capsules.len - 1];
    if (last.header.kind != .handoff_manifest) {
        for (capsules) |item| {
            if (item.header.kind == .handoff_manifest) return error.ManifestNotLast;
        }
        return error.MissingManifest;
    }
    for (capsules[0 .. capsules.len - 1]) |item| {
        if (item.header.kind == .handoff_manifest) return error.DuplicateManifest;
    }

    const expected_header = capsule.Header.init(.handoff_manifest);
    if (last.header.schema_id != expected_header.schema_id or
        last.header.version != expected_header.version or
        last.header.min_supported != expected_header.min_supported or
        last.header.max_supported != expected_header.max_supported)
    {
        return error.WrongManifestHeader;
    }
    if (last.fields.len != 1 or last.fields[0].ordinal != handoff_manifest.field_ordinal) {
        return error.NonCanonicalManifest;
    }

    var accumulator = handoff_manifest.Accumulator.init();
    for (capsules[0 .. capsules.len - 1]) |item| {
        if (item.fields.len != 1 or item.fields[0].ordinal != handoff_manifest.field_ordinal) {
            return error.NonCanonicalPiece;
        }
        try accumulator.add(.{
            .header = .{
                .schema_id = item.header.schema_id,
                .kind = @intFromEnum(item.header.kind),
                .version = item.header.version,
                .min_supported = item.header.min_supported,
                .max_supported = item.header.max_supported,
            },
            .ordinal = item.fields[0].ordinal,
            .bytes = item.fields[0].bytes,
        });
    }
    try handoff_manifest.verify(last.fields[0].bytes, accumulator);
}

pub const PrepareInputs = struct {
    epoch: u64,
    now_ms: i64,
    timeout_ms: i64,
    arena_name: []const u8,
    pieces: []const StatePiece,
    fds: []const handoff.Fd,
};

pub const Prepared = struct {
    runtime: supervisor.Runtime,
    model: supervisor.Model,
    capsule_count: u32,
    fd_count: u32,

    pub fn deinit(self: *Prepared) void {
        self.runtime.deinit();
        self.* = .{
            .runtime = .{},
            .model = .{},
            .capsule_count = 0,
            .fd_count = 0,
        };
    }
};

/// Worker side of UPGRADE: create and seal the arena, serialize capsules,
/// initialize the control socket, and advance the model to the pass-fds action.
pub fn prepare(allocator: std.mem.Allocator, inputs: PrepareInputs) anyerror!Prepared {
    if (builtin.os.tag != .linux) return error.Unsupported;
    // One slot is reserved for the mandatory canonical final manifest. Build it
    // here, at the only live arena-serialization boundary, so no producer can
    // accidentally emit an uncommitted current-generation arena.
    if (inputs.pieces.len >= std.math.maxInt(u32)) return error.TooManyCapsules;
    if (inputs.fds.len > std.math.maxInt(u32)) return error.TooManyFds;
    var manifested = try appendHandoffManifest(allocator, inputs.pieces);
    defer manifested.deinit(allocator);

    var runtime: supervisor.Runtime = .{};
    errdefer runtime.deinit();

    try runtime.createArena(inputs.arena_name);
    if (runtime.arena) |*arena| {
        for (manifested.pieces) |piece| {
            var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
            var cap = capsule.make(piece.kind, fields[0..]);
            if (piece.min_supported) |minimum| cap.header.min_supported = minimum;
            const encoded = try capsule.encode(allocator, cap);
            defer allocator.free(encoded);
            try arena.writeAll(encoded);
        }
        try arena.seal();
    } else {
        return error.MissingArena;
    }

    try runtime.initControl();

    var model = supervisor.Model.begin(inputs.epoch, inputs.now_ms, inputs.timeout_ms);
    var step = try supervisor.transition(model, .{ .request_upgrade = inputs.epoch });
    model = step.model;
    step = try supervisor.transition(model, .accept_frozen);
    model = step.model;
    step = try supervisor.transition(model, .drain_complete);
    model = step.model;
    step = try supervisor.transition(model, .{ .capsules_serialized = @intCast(manifested.pieces.len) });
    model = step.model;

    return .{
        .runtime = runtime,
        .model = model,
        .capsule_count = @intCast(manifested.pieces.len),
        .fd_count = @intCast(inputs.fds.len),
    };
}

/// Hand the fds plus sealed arena to the successor over the control socket and
/// advance the supervisor model to `awaiting_attestation`.
pub fn handOff(prepared: *Prepared, fds: []const handoff.Fd, arena_fd: handoff.Fd) anyerror!usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len > std.math.maxInt(u32)) return error.TooManyFds;

    var sent_batches: usize = 0;
    if (fds.len + 1 <= handoff.max_fds_per_message) {
        var batch: [handoff.max_fds_per_message]handoff.Fd = undefined;
        batch[0] = arena_fd;
        @memcpy(batch[1 .. fds.len + 1], fds);
        sent_batches = try prepared.runtime.passFds(batch[0 .. fds.len + 1], "helix-live");
    } else {
        var first: [handoff.max_fds_per_message]handoff.Fd = undefined;
        first[0] = arena_fd;
        const first_fd_count = handoff.max_fds_per_message - 1;
        @memcpy(first[1..], fds[0..first_fd_count]);
        sent_batches += try prepared.runtime.passFds(first[0..], "helix-live");
        sent_batches += try prepared.runtime.passFds(fds[first_fd_count..], "helix-live");
    }

    const step = try supervisor.transition(prepared.model, .{ .fds_handed_off = @intCast(fds.len) });
    prepared.model = step.model;
    prepared.fd_count = @intCast(fds.len);
    return sent_batches;
}

/// Environment-variable names used to pass inherited fds across execve to the successor.
pub const env_arena_fd = "ONYX_HELIX_ARENA_FD";
pub const env_control_fd = "ONYX_HELIX_CONTROL_FD";
/// The inherited listening-socket fd, preserved across execve so the successor
/// keeps the port bound (no connection-refused window during an UPGRADE).
pub const env_listen_fd = "ONYX_HELIX_LISTEN_FD";
/// Multi-shard listener handoff: comma-separated per-shard client-listener fds
/// in shard order (`fd0,fd1,...`), preserved across execve so EVERY shard's
/// SO_REUSEPORT listener survives the swap (no accept-queue drop on shards
/// 1..N-1). `env_listen_fd` still carries shard 0's fd as the canonical
/// singular alias. Emitted only when more than one shard listener exists. The
/// pinned target capability handshake runs before any CLOEXEC mutation, so a
/// binary that predates this ownership contract is refused while the
/// predecessor keeps every listener and connection live; it can never inherit
/// and strand unrecognized SO_REUSEPORT listeners.
pub const env_listen_fds = "ONYX_HELIX_LISTEN_FDS";
/// Hard cap on inherited per-shard listener fds. Producer and parser share the
/// fixed `Resume` bound; an upgrade with more listeners is refused rather than
/// truncating the list and leaking unowned sockets in the successor.
pub const max_inherited_listeners = 64;
/// Authoritative list of every client and S2S socket fd carried inside the
/// state arena. Unlike the capsule stream this manifest is version-independent:
/// a successor can close the sockets even when the arena is corrupt or uses a
/// future schema that it cannot decode.
pub const env_state_fds = "ONYX_HELIX_STATE_FDS";
/// Hard cap for the authoritative state-fd manifest. Both producer and parser
/// reject lists above this bound; the list is never silently truncated because
/// losing even one fd would strand that connection across a refused upgrade.
pub const max_inherited_state_fds = 4096;

/// Exact machine-readable answer returned by the daemon's private upgrade
/// capability probe. A predecessor requires this complete line before it makes
/// any client, mesh, listener, or arena descriptor inheritable. Keep this token
/// in lockstep with the mandatory outer capsule and fd-ownership contracts.
/// `clients-v5` promises exact client-tail validation through the canonical
/// `was_websocket` discriminator; a target lacking it must never receive fds.
pub const upgrade_capability_arg = "--helix-upgrade-capabilities-v1";
const upgrade_capability_caps =
    "attachment-delivery-spool-v1,clients-v5,e2ee-group-authority-v2,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,mesh-clock-v3,property-state-v2,relay-v2-event-log-v1,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2";
pub const upgrade_capability_token =
    "ONYX_HELIX_UPGRADE_CAPS=" ++ upgrade_capability_caps;

/// Require the capability token as a complete output line. Substring matching
/// would let a diagnostic such as "missing TOKEN" accidentally authorize a
/// handoff to an incompatible image. English ONYX_ brand only — no Japanese
/// product aliases.
pub fn hasUpgradeCapabilityLine(output: []const u8) bool {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.eql(u8, line, upgrade_capability_token)) return true;
    }
    return false;
}

/// Execute an already-open target image in private capability mode. The child
/// resolves its inherited CLOEXEC descriptor through `/proc/self/fd` as part of
/// exec; the descriptor closes only after that resolution succeeds. This keeps
/// the probe pinned to the retained inode without depending on parent-pid procfs
/// visibility.
pub fn probeUpgradeExecutableFd(
    allocator: std.mem.Allocator,
    io: std.Io,
    executable_fd: handoff.Fd,
) !bool {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (executable_fd < 0) return error.InvalidExecutableFd;
    var proc_path_buf: [64]u8 = undefined;
    const proc_path = try std.fmt.bufPrint(&proc_path_buf, "/proc/self/fd/{d}", .{executable_fd});
    // Use one absolute deadline for the complete probe. A relative duration is
    // restarted by each stdout/stderr fill, allowing a child that drips output
    // to stretch a nominal two-second compatibility check far beyond its bound.
    const deadline = (std.Io.Timeout{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } }).toDeadline(io);
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ proc_path, upgrade_capability_arg },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = deadline,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return result.term.success() and
        (hasUpgradeCapabilityLine(result.stdout) or hasUpgradeCapabilityLine(result.stderr));
}

pub const ExecPlan = struct {
    argv: []const [:0]const u8,
    envp: []const [:0]const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,

    pub fn deinit(self: *ExecPlan, allocator: std.mem.Allocator) void {
        for (self.argv) |arg| allocator.free(arg);
        for (self.envp) |entry| allocator.free(entry);
        allocator.free(self.argv);
        allocator.free(self.envp);
        self.* = .{ .argv = &.{}, .envp = &.{}, .arena_fd = -1, .control_fd = -1 };
    }

    pub fn commit(self: ExecPlan, allocator: std.mem.Allocator) anyerror!noreturn {
        if (builtin.os.tag != .linux) return error.Unsupported;

        // execve wants null-sentinel-terminated arrays of [*:0] pointers.
        const argv_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.argv.len, null);
        defer allocator.free(argv_ptrs);
        for (self.argv, 0..) |arg, i| argv_ptrs[i] = arg.ptr;

        const envp_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.envp.len, null);
        defer allocator.free(envp_ptrs);
        for (self.envp, 0..) |entry, i| envp_ptrs[i] = entry.ptr;

        const rc = linux.execve(self.argv[0].ptr, argv_ptrs.ptr, envp_ptrs.ptr);
        switch (linux.errno(rc)) {
            .SUCCESS => unreachable,
            else => return error.ExecFailed,
        }
    }

    /// Execute an already-open, probed binary rather than resolving argv[0]
    /// again. `execveat(AT_EMPTY_PATH)` closes the probe/exec TOCTOU window: the
    /// image that answered the capability handshake is exactly the image that
    /// receives the inherited descriptors. The caller retains fd ownership if
    /// exec fails; successful exec closes a CLOEXEC target fd in the new image.
    pub fn commitExecutableFd(
        self: ExecPlan,
        allocator: std.mem.Allocator,
        executable_fd: handoff.Fd,
    ) anyerror!noreturn {
        if (builtin.os.tag != .linux) return error.Unsupported;
        if (executable_fd < 0) return error.InvalidExecutableFd;

        const argv_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.argv.len, null);
        defer allocator.free(argv_ptrs);
        for (self.argv, 0..) |arg, i| argv_ptrs[i] = arg.ptr;

        const envp_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.envp.len, null);
        defer allocator.free(envp_ptrs);
        for (self.envp, 0..) |entry, i| envp_ptrs[i] = entry.ptr;

        const rc = linux.execveat(
            executable_fd,
            "",
            argv_ptrs.ptr,
            envp_ptrs.ptr,
            .{ .SYMLINK_NOFOLLOW = false, .EMPTY_PATH = true },
        );
        switch (linux.errno(rc)) {
            .SUCCESS => unreachable,
            else => return error.ExecFailed,
        }
    }
};

/// Build the argv/env vector an execve handoff would use. The caller owns the
/// returned vectors and entries; use `ExecPlan.deinit` to release them.
pub fn buildExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeSentinel(u8, binary_path, 0);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeSentinel(u8, "--supervisor", 0);
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_control_fd, control_fd);
    errdefer allocator.free(envp[1]);

    return .{
        .argv = argv,
        .envp = envp,
        .arena_fd = arena_fd,
        .control_fd = control_fd,
    };
}

/// Build an exec plan that ALSO preserves the listening-socket fd across the
/// handoff, so the successor can adopt it and keep the port bound. The caller
/// must clear `FD_CLOEXEC` on `listen_fd` before `commit` so it survives execve.
pub fn buildExecPlanWithListener(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,
    listen_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeSentinel(u8, binary_path, 0);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeSentinel(u8, "--supervisor", 0);
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 3);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_control_fd, control_fd);
    errdefer allocator.free(envp[1]);
    envp[2] = try fdEnvEntry(allocator, env_listen_fd, listen_fd);
    errdefer allocator.free(envp[2]);

    return .{ .argv = argv, .envp = envp, .arena_fd = arena_fd, .control_fd = control_fd };
}

/// Build a minimal listener-only exec plan: re-exec the binary preserving just
/// the listening socket fd (state capsules are not carried). The caller must
/// clear `FD_CLOEXEC` on `listen_fd` before `commit` so it survives execve.
pub fn buildListenerExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    listen_fd: handoff.Fd,
    config_path: ?[]const u8,
) anyerror!ExecPlan {
    const argc: usize = if (config_path != null) 3 else 2;
    var argv = try allocator.alloc([:0]const u8, argc);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeSentinel(u8, binary_path, 0);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeSentinel(u8, "--supervisor", 0);
    errdefer allocator.free(argv[1]);
    if (config_path) |cp| {
        argv[2] = try allocator.dupeSentinel(u8, cp, 0);
    }
    // Registered at function scope (not inside the `if` block), so later env
    // allocation failures still release the optional config-path argument.
    errdefer if (config_path != null) allocator.free(argv[2]);

    var envp = try allocator.alloc([:0]const u8, 1);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_listen_fd, listen_fd);
    errdefer allocator.free(envp[0]);

    return .{ .argv = argv, .envp = envp, .arena_fd = -1, .control_fd = -1 };
}

/// Build an exec plan carrying the sealed state arena AND the listening
/// socket(s) (no control socket). `listen_fds` is the per-shard client-listener
/// fd list in shard order; `listen_fds[0]` (shard 0) rides the singular
/// `env_listen_fd` for older successors, and the full list additionally rides
/// `env_listen_fds` when more than one shard listener is carried. The successor
/// reads the arena's capsules and adopts the listeners. `state_fds` is the exact
/// set of client/S2S descriptors referenced by that arena and rides a separate,
/// version-independent manifest. The caller must clear `FD_CLOEXEC` on the
/// arena, listener, and state fds before `commit`.
pub fn buildArenaListenerExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    listen_fds: []const handoff.Fd,
    state_fds: []const handoff.Fd,
    config_path: ?[]const u8,
) anyerror!ExecPlan {
    if (listen_fds.len == 0) return error.NoListener;
    if (listen_fds.len > max_inherited_listeners) return error.TooManyListeners;
    if (state_fds.len > max_inherited_state_fds) return error.TooManyStateFds;
    if (arena_fd < 0) return error.InvalidArenaFd;
    for (listen_fds, 0..) |listen_fd, i| {
        if (listen_fd < 0) return error.InvalidListenerFd;
        if (listen_fd == arena_fd) return error.ArenaFdCollidesWithListener;
        for (listen_fds[0..i]) |prior| if (prior == listen_fd) return error.DuplicateListenerFd;
    }
    for (state_fds, 0..) |fd, i| {
        if (fd < 0) return error.InvalidStateFd;
        if (fd == arena_fd) return error.StateFdCollidesWithArena;
        for (listen_fds) |listen_fd| if (fd == listen_fd) return error.StateFdCollidesWithListener;
        for (state_fds[0..i]) |prior| if (prior == fd) return error.DuplicateStateFd;
    }
    // argv = [binary, --supervisor, (config_path)?]. The config path is passed
    // through so the successor boots with the SAME config (ports, certs, opers,
    // cloak) rather than the built-in defaults.
    const argc: usize = if (config_path != null) 3 else 2;
    var argv = try allocator.alloc([:0]const u8, argc);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeSentinel(u8, binary_path, 0);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeSentinel(u8, "--supervisor", 0);
    errdefer allocator.free(argv[1]);
    if (config_path) |cp| {
        argv[2] = try allocator.dupeSentinel(u8, cp, 0);
    }
    // Registered in the function body rather than the conditional block, so
    // any later environment allocation failure still releases this argument.
    errdefer if (config_path != null) allocator.free(argv[2]);

    const envc: usize = 2 +
        @as(usize, @intFromBool(listen_fds.len > 1)) +
        @as(usize, @intFromBool(state_fds.len != 0));
    var envp = try allocator.alloc([:0]const u8, envc);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_listen_fd, listen_fds[0]);
    errdefer allocator.free(envp[1]);
    var env_i: usize = 2;
    if (listen_fds.len > 1) {
        const listen_env_i = env_i;
        envp[listen_env_i] = try fdListEnvEntry(allocator, env_listen_fds, listen_fds);
        env_i += 1;
    }
    // Like argv[2], this cleanup must outlive the conditional block because the
    // following state-manifest allocation can fail.
    errdefer if (listen_fds.len > 1) allocator.free(envp[2]);
    if (state_fds.len != 0) {
        const state_env_i = env_i;
        envp[state_env_i] = try fdListEnvEntry(allocator, env_state_fds, state_fds);
    }

    return .{ .argv = argv, .envp = envp, .arena_fd = arena_fd, .control_fd = -1 };
}

/// Supervisor/resume side: read inherited fds from the environment, or return
/// null for a normal boot. Each fd is optional — a listener-only handoff carries
/// just `listen_fd`, while a full state handoff also carries arena + control.
pub const Resume = struct {
    arena_fd: ?handoff.Fd = null,
    control_fd: ?handoff.Fd = null,
    /// The inherited listening socket, or null if the predecessor did not pass
    /// one (older handoff / listener not preserved).
    listen_fd: ?handoff.Fd = null,
    /// Multi-shard listener handoff: the per-shard client-listener fds in shard
    /// order (`listen_fds[0..listen_fd_count]`). Empty when the predecessor was
    /// single-shard (or predates the list variable); `listen_fd` then carries
    /// shard 0 alone.
    listen_fds: [max_inherited_listeners]handoff.Fd = @splat(-1),
    listen_fd_count: usize = 0,
    /// Authoritative carried client/S2S fds. Empty means a legacy predecessor
    /// omitted the manifest and the successor must fall back to capsule peeks.
    state_fds: [max_inherited_state_fds]handoff.Fd = @splat(-1),
    state_fd_count: usize = 0,
    state_fd_manifest_present: bool = false,
    state_fd_manifest_valid: bool = false,

    pub fn listenFds(self: *const Resume) []const handoff.Fd {
        return self.listen_fds[0..self.listen_fd_count];
    }

    pub fn stateFds(self: *const Resume) []const handoff.Fd {
        return self.state_fds[0..self.state_fd_count];
    }
};

pub fn resumeFromEnv() ?Resume {
    if (builtin.os.tag != .linux) return null;

    var buf: [64 * 1024]u8 = undefined;
    const fd = linux.open("/proc/self/environ", .{ .CLOEXEC = true }, 0);
    switch (linux.errno(fd)) {
        .SUCCESS => {},
        else => return null,
    }
    defer _ = linux.close(@intCast(fd));

    const read_len = linux.read(@intCast(fd), &buf, buf.len);
    switch (linux.errno(read_len)) {
        .SUCCESS => {},
        else => return null,
    }
    const env = buf[0..@as(usize, @intCast(read_len))];
    return resumeFromEnvBlock(env);
}

fn resumeFromEnvBlock(env: []const u8) ?Resume {
    // ONYX_ Helix env names only (Onyx brand only).
    const arena_fd = readFdFromEnvBlock(env, env_arena_fd);
    const control_fd = readFdFromEnvBlock(env, env_control_fd);
    const listen_fd = readFdFromEnvBlock(env, env_listen_fd);
    const state_fd_value = findEnvValue(env, env_state_fds);
    if (arena_fd == null and control_fd == null and listen_fd == null and state_fd_value == null) return null;
    var r: Resume = .{ .arena_fd = arena_fd, .control_fd = control_fd, .listen_fd = listen_fd };
    if (findEnvValue(env, env_listen_fds)) |list| {
        r.listen_fd_count = parseFdList(list, &r.listen_fds);
    }
    if (state_fd_value) |list| {
        r.state_fd_manifest_present = true;
        if (parseFdListExact(list, &r.state_fds)) |count| {
            r.state_fd_count = count;
            r.state_fd_manifest_valid = true;
        }
    }
    return r;
}

/// Successor side: read the sealed capsule arena (inherited memfd) and decode the
/// concatenated capsule stream. The caller owns the returned slice and must
/// `deinit` each capsule and free the slice. The fds for client re-attach are a
/// separate (later) step; this surfaces the serialized state pieces.
pub fn readArena(allocator: std.mem.Allocator, arena_fd: handoff.Fd) anyerror![]capsule.Capsule {
    if (builtin.os.tag != .linux) return error.Unsupported;

    // Read the whole sealed memfd via positional reads (no size syscall needed).
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    var tmp: [4096]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        const rc = linux.pread(arena_fd, &tmp, tmp.len, @intCast(off));
        switch (linux.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) break; // EOF
                // Fail closed before growing past the ceiling so a corrupt or
                // never-EOFing inherited fd cannot OOM the successor pre-validation.
                if (buf.items.len + n > max_arena_bytes) return error.ArenaTooLarge;
                try buf.appendSlice(allocator, tmp[0..n]);
                off += n;
            },
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
    return capsule.decodeStream(allocator, buf.items);
}

fn fdEnvEntry(allocator: std.mem.Allocator, name: []const u8, fd: handoff.Fd) ![:0]u8 {
    var buf: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{s}={d}", .{ name, fd });
    return try allocator.dupeSentinel(u8, text, 0);
}

fn readFdFromEnvBlock(env: []const u8, name: []const u8) ?handoff.Fd {
    const value = findEnvValue(env, name) orelse return null;
    return std.fmt.parseInt(handoff.Fd, value, 10) catch null;
}

/// Find `name=` in a NUL-separated environ block; return the raw value slice.
fn findEnvValue(env: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, env, 0);
    while (it.next()) |entry| {
        if (entry.len <= name.len or entry[name.len] != '=') continue;
        if (!std.mem.eql(u8, entry[0..name.len], name)) continue;
        return entry[name.len + 1 ..];
    }
    return null;
}

/// Parse a comma-separated fd list ("3,5,7") into `out`. Fail-closed on any
/// malformed or negative element: the whole list is rejected (returns 0) so the
/// successor falls back to the singular `env_listen_fd` + fresh binds rather
/// than adopting a half-parsed set. Entries past `out.len` are ignored (those
/// shards bind fresh SO_REUSEPORT listeners).
fn parseFdList(value: []const u8, out: []handoff.Fd) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |tok| {
        const fd = std.fmt.parseInt(handoff.Fd, tok, 10) catch return 0;
        if (fd < 0) return 0;
        if (n < out.len) {
            out[n] = fd;
            n += 1;
        }
    }
    return n;
}

/// Parse an authoritative fd list without truncation. Any malformed/negative
/// element, empty list, or element beyond `out` rejects the complete manifest.
fn parseFdListExact(value: []const u8, out: []handoff.Fd) ?usize {
    if (value.len == 0) return null;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |tok| {
        if (tok.len == 0 or n == out.len) return null;
        const fd = std.fmt.parseInt(handoff.Fd, tok, 10) catch return null;
        if (fd < 0) return null;
        for (out[0..n]) |prior| if (prior == fd) return null;
        out[n] = fd;
        n += 1;
    }
    return n;
}

fn fdListEnvEntry(allocator: std.mem.Allocator, name: []const u8, fds: []const handoff.Fd) ![:0]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try text.appendSlice(allocator, name);
    try text.append(allocator, '=');
    for (fds, 0..) |fd, i| {
        if (i != 0) try text.append(allocator, ',');
        var nbuf: [16]u8 = undefined;
        try text.appendSlice(allocator, std.fmt.bufPrint(&nbuf, "{d}", .{fd}) catch unreachable);
    }
    return try allocator.dupeSentinel(u8, text.items, 0);
}

test "live prepare seals capsules and handoff passes fds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var extra = try handoff.Arena.create("helix-live-extra");
    defer extra.close();

    const pieces = [_]StatePiece{
        .{ .kind = .clients, .bytes = "client-state" },
        .{ .kind = .channels, .bytes = "channel-state" },
    };
    const fds = [_]handoff.Fd{extra.fd};
    var prepared = try prepare(allocator, .{
        .epoch = 44,
        .now_ms = 1000,
        .timeout_ms = 5000,
        .arena_name = "helix-live-test",
        .pieces = pieces[0..],
        .fds = fds[0..],
    });
    defer prepared.deinit();

    try std.testing.expectEqual(@as(u32, 3), prepared.capsule_count);
    try std.testing.expectEqual(@as(u32, 1), prepared.fd_count);
    try std.testing.expect(prepared.runtime.arena.?.sealed);
    try std.testing.expect(prepared.runtime.arena.?.size > 0);
    try std.testing.expectEqual(supervisor.State.fds_handed_off, prepared.model.state);

    const recv_socket = prepared.runtime.control.?.worker;
    const arena_fd = prepared.runtime.arena.?.fd;
    try std.testing.expectEqual(@as(usize, 1), try handOff(&prepared, fds[0..], arena_fd));

    var recv = try handoff.recvFdBatch(allocator, recv_socket, 64);
    defer {
        for (recv.fds) |fd| _ = linux.close(fd);
        recv.deinit(allocator);
    }
    try std.testing.expect(std.mem.eql(u8, recv.bytes, "helix-live"));
    try std.testing.expectEqual(@as(usize, 2), recv.fds.len);
    try std.testing.expectEqual(supervisor.State.awaiting_attestation, prepared.model.state);
}

test "resumeFromEnv returns null when fd variables are absent" {
    try std.testing.expectEqual(@as(?Resume, null), resumeFromEnv());
}

test "readArena round-trips the sealed capsule stream" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    // Prepare seals two data capsules plus its mandatory final manifest.
    const pieces = [_]StatePiece{
        .{ .kind = .clients, .bytes = "client-state" },
        .{ .kind = .channels, .bytes = "channel-state" },
    };
    var prepared = try prepare(allocator, .{
        .epoch = 7,
        .now_ms = 1,
        .timeout_ms = 1000,
        .arena_name = "helix-readarena",
        .pieces = pieces[0..],
        .fds = &.{},
    });
    defer prepared.deinit();

    const caps = try readArena(allocator, prepared.runtime.arena.?.fd);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }
    try std.testing.expectEqual(@as(usize, 3), caps.len);
    try std.testing.expectEqual(capsule.CapsuleKind.clients, caps[0].header.kind);
    try std.testing.expect(std.mem.eql(u8, "client-state", caps[0].fields[0].bytes));
    try std.testing.expectEqual(capsule.CapsuleKind.channels, caps[1].header.kind);
    try std.testing.expect(std.mem.eql(u8, "channel-state", caps[1].fields[0].bytes));
    try std.testing.expectEqual(capsule.CapsuleKind.handoff_manifest, caps[2].header.kind);
    try verifyHandoffManifest(caps);
}

test "whole handoff manifest helper accepts canonical empty state" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var manifested = try appendHandoffManifest(allocator, &.{});
    defer manifested.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), manifested.pieces.len);
    try std.testing.expectEqual(capsule.CapsuleKind.handoff_manifest, manifested.pieces[0].kind);
    try std.testing.expectEqual(@as(usize, handoff_manifest.encoded_len), manifested.manifest_bytes.len);

    var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = manifested.manifest_bytes }};
    const caps = [_]capsule.Capsule{capsule.make(.handoff_manifest, fields[0..])};
    try verifyHandoffManifest(&caps);

    // The actual serialization boundary independently guarantees the same
    // canonical manifest even when the caller supplies no data pieces.
    var prepared = try prepare(allocator, .{
        .epoch = 8,
        .now_ms = 2,
        .timeout_ms = 1000,
        .arena_name = "helix-empty-whole-manifest",
        .pieces = &.{},
        .fds = &.{},
    });
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 1), prepared.capsule_count);
    const decoded = try readArena(allocator, prepared.runtime.arena.?.fd);
    defer {
        for (decoded) |*item| item.deinit(allocator);
        allocator.free(decoded);
    }
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try verifyHandoffManifest(decoded);
}

test "whole handoff manifest predecessor append is allocation-failure clean" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const pieces = [_]StatePiece{
                .{ .kind = .clients, .bytes = "alice" },
                .{ .kind = .channels, .bytes = "#mesh" },
                .{ .kind = .sessions, .bytes = "account" },
            };
            var manifested = try appendHandoffManifest(allocator, &pieces);
            defer manifested.deinit(allocator);
            if (manifested.pieces.len != pieces.len + 1) return error.BadPieceCount;
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "whole handoff manifest round-trips arena and rejects every completeness mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const source = [_]StatePiece{
        .{ .kind = .clients, .bytes = "alice" },
        .{ .kind = .channels, .bytes = "#mesh" },
        .{ .kind = .webhook_store, .bytes = "webhooks" },
    };
    var manifested = try appendHandoffManifest(allocator, &source);
    defer manifested.deinit(allocator);
    try std.testing.expectError(error.DuplicateManifest, appendHandoffManifest(allocator, manifested.pieces));
    try std.testing.expectError(error.DuplicateManifest, prepare(allocator, .{
        .epoch = 9,
        .now_ms = 3,
        .timeout_ms = 1000,
        .arena_name = "helix-double-whole-manifest",
        .pieces = manifested.pieces,
        .fds = &.{},
    }));

    var prepared = try prepare(allocator, .{
        .epoch = 9,
        .now_ms = 3,
        .timeout_ms = 1000,
        .arena_name = "helix-whole-manifest",
        .pieces = &source,
        .fds = &.{},
    });
    defer prepared.deinit();

    const caps = try readArena(allocator, prepared.runtime.arena.?.fd);
    defer {
        for (caps) |*item| item.deinit(allocator);
        allocator.free(caps);
    }
    try std.testing.expectEqual(@as(usize, 4), caps.len);
    try std.testing.expectEqual(capsule.CapsuleKind.handoff_manifest, caps[3].header.kind);
    try verifyHandoffManifest(caps);

    // Dropping or duplicating any ordinary piece changes both the total and its
    // exact per-kind count.
    const dropped = [_]capsule.Capsule{ caps[0], caps[2], caps[3] };
    try std.testing.expectError(error.CountMismatch, verifyHandoffManifest(&dropped));
    const duplicated = [_]capsule.Capsule{ caps[0], caps[1], caps[1], caps[2], caps[3] };
    try std.testing.expectError(error.CountMismatch, verifyHandoffManifest(&duplicated));

    // Ordering, payloads, and effective outer headers are digest-bound even
    // when their aggregate counts remain unchanged.
    const reordered = [_]capsule.Capsule{ caps[1], caps[0], caps[2], caps[3] };
    try std.testing.expectError(error.DigestMismatch, verifyHandoffManifest(&reordered));
    var flipped = try allocator.dupe(u8, caps[1].fields[0].bytes);
    defer allocator.free(flipped);
    flipped[0] ^= 1;
    var corrupt_payload = caps[1];
    var corrupt_payload_fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = flipped }};
    corrupt_payload.fields = &corrupt_payload_fields;
    const bitflipped = [_]capsule.Capsule{ caps[0], corrupt_payload, caps[2], caps[3] };
    try std.testing.expectError(error.DigestMismatch, verifyHandoffManifest(&bitflipped));
    var corrupt_header = caps[1];
    corrupt_header.header.schema_id ^= 1;
    const wrong_data_header = [_]capsule.Capsule{ caps[0], corrupt_header, caps[2], caps[3] };
    try std.testing.expectError(error.DigestMismatch, verifyHandoffManifest(&wrong_data_header));

    // Manifest position, uniqueness, exact outer header, and one-field shape
    // are structural requirements independent of the checksum.
    try std.testing.expectError(error.MissingManifest, verifyHandoffManifest(caps[0..3]));
    const duplicate_manifest = [_]capsule.Capsule{ caps[3], caps[1], caps[2], caps[3] };
    try std.testing.expectError(error.DuplicateManifest, verifyHandoffManifest(&duplicate_manifest));
    const manifest_not_last = [_]capsule.Capsule{ caps[0], caps[1], caps[3], caps[2] };
    try std.testing.expectError(error.ManifestNotLast, verifyHandoffManifest(&manifest_not_last));
    var wrong_manifest_header = caps[3];
    wrong_manifest_header.header.max_supported = 2;
    const wrong_outer = [_]capsule.Capsule{ caps[0], caps[1], caps[2], wrong_manifest_header };
    try std.testing.expectError(error.WrongManifestHeader, verifyHandoffManifest(&wrong_outer));
    var noncanonical_manifest = caps[3];
    var extra_manifest_fields = [_]capsule.Field{
        caps[3].fields[0],
        .{ .ordinal = 2, .bytes = "extra" },
    };
    noncanonical_manifest.fields = &extra_manifest_fields;
    const extra_manifest_field = [_]capsule.Capsule{ caps[0], caps[1], caps[2], noncanonical_manifest };
    try std.testing.expectError(error.NonCanonicalManifest, verifyHandoffManifest(&extra_manifest_field));
    var noncanonical_piece = caps[0];
    var extra_piece_fields = [_]capsule.Field{
        caps[0].fields[0],
        .{ .ordinal = 2, .bytes = "extra" },
    };
    noncanonical_piece.fields = &extra_piece_fields;
    const extra_piece_field = [_]capsule.Capsule{ noncanonical_piece, caps[1], caps[2], caps[3] };
    try std.testing.expectError(error.NonCanonicalPiece, verifyHandoffManifest(&extra_piece_field));
}

test "mesh state pieces advertise ordinary overlap and exact property requirement" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const pieces = [_]StatePiece{
        .{ .kind = .mesh_checkpoint, .bytes = "ordinary-mesh-state" },
        .{ .kind = .mesh_checkpoint, .bytes = "exact-property-state", .min_supported = 2 },
    };
    var prepared = try prepare(allocator, .{
        .epoch = 8,
        .now_ms = 2,
        .timeout_ms = 1000,
        .arena_name = "helix-mesh-v2-ranges",
        .pieces = pieces[0..],
        .fds = &.{},
    });
    defer prepared.deinit();

    const caps = try readArena(allocator, prepared.runtime.arena.?.fd);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }
    try std.testing.expectEqual(@as(usize, 3), caps.len);
    for (caps[0..2]) |cap| {
        try std.testing.expectEqual(capsule.CapsuleKind.mesh_checkpoint, cap.header.kind);
        try std.testing.expectEqual(@as(u16, 2), cap.header.version);
        try std.testing.expectEqual(@as(u16, 2), cap.header.max_supported);
        try std.testing.expectEqual(@as(usize, 1), cap.fields.len);
        try std.testing.expectEqual(@as(u32, 1), cap.fields[0].ordinal);
    }
    try std.testing.expectEqual(@as(u16, 1), caps[0].header.min_supported);
    try std.testing.expectEqualStrings("ordinary-mesh-state", caps[0].fields[0].bytes);
    try std.testing.expectEqual(@as(u16, 2), caps[1].header.min_supported);
    try std.testing.expectEqualStrings("exact-property-state", caps[1].fields[0].bytes);
    try std.testing.expectEqual(capsule.CapsuleKind.handoff_manifest, caps[2].header.kind);
    try verifyHandoffManifest(caps);

    var legacy = capsule.descriptor(.mesh_checkpoint);
    legacy.current_version = 1;
    legacy.min_supported = 1;
    legacy.max_supported = 1;
    try std.testing.expectEqual(@as(u16, 1), try capsule.negotiate(legacy, caps[0].header));
    try std.testing.expectError(
        error.VersionUnsupported,
        capsule.negotiate(legacy, caps[1].header),
    );
}

test "exec plan with listener carries the listen fd env entry" {
    const allocator = std.testing.allocator;
    var plan = try buildExecPlanWithListener(allocator, "/tmp/onyx", 10, 11, 12);
    defer plan.deinit(allocator);

    try std.testing.expectEqualStrings("/tmp/onyx", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqual(@as(usize, 3), plan.envp.len);
    try std.testing.expectEqualStrings("ONYX_HELIX_ARENA_FD=10", plan.envp[0]);
    try std.testing.expectEqualStrings("ONYX_HELIX_CONTROL_FD=11", plan.envp[1]);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FD=12", plan.envp[2]);
}

test "ExecPlan.commit execve's the target (fork + /bin/true)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    // Build a plan pointing at /bin/true so the child execs and exits 0.
    var plan = try buildListenerExecPlan(allocator, "/bin/true", 0, null);
    defer plan.deinit(allocator);

    const pid_rc = linux.fork();
    const pid: i32 = @intCast(@as(isize, @bitCast(pid_rc)));
    if (pid == 0) {
        // Child: commit replaces the image; if it returns, exec failed.
        plan.commit(allocator) catch {};
        linux.exit(127);
    }
    var status: i32 = 0;
    _ = linux.wait4(pid, &status, 0, null);
    // Exited cleanly via the execve'd /bin/true (low 7 bits 0, exit code 0),
    // not the 127 exec-failed fallback.
    try std.testing.expectEqual(@as(i32, 0), status & 0x7f); // WIFEXITED
    try std.testing.expectEqual(@as(i32, 0), (status >> 8) & 0xff); // exit code
}

test "upgrade capability token must occupy a complete output line" {
    try std.testing.expect(hasUpgradeCapabilityLine(upgrade_capability_token ++ "\n"));
    try std.testing.expect(hasUpgradeCapabilityLine("banner\r\n" ++ upgrade_capability_token ++ "\r\n"));
    try std.testing.expect(!hasUpgradeCapabilityLine("prefix " ++ upgrade_capability_token ++ "\n"));
    try std.testing.expect(!hasUpgradeCapabilityLine(upgrade_capability_token ++ " suffix\n"));
    try std.testing.expect(!hasUpgradeCapabilityLine("ONYX_HELIX_UPGRADE_CAPS=mesh-checkpoint-v1\n"));
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    // The immediately preceding token understood RVO2 but not the mandatory
    // RVL2/ADS1 authorities. It must be refused before any fd loses CLOEXEC;
    // otherwise the successor would exec successfully and only then reject the
    // newly mandatory mesh checkpoints, disconnecting every carried client.
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=attachment-delivery-spool-v1,clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,relay-v2-event-log-v1,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    // The immediately preceding current token has no strict MHLC v3 activation
    // authority. Accepting it could exec a successor that resets an active
    // MESSAGE_V2 author back to compatibility mode.
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=attachment-delivery-spool-v1,clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,property-state-v2,relay-v2-event-log-v1,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    // HEAD predecessor without e2ee-group-authority-v2 must refuse this target
    // before exec: EGRG no longer seals completed receipts, and admit freezes
    // event-time peer custody on first accept only.
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=attachment-delivery-spool-v1,clients-v5,handoff-manifest-v1,history-v1,mesh-checkpoint-v2,mesh-clock-v3,property-state-v2,relay-v2-event-log-v1,relay-v2-outbox-v2,state-fd-manifest-v1,webhook-store-v1,world-v2\n",
    ));
    // Exact current token (including e2ee-group-authority-v2) remains accepted.
    try std.testing.expect(hasUpgradeCapabilityLine(upgrade_capability_token ++ "\n"));
    try std.testing.expect(std.mem.indexOf(u8, upgrade_capability_caps, "e2ee-group-authority-v2") != null);
    // A predecessor that predates whole-arena integrity or exact
    // World/history/webhook ownership must refuse the new handoff contract;
    // operators can still cold-restart it.
    try std.testing.expect(!hasUpgradeCapabilityLine(
        "ONYX_HELIX_UPGRADE_CAPS=mesh-checkpoint-v2,property-state-v2,state-fd-manifest-v1\n",
    ));
}

test "std.process.run can execute a CLOEXEC image through proc self fd" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const open_rc = linux.open("/bin/true", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.SkipZigTest;
    const executable_fd: handoff.Fd = @intCast(open_rc);
    defer _ = linux.close(executable_fd);

    var proc_path_buf: [64]u8 = undefined;
    const proc_path = try std.fmt.bufPrint(&proc_path_buf, "/proc/self/fd/{d}", .{executable_fd});
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{proc_path},
        .stdout_limit = .limited(64),
        .stderr_limit = .limited(64),
        .timeout = .{ .duration = .{
            .clock = .awake,
            .raw = .fromSeconds(2),
        } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expect(result.term.success());
}

test "ExecPlan.commitExecutableFd executes the already-open image" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const open_rc = linux.open("/bin/true", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.SkipZigTest;
    const executable_fd: handoff.Fd = @intCast(open_rc);
    defer _ = linux.close(executable_fd);

    var plan = try buildListenerExecPlan(allocator, "/ignored/after-open", 0, null);
    defer plan.deinit(allocator);
    const pid_rc = linux.fork();
    const pid: i32 = @intCast(@as(isize, @bitCast(pid_rc)));
    if (pid == 0) {
        plan.commitExecutableFd(allocator, executable_fd) catch {};
        linux.exit(127);
    }
    var status: i32 = 0;
    _ = linux.wait4(pid, &status, 0, null);
    try std.testing.expectEqual(@as(i32, 0), status & 0x7f);
    try std.testing.expectEqual(@as(i32, 0), (status >> 8) & 0xff);
}

test "arena+listener exec plan carries both fds, no control" {
    const allocator = std.testing.allocator;
    var plan = try buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &.{}, null);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.envp.len);
    try std.testing.expectEqualStrings("ONYX_HELIX_ARENA_FD=5", plan.envp[0]);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FD=6", plan.envp[1]);
    try std.testing.expectEqual(@as(handoff.Fd, -1), plan.control_fd);
}

test "arena+listener exec plan carries the per-shard listener list (multi-shard)" {
    const allocator = std.testing.allocator;
    var plan = try buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{ 6, 9, 12 }, &.{}, null);
    defer plan.deinit(allocator);
    // Singular var still carries shard 0 (older-successor compatibility), and
    // the full shard-ordered list rides the plural var.
    try std.testing.expectEqual(@as(usize, 3), plan.envp.len);
    try std.testing.expectEqualStrings("ONYX_HELIX_ARENA_FD=5", plan.envp[0]);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FD=6", plan.envp[1]);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FDS=6,9,12", plan.envp[2]);
    // An empty listener set is a caller bug — fail closed, never exec plan-less.
    try std.testing.expectError(error.NoListener, buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{}, &.{}, null));
    try std.testing.expectError(error.InvalidArenaFd, buildArenaListenerExecPlan(allocator, "/proc/self/exe", -1, &.{6}, &.{}, null));
    try std.testing.expectError(error.InvalidListenerFd, buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{-1}, &.{}, null));
    try std.testing.expectError(error.ArenaFdCollidesWithListener, buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{5}, &.{}, null));
    try std.testing.expectError(error.DuplicateListenerFd, buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{ 6, 6 }, &.{}, null));
    var too_many: [max_inherited_listeners + 1]handoff.Fd = undefined;
    for (&too_many, 0..) |*fd, index| fd.* = @intCast(index + 10);
    try std.testing.expectError(error.TooManyListeners, buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &too_many, &.{}, null));
}

test "arena exec plan carries authoritative state fds without truncation" {
    const allocator = std.testing.allocator;
    var plan = try buildArenaListenerExecPlan(
        allocator,
        "/proc/self/exe",
        5,
        &.{ 6, 9 },
        &.{ 21, 34, 55 },
        null,
    );
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), plan.envp.len);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FDS=6,9", plan.envp[2]);
    try std.testing.expectEqualStrings("ONYX_HELIX_STATE_FDS=21,34,55", plan.envp[3]);

    var too_many: [max_inherited_state_fds + 1]handoff.Fd = @splat(7);
    try std.testing.expectError(
        error.TooManyStateFds,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &too_many, null),
    );
    try std.testing.expectError(
        error.DuplicateStateFd,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &.{ 21, 21 }, null),
    );
    try std.testing.expectError(
        error.StateFdCollidesWithArena,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &.{5}, null),
    );
    try std.testing.expectError(
        error.StateFdCollidesWithListener,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &.{6}, null),
    );
    try std.testing.expectError(
        error.InvalidStateFd,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{6}, &.{-1}, null),
    );
    try std.testing.expectError(
        error.StateFdCollidesWithListener,
        buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, &.{ 6, 9 }, &.{9}, null),
    );
}

test "arena exec plan with both fd manifests is allocation-failure clean" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var plan = try buildArenaListenerExecPlan(
                allocator,
                "/proc/self/exe",
                5,
                &.{ 6, 9 },
                &.{ 21, 34, 55 },
                "/tmp/onyx_server.conf",
            );
            defer plan.deinit(allocator);
            try std.testing.expectEqual(@as(usize, 4), plan.envp.len);
            try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FDS=6,9", plan.envp[2]);
            try std.testing.expectEqualStrings("ONYX_HELIX_STATE_FDS=21,34,55", plan.envp[3]);
        }
    };

    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "parseFdList round-trips, rejects malformed lists fail-closed" {
    var out: [max_inherited_listeners]handoff.Fd = @splat(-1);
    // Well-formed list parses in order.
    try std.testing.expectEqual(@as(usize, 3), parseFdList("6,9,12", &out));
    try std.testing.expectEqual(@as(handoff.Fd, 6), out[0]);
    try std.testing.expectEqual(@as(handoff.Fd, 9), out[1]);
    try std.testing.expectEqual(@as(handoff.Fd, 12), out[2]);
    // A single fd is a one-element list.
    try std.testing.expectEqual(@as(usize, 1), parseFdList("7", &out));
    // Malformed / negative / empty elements reject the WHOLE list (the
    // successor then falls back to the singular listen fd + fresh binds).
    try std.testing.expectEqual(@as(usize, 0), parseFdList("6,x,12", &out));
    try std.testing.expectEqual(@as(usize, 0), parseFdList("6,-1", &out));
    try std.testing.expectEqual(@as(usize, 0), parseFdList("6,,9", &out));
    try std.testing.expectEqual(@as(usize, 0), parseFdList("", &out));
}

test "authoritative state fd parser rejects overflow rather than truncating" {
    var out: [3]handoff.Fd = @splat(-1);
    try std.testing.expectEqual(@as(?usize, 3), parseFdListExact("21,34,55", &out));
    try std.testing.expectEqual(@as(handoff.Fd, 55), out[2]);
    try std.testing.expectEqual(@as(?usize, null), parseFdListExact("21,34,55,89", &out));
    try std.testing.expectEqual(@as(?usize, null), parseFdListExact("21,,55", &out));
    try std.testing.expectEqual(@as(?usize, null), parseFdListExact("21,-1", &out));
    try std.testing.expectEqual(@as(?usize, null), parseFdListExact("21,34,21", &out));
    try std.testing.expectEqual(@as(?usize, null), parseFdListExact("", &out));
}

test "resume env records valid and malformed authoritative manifests" {
    const good = resumeFromEnvBlock(
        "ONYX_HELIX_ARENA_FD=5\x00ONYX_HELIX_LISTEN_FD=6\x00ONYX_HELIX_STATE_FDS=21,34,55\x00",
    ).?;
    try std.testing.expect(good.state_fd_manifest_present);
    try std.testing.expect(good.state_fd_manifest_valid);
    try std.testing.expectEqualSlices(handoff.Fd, &.{ 21, 34, 55 }, good.stateFds());

    const bad = resumeFromEnvBlock(
        "ONYX_HELIX_ARENA_FD=5\x00ONYX_HELIX_STATE_FDS=21,21\x00",
    ).?;
    try std.testing.expect(bad.state_fd_manifest_present);
    try std.testing.expect(!bad.state_fd_manifest_valid);
    try std.testing.expectEqual(@as(usize, 0), bad.state_fd_count);
}

test "findEnvValue locates the listener list in an environ block" {
    const block = "FOO=bar\x00ONYX_HELIX_LISTEN_FDS=6,9\x00BAZ=qux\x00";
    try std.testing.expectEqualStrings("6,9", findEnvValue(block, env_listen_fds).?);
    try std.testing.expectEqual(@as(?[]const u8, null), findEnvValue("FOO=bar\x00", env_listen_fds));
}

test "findEnvValue locates the authoritative state fd list" {
    const block = "FOO=bar\x00ONYX_HELIX_STATE_FDS=21,34,55\x00BAZ=qux\x00";
    try std.testing.expectEqualStrings("21,34,55", findEnvValue(block, env_state_fds).?);
}

test "listener-only exec plan carries just the listen fd" {
    const allocator = std.testing.allocator;
    var plan = try buildListenerExecPlan(allocator, "/proc/self/exe", 7, null);
    defer plan.deinit(allocator);
    try std.testing.expectEqualStrings("/proc/self/exe", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqual(@as(usize, 1), plan.envp.len);
    try std.testing.expectEqualStrings("ONYX_HELIX_LISTEN_FD=7", plan.envp[0]);
}

test "readFdFromEnvBlock parses the listen fd, absent -> null" {
    const block = "FOO=bar\x00ONYX_HELIX_LISTEN_FD=37\x00BAZ=qux\x00";
    try std.testing.expectEqual(@as(?handoff.Fd, 37), readFdFromEnvBlock(block, env_listen_fd));
    const none = "FOO=bar\x00BAZ=qux\x00";
    try std.testing.expectEqual(@as(?handoff.Fd, null), readFdFromEnvBlock(none, env_listen_fd));
}

test "exec plan owns argv and envp without committing" {
    const allocator = std.testing.allocator;

    var plan = try buildExecPlan(allocator, "/tmp/onyx", 10, 11);
    defer plan.deinit(allocator);

    try std.testing.expectEqualStrings("/tmp/onyx", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqualStrings("ONYX_HELIX_ARENA_FD=10", plan.envp[0]);
    try std.testing.expectEqualStrings("ONYX_HELIX_CONTROL_FD=11", plan.envp[1]);
}
