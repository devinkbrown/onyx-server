// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline policy export. The caller must quiesce the issuer and supply a
//! trusted private baseline; this command never operates on a live service.
const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");
const config = onyx.daemon.config_format;
const activation = onyx.daemon.relay_v2_activation;
const durable = onyx.daemon.session_group_revoke_durable;
const policy = onyx.daemon.session_group_retired_policy;
const baseline = onyx.daemon.session_retirement_baseline;
const sign = onyx.crypto.sign;
const frame = onyx.substrate.undertow.signed_frame;

pub const usage = "usage: onyx-server session-fences export <config> --baseline <private-offline-dir> --issuer <64-lower-hex> --output <new-policy-file> [--wal-name accounts.wal]\n";

pub const Options = struct {
    config_path: []const u8,
    baseline_path: []const u8,
    issuer: sign.PublicKey,
    output_path: []const u8,
    wal_name: []const u8 = "accounts.wal",
};

fn pathArgument(value: []const u8) bool {
    return value.len != 0 and value.len <= 4096 and value[0] != '-' and
        std.mem.indexOfAny(u8, value, "\x00\r\n") == null;
}

fn issuerArgument(value: []const u8) error{InvalidArguments}!sign.PublicKey {
    if (value.len != 64) return error.InvalidArguments;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidArguments;
    var key: sign.PublicKey = undefined;
    _ = std.fmt.hexToBytes(&key, value) catch return error.InvalidArguments;
    if (std.mem.allEqual(u8, &key, 0)) return error.InvalidArguments;
    return key;
}

pub fn parse(args: []const []const u8) error{InvalidArguments}!Options {
    if (args.len < 8 or args.len > 10 or !std.mem.eql(u8, args[0], "export") or !pathArgument(args[1])) return error.InvalidArguments;
    var baseline_path: ?[]const u8 = null;
    var issuer: ?sign.PublicKey = null;
    var output_path: ?[]const u8 = null;
    var wal_name: ?[]const u8 = null;
    var index: usize = 2;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len or !pathArgument(args[index + 1])) return error.InvalidArguments;
        const flag = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, flag, "--baseline") and baseline_path == null) {
            baseline_path = value;
        } else if (std.mem.eql(u8, flag, "--issuer") and issuer == null) {
            issuer = try issuerArgument(value);
        } else if (std.mem.eql(u8, flag, "--output") and output_path == null) {
            output_path = value;
        } else if (std.mem.eql(u8, flag, "--wal-name") and wal_name == null) {
            if (value.len > 250 or std.mem.indexOfAny(u8, value, "/\\") != null or
                std.mem.eql(u8, value, ".") or std.mem.eql(u8, value, "..")) return error.InvalidArguments;
            wal_name = value;
        } else return error.InvalidArguments;
    }
    return .{
        .config_path = args[1],
        .baseline_path = baseline_path orelse return error.InvalidArguments,
        .issuer = issuer orelse return error.InvalidArguments,
        .output_path = output_path orelse return error.InvalidArguments,
        .wal_name = wal_name orelse "accounts.wal",
    };
}

const TrustContext = struct {
    roster: *const activation.CanonicalRoster,
    grants: []const policy.Grant,

    fn active(ctx: *const anyopaque, key: sign.PublicKey, origin: u64) bool {
        const self: *const TrustContext = @ptrCast(@alignCast(ctx));
        return origin == frame.originShortId(key) and self.roster.contains(key);
    }

    fn retained(ctx: *const anyopaque, key: sign.PublicKey, origin: u64, group: policy.Digest, fact: policy.Digest) bool {
        const self: *const TrustContext = @ptrCast(@alignCast(ctx));
        return origin == frame.originShortId(key) and policy.allows(self.grants, key, group, fact);
    }

    fn trust(self: *const TrustContext) durable.Trust {
        return .{ .ctx = self, .allows = active, .allows_retired = retained, .required_grants = self.grants };
    }
};

pub const Summary = struct {
    grants: usize,
    sha256: [32]u8,
};

/// Kernel leases witness ordinary writer exclusion during this operation.
/// The trusted owner must keep the issuer quiesced through retirement; this
/// command cannot prove that no other copy of its signing key exists.
pub fn run(allocator: std.mem.Allocator, io: std.Io, opts: Options, resolver: config.Resolver) !Summary {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const text = try std.Io.Dir.cwd().readFileAlloc(io, opts.config_path, allocator, .limited(config.max_config_bytes));
    defer allocator.free(text);
    var parsed = try config.parseToml(allocator, text, resolver);
    defer parsed.deinit(allocator);
    if (parsed.mesh.relay_v2_activation_epoch == 0 or parsed.mesh.relay_v2_roster.len < 2) return error.MissingActiveRoster;
    var roster = try activation.canonicalizeRoster(allocator, parsed.mesh.relay_v2_roster);
    defer roster.deinit();
    const trust_context = TrustContext{ .roster = &roster, .grants = parsed.mesh.retired_session_group_fences };

    const input_parent = try std.Io.Dir.cwd().openDir(io, std.fs.path.dirname(opts.baseline_path) orelse ".", .{ .follow_symlinks = false });
    defer input_parent.close(io);
    var guard = try baseline.Guard.acquire(io, input_parent, std.fs.path.basename(opts.baseline_path), opts.wal_name);
    defer guard.deinit();
    var db = try onyx.daemon.store.OroStore.openReadOnlyWithConfig(allocator, io, guard.directory(), opts.wal_name, parsed.storage);
    defer db.deinit();
    try guard.assertStable();
    const bytes = try durable.prepareExport(allocator, &db, trust_context.trust(), opts.issuer);
    defer allocator.free(bytes);
    try guard.assertStable();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});

    const output_parent = try std.Io.Dir.cwd().openDir(io, std.fs.path.dirname(opts.output_path) orelse ".", .{ .follow_symlinks = false });
    defer output_parent.close(io);
    var output = try output_parent.createFileAtomic(io, std.fs.path.basename(opts.output_path), .{ .replace = false, .permissions = .fromMode(0o600) });
    defer output.deinit(io);
    try output.file.writeStreamingAll(io, bytes);
    try output.file.sync(io);
    try guard.assertStable();
    // Keep all input descriptors and leases through publication. There is no
    // adversarial-owner/latest-at-publication guarantee beyond the explicit
    // trusted quiescent-baseline contract.
    try output.link(io);
    return .{ .grants = std.mem.count(u8, bytes, "[[mesh.retired_session_group_fences]]"), .sha256 = digest };
}

test "retirement export arguments separate policy selectors from credential inputs" {
    const key = "1111111111111111111111111111111111111111111111111111111111111111";
    const valid = try parse(&.{ "export", "config.toml", "--baseline", "closed", "--issuer", key, "--output", "policy.toml" });
    try std.testing.expectEqualStrings("accounts.wal", valid.wal_name);
    try std.testing.expectEqual(@as(u8, 0x11), valid.issuer[0]);
    for ([_][]const []const u8{
        &.{},
        &.{ "export", "cfg", "--baseline", "closed", "--issuer", key, "--output" },
        &.{ "export", "cfg", "--baseline", "closed", "--issuer", key, "--output", "policy", "--issuer", key },
        &.{ "export", "cfg", "--baseline", "closed", "--issuer", key, "--output", "policy", "--wal-name", "../live.wal" },
        &.{ "export", "cfg", "--baseline", "closed", "--issuer", "TOKEN", "--output", "policy" },
    }) |invalid| try std.testing.expectError(error.InvalidArguments, parse(invalid));
}

test "retirement export missing configuration cannot publish an artifact" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const allocator = std.testing.allocator;
    const root = try temporary.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(root);
    const missing = try std.fs.path.join(allocator, &.{ root, "missing.toml" });
    defer allocator.free(missing);
    const output = try std.fs.path.join(allocator, &.{ root, "policy.toml" });
    defer allocator.free(output);
    try std.testing.expectError(error.FileNotFound, run(allocator, std.testing.io, .{
        .config_path = missing,
        .baseline_path = root,
        .issuer = @splat(1),
        .output_path = output,
    }, .{}));
    try std.testing.expectError(error.FileNotFound, temporary.dir.openFile(std.testing.io, "policy.toml", .{}));
}
