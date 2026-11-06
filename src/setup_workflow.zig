// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secret-free new-install choices and immutable ordinary TOML candidates.
//! Generated candidates are always passed through the daemon boot loader.
const std = @import("std");
const builtin = @import("builtin");
pub const account = @import("setup_account.zig");

pub const Profile = enum { existing, private, community, media };
pub const Service = enum { auto, openrc, systemd, foreground };

/// Nonsecret choices projected directly into the authoritative TOML schema.
/// Borrowed strings must outlive candidate generation (interactive callers own
/// a bounded input arena; parsed drafts own their JSON string allocations).
pub const Settings = struct {
    hostname: []const u8 = "localhost",
    listen_host: []const u8 = "127.0.0.1",
    irc_port: u16 = 6680,
    node_id: u64 = 1,
    tls_enabled: bool = false,
    tls_port: u16 = 6697,
    max_clients: ?u31 = null,
    media_port: u16 = 0,
    bootstrap: account.Intent = .{},

    pub fn validate(self: Settings) !void {
        try self.bootstrap.validate();
        if (!validHostname(self.hostname)) return error.InvalidHostname;
        _ = std.Io.net.IpAddress.parse(self.listen_host, self.irc_port) catch return error.InvalidListenAddress;
        if (self.irc_port == 0 or self.node_id == 0 or self.node_id > std.math.maxInt(i64)) return error.InvalidSettings;
        if (self.tls_enabled and (self.tls_port == 0 or self.tls_port == self.irc_port)) return error.InvalidTlsPort;
        if (self.max_clients) |value| if (value == 0 or value > 32767) return error.InvalidCapacity;
    }

    /// Caller preserves the backing input; publish a changed choice only after
    /// validating the full proposed settings, including port collisions.
    pub fn set(self: *Settings, key: []const u8, value: []const u8) !void {
        var next = self.*;
        try next.assign(key, value);
        try next.validate();
        self.* = next;
    }

    pub fn assign(self: *Settings, key: []const u8, value: []const u8) !void {
        var next = self.*;
        if (std.mem.eql(u8, key, "account")) next.bootstrap.account = value else if (std.mem.eql(u8, key, "privileges")) next.bootstrap.privileges = value else if (std.mem.eql(u8, key, "hostname")) next.hostname = value else if (std.mem.eql(u8, key, "listen")) next.listen_host = value else if (std.mem.eql(u8, key, "irc-port")) next.irc_port = try std.fmt.parseInt(u16, value, 10) else if (std.mem.eql(u8, key, "node-id")) next.node_id = try std.fmt.parseInt(u64, value, 10) else if (std.mem.eql(u8, key, "tls-port")) {
            next.tls_port = try std.fmt.parseInt(u16, value, 10);
            next.tls_enabled = true;
        } else if (std.mem.eql(u8, key, "tls")) {
            if (std.mem.eql(u8, value, "on")) next.tls_enabled = true else if (std.mem.eql(u8, value, "off")) next.tls_enabled = false else return error.InvalidSettings;
        } else if (std.mem.eql(u8, key, "max-clients")) next.max_clients = try std.fmt.parseInt(u31, value, 10) else if (std.mem.eql(u8, key, "media-port")) next.media_port = try std.fmt.parseInt(u16, value, 10) else return error.UnknownSetting;
        self.* = next;
    }
};

/// DNS-label syntax only; this does not resolve or establish ownership.
pub fn validHostname(hostname: []const u8) bool {
    if (hostname.len == 0 or hostname.len > 253) return false;
    var labels = std.mem.splitScalar(u8, hostname, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

pub fn description(profile: Profile) []const u8 {
    return switch (profile) {
        .existing => "Existing configuration: preserve every source byte; no profile edits.",
        .private => "Private baseline: listen.host=127.0.0.1; listen.irc=6680; limits.max_clients=128; media.enabled=false; network.discoverable=false.",
        .community => "Community baseline: listen.host=127.0.0.1; listen.irc=6680; limits.max_clients=1024; media.enabled=false; network.discoverable=false.",
        .media => "Media baseline: listen.host=127.0.0.1; listen.irc=6680; limits.max_clients=128; media.enabled=true; network.discoverable=false.",
    };
}

/// These templates are actual configuration schema values, not a second config
/// model. All start on loopback without public discovery or fabricated secrets.
pub fn candidate(allocator: std.mem.Allocator, profile: Profile) ![]u8 {
    return configuredCandidate(allocator, profile, .{}, null);
}

/// Profile-controlled schema values after applying the current overrides.
/// Existing configuration has no inferred values and is never projected.
pub const EffectiveProfile = struct { max_clients: u31, media_enabled: bool };
pub fn effectiveProfile(profile: Profile, settings: Settings) ?EffectiveProfile {
    if (profile == .existing) return null;
    return .{ .max_clients = settings.max_clients orelse if (profile == .community) 1024 else 128, .media_enabled = profile == .media };
}

/// Bundle references are final absolute paths; temporary staging paths never
/// enter published configuration. Only generated templates are rewritten.
pub fn configuredCandidate(allocator: std.mem.Allocator, profile: Profile, settings: Settings, bundle: ?[]const u8) ![]u8 {
    if (profile == .existing) return error.ExistingProfileNeedsConfig;
    try settings.validate();
    const effective = effectiveProfile(profile, settings).?;
    const name = try std.json.Stringify.valueAlloc(allocator, settings.hostname, .{});
    defer allocator.free(name);
    const host = try std.json.Stringify.valueAlloc(allocator, settings.listen_host, .{});
    defer allocator.free(host);
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    out.writer.print(
        "# Onyx Server generated candidate. Review authentication and mesh trust before public use.\n" ++
            "[node]\nid = {d}\n[network]\nname = \"Onyx\"\nserver_name = {s}\ndiscoverable = false\n" ++
            "[listen]\nhost = {s}\nirc = {d}\nmedia = {d}\n[limits]\nmax_clients = {d}\n" ++
            "[media]\nenabled = {s}\n[tls]\nenabled = {s}\nport = {d}\ndns_name = {s}\n",
        .{ settings.node_id, name, host, settings.irc_port, settings.media_port, effective.max_clients, if (effective.media_enabled) "true" else "false", if (settings.tls_enabled) "true" else "false", settings.tls_port, name },
    ) catch return error.OutOfMemory;
    if (bundle) |path| {
        const cert_path = try std.fs.path.join(allocator, &.{ path, "tls-cert.der" });
        defer allocator.free(cert_path);
        const key_path = try std.fs.path.join(allocator, &.{ path, "tls-key.der" });
        defer allocator.free(key_path);
        const cloak_path = try std.fmt.allocPrint(allocator, "@file:{s}/cloak.secret", .{path});
        defer allocator.free(cloak_path);
        const cert = try std.json.Stringify.valueAlloc(allocator, cert_path, .{});
        defer allocator.free(cert);
        const key = try std.json.Stringify.valueAlloc(allocator, key_path, .{});
        defer allocator.free(key);
        const cloak = try std.json.Stringify.valueAlloc(allocator, cloak_path, .{});
        defer allocator.free(cloak);
        out.writer.print("cert_path = {s}\nkey_path = {s}\n[cloak]\nsecret = {s}\n", .{ cert, key, cloak }) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice();
}

/// Compare profile-controlled effective values with the SAME overrides on
/// both sides. Caller supplies storage; no secrets or allocations are involved.
pub fn diff(buf: []u8, from: Profile, to: Profile, settings: Settings) ![]const u8 {
    const before = effectiveProfile(from, settings) orelse return "Existing config is preserved; profiles apply only to a new installation.";
    const after = effectiveProfile(to, settings) orelse return "Existing config is preserved; profiles apply only to a new installation.";
    if (before.max_clients == after.max_clients and before.media_enabled == after.media_enabled) return "No effective profile changes.";
    if (before.max_clients != after.max_clients and before.media_enabled != after.media_enabled)
        return std.fmt.bufPrint(buf, "limits.max_clients: {d} -> {d}; media.enabled: {s} -> {s}", .{ before.max_clients, after.max_clients, if (before.media_enabled) "true" else "false", if (after.media_enabled) "true" else "false" });
    if (before.max_clients != after.max_clients)
        return std.fmt.bufPrint(buf, "limits.max_clients: {d} -> {d}", .{ before.max_clients, after.max_clients });
    return std.fmt.bufPrint(buf, "media.enabled: {s} -> {s}", .{ if (before.media_enabled) "true" else "false", if (after.media_enabled) "true" else "false" });
}

pub const Wizard = struct {
    profile: Profile = .private,
    previous: Profile = .private,
    settings: Settings = .{},
    reviewing: bool = false,
    pub const Action = enum { changed, help, search, invalid, cancel, finish, save };

    pub fn command(self: *Wizard, raw: []const u8) Action {
        const input = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, input, "cancel") or std.mem.eql(u8, input, "q")) return .cancel;
        if (std.mem.eql(u8, input, "help") or std.mem.eql(u8, input, "?")) return .help;
        if (searchQuery(input) != null) return .search;
        if (!self.reviewing and std.mem.startsWith(u8, input, "set ")) {
            const pair = std.mem.trim(u8, input[4..], " \t");
            const separator = std.mem.indexOfAny(u8, pair, " \t") orelse return .invalid;
            self.settings.set(pair[0..separator], std.mem.trim(u8, pair[separator + 1 ..], " \t")) catch return .invalid;
            return .changed;
        }
        if (std.mem.eql(u8, input, "back") or std.mem.eql(u8, input, "profiles")) {
            self.reviewing = false;
            return .changed;
        }
        if (std.mem.eql(u8, input, "review")) {
            self.reviewing = true;
            return .changed;
        }
        if (self.reviewing) {
            if (std.mem.eql(u8, input, "done")) return .finish;
            if (std.mem.eql(u8, input, "save")) return .save;
            return .invalid;
        }
        const profile: Profile = if (std.mem.eql(u8, input, "1") or std.mem.eql(u8, input, "private")) .private else if (std.mem.eql(u8, input, "2") or std.mem.eql(u8, input, "community")) .community else if (std.mem.eql(u8, input, "3") or std.mem.eql(u8, input, "media")) .media else return .invalid;
        self.previous = self.profile;
        self.profile = profile;
        return .changed;
    }
};

pub fn searchQuery(raw: []const u8) ?[]const u8 {
    const input = std.mem.trim(u8, raw, " \t\r\n");
    if (!std.mem.startsWith(u8, input, "search ")) return null;
    const query = std.mem.trim(u8, input["search ".len..], " \t");
    return if (query.len == 0) null else query;
}

pub fn matchesText(text: []const u8, query: []const u8) bool {
    if (query.len > text.len) return false;
    for (0..text.len - query.len + 1) |i| {
        if (std.ascii.eqlIgnoreCase(text[i..][0..query.len], query)) return true;
    }
    return false;
}
pub fn matches(profile: Profile, query: []const u8) bool {
    return matchesText(description(profile), query);
}
pub const search_fields = [_][]const u8{
    "existing network: set config <path> to validate and review an existing configuration",
    "hostname: set hostname <dns-name>",
    "listen: set listen <ip-address>",
    "irc-port: set irc-port <port>",
    "node-id: set node-id <id>",
    "tls: set tls on or off; set tls-port <port>",
    "max-clients: set max-clients <count>",
    "media-port: set media-port <port>",
    "account: set account <name>; set privileges <names>",
};

/// Drafts store choices, never candidate source, resolved values, or secrets.
/// Versioning is explicit; unknown fields and incompatible versions fail closed.
pub const Draft = struct {
    version: u8,
    profile: Profile,
    service: Service,
    settings: ?Settings = null,
};

/// Create a new private artifact transactionally, without replacing any file,
/// symlink, or live configuration. Restrict to Linux until other platform
/// privacy/publication semantics have corresponding acceptance evidence.
pub fn publish(io: std.Io, dir: std.Io.Dir, path: []const u8, bytes: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = false, .permissions = .fromMode(0o600) });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, bytes);
    try atomic.file.sync(io);
    try atomic.link(io);
}

pub fn requireDraftOwner(file: std.Io.File, expected_uid: u32) !void {
    var metadata: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
    while (true) switch (std.os.linux.errno(std.os.linux.statx(file.handle, "", std.os.linux.AT.EMPTY_PATH, .{ .UID = true }, &metadata))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.DraftOwnerUnavailable,
    };
    if (!metadata.mask.UID) return error.DraftOwnerUnavailable;
    if (metadata.uid != expected_uid) return error.InsecureDraft;
}

pub fn readDraft(io: std.Io, dir: std.Io.Dir, path: []const u8, allocator: std.mem.Allocator) !std.json.Parsed(Draft) {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return readDraftForUid(io, dir, path, allocator, std.os.linux.geteuid());
}

fn readDraftForUid(io: std.Io, dir: std.Io.Dir, path: []const u8, allocator: std.mem.Allocator, expected_uid: u32) !std.json.Parsed(Draft) {
    // O_PATH never blocks on FIFOs/devices. Hold that exact object while
    // rejecting symlinks and nonregular/private metadata, then reopen via the
    // kernel fd link so a pathname replacement cannot substitute a FIFO.
    const held = try dir.openFile(io, path, .{ .follow_symlinks = false, .path_only = true });
    defer held.close(io);
    const held_stat = try held.stat(io);
    try requireDraftOwner(held, expected_uid);
    if (held_stat.kind != .file or held_stat.nlink != 1 or held_stat.permissions.toMode() & 0o077 != 0) return error.InsecureDraft;
    var fd_path_buffer: [64]u8 = undefined;
    const fd_path = try std.fmt.bufPrint(&fd_path_buffer, "/proc/self/fd/{d}", .{held.handle});
    const file = try std.Io.Dir.openFileAbsolute(io, fd_path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try requireDraftOwner(file, expected_uid);
    if (stat.inode != held_stat.inode or stat.kind != .file or stat.nlink != 1 or stat.permissions.toMode() & 0o077 != 0) return error.InsecureDraft;
    var buffer: [4097]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const n = file.readStreaming(io, &.{buffer[used..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        used += n;
    }
    if (used > 4096) return error.DraftTooLarge;
    var parsed = try std.json.parseFromSlice(Draft, allocator, buffer[0..used], .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    if (parsed.value.profile == .existing) return error.InvalidDraft;
    if (parsed.value.version == 1) {
        if (parsed.value.settings != null) return error.InvalidDraft;
    } else if (parsed.value.version == 2 or parsed.value.version == 3) {
        const settings = parsed.value.settings orelse return error.InvalidDraft;
        try settings.validate();
        if (parsed.value.version == 2 and (settings.bootstrap.enabled() or !std.mem.eql(u8, settings.bootstrap.privileges, "none"))) return error.InvalidDraft;
    } else return error.InvalidDraft;
    return parsed;
}

test "setup wizard navigation review cancellation and explicit diff" {
    var wizard: Wizard = .{};
    try std.testing.expectEqual(Wizard.Action.invalid, wizard.command("done"));
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("2"));
    var diff_buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("limits.max_clients: 128 -> 1024", try diff(&diff_buf, wizard.previous, wizard.profile, wizard.settings));
    try std.testing.expectEqual(Wizard.Action.help, wizard.command("help"));
    try std.testing.expectEqual(Wizard.Action.search, wizard.command(" search media "));
    try std.testing.expect(matches(.media, "MEDIA.ENABLED=TRUE"));
    try std.testing.expect(!matches(.private, "MEDIA.ENABLED=TRUE"));
    _ = wizard.command("review");
    try std.testing.expectEqual(Wizard.Action.finish, wizard.command("done"));
    _ = wizard.command("back");
    _ = wizard.command("media");
    try std.testing.expectEqual(Profile.media, wizard.profile);
    _ = wizard.command("review");
    try std.testing.expectEqual(Wizard.Action.save, wizard.command("save"));
    try std.testing.expectEqual(Wizard.Action.cancel, wizard.command("cancel"));
}

test "setup private publication refuses replacement and resumes choice-only draft" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const bytes = try std.json.Stringify.valueAlloc(allocator, Draft{ .version = 1, .profile = .media, .service = .openrc }, .{});
    defer allocator.free(bytes);
    try publish(std.testing.io, tmp.dir, "draft.json", bytes);
    try std.testing.expectError(error.PathAlreadyExists, publish(std.testing.io, tmp.dir, "draft.json", "replacement"));
    const parsed = try readDraft(std.testing.io, tmp.dir, "draft.json", allocator);
    defer parsed.deinit();
    try std.testing.expectEqual(Profile.media, parsed.value.profile);
    try std.testing.expectEqual(Service.openrc, parsed.value.service);
    try std.testing.expectError(error.InsecureDraft, readDraftForUid(std.testing.io, tmp.dir, "draft.json", allocator, std.os.linux.geteuid() ^ 1));
    try tmp.dir.setFilePermissions(std.testing.io, "draft.json", .fromMode(0o644), .{});
    try std.testing.expectError(error.InsecureDraft, readDraft(std.testing.io, tmp.dir, "draft.json", allocator));
}

test "setup resume refuses symlinks hardlinks unknown schemas and oversize input" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    try publish(std.testing.io, tmp.dir, "draft", "{\"version\":2,\"profile\":\"private\",\"service\":\"auto\"}");
    try std.testing.expectError(error.InvalidDraft, readDraft(std.testing.io, tmp.dir, "draft", allocator));
    try tmp.dir.symLink(std.testing.io, "draft", "symlink", .{});
    if (readDraft(std.testing.io, tmp.dir, "symlink", allocator)) |parsed| {
        parsed.deinit();
        return error.TestExpectedError;
    } else |_| {}
    try tmp.dir.hardLink("draft", tmp.dir, "hardlink", std.testing.io, .{});
    try std.testing.expectError(error.InsecureDraft, readDraft(std.testing.io, tmp.dir, "hardlink", allocator));
    try publish(std.testing.io, tmp.dir, "unknown", "{\"profile\":\"private\",\"service\":\"auto\",\"secret\":\"forbidden\"}");
    try std.testing.expectError(error.UnknownField, readDraft(std.testing.io, tmp.dir, "unknown", allocator));
    const oversized: [4097]u8 = @splat(' ');
    try publish(std.testing.io, tmp.dir, "large", &oversized);
    try std.testing.expectError(error.DraftTooLarge, readDraft(std.testing.io, tmp.dir, "large", allocator));
}

fn candidateAllocationProbe(allocator: std.mem.Allocator) !void {
    for ([_]Profile{ .private, .community, .media }) |profile| {
        const text = try candidate(allocator, profile);
        defer allocator.free(text);
    }
}

test "setup profile candidate allocation failures never publish state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, candidateAllocationProbe, .{});
}

test "setup field navigation retains valid settings after rejected change" {
    var wizard: Wizard = .{};
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("set hostname irc.example.test"));
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("set irc-port 7000"));
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("set tls-port 7001"));
    try std.testing.expectEqual(Wizard.Action.invalid, wizard.command("set tls-port 7000"));
    try std.testing.expectEqual(@as(u16, 7001), wizard.settings.tls_port);
    _ = wizard.command("review");
    try std.testing.expectEqual(Wizard.Action.invalid, wizard.command("set node-id 17"));
    _ = wizard.command("back");
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("set node-id 17"));
}

test "setup effective profile diff follows actual candidate and previous selection" {
    const a = std.testing.allocator;
    var wizard: Wizard = .{};
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("set max-clients 512"));
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("community"));
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("No effective profile changes.", try diff(&buf, wizard.previous, wizard.profile, wizard.settings));
    for ([_]Profile{ wizard.previous, wizard.profile }) |profile| {
        const text = try configuredCandidate(a, profile, wizard.settings, null);
        defer a.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "max_clients = 512") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "[media]\nenabled = false") != null);
    }
    try std.testing.expectEqual(Wizard.Action.changed, wizard.command("media"));
    try std.testing.expectEqual(Profile.community, wizard.previous);
    try std.testing.expectEqualStrings("media.enabled: false -> true", try diff(&buf, wizard.previous, wizard.profile, wizard.settings));
    const media = try configuredCandidate(a, wizard.profile, wizard.settings, null);
    defer a.free(media);
    try std.testing.expect(std.mem.indexOf(u8, media, "max_clients = 512") != null);
    try std.testing.expect(std.mem.indexOf(u8, media, "[media]\nenabled = true") != null);
    try std.testing.expectEqual(Wizard.Action.invalid, wizard.command("set max-clients 0"));
    try std.testing.expectEqual(@as(?u31, 512), wizard.settings.max_clients);
    try std.testing.expectEqual(Profile.community, wizard.previous);
    try std.testing.expectEqual(Profile.media, wizard.profile);
    try std.testing.expectEqualStrings("media.enabled: false -> true", try diff(&buf, wizard.previous, wizard.profile, wizard.settings));
    try std.testing.expectEqualStrings("limits.max_clients: 1024 -> 128; media.enabled: false -> true", try diff(&buf, .community, .media, .{}));
    try std.testing.expectEqualStrings("limits.max_clients: 128 -> 1024; media.enabled: true -> false", try diff(&buf, .media, .community, .{}));
    try std.testing.expectEqualStrings("Existing config is preserved; profiles apply only to a new installation.", try diff(&buf, .existing, .private, .{}));
}

test "setup search includes existing network and nonsecret settings" {
    var existing = false;
    var capacity = false;
    for (search_fields) |entry| {
        if (matchesText(entry, "EXISTING")) existing = true;
        if (matchesText(entry, "max-clients")) capacity = true;
    }
    try std.testing.expect(existing and capacity);
}

/// Existing-runtime branch of the setup wizard. Review ids are request
/// correlation, not authorization or credentials; the backend owns all guards.
pub const MaintenanceWizard = struct {
    review_id: ?[32]u8 = null,
    pub const Action = enum { review, back, cancel, apply, change_restore, edit_config, preview_config, discard_config, save_config, invalid };
    pub fn enterReview(self: *MaintenanceWizard, id: [32]u8) void {
        self.review_id = id;
    }
    pub fn command(self: *MaintenanceWizard, raw: []const u8) Action {
        const text = std.mem.trim(u8, raw, " \t\r\n");
        if (std.mem.eql(u8, text, "cancel") or std.mem.eql(u8, text, "q")) {
            self.review_id = null;
            return .cancel;
        }
        if (std.mem.eql(u8, text, "back")) {
            self.review_id = null;
            return .back;
        }
        if (std.mem.eql(u8, text, "review") and self.review_id == null) return .review;
        if (self.review_id == null and maintenanceRestorePath(text) != null) return .change_restore;
        if (std.mem.eql(u8, text, "preview")) return .preview_config;
        if (self.review_id == null and maintenanceConfigEdit(text) != null) return .edit_config;
        if (self.review_id == null and std.mem.eql(u8, text, "discard")) return .discard_config;
        if (self.review_id == null and maintenanceSavePath(text) != null) return .save_config;
        if (self.review_id) |id| {
            if (text.len == 6 + id.len and std.mem.startsWith(u8, text, "apply ") and std.mem.eql(u8, text[6..], &id)) return .apply;
        }
        return .invalid;
    }
};

test "maintenance wizard requires exact current review before apply and invalidates on back cancel" {
    var wizard: MaintenanceWizard = .{};
    const id: [32]u8 = @splat('a');
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("apply"));
    try std.testing.expectEqual(MaintenanceWizard.Action.review, wizard.command("review"));
    wizard.enterReview(id);
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("apply bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    try std.testing.expectEqual(MaintenanceWizard.Action.apply, wizard.command("apply aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    try std.testing.expectEqual(MaintenanceWizard.Action.back, wizard.command("back"));
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("apply aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    wizard.enterReview(id);
    try std.testing.expectEqual(MaintenanceWizard.Action.cancel, wizard.command("cancel"));
    try std.testing.expect(wizard.review_id == null);
}

pub fn maintenanceRestorePath(raw: []const u8) ?[]const u8 {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const prefix = "set restore-into ";
    if (!std.mem.startsWith(u8, text, prefix) or text.len == prefix.len) return null;
    const path = text[prefix.len..];
    for (path) |byte| if (byte < 0x20 or byte == 0x7f) return null;
    return path;
}

/// Maintenance config edit, using the same `set <key> <value>` keys as the
/// new-install wizard. `restore-into` is a custody choice, not configuration.
pub const ConfigEdit = struct { key: []const u8, value: []const u8 };
pub fn maintenanceConfigEdit(raw: []const u8) ?ConfigEdit {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    if (!std.mem.startsWith(u8, text, "set ")) return null;
    const pair = std.mem.trim(u8, text[4..], " \t");
    const separator = std.mem.indexOfAny(u8, pair, " \t") orelse return null;
    const key = pair[0..separator];
    const value = std.mem.trim(u8, pair[separator + 1 ..], " \t");
    if (value.len == 0 or std.mem.eql(u8, key, "restore-into")) return null;
    for (pair) |byte| if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return null;
    return .{ .key = key, .value = value };
}

/// New private candidate path for `save-config`; never the live file.
pub fn maintenanceSavePath(raw: []const u8) ?[]const u8 {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const prefix = "save-config ";
    if (!std.mem.startsWith(u8, text, prefix)) return null;
    const path = std.mem.trim(u8, text[prefix.len..], " \t");
    if (path.len == 0 or path[0] != '/') return null;
    for (path) |byte| if (byte < 0x20 or byte == 0x7f) return null;
    return path;
}

test "maintenance wizard routes config edits preview discard and save only outside review" {
    var wizard: MaintenanceWizard = .{};
    try std.testing.expectEqual(MaintenanceWizard.Action.edit_config, wizard.command("set irc-port 7000"));
    try std.testing.expectEqualStrings("irc-port", maintenanceConfigEdit("set  irc-port   7000 ").?.key);
    try std.testing.expectEqualStrings("7000", maintenanceConfigEdit("set irc-port 7000").?.value);
    try std.testing.expect(maintenanceConfigEdit("set irc-port") == null);
    try std.testing.expect(maintenanceConfigEdit("set hostname a\x1b[2J") == null);
    try std.testing.expect(maintenanceConfigEdit("set restore-into /x") == null);
    try std.testing.expectEqual(MaintenanceWizard.Action.change_restore, wizard.command("set restore-into /x"));
    try std.testing.expectEqual(MaintenanceWizard.Action.preview_config, wizard.command("preview"));
    try std.testing.expectEqual(MaintenanceWizard.Action.discard_config, wizard.command("discard"));
    try std.testing.expectEqual(MaintenanceWizard.Action.save_config, wizard.command("save-config /private/candidate.toml"));
    try std.testing.expect(maintenanceSavePath("save-config relative.toml") == null);
    try std.testing.expect(maintenanceSavePath("save-config /bad\x07path") == null);
    wizard.enterReview(@splat('a'));
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("set irc-port 7001"));
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("discard"));
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("save-config /private/c.toml"));
    try std.testing.expectEqual(MaintenanceWizard.Action.preview_config, wizard.command("preview"));
    try std.testing.expect(wizard.review_id != null);
}

test "maintenance wizard changes retained scratch only from choices" {
    var wizard: MaintenanceWizard = .{};
    try std.testing.expectEqual(MaintenanceWizard.Action.change_restore, wizard.command("set restore-into /new/private/scratch"));
    try std.testing.expectEqualStrings("/new/private/scratch", maintenanceRestorePath("set restore-into /new/private/scratch").?);
    wizard.enterReview(@splat('a'));
    try std.testing.expectEqual(MaintenanceWizard.Action.invalid, wizard.command("set restore-into /another"));
    try std.testing.expectEqual(MaintenanceWizard.Action.back, wizard.command("back"));
    try std.testing.expectEqual(MaintenanceWizard.Action.change_restore, wizard.command("set restore-into /another"));
    try std.testing.expect(maintenanceRestorePath("set restore-into /bad\x1bpath") == null);
}
