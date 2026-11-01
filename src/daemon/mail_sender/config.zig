// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Borrowed SMTP submission policy and its stable checkpoint digest.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const runtime_pause = @import("../runtime_pause.zig");

/// Submission parameters; all slices are borrowed (owned by the daemon config).
pub const Config = struct {
    relay_host: []const u8,
    relay_port: u16 = 587,
    starttls: bool = true,
    /// Skip relay certificate verification. AUTH over a remote relay is refused
    /// unless this is set or `trust_anchors` is non-empty.
    insecure_skip_verify: bool = false,
    /// DER trust anchors for the relay certificate. Empty means a remote AUTH
    /// session is not verified.
    trust_anchors: []const []const u8 = &.{},
    ehlo_domain: []const u8,
    from: []const u8,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    /// OroStore WAL that receives one props row per failed delivery.
    failure_wal: ?[]const u8 = null,
    failure_io: ?std.Io = null,
    failure_dir: ?std.Io.Dir = null,
    /// Production Windows mail requires a private, handle-bound failure WAL.
    /// Tests can retain the generic store by leaving this false.
    private_failure_windows: bool = false,
};

/// Commits configured value fields. The actual failure-store Io/Dir lineage is
/// separately held by the whole owner; these presence tags do not prove custody.
pub fn configDigest(config: Config) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx/companion/mail-config/v1");
    try runtime_pause.hashBytes(&hash, config.relay_host);
    var numbers: [2]u8 = undefined;
    std.mem.writeInt(u16, &numbers, config.relay_port, .big);
    hash.update(&numbers);
    hash.update(&.{ @intFromBool(config.starttls), @intFromBool(config.insecure_skip_verify) });
    const count = std.math.cast(u32, config.trust_anchors.len) orelse return error.Capacity;
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, count, .big);
    hash.update(&prefix);
    for (config.trust_anchors) |anchor| try runtime_pause.hashBytes(&hash, anchor);
    try runtime_pause.hashBytes(&hash, config.ehlo_domain);
    try runtime_pause.hashBytes(&hash, config.from);
    try runtime_pause.hashOptional(&hash, config.user);
    try runtime_pause.hashOptional(&hash, config.pass);
    try runtime_pause.hashOptional(&hash, config.failure_wal);
    hash.update(&.{ @intFromBool(config.failure_io != null), @intFromBool(config.failure_dir != null) });
    if (config.private_failure_windows) hash.update("windows-private-failure-wal");
    return hash.finalResult();
}
