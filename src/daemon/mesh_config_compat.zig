// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mesh config and cloak compatibility diagnostics.
//!
//! Two Mooring-secured peers each send one bounded `OCC1` record that
//! describes the config facts which must agree across a mesh for cloaks,
//! WARD host/subnet bans and link policy to federate. The receiver compares
//! the record with its own profile and keeps a fixed-size `Report`: a status,
//! an optional unknown reason and a set of fixed finding ids. Each id maps to
//! a fixed severity and a fixed remediation text.
//!
//! Secrets never leave the node. The cloak secret (and the previous secret
//! during a rotation) is represented only by an HMAC-SHA256 proof keyed by
//! that secret over the link binding and the record body. The body binds the
//! sender node key, the receiver node key and a sender nonce, so a proof is
//! useless at any other receiver, cannot be reflected back to its author, and
//! does not repeat across sends. A peer that does not know the secret cannot
//! produce a matching proof. Proof bytes, nonces, keys and the peer's suffix
//! or network name never enter a `Report`, so a rendered report cannot
//! contain them.
//!
//! Records are accepted only from a secured link: the caller passes the
//! Mooring-authenticated peer node key, and a record whose sender or receiver
//! binding differs is classified `unknown`/`misbound` rather than compared.
//! The link binding (`deriveLinkBinding`) is derived from the Mooring session
//! root key that only the two endpoints of this session share. It is never
//! transmitted; a record carries a `link_tag` keyed by it, so a record
//! replayed from an earlier session between the same nodes is classified
//! `unknown`/`stale_session` and its proofs are never evaluated.
//! Decoding is strict: wrong magic, unknown version, reserved flag bits,
//! invalid fields, truncation, oversize input and trailing bytes all yield an
//! `unknown` status with a fixed reason. Nothing here allocates.

const std = @import("std");
const cloak = @import("../proto/cloak.zig");
const mesh_report = @import("../proto/mesh_report.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const magic = "OCC1";
pub const version: u8 = 1;
/// Hard wire bound for one record. The largest legal v1 record is far
/// smaller (`max_encoded_len`); the bound is what the frame layer enforces.
pub const max_record_len: usize = 512;
pub const nonce_len: usize = 16;
pub const node_key_len: usize = 32;
pub const proof_len: usize = HmacSha256.mac_length;
pub const link_binding_len: usize = HmacSha256.mac_length;
pub const link_tag_len: usize = HmacSha256.mac_length;
/// Public network name bound. Config does not restrict `[network] name`
/// beyond non-emptiness, so this accepts any non-control byte (UTF-8 names
/// included); the name is compared, never rendered.
pub const max_network_name_len: usize = 128;
/// `cloak.normalizeSuffix` reserves 74 bytes of the 253-byte hostname for the
/// longest generated cloak prefix.
pub const max_suffix_len: usize = cloak.max_hostname_len - 74;

/// Domain labels. New protocol constants.
const proof_domain = "onyx/config-compat/v1/cloak-proof";
const link_tag_domain = "onyx/config-compat/v1/link-tag";
const link_binding_domain = "onyx/config-compat/v1/link-binding";

const flag_cloak_configured: u8 = 1 << 0;
const flag_prev_configured: u8 = 1 << 1;
const flag_opaque: u8 = 1 << 2;
const flag_account: u8 = 1 << 3;
const flag_require_secured: u8 = 1 << 4;
const flag_require_signed_frames: u8 = 1 << 5;
const flags_known: u8 = flag_cloak_configured | flag_prev_configured | flag_opaque | flag_account |
    flag_require_secured | flag_require_signed_frames;

const fixed_head_len: usize = magic.len + 1 + 1 + 8 + node_key_len + node_key_len + nonce_len;
pub const max_encoded_len: usize = fixed_head_len + 1 + max_suffix_len + 1 + max_network_name_len + link_tag_len + 2 * proof_len;

comptime {
    std.debug.assert(max_encoded_len <= max_record_len);
}

/// The local config facts that must agree across the mesh. Built by the
/// daemon from its live config for one send or one evaluation, then dropped.
/// `cloak_key`/`cloak_prev_key` are borrowed secret material; callers keep
/// them in the owning config and must not log this struct.
pub const LocalProfile = struct {
    cloak_key: ?cloak.SecretKey = null,
    cloak_prev_key: ?cloak.SecretKey = null,
    /// Any `cloak.normalizeSuffix`-valid suffix; it is lowercased on the wire
    /// and compared case-insensitively, exactly as DNS names compare.
    cloak_suffix: []const u8 = cloak.default_suffix,
    cloak_opaque: bool = false,
    cloak_account: bool = false,
    cloak_anon_epoch_secs: u64 = 0,
    require_secured: bool = false,
    require_signed_frames: bool = true,
    /// Public network name; 1..`max_network_name_len` non-control bytes.
    network_name: []const u8 = "Onyx",

    fn valid(self: *const LocalProfile) bool {
        if (self.cloak_prev_key != null and self.cloak_key == null) return false;
        return validSuffix(self.cloak_suffix) and validNetworkName(self.network_name);
    }

    fn flags(self: *const LocalProfile) u8 {
        var f: u8 = 0;
        if (self.cloak_key != null) f |= flag_cloak_configured;
        if (self.cloak_prev_key != null) f |= flag_prev_configured;
        if (self.cloak_opaque) f |= flag_opaque;
        if (self.cloak_account) f |= flag_account;
        if (self.require_secured) f |= flag_require_secured;
        if (self.require_signed_frames) f |= flag_require_signed_frames;
        return f;
    }
};

fn validSuffix(suffix: []const u8) bool {
    if (suffix.len == 0 or suffix.len > max_suffix_len) return false;
    var buf: [max_suffix_len]u8 = undefined;
    _ = cloak.normalizeSuffix(&buf, suffix) catch return false;
    return true;
}

/// Wire form: valid and already lowercase, so equal suffixes are equal bytes.
fn validWireSuffix(suffix: []const u8) bool {
    if (!validSuffix(suffix)) return false;
    for (suffix) |c| if (std.ascii.isUpper(c)) return false;
    return true;
}

fn validNetworkName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_network_name_len) return false;
    for (name) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

/// Per-session binding key for config-compat records. `root_key` is the
/// Mooring session root key, identical at both endpoints and fixed for the
/// session's lifetime (including Helix resume). The result is secret: never
/// log or transmit it, and wipe it after use.
pub fn deriveLinkBinding(root_key: []const u8) [link_binding_len]u8 {
    var out: [link_binding_len]u8 = undefined;
    HmacSha256.create(&out, link_binding_domain, root_key);
    return out;
}

pub const EncodeError = error{ InvalidProfile, InvalidBinding };

/// Encode the v1 record addressed from `local_node_key` to `remote_node_key`
/// on the session identified by `link_binding`. `nonce` must be fresh random
/// bytes per send. Returns a slice of `out`; on error `out` holds no record.
pub fn encodeRecord(
    profile: *const LocalProfile,
    local_node_key: [node_key_len]u8,
    remote_node_key: [node_key_len]u8,
    link_binding: *const [link_binding_len]u8,
    nonce: [nonce_len]u8,
    out: *[max_record_len]u8,
) EncodeError![]const u8 {
    if (!profile.valid()) return error.InvalidProfile;
    if (std.mem.eql(u8, &local_node_key, &remote_node_key)) return error.InvalidBinding;

    var n: usize = 0;
    put(out, &n, magic);
    put(out, &n, &.{ version, profile.flags() });
    std.mem.writeInt(u64, out[n..][0..8], profile.cloak_anon_epoch_secs, .little);
    n += 8;
    put(out, &n, &local_node_key);
    put(out, &n, &remote_node_key);
    put(out, &n, &nonce);
    put(out, &n, &.{@intCast(profile.cloak_suffix.len)});
    for (profile.cloak_suffix) |c| put(out, &n, &.{std.ascii.toLower(c)});
    put(out, &n, &.{@intCast(profile.network_name.len)});
    put(out, &n, profile.network_name);

    const body_len = n;
    linkTag(link_binding, out[0..body_len], out[n..][0..link_tag_len]);
    n += link_tag_len;
    if (profile.cloak_key) |*key| {
        proof(key, link_binding, out[0..body_len], out[n..][0..proof_len]);
        n += proof_len;
    }
    if (profile.cloak_prev_key) |*key| {
        proof(key, link_binding, out[0..body_len], out[n..][0..proof_len]);
        n += proof_len;
    }
    return out[0..n];
}

fn put(out: *[max_record_len]u8, n: *usize, bytes: []const u8) void {
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

/// The link binding is mixed into every proof so a proof cannot be lifted
/// from an earlier session's record into a fresh record on this session.
fn proof(key: *const cloak.SecretKey, link_binding: *const [link_binding_len]u8, body: []const u8, out: *[proof_len]u8) void {
    var mac = HmacSha256.init(&key.bytes);
    mac.update(proof_domain);
    mac.update(link_binding);
    mac.update(body);
    mac.final(out);
    std.crypto.secureZero(u8, std.mem.asBytes(&mac));
}

fn linkTag(link_binding: *const [link_binding_len]u8, body: []const u8, out: *[link_tag_len]u8) void {
    var mac = HmacSha256.init(link_binding);
    mac.update(link_tag_domain);
    mac.update(body);
    mac.final(out);
    std.crypto.secureZero(u8, std.mem.asBytes(&mac));
}

/// Borrowed view of a strictly decoded record. Slices point into the input.
pub const Record = struct {
    flags: u8,
    anon_epoch_secs: u64,
    sender_key: [node_key_len]u8,
    receiver_key: [node_key_len]u8,
    nonce: [nonce_len]u8,
    suffix: []const u8,
    network_name: []const u8,
    link_tag: [link_tag_len]u8,
    proof_cur: ?[proof_len]u8,
    proof_prev: ?[proof_len]u8,
    /// Bytes covered by the link tag and the proofs.
    body: []const u8,

    fn has(self: *const Record, flag: u8) bool {
        return self.flags & flag != 0;
    }
};

pub const DecodeError = error{ Oversize, Truncated, BadMagic, UnsupportedVersion, ReservedFlags, InvalidField, TrailingBytes };

pub fn decodeRecord(bytes: []const u8) DecodeError!Record {
    if (bytes.len > max_record_len) return error.Oversize;
    var r = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, try r.take(magic.len), magic)) return error.BadMagic;
    if ((try r.take(1))[0] != version) return error.UnsupportedVersion;
    const flags = (try r.take(1))[0];
    if (flags & ~flags_known != 0) return error.ReservedFlags;
    if (flags & flag_prev_configured != 0 and flags & flag_cloak_configured == 0) return error.InvalidField;
    const anon_epoch_secs = std.mem.readInt(u64, (try r.take(8))[0..8], .little);
    const sender_key = (try r.take(node_key_len))[0..node_key_len].*;
    const receiver_key = (try r.take(node_key_len))[0..node_key_len].*;
    const nonce = (try r.take(nonce_len))[0..nonce_len].*;
    const suffix = try r.take((try r.take(1))[0]);
    if (!validWireSuffix(suffix)) return error.InvalidField;
    const network_name = try r.take((try r.take(1))[0]);
    if (!validNetworkName(network_name)) return error.InvalidField;
    const body = bytes[0..r.pos];
    const link_tag = (try r.take(link_tag_len))[0..link_tag_len].*;
    const proof_cur: ?[proof_len]u8 = if (flags & flag_cloak_configured != 0) (try r.take(proof_len))[0..proof_len].* else null;
    const proof_prev: ?[proof_len]u8 = if (flags & flag_prev_configured != 0) (try r.take(proof_len))[0..proof_len].* else null;
    if (r.pos != bytes.len) return error.TrailingBytes;
    return .{
        .flags = flags,
        .anon_epoch_secs = anon_epoch_secs,
        .sender_key = sender_key,
        .receiver_key = receiver_key,
        .nonce = nonce,
        .suffix = suffix,
        .network_name = network_name,
        .link_tag = link_tag,
        .proof_cur = proof_cur,
        .proof_prev = proof_prev,
        .body = body,
    };
}

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) DecodeError![]const u8 {
        if (self.bytes.len - self.pos < len) return error.Truncated;
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }
};

pub const Severity = enum {
    /// Works today; fix before the next maintenance step.
    advisory,
    /// Link policy differs between the nodes; behavior is asymmetric.
    degraded,
    /// The nodes show different cloaks for the same client or cannot
    /// federate host/subnet bans.
    breaks_identity,
};

pub const FindingId = enum {
    cloak_secret_mismatch,
    cloak_rotation_skew,
    cloak_secret_missing_local,
    cloak_secret_missing_peer,
    cloak_suffix_mismatch,
    cloak_mode_mismatch,
    cloak_account_mismatch,
    cloak_cadence_mismatch,
    require_secured_mismatch,
    require_signed_frames_mismatch,
    network_name_mismatch,

    pub fn severity(self: FindingId) Severity {
        return switch (self) {
            .cloak_rotation_skew => .advisory,
            .require_secured_mismatch, .require_signed_frames_mismatch, .network_name_mismatch => .degraded,
            .cloak_secret_mismatch,
            .cloak_secret_missing_local,
            .cloak_secret_missing_peer,
            .cloak_suffix_mismatch,
            .cloak_mode_mismatch,
            .cloak_account_mismatch,
            .cloak_cadence_mismatch,
            => .breaks_identity,
        };
    }

    pub fn remediation(self: FindingId) []const u8 {
        return switch (self) {
            .cloak_secret_mismatch => "set the same [cloak] secret on every mesh node",
            .cloak_rotation_skew => "finish the [cloak] secret rotation on every mesh node; keep the old secret as [cloak] previous_secret until all nodes use the new one",
            .cloak_secret_missing_local => "set the shared [cloak] secret on this node",
            .cloak_secret_missing_peer => "set the shared [cloak] secret on the peer node",
            .cloak_suffix_mismatch => "set the same [cloak] suffix on every mesh node",
            .cloak_mode_mismatch => "set the same [cloak] mode on every mesh node",
            .cloak_account_mismatch => "set the same [cloak] account_cloak on every mesh node",
            .cloak_cadence_mismatch => "set the same [cloak] anon_epoch_secs on every mesh node",
            .require_secured_mismatch => "set the same [mesh] require_secured on every mesh node",
            .require_signed_frames_mismatch => "set the same [mesh] require_signed_frames on every mesh node",
            .network_name_mismatch => "set the same [network] name on every mesh node",
        };
    }
};

pub const FindingSet = std.EnumSet(FindingId);

pub const Status = enum { unknown, compatible, advisory, mismatch };

pub const UnknownReason = enum {
    none,
    /// No record has been received on this link (old peer or not yet sent).
    not_received,
    malformed,
    unsupported_version,
    /// Sender is not the authenticated peer, or the record is for another
    /// receiver (relayed or reflected).
    misbound,
    /// Correctly addressed, but bound to a different Mooring session
    /// (replayed from an earlier connection between the same nodes).
    stale_session,
    /// The local profile itself is not encodable; nothing was compared.
    local_profile_invalid,
};

/// Fixed-size per-link outcome. Holds no slices and no peer-supplied bytes.
pub const Report = struct {
    status: Status = .unknown,
    reason: UnknownReason = .not_received,
    findings: FindingSet = .empty,

    pub const not_received: Report = .{};

    pub fn unknown(reason: UnknownReason) Report {
        return .{ .status = .unknown, .reason = reason };
    }

    fn fromFindings(findings: FindingSet) Report {
        var status: Status = .compatible;
        var it = findings.iterator();
        while (it.next()) |id| {
            status = if (id.severity() == .advisory) .advisory else .mismatch;
            if (status == .mismatch) break;
        }
        return .{ .status = status, .reason = .none, .findings = findings };
    }

    pub fn meshStatus(self: Report) mesh_report.Status.ConfigCompat {
        return switch (self.status) {
            .unknown => .unknown,
            .compatible => .compatible,
            .advisory => .advisory,
            .mismatch => .mismatch,
        };
    }
};

/// Compare a peer record with the local profile. `peer_node_key` and
/// `link_binding` must come from the Mooring session the record arrived on.
pub fn evaluate(
    local: *const LocalProfile,
    local_node_key: [node_key_len]u8,
    peer_node_key: [node_key_len]u8,
    link_binding: *const [link_binding_len]u8,
    record_bytes: []const u8,
) Report {
    if (!local.valid()) return .unknown(.local_profile_invalid);
    const rec = decodeRecord(record_bytes) catch |err| return .unknown(switch (err) {
        error.UnsupportedVersion => .unsupported_version,
        else => .malformed,
    });
    if (!std.mem.eql(u8, &rec.sender_key, &peer_node_key) or
        !std.mem.eql(u8, &rec.receiver_key, &local_node_key) or
        std.mem.eql(u8, &peer_node_key, &local_node_key))
        return .unknown(.misbound);
    var expect_tag: [link_tag_len]u8 = undefined;
    linkTag(link_binding, rec.body, &expect_tag);
    if (!std.crypto.timing_safe.eql([link_tag_len]u8, rec.link_tag, expect_tag))
        return .unknown(.stale_session);

    var findings: FindingSet = .empty;
    if (secretFinding(local, link_binding, &rec)) |id| findings.insert(id);
    // The wire suffix is lowercase; the local one may be mixed case.
    if (!std.ascii.eqlIgnoreCase(rec.suffix, local.cloak_suffix)) findings.insert(.cloak_suffix_mismatch);
    if (rec.has(flag_opaque) != local.cloak_opaque) findings.insert(.cloak_mode_mismatch);
    if (rec.has(flag_account) != local.cloak_account) findings.insert(.cloak_account_mismatch);
    if (rec.anon_epoch_secs != local.cloak_anon_epoch_secs) findings.insert(.cloak_cadence_mismatch);
    if (rec.has(flag_require_secured) != local.require_secured) findings.insert(.require_secured_mismatch);
    if (rec.has(flag_require_signed_frames) != local.require_signed_frames) findings.insert(.require_signed_frames_mismatch);
    if (!std.mem.eql(u8, rec.network_name, local.network_name)) findings.insert(.network_name_mismatch);
    return .fromFindings(findings);
}

fn secretFinding(local: *const LocalProfile, link_binding: *const [link_binding_len]u8, rec: *const Record) ?FindingId {
    const peer_cur = rec.proof_cur orelse
        return if (local.cloak_key != null) .cloak_secret_missing_peer else null;
    const local_key: *const cloak.SecretKey = if (local.cloak_key) |*key| key else return .cloak_secret_missing_local;

    var expect_cur: [proof_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &expect_cur);
    proof(local_key, link_binding, rec.body, &expect_cur);
    // Evaluate every comparison so timing does not reveal which key matched.
    const cur_cur = std.crypto.timing_safe.eql([proof_len]u8, peer_cur, expect_cur);
    const peer_prev_cur = if (rec.proof_prev) |p| std.crypto.timing_safe.eql([proof_len]u8, p, expect_cur) else false;
    var cur_prev = false;
    if (local.cloak_prev_key) |*prev| {
        var expect_prev: [proof_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &expect_prev);
        proof(prev, link_binding, rec.body, &expect_prev);
        cur_prev = std.crypto.timing_safe.eql([proof_len]u8, peer_cur, expect_prev);
    }
    if (cur_cur) return null;
    if (cur_prev or peer_prev_cur) return .cloak_rotation_skew;
    return .cloak_secret_mismatch;
}

pub const RenderError = error{NameTooLong};

/// Operator-only lines for one peer. `peer_name` is the daemon's link name;
/// it is sanitized like `mesh_report.renderStatus`. Every other byte comes
/// from fixed tables, so secrets, proofs, nonces and peer-supplied suffix or
/// network-name text cannot appear in the output.
pub fn renderReport(report: Report, peer_name: []const u8, w: anytype) !void {
    if (peer_name.len > mesh_report.Status.max_name_bytes) return error.NameTooLong;
    try w.writeAll("config-compat peer=");
    try writeName(w, peer_name);
    try w.print(" status={s}", .{@tagName(report.status)});
    if (report.status == .unknown) {
        try w.print(" reason={s}\n", .{@tagName(report.reason)});
        return;
    }
    try w.print(" findings={d}\n", .{report.findings.count()});
    var it = report.findings.iterator();
    while (it.next()) |id| {
        try w.writeAll("config-compat peer=");
        try writeName(w, peer_name);
        try w.print(" finding={s} severity={s} fix={s}\n", .{ @tagName(id), @tagName(id.severity()), id.remediation() });
    }
}

/// Upper bound of `renderReport` output for any report and any accepted peer
/// name, so a caller can render into a fixed buffer without truncation.
pub const max_render_len: usize = blk: {
    const prefix = "config-compat peer=".len + mesh_report.Status.max_name_bytes;
    var longest_status: usize = 0;
    for (std.meta.fieldNames(Status)) |name| longest_status = @max(longest_status, name.len);
    var longest_reason: usize = 0;
    for (std.meta.fieldNames(UnknownReason)) |name| longest_reason = @max(longest_reason, name.len);
    const finding_count_digits = std.fmt.count("{d}", .{std.enums.values(FindingId).len});
    var total: usize = prefix + " status=".len + longest_status +
        @max(" reason=".len + longest_reason, " findings=".len + finding_count_digits) + 1;
    for (std.enums.values(FindingId)) |id| {
        total += prefix + " finding=".len + @tagName(id).len + " severity=".len +
            @tagName(id.severity()).len + " fix=".len + id.remediation().len + 1;
    }
    break :blk total;
};

fn writeName(w: anytype, name: []const u8) !void {
    if (name.len == 0) return w.writeByte('-');
    for (name) |c| try w.writeByte(if (c >= 33 and c <= 126 and c != '=') c else '?');
}

// --- tests -----------------------------------------------------------------

const testing = std.testing;

const key_a: [32]u8 = @splat(0xA1);
const key_b: [32]u8 = @splat(0xB2);
const key_c: [32]u8 = @splat(0xC3);
const secret_1 = cloak.SecretKey.init(@splat(0x11));
const secret_2 = cloak.SecretKey.init(@splat(0x22));
const secret_3 = cloak.SecretKey.init(@splat(0x33));
const nonce_1: [16]u8 = @splat(0x5A);
const nonce_2: [16]u8 = @splat(0x6B);
const bind_1: [link_binding_len]u8 = @splat(0x7E);
const bind_2: [link_binding_len]u8 = @splat(0x7F);

fn baseProfile() LocalProfile {
    return .{ .cloak_key = secret_1, .cloak_suffix = "onyx", .network_name = "Onyx" };
}

/// Record from `sender` (profile `p`) evaluated at `receiver` (profile `l`).
fn exchange(p: LocalProfile, l: LocalProfile) !Report {
    var buf: [max_record_len]u8 = undefined;
    const rec = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf);
    return evaluate(&l, key_b, key_a, &bind_1, rec);
}

fn expectOnly(report: Report, id: FindingId) !void {
    try testing.expectEqual(@as(usize, 1), report.findings.count());
    try testing.expect(report.findings.contains(id));
    try testing.expectEqual(UnknownReason.none, report.reason);
}

test "mesh_config_compat: identical profiles verify as compatible in both directions" {
    var p = baseProfile();
    p.cloak_prev_key = secret_2;
    p.cloak_opaque = true;
    p.cloak_account = true;
    p.cloak_anon_epoch_secs = 3600;
    p.require_secured = true;
    var buf: [max_record_len]u8 = undefined;
    const ab = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf);
    const at_b = evaluate(&p, key_b, key_a, &bind_1, ab);
    try testing.expectEqual(Status.compatible, at_b.status);
    try testing.expectEqual(UnknownReason.none, at_b.reason);
    try testing.expectEqual(@as(usize, 0), at_b.findings.count());
    const ba = try encodeRecord(&p, key_b, key_a, &bind_1, nonce_2, &buf);
    const at_a = evaluate(&p, key_a, key_b, &bind_1, ba);
    try testing.expectEqual(Status.compatible, at_a.status);
    try testing.expectEqual(mesh_report.Status.ConfigCompat.compatible, at_a.meshStatus());

    // Both sides without any cloak secret is consistent, not a finding.
    const plain: LocalProfile = .{};
    try testing.expectEqual(Status.compatible, (try exchange(plain, plain)).status);
}

test "mesh_config_compat: different cloak secrets report cloak_secret_mismatch with breaks_identity severity and remediation text" {
    var peer = baseProfile();
    peer.cloak_key = secret_2;
    const report = try exchange(peer, baseProfile());
    try testing.expectEqual(Status.mismatch, report.status);
    try expectOnly(report, .cloak_secret_mismatch);
    try testing.expectEqual(Severity.breaks_identity, FindingId.cloak_secret_mismatch.severity());
    try testing.expectEqualStrings("set the same [cloak] secret on every mesh node", FindingId.cloak_secret_mismatch.remediation());

    // A peer that copies an honest node's proof into its own record cannot
    // claim the secret: the proof binds the honest sender's key.
    var honest_buf: [max_record_len]u8 = undefined;
    const honest = try encodeRecord(&baseProfile(), key_c, key_b, &bind_1, nonce_1, &honest_buf);
    var forged_buf: [max_record_len]u8 = undefined;
    const forged_len = (try encodeRecord(&peer, key_a, key_b, &bind_1, nonce_1, &forged_buf)).len;
    @memcpy(forged_buf[forged_len - proof_len ..][0..proof_len], honest[honest.len - proof_len ..]);
    try expectOnly(evaluate(&baseProfile(), key_b, key_a, &bind_1, forged_buf[0..forged_len]), .cloak_secret_mismatch);
}

test "mesh_config_compat: peer current == local previous reports cloak_rotation_skew (advisory) instead of hard mismatch" {
    // Local rotated to secret_2 (previous secret_1); peer still on secret_1.
    var local = baseProfile();
    local.cloak_key = secret_2;
    local.cloak_prev_key = secret_1;
    const lagging = try exchange(baseProfile(), local);
    try testing.expectEqual(Status.advisory, lagging.status);
    try expectOnly(lagging, .cloak_rotation_skew);
    try testing.expectEqual(Severity.advisory, FindingId.cloak_rotation_skew.severity());
    try testing.expectEqual(mesh_report.Status.ConfigCompat.advisory, lagging.meshStatus());

    // Mirror: peer rotated (previous == local current), local has not.
    const ahead = try exchange(local, baseProfile());
    try expectOnly(ahead, .cloak_rotation_skew);

    // A previous secret that matches neither side is still a hard mismatch.
    var stranger = baseProfile();
    stranger.cloak_key = secret_3;
    stranger.cloak_prev_key = secret_2;
    try expectOnly(try exchange(stranger, baseProfile()), .cloak_secret_mismatch);
}

test "mesh_config_compat: missing local/peer secret reports cloak_secret_missing_local/peer" {
    var none = baseProfile();
    none.cloak_key = null;
    const missing_peer = try exchange(none, baseProfile());
    try testing.expectEqual(Status.mismatch, missing_peer.status);
    try expectOnly(missing_peer, .cloak_secret_missing_peer);
    try expectOnly(try exchange(baseProfile(), none), .cloak_secret_missing_local);
}

test "mesh_config_compat: suffix/mode/account/cadence/require_secured/require_signed_frames/network_name mismatches each map to their fixed id" {
    const Case = struct { id: FindingId, severity: Severity };
    const cases = [_]Case{
        .{ .id = .cloak_suffix_mismatch, .severity = .breaks_identity },
        .{ .id = .cloak_mode_mismatch, .severity = .breaks_identity },
        .{ .id = .cloak_account_mismatch, .severity = .breaks_identity },
        .{ .id = .cloak_cadence_mismatch, .severity = .breaks_identity },
        .{ .id = .require_secured_mismatch, .severity = .degraded },
        .{ .id = .require_signed_frames_mismatch, .severity = .degraded },
        .{ .id = .network_name_mismatch, .severity = .degraded },
    };
    for (cases) |case| {
        var peer = baseProfile();
        switch (case.id) {
            .cloak_suffix_mismatch => peer.cloak_suffix = "other.net",
            .cloak_mode_mismatch => peer.cloak_opaque = true,
            .cloak_account_mismatch => peer.cloak_account = true,
            .cloak_cadence_mismatch => peer.cloak_anon_epoch_secs = 86_400,
            .require_secured_mismatch => peer.require_secured = true,
            .require_signed_frames_mismatch => peer.require_signed_frames = false,
            .network_name_mismatch => peer.network_name = "OtherNet",
            else => unreachable,
        }
        const report = try exchange(peer, baseProfile());
        try expectOnly(report, case.id);
        try testing.expectEqual(case.severity, case.id.severity());
        try testing.expectEqual(Status.mismatch, report.status);
        try testing.expect(case.id.remediation().len != 0);
    }

    // Several differences accumulate; the strongest severity sets the status.
    var many = baseProfile();
    many.cloak_key = secret_2;
    many.network_name = "OtherNet";
    many.require_secured = true;
    const report = try exchange(many, baseProfile());
    try testing.expectEqual(@as(usize, 3), report.findings.count());
    try testing.expectEqual(Status.mismatch, report.status);
}

test "mesh_config_compat: proof bound to node keys and nonce (record for receiver X fails verification at receiver Y; changed nonce changes proof)" {
    const p = baseProfile();
    var buf: [max_record_len]u8 = undefined;
    const for_b = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf);

    // Relayed to a different receiver C by any node: misbound, never compared.
    const at_c = evaluate(&p, key_c, key_a, &bind_1, for_b);
    try testing.expectEqual(Status.unknown, at_c.status);
    try testing.expectEqual(UnknownReason.misbound, at_c.reason);
    try testing.expectEqual(@as(usize, 0), at_c.findings.count());
    // Delivered by a link whose authenticated peer is not the sender.
    try testing.expectEqual(UnknownReason.misbound, evaluate(&p, key_b, key_c, &bind_1, for_b).reason);
    // Reflected back to its author.
    try testing.expectEqual(UnknownReason.misbound, evaluate(&p, key_a, key_b, &bind_1, for_b).reason);
    // Self-addressed records are refused on both ends.
    try testing.expectError(error.InvalidBinding, encodeRecord(&p, key_a, key_a, &bind_1, nonce_1, &buf));

    // Rewriting the receiver field to C breaks the session link tag.
    var relabeled: [max_record_len]u8 = undefined;
    const len = (try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &relabeled)).len;
    @memcpy(relabeled[magic.len + 10 + node_key_len ..][0..node_key_len], &key_c);
    try testing.expectEqual(UnknownReason.stale_session, evaluate(&p, key_c, key_a, &bind_1, relabeled[0..len]).reason);
    // Even with a valid link tag recomputed for the rewritten body, the proof
    // does not follow the receiver change.
    const body_len = len - link_tag_len - proof_len;
    linkTag(&bind_1, relabeled[0..body_len], relabeled[body_len..][0..link_tag_len]);
    try expectOnly(evaluate(&p, key_c, key_a, &bind_1, relabeled[0..len]), .cloak_secret_mismatch);

    // A different nonce yields a different proof for the same key and binding.
    var buf1: [max_record_len]u8 = undefined;
    var buf2: [max_record_len]u8 = undefined;
    const r1 = try decodeRecord(try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf1));
    const r2 = try decodeRecord(try encodeRecord(&p, key_a, key_b, &bind_1, nonce_2, &buf2));
    try testing.expect(!std.mem.eql(u8, &r1.proof_cur.?, &r2.proof_cur.?));
    try testing.expectEqualSlices(u8, &nonce_2, &r2.nonce);
    // A different receiver key yields a different proof.
    var buf3: [max_record_len]u8 = undefined;
    const r3 = try decodeRecord(try encodeRecord(&p, key_a, key_c, &bind_1, nonce_1, &buf3));
    try testing.expect(!std.mem.eql(u8, &r1.proof_cur.?, &r3.proof_cur.?));
}

test "mesh_config_compat: record replayed from another Mooring session is stale and never compared" {
    const p = baseProfile();
    var buf: [max_record_len]u8 = undefined;
    const old = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf);
    const replayed = evaluate(&p, key_b, key_a, &bind_2, old);
    try testing.expectEqual(Status.unknown, replayed.status);
    try testing.expectEqual(UnknownReason.stale_session, replayed.reason);
    try testing.expectEqual(@as(usize, 0), replayed.findings.count());

    // A peer that lost the secret cannot lift its old proof into a fresh
    // record for the new session: the proof binds the session too.
    var none = p;
    none.cloak_key = null;
    var fresh_buf: [max_record_len + proof_len]u8 = undefined;
    const fresh = try encodeRecord(&none, key_a, key_b, &bind_2, nonce_1, fresh_buf[0..max_record_len]);
    // Re-flag the fresh record as cloak-configured; its body still equals the
    // old body because flags, keys, nonce and fields are identical.
    fresh_buf[5] |= flag_cloak_configured;
    const body_len = fresh.len - link_tag_len;
    linkTag(&bind_2, fresh_buf[0..body_len], fresh_buf[body_len..][0..link_tag_len]);
    @memcpy(fresh_buf[fresh.len..][0..proof_len], old[old.len - proof_len ..]);
    try testing.expectEqualSlices(u8, old[0..body_len], fresh_buf[0..body_len]);
    try expectOnly(evaluate(&p, key_b, key_a, &bind_2, fresh_buf[0 .. fresh.len + proof_len]), .cloak_secret_mismatch);

    // The binding is a keyed derivation of the session root key.
    const root_1: [32]u8 = @splat(0x01);
    const root_2: [32]u8 = @splat(0x02);
    const b1 = deriveLinkBinding(&root_1);
    try testing.expectEqualSlices(u8, &b1, &deriveLinkBinding(&root_1));
    try testing.expect(!std.mem.eql(u8, &b1, &deriveLinkBinding(&root_2)));
    try testing.expect(!std.mem.eql(u8, &b1, &root_1));
}

test "mesh_config_compat: suffix compares as a DNS name and network names accept any non-control byte" {
    var mixed = baseProfile();
    mixed.cloak_suffix = "Onyx.NET";
    var lower = baseProfile();
    lower.cloak_suffix = "onyx.net";
    var buf: [max_record_len]u8 = undefined;
    const rec = try decodeRecord(try encodeRecord(&mixed, key_a, key_b, &bind_1, nonce_1, &buf));
    try testing.expectEqualStrings("onyx.net", rec.suffix);
    try testing.expectEqual(Status.compatible, (try exchange(mixed, lower)).status);
    try testing.expectEqual(Status.compatible, (try exchange(lower, mixed)).status);

    var spaced = baseProfile();
    spaced.network_name = "Onyx Net \xc3\xa9";
    try testing.expectEqual(Status.compatible, (try exchange(spaced, spaced)).status);
    try expectOnly(try exchange(spaced, baseProfile()), .network_name_mismatch);

    var invalid = baseProfile();
    invalid.network_name = "Onyx\r\nNet";
    try testing.expectError(error.InvalidProfile, encodeRecord(&invalid, key_a, key_b, &bind_1, nonce_1, &buf));
    invalid.network_name = "";
    try testing.expectError(error.InvalidProfile, encodeRecord(&invalid, key_a, key_b, &bind_1, nonce_1, &buf));
}

test "mesh_config_compat: decode rejects trailing bytes, oversize, truncated, unknown version -> unknown status" {
    var p = baseProfile();
    p.cloak_prev_key = secret_2;
    var buf: [max_record_len + 1]u8 = undefined;
    const good = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, buf[0..max_record_len]);
    const n = good.len;
    try testing.expect(n <= max_encoded_len);
    try testing.expectEqual(Status.compatible, evaluate(&p, key_b, key_a, &bind_1, buf[0..n]).status);

    buf[n] = 0;
    try testing.expectError(error.TrailingBytes, decodeRecord(buf[0 .. n + 1]));
    try testing.expectEqual(UnknownReason.malformed, evaluate(&p, key_b, key_a, &bind_1, buf[0 .. n + 1]).reason);

    var big: [max_record_len + 1]u8 = @splat(0);
    @memcpy(big[0..n], buf[0..n]);
    try testing.expectError(error.Oversize, decodeRecord(&big));

    var cut: usize = 0;
    while (cut < n) : (cut += 1) {
        // Every field is length-checked before validation, so any cut is
        // reported as truncation rather than as a short valid-looking field.
        try testing.expectError(error.Truncated, decodeRecord(buf[0..cut]));
        const r = evaluate(&p, key_b, key_a, &bind_1, buf[0..cut]);
        try testing.expectEqual(Status.unknown, r.status);
        try testing.expectEqual(UnknownReason.malformed, r.reason);
    }

    var bad: [max_record_len]u8 = undefined;
    @memcpy(bad[0..n], buf[0..n]);
    bad[4] = 2;
    try testing.expectError(error.UnsupportedVersion, decodeRecord(bad[0..n]));
    const v2 = evaluate(&p, key_b, key_a, &bind_1, bad[0..n]);
    try testing.expectEqual(Status.unknown, v2.status);
    try testing.expectEqual(UnknownReason.unsupported_version, v2.reason);

    @memcpy(bad[0..n], buf[0..n]);
    bad[0] = 'X';
    try testing.expectError(error.BadMagic, decodeRecord(bad[0..n]));
    @memcpy(bad[0..n], buf[0..n]);
    bad[5] |= 0x80;
    try testing.expectError(error.ReservedFlags, decodeRecord(bad[0..n]));
    @memcpy(bad[0..n], buf[0..n]);
    bad[5] &= ~flag_cloak_configured;
    try testing.expectError(error.InvalidField, decodeRecord(bad[0..n]));
    // Uppercase suffix is not normalized and is rejected.
    @memcpy(bad[0..n], buf[0..n]);
    bad[fixed_head_len + 1] = 'O';
    try testing.expectError(error.InvalidField, decodeRecord(bad[0..n]));
    try testing.expectEqual(Status.unknown, evaluate(&p, key_b, key_a, &bind_1, &.{}).status);
    try testing.expectEqual(Report.not_received, Report{});

    // Invalid local profiles are refused before anything is compared.
    var invalid = baseProfile();
    invalid.cloak_suffix = "Bad Suffix";
    try testing.expectError(error.InvalidProfile, encodeRecord(&invalid, key_a, key_b, &bind_1, nonce_1, buf[0..max_record_len]));
    try testing.expectEqual(UnknownReason.local_profile_invalid, evaluate(&invalid, key_b, key_a, &bind_1, good).reason);
    invalid = .{ .cloak_prev_key = secret_2 };
    try testing.expectError(error.InvalidProfile, encodeRecord(&invalid, key_a, key_b, &bind_1, nonce_1, buf[0..max_record_len]));
    const long_name: [max_network_name_len + 1]u8 = @splat('N');
    invalid = .{ .network_name = &long_name };
    try testing.expectError(error.InvalidProfile, encodeRecord(&invalid, key_a, key_b, &bind_1, nonce_1, buf[0..max_record_len]));
}

test "mesh_config_compat: largest legal record stays within the wire bound" {
    var p = baseProfile();
    p.cloak_prev_key = secret_2;
    const label: [63]u8 = @splat('s');
    var suffix_buf: [max_suffix_len]u8 = undefined;
    var n: usize = 0;
    while (n + label.len + 1 <= max_suffix_len) {
        if (n != 0) {
            suffix_buf[n] = '.';
            n += 1;
        }
        @memcpy(suffix_buf[n..][0..label.len], &label);
        n += label.len;
    }
    p.cloak_suffix = suffix_buf[0..n];
    const name: [max_network_name_len]u8 = @splat('N');
    p.network_name = &name;
    var buf: [max_record_len]u8 = undefined;
    const rec = try encodeRecord(&p, key_a, key_b, &bind_1, nonce_1, &buf);
    try testing.expect(rec.len <= max_record_len);
    try testing.expectEqual(Status.compatible, evaluate(&p, key_b, key_a, &bind_1, rec).status);
}

test "mesh_config_compat: rendered summary/finding lines never contain secret bytes, proof bytes, nonce, or peer-supplied suffix/network_name text" {
    var peer = baseProfile();
    peer.cloak_key = secret_2;
    peer.cloak_suffix = "zzleak.example";
    peer.network_name = "QQLEAKNET";
    var rec_buf: [max_record_len]u8 = undefined;
    const rec_bytes = try encodeRecord(&peer, key_a, key_b, &bind_1, nonce_1, &rec_buf);
    const rec = try decodeRecord(rec_bytes);
    const report = evaluate(&baseProfile(), key_b, key_a, &bind_1, rec_bytes);
    try testing.expectEqual(@as(usize, 3), report.findings.count());

    var out: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try renderReport(report, "peer\r\n=x", &w);
    const text = w.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "config-compat peer=peer???x status=mismatch findings=3\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "finding=cloak_secret_mismatch severity=breaks_identity fix=set the same [cloak] secret on every mesh node\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "finding=cloak_suffix_mismatch severity=breaks_identity") != null);
    try testing.expect(std.mem.indexOf(u8, text, "finding=network_name_mismatch severity=degraded") != null);
    try testing.expect(std.mem.indexOf(u8, text, "zzleak") == null);
    try testing.expect(std.mem.indexOf(u8, text, "QQLEAK") == null);
    try testing.expect(std.mem.indexOfScalar(u8, text, '\r') == null);
    for ([_][]const u8{ &secret_1.bytes, &secret_2.bytes, &rec.proof_cur.?, &rec.nonce, &key_a, &key_b }) |needle| {
        try testing.expect(std.mem.indexOf(u8, text, needle[0..8]) == null);
    }
    // Hex renderings of the proof or nonce never appear either.
    const proof_hex = std.fmt.bytesToHex(rec.proof_cur.?[0..8].*, .lower);
    const nonce_hex = std.fmt.bytesToHex(rec.nonce[0..8].*, .lower);
    try testing.expect(std.mem.indexOf(u8, text, &proof_hex) == null);
    try testing.expect(std.mem.indexOf(u8, text, &nonce_hex) == null);

    var uw = std.Io.Writer.fixed(&out);
    try renderReport(.unknown(.misbound), "", &uw);
    try testing.expectEqualStrings("config-compat peer=- status=unknown reason=misbound\n", uw.buffered());

    // Worst case (every finding, longest name) fits `max_render_len` exactly
    // or below; one byte less than the real length must fail.
    var all: Report = .{ .status = .mismatch, .reason = .none, .findings = .full };
    var worst_buf: [max_render_len]u8 = undefined;
    var ww = std.Io.Writer.fixed(&worst_buf);
    const longest_name: [mesh_report.Status.max_name_bytes]u8 = @splat('n');
    try renderReport(all, &longest_name, &ww);
    try testing.expect(ww.buffered().len <= max_render_len);
    var short_buf: [max_render_len]u8 = undefined;
    var sw = std.Io.Writer.fixed(short_buf[0 .. ww.buffered().len - 1]);
    try testing.expectError(error.WriteFailed, renderReport(all, &longest_name, &sw));
    all.findings = .empty;
    all.status = .compatible;
    var cw = std.Io.Writer.fixed(&out);
    try renderReport(all, "ok", &cw);
    try testing.expectEqualStrings("config-compat peer=ok status=compatible findings=0\n", cw.buffered());

    var ow = std.Io.Writer.fixed(&out);
    const long: [mesh_report.Status.max_name_bytes + 1]u8 = @splat('a');
    try testing.expectError(error.NameTooLong, renderReport(report, &long, &ow));
    try testing.expectEqual(@as(usize, 0), ow.buffered().len);
}
