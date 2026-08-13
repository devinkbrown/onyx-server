// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inactive allocation-free OCG2 reconciliation/expiry schedule.
//!
//! Consumes a fixed canonical `durable_oper_authority.TransactionCopy`
//! inventory and emits advisory account/deadline reinspection hints only.
//! This leaf cannot grant or remove privilege, mutate sessions, own a clock,
//! perform I/O, write durable state, or emit mesh/events/transmit.

const std = @import("std");
const durable_oper_authority = @import("durable_oper_authority.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;
const Sha256 = std.crypto.hash.sha2.Sha256;

const TransactionCopy = durable_oper_authority.TransactionCopy;
const max_account_len = durable_oper_authority.max_account_len;
const max_wire_len = durable_oper_authority.max_wire_len;
const digest_len = durable_oper_authority.digest_len;
const authority_pubkey_len = oper_cred_share.ocg2_pubkey_len;

pub const Phase = enum {
    not_yet_valid,
    active,
    expired,
    tombstone,
    equivocation,
};

pub const InvalidReason = enum {
    account_bounds,
    account_order,
    zero_revision,
    malformed_authority,
    malformed_wire,
    signature_mismatch,
    field_mismatch,
    digest_mismatch,
    temporal_tuple,
    equivocation_tuple,
};

pub const ReinspectHint = struct {
    account_buf: [max_account_len]u8 = @splat(0),
    account_len: usize = 0,
    revision: u64 = 0,
    digest: [digest_len]u8 = @splat(0),
    wire_sha256: [digest_len]u8 = @splat(0),
    phase: Phase = .expired,
    next_transition_ms: ?u64 = null,
};

pub const Summary = struct {
    count: usize,
    earliest_transition_ms: ?u64,
};

pub const BuildResult = union(enum) {
    complete: Summary,
    insufficient_output: usize,
    invalid: struct {
        index: usize,
        reason: InvalidReason,
    },
};

const ParsedWire = struct {
    kind: oper_cred_share.Ocg2Kind,
    authority_node_id: u64,
    revision: u64,
    issued_ms: u64,
    expiry_ms: u64,
    privilege_bits: u64,
    account: []const u8,
    class: []const u8,
    title: []const u8,
    authority_pubkey: [authority_pubkey_len]u8,
};

comptime {
    if (max_account_len != oper_cred_share.ocg2_max_account_len)
        @compileError("S6-C3 account bound is frozen to the C2/OCG2 account width");
    if (max_wire_len != oper_cred_share.ocg2_max_wire_len)
        @compileError("S6-C3 wire bound is frozen to the C2/OCG2 wire width");
    if (digest_len != Blake3.digest_length or digest_len != Sha256.digest_length)
        @compileError("S6-C3 identity width must match BLAKE3 and SHA-256");
    if (oper_cred_share.ocg2_max_ttl_ms != 86_400_000)
        @compileError("S6-C3 temporal bound depends on the frozen 24h OCG2 TTL");
    if (oper_cred_share.ocg2_max_future_skew_ms != 300_000)
        @compileError("S6-C3 future-issue bound depends on the frozen 5-minute OCG2 skew");

    const build_info = @typeInfo(@TypeOf(build)).@"fn";
    if (build_info.param_types.len != 3)
        @compileError("build has a fixed (transactions, security_now_ms, out) surface");
    if (build_info.param_types[0] != []const TransactionCopy)
        @compileError("build consumes the C2 TransactionCopy inventory");
    if (build_info.param_types[1] != u64)
        @compileError("build takes caller-supplied security_now_ms and owns no clock");
    if (build_info.param_types[2] != []ReinspectHint)
        @compileError("build writes inline ReinspectHint values only");
    if (build_info.return_type != BuildResult)
        @compileError("build returns BuildResult");

    for (build_info.param_types) |param_type| {
        if (param_type == std.mem.Allocator)
            @compileError("build must stay allocation-free");
    }

    const hint_info = @typeInfo(ReinspectHint).@"struct";
    const allowed_hint_fields = .{
        "account_buf", "account_len", "revision",           "digest",
        "wire_sha256", "phase",       "next_transition_ms",
    };
    if (hint_info.field_names.len != allowed_hint_fields.len)
        @compileError("ReinspectHint may only carry advisory identity/deadline fields");
    for (hint_info.field_names, hint_info.field_types) |name, field_type| {
        switch (@typeInfo(field_type)) {
            .pointer => @compileError("ReinspectHint must not hold pointers or slices"),
            else => {},
        }
        var allowed = false;
        for (allowed_hint_fields) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed) @compileError("ReinspectHint carries a forbidden field");
    }
    if (hint_info.decl_names.len != 0)
        @compileError("ReinspectHint must not expose methods or nested public declarations");

    const allowed_public_decls = .{
        "Phase",   "InvalidReason", "ReinspectHint",
        "Summary", "BuildResult",   "build",
    };
    const module_decls = @typeInfo(@This()).@"struct".decl_names;
    if (module_decls.len != allowed_public_decls.len)
        @compileError("S6-C3 public surface is an exact six-declaration allowlist");
    for (module_decls) |name| {
        var allowed = false;
        for (allowed_public_decls) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed)
            @compileError("S6-C3 public surface rejected an undeclared public declaration");
    }

    for (.{
        "apply",             "execute",       "grant",
        "revoke",            "mint",          "transmit",
        "session",           "callback",      "executeAuthorized",
        "issue",             "issueGrant",    "issueRevoke",
        "executeGrant",      "executeRevoke", "ProjectionData",
        "DurableOperLookup", "Visitor",       "reconcile",
    }) |name| {
        if (@hasDecl(@This(), name))
            @compileError("OCG2 reconcile schedule must not expose a runtime privilege surface");
    }
}

/// Classify a fully validated C2 copy.  Issue is inclusive and expiry is
/// exclusive.  Equivocation is terminal and outranks every other phase.
/// Deadlines are the exact issued/expiry timestamps; this leaf never adds or
/// subtracts a millisecond.
fn classify(copy: *const TransactionCopy, security_now_ms: u64) struct { Phase, ?u64 } {
    if (copy.equivocation) return .{ .equivocation, null };
    if (copy.kind == .tombstone) return .{ .tombstone, null };
    if (security_now_ms < copy.issued_ms) return .{ .not_yet_valid, copy.issued_ms };
    if (security_now_ms < copy.expiry_ms) return .{ .active, copy.expiry_ms };
    return .{ .expired, null };
}

fn boundedAccount(copy: *const TransactionCopy) ?[]const u8 {
    if (copy.account_len == 0 or copy.account_len > copy.account_buf.len or
        copy.account_len > max_account_len)
        return null;
    return copy.account_buf[0..copy.account_len];
}

fn boundedWire(copy: *const TransactionCopy) ?[]const u8 {
    if (copy.wire_len == 0 or copy.wire_len > copy.wire_buf.len or
        copy.wire_len > max_wire_len)
        return null;
    return copy.wire_buf[0..copy.wire_len];
}

fn canonicalAccount(account: []const u8) bool {
    if (account.len == 0 or account.len > max_account_len) return false;
    for (account) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '-';
        if (!ok) return false;
    }
    return true;
}

fn allZero(bytes: [digest_len]u8) bool {
    return std.mem.allEqual(u8, &bytes, 0);
}

fn take(src: []const u8, pos: *usize, len: usize) ?[]const u8 {
    if (len > src.len -| pos.*) return null;
    const value = src[pos.*..][0..len];
    pos.* += len;
    return value;
}

fn takeByte(src: []const u8, pos: *usize) ?u8 {
    const bytes = take(src, pos, 1) orelse return null;
    return bytes[0];
}

fn takeU64(src: []const u8, pos: *usize) ?u64 {
    const bytes = take(src, pos, 8) orelse return null;
    return std.mem.readInt(u64, bytes[0..8], .big);
}

fn takePrefixed(src: []const u8, pos: *usize) ?[]const u8 {
    const field_len = takeByte(src, pos) orelse return null;
    return take(src, pos, field_len);
}

fn parseWire(wire: []const u8) ?ParsedWire {
    const min_len = oper_cred_share.ocg2_domain.len + 1 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 1 +
        authority_pubkey_len + oper_cred_share.signature_len;
    if (wire.len < min_len) return null;
    if (oper_cred_share.classifyWire(wire) != .ocg2) return null;
    const signed_len = wire.len - oper_cred_share.signature_len;
    if (signed_len < oper_cred_share.ocg2_domain.len) return null;
    const signed = wire[0..signed_len];
    var pos: usize = oper_cred_share.ocg2_domain.len;
    const kind: oper_cred_share.Ocg2Kind = switch (takeByte(signed, &pos) orelse return null) {
        1 => .grant,
        2 => .tombstone,
        else => return null,
    };
    const authority_node_id = takeU64(signed, &pos) orelse return null;
    const revision = takeU64(signed, &pos) orelse return null;
    const issued_ms = takeU64(signed, &pos) orelse return null;
    const expiry_ms = takeU64(signed, &pos) orelse return null;
    const privilege_bits = takeU64(signed, &pos) orelse return null;
    const account = takePrefixed(signed, &pos) orelse return null;
    const class = takePrefixed(signed, &pos) orelse return null;
    const title = takePrefixed(signed, &pos) orelse return null;
    const pubkey_bytes = take(signed, &pos, authority_pubkey_len) orelse return null;
    if (pos != signed_len) return null;
    return .{
        .kind = kind,
        .authority_node_id = authority_node_id,
        .revision = revision,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
        .privilege_bits = privilege_bits,
        .account = account,
        .class = class,
        .title = title,
        .authority_pubkey = pubkey_bytes[0..authority_pubkey_len].*,
    };
}

fn policyReason(err: oper_cred_share.Ocg2Error) InvalidReason {
    return switch (err) {
        error.InvalidAccount => .account_bounds,
        error.InvalidRevision => .zero_revision,
        error.WrongAuthority => .malformed_authority,
        error.InvalidTime, error.Expired => .temporal_tuple,
        error.BadFormat, error.InvalidPrivileges, error.InvalidText => .malformed_wire,
        error.BadSignature => .signature_mismatch,
        error.BufferTooSmall, error.SignFailed => .malformed_wire,
    };
}

fn futureIssueBoundExceeded(issued_ms: u64, security_now_ms: u64) bool {
    const latest_issue = std.math.add(u64, security_now_ms, oper_cred_share.ocg2_max_future_skew_ms) catch
        std.math.maxInt(u64);
    return issued_ms > latest_issue;
}

fn validateOne(copy: *const TransactionCopy, previous_account: ?[]const u8, security_now_ms: u64) ?InvalidReason {
    const account = boundedAccount(copy) orelse return .account_bounds;
    if (!canonicalAccount(account)) return .account_bounds;
    if (previous_account) |previous| {
        if (std.mem.order(u8, previous, account) != .lt) return .account_order;
    }
    if (copy.revision == 0) return .zero_revision;
    if (copy.authority_node_id == 0) return .malformed_authority;
    const public_key = Ed25519.PublicKey.fromBytes(copy.authority_pubkey) catch
        return .malformed_authority;
    if (node_short_id.shortId(node_identity.nodeIdFromPublicKey(copy.authority_pubkey)) !=
        copy.authority_node_id)
        return .malformed_authority;

    const wire = boundedWire(copy) orelse return .malformed_wire;
    const parsed = parseWire(wire) orelse return .malformed_wire;
    if (parsed.kind != copy.kind or parsed.revision != copy.revision or
        parsed.issued_ms != copy.issued_ms or parsed.expiry_ms != copy.expiry_ms or
        parsed.authority_node_id != copy.authority_node_id or
        !std.mem.eql(u8, parsed.account, account) or
        !std.mem.eql(u8, &parsed.authority_pubkey, &copy.authority_pubkey))
        return .field_mismatch;

    const signed_len = wire.len - oper_cred_share.signature_len;
    const signature = Ed25519.Signature.fromBytes(wire[signed_len..][0..oper_cred_share.signature_len].*);
    signature.verifyStrict(wire[0..signed_len], public_key) catch return .signature_mismatch;

    var blake3_digest: [digest_len]u8 = undefined;
    Blake3.hash(wire, &blake3_digest, .{});
    var sha256_digest: [digest_len]u8 = undefined;
    Sha256.hash(wire, &sha256_digest, .{});
    if (!std.mem.eql(u8, &blake3_digest, &copy.digest) or
        !std.mem.eql(u8, &sha256_digest, &copy.wire_sha256))
        return .digest_mismatch;

    switch (copy.kind) {
        .grant => {
            if (copy.expiry_ms <= copy.issued_ms) return .temporal_tuple;
            if (copy.expiry_ms - copy.issued_ms > oper_cred_share.ocg2_max_ttl_ms)
                return .temporal_tuple;
        },
        .tombstone => {
            if (copy.expiry_ms != 0) return .temporal_tuple;
        },
    }
    if (futureIssueBoundExceeded(copy.issued_ms, security_now_ms)) return .temporal_tuple;

    // Caller security_now_ms is the OCG2 verifier clock. Expired grants stay
    // classifiable/schedulable; only the canonical max-future issue bound is
    // enforced against that clock.
    oper_cred_share.validateOcg2Fields(.{
        .kind = parsed.kind,
        .account = parsed.account,
        .revision = parsed.revision,
        .privilege_bits = parsed.privilege_bits,
        .class = parsed.class,
        .title = parsed.title,
        .authority_node_id = parsed.authority_node_id,
        .authority_pubkey = parsed.authority_pubkey,
        .issued_ms = parsed.issued_ms,
        .expiry_ms = parsed.expiry_ms,
    }, security_now_ms) catch |err| switch (err) {
        error.Expired => {},
        else => return policyReason(err),
    };

    if (copy.equivocation) {
        if (allZero(copy.conflict_digest) or
            std.mem.eql(u8, &copy.conflict_digest, &copy.digest))
            return .equivocation_tuple;
    } else if (!allZero(copy.conflict_digest)) {
        return .equivocation_tuple;
    }
    return null;
}

fn writeHint(copy: *const TransactionCopy, security_now_ms: u64) ReinspectHint {
    const classified = classify(copy, security_now_ms);
    var hint = ReinspectHint{
        .revision = copy.revision,
        .digest = copy.digest,
        .wire_sha256 = copy.wire_sha256,
        .phase = classified[0],
        .next_transition_ms = classified[1],
    };
    const account = boundedAccount(copy).?;
    @memcpy(hint.account_buf[0..account.len], account);
    hint.account_len = account.len;
    return hint;
}

/// Build advisory reinspection hints from a canonical C2 inventory.
/// Validation of every input completes before `out` is written.  Invalid or
/// insufficient output leaves `out` byte-for-byte untouched.
pub fn build(
    transactions: []const TransactionCopy,
    security_now_ms: u64,
    out: []ReinspectHint,
) BuildResult {
    var first_invalid: ?BuildResult = null;
    var previous_account: ?[]const u8 = null;
    for (transactions, 0..) |*copy, index| {
        if (validateOne(copy, previous_account, security_now_ms)) |reason| {
            if (first_invalid == null)
                first_invalid = .{ .invalid = .{ .index = index, .reason = reason } };
        }
        if (boundedAccount(copy)) |account| {
            if (canonicalAccount(account)) previous_account = account;
        }
    }
    if (first_invalid) |result| return result;
    if (out.len < transactions.len) return .{ .insufficient_output = transactions.len };

    var earliest_transition_ms: ?u64 = null;
    for (transactions, 0..) |*copy, index| {
        const hint = writeHint(copy, security_now_ms);
        out[index] = hint;
        if (hint.next_transition_ms) |deadline| {
            earliest_transition_ms = if (earliest_transition_ms) |earliest|
                if (deadline < earliest) deadline else earliest
            else
                deadline;
        }
    }
    return .{
        .complete = .{
            .count = transactions.len,
            .earliest_transition_ms = earliest_transition_ms,
        },
    };
}

const testing = std.testing;

fn testKey(seed: u8) !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
}

fn testConfig(kp: Ed25519.KeyPair) durable_oper_authority.Config {
    const public_key = kp.public_key.toBytes();
    return .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
}

fn signFields(
    kp: Ed25519.KeyPair,
    fields: oper_cred_share.Ocg2Fields,
    now_ms: u64,
    out: []u8,
) ![]u8 {
    const len = try oper_cred_share.signOcg2(kp, fields, now_ms, out);
    return out[0..len];
}

fn grantFields(
    config: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
    expiry_ms: u64,
    title: []const u8,
) oper_cred_share.Ocg2Fields {
    return .{
        .kind = .grant,
        .account = account,
        .revision = revision,
        .privilege_bits = @as(u64, 1) << 3,
        .class = "moderator",
        .title = title,
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    };
}

fn tombstoneFields(
    config: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
) oper_cred_share.Ocg2Fields {
    return .{
        .kind = .tombstone,
        .account = account,
        .revision = revision,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = 0,
    };
}

fn fillCopy(
    copy: *TransactionCopy,
    config: durable_oper_authority.Config,
    wire: []const u8,
    fields: oper_cred_share.Ocg2Fields,
    equivocation: bool,
    conflict_digest: [digest_len]u8,
) void {
    copy.* = .{
        .revision = fields.revision,
        .kind = fields.kind,
        .issued_ms = fields.issued_ms,
        .expiry_ms = fields.expiry_ms,
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .equivocation = equivocation,
        .conflict_digest = conflict_digest,
    };
    @memcpy(copy.account_buf[0..fields.account.len], fields.account);
    copy.account_len = fields.account.len;
    @memcpy(copy.wire_buf[0..wire.len], wire);
    copy.wire_len = wire.len;
    Blake3.hash(wire, &copy.digest, .{});
    Sha256.hash(wire, &copy.wire_sha256, .{});
}

fn makeCopy(
    kp: Ed25519.KeyPair,
    fields: oper_cred_share.Ocg2Fields,
    equivocation: bool,
    conflict_digest: [digest_len]u8,
) !TransactionCopy {
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try signFields(kp, fields, fields.issued_ms, &wire_buf);
    var copy = TransactionCopy{};
    fillCopy(&copy, testConfig(kp), wire, fields, equivocation, conflict_digest);
    return copy;
}

fn encodeUnchecked(out: []u8, fields: oper_cred_share.Ocg2Fields) !usize {
    var pos: usize = 0;
    const Put = struct {
        fn raw(dst: []u8, at: *usize, bytes: []const u8) !void {
            if (bytes.len > dst.len -| at.*) return error.BufferTooSmall;
            @memcpy(dst[at.*..][0..bytes.len], bytes);
            at.* += bytes.len;
        }
        fn byte(dst: []u8, at: *usize, value: u8) !void {
            return raw(dst, at, &.{value});
        }
        fn u64be(dst: []u8, at: *usize, value: u64) !void {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, value, .big);
            return raw(dst, at, &bytes);
        }
        fn field(dst: []u8, at: *usize, value: []const u8) !void {
            if (value.len > std.math.maxInt(u8)) return error.BadFormat;
            try byte(dst, at, @intCast(value.len));
            try raw(dst, at, value);
        }
    };
    try Put.raw(out, &pos, oper_cred_share.ocg2_domain);
    try Put.byte(out, &pos, @intFromEnum(fields.kind));
    try Put.u64be(out, &pos, fields.authority_node_id);
    try Put.u64be(out, &pos, fields.revision);
    try Put.u64be(out, &pos, fields.issued_ms);
    try Put.u64be(out, &pos, fields.expiry_ms);
    try Put.u64be(out, &pos, fields.privilege_bits);
    try Put.field(out, &pos, fields.account);
    try Put.field(out, &pos, fields.class);
    try Put.field(out, &pos, fields.title);
    try Put.raw(out, &pos, &fields.authority_pubkey);
    return pos;
}

fn signUnchecked(kp: Ed25519.KeyPair, fields: oper_cred_share.Ocg2Fields, out: []u8) ![]u8 {
    const signed_len = try encodeUnchecked(out, fields);
    if (oper_cred_share.signature_len > out.len -| signed_len) return error.BufferTooSmall;
    const signature = try kp.sign(out[0..signed_len], null);
    @memcpy(out[signed_len..][0..oper_cred_share.signature_len], &signature.toBytes());
    return out[0 .. signed_len + oper_cred_share.signature_len];
}

fn makeUnchecked(
    kp: Ed25519.KeyPair,
    fields: oper_cred_share.Ocg2Fields,
    equivocation: bool,
    conflict_digest: [digest_len]u8,
) !TransactionCopy {
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try signUnchecked(kp, fields, &wire_buf);
    var copy = TransactionCopy{};
    fillCopy(&copy, testConfig(kp), wire, fields, equivocation, conflict_digest);
    return copy;
}

fn expectComplete(result: BuildResult, count: usize, earliest: ?u64) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).complete, std.meta.activeTag(result));
    try testing.expectEqual(count, result.complete.count);
    try testing.expectEqual(earliest, result.complete.earliest_transition_ms);
}

fn expectInvalid(result: BuildResult, index: usize, reason: InvalidReason) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).invalid, std.meta.activeTag(result));
    try testing.expectEqual(index, result.invalid.index);
    try testing.expectEqual(reason, result.invalid.reason);
}

fn hintAccount(hint: *const ReinspectHint) []const u8 {
    return hint.account_buf[0..hint.account_len];
}

fn expectHint(
    hint: ReinspectHint,
    account: []const u8,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    digest: [digest_len]u8,
    wire_sha256: [digest_len]u8,
) !void {
    try testing.expectEqualStrings(account, hintAccount(&hint));
    try testing.expectEqual(revision, hint.revision);
    try testing.expectEqual(phase, hint.phase);
    try testing.expectEqual(next_transition_ms, hint.next_transition_ms);
    try testing.expectEqualSlices(u8, &digest, &hint.digest);
    try testing.expectEqualSlices(u8, &wire_sha256, &hint.wire_sha256);
}

fn snapshotHints(hints: []const ReinspectHint) [4096]u8 {
    var out: [4096]u8 = undefined;
    const bytes = std.mem.sliceAsBytes(hints);
    std.debug.assert(bytes.len <= out.len);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

fn expectUntouched(before: [4096]u8, hints: []const ReinspectHint) !void {
    const bytes = std.mem.sliceAsBytes(hints);
    try testing.expectEqualSlices(u8, before[0..bytes.len], bytes);
}

fn testCommit(
    state: *durable_oper_authority.State,
    wire: []const u8,
    now_ms: u64,
) !durable_oper_authority.UpdateDisposition {
    if (!state.securityTimeAuthorized()) {
        const horizon = std.math.add(u64, now_ms, oper_cred_share.ocg2_max_ttl_ms + 1) catch
            std.math.maxInt(u64);
        var reservation = try state.prepareSecurityTimeReservation(now_ms, horizon);
        reservation.update.commitInto(state);
    }
    var outcome = try state.prepareMerge(wire, now_ms);
    return switch (outcome) {
        .update => |*update| blk: {
            const disposition = update.disposition;
            update.commitInto(state);
            break :blk disposition;
        },
        else => error.TestUnexpectedResult,
    };
}

test "OCG2SCHED empty inventory is complete and writes nothing" {
    const sentinel = ReinspectHint{ .revision = 0xdead_beef };
    var out = [_]ReinspectHint{sentinel};
    const before = snapshotHints(&out);
    try expectComplete(build(&.{}, 1_000, out[0..0]), 0, null);
    try expectUntouched(before, &out);
}

test "OCG2SCHED grant phases use inclusive issue and exclusive expiry" {
    const kp = try testKey(0xC3);
    const config = testConfig(kp);
    const fields = grantFields(config, "alice", 2, 1_000, 5_000, "Now");
    const copy = try makeCopy(kp, fields, false, @splat(0));
    var out: [1]ReinspectHint = undefined;

    try expectComplete(build(&.{copy}, 999, &out), 1, 1_000);
    try expectHint(out[0], "alice", 2, .not_yet_valid, 1_000, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, 1_000, &out), 1, 5_000);
    try expectHint(out[0], "alice", 2, .active, 5_000, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, 4_999, &out), 1, 5_000);
    try expectHint(out[0], "alice", 2, .active, 5_000, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, 5_000, &out), 1, null);
    try expectHint(out[0], "alice", 2, .expired, null, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, 9_000, &out), 1, null);
    try expectHint(out[0], "alice", 2, .expired, null, copy.digest, copy.wire_sha256);
}

test "OCG2SCHED tombstone and equivocation are terminal with equivocation precedence" {
    const kp = try testKey(0xC4);
    const config = testConfig(kp);
    const tomb = try makeCopy(kp, tombstoneFields(config, "alice", 3, 1_200), false, @splat(0));
    var conflict: [digest_len]u8 = @splat(1);
    conflict[0] = 0x5a;
    const equivocated_grant = try makeCopy(
        kp,
        grantFields(config, "bob", 1, 1_000, 5_000, "Live"),
        true,
        conflict,
    );
    const equivocated_tomb = try makeCopy(
        kp,
        tombstoneFields(config, "car", 4, 1_300),
        true,
        conflict,
    );

    var out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{tomb}, 0, &out), 1, null);
    try expectHint(out[0], "alice", 3, .tombstone, null, tomb.digest, tomb.wire_sha256);

    try expectComplete(build(&.{equivocated_grant}, 10_000, &out), 1, null);
    try expectHint(out[0], "bob", 1, .equivocation, null, equivocated_grant.digest, equivocated_grant.wire_sha256);

    try expectComplete(build(&.{equivocated_tomb}, 0, &out), 1, null);
    try expectHint(out[0], "car", 4, .equivocation, null, equivocated_tomb.digest, equivocated_tomb.wire_sha256);
}

test "OCG2SCHED mixed inventory reports exact earliest transition without arithmetic" {
    const kp = try testKey(0xC5);
    const config = testConfig(kp);
    const conflict: [digest_len]u8 = @splat(2);
    const copies = [_]TransactionCopy{
        try makeCopy(kp, grantFields(config, "alice", 1, 5_000, 9_000, "Future"), false, @splat(0)),
        try makeCopy(kp, grantFields(config, "bob", 1, 1_000, 4_000, "Live"), false, @splat(0)),
        try makeCopy(kp, grantFields(config, "car", 1, 100, 200, "Old"), false, @splat(0)),
        try makeCopy(kp, grantFields(config, "mallory", 1, 1_000, 8_000, "Split"), true, conflict),
        try makeCopy(kp, tombstoneFields(config, "zed", 1, 1_200), false, @splat(0)),
    };
    var out: [5]ReinspectHint = undefined;
    try expectComplete(build(&copies, 1_000, &out), 5, 4_000);
    try testing.expectEqual(Phase.not_yet_valid, out[0].phase);
    try testing.expectEqual(@as(?u64, 5_000), out[0].next_transition_ms);
    try testing.expectEqual(Phase.active, out[1].phase);
    try testing.expectEqual(@as(?u64, 4_000), out[1].next_transition_ms);
    try testing.expectEqual(Phase.expired, out[2].phase);
    try testing.expectEqual(@as(?u64, null), out[2].next_transition_ms);
    try testing.expectEqual(Phase.equivocation, out[3].phase);
    try testing.expectEqual(Phase.tombstone, out[4].phase);
}

test "OCG2SCHED rejects duplicates and permutations without sorting" {
    const kp = try testKey(0xC6);
    const config = testConfig(kp);
    const alice = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    const bob = try makeCopy(kp, grantFields(config, "bob", 1, 1_000, 5_000, "B"), false, @splat(0));
    const car = try makeCopy(kp, grantFields(config, "car", 1, 1_000, 5_000, "C"), false, @splat(0));

    const sentinel = ReinspectHint{ .revision = 11 };
    var out = [_]ReinspectHint{ sentinel, sentinel, sentinel };
    const before = snapshotHints(&out);

    try expectInvalid(build(&.{ alice, alice }, 1_000, &out), 1, .account_order);
    try expectUntouched(before, &out);
    try expectInvalid(build(&.{ bob, alice }, 1_000, &out), 1, .account_order);
    try expectUntouched(before, &out);
    try expectInvalid(build(&.{ alice, car, bob }, 1_000, &out), 2, .account_order);
    try expectUntouched(before, &out);

    var ordered: [3]ReinspectHint = undefined;
    try expectComplete(build(&.{ alice, bob, car }, 1_000, &ordered), 3, 5_000);
    try testing.expectEqualStrings("alice", hintAccount(&ordered[0]));
    try testing.expectEqualStrings("bob", hintAccount(&ordered[1]));
    try testing.expectEqualStrings("car", hintAccount(&ordered[2]));
}

test "OCG2SCHED account bounds and noncanonical names fail closed before slicing" {
    const kp = try testKey(0xC7);
    const config = testConfig(kp);
    var empty = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    empty.account_len = 0;
    var too_long = empty;
    too_long.account_len = max_account_len + 1;
    var overflow = empty;
    overflow.account_len = std.math.maxInt(usize);
    var upper = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    upper.account_buf[0] = 'A';

    var out = [_]ReinspectHint{.{ .revision = 3 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{empty}, 1_000, &out), 0, .account_bounds);
    try expectInvalid(build(&.{too_long}, 1_000, &out), 0, .account_bounds);
    try expectInvalid(build(&.{overflow}, 1_000, &out), 0, .account_bounds);
    try expectInvalid(build(&.{upper}, 1_000, &out), 0, .account_bounds);
    try expectUntouched(before, &out);

    var max_name: [max_account_len]u8 = @splat('a');
    const max_fields = grantFields(config, &max_name, 1, 1_000, 5_000, "Max");
    const max_copy = try makeCopy(kp, max_fields, false, @splat(0));
    var max_out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{max_copy}, 1_000, &max_out), 1, 5_000);
    try testing.expectEqual(@as(usize, max_account_len), max_out[0].account_len);
}

test "OCG2SCHED zero revision and malformed authority fail closed" {
    const kp = try testKey(0xC8);
    const config = testConfig(kp);
    var zero_rev = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    zero_rev.revision = 0;
    var zero_node = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    zero_node.authority_node_id = 0;
    var mismatch = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    mismatch.authority_node_id = config.authority_node_id + 1;

    var out = [_]ReinspectHint{.{ .revision = 4 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{zero_rev}, 1_000, &out), 0, .zero_revision);
    try expectInvalid(build(&.{zero_node}, 1_000, &out), 0, .malformed_authority);
    try expectInvalid(build(&.{mismatch}, 1_000, &out), 0, .malformed_authority);
    try expectUntouched(before, &out);
}

test "OCG2SCHED malformed wire bounds and truncated frames fail closed" {
    const kp = try testKey(0xC9);
    const config = testConfig(kp);
    var empty_wire = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    empty_wire.wire_len = 0;
    var overflow_wire = empty_wire;
    overflow_wire.wire_len = max_wire_len + 1;
    var short_wire = empty_wire;
    short_wire.wire_len = 3;
    var bad_magic = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    bad_magic.wire_buf[0] ^= 0xff;
    Blake3.hash(bad_magic.signedWire(), &bad_magic.digest, .{});
    Sha256.hash(bad_magic.signedWire(), &bad_magic.wire_sha256, .{});

    var out = [_]ReinspectHint{.{ .revision = 5 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{empty_wire}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{overflow_wire}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{short_wire}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{bad_magic}, 1_000, &out), 0, .malformed_wire);
    try expectUntouched(before, &out);
}

test "OCG2SCHED signature and field mismatches fail closed" {
    const kp = try testKey(0xCA);
    const config = testConfig(kp);
    var flipped_sig = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    flipped_sig.wire_buf[flipped_sig.wire_len - 1] ^= 0x01;
    Blake3.hash(flipped_sig.signedWire(), &flipped_sig.digest, .{});
    Sha256.hash(flipped_sig.signedWire(), &flipped_sig.wire_sha256, .{});

    var account_field = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    account_field.account_buf[0] = 'b';
    var revision_field = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    revision_field.revision = 9;
    var kind_field = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    kind_field.kind = .tombstone;
    kind_field.expiry_ms = 0;
    var time_field = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    time_field.issued_ms = 1_001;

    var out = [_]ReinspectHint{.{ .revision = 6 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{flipped_sig}, 1_000, &out), 0, .signature_mismatch);
    try expectInvalid(build(&.{account_field}, 1_000, &out), 0, .field_mismatch);
    try expectInvalid(build(&.{revision_field}, 1_000, &out), 0, .field_mismatch);
    try expectInvalid(build(&.{kind_field}, 1_000, &out), 0, .field_mismatch);
    try expectInvalid(build(&.{time_field}, 1_000, &out), 0, .field_mismatch);
    try expectUntouched(before, &out);
}

test "OCG2SCHED digest mismatch covers BLAKE3 and exact-wire SHA-256" {
    const kp = try testKey(0xCB);
    const config = testConfig(kp);
    var blake = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    blake.digest[0] ^= 0xff;
    var sha = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    sha.wire_sha256[0] ^= 0xff;

    var out = [_]ReinspectHint{.{ .revision = 7 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{blake}, 1_000, &out), 0, .digest_mismatch);
    try expectInvalid(build(&.{sha}, 1_000, &out), 0, .digest_mismatch);
    try expectUntouched(before, &out);
}

test "OCG2SCHED temporal tuple rejects inverted equal and oversize deadlines" {
    const kp = try testKey(0xCC);
    const config = testConfig(kp);
    const equal = grantFields(config, "alice", 1, 1_000, 1_000, "A");
    const inverted = grantFields(config, "alice", 1, 2_000, 1_000, "A");
    const oversize = grantFields(config, "alice", 1, 1_000, 1_000 + oper_cred_share.ocg2_max_ttl_ms + 1, "A");
    var tomb_expiry = tombstoneFields(config, "alice", 1, 1_000);
    tomb_expiry.expiry_ms = 1;

    var out = [_]ReinspectHint{.{ .revision = 8 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{try makeUnchecked(kp, equal, false, @splat(0))}, 1_000, &out), 0, .temporal_tuple);
    try expectInvalid(build(&.{try makeUnchecked(kp, inverted, false, @splat(0))}, 1_000, &out), 0, .temporal_tuple);
    try expectInvalid(build(&.{try makeUnchecked(kp, oversize, false, @splat(0))}, 1_000, &out), 0, .temporal_tuple);
    try expectInvalid(build(&.{try makeUnchecked(kp, tomb_expiry, false, @splat(0))}, 1_000, &out), 0, .temporal_tuple);
    try expectUntouched(before, &out);

    const exact = grantFields(
        config,
        "alice",
        1,
        1_000,
        1_000 + oper_cred_share.ocg2_max_ttl_ms,
        "Exact",
    );
    var exact_out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{try makeCopy(kp, exact, false, @splat(0))}, 1_000, &exact_out), 1, exact.expiry_ms);
}

test "OCG2SCHED equivocation tuple requires distinct nonzero conflict digest" {
    const kp = try testKey(0xCD);
    const config = testConfig(kp);
    const grant = grantFields(config, "alice", 1, 1_000, 5_000, "A");
    const missing = try makeCopy(kp, grant, true, @splat(0));
    var same = try makeCopy(kp, grant, true, @splat(0));
    same.conflict_digest = same.digest;
    const leaked = try makeCopy(kp, grant, false, @splat(1));

    var out = [_]ReinspectHint{.{ .revision = 9 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{missing}, 1_000, &out), 0, .equivocation_tuple);
    try expectInvalid(build(&.{same}, 1_000, &out), 0, .equivocation_tuple);
    try expectInvalid(build(&.{leaked}, 1_000, &out), 0, .equivocation_tuple);
    try expectUntouched(before, &out);
}

test "OCG2SCHED preserves grant and tombstone policy without privilege leakage" {
    const kp = try testKey(0xCE);
    const config = testConfig(kp);
    var empty_privs = grantFields(config, "alice", 1, 1_000, 5_000, "A");
    empty_privs.privilege_bits = 0;
    var forbidden = grantFields(config, "alice", 1, 1_000, 5_000, "A");
    forbidden.privilege_bits = @as(u64, 1) << 0;
    var empty_class = grantFields(config, "alice", 1, 1_000, 5_000, "A");
    empty_class.class = "";
    var tomb_privs = tombstoneFields(config, "alice", 1, 1_000);
    tomb_privs.privilege_bits = 1 << 3;
    var tomb_class = tombstoneFields(config, "alice", 1, 1_000);
    tomb_class.class = "moderator";

    var out = [_]ReinspectHint{.{ .revision = 10 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{try makeUnchecked(kp, empty_privs, false, @splat(0))}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{try makeUnchecked(kp, forbidden, false, @splat(0))}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{try makeUnchecked(kp, empty_class, false, @splat(0))}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{try makeUnchecked(kp, tomb_privs, false, @splat(0))}, 1_000, &out), 0, .malformed_wire);
    try expectInvalid(build(&.{try makeUnchecked(kp, tomb_class, false, @splat(0))}, 1_000, &out), 0, .malformed_wire);
    try expectUntouched(before, &out);

    inline for (@typeInfo(ReinspectHint).@"struct".field_names) |name| {
        try testing.expect(!std.mem.eql(u8, name, "privilege_bits"));
        try testing.expect(!std.mem.eql(u8, name, "privileges"));
        try testing.expect(!std.mem.eql(u8, name, "class"));
        try testing.expect(!std.mem.eql(u8, name, "class_buf"));
        try testing.expect(!std.mem.eql(u8, name, "title"));
        try testing.expect(!std.mem.eql(u8, name, "title_buf"));
        try testing.expect(!std.mem.eql(u8, name, "wire"));
        try testing.expect(!std.mem.eql(u8, name, "wire_buf"));
        try testing.expect(!std.mem.eql(u8, name, "authority_pubkey"));
    }
}

test "OCG2SCHED invalid later record is failure-atomic for earlier valid copies" {
    const kp = try testKey(0xCF);
    const config = testConfig(kp);
    const alice = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    var bob = try makeCopy(kp, grantFields(config, "bob", 1, 1_000, 5_000, "B"), false, @splat(0));
    bob.digest[0] ^= 0xff;
    const sentinel = ReinspectHint{ .revision = 12, .phase = .active };
    var out = [_]ReinspectHint{ sentinel, sentinel };
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{ alice, bob }, 1_000, &out), 1, .digest_mismatch);
    try expectUntouched(before, &out);
}

test "OCG2SCHED insufficient output reports required count and leaves dest untouched" {
    const kp = try testKey(0xD0);
    const config = testConfig(kp);
    const alice = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    const bob = try makeCopy(kp, grantFields(config, "bob", 1, 1_000, 5_000, "B"), false, @splat(0));
    const sentinel = ReinspectHint{ .revision = 13 };
    var under = [_]ReinspectHint{sentinel};
    const before = snapshotHints(&under);
    const result = build(&.{ alice, bob }, 1_000, &under);
    try testing.expectEqual(std.meta.Tag(BuildResult).insufficient_output, std.meta.activeTag(result));
    try testing.expectEqual(@as(usize, 2), result.insufficient_output);
    try expectUntouched(before, &under);

    var exact: [2]ReinspectHint = .{ sentinel, sentinel };
    try expectComplete(build(&.{ alice, bob }, 1_000, &exact), 2, 5_000);
    var over = [_]ReinspectHint{ sentinel, sentinel, sentinel };
    try expectComplete(build(&.{ alice, bob }, 1_000, &over), 2, 5_000);
    try testing.expectEqual(@as(u64, 13), over[2].revision);
}

test "OCG2SCHED invalid inventory wins over insufficient output" {
    const kp = try testKey(0xD1);
    const config = testConfig(kp);
    var alice = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    alice.revision = 0;
    var out = [_]ReinspectHint{.{ .revision = 14 }};
    const before = snapshotHints(&out);
    try expectInvalid(build(&.{alice}, 1_000, out[0..0]), 0, .zero_revision);
    try expectUntouched(before, &out);
}

test "OCG2SCHED consumes accepted C2 copyTransactions inventory" {
    const kp = try testKey(0xD2);
    const config = testConfig(kp);
    var state = try durable_oper_authority.State.init(testing.allocator, config);
    defer state.deinit();

    var car_buf: [max_wire_len]u8 = undefined;
    const car = try signFields(kp, grantFields(config, "car", 1, 4_000, 9_000, "Future"), 1_000, &car_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, car, 1_000));
    var alice_buf: [max_wire_len]u8 = undefined;
    const alice = try signFields(kp, grantFields(config, "alice", 1, 500, 900, "Expired"), 500, &alice_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, alice, 500));
    var bob_first_buf: [max_wire_len]u8 = undefined;
    const bob_first = try signFields(kp, grantFields(config, "bob", 1, 1_000, 5_000, "First"), 1_000, &bob_first_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, bob_first, 1_000));
    var bob_conflict_buf: [max_wire_len]u8 = undefined;
    const bob_conflict = try signFields(kp, grantFields(config, "bob", 1, 1_000, 5_000, "Conflict"), 1_000, &bob_conflict_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.equivocation, try testCommit(&state, bob_conflict, 1_000));
    var zed_buf: [max_wire_len]u8 = undefined;
    const zed = try signFields(kp, tombstoneFields(config, "zed", 1, 1_200), 1_200, &zed_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, zed, 1_200));

    var copies: [4]TransactionCopy = undefined;
    try testing.expectEqual(@as(usize, 4), try state.copyTransactions(&copies));
    var out: [4]ReinspectHint = undefined;
    try expectComplete(build(&copies, 1_000, &out), 4, 4_000);
    try testing.expectEqualStrings("alice", hintAccount(&out[0]));
    try testing.expectEqual(Phase.expired, out[0].phase);
    try testing.expectEqualStrings("bob", hintAccount(&out[1]));
    try testing.expectEqual(Phase.equivocation, out[1].phase);
    try testing.expectEqualStrings("car", hintAccount(&out[2]));
    try testing.expectEqual(Phase.not_yet_valid, out[2].phase);
    try testing.expectEqual(@as(?u64, 4_000), out[2].next_transition_ms);
    try testing.expectEqualStrings("zed", hintAccount(&out[3]));
    try testing.expectEqual(Phase.tombstone, out[3].phase);
}

test "OCG2SCHED now at zero and maxInt stay exact" {
    const kp = try testKey(0xD3);
    const config = testConfig(kp);
    const epoch = try makeCopy(kp, grantFields(config, "alice", 1, 0, 1, "Epoch"), false, @splat(0));
    var out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{epoch}, 0, &out), 1, 1);
    try testing.expectEqual(Phase.active, out[0].phase);
    try expectComplete(build(&.{epoch}, 1, &out), 1, null);
    try testing.expectEqual(Phase.expired, out[0].phase);

    const late = try makeCopy(
        kp,
        grantFields(config, "alice", 1, std.math.maxInt(u64) - 2, std.math.maxInt(u64), "Late"),
        false,
        @splat(0),
    );
    try expectComplete(build(&.{late}, std.math.maxInt(u64) - 3, &out), 1, std.math.maxInt(u64) - 2);
    try testing.expectEqual(Phase.not_yet_valid, out[0].phase);
    try expectComplete(build(&.{late}, std.math.maxInt(u64) - 2, &out), 1, std.math.maxInt(u64));
    try testing.expectEqual(Phase.active, out[0].phase);
    try expectComplete(build(&.{late}, std.math.maxInt(u64), &out), 1, null);
    try testing.expectEqual(Phase.expired, out[0].phase);
}

test "OCG2SCHED build never allocates" {
    const kp = try testKey(0xD4);
    const config = testConfig(kp);
    const copy = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const unused = failing.allocator();
    _ = unused;
    var out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{copy}, 1_000, &out), 1, 5_000);
}

test "OCG2SCHED reflection and import boundary stay advisory only" {
    const allowed = .{
        "Phase",   "InvalidReason", "ReinspectHint",
        "Summary", "BuildResult",   "build",
    };
    const names = @typeInfo(@This()).@"struct".decl_names;
    try testing.expectEqual(@as(usize, allowed.len), names.len);
    inline for (names) |name| {
        var found = false;
        inline for (allowed) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) found = true;
        }
        try testing.expect(found);
    }
    try testing.expectEqual(@as(usize, 0), @typeInfo(ReinspectHint).@"struct".decl_names.len);
    inline for (.{
        "apply",
        "execute",
        "grant",
        "revoke",
        "mint",
        "transmit",
        "session",
        "callback",
        "executeAuthorized",
        "issue",
        "issueGrant",
        "issueRevoke",
        "executeGrant",
        "executeRevoke",
        "ProjectionData",
        "DurableOperLookup",
        "Visitor",
        "reconcile",
        "Services",
        "LinuxServer",
        "buildAlloc",
        "buildWithAllocator",
    }) |name| {
        try testing.expect(!@hasDecl(@This(), name));
    }
    try testing.expectEqual(@as(usize, 3), @typeInfo(@TypeOf(build)).@"fn".param_types.len);
}

test "OCG2SCHED hints copy account bytes and share no input pointers" {
    const kp = try testKey(0xD5);
    const config = testConfig(kp);
    var copy = try makeCopy(kp, grantFields(config, "alice", 1, 1_000, 5_000, "A"), false, @splat(0));
    var out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{copy}, 1_000, &out), 1, 5_000);
    try testing.expect(hintAccount(&out[0]).ptr != copy.account().ptr);
    copy.account_buf[0] = 'z';
    try testing.expectEqualStrings("alice", hintAccount(&out[0]));
}

test "OCG2SCHED future issue bound uses caller now not record issued" {
    const kp = try testKey(0xD6);
    const config = testConfig(kp);
    const now: u64 = 10_000;
    const skew = oper_cred_share.ocg2_max_future_skew_ms;
    try testing.expectEqual(@as(u64, 300_000), skew);

    const accepted_fields = grantFields(config, "alice", 1, now + skew, now + skew + 1_000, "Edge");
    const rejected_fields = grantFields(config, "alice", 1, now + skew + 1, now + skew + 1_001, "Over");
    const accepted = try makeCopy(kp, accepted_fields, false, @splat(0));

    var out: [1]ReinspectHint = undefined;
    try expectComplete(build(&.{accepted}, now, &out), 1, accepted_fields.issued_ms);
    try expectHint(out[0], "alice", 1, .not_yet_valid, accepted_fields.issued_ms, accepted.digest, accepted.wire_sha256);

    const sentinel = ReinspectHint{ .revision = 15 };
    var dest = [_]ReinspectHint{sentinel};
    const before = snapshotHints(&dest);
    try expectInvalid(build(&.{try makeCopy(kp, rejected_fields, false, @splat(0))}, now, &dest), 0, .temporal_tuple);
    try expectUntouched(before, &dest);

    const tomb_ok = try makeCopy(kp, tombstoneFields(config, "bob", 1, now + skew), false, @splat(0));
    try expectComplete(build(&.{tomb_ok}, now, &out), 1, null);
    try expectHint(out[0], "bob", 1, .tombstone, null, tomb_ok.digest, tomb_ok.wire_sha256);

    try expectInvalid(
        build(&.{try makeCopy(kp, tombstoneFields(config, "car", 1, now + skew + 1), false, @splat(0))}, now, &dest),
        0,
        .temporal_tuple,
    );
    try expectUntouched(before, &dest);
}

test "OCG2SCHED future issue bound is overflow-safe at u64 max" {
    const kp = try testKey(0xD7);
    const config = testConfig(kp);
    const skew = oper_cred_share.ocg2_max_future_skew_ms;
    const max_u64 = std.math.maxInt(u64);
    const late_issued = max_u64 - 1;
    const late_grant = try makeCopy(
        kp,
        grantFields(config, "alice", 1, late_issued, max_u64, "Late"),
        false,
        @splat(0),
    );
    const max_tomb = try makeCopy(kp, tombstoneFields(config, "bob", 1, max_u64), false, @splat(0));

    var out: [1]ReinspectHint = undefined;
    const accepted_now = late_issued - skew;
    try expectComplete(build(&.{late_grant}, accepted_now, &out), 1, late_issued);
    try testing.expectEqual(Phase.not_yet_valid, out[0].phase);

    const sentinel = ReinspectHint{ .revision = 16 };
    var dest = [_]ReinspectHint{sentinel};
    const before = snapshotHints(&dest);
    try expectInvalid(build(&.{late_grant}, accepted_now - 1, &dest), 0, .temporal_tuple);
    try expectUntouched(before, &dest);

    const tomb_accepted_now = max_u64 - skew;
    try expectComplete(build(&.{max_tomb}, tomb_accepted_now, &out), 1, null);
    try testing.expectEqual(Phase.tombstone, out[0].phase);
    try expectInvalid(build(&.{max_tomb}, tomb_accepted_now - 1, &dest), 0, .temporal_tuple);
    try expectUntouched(before, &dest);

    const overflow_now = max_u64 - skew + 1;
    try testing.expectError(error.Overflow, std.math.add(u64, overflow_now, skew));
    try expectComplete(build(&.{max_tomb}, overflow_now, &out), 1, null);
    try testing.expectEqual(Phase.tombstone, out[0].phase);
    try expectComplete(build(&.{late_grant}, overflow_now, &out), 1, late_issued);
    try testing.expectEqual(Phase.not_yet_valid, out[0].phase);
}

test "OCG2SCHED expired grants remain classifiable and schedulable" {
    const kp = try testKey(0xD8);
    const config = testConfig(kp);
    const fields = grantFields(config, "alice", 1, 1_000, 5_000, "Old");
    const copy = try makeCopy(kp, fields, false, @splat(0));
    var out: [1]ReinspectHint = undefined;

    try expectComplete(build(&.{copy}, 5_000, &out), 1, null);
    try expectHint(out[0], "alice", 1, .expired, null, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, 9_000, &out), 1, null);
    try expectHint(out[0], "alice", 1, .expired, null, copy.digest, copy.wire_sha256);

    try expectComplete(build(&.{copy}, std.math.maxInt(u64), &out), 1, null);
    try expectHint(out[0], "alice", 1, .expired, null, copy.digest, copy.wire_sha256);
}
