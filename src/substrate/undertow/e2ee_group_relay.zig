// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical, origin-signed mesh record for opaque E2EEGROUP controls.
//!
//! This codec establishes immutable signed bytes and a stable relay identity.
//! It does not allocate a mesh frame, authorize membership/device ownership,
//! persist payloads, or provide authoritative replay admission.

const std = @import("std");

const cpv = @import("../../proto/coilpack_value.zig");
const control = @import("../../proto/e2ee_group_control.zig");
const sign = @import("../../crypto/sign.zig");
const message_relay = @import("message_relay.zig");
const signed_frame = @import("signed_frame.zig");

pub const pubkey_len = sign.public_key_len;
pub const sig_len = sign.signature_len;
pub const relay_id_len: usize = 16;
pub const RelayId = [relay_id_len]u8;
pub const Kind = control.Kind;
/// Conservative ceiling over every semantically valid canonical record. Check
/// this before the allocating generic CoilPack decoder.
pub const max_wire_len: usize = 8192;

pub const sign_domain = "onyx-s2s-e2ee-group-v1";
pub const relay_id_domain = "onyx-s2s-e2ee-group-id-v1";

pub const RelayRecord = struct {
    wire_schema: u8 = 1,
    kind: Kind,
    channel: []const u8,
    source_prefix: []const u8,
    account: []const u8,
    from_device: []const u8,
    to_account: []const u8 = "",
    to_device: []const u8 = "",
    payload: []const u8,
    origin_node: u64,
    hlc: u64,
    origin_pubkey: []const u8 = "",
    origin_sig: []const u8 = "",
};

pub const Owned = struct {
    record: RelayRecord,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.record.channel);
        allocator.free(self.record.source_prefix);
        allocator.free(self.record.account);
        allocator.free(self.record.from_device);
        allocator.free(self.record.to_account);
        allocator.free(self.record.to_device);
        allocator.free(self.record.payload);
        allocator.free(self.record.origin_pubkey);
        allocator.free(self.record.origin_sig);
        self.* = undefined;
    }
};

pub const DecodeError = error{
    InvalidDocument,
    InvalidFieldType,
    InvalidKind,
    InvalidSemantic,
    MissingField,
    RecordTooLarge,
    UnknownField,
};
pub const SemanticError = error{InvalidSemantic};
pub const TranscriptError = error{FieldTooLong};
pub const StampError = sign.SignError || std.mem.Allocator.Error || SemanticError ||
    TranscriptError || error{OriginMismatch};

fn sourceNick(prefix: []const u8) ?[]const u8 {
    const bang = std.mem.indexOfScalar(u8, prefix, '!') orelse return null;
    if (bang == 0) return null;
    return prefix[0..bang];
}

fn validateBody(record: RelayRecord) SemanticError!void {
    if (record.wire_schema != 1) return error.InvalidSemantic;
    const nick = sourceNick(record.source_prefix) orelse return error.InvalidSemantic;

    // Reuse the hardened identity grammar without treating this control as a
    // chat relay. The synthetic body is never encoded or delivered.
    message_relay.validateSemantic(.{
        .verb = .privmsg,
        .target = record.channel,
        .source_nick = nick,
        .source_prefix = record.source_prefix,
        .account = record.account,
        .text = "control",
        .origin_node = record.origin_node,
        .hlc = record.hlc,
    }) catch return error.InvalidSemantic;
    if (record.account.len == 0) return error.InvalidSemantic;

    const to_account: ?[]const u8 = if (record.to_account.len == 0) null else record.to_account;
    const to_device: ?[]const u8 = if (record.to_device.len == 0) null else record.to_device;
    control.validate(.{
        .channel = record.channel,
        .kind = record.kind,
        .from_device = record.from_device,
        .to_account = to_account,
        .to_device = to_device,
        .payload = record.payload,
    }) catch return error.InvalidSemantic;
}

pub fn validateSemantic(record: RelayRecord) SemanticError!void {
    try validateBody(record);
    if (record.origin_pubkey.len != pubkey_len or record.origin_sig.len != sig_len)
        return error.InvalidSemantic;
}

/// Canonical CoilPack map. Every schema field is present; absent welcome
/// targets are encoded as empty strings.
pub fn encode(allocator: std.mem.Allocator, record: RelayRecord) ![]u8 {
    try validateSemantic(record);
    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = record.account } },
        .{ .key = "channel", .value = .{ .string = record.channel } },
        .{ .key = "from_device", .value = .{ .string = record.from_device } },
        .{ .key = "hlc", .value = .{ .unsigned = record.hlc } },
        .{ .key = "kind", .value = .{ .unsigned = @intFromEnum(record.kind) } },
        .{ .key = "origin_node", .value = .{ .unsigned = record.origin_node } },
        .{ .key = "origin_pubkey", .value = .{ .bytes = record.origin_pubkey } },
        .{ .key = "origin_sig", .value = .{ .bytes = record.origin_sig } },
        .{ .key = "payload", .value = .{ .string = record.payload } },
        .{ .key = "source_prefix", .value = .{ .string = record.source_prefix } },
        .{ .key = "to_account", .value = .{ .string = record.to_account } },
        .{ .key = "to_device", .value = .{ .string = record.to_device } },
        .{ .key = "wire_schema", .value = .{ .unsigned = record.wire_schema } },
    };
    return cpv.Encoder.encode(allocator, .{ .map = &entries });
}

const Field = enum(u4) {
    account,
    channel,
    from_device,
    hlc,
    kind,
    origin_node,
    origin_pubkey,
    origin_sig,
    payload,
    source_prefix,
    to_account,
    to_device,
    wire_schema,
};

fn claimField(seen: *u16, field: Field) DecodeError!void {
    const mask = @as(u16, 1) << @as(u4, @intCast(@intFromEnum(field)));
    if ((seen.* & mask) != 0) return error.InvalidDocument;
    seen.* |= mask;
}

fn allFieldsMask() u16 {
    return (@as(u16, 1) << 13) - 1;
}

fn readString(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .string => |text| text,
        else => error.InvalidFieldType,
    };
}

fn readBytes(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .bytes => |bytes| bytes,
        else => error.InvalidFieldType,
    };
}

fn readU64(value: cpv.Value) DecodeError!u64 {
    return switch (value) {
        .unsigned => |number| number,
        else => error.InvalidFieldType,
    };
}

fn readKind(value: cpv.Value) DecodeError!Kind {
    return switch (try readU64(value)) {
        1 => .key_package,
        2 => .welcome,
        3 => .commit,
        else => error.InvalidKind,
    };
}

pub fn decode(allocator: std.mem.Allocator, wire: []const u8) !Owned {
    if (wire.len > max_wire_len) return error.RecordTooLarge;
    var value = try cpv.Decoder.decode(allocator, wire);
    defer value.deinit(allocator);
    const entries = switch (value) {
        .map => |map| map,
        else => return error.InvalidDocument,
    };

    var seen: u16 = 0;
    var record: RelayRecord = .{
        .kind = .commit,
        .channel = "",
        .source_prefix = "",
        .account = "",
        .from_device = "",
        .payload = "",
        .origin_node = 0,
        .hlc = 0,
    };
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "account")) {
            try claimField(&seen, .account);
            record.account = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "channel")) {
            try claimField(&seen, .channel);
            record.channel = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "from_device")) {
            try claimField(&seen, .from_device);
            record.from_device = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "hlc")) {
            try claimField(&seen, .hlc);
            record.hlc = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "kind")) {
            try claimField(&seen, .kind);
            record.kind = try readKind(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_node")) {
            try claimField(&seen, .origin_node);
            record.origin_node = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_pubkey")) {
            try claimField(&seen, .origin_pubkey);
            record.origin_pubkey = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_sig")) {
            try claimField(&seen, .origin_sig);
            record.origin_sig = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "payload")) {
            try claimField(&seen, .payload);
            record.payload = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_prefix")) {
            try claimField(&seen, .source_prefix);
            record.source_prefix = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "to_account")) {
            try claimField(&seen, .to_account);
            record.to_account = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "to_device")) {
            try claimField(&seen, .to_device);
            record.to_device = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "wire_schema")) {
            try claimField(&seen, .wire_schema);
            const schema = try readU64(entry.value);
            if (schema > std.math.maxInt(u8)) return error.InvalidFieldType;
            record.wire_schema = @intCast(schema);
        } else return error.UnknownField;
    }
    if (seen != allFieldsMask()) return error.MissingField;
    if (record.origin_pubkey.len != pubkey_len or record.origin_sig.len != sig_len)
        return error.InvalidFieldType;
    validateSemantic(record) catch return error.InvalidSemantic;

    const channel = try allocator.dupe(u8, record.channel);
    errdefer allocator.free(channel);
    const source_prefix = try allocator.dupe(u8, record.source_prefix);
    errdefer allocator.free(source_prefix);
    const account = try allocator.dupe(u8, record.account);
    errdefer allocator.free(account);
    const from_device = try allocator.dupe(u8, record.from_device);
    errdefer allocator.free(from_device);
    const to_account = try allocator.dupe(u8, record.to_account);
    errdefer allocator.free(to_account);
    const to_device = try allocator.dupe(u8, record.to_device);
    errdefer allocator.free(to_device);
    const payload = try allocator.dupe(u8, record.payload);
    errdefer allocator.free(payload);
    const origin_pubkey = try allocator.dupe(u8, record.origin_pubkey);
    errdefer allocator.free(origin_pubkey);
    const origin_sig = try allocator.dupe(u8, record.origin_sig);
    errdefer allocator.free(origin_sig);

    record.channel = channel;
    record.source_prefix = source_prefix;
    record.account = account;
    record.from_device = from_device;
    record.to_account = to_account;
    record.to_device = to_device;
    record.payload = payload;
    record.origin_pubkey = origin_pubkey;
    record.origin_sig = origin_sig;
    return .{ .record = record };
}

fn appendLenPrefixed(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    field: []const u8,
) !void {
    if (field.len > std.math.maxInt(u32)) return error.FieldTooLong;
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(field.len), .little);
    try out.appendSlice(allocator, &len);
    try out.appendSlice(allocator, field);
}

/// Canonical signature transcript containing every non-signature wire field.
pub fn originTranscript(allocator: std.mem.Allocator, record: RelayRecord) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, record.wire_schema);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, record.origin_node, .little);
    try out.appendSlice(allocator, &number);
    std.mem.writeInt(u64, &number, record.hlc, .little);
    try out.appendSlice(allocator, &number);
    try out.append(allocator, @intFromEnum(record.kind));
    try appendLenPrefixed(&out, allocator, record.channel);
    try appendLenPrefixed(&out, allocator, record.source_prefix);
    try appendLenPrefixed(&out, allocator, record.account);
    try appendLenPrefixed(&out, allocator, record.from_device);
    try appendLenPrefixed(&out, allocator, record.to_account);
    try appendLenPrefixed(&out, allocator, record.to_device);
    try appendLenPrefixed(&out, allocator, record.payload);
    return out.toOwnedSlice(allocator);
}

pub fn stampOrigin(
    allocator: std.mem.Allocator,
    record: *RelayRecord,
    kp: *const sign.KeyPair,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) StampError!void {
    if (signed_frame.originShortId(kp.public_key) != record.origin_node)
        return error.OriginMismatch;
    try validateBody(record.*);
    const transcript = try originTranscript(allocator, record.*);
    defer allocator.free(transcript);
    pubkey_buf.* = kp.public_key;
    sig_buf.* = try kp.signCtx(sign_domain, transcript);
    record.origin_pubkey = pubkey_buf;
    record.origin_sig = sig_buf;
}

pub const VerifyAndIdOutcome = union(enum) {
    verified: RelayId,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

/// Verify before exposing the relay identity so a forged record cannot reserve
/// an authentic event's future replay slot.
pub fn verifyAndRelayId(
    allocator: std.mem.Allocator,
    record: RelayRecord,
) std.mem.Allocator.Error!VerifyAndIdOutcome {
    validateSemantic(record) catch return .invalid_semantic;
    const pubkey: sign.PublicKey = record.origin_pubkey[0..pubkey_len].*;
    if (signed_frame.originShortId(pubkey) != record.origin_node) return .origin_mismatch;
    const signature: sign.Signature = record.origin_sig[0..sig_len].*;
    const transcript = originTranscript(allocator, record) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .invalid_semantic,
    };
    defer allocator.free(transcript);
    const valid = sign.verifyCtx(sign_domain, transcript, signature, pubkey) catch false;
    if (!valid) return .bad_signature;

    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(relay_id_domain);
    hash.update(record.origin_pubkey);
    hash.update(record.origin_sig);
    hash.update(transcript);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    hash.final(&digest);
    return .{ .verified = digest[0..relay_id_len].* };
}

fn testKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

fn signedSample(
    kind: Kind,
    kp: *const sign.KeyPair,
    pubkey: *[pubkey_len]u8,
    signature: *[sig_len]u8,
) !RelayRecord {
    var record = RelayRecord{
        .kind = kind,
        .channel = "#root",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop.1",
        .to_account = if (kind == .welcome) "bob" else "",
        .to_device = if (kind == .welcome) "phone-2" else "",
        .payload = if (kind == .welcome) "b3BhcXVl" else "AQIDBA",
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = 42,
    };
    try stampOrigin(std.testing.allocator, &record, kp, pubkey, signature);
    return record;
}

test "E2EEGROUP signed relay kinds round-trip canonically" {
    const allocator = std.testing.allocator;
    inline for (.{ Kind.key_package, Kind.welcome, Kind.commit }, 0..) |kind, index| {
        var kp = try testKeyPair(0x60 + @as(u8, @intCast(index)));
        defer kp.deinit();
        var pubkey: [pubkey_len]u8 = undefined;
        var signature: [sig_len]u8 = undefined;
        const record = try signedSample(kind, &kp, &pubkey, &signature);
        const before = switch (try verifyAndRelayId(allocator, record)) {
            .verified => |id| id,
            else => return error.TestUnexpectedResult,
        };
        const wire = try encode(allocator, record);
        defer allocator.free(wire);
        var owned = try decode(allocator, wire);
        defer owned.deinit(allocator);
        const after = switch (try verifyAndRelayId(allocator, owned.record)) {
            .verified => |id| id,
            else => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(before, after);
        const wire_again = try encode(allocator, owned.record);
        defer allocator.free(wire_again);
        try std.testing.expectEqualSlices(u8, wire, wire_again);
        try std.testing.expectEqual(kind, owned.record.kind);
    }
}

test "E2EEGROUP signature binds routing identity kind clock and payload" {
    var kp = try testKeyPair(0x64);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const original = try signedSample(.welcome, &kp, &pubkey, &signature);

    var changed = original;
    changed.channel = "#other";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.source_prefix = "mallory!user@example.invalid";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.account = "mallory";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.from_device = "phone";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.to_account = "carol";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.to_device = "tablet";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.payload = "AQ";
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.hlc += 1;
    try std.testing.expectEqual(VerifyAndIdOutcome.bad_signature, try verifyAndRelayId(std.testing.allocator, changed));
    changed = original;
    changed.kind = .commit;
    try std.testing.expectEqual(VerifyAndIdOutcome.invalid_semantic, try verifyAndRelayId(std.testing.allocator, changed));
}

test "E2EEGROUP targeting and origin identity fail closed" {
    var kp = try testKeyPair(0x65);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;

    var welcome = try signedSample(.welcome, &kp, &pubkey, &signature);
    welcome.to_device = "";
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(welcome));
    var commit = try signedSample(.commit, &kp, &pubkey, &signature);
    commit.to_account = "bob";
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(commit));

    var unstamped = RelayRecord{
        .kind = .commit,
        .channel = "#root",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .from_device = "laptop",
        .payload = "AQ",
        .origin_node = signed_frame.originShortId(kp.public_key) ^ 1,
        .hlc = 1,
    };
    try std.testing.expectError(
        error.OriginMismatch,
        stampOrigin(std.testing.allocator, &unstamped, &kp, &pubkey, &signature),
    );
}

test "E2EEGROUP decoder rejects missing unknown and wrong-type fields" {
    const allocator = std.testing.allocator;
    var kp = try testKeyPair(0x66);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const record = try signedSample(.commit, &kp, &pubkey, &signature);
    const wire = try encode(allocator, record);
    defer allocator.free(wire);
    var doc = try cpv.Decoder.decode(allocator, wire);
    defer doc.deinit(allocator);
    const entries = switch (doc) {
        .map => |map| map,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 13), entries.len);

    var missing: [12]cpv.MapEntry = undefined;
    @memcpy(&missing, entries[0..12]);
    const missing_wire = try cpv.Encoder.encode(allocator, .{ .map = &missing });
    defer allocator.free(missing_wire);
    try std.testing.expectError(error.MissingField, decode(allocator, missing_wire));

    var unknown: [14]cpv.MapEntry = undefined;
    @memcpy(unknown[0..13], entries);
    unknown[13] = .{ .key = "unknown", .value = .{ .unsigned = 1 } };
    const unknown_wire = try cpv.Encoder.encode(allocator, .{ .map = &unknown });
    defer allocator.free(unknown_wire);
    try std.testing.expectError(error.UnknownField, decode(allocator, unknown_wire));

    var wrong: [13]cpv.MapEntry = undefined;
    @memcpy(&wrong, entries);
    for (&wrong) |*entry| {
        if (std.mem.eql(u8, entry.key, "payload")) {
            entry.value = .{ .unsigned = 1 };
            break;
        }
    }
    const wrong_wire = try cpv.Encoder.encode(allocator, .{ .map = &wrong });
    defer allocator.free(wrong_wire);
    try std.testing.expectError(error.InvalidFieldType, decode(allocator, wrong_wire));
}

test "E2EEGROUP decoder rejects oversized wire before allocation" {
    const oversized: [max_wire_len + 1]u8 = @splat(0xff);
    try std.testing.expectError(
        error.RecordTooLarge,
        decode(std.testing.failing_allocator, &oversized),
    );
}

test "E2EEGROUP decode and verification are leak-free across allocation failure" {
    var kp = try testKeyPair(0x68);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const record = try signedSample(.commit, &kp, &pubkey, &signature);
    const wire = try encode(std.testing.allocator, record);
    defer std.testing.allocator.free(wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, encoded: []const u8) !void {
            var owned = try decode(allocator, encoded);
            defer owned.deinit(allocator);
            switch (try verifyAndRelayId(allocator, owned.record)) {
                .verified => {},
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{wire});
}
