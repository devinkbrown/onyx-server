// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact Windows Helix custody for pending verification/reset tokens and TOTP.
//! The server must freeze accepted account actions before capture and must stage
//! this mandatory piece before publishing the inherited listener.

const std = @import("std");
const verify_mod = @import("../account_verify.zig");
const reset_mod = @import("../password_reset.zig");
const totp_mod = @import("../totp_auth.zig");
const wire = @import("abuse_checkpoint_wire.zig");

pub const checkpoint_magic = [_]u8{ 'H', 'X', 'A', 'F' };
const domain = "onyx-native-windows-account-flow-v1";
const header_len: usize = 64;
const max_entries: usize = 65_536;
const max_account_len: usize = 1_024;
const max_contact_len: usize = 4_096;
const max_token_bytes: usize = 4_096;
const max_secret_b32_len: usize = 4_096;
pub const max_checkpoint_bytes: usize = 64 * 1024 * 1024;
pub const Error = wire.Error || error{ConfigMismatch};

const Header = struct {
    verify_count: usize,
    reset_count: usize,
    totp_count: usize,
    verify_params: verify_mod.Params,
    reset_params: reset_mod.Params,
    totp_params: totp_mod.Params,
};

const VerifyRecord = struct {
    key: []const u8,
    account: []const u8,
    contact: []const u8,
    token: []const u8,
    issued_ms: u64,
    attempts: u8,
};

const ResetRecord = struct {
    key: []const u8,
    account: []const u8,
    token: []const u8,
    issued_ms: u64,
    attempts: u8,
};

const TotpRecord = struct {
    key: []const u8,
    secret_b32: []const u8,
    active: bool,
    last_step: ?i64,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return wire.isCheckpoint(bytes, checkpoint_magic);
}

/// Structural validation allocates nothing. Recomputed checksums alone cannot
/// smuggle duplicate names, impossible phases, invalid base32, or policy fields.
pub fn validateCheckpoint(bytes: []const u8) Error!void {
    const h = try parseHeader(bytes);
    const body = try wire.parseFrame(bytes, checkpoint_magic, header_len, domain);
    if (h.verify_count > body.len / 22 or h.reset_count > body.len / 18 or
        h.totp_count > body.len / 17) return error.Truncated;
    var reader = wire.Reader{ .bytes = body };
    var previous: ?[]const u8 = null;
    for (0..h.verify_count) |_| {
        const record = try readVerify(&reader, h.verify_params);
        try advanceKey(&previous, record.key);
    }
    previous = null;
    for (0..h.reset_count) |_| {
        const record = try readReset(&reader, h.reset_params);
        try advanceKey(&previous, record.key);
    }
    previous = null;
    for (0..h.totp_count) |_| {
        const record = try readTotp(&reader);
        try advanceKey(&previous, record.key);
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Capture under the server's accepted-event cut. TotpStore also holds its read
/// lock for the entire sort and serialization, including the replay counters.
pub fn encode(
    allocator: std.mem.Allocator,
    verifies: *const verify_mod.VerifyStore,
    resets: *const reset_mod.ResetStore,
    totp: *totp_mod.TotpStore,
) Error![]u8 {
    totp.lock.lockShared();
    defer totp.lock.unlockShared();
    const h = try sourceHeader(verifies, resets, totp);
    const verify_keys = try sortedKeys(allocator, &verifies.entries);
    defer allocator.free(verify_keys);
    const reset_keys = try sortedKeys(allocator, &resets.entries);
    defer allocator.free(reset_keys);
    const totp_keys = try sortedKeys(allocator, &totp.entries);
    defer allocator.free(totp_keys);

    var size: usize = header_len + wire.checksum_len;
    for (verify_keys) |key| {
        const item = verifies.entries.get(key).?;
        try checkVerify(key, item.account, item.contact, item.token, item.attempts, h.verify_params);
        try wire.addLen(&size, 17 + key.len + item.account.len + item.contact.len + item.token.len);
    }
    for (reset_keys) |key| {
        const item = resets.entries.get(key).?;
        try checkReset(key, item.account, item.token, item.attempts, h.reset_params);
        try wire.addLen(&size, 15 + key.len + item.account.len + item.token.len);
    }
    for (totp_keys) |key| {
        const item = totp.entries.get(key).?;
        try checkTotp(key, item.secret_b32, @intFromEnum(item.phase) == 1, item.last_step);
        if (item.secret.len == 0) return error.InvalidField;
        try wire.addLen(&size, 14 + key.len + item.secret_b32.len);
    }
    if (size > max_checkpoint_bytes) return error.CheckpointTooLarge;

    const bytes = try allocator.alloc(u8, size);
    errdefer freeEncoded(allocator, bytes);
    var writer = wire.Writer{ .bytes = bytes };
    writeHeader(&writer, h, size - header_len - wire.checksum_len);
    for (verify_keys) |key| {
        const item = verifies.entries.get(key).?;
        writer.writeU16(@intCast(key.len));
        writer.writeU16(@intCast(item.account.len));
        writer.writeU16(@intCast(item.contact.len));
        writer.writeU16(@intCast(item.token.len));
        writer.writeU64(item.issued_ms);
        writer.writeByte(item.attempts);
        writer.writeBytes(key);
        writer.writeBytes(item.account);
        writer.writeBytes(item.contact);
        writer.writeBytes(item.token);
    }
    for (reset_keys) |key| {
        const item = resets.entries.get(key).?;
        writer.writeU16(@intCast(key.len));
        writer.writeU16(@intCast(item.account.len));
        writer.writeU16(@intCast(item.token.len));
        writer.writeU64(item.issued_ms);
        writer.writeByte(item.attempts);
        writer.writeBytes(key);
        writer.writeBytes(item.account);
        writer.writeBytes(item.token);
    }
    for (totp_keys) |key| {
        const item = totp.entries.get(key).?;
        writer.writeU16(@intCast(key.len));
        writer.writeU16(@intCast(item.secret_b32.len));
        writer.writeByte(@intFromEnum(item.phase));
        writer.writeByte(@intFromBool(item.last_step != null));
        writer.writeI64(item.last_step orelse 0);
        writer.writeBytes(key);
        writer.writeBytes(item.secret_b32);
    }
    wire.finish(&writer, domain);
    try validateCheckpoint(bytes);
    return bytes;
}

/// Wipe the checkpoint because it contains live bearer tokens and TOTP secrets.
pub fn freeEncoded(allocator: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
}

/// Candidates are fully owned until commit. After commit they own the replaced
/// maps; `deinit` then wipes the old bearer tokens and TOTP secrets.
pub const Staged = struct {
    target_verifies: *verify_mod.VerifyStore,
    target_resets: *reset_mod.ResetStore,
    target_totp: *totp_mod.TotpStore,
    verifies: verify_mod.VerifyStore,
    resets: reset_mod.ResetStore,
    totp: totp_mod.TotpStore,
    committed: bool = false,

    pub fn commit(self: *Staged) void {
        std.debug.assert(!self.committed);
        self.target_totp.lock.lockExclusive();
        defer self.target_totp.lock.unlockExclusive();
        std.mem.swap(@TypeOf(self.verifies.entries), &self.verifies.entries, &self.target_verifies.entries);
        std.mem.swap(@TypeOf(self.resets.entries), &self.resets.entries, &self.target_resets.entries);
        std.mem.swap(@TypeOf(self.totp.entries), &self.totp.entries, &self.target_totp.entries);
        self.committed = true;
    }

    pub fn deinit(self: *Staged) void {
        self.verifies.deinit();
        self.resets.deinit();
        self.totp.deinit();
        self.* = undefined;
    }
};

/// Validate and build every replacement before a no-allocation commit. A bad
/// policy or malformed wire is refused before any candidate allocation.
pub fn stageFor(
    bytes: []const u8,
    verifies: *verify_mod.VerifyStore,
    resets: *reset_mod.ResetStore,
    totp: *totp_mod.TotpStore,
) Error!Staged {
    try validateCheckpoint(bytes);
    const h = try parseHeader(bytes);
    if (!std.meta.eql(h.verify_params, verifies.params) or
        !std.meta.eql(h.reset_params, resets.params) or
        !std.meta.eql(h.totp_params, totp.params)) return error.ConfigMismatch;

    var result: Staged = .{
        .target_verifies = verifies,
        .target_resets = resets,
        .target_totp = totp,
        .verifies = verify_mod.VerifyStore.init(verifies.allocator, verifies.params),
        .resets = reset_mod.ResetStore.init(resets.allocator, resets.params),
        .totp = totp_mod.TotpStore.init(totp.allocator, totp.params),
    };
    errdefer result.deinit();
    var reader = wire.Reader{ .bytes = bytes[header_len .. bytes.len - wire.checksum_len] };
    for (0..h.verify_count) |_| try addVerify(&result.verifies, try readVerify(&reader, h.verify_params));
    for (0..h.reset_count) |_| try addReset(&result.resets, try readReset(&reader, h.reset_params));
    for (0..h.totp_count) |_| {
        const record = try readTotp(&reader);
        if (record.active) {
            result.totp.loadActive(record.key, record.secret_b32) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidField,
            };
        } else {
            result.totp.enroll(record.key, record.secret_b32) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidField,
            };
        }
        result.totp.entries.getPtr(record.key).?.last_step = record.last_step;
    }
    std.debug.assert(reader.remaining() == 0);
    return result;
}

fn sourceHeader(verifies: *const verify_mod.VerifyStore, resets: *const reset_mod.ResetStore, totp: *const totp_mod.TotpStore) Error!Header {
    const h: Header = .{
        .verify_count = verifies.entries.count(),
        .reset_count = resets.entries.count(),
        .totp_count = totp.entries.count(),
        .verify_params = verifies.params,
        .reset_params = resets.params,
        .totp_params = totp.params,
    };
    try checkHeader(h);
    return h;
}

fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < header_len + wire.checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != 1) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 }) or
        !std.mem.eql(u8, bytes[61..64], &.{ 0, 0, 0 })) return error.InvalidField;
    if (bytes[60] > 2) return error.InvalidField;
    const h: Header = .{
        .verify_count = std.mem.readInt(u32, bytes[12..16], .little),
        .reset_count = std.mem.readInt(u32, bytes[16..20], .little),
        .totp_count = std.mem.readInt(u32, bytes[20..24], .little),
        .verify_params = .{
            .max_pending = std.mem.readInt(u32, bytes[24..28], .little),
            .token_bytes = std.mem.readInt(u16, bytes[28..30], .little),
            .ttl_ms = std.mem.readInt(u64, bytes[30..38], .little),
            .max_attempts = bytes[38],
            .max_account_bytes = std.mem.readInt(u16, bytes[39..41], .little),
            .max_contact_bytes = std.mem.readInt(u16, bytes[41..43], .little),
        },
        .reset_params = .{
            .token_bytes = std.mem.readInt(u16, bytes[43..45], .little),
            .ttl_ms = std.mem.readInt(u64, bytes[45..53], .little),
            .max_attempts = bytes[53],
        },
        .totp_params = .{
            .window = bytes[54],
            .digits = bytes[55],
            .algo = @enumFromInt(bytes[60]),
        },
    };
    if (!std.mem.eql(u8, bytes[56..60], &.{ 0, 0, 0, 0 })) return error.InvalidField;
    try checkHeader(h);
    return h;
}

fn checkHeader(h: Header) Error!void {
    if (h.verify_count > max_entries or h.reset_count > max_entries or h.totp_count > max_entries or
        h.verify_count > h.verify_params.max_pending or h.verify_params.max_pending > max_entries or
        h.verify_params.token_bytes == 0 or h.verify_params.token_bytes > max_token_bytes or
        h.verify_params.max_account_bytes == 0 or h.verify_params.max_account_bytes > max_account_len or
        h.verify_params.max_contact_bytes == 0 or h.verify_params.max_contact_bytes > max_contact_len or
        h.reset_params.token_bytes == 0 or h.reset_params.token_bytes > max_token_bytes or
        h.totp_params.digits == 0 or h.totp_params.digits > 9) return error.InvalidField;
}

fn writeHeader(writer: *wire.Writer, h: Header, body_len: usize) void {
    writer.writeBytes(&checkpoint_magic);
    writer.writeByte(1);
    writer.writeBytes(&.{ 0, 0, 0 });
    writer.writeU32(@intCast(body_len));
    writer.writeU32(@intCast(h.verify_count));
    writer.writeU32(@intCast(h.reset_count));
    writer.writeU32(@intCast(h.totp_count));
    writer.writeU32(@intCast(h.verify_params.max_pending));
    writer.writeU16(@intCast(h.verify_params.token_bytes));
    writer.writeU64(h.verify_params.ttl_ms);
    writer.writeByte(h.verify_params.max_attempts);
    writer.writeU16(@intCast(h.verify_params.max_account_bytes));
    writer.writeU16(@intCast(h.verify_params.max_contact_bytes));
    writer.writeU16(@intCast(h.reset_params.token_bytes));
    writer.writeU64(h.reset_params.ttl_ms);
    writer.writeByte(h.reset_params.max_attempts);
    writer.writeByte(h.totp_params.window);
    writer.writeByte(h.totp_params.digits);
    writer.writeBytes(&.{ 0, 0, 0, 0 });
    writer.writeByte(@intFromEnum(h.totp_params.algo));
    writer.writeBytes(&.{ 0, 0, 0 });
    std.debug.assert(writer.pos == header_len);
}

fn sortedKeys(allocator: std.mem.Allocator, map: anytype) Error![][]const u8 {
    const keys = try allocator.alloc([]const u8, map.count());
    var it = map.iterator();
    var i: usize = 0;
    while (it.next()) |entry| : (i += 1) keys[i] = entry.key_ptr.*;
    std.mem.sort([]const u8, keys, {}, lessThan);
    return keys;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn advanceKey(previous: *?[]const u8, key: []const u8) Error!void {
    if (previous.*) |prior| {
        if (!std.mem.lessThan(u8, prior, key)) return error.NonCanonicalOrder;
    }
    previous.* = key;
}

fn readVerify(reader: *wire.Reader, params: verify_mod.Params) Error!VerifyRecord {
    const key_len: usize = try reader.readU16();
    const account_len: usize = try reader.readU16();
    const contact_len: usize = try reader.readU16();
    const token_len: usize = try reader.readU16();
    const issued_ms = try reader.readU64();
    const attempts = try reader.readByte();
    const key = try reader.take(key_len);
    const account = try reader.take(account_len);
    const contact = try reader.take(contact_len);
    const token = try reader.take(token_len);
    try checkVerify(key, account, contact, token, attempts, params);
    return .{ .key = key, .account = account, .contact = contact, .token = token, .issued_ms = issued_ms, .attempts = attempts };
}

fn readReset(reader: *wire.Reader, params: reset_mod.Params) Error!ResetRecord {
    const key_len: usize = try reader.readU16();
    const account_len: usize = try reader.readU16();
    const token_len: usize = try reader.readU16();
    const issued_ms = try reader.readU64();
    const attempts = try reader.readByte();
    const key = try reader.take(key_len);
    const account = try reader.take(account_len);
    const token = try reader.take(token_len);
    try checkReset(key, account, token, attempts, params);
    return .{ .key = key, .account = account, .token = token, .issued_ms = issued_ms, .attempts = attempts };
}

fn readTotp(reader: *wire.Reader) Error!TotpRecord {
    const key_len: usize = try reader.readU16();
    const b32_len: usize = try reader.readU16();
    const phase = try reader.readByte();
    const has_step = try reader.readByte();
    const step = try reader.readI64();
    const key = try reader.take(key_len);
    const b32 = try reader.take(b32_len);
    if (phase > 1 or has_step > 1 or (has_step == 0 and step != 0) or
        (has_step == 1 and (phase == 0 or step < 0))) return error.InvalidField;
    try checkTotp(key, b32, phase == 1, if (has_step == 1) step else null);
    return .{ .key = key, .secret_b32 = b32, .active = phase == 1, .last_step = if (has_step == 1) step else null };
}

fn checkVerify(key: []const u8, account: []const u8, contact: []const u8, token: []const u8, attempts: u8, params: verify_mod.Params) Error!void {
    if (key.len == 0 or key.len > params.max_account_bytes or account.len != key.len or
        contact.len == 0 or contact.len > params.max_contact_bytes or
        token.len != params.token_bytes * 2 or attempts > params.max_attempts) return error.InvalidField;
    try checkAccountKey(key, account);
    for (contact) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidField;
    for (token) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidField;
}

fn checkReset(key: []const u8, account: []const u8, token: []const u8, attempts: u8, params: reset_mod.Params) Error!void {
    if (key.len == 0 or key.len > max_account_len or account.len != key.len or
        token.len != params.token_bytes or attempts > params.max_attempts) return error.InvalidField;
    try checkAccountKey(key, account);
}

fn checkTotp(key: []const u8, b32: []const u8, active: bool, last_step: ?i64) Error!void {
    if (key.len == 0 or key.len > max_account_len or b32.len == 0 or b32.len > max_secret_b32_len or
        (!active and last_step != null)) return error.InvalidField;
    if (last_step) |step| if (step < 0) return error.InvalidField;
    try checkAccountKey(key, key);
    try checkBase32(b32);
}

fn checkAccountKey(key: []const u8, account: []const u8) Error!void {
    if (key.len != account.len or key.len == 0) return error.InvalidField;
    for (key, account) |lower, original| {
        if (!(original >= 'A' and original <= 'Z') and
            !(original >= 'a' and original <= 'z') and
            !(original >= '0' and original <= '9') and
            original != '-' and original != '_' and original != '.' and original != '@') return error.InvalidField;
        if (lower != std.ascii.toLower(original)) return error.InvalidField;
    }
}

/// Matches crypto/totp.zig's accepted base32 alphabet, padding, and tail bits.
fn checkBase32(encoded: []const u8) Error!void {
    var acc: u16 = 0;
    var bits: u4 = 0;
    var symbols: usize = 0;
    var padding: usize = 0;
    var seen_padding = false;
    for (encoded) |byte| {
        switch (byte) {
            ' ', '\t', '\r', '\n' => continue,
            '=' => {
                seen_padding = true;
                padding += 1;
                continue;
            },
            else => {},
        }
        if (seen_padding) return error.InvalidField;
        const value: u16 = switch (byte) {
            'A'...'Z' => byte - 'A',
            'a'...'z' => byte - 'a',
            '2'...'7' => byte - '2' + 26,
            else => return error.InvalidField,
        };
        symbols += 1;
        acc = (acc << 5) | value;
        bits += 5;
        while (bits >= 8) bits -= 8;
    }
    if (symbols < 2) return error.InvalidField;
    const expected_padding: usize = switch (symbols % 8) {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        else => return error.InvalidField,
    };
    if (padding != 0 and (padding != expected_padding or (symbols + padding) % 8 != 0)) return error.InvalidField;
    if (bits != 0 and (acc & ((@as(u16, 1) << bits) - 1)) != 0) return error.InvalidField;
}

fn addVerify(store: *verify_mod.VerifyStore, record: VerifyRecord) Error!void {
    const key = try store.allocator.dupe(u8, record.key);
    errdefer store.allocator.free(key);
    const account = try store.allocator.dupe(u8, record.account);
    errdefer store.allocator.free(account);
    const contact = try store.allocator.dupe(u8, record.contact);
    errdefer store.allocator.free(contact);
    const token = try store.allocator.dupe(u8, record.token);
    errdefer {
        std.crypto.secureZero(u8, token);
        store.allocator.free(token);
    }
    try store.entries.putNoClobber(key, .{ .account = account, .contact = contact, .token = token, .issued_ms = record.issued_ms, .attempts = record.attempts });
}

fn addReset(store: *reset_mod.ResetStore, record: ResetRecord) Error!void {
    const key = try store.allocator.dupe(u8, record.key);
    errdefer store.allocator.free(key);
    const account = try store.allocator.dupe(u8, record.account);
    errdefer store.allocator.free(account);
    const token = try store.allocator.dupe(u8, record.token);
    errdefer {
        std.crypto.secureZero(u8, token);
        store.allocator.free(token);
    }
    try store.entries.putNoClobber(key, .{ .account = account, .token = token, .issued_ms = record.issued_ms, .attempts = record.attempts });
}

fn rechecksum(bytes: []u8) void {
    var digest: [wire.checksum_len]u8 = undefined;
    wire.checksum(domain, bytes[0 .. bytes.len - wire.checksum_len], &digest);
    @memcpy(bytes[bytes.len - wire.checksum_len ..], &digest);
}

fn testCode(secret: []const u8, now: i64) ![6]u8 {
    const crypto_totp = @import("../../crypto/totp.zig");
    var value = try crypto_totp.totp(secret, now, 30, 0, 6, .sha1);
    var result: [6]u8 = undefined;
    var i: usize = result.len;
    while (i > 0) {
        i -= 1;
        result[i] = @intCast('0' + value % 10);
        value /= 10;
    }
    return result;
}

test "Windows account-flow checkpoint preserves pending attempts and TOTP replay guard" {
    const allocator = std.testing.allocator;
    var verifies = verify_mod.VerifyStore.init(allocator, .{ .token_bytes = 2, .max_attempts = 3 });
    defer verifies.deinit();
    var resets = reset_mod.ResetStore.init(allocator, .{ .token_bytes = 2, .max_attempts = 3 });
    defer resets.deinit();
    var totp = totp_mod.TotpStore.init(allocator, .{});
    defer totp.deinit();
    const verify_token = try verifies.issue("Alice", "alice@example.invalid", &.{ 0xab, 0xcd }, 100);
    _ = verifies.confirm("alice", "wrong", 101);
    _ = try verifies.issue("bob", "bob@example.invalid", &.{ 0x01, 0x02 }, 102);
    try resets.issue("Alice", &.{ 0x72, 0x73 }, 103);
    _ = resets.confirm("alice", "wrong", 104);
    try totp.enroll("bob", "MZXW6YTBOI======");
    try totp.loadActive("alice", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    totp.entries.getPtr("alice").?.last_step = 1;

    const bytes = try encode(allocator, &verifies, &resets, &totp);
    defer freeEncoded(allocator, bytes);
    try validateCheckpoint(bytes);
    var fresh_verifies = verify_mod.VerifyStore.init(allocator, verifies.params);
    defer fresh_verifies.deinit();
    var fresh_resets = reset_mod.ResetStore.init(allocator, resets.params);
    defer fresh_resets.deinit();
    var fresh_totp = totp_mod.TotpStore.init(allocator, totp.params);
    defer fresh_totp.deinit();
    _ = try fresh_verifies.issue("old", "old@example.invalid", &.{ 0x04, 0x05 }, 1);
    try fresh_resets.issue("old", &.{ 0x06, 0x07 }, 1);
    try fresh_totp.enroll("old", "MZXW6YTBOI======");

    var staged = try stageFor(bytes, &fresh_verifies, &fresh_resets, &fresh_totp);
    defer staged.deinit();
    try std.testing.expect(fresh_verifies.isPending("old"));
    try std.testing.expect(fresh_totp.isPending("old"));
    const again = try encode(allocator, &staged.verifies, &staged.resets, &staged.totp);
    defer freeEncoded(allocator, again);
    try std.testing.expectEqualSlices(u8, bytes, again);
    staged.commit();
    try std.testing.expect(!fresh_verifies.isPending("old"));
    try std.testing.expect(!fresh_resets.isPending("old"));
    try std.testing.expect(!fresh_totp.isPending("old"));
    try std.testing.expectEqual(@as(u8, 1), fresh_verifies.pending("alice").?.attempts);
    try std.testing.expectEqual(@as(u64, 100), fresh_verifies.pending("alice").?.issued_ms);
    try std.testing.expectEqual(@as(u8, 1), fresh_resets.pending("alice").?.attempts);
    try std.testing.expectEqual(@as(u64, 103), fresh_resets.pending("alice").?.issued_ms);
    try std.testing.expect(fresh_totp.isPending("bob"));
    try std.testing.expect(fresh_totp.isEnrolled("alice"));
    try std.testing.expectEqual(@as(?i64, 1), fresh_totp.entries.get("alice").?.last_step);
    try std.testing.expectEqual(verify_mod.Result.verified, fresh_verifies.confirm("ALICE", verify_token, 105));
    try std.testing.expectEqual(reset_mod.Result.ok, fresh_resets.confirm("alice", &.{ 0x72, 0x73 }, 105));
    const old_code = try testCode(fresh_totp.entries.get("alice").?.secret, 59);
    try std.testing.expectEqual(totp_mod.VerifyOutcome.bad_code, try fresh_totp.verify("alice", &old_code, 59));
    const next_code = try testCode(fresh_totp.entries.get("alice").?.secret, 89);
    try std.testing.expectEqual(totp_mod.VerifyOutcome.ok, try fresh_totp.verify("alice", &next_code, 89));
}

test "Windows account-flow checkpoint rejects tampering and policy mismatch" {
    const allocator = std.testing.allocator;
    var verifies = verify_mod.VerifyStore.init(allocator, .{ .token_bytes = 2 });
    defer verifies.deinit();
    var resets = reset_mod.ResetStore.init(allocator, .{ .token_bytes = 2 });
    defer resets.deinit();
    var totp = totp_mod.TotpStore.init(allocator, .{});
    defer totp.deinit();
    _ = try verifies.issue("a", "a@b", &.{ 0xab, 0xcd }, 7);
    try resets.issue("b", &.{ 0x01, 0x02 }, 8);
    try totp.enroll("c", "MZXW6YTBOI======");
    const bytes = try encode(allocator, &verifies, &resets, &totp);
    defer freeEncoded(allocator, bytes);
    try std.testing.expectError(error.Truncated, validateCheckpoint(bytes[0 .. bytes.len - 1]));
    var bad = try allocator.dupe(u8, bytes);
    defer freeEncoded(allocator, bad);
    bad[header_len + 17 + 1 + 1 + 3] = 'X';
    try std.testing.expectError(error.ChecksumMismatch, validateCheckpoint(bad));
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[55] = 10;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    const totp_offset = header_len + (17 + 1 + 1 + 3 + 4) + (15 + 1 + 1 + 2);
    bad[totp_offset + 4] = 2;
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));
    @memcpy(bad, bytes);
    bad[totp_offset + 14 + 1] = '!';
    rechecksum(bad);
    try std.testing.expectError(error.InvalidField, validateCheckpoint(bad));

    var changed = verify_mod.VerifyStore.init(allocator, .{ .token_bytes = 2, .ttl_ms = 1 });
    defer changed.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    changed.allocator = failing.allocator();
    try std.testing.expectError(error.ConfigMismatch, stageFor(bytes, &changed, &resets, &totp));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

fn allocationRollback(allocator: std.mem.Allocator, bytes: []const u8) !void {
    const stable = std.testing.allocator;
    var verifies = verify_mod.VerifyStore.init(stable, .{ .token_bytes = 2 });
    defer verifies.deinit();
    var resets = reset_mod.ResetStore.init(stable, .{ .token_bytes = 2 });
    defer resets.deinit();
    var totp = totp_mod.TotpStore.init(stable, .{});
    defer totp.deinit();
    _ = try verifies.issue("old", "old@example.invalid", &.{ 0x03, 0x04 }, 1);
    try resets.issue("old", &.{ 0x05, 0x06 }, 1);
    try totp.loadActive("old", "MZXW6YTBOI======");
    totp.entries.getPtr("old").?.last_step = 4;
    const before = try encode(stable, &verifies, &resets, &totp);
    defer freeEncoded(stable, before);
    verifies.allocator = allocator;
    resets.allocator = allocator;
    totp.allocator = allocator;
    defer {
        verifies.allocator = stable;
        resets.allocator = stable;
        totp.allocator = stable;
    }
    var staged = stageFor(bytes, &verifies, &resets, &totp) catch |err| {
        verifies.allocator = stable;
        resets.allocator = stable;
        totp.allocator = stable;
        const after_failure = try encode(stable, &verifies, &resets, &totp);
        defer freeEncoded(stable, after_failure);
        try std.testing.expectEqualSlices(u8, before, after_failure);
        return err;
    };
    staged.deinit();
    verifies.allocator = stable;
    resets.allocator = stable;
    totp.allocator = stable;
    const after_success = try encode(stable, &verifies, &resets, &totp);
    defer freeEncoded(stable, after_success);
    try std.testing.expectEqualSlices(u8, before, after_success);
}

test "Windows account-flow stage sweeps allocations with byte-exact rollback" {
    const allocator = std.testing.allocator;
    var verifies = verify_mod.VerifyStore.init(allocator, .{ .token_bytes = 2 });
    defer verifies.deinit();
    var resets = reset_mod.ResetStore.init(allocator, .{ .token_bytes = 2 });
    defer resets.deinit();
    var totp = totp_mod.TotpStore.init(allocator, .{});
    defer totp.deinit();
    _ = try verifies.issue("alice", "alice@example.invalid", &.{ 0x01, 0x02 }, 11);
    try resets.issue("bob", &.{ 0x01, 0x02 }, 12);
    try totp.enroll("alice", "MZXW6YTBOI======");
    try totp.loadActive("bob", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    totp.entries.getPtr("bob").?.last_step = 4;
    const bytes = try encode(allocator, &verifies, &resets, &totp);
    defer freeEncoded(allocator, bytes);
    try std.testing.checkAllAllocationFailures(allocator, allocationRollback, .{bytes});
}
