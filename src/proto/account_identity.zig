// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable account identity assertions.
//!
//! A sovereign account key is an Ed25519 public key plus a self-signature over
//! the account binding. The daemon does not mint user keys; it verifies that the
//! presented key controls its own account assertion, then stores the bounded
//! public metadata as user PROP facts that ride ENTITY_PROP replication.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

pub const prop_prefix = "identity.key.";
pub const max_label_len: usize = 32;
pub const public_key_len: usize = Ed25519.PublicKey.encoded_length;
pub const signature_len: usize = Ed25519.Signature.encoded_length;
pub const public_key_hex_len: usize = public_key_len * 2;
pub const signature_hex_len: usize = signature_len * 2;
pub const max_value_len: usize = public_key_hex_len + 1 + signature_hex_len;
pub const max_account_len: usize = 64;
pub const max_transcript_len: usize = transcript_domain.len + 1 + max_account_len + 1 + max_label_len + 1 + public_key_len;

const transcript_domain = "OROCHI-ACCOUNT-IDENTITY-v1";

pub const Claim = struct {
    public_key: [public_key_len]u8,
    signature: [signature_len]u8,
};

pub fn validLabel(raw: []const u8) bool {
    if (raw.len == 0 or raw.len > max_label_len) return false;
    for (raw) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
        else => return false,
    };
    return true;
}

fn decodeHex(comptime len: usize, raw: []const u8) ?[len / 2]u8 {
    if (raw.len != len) return null;
    var out: [len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, raw) catch return null;
    return out;
}

pub fn parsePublicKeyHex(raw: []const u8) ?[public_key_len]u8 {
    return decodeHex(public_key_hex_len, raw);
}

pub fn parseSignatureHex(raw: []const u8) ?[signature_len]u8 {
    return decodeHex(signature_hex_len, raw);
}

pub fn transcript(account: []const u8, label: []const u8, public_key: [public_key_len]u8, out: []u8) ?[]const u8 {
    if (account.len == 0 or account.len > max_account_len or !validLabel(label)) return null;
    const need = transcript_domain.len + 1 + account.len + 1 + label.len + 1 + public_key.len;
    if (need > out.len) return null;
    var off: usize = 0;
    @memcpy(out[off..][0..transcript_domain.len], transcript_domain);
    off += transcript_domain.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..account.len], account);
    off += account.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..label.len], label);
    off += label.len;
    out[off] = 0;
    off += 1;
    @memcpy(out[off..][0..public_key.len], &public_key);
    off += public_key.len;
    return out[0..off];
}

pub fn verifyClaim(account: []const u8, label: []const u8, public_key_hex: []const u8, signature_hex: []const u8) bool {
    const public_key = parsePublicKeyHex(public_key_hex) orelse return false;
    const signature = parseSignatureHex(signature_hex) orelse return false;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript(account, label, public_key, &transcript_buf) orelse return false;
    sig.verifyStrict(msg, pk) catch return false;
    return true;
}

pub fn propKey(label: []const u8, out: []u8) ?[]const u8 {
    if (!validLabel(label)) return null;
    if (prop_prefix.len + label.len > out.len) return null;
    @memcpy(out[0..prop_prefix.len], prop_prefix);
    @memcpy(out[prop_prefix.len..][0..label.len], label);
    return out[0 .. prop_prefix.len + label.len];
}

pub fn isPropKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, prop_prefix) and validLabel(key[prop_prefix.len..]);
}

pub fn claimValue(public_key_hex: []const u8, signature_hex: []const u8, out: []u8) ?[]const u8 {
    const public_key = parsePublicKeyHex(public_key_hex) orelse return null;
    const signature = parseSignatureHex(signature_hex) orelse return null;
    if (max_value_len > out.len) return null;
    const public_hex = std.fmt.bytesToHex(public_key, .lower);
    const sig_hex = std.fmt.bytesToHex(signature, .lower);
    @memcpy(out[0..public_key_hex_len], &public_hex);
    out[public_key_hex_len] = ':';
    @memcpy(out[public_key_hex_len + 1 ..][0..signature_hex_len], &sig_hex);
    return out[0..max_value_len];
}

pub fn parseClaimValue(value: []const u8) ?Claim {
    if (value.len != max_value_len or value[public_key_hex_len] != ':') return null;
    return .{
        .public_key = parsePublicKeyHex(value[0..public_key_hex_len]) orelse return null,
        .signature = parseSignatureHex(value[public_key_hex_len + 1 ..]) orelse return null,
    };
}

// ---------------------------------------------------------------------------
// Residence proofs (Design C — account-key residence proof over ENTITY_PROP)
// ---------------------------------------------------------------------------
//
// A residence proof is ONE login-time signature by the account's identity key
// binding `{account, node-shortId, epoch, expiry_ms}`: "this account is really
// logged in on this node until expiry". It rides an ordinary replicated user
// PROP (`identity.residence.<node-hex>`) — no membership wire change — and any
// node verifies it against the RECEIVER-OWNED replicated `identity.key.*`
// pubkey, never a key from the wire. A Byzantine peer B holds no account key,
// so it cannot mint a proof binding the account to B; and a genuine
// proof-for-N fails the node binding when replayed from B's frames.
//
// Wire (all integers big-endian; canonical, length-prefixed):
//   magic:u32("ARP1") || len8(account) || account || node:u64 || epoch:u64
//     || expiry_ms:u64 || sig:64
// Signed message = residence_domain || 0x00 || wire[0 .. wire.len - 64]
// (domain-separated from "OROCHI-ACCOUNT-IDENTITY-v1", signed_frame, and
// oper_cred_share "OCG1"). `expiry_ms` is WALL-CLOCK ms — cross-host absolute
// times always use the real-time clock, never a per-node monotonic clock.

pub const residence_prop_prefix = "identity.residence.";
pub const residence_domain = "OROCHI-ACCOUNT-RESIDENCE-v1";
pub const residence_magic: u32 = 0x41525031; // "ARP1"
/// Node shortIds render as fixed-width 16-char lower hex in the prop key.
pub const residence_node_hex_len: usize = 16;
/// Fixed-width part of the wire: magic + account length byte + node + epoch + expiry.
pub const residence_fixed_len: usize = 4 + 1 + 8 + 8 + 8;
pub const max_residence_len: usize = residence_fixed_len + max_account_len + signature_len;
/// The prop VALUE is the wire in lower hex (prop values are text; 314 <= the
/// 512-byte IRCX prop value cap).
pub const max_residence_hex_len: usize = max_residence_len * 2;
/// Hard upper bound on `expiry_ms - now_ms` at verify time: bounds the replay
/// blast radius of a captured proof (the compromised-HOME-node residual, R2).
/// The client re-signs at login/epoch — not per frame — so one hour is generous
/// against clock skew while keeping the bearer window short.
pub const max_residence_window_ms: u64 = 60 * 60 * 1000;

/// Plaintext residence binding. `account` borrows from the caller on encode
/// and from the wire buffer on parse.
pub const Residence = struct {
    account: []const u8,
    /// The residing node's mesh shortId (`signed_frame.originShortId` domain) —
    /// NEVER a nick/UID. The verifier requires `node == frame origin`.
    node: u64,
    /// Monotonic per-(account,node) counter; the store rejects a non-increasing
    /// epoch so a captured older proof cannot supersede a newer one.
    epoch: u64,
    /// Wall-clock expiry in ms (exclusive upper bound).
    expiry_ms: u64,
};

pub const ParsedResidence = struct {
    res: Residence,
    signature: [signature_len]u8,
};

pub const ResidenceVerifyError = error{
    /// Structural problem: truncated, oversize/empty account, bad magic, or
    /// trailing bytes.
    BadFormat,
    /// Signature did not verify against the supplied account public key.
    BadSignature,
    /// `account` did not match the claim being admitted.
    WrongAccount,
    /// `node` did not match the frame's signed origin (a valid proof-for-N
    /// replayed from a different node).
    WrongNode,
    /// `now_ms >= expiry_ms`.
    Expired,
    /// `expiry_ms` further than `max_residence_window_ms` past `now_ms` —
    /// rejected to bound the bearer/replay window.
    TooFarFuture,
};

/// Serialize the unsigned wire prefix (everything the signature covers, minus
/// the domain framing) into `out`. Null on an invalid account or a short buffer.
fn residenceUnsigned(res: Residence, out: []u8) ?[]const u8 {
    if (res.account.len == 0 or res.account.len > max_account_len) return null;
    const need = residence_fixed_len + res.account.len;
    if (need > out.len) return null;
    var off: usize = 0;
    std.mem.writeInt(u32, out[off..][0..4], residence_magic, .big);
    off += 4;
    out[off] = @intCast(res.account.len);
    off += 1;
    @memcpy(out[off..][0..res.account.len], res.account);
    off += res.account.len;
    std.mem.writeInt(u64, out[off..][0..8], res.node, .big);
    off += 8;
    std.mem.writeInt(u64, out[off..][0..8], res.epoch, .big);
    off += 8;
    std.mem.writeInt(u64, out[off..][0..8], res.expiry_ms, .big);
    off += 8;
    return out[0..off];
}

/// The exact bytes the account key signs: domain || 0x00 || unsigned-wire.
fn residenceMessage(unsigned: []const u8, out: []u8) ?[]const u8 {
    const need = residence_domain.len + 1 + unsigned.len;
    if (need > out.len) return null;
    @memcpy(out[0..residence_domain.len], residence_domain);
    out[residence_domain.len] = 0;
    @memcpy(out[residence_domain.len + 1 ..][0..unsigned.len], unsigned);
    return out[0..need];
}

const max_residence_msg_len: usize = residence_domain.len + 1 + residence_fixed_len + max_account_len;

/// Assemble the full wire from fields + a caller-supplied signature (the daemon
/// side: the CLIENT signs; the server only ever assembles what it verified).
pub fn encodeResidence(res: Residence, signature: [signature_len]u8, out: []u8) ?[]const u8 {
    const unsigned = residenceUnsigned(res, out) orelse return null;
    if (unsigned.len + signature_len > out.len) return null;
    @memcpy(out[unsigned.len..][0..signature_len], &signature);
    return out[0 .. unsigned.len + signature_len];
}

/// Sign a residence binding with the account identity key (tests + tooling; in
/// production the client device holds the key and the daemon never signs).
pub fn signResidence(res: Residence, key_pair: Ed25519.KeyPair, out: []u8) ?[]const u8 {
    var unsigned_buf: [residence_fixed_len + max_account_len]u8 = undefined;
    const unsigned = residenceUnsigned(res, &unsigned_buf) orelse return null;
    var msg_buf: [max_residence_msg_len]u8 = undefined;
    const msg = residenceMessage(unsigned, &msg_buf) orelse return null;
    const sig = key_pair.sign(msg, null) catch return null;
    return encodeResidence(res, sig.toBytes(), out);
}

/// Structural parse — bounds and framing only, BEFORE any crypto. Rejects
/// truncation, an empty/oversize account, bad magic, and trailing bytes.
pub fn parseResidence(wire: []const u8) ?ParsedResidence {
    if (wire.len < residence_fixed_len + 1 + signature_len) return null;
    if (std.mem.readInt(u32, wire[0..4], .big) != residence_magic) return null;
    const account_len: usize = wire[4];
    if (account_len == 0 or account_len > max_account_len) return null;
    if (wire.len != residence_fixed_len + account_len + signature_len) return null;
    var off: usize = 5;
    const account = wire[off..][0..account_len];
    off += account_len;
    const node = std.mem.readInt(u64, wire[off..][0..8], .big);
    off += 8;
    const epoch = std.mem.readInt(u64, wire[off..][0..8], .big);
    off += 8;
    const expiry_ms = std.mem.readInt(u64, wire[off..][0..8], .big);
    off += 8;
    var signature: [signature_len]u8 = undefined;
    @memcpy(&signature, wire[off..][0..signature_len]);
    return .{
        .res = .{ .account = account, .node = node, .epoch = epoch, .expiry_ms = expiry_ms },
        .signature = signature,
    };
}

/// Full fail-closed verify: structural parse, exact account binding, exact node
/// binding (== the frame's signed origin), wall-clock freshness bounded by the
/// hard replay window, then `verifyStrict` against the RECEIVER-OWNED account
/// pubkey. EVERY failure is an error — the caller maps any error to
/// `account_trusted = false` (the conservative UID path). Returns the parsed
/// binding (epoch for the store's supersede floor).
pub fn verifyResidence(
    wire: []const u8,
    public_key: [public_key_len]u8,
    expected_account: []const u8,
    expected_node: u64,
    now_ms: u64,
) ResidenceVerifyError!Residence {
    const parsed = parseResidence(wire) orelse return error.BadFormat;
    // Accounts are canonical (one fixed spelling daemon-wide), so exact bytes —
    // the same rule as route_table.sameAccount. An empty expectation never matches.
    if (expected_account.len == 0 or !std.mem.eql(u8, parsed.res.account, expected_account)) return error.WrongAccount;
    if (parsed.res.node != expected_node) return error.WrongNode;
    if (now_ms >= parsed.res.expiry_ms) return error.Expired;
    if (parsed.res.expiry_ms - now_ms > max_residence_window_ms) return error.TooFarFuture;
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(parsed.signature);
    var unsigned_buf: [residence_fixed_len + max_account_len]u8 = undefined;
    const unsigned = residenceUnsigned(parsed.res, &unsigned_buf) orelse return error.BadFormat;
    var msg_buf: [max_residence_msg_len]u8 = undefined;
    const msg = residenceMessage(unsigned, &msg_buf) orelse return error.BadFormat;
    sig.verifyStrict(msg, pk) catch return error.BadSignature;
    return parsed.res;
}

/// Prop key for a node's residence proof: `identity.residence.<16-lower-hex>`.
pub fn residencePropKey(node: u64, out: []u8) ?[]const u8 {
    if (residence_prop_prefix.len + residence_node_hex_len > out.len) return null;
    @memcpy(out[0..residence_prop_prefix.len], residence_prop_prefix);
    _ = std.fmt.bufPrint(out[residence_prop_prefix.len..], "{x:0>16}", .{node}) catch return null;
    return out[0 .. residence_prop_prefix.len + residence_node_hex_len];
}

pub fn isResidencePropKey(key: []const u8) bool {
    return residencePropNode(key) != null;
}

/// The node shortId a residence prop key names, or null when `key` is not a
/// well-formed residence key (wrong prefix/width/case).
pub fn residencePropNode(key: []const u8) ?u64 {
    if (key.len != residence_prop_prefix.len + residence_node_hex_len) return null;
    if (!std.mem.startsWith(u8, key, residence_prop_prefix)) return null;
    const hex = key[residence_prop_prefix.len..];
    for (hex) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return null, // canonical lower-hex only
    };
    return std.fmt.parseUnsigned(u64, hex, 16) catch null;
}

test "account identity claim validates self-signed account binding" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x41)));
    const public_hex = std.fmt.bytesToHex(kp.public_key.toBytes(), .lower);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript("alice", "primary", kp.public_key.toBytes(), &transcript_buf).?;
    const sig = try kp.sign(msg, null);
    const sig_hex = std.fmt.bytesToHex(sig.toBytes(), .lower);

    try std.testing.expect(verifyClaim("alice", "primary", &public_hex, &sig_hex));
    try std.testing.expect(!verifyClaim("alice", "laptop", &public_hex, &sig_hex));
    try std.testing.expect(!verifyClaim("bob", "primary", &public_hex, &sig_hex));
}

test "account identity props are bounded and normalized" {
    var key_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("identity.key.primary", propKey("primary", &key_buf).?);
    try std.testing.expect(propKey("bad label", &key_buf) == null);
    try std.testing.expect(isPropKey("identity.key.primary"));
    try std.testing.expect(!isPropKey("identity.key.bad label"));

    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x42)));
    const public_hex = std.fmt.bytesToHex(kp.public_key.toBytes(), .upper);
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript("alice", "primary", kp.public_key.toBytes(), &transcript_buf).?;
    const sig = try kp.sign(msg, null);
    const sig_hex = std.fmt.bytesToHex(sig.toBytes(), .upper);
    var value_buf: [max_value_len]u8 = undefined;
    const value = claimValue(&public_hex, &sig_hex, &value_buf).?;
    try std.testing.expectEqual(@as(usize, max_value_len), value.len);
    try std.testing.expect(parseClaimValue(value) != null);
}

test "account residence proof signs and verifies the full binding (KAT round-trip)" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const res = Residence{ .account = "kain", .node = 0xA1B2_C3D4_E5F6_0718, .epoch = 7, .expiry_ms = 1_000_000 };
    var wire_buf: [max_residence_len]u8 = undefined;
    const wire = signResidence(res, kp, &wire_buf).?;
    try std.testing.expectEqual(residence_fixed_len + res.account.len + signature_len, wire.len);

    const got = try verifyResidence(wire, kp.public_key.toBytes(), "kain", res.node, 500_000);
    try std.testing.expectEqualStrings("kain", got.account);
    try std.testing.expectEqual(res.node, got.node);
    try std.testing.expectEqual(res.epoch, got.epoch);
    try std.testing.expectEqual(res.expiry_ms, got.expiry_ms);
}

test "account residence proof fails CLOSED on every tampered or misbound input" {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x52)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x53)));
    const node: u64 = 0x1111_2222_3333_4444;
    // Expiry far enough out that `expiry - window - 1` (the TooFarFuture probe)
    // stays a valid u64 instant.
    const res = Residence{ .account = "kain", .node = node, .epoch = 3, .expiry_ms = max_residence_window_ms + 2_000_000 };
    var wire_buf: [max_residence_len]u8 = undefined;
    const wire = signResidence(res, kp, &wire_buf).?;
    const pk = kp.public_key.toBytes();
    const now: u64 = res.expiry_ms - 500_000;

    // Bad signature: any flipped wire byte (covered field or the sig itself).
    var tampered: [max_residence_len]u8 = undefined;
    @memcpy(tampered[0..wire.len], wire);
    tampered[wire.len - 1] ^= 0x01; // sig byte
    try std.testing.expectError(error.BadSignature, verifyResidence(tampered[0..wire.len], pk, "kain", node, now));
    @memcpy(tampered[0..wire.len], wire);
    tampered[6] ^= 0x01; // account byte ("kain" -> "kcin"): binding mismatch first
    try std.testing.expectError(error.WrongAccount, verifyResidence(tampered[0..wire.len], pk, "kain", node, now));

    // Wrong key (the attacker's own key never verifies the victim's proof).
    try std.testing.expectError(error.BadSignature, verifyResidence(wire, other.public_key.toBytes(), "kain", node, now));

    // Node reattach: a valid kain-proof-for-N presented as bound to node B.
    try std.testing.expectError(error.WrongNode, verifyResidence(wire, pk, "kain", node + 1, now));
    // Account reattach: a valid proof presented for a different account claim.
    try std.testing.expectError(error.WrongAccount, verifyResidence(wire, pk, "mallory", node, now));
    // An empty expected account never matches (unknown never trusts).
    try std.testing.expectError(error.WrongAccount, verifyResidence(wire, pk, "", node, now));

    // Freshness: at/after expiry fails; too far in the future fails (replay cap).
    try std.testing.expectError(error.Expired, verifyResidence(wire, pk, "kain", node, res.expiry_ms));
    try std.testing.expectError(error.Expired, verifyResidence(wire, pk, "kain", node, res.expiry_ms + 1));
    try std.testing.expectError(error.TooFarFuture, verifyResidence(wire, pk, "kain", node, res.expiry_ms - max_residence_window_ms - 1));
    // Exactly at the window boundary is still acceptable.
    _ = try verifyResidence(wire, pk, "kain", node, res.expiry_ms - max_residence_window_ms);

    // Structural: truncation, trailing bytes, bad magic, oversize/empty account.
    try std.testing.expectError(error.BadFormat, verifyResidence(wire[0 .. wire.len - 1], pk, "kain", node, now));
    var padded: [max_residence_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0;
    try std.testing.expectError(error.BadFormat, verifyResidence(padded[0 .. wire.len + 1], pk, "kain", node, now));
    @memcpy(tampered[0..wire.len], wire);
    tampered[0] ^= 0xFF; // magic
    try std.testing.expectError(error.BadFormat, verifyResidence(tampered[0..wire.len], pk, "kain", node, now));
    @memcpy(tampered[0..wire.len], wire);
    tampered[4] = 0; // account_len = 0
    try std.testing.expectError(error.BadFormat, verifyResidence(tampered[0..wire.len], pk, "kain", node, now));
    @memcpy(tampered[0..wire.len], wire);
    tampered[4] = @intCast(max_account_len + 1); // oversize account_len
    try std.testing.expectError(error.BadFormat, verifyResidence(tampered[0..wire.len], pk, "kain", node, now));
    try std.testing.expect(parseResidence(&.{}) == null);
}

test "account residence proof is domain-separated from the identity claim transcript" {
    // A signature minted for the IDENTITY-v1 transcript must never verify as a
    // residence proof, even with attacker-controlled residence fields: the
    // residence message carries its own domain prefix, so the byte strings can
    // never collide.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x54)));
    var transcript_buf: [max_transcript_len]u8 = undefined;
    const msg = transcript("kain", "primary", kp.public_key.toBytes(), &transcript_buf).?;
    const identity_sig = try kp.sign(msg, null);
    const res = Residence{ .account = "kain", .node = 1, .epoch = 1, .expiry_ms = 1_000_000 };
    var wire_buf: [max_residence_len]u8 = undefined;
    const wire = encodeResidence(res, identity_sig.toBytes(), &wire_buf).?;
    try std.testing.expectError(error.BadSignature, verifyResidence(wire, kp.public_key.toBytes(), "kain", 1, 500_000));
}

test "account residence prop keys are canonical fixed-width lower hex" {
    var key_buf: [residence_prop_prefix.len + residence_node_hex_len]u8 = undefined;
    const key = residencePropKey(0x00AB_CDEF_0123_4567, &key_buf).?;
    try std.testing.expectEqualStrings("identity.residence.00abcdef01234567", key);
    try std.testing.expect(isResidencePropKey(key));
    try std.testing.expectEqual(@as(u64, 0x00AB_CDEF_0123_4567), residencePropNode(key).?);
    // Reject: wrong width, upper case, non-hex, wrong prefix, and the identity
    // key namespace (the two prop families never alias).
    try std.testing.expect(!isResidencePropKey("identity.residence.abc"));
    try std.testing.expect(!isResidencePropKey("identity.residence.00ABCDEF01234567"));
    try std.testing.expect(!isResidencePropKey("identity.residence.00abcdef0123456g"));
    try std.testing.expect(!isResidencePropKey("identity.key.primary"));
    try std.testing.expect(!isPropKey("identity.residence.00abcdef01234567"));
}
