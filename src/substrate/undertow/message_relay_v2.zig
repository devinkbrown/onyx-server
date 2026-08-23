// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secured, correctness-first multi-hop user-message relay.
//!
//! Unlike relay v1, every routing and rendering field is immutable and covered
//! by the origin signature. A relay forwards the decoded message verbatim; it
//! may derive a sanitized local rendering view, but it must never rewrite the
//! signed object. Portable-session routing carries a one-way route identifier,
//! never the reusable 16-byte bearer token itself.

const std = @import("std");

const cpv = @import("../../proto/coilpack_value.zig");
const sign = @import("../../crypto/sign.zig");
const signed_frame = @import("signed_frame.zig");
const relay_v1 = @import("message_relay.zig");

pub const pubkey_len = sign.public_key_len;
pub const sig_len = sign.signature_len;
pub const route_id_len: usize = 16;
pub const relay_id_len: usize = 16;

pub const RouteId = [route_id_len]u8;
pub const RelayId = [relay_id_len]u8;
pub const SessionToken = [16]u8;
pub const Verb = relay_v1.Verb;

pub const sign_domain = "onyx-s2s-relay-msg-v2";
pub const route_id_domain = "onyx-session-route-id-v1";
pub const relay_id_domain = "onyx-s2s-relay-id-v2";

pub const ScopeKind = enum(u8) {
    /// Shared-channel delivery. WHISPER is deliberately excluded because it has
    /// an exact logical-session recipient and uses `channel_whisper` instead.
    channel = 1,
    /// Exact logical-session delivery. Nickname-only direct messages remain on
    /// relay v1 until they have a separate signed scope; v2 direct messages
    /// always carry `recipient_route_id`.
    direct = 2,
    /// WHISPER inside a signed channel context: `target` is the channel,
    /// `recipient` is the display nick, and `recipient_route_id` is the exact
    /// logical session. Receivers later require that route to be locally
    /// attached to the recipient and joined to the signed channel.
    channel_whisper = 3,
};

pub const RelayMessage = struct {
    /// Transcript schema selected by decode. Not encoded as a map field: field
    /// presence itself distinguishes legacy 16-field v2 from current v2.1.
    wire_schema: u8 = 2,
    verb: Verb,
    target: []const u8,
    min_rank: u8 = 0,
    source_prefix: []const u8,
    account: []const u8 = "",
    tags: []const u8 = "",
    text: []const u8,
    data_tag: []const u8 = "",
    recipient: []const u8 = "",
    scope_kind: ScopeKind,
    /// One-way identifier for the author's exact portable logical session.
    sender_route_id: ?RouteId = null,
    /// Origin-signed channel membership/status assertion for this event. A
    /// present zero value means an ordinary member; null carries no membership
    /// authority. This lets multi-hop receivers enforce +n/+m without granting
    /// topology-based trust to an intermediate relay.
    sender_member_modes: ?u8 = null,
    /// One-way identifier for the direct recipient's exact logical session.
    /// Present for `direct` and `channel_whisper`; absent for `channel`.
    recipient_route_id: ?RouteId = null,
    origin_node: u64,
    hlc: u64,
    origin_pubkey: []const u8 = "",
    origin_sig: []const u8 = "",

    /// The source nick is not duplicated on the wire. It is derived from the
    /// signed `nick!user@host` prefix, eliminating an unsigned alias field.
    pub fn sourceNick(self: RelayMessage) ?[]const u8 {
        const bang = std.mem.indexOfScalar(u8, self.source_prefix, '!') orelse return null;
        if (bang == 0) return null;
        return self.source_prefix[0..bang];
    }
};

pub const Owned = struct {
    msg: RelayMessage,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.msg.target);
        allocator.free(self.msg.source_prefix);
        allocator.free(self.msg.account);
        allocator.free(self.msg.tags);
        allocator.free(self.msg.text);
        allocator.free(self.msg.data_tag);
        allocator.free(self.msg.recipient);
        allocator.free(self.msg.origin_pubkey);
        allocator.free(self.msg.origin_sig);
        self.* = undefined;
    }
};

pub const DecodeError = error{
    InvalidDocument,
    InvalidFieldType,
    InvalidVerb,
    InvalidScope,
    InvalidSemantic,
    MissingField,
    UnknownField,
};

pub const SemanticError = error{InvalidSemantic};
pub const RouteIdError = error{ NullSessionToken, InvalidRouteId };
pub const TranscriptError = error{FieldTooLong};
pub const StampError = sign.SignError || std.mem.Allocator.Error || SemanticError || TranscriptError || error{OriginMismatch};

fn isChannelTarget(target: []const u8) bool {
    if (target.len == 0) return false;
    if (target[0] == '#' or target[0] == '&') return true;
    return target.len >= 2 and target[0] == '%' and (target[1] == '#' or target[1] == '&');
}

fn routeIdIsNull(id: RouteId) bool {
    return std.mem.allEqual(u8, &id, 0);
}

/// Enforce the v2 scope contract and reuse v1's hardened IRC grammar for all
/// rendered fields. Signature presence is checked separately so an origin can
/// validate the body before stamping it.
fn validateBody(msg: RelayMessage) SemanticError!void {
    if (msg.wire_schema != 1 and msg.wire_schema != 2) return error.InvalidSemantic;
    const nick = msg.sourceNick() orelse return error.InvalidSemantic;
    relay_v1.validateSemantic(.{
        .verb = msg.verb,
        .target = msg.target,
        .min_rank = msg.min_rank,
        .source_nick = nick,
        .source_prefix = msg.source_prefix,
        .account = msg.account,
        .tags = msg.tags,
        .text = msg.text,
        .data_tag = msg.data_tag,
        .recipient = msg.recipient,
        .origin_node = msg.origin_node,
        .hlc = msg.hlc,
        .origin_pubkey = "",
        .origin_sig = "",
    }) catch return error.InvalidSemantic;
    if (msg.sender_route_id) |id| {
        if (routeIdIsNull(id)) return error.InvalidSemantic;
    }
    if (msg.sender_member_modes) |modes| {
        if ((modes & 0xF0) != 0) return error.InvalidSemantic;
    }
    if (msg.recipient_route_id) |id| {
        if (routeIdIsNull(id)) return error.InvalidSemantic;
    }
    switch (msg.scope_kind) {
        .channel => {
            if (!isChannelTarget(msg.target) or msg.verb == .whisper or msg.recipient_route_id != null)
                return error.InvalidSemantic;
        },
        .direct => {
            if (isChannelTarget(msg.target) or msg.recipient.len != 0 or msg.recipient_route_id == null or
                msg.sender_member_modes != null)
                return error.InvalidSemantic;
        },
        .channel_whisper => {
            if (msg.verb != .whisper or !isChannelTarget(msg.target) or
                msg.recipient.len == 0 or msg.recipient_route_id == null)
                return error.InvalidSemantic;
        },
    }
}

/// A v2 message is always origin-signed; there is deliberately no unsigned
/// compatibility mode under the MESSAGE_V2 frame tag.
pub fn validateSemantic(msg: RelayMessage) SemanticError!void {
    try validateBody(msg);
    if (msg.origin_pubkey.len != pubkey_len or msg.origin_sig.len != sig_len)
        return error.InvalidSemantic;
}

/// Derive a non-bearer routing identifier from a reusable session token. The
/// all-zero sentinel means "no credential" throughout SessionStore and must
/// never collapse unrelated CSPRNG-less sessions onto one routing identity.
pub fn routeId(token: SessionToken) RouteIdError!RouteId {
    if (std.mem.allEqual(u8, &token, 0)) return error.NullSessionToken;
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(route_id_domain);
    h.update(&token);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    h.final(&digest);
    const id: RouteId = digest[0..route_id_len].*;
    if (routeIdIsNull(id)) return error.InvalidRouteId;
    return id;
}

/// Canonical CoilPack encode. Every field is present so alternate encodings do
/// not create multiple wire representations of one signed event.
pub fn encode(allocator: std.mem.Allocator, msg: RelayMessage) ![]u8 {
    try validateSemantic(msg);
    const sender_route: []const u8 = if (msg.sender_route_id) |*id| id else "";
    const recipient_route: []const u8 = if (msg.recipient_route_id) |*id| id else "";
    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = msg.account } },
        .{ .key = "data_tag", .value = .{ .string = msg.data_tag } },
        .{ .key = "hlc", .value = .{ .unsigned = msg.hlc } },
        .{ .key = "min_rank", .value = .{ .unsigned = msg.min_rank } },
        .{ .key = "origin_node", .value = .{ .unsigned = msg.origin_node } },
        .{ .key = "origin_pubkey", .value = .{ .bytes = msg.origin_pubkey } },
        .{ .key = "origin_sig", .value = .{ .bytes = msg.origin_sig } },
        .{ .key = "recipient", .value = .{ .string = msg.recipient } },
        .{ .key = "recipient_route_id", .value = .{ .bytes = recipient_route } },
        .{ .key = "scope_kind", .value = .{ .unsigned = @intFromEnum(msg.scope_kind) } },
        .{ .key = "sender_member_modes", .value = .{ .unsigned = if (msg.sender_member_modes) |m| m else 256 } },
        .{ .key = "sender_route_id", .value = .{ .bytes = sender_route } },
        .{ .key = "source_prefix", .value = .{ .string = msg.source_prefix } },
        .{ .key = "tags", .value = .{ .string = msg.tags } },
        .{ .key = "target", .value = .{ .string = msg.target } },
        .{ .key = "text", .value = .{ .string = msg.text } },
        .{ .key = "verb", .value = .{ .unsigned = @intFromEnum(msg.verb) } },
    };
    return cpv.Encoder.encode(allocator, .{ .map = entries[0..] });
}

const Field = enum(u5) {
    account,
    data_tag,
    hlc,
    min_rank,
    origin_node,
    origin_pubkey,
    origin_sig,
    recipient,
    recipient_route_id,
    scope_kind,
    sender_member_modes,
    sender_route_id,
    source_prefix,
    tags,
    target,
    text,
    verb,
};

fn claimField(seen: *u32, field: Field) DecodeError!void {
    const mask = @as(u32, 1) << @as(u5, @intCast(@intFromEnum(field)));
    if ((seen.* & mask) != 0) return error.InvalidDocument;
    seen.* |= mask;
}

fn allFieldsMask() u32 {
    // The canonical v2 map has exactly the 17 fields enumerated above. Keep the
    // mask explicit: Zig 0.17 deliberately removed generic enum-field reflection.
    return (@as(u32, 1) << 17) - 1;
}

fn legacyFieldsMask() u32 {
    return allFieldsMask() & ~(@as(u32, 1) << @intFromEnum(Field.sender_member_modes));
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Owned {
    var value = try cpv.Decoder.decode(allocator, bytes);
    defer value.deinit(allocator);
    const entries = switch (value) {
        .map => |map| map,
        else => return error.InvalidDocument,
    };

    var seen: u32 = 0;
    var msg: RelayMessage = .{
        .verb = .privmsg,
        .target = "",
        .source_prefix = "",
        .text = "",
        .scope_kind = .channel,
        .origin_node = 0,
        .hlc = 0,
    };

    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "account")) {
            try claimField(&seen, .account);
            msg.account = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "data_tag")) {
            try claimField(&seen, .data_tag);
            msg.data_tag = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "hlc")) {
            try claimField(&seen, .hlc);
            msg.hlc = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "min_rank")) {
            try claimField(&seen, .min_rank);
            msg.min_rank = try readRank(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_node")) {
            try claimField(&seen, .origin_node);
            msg.origin_node = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_pubkey")) {
            try claimField(&seen, .origin_pubkey);
            msg.origin_pubkey = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_sig")) {
            try claimField(&seen, .origin_sig);
            msg.origin_sig = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "recipient")) {
            try claimField(&seen, .recipient);
            msg.recipient = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "recipient_route_id")) {
            try claimField(&seen, .recipient_route_id);
            msg.recipient_route_id = try readRouteId(entry.value);
        } else if (std.mem.eql(u8, entry.key, "scope_kind")) {
            try claimField(&seen, .scope_kind);
            msg.scope_kind = try readScope(entry.value);
        } else if (std.mem.eql(u8, entry.key, "sender_member_modes")) {
            try claimField(&seen, .sender_member_modes);
            const modes = try readU64(entry.value);
            if (modes > 256) return error.InvalidFieldType;
            msg.sender_member_modes = if (modes == 256) null else @intCast(modes);
        } else if (std.mem.eql(u8, entry.key, "sender_route_id")) {
            try claimField(&seen, .sender_route_id);
            msg.sender_route_id = try readRouteId(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_prefix")) {
            try claimField(&seen, .source_prefix);
            msg.source_prefix = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "tags")) {
            try claimField(&seen, .tags);
            msg.tags = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "target")) {
            try claimField(&seen, .target);
            msg.target = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "text")) {
            try claimField(&seen, .text);
            msg.text = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "verb")) {
            try claimField(&seen, .verb);
            msg.verb = try readVerb(entry.value);
        } else return error.UnknownField;
    }
    // The original secure-relay-v2 schema had 16 fields. Decode it as an
    // authority-free membership assertion; emission of the 17-field current
    // schema is separately capability-probed so a strict old decoder never sees
    // an unknown key during a rolling upgrade.
    if (seen != allFieldsMask() and seen != legacyFieldsMask()) return error.MissingField;
    msg.wire_schema = if (seen == legacyFieldsMask()) 1 else 2;
    if (msg.origin_pubkey.len != pubkey_len or msg.origin_sig.len != sig_len)
        return error.InvalidFieldType;
    try validateSemantic(msg);

    const target = try allocator.dupe(u8, msg.target);
    errdefer allocator.free(target);
    const source_prefix = try allocator.dupe(u8, msg.source_prefix);
    errdefer allocator.free(source_prefix);
    const account = try allocator.dupe(u8, msg.account);
    errdefer allocator.free(account);
    const tags = try allocator.dupe(u8, msg.tags);
    errdefer allocator.free(tags);
    const text = try allocator.dupe(u8, msg.text);
    errdefer allocator.free(text);
    const data_tag = try allocator.dupe(u8, msg.data_tag);
    errdefer allocator.free(data_tag);
    const recipient = try allocator.dupe(u8, msg.recipient);
    errdefer allocator.free(recipient);
    const origin_pubkey = try allocator.dupe(u8, msg.origin_pubkey);
    errdefer allocator.free(origin_pubkey);
    const origin_sig = try allocator.dupe(u8, msg.origin_sig);
    errdefer allocator.free(origin_sig);

    msg.target = target;
    msg.source_prefix = source_prefix;
    msg.account = account;
    msg.tags = tags;
    msg.text = text;
    msg.data_tag = data_tag;
    msg.recipient = recipient;
    msg.origin_pubkey = origin_pubkey;
    msg.origin_sig = origin_sig;
    return .{ .msg = msg };
}

fn appendLenPrefixed(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, field: []const u8) !void {
    if (field.len > std.math.maxInt(u32)) return error.FieldTooLong;
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(field.len), .little);
    try out.appendSlice(allocator, &len);
    try out.appendSlice(allocator, field);
}

fn appendRoute(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, route: ?RouteId) !void {
    try out.append(allocator, @intFromBool(route != null));
    if (route) |id| try out.appendSlice(allocator, &id);
}

/// Canonical origin transcript. Every non-signature wire field is included.
pub fn originTranscript(allocator: std.mem.Allocator, msg: RelayMessage) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    var u64_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_le, msg.origin_node, .little);
    try out.appendSlice(allocator, &u64_le);
    std.mem.writeInt(u64, &u64_le, msg.hlc, .little);
    try out.appendSlice(allocator, &u64_le);
    try out.append(allocator, @intFromEnum(msg.verb));
    try out.append(allocator, @intFromEnum(msg.scope_kind));
    try out.append(allocator, msg.min_rank);
    if (msg.wire_schema >= 2) {
        try out.append(allocator, @intFromBool(msg.sender_member_modes != null));
        if (msg.sender_member_modes) |modes| try out.append(allocator, modes);
    }
    try appendRoute(&out, allocator, msg.sender_route_id);
    try appendRoute(&out, allocator, msg.recipient_route_id);
    try appendLenPrefixed(&out, allocator, msg.source_prefix);
    try appendLenPrefixed(&out, allocator, msg.account);
    try appendLenPrefixed(&out, allocator, msg.tags);
    try appendLenPrefixed(&out, allocator, msg.target);
    try appendLenPrefixed(&out, allocator, msg.text);
    try appendLenPrefixed(&out, allocator, msg.data_tag);
    try appendLenPrefixed(&out, allocator, msg.recipient);
    return out.toOwnedSlice(allocator);
}

/// Validate and stamp an origin-authored message in one operation. Keeping
/// transcript construction inside this API prevents callers from signing a
/// stale body, and the self-certifying origin check catches identity/config
/// mismatches before an unusable frame reaches the network.
pub fn stampOrigin(
    allocator: std.mem.Allocator,
    msg: *RelayMessage,
    kp: *const sign.KeyPair,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) StampError!void {
    if (signed_frame.originShortId(kp.public_key) != msg.origin_node) return error.OriginMismatch;
    try validateBody(msg.*);
    const transcript = try originTranscript(allocator, msg.*);
    defer allocator.free(transcript);
    pubkey_buf.* = kp.public_key;
    sig_buf.* = try kp.signCtx(sign_domain, transcript);
    msg.origin_pubkey = pubkey_buf;
    msg.origin_sig = sig_buf;
}

pub const VerifyOutcome = enum { verified, origin_mismatch, bad_signature };

pub fn verifyOrigin(allocator: std.mem.Allocator, msg: RelayMessage) !VerifyOutcome {
    if (msg.origin_pubkey.len != pubkey_len or msg.origin_sig.len != sig_len) return .bad_signature;
    const pubkey: sign.PublicKey = msg.origin_pubkey[0..pubkey_len].*;
    if (signed_frame.originShortId(pubkey) != msg.origin_node) return .origin_mismatch;
    const signature: sign.Signature = msg.origin_sig[0..sig_len].*;
    const transcript = try originTranscript(allocator, msg);
    defer allocator.free(transcript);
    const ok = sign.verifyCtx(sign_domain, transcript, signature, pubkey) catch return .bad_signature;
    return if (ok) .verified else .bad_signature;
}

pub fn relayId(allocator: std.mem.Allocator, msg: RelayMessage) !RelayId {
    if (msg.origin_pubkey.len != pubkey_len or msg.origin_sig.len != sig_len)
        return error.InvalidSemantic;
    const transcript = try originTranscript(allocator, msg);
    defer allocator.free(transcript);
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(relay_id_domain);
    h.update(msg.origin_pubkey);
    h.update(msg.origin_sig);
    h.update(transcript);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    h.final(&digest);
    return digest[0..relay_id_len].*;
}

/// Verify first and only then derive the dedup identity. Consumers should use
/// this combined API at trust boundaries so a forged frame can never reserve a
/// valid event's cache key.
pub const VerifyAndIdOutcome = union(enum) {
    verified: RelayId,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

pub fn verifyAndRelayId(
    allocator: std.mem.Allocator,
    msg: RelayMessage,
) std.mem.Allocator.Error!VerifyAndIdOutcome {
    validateSemantic(msg) catch return .invalid_semantic;
    const pubkey: sign.PublicKey = msg.origin_pubkey[0..pubkey_len].*;
    if (signed_frame.originShortId(pubkey) != msg.origin_node) return .origin_mismatch;
    const signature: sign.Signature = msg.origin_sig[0..sig_len].*;
    // Build the canonical transcript once. The same authenticated bytes feed
    // both Ed25519 verification and the exact relay identity, so admission
    // callers never need a second derivation pass that could drift.
    const transcript = originTranscript(allocator, msg) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .invalid_semantic,
    };
    defer allocator.free(transcript);
    const valid = sign.verifyCtx(sign_domain, transcript, signature, pubkey) catch false;
    if (!valid) return .bad_signature;

    var h = std.crypto.hash.Blake3.init(.{});
    h.update(relay_id_domain);
    h.update(msg.origin_pubkey);
    h.update(msg.origin_sig);
    h.update(transcript);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    h.final(&digest);
    return .{ .verified = digest[0..relay_id_len].* };
}

/// Bounded per-link exact-event loop cache. This suppresses immediate mesh
/// reflections only; it is NOT authoritative replay protection because an
/// evicted capture is accepted again. The daemon-wide delivery/flood path must
/// add per-origin retired-HLC watermarks before MESSAGE_V2 becomes live.
/// Admission probes with `contains` before queueing and records with `observe`
/// only after ownership transfer; cache allocation failure therefore weakens
/// this optimization but never rejects or poisons an otherwise valid delivery.
pub const SeenSet = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    seen: std.AutoHashMapUnmanaged(RelayId, void) = .empty,
    order: std.ArrayListUnmanaged(RelayId) = .empty,
    next_evict: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) SeenSet {
        return .{ .allocator = allocator, .capacity = capacity };
    }

    /// Non-mutating duplicate probe. Admission paths use this before reserving
    /// queue ownership so a full queue cannot poison the reflection cache.
    pub fn contains(self: *const SeenSet, id: RelayId) bool {
        return self.seen.contains(id);
    }

    pub fn observe(self: *SeenSet, id: RelayId) bool {
        if (self.capacity == 0) return true;
        if (self.seen.contains(id)) return true;
        self.seen.ensureTotalCapacity(self.allocator, @intCast(self.capacity)) catch return true;
        self.order.ensureTotalCapacity(self.allocator, self.capacity) catch return true;
        if (self.order.items.len < self.capacity) {
            self.order.appendAssumeCapacity(id);
            self.seen.putAssumeCapacity(id, {});
            return false;
        }
        const old = self.order.items[self.next_evict];
        _ = self.seen.remove(old);
        self.order.items[self.next_evict] = id;
        self.next_evict = (self.next_evict + 1) % self.capacity;
        self.seen.putAssumeCapacity(id, {});
        return false;
    }

    pub fn deinit(self: *SeenSet) void {
        self.seen.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.* = undefined;
    }
};

fn readString(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .string => |s| s,
        else => error.InvalidFieldType,
    };
}

fn readBytes(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .bytes => |b| b,
        else => error.InvalidFieldType,
    };
}

fn readU64(value: cpv.Value) DecodeError!u64 {
    return switch (value) {
        .unsigned => |n| n,
        else => error.InvalidFieldType,
    };
}

fn readRank(value: cpv.Value) DecodeError!u8 {
    const raw = try readU64(value);
    if (raw > 4) return error.InvalidFieldType;
    return @intCast(raw);
}

fn readVerb(value: cpv.Value) DecodeError!Verb {
    return switch (try readU64(value)) {
        1 => .privmsg,
        2 => .notice,
        3 => .tagmsg,
        4 => .data,
        5 => .request,
        6 => .reply,
        7 => .whisper,
        else => error.InvalidVerb,
    };
}

fn readScope(value: cpv.Value) DecodeError!ScopeKind {
    return switch (try readU64(value)) {
        1 => .channel,
        2 => .direct,
        3 => .channel_whisper,
        else => error.InvalidScope,
    };
}

fn readRouteId(value: cpv.Value) DecodeError!?RouteId {
    const bytes = try readBytes(value);
    if (bytes.len == 0) return null;
    if (bytes.len != route_id_len) return error.InvalidFieldType;
    const id: RouteId = bytes[0..route_id_len].*;
    if (routeIdIsNull(id)) return error.InvalidFieldType;
    return id;
}

fn testKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

fn signedSample(
    kp: *const sign.KeyPair,
    pubkey: *[pubkey_len]u8,
    signature: *[sig_len]u8,
) !RelayMessage {
    const sender = try routeId(@splat(0x11));
    var msg = RelayMessage{
        .verb = .privmsg,
        .target = "#onyx",
        .min_rank = 2,
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "secure flood",
        .scope_kind = .channel,
        .sender_route_id = sender,
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = 99,
    };
    try stampOrigin(std.testing.allocator, &msg, kp, pubkey, signature);
    return msg;
}

test "secure relay v2 signed channel and direct scopes round-trip" {
    var kp = try testKeyPair(0x51);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    var channel = try signedSample(&kp, &pubkey, &signature);
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, channel);
    defer allocator.free(wire);
    var decoded = try decode(allocator, wire);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, decoded.msg));
    try std.testing.expectEqual(ScopeKind.channel, decoded.msg.scope_kind);
    try std.testing.expectEqualSlices(u8, &channel.sender_route_id.?, &decoded.msg.sender_route_id.?);

    channel.scope_kind = .direct;
    channel.target = "bob";
    channel.min_rank = 0;
    channel.recipient_route_id = try routeId(@splat(0x22));
    try stampOrigin(allocator, &channel, &kp, &pubkey, &signature);
    const direct_wire = try encode(allocator, channel);
    defer allocator.free(direct_wire);
    var direct = try decode(allocator, direct_wire);
    defer direct.deinit(allocator);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, direct.msg));
    try std.testing.expectEqualSlices(u8, &channel.recipient_route_id.?, &direct.msg.recipient_route_id.?);
}

test "secure relay v2 signs immutable scope route policy and rendering fields" {
    var kp = try testKeyPair(0x52);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const original = try signedSample(&kp, &pubkey, &signature);

    var changed = original;
    changed.scope_kind = .direct;
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, changed));
    changed = original;
    changed.sender_route_id = try routeId(@splat(0x33));
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, changed));
    changed = original;
    changed.min_rank = 1;
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, changed));
    changed = original;
    changed.tags = "+draft/reply=changed";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, changed));
    changed = original;
    changed.account = "mallory";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, changed));

    // Sender and recipient roles are independently bound, not an unordered pair.
    var direct = original;
    direct.scope_kind = .direct;
    direct.target = "bob";
    direct.min_rank = 0;
    direct.recipient_route_id = try routeId(@splat(0x34));
    try stampOrigin(std.testing.allocator, &direct, &kp, &pubkey, &signature);
    const stamped_sender = direct.sender_route_id.?;
    const stamped_recipient = direct.recipient_route_id.?;
    direct.sender_route_id = stamped_recipient;
    direct.recipient_route_id = stamped_sender;
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, direct));
}

test "secure relay v2 channel whisper signs display channel and exact recipient route" {
    const allocator = std.testing.allocator;
    var kp = try testKeyPair(0x58);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    var msg = RelayMessage{
        .verb = .whisper,
        .target = "#onyx",
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .text = "exact channel whisper",
        .recipient = "bob",
        .scope_kind = .channel_whisper,
        .sender_route_id = try routeId(@splat(0x61)),
        .recipient_route_id = try routeId(@splat(0x62)),
        .origin_node = signed_frame.originShortId(kp.public_key),
        .hlc = 100,
    };
    try stampOrigin(allocator, &msg, &kp, &pubkey, &signature);
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(msg.scope_kind));
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);
    var owned = try decode(allocator, wire);
    defer owned.deinit(allocator);
    try std.testing.expectEqual(ScopeKind.channel_whisper, owned.msg.scope_kind);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, owned.msg));

    var changed = msg;
    changed.scope_kind = .channel;
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(allocator, changed));
    changed = msg;
    changed.target = "#other";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(allocator, changed));
    changed = msg;
    changed.recipient = "mallory";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(allocator, changed));
    changed = msg;
    changed.recipient_route_id = try routeId(@splat(0x63));
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(allocator, changed));

    changed = msg;
    changed.recipient_route_id = null;
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(changed));
    changed = msg;
    changed.scope_kind = .channel;
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(changed));
}

test "secure relay v2 scope and mandatory signature are strict" {
    var kp = try testKeyPair(0x53);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    var msg = try signedSample(&kp, &pubkey, &signature);
    msg.scope_kind = .direct;
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    msg.target = "bob";
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    msg = try signedSample(&kp, &pubkey, &signature);
    msg.recipient_route_id = try routeId(@splat(0x44));
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    msg = try signedSample(&kp, &pubkey, &signature);
    msg.sender_route_id = @splat(0);
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    msg = try signedSample(&kp, &pubkey, &signature);
    msg.scope_kind = .direct;
    msg.target = "bob";
    msg.recipient_route_id = @splat(0);
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    msg = try signedSample(&kp, &pubkey, &signature);
    msg.origin_sig = "";
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
}

test "secure relay v2 peer loop cache is bounded and eviction is not replay authority" {
    var seen = SeenSet.init(std.testing.allocator, 2);
    defer seen.deinit();
    const a: RelayId = @splat(1);
    const b: RelayId = @splat(2);
    const c: RelayId = @splat(3);
    // Cache-only semantics: once evicted, `a` is admitted again. The daemon's
    // later global retired-HLC guard is the authoritative replay boundary.
    try std.testing.expect(!seen.observe(a));
    try std.testing.expect(seen.observe(a));
    try std.testing.expect(!seen.observe(b));
    try std.testing.expect(!seen.observe(c));
    try std.testing.expect(!seen.observe(a));

    var closed = SeenSet.init(std.testing.allocator, 0);
    defer closed.deinit();
    try std.testing.expect(closed.observe(a));
    try std.testing.expect(!closed.contains(a));
}

test "secure relay v2 route identifiers are deterministic non-bearer digests" {
    const token: SessionToken = @splat(0xa5);
    const id = try routeId(token);
    const known = [_]u8{
        0x7d, 0xbd, 0xed, 0xff, 0xa4, 0xa4, 0x4b, 0x27,
        0xa8, 0xf9, 0xba, 0xda, 0x2a, 0xe7, 0x03, 0xbe,
    };
    try std.testing.expectEqual(known, id);
    try std.testing.expectEqual(id, try routeId(token));
    try std.testing.expect(!std.mem.eql(u8, &token, &id));
    var other = token;
    other[15] ^= 1;
    const other_id = try routeId(other);
    try std.testing.expect(!std.mem.eql(u8, &id, &other_id));
    try std.testing.expectError(error.NullSessionToken, routeId(@splat(0)));
}

test "secure relay v2 origin stamping rejects a mismatched self-certified node" {
    var kp = try testKeyPair(0x54);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    var msg = RelayMessage{
        .verb = .privmsg,
        .target = "#onyx",
        .source_prefix = "alice!u@example.invalid",
        .text = "wrong origin",
        .scope_kind = .channel,
        .origin_node = signed_frame.originShortId(kp.public_key) ^ 1,
        .hlc = 1,
    };
    try std.testing.expectError(
        error.OriginMismatch,
        stampOrigin(std.testing.allocator, &msg, &kp, &pubkey, &signature),
    );
    try std.testing.expectEqual(@as(usize, 0), msg.origin_sig.len);
}

test "secure relay v2 verify-and-id rejects forgery before exposing a cache key" {
    var kp = try testKeyPair(0x55);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    var msg = try signedSample(&kp, &pubkey, &signature);
    const valid = try verifyAndRelayId(std.testing.allocator, msg);
    try std.testing.expect(valid == .verified);
    msg.text = "forged before valid";
    try std.testing.expectEqual(
        VerifyAndIdOutcome.bad_signature,
        try verifyAndRelayId(std.testing.allocator, msg),
    );
}

test "secure relay v2 relay id and canonical bytes survive decode re-encode" {
    const allocator = std.testing.allocator;
    var kp = try testKeyPair(0x56);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const msg = try signedSample(&kp, &pubkey, &signature);
    const before = switch (try verifyAndRelayId(allocator, msg)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);
    var owned = try decode(allocator, wire);
    defer owned.deinit(allocator);
    const after = switch (try verifyAndRelayId(allocator, owned.msg)) {
        .verified => |id| id,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(before, after);
    const wire_again = try encode(allocator, owned.msg);
    defer allocator.free(wire_again);
    try std.testing.expectEqualSlices(u8, wire, wire_again);
    try std.testing.expectEqualSlices(u8, msg.origin_pubkey, owned.msg.origin_pubkey);
    try std.testing.expectEqualSlices(u8, msg.origin_sig, owned.msg.origin_sig);
}

test "secure relay v2 decoder rejects missing unknown and wrong-width fields" {
    const allocator = std.testing.allocator;
    var kp = try testKeyPair(0x57);
    defer kp.deinit();
    var pubkey: [pubkey_len]u8 = undefined;
    var signature: [sig_len]u8 = undefined;
    const msg = try signedSample(&kp, &pubkey, &signature);
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);
    var doc = try cpv.Decoder.decode(allocator, wire);
    defer doc.deinit(allocator);
    const entries = switch (doc) {
        .map => |map| map,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 17), entries.len);

    var missing: [16]cpv.MapEntry = undefined;
    @memcpy(&missing, entries[0..16]);
    const missing_wire = try cpv.Encoder.encode(allocator, .{ .map = &missing });
    defer allocator.free(missing_wire);
    try std.testing.expectError(error.MissingField, decode(allocator, missing_wire));

    var unknown: [18]cpv.MapEntry = undefined;
    @memcpy(unknown[0..17], entries);
    unknown[17] = .{ .key = "zzz", .value = .{ .unsigned = 0 } };
    const unknown_wire = try cpv.Encoder.encode(allocator, .{ .map = &unknown });
    defer allocator.free(unknown_wire);
    try std.testing.expectError(error.UnknownField, decode(allocator, unknown_wire));

    var wrong_route: [17]cpv.MapEntry = undefined;
    @memcpy(&wrong_route, entries);
    for (&wrong_route) |*entry| {
        if (std.mem.eql(u8, entry.key, "sender_route_id")) {
            entry.value = .{ .bytes = &.{0x01} };
            break;
        }
    }
    const wrong_route_wire = try cpv.Encoder.encode(allocator, .{ .map = &wrong_route });
    defer allocator.free(wrong_route_wire);
    try std.testing.expectError(error.InvalidFieldType, decode(allocator, wrong_route_wire));

    var zero_route: [17]cpv.MapEntry = undefined;
    @memcpy(&zero_route, entries);
    const zero_id: RouteId = @splat(0);
    for (&zero_route) |*entry| {
        if (std.mem.eql(u8, entry.key, "sender_route_id")) {
            entry.value = .{ .bytes = &zero_id };
            break;
        }
    }
    const zero_route_wire = try cpv.Encoder.encode(allocator, .{ .map = &zero_route });
    defer allocator.free(zero_route_wire);
    try std.testing.expectError(error.InvalidFieldType, decode(allocator, zero_route_wire));

    var wrong_key: [17]cpv.MapEntry = undefined;
    @memcpy(&wrong_key, entries);
    const short_key: [pubkey_len - 1]u8 = @splat(0x01);
    for (&wrong_key) |*entry| {
        if (std.mem.eql(u8, entry.key, "origin_pubkey")) {
            entry.value = .{ .bytes = &short_key };
            break;
        }
    }
    const wrong_key_wire = try cpv.Encoder.encode(allocator, .{ .map = &wrong_key });
    defer allocator.free(wrong_key_wire);
    try std.testing.expectError(error.InvalidFieldType, decode(allocator, wrong_key_wire));
}
