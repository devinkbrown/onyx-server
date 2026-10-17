// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Undertow mesh user-message relay codec and loop guard.
//!
//! Relayed PRIVMSG/NOTICE/TAGMSG payloads are canonical CoilPack maps. The
//! schema is intentionally small and strict so the exact encoded bytes remain
//! stable for signing and forwarding decisions.

const std = @import("std");

const cpv = @import("../../proto/coilpack_value.zig");
const sign = @import("../../crypto/sign.zig");
const signed_frame = @import("signed_frame.zig");
const utf8 = @import("../utf8.zig");

pub const pubkey_len = sign.public_key_len; // 32
pub const sig_len = sign.signature_len; // 64

// Hard protocol bounds. These deliberately do not depend on a receiving
// daemon's runtime configuration: every peer must agree on whether a relay
// frame is structurally safe before it can be rendered as an IRC line.
pub const max_nick_len: usize = 64;
pub const max_user_len: usize = 64;
pub const max_host_len: usize = 255;
pub const max_channel_len: usize = 200;
pub const max_account_len: usize = 64;
pub const max_tags_len: usize = 4094;
pub const max_tag_count: usize = 32;
pub const max_tag_key_len: usize = 96;
pub const max_text_len: usize = 4096;
pub const max_data_tag_len: usize = 15;
pub const max_prefix_len: usize = max_nick_len + 1 + max_user_len + 1 + max_host_len;

/// Domain label folded into the Ed25519 transcript of a self-contained MESSAGE
/// origin signature (via `sign.signCtx`). Distinct from `signed_frame`'s
/// per-link `sign_domain` and from every other Ed25519 use in Onyx Server, so a
/// relay-message signature can never validate in another context (a per-link
/// state frame, a node identity, an oper grant, or a migration token).
pub const sign_domain = "onyx-s2s-relay-msg-v1";

pub const SignError = sign.SignError || error{NoSpaceLeft};
pub const VerifyError = sign.VerifyError;

pub const Verb = enum(u8) {
    privmsg = 1,
    notice = 2,
    tagmsg = 3,
    // IRCX typed directed messaging (channel- or nick-scoped). DATA/REQUEST/REPLY
    // carry an extra IRCX data tag in `data_tag`; WHISPER carries the recipient
    // nick in `recipient` while `target` stays the shared channel.
    data = 4,
    request = 5,
    reply = 6,
    whisper = 7,

    /// The IRCX command word rendered on the wire for this verb (server-side
    /// reconstruction in deliverRelay). PRIVMSG/NOTICE/TAGMSG return their own
    /// command words too so callers can share one switch.
    pub fn commandWord(self: Verb) []const u8 {
        return switch (self) {
            .privmsg => "PRIVMSG",
            .notice => "NOTICE",
            .tagmsg => "TAGMSG",
            .data => "DATA",
            .request => "REQUEST",
            .reply => "REPLY",
            .whisper => "WHISPER",
        };
    }
};

pub const RelayMessage = struct {
    verb: Verb,
    target: []const u8,
    /// STATUSMSG delivery floor for channel targets (0 = every member, 1 = +,
    /// 2 = @, 3 = owner, 4 = founder). The target stays the bare channel name.
    min_rank: u8 = 0,
    source_nick: []const u8,
    source_prefix: []const u8,
    account: []const u8 = "",
    tags: []const u8 = "",
    text: []const u8,
    /// IRCX data tag for DATA/REQUEST/REPLY (e.g. "SYS.foo"); "" otherwise.
    data_tag: []const u8 = "",
    /// WHISPER recipient nick (the channel co-member to deliver to); "" otherwise.
    /// For WHISPER, `target` is the shared channel and `recipient` is the nick.
    recipient: []const u8 = "",
    origin_node: u64,
    hlc: u64,
    /// SELF-CONTAINED multi-hop origin signature: the origin node's 32-byte
    /// Ed25519 public key, created ONCE at the author and forwarded VERBATIM by
    /// every relay. Empty ("") on the legacy unsigned path (older peers / single
    /// node with no node identity). When non-empty it is exactly `pubkey_len`
    /// bytes and self-certifies the origin: a receiver requires
    /// `signed_frame.originShortId(origin_pubkey) == origin_node`.
    origin_pubkey: []const u8 = "",
    /// The 64-byte Ed25519 signature over the canonical origin transcript (see
    /// `originTranscript`), bound to `sign_domain`. Empty when unsigned. A relay
    /// re-emits this byte-for-byte; it never re-signs (re-signing with its own
    /// key would either fail the receiver's origin check or erase the true
    /// author). Always paired with `origin_pubkey` (both empty or both present).
    origin_sig: []const u8 = "",
};

pub const Owned = struct {
    msg: RelayMessage,

    pub fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.msg.target);
        allocator.free(self.msg.source_nick);
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
    InvalidSemantic,
    MissingField,
    UnknownField,
};

pub const SemanticError = error{InvalidSemantic};

fn invalid() SemanticError {
    return error.InvalidSemantic;
}

fn hasControl(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte < 0x20 or byte == 0x7f) return true;
    }
    return false;
}

/// IRC message bodies intentionally carry mIRC/IRCv3 formatting C0 codes
/// (bold/colour/reset/italic/underline/…). Those are content, not protocol
/// framing. CR/LF/NUL (and other non-format C0 / DEL) remain forbidden so a
/// body can never inject a second IRC line or smuggle CTCP framing (\x01).
fn isIrcFormatControl(byte: u8) bool {
    return switch (byte) {
        0x02, // bold
        0x03, // colour (mIRC \x03NN[,NN])
        0x04, // hex colour (modern clients)
        0x0f, // reset / ordin
        0x11, // monospace
        0x16, // reverse
        0x1d, // italic
        0x1e, // strikethrough
        0x1f, // underline
        => true,
        else => false,
    };
}

fn hasDisallowedTextControl(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte >= 0x20 and byte != 0x7f) continue;
        if (isIrcFormatControl(byte)) continue;
        return true; // CR/LF/NUL/SOH/TAB/…/DEL
    }
    return false;
}

fn validUtf8Field(bytes: []const u8, max_len: usize, allow_empty: bool) bool {
    if ((!allow_empty and bytes.len == 0) or bytes.len > max_len) return false;
    return !hasControl(bytes) and utf8.validateUtf8(bytes);
}

/// Message body field: UTF-8, length-bounded, IRC formatting allowed, line
/// breakers and non-format C0 still rejected.
fn validTextField(bytes: []const u8, max_len: usize, allow_empty: bool) bool {
    if ((!allow_empty and bytes.len == 0) or bytes.len > max_len) return false;
    return !hasDisallowedTextControl(bytes) and utf8.validateUtf8(bytes);
}

fn validNick(nick: []const u8) bool {
    return utf8.isValidNickWith(.utf8_only, nick, .{ .max_nick_bytes = max_nick_len });
}

fn validChannel(channel: []const u8) bool {
    if (channel.len > max_channel_len) return false;
    // IRCX prefixes UTF-8 channel names with '%', while the following '#'/ '&'
    // remains the actual channel sigil. Validate the remainder with the same
    // grammar as an ordinary channel and include '%' in the total bound above.
    const name = if (channel.len >= 2 and channel[0] == '%') channel[1..] else channel;
    return utf8.isValidChannelWith(.utf8_only, name, .{
        .max_channel_bytes = max_channel_len,
        .allow_ampersand_channel = true,
    });
}

fn validUser(user: []const u8) bool {
    if (!validUtf8Field(user, max_user_len, false)) return false;
    for (user) |byte| {
        if (byte == '!' or byte == '@' or byte == ':' or byte == ' ') return false;
    }
    return true;
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > max_host_len) return false;
    for (host) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or
            byte == '.' or byte == '-' or byte == '_' or byte == ':' or
            byte == '[' or byte == ']' or byte == '/';
        if (!ok) return false;
    }
    return true;
}

fn validPrefix(prefix: []const u8, source_nick: []const u8) bool {
    if (prefix.len == 0 or prefix.len > max_prefix_len or prefix[0] == ':') return false;
    const bang = std.mem.indexOfScalar(u8, prefix, '!') orelse return false;
    const at_rel = std.mem.indexOfScalar(u8, prefix[bang + 1 ..], '@') orelse return false;
    const at = bang + 1 + at_rel;
    const nick = prefix[0..bang];
    const user = prefix[bang + 1 .. at];
    const host = prefix[at + 1 ..];

    // Require exactly nick!user@host. Extra separators are not meaningful IRC
    // prefix syntax and would make downstream identity parsing ambiguous.
    if (std.mem.indexOfScalar(u8, prefix[bang + 1 ..], '!') != null) return false;
    if (std.mem.indexOfScalar(u8, host, '@') != null) return false;
    if (!validNick(nick) or !utf8.eql(.utf8_only, nick, source_nick)) return false;
    if (!validUser(user) or !validHost(host)) return false;
    return true;
}

fn validAccount(account: []const u8) bool {
    if (account.len == 0) return true;
    if (!validUtf8Field(account, max_account_len, false)) return false;
    for (account) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
        if (!ok) return false;
    }
    return true;
}

fn validTagKey(key: []const u8) bool {
    // The relay field carries client-only tags, so every key retains the IRCv3
    // '+' marker. Server tags (time/account/msgid) are stamped at each hop.
    if (key.len < 2 or key.len > max_tag_key_len or key[0] != '+') return false;
    for (key[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '.' and byte != '/') return false;
    }
    return true;
}

fn validTags(raw: []const u8) bool {
    if (raw.len == 0) return true;
    if (!validUtf8Field(raw, max_tags_len, false)) return false;

    var seen: [max_tag_count][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |tag| {
        if (tag.len == 0 or count == max_tag_count) return false;
        const eq = std.mem.indexOfScalar(u8, tag, '=') orelse tag.len;
        const key = tag[0..eq];
        if (!validTagKey(key)) return false;
        for (seen[0..count]) |prior| {
            if (std.mem.eql(u8, prior, key)) return false;
        }
        if (eq < tag.len) {
            for (tag[eq + 1 ..]) |byte| {
                if (byte == ' ' or byte == ';') return false;
            }
        }
        seen[count] = key;
        count += 1;
    }
    return count != 0;
}

fn validDataTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > max_data_tag_len or !std.ascii.isAlphabetic(tag[0])) return false;
    for (tag) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.') return false;
    }
    return true;
}

/// Validate all semantic invariants required before a relay message is rendered
/// into an IRC line. `decode` calls this before allocating owned field copies;
/// direct/in-process callers must call it at their trust boundary too.
pub fn validateSemantic(msg: RelayMessage) SemanticError!void {
    if (msg.min_rank > 4) return invalid();
    if (!validNick(msg.source_nick)) return invalid();
    if (!validPrefix(msg.source_prefix, msg.source_nick)) return invalid();
    if (!validAccount(msg.account)) return invalid();
    if (!validTags(msg.tags)) return invalid();
    // Body text is the only rendered field that may carry mIRC formatting.
    // Identity fields (nick/prefix/account/tags/target) stay control-free.
    if (!validTextField(msg.text, max_text_len, true)) return invalid();

    const target_is_channel = validChannel(msg.target);
    const target_is_nick = validNick(msg.target);
    if (!target_is_channel and !target_is_nick) return invalid();
    if (!target_is_channel and msg.min_rank != 0) return invalid();

    if (msg.origin_pubkey.len != 0 and msg.origin_pubkey.len != pubkey_len) return invalid();
    if (msg.origin_sig.len != 0 and msg.origin_sig.len != sig_len) return invalid();
    if ((msg.origin_pubkey.len == 0) != (msg.origin_sig.len == 0)) return invalid();

    switch (msg.verb) {
        .privmsg, .notice => {
            if (msg.text.len == 0 or msg.data_tag.len != 0 or msg.recipient.len != 0) return invalid();
        },
        .tagmsg => {
            if (msg.text.len != 0 or msg.tags.len == 0 or msg.data_tag.len != 0 or msg.recipient.len != 0) return invalid();
        },
        .data, .request, .reply => {
            if (msg.text.len == 0 or !validDataTag(msg.data_tag) or msg.recipient.len != 0) return invalid();
        },
        .whisper => {
            if (!target_is_channel or msg.min_rank != 0 or msg.text.len == 0 or msg.data_tag.len != 0 or !validNick(msg.recipient)) return invalid();
        },
    }
}

/// Canonical CoilPack encode (stable field order - signature-stable).
pub fn encode(allocator: std.mem.Allocator, msg: RelayMessage) ![]u8 {
    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = msg.account } },
        .{ .key = "data_tag", .value = .{ .string = msg.data_tag } },
        .{ .key = "hlc", .value = .{ .unsigned = msg.hlc } },
        .{ .key = "min_rank", .value = .{ .unsigned = msg.min_rank } },
        .{ .key = "origin_node", .value = .{ .unsigned = msg.origin_node } },
        // Raw Ed25519 key/signature bytes are binary (not valid UTF-8), so they
        // ride as CoilPack `bytes`, not `string`.
        .{ .key = "origin_pubkey", .value = .{ .bytes = msg.origin_pubkey } },
        .{ .key = "origin_sig", .value = .{ .bytes = msg.origin_sig } },
        .{ .key = "recipient", .value = .{ .string = msg.recipient } },
        .{ .key = "source_nick", .value = .{ .string = msg.source_nick } },
        .{ .key = "source_prefix", .value = .{ .string = msg.source_prefix } },
        .{ .key = "tags", .value = .{ .string = msg.tags } },
        .{ .key = "target", .value = .{ .string = msg.target } },
        .{ .key = "text", .value = .{ .string = msg.text } },
        .{ .key = "verb", .value = .{ .unsigned = @intFromEnum(msg.verb) } },
    };
    return cpv.Encoder.encode(allocator, .{ .map = entries[0..] });
}

/// Decode into owned copies, rejecting unsafe or semantically inconsistent
/// relay frames before any rendered field reaches daemon code.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Owned {
    var value = try cpv.Decoder.decode(allocator, bytes);
    defer value.deinit(allocator);

    const entries = switch (value) {
        .map => |entries| entries,
        else => return DecodeError.InvalidDocument,
    };

    var verb_opt: ?Verb = null;
    var target_opt: ?[]const u8 = null;
    var source_nick_opt: ?[]const u8 = null;
    var source_prefix_opt: ?[]const u8 = null;
    var account_opt: ?[]const u8 = null;
    var tags_opt: ?[]const u8 = null;
    var text_opt: ?[]const u8 = null;
    var data_tag_opt: ?[]const u8 = null;
    var recipient_opt: ?[]const u8 = null;
    var origin_pubkey_opt: ?[]const u8 = null;
    var origin_sig_opt: ?[]const u8 = null;
    var min_rank: u8 = 0;
    var origin_node_opt: ?u64 = null;
    var hlc_opt: ?u64 = null;

    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "account")) {
            account_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "data_tag")) {
            data_tag_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "hlc")) {
            hlc_opt = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "min_rank")) {
            min_rank = try readRank(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_node")) {
            origin_node_opt = try readU64(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_pubkey")) {
            origin_pubkey_opt = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "origin_sig")) {
            origin_sig_opt = try readBytes(entry.value);
        } else if (std.mem.eql(u8, entry.key, "recipient")) {
            recipient_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_nick")) {
            source_nick_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "source_prefix")) {
            source_prefix_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "tags")) {
            tags_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "target")) {
            target_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "text")) {
            text_opt = try readString(entry.value);
        } else if (std.mem.eql(u8, entry.key, "verb")) {
            verb_opt = try readVerb(entry.value);
        } else {
            return DecodeError.UnknownField;
        }
    }

    const target = target_opt orelse return DecodeError.MissingField;
    const source_nick = source_nick_opt orelse return DecodeError.MissingField;
    const source_prefix = source_prefix_opt orelse return DecodeError.MissingField;
    const account = account_opt orelse return DecodeError.MissingField;
    const tags = tags_opt orelse return DecodeError.MissingField;
    const text = text_opt orelse return DecodeError.MissingField;
    // Optional (default ""): absent for PRIVMSG/NOTICE/TAGMSG and from older
    // peers that predate the typed-IRCX verbs, mirroring min_rank's tolerance.
    const data_tag = data_tag_opt orelse "";
    const recipient = recipient_opt orelse "";
    // Optional self-contained origin signature. Absent (legacy / unsigned)
    // decodes to "". Present must be the exact Ed25519 field widths; a wrong
    // length is a malformed frame, rejected up front so verification never sees
    // a truncated key/signature. Both must be present together or both absent.
    const origin_pubkey = origin_pubkey_opt orelse "";
    const origin_sig = origin_sig_opt orelse "";
    if (origin_pubkey.len != 0 and origin_pubkey.len != pubkey_len) return DecodeError.InvalidFieldType;
    if (origin_sig.len != 0 and origin_sig.len != sig_len) return DecodeError.InvalidFieldType;
    if ((origin_pubkey.len == 0) != (origin_sig.len == 0)) return DecodeError.InvalidFieldType;

    const verb = verb_opt orelse return DecodeError.MissingField;
    try validateSemantic(.{
        .verb = verb,
        .target = target,
        .source_nick = source_nick,
        .source_prefix = source_prefix,
        .account = account,
        .tags = tags,
        .text = text,
        .data_tag = data_tag,
        .recipient = recipient,
        .min_rank = min_rank,
        .origin_node = origin_node_opt orelse return DecodeError.MissingField,
        .hlc = hlc_opt orelse return DecodeError.MissingField,
        .origin_pubkey = origin_pubkey,
        .origin_sig = origin_sig,
    });

    const target_owned = try allocator.dupe(u8, target);
    errdefer allocator.free(target_owned);
    const source_nick_owned = try allocator.dupe(u8, source_nick);
    errdefer allocator.free(source_nick_owned);
    const source_prefix_owned = try allocator.dupe(u8, source_prefix);
    errdefer allocator.free(source_prefix_owned);
    const account_owned = try allocator.dupe(u8, account);
    errdefer allocator.free(account_owned);
    const tags_owned = try allocator.dupe(u8, tags);
    errdefer allocator.free(tags_owned);
    const text_owned = try allocator.dupe(u8, text);
    errdefer allocator.free(text_owned);
    const data_tag_owned = try allocator.dupe(u8, data_tag);
    errdefer allocator.free(data_tag_owned);
    const recipient_owned = try allocator.dupe(u8, recipient);
    errdefer allocator.free(recipient_owned);
    const origin_pubkey_owned = try allocator.dupe(u8, origin_pubkey);
    errdefer allocator.free(origin_pubkey_owned);
    const origin_sig_owned = try allocator.dupe(u8, origin_sig);
    errdefer allocator.free(origin_sig_owned);

    return .{ .msg = .{
        .verb = verb,
        .target = target_owned,
        .source_nick = source_nick_owned,
        .source_prefix = source_prefix_owned,
        .account = account_owned,
        .tags = tags_owned,
        .text = text_owned,
        .data_tag = data_tag_owned,
        .recipient = recipient_owned,
        .min_rank = min_rank,
        .origin_node = origin_node_opt orelse return DecodeError.MissingField,
        .hlc = hlc_opt orelse return DecodeError.MissingField,
        .origin_pubkey = origin_pubkey_owned,
        .origin_sig = origin_sig_owned,
    } };
}

// ---------------------------------------------------------------------------
// Self-contained multi-hop origin signature
//
// MESSAGE is relayed VERBATIM with the original `origin_node` preserved, so a
// per-link envelope (like `signed_frame`, where the sending peer IS the origin)
// cannot authenticate it past the first hop. Instead the AUTHOR signs a
// canonical transcript of its IMMUTABLE fields ONCE; every relay forwards the
// `(origin_pubkey, origin_sig)` pair byte-for-byte, and every hop verifies it
// against the CLAIMED origin. Because the node id is self-certifying
// (`node_id = BLAKE3-160(pubkey)`, `origin_node = shortId(node_id)`), a receiver
// needs NO key distribution: it checks `originShortId(pubkey) == origin_node`
// plus the signature. A relay cannot forge or alter an authored message without
// the origin's private key.
//
// SIGNED FIELDS (immutable, origin-authored): origin_node, hlc, verb,
// source_prefix, target, text, data_tag, recipient. EXCLUDED (mutable / hop-
// local, so signing them would break legitimate relays): min_rank (relays raise
// it to 2 for op-moderation / status floors), tags (msgid is server-stamped and
// per-hop client-tag filtered), source_nick and account (derivable / advisory;
// the authoritative identity is the signed source_prefix).
// ---------------------------------------------------------------------------

/// Re-export so callers verify the self-certifying `originShortId(pubkey) ==
/// origin_node` invariant without importing `signed_frame` directly.
pub const originShortId = signed_frame.originShortId;

/// Append a length-prefixed string field to the transcript: a u32-LE length
/// followed by the raw bytes. Length-framing every variable field makes the
/// serialization unambiguous (no field boundary can be shifted by moving bytes
/// between adjacent fields).
fn appendLenPrefixed(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, field: []const u8) !void {
    var len_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_le, @intCast(field.len), .little);
    try out.appendSlice(allocator, &len_le);
    try out.appendSlice(allocator, field);
}

/// Build the canonical signed transcript of `msg`'s immutable origin-authored
/// fields into a freshly-allocated buffer the caller owns. Deterministic across
/// nodes: fixed field order, fixed-width integers (LE), and u32-LE length
/// framing on every string. Independent of CoilPack map ordering and of the
/// mutable/hop-local fields, so a relay that legitimately adjusts `min_rank` or
/// re-stamps `tags`/`msgid` does not invalidate the signature.
pub fn originTranscript(allocator: std.mem.Allocator, msg: RelayMessage) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var u64_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_le, msg.origin_node, .little);
    try out.appendSlice(allocator, &u64_le);
    std.mem.writeInt(u64, &u64_le, msg.hlc, .little);
    try out.appendSlice(allocator, &u64_le);
    try out.append(allocator, @intFromEnum(msg.verb));
    try appendLenPrefixed(&out, allocator, msg.source_prefix);
    try appendLenPrefixed(&out, allocator, msg.target);
    try appendLenPrefixed(&out, allocator, msg.text);
    try appendLenPrefixed(&out, allocator, msg.data_tag);
    try appendLenPrefixed(&out, allocator, msg.recipient);

    return out.toOwnedSlice(allocator);
}

/// Sign `msg`'s canonical origin transcript with the author's Ed25519 keypair
/// and STAMP `origin_pubkey`/`origin_sig` in place. Call this ONCE, at the node
/// that creates the relay message (where `origin_node` is the local node). The
/// caller MUST guarantee the self-certifying invariant
/// `originShortId(kp.public_key) == msg.origin_node`; otherwise the stamped
/// signature would fail every receiver's origin check (sign at the origin or not
/// at all). `pubkey_buf`/`sig_buf` back the stamped slices and must outlive the
/// encode that follows.
pub fn signInPlace(
    msg: *RelayMessage,
    kp: *const sign.KeyPair,
    transcript: []const u8,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) sign.SignError!void {
    const sig = try kp.signCtx(sign_domain, transcript);
    pubkey_buf.* = kp.public_key;
    sig_buf.* = sig;
    msg.origin_pubkey = pubkey_buf;
    msg.origin_sig = sig_buf;
}

pub const VerifyOutcome = enum {
    /// No `(origin_pubkey, origin_sig)` present: legacy unsigned path. The caller
    /// follows the existing (pre-signature) behavior unchanged.
    unsigned,
    /// Signature present, origin self-certifies, and the transcript verifies.
    verified,
    /// Signature present but the self-certified origin id did not match
    /// `origin_node` (a peer asserting another node's origin without its key).
    origin_mismatch,
    /// Signature present and origin matched, but the Ed25519 signature over the
    /// canonical transcript failed (forged or tampered message).
    bad_signature,
};

/// Verify `msg`'s self-contained origin signature. Allocates the transcript
/// internally (freed before return). Returns `.unsigned` when no signature is
/// carried (backward-compatible legacy path), `.verified` on full success, or a
/// specific rejection reason. Field-width invariants are enforced at decode, so
/// a non-empty `origin_pubkey`/`origin_sig` here is always exactly sized.
pub fn verifyOrigin(allocator: std.mem.Allocator, msg: RelayMessage) !VerifyOutcome {
    if (msg.origin_pubkey.len == 0 and msg.origin_sig.len == 0) return .unsigned;
    // Decode-time validation guarantees the pair is present and exactly sized;
    // be defensive anyway so a hand-built struct can never index out of range.
    if (msg.origin_pubkey.len != pubkey_len or msg.origin_sig.len != sig_len) return .bad_signature;

    const pubkey: sign.PublicKey = msg.origin_pubkey[0..pubkey_len].*;
    // Self-certifying origin: the key that signed must DERIVE the claimed
    // origin id. A relay cannot assert another node's origin because it lacks
    // that node's private key (substituting its own key changes the derived id).
    if (originShortId(pubkey) != msg.origin_node) return .origin_mismatch;

    const sig: sign.Signature = msg.origin_sig[0..sig_len].*;
    const transcript = try originTranscript(allocator, msg);
    defer allocator.free(transcript);

    const ok = sign.verifyCtx(sign_domain, transcript, sig, pubkey) catch return .bad_signature;
    return if (ok) .verified else .bad_signature;
}

pub const SeenSet = struct {
    const Key = struct {
        origin_node: u64,
        hlc: u64,
        authenticated: bool,
    };

    allocator: std.mem.Allocator,
    capacity: usize,
    seen: std.AutoHashMapUnmanaged(Key, void) = .empty,
    order: std.ArrayListUnmanaged(Key) = .empty,
    next_evict: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) SeenSet {
        return .{ .allocator = allocator, .capacity = capacity };
    }

    pub fn observe(self: *SeenSet, origin_node: u64, hlc: u64) bool {
        return self.observeClass(origin_node, hlc, true);
    }

    /// Legacy unsigned relays occupy an independent dedup namespace. An
    /// admitted legacy/byzantine peer therefore cannot claim a victim's signed
    /// `(origin,hlc)` first and suppress the later authenticated event.
    pub fn observeUnsigned(self: *SeenSet, origin_node: u64, hlc: u64) bool {
        return self.observeClass(origin_node, hlc, false);
    }

    fn observeClass(self: *SeenSet, origin_node: u64, hlc: u64, authenticated: bool) bool {
        if (self.capacity == 0) return false;

        const key = Key{ .origin_node = origin_node, .hlc = hlc, .authenticated = authenticated };
        if (self.seen.contains(key)) return true;
        self.ensureCapacity() catch return true;

        if (self.order.items.len < self.capacity) {
            self.order.append(self.allocator, key) catch return true;
            self.seen.put(self.allocator, key, {}) catch return true;
            return false;
        }

        const evicted = self.order.items[self.next_evict];
        _ = self.seen.remove(evicted);
        self.order.items[self.next_evict] = key;
        self.next_evict = (self.next_evict + 1) % self.capacity;
        self.seen.put(self.allocator, key, {}) catch return true;
        return false;
    }

    pub fn deinit(self: *SeenSet) void {
        self.seen.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.* = undefined;
    }

    fn ensureCapacity(self: *SeenSet) !void {
        try self.seen.ensureTotalCapacity(self.allocator, @intCast(self.capacity));
        try self.order.ensureTotalCapacity(self.allocator, self.capacity);
    }
};

fn readString(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .string => |string| string,
        else => DecodeError.InvalidFieldType,
    };
}

fn readBytes(value: cpv.Value) DecodeError![]const u8 {
    return switch (value) {
        .bytes => |bytes| bytes,
        else => DecodeError.InvalidFieldType,
    };
}

fn readU64(value: cpv.Value) DecodeError!u64 {
    return switch (value) {
        .unsigned => |n| n,
        else => DecodeError.InvalidFieldType,
    };
}

fn readVerb(value: cpv.Value) DecodeError!Verb {
    const raw = try readU64(value);
    return switch (raw) {
        1 => .privmsg,
        2 => .notice,
        3 => .tagmsg,
        4 => .data,
        5 => .request,
        6 => .reply,
        7 => .whisper,
        else => DecodeError.InvalidVerb,
    };
}

fn readRank(value: cpv.Value) DecodeError!u8 {
    const raw = try readU64(value);
    if (raw > 4) return DecodeError.InvalidFieldType;
    return @intCast(raw);
}

fn expectRoundTrip(msg: RelayMessage) !void {
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);

    var owned = try decode(allocator, wire);
    defer owned.deinit(allocator);

    try std.testing.expectEqual(msg.verb, owned.msg.verb);
    try std.testing.expectEqualStrings(msg.target, owned.msg.target);
    try std.testing.expectEqualStrings(msg.source_nick, owned.msg.source_nick);
    try std.testing.expectEqualStrings(msg.source_prefix, owned.msg.source_prefix);
    try std.testing.expectEqualStrings(msg.account, owned.msg.account);
    try std.testing.expectEqualStrings(msg.tags, owned.msg.tags);
    try std.testing.expectEqualStrings(msg.text, owned.msg.text);
    try std.testing.expectEqualStrings(msg.data_tag, owned.msg.data_tag);
    try std.testing.expectEqualStrings(msg.recipient, owned.msg.recipient);
    try std.testing.expectEqual(msg.min_rank, owned.msg.min_rank);
    try std.testing.expectEqual(msg.origin_node, owned.msg.origin_node);
    try std.testing.expectEqual(msg.hlc, owned.msg.hlc);
    try std.testing.expectEqualSlices(u8, msg.origin_pubkey, owned.msg.origin_pubkey);
    try std.testing.expectEqualSlices(u8, msg.origin_sig, owned.msg.origin_sig);
}

fn semanticSample() RelayMessage {
    return .{
        .verb = .privmsg,
        .target = "#onyx",
        .source_nick = "alice",
        .source_prefix = "alice!user@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "hello mesh",
        .origin_node = 7,
        .hlc = 101,
    };
}

fn expectSemanticInvalidOnWire(msg: RelayMessage) !void {
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(msg));
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);
    try std.testing.expectError(error.InvalidSemantic, decode(allocator, wire));
}

test "semantic validation rejects CR LF NUL and controls in every rendered field" {
    const Field = enum {
        target,
        source_nick,
        source_prefix,
        account,
        tags,
        text,
        data_tag,
        recipient,
    };
    // For text: c0 is CTCP SOH (\x01) — still forbidden. mIRC format codes are
    // content and are covered by a separate allow-test below.
    const BadByte = enum { cr, lf, crlf, nul, c0, del };

    inline for (std.meta.tags(Field)) |field| {
        inline for (std.meta.tags(BadByte)) |bad| {
            var msg = semanticSample();
            switch (field) {
                .target => msg.target = switch (bad) {
                    .cr => "#bad\rtarget",
                    .lf => "#bad\ntarget",
                    .crlf => "#bad\r\ntarget",
                    .nul => "#bad\x00target",
                    .c0 => "#bad\x01target",
                    .del => "#bad\x7ftarget",
                },
                .source_nick => msg.source_nick = switch (bad) {
                    .cr => "ali\rce",
                    .lf => "ali\nce",
                    .crlf => "ali\r\nce",
                    .nul => "ali\x00ce",
                    .c0 => "ali\x01ce",
                    .del => "ali\x7fce",
                },
                .source_prefix => msg.source_prefix = switch (bad) {
                    .cr => "alice!user@bad\rhost",
                    .lf => "alice!user@bad\nhost",
                    .crlf => "alice!user@bad\r\nhost",
                    .nul => "alice!user@bad\x00host",
                    .c0 => "alice!user@bad\x01host",
                    .del => "alice!user@bad\x7fhost",
                },
                .account => msg.account = switch (bad) {
                    .cr => "ali\rce",
                    .lf => "ali\nce",
                    .crlf => "ali\r\nce",
                    .nul => "ali\x00ce",
                    .c0 => "ali\x01ce",
                    .del => "ali\x7fce",
                },
                .tags => msg.tags = switch (bad) {
                    .cr => "+draft/reply=bad\rvalue",
                    .lf => "+draft/reply=bad\nvalue",
                    .crlf => "+draft/reply=bad\r\nvalue",
                    .nul => "+draft/reply=bad\x00value",
                    .c0 => "+draft/reply=bad\x01value",
                    .del => "+draft/reply=bad\x7fvalue",
                },
                .text => msg.text = switch (bad) {
                    .cr => "hello\rNOTICE victim :forged",
                    .lf => "hello\nNOTICE victim :forged",
                    .crlf => "hello\r\nNOTICE victim :forged",
                    .nul => "hello\x00world",
                    .c0 => "hello\x01world",
                    .del => "hello\x7fworld",
                },
                .data_tag => {
                    msg.verb = .data;
                    msg.data_tag = switch (bad) {
                        .cr => "SYS\rProbe",
                        .lf => "SYS\nProbe",
                        .crlf => "SYS\r\nProbe",
                        .nul => "SYS\x00Probe",
                        .c0 => "SYS\x01Probe",
                        .del => "SYS\x7fProbe",
                    };
                },
                .recipient => {
                    msg.verb = .whisper;
                    msg.tags = "";
                    msg.recipient = switch (bad) {
                        .cr => "bo\rb",
                        .lf => "bo\nb",
                        .crlf => "bo\r\nb",
                        .nul => "bo\x00b",
                        .c0 => "bo\x01b",
                        .del => "bo\x7fb",
                    };
                },
            }
            try expectSemanticInvalidOnWire(msg);
        }
    }
}

test "semantic validation allows mIRC formatting controls in message text only" {
    // Body text: every standard IRC format code is content, not framing.
    const format_samples = [_][]const u8{
        "\x02bold\x02",
        "\x0304red\x03 plain",
        "\x0312,01blue on black\x03",
        "\x04FF0000hex\x04",
        "\x1funderline\x1f",
        "\x1ditalic\x1d",
        "\x1estrike\x1e",
        "\x16reverse\x16",
        "\x11mono\x11",
        "\x02\x0309feat\x0f done",
        "mixed \x02bold\x0f and plain",
    };
    for (format_samples) |text| {
        var msg = semanticSample();
        msg.text = text;
        try validateSemantic(msg);
        const allocator = std.testing.allocator;
        const wire = try encode(allocator, msg);
        defer allocator.free(wire);
        var owned = try decode(allocator, wire);
        defer owned.deinit(allocator);
        try std.testing.expectEqualStrings(text, owned.msg.text);
    }

    // Same bytes in identity fields remain illegal (no format smuggling into nick).
    var bad_nick = semanticSample();
    bad_nick.source_nick = "al\x03ice";
    try expectSemanticInvalidOnWire(bad_nick);

    var bad_prefix = semanticSample();
    bad_prefix.source_prefix = "alice!us\x02er@example.invalid";
    try expectSemanticInvalidOnWire(bad_prefix);

    // Non-format C0 still rejected in text (TAB, BEL, SOH/CTCP, ESC).
    for ([_][]const u8{ "a\tb", "a\x07b", "a\x01b", "a\x1bb" }) |text| {
        var msg = semanticSample();
        msg.text = text;
        try expectSemanticInvalidOnWire(msg);
    }
}

test "semantic validation enforces full prefix target and tag grammar" {
    for ([_][]const u8{
        "aliceuser@example.invalid",
        "alice!userexample.invalid",
        "!user@example.invalid",
        "alice!@example.invalid",
        "alice!user@",
        "alice!!user@example.invalid",
        "alice!user@example.invalid@evil",
        "alice!bad:user@example.invalid",
        "alice!user@bad,host",
        "bob!user@example.invalid",
    }) |prefix| {
        var msg = semanticSample();
        msg.source_prefix = prefix;
        try expectSemanticInvalidOnWire(msg);
    }

    for ([_][]const u8{ "", "#", "%#", "#bad,name", "9invalid", "bad target" }) |target| {
        var msg = semanticSample();
        msg.target = target;
        try expectSemanticInvalidOnWire(msg);
    }

    for ([_][]const u8{
        "draft/reply=42",
        "+bad_key=value",
        "+empty=ok;",
        "+dup=one;+dup=two",
        "+space=not allowed",
        "+semi=not;allowed",
    }) |tags| {
        var msg = semanticSample();
        msg.tags = tags;
        try expectSemanticInvalidOnWire(msg);
    }

    var invalid_utf8_tag = semanticSample();
    invalid_utf8_tag.tags = "+invalid=\xff";
    try std.testing.expectError(error.InvalidSemantic, validateSemantic(invalid_utf8_tag));
    try std.testing.expectError(cpv.FormatError.InvalidUtf8, encode(std.testing.allocator, invalid_utf8_tag));

    var ranked_nick = semanticSample();
    ranked_nick.target = "bob";
    ranked_nick.min_rank = 1;
    try expectSemanticInvalidOnWire(ranked_nick);

    var whisper_to_nick = semanticSample();
    whisper_to_nick.verb = .whisper;
    whisper_to_nick.target = "bob";
    whisper_to_nick.tags = "";
    whisper_to_nick.recipient = "carol";
    try expectSemanticInvalidOnWire(whisper_to_nick);
}

test "semantic validation enforces verb-specific fields" {
    var msg = semanticSample();
    msg.text = "";
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.data_tag = "SYS.Probe";
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.recipient = "bob";
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.verb = .tagmsg;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.verb = .tagmsg;
    msg.text = "";
    msg.tags = "";
    try expectSemanticInvalidOnWire(msg);

    inline for (.{ Verb.data, Verb.request, Verb.reply }) |verb| {
        msg = semanticSample();
        msg.verb = verb;
        msg.data_tag = "";
        try expectSemanticInvalidOnWire(msg);

        msg.data_tag = "9bad";
        try expectSemanticInvalidOnWire(msg);

        msg.data_tag = "SYS.Probe";
        msg.text = "";
        try expectSemanticInvalidOnWire(msg);
    }

    msg = semanticSample();
    msg.verb = .whisper;
    msg.tags = "";
    msg.recipient = "";
    try expectSemanticInvalidOnWire(msg);

    msg.recipient = "bob";
    msg.min_rank = 1;
    try expectSemanticInvalidOnWire(msg);

    msg.min_rank = 0;
    msg.data_tag = "SYS.Probe";
    try expectSemanticInvalidOnWire(msg);
}

test "semantic validation enforces hard field bounds" {
    var too_long_nick: [max_nick_len + 1]u8 = @splat('a');
    var too_long_channel: [max_channel_len + 1]u8 = @splat('a');
    too_long_channel[0] = '#';
    var too_long_account: [max_account_len + 1]u8 = @splat('a');
    var too_long_tags: [max_tags_len + 1]u8 = @splat('a');
    too_long_tags[0] = '+';
    var too_long_text: [max_text_len + 1]u8 = @splat('a');
    var too_long_data_tag: [max_data_tag_len + 1]u8 = @splat('a');
    const too_long_user: [max_user_len + 1]u8 = @splat('u');
    const too_long_host: [max_host_len + 1]u8 = @splat('h');

    var msg = semanticSample();
    msg.source_nick = &too_long_nick;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.target = &too_long_channel;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.account = &too_long_account;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.tags = &too_long_tags;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.text = &too_long_text;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.verb = .data;
    msg.data_tag = &too_long_data_tag;
    try expectSemanticInvalidOnWire(msg);

    msg = semanticSample();
    msg.verb = .whisper;
    msg.tags = "";
    msg.recipient = &too_long_nick;
    try expectSemanticInvalidOnWire(msg);

    var prefix_buf: [max_prefix_len + 2]u8 = undefined;
    msg = semanticSample();
    msg.source_prefix = try std.fmt.bufPrint(&prefix_buf, "alice!{s}@host", .{too_long_user});
    try expectSemanticInvalidOnWire(msg);

    msg.source_prefix = try std.fmt.bufPrint(&prefix_buf, "alice!user@{s}", .{too_long_host});
    try expectSemanticInvalidOnWire(msg);
}

test "semantic validation preserves supported UTF8 IRCX and prefix forms" {
    try expectRoundTrip(.{
        .verb = .privmsg,
        .target = "%#\xe9\x83\xa8\xe5\xb1\x8b",
        .source_nick = "\xce\x94\xce\xb5\xce\xbb\xcf\x84\xce\xb1",
        .source_prefix = "\xce\x94\xce\xb5\xce\xbb\xcf\x84\xce\xb1!~user@[2001:db8::1]",
        .tags = "+draft/reply=one\\stwo;+vendor.example/tag=ok",
        .text = "mesh UTF8",
        .origin_node = 20,
        .hlc = 200,
    });

    try expectRoundTrip(.{
        .verb = .notice,
        .target = "[Nick]",
        .source_nick = "Service",
        .source_prefix = "Service!svc@cloak/services/notice",
        .text = "RFC special nick and cloaked host",
        .origin_node = 21,
        .hlc = 201,
    });

    try expectRoundTrip(.{
        .verb = .whisper,
        .target = "%&local",
        .source_nick = "alice",
        .source_prefix = "alice!user@example.invalid",
        .text = "IRCX local UTF8 channel",
        .recipient = "bob",
        .origin_node = 22,
        .hlc = 202,
    });
}

test "relay messages round-trip for each verb" {
    try expectRoundTrip(.{
        .verb = .privmsg,
        .target = "#onyx",
        .source_nick = "alice",
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "hello mesh",
        .min_rank = 2,
        .origin_node = 7,
        .hlc = 101,
    });

    try expectRoundTrip(.{
        .verb = .notice,
        .target = "bob",
        .source_nick = "service",
        .source_prefix = "service!svc@example.invalid",
        .account = "",
        .tags = "",
        .text = "maintenance soon",
        .origin_node = 8,
        .hlc = 102,
    });

    try expectRoundTrip(.{
        .verb = .tagmsg,
        .target = "#onyx",
        .source_nick = "carol",
        .source_prefix = "carol!u@example.invalid",
        .account = "",
        .tags = "+typing=active",
        .text = "",
        .origin_node = 9,
        .hlc = 103,
    });

    // IRCX typed channel DATA carries the data tag; recipient stays empty.
    try expectRoundTrip(.{
        .verb = .data,
        .target = "#onyx",
        .source_nick = "dave",
        .source_prefix = "dave!u@example.invalid",
        .account = "dave",
        .tags = "",
        .text = "comic frame payload",
        .data_tag = "MSN.Avatar",
        .min_rank = 0,
        .origin_node = 10,
        .hlc = 104,
    });

    // REQUEST to a nick target (no channel scope), data tag present.
    try expectRoundTrip(.{
        .verb = .request,
        .target = "erin",
        .source_nick = "dave",
        .source_prefix = "dave!u@example.invalid",
        .text = "ping",
        .data_tag = "SYS.Probe",
        .origin_node = 11,
        .hlc = 105,
    });

    // REPLY to a STATUSMSG channel target (min_rank floor), data tag present.
    try expectRoundTrip(.{
        .verb = .reply,
        .target = "#onyx",
        .source_nick = "erin",
        .source_prefix = "erin!u@example.invalid",
        .text = "pong",
        .data_tag = "SYS.Probe",
        .min_rank = 2,
        .origin_node = 12,
        .hlc = 106,
    });

    // WHISPER: target is the shared channel, recipient is the co-member nick.
    try expectRoundTrip(.{
        .verb = .whisper,
        .target = "#onyx",
        .source_nick = "alice",
        .source_prefix = "alice!u@example.invalid",
        .text = "psst over the mesh",
        .recipient = "bob",
        .origin_node = 13,
        .hlc = 107,
    });
}

test "decode rejects truncated and garbage buffers" {
    const allocator = std.testing.allocator;
    const wire = try encode(allocator, .{
        .verb = .privmsg,
        .target = "#x",
        .source_nick = "n",
        .source_prefix = "n!u@h",
        .text = "hi",
        .origin_node = 1,
        .hlc = 2,
    });
    defer allocator.free(wire);

    try std.testing.expectError(cpv.FormatError.Truncated, decode(allocator, wire[0 .. wire.len - 1]));
    try std.testing.expectError(cpv.FormatError.UnknownTag, decode(allocator, &.{0xff}));
}

test "seen set detects repeats and evicts oldest" {
    var seen = SeenSet.init(std.testing.allocator, 2);
    defer seen.deinit();

    try std.testing.expect(!seen.observe(1, 10));
    try std.testing.expect(seen.observe(1, 10));
    try std.testing.expect(!seen.observe(2, 20));
    try std.testing.expect(!seen.observe(3, 30));
    try std.testing.expect(!seen.observe(1, 10));
    try std.testing.expect(seen.observe(3, 30));
}

test "unsigned dedup cannot poison the authenticated event namespace" {
    var seen = SeenSet.init(std.testing.allocator, 8);
    defer seen.deinit();

    try std.testing.expect(!seen.observeUnsigned(7, 11));
    try std.testing.expect(seen.observeUnsigned(7, 11));
    try std.testing.expect(!seen.observe(7, 11));
    try std.testing.expect(seen.observe(7, 11));
}

// ---------------------------------------------------------------------------
// Self-contained origin signature tests
// ---------------------------------------------------------------------------

fn testKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

/// Build a base relay message whose `origin_node` is the self-certified short id
/// of `kp` (so a signature minted by `kp` satisfies the receiver's origin check),
/// then sign it in place using caller-provided backing buffers.
fn signSample(
    kp: *const sign.KeyPair,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) !RelayMessage {
    var msg = RelayMessage{
        .verb = .privmsg,
        .target = "#onyx",
        .source_nick = "alice",
        .source_prefix = "alice!u@example.invalid",
        .account = "alice",
        .tags = "+draft/reply=42",
        .text = "authored once, relayed everywhere",
        .min_rank = 0,
        .origin_node = originShortId(kp.public_key),
        .hlc = 4242,
    };
    const transcript = try originTranscript(std.testing.allocator, msg);
    defer std.testing.allocator.free(transcript);
    try signInPlace(&msg, kp, transcript, pubkey_buf, sig_buf);
    return msg;
}

test "relay message round-trips WITH a signature" {
    var kp = try testKeyPair(0xA1);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const msg = try signSample(&kp, &pk_buf, &sig_buf);
    // Round-trips and the verifier accepts the decoded copy.
    try expectRoundTrip(msg);

    const allocator = std.testing.allocator;
    const wire = try encode(allocator, msg);
    defer allocator.free(wire);
    var owned = try decode(allocator, wire);
    defer owned.deinit(allocator);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, owned.msg));
}

test "relay message round-trips WITHOUT a signature (legacy unsigned)" {
    const msg = RelayMessage{
        .verb = .notice,
        .target = "bob",
        .source_nick = "service",
        .source_prefix = "service!svc@example.invalid",
        .text = "legacy unsigned path",
        .origin_node = 7,
        .hlc = 9,
    };
    try expectRoundTrip(msg);
    // No signature carried => the verifier reports the legacy path, never a reject.
    try std.testing.expectEqual(VerifyOutcome.unsigned, try verifyOrigin(std.testing.allocator, msg));
}

test "a signed relay message verifies" {
    var kp = try testKeyPair(0xB2);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const msg = try signSample(&kp, &pk_buf, &sig_buf);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(std.testing.allocator, msg));
}

test "a forged signature (valid structure, wrong key) is rejected" {
    var origin_kp = try testKeyPair(0xC3);
    defer origin_kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var msg = try signSample(&origin_kp, &pk_buf, &sig_buf);

    // Attacker re-signs the SAME transcript with its OWN key but keeps the
    // victim's origin_node + pubkey. The pubkey no longer matches the sig.
    var attacker = try testKeyPair(0xC4);
    defer attacker.deinit();
    const transcript = try originTranscript(std.testing.allocator, msg);
    defer std.testing.allocator.free(transcript);
    sig_buf = try attacker.signCtx(sign_domain, transcript);
    msg.origin_sig = &sig_buf;
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, msg));
}

test "a pubkey whose originShortId != origin_node is rejected" {
    var attacker = try testKeyPair(0xD5);
    defer attacker.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var msg = try signSample(&attacker, &pk_buf, &sig_buf);
    // The attacker validly signs with its OWN key, but claims a DIFFERENT
    // origin_node than its key self-certifies: the origin check must fail.
    msg.origin_node = originShortId(attacker.public_key) ^ 0x1;
    try std.testing.expectEqual(VerifyOutcome.origin_mismatch, try verifyOrigin(std.testing.allocator, msg));
}

test "tampering with text after signing fails verification" {
    var kp = try testKeyPair(0xE6);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var msg = try signSample(&kp, &pk_buf, &sig_buf);
    msg.text = "tampered body the origin never authored";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, msg));
}

test "tampering with target after signing fails verification" {
    var kp = try testKeyPair(0xE7);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var msg = try signSample(&kp, &pk_buf, &sig_buf);
    msg.target = "#hijacked";
    try std.testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(std.testing.allocator, msg));
}

test "re-forward preserves the signature: a relayed copy still verifies" {
    var kp = try testKeyPair(0xF8);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const origin_msg = try signSample(&kp, &pk_buf, &sig_buf);

    const allocator = std.testing.allocator;
    // Hop 1 receives, decodes, then re-encodes VERBATIM (forward without re-sign).
    const wire1 = try encode(allocator, origin_msg);
    defer allocator.free(wire1);
    var hop1 = try decode(allocator, wire1);
    defer hop1.deinit(allocator);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, hop1.msg));

    // Hop 1 re-forwards the decoded message unchanged; hop 2 still verifies the
    // ORIGINAL origin (not hop 1), which is the whole point of multi-hop signing.
    const wire2 = try encode(allocator, hop1.msg);
    defer allocator.free(wire2);
    var hop2 = try decode(allocator, wire2);
    defer hop2.deinit(allocator);
    try std.testing.expectEqualSlices(u8, origin_msg.origin_pubkey, hop2.msg.origin_pubkey);
    try std.testing.expectEqualSlices(u8, origin_msg.origin_sig, hop2.msg.origin_sig);
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(allocator, hop2.msg));
}

test "mutable fields (min_rank, tags, msgid) do not invalidate the signature" {
    var kp = try testKeyPair(0x19);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var msg = try signSample(&kp, &pk_buf, &sig_buf);
    // A relay legitimately raises the status floor and re-stamps client tags; the
    // signature (over the immutable fields only) must still verify.
    msg.min_rank = 2;
    msg.tags = "+server-time=2026-06-15T00:00:00.000Z;msgid=abcdef";
    msg.account = "rewritten-by-relay";
    msg.source_nick = "ALICE";
    try std.testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(std.testing.allocator, msg));
}

test "decode rejects a wrong-width origin_pubkey" {
    const allocator = std.testing.allocator;
    // Hand-build a CoilPack map with a 31-byte pubkey (one short of 32).
    var bad_pubkey = @as([31]u8, @splat(0xAB));
    var bad_sig = @as([sig_len]u8, @splat(0xCD));
    var entries = [_]cpv.MapEntry{
        .{ .key = "account", .value = .{ .string = "" } },
        .{ .key = "data_tag", .value = .{ .string = "" } },
        .{ .key = "hlc", .value = .{ .unsigned = 1 } },
        .{ .key = "min_rank", .value = .{ .unsigned = 0 } },
        .{ .key = "origin_node", .value = .{ .unsigned = 5 } },
        .{ .key = "origin_pubkey", .value = .{ .bytes = bad_pubkey[0..] } },
        .{ .key = "origin_sig", .value = .{ .bytes = bad_sig[0..] } },
        .{ .key = "recipient", .value = .{ .string = "" } },
        .{ .key = "source_nick", .value = .{ .string = "n" } },
        .{ .key = "source_prefix", .value = .{ .string = "n!u@h" } },
        .{ .key = "tags", .value = .{ .string = "" } },
        .{ .key = "target", .value = .{ .string = "#x" } },
        .{ .key = "text", .value = .{ .string = "hi" } },
        .{ .key = "verb", .value = .{ .unsigned = 1 } },
    };
    const wire = try cpv.Encoder.encode(allocator, .{ .map = entries[0..] });
    defer allocator.free(wire);
    try std.testing.expectError(DecodeError.InvalidFieldType, decode(allocator, wire));
}
