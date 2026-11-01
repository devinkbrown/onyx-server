// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 CAP negotiation state machine.
//!
//! Capabilities are represented as stable enum bits and advertised through a
//! registry. Per-client sessions keep only negotiated state plus the
//! preregistration CAP negotiation phase.
const std = @import("std");

pub const MAX_CAP_REPLY_BODY: usize = 500;

/// Known IRCv3 capability identifiers.
pub const CapId = enum(u6) {
    server_time,
    message_tags,
    account_tag,
    batch,
    echo_message,
    cap_notify,
    sts,
    bot,
    multiline,
    chathistory,
    account_notify,
    away_notify,
    setname,
    chghost,
    extended_monitor,
    labeled_response,
    sasl,
    msgid,
    account_extban,
    tls,
    utf8_only,
    no_implicit_names,
    event_playback,
    read_marker,
    channel_rename,
    file_upload,
    search,
    reply,
    react,
    message_editing,
    message_redaction,
    typing,
    onyx_session_sync,
    onyx_bouncer,
    onyx_cadence_media,
};

pub const CAP_COUNT: usize = @typeInfo(CapId).@"enum".field_names.len;

comptime {
    if (CAP_COUNT > 64) @compileError("CapSet stores bits in u64");
}

/// Bitset over known capabilities.
pub const CapSet = struct {
    bits: u64 = 0,

    pub fn empty() CapSet {
        return .{};
    }

    pub fn one(id: CapId) CapSet {
        var set = CapSet.empty();
        set.add(id);
        return set;
    }

    pub fn add(self: *CapSet, id: CapId) void {
        self.bits |= bit(id);
    }

    pub fn remove(self: *CapSet, id: CapId) void {
        self.bits &= ~bit(id);
    }

    pub fn contains(self: CapSet, id: CapId) bool {
        return (self.bits & bit(id)) != 0;
    }

    pub fn containsAll(self: CapSet, other: CapSet) bool {
        return (self.bits & other.bits) == other.bits;
    }

    pub fn isEmpty(self: CapSet) bool {
        return self.bits == 0;
    }

    pub fn unionWith(self: *CapSet, other: CapSet) void {
        self.bits |= other.bits;
    }

    pub fn subtract(self: *CapSet, other: CapSet) void {
        self.bits &= ~other.bits;
    }

    fn bit(id: CapId) u64 {
        return @as(u64, 1) << @as(u6, @intCast(@backingInt(id)));
    }
};

/// Whether a capability is for client negotiation or server-to-server policy.
pub const CapKind = enum {
    client,
    server,
};

/// One capability advertised by the daemon.
pub const CapSpec = struct {
    id: CapId,
    name: []const u8,
    value_302: ?[]const u8 = null,
    kind: CapKind = .client,
    advertised: bool = true,
};

/// Registry of capabilities visible to CAP negotiation.
pub const CapRegistry = struct {
    specs: []const CapSpec,

    pub fn default() CapRegistry {
        return .{ .specs = &default_specs };
    }

    pub fn find(self: CapRegistry, name: []const u8) ?CapSpec {
        for (self.specs) |spec| {
            if (std.mem.eql(u8, spec.name, name)) return spec;
        }
        return null;
    }

    pub fn nameOf(self: CapRegistry, id: CapId) ?[]const u8 {
        for (self.specs) |spec| {
            if (spec.id == id) return spec.name;
        }
        return null;
    }

    pub fn advertisedSet(self: CapRegistry) CapSet {
        var set = CapSet.empty();
        for (self.specs) |spec| {
            if (spec.kind == .client and spec.advertised) {
                set.add(spec.id);
            }
        }
        return set;
    }

    pub fn emitLs(
        self: CapRegistry,
        cap_302: bool,
        max_body: usize,
        sink: *CapReplySink,
    ) CapError!void {
        if (max_body == 0 or max_body > MAX_CAP_REPLY_BODY) {
            return error.OutputTooSmall;
        }

        var body: [MAX_CAP_REPLY_BODY]u8 = undefined;
        var body_len: usize = 0;
        var emitted_any = false;

        for (self.specs) |spec| {
            if (spec.kind != .client or !spec.advertised) continue;

            var token: [MAX_CAP_REPLY_BODY]u8 = undefined;
            const token_text = try writeToken(spec, cap_302, &token);
            if (token_text.len > max_body) return error.OutputTooSmall;

            const extra_space: usize = if (body_len == 0) 0 else 1;
            if (body_len != 0 and body_len + extra_space + token_text.len > max_body) {
                try sink.append(.ls, true, body[0..body_len]);
                emitted_any = true;
                body_len = 0;
            }

            if (body_len != 0) {
                body[body_len] = ' ';
                body_len += 1;
            }
            @memcpy(body[body_len .. body_len + token_text.len], token_text);
            body_len += token_text.len;
        }

        if (body_len != 0 or !emitted_any) {
            try sink.append(.ls, false, body[0..body_len]);
        } else {
            sink.replies[sink.count - 1].continuation = false;
        }
    }
};

pub const CapError = error{
    InvalidCommand,
    MissingParameter,
    OutputTooSmall,
    TooManyReplies,
};

pub const CapReplyKind = enum {
    ls,
    list,
    ack,
    nak,
};

/// Structured CAP reply. `continuation` maps to the extra `*` in CAP LS.
pub const CapReply = struct {
    kind: CapReplyKind,
    continuation: bool = false,
    body: []const u8,
};

/// Caller-provided storage for structured CAP replies.
pub const CapReplySink = struct {
    replies: []CapReply,
    storage: []u8,
    count: usize = 0,
    used: usize = 0,

    pub fn append(
        self: *CapReplySink,
        kind: CapReplyKind,
        continuation: bool,
        body: []const u8,
    ) CapError!void {
        if (self.count >= self.replies.len) return error.TooManyReplies;
        if (self.used + body.len > self.storage.len) return error.OutputTooSmall;

        const start = self.used;
        const end = start + body.len;
        @memcpy(self.storage[start..end], body);
        self.used = end;
        self.replies[self.count] = .{
            .kind = kind,
            .continuation = continuation,
            .body = self.storage[start..end],
        };
        self.count += 1;
    }

    pub fn slice(self: *const CapReplySink) []const CapReply {
        return self.replies[0..self.count];
    }
};

pub const CapState = enum {
    idle,
    negotiating,
    complete,
};

/// Per-client CAP state machine.
pub const CapSession = struct {
    state: CapState = .idle,
    negotiated: CapSet = .{},
    cap_302: bool = false,

    pub fn registrationHeld(self: CapSession) bool {
        return self.state == .negotiating;
    }

    pub fn handle(
        self: *CapSession,
        registry: CapRegistry,
        subcommand: []const u8,
        params: []const []const u8,
        sink: *CapReplySink,
    ) CapError!void {
        if (eqlIgnoreCase(subcommand, "LS")) {
            const requested_302 = params.len != 0 and std.mem.eql(u8, params[0], "302");
            return self.handleLs(registry, requested_302, MAX_CAP_REPLY_BODY, sink);
        }
        if (eqlIgnoreCase(subcommand, "LIST")) {
            return self.handleList(registry, sink);
        }
        if (eqlIgnoreCase(subcommand, "REQ")) {
            if (params.len == 0) return error.MissingParameter;
            return self.handleReq(registry, params[0], sink);
        }
        if (eqlIgnoreCase(subcommand, "ACK")) {
            if (params.len == 0) return error.MissingParameter;
            return self.handleAck(registry, params[0]);
        }
        if (eqlIgnoreCase(subcommand, "END")) {
            self.handleEnd();
            return;
        }
        return error.InvalidCommand;
    }

    pub fn handleLs(
        self: *CapSession,
        registry: CapRegistry,
        requested_302: bool,
        max_body: usize,
        sink: *CapReplySink,
    ) CapError!void {
        self.state = .negotiating;
        self.cap_302 = self.cap_302 or requested_302;
        try registry.emitLs(self.cap_302, max_body, sink);
    }

    pub fn handleList(
        self: *CapSession,
        registry: CapRegistry,
        sink: *CapReplySink,
    ) CapError!void {
        var body: [MAX_CAP_REPLY_BODY]u8 = undefined;
        const written = try writeSetNames(registry, self.negotiated, &body);
        try sink.append(.list, false, written);
    }

    pub fn handleReq(
        self: *CapSession,
        registry: CapRegistry,
        raw_list: []const u8,
        sink: *CapReplySink,
    ) CapError!void {
        self.state = .negotiating;

        const changes = parseRequestedSet(registry, raw_list) orelse {
            try sink.append(.nak, false, raw_list);
            return;
        };

        self.negotiated.unionWith(changes.add);
        self.negotiated.subtract(changes.remove);
        try sink.append(.ack, false, raw_list);
    }

    pub fn handleAck(
        self: *CapSession,
        registry: CapRegistry,
        raw_list: []const u8,
    ) CapError!void {
        const changes = parseRequestedSet(registry, raw_list) orelse return error.InvalidCommand;
        self.negotiated.unionWith(changes.add);
        self.negotiated.subtract(changes.remove);
    }

    pub fn handleEnd(self: *CapSession) void {
        self.state = .complete;
    }
};

/// Return whether an outbound IRCv3 tag may be sent to this client.
pub fn maySendTag(caps: CapSet, tag_key: []const u8) bool {
    const required = capForTag(tag_key) orelse return false;
    return caps.contains(required);
}

pub fn capForTag(tag_key: []const u8) ?CapId {
    if (std.mem.eql(u8, tag_key, "time") or std.mem.eql(u8, tag_key, "server-time")) {
        return .server_time;
    }
    if (std.mem.eql(u8, tag_key, "account")) return .account_tag;
    if (std.mem.eql(u8, tag_key, "batch")) return .batch;
    if (std.mem.eql(u8, tag_key, "bot")) return .bot;
    if (std.mem.eql(u8, tag_key, "label")) return .labeled_response;
    if (std.mem.eql(u8, tag_key, "msgid")) return .msgid;
    if (std.mem.eql(u8, tag_key, "draft/multiline-concat")) return .multiline;
    return null;
}

const RequestedSet = struct {
    add: CapSet = .{},
    remove: CapSet = .{},
};

const default_specs = [_]CapSpec{
    .{ .id = .server_time, .name = "server-time" },
    .{ .id = .message_tags, .name = "message-tags" },
    .{ .id = .account_tag, .name = "account-tag" },
    .{ .id = .batch, .name = "batch" },
    .{ .id = .echo_message, .name = "echo-message" },
    .{ .id = .cap_notify, .name = "cap-notify" },
    .{ .id = .sts, .name = "sts", .value_302 = "duration=604800" },
    .{ .id = .bot, .name = "bot" },
    .{ .id = .multiline, .name = "multiline" },
    .{ .id = .chathistory, .name = "chathistory" },
    .{ .id = .account_notify, .name = "account-notify" },
    .{ .id = .away_notify, .name = "away-notify" },
    .{ .id = .setname, .name = "setname" },
    .{ .id = .chghost, .name = "chghost" },
    .{ .id = .extended_monitor, .name = "extended-monitor" },
    .{ .id = .labeled_response, .name = "labeled-response" },
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN,EXTERNAL" },
    .{ .id = .msgid, .name = "msgid" },
    .{ .id = .account_extban, .name = "account-extban" },
    .{ .id = .tls, .name = "tls" },
    .{ .id = .utf8_only, .name = "utf8-only" },
    .{ .id = .no_implicit_names, .name = "no-implicit-names" },
    // Dual-advertise the spec-conformant draft token so IRCv3 clients that only
    // recognize `draft/no-implicit-names` actually engage the feature. Same id,
    // so REQ of either name toggles one capability; CAP ACK echoes the client's
    // requested token verbatim, so a client never sees a name it didn't ask for.
    .{ .id = .no_implicit_names, .name = "draft/no-implicit-names" },
    .{ .id = .event_playback, .name = "event-playback" },
    .{ .id = .read_marker, .name = "read-marker" },
    .{ .id = .channel_rename, .name = "channel-rename" },
    .{ .id = .file_upload, .name = "file-upload" },
    .{ .id = .search, .name = "draft/search" },
    .{ .id = .reply, .name = "reply" },
    .{ .id = .react, .name = "react" },
    .{ .id = .message_editing, .name = "message-editing" },
    .{ .id = .message_redaction, .name = "message-redaction" },
    .{ .id = .typing, .name = "typing" },
    .{ .id = .onyx_session_sync, .name = "onyx/session-sync" },
    .{ .id = .onyx_bouncer, .name = "onyx/bouncer" },
    .{ .id = .onyx_cadence_media, .name = "onyx/cadence-media" },
};

fn parseRequestedSet(registry: CapRegistry, raw_list: []const u8) ?RequestedSet {
    var changes = RequestedSet{};
    var saw_token = false;
    var cursor: usize = 0;

    while (cursor < raw_list.len) {
        while (cursor < raw_list.len and raw_list[cursor] == ' ') {
            cursor += 1;
        }
        if (cursor >= raw_list.len) break;

        const token_start = cursor;
        while (cursor < raw_list.len and raw_list[cursor] != ' ') {
            cursor += 1;
        }

        var token = raw_list[token_start..cursor];
        const remove = token.len > 0 and token[0] == '-';
        if (remove) token = token[1..];
        if (token.len == 0) return null;

        const spec = registry.find(token) orelse return null;
        if (spec.kind != .client or !spec.advertised) return null;

        if (remove) {
            changes.remove.add(spec.id);
            changes.add.remove(spec.id);
        } else {
            changes.add.add(spec.id);
            changes.remove.remove(spec.id);
        }
        saw_token = true;
    }

    return if (saw_token) changes else null;
}

fn writeSetNames(registry: CapRegistry, set: CapSet, out: []u8) CapError![]const u8 {
    var len: usize = 0;
    for (registry.specs) |spec| {
        if (!set.contains(spec.id)) continue;

        const extra_space: usize = if (len == 0) 0 else 1;
        if (len + extra_space + spec.name.len > out.len) return error.OutputTooSmall;
        if (len != 0) {
            out[len] = ' ';
            len += 1;
        }
        @memcpy(out[len .. len + spec.name.len], spec.name);
        len += spec.name.len;
    }
    return out[0..len];
}

fn writeToken(spec: CapSpec, cap_302: bool, out: []u8) CapError![]const u8 {
    const value = if (cap_302) spec.value_302 else null;
    const value_len = if (value) |v| 1 + v.len else 0;
    if (spec.name.len + value_len > out.len) return error.OutputTooSmall;

    @memcpy(out[0..spec.name.len], spec.name);
    var len = spec.name.len;
    if (value) |v| {
        out[len] = '=';
        len += 1;
        @memcpy(out[len .. len + v.len], v);
        len += v.len;
    }
    return out[0..len];
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

test "LS lists advertised caps and CAP 302 values" {
    var replies: [8]CapReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = CapReplySink{ .replies = &replies, .storage = &storage };
    var session = CapSession{};

    try session.handleLs(CapRegistry.default(), true, MAX_CAP_REPLY_BODY, &sink);

    const out = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqual(CapReplyKind.ls, out[0].kind);
    try std.testing.expect(!out[0].continuation);
    try std.testing.expect(std.mem.indexOf(u8, out[0].body, "server-time") != null);
    try std.testing.expect(std.mem.indexOf(u8, out[0].body, "message-tags") != null);
    try std.testing.expect(std.mem.indexOf(u8, out[0].body, "sts=duration=604800") != null);
    try std.testing.expect(std.mem.indexOf(u8, out[0].body, "sasl=PLAIN,EXTERNAL") != null);
    try std.testing.expect(session.registrationHeld());
}

test "LS chunks advertised caps when body limit is exceeded" {
    var replies: [16]CapReply = undefined;
    var storage: [1024]u8 = undefined;
    var sink = CapReplySink{ .replies = &replies, .storage = &storage };
    var session = CapSession{};

    try session.handleLs(CapRegistry.default(), true, 40, &sink);

    const out = sink.slice();
    try std.testing.expect(out.len > 1);
    var index: usize = 0;
    while (index + 1 < out.len) : (index += 1) {
        try std.testing.expectEqual(CapReplyKind.ls, out[index].kind);
        try std.testing.expect(out[index].continuation);
        try std.testing.expect(out[index].body.len <= 40);
    }
    try std.testing.expectEqual(CapReplyKind.ls, out[out.len - 1].kind);
    try std.testing.expect(!out[out.len - 1].continuation);
    try std.testing.expect(out[out.len - 1].body.len <= 40);
}

test "REQ of a known set ACKs and sets bits" {
    var replies: [4]CapReply = undefined;
    var storage: [256]u8 = undefined;
    var sink = CapReplySink{ .replies = &replies, .storage = &storage };
    var session = CapSession{};

    try session.handleReq(CapRegistry.default(), "server-time message-tags sasl", &sink);

    const out = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqual(CapReplyKind.ack, out[0].kind);
    try std.testing.expectEqualStrings("server-time message-tags sasl", out[0].body);
    try std.testing.expect(session.negotiated.contains(.server_time));
    try std.testing.expect(session.negotiated.contains(.message_tags));
    try std.testing.expect(session.negotiated.contains(.sasl));
}

test "REQ containing unknown cap NAKs whole set without partial mutation" {
    var replies: [4]CapReply = undefined;
    var storage: [256]u8 = undefined;
    var sink = CapReplySink{ .replies = &replies, .storage = &storage };
    var session = CapSession{};

    try session.handleReq(CapRegistry.default(), "server-time unknown-cap sasl", &sink);

    const out = sink.slice();
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqual(CapReplyKind.nak, out[0].kind);
    try std.testing.expectEqualStrings("server-time unknown-cap sasl", out[0].body);
    try std.testing.expect(!session.negotiated.contains(.server_time));
    try std.testing.expect(!session.negotiated.contains(.sasl));
}

test "END completes negotiation and releases registration gate" {
    var session = CapSession{};
    session.state = .negotiating;

    try std.testing.expect(session.registrationHeld());
    session.handleEnd();
    try std.testing.expectEqual(CapState.complete, session.state);
    try std.testing.expect(!session.registrationHeld());
}

test "tag gating returns false for un-negotiated caps" {
    var caps = CapSet.empty();

    try std.testing.expect(!maySendTag(caps, "time"));
    try std.testing.expect(!maySendTag(caps, "server-time"));

    caps.add(.server_time);
    try std.testing.expect(maySendTag(caps, "time"));
    try std.testing.expect(maySendTag(caps, "server-time"));
    try std.testing.expect(!maySendTag(caps, "account"));
    try std.testing.expect(!maySendTag(caps, "unknown/vendor-tag"));
}
