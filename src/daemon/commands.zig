// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core IRC channel and message command handlers.
//!
//! `zig test src/daemon/commands.zig` makes `src/daemon` the module root, so
//! this file keeps the small protocol/state surface it needs local while using
//! the real client table in `client.zig`. The local state shape mirrors the
//! committed UNDERTOW NetworkState API used by these handlers.
const std = @import("std");
const client_model = @import("client.zig");

const server_name = "onyx.local";

pub const ClientId = client_model.ClientId;
pub const Client = client_model.Client;
pub const ClientTable = client_model.Table(Client, ClientId);

pub const Numeric = enum(u16) {
    RPL_CHANNELMODEIS = 324,
    RPL_NOTOPIC = 331,
    RPL_TOPIC = 332,
    RPL_TOPICWHOTIME = 333,
    RPL_NAMREPLY = 353,
    RPL_ENDOFNAMES = 366,
    ERR_NOSUCHNICK = 401,
    ERR_NOSUCHCHANNEL = 403,
    ERR_USERNOTINCHANNEL = 441,
    ERR_NOTONCHANNEL = 442,
    ERR_NEEDMOREPARAMS = 461,
    ERR_CHANOPRIVSNEEDED = 482,
};

pub fn formatCode(n: Numeric, buf: []u8) []const u8 {
    const value: u16 = @backingInt(n);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

fn InlineString(comptime max_len: usize) type {
    return struct {
        bytes: [max_len]u8 = @splat(0),
        len: u16 = 0,

        fn init(input: []const u8) !@This() {
            if (input.len > max_len) return error.StringTooLong;
            var out = @This(){};
            if (input.len != 0) @memcpy(out.bytes[0..input.len], input);
            out.len = @intCast(input.len);
            return out;
        }

        fn initLower(input: []const u8) !@This() {
            var out = try @This().init(input);
            for (out.bytes[0..out.len]) |*byte| {
                if (byte.* >= 'A' and byte.* <= 'Z') byte.* += 'a' - 'A';
            }
            return out;
        }

        fn asSlice(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }

        fn eql(a: @This(), b: @This()) bool {
            return a.len == b.len and std.mem.eql(u8, a.asSlice(), b.asSlice());
        }
    };
}

pub const Hlc = packed struct {
    wall_ms: u48 = 0,
    logical: u16 = 0,

    fn init(wall_ms: u64, logical: u16) !Hlc {
        if (wall_ms > std.math.maxInt(u48)) return error.WallTimeOutOfRange;
        return .{ .wall_ms = @intCast(wall_ms), .logical = logical };
    }
};

pub const Uid = InlineString(32);
pub const ChannelName = InlineString(64);
pub const TopicText = InlineString(390);
pub const Authority = u16;

pub const MembershipKey = struct {
    channel: ChannelName,
    uid: Uid,
    session: u64,
};

pub const PrefixModeKey = struct {
    channel: ChannelName,
    uid: Uid,
    mode: u8,
};

pub const BooleanModeKey = struct {
    channel: ChannelName,
    mode: u8,
};

pub const TopicValue = struct {
    text: TopicText,
    setter: Uid,
    hlc: Hlc,
};

const ChannelRoot = struct {
    name: ChannelName,
    birth_hlc: Hlc,
    authority: Authority,
};

const MembershipSet = struct {
    const Entry = struct { value: MembershipKey };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    fn init(allocator: std.mem.Allocator) MembershipSet {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *MembershipSet) void {
        self.entries.deinit(self.allocator);
    }

    fn contains(self: *const MembershipSet, value: MembershipKey) bool {
        for (self.entries.items) |entry| {
            if (std.meta.eql(entry.value, value)) return true;
        }
        return false;
    }

    fn add(self: *MembershipSet, value: MembershipKey) !void {
        if (!self.contains(value)) try self.entries.append(self.allocator, .{ .value = value });
    }

    fn remove(self: *MembershipSet, value: MembershipKey) !void {
        for (self.entries.items, 0..) |entry, idx| {
            if (std.meta.eql(entry.value, value)) {
                _ = self.entries.swapRemove(idx);
                return;
            }
        }
    }
};

const PrefixModeEntry = struct {
    key: PrefixModeKey,
    enabled: bool,
    authority: Authority,
    hlc: Hlc,
};

const BooleanModeEntry = struct {
    key: BooleanModeKey,
    enabled: bool,
    hlc: Hlc,
};

const TopicEntry = struct {
    channel: ChannelName,
    value: TopicValue,
};

/// Minimal UNDERTOW-style network state used by this command surface.
pub const NetworkState = struct {
    allocator: std.mem.Allocator,
    node_id: u64,
    channels: std.ArrayList(ChannelRoot) = .empty,
    memberships: MembershipSet,
    prefix_modes: std.ArrayList(PrefixModeEntry) = .empty,
    boolean_modes: std.ArrayList(BooleanModeEntry) = .empty,
    topics: std.ArrayList(TopicEntry) = .empty,

    pub fn init(allocator: std.mem.Allocator, _: u64, node_id: u64) NetworkState {
        return .{ .allocator = allocator, .node_id = node_id, .memberships = MembershipSet.init(allocator) };
    }

    pub fn deinit(self: *NetworkState) void {
        self.channels.deinit(self.allocator);
        self.memberships.deinit();
        self.prefix_modes.deinit(self.allocator);
        self.boolean_modes.deinit(self.allocator);
        self.topics.deinit(self.allocator);
    }

    pub fn createChannel(self: *NetworkState, name: ChannelName, birth_hlc: Hlc, authority: Authority) !void {
        for (self.channels.items) |*root| {
            if (!ChannelName.eql(root.name, name)) continue;
            if (birth_hlc.wall_ms < root.birth_hlc.wall_ms or
                (birth_hlc.wall_ms == root.birth_hlc.wall_ms and birth_hlc.logical < root.birth_hlc.logical))
            {
                root.birth_hlc = birth_hlc;
                root.authority = authority;
            }
            return;
        }
        try self.channels.append(self.allocator, .{ .name = name, .birth_hlc = birth_hlc, .authority = authority });
    }

    pub fn channelBirth(self: *const NetworkState, name: ChannelName) ?Hlc {
        for (self.channels.items) |root| if (ChannelName.eql(root.name, name)) return root.birth_hlc;
        return null;
    }

    pub fn join(self: *NetworkState, channel: ChannelName, uid: Uid, session: u64) !void {
        try self.memberships.add(.{ .channel = channel, .uid = uid, .session = session });
    }

    pub fn part(self: *NetworkState, channel: ChannelName, uid: Uid, session: u64) !void {
        try self.memberships.remove(.{ .channel = channel, .uid = uid, .session = session });
    }

    pub fn hasMember(self: *const NetworkState, channel: ChannelName, uid: Uid, session: u64) bool {
        return self.memberships.contains(.{ .channel = channel, .uid = uid, .session = session });
    }

    pub fn setPrefixMode(self: *NetworkState, key: PrefixModeKey, enabled: bool, authority: Authority, hlc: Hlc) !void {
        for (self.prefix_modes.items) |*entry| {
            if (!std.meta.eql(entry.key, key)) continue;
            if (authority > entry.authority or hlc.wall_ms > entry.hlc.wall_ms or
                (hlc.wall_ms == entry.hlc.wall_ms and hlc.logical >= entry.hlc.logical))
            {
                entry.enabled = enabled;
                entry.authority = authority;
                entry.hlc = hlc;
            }
            return;
        }
        try self.prefix_modes.append(self.allocator, .{ .key = key, .enabled = enabled, .authority = authority, .hlc = hlc });
    }

    pub fn setBooleanMode(self: *NetworkState, key: BooleanModeKey, enabled: bool, hlc: Hlc) !void {
        for (self.boolean_modes.items) |*entry| {
            if (!std.meta.eql(entry.key, key)) continue;
            entry.enabled = enabled;
            entry.hlc = hlc;
            return;
        }
        try self.boolean_modes.append(self.allocator, .{ .key = key, .enabled = enabled, .hlc = hlc });
    }

    pub fn setTopic(self: *NetworkState, channel: ChannelName, text: TopicText, setter: Uid, hlc: Hlc) !void {
        for (self.topics.items) |*entry| {
            if (!ChannelName.eql(entry.channel, channel)) continue;
            if (hlc.wall_ms > entry.value.hlc.wall_ms or
                (hlc.wall_ms == entry.value.hlc.wall_ms and hlc.logical >= entry.value.hlc.logical))
            {
                entry.value = .{ .text = text, .setter = setter, .hlc = hlc };
            }
            return;
        }
        try self.topics.append(self.allocator, .{ .channel = channel, .value = .{ .text = text, .setter = setter, .hlc = hlc } });
    }
};

pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, ClientId, []const u8) anyerror!void,
    };

    pub fn send(self: Sink, target: ClientId, text: []const u8) anyerror!void {
        try self.vtable.send(self.ptr, target, text);
    }
};

pub const DeltaKind = enum {
    channel_birth,
    membership_add,
    membership_remove,
    topic_set,
    prefix_mode_set,
    boolean_mode_set,
    client_quit,
};

pub const DeltaSet = struct {
    items: [16]DeltaKind = @splat(.channel_birth),
    len: usize = 0,

    fn add(self: *DeltaSet, kind: DeltaKind) void {
        if (self.len < self.items.len) {
            self.items[self.len] = kind;
            self.len += 1;
        }
    }
};

pub const CommandResult = struct { deltas: DeltaSet = .{} };

pub const CommandContext = struct {
    client_id: ClientId,
    command: []const u8,
    params: []const []const u8,
    scratch: []u8,
    network: *NetworkState,
    clients: *ClientTable,
    sink: Sink,
    wall_ms: u64 = 1,
    logical: u16 = 0,
    authority: Authority = 1,

    fn nextHlc(self: *CommandContext) !Hlc {
        if (self.logical == std.math.maxInt(u16)) return error.LogicalOverflow;
        self.logical += 1;
        return Hlc.init(self.wall_ms, self.logical);
    }

    fn selfClient(self: *CommandContext) ?*Client {
        return self.clients.get(self.client_id);
    }
};

pub fn handleJoin(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 1 or ctx.params[0].len == 0) return needMore(ctx, "JOIN");
    const chan = try channelName(ctx.params[0]);
    const uid = try currentUid(ctx);
    const session = sessionFor(ctx.client_id);
    var result = CommandResult{};
    const first_member = channelMemberCount(ctx.network, chan, ctx.clients) == 0;
    if (ctx.network.channelBirth(chan) == null) {
        try ctx.network.createChannel(chan, try ctx.nextHlc(), ctx.authority);
        result.deltas.add(.channel_birth);
    }
    if (!ctx.network.hasMember(chan, uid, session)) {
        try ctx.network.join(chan, uid, session);
        result.deltas.add(.membership_add);
    }
    if (first_member) {
        try ctx.network.setPrefixMode(.{ .channel = chan, .uid = uid, .mode = 'o' }, true, ctx.authority, try ctx.nextHlc());
        result.deltas.add(.prefix_mode_set);
    }
    try emitToChannel(ctx, chan, try line(ctx, ":{s} JOIN {s}\r\n", .{ prefixOf(ctx.selfClient().?), chan.asSlice() }), false);
    try emitNames(ctx, chan);
    return result;
}

pub fn handlePart(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 1) return needMore(ctx, "PART");
    const chan = try channelName(ctx.params[0]);
    if (!try requireMember(ctx, chan)) return .{};
    const uid = try currentUid(ctx);
    const part_line = if (ctx.params.len > 1)
        try line(ctx, ":{s} PART {s} :{s}\r\n", .{ prefixOf(ctx.selfClient().?), chan.asSlice(), ctx.params[1] })
    else
        try line(ctx, ":{s} PART {s}\r\n", .{ prefixOf(ctx.selfClient().?), chan.asSlice() });
    try emitToChannel(ctx, chan, part_line, false);
    try ctx.network.part(chan, uid, sessionFor(ctx.client_id));
    var result = CommandResult{};
    result.deltas.add(.membership_remove);
    return result;
}

pub fn handleKick(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 2) return needMore(ctx, "KICK");
    const chan = try channelName(ctx.params[0]);
    if (!try requireOperator(ctx, chan)) return .{};
    const target_id = findClientByNick(ctx.clients, ctx.params[1]) orelse {
        try nickErr(ctx, .ERR_NOSUCHNICK, ctx.params[1], "No such nick");
        return .{};
    };
    const target_uid = try uidOf(ctx.clients.get(target_id).?);
    if (!ctx.network.hasMember(chan, target_uid, sessionFor(target_id))) {
        try numericReply(ctx, .ERR_USERNOTINCHANNEL, "{s} {s} :They aren't on that channel", .{ ctx.params[1], chan.asSlice() });
        return .{};
    }
    const reason = if (ctx.params.len > 2) ctx.params[2] else ctx.params[1];
    try emitToChannel(ctx, chan, try line(ctx, ":{s} KICK {s} {s} :{s}\r\n", .{ prefixOf(ctx.selfClient().?), chan.asSlice(), nickOf(ctx.clients.get(target_id).?), reason }), false);
    try ctx.network.part(chan, target_uid, sessionFor(target_id));
    var result = CommandResult{};
    result.deltas.add(.membership_remove);
    return result;
}

pub fn handleTopic(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 1) return needMore(ctx, "TOPIC");
    const chan = try channelName(ctx.params[0]);
    if (!try requireMember(ctx, chan)) return .{};
    if (ctx.params.len == 1) {
        try topicNumerics(ctx, chan);
        return .{};
    }
    if (!isOp(ctx.network, chan, try currentUid(ctx))) {
        try chanErr(ctx, .ERR_CHANOPRIVSNEEDED, chan, "You're not channel operator");
        return .{};
    }
    try ctx.network.setTopic(chan, try TopicText.init(ctx.params[1]), try currentUid(ctx), try ctx.nextHlc());
    try emitToChannel(ctx, chan, try line(ctx, ":{s} TOPIC {s} :{s}\r\n", .{ prefixOf(ctx.selfClient().?), chan.asSlice(), ctx.params[1] }), false);
    var result = CommandResult{};
    result.deltas.add(.topic_set);
    return result;
}

pub fn handleNames(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 1) return needMore(ctx, "NAMES");
    const chan = try channelName(ctx.params[0]);
    if (ctx.network.channelBirth(chan) == null) {
        try chanErr(ctx, .ERR_NOSUCHCHANNEL, chan, "No such channel");
        return .{};
    }
    try emitNames(ctx, chan);
    return .{};
}

pub fn handleMode(ctx: *CommandContext) anyerror!CommandResult {
    if (ctx.params.len < 1) return needMore(ctx, "MODE");
    const chan = try channelName(ctx.params[0]);
    if (!try requireMember(ctx, chan)) return .{};
    if (ctx.params.len == 1) {
        try channelModes(ctx, chan);
        return .{};
    }
    if (!isOp(ctx.network, chan, try currentUid(ctx))) {
        try chanErr(ctx, .ERR_CHANOPRIVSNEEDED, chan, "You're not channel operator");
        return .{};
    }
    var result = CommandResult{};
    var adding = true;
    var param_index: usize = 2;
    for (ctx.params[1]) |mode| switch (mode) {
        '+' => adding = true,
        '-' => adding = false,
        'o', 'v' => {
            if (param_index >= ctx.params.len) return needMore(ctx, "MODE");
            const target_id = findClientByNick(ctx.clients, ctx.params[param_index]) orelse {
                try nickErr(ctx, .ERR_NOSUCHNICK, ctx.params[param_index], "No such nick");
                return .{};
            };
            param_index += 1;
            const target_uid = try uidOf(ctx.clients.get(target_id).?);
            if (!ctx.network.hasMember(chan, target_uid, sessionFor(target_id))) {
                try numericReply(ctx, .ERR_USERNOTINCHANNEL, "{s} {s} :They aren't on that channel", .{ nickOf(ctx.clients.get(target_id).?), chan.asSlice() });
                return .{};
            }
            try ctx.network.setPrefixMode(.{ .channel = chan, .uid = target_uid, .mode = mode }, adding, ctx.authority, try ctx.nextHlc());
            result.deltas.add(.prefix_mode_set);
        },
        else => {
            try ctx.network.setBooleanMode(.{ .channel = chan, .mode = mode }, adding, try ctx.nextHlc());
            result.deltas.add(.boolean_mode_set);
        },
    };
    try emitToChannel(ctx, chan, try modeLine(ctx, chan, ctx.params[1], ctx.params[2..param_index]), false);
    return result;
}

pub fn handlePrivmsg(ctx: *CommandContext) anyerror!CommandResult {
    return message(ctx, "PRIVMSG", true);
}

pub fn handleNotice(ctx: *CommandContext) anyerror!CommandResult {
    return message(ctx, "NOTICE", true);
}

pub fn handleTagmsg(ctx: *CommandContext) anyerror!CommandResult {
    return message(ctx, "TAGMSG", false);
}

pub fn handleQuit(ctx: *CommandContext) anyerror!CommandResult {
    const uid = try currentUid(ctx);
    const session = sessionFor(ctx.client_id);
    const reason = if (ctx.params.len > 0) ctx.params[0] else "Client quit";
    const quit_line = try line(ctx, ":{s} QUIT :{s}\r\n", .{ prefixOf(ctx.selfClient().?), reason });
    while (findMembership(ctx.network, uid, session)) |member| {
        try emitToChannel(ctx, member.channel, quit_line, true);
        try ctx.network.part(member.channel, uid, session);
    }
    _ = ctx.clients.free(ctx.client_id);
    var result = CommandResult{};
    result.deltas.add(.client_quit);
    return result;
}

fn message(ctx: *CommandContext, name: []const u8, comptime needs_text: bool) anyerror!CommandResult {
    if (ctx.params.len < if (needs_text) 2 else 1) return needMore(ctx, name);
    if (isChannel(ctx.params[0])) {
        const chan = try channelName(ctx.params[0]);
        if (!try requireMember(ctx, chan)) return .{};
        const text = if (needs_text)
            try line(ctx, ":{s} {s} {s} :{s}\r\n", .{ prefixOf(ctx.selfClient().?), name, chan.asSlice(), ctx.params[1] })
        else
            try line(ctx, ":{s} {s} {s}\r\n", .{ prefixOf(ctx.selfClient().?), name, chan.asSlice() });
        try emitToChannel(ctx, chan, text, true);
        return .{};
    }
    const target = findClientByNick(ctx.clients, ctx.params[0]) orelse {
        try nickErr(ctx, .ERR_NOSUCHNICK, ctx.params[0], "No such nick");
        return .{};
    };
    const text = if (needs_text)
        try line(ctx, ":{s} {s} {s} :{s}\r\n", .{ prefixOf(ctx.selfClient().?), name, nickOf(ctx.clients.get(target).?), ctx.params[1] })
    else
        try line(ctx, ":{s} {s} {s}\r\n", .{ prefixOf(ctx.selfClient().?), name, nickOf(ctx.clients.get(target).?) });
    try ctx.sink.send(target, text);
    return .{};
}

fn needMore(ctx: *CommandContext, name: []const u8) anyerror!CommandResult {
    try numericReply(ctx, .ERR_NEEDMOREPARAMS, "{s} :Not enough parameters", .{name});
    return .{};
}

fn requireMember(ctx: *CommandContext, chan: ChannelName) !bool {
    if (ctx.network.channelBirth(chan) == null) {
        try chanErr(ctx, .ERR_NOSUCHCHANNEL, chan, "No such channel");
        return false;
    }
    const uid = try currentUid(ctx);
    if (!ctx.network.hasMember(chan, uid, sessionFor(ctx.client_id))) {
        try chanErr(ctx, .ERR_NOTONCHANNEL, chan, "You're not on that channel");
        return false;
    }
    return true;
}

fn requireOperator(ctx: *CommandContext, chan: ChannelName) !bool {
    if (!try requireMember(ctx, chan)) return false;
    if (!isOp(ctx.network, chan, try currentUid(ctx))) {
        try chanErr(ctx, .ERR_CHANOPRIVSNEEDED, chan, "You're not channel operator");
        return false;
    }
    return true;
}

fn numericReply(ctx: *CommandContext, code: Numeric, comptime fmt: []const u8, args: anytype) !void {
    var code_buf: [3]u8 = undefined;
    var writer = std.Io.Writer.fixed(ctx.scratch);
    try writer.print(":{s} {s} {s} ", .{ server_name, formatCode(code, &code_buf), replyNick(ctx) });
    try writer.print(fmt, args);
    try writer.writeAll("\r\n");
    try ctx.sink.send(ctx.client_id, writer.buffered());
}

fn chanErr(ctx: *CommandContext, code: Numeric, chan: ChannelName, text: []const u8) !void {
    try numericReply(ctx, code, "{s} :{s}", .{ chan.asSlice(), text });
}

fn nickErr(ctx: *CommandContext, code: Numeric, nick: []const u8, text: []const u8) !void {
    try numericReply(ctx, code, "{s} :{s}", .{ nick, text });
}

fn emitNames(ctx: *CommandContext, chan: ChannelName) !void {
    var writer = std.Io.Writer.fixed(ctx.scratch);
    var code_buf: [3]u8 = undefined;
    try writer.print(":{s} {s} {s} = {s} :", .{ server_name, formatCode(.RPL_NAMREPLY, &code_buf), replyNick(ctx), chan.asSlice() });
    var first = true;
    for (ctx.network.memberships.entries.items) |entry| {
        const member = entry.value;
        if (!ChannelName.eql(member.channel, chan)) continue;
        const id = findClientByUidSession(ctx.clients, member.uid, member.session) orelse continue;
        if (!first) try writer.writeByte(' ');
        first = false;
        if (isOp(ctx.network, chan, member.uid)) try writer.writeByte('@') else if (hasPrefix(ctx.network, chan, member.uid, 'v')) try writer.writeByte('+');
        try writer.writeAll(nickOf(ctx.clients.get(id).?));
    }
    try writer.writeAll("\r\n");
    try ctx.sink.send(ctx.client_id, writer.buffered());
    try numericReply(ctx, .RPL_ENDOFNAMES, "{s} :End of /NAMES list", .{chan.asSlice()});
}

fn topicNumerics(ctx: *CommandContext, chan: ChannelName) !void {
    for (ctx.network.topics.items) |topic| {
        if (!ChannelName.eql(topic.channel, chan)) continue;
        try numericReply(ctx, .RPL_TOPIC, "{s} :{s}", .{ chan.asSlice(), topic.value.text.asSlice() });
        try numericReply(ctx, .RPL_TOPICWHOTIME, "{s} {s} {d}", .{ chan.asSlice(), setterName(ctx, topic.value.setter), topic.value.hlc.wall_ms });
        return;
    }
    try numericReply(ctx, .RPL_NOTOPIC, "{s} :No topic is set", .{chan.asSlice()});
}

fn channelModes(ctx: *CommandContext, chan: ChannelName) !void {
    var writer = std.Io.Writer.fixed(ctx.scratch);
    var code_buf: [3]u8 = undefined;
    try writer.print(":{s} {s} {s} {s} +", .{ server_name, formatCode(.RPL_CHANNELMODEIS, &code_buf), replyNick(ctx), chan.asSlice() });
    for (ctx.network.boolean_modes.items) |entry| if (ChannelName.eql(entry.key.channel, chan) and entry.enabled) try writer.writeByte(entry.key.mode);
    try writer.writeAll("\r\n");
    try ctx.sink.send(ctx.client_id, writer.buffered());
}

fn emitToChannel(ctx: *CommandContext, chan: ChannelName, text: []const u8, skip_sender: bool) !void {
    for (ctx.network.memberships.entries.items) |entry| {
        const member = entry.value;
        if (!ChannelName.eql(member.channel, chan)) continue;
        const id = findClientByUidSession(ctx.clients, member.uid, member.session) orelse continue;
        if (skip_sender and id.eql(ctx.client_id)) continue;
        try ctx.sink.send(id, text);
    }
}

fn line(ctx: *CommandContext, comptime fmt: []const u8, args: anytype) ![]const u8 {
    return std.fmt.bufPrint(ctx.scratch, fmt, args);
}

fn modeLine(ctx: *CommandContext, chan: ChannelName, modes: []const u8, args: []const []const u8) ![]const u8 {
    var writer = std.Io.Writer.fixed(ctx.scratch);
    try writer.print(":{s} MODE {s} {s}", .{ prefixOf(ctx.selfClient().?), chan.asSlice(), modes });
    for (args) |arg| try writer.print(" {s}", .{arg});
    try writer.writeAll("\r\n");
    return writer.buffered();
}

fn channelName(name: []const u8) !ChannelName {
    if (!isChannel(name)) return error.BadChannelName;
    return ChannelName.initLower(name);
}

fn isChannel(name: []const u8) bool {
    return name.len != 0 and (name[0] == '#' or name[0] == '&');
}

fn currentUid(ctx: *CommandContext) !Uid {
    return uidOf(ctx.selfClient() orelse return error.UnknownClient);
}

fn uidOf(client: *const Client) !Uid {
    return Uid.init(client.identity.uid.slice());
}

fn nickOf(client: *const Client) []const u8 {
    return client.identity.nick.slice();
}

fn replyNick(ctx: *CommandContext) []const u8 {
    const self = ctx.selfClient() orelse return "*";
    const nick = nickOf(self);
    return if (nick.len == 0) "*" else nick;
}

fn prefixOf(client: *const Client) []const u8 {
    return nickOf(client);
}

fn sessionFor(id: ClientId) u64 {
    return (@as(u64, id.shard) << 52) | (@as(u64, id.slot) << 32) | @as(u64, id.gen);
}

fn findClientByNick(clients: *ClientTable, nick: []const u8) ?ClientId {
    for (clients.slots.items, 0..) |slot, idx| {
        if (slot.occupied and std.ascii.eqlIgnoreCase(slot.value.identity.nick.slice(), nick)) {
            return .{ .shard = clients.shard, .slot = @intCast(idx), .gen = slot.gen };
        }
    }
    return null;
}

fn findClientByUidSession(clients: *ClientTable, uid: Uid, session: u64) ?ClientId {
    for (clients.slots.items, 0..) |slot, idx| {
        if (!slot.occupied) continue;
        const id = ClientId{ .shard = clients.shard, .slot = @intCast(idx), .gen = slot.gen };
        if (sessionFor(id) == session and std.mem.eql(u8, slot.value.identity.uid.slice(), uid.asSlice())) return id;
    }
    return null;
}

fn findMembership(network: *NetworkState, uid: Uid, session: u64) ?MembershipKey {
    for (network.memberships.entries.items) |entry| {
        if (Uid.eql(entry.value.uid, uid) and entry.value.session == session) return entry.value;
    }
    return null;
}

fn hasPrefix(network: *NetworkState, chan: ChannelName, uid: Uid, mode: u8) bool {
    for (network.prefix_modes.items) |entry| {
        if (ChannelName.eql(entry.key.channel, chan) and Uid.eql(entry.key.uid, uid) and entry.key.mode == mode) return entry.enabled;
    }
    return false;
}

fn isOp(network: *NetworkState, chan: ChannelName, uid: Uid) bool {
    return hasPrefix(network, chan, uid, 'o');
}

fn channelMemberCount(network: *NetworkState, chan: ChannelName, clients: *ClientTable) usize {
    var count: usize = 0;
    for (network.memberships.entries.items) |entry| {
        if (ChannelName.eql(entry.value.channel, chan) and findClientByUidSession(clients, entry.value.uid, entry.value.session) != null) count += 1;
    }
    return count;
}

fn setterName(ctx: *CommandContext, uid: Uid) []const u8 {
    for (ctx.clients.slots.items) |slot| {
        if (slot.occupied and std.mem.eql(u8, slot.value.identity.uid.slice(), uid.asSlice())) return slot.value.identity.nick.slice();
    }
    return uid.asSlice();
}

const Capture = struct {
    allocator: std.mem.Allocator,
    lines: std.ArrayList(Line) = .empty,
    const Line = struct { target: ClientId, text: []u8 };

    fn init(allocator: std.mem.Allocator) Capture {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *Capture) void {
        self.clear();
        self.lines.deinit(self.allocator);
    }

    fn sink(self: *Capture) Sink {
        return .{ .ptr = self, .vtable = &.{ .send = send } };
    }

    fn send(ptr: *anyopaque, target: ClientId, text: []const u8) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ptr));
        try self.lines.append(self.allocator, .{ .target = target, .text = try self.allocator.dupe(u8, text) });
    }

    fn contains(self: *const Capture, target: ClientId, needle: []const u8) bool {
        for (self.lines.items) |item| if (item.target.eql(target) and std.mem.indexOf(u8, item.text, needle) != null) return true;
        return false;
    }

    fn clear(self: *Capture) void {
        for (self.lines.items) |item| self.allocator.free(item.text);
        self.lines.clearRetainingCapacity();
    }
};

fn addClient(clients: *ClientTable, nick: []const u8, uid: []const u8) !ClientId {
    return clients.alloc(try Client.init(.{ .nick = nick, .uid = uid, .realname = nick, .visible_host = "host", .cloaked_host = "cloak" }));
}

fn makeCtx(network: *NetworkState, clients: *ClientTable, sink: Sink, scratch: []u8, id: ClientId, params: []const []const u8) CommandContext {
    return .{ .client_id = id, .command = "", .params = params, .scratch = scratch, .network = network, .clients = clients, .sink = sink };
}

test "join names privmsg part mode and errors" {
    const allocator = std.testing.allocator;
    var network = NetworkState.init(allocator, 1, 1);
    defer network.deinit();
    var clients = ClientTable.init(allocator, 1);
    defer clients.deinit();
    var capture = Capture.init(allocator);
    defer capture.deinit();
    var scratch: [4096]u8 = undefined;
    const alice = try addClient(&clients, "alice", "001ALICE");
    const bob = try addClient(&clients, "bob", "002BOB");

    var missing = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{});
    _ = try handleJoin(&missing);
    try std.testing.expect(capture.contains(alice, " 461 alice JOIN :Not enough parameters"));
    capture.clear();

    var join_a = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{"#onyx"});
    _ = try handleJoin(&join_a);
    var join_b = makeCtx(&network, &clients, capture.sink(), &scratch, bob, &.{"#onyx"});
    _ = try handleJoin(&join_b);
    var names = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{"#onyx"});
    _ = try handleNames(&names);
    try std.testing.expect(capture.contains(alice, " 353 alice = #onyx :@alice bob"));
    try std.testing.expect(capture.contains(alice, " 366 alice #onyx :End of /NAMES list"));

    capture.clear();
    var msg = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{ "#onyx", "hello bob" });
    _ = try handlePrivmsg(&msg);
    try std.testing.expect(capture.contains(bob, ":alice PRIVMSG #onyx :hello bob"));
    try std.testing.expect(!capture.contains(alice, ":alice PRIVMSG #onyx :hello bob"));

    var mode = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{ "#onyx", "+o", "bob" });
    _ = try handleMode(&mode);
    try std.testing.expect(isOp(&network, try ChannelName.initLower("#onyx"), try Uid.init("002BOB")));

    var part = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{"#onyx"});
    _ = try handlePart(&part);
    try std.testing.expect(!network.hasMember(try ChannelName.initLower("#onyx"), try Uid.init("001ALICE"), sessionFor(alice)));

    capture.clear();
    var not_on = makeCtx(&network, &clients, capture.sink(), &scratch, alice, &.{"#onyx"});
    _ = try handlePart(&not_on);
    try std.testing.expect(capture.contains(alice, " 442 alice #onyx :You're not on that channel"));
}
