// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX PROP request parsing and reply rendering.

const std = @import("std");
const irc_line = @import("../irc_line.zig");
const model = @import("model.zig");

pub fn parseLine(line: []const u8) model.PropError!model.Request {
    return parseLineBounded(.{}, line);
}

pub fn parseLineBounded(comptime params: model.Params, line: []const u8) model.PropError!model.Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "PROP")) return error.InvalidCommand;
    return parseParamsBounded(params, parsed.paramSlice(), parsed.trailing != null);
}

pub fn parseParamsBounded(comptime params: model.Params, params_slice: []const []const u8, had_trailing: bool) model.PropError!model.Request {
    if (params_slice.len == 0) return error.NeedMoreParams;
    if (params_slice.len > 4) return error.TooManyParams;

    const entity = try model.Entity.fromId(params_slice[0]);
    try model.validateEntity(entity, params.max_entity_id);

    if (params_slice.len == 1) return .{ .list = entity };

    if (std.ascii.eqlIgnoreCase(params_slice[1], "CLEAR")) {
        if (params_slice.len != 2) return error.TooManyParams;
        return .{ .delete = .{ .entity = entity, .key = "" } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "GET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        if (params_slice.len > 3) return error.TooManyParams;
        const keys = params_slice[2];
        try model.validateKeyList(keys, params.max_key, params.max_request_keys);
        return .{ .get = .{ .entity = entity, .keys = keys } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "SET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        const key = params_slice[2];
        try model.validateKeyWithLimit(key, params.max_key);
        if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;
        if (params_slice.len == 3) return .{ .delete = .{ .entity = entity, .key = key } };

        const value = params_slice[3];
        if (had_trailing and value.len == 0) {
            return .{ .delete = .{ .entity = entity, .key = key } };
        }

        try model.validateValue(value, params.max_value);
        return .{ .set = .{ .entity = entity, .key = key, .value = value } };
    }

    if (params_slice.len > 3) return error.TooManyParams;

    const key = params_slice[1];
    try model.validateKeyList(key, params.max_key, params.max_request_keys);

    if (params_slice.len == 2) return .{ .get = .{ .entity = entity, .keys = key } };
    if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;

    const value = params_slice[2];
    if (had_trailing and value.len == 0) {
        return .{ .delete = .{ .entity = entity, .key = key } };
    }

    try model.validateValue(value, params.max_value);
    return .{ .set = .{ .entity = entity, .key = key, .value = value } };
}

pub fn buildPropMessage(entity: model.Entity, key: []const u8, value: []const u8, out: []u8) model.PropError![]const u8 {
    try model.validateEntity(entity, model.default_max_entity_id);
    try model.validateKeyWithLimit(key, model.default_max_key);
    try model.validateValue(value, model.default_max_value);
    return std.fmt.bufPrint(out, "PROP {s} {s} :{s}", .{ entity.id, key, value }) catch error.OutputTooSmall;
}

pub fn buildPropListReply(server: []const u8, nick: []const u8, entry: model.EntryView, out: []u8) model.PropError![]const u8 {
    try model.validateReplyAtom(server);
    try model.validateReplyAtom(nick);
    return std.fmt.bufPrint(out, ":{s} 818 {s} {s} {s} :{s}", .{
        server,
        nick,
        entry.entity.id,
        entry.key,
        entry.value,
    }) catch error.OutputTooSmall;
}

pub fn buildPropEndReply(server: []const u8, nick: []const u8, entity: model.Entity, out: []u8) model.PropError![]const u8 {
    try model.validateReplyAtom(server);
    try model.validateReplyAtom(nick);
    try model.validateEntity(entity, model.default_max_entity_id);
    return std.fmt.bufPrint(out, ":{s} 819 {s} {s} :End of properties", .{ server, nick, entity.id }) catch error.OutputTooSmall;
}
