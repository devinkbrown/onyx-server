// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX LISTX parsing, filtering, and numeric reply builders.
//!
//! LISTX is the extended channel list command. This module is deliberately
//! allocator-free: filter text is borrowed from command parameters, parsed
//! filters are written into caller-owned storage, and numeric replies are
//! emitted into caller-owned line buffers.
const std = @import("std");
const numeric = @import("numeric.zig");
const limits_config = @import("limits_config.zig");

pub const RPL_LISTXSTART: u16 = 811;
pub const RPL_LISTXENTRY: u16 = 812;
pub const RPL_LISTXPICS: u16 = 813;
pub const RPL_LISTXTRUNC: u16 = 816;
pub const RPL_LISTXEND: u16 = 817;

pub const DEFAULT_MAX_FILTERS: usize = 16;
pub const DEFAULT_MAX_FILTER_BYTES: usize = 512;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_NAME_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_TOPIC_BYTES: usize = 512;
pub const DEFAULT_MAX_PICS_BYTES: usize = 255;

pub const ListxError = error{
    InvalidParameter,
    InvalidFilter,
    InvalidMask,
    InvalidValue,
    InvalidServerName,
    InvalidRequester,
    InvalidChannelName,
    InvalidTopic,
    FilterTooLong,
    MaskTooLong,
    LineTooLong,
    OutputTooSmall,
    TooManyFilters,
};

/// Compile-time parser and builder limits.
pub const Params = struct {
    max_filters: usize = DEFAULT_MAX_FILTERS,
    max_filter_bytes: usize = DEFAULT_MAX_FILTER_BYTES,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_NAME_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_topic_bytes: usize = DEFAULT_MAX_TOPIC_BYTES,
    max_pics_bytes: usize = DEFAULT_MAX_PICS_BYTES,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_line_bytes` and `max_filter_bytes` are wire budgets and keep their
    /// defaults.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_filters = limits.list_max_filters,
            .max_mask_bytes = limits.list_mask_len,
            .max_server_bytes = limits.server_name_len,
            .max_requester_bytes = limits.nick_len,
            .max_channel_bytes = limits.target_len_128,
            .max_topic_bytes = limits.topic_len,
        };
    }
};

/// Threshold comparison used by LISTX numeric filters. Bare `>`/`<` are strict;
/// a trailing `=` makes the comparison inclusive (`>=`/`<=`) so "at least N" is
/// directly expressible. All three numeric filters — member-count, creation-age
/// (`C`), and topic-age (`T`) — share this one operator grammar.
pub const Comparison = enum {
    greater_than,
    less_than,
    greater_equal,
    less_equal,

    fn testValue(self: Comparison, actual: u64, threshold: u64) bool {
        return switch (self) {
            .greater_than => actual > threshold,
            .less_than => actual < threshold,
            .greater_equal => actual >= threshold,
            .less_equal => actual <= threshold,
        };
    }
};

/// One typed LISTX filter.
pub const Filter = struct {
    criterion: Criterion,

    pub const Threshold = struct {
        comparison: Comparison,
        value: u64,
    };

    pub const Criterion = union(enum) {
        member_count: Threshold,
        creation_age_ms: Threshold,
        topic_age_ms: Threshold,
        topic_only,
        channel_mask: []const u8,
        /// `N=<mask>` — channel-name mask (synonym surface to a bare `#mask`).
        name_mask: []const u8,
        /// `T=<mask>` — topic-text mask.
        topic_mask: []const u8,
        /// `S=<mask>` — subject-text mask.
        subject_mask: []const u8,
        /// `L=<mask>` — language-tag mask.
        language_mask: []const u8,
        /// `R=0` / `R=1` — unregistered / registered channel filter.
        registered: bool,
    };
};

/// Parsed LISTX request backed by a fixed-size inline filter array.
pub fn RequestType(comptime max_filters: usize) type {
    if (max_filters == 0) @compileError("LISTX request needs at least one filter slot");

    return struct {
        const Self = @This();

        filters: [max_filters]Filter = undefined,
        count: usize = 0,
        /// Draft query limit. Null means the client asked for the server cap
        /// (the parameter was absent, or it was `0`).
        query_limit: ?u32 = null,

        pub fn slice(self: *const Self) []const Filter {
            return self.filters[0..self.count];
        }

        pub fn matches(self: *const Self, channel: ChannelInfo, now_ms: u64) bool {
            return matchesFilters(self.slice(), channel, now_ms);
        }

        fn append(self: *Self, filter: Filter) ListxError!void {
            if (self.count >= self.filters.len) return error.TooManyFilters;
            self.filters[self.count] = filter;
            self.count += 1;
        }
    };
}

pub const Request = RequestType(DEFAULT_MAX_FILTERS);

/// Channel data needed by LISTX matching and entry emission.
pub const ChannelInfo = struct {
    name: []const u8,
    members: u64,
    topic: []const u8 = "",
    created_ms: u64,
    topic_ms: ?u64 = null,
    /// Channel subject text used by the `S=` filter.
    subject: []const u8 = "",
    /// Channel language tag used by the `L=` filter.
    language: []const u8 = "",
    /// Channel registration state used by the `R=` filter.
    registered: bool = false,
};

/// Reply-level data shared by LISTX numerics.
pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// Parse tokenized LISTX parameters into the default request size.
pub fn parse(params: []const []const u8) ListxError!Request {
    return parseWithMax(DEFAULT_MAX_FILTERS, params);
}

/// Parse tokenized LISTX parameters using a caller-selected max filter count.
pub fn parseWithMax(
    comptime max_filters: usize,
    params: []const []const u8,
) ListxError!RequestType(max_filters) {
    if (params.len > 2) return error.InvalidParameter;

    var request = RequestType(max_filters){};
    if (params.len == 2) request.query_limit = try parseQueryLimit(params[1]);
    if (params.len == 0 or params[0].len == 0) return request;

    try parseFilterTextWith(.{ .max_filters = max_filters }, params[0], &request);
    return request;
}

/// Parse the draft LISTX query limit. `0` is unlimited and returns null so the
/// caller keeps its own cap. A non-numeric token is `InvalidParameter` (a
/// filter that was split into a second argument). Overflow and leading zeros
/// are `InvalidValue`.
pub fn parseQueryLimit(token: []const u8) ListxError!?u32 {
    if (token.len == 0 or token.len > 10) return error.InvalidValue;
    for (token) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidParameter;
    }
    if (token.len > 1 and token[0] == '0') return error.InvalidValue;
    const value = std.fmt.parseInt(u32, token, 10) catch return error.InvalidValue;
    if (value == 0) return null;
    return value;
}

/// Smaller of the client's query limit and the server's hard cap.
pub fn resultCap(requested: ?u32, server_max: usize) usize {
    const asked = requested orelse return server_max;
    return @min(@as(usize, asked), server_max);
}

/// Parse one comma-separated LISTX filter parameter into caller-owned storage.
pub fn parseFilters(input: []const u8, out: []Filter) ListxError![]const Filter {
    return parseFiltersWith(.{}, input, out);
}

/// Parse one comma-separated LISTX filter parameter with caller-selected limits.
pub fn parseFiltersWith(comptime params: Params, input: []const u8, out: []Filter) ListxError![]const Filter {
    if (input.len == 0) return out[0..0];
    if (input.len > params.max_filter_bytes) return error.FilterTooLong;

    var count: usize = 0;
    var cursor: usize = 0;
    while (cursor <= input.len) {
        const next = findByte(input, cursor, ',') orelse input.len;
        if (count >= out.len or count >= params.max_filters) return error.TooManyFilters;
        out[count] = try parseFilterWith(params, input[cursor..next]);
        count += 1;
        if (next == input.len) break;
        cursor = next + 1;
    }

    return out[0..count];
}

fn parseFilterTextWith(comptime params: Params, input: []const u8, request: anytype) ListxError!void {
    if (input.len > params.max_filter_bytes) return error.FilterTooLong;

    var cursor: usize = 0;
    while (cursor <= input.len) {
        const next = findByte(input, cursor, ',') orelse input.len;
        try request.append(try parseFilterWith(params, input[cursor..next]));
        if (next == input.len) break;
        cursor = next + 1;
    }
}

/// Parse one LISTX filter token.
pub fn parseFilter(token: []const u8) ListxError!Filter {
    return parseFilterWith(.{}, token);
}

/// Parse one LISTX filter token with caller-selected limits.
pub fn parseFilterWith(comptime params: Params, token: []const u8) ListxError!Filter {
    if (token.len == 0) return error.InvalidFilter;
    if (token.len > params.max_filter_bytes) return error.FilterTooLong;
    try validateFilterBytes(token);

    if (token[0] == '>' or token[0] == '<') {
        // Member-count threshold. Detected before the generic `X=<mask>` branch
        // (which requires a leading letter), so there is no ambiguity.
        return .{ .criterion = .{ .member_count = try parseThreshold(token) } };
    }

    if (token.len >= 3 and asciiEqual(token[0], 'C')) {
        // `C>N` / `C<N` and inclusive `C>=N` / `C<=N` creation-age thresholds.
        return .{ .criterion = .{ .creation_age_ms = try parseThreshold(token[1..]) } };
    }

    if (asciiEql(token, "TOPICONLY")) {
        return .{ .criterion = .topic_only };
    }

    if (token.len >= 3 and asciiEqual(token[0], 'T') and (token[1] == '<' or token[1] == '>')) {
        // `T>N` / `T<N` and inclusive `T>=N` / `T<=N` topic-age thresholds. The
        // leading-operator guard keeps `T=<mask>` routed to the topic-text mask
        // branch below.
        return .{ .criterion = .{ .topic_age_ms = try parseThreshold(token[1..]) } };
    }

    // `R=0` / `R=1` registered filter.
    if (token.len == 3 and asciiEqual(token[0], 'R') and token[1] == '=') {
        return switch (token[2]) {
            '0' => .{ .criterion = .{ .registered = false } },
            '1' => .{ .criterion = .{ .registered = true } },
            else => error.InvalidValue,
        };
    }

    // `N=` / `T=` / `S=` / `L=` text-mask filters.
    if (token.len >= 2 and token[1] == '=') {
        const mask = token[2..];
        if (mask.len == 0) return error.InvalidMask;
        try validateTextMaskWith(params, mask);
        return switch (asciiLower(token[0])) {
            'n' => .{ .criterion = .{ .name_mask = mask } },
            't' => .{ .criterion = .{ .topic_mask = mask } },
            's' => .{ .criterion = .{ .subject_mask = mask } },
            'l' => .{ .criterion = .{ .language_mask = mask } },
            else => error.InvalidFilter,
        };
    }

    if (validChannelNamePrefix(token)) {
        try validateMaskWith(params, token);
        return .{ .criterion = .{ .channel_mask = token } };
    }

    return error.InvalidFilter;
}

/// Return true when `channel` satisfies every LISTX filter.
pub fn matchesFilters(filters: []const Filter, channel: ChannelInfo, now_ms: u64) bool {
    var has_mask = false;
    var matched_mask = false;

    for (filters) |filter| {
        switch (filter.criterion) {
            .member_count => |threshold| {
                if (!threshold.comparison.testValue(channel.members, threshold.value)) return false;
            },
            .creation_age_ms => |threshold| {
                const age_ms = elapsedMs(now_ms, channel.created_ms);
                if (!threshold.comparison.testValue(age_ms, threshold.value)) return false;
            },
            .topic_age_ms => |threshold| {
                if (channel.topic.len == 0) return false;
                const topic_ms = channel.topic_ms orelse return false;
                const age_ms = elapsedMs(now_ms, topic_ms);
                if (!threshold.comparison.testValue(age_ms, threshold.value)) return false;
            },
            .topic_only => {
                if (channel.topic.len == 0) return false;
            },
            .channel_mask => |mask| {
                has_mask = true;
                matched_mask = matched_mask or globMatch(mask, channel.name);
            },
            .name_mask => |mask| {
                has_mask = true;
                matched_mask = matched_mask or globMatch(mask, channel.name);
            },
            .topic_mask => |mask| {
                if (!globMatch(mask, channel.topic)) return false;
            },
            .subject_mask => |mask| {
                if (!globMatch(mask, channel.subject)) return false;
            },
            .language_mask => |mask| {
                if (!globMatch(mask, channel.language)) return false;
            },
            .registered => |want| {
                if (channel.registered != want) return false;
            },
        }
    }

    return !has_mask or matched_mask;
}

/// Case-insensitive ASCII glob matcher for channel masks.
pub fn globMatch(mask: []const u8, text: []const u8) bool {
    var mask_i: usize = 0;
    var text_i: usize = 0;
    var star_i: ?usize = null;
    var retry_text_i: usize = 0;

    while (text_i < text.len) {
        if (mask_i < mask.len and (mask[mask_i] == '?' or asciiEqual(mask[mask_i], text[text_i]))) {
            mask_i += 1;
            text_i += 1;
        } else if (mask_i < mask.len and mask[mask_i] == '*') {
            star_i = mask_i;
            mask_i += 1;
            retry_text_i = text_i;
        } else if (star_i) |star| {
            mask_i = star + 1;
            retry_text_i += 1;
            text_i = retry_text_i;
        } else {
            return false;
        }
    }

    while (mask_i < mask.len and mask[mask_i] == '*') {
        mask_i += 1;
    }

    return mask_i == mask.len;
}

/// Build RPL_LISTXSTART (811).
pub fn writeListxStart(out: []u8, ctx: ReplyContext) ListxError![]const u8 {
    return writeListxStartWith(.{}, out, ctx);
}

/// Build RPL_LISTXSTART (811) with caller-selected limits.
pub fn writeListxStartWith(comptime params: Params, out: []u8, ctx: ReplyContext) ListxError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_LISTXSTART, ctx.server_name, ctx.requester);
    try b.spaceParam("Channel");
    try b.spaceParam("Members");
    try b.spaceParam("CreatedMs");
    try b.spaceParam("TopicMs");
    try b.spaceTrailing("Topic");
    try b.crlf();
    return b.slice();
}

/// Build one RPL_LISTXENTRY (812) line.
pub fn writeListxEntry(out: []u8, ctx: ReplyContext, channel: ChannelInfo) ListxError![]const u8 {
    return writeListxEntryWith(.{}, out, ctx, channel);
}

/// Build one RPL_LISTXENTRY (812) line with caller-selected limits.
pub fn writeListxEntryWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    channel: ChannelInfo,
) ListxError![]const u8 {
    try validateContextWith(params, ctx);
    try validateChannelWith(params, channel);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_LISTXENTRY, ctx.server_name, ctx.requester);
    try b.spaceParam(channel.name);
    try b.spaceUnsigned(channel.members);
    try b.spaceUnsigned(channel.created_ms);
    try b.spaceUnsigned(channel.topic_ms orelse 0);
    try b.spaceTrailing(channel.topic);
    try b.crlf();
    return b.slice();
}

/// Build RPL_LISTXTRUNC (816).
pub fn writeListxTrunc(out: []u8, ctx: ReplyContext, emitted: u64) ListxError![]const u8 {
    return writeListxTruncWith(.{}, out, ctx, emitted);
}

/// Build one RPL_LISTXPICS (813) line.
pub fn writeListxPics(out: []u8, ctx: ReplyContext, channel: []const u8, pics: []const u8) ListxError![]const u8 {
    return writeListxPicsWith(.{}, out, ctx, channel, pics);
}

/// Build one RPL_LISTXPICS (813) line with caller-selected limits.
pub fn writeListxPicsWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    channel: []const u8,
    pics: []const u8,
) ListxError![]const u8 {
    try validateContextWith(params, ctx);
    try validateChannelNameWith(params, channel);
    if (pics.len > params.max_pics_bytes) return error.InvalidValue;
    try validateTrailingBytes(pics, error.InvalidValue);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_LISTXPICS, ctx.server_name, ctx.requester);
    try b.spaceParam(channel);
    try b.spaceTrailing(pics);
    try b.crlf();
    return b.slice();
}

/// Build RPL_LISTXTRUNC (816) with caller-selected limits.
pub fn writeListxTruncWith(
    comptime params: Params,
    out: []u8,
    ctx: ReplyContext,
    emitted: u64,
) ListxError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_LISTXTRUNC, ctx.server_name, ctx.requester);
    try b.spaceUnsigned(emitted);
    try b.spaceTrailing("LISTX results truncated");
    try b.crlf();
    return b.slice();
}

/// Build RPL_LISTXEND (817).
pub fn writeListxEnd(out: []u8, ctx: ReplyContext) ListxError![]const u8 {
    return writeListxEndWith(.{}, out, ctx);
}

/// Build RPL_LISTXEND (817) with caller-selected limits.
pub fn writeListxEndWith(comptime params: Params, out: []u8, ctx: ReplyContext) ListxError![]const u8 {
    try validateContextWith(params, ctx);

    var b = LineBuilder.init(out, params.max_line_bytes);
    try b.numericPrefix(RPL_LISTXEND, ctx.server_name, ctx.requester);
    try b.spaceTrailing("End of LISTX");
    try b.crlf();
    return b.slice();
}

fn validateContextWith(comptime params: Params, ctx: ReplyContext) ListxError!void {
    try validateParamBounded(ctx.server_name, params.max_server_bytes, error.InvalidServerName);
    try validateParamBounded(ctx.requester, params.max_requester_bytes, error.InvalidRequester);
}

fn validateChannelWith(comptime params: Params, channel: ChannelInfo) ListxError!void {
    try validateChannelNameWith(params, channel.name);
    if (channel.topic.len > params.max_topic_bytes) return error.InvalidTopic;
    try validateTrailingBytes(channel.topic, error.InvalidTopic);
}

fn validateChannelNameWith(comptime params: Params, name: []const u8) ListxError!void {
    try validateParamBounded(name, params.max_channel_bytes, error.InvalidChannelName);
    if (!validChannelNamePrefix(name)) return error.InvalidChannelName;
}

fn validChannelNamePrefix(name: []const u8) bool {
    if (name.len == 0) return false;
    return switch (name[0]) {
        '#', '&' => true,
        '%' => name.len >= 2 and (name[1] == '#' or name[1] == '&'),
        else => false,
    };
}

fn validateParamBounded(param: []const u8, max_len: usize, err: ListxError) ListxError!void {
    if (param.len == 0 or param.len > max_len) return err;
    if (param[0] == ':') return err;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn validateTrailingBytes(bytes: []const u8, err: ListxError) ListxError!void {
    for (bytes) |byte| {
        switch (byte) {
            0, '\r', '\n' => return err,
            else => {},
        }
    }
}

fn validateFilterBytes(token: []const u8) ListxError!void {
    for (token) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidFilter,
            else => {},
        }
    }
}

fn validateMaskWith(comptime params: Params, mask: []const u8) ListxError!void {
    if (mask.len <= 1) return error.InvalidMask;
    if (mask.len > params.max_mask_bytes) return error.MaskTooLong;
    for (mask) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return error.InvalidMask,
            else => {},
        }
    }
}

fn validateTextMaskWith(comptime params: Params, mask: []const u8) ListxError!void {
    if (mask.len > params.max_mask_bytes) return error.MaskTooLong;
    // `validateFilterBytes` already rejected control bytes, commas, and spaces in
    // the whole token; nothing further is required for a text-mask payload.
}

/// Parse a threshold expression whose first byte is `>` or `<`, optionally
/// followed by `=` for an inclusive comparison, then a decimal value. Shared by
/// the member-count, creation-age (`C`), and topic-age (`T`) filters so all
/// three honor the same `>N` / `<N` / `>=N` / `<=N` grammar. A bare operator
/// (e.g. `>=` with no digits) is rejected via `parseDecimal`.
fn parseThreshold(expr: []const u8) ListxError!Filter.Threshold {
    if (expr.len == 0) return error.InvalidFilter;
    const is_greater = switch (expr[0]) {
        '>' => true,
        '<' => false,
        else => return error.InvalidFilter,
    };
    const inclusive = expr.len >= 2 and expr[1] == '=';
    const digits_start: usize = if (inclusive) 2 else 1;
    const comparison: Comparison = if (is_greater)
        (if (inclusive) .greater_equal else .greater_than)
    else
        (if (inclusive) .less_equal else .less_than);
    return .{
        .comparison = comparison,
        .value = try parseDecimal(expr[digits_start..]),
    };
}

fn parseDecimal(bytes: []const u8) ListxError!u64 {
    if (bytes.len == 0) return error.InvalidValue;

    var value: u64 = 0;
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidValue;
        const digit: u64 = byte - '0';
        if (value > (std.math.maxInt(u64) - digit) / 10) return error.InvalidValue;
        value = value * 10 + digit;
    }

    return value;
}

fn elapsedMs(now_ms: u64, event_ms: u64) u64 {
    if (event_ms >= now_ms) return 0;
    return now_ms - event_ms;
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!asciiEqual(left, right)) return false;
    }
    return true;
}

fn asciiEqual(a: u8, b: u8) bool {
    return asciiLower(a) == asciiLower(b);
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

fn formatCodeValue(value: u16, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{
            .out = out,
            .max_line_bytes = @min(max_line_bytes, DEFAULT_MAX_LINE_BYTES),
        };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code_value: u16, server_name: []const u8, requester: []const u8) ListxError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');

        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCodeValue(code_value, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) ListxError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) ListxError!void {
        try self.appendBytes(" :");
        try self.appendBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u64) ListxError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) ListxError!void {
        var buf: [20]u8 = undefined;
        var cursor: usize = buf.len;
        var current = value;

        while (true) {
            cursor -= 1;
            buf[cursor] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }

        try self.appendBytes(buf[cursor..]);
    }

    fn crlf(self: *LineBuilder) ListxError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) ListxError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) ListxError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test {
    _ = numeric.numericTable;
}

test "parse member count filters" {
    const request = try parse(&.{">10,<50"});

    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(Comparison.greater_than, request.filters[0].criterion.member_count.comparison);
    try std.testing.expectEqual(@as(u64, 10), request.filters[0].criterion.member_count.value);
    try std.testing.expectEqual(Comparison.less_than, request.filters[1].criterion.member_count.comparison);
    try std.testing.expectEqual(@as(u64, 50), request.filters[1].criterion.member_count.value);
}

test "LISTX inclusive member-count thresholds parse" {
    const request = try parse(&.{">=10,<=50"});

    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(Comparison.greater_equal, request.filters[0].criterion.member_count.comparison);
    try std.testing.expectEqual(@as(u64, 10), request.filters[0].criterion.member_count.value);
    try std.testing.expectEqual(Comparison.less_equal, request.filters[1].criterion.member_count.comparison);
    try std.testing.expectEqual(@as(u64, 50), request.filters[1].criterion.member_count.value);
}

test "LISTX inclusive threshold includes the boundary value" {
    const at_least_10 = try parse(&.{">=10"});
    const at_most_10 = try parse(&.{"<=10"});
    const boundary = ChannelInfo{ .name = "#edge", .members = 10, .created_ms = 0 };
    const below = ChannelInfo{ .name = "#edge", .members = 9, .created_ms = 0 };
    const above = ChannelInfo{ .name = "#edge", .members = 11, .created_ms = 0 };

    // `>=10` admits exactly-10 where strict `>10` would reject it.
    try std.testing.expect(at_least_10.matches(boundary, 0));
    try std.testing.expect(at_least_10.matches(above, 0));
    try std.testing.expect(!at_least_10.matches(below, 0));
    try std.testing.expect(!(try parse(&.{">10"})).matches(boundary, 0));

    // `<=10` admits exactly-10 where strict `<10` would reject it.
    try std.testing.expect(at_most_10.matches(boundary, 0));
    try std.testing.expect(at_most_10.matches(below, 0));
    try std.testing.expect(!at_most_10.matches(above, 0));
    try std.testing.expect(!(try parse(&.{"<10"})).matches(boundary, 0));
}

test "LISTX inclusive thresholds compose into a closed range" {
    const request = try parse(&.{">=10,<=50"});
    const in_range = ChannelInfo{ .name = "#a", .members = 10, .created_ms = 0 };
    const top = ChannelInfo{ .name = "#b", .members = 50, .created_ms = 0 };
    const too_big = ChannelInfo{ .name = "#c", .members = 51, .created_ms = 0 };

    try std.testing.expect(request.matches(in_range, 0));
    try std.testing.expect(request.matches(top, 0));
    try std.testing.expect(!request.matches(too_big, 0));
}

test "LISTX inclusive threshold rejects a missing value" {
    try std.testing.expectError(error.InvalidValue, parse(&.{">="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"<="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{">=abc"}));
}

test "LISTX inclusive creation-age thresholds parse" {
    const request = try parse(&.{"C>=60000,C<=3600000"});

    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(Comparison.greater_equal, request.filters[0].criterion.creation_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 60_000), request.filters[0].criterion.creation_age_ms.value);
    try std.testing.expectEqual(Comparison.less_equal, request.filters[1].criterion.creation_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 3_600_000), request.filters[1].criterion.creation_age_ms.value);
}

test "LISTX inclusive topic-age thresholds parse" {
    const request = try parse(&.{"T>=1000,T<=9000"});

    try std.testing.expectEqual(@as(usize, 2), request.count);
    try std.testing.expectEqual(Comparison.greater_equal, request.filters[0].criterion.topic_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 1000), request.filters[0].criterion.topic_age_ms.value);
    try std.testing.expectEqual(Comparison.less_equal, request.filters[1].criterion.topic_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 9000), request.filters[1].criterion.topic_age_ms.value);
}

test "LISTX inclusive age threshold includes the boundary and stays byte-identical for strict" {
    // now_ms=100_000, channel created at 40_000 -> exactly 60_000ms old.
    const now: u64 = 100_000;
    const exactly_60k = ChannelInfo{ .name = "#c", .members = 1, .created_ms = 40_000 };

    // `C>=60000` admits the boundary where strict `C>60000` rejects it.
    try std.testing.expect((try parse(&.{"C>=60000"})).matches(exactly_60k, now));
    try std.testing.expect(!(try parse(&.{"C>60000"})).matches(exactly_60k, now));
    // `C<=60000` admits the boundary where strict `C<60000` rejects it.
    try std.testing.expect((try parse(&.{"C<=60000"})).matches(exactly_60k, now));
    try std.testing.expect(!(try parse(&.{"C<60000"})).matches(exactly_60k, now));

    // Topic-age boundary: topic set at 40_000 -> exactly 60_000ms old.
    const with_topic = ChannelInfo{
        .name = "#t",
        .members = 1,
        .topic = "hi",
        .created_ms = 0,
        .topic_ms = 40_000,
    };
    try std.testing.expect((try parse(&.{"T>=60000"})).matches(with_topic, now));
    try std.testing.expect(!(try parse(&.{"T>60000"})).matches(with_topic, now));
    try std.testing.expect((try parse(&.{"T<=60000"})).matches(with_topic, now));
    try std.testing.expect(!(try parse(&.{"T<60000"})).matches(with_topic, now));
}

test "LISTX inclusive age thresholds reject a missing value" {
    try std.testing.expectError(error.InvalidValue, parse(&.{"C>="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"C<="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"T>="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"T<=abc"}));
}

test "LISTX topic-age =mask disambiguation is preserved" {
    // `T=<mask>` stays a topic-text mask; only `T>`/`T<` are age thresholds.
    const request = try parse(&.{"T=*ship*"});
    try std.testing.expectEqualStrings("*ship*", request.filters[0].criterion.topic_mask);
}

test "parse creation age filters" {
    const request = try parse(&.{"C>60000,C<3600000"});

    try std.testing.expectEqual(Comparison.greater_than, request.filters[0].criterion.creation_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 60_000), request.filters[0].criterion.creation_age_ms.value);
    try std.testing.expectEqual(Comparison.less_than, request.filters[1].criterion.creation_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 3_600_000), request.filters[1].criterion.creation_age_ms.value);
}

test "parse topic age filters and topic only" {
    const request = try parse(&.{"T>1000,T<9000,TOPICONLY"});

    try std.testing.expectEqual(Comparison.greater_than, request.filters[0].criterion.topic_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 1000), request.filters[0].criterion.topic_age_ms.value);
    try std.testing.expectEqual(Comparison.less_than, request.filters[1].criterion.topic_age_ms.comparison);
    try std.testing.expectEqual(@as(u64, 9000), request.filters[1].criterion.topic_age_ms.value);
    try std.testing.expectEqual(Filter.Criterion.topic_only, request.filters[2].criterion);
}

test "parse channel mask filter" {
    const request = try parse(&.{"#zig*"});

    try std.testing.expectEqualStrings("#zig*", request.filters[0].criterion.channel_mask);
}

test "glob match is ascii case-insensitive" {
    try std.testing.expect(globMatch("#Z*", "#zig"));
    try std.testing.expect(globMatch("#?ig", "#ZIG"));
    try std.testing.expect(globMatch("#chat-*", "#CHAT-dev"));
    try std.testing.expect(!globMatch("#ops", "#zig"));
}

test "combined filters match with mask disjunction" {
    const request = try parse(&.{">10,C>1000,T<10000,TOPICONLY,#zig*,#dev*"});

    const matching = ChannelInfo{
        .name = "#DevOps",
        .members = 42,
        .topic = "shipping",
        .created_ms = 1_000,
        .topic_ms = 95_000,
    };
    const too_small = ChannelInfo{
        .name = "#dev-low",
        .members = 2,
        .topic = "quiet",
        .created_ms = 1_000,
        .topic_ms = 95_000,
    };
    const wrong_mask = ChannelInfo{
        .name = "#ops",
        .members = 42,
        .topic = "shipping",
        .created_ms = 1_000,
        .topic_ms = 95_000,
    };

    try std.testing.expect(request.matches(matching, 100_000));
    try std.testing.expect(!request.matches(too_small, 100_000));
    try std.testing.expect(!request.matches(wrong_mask, 100_000));
}

test "parse text mask and registered filters" {
    const request = try parse(&.{"N=#zig*,T=*release*,S=dev,L=en,R=1"});

    try std.testing.expectEqualStrings("#zig*", request.filters[0].criterion.name_mask);
    try std.testing.expectEqualStrings("*release*", request.filters[1].criterion.topic_mask);
    try std.testing.expectEqualStrings("dev", request.filters[2].criterion.subject_mask);
    try std.testing.expectEqualStrings("en", request.filters[3].criterion.language_mask);
    try std.testing.expectEqual(true, request.filters[4].criterion.registered);

    const unreg = try parse(&.{"R=0"});
    try std.testing.expectEqual(false, unreg.filters[0].criterion.registered);
}

test "text mask and registered filters match channel metadata" {
    const request = try parse(&.{"N=#zig*,T=*ship*,S=dev,L=en,R=1"});

    const matching = ChannelInfo{
        .name = "#zig-core",
        .members = 5,
        .topic = "now shipping",
        .created_ms = 0,
        .subject = "dev",
        .language = "en",
        .registered = true,
    };
    const wrong_topic = ChannelInfo{
        .name = "#zig-core",
        .members = 5,
        .topic = "quiet day",
        .created_ms = 0,
        .subject = "dev",
        .language = "en",
        .registered = true,
    };
    const unregistered = ChannelInfo{
        .name = "#zig-core",
        .members = 5,
        .topic = "now shipping",
        .created_ms = 0,
        .subject = "dev",
        .language = "en",
        .registered = false,
    };
    const wrong_name = ChannelInfo{
        .name = "#ops",
        .members = 5,
        .topic = "now shipping",
        .created_ms = 0,
        .subject = "dev",
        .language = "en",
        .registered = true,
    };

    try std.testing.expect(request.matches(matching, 1_000));
    try std.testing.expect(!request.matches(wrong_topic, 1_000));
    try std.testing.expect(!request.matches(unregistered, 1_000));
    try std.testing.expect(!request.matches(wrong_name, 1_000));
}

test "registered=0 selects only unregistered channels" {
    const request = try parse(&.{"R=0"});
    const reg = ChannelInfo{ .name = "#a", .members = 1, .created_ms = 0, .registered = true };
    const unreg = ChannelInfo{ .name = "#b", .members = 1, .created_ms = 0, .registered = false };

    try std.testing.expect(!request.matches(reg, 0));
    try std.testing.expect(request.matches(unreg, 0));
}

test "malformed text mask filters are rejected" {
    try std.testing.expectError(error.InvalidMask, parse(&.{"N="}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"R=2"}));
    try std.testing.expectError(error.InvalidFilter, parse(&.{"Q=foo"}));
}

test "topic filters reject channels without topic metadata" {
    const request = try parse(&.{"T>10"});

    try std.testing.expect(!request.matches(.{
        .name = "#empty",
        .members = 20,
        .topic = "",
        .created_ms = 0,
        .topic_ms = null,
    }, 100));
}

test "malformed filters are rejected" {
    try std.testing.expectError(error.InvalidFilter, parse(&.{","}));
    try std.testing.expectError(error.InvalidValue, parse(&.{">"}));
    try std.testing.expectError(error.InvalidValue, parse(&.{"C>abc"}));
    try std.testing.expectError(error.InvalidFilter, parse(&.{"X>10"}));
    try std.testing.expectError(error.InvalidMask, parse(&.{"#"}));
    try std.testing.expectError(error.InvalidFilter, parse(&.{"#bad\rmask"}));
    try std.testing.expectError(error.InvalidParameter, parse(&.{ "#zig*", ">10" }));
}

test "LISTX query limit is a trailing whole number and zero means the server cap" {
    const limited = try parse(&.{ ">10", "2" });
    try std.testing.expectEqual(@as(?u32, 2), limited.query_limit);
    try std.testing.expectEqual(@as(usize, 1), limited.slice().len);
    try std.testing.expectEqual(@as(u64, 10), limited.slice()[0].criterion.member_count.value);

    const open = try parse(&.{ "#zig*", "0" });
    try std.testing.expect(open.query_limit == null);
    try std.testing.expectEqual(@as(usize, 2), resultCap(open.query_limit, 2));
    try std.testing.expectEqual(@as(usize, 2), resultCap(limited.query_limit, 1024));
    try std.testing.expectEqual(@as(usize, 1024), resultCap(try parseQueryLimit("5000"), 1024));

    try std.testing.expect((try parse(&.{"#zig*"})).query_limit == null);
    try std.testing.expectError(error.InvalidValue, parse(&.{ "#zig*", "01" }));
    try std.testing.expectError(error.InvalidValue, parse(&.{ "#zig*", "4294967296" }));
    try std.testing.expectError(error.InvalidParameter, parse(&.{ "#zig*", "2", "3" }));
}

test "parse filters uses caller-owned storage" {
    var filters: [2]Filter = undefined;
    const parsed = try parseFilters(">1,#z*", &filters);

    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqual(@as(u64, 1), parsed[0].criterion.member_count.value);
    try std.testing.expectEqualStrings("#z*", parsed[1].criterion.channel_mask);
    try std.testing.expectError(error.TooManyFilters, parseFilters(">1,<9,#x*", &filters));
}

test "line builders emit LISTX numerics" {
    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    const channel = ChannelInfo{
        .name = "#zig",
        .members = 42,
        .topic = "Zig talk",
        .created_ms = 10_000,
        .topic_ms = 20_000,
    };

    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        ":irc.example.test 811 dan Channel Members CreatedMs TopicMs :Topic\r\n",
        try writeListxStart(&buf, ctx),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 812 dan #zig 42 10000 20000 :Zig talk\r\n",
        try writeListxEntry(&buf, ctx, channel),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 813 dan #zig :rated-safe\r\n",
        try writeListxPics(&buf, ctx, channel.name, "rated-safe"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 816 dan 100 :LISTX results truncated\r\n",
        try writeListxTrunc(&buf, ctx, 100),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 817 dan :End of LISTX\r\n",
        try writeListxEnd(&buf, ctx),
    );
}

test "line builders validate attacker bytes and buffer bounds" {
    const bad_ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "bad nick" };
    const good_ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    const bad_channel = ChannelInfo{
        .name = "#zig",
        .members = 42,
        .topic = "bad\rtopic",
        .created_ms = 0,
        .topic_ms = null,
    };

    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidRequester, writeListxEnd(&buf, bad_ctx));
    try std.testing.expectError(error.InvalidTopic, writeListxEntry(&buf, good_ctx, bad_channel));

    var short: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, writeListxEnd(&short, good_ctx));
    try std.testing.expectError(error.InvalidValue, writeListxPics(&buf, good_ctx, "#zig", "bad\rpics"));
}
