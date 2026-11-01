// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Event Spine typed oper event bus.
//!
//! Daemon subsystems publish typed events here, while oper sessions subscribe
//! by `EventCategory` mask. The spine owns no allocation and keeps no global
//! state: callers provide subscriber storage, publish sinks, and render buffers.
const std = @import("std");

/// Onyx Server event categories. These replace untyped oper broadcast channels.
pub const EventCategory = enum(u6) {
    connect,
    disconnect,
    server_link,
    flood,
    @"error",
    announce,
    oper_action,
    kill,
    spam,
    debug,
    policy,
    service,
    security,

    pub fn token(self: EventCategory) []const u8 {
        return @tagName(self);
    }

    /// Resolve a live-command token to a REAL category by `code()`/`token()`
    /// only — deliberately NOT the IRCX draft aliases (CHANNEL/MEMBER/USER),
    /// which are the separate token-routed IRCX plane and must not fold back
    /// into the category mask. Returns null for an unknown token.
    pub fn parse(raw: []const u8) ?EventCategory {
        inline for (@typeInfo(EventCategory).@"enum".field_names) |field_name| {
            const cat: EventCategory = @field(EventCategory, field_name);
            if (std.ascii.eqlIgnoreCase(raw, cat.code()) or std.ascii.eqlIgnoreCase(raw, cat.token()))
                return cat;
        }
        return null;
    }

    pub fn code(self: EventCategory) []const u8 {
        return switch (self) {
            .connect => "CONNECT",
            .disconnect => "DISCONNECT",
            .server_link => "SERVER_LINK",
            .flood => "FLOOD",
            .@"error" => "ERROR",
            .announce => "ANNOUNCE",
            .oper_action => "OPER_ACTION",
            .kill => "KILL",
            .spam => "SPAM",
            .debug => "DEBUG",
            .policy => "POLICY",
            .service => "SERVICE",
            .security => "SECURITY",
        };
    }
};

/// Event severity used for routing presentation and structured wire tags.
pub const EventSeverity = enum {
    debug,
    info,
    notice,
    warn,
    @"error",
    critical,

    pub fn token(self: EventSeverity) []const u8 {
        return @tagName(self);
    }

    /// Parse a severity token (case-insensitive `@tagName`, plus the common
    /// alias "warning"→warn). Returns null for an unknown token.
    pub fn parse(raw: []const u8) ?EventSeverity {
        if (std.ascii.eqlIgnoreCase(raw, "warning")) return .warn;
        inline for (@typeInfo(EventSeverity).@"enum".field_names) |field_name| {
            if (std.ascii.eqlIgnoreCase(raw, field_name)) return @field(EventSeverity, field_name);
        }
        return null;
    }

    /// True when this severity ranks at or above `floor` in the fixed low→high
    /// order (debug<info<notice<warn<error<critical) — the typed threshold
    /// predicate for a min-severity filter, e.g. the per-session delivery floor
    /// (`ClientSession.severityWanted`). Prefer this over open-coding an
    /// `@intFromEnum` comparison; the declaration order it depends on is pinned
    /// by the comptime guard below (which also protects `EVENT REPLAY`'s floor
    /// and event-collapse's "never collapse ≥ warn" safety rule).
    pub fn atLeast(self: EventSeverity, floor: EventSeverity) bool {
        return @backingInt(self) >= @backingInt(floor);
    }
};

comptime {
    // `EventSeverity.atLeast`, the per-session delivery floor, `EVENT REPLAY`'s
    // floor, and event-collapse's SAFETY rule ("severity ≥ warn is NEVER
    // collapsed" — a kill/ward must always reach opers) all treat the enum's
    // DECLARATION order as the severity order. Pin it so a reorder is a compile
    // error HERE, rather than a silent mis-filter that could coalesce a kill or
    // invert the collapse ceiling while the affected tests move in lockstep and
    // stay green. Update this list — deliberately — when adding a level.
    const ordered = [_]EventSeverity{ .debug, .info, .notice, .warn, .@"error", .critical };
    if (ordered.len != @typeInfo(EventSeverity).@"enum".field_names.len)
        @compileError("EventSeverity: add the new level to the ordered-severity guard");
    for (ordered, 0..) |sev, i| {
        if (@backingInt(sev) != i)
            @compileError("EventSeverity ordinals must follow the low->high declaration order");
    }
}

/// Bit mask over `EventCategory`.
pub const CategoryMask = struct {
    bits: u64 = 0,

    pub fn empty() CategoryMask {
        return .{};
    }

    pub fn all() CategoryMask {
        var out = CategoryMask.empty();
        inline for (@typeInfo(EventCategory).@"enum".field_names) |field_name| {
            out.add(@field(EventCategory, field_name));
        }
        return out;
    }

    pub fn only(category: EventCategory) CategoryMask {
        return .{ .bits = bit(category) };
    }

    pub fn fromCategories(categories: []const EventCategory) CategoryMask {
        var out = CategoryMask.empty();
        for (categories) |category| out.add(category);
        return out;
    }

    pub fn add(self: *CategoryMask, category: EventCategory) void {
        self.bits |= bit(category);
    }

    pub fn remove(self: *CategoryMask, category: EventCategory) void {
        self.bits &= ~bit(category);
    }

    pub fn include(self: CategoryMask, other: CategoryMask) CategoryMask {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn exclude(self: CategoryMask, other: CategoryMask) CategoryMask {
        return .{ .bits = self.bits & ~other.bits };
    }

    pub fn contains(self: CategoryMask, category: EventCategory) bool {
        return (self.bits & bit(category)) != 0;
    }

    pub fn intersects(self: CategoryMask, other: CategoryMask) bool {
        return (self.bits & other.bits) != 0;
    }

    pub fn isEmpty(self: CategoryMask) bool {
        return self.bits == 0;
    }

    fn bit(category: EventCategory) u64 {
        return @as(u64, 1) << @backingInt(category);
    }
};

/// Build a `CategoryMask` from config tokens: case-insensitive `EventCategory`
/// names (e.g. "ANNOUNCE", "KILL", "OPER_ACTION") or the special "ALL". Unknown
/// tokens are ignored. Used by `[[opers]] presubscribe`.
pub fn categoryMaskFromTokens(tokens: []const []const u8) CategoryMask {
    var mask = CategoryMask.empty();
    for (tokens) |tok| {
        if (std.ascii.eqlIgnoreCase(tok, "ALL")) {
            mask = mask.include(CategoryMask.all());
            continue;
        }
        inline for (@typeInfo(EventCategory).@"enum".field_names) |field_name| {
            const cat: EventCategory = @field(EventCategory, field_name);
            if (std.ascii.eqlIgnoreCase(tok, cat.token())) mask.add(cat);
        }
    }
    return mask;
}

pub const IRCX_EVENT_TYPE_COUNT: usize = @typeInfo(IrcxEventType).@"enum".field_names.len;

/// IRCX EVENT subscription types supported by the client-facing command.
/// These are intentionally distinct from Onyx Server's EventCategory taxonomy:
/// command replies/listing use the IRCX names, while delivery maps each type to
/// the closest existing Event Spine categories.
pub const IrcxEventType = enum(u3) {
    channel,
    member,
    user,
    /// In-channel real-time media (voice/video) presence + state: a call
    /// participant joins/leaves/mutes/speaks. Channel-scoped like CHANNEL/MEMBER;
    /// unlike them it is subscribable by ordinary (non-oper) clients for channels
    /// they are in, since it is the call-presence feed the chat client renders.
    media,

    pub fn wireName(self: IrcxEventType) []const u8 {
        return switch (self) {
            .channel => "CHANNEL",
            .member => "MEMBER",
            .user => "USER",
            .media => "MEDIA",
        };
    }

    pub fn parse(raw: []const u8) ?IrcxEventType {
        inline for (@typeInfo(IrcxEventType).@"enum".field_values) |field_value| {
            const typ: IrcxEventType = @fromBackingInt(@intCast(field_value));
            if (std.ascii.eqlIgnoreCase(raw, typ.wireName())) return typ;
        }
        return null;
    }

    /// Classify an Event-Spine message BODY by its leading TYPE token — every IRCX
    /// lifecycle event is published as `"<TYPE> <ACTION> <subject> …"` (e.g.
    /// "CHANNEL MODE #c +nt", "MEMBER JOIN #c nick", "USER CONNECT n!u@h"). This is
    /// the authoritative routing key for IRCX EVENT subscribers: it is exact (no
    /// category cross-talk between MEMBER and USER) and survives the wire verbatim,
    /// so local, cross-shard, and mesh-drained events all classify identically.
    /// Returns null for non-IRCX oper notices (kill prose, "SERVER LINK …", flood
    /// warnings), which reach legacy oper subscribers purely by EventCategory.
    pub fn fromMessage(message: []const u8) ?IrcxEventType {
        const end = std.mem.indexOfScalar(u8, message, ' ') orelse message.len;
        return parse(message[0..end]);
    }

    pub fn bit(self: IrcxEventType) u8 {
        return @as(u8, 1) << @intCast(@backingInt(self));
    }
};

pub const ircx_event_types = [_]IrcxEventType{ .channel, .member, .user, .media };

pub const IrcxEventMask = struct {
    bits: u8 = 0,

    pub fn empty() IrcxEventMask {
        return .{};
    }

    pub fn add(self: *IrcxEventMask, typ: IrcxEventType) void {
        self.bits |= typ.bit();
    }

    pub fn remove(self: *IrcxEventMask, typ: IrcxEventType) void {
        self.bits &= ~typ.bit();
    }

    pub fn contains(self: IrcxEventMask, typ: IrcxEventType) bool {
        return (self.bits & typ.bit()) != 0;
    }

    pub fn isEmpty(self: IrcxEventMask) bool {
        return self.bits == 0;
    }
};

/// Borrowed event payload. `timestamp_ms` is supplied by the caller.
pub const Event = struct {
    category: EventCategory,
    severity: EventSeverity,
    timestamp_ms: i64,
    message: []const u8,
};

/// One oper subscription slot. `id` and `mask` are caller-owned values.
pub const Subscriber = struct {
    id: []const u8 = "",
    mask: CategoryMask = .{},
};

/// One selected event delivery.
pub const Delivery = struct {
    subscriber_id: []const u8,
    event: Event,
};

/// Caller-owned sink filled by `EventSpine.publish`.
pub const PublishSink = struct {
    deliveries: []Delivery,
    count: usize = 0,

    pub fn init(deliveries: []Delivery) PublishSink {
        return .{ .deliveries = deliveries };
    }

    pub fn reset(self: *PublishSink) void {
        self.count = 0;
    }

    pub fn slice(self: *const PublishSink) []const Delivery {
        return self.deliveries[0..self.count];
    }

    fn remaining(self: *const PublishSink) usize {
        return self.deliveries.len - self.count;
    }

    fn append(self: *PublishSink, delivery: Delivery) PublishError!void {
        if (self.count >= self.deliveries.len) return error.OutputTooSmall;
        self.deliveries[self.count] = delivery;
        self.count += 1;
    }
};

pub const SubscriptionError = error{
    EmptyMask,
    InvalidSubscriberId,
    TooManySubscribers,
};

pub const PublishError = error{
    OutputTooSmall,
};

pub const RenderError = error{
    InvalidMessage,
    InvalidServerName,
    InvalidTimestamp,
    MessageTooLong,
    OutputTooSmall,
};

/// Event Spine over caller-owned subscriber slots.
pub const EventSpine = struct {
    subscribers: []Subscriber,
    count: usize = 0,

    pub fn init(subscribers: []Subscriber) EventSpine {
        return .{ .subscribers = subscribers };
    }

    pub fn subscriberSlice(self: *const EventSpine) []const Subscriber {
        return self.subscribers[0..self.count];
    }

    /// Add or replace one subscriber's category mask.
    pub fn subscribe(
        self: *EventSpine,
        subscriber_id: []const u8,
        mask: CategoryMask,
    ) SubscriptionError!void {
        try validateSubscriberId(subscriber_id);
        if (mask.isEmpty()) return error.EmptyMask;

        if (self.findIndex(subscriber_id)) |index| {
            self.subscribers[index].mask = mask;
            return;
        }

        if (self.count >= self.subscribers.len) return error.TooManySubscribers;
        self.subscribers[self.count] = .{ .id = subscriber_id, .mask = mask };
        self.count += 1;
    }

    /// Remove categories from a subscriber. The subscriber is dropped when its
    /// mask becomes empty. Missing subscribers are a successful no-op.
    pub fn unsubscribe(
        self: *EventSpine,
        subscriber_id: []const u8,
        mask: CategoryMask,
    ) SubscriptionError!bool {
        try validateSubscriberId(subscriber_id);
        if (mask.isEmpty()) return error.EmptyMask;

        const index = self.findIndex(subscriber_id) orelse return false;
        const next = self.subscribers[index].mask.exclude(mask);
        if (next.isEmpty()) {
            self.removeAt(index);
        } else {
            self.subscribers[index].mask = next;
        }
        return true;
    }

    /// Remove a subscriber entirely. Missing subscribers are a successful no-op.
    pub fn unsubscribeAll(self: *EventSpine, subscriber_id: []const u8) SubscriptionError!bool {
        try validateSubscriberId(subscriber_id);
        const index = self.findIndex(subscriber_id) orelse return false;
        self.removeAt(index);
        return true;
    }

    /// Select subscribers whose masks include the event category into `sink`.
    pub fn publish(self: *const EventSpine, event: Event, sink: *PublishSink) PublishError![]const Delivery {
        const needed = self.matchCount(event.category);
        if (needed > sink.remaining()) return error.OutputTooSmall;

        const event_mask = CategoryMask.only(event.category);
        for (self.subscriberSlice()) |subscriber| {
            if (!subscriber.mask.intersects(event_mask)) continue;
            try sink.append(.{ .subscriber_id = subscriber.id, .event = event });
        }
        return sink.slice();
    }

    fn matchCount(self: *const EventSpine, category: EventCategory) usize {
        const event_mask = CategoryMask.only(category);
        var count: usize = 0;
        for (self.subscriberSlice()) |subscriber| {
            if (subscriber.mask.intersects(event_mask)) count += 1;
        }
        return count;
    }

    fn findIndex(self: *const EventSpine, subscriber_id: []const u8) ?usize {
        for (self.subscriberSlice(), 0..) |subscriber, index| {
            if (std.mem.eql(u8, subscriber.id, subscriber_id)) return index;
        }
        return null;
    }

    fn removeAt(self: *EventSpine, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.subscribers[cursor] = self.subscribers[cursor + 1];
        }
        self.count -= 1;
        self.subscribers[self.count] = .{};
    }
};

/// Maximum rendered event line length (classic IRC 512 is too small for IRCv3-era
/// hosts/reasons; matches the prior renderer's cap).
pub const max_event_line_len: usize = 8191;

/// Render one chatsvc-faithful raw EVENT line into `out`:
///   `:<server> EVENT <target> <message>\r\n`
///
/// Modeled after the MS Exchange 5.5 Chat Service (chatsvc), whose event
/// notifications are raw `:<srv> EVENT <target> <TYPE> <SUBTYPE> <args>` lines —
/// not the older draft-note or numeric form. `target` is the recipient (the
/// subscribed oper's nick); `message` is the structured payload the caller built,
/// e.g. "USER CONNECT n!u@h", "USER DISCONNECT n!u@h :quit", "MEMBER JOIN #c nick",
/// "SERVER LINK ircx.us". The subscription category is applied upstream for
/// filtering; it is intentionally absent from the wire (the TYPE leads the body).
pub fn renderEvent(server_name: []const u8, target: []const u8, message: []const u8, out: []u8) RenderError![]const u8 {
    try validateServerName(server_name);
    if (!validAtom(target)) return error.InvalidMessage; // recipient nick atom
    if (message.len == 0) return error.InvalidMessage;
    for (message) |ch| {
        if (unsafeTextByte(ch)) return error.InvalidMessage;
    }
    const needed = ":".len + server_name.len + " EVENT ".len + target.len + " ".len + message.len + "\r\n".len;
    if (needed > max_event_line_len) return error.MessageTooLong;
    if (out.len < needed) return error.OutputTooSmall;

    var writer = SliceWriter{ .buf = out };
    try writer.append(":");
    try writer.append(server_name);
    try writer.append(" EVENT ");
    try writer.append(target);
    try writer.append(" ");
    try writer.append(message);
    try writer.append("\r\n");
    return out[0..writer.len];
}

/// Build the IRCv3 message-tag prefix for a structured event delivery, e.g.
/// `onyx_server.io/category=KILL;onyx_server.io/severity=warn`. Both values come from
/// fixed `code()`/`token()` tables (uppercase / lowercase ASCII), so they are
/// already tag-safe and need no escaping.
pub fn buildEventTags(out: []u8, category: EventCategory, severity: EventSeverity) RenderError![]const u8 {
    return std.fmt.bufPrint(out, "onyx_server.io/category={s};onyx_server.io/severity={s}", .{ category.code(), severity.token() }) catch error.OutputTooSmall;
}

/// Like `renderEvent`, but prepends an IRCv3 message-tag block:
///   `@<tags> :<server> EVENT <target> <message>\r\n`
/// Empty `tags` degrades to the plain `renderEvent` form. Delivered only to
/// clients that negotiated `message-tags`; everyone else gets the plain line.
pub fn renderEventTagged(tags: []const u8, server_name: []const u8, target: []const u8, message: []const u8, out: []u8) RenderError![]const u8 {
    if (tags.len == 0) return renderEvent(server_name, target, message, out);
    // Tags are server-built from known-safe tables, but validate defensively so
    // a future caller can never inject a space/control byte into the tag block.
    for (tags) |ch| {
        if (ch <= ' ' or ch == 0x7f) return error.InvalidMessage;
    }
    try validateServerName(server_name);
    if (!validAtom(target)) return error.InvalidMessage;
    if (message.len == 0) return error.InvalidMessage;
    for (message) |ch| {
        if (unsafeTextByte(ch)) return error.InvalidMessage;
    }
    const needed = "@".len + tags.len + " ".len + ":".len + server_name.len + " EVENT ".len + target.len + " ".len + message.len + "\r\n".len;
    if (needed > max_event_line_len) return error.MessageTooLong;
    if (out.len < needed) return error.OutputTooSmall;
    var writer = SliceWriter{ .buf = out };
    try writer.append("@");
    try writer.append(tags);
    try writer.append(" :");
    try writer.append(server_name);
    try writer.append(" EVENT ");
    try writer.append(target);
    try writer.append(" ");
    try writer.append(message);
    try writer.append("\r\n");
    return out[0..writer.len];
}

fn validateSubscriberId(id: []const u8) SubscriptionError!void {
    if (!validAtom(id)) return error.InvalidSubscriberId;
}

fn validateServerName(name: []const u8) RenderError!void {
    if (!validAtom(name)) return error.InvalidServerName;
}

fn validAtom(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |ch| {
        if (ch <= ' ' or ch == 0x7f or ch == ':' or ch == ';') return false;
    }
    return true;
}

fn unsafeTextByte(ch: u8) bool {
    return ch < ' ' or ch == 0x7f;
}

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) RenderError!void {
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }
};

test "category masks add remove and combine categories" {
    var mask = CategoryMask.empty();
    try std.testing.expect(mask.isEmpty());

    mask.add(.connect);
    mask.add(.flood);
    try std.testing.expect(mask.contains(.connect));
    try std.testing.expect(mask.contains(.flood));
    try std.testing.expect(!mask.contains(.debug));

    mask.remove(.connect);
    try std.testing.expect(!mask.contains(.connect));
    try std.testing.expect(mask.contains(.flood));

    const combined = mask.include(CategoryMask.fromCategories(&.{ .debug, .@"error" }));
    try std.testing.expect(combined.contains(.flood));
    try std.testing.expect(combined.contains(.debug));
    try std.testing.expect(combined.contains(.@"error"));
}

test "EventCategory.parse resolves real categories but NOT IRCX draft aliases" {
    try std.testing.expectEqual(EventCategory.kill, EventCategory.parse("KILL").?);
    try std.testing.expectEqual(EventCategory.kill, EventCategory.parse("kill").?);
    try std.testing.expectEqual(EventCategory.security, EventCategory.parse("SECURITY").?);
    try std.testing.expectEqual(EventCategory.oper_action, EventCategory.parse("OPER_ACTION").?);
    // The IRCX draft aliases (CHANNEL/MEMBER/USER) must NOT fold into a category
    // here — that plane is token-routed separately and this parser is alias-free.
    try std.testing.expectEqual(@as(?EventCategory, null), EventCategory.parse("CHANNEL"));
    try std.testing.expectEqual(@as(?EventCategory, null), EventCategory.parse("MEMBER"));
    try std.testing.expectEqual(@as(?EventCategory, null), EventCategory.parse("USER"));
    try std.testing.expectEqual(@as(?EventCategory, null), EventCategory.parse("nonsense"));
}

test "EventSeverity.parse and ordering supports a min-severity filter" {
    try std.testing.expectEqual(EventSeverity.warn, EventSeverity.parse("warn").?);
    try std.testing.expectEqual(EventSeverity.warn, EventSeverity.parse("WARNING").?);
    try std.testing.expectEqual(EventSeverity.critical, EventSeverity.parse("Critical").?);
    try std.testing.expectEqual(@as(?EventSeverity, null), EventSeverity.parse("loud"));
    // Ordered low→high, so `@intFromEnum(sev) >= min` is a valid threshold test.
    try std.testing.expect(@backingInt(EventSeverity.debug) < @backingInt(EventSeverity.info));
    try std.testing.expect(@backingInt(EventSeverity.info) < @backingInt(EventSeverity.notice));
    try std.testing.expect(@backingInt(EventSeverity.notice) < @backingInt(EventSeverity.warn));
    try std.testing.expect(@backingInt(EventSeverity.warn) < @backingInt(EventSeverity.@"error"));
    try std.testing.expect(@backingInt(EventSeverity.@"error") < @backingInt(EventSeverity.critical));
}

test "event spine severity threshold predicate atLeast follows the low->high order" {
    const order = [_]EventSeverity{ .debug, .info, .notice, .warn, .@"error", .critical };
    // atLeast(floor) is true exactly when self ranks at or above floor.
    for (order, 0..) |sev, si| {
        for (order, 0..) |floor, fi| {
            try std.testing.expectEqual(si >= fi, sev.atLeast(floor));
        }
    }
    // Reflexive at every level.
    for (order) |sev| try std.testing.expect(sev.atLeast(sev));
    // The event-collapse SAFETY boundary: warn and above clear a warn floor;
    // notice and below do not (a kill/ward must never fall under it).
    try std.testing.expect(EventSeverity.critical.atLeast(.warn));
    try std.testing.expect(EventSeverity.@"error".atLeast(.warn));
    try std.testing.expect(EventSeverity.warn.atLeast(.warn));
    try std.testing.expect(!EventSeverity.notice.atLeast(.warn));
    try std.testing.expect(!EventSeverity.debug.atLeast(.warn));
    // A debug floor (the default session floor) admits everything.
    for (order) |sev| try std.testing.expect(sev.atLeast(.debug));
}

test "IRCX event types parse from a bare token" {
    try std.testing.expectEqual(IrcxEventType.channel, IrcxEventType.parse("CHANNEL").?);
    try std.testing.expectEqual(IrcxEventType.member, IrcxEventType.parse("member").?);
    try std.testing.expectEqual(IrcxEventType.user, IrcxEventType.parse("User").?);
    try std.testing.expectEqual(@as(?IrcxEventType, null), IrcxEventType.parse("SERVER"));
}

test "IRCX event type classification from a message body routes by leading token" {
    // Each lifecycle body classifies to exactly one IRCX type — no cross-talk.
    try std.testing.expectEqual(IrcxEventType.channel, IrcxEventType.fromMessage("CHANNEL MODE #ops +nt").?);
    try std.testing.expectEqual(IrcxEventType.member, IrcxEventType.fromMessage("MEMBER JOIN #ops kain").?);
    try std.testing.expectEqual(IrcxEventType.member, IrcxEventType.fromMessage("MEMBER KNOCK #ops nick :let me in").?);
    try std.testing.expectEqual(IrcxEventType.user, IrcxEventType.fromMessage("USER CONNECT n!u@h").?);
    try std.testing.expectEqual(IrcxEventType.user, IrcxEventType.fromMessage("USER NICK old!u@h -> new").?);
    // A single-token body still classifies (no trailing space).
    try std.testing.expectEqual(IrcxEventType.user, IrcxEventType.fromMessage("USER").?);
    // Non-IRCX oper notices never match an IRCX type — they reach legacy
    // EventCategory subscribers only.
    try std.testing.expectEqual(@as(?IrcxEventType, null), IrcxEventType.fromMessage("SERVER LINK ircx.us"));
    try std.testing.expectEqual(@as(?IrcxEventType, null), IrcxEventType.fromMessage("kain killed spammer (flood)"));
    try std.testing.expectEqual(@as(?IrcxEventType, null), IrcxEventType.fromMessage(""));
}

test "IRCX event mask tracks distinct subscription bits" {
    var mask = IrcxEventMask.empty();
    try std.testing.expect(mask.isEmpty());
    mask.add(.channel);
    mask.add(.user);
    try std.testing.expect(mask.contains(.channel));
    try std.testing.expect(!mask.contains(.member));
    try std.testing.expect(mask.contains(.user));
    mask.remove(.channel);
    try std.testing.expect(!mask.contains(.channel));
    try std.testing.expect(!mask.isEmpty());
}

test "multi-subscriber fan-out preserves subscription order" {
    var subscribers: [4]Subscriber = @splat(.{});
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.fromCategories(&.{ .connect, .flood }));
    try spine.subscribe("oper-b", CategoryMask.only(.flood));
    try spine.subscribe("oper-c", CategoryMask.only(.debug));

    var deliveries: [4]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);
    const selected = try spine.publish(.{
        .category = .flood,
        .severity = .warn,
        .timestamp_ms = 1200,
        .message = "Flood limiter tripped",
    }, &sink);

    try std.testing.expectEqual(@as(usize, 2), selected.len);
    try std.testing.expectEqualStrings("oper-a", selected[0].subscriber_id);
    try std.testing.expectEqualStrings("oper-b", selected[1].subscriber_id);
    try std.testing.expectEqual(EventCategory.flood, selected[0].event.category);
    try std.testing.expectEqual(EventSeverity.warn, selected[1].event.severity);
}

test "unsubscribe removes selected categories and drops empty subscribers" {
    var subscribers: [3]Subscriber = @splat(.{});
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.fromCategories(&.{ .connect, .flood }));
    try std.testing.expect(try spine.unsubscribe("oper-a", CategoryMask.only(.connect)));
    try std.testing.expectEqual(@as(usize, 1), spine.subscriberSlice().len);
    try std.testing.expect(!spine.subscriberSlice()[0].mask.contains(.connect));
    try std.testing.expect(spine.subscriberSlice()[0].mask.contains(.flood));

    try std.testing.expect(try spine.unsubscribe("oper-a", CategoryMask.only(.flood)));
    try std.testing.expectEqual(@as(usize, 0), spine.subscriberSlice().len);
    try std.testing.expect(!try spine.unsubscribeAll("oper-a"));
}

test "tagged render prepends an IRCv3 message-tag block; empty tags degrade to plain" {
    var tbuf: [128]u8 = undefined;
    const tags = try buildEventTags(&tbuf, .kill, .warn);
    try std.testing.expectEqualStrings("onyx_server.io/category=KILL;onyx_server.io/severity=warn", tags);

    var out: [256]u8 = undefined;
    const line = try renderEventTagged(tags, "onyx.local", "kain", "k killed s (flood)", &out);
    try std.testing.expectEqualStrings(
        "@onyx_server.io/category=KILL;onyx_server.io/severity=warn :onyx.local EVENT kain k killed s (flood)\r\n",
        line,
    );
    // Empty tags → identical to the plain renderer.
    var out2: [256]u8 = undefined;
    const plain = try renderEventTagged("", "onyx.local", "kain", "SERVER LINK ircx.us", &out2);
    try std.testing.expectEqualStrings(":onyx.local EVENT kain SERVER LINK ircx.us\r\n", plain);
}

test "render output is a chatsvc-faithful raw EVENT line (per-recipient target)" {
    var out: [256]u8 = undefined;
    const line = try renderEvent("onyx.local", "kain", "SERVER LINK ircx.us", &out);
    try std.testing.expectEqualStrings(
        ":onyx.local EVENT kain SERVER LINK ircx.us\r\n",
        line,
    );
}

test "render carries a structured body with a trailing reason verbatim" {
    var out: [256]u8 = undefined;
    // A ':'-introduced reason and an IPv6 host (colons) must survive in the body.
    const line = try renderEvent("onyx.local", "kain", "USER DISCONNECT n!u@fe80:0:0:0:1 :Client quit", &out);
    try std.testing.expectEqualStrings(
        ":onyx.local EVENT kain USER DISCONNECT n!u@fe80:0:0:0:1 :Client quit\r\n",
        line,
    );
}

test "publish with no matching subscribers returns empty selection" {
    var subscribers: [2]Subscriber = @splat(.{});
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.only(.debug));

    var deliveries: [2]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);
    const selected = try spine.publish(.{
        .category = .kill,
        .severity = .notice,
        .timestamp_ms = 33,
        .message = "user removed",
    }, &sink);

    try std.testing.expectEqual(@as(usize, 0), selected.len);
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "publish reports too-small sinks before partial fan-out" {
    var subscribers: [2]Subscriber = @splat(.{});
    var spine = EventSpine.init(&subscribers);

    try spine.subscribe("oper-a", CategoryMask.only(.announce));
    try spine.subscribe("oper-b", CategoryMask.only(.announce));

    var deliveries: [1]Delivery = undefined;
    var sink = PublishSink.init(&deliveries);

    try std.testing.expectError(error.OutputTooSmall, spine.publish(.{
        .category = .announce,
        .severity = .info,
        .timestamp_ms = 50,
        .message = "maintenance window",
    }, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.count);
}

test "renderer validates unsafe wire text and caller-owned output size" {
    var out: [64]u8 = undefined;

    // Control bytes in the body are rejected.
    try std.testing.expectError(error.InvalidMessage, renderEvent("onyx.local", "kain", "bad\nline", &out));
    // A bad target (contains ':') is rejected.
    try std.testing.expectError(error.InvalidMessage, renderEvent("onyx.local", "ka:in", "connected", &out));
    // Output buffer too small for the rendered line.
    try std.testing.expectError(error.OutputTooSmall, renderEvent("onyx.local", "kain", "USER CONNECT n!u@host", out[0..8]));
}
