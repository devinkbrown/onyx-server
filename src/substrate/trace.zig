// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure observability spine: structured trace events, level/category filtering,
//! sink dispatch, and a lock-free single-producer flight recorder.
const std = @import("std");

pub const max_fields: usize = 8;
pub const max_recorded_key_len: usize = 32;
pub const max_recorded_str_len: usize = 128;
pub const max_recorded_msg_len: usize = 160;
pub const category_slots: usize = 256;
pub const cache_line_bytes: usize = 64;

pub const Level = enum(u3) {
    debug,
    info,
    notice,
    warn,
    err,
    fatal,

    pub fn token(self: Level) []const u8 {
        return @tagName(self);
    }

    pub fn allows(minimum: Level, level: Level) bool {
        return @backingInt(level) >= @backingInt(minimum);
    }
};

/// Non-exhaustive category space. Known categories have stable low numeric IDs;
/// future subsystems can still carry an enum value through filters/recorders.
pub const Category = enum(u8) {
    reactor,
    s2s,
    crdt,
    sasl,
    channel,
    oper,
    media,
    config,
    auth,
    net,
    storage,
    timer,
    tls,
    dns,
    metrics,
    security,
    protocol,
    _,

    pub fn token(self: Category) []const u8 {
        return switch (self) {
            .reactor => "reactor",
            .s2s => "s2s",
            .crdt => "crdt",
            .sasl => "sasl",
            .channel => "channel",
            .oper => "oper",
            .media => "media",
            .config => "config",
            .auth => "auth",
            .net => "net",
            .storage => "storage",
            .timer => "timer",
            .tls => "tls",
            .dns => "dns",
            .metrics => "metrics",
            .security => "security",
            .protocol => "protocol",
            _ => "unknown",
        };
    }

    pub fn slot(self: Category) usize {
        return @backingInt(self);
    }
};

pub const Value = union(enum) {
    str: []const u8,
    uint: u64,
    int: i64,
    bool: bool,
};

pub const Field = struct {
    key: []const u8,
    val: Value,
};

pub const Hlc = u64;

/// Borrowed event view. Field keys, string values, and message bytes are owned
/// by the caller unless copied into a recorder.
pub const Event = struct {
    level: Level,
    category: Category,
    ts_mono_ns: u64,
    hlc: Hlc,
    msg: []const u8,
    fields: []const Field = &.{},
};

pub const SinkError = anyerror;

pub const Sink = struct {
    ptr: *anyopaque,
    writeFn: *const fn (*anyopaque, Event) SinkError!void,

    pub fn init(comptime T: type, ptr: *T) Sink {
        return .{
            .ptr = ptr,
            .writeFn = struct {
                fn write(ctx: *anyopaque, event: Event) SinkError!void {
                    const self: *T = @ptrCast(@alignCast(ctx));
                    try self.write(event);
                }
            }.write,
        };
    }

    pub fn write(self: Sink, event: Event) SinkError!void {
        try self.writeFn(self.ptr, event);
    }
};

pub const CategoryFilter = struct {
    levels: [category_slots]Level,

    pub fn init(default_level: Level) CategoryFilter {
        return .{ .levels = @as([category_slots]Level, @splat(default_level)) };
    }

    pub fn set(self: *CategoryFilter, category: Category, minimum: Level) void {
        self.levels[category.slot()] = minimum;
    }

    pub fn get(self: *const CategoryFilter, category: Category) Level {
        return self.levels[category.slot()];
    }

    pub fn enabled(self: *const CategoryFilter, category: Category, level: Level) bool {
        return self.get(category).allows(level);
    }
};

pub fn comptimeEnabled(comptime compiled_min: Level, comptime level: Level) bool {
    return compiled_min.allows(level);
}

pub fn emit(
    comptime compiled_min: Level,
    comptime level: Level,
    filter: *const CategoryFilter,
    sink: Sink,
    category: Category,
    ts_mono_ns: u64,
    hlc: Hlc,
    msg: []const u8,
    fields: []const Field,
) SinkError!void {
    if (comptime !comptimeEnabled(compiled_min, level)) return;
    if (!filter.enabled(category, level)) return;
    try sink.write(.{
        .level = level,
        .category = category,
        .ts_mono_ns = ts_mono_ns,
        .hlc = hlc,
        .msg = msg,
        .fields = fields[0..@min(fields.len, max_fields)],
    });
}

pub const RecordedValue = union(enum) {
    str: StoredStr,
    uint: u64,
    int: i64,
    bool: bool,

    pub fn toValue(self: *const RecordedValue) Value {
        return switch (self.*) {
            .str => |*s| .{ .str = s.slice() },
            .uint => |v| .{ .uint = v },
            .int => |v| .{ .int = v },
            .bool => |v| .{ .bool = v },
        };
    }
};

pub const RecordedField = struct {
    key: StoredKey = .{},
    val: RecordedValue = .{ .str = .{} },

    pub fn toField(self: *const RecordedField) Field {
        return .{ .key = self.key.slice(), .val = self.val.toValue() };
    }
};

pub const RecordedEvent = struct {
    level: Level = .debug,
    category: Category = .reactor,
    ts_mono_ns: u64 = 0,
    hlc: Hlc = 0,
    msg: StoredMsg = .{},
    fields: [max_fields]RecordedField = @splat(.{}),
    field_count: usize = 0,

    pub fn fromEvent(event: Event) RecordedEvent {
        var out = RecordedEvent{
            .level = event.level,
            .category = event.category,
            .ts_mono_ns = event.ts_mono_ns,
            .hlc = event.hlc,
            .msg = StoredMsg.fromSlice(event.msg),
        };
        out.field_count = @min(event.fields.len, max_fields);
        for (event.fields[0..out.field_count], 0..) |kv, idx| {
            out.fields[idx] = .{
                .key = StoredKey.fromSlice(kv.key),
                .val = recordValue(kv.val),
            };
        }
        return out;
    }

    pub fn message(self: *const RecordedEvent) []const u8 {
        return self.msg.slice();
    }

    pub fn field(self: *const RecordedEvent, index: usize) ?Field {
        if (index >= self.field_count) return null;
        return self.fields[index].toField();
    }
};

pub fn FlightRecorder(comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);

    return struct {
        const Self = @This();
        const Counter = std.atomic.Value(usize);

        head: Counter align(cache_line_bytes) = .init(0),
        tail: Counter align(cache_line_bytes) = .init(0),
        events: [capacity]RecordedEvent = @splat(.{}),

        pub fn init() Self {
            return .{};
        }

        pub fn sink(self: *Self) Sink {
            return Sink.init(Self, self);
        }

        pub fn write(self: *Self, event: Event) !void {
            const head = self.head.load(.monotonic);
            self.events[head % capacity] = RecordedEvent.fromEvent(event);

            const next_head = head +% 1;
            const tail = self.tail.load(.monotonic);
            if (next_head -% tail > capacity) {
                self.tail.store(next_head - capacity, .release);
            }
            self.head.store(next_head, .release);
        }

        pub fn dump(self: *const Self, out: []RecordedEvent) []const RecordedEvent {
            const head = self.head.load(.acquire);
            var tail = self.tail.load(.acquire);
            if (head -% tail > capacity) tail = head - capacity;

            const available = head -% tail;
            const count = @min(available, out.len);
            const start = head - count;
            for (out[0..count], 0..) |*slot, idx| {
                slot.* = self.events[(start + idx) % capacity];
            }
            return out[0..count];
        }

        pub fn len(self: *const Self) usize {
            const head = self.head.load(.acquire);
            const tail = self.tail.load(.acquire);
            return @min(head -% tail, capacity);
        }
    };
}

pub const RenderError = error{
    OutputTooSmall,
};

pub fn render(event: Event, out: []u8) RenderError![]const u8 {
    var writer = SliceWriter{ .buf = out };
    try writer.append("level=");
    try writer.append(event.level.token());
    try writer.append(" category=");
    try writer.append(event.category.token());
    try writer.append(" ts_mono_ns=");
    try writer.appendUnsigned(event.ts_mono_ns);
    try writer.append(" hlc=");
    try writer.appendUnsigned(event.hlc);
    try writer.append(" msg=");
    try writer.appendQuoted(event.msg);
    for (event.fields[0..@min(event.fields.len, max_fields)]) |field| {
        try writer.append(" ");
        try writer.append(field.key);
        try writer.append("=");
        try writer.appendValue(field.val);
    }
    return out[0..writer.len];
}

fn recordValue(value: Value) RecordedValue {
    return switch (value) {
        .str => |s| .{ .str = StoredStr.fromSlice(s) },
        .uint => |v| .{ .uint = v },
        .int => |v| .{ .int = v },
        .bool => |v| .{ .bool = v },
    };
}

fn Stored(comptime max_len: usize) type {
    return struct {
        const Self = @This();

        buf: [max_len]u8 = @splat(0),
        len: usize = 0,

        pub fn fromSlice(src: []const u8) Self {
            var out = Self{};
            out.len = @min(src.len, max_len);
            @memcpy(out.buf[0..out.len], src[0..out.len]);
            return out;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }
    };
}

pub const StoredKey = Stored(max_recorded_key_len);
pub const StoredStr = Stored(max_recorded_str_len);
pub const StoredMsg = Stored(max_recorded_msg_len);

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) RenderError!void {
        if (bytes.len > self.buf.len - self.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *SliceWriter, byte: u8) RenderError!void {
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    fn appendUnsigned(self: *SliceWriter, value: u64) RenderError!void {
        const written = std.fmt.bufPrint(self.buf[self.len..], "{}", .{value}) catch {
            return error.OutputTooSmall;
        };
        self.len += written.len;
    }

    fn appendSigned(self: *SliceWriter, value: i64) RenderError!void {
        const written = std.fmt.bufPrint(self.buf[self.len..], "{}", .{value}) catch {
            return error.OutputTooSmall;
        };
        self.len += written.len;
    }

    fn appendValue(self: *SliceWriter, value: Value) RenderError!void {
        switch (value) {
            .str => |s| try self.appendQuoted(s),
            .uint => |v| try self.appendUnsigned(v),
            .int => |v| try self.appendSigned(v),
            .bool => |v| try self.append(if (v) "true" else "false"),
        }
    }

    fn appendQuoted(self: *SliceWriter, bytes: []const u8) RenderError!void {
        try self.appendByte('"');
        for (bytes) |byte| {
            switch (byte) {
                '\\' => try self.append("\\\\"),
                '"' => try self.append("\\\""),
                '\n' => try self.append("\\n"),
                '\r' => try self.append("\\r"),
                '\t' => try self.append("\\t"),
                else => try self.appendByte(byte),
            }
        }
        try self.appendByte('"');
    }
};

const CaptureSink = struct {
    events: []Event,
    count: usize = 0,

    fn write(self: *CaptureSink, event: Event) !void {
        if (self.count >= self.events.len) return error.OutputTooSmall;
        self.events[self.count] = event;
        self.count += 1;
    }
};

test "emit filters by level and category" {
    _ = std.testing.allocator;
    var filter = CategoryFilter.init(.info);
    filter.set(.s2s, .warn);
    filter.set(.channel, .debug);

    var events: [4]Event = undefined;
    var capture = CaptureSink{ .events = &events };
    const sink = Sink.init(CaptureSink, &capture);

    try emit(.debug, .info, &filter, sink, .s2s, 1, 2, "quiet", &.{});
    try emit(.debug, .warn, &filter, sink, .s2s, 3, 4, "warn", &.{});
    try emit(.debug, .debug, &filter, sink, .channel, 5, 6, "debug", &.{});
    try emit(.debug, .debug, &filter, sink, .oper, 7, 8, "filtered", &.{});

    try std.testing.expectEqual(@as(usize, 2), capture.count);
    try std.testing.expectEqual(Level.warn, events[0].level);
    try std.testing.expectEqual(Category.s2s, events[0].category);
    try std.testing.expectEqualStrings("warn", events[0].msg);
    try std.testing.expectEqual(Level.debug, events[1].level);
    try std.testing.expectEqual(Category.channel, events[1].category);
}

test "flight recorder overwrites oldest and dumps last events in order" {
    const allocator = std.testing.allocator;
    var recorder = FlightRecorder(3).init();
    const filter = CategoryFilter.init(.debug);
    const sink = recorder.sink();

    try emit(.debug, .info, &filter, sink, .reactor, 1, 10, "one", &.{});
    try emit(.debug, .info, &filter, sink, .reactor, 2, 20, "two", &.{});
    try emit(.debug, .info, &filter, sink, .reactor, 3, 30, "three", &.{});
    try emit(.debug, .info, &filter, sink, .reactor, 4, 40, "four", &.{});

    const out = try allocator.alloc(RecordedEvent, 3);
    defer allocator.free(out);

    const dump = recorder.dump(out);
    try std.testing.expectEqual(@as(usize, 3), dump.len);
    try std.testing.expectEqual(@as(u64, 2), dump[0].ts_mono_ns);
    try std.testing.expectEqualStrings("two", dump[0].message());
    try std.testing.expectEqualStrings("three", dump[1].message());
    try std.testing.expectEqualStrings("four", dump[2].message());
}

test "comptime disabled level is a no-op" {
    var filter = CategoryFilter.init(.debug);
    var events: [1]Event = undefined;
    var capture = CaptureSink{ .events = &events };

    try emit(.info, .debug, &filter, Sink.init(CaptureSink, &capture), .oper, 1, 1, "drop", &.{});

    try std.testing.expect(!comptimeEnabled(.info, .debug));
    try std.testing.expectEqual(@as(usize, 0), capture.count);
}

test "kv fields render and recorder copies borrowed slices" {
    var msg_buf = [_]u8{ 'l', 'i', 'n', 'k', 'e', 'd' };
    var peer_buf = [_]u8{ 'i', 'r', 'c', 'x' };
    const fields = [_]Field{
        .{ .key = "peer", .val = .{ .str = peer_buf[0..] } },
        .{ .key = "tries", .val = .{ .uint = 2 } },
        .{ .key = "delta", .val = .{ .int = -3 } },
        .{ .key = "up", .val = .{ .bool = true } },
    };
    const event = Event{
        .level = .notice,
        .category = .s2s,
        .ts_mono_ns = 42,
        .hlc = 99,
        .msg = msg_buf[0..],
        .fields = &fields,
    };

    var rendered: [256]u8 = undefined;
    const line = try render(event, &rendered);
    try std.testing.expect(std.mem.indexOf(u8, line, "level=notice") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "category=s2s") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "msg=\"linked\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "peer=\"ircx\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "tries=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "delta=-3") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "up=true") != null);

    var recorder = FlightRecorder(2).init();
    try recorder.write(event);
    msg_buf[0] = 'X';
    peer_buf[0] = 'X';

    var out: [2]RecordedEvent = undefined;
    const dump = recorder.dump(&out);
    try std.testing.expectEqual(@as(usize, 1), dump.len);
    try std.testing.expectEqualStrings("linked", dump[0].message());
    try std.testing.expectEqual(@as(usize, 4), dump[0].field_count);
    const peer = dump[0].field(0).?;
    try std.testing.expectEqualStrings("peer", peer.key);
    try std.testing.expectEqualStrings("ircx", peer.val.str);
}
