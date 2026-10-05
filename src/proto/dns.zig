// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS wire codec and resolver cache.
//!
//! The codec is intentionally transport-free: callers provide complete DNS
//! messages and output buffers. The resolver below uses the same codec for
//! blocking UDP lookups on the dedicated resolver path.
const std = @import("std");

pub const max_message_len: usize = 512;
pub const max_domain_text_len: usize = 253;
pub const max_cache_addrs: usize = 8;
pub const class_in: u16 = 1;

pub const EncodeError = error{
    OutputTooSmall,
    NameTooLong,
    InvalidName,
    TooManyQuestions,
    TooManyAnswers,
    UnsupportedType,
    TxtStringTooLong,
};

pub const DecodeError = error{
    TruncatedMessage,
    OversizeMessage,
    InvalidName,
    NameTooLong,
    CompressionLoop,
    TooManyQuestions,
    TooManyAnswers,
    UnsupportedType,
    UnsupportedClass,
    UnsupportedSection,
    MalformedRData,
    TrailingBytes,
};

pub const CacheError = error{
    TooManyAddresses,
} || std.mem.Allocator.Error;

pub const RecordType = enum(u16) {
    a = 1,
    ptr = 12,
    txt = 16,
    aaaa = 28,

    pub fn fromInt(value: u16) DecodeError!RecordType {
        return switch (value) {
            1 => .a,
            12 => .ptr,
            16 => .txt,
            28 => .aaaa,
            else => error.UnsupportedType,
        };
    }
};

pub const Header = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub fn isResponse(self: Header) bool {
        return (self.flags & 0x8000) != 0;
    }

    pub fn rcode(self: Header) u4 {
        return @intCast(self.flags & 0x000f);
    }
};

pub const Name = struct {
    bytes: [max_domain_text_len]u8 = @splat(0),
    len: usize = 0,

    pub fn fromSlice(text: []const u8) EncodeError!Name {
        if (text.len > max_domain_text_len) return error.NameTooLong;
        var name = Name{};
        @memcpy(name.bytes[0..text.len], text);
        name.len = text.len;
        return name;
    }

    pub fn slice(self: *const Name) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    fn key(self: Address) AddressKey {
        var out = AddressKey{ .family = .ipv4, .bytes = @as([16]u8, @splat(0)) };
        switch (self) {
            .ipv4 => |bytes| {
                out.family = .ipv4;
                @memcpy(out.bytes[0..4], &bytes);
            },
            .ipv6 => |bytes| {
                out.family = .ipv6;
                @memcpy(out.bytes[0..16], &bytes);
            },
        }
        return out;
    }
};

pub const Question = struct {
    name: Name,
    qtype: RecordType,
    qclass: u16 = class_in,
};

pub const RData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ptr: Name,
};

pub const ResourceRecord = struct {
    name: Name,
    rr_type: RecordType,
    class: u16,
    ttl: u32,
    data: RData,
    txt: Txt = .{},

    pub fn txtData(self: *const ResourceRecord) ?*const Txt {
        if (self.rr_type != .txt) return null;
        return &self.txt;
    }
};

pub const Query = struct {
    name: []const u8,
    qtype: RecordType,
    qclass: u16 = class_in,
};

pub const AnswerData = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    ptr: []const u8,
    txt: []const []const u8,
};

pub const Answer = struct {
    name: []const u8,
    rr_type: RecordType,
    class: u16 = class_in,
    ttl: u32,
    data: AnswerData,
};

pub const BuildMessage = struct {
    id: u16,
    response: bool = false,
    recursion_desired: bool = true,
    recursion_available: bool = false,
    rcode: u4 = 0,
    questions: []const Query = &[_]Query{},
    answers: []const Answer = &[_]Answer{},
};

pub const max_txt_rdata_len: usize = max_message_len;
pub const max_txt_character_string_len: usize = 255;

pub const Txt = struct {
    bytes: [max_txt_rdata_len]u8 = @splat(0),
    len: usize = 0,
    string_count: usize = 0,

    pub fn rdata(self: *const Txt) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn iterator(self: *const Txt) TxtIterator {
        return .{ .rdata = self.rdata() };
    }

    pub fn stringCount(self: *const Txt) usize {
        return self.string_count;
    }

    pub fn stringAt(self: *const Txt, index: usize) ?[]const u8 {
        var it = self.iterator();
        var i: usize = 0;
        while (it.next()) |part| {
            if (i == index) return part;
            i += 1;
        }
        return null;
    }
};

pub const TxtIterator = struct {
    rdata: []const u8,
    pos: usize = 0,

    pub fn next(self: *TxtIterator) ?[]const u8 {
        if (self.pos >= self.rdata.len) return null;
        const len: usize = self.rdata[self.pos];
        const start = self.pos + 1;
        const end = start + len;
        if (end > self.rdata.len) return null;
        self.pos = end;
        return self.rdata[start..end];
    }
};

pub fn Message(comptime max_questions: usize, comptime max_answers: usize) type {
    return struct {
        header: Header,
        questions: [max_questions]Question = undefined,
        question_count: usize = 0,
        answers: [max_answers]ResourceRecord = undefined,
        answer_count: usize = 0,

        pub fn questionSlice(self: *const @This()) []const Question {
            return self.questions[0..self.question_count];
        }

        pub fn answerSlice(self: *const @This()) []const ResourceRecord {
            return self.answers[0..self.answer_count];
        }
    };
}

/// Encode any supported query/response message without name compression.
pub fn encodeMessage(out: []u8, msg: BuildMessage) EncodeError![]const u8 {
    if (msg.questions.len > std.math.maxInt(u16)) return error.TooManyQuestions;
    if (msg.answers.len > std.math.maxInt(u16)) return error.TooManyAnswers;

    var w = Writer{ .buf = out };
    try w.putU16(msg.id);
    var flags: u16 = @as(u16, msg.rcode);
    if (msg.response) flags |= 0x8000;
    if (msg.recursion_desired) flags |= 0x0100;
    if (msg.recursion_available) flags |= 0x0080;
    try w.putU16(flags);
    try w.putU16(@intCast(msg.questions.len));
    try w.putU16(@intCast(msg.answers.len));
    try w.putU16(0);
    try w.putU16(0);

    for (msg.questions) |question| {
        try encodeName(&w, question.name);
        try w.putU16(@intFromEnum(question.qtype));
        try w.putU16(question.qclass);
    }

    for (msg.answers) |answer| {
        try encodeName(&w, answer.name);
        try w.putU16(@intFromEnum(answer.rr_type));
        try w.putU16(answer.class);
        try w.putU32(answer.ttl);
        const rdlen_at = w.pos;
        try w.putU16(0);
        const rdata_start = w.pos;
        switch (answer.data) {
            .a => |bytes| {
                if (answer.rr_type != .a) return error.UnsupportedType;
                try w.putBytes(&bytes);
            },
            .aaaa => |bytes| {
                if (answer.rr_type != .aaaa) return error.UnsupportedType;
                try w.putBytes(&bytes);
            },
            .ptr => |ptr| {
                if (answer.rr_type != .ptr) return error.UnsupportedType;
                try encodeName(&w, ptr);
            },
            .txt => |strings| {
                if (answer.rr_type != .txt) return error.UnsupportedType;
                try encodeTxtRData(&w, strings);
            },
        }
        std.mem.writeInt(u16, out[rdlen_at..][0..2], @intCast(w.pos - rdata_start), .big);
    }

    return out[0..w.pos];
}

/// Encode a single-question DNS query.
pub fn encodeQuery(out: []u8, id: u16, name: []const u8, qtype: RecordType) EncodeError![]const u8 {
    const question = Query{ .name = name, .qtype = qtype };
    return encodeMessage(out, .{ .id = id, .questions = (&question)[0..1] });
}

/// Encode a TXT query.
pub fn encodeTxtQuery(out: []u8, id: u16, name: []const u8) EncodeError![]const u8 {
    return encodeQuery(out, id, name, .txt);
}

/// Encode a PTR query for an IPv4 or IPv6 reverse-DNS name.
pub fn encodePtrQuery(out: []u8, id: u16, address: Address) EncodeError![]const u8 {
    var name_buf: [max_domain_text_len]u8 = undefined;
    const name = try reverseName(&name_buf, address);
    return encodeQuery(out, id, name, .ptr);
}

/// Parse a DNS message into fixed-capacity caller-selected storage.
pub fn parseMessage(
    comptime max_questions: usize,
    comptime max_answers: usize,
    packet: []const u8,
) DecodeError!Message(max_questions, max_answers) {
    if (packet.len > max_message_len) return error.OversizeMessage;
    if (packet.len < 12) return error.TruncatedMessage;

    const header = Header{
        .id = readU16(packet, 0),
        .flags = readU16(packet, 2),
        .qdcount = readU16(packet, 4),
        .ancount = readU16(packet, 6),
        .nscount = readU16(packet, 8),
        .arcount = readU16(packet, 10),
    };
    // Authority/additional sections are tolerated: we parse the answer section
    // and ignore the rest. This lets us extract A/AAAA records from CNAME-chained
    // or EDNS responses (recursive resolvers return the resolved address records
    // alongside CNAME records the answer section).
    if (header.qdcount > max_questions) return error.TooManyQuestions;

    var msg = Message(max_questions, max_answers){
        .header = header,
        .question_count = header.qdcount,
        .answer_count = header.ancount,
    };
    var pos: usize = 12;

    if (max_questions > 0) {
        var qi: usize = 0;
        while (qi < msg.question_count) : (qi += 1) {
            var name = Name{};
            pos = try decodeName(packet, pos, &name);
            if (pos + 4 > packet.len) return error.TruncatedMessage;
            const qtype = try RecordType.fromInt(readU16(packet, pos));
            const qclass = readU16(packet, pos + 2);
            if (qclass != class_in) return error.UnsupportedClass;
            msg.questions[qi] = .{ .name = name, .qtype = qtype, .qclass = qclass };
            pos += 4;
        }
    }

    // Walk every answer record to keep `pos` correct, but only STORE the record
    // types we model (A/AAAA/PTR/TXT). Unknown types (e.g. CNAME) are skipped, so a
    // CNAME chain still yields its terminal address records.
    var stored: usize = 0;
    var ai: usize = 0;
    while (ai < header.ancount) : (ai += 1) {
        var name = Name{};
        pos = try decodeName(packet, pos, &name);
        if (pos + 10 > packet.len) return error.TruncatedMessage;

        const raw_type = readU16(packet, pos);
        const class = readU16(packet, pos + 2);
        const ttl = readU32(packet, pos + 4);
        const rdlen = readU16(packet, pos + 8);
        pos += 10;
        if (pos + rdlen > packet.len) return error.TruncatedMessage;
        const rdata_start = pos;
        const rdata_end = pos + rdlen;
        pos = rdata_end;

        const rr_type = RecordType.fromInt(raw_type) catch continue; // skip unknown (CNAME, ...)
        if (class != class_in) continue;
        if (max_answers == 0 or stored >= max_answers) continue;

        var txt = Txt{};
        const data = switch (rr_type) {
            .a => blk: {
                if (rdlen != 4) return error.MalformedRData;
                break :blk RData{ .a = packet[rdata_start..][0..4].* };
            },
            .aaaa => blk: {
                if (rdlen != 16) return error.MalformedRData;
                break :blk RData{ .aaaa = packet[rdata_start..][0..16].* };
            },
            .ptr => blk: {
                var ptr_name = Name{};
                const ptr_next = try decodeName(packet, rdata_start, &ptr_name);
                if (ptr_next != rdata_end) return error.MalformedRData;
                break :blk RData{ .ptr = ptr_name };
            },
            .txt => blk: {
                try decodeTxtRData(packet[rdata_start..rdata_end], &txt);
                break :blk RData{ .ptr = .{} };
            },
        };

        msg.answers[stored] = .{
            .name = name,
            .rr_type = rr_type,
            .class = class,
            .ttl = ttl,
            .data = data,
            .txt = txt,
        };
        stored += 1;
    }
    msg.answer_count = stored;

    return msg;
}

/// Build the canonical reverse-DNS name for an address into caller storage.
pub fn reverseName(out: []u8, address: Address) EncodeError![]const u8 {
    var w = Writer{ .buf = out };
    switch (address) {
        .ipv4 => |bytes| {
            try w.print("{d}.{d}.{d}.{d}.in-addr.arpa", .{ bytes[3], bytes[2], bytes[1], bytes[0] });
        },
        .ipv6 => |bytes| {
            const hex = "0123456789abcdef";
            var i: usize = 16;
            while (i > 0) {
                i -= 1;
                const b = bytes[i];
                try w.putByte(hex[b & 0x0f]);
                try w.putByte('.');
                try w.putByte(hex[b >> 4]);
                try w.putByte('.');
            }
            try w.putBytes("ip6.arpa");
        },
    }
    return out[0..w.pos];
}

pub const HostCacheEntry = struct {
    addrs: [max_cache_addrs]Address = undefined,
    addrs_len: usize = 0,
    expires_ms: i64 = 0,

    pub fn addressSlice(self: *const HostCacheEntry) []const Address {
        return self.addrs[0..self.addrs_len];
    }
};

pub const PtrCacheEntry = struct {
    ptr: []const u8,
    expires_ms: i64,
};

/// TTL cache for forward and reverse resolver results.
pub const Cache = struct {
    allocator: std.mem.Allocator,
    hosts: std.StringHashMap(HostCacheEntry),
    ptrs: std.AutoHashMap(AddressKey, PtrCacheEntry),

    pub fn init(allocator: std.mem.Allocator) Cache {
        return .{
            .allocator = allocator,
            .hosts = std.StringHashMap(HostCacheEntry).init(allocator),
            .ptrs = std.AutoHashMap(AddressKey, PtrCacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Cache) void {
        var hit = self.hosts.iterator();
        while (hit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.hosts.deinit();

        var pit = self.ptrs.iterator();
        while (pit.next()) |entry| {
            self.allocator.free(entry.value_ptr.ptr);
        }
        self.ptrs.deinit();
    }

    pub fn putHost(
        self: *Cache,
        now_ms: i64,
        host: []const u8,
        addrs: []const Address,
        ttl_seconds: u32,
    ) CacheError!void {
        if (addrs.len > max_cache_addrs) return error.TooManyAddresses;

        var value = HostCacheEntry{ .addrs_len = addrs.len, .expires_ms = expiresAt(now_ms, ttl_seconds) };
        for (addrs, 0..) |addr, i| value.addrs[i] = addr;

        const owned_key = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_key);

        const gop = try self.hosts.getOrPut(owned_key);
        if (gop.found_existing) {
            self.allocator.free(owned_key);
            gop.value_ptr.* = value;
            return;
        }
        gop.value_ptr.* = value;
    }

    pub fn getHost(self: *Cache, now_ms: i64, host: []const u8) ?HostCacheEntry {
        const entry = self.hosts.getEntry(host) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const owned_key = entry.key_ptr.*;
            _ = self.hosts.remove(owned_key);
            self.allocator.free(owned_key);
            return null;
        }
        return entry.value_ptr.*;
    }

    pub fn putPtr(
        self: *Cache,
        now_ms: i64,
        address: Address,
        ptr: []const u8,
        ttl_seconds: u32,
    ) CacheError!void {
        const key = address.key();
        const value = PtrCacheEntry{
            .ptr = try self.allocator.dupe(u8, ptr),
            .expires_ms = expiresAt(now_ms, ttl_seconds),
        };
        errdefer self.allocator.free(value.ptr);

        const gop = try self.ptrs.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.ptr);
            gop.value_ptr.* = value;
            return;
        }
        gop.value_ptr.* = value;
    }

    pub fn getPtr(self: *Cache, now_ms: i64, address: Address) ?[]const u8 {
        const key = address.key();
        const entry = self.ptrs.getEntry(key) orelse return null;
        if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
            const removed = self.ptrs.fetchRemove(key).?;
            self.allocator.free(removed.value.ptr);
            return null;
        }
        return entry.value_ptr.ptr;
    }

    pub fn pruneExpired(self: *Cache, now_ms: i64) void {
        var host_keys: [32][]const u8 = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.hosts.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    host_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == host_keys.len) break;
                }
            }
            if (count == 0) break;
            for (host_keys[0..count]) |key| {
                _ = self.hosts.remove(key);
                self.allocator.free(key);
            }
        }

        var ptr_keys: [32]AddressKey = undefined;
        while (true) {
            var count: usize = 0;
            var it = self.ptrs.iterator();
            while (it.next()) |entry| {
                if (isExpired(now_ms, entry.value_ptr.expires_ms)) {
                    ptr_keys[count] = entry.key_ptr.*;
                    count += 1;
                    if (count == ptr_keys.len) break;
                }
            }
            if (count == 0) break;
            for (ptr_keys[0..count]) |key| {
                const removed = self.ptrs.fetchRemove(key).?;
                self.allocator.free(removed.value.ptr);
            }
        }
    }
};

const AddressFamily = enum { ipv4, ipv6 };

const AddressKey = struct {
    family: AddressFamily,
    bytes: [16]u8,
};

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn putByte(self: *Writer, byte: u8) EncodeError!void {
        if (self.pos >= self.buf.len) return error.OutputTooSmall;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    fn putBytes(self: *Writer, bytes: []const u8) EncodeError!void {
        if (self.pos + bytes.len > self.buf.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn putU16(self: *Writer, value: u16) EncodeError!void {
        if (self.pos + 2 > self.buf.len) return error.OutputTooSmall;
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn putU32(self: *Writer, value: u32) EncodeError!void {
        if (self.pos + 4 > self.buf.len) return error.OutputTooSmall;
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn print(self: *Writer, comptime fmt: []const u8, args: anytype) EncodeError!void {
        const written = std.fmt.bufPrint(self.buf[self.pos..], fmt, args) catch return error.OutputTooSmall;
        self.pos += written.len;
    }
};

fn encodeName(w: *Writer, raw_name: []const u8) EncodeError!void {
    var name = raw_name;
    if (name.len == 0) return error.InvalidName;
    if (name.len == 1 and name[0] == '.') {
        try w.putByte(0);
        return;
    }
    if (name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    if (name.len == 0 or name.len > max_domain_text_len) return error.NameTooLong;

    var wire_len: usize = 1;
    var cursor: usize = 0;
    while (cursor <= name.len) {
        const next = findByte(name, cursor, '.') orelse name.len;
        if (next == cursor) return error.InvalidName;
        const label = name[cursor..next];
        if (label.len > 63) return error.NameTooLong;
        for (label) |ch| {
            if (!isLabelByte(ch)) return error.InvalidName;
        }
        wire_len += 1 + label.len;
        if (wire_len > 255) return error.NameTooLong;
        try w.putByte(@intCast(label.len));
        try w.putBytes(label);
        if (next == name.len) break;
        cursor = next + 1;
    }
    try w.putByte(0);
}

fn decodeName(packet: []const u8, start: usize, out: *Name) DecodeError!usize {
    if (start >= packet.len) return error.TruncatedMessage;

    var seen = @as([max_message_len]bool, @splat(false));
    var cursor = start;
    var next_offset: ?usize = null;
    var wire_len: usize = 0;
    var text_len: usize = 0;

    while (true) {
        if (cursor >= packet.len) return error.TruncatedMessage;
        if (seen[cursor]) return error.CompressionLoop;
        seen[cursor] = true;

        const len = packet[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.len) return error.TruncatedMessage;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[cursor + 1];
            if (ptr >= packet.len) return error.InvalidName;
            if (next_offset == null) next_offset = cursor + 2;
            wire_len += 2;
            if (wire_len > 255) return error.NameTooLong;
            cursor = ptr;
            continue;
        }
        if ((len & 0xc0) != 0) return error.InvalidName;

        cursor += 1;
        wire_len += 1 + len;
        if (wire_len > 255) return error.NameTooLong;
        if (len == 0) {
            if (text_len == 0) {
                out.bytes[0] = '.';
                out.len = 1;
            } else {
                out.len = text_len;
            }
            return next_offset orelse cursor;
        }
        if (len > 63) return error.NameTooLong;
        if (cursor + len > packet.len) return error.TruncatedMessage;
        for (packet[cursor..][0..len]) |ch| {
            if (!isLabelByte(ch)) return error.InvalidName;
        }

        if (text_len != 0) {
            if (text_len >= out.bytes.len) return error.NameTooLong;
            out.bytes[text_len] = '.';
            text_len += 1;
        }
        if (text_len + len > out.bytes.len) return error.NameTooLong;
        @memcpy(out.bytes[text_len..][0..len], packet[cursor..][0..len]);
        text_len += len;
        cursor += len;
    }
}

fn isLabelByte(ch: u8) bool {
    return switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

fn findByte(bytes: []const u8, start: usize, needle: u8) ?usize {
    var cursor = start;
    while (cursor < bytes.len) : (cursor += 1) {
        if (bytes[cursor] == needle) return cursor;
    }
    return null;
}

fn encodeTxtRData(w: *Writer, strings: []const []const u8) EncodeError!void {
    for (strings) |s| {
        if (s.len > max_txt_character_string_len) return error.TxtStringTooLong;
        try w.putByte(@intCast(s.len));
        try w.putBytes(s);
    }
}

fn decodeTxtRData(rdata: []const u8, out: *Txt) DecodeError!void {
    if (rdata.len > out.bytes.len) return error.MalformedRData;

    var pos: usize = 0;
    var count: usize = 0;
    while (pos < rdata.len) {
        const len: usize = rdata[pos];
        const start = pos + 1;
        const end = start + len;
        if (end > rdata.len) return error.MalformedRData;
        count += 1;
        pos = end;
    }

    @memcpy(out.bytes[0..rdata.len], rdata);
    out.len = rdata.len;
    out.string_count = count;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .big);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .big);
}

fn expiresAt(now_ms: i64, ttl_seconds: u32) i64 {
    return now_ms + @as(i64, @intCast(ttl_seconds)) * 1000;
}

fn isExpired(now_ms: i64, expires_ms: i64) bool {
    return now_ms >= expires_ms;
}

// ===========================================================================
// Live resolver — UDP transport + forward / reverse / forward-confirmed rDNS.
//
// The wire codec above is transport-free; this section adds a blocking UDP
// resolver suitable for a dedicated resolver thread (the daemon never blocks
// its io_uring loop on DNS). Reverse lookups feed the cloak/host pipeline, and
// `resolveConfirmed` implements forward-confirmed reverse DNS (FCrDNS): a PTR
// hostname is only trusted once it forward-resolves back to the same IP, which
// defeats PTR spoofing (an attacker controlling only their own reverse zone
// cannot forge a hostname that maps elsewhere).
// ===========================================================================

const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

// Native Windows DNS configuration and UDP transport. These are direct Win32
// ABI declarations; no libc resolver or process-global DNS search path is used.
const win = struct {
    const invalid_socket = std.math.maxInt(usize);
    const af_unspec: u32 = 0;
    const af_inet: u16 = 2;
    const af_inet6: u16 = 23;
    const sock_dgram: i32 = 2;
    const ipproto_udp: i32 = 17;
    const sol_socket: i32 = 0xffff;
    const so_rcvtimeo: i32 = 0x1006;
    const so_sndtimeo: i32 = 0x1005;
    const error_buffer_overflow: u32 = 111;
    const max_adapter_bytes: usize = 256 * 1024;

    const SocketAddress = extern struct {
        sockaddr: ?*const anyopaque,
        length: i32,
    };
    const DnsServerAddress = extern struct {
        length: u32,
        reserved: u32,
        next: ?*DnsServerAddress,
        address: SocketAddress,
    };
    const AdapterAddresses = extern struct {
        length: u32,
        if_index: u32,
        next: ?*AdapterAddresses,
        adapter_name: ?[*:0]const u8,
        first_unicast: ?*anyopaque,
        first_anycast: ?*anyopaque,
        first_multicast: ?*anyopaque,
        first_dns: ?*DnsServerAddress,
    };
    const SockAddr4 = extern struct {
        family: u16,
        port: u16,
        addr: [4]u8,
        zero: [8]u8 = @splat(0),
    };
    const SockAddr6 = extern struct {
        family: u16,
        port: u16,
        flowinfo: u32 = 0,
        addr: [16]u8,
        scope_id: u32 = 0,
    };

    comptime {
        if (@sizeOf(AdapterAddresses) != 56 or @offsetOf(AdapterAddresses, "first_dns") != 48 or
            @sizeOf(DnsServerAddress) != 32 or @sizeOf(SockAddr4) != 16 or @sizeOf(SockAddr6) != 28)
            @compileError("Windows DNS socket ABI shape changed");
    }

    extern "iphlpapi" fn GetAdaptersAddresses(family: u32, flags: u32, reserved: ?*anyopaque, adapters: ?*AdapterAddresses, size: *u32) callconv(.winapi) u32;
    extern "ws2_32" fn WSAStartup(version_requested: u16, data: *anyopaque) callconv(.winapi) i32;
    extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;
    extern "ws2_32" fn WSASocketW(family: i32, socket_type: i32, protocol: i32, protocol_info: ?*anyopaque, group: u32, flags: u32) callconv(.winapi) usize;
    extern "ws2_32" fn closesocket(socket: usize) callconv(.winapi) i32;
    extern "ws2_32" fn bind(socket: usize, address: *const SockAddr4, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn getsockname(socket: usize, address: *SockAddr4, address_len: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn connect(socket: usize, address: *const anyopaque, address_len: i32) callconv(.winapi) i32;
    extern "ws2_32" fn setsockopt(socket: usize, level: i32, option: i32, value: *const anyopaque, length: i32) callconv(.winapi) i32;
    extern "ws2_32" fn send(socket: usize, bytes: [*]const u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recv(socket: usize, bytes: [*]u8, length: i32, flags: i32) callconv(.winapi) i32;
    extern "ws2_32" fn recvfrom(socket: usize, bytes: [*]u8, length: i32, flags: i32, from: *SockAddr4, from_length: *i32) callconv(.winapi) i32;
    extern "ws2_32" fn sendto(socket: usize, bytes: [*]const u8, length: i32, flags: i32, to: *const SockAddr4, to_length: i32) callconv(.winapi) i32;
};

pub const max_nameservers: usize = 4;

pub const ResolveError = error{
    NoNameservers,
    SocketUnavailable,
    SendFailed,
    Timeout,
    IdMismatch,
    ServerFailure,
    NameError,
    NoData,
    RandomSourceFailed,
} || EncodeError || DecodeError;

/// Resolver settings: the nameserver list (UDP) plus timeout/retry policy.
pub const ResolverConfig = struct {
    nameservers: [max_nameservers]Address = undefined,
    /// IPv6 link-local DNS servers require the adapter's scope ID on Windows.
    nameserver_scope_ids: [max_nameservers]u32 = @splat(0),
    nameserver_count: usize = 0,
    port: u16 = 53,
    timeout_ms: u32 = 2000,
    attempts: u8 = 2,

    pub fn addNameserver(self: *ResolverConfig, addr: Address) void {
        if (self.nameserver_count >= max_nameservers) return;
        self.nameservers[self.nameserver_count] = addr;
        self.nameserver_scope_ids[self.nameserver_count] = 0;
        self.nameserver_count += 1;
    }

    fn addSystemNameserver(self: *ResolverConfig, addr: Address, scope_id: u32) void {
        for (self.nsSlice(), 0..) |existing, index| {
            if (addressEql(existing, addr) and self.nameserver_scope_ids[index] == scope_id) return;
        }
        if (self.nameserver_count >= max_nameservers) return;
        self.nameservers[self.nameserver_count] = addr;
        self.nameserver_scope_ids[self.nameserver_count] = scope_id;
        self.nameserver_count += 1;
    }

    pub fn nsSlice(self: *const ResolverConfig) []const Address {
        return self.nameservers[0..self.nameserver_count];
    }
};

/// Parse an IPv4 or IPv6 literal into an Address (null on malformed input).
pub fn parseIpLiteral(text: []const u8) ?Address {
    const net = std.Io.net;
    if (net.IpAddress.parseIp4(text, 0)) |addr| {
        return Address{ .ipv4 = addr.ip4.bytes };
    } else |_| {}
    if (net.IpAddress.parseIp6(text, 0)) |addr| {
        return Address{ .ipv6 = addr.ip6.bytes };
    } else |_| {}
    return null;
}

/// Parse `nameserver` directives out of resolv.conf text into `cfg`. IPv4 and
/// IPv6 literals are recognized; comments and other directives are ignored.
/// Returns the total nameserver count now held by `cfg`.
pub fn parseResolvConf(text: []const u8, cfg: *ResolverConfig) usize {
    var it = std.mem.tokenizeAny(u8, text, "\r\n");
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (!std.mem.startsWith(u8, line, "nameserver")) continue;
        const rest = std.mem.trim(u8, line["nameserver".len..], " \t");
        if (rest.len == 0 or rest.len == line.len) continue; // need whitespace after keyword
        // Strip an optional %zone / trailing comment token.
        var field = rest;
        if (std.mem.indexOfAny(u8, field, " \t#;%")) |cut| field = field[0..cut];
        if (parseIpLiteral(field)) |addr| cfg.addNameserver(addr);
    }
    return cfg.nameserver_count;
}

/// Build a resolver config from the host's configured DNS servers. Windows
/// fails closed when adapter discovery is unavailable; POSIX retains its
/// historical resolv.conf and public-resolver fallback.
pub fn systemResolverConfig() ResolverConfig {
    var cfg = ResolverConfig{};
    if (comptime builtin.os.tag == .windows) {
        windowsSystemNameservers(&cfg);
        return cfg;
    }
    var buf: [8192]u8 = undefined;
    if (readFileZ("/etc/resolv.conf", &buf)) |contents| {
        _ = parseResolvConf(contents, &cfg);
    }
    if (cfg.nameserver_count == 0) {
        cfg.addNameserver(.{ .ipv4 = .{ 1, 1, 1, 1 } });
        cfg.addNameserver(.{ .ipv4 = .{ 8, 8, 8, 8 } });
    }
    return cfg;
}

fn windowsSystemNameservers(cfg: *ResolverConfig) void {
    if (comptime builtin.os.tag != .windows) return;
    var bytes_needed: u32 = 0;
    if (win.GetAdaptersAddresses(win.af_unspec, 0, null, null, &bytes_needed) != win.error_buffer_overflow or
        bytes_needed < @sizeOf(win.AdapterAddresses) or bytes_needed > win.max_adapter_bytes) return;
    const bytes = std.heap.page_allocator.alignedAlloc(u8, .@"8", @intCast(bytes_needed)) catch return;
    defer std.heap.page_allocator.free(bytes);
    var actual_size = bytes_needed;
    const first: *win.AdapterAddresses = @ptrCast(bytes.ptr);
    if (win.GetAdaptersAddresses(win.af_unspec, 0, null, first, &actual_size) != 0 or
        @as(usize, actual_size) > bytes.len) return;
    const filled = bytes[0..@intCast(actual_size)];

    var adapter: ?*win.AdapterAddresses = first;
    var adapter_count: usize = 0;
    while (adapter) |item| : (adapter_count += 1) {
        if (adapter_count == 128 or cfg.nameserver_count == max_nameservers or
            !windowsPointerInBuffer(win.AdapterAddresses, item, filled) or
            item.length < @sizeOf(win.AdapterAddresses)) break;
        var server = item.first_dns;
        var server_count: usize = 0;
        while (server) |dns_server| : (server_count += 1) {
            if (server_count == 128 or cfg.nameserver_count == max_nameservers or
                !windowsPointerInBuffer(win.DnsServerAddress, dns_server, filled) or
                dns_server.length < @sizeOf(win.DnsServerAddress)) break;
            if (dns_server.address.sockaddr) |raw| {
                if (dns_server.address.length >= @sizeOf(u16) and
                    windowsPointerInBuffer(u16, raw, filled))
                {
                    const family: *const u16 = @ptrCast(@alignCast(raw));
                    if (family.* == win.af_inet and dns_server.address.length >= @sizeOf(win.SockAddr4) and
                        windowsPointerInBuffer(win.SockAddr4, raw, filled))
                    {
                        const addr: *const win.SockAddr4 = @ptrCast(@alignCast(raw));
                        if (windowsAddressNonzero(&addr.addr))
                            cfg.addSystemNameserver(.{ .ipv4 = addr.addr }, 0);
                    } else if (family.* == win.af_inet6 and dns_server.address.length >= @sizeOf(win.SockAddr6) and
                        windowsPointerInBuffer(win.SockAddr6, raw, filled))
                    {
                        const addr: *const win.SockAddr6 = @ptrCast(@alignCast(raw));
                        if (windowsAddressNonzero(&addr.addr))
                            cfg.addSystemNameserver(.{ .ipv6 = addr.addr }, addr.scope_id);
                    }
                }
            }
            server = dns_server.next;
        }
        adapter = item.next;
    }
}

fn windowsPointerInBuffer(comptime T: type, ptr: *const anyopaque, bytes: []const u8) bool {
    const start = @intFromPtr(bytes.ptr);
    const current = @intFromPtr(ptr);
    return bytes.len >= @sizeOf(T) and current >= start and current - start <= bytes.len - @sizeOf(T) and
        current % @alignOf(T) == 0;
}

fn windowsAddressNonzero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return true;
    return false;
}

/// Read a small file into `buf` (no allocator / Io dependency), or null on error.
/// Linux `open` is syscall 2. That number is `fork` on FreeBSD, so this uses
/// the target POSIX open rather than `std.os.linux`.
fn readFileZ(path: [*:0]const u8, buf: []u8) ?[]u8 {
    if (comptime builtin.os.tag == .windows) return null;
    const fd = posix.openatZ(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return null;
    defer _ = posix.system.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const got = posix.read(fd, buf[total..]) catch return null;
        if (got == 0) break;
        total += got;
    }
    return buf[0..total];
}

fn randomIdHost() ResolveError!u16 {
    switch (builtin.os.tag) {
        .linux => return error.RandomSourceFailed,
        .windows => {
            var bytes: [2]u8 = undefined;
            @import("../substrate/platform.zig").fillOsEntropy(&bytes) catch return error.RandomSourceFailed;
            const id = std.mem.readInt(u16, &bytes, .little);
            return if (id == 0) 1 else id;
        },
        else => {
            var b: [2]u8 = undefined;
            std.c.arc4random_buf(&b, b.len);
            const id = std.mem.readInt(u16, &b, .little);
            return if (id == 0) 1 else id;
        },
    }
}

fn addressEql(a: Address, b: Address) bool {
    return switch (a) {
        .ipv4 => |x| switch (b) {
            .ipv4 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
        .ipv6 => |x| switch (b) {
            .ipv6 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
    };
}

fn trimRootDot(name: []const u8) []const u8 {
    if (name.len > 1 and name[name.len - 1] == '.') return name[0 .. name.len - 1];
    return name;
}

pub fn namesEqual(a: []const u8, b: []const u8) bool {
    const left = trimRootDot(a);
    const right = trimRootDot(b);
    if (left.len != right.len) return false;
    for (left, right) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

pub fn responseMatchesQuestion(
    comptime max_questions: usize,
    comptime max_answers: usize,
    msg: *const Message(max_questions, max_answers),
    name: []const u8,
    qtype: RecordType,
) bool {
    if (!msg.header.isResponse()) return false;
    if (msg.question_count != 1) return false;
    const q = msg.questions[0];
    return q.qclass == class_in and q.qtype == qtype and namesEqual(q.name.slice(), name);
}

pub fn rrMatchesQuestion(rr: ResourceRecord, name: []const u8, qtype: RecordType) bool {
    return rr.class == class_in and rr.rr_type == qtype and namesEqual(rr.name.slice(), name);
}

/// Validate the answer section's bounded CNAME chain against the original
/// question. parseMessage intentionally drops CNAME records, so their ownership
/// must be checked on the original wire before accepting a canonical address.
pub fn responseAnswersFollowCnames(comptime max_addresses: usize, packet: []const u8, name: []const u8, qtype: RecordType) bool {
    if (packet.len < 12 or packet.len > max_message_len or readU16(packet, 4) != 1) return false;
    const Alias = struct { owner: Name, target: Name };
    var aliases: [16]Alias = undefined;
    var alias_n: usize = 0;
    var owners: [max_addresses]Name = undefined;
    var owner_n: usize = 0;
    var question = Name{};
    var pos = decodeName(packet, 12, &question) catch return false;
    if (pos + 4 > packet.len or !namesEqual(question.slice(), name) or readU16(packet, pos) != @intFromEnum(qtype) or readU16(packet, pos + 2) != class_in) return false;
    pos += 4;
    for (0..readU16(packet, 6)) |_| {
        var owner = Name{};
        pos = decodeName(packet, pos, &owner) catch return false;
        if (pos + 10 > packet.len) return false;
        const typ = readU16(packet, pos);
        const class = readU16(packet, pos + 2);
        const rdlen = readU16(packet, pos + 8);
        pos += 10;
        if (rdlen > packet.len - pos) return false;
        const end = pos + rdlen;
        if (typ == 5) {
            if (class != class_in or alias_n == aliases.len) return false;
            var target = Name{};
            if ((decodeName(packet, pos, &target) catch return false) != end) return false;
            aliases[alias_n] = .{ .owner = owner, .target = target };
            alias_n += 1;
        } else if (typ == @intFromEnum(qtype)) {
            if (class != class_in or owner_n == owners.len) return false;
            owners[owner_n] = owner;
            owner_n += 1;
        } else if (RecordType.fromInt(typ)) |_| {
            return false;
        } else |_| {}
        pos = end;
    }
    var current = Name.fromSlice(name) catch return false;
    var visited: [16]bool = @splat(false);
    var traversed: usize = 0;
    while (true) {
        var next: ?usize = null;
        for (aliases[0..alias_n], 0..) |alias, i| {
            if (!namesEqual(alias.owner.slice(), current.slice())) continue;
            // Repeated owner or cycle is ambiguous and fails closed.
            if (next != null or visited[i]) return false;
            next = i;
        }
        const idx = next orelse break;
        visited[idx] = true;
        traversed += 1;
        current = aliases[idx].target;
    }
    if (traversed != alias_n or owner_n == 0) return false;
    for (owners[0..owner_n]) |owner| if (!namesEqual(owner.slice(), current.slice())) return false;
    return true;
}

fn responseAnswersInBailiwick(
    comptime max_questions: usize,
    comptime max_answers: usize,
    msg: *const Message(max_questions, max_answers),
    name: []const u8,
    qtype: RecordType,
) bool {
    for (msg.answerSlice()) |rr| {
        if (!rrMatchesQuestion(rr, name, qtype)) return false;
    }
    return true;
}

/// Pure FCrDNS decision: is `address` present in a PTR name's forward A/AAAA set?
pub fn forwardConfirms(address: Address, forward_addrs: []const Address) bool {
    for (forward_addrs) |a| {
        if (addressEql(a, address)) return true;
    }
    return false;
}

/// Send one query to a single nameserver over a blocking, recv-timeout UDP
/// socket and return the raw response bytes (a slice of `recv_buf`).
fn queryServer(ns: Address, scope_id: u32, port: u16, query: []const u8, recv_buf: []u8, timeout_ms: u32) ResolveError![]const u8 {
    switch (builtin.os.tag) {
        .windows => return queryServerWindows(ns, scope_id, port, query, recv_buf, timeout_ms),
        .linux => {
            const family: u32 = switch (ns) {
                .ipv4 => posix.AF.INET,
                .ipv6 => posix.AF.INET6,
            };
            const rc = linux.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, linux.IPPROTO.UDP);
            if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
            const fd: linux.fd_t = @intCast(rc);
            defer _ = linux.close(fd);

            const tv = linux.timeval{ .sec = @intCast(timeout_ms / 1000), .usec = @intCast((timeout_ms % 1000) * 1000) };
            _ = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

            switch (ns) {
                .ipv4 => |b| {
                    var sa = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(b) };
                    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
                        return error.SendFailed;
                },
                .ipv6 => |b| {
                    var sa = linux.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = b, .scope_id = 0 };
                    if (posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6))) != .SUCCESS)
                        return error.SendFailed;
                },
            }

            const sent = linux.sendto(fd, query.ptr, query.len, 0, null, 0);
            if (posix.errno(sent) != .SUCCESS) return error.SendFailed;

            const got = linux.recvfrom(fd, recv_buf.ptr, recv_buf.len, 0, null, null);
            if (posix.errno(got) != .SUCCESS) return error.Timeout;
            return recv_buf[0..@intCast(got)];
        },
        .openbsd => {
            const sys = posix.system;
            const family: c_uint = if (ns == .ipv4) posix.AF.INET else posix.AF.INET6;
            const fd = sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
            if (posix.errno(fd) != .SUCCESS) return error.SocketUnavailable;
            defer _ = sys.close(fd);
            const finite_ms = @max(timeout_ms, 1);
            const tv = sys.timeval{ .sec = @intCast(finite_ms / 1000), .usec = @intCast((finite_ms % 1000) * 1000) };
            if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))) != .SUCCESS or
                posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))) != .SUCCESS) return error.SocketUnavailable;
            const connected = switch (ns) {
                .ipv4 => |bytes| blk: {
                    var addr = posix.sockaddr.in{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(bytes) };
                    break :blk sys.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
                },
                .ipv6 => |bytes| blk: {
                    var addr = posix.sockaddr.in6{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = bytes, .scope_id = 0 };
                    break :blk sys.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
                },
            };
            if (posix.errno(connected) != .SUCCESS) return error.SendFailed;
            const sent = sys.sendto(fd, query.ptr, query.len, 0, null, 0);
            if (posix.errno(sent) != .SUCCESS or sent != query.len) return error.SendFailed;
            const received = sys.recvfrom(fd, recv_buf.ptr, recv_buf.len, 0, null, null);
            if (posix.errno(received) != .SUCCESS) return error.Timeout;
            return recv_buf[0..@intCast(received)];
        },
        else => return error.SocketUnavailable,
    }
}

fn queryServerWindows(ns: Address, scope_id: u32, port: u16, query: []const u8, recv_buf: []u8, timeout_ms: u32) ResolveError![]const u8 {
    if (comptime builtin.os.tag != .windows) return error.SocketUnavailable;
    var startup: [408]u8 align(8) = @splat(0);
    if (win.WSAStartup(0x0202, &startup) != 0) return error.SocketUnavailable;
    defer _ = win.WSACleanup();
    const family: i32 = if (ns == .ipv4) win.af_inet else win.af_inet6;
    const socket = win.WSASocketW(family, win.sock_dgram, win.ipproto_udp, null, 0, 1);
    if (socket == win.invalid_socket) return error.SocketUnavailable;
    defer _ = win.closesocket(socket);

    // SO_RCVTIMEO and SO_SNDTIMEO bound each UDP attempt, even when the caller
    // supplies zero or an arbitrarily large timeout.
    const finite_ms: u32 = @max(1, @min(timeout_ms, 5000));
    if (win.setsockopt(socket, win.sol_socket, win.so_rcvtimeo, &finite_ms, @sizeOf(u32)) != 0 or
        win.setsockopt(socket, win.sol_socket, win.so_sndtimeo, &finite_ms, @sizeOf(u32)) != 0)
        return error.SocketUnavailable;
    const connected = switch (ns) {
        .ipv4 => |bytes| blk: {
            const addr = win.SockAddr4{ .family = win.af_inet, .port = std.mem.nativeToBig(u16, port), .addr = bytes };
            break :blk win.connect(socket, &addr, @sizeOf(win.SockAddr4));
        },
        .ipv6 => |bytes| blk: {
            const addr = win.SockAddr6{ .family = win.af_inet6, .port = std.mem.nativeToBig(u16, port), .addr = bytes, .scope_id = scope_id };
            break :blk win.connect(socket, &addr, @sizeOf(win.SockAddr6));
        },
    };
    if (connected != 0) return error.SendFailed;
    const sent = win.send(socket, query.ptr, @intCast(query.len), 0);
    if (sent < 0 or @as(usize, @intCast(sent)) != query.len) return error.SendFailed;
    const received = win.recv(socket, recv_buf.ptr, @intCast(recv_buf.len), 0);
    if (received <= 0) return error.Timeout;
    return recv_buf[0..@intCast(received)];
}

/// Query every configured nameserver (round-robin over `attempts`) until one
/// returns a well-formed, id-matched, non-error answer.
fn queryAll(
    comptime maxq: usize,
    comptime maxa: usize,
    cfg: *const ResolverConfig,
    name: []const u8,
    qtype: RecordType,
    id: u16,
) ResolveError!Message(maxq, maxa) {
    if (cfg.nameserver_count == 0) return error.NoNameservers;
    var qbuf: [max_message_len]u8 = undefined;
    const query = try encodeQuery(&qbuf, id, name, qtype);
    var rbuf: [max_message_len]u8 = undefined;

    var attempt: u8 = 0;
    const attempts = if (builtin.os.tag == .windows) @min(cfg.attempts, 3) else cfg.attempts;
    while (attempt < attempts) : (attempt += 1) {
        for (cfg.nsSlice(), 0..) |ns, index| {
            const resp = queryServer(ns, cfg.nameserver_scope_ids[index], cfg.port, query, &rbuf, cfg.timeout_ms) catch continue;
            const msg = parseMessage(maxq, maxa, resp) catch continue;
            if (msg.header.id != id or msg.header.flags & 0x7a00 != 0) continue;
            if (!responseMatchesQuestion(maxq, maxa, &msg, name, qtype)) continue;
            switch (msg.header.rcode()) {
                0 => {
                    if ((qtype == .a or qtype == .aaaa) and msg.answer_count != 0) {
                        if (!responseAnswersFollowCnames(maxa, resp, name, qtype)) continue;
                    } else if (!responseAnswersInBailiwick(maxq, maxa, &msg, name, qtype)) continue;
                    return msg;
                },
                3 => return error.NameError, // NXDOMAIN — authoritative "no such name"
                else => continue, // SERVFAIL/REFUSED — try the next server
            }
        }
    }
    return error.Timeout;
}

fn randomId() ResolveError!u16 {
    // Linux getrandom is syscall 318. Off Linux that number is not getrandom.
    if (comptime builtin.os.tag != .linux) return randomIdHost();
    var b: [2]u8 = undefined;
    var filled: usize = 0;
    while (filled < b.len) {
        const rc = linux.getrandom(b[filled..].ptr, b.len - filled, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const got: usize = rc;
                if (got == 0) return error.RandomSourceFailed;
                filled += got;
            },
            .INTR => continue,
            else => return error.RandomSourceFailed,
        }
    }
    return std.mem.readInt(u16, &b, .little);
}

/// Forward-resolve `name` to A (or AAAA when `want_v6`) addresses into `out`.
pub fn resolveForward(cfg: *const ResolverConfig, name: []const u8, want_v6: bool, out: []Address) ResolveError![]Address {
    const qtype: RecordType = if (want_v6) .aaaa else .a;
    const msg = try queryAll(1, max_cache_addrs, cfg, name, qtype, try randomId());
    var n: usize = 0;
    for (msg.answerSlice()) |rr| {
        if (n >= out.len) break;
        switch (rr.data) {
            .a => |b| {
                out[n] = .{ .ipv4 = b };
                n += 1;
            },
            .aaaa => |b| {
                out[n] = .{ .ipv6 = b };
                n += 1;
            },
            else => {},
        }
    }
    if (n == 0) return error.NoData;
    return out[0..n];
}

/// Reverse-resolve `address` to its PTR hostname (no trailing dot) into `name_out`.
pub fn resolveReverse(cfg: *const ResolverConfig, address: Address, name_out: []u8) ResolveError![]const u8 {
    var qbuf: [max_domain_text_len]u8 = undefined;
    const qname = try reverseName(&qbuf, address);
    const msg = try queryAll(1, max_cache_addrs, cfg, qname, .ptr, try randomId());
    for (msg.answerSlice()) |rr| {
        if (rr.rr_type != .ptr) continue;
        const s = rr.data.ptr.slice();
        if (s.len == 0 or s.len > name_out.len) continue;
        @memcpy(name_out[0..s.len], s);
        return name_out[0..s.len];
    }
    return error.NoData;
}

/// Forward-confirmed reverse DNS. PTR(address) → name, then confirm `name`
/// forward-resolves back to `address`. Returns the trusted hostname, or null
/// when there is no PTR, no confirmation, or any lookup fails — in which case
/// the caller should fall back to the bare (cloaked) IP.
pub fn resolveConfirmed(cfg: *const ResolverConfig, address: Address, name_out: []u8) ?[]const u8 {
    const name = resolveReverse(cfg, address, name_out) catch return null;
    var fwd: [max_cache_addrs]Address = undefined;
    const addrs = resolveForward(cfg, name, address == .ipv6, &fwd) catch return null;
    return if (forwardConfirms(address, addrs)) name else null;
}

test "encodes and parses A query and response round trip" {
    var buf: [max_message_len]u8 = undefined;
    const query = try encodeQuery(&buf, 0x1234, "example.com", .a);
    const parsed_query = try parseMessage(1, 0, query);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed_query.header.id);
    try std.testing.expect(!parsed_query.header.isResponse());
    try std.testing.expectEqualStrings("example.com", parsed_query.questions[0].name.slice());
    try std.testing.expectEqual(RecordType.a, parsed_query.questions[0].qtype);

    const q = Query{ .name = "example.com", .qtype = .a };
    const answer = Answer{
        .name = "example.com",
        .rr_type = .a,
        .ttl = 60,
        .data = .{ .a = .{ 93, 184, 216, 34 } },
    };
    const response = try encodeMessage(&buf, .{
        .id = 0x1234,
        .response = true,
        .recursion_available = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });
    const parsed_response = try parseMessage(1, 1, response);
    try std.testing.expect(parsed_response.header.isResponse());
    try std.testing.expectEqual(@as(u32, 60), parsed_response.answers[0].ttl);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &parsed_response.answers[0].data.a);
}

test "encodes and parses PTR query and response round trip" {
    var buf: [max_message_len]u8 = undefined;
    const query = try encodePtrQuery(&buf, 7, .{ .ipv4 = .{ 127, 0, 0, 1 } });
    const parsed_query = try parseMessage(1, 0, query);
    try std.testing.expectEqualStrings("1.0.0.127.in-addr.arpa", parsed_query.questions[0].name.slice());
    try std.testing.expectEqual(RecordType.ptr, parsed_query.questions[0].qtype);

    const q = Query{ .name = "1.0.0.127.in-addr.arpa", .qtype = .ptr };
    const answer = Answer{
        .name = "1.0.0.127.in-addr.arpa",
        .rr_type = .ptr,
        .ttl = 300,
        .data = .{ .ptr = "localhost" },
    };
    const response = try encodeMessage(&buf, .{
        .id = 7,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });
    const parsed_response = try parseMessage(1, 1, response);
    try std.testing.expectEqualStrings("localhost", parsed_response.answers[0].data.ptr.slice());
}

test "encodes and parses TXT query and response round trip" {
    var buf: [max_message_len]u8 = undefined;
    const query = try encodeTxtQuery(&buf, 0xbeef, "2.0.0.127.dnsbl.example");
    const parsed_query = try parseMessage(1, 0, query);
    try std.testing.expectEqual(@as(u16, 0xbeef), parsed_query.header.id);
    try std.testing.expectEqualStrings("2.0.0.127.dnsbl.example", parsed_query.questions[0].name.slice());
    try std.testing.expectEqual(RecordType.txt, parsed_query.questions[0].qtype);

    const q = Query{ .name = "2.0.0.127.dnsbl.example", .qtype = .txt };
    const txt_strings = [_][]const u8{ "listed", "policy reason" };
    const answer = Answer{
        .name = "2.0.0.127.dnsbl.example",
        .rr_type = .txt,
        .ttl = 120,
        .data = .{ .txt = &txt_strings },
    };
    const response = try encodeMessage(&buf, .{
        .id = 0xbeef,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&answer)[0..1],
    });

    const parsed_response = try parseMessage(1, 1, response);
    try std.testing.expect(parsed_response.header.isResponse());
    try std.testing.expectEqual(@as(u32, 120), parsed_response.answers[0].ttl);
    try std.testing.expectEqual(RecordType.txt, parsed_response.answers[0].rr_type);
    const txt = parsed_response.answers[0].txtData().?;
    try std.testing.expectEqual(@as(usize, 2), txt.stringCount());
    try std.testing.expectEqualStrings("listed", txt.stringAt(0).?);
    try std.testing.expectEqualStrings("policy reason", txt.stringAt(1).?);
    try std.testing.expect(txt.stringAt(2) == null);

    var it = txt.iterator();
    try std.testing.expectEqualStrings("listed", it.next().?);
    try std.testing.expectEqualStrings("policy reason", it.next().?);
    try std.testing.expect(it.next() == null);
}

test "parses compressed answer name and rejects compression loops" {
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
    };
    const parsed = try parseMessage(1, 1, &packet);
    try std.testing.expectEqualStrings("example.com", parsed.answers[0].name.slice());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);

    const loop = [_]u8{
        0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    };
    try std.testing.expectError(error.CompressionLoop, parseMessage(1, 0, &loop));
}

test "skips CNAME records and returns the terminal A record" {
    // Header: id=0x1234, response, qd=1, an=2 (CNAME + A), ns=0, ar=0.
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        // question: example.com A IN
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        // answer 1: name=ptr(0x0c), type CNAME(5), IN, ttl, rdlen=2, rdata=ptr(0x0c)
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x02, 0xc0, 0x0c,
        // answer 2: name=ptr(0x0c), type A(1), IN, ttl, rdlen=4, rdata=192.0.2.1
        0xc0, 0x0c, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
    };
    const parsed = try parseMessage(1, max_cache_addrs, &packet);
    try std.testing.expectEqual(@as(usize, 1), parsed.answer_count);
    try std.testing.expectEqual(RecordType.a, parsed.answers[0].rr_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);
}

test "tolerates additional/authority records after the answer section" {
    // an=1 (A) followed by ar=1 (an A-shaped record we should ignore safely).
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
        // answer: A 192.0.2.1
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x2a, 0x00, 0x04, 192,  0,    2,    1,
        // additional: (ignored) A 203.0.113.9
           0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x04, 203,  0,    113,
        9,
    };
    const parsed = try parseMessage(1, max_cache_addrs, &packet);
    try std.testing.expectEqual(@as(usize, 1), parsed.answer_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &parsed.answers[0].data.a);
}

test "rejects truncated and oversize messages" {
    try std.testing.expectError(error.TruncatedMessage, parseMessage(1, 1, &[_]u8{ 1, 2, 3 }));

    var oversize = @as([(max_message_len + 1)]u8, @splat(0));
    try std.testing.expectError(error.OversizeMessage, parseMessage(1, 1, &oversize));

    const bad_name = [_]u8{
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't',  'e',
    };
    try std.testing.expectError(error.TruncatedMessage, parseMessage(1, 0, &bad_name));
}

test "cache returns hits and expires forward and reverse entries" {
    var cache = Cache.init(std.testing.allocator);
    defer cache.deinit();

    const addrs = [_]Address{
        .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    };
    try cache.putHost(1000, "localhost", &addrs, 2);
    const hit = cache.getHost(1999, "localhost").?;
    try std.testing.expectEqual(@as(usize, 2), hit.addrs_len);
    try std.testing.expect(cache.getHost(3000, "localhost") == null);

    try cache.putPtr(4000, addrs[0], "localhost", 1);
    try std.testing.expectEqualStrings("localhost", cache.getPtr(4999, addrs[0]).?);
    try std.testing.expect(cache.getPtr(5000, addrs[0]) == null);
}

test "parses IPv4 and IPv6 nameserver literals" {
    try std.testing.expectEqual(Address{ .ipv4 = .{ 1, 1, 1, 1 } }, parseIpLiteral("1.1.1.1").?);
    const v6 = parseIpLiteral("2001:4860:4860::8888").?;
    try std.testing.expect(v6 == .ipv6);
    try std.testing.expectEqual(@as(u8, 0x20), v6.ipv6[0]);
    try std.testing.expect(parseIpLiteral("not-an-ip") == null);
    try std.testing.expect(parseIpLiteral("999.1.1.1") == null);
}

test "systemResolverConfig bounds host DNS entries and retains the POSIX fallback" {
    const cfg = systemResolverConfig();
    if (builtin.os.tag != .windows) try std.testing.expect(cfg.nameserver_count > 0);
    try std.testing.expect(cfg.nameserver_count <= max_nameservers);
}

test "parseResolvConf extracts nameservers and ignores noise" {
    var cfg = ResolverConfig{};
    const text =
        \\# generated
        \\nameserver 8.8.8.8
        \\options ndots:1
        \\nameserver 2606:4700:4700::1111
        \\;nameserver 9.9.9.9
        \\nameserver 192.168.1.1 # router
        \\search lan
    ;
    const n = parseResolvConf(text, &cfg);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(Address{ .ipv4 = .{ 8, 8, 8, 8 } }, cfg.nameservers[0]);
    try std.testing.expect(cfg.nameservers[1] == .ipv6);
    try std.testing.expectEqual(Address{ .ipv4 = .{ 192, 168, 1, 1 } }, cfg.nameservers[2]);
}

test "ResolverConfig caps nameservers at max_nameservers" {
    var cfg = ResolverConfig{};
    var i: usize = 0;
    while (i < max_nameservers + 3) : (i += 1) cfg.addNameserver(.{ .ipv4 = .{ 10, 0, 0, @intCast(i) } });
    try std.testing.expectEqual(max_nameservers, cfg.nameserver_count);
    try std.testing.expectEqual(max_nameservers, cfg.nsSlice().len);
}

test "DNS Windows native UDP A and AAAA replies are identity checked and time bounded" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var startup: [408]u8 align(8) = @splat(0);
    try std.testing.expectEqual(@as(i32, 0), win.WSAStartup(0x0202, &startup));
    defer _ = win.WSACleanup();
    const socket = win.WSASocketW(win.af_inet, win.sock_dgram, win.ipproto_udp, null, 0, 1);
    try std.testing.expect(socket != win.invalid_socket);
    defer _ = win.closesocket(socket);
    var bind_addr = win.SockAddr4{ .family = win.af_inet, .port = 0, .addr = .{ 127, 0, 0, 1 } };
    try std.testing.expectEqual(@as(i32, 0), win.bind(socket, &bind_addr, @sizeOf(win.SockAddr4)));
    var addr_len: i32 = @sizeOf(win.SockAddr4);
    try std.testing.expectEqual(@as(i32, 0), win.getsockname(socket, &bind_addr, &addr_len));
    const timeout_ms: u32 = 1000;
    try std.testing.expectEqual(@as(i32, 0), win.setsockopt(socket, win.sol_socket, win.so_rcvtimeo, &timeout_ms, @sizeOf(u32)));

    const Responder = struct {
        socket: usize,
        served: std.atomic.Value(u32) = .{ .raw = 0 },

        fn run(self: *@This()) void {
            for (0..3) |index| {
                var query_buf: [max_message_len]u8 = undefined;
                var peer: win.SockAddr4 = undefined;
                var peer_len: i32 = @sizeOf(win.SockAddr4);
                const got = win.recvfrom(self.socket, &query_buf, @intCast(query_buf.len), 0, &peer, &peer_len);
                if (got <= 0) return;
                const parsed = parseMessage(1, 0, query_buf[0..@intCast(got)]) catch return;
                if (parsed.question_count != 1) return;
                const question = parsed.questions[0];
                const q = Query{ .name = question.name.slice(), .qtype = question.qtype };
                const data: AnswerData = switch (q.qtype) {
                    .a => .{ .a = .{ 192, 0, 2, 42 } },
                    .aaaa => .{ .aaaa = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 } },
                    else => return,
                };
                const answer = Answer{ .name = q.name, .rr_type = q.qtype, .ttl = 30, .data = data };
                var response_buf: [max_message_len]u8 = undefined;
                const response = encodeMessage(&response_buf, .{
                    .id = if (index == 2) parsed.header.id +% 1 else parsed.header.id,
                    .response = true,
                    .questions = &.{q},
                    .answers = &.{answer},
                }) catch return;
                if (win.sendto(self.socket, response.ptr, @intCast(response.len), 0, &peer, peer_len) != @as(i32, @intCast(response.len))) return;
                _ = self.served.fetchAdd(1, .acq_rel);
            }
        }
    };
    var responder = Responder{ .socket = socket };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    defer thread.join();

    var cfg = ResolverConfig{ .port = std.mem.bigToNative(u16, bind_addr.port), .timeout_ms = 500, .attempts = 1 };
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    var addresses: [max_cache_addrs]Address = undefined;
    const a = try resolveForward(&cfg, "windows-dns.test", false, &addresses);
    try std.testing.expectEqual(Address{ .ipv4 = .{ 192, 0, 2, 42 } }, a[0]);
    const aaaa = try resolveForward(&cfg, "windows-dns.test", true, &addresses);
    try std.testing.expectEqual(Address{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 } }, aaaa[0]);
    try std.testing.expectError(error.Timeout, resolveForward(&cfg, "wrong-id.test", false, &addresses));
    try std.testing.expectEqual(@as(u32, 3), responder.served.load(.acquire));

    const start_ms = @import("../substrate/platform.zig").monotonicMillis();
    try std.testing.expectError(error.Timeout, resolveForward(&cfg, "no-reply.test", false, &addresses));
    const elapsed_ms = @import("../substrate/platform.zig").monotonicMillis() - start_ms;
    try std.testing.expect(elapsed_ms >= 0 and elapsed_ms < 3000);
}

test "forwardConfirms implements the FCrDNS match (anti-spoof)" {
    const ip = Address{ .ipv4 = .{ 203, 0, 113, 7 } };
    const matching = [_]Address{ .{ .ipv4 = .{ 198, 51, 100, 1 } }, ip };
    const spoofed = [_]Address{.{ .ipv4 = .{ 198, 51, 100, 9 } }};
    try std.testing.expect(forwardConfirms(ip, &matching)); // PTR name resolves back → trust
    try std.testing.expect(!forwardConfirms(ip, &spoofed)); // forward set excludes IP → reject
    try std.testing.expect(!forwardConfirms(ip, &[_]Address{})); // no data → reject
    // Family mismatch never confirms.
    const v6 = Address{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    try std.testing.expect(!forwardConfirms(v6, &matching));
}

test "DNS CNAME answer ownership follows canonical target and rejects unrelated cycles" {
    const q = Query{ .name = "alias.test", .qtype = .a };
    var bytes: [512]u8 = undefined;
    const address = Answer{ .name = "canonical.test", .rr_type = .a, .ttl = 5, .data = .{ .a = .{ 127, 0, 0, 7 } } };
    const response = try encodeMessage(&bytes, .{ .id = 7, .response = true, .questions = &.{q}, .answers = &.{address} });
    var w = Writer{ .buf = &bytes, .pos = response.len };
    try encodeName(&w, q.name);
    try w.putU16(5);
    try w.putU16(class_in);
    try w.putU32(5);
    const rdlen_at = w.pos;
    try w.putU16(0);
    const start = w.pos;
    try encodeName(&w, "canonical.test");
    std.mem.writeInt(u16, bytes[rdlen_at..][0..2], @intCast(w.pos - start), .big);
    std.mem.writeInt(u16, bytes[6..8], 2, .big);
    try std.testing.expect(responseAnswersFollowCnames(4, bytes[0..w.pos], q.name, .a));
    // No CNAME authority means the canonical owner is unrelated to the question.
    std.mem.writeInt(u16, bytes[6..8], 1, .big);
    try std.testing.expect(!responseAnswersFollowCnames(4, bytes[0..response.len], q.name, .a));
    std.mem.writeInt(u16, bytes[6..8], 2, .big);
    // The original owner points to itself: no cyclic authority is accepted.
    var cycle = Writer{ .buf = bytes[start..] };
    try encodeName(&cycle, q.name);
    std.mem.writeInt(u16, bytes[rdlen_at..][0..2], @intCast(cycle.pos), .big);
    try std.testing.expect(!responseAnswersFollowCnames(4, bytes[0 .. start + cycle.pos], q.name, .a));
}

test "DNS native resolver forward reverse and confirmation use IPv4 and IPv6 UDP" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.SkipZigTest;
    const sys = posix.system;
    const Worker = struct {
        fd: posix.fd_t,
        count: usize = 0,
        fn run(self: *@This()) void {
            for (0..4) |_| {
                var packet: [1024]u8 = undefined;
                var peer: posix.sockaddr.storage = undefined;
                var peer_len: posix.socklen_t = @sizeOf(@TypeOf(peer));
                const got = sys.recvfrom(self.fd, &packet, packet.len, 0, @ptrCast(&peer), &peer_len);
                if (posix.errno(got) != .SUCCESS) return;
                const parsed = parseMessage(1, 0, packet[0..@intCast(got)]) catch return;
                if (parsed.question_count != 1) return;
                const q = parsed.questions[0];
                const question = Query{ .name = q.name.slice(), .qtype = q.qtype };
                var ipv6: [16]u8 = @splat(0);
                ipv6[15] = 1;
                const answer = Answer{ .name = question.name, .rr_type = q.qtype, .ttl = 5, .data = switch (q.qtype) {
                    .a => .{ .a = .{ 127, 0, 0, 7 } },
                    .aaaa => .{ .aaaa = ipv6 },
                    .ptr => .{ .ptr = "confirmed-worker.test" },
                    else => return,
                } };
                var reply_buf: [1024]u8 = undefined;
                const reply = encodeMessage(&reply_buf, .{ .id = parsed.header.id, .response = true, .questions = &.{question}, .answers = &.{answer} }) catch return;
                const sent = sys.sendto(self.fd, reply.ptr, reply.len, 0, @ptrCast(&peer), peer_len);
                if (posix.errno(sent) != .SUCCESS or sent != reply.len) return;
                self.count += 1;
            }
        }
    };
    for ([_]bool{ false, true }) |ipv6| {
        const fd_raw = sys.socket(if (ipv6) posix.AF.INET6 else posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(fd_raw));
        const fd: posix.fd_t = @intCast(fd_raw);
        defer _ = sys.close(fd);
        const tv = sys.timeval{ .sec = 1, .usec = 0 };
        try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(@TypeOf(tv)))));
        var loopback6: [16]u8 = @splat(0);
        loopback6[15] = 1;
        var port: u16 = 0;
        if (ipv6) {
            var addr = posix.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = loopback6, .scope_id = 0 };
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
            var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)));
            port = std.mem.bigToNative(u16, addr.port);
        } else {
            var addr = posix.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))));
            var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
            try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.getsockname(fd, @ptrCast(&addr), &len)));
            port = std.mem.bigToNative(u16, addr.port);
        }
        var cfg = ResolverConfig{ .port = port, .timeout_ms = 100, .attempts = 1 };
        cfg.addNameserver(if (ipv6) .{ .ipv6 = loopback6 } else .{ .ipv4 = .{ 127, 0, 0, 1 } });
        var worker = Worker{ .fd = fd };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var joined = false;
        defer if (!joined) thread.join();
        const target = if (ipv6) Address{ .ipv6 = loopback6 } else Address{ .ipv4 = .{ 127, 0, 0, 7 } };
        var addresses: [4]Address = undefined;
        const forward = try resolveForward(&cfg, "confirmed-worker.test", ipv6, &addresses);
        try std.testing.expectEqual(@as(usize, 1), forward.len);
        try std.testing.expect(addressEql(target, forward[0]));
        var host: [max_domain_text_len]u8 = undefined;
        try std.testing.expectEqualStrings("confirmed-worker.test", try resolveReverse(&cfg, target, &host));
        try std.testing.expectEqualStrings("confirmed-worker.test", resolveConfirmed(&cfg, target, &host) orelse return error.TestUnexpectedResult);
        thread.join();
        joined = true;
        try std.testing.expectEqual(@as(usize, 4), worker.count);
    }
}
