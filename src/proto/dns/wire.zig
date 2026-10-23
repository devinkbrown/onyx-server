// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport-free DNS messages, bounded name decoding, and answer ownership validation.

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
        try w.putU16(@backingInt(question.qtype));
        try w.putU16(question.qclass);
    }

    for (msg.answers) |answer| {
        try encodeName(&w, answer.name);
        try w.putU16(@backingInt(answer.rr_type));
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

pub fn addressEql(a: Address, b: Address) bool {
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
    if (pos + 4 > packet.len or !namesEqual(question.slice(), name) or readU16(packet, pos) != @backingInt(qtype) or readU16(packet, pos + 2) != class_in) return false;
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
        } else if (typ == @backingInt(qtype)) {
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

pub fn responseAnswersInBailiwick(
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
