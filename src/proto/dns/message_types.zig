// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public fixed-capacity DNS message and query contracts.

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
