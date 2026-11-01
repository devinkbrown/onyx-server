// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for the DNS wire parser.
const std = @import("std");
const dns = @import("dns.zig");

const seed: u64 = 0x4d495a554348_444e;
const random_iterations: usize = 1400;
const structured_iterations: usize = 700;

fn expectDecodeError(err: dns.DecodeError) !void {
    switch (err) {
        error.TruncatedMessage,
        error.OversizeMessage,
        error.InvalidName,
        error.NameTooLong,
        error.CompressionLoop,
        error.TooManyQuestions,
        error.TooManyAnswers,
        error.UnsupportedType,
        error.UnsupportedClass,
        error.UnsupportedSection,
        error.MalformedRData,
        error.TrailingBytes,
        => {},
    }
}

fn parseOkOrTypedError(input: []const u8) !void {
    const parsed = dns.parseMessage(4, 4, input) catch |err| {
        try expectDecodeError(err);
        return;
    };

    try expectMessageInvariants(parsed);
}

fn expectMessageInvariants(msg: anytype) !void {
    try std.testing.expectEqual(@as(usize, msg.header.qdcount), msg.question_count);
    // parseMessage stores only the answer record types it models (A/AAAA/PTR),
    // skipping others (e.g. CNAME), so stored answers are a subset of ancount.
    try std.testing.expect(msg.answer_count <= msg.header.ancount);
    try std.testing.expect(msg.question_count <= msg.questions.len);
    try std.testing.expect(msg.answer_count <= msg.answers.len);

    const questions = msg.questionSlice();
    const answers = msg.answerSlice();
    try expectTypedSliceWithin(dns.Question, msg.questions[0..], questions);
    try expectTypedSliceWithin(dns.ResourceRecord, msg.answers[0..], answers);

    for (questions) |*question| {
        try expectNameSliceWithin(question.name);
        try std.testing.expectEqual(dns.class_in, question.qclass);
    }

    for (answers) |*answer| {
        try expectNameSliceWithin(answer.name);
        try std.testing.expectEqual(dns.class_in, answer.class);
        switch (answer.data) {
            .ptr => |ptr_name| try expectNameSliceWithin(ptr_name),
            .a, .aaaa => {},
        }
    }
}

fn expectNameSliceWithin(name: dns.Name) !void {
    const view = name.slice();
    try std.testing.expect(view.len <= dns.max_domain_text_len);
    try expectByteSliceWithin(name.bytes[0..], view);
}

fn expectByteSliceWithin(owner: []const u8, slice: []const u8) !void {
    const owner_start = @intFromPtr(owner.ptr);
    const owner_end = owner_start + owner.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= owner_start);
    try std.testing.expect(slice_start <= owner_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= owner_end);
}

fn expectTypedSliceWithin(comptime T: type, owner: []const T, slice: []const T) !void {
    const owner_start = @intFromPtr(owner.ptr);
    const owner_end = owner_start + owner.len * @sizeOf(T);
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len * @sizeOf(T);

    try std.testing.expect(slice_start >= owner_start);
    try std.testing.expect(slice_start <= owner_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= owner_end);
}

fn randomLength(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => 11,
        3 => 12,
        4 => 13,
        5 => dns.max_message_len - 1,
        6 => dns.max_message_len,
        7 => dns.max_message_len + 1,
        else => random.uintLessThan(usize, max_len + 1),
    };
}

fn fillAttackerBytes(random: std.Random, out: []u8, iteration: usize) void {
    for (out, 0..) |*byte, i| {
        byte.* = switch (random.uintLessThan(u8, 32)) {
            0 => 0x00,
            1 => 0x01,
            2 => 0x03,
            3 => 0x3f,
            4 => 0x40,
            5 => 0x7f,
            6 => 0x80,
            7 => 0xc0,
            8 => 0xff,
            9...12 => 'a' + random.uintLessThan(u8, 26),
            13...15 => '0' + random.uintLessThan(u8, 10),
            else => random.int(u8),
        };
        if (i < 12 and iteration % 5 == 0) byte.* = 0;
    }

    if (out.len >= 12 and iteration % 5 == 0) {
        out[4] = @intCast(random.uintLessThan(u8, 5));
        out[6] = @intCast(random.uintLessThan(u8, 5));
        out[8] = 0;
        out[10] = 0;
    }
}

fn mutatePacket(random: std.Random, packet: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 17) {
        0 => 0,
        1 => 11,
        2 => 12,
        3 => packet.len - 1,
        else => packet.len,
    };

    if (len == 0) return packet[0..0];

    const edits = 1 + random.uintLessThan(usize, 8);
    var i: usize = 0;
    while (i < edits) : (i += 1) {
        const pos = random.uintLessThan(usize, len);
        packet[pos] = switch ((iteration + i) % 10) {
            0 => 0xc0,
            1 => 0x0c,
            2 => 0xff,
            3 => 0x40,
            4 => 0,
            else => random.int(u8),
        };
    }

    return packet[0..len];
}

fn writeU16(out: []u8, pos: *usize, value: u16) void {
    std.mem.writeInt(u16, out[pos.*..][0..2], value, .big);
    pos.* += 2;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}

fn writeHeader(out: []u8, pos: *usize, qdcount: u16, ancount: u16) void {
    writeU16(out, pos, 0x1234);
    writeU16(out, pos, 0x8180);
    writeU16(out, pos, qdcount);
    writeU16(out, pos, ancount);
    writeU16(out, pos, 0);
    writeU16(out, pos, 0);
}

fn writeRepeatedLabel(out: []u8, pos: *usize, len: usize, byte: u8) void {
    out[pos.*] = @intCast(len);
    pos.* += 1;
    @memset(out[pos.*..][0..len], byte);
    pos.* += len;
}

fn writeQuestionTail(out: []u8, pos: *usize, rr_type: dns.RecordType) void {
    writeU16(out, pos, @backingInt(rr_type));
    writeU16(out, pos, dns.class_in);
}

fn buildQuestionWithLabelLengths(out: []u8, lengths: []const usize) []const u8 {
    var pos: usize = 0;
    writeHeader(out, &pos, 1, 0);
    for (lengths, 0..) |len, i| {
        writeRepeatedLabel(out, &pos, len, 'a' + @as(u8, @intCast(i)));
    }
    out[pos] = 0;
    pos += 1;
    writeQuestionTail(out, &pos, .a);
    return out[0..pos];
}

fn fillTextName(out: []u8, lengths: []const usize) []const u8 {
    var pos: usize = 0;
    for (lengths, 0..) |len, i| {
        if (i != 0) {
            out[pos] = '.';
            pos += 1;
        }
        @memset(out[pos..][0..len], 'a' + @as(u8, @intCast(i)));
        pos += len;
    }
    return out[0..pos];
}

fn buildPointerLoop(out: []u8) []const u8 {
    var pos: usize = 0;
    writeHeader(out, &pos, 1, 0);
    out[pos] = 0xc0;
    out[pos + 1] = 0x0e;
    out[pos + 2] = 0xc0;
    out[pos + 3] = 0x0c;
    pos += 4;
    return out[0..pos];
}

fn buildPointerExpandedOversizeName(out: []u8) []const u8 {
    var pos: usize = 0;
    writeHeader(out, &pos, 1, 0);
    writeRepeatedLabel(out, &pos, 63, 'a');
    const target = pos + 2;
    out[pos] = 0xc0 | @as(u8, @intCast((target >> 8) & 0x3f));
    out[pos + 1] = @intCast(target & 0xff);
    pos += 2;
    writeRepeatedLabel(out, &pos, 63, 'b');
    writeRepeatedLabel(out, &pos, 63, 'c');
    writeRepeatedLabel(out, &pos, 63, 'd');
    out[pos] = 0;
    pos += 1;
    return out[0..pos];
}

fn buildCompressedResponse(out: []u8) []const u8 {
    var pos: usize = 0;
    writeHeader(out, &pos, 1, 1);
    out[pos] = 7;
    pos += 1;
    @memcpy(out[pos..][0..7], "example");
    pos += 7;
    out[pos] = 3;
    pos += 1;
    @memcpy(out[pos..][0..3], "com");
    pos += 3;
    out[pos] = 0;
    pos += 1;
    writeQuestionTail(out, &pos, .a);

    out[pos] = 0xc0;
    out[pos + 1] = 0x0c;
    pos += 2;
    writeU16(out, &pos, @backingInt(dns.RecordType.a));
    writeU16(out, &pos, dns.class_in);
    writeU32(out, &pos, 60);
    writeU16(out, &pos, 4);
    out[pos..][0..4].* = .{ 192, 0, 2, 9 };
    pos += 4;
    return out[0..pos];
}

test "parseMessage returns ok or typed errors for arbitrary attacker bytes" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x1001);
    const random = prng.random();
    var input: [dns.max_message_len + 1]u8 = undefined;

    for (0..random_iterations) |iteration| {
        const len = randomLength(random, iteration, input.len);
        fillAttackerBytes(random, input[0..len], iteration);
        try parseOkOrTypedError(input[0..len]);
    }
}

test "parseMessage handles structured corrupt packets without escaping typed errors" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x2002);
    const random = prng.random();
    var base: [dns.max_message_len]u8 = undefined;
    const response = buildCompressedResponse(&base);
    var packet: [dns.max_message_len]u8 = undefined;

    for (0..structured_iterations) |iteration| {
        @memcpy(packet[0..response.len], response);
        const mutated = mutatePacket(random, packet[0..response.len], iteration);
        try parseOkOrTypedError(mutated);
    }
}

test "compression pointers reject loops and oversized expanded names" {
    var packet: [dns.max_message_len]u8 = undefined;

    const loop = buildPointerLoop(&packet);
    try std.testing.expectError(error.CompressionLoop, dns.parseMessage(1, 0, loop));

    const oversize = buildPointerExpandedOversizeName(&packet);
    try std.testing.expectError(error.NameTooLong, dns.parseMessage(1, 0, oversize));

    const compressed = buildCompressedResponse(&packet);
    const parsed = try dns.parseMessage(1, 1, compressed);
    try std.testing.expectEqualStrings("example.com", parsed.questionSlice()[0].name.slice());
    try std.testing.expectEqualStrings("example.com", parsed.answerSlice()[0].name.slice());
    try expectMessageInvariants(parsed);
}

test "truncated valid messages return TruncatedMessage" {
    var query_buf: [dns.max_message_len]u8 = undefined;
    const query = try dns.encodeQuery(&query_buf, 0xbeef, "example.com", .a);
    for (0..query.len) |len| {
        try std.testing.expectError(error.TruncatedMessage, dns.parseMessage(1, 0, query[0..len]));
    }

    var response_buf: [dns.max_message_len]u8 = undefined;
    const response = buildCompressedResponse(&response_buf);
    for (0..response.len) |len| {
        try std.testing.expectError(error.TruncatedMessage, dns.parseMessage(1, 1, response[0..len]));
    }
}

test "label and name length boundaries are enforced" {
    var text: [dns.max_domain_text_len + 1]u8 = undefined;
    var packet: [dns.max_message_len]u8 = undefined;
    var out: [dns.max_message_len]u8 = undefined;

    const max_text = fillTextName(&text, &[_]usize{ 63, 63, 63, 61 });
    const encoded = try dns.encodeQuery(&out, 1, max_text, .a);
    const parsed_encoded = try dns.parseMessage(1, 0, encoded);
    try std.testing.expectEqualStrings(max_text, parsed_encoded.questionSlice()[0].name.slice());
    try expectMessageInvariants(parsed_encoded);

    const max_wire = buildQuestionWithLabelLengths(&packet, &[_]usize{ 63, 63, 63, 61 });
    const parsed_wire = try dns.parseMessage(1, 0, max_wire);
    try std.testing.expectEqualStrings(max_text, parsed_wire.questionSlice()[0].name.slice());

    const over_text = fillTextName(&text, &[_]usize{ 63, 63, 63, 62 });
    try std.testing.expectError(error.NameTooLong, dns.encodeQuery(&out, 1, over_text, .a));

    const over_wire = buildQuestionWithLabelLengths(&packet, &[_]usize{ 63, 63, 63, 62 });
    try std.testing.expectError(error.NameTooLong, dns.parseMessage(1, 0, over_wire));

    var long_label: [64]u8 = undefined;
    @memset(&long_label, 'x');
    try std.testing.expectError(error.NameTooLong, dns.encodeQuery(&out, 1, &long_label, .a));
}

test "public returned slices stay within caller or message storage" {
    var out: [dns.max_message_len]u8 = undefined;
    const query = try dns.encodeQuery(&out, 0x444e, "slice.test", .aaaa);
    try expectByteSliceWithin(out[0..], query);

    var ptr_out: [dns.max_domain_text_len]u8 = undefined;
    const ptr_name = try dns.reverseName(&ptr_out, .{ .ipv4 = .{ 203, 0, 113, 7 } });
    try expectByteSliceWithin(ptr_out[0..], ptr_name);

    const parsed_query = try dns.parseMessage(1, 0, query);
    try expectMessageInvariants(parsed_query);

    const q = dns.Query{ .name = "slice.test", .qtype = .a };
    const a = dns.Answer{
        .name = "slice.test",
        .rr_type = .a,
        .ttl = 30,
        .data = .{ .a = .{ 203, 0, 113, 9 } },
    };
    const response = try dns.encodeMessage(&out, .{
        .id = 0x444e,
        .response = true,
        .questions = (&q)[0..1],
        .answers = (&a)[0..1],
    });
    try expectByteSliceWithin(out[0..], response);

    const parsed_response = try dns.parseMessage(1, 1, response);
    try expectMessageInvariants(parsed_response);
}
