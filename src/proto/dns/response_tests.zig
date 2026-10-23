// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Response identity, alias ownership, section framing, and DNS TTL regressions.

const std = @import("std");
const response = @import("response.zig");
const wire = @import("wire.zig");
const Packet = @import("test_packet.zig").Packet;

test "DNS response identity validates ID flags exact question and class" {
    const question = wire.Query{ .name = "Example.test.", .qtype = .a };
    var packet = try Packet.init(7, "example.test", .a);
    try packet.address("EXAMPLE.test", 30, .{ .ipv4 = .{ 192, 0, 2, 1 } });
    const result = try response.inspect(packet.slice(), 7, question);
    try std.testing.expectEqual(response.Outcome.positive, result.outcome);
    try std.testing.expectEqual(@as(usize, 1), result.address_count);
    try std.testing.expectEqual(@as(u32, 30), result.ttl_seconds);
    try std.testing.expectError(error.IdMismatch, response.inspect(packet.slice(), 8, question));
    try std.testing.expectError(error.QuestionMismatch, response.inspect(packet.slice(), 7, .{ .name = "other.test", .qtype = .a }));
    try std.testing.expectError(error.QuestionMismatch, response.inspect(packet.slice(), 7, .{ .name = question.name, .qtype = .aaaa }));
    try std.testing.expectError(error.QuestionMismatch, response.inspect(packet.slice(), 7, .{ .name = question.name, .qtype = .a, .qclass = 3 }));
    for ([_]u16{ 0x0100, 0x8980, 0x81c0 }) |flags| {
        packet.flags(flags);
        try std.testing.expectError(error.InvalidResponse, response.inspect(packet.slice(), 7, question));
    }
}

test "DNS response CNAME chain accepts reordered records and retains minimum TTL" {
    var packet = try Packet.init(7, "alias.test", .a);
    try packet.nameRecord("middle.test", 5, 20, "canonical.test");
    try packet.address("canonical.test", 90, .{ .ipv4 = .{ 192, 0, 2, 7 } });
    try packet.nameRecord("alias.test", 5, 40, "middle.test");
    const result = try response.inspect(packet.slice(), 7, .{ .name = "alias.test", .qtype = .a });
    try std.testing.expectEqualStrings("canonical.test", result.canonical_name.slice());
    try std.testing.expectEqual(@as(u32, 20), result.ttl_seconds);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 0, 2, 7 } }, result.addresses[0]);

    var alias_only = try Packet.init(8, "alias.test", .aaaa);
    try alias_only.nameRecord("alias.test", 5, 5, "canonical.test");
    const followup = try response.inspect(alias_only.slice(), 8, .{ .name = "alias.test", .qtype = .aaaa });
    try std.testing.expectEqual(response.Outcome.alias, followup.outcome);
    try std.testing.expectEqual(@as(u32, 5), followup.ttl_seconds);
}

test "DNS response rejects unrelated owners duplicate aliases and cycles" {
    const question = wire.Query{ .name = "alias.test", .qtype = .a };
    var unrelated = try Packet.init(7, question.name, .a);
    try unrelated.address("unrelated.test", 30, .{ .ipv4 = .{ 192, 0, 2, 1 } });
    try std.testing.expectError(error.InvalidOwner, response.inspect(unrelated.slice(), 7, question));
    var duplicate = try Packet.init(7, question.name, .a);
    try duplicate.nameRecord(question.name, 5, 30, "one.test");
    try duplicate.nameRecord(question.name, 5, 30, "two.test");
    try std.testing.expectError(error.AliasLoop, response.inspect(duplicate.slice(), 7, question));
    var cycle = try Packet.init(7, question.name, .a);
    try cycle.nameRecord(question.name, 5, 30, "other.test");
    try cycle.nameRecord("other.test", 5, 30, question.name);
    try std.testing.expectError(error.AliasLoop, response.inspect(cycle.slice(), 7, question));
    var detached = try Packet.init(7, question.name, .a);
    try detached.nameRecord("outside.test", 5, 30, "other.test");
    try detached.address(question.name, 30, .{ .ipv4 = .{ 192, 0, 2, 1 } });
    try std.testing.expectError(error.InvalidOwner, response.inspect(detached.slice(), 7, question));
}

test "DNS response follows PTR aliases without trusting additional addresses" {
    const question = wire.Query{ .name = "7.2.0.192.in-addr.arpa", .qtype = .ptr };
    var packet = try Packet.init(9, question.name, .ptr);
    try packet.nameRecord(question.name, 5, 10, "reverse.example");
    try packet.nameRecord("reverse.example", 12, 60, "host.example");
    try packet.record(.additional, "attacker.example", 1, 999, &.{ 192, 0, 2, 99 });
    const result = try response.inspect(packet.slice(), 9, question);
    try std.testing.expectEqualStrings("host.example", result.ptr_name.slice());
    try std.testing.expectEqual(@as(u32, 10), result.ttl_seconds);
    try std.testing.expectEqual(@as(usize, 0), result.address_count);
}

test "DNS negative TTL requires relevant SOA and obeys chain SOA and minimum lifetimes" {
    const question = wire.Query{ .name = "alias.example", .qtype = .a };
    var packet = try Packet.init(7, question.name, .a);
    packet.flags(0x8183);
    try packet.nameRecord(question.name, 5, 4, "missing.example");
    try packet.soa("example", 60, 20);
    const result = try response.inspect(packet.slice(), 7, question);
    try std.testing.expectEqual(response.Outcome.nxdomain, result.outcome);
    try std.testing.expectEqual(@as(u32, 4), result.ttl_seconds);

    var no_soa = try Packet.init(7, question.name, .a);
    no_soa.flags(0x8183);
    try std.testing.expectEqual(@as(u32, 0), (try response.inspect(no_soa.slice(), 7, question)).ttl_seconds);
    try no_soa.soa("unrelated.example", 60, 20);
    try std.testing.expectEqual(@as(u32, 0), (try response.inspect(no_soa.slice(), 7, question)).ttl_seconds);

    var nodata = try Packet.init(7, question.name, .a);
    try nodata.soa("example", 10, 40);
    const empty = try response.inspect(nodata.slice(), 7, question);
    try std.testing.expectEqual(response.Outcome.nodata, empty.outcome);
    try std.testing.expectEqual(@as(u32, 10), empty.ttl_seconds);
    nodata.flags(0x8182);
    try std.testing.expectError(error.ServerFailure, response.inspect(nodata.slice(), 7, question));
}

test "DNS truncated envelopes validate question before TCP fallback without demanding whole answers" {
    const question = wire.Query{ .name = "truncated.test", .qtype = .a };
    var packet = try Packet.init(7, question.name, .a);
    const question_end = packet.len;
    try packet.address(question.name, 30, .{ .ipv4 = .{ 192, 0, 2, 1 } });
    packet.flags(0x8380);
    const truncated = packet.bytes[0 .. packet.len - 2];
    try std.testing.expect((try response.envelope(truncated, 7, question)).truncated());
    try std.testing.expectError(error.IdMismatch, response.envelope(truncated, 8, question));
    try std.testing.expectError(error.QuestionMismatch, response.envelope(truncated, 7, .{ .name = "wrong.test", .qtype = .a }));
    try std.testing.expectError(error.TruncatedMessage, response.envelope(packet.bytes[0 .. question_end - 1], 7, question));
    try std.testing.expectError(error.InvalidResponse, response.inspect(truncated, 7, question));
}

test "DNS response validates all section framing and rejects trailing bytes and excessive records" {
    const question = wire.Query{ .name = "framing.test", .qtype = .a };
    var packet = try Packet.init(7, question.name, .a);
    try packet.address(question.name, 30, .{ .ipv4 = .{ 192, 0, 2, 1 } });
    try packet.record(.additional, "ignored.test", 46, 30, &.{ 1, 2, 3 });
    for (0..packet.len) |len| {
        if (response.inspect(packet.bytes[0..len], 7, question)) |_| return error.TestUnexpectedResult else |_| {}
    }
    _ = try response.inspect(packet.slice(), 7, question);
    packet.bytes[packet.len] = 0;
    try std.testing.expectError(error.TrailingBytes, response.inspect(packet.bytes[0 .. packet.len + 1], 7, question));
    std.mem.writeInt(u16, packet.bytes[6..8], response.max_records + 1, .big);
    try std.testing.expectError(error.TooManyRecords, response.inspect(packet.slice(), 7, question));
}

test "DNS TCP-sized responses retain answer data beyond classic UDP limit" {
    const question = wire.Query{ .name = "large.test", .qtype = .a };
    var packet = try Packet.init(7, question.name, .a);
    const ignored: [600]u8 = @splat(0);
    try packet.record(.answer, question.name, 46, 30, &ignored);
    try packet.address(question.name, 30, .{ .ipv4 = .{ 192, 0, 2, 7 } });
    try std.testing.expect(packet.len > wire.max_message_len);
    try std.testing.expectError(error.OversizeMessage, wire.parseMessage(1, 8, packet.slice()));
    const result = try response.inspect(packet.slice(), 7, question);
    try std.testing.expectEqual(wire.Address{ .ipv4 = .{ 192, 0, 2, 7 } }, result.addresses[0]);
}

test "DNS zero and invalid high-bit TTLs never acquire positive cache lifetime" {
    const question = wire.Query{ .name = "ttl.test", .qtype = .a };
    for ([_]u32{ 0, 0x80000001, 0xffffffff }) |ttl| {
        var packet = try Packet.init(7, question.name, .a);
        try packet.address(question.name, ttl, .{ .ipv4 = .{ 192, 0, 2, 7 } });
        try std.testing.expectEqual(@as(u32, 0), (try response.inspect(packet.slice(), 7, question)).ttl_seconds);
    }
}
