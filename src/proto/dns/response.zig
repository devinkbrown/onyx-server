// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-question DNS response validation and bounded positive/negative results.
//! Authority/additional records never become answer data. Negative lifetime is
//! derived only from a relevant authority SOA (RFC 2308 section 5).

const std = @import("std");
const types = @import("message_types.zig");
const names = @import("name_codec.zig");

pub const max_packet_len: usize = 16 * 1024;
pub const max_records: usize = 128;
pub const max_aliases: usize = 16;

pub const Error = types.DecodeError || error{
    IdMismatch,
    QuestionMismatch,
    InvalidResponse,
    InvalidOwner,
    TooManyAliases,
    TooManyRecords,
    AliasLoop,
    ServerFailure,
};

pub const Envelope = struct {
    header: types.Header,
    body_offset: usize,

    pub fn truncated(self: Envelope) bool {
        return self.header.flags & 0x0200 != 0;
    }
};

pub const Outcome = enum { positive, alias, nxdomain, nodata };

/// Entirely owned inline result. `ttl_seconds == 0` must never be cached.
/// Alias results request a follow-up lookup under the same overall deadline.
pub const Result = struct {
    outcome: Outcome,
    canonical_name: types.Name,
    addresses: [types.max_cache_addrs]types.Address = undefined,
    address_count: usize = 0,
    ptr_name: types.Name = .{},
    ttl_seconds: u32 = 0,
    alias_count: usize = 0,

    pub fn addressSlice(self: *const Result) []const types.Address {
        return self.addresses[0..self.address_count];
    }
};

/// Validate only the complete echoed question before permitting TCP fallback.
/// A TC response may legitimately end midway through its answer section.
pub fn envelope(packet: []const u8, expected_id: u16, question: types.Query) Error!Envelope {
    if (packet.len > max_packet_len) return error.OversizeMessage;
    if (packet.len < 12) return error.TruncatedMessage;
    const header = types.Header{
        .id = readU16(packet, 0),
        .flags = readU16(packet, 2),
        .qdcount = readU16(packet, 4),
        .ancount = readU16(packet, 6),
        .nscount = readU16(packet, 8),
        .arcount = readU16(packet, 10),
    };
    if (header.id != expected_id) return error.IdMismatch;
    // QR must be set; only standard QUERY and a clear reserved Z bit are valid.
    // AD/CD are not DNSSEC proof and do not authorize any additional data.
    if (!header.isResponse() or header.flags & 0x7840 != 0) return error.InvalidResponse;
    if (header.qdcount != 1) return error.QuestionMismatch;
    var name: types.Name = .{};
    const end = try readName(packet, 12, &name);
    if (packet.len - end < 4) return error.TruncatedMessage;
    if (question.qclass != types.class_in or readU16(packet, end + 2) != types.class_in or
        readU16(packet, end) != @backingInt(question.qtype) or !names.equal(name.slice(), question.name))
        return error.QuestionMismatch;
    return .{ .header = header, .body_offset = end + 4 };
}

const Alias = struct { owner: types.Name, target: types.Name, ttl: u32 };
const Terminal = struct { owner: types.Name, ttl: u32 };
const NegativeAuthority = struct { owner: types.Name, ttl: u32 };

pub fn inspect(packet: []const u8, expected_id: u16, question: types.Query) Error!Result {
    return (try inspectWithPath(packet, expected_id, question)).result;
}

/// Alias targets accompany the owned result only while resolving. Keeping the
/// path out of Result avoids multiplying cache storage by the alias-work cap.
pub const Inspection = struct {
    result: Result,
    alias_targets: [max_aliases]types.Name = undefined,
};

pub fn inspectWithPath(packet: []const u8, expected_id: u16, question: types.Query) Error!Inspection {
    const env = try envelope(packet, expected_id, question);
    if (env.truncated()) return error.InvalidResponse;
    if (env.header.rcode() != 0 and env.header.rcode() != 3) return error.ServerFailure;
    if (question.qtype == .txt) return error.UnsupportedType;
    const record_count = @as(usize, env.header.ancount) + env.header.nscount + env.header.arcount;
    if (record_count > max_records) return error.TooManyRecords;
    var aliases: [max_aliases]Alias = undefined;
    var alias_count: usize = 0;
    // Keep ownership and TTL metadata for every bounded answer record, but
    // only retain a cache-sized prefix of the address/name data itself.
    var terminals: [max_records]Terminal = undefined;
    var terminal_data: [types.max_cache_addrs]types.RData = undefined;
    var terminal_count: usize = 0;
    var authorities: [max_aliases]NegativeAuthority = undefined;
    var authority_count: usize = 0;
    var pos = env.body_offset;
    for (0..record_count) |index| {
        var owner: types.Name = .{};
        pos = try readName(packet, pos, &owner);
        if (packet.len - pos < 10) return error.TruncatedMessage;
        const kind = readU16(packet, pos);
        const class = readU16(packet, pos + 2);
        const ttl = effectiveTtl(readU32(packet, pos + 4));
        const len: usize = readU16(packet, pos + 8);
        pos += 10;
        if (len > packet.len - pos) return error.TruncatedMessage;
        const start = pos;
        const end = pos + len;
        pos = end;
        const in_answer = index < env.header.ancount;
        const in_authority = !in_answer and index < @as(usize, env.header.ancount) + env.header.nscount;
        if (kind == 41) {
            // Extended EDNS RCODE/version must not masquerade as NOERROR.
            if (in_answer or in_authority or readU32(packet, start - 6) >> 16 != 0) return error.InvalidResponse;
            continue;
        }
        if (kind == 5 and in_answer) {
            if (class != types.class_in) return error.UnsupportedClass;
            if (alias_count == aliases.len) return error.TooManyAliases;
            var target: types.Name = .{};
            if (try readName(packet, start, &target) != end) return error.MalformedRData;
            aliases[alias_count] = .{ .owner = owner, .target = target, .ttl = ttl };
            alias_count += 1;
        } else if (in_answer and kind == @backingInt(question.qtype)) {
            if (class != types.class_in) return error.UnsupportedClass;
            const data: types.RData = switch (question.qtype) {
                .a => blk: {
                    if (len != 4) return error.MalformedRData;
                    break :blk .{ .a = packet[start..][0..4].* };
                },
                .aaaa => blk: {
                    if (len != 16) return error.MalformedRData;
                    break :blk .{ .aaaa = packet[start..][0..16].* };
                },
                .ptr => blk: {
                    var target: types.Name = .{};
                    if (try readName(packet, start, &target) != end) return error.MalformedRData;
                    break :blk .{ .ptr = target };
                },
                .txt => unreachable,
            };
            if (terminal_count < terminal_data.len) terminal_data[terminal_count] = data;
            terminals[terminal_count] = .{ .owner = owner, .ttl = ttl };
            terminal_count += 1;
        } else if (in_answer and (kind == 1 or kind == 28 or kind == 12 or kind == 16)) {
            return error.InvalidOwner;
        } else if (in_authority and kind == 6 and class == types.class_in) {
            if (authority_count == authorities.len) return error.TooManyRecords;
            var scratch: types.Name = .{};
            var soa_pos = try readName(packet, start, &scratch);
            if (soa_pos > end) return error.MalformedRData;
            soa_pos = try readName(packet, soa_pos, &scratch);
            if (soa_pos > end or end - soa_pos != 20) return error.MalformedRData;
            authorities[authority_count] = .{ .owner = owner, .ttl = @min(ttl, effectiveTtl(readU32(packet, soa_pos + 16))) };
            authority_count += 1;
        }
    }
    if (pos != packet.len) return error.TrailingBytes;

    var canonical: types.Name = .{};
    const normalized = names.normalize(&canonical.bytes, question.name) catch return error.InvalidName;
    canonical.len = normalized.len;
    var lifetime: u32 = std.math.maxInt(u32);
    var visited: [max_aliases]bool = @splat(false);
    var targets: [max_aliases]types.Name = undefined;
    var traversed: usize = 0;
    while (true) {
        var next: ?usize = null;
        for (aliases[0..alias_count], 0..) |alias, index| {
            if (!names.equal(alias.owner.slice(), canonical.slice())) continue;
            if (next != null or visited[index]) return error.AliasLoop;
            next = index;
        }
        const index = next orelse break;
        visited[index] = true;
        traversed += 1;
        lifetime = @min(lifetime, aliases[index].ttl);
        canonical = aliases[index].target;
        targets[traversed - 1] = canonical;
    }
    if (traversed != alias_count) return error.InvalidOwner;

    var result = Result{ .outcome = .positive, .canonical_name = canonical, .alias_count = traversed };
    for (terminals[0..terminal_count], 0..) |terminal, index| {
        if (!names.equal(terminal.owner.slice(), canonical.slice())) return error.InvalidOwner;
        lifetime = @min(lifetime, terminal.ttl);
        if (index >= terminal_data.len) continue;
        switch (terminal_data[index]) {
            .a => |address| {
                result.addresses[result.address_count] = .{ .ipv4 = address };
                result.address_count += 1;
            },
            .aaaa => |address| {
                result.addresses[result.address_count] = .{ .ipv6 = address };
                result.address_count += 1;
            },
            .ptr => |name| if (index == 0) {
                result.ptr_name = name;
            },
        }
    }
    if (terminal_count != 0) {
        if (env.header.rcode() != 0) return error.InvalidResponse;
        result.ttl_seconds = lifetime;
        return .{ .result = result, .alias_targets = targets };
    }

    var negative_ttl: ?u32 = null;
    var closest_zone_len: usize = 0;
    for (authorities[0..authority_count]) |authority| {
        if (!names.withinZone(canonical.slice(), authority.owner.slice())) continue;
        if (authority.owner.len < closest_zone_len) continue;
        negative_ttl = if (authority.owner.len == closest_zone_len and negative_ttl != null)
            @min(negative_ttl.?, authority.ttl)
        else
            authority.ttl;
        closest_zone_len = authority.owner.len;
    }
    result.outcome = if (env.header.rcode() == 3) .nxdomain else if (negative_ttl != null or alias_count == 0) .nodata else .alias;
    result.ttl_seconds = if (result.outcome == .alias) lifetime else if (negative_ttl) |ttl| @min(lifetime, ttl) else 0;
    return .{ .result = result, .alias_targets = targets };
}

fn readName(packet: []const u8, pos: usize, out: *types.Name) Error!usize {
    return names.decode(max_packet_len, packet, pos, &out.bytes, &out.len);
}

fn readU16(bytes: []const u8, pos: usize) u16 {
    return std.mem.readInt(u16, bytes[pos..][0..2], .big);
}

fn readU32(bytes: []const u8, pos: usize) u32 {
    return std.mem.readInt(u32, bytes[pos..][0..4], .big);
}

fn effectiveTtl(ttl: u32) u32 {
    // RFC 2181 section 8: the high bit is not part of a valid positive TTL.
    return if (ttl & 0x80000000 != 0) 0 else ttl;
}
