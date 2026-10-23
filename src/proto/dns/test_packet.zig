// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Controlled DNS response fixtures for validation and local transport tests.

const std = @import("std");
const wire = @import("wire.zig");
const names = @import("name_codec.zig");
const response = @import("response.zig");

pub const Section = enum { answer, authority, additional };

pub const Packet = struct {
    bytes: [response.max_packet_len]u8 = undefined,
    len: usize = 0,

    pub fn init(id: u16, name: []const u8, kind: wire.RecordType) !Packet {
        var packet = Packet{};
        const query = try wire.encodeQuery(&packet.bytes, id, name, kind);
        packet.len = query.len;
        packet.flags(0x8180);
        return packet;
    }

    pub fn flags(self: *Packet, value: u16) void {
        std.mem.writeInt(u16, self.bytes[2..4], value, .big);
    }

    pub fn slice(self: *const Packet) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn record(self: *Packet, section: Section, owner: []const u8, kind: u16, ttl: u32, data: []const u8) !void {
        self.len += try names.encode(self.bytes[self.len..], owner);
        if (10 + data.len > self.bytes.len - self.len) return error.OutputTooSmall;
        std.mem.writeInt(u16, self.bytes[self.len..][0..2], kind, .big);
        std.mem.writeInt(u16, self.bytes[self.len + 2 ..][0..2], wire.class_in, .big);
        std.mem.writeInt(u32, self.bytes[self.len + 4 ..][0..4], ttl, .big);
        std.mem.writeInt(u16, self.bytes[self.len + 8 ..][0..2], @intCast(data.len), .big);
        self.len += 10;
        @memcpy(self.bytes[self.len..][0..data.len], data);
        self.len += data.len;
        const offset: usize = switch (section) {
            .answer => 6,
            .authority => 8,
            .additional => 10,
        };
        const old = std.mem.readInt(u16, self.bytes[offset..][0..2], .big);
        std.mem.writeInt(u16, self.bytes[offset..][0..2], old + 1, .big);
    }

    pub fn address(self: *Packet, owner: []const u8, ttl: u32, value: wire.Address) !void {
        switch (value) {
            .ipv4 => |bytes| try self.record(.answer, owner, 1, ttl, &bytes),
            .ipv6 => |bytes| try self.record(.answer, owner, 28, ttl, &bytes),
        }
    }

    pub fn nameRecord(self: *Packet, owner: []const u8, kind: u16, ttl: u32, target: []const u8) !void {
        var data: [names.max_wire_len]u8 = undefined;
        const len = try names.encode(&data, target);
        try self.record(.answer, owner, kind, ttl, data[0..len]);
    }

    pub fn soa(self: *Packet, zone: []const u8, ttl: u32, minimum: u32) !void {
        var data: [2 * names.max_wire_len + 20]u8 = @splat(0);
        var len = try names.encode(&data, "ns.example");
        len += try names.encode(data[len..], "hostmaster.example");
        std.mem.writeInt(u32, data[len + 16 ..][0..4], minimum, .big);
        try self.record(.authority, zone, 6, ttl, data[0 .. len + 20]);
    }
};
