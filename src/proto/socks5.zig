// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const version: u8 = 0x05;
pub const user_pass_version: u8 = 0x01;

pub const Error = error{
    BadVersion,
    BadReserved,
    InvalidAddressType,
    InvalidCredentialLength,
    InvalidDomainLength,
    InvalidLength,
    InvalidReplyCode,
    NoMethods,
    TooManyMethods,
    Truncated,
    UnsupportedCommand,
};

pub const Method = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xff,
    _,
};

pub const Greeting = struct {
    methods: []const Method,

    pub fn deinit(self: Greeting, allocator: Allocator) void {
        allocator.free(self.methods);
    }
};

pub const MethodSelection = struct {
    method: Method,
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const AuthStatus = enum(u8) {
    success = 0x00,
    failure = 0x01,
    _,
};

pub const AuthResponse = struct {
    status: AuthStatus,
};

pub const Command = enum(u8) {
    connect = 0x01,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const Address = union(AddressType) {
    ipv4: [4]u8,
    domain: []const u8,
    ipv6: [16]u8,
};

pub const ConnectRequest = struct {
    address: Address,
    port: u16,
};

pub const ReplyCode = enum(u8) {
    success = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub const Reply = struct {
    code: ReplyCode,
    address: Address,
    port: u16,
};

const ParsedAddress = struct {
    address: Address,
    port: u16,
    next: usize,
};

pub fn encodeGreeting(allocator: Allocator, methods: []const Method) ![]u8 {
    if (methods.len == 0) return Error.NoMethods;
    if (methods.len > 255) return Error.TooManyMethods;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, version);
    try out.append(allocator, @intCast(methods.len));
    for (methods) |method| {
        try out.append(allocator, @backingInt(method));
    }
    return out.toOwnedSlice(allocator);
}

pub fn decodeGreeting(allocator: Allocator, bytes: []const u8) !Greeting {
    if (bytes.len < 2) return Error.Truncated;
    if (bytes[0] != version) return Error.BadVersion;

    const count: usize = bytes[1];
    if (count == 0) return Error.NoMethods;
    if (bytes.len < 2 + count) return Error.Truncated;
    if (bytes.len != 2 + count) return Error.InvalidLength;

    const methods = try allocator.alloc(Method, count);
    errdefer allocator.free(methods);

    for (methods, 0..) |*method, i| {
        method.* = @fromBackingInt(@intCast(bytes[2 + i]));
    }

    return .{ .methods = methods };
}

pub fn encodeMethodSelection(allocator: Allocator, selection: MethodSelection) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, version);
    try out.append(allocator, @backingInt(selection.method));
    return out.toOwnedSlice(allocator);
}

pub fn decodeMethodSelection(bytes: []const u8) Error!MethodSelection {
    if (bytes.len < 2) return Error.Truncated;
    if (bytes[0] != version) return Error.BadVersion;
    if (bytes.len != 2) return Error.InvalidLength;

    return .{ .method = @fromBackingInt(@intCast(bytes[1])) };
}

pub fn encodeUserPassRequest(allocator: Allocator, credentials: Credentials) ![]u8 {
    if (!validCredentialPart(credentials.username) or !validCredentialPart(credentials.password)) {
        return Error.InvalidCredentialLength;
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, user_pass_version);
    try out.append(allocator, @intCast(credentials.username.len));
    try out.appendSlice(allocator, credentials.username);
    try out.append(allocator, @intCast(credentials.password.len));
    try out.appendSlice(allocator, credentials.password);
    return out.toOwnedSlice(allocator);
}

pub fn decodeUserPassRequest(bytes: []const u8) Error!Credentials {
    if (bytes.len < 2) return Error.Truncated;
    if (bytes[0] != user_pass_version) return Error.BadVersion;

    const username_len: usize = bytes[1];
    if (username_len == 0) return Error.InvalidCredentialLength;
    if (bytes.len < 2 + username_len + 1) return Error.Truncated;

    const password_len_index = 2 + username_len;
    const password_len: usize = bytes[password_len_index];
    if (password_len == 0) return Error.InvalidCredentialLength;

    const expected_len = password_len_index + 1 + password_len;
    if (bytes.len < expected_len) return Error.Truncated;
    if (bytes.len != expected_len) return Error.InvalidLength;

    return .{
        .username = bytes[2..password_len_index],
        .password = bytes[password_len_index + 1 .. expected_len],
    };
}

pub fn encodeUserPassResponse(allocator: Allocator, response: AuthResponse) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, user_pass_version);
    try out.append(allocator, @backingInt(response.status));
    return out.toOwnedSlice(allocator);
}

pub fn decodeUserPassResponse(bytes: []const u8) Error!AuthResponse {
    if (bytes.len < 2) return Error.Truncated;
    if (bytes[0] != user_pass_version) return Error.BadVersion;
    if (bytes.len != 2) return Error.InvalidLength;

    return .{ .status = @fromBackingInt(@intCast(bytes[1])) };
}

pub fn encodeConnectRequest(allocator: Allocator, request: ConnectRequest) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, version);
    try out.append(allocator, @backingInt(Command.connect));
    try out.append(allocator, 0x00);
    try appendAddress(&out, allocator, request.address);
    try appendU16(&out, allocator, request.port);
    return out.toOwnedSlice(allocator);
}

pub fn decodeConnectRequest(bytes: []const u8) Error!ConnectRequest {
    if (bytes.len < 4) return Error.Truncated;
    if (bytes[0] != version) return Error.BadVersion;
    if (bytes[1] != @backingInt(Command.connect)) return Error.UnsupportedCommand;
    if (bytes[2] != 0x00) return Error.BadReserved;

    const parsed = try parseAddress(bytes, 3);
    if (parsed.next != bytes.len) return Error.InvalidLength;
    return .{ .address = parsed.address, .port = parsed.port };
}

pub fn encodeReply(allocator: Allocator, reply: Reply) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    try out.append(allocator, version);
    try out.append(allocator, @backingInt(reply.code));
    try out.append(allocator, 0x00);
    try appendAddress(&out, allocator, reply.address);
    try appendU16(&out, allocator, reply.port);
    return out.toOwnedSlice(allocator);
}

pub fn decodeReply(bytes: []const u8) Error!Reply {
    if (bytes.len < 4) return Error.Truncated;
    if (bytes[0] != version) return Error.BadVersion;
    if (!isValidReplyCode(bytes[1])) return Error.InvalidReplyCode;
    if (bytes[2] != 0x00) return Error.BadReserved;

    const parsed = try parseAddress(bytes, 3);
    if (parsed.next != bytes.len) return Error.InvalidLength;
    return .{
        .code = @fromBackingInt(@intCast(bytes[1])),
        .address = parsed.address,
        .port = parsed.port,
    };
}

fn validCredentialPart(part: []const u8) bool {
    return part.len > 0 and part.len <= 255;
}

fn validDomain(domain: []const u8) bool {
    return domain.len > 0 and domain.len <= 255;
}

fn appendAddress(out: *std.ArrayList(u8), allocator: Allocator, address: Address) !void {
    switch (address) {
        .ipv4 => |octets| {
            try out.append(allocator, @backingInt(AddressType.ipv4));
            try out.appendSlice(allocator, &octets);
        },
        .domain => |domain| {
            if (!validDomain(domain)) return Error.InvalidDomainLength;
            try out.append(allocator, @backingInt(AddressType.domain));
            try out.append(allocator, @intCast(domain.len));
            try out.appendSlice(allocator, domain);
        },
        .ipv6 => |octets| {
            try out.append(allocator, @backingInt(AddressType.ipv6));
            try out.appendSlice(allocator, &octets);
        },
    }
}

fn appendU16(out: *std.ArrayList(u8), allocator: Allocator, value: u16) !void {
    try out.append(allocator, @intCast(value >> 8));
    try out.append(allocator, @intCast(value & 0xff));
}

fn parseAddress(bytes: []const u8, start: usize) Error!ParsedAddress {
    if (bytes.len <= start) return Error.Truncated;

    var offset = start;
    const atyp = bytes[offset];
    offset += 1;

    const address: Address = switch (atyp) {
        @backingInt(AddressType.ipv4) => blk: {
            if (bytes.len < offset + 4) return Error.Truncated;
            var octets: [4]u8 = undefined;
            @memcpy(&octets, bytes[offset .. offset + 4]);
            offset += 4;
            break :blk .{ .ipv4 = octets };
        },
        @backingInt(AddressType.domain) => blk: {
            if (bytes.len < offset + 1) return Error.Truncated;
            const domain_len: usize = bytes[offset];
            offset += 1;
            if (domain_len == 0) return Error.InvalidDomainLength;
            if (bytes.len < offset + domain_len) return Error.Truncated;
            const domain = bytes[offset .. offset + domain_len];
            offset += domain_len;
            break :blk .{ .domain = domain };
        },
        @backingInt(AddressType.ipv6) => blk: {
            if (bytes.len < offset + 16) return Error.Truncated;
            var octets: [16]u8 = undefined;
            @memcpy(&octets, bytes[offset .. offset + 16]);
            offset += 16;
            break :blk .{ .ipv6 = octets };
        },
        else => return Error.InvalidAddressType,
    };

    if (bytes.len < offset + 2) return Error.Truncated;
    const port = readU16(bytes[offset .. offset + 2]);
    offset += 2;

    return .{ .address = address, .port = port, .next = offset };
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn isValidReplyCode(code: u8) bool {
    return code <= @backingInt(ReplyCode.address_type_not_supported);
}

test "greeting and method selection encode decode" {
    const allocator = std.testing.allocator;

    const methods = [_]Method{ .no_auth, .username_password };
    const encoded = try encodeGreeting(allocator, &methods);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x02, 0x00, 0x02 }, encoded);

    const decoded = try decodeGreeting(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualSlices(Method, &methods, decoded.methods);

    const selected = try encodeMethodSelection(allocator, .{ .method = .no_auth });
    defer allocator.free(selected);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00 }, selected);

    const decoded_selected = try decodeMethodSelection(selected);
    try std.testing.expectEqual(Method.no_auth, decoded_selected.method);

    const rejected = try encodeMethodSelection(allocator, .{ .method = .no_acceptable });
    defer allocator.free(rejected);
    const decoded_rejected = try decodeMethodSelection(rejected);
    try std.testing.expectEqual(Method.no_acceptable, decoded_rejected.method);
}

test "username password auth exchange encode decode" {
    const allocator = std.testing.allocator;

    const encoded = try encodeUserPassRequest(allocator, .{
        .username = "example",
        .password = "river-pass",
    });
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x0a, 'r', 'i', 'v', 'e', 'r', '-', 'p', 'a', 's', 's' },
        encoded,
    );

    const decoded = try decodeUserPassRequest(encoded);
    try std.testing.expectEqualStrings("example", decoded.username);
    try std.testing.expectEqualStrings("river-pass", decoded.password);

    const success = try encodeUserPassResponse(allocator, .{ .status = .success });
    defer allocator.free(success);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, success);
    try std.testing.expectEqual(AuthStatus.success, (try decodeUserPassResponse(success)).status);

    const failure = try encodeUserPassResponse(allocator, .{ .status = .failure });
    defer allocator.free(failure);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x01 }, failure);
    try std.testing.expectEqual(AuthStatus.failure, (try decodeUserPassResponse(failure)).status);
}

test "connect request round trips ipv4 ipv6 and domain" {
    const allocator = std.testing.allocator;

    const ipv4_request = ConnectRequest{
        .address = .{ .ipv4 = .{ 127, 0, 0, 1 } },
        .port = 6667,
    };
    const ipv4_encoded = try encodeConnectRequest(allocator, ipv4_request);
    defer allocator.free(ipv4_encoded);
    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1a, 0x0b }, ipv4_encoded);
    try expectConnectRequestEqual(ipv4_request, try decodeConnectRequest(ipv4_encoded));

    const ipv6_addr = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const ipv6_request = ConnectRequest{
        .address = .{ .ipv6 = ipv6_addr },
        .port = 6697,
    };
    const ipv6_encoded = try encodeConnectRequest(allocator, ipv6_request);
    defer allocator.free(ipv6_encoded);
    try expectConnectRequestEqual(ipv6_request, try decodeConnectRequest(ipv6_encoded));

    const domain_request = ConnectRequest{
        .address = .{ .domain = "irc.example.net" },
        .port = 7000,
    };
    const domain_encoded = try encodeConnectRequest(allocator, domain_request);
    defer allocator.free(domain_encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x05, 0x01, 0x00, 0x03, 0x0f, 'i', 'r', 'c', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'n', 'e', 't', 0x1b, 0x58 },
        domain_encoded,
    );
    try expectConnectRequestEqual(domain_request, try decodeConnectRequest(domain_encoded));
}

test "reply success and failure codes encode decode" {
    const allocator = std.testing.allocator;

    const success_reply = Reply{
        .code = .success,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .port = 0,
    };
    const success_encoded = try encodeReply(allocator, success_reply);
    defer allocator.free(success_encoded);

    try std.testing.expectEqualSlices(u8, &.{ 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, success_encoded);
    try expectReplyEqual(success_reply, try decodeReply(success_encoded));

    const failure_reply = Reply{
        .code = .host_unreachable,
        .address = .{ .domain = "failed.example" },
        .port = 443,
    };
    const failure_encoded = try encodeReply(allocator, failure_reply);
    defer allocator.free(failure_encoded);

    const decoded_failure = try decodeReply(failure_encoded);
    try std.testing.expectEqual(ReplyCode.host_unreachable, decoded_failure.code);
    try expectReplyEqual(failure_reply, decoded_failure);

    const ttl_reply = Reply{
        .code = .ttl_expired,
        .address = .{ .ipv6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .port = 1080,
    };
    const ttl_encoded = try encodeReply(allocator, ttl_reply);
    defer allocator.free(ttl_encoded);
    try expectReplyEqual(ttl_reply, try decodeReply(ttl_encoded));
}

test "truncation and bad versions are rejected" {
    try std.testing.expectError(Error.Truncated, decodeMethodSelection(&.{0x05}));
    try std.testing.expectError(Error.BadVersion, decodeMethodSelection(&.{ 0x04, 0x00 }));
    try std.testing.expectError(Error.InvalidLength, decodeMethodSelection(&.{ 0x05, 0x00, 0x00 }));

    try std.testing.expectError(Error.Truncated, decodeUserPassRequest(&.{0x01}));
    try std.testing.expectError(Error.BadVersion, decodeUserPassRequest(&.{ 0x05, 0x01, 'a', 0x01, 'b' }));
    try std.testing.expectError(Error.Truncated, decodeUserPassRequest(&.{ 0x01, 0x04, 'u', 's' }));
    try std.testing.expectError(Error.InvalidLength, decodeUserPassRequest(&.{ 0x01, 0x01, 'u', 0x01, 'p', 0x00 }));

    try std.testing.expectError(Error.Truncated, decodeConnectRequest(&.{ 0x05, 0x01, 0x00 }));
    try std.testing.expectError(Error.BadVersion, decodeConnectRequest(&.{ 0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80 }));
    try std.testing.expectError(Error.UnsupportedCommand, decodeConnectRequest(&.{ 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80 }));
    try std.testing.expectError(Error.BadReserved, decodeConnectRequest(&.{ 0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0, 80 }));
    try std.testing.expectError(Error.InvalidAddressType, decodeConnectRequest(&.{ 0x05, 0x01, 0x00, 0x02, 127, 0, 0, 1, 0, 80 }));
    try std.testing.expectError(Error.Truncated, decodeConnectRequest(&.{ 0x05, 0x01, 0x00, 0x03, 0x04, 'h', 'o' }));

    try std.testing.expectError(Error.BadVersion, decodeReply(&.{ 0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expectError(Error.InvalidReplyCode, decodeReply(&.{ 0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expectError(Error.Truncated, decodeReply(&.{ 0x05, 0x00, 0x00, 0x04, 0, 0 }));
}

test "greeting rejects truncation bad version and invalid method counts" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(Error.Truncated, decodeGreeting(allocator, &.{0x05}));
    try std.testing.expectError(Error.BadVersion, decodeGreeting(allocator, &.{ 0x04, 0x01, 0x00 }));
    try std.testing.expectError(Error.NoMethods, decodeGreeting(allocator, &.{ 0x05, 0x00 }));
    try std.testing.expectError(Error.Truncated, decodeGreeting(allocator, &.{ 0x05, 0x02, 0x00 }));
    try std.testing.expectError(Error.InvalidLength, decodeGreeting(allocator, &.{ 0x05, 0x01, 0x00, 0x02 }));
    try std.testing.expectError(Error.NoMethods, encodeGreeting(allocator, &.{}));
}

fn expectConnectRequestEqual(expected: ConnectRequest, actual: ConnectRequest) !void {
    try expectAddressEqual(expected.address, actual.address);
    try std.testing.expectEqual(expected.port, actual.port);
}

fn expectReplyEqual(expected: Reply, actual: Reply) !void {
    try std.testing.expectEqual(expected.code, actual.code);
    try expectAddressEqual(expected.address, actual.address);
    try std.testing.expectEqual(expected.port, actual.port);
}

fn expectAddressEqual(expected: Address, actual: Address) !void {
    try std.testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));

    switch (expected) {
        .ipv4 => |octets| try std.testing.expectEqualSlices(u8, &octets, &actual.ipv4),
        .domain => |domain| try std.testing.expectEqualStrings(domain, actual.domain),
        .ipv6 => |octets| try std.testing.expectEqualSlices(u8, &octets, &actual.ipv6),
    }
}
