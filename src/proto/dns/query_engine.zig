// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded stub resolution: connected UDP, validated TCP fallback, and aliases.
//! This API performs blocking work only on dedicated resolver workers. Native
//! sockets remain nonblocking; every readiness wait shares an absolute budget.

const std = @import("std");
const wire = @import("wire.zig");
const config = @import("resolver_config.zig");
const names = @import("name_codec.zig");
const response = @import("response.zig");
const transport = @import("transport.zig");
const timing = @import("deadline.zig");
const platform = @import("../../substrate/platform.zig");

pub const max_attempts: u8 = 3;
pub const max_rejected_datagrams: usize = 16;
pub const Error = wire.EncodeError || response.Error || transport.Error || error{
    NoNameservers,
    InvalidConfig,
    NameError,
    NoData,
    RandomSourceFailed,
};

pub const Options = struct {
    /// Optional whole-lookup budget, including all retries and alias/TCP work.
    /// Always clamped to deadline.max_query_ms (5 seconds); zero means 1 ms.
    /// Null derives the budget from the existing ResolverConfig fields.
    total_timeout_ms: ?u32 = null,
};

pub fn resolve(cfg: *const config.ResolverConfig, name: []const u8, qtype: wire.RecordType, options: Options) Error!response.Result {
    try validateConfig(cfg);
    const budget = options.total_timeout_ms orelse defaultBudget(cfg);
    return resolveUntil(cfg, name, qtype, timing.Deadline.after(budget));
}

pub fn resolveUntil(cfg: *const config.ResolverConfig, name: []const u8, qtype: wire.RecordType, deadline: timing.Deadline) Error!response.Result {
    try validateConfig(cfg);
    if (qtype == .txt) return error.UnsupportedType;
    var current: wire.Name = .{};
    const normalized = try names.normalize(&current.bytes, name);
    current.len = normalized.len;
    var visited: [response.max_aliases + 1]wire.Name = undefined;
    visited[0] = current;
    var visited_count: usize = 1;
    var total_aliases: usize = 0;
    var expires_ms: i64 = std.math.maxInt(i64);
    while (true) {
        _ = try deadline.remaining();
        const inspected = try query(cfg, current.slice(), qtype, deadline);
        var result = inspected.result;
        total_aliases += result.alias_count;
        if (total_aliases > response.max_aliases) return error.AliasLoop;
        for (inspected.alias_targets[0..result.alias_count]) |target| {
            for (visited[0..visited_count]) |previous| {
                if (names.equal(previous.slice(), target.slice())) return error.AliasLoop;
            }
            visited[visited_count] = target;
            visited_count += 1;
        }
        const now_ms = platform.monotonicMillis();
        expires_ms = @min(expires_ms, now_ms +| @as(i64, result.ttl_seconds) * 1000);
        if (result.outcome != .alias) {
            result.ttl_seconds = @intCast(@divTrunc(@max(@as(i128, 0), @as(i128, expires_ms) - now_ms), 1000));
            result.alias_count = total_aliases;
            return result;
        }
        current = result.canonical_name;
    }
}

pub fn defaultBudget(cfg: *const config.ResolverConfig) u32 {
    const per_attempt: u64 = @max(@as(u64, 1), cfg.timeout_ms);
    const attempts: u64 = @min(@max(@as(u64, 1), cfg.attempts), max_attempts);
    const servers: u64 = @min(@max(@as(u64, 1), cfg.nameserver_count), config.max_nameservers);
    return @intCast(@min(timing.max_query_ms, per_attempt * attempts * servers));
}

fn validateConfig(cfg: *const config.ResolverConfig) Error!void {
    if (cfg.nameserver_count == 0) return error.NoNameservers;
    if (cfg.nameserver_count > config.max_nameservers or cfg.port == 0) return error.InvalidConfig;
}

fn query(cfg: *const config.ResolverConfig, name: []const u8, qtype: wire.RecordType, deadline: timing.Deadline) Error!response.Inspection {
    var last_error: Error = error.Timeout;
    for (0..@min(@max(cfg.attempts, 1), max_attempts)) |_| {
        for (cfg.nsSlice(), 0..) |address, index| {
            _ = try deadline.remaining();
            const endpoint = transport.Endpoint{ .address = address, .scope_id = cfg.nameserver_scope_ids[index], .port = cfg.port };
            const attempt_deadline = try deadline.slice(cfg.timeout_ms);
            return queryEndpoint(endpoint, name, qtype, attempt_deadline) catch |err| {
                last_error = err;
                continue;
            };
        }
    }
    return last_error;
}

fn queryEndpoint(endpoint: transport.Endpoint, name: []const u8, qtype: wire.RecordType, deadline: timing.Deadline) Error!response.Inspection {
    var entropy: [2]u8 = undefined;
    platform.fillOsEntropy(&entropy) catch return error.RandomSourceFailed;
    const id = std.mem.readInt(u16, &entropy, .little);
    const question = wire.Query{ .name = name, .qtype = qtype };
    var query_buf: [wire.max_message_len]u8 = undefined;
    const query_bytes = try wire.encodeQuery(&query_buf, id, name, qtype);
    var connection = try transport.Connection.open(endpoint, .udp, deadline);
    defer connection.close();
    try connection.send(query_bytes, deadline);
    // One extra byte detects UDP truncation even when the kernel does not
    // expose MSG_TRUNC through its portable recv interface.
    var received: [response.max_packet_len + 1]u8 = undefined;
    for (0..max_rejected_datagrams) |_| {
        const count = try connection.receive(&received, deadline);
        if (count > response.max_packet_len) continue;
        const packet = received[0..count];
        const env = response.envelope(packet, id, question) catch continue;
        if (env.truncated()) {
            if (env.header.rcode() != 0 and env.header.rcode() != 3) return error.ServerFailure;
            const complete = try transport.tcpExchange(endpoint, query_bytes, received[0..response.max_packet_len], deadline);
            return response.inspectWithPath(complete, id, question);
        }
        return response.inspectWithPath(packet, id, question) catch |err| switch (err) {
            error.ServerFailure => return err,
            else => continue,
        };
    }
    return error.InvalidResponse;
}

test "DNS query budgets cap attempts servers and overflow without changing configured fields" {
    var cfg = config.ResolverConfig{ .timeout_ms = std.math.maxInt(u32), .attempts = 255 };
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 1 } });
    try std.testing.expectEqual(timing.max_query_ms, defaultBudget(&cfg));
    cfg.timeout_ms = 20;
    cfg.attempts = 2;
    try std.testing.expectEqual(@as(u32, 40), defaultBudget(&cfg));
    cfg.addNameserver(.{ .ipv4 = .{ 127, 0, 0, 2 } });
    try std.testing.expectEqual(@as(u32, 80), defaultBudget(&cfg));
    cfg.timeout_ms = 0;
    try std.testing.expectEqual(@as(u32, 4), defaultBudget(&cfg));
    cfg.nameserver_count = config.max_nameservers + 1;
    try std.testing.expectError(error.InvalidConfig, resolve(&cfg, "invalid.test", .a, .{}));
}

test {
    _ = timing;
    _ = transport;
}
