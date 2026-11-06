// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit memory / CPU / network limits and benchmark-based capacity estimates.
//!
//! Pure leaf: no I/O, no allocation, no globals. `config_format.zig` projects the
//! `[resources]` / `[resources.basis]` tables onto `Config`; `config_boot.zig`
//! cross-checks them against `[limits]` and `[mesh]` with `validate`; the live
//! accept path uses `admitByMemory`. Every default is "unset" (`0`), so a config
//! without `[resources]` reproduces current behaviour exactly.
//!
//! An estimate is never anonymous: `estimate` refuses to produce a number unless
//! the operator named the measurement it extrapolates from (`BenchmarkBasis`:
//! name, harness, source/artifact revision, measured client count and measured
//! resident bytes per client, typically from `tools/bench_live.py`). The
//! formatted line always carries that basis and flags extrapolation beyond twice
//! the measured scale. No measurement is invented here.

const std = @import("std");

/// Hard ceiling for `cpu_max_shards`; equals `shard.max_shards` (4096). Kept as a
/// literal so this leaf has no daemon imports; `config_format` asserts equality.
pub const max_cpu_shards: u16 = 4096;

/// Longest accepted basis text field and the printable-ASCII rule it follows.
pub const max_basis_text_bytes: usize = 128;

/// Estimates beyond this multiple of `measured_clients` are marked extrapolated.
pub const extrapolation_factor: u64 = 2;

/// Operator-supplied description of the measurement an estimate extrapolates from.
/// All text is borrowed; `config_format` owns the parsed copies.
pub const BenchmarkBasis = struct {
    /// Short label for the run (for example a dated receipt id).
    name: []const u8 = "",
    /// Harness and profile that produced it (for example `tools/bench_live.py --quick`).
    harness: []const u8 = "",
    /// Source revision or artifact digest that was measured.
    revision: []const u8 = "",
    /// Concurrent clients present during the measurement.
    measured_clients: u32 = 0,
    /// Resident bytes per client observed at `measured_clients`.
    rss_per_client_bytes: u64 = 0,
    /// Sustained egress bytes per second per client observed (0 = not measured).
    egress_bytes_per_sec_per_client: u64 = 0,
};

/// `[resources]` table. `0` means unset/derived for every limit except `fd_reserve`.
pub const Config = struct {
    /// Total bytes the admission path may commit to client connections.
    memory_budget_bytes: u64 = 0,
    /// Committed bytes per client for budget admission; 0 derives it from
    /// `derivedPerClientBytes`.
    per_client_memory_bytes: u64 = 0,
    /// Upper bound on reactor shards the operator accepts for CPU capacity;
    /// 0 follows `[limits].num_shards`.
    cpu_max_shards: u16 = 0,
    /// Aggregate ingress / egress budget in bytes per second (0 = unlimited).
    net_ingress_bytes_per_sec: u64 = 0,
    net_egress_bytes_per_sec: u64 = 0,
    /// Cap on configured outbound mesh peers (`[mesh].connect`); 0 = unlimited.
    net_max_s2s_peers: u32 = 0,
    /// File descriptors held back from the client count for listeners, logs,
    /// stores and mesh links.
    fd_reserve: u32 = 64,
    basis: BenchmarkBasis = .{},
};

/// Values from other config sections or the host that limits are checked against.
pub const Context = struct {
    /// `[limits].max_clients`.
    max_clients: u32,
    /// `[limits].num_shards`.
    num_shards: u16 = 1,
    /// Number of `[mesh].connect` peers.
    mesh_connect_len: usize = 0,
    /// Class SendQ ceiling per client (bytes).
    sendq_cap_bytes: u64 = 1 << 20,
    /// Class RecvQ overflow ceiling per client (bytes); 0 = inherit inline buffer.
    recvq_cap_bytes: u64 = 0,
    /// Fixed resident bytes of one connection record (`@sizeOf(ConnState)`).
    conn_fixed_bytes: u64 = 0,
};

pub const Violation = enum {
    shards_above_ceiling,
    shards_below_configured,
    per_client_overflow,
    budget_below_max_clients,
    s2s_peers_above_cap,
};

pub fn violationReason(v: Violation) []const u8 {
    return switch (v) {
        .shards_above_ceiling => "resources.cpu_max_shards exceeds the 4096-shard ceiling",
        .shards_below_configured => "limits.num_shards exceeds resources.cpu_max_shards",
        .per_client_overflow => "resources per-client memory arithmetic overflows",
        .budget_below_max_clients => "resources.memory_budget_bytes cannot hold limits.max_clients at the per-client memory commitment",
        .s2s_peers_above_cap => "mesh.connect lists more peers than resources.net_max_s2s_peers",
    };
}

/// Worst-case committed bytes of one client: SendQ ceiling + RecvQ overflow
/// ceiling + fixed connection record. `null` on arithmetic overflow.
pub fn derivedPerClientBytes(ctx: Context) ?u64 {
    const a = std.math.add(u64, ctx.sendq_cap_bytes, ctx.recvq_cap_bytes) catch return null;
    return std.math.add(u64, a, ctx.conn_fixed_bytes) catch null;
}

/// Bytes committed per client: the explicit override or the derived worst case.
pub fn perClientBytes(cfg: Config, ctx: Context) ?u64 {
    if (cfg.per_client_memory_bytes != 0) return cfg.per_client_memory_bytes;
    return derivedPerClientBytes(ctx);
}

/// Shards in force for CPU accounting: the cap when set, else `[limits]`.
pub fn effectiveShardCap(cfg: Config, ctx: Context) u16 {
    return if (cfg.cpu_max_shards != 0) cfg.cpu_max_shards else ctx.num_shards;
}

/// Cross-section consistency. Null means the combination is admissible; the
/// all-default `Config` always returns null.
pub fn validate(cfg: Config, ctx: Context) ?Violation {
    if (cfg.cpu_max_shards > max_cpu_shards) return .shards_above_ceiling;
    if (cfg.cpu_max_shards != 0 and ctx.num_shards > cfg.cpu_max_shards) return .shards_below_configured;
    if (cfg.net_max_s2s_peers != 0 and ctx.mesh_connect_len > cfg.net_max_s2s_peers) return .s2s_peers_above_cap;
    if (cfg.memory_budget_bytes != 0) {
        const per = perClientBytes(cfg, ctx) orelse return .per_client_overflow;
        const need = std.math.mul(u64, per, ctx.max_clients) catch return .per_client_overflow;
        if (need > cfg.memory_budget_bytes) return .budget_below_max_clients;
    }
    return null;
}

/// Accept-time memory admission: may one more client be admitted when
/// `clients_now` are live. An unset budget or per-client size admits (current
/// behaviour); arithmetic overflow refuses, fail-closed.
pub fn admitByMemory(clients_now: usize, per_client_bytes: u64, budget_bytes: u64) bool {
    if (budget_bytes == 0 or per_client_bytes == 0) return true;
    const next = std.math.add(u64, clients_now, 1) catch return false;
    const need = std.math.mul(u64, next, per_client_bytes) catch return false;
    return need <= budget_bytes;
}

/// Facts about the host the estimate is for; `0` means unknown (constraint skipped).
pub const Host = struct {
    memory_bytes: u64 = 0,
    fd_limit: u64 = 0,
};

pub const Constraint = enum { config_max_clients, memory, fd, egress };

pub const EstimateError = error{ MissingBenchmarkBasis, InvalidBenchmarkBasis };

pub const Estimate = struct {
    max_clients: u64,
    binding: Constraint,
    basis: BenchmarkBasis,
    /// True when `max_clients` exceeds `extrapolation_factor` times the measured scale.
    extrapolated: bool,
};

/// Printable ASCII, 1..`max_basis_text_bytes`: safe for logs and doctor lines.
pub fn validBasisText(text: []const u8) bool {
    if (text.len == 0 or text.len > max_basis_text_bytes) return false;
    for (text) |c| if (c < 0x20 or c > 0x7e) return false;
    return true;
}

/// Check that a basis is complete: named, sourced, and carrying a real measurement.
pub fn checkBasis(basis: BenchmarkBasis) EstimateError!void {
    if (basis.name.len == 0 or basis.harness.len == 0 or basis.revision.len == 0 or
        basis.measured_clients == 0 or basis.rss_per_client_bytes == 0)
        return error.MissingBenchmarkBasis;
    if (!validBasisText(basis.name) or !validBasisText(basis.harness) or !validBasisText(basis.revision))
        return error.InvalidBenchmarkBasis;
}

fn consider(best: *Estimate, value: u64, which: Constraint) void {
    if (value < best.max_clients) {
        best.max_clients = value;
        best.binding = which;
    }
}

/// Capacity estimate: the smallest of the configured client cap, the memory
/// that fits at the measured per-client RSS, the descriptors left after the
/// reserve and mesh peers, and the egress budget at the measured per-client
/// rate. Refuses without a complete named basis.
pub fn estimate(cfg: Config, ctx: Context, host: Host) EstimateError!Estimate {
    try checkBasis(cfg.basis);
    var best: Estimate = .{
        .max_clients = ctx.max_clients,
        .binding = .config_max_clients,
        .basis = cfg.basis,
        .extrapolated = false,
    };
    const mem = if (cfg.memory_budget_bytes != 0) cfg.memory_budget_bytes else host.memory_bytes;
    if (mem != 0) consider(&best, mem / cfg.basis.rss_per_client_bytes, .memory);
    if (host.fd_limit != 0) {
        const held = @as(u64, cfg.fd_reserve) + @as(u64, ctx.mesh_connect_len);
        consider(&best, host.fd_limit -| held, .fd);
    }
    if (cfg.net_egress_bytes_per_sec != 0 and cfg.basis.egress_bytes_per_sec_per_client != 0)
        consider(&best, cfg.net_egress_bytes_per_sec / cfg.basis.egress_bytes_per_sec_per_client, .egress);
    const scale = std.math.mul(u64, cfg.basis.measured_clients, extrapolation_factor) catch std.math.maxInt(u64);
    best.extrapolated = best.max_clients > scale;
    return best;
}

/// One doctor/log line that always names the benchmark basis.
pub fn formatEstimate(buf: []u8, e: Estimate) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "estimated max_clients={d} bound_by={s} basis={s} harness={s} revision={s} measured_clients={d} rss_per_client_bytes={d}{s}", .{
        e.max_clients,
        @tagName(e.binding),
        e.basis.name,
        e.basis.harness,
        e.basis.revision,
        e.basis.measured_clients,
        e.basis.rss_per_client_bytes,
        if (e.extrapolated) " extrapolated=true" else "",
    });
}

const testing = std.testing;

fn testBasis() BenchmarkBasis {
    return .{
        .name = "pilot-1",
        .harness = "tools/bench_live.py --quick",
        .revision = "0.9.0+5bdd9dc55d99",
        .measured_clients = 1000,
        .rss_per_client_bytes = 64 * 1024,
        .egress_bytes_per_sec_per_client = 1000,
    };
}

test "resource_limits: defaults reproduce current behaviour (all budgets unset, validate returns null)" {
    const cfg: Config = .{};
    try testing.expectEqual(@as(u64, 0), cfg.memory_budget_bytes);
    try testing.expectEqual(@as(u64, 0), cfg.net_egress_bytes_per_sec);
    try testing.expectEqual(@as(u32, 64), cfg.fd_reserve);
    try testing.expect(validate(cfg, .{ .max_clients = 32767, .num_shards = 4096, .mesh_connect_len = 1000 }) == null);
    try testing.expect(admitByMemory(1 << 40, 1 << 20, 0));
    try testing.expectEqual(@as(u16, 7), effectiveShardCap(cfg, .{ .max_clients = 1, .num_shards = 7 }));
}

test "resource_limits: derivedPerClientBytes uses class sendq+recvq with overflow-safe math (saturating/checked)" {
    const ctx: Context = .{ .max_clients = 1, .sendq_cap_bytes = 1 << 20, .recvq_cap_bytes = 4096, .conn_fixed_bytes = 100 };
    try testing.expectEqual(@as(?u64, (1 << 20) + 4096 + 100), derivedPerClientBytes(ctx));
    var big = ctx;
    big.sendq_cap_bytes = std.math.maxInt(u64);
    try testing.expect(derivedPerClientBytes(big) == null);
    // The explicit override wins and needs no derivation.
    try testing.expectEqual(@as(?u64, 5), perClientBytes(.{ .per_client_memory_bytes = 5 }, big));
    try testing.expect(perClientBytes(.{}, big) == null);
}

test "resource_limits: validate rejects max_clients*per_client_bytes > memory_budget, cpu_max_shards < num_shards, mesh.connect.len > net_max_s2s_peers" {
    const ctx: Context = .{ .max_clients = 100, .num_shards = 4, .mesh_connect_len = 3, .sendq_cap_bytes = 1000, .conn_fixed_bytes = 24 };
    try testing.expect(validate(.{ .memory_budget_bytes = 102_400 }, ctx) == null);
    try testing.expectEqual(Violation.budget_below_max_clients, validate(.{ .memory_budget_bytes = 102_399 }, ctx).?);
    try testing.expectEqual(Violation.budget_below_max_clients, validate(.{ .memory_budget_bytes = 99_999, .per_client_memory_bytes = 1000 }, ctx).?);
    try testing.expect(validate(.{ .memory_budget_bytes = 100_000, .per_client_memory_bytes = 1000 }, ctx) == null);
    try testing.expectEqual(Violation.shards_below_configured, validate(.{ .cpu_max_shards = 3 }, ctx).?);
    try testing.expect(validate(.{ .cpu_max_shards = 4 }, ctx) == null);
    try testing.expectEqual(Violation.shards_above_ceiling, validate(.{ .cpu_max_shards = 4097 }, ctx).?);
    try testing.expectEqual(Violation.s2s_peers_above_cap, validate(.{ .net_max_s2s_peers = 2 }, ctx).?);
    try testing.expect(validate(.{ .net_max_s2s_peers = 3 }, ctx) == null);
    // A budget with unrepresentable arithmetic fails closed instead of wrapping.
    var huge = ctx;
    huge.sendq_cap_bytes = std.math.maxInt(u64) / 2;
    huge.max_clients = 4;
    try testing.expectEqual(Violation.per_client_overflow, validate(.{ .memory_budget_bytes = 1 }, huge).?);
    for (std.enums.values(Violation)) |v| try testing.expect(violationReason(v).len != 0);
}

test "resource_limits: admitByMemory admits up to the budget and fails closed on overflow" {
    try testing.expect(admitByMemory(0, 100, 100));
    try testing.expect(!admitByMemory(1, 100, 100));
    try testing.expect(admitByMemory(9, 100, 1000));
    try testing.expect(!admitByMemory(10, 100, 1000));
    try testing.expect(admitByMemory(5, 0, 1000));
    try testing.expect(!admitByMemory(std.math.maxInt(usize), 2, std.math.maxInt(u64)));
    try testing.expect(!admitByMemory(std.math.maxInt(usize), 1, std.math.maxInt(u64)));
}

test "resource_limits: estimate returns error.MissingBenchmarkBasis when basis name/harness empty or rss_per_client zero" {
    const ctx: Context = .{ .max_clients = 1024 };
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{}, ctx, .{}));
    var b = testBasis();
    b.name = "";
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
    b = testBasis();
    b.harness = "";
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
    b = testBasis();
    b.revision = "";
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
    b = testBasis();
    b.rss_per_client_bytes = 0;
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
    b = testBasis();
    b.measured_clients = 0;
    try testing.expectError(error.MissingBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
    // Control bytes in a name would corrupt a doctor line.
    b = testBasis();
    b.name = "bad\nname";
    try testing.expectError(error.InvalidBenchmarkBasis, estimate(.{ .basis = b }, ctx, .{}));
}

test "resource_limits: estimate picks binding constraint (memory vs fd vs config vs egress) and its formatted line contains basis name, harness and revision" {
    const b = testBasis();
    const ctx: Context = .{ .max_clients = 1000, .mesh_connect_len = 2 };

    // Config cap binds when the host is ample.
    var e = try estimate(.{ .basis = b }, ctx, .{ .memory_bytes = 1 << 40, .fd_limit = 1 << 20 });
    try testing.expectEqual(Constraint.config_max_clients, e.binding);
    try testing.expectEqual(@as(u64, 1000), e.max_clients);
    try testing.expect(!e.extrapolated);

    // Memory: 32 MiB / 64 KiB = 512.
    e = try estimate(.{ .basis = b, .memory_budget_bytes = 32 << 20 }, ctx, .{ .memory_bytes = 1 << 40 });
    try testing.expectEqual(Constraint.memory, e.binding);
    try testing.expectEqual(@as(u64, 512), e.max_clients);

    // Descriptors: 300 - 64 reserve - 2 peers = 234.
    e = try estimate(.{ .basis = b }, ctx, .{ .fd_limit = 300 });
    try testing.expectEqual(Constraint.fd, e.binding);
    try testing.expectEqual(@as(u64, 234), e.max_clients);

    // fd limit below the reserve saturates at zero rather than wrapping.
    e = try estimate(.{ .basis = b }, ctx, .{ .fd_limit = 10 });
    try testing.expectEqual(@as(u64, 0), e.max_clients);

    // Egress: 100000 B/s at 1000 B/s per client = 100.
    e = try estimate(.{ .basis = b, .net_egress_bytes_per_sec = 100_000 }, ctx, .{});
    try testing.expectEqual(Constraint.egress, e.binding);
    try testing.expectEqual(@as(u64, 100), e.max_clients);

    var buf: [512]u8 = undefined;
    const text = try formatEstimate(&buf, e);
    try testing.expect(std.mem.indexOf(u8, text, "basis=pilot-1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "harness=tools/bench_live.py --quick") != null);
    try testing.expect(std.mem.indexOf(u8, text, "revision=0.9.0+5bdd9dc55d99") != null);
    try testing.expect(std.mem.indexOf(u8, text, "bound_by=egress") != null);
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, formatEstimate(&tiny, e));
}

test "resource_limits: estimate flags extrapolated when result exceeds 2x basis.measured_clients" {
    const b = testBasis(); // measured at 1000 clients
    const at_limit = try estimate(.{ .basis = b }, .{ .max_clients = 2000 }, .{});
    try testing.expect(!at_limit.extrapolated);
    const beyond = try estimate(.{ .basis = b }, .{ .max_clients = 2001 }, .{});
    try testing.expect(beyond.extrapolated);
    var buf: [512]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, try formatEstimate(&buf, beyond), "extrapolated=true") != null);
    try testing.expect(std.mem.indexOf(u8, try formatEstimate(&buf, at_limit), "extrapolated") == null);
}
