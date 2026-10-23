// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compatible resolver entry points over the bounded UDP/TCP query engine.
//! These calls wait on native sockets and belong on dedicated worker threads.

const wire = @import("wire.zig");
const config = @import("resolver_config.zig");
const engine = @import("query_engine.zig");
const response = @import("response.zig");
const Deadline = @import("deadline.zig").Deadline;

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
} || wire.EncodeError || wire.DecodeError;

/// Pure FCrDNS decision: is `address` present in a PTR name's forward A/AAAA set?
pub fn forwardConfirms(address: wire.Address, forward_addrs: []const wire.Address) bool {
    for (forward_addrs) |candidate| if (wire.addressEql(candidate, address)) return true;
    return false;
}

/// Forward-resolve A/AAAA into caller-owned storage. Existing callers retain
/// their error vocabulary; detailed outcomes and TTLs are available via resolve.
pub fn resolveForward(cfg: *const config.ResolverConfig, name: []const u8, want_v6: bool, out: []wire.Address) ResolveError![]wire.Address {
    const result = engine.resolve(cfg, name, if (want_v6) .aaaa else .a, .{}) catch |err| return legacyError(err);
    try requirePositive(result);
    const count = @min(out.len, result.address_count);
    if (count == 0) return error.NoData;
    @memcpy(out[0..count], result.addresses[0..count]);
    return out[0..count];
}

/// Reverse-resolve an address to an owned caller-buffer PTR name.
pub fn resolveReverse(cfg: *const config.ResolverConfig, address: wire.Address, name_out: []u8) ResolveError![]const u8 {
    return reverseUntil(cfg, address, name_out, Deadline.after(engine.defaultBudget(cfg)));
}

fn reverseUntil(cfg: *const config.ResolverConfig, address: wire.Address, name_out: []u8, deadline: Deadline) ResolveError![]const u8 {
    var query_name: [wire.max_domain_text_len]u8 = undefined;
    const name = try wire.reverseName(&query_name, address);
    const result = engine.resolveUntil(cfg, name, .ptr, deadline) catch |err| return legacyError(err);
    try requirePositive(result);
    const ptr = result.ptr_name.slice();
    if (ptr.len == 0 or ptr.len > name_out.len) return error.NoData;
    @memcpy(name_out[0..ptr.len], ptr);
    return name_out[0..ptr.len];
}

/// PTR and its confirming A/AAAA lookup share one absolute budget. Failed or
/// unconfirmed lookups return null so the caller retains its IP-based identity.
pub fn resolveConfirmed(cfg: *const config.ResolverConfig, address: wire.Address, name_out: []u8) ?[]const u8 {
    const deadline = Deadline.after(engine.defaultBudget(cfg));
    const name = reverseUntil(cfg, address, name_out, deadline) catch return null;
    const result = engine.resolveUntil(cfg, name, if (address == .ipv6) .aaaa else .a, deadline) catch return null;
    if (result.outcome != .positive or !forwardConfirms(address, result.addressSlice())) return null;
    return name;
}

fn requirePositive(result: response.Result) ResolveError!void {
    switch (result.outcome) {
        .positive => {},
        .nxdomain => return error.NameError,
        .nodata, .alias => return error.NoData,
    }
}

fn legacyError(err: engine.Error) ResolveError {
    // Historically endpoint I/O, malformed packets and server errors exhausted
    // retries as Timeout. Keep that contract for exhaustive legacy callers.
    return switch (err) {
        error.NoNameservers => error.NoNameservers,
        error.InvalidConfig => error.SocketUnavailable,
        error.RandomSourceFailed => error.RandomSourceFailed,
        error.OutputTooSmall => error.OutputTooSmall,
        error.InvalidName => error.InvalidName,
        error.NameTooLong => error.NameTooLong,
        error.UnsupportedType => error.UnsupportedType,
        else => error.Timeout,
    };
}

test {
    _ = @import("resolver_tests.zig");
}
