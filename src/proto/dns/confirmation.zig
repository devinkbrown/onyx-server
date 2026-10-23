// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned PTR observation and forward confirmation under one absolute deadline.

const wire = @import("wire.zig");
const config = @import("resolver_config.zig");
const engine = @import("query_engine.zig");
const resolver = @import("resolver.zig");
const Deadline = @import("deadline.zig").Deadline;

pub const Observation = struct {
    name: wire.Name = .{},
    confirmed: bool = false,
};

/// A successful PTR remains owned by the result even when the confirming
/// lookup fails, disagrees, or exhausts the shared deadline. This observation
/// carries no cache lifetime or authority beyond `confirmed`.
pub fn resolveUntil(cfg: *const config.ResolverConfig, address: wire.Address, deadline: Deadline) Observation {
    var reverse_buf: [wire.max_domain_text_len]u8 = undefined;
    const reverse = wire.reverseName(&reverse_buf, address) catch return .{};
    const ptr = engine.resolveUntil(cfg, reverse, .ptr, deadline) catch return .{};
    if (ptr.outcome != .positive or ptr.ptr_name.len == 0) return .{};
    var observed = Observation{ .name = ptr.ptr_name };
    const forward = engine.resolveUntil(cfg, observed.name.slice(), if (address == .ipv6) .aaaa else .a, deadline) catch return observed;
    observed.confirmed = forward.outcome == .positive and resolver.forwardConfirms(address, forward.addressSlice());
    return observed;
}
