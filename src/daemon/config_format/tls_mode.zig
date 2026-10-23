// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Decode TLS offload mode into the canonical configuration enum.

const std = @import("std");
const Config = @import("model.zig").Config;

/// Map a `[tls] ktls` string to the mode enum, or null for an unknown value.
pub fn parseKtlsMode(s: []const u8) ?Config.KtlsMode {
    if (std.mem.eql(u8, s, "off")) return .off;
    if (std.mem.eql(u8, s, "tx")) return .tx;
    if (std.mem.eql(u8, s, "txrx")) return .txrx;
    return null;
}
