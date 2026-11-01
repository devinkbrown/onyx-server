// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCG2 intent detection and public authority tuple decoding.

const std = @import("std");
const crypto_sign = @import("../../crypto/sign.zig");
const Resolver = @import("contracts.zig").Resolver;
const TomlError = @import("contracts.zig").TomlError;
const resolveStr = @import("values.zig").resolveStr;

/// Conservative fail-closed hint for normal boot: if a supplied config appears
/// to mention the OCG2 section but typed projection fails, main must not fall
/// back to an authority-disabled default. Comments are ignored; false positives
/// only make an already-invalid config fatal.
pub fn containsOcg2Intent(source: []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = if (std.mem.indexOfScalar(u8, raw_line, '#')) |comment|
            raw_line[0..comment]
        else
            raw_line;
        if (std.mem.indexOf(u8, line, "oper") != null and
            std.mem.indexOf(u8, line, "ocg2") != null) return true;
    }
    return false;
}

pub fn parseOcg2PublicKey(
    allocator: std.mem.Allocator,
    resolver: Resolver,
    raw: []const u8,
) TomlError![crypto_sign.public_key_len]u8 {
    const owned = try resolveStr(allocator, resolver, raw);
    defer allocator.free(owned);
    const text = std.mem.trim(u8, owned, " \t\r\n");
    var out: [crypto_sign.public_key_len]u8 = undefined;
    if (text.len == out.len * 2) {
        const decoded = std.fmt.hexToBytes(&out, text) catch
            return error.InvalidOcg2AuthorityPublicKey;
        if (decoded.len != out.len) return error.InvalidOcg2AuthorityPublicKey;
    } else {
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(text) catch
            return error.InvalidOcg2AuthorityPublicKey;
        if (decoded_len != out.len) return error.InvalidOcg2AuthorityPublicKey;
        std.base64.standard.Decoder.decode(&out, text) catch
            return error.InvalidOcg2AuthorityPublicKey;
    }
    return out;
}

pub fn parseOcg2NodeId(text: []const u8) ?u64 {
    if (text.len != 16) return null;
    const node_id = std.fmt.parseUnsigned(u64, text, 16) catch return null;
    return if (node_id == 0) null else node_id;
}
