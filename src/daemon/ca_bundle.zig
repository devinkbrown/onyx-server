// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! PEM CA bundle -> owned DER trust anchors for outbound HTTPS.
//!
//! Shared by the ACME client (`acme_cli`, `acme_renewal`, CLI tools) and the
//! geo news fetcher. The bundle is an operator file in the usual
//! `ca-certificates.crt` shape: a concatenation of RFC 7468 §5.1
//! `-----BEGIN CERTIFICATE-----` blocks, optionally with explanatory text
//! between them (RFC 7468 §2 permits text outside the encapsulation
//! boundaries). Each block's body is the DER `Certificate` of RFC 5280 §4.1;
//! chain building and validation against these anchors is done by the TLS
//! client (RFC 8446 §4.4.2.2 / RFC 5280 §6).

const std = @import("std");
const pem = @import("../proto/pem.zig");

const Allocator = std.mem.Allocator;

/// Debian/Alpine/Arch system bundle. Also the ACME default.
pub const default_path = "/etc/ssl/certs/ca-certificates.crt";
/// Upper bound on a bundle read. The Mozilla store is ~220 KiB as PEM.
pub const default_max_bytes: usize = 4 << 20;

/// Decode every `CERTIFICATE` PEM block in `text` into owned DER, in order.
/// An oversize or malformed block is skipped so one bad root does not drop
/// the rest of the store; the caller decides whether an empty result is fatal.
pub fn loadTrustAnchors(allocator: Allocator, text: []const u8) !std.ArrayList([]u8) {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";

    var anchors: std.ArrayList([]u8) = .empty;
    errdefer freeTrustAnchors(allocator, &anchors);

    var scratch: [8192]u8 = undefined;
    var off: usize = 0;
    while (std.mem.indexOfPos(u8, text, off, begin)) |b| {
        const e = std.mem.indexOfPos(u8, text, b, end) orelse break;
        const block = text[b .. e + end.len];
        const der = pem.decode(block, "CERTIFICATE", &scratch) catch {
            off = e + end.len;
            continue; // skip an oversize/malformed root, keep the rest
        };
        const owned = try allocator.dupe(u8, der);
        errdefer allocator.free(owned);
        try anchors.append(allocator, owned);
        off = e + end.len;
    }
    return anchors;
}

pub fn freeTrustAnchors(allocator: Allocator, anchors: *std.ArrayList([]u8)) void {
    for (anchors.items) |a| allocator.free(a);
    anchors.deinit(allocator);
}

/// Owned, non-empty anchor set. Fails closed: a bundle with no decodable
/// certificate is an error, never an empty (verify-nothing) store.
pub const TrustStore = struct {
    anchors: std.ArrayList([]u8) = .empty,

    pub fn fromPem(allocator: Allocator, text: []const u8) !TrustStore {
        var anchors = try loadTrustAnchors(allocator, text);
        if (anchors.items.len == 0) {
            anchors.deinit(allocator);
            return error.NoTrustAnchors;
        }
        return .{ .anchors = anchors };
    }

    pub fn slice(self: *const TrustStore) []const []const u8 {
        return self.anchors.items;
    }

    pub fn deinit(self: *TrustStore, allocator: Allocator) void {
        freeTrustAnchors(allocator, &self.anchors);
        self.* = .{};
    }
};

test "TrustStore rejects a bundle with no certificates" {
    try std.testing.expectError(error.NoTrustAnchors, TrustStore.fromPem(std.testing.allocator, "not a bundle\n"));
    try std.testing.expectError(error.NoTrustAnchors, TrustStore.fromPem(std.testing.allocator, "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"));
}

test "TrustStore keeps every decodable certificate in order" {
    const text =
        "comment line\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n" ++
        "-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n";
    var store = try TrustStore.fromPem(std.testing.allocator, text);
    defer store.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), store.slice().len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, store.slice()[0]);
    try std.testing.expectEqualSlices(u8, &.{ 4, 5, 6 }, store.slice()[1]);
}
