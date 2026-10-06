// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trust anchors for daemon-initiated HTTPS. DER slices are borrowed by TLS
//! clients, so a Store must outlive every fetch using `anchors()` or
//! `disallowed()`.
const std = @import("std");
const builtin = @import("builtin");
const acme_cli = @import("acme_cli.zig");

const Allocator = std.mem.Allocator;
const windows = std.os.windows;
const crypt32 = windows.crypt32;

const max_certs: usize = 8192;
const max_cert_bytes: usize = 256 << 10;
const max_total_bytes: usize = 32 << 20;
const max_eku_bytes: usize = 4096;
const max_eku_oids: usize = 128;
const server_auth_oid = "1.3.6.1.5.5.7.3.1";
const any_eku_oid = "2.5.29.37.0";

const WinCrypt = struct {
    extern "crypt32" fn CertGetEnhancedKeyUsage(
        context: *const crypt32.CERT_CONTEXT,
        flags: u32,
        usage: ?*crypt32.CERT_ENHKEY_USAGE,
        size: *u32,
    ) callconv(.winapi) windows.BOOL;
};

const Disallowed = struct {
    allocator: Allocator,
    certs: std.ArrayList([]u8) = .empty,
    index: std.StringHashMapUnmanaged(void) = .empty,

    fn add(self: *Disallowed, der: []const u8) !void {
        if (self.index.contains(der)) return;
        const owned = try self.allocator.dupe(u8, der);
        errdefer self.allocator.free(owned);
        try self.certs.append(self.allocator, owned);
        errdefer self.certs.items.len -= 1;
        try self.index.put(self.allocator, owned, {});
    }

    fn contains(self: *const Disallowed, der: []const u8) bool {
        return self.index.contains(der);
    }

    fn deinit(self: *Disallowed) void {
        for (self.certs.items) |der| self.allocator.free(der);
        self.certs.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: Allocator,
    certs: std.ArrayList([]u8) = .empty,
    denied: Disallowed,

    pub fn anchors(self: *const Store) []const []const u8 {
        return self.certs.items;
    }

    /// Borrow the exact DER certificates from Windows' Disallowed store.
    /// Linux has no corresponding native store and returns an empty slice.
    pub fn disallowed(self: *const Store) []const []const u8 {
        return self.denied.certs.items;
    }

    pub fn deinit(self: *Store) void {
        for (self.certs.items) |der| self.allocator.free(der);
        self.certs.deinit(self.allocator);
        self.denied.deinit();
        self.* = undefined;
    }
};

/// Load the platform's HTTPS roots. Failure or an empty store denies outbound
/// certificate validation rather than silently accepting an untrusted peer.
pub fn load(allocator: Allocator, io: std.Io) !Store {
    return switch (builtin.os.tag) {
        .windows => loadWindows(allocator),
        .linux => loadLinux(allocator, io),
        else => error.UnsupportedPlatform,
    };
}

fn loadLinux(allocator: Allocator, io: std.Io) !Store {
    const paths = [_][]const u8{
        acme_cli.default_ca_bundle,
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
    };
    for (paths) |path| {
        const text = std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(acme_cli.default_ca_bundle_max_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer allocator.free(text);
        return loadPem(allocator, text);
    }
    return error.RootStoreUnavailable;
}

fn loadPem(allocator: Allocator, text: []const u8) !Store {
    var certs = try acme_cli.loadTrustAnchors(allocator, text);
    if (certs.items.len == 0) {
        certs.deinit(allocator);
        return error.NoTrustAnchors;
    }
    return .{ .allocator = allocator, .certs = certs, .denied = .{ .allocator = allocator } };
}

fn loadWindows(allocator: Allocator) !Store {
    var result: Store = .{ .allocator = allocator, .denied = try loadDisallowed(allocator) };
    errdefer result.deinit();

    const root = [4:0]u16{ 'R', 'O', 'O', 'T' };
    const handle = crypt32.CertOpenSystemStoreW(.NULL, &root) orelse return error.RootStoreUnavailable;
    defer _ = crypt32.CertCloseStore(handle, .{});

    var total_bytes: usize = 0;
    var count: usize = 0;
    var context: ?*crypt32.CERT_CONTEXT = null;
    defer {
        if (context) |cert| _ = crypt32.CertFreeCertificateContext(cert);
    }
    while (true) {
        // CertEnum frees its previous context, including on end-of-store.
        context = crypt32.CertEnumCertificatesInStore(handle, context);
        const cert = context orelse {
            if (windows.GetLastError() != .CRYPT_E_NOT_FOUND) return error.RootStoreEnumerationFailed;
            break;
        };
        const len: usize = cert.cbCertEncoded;
        if (len == 0 or len > max_cert_bytes or count >= max_certs or
            len > max_total_bytes - total_bytes) return error.RootStoreTooLarge;
        count += 1;
        total_bytes += len;
        const encoded = cert.pbCertEncoded[0..len];
        if (result.denied.contains(encoded) or !try allowsServerAuth(cert)) continue;
        const der = try allocator.dupe(u8, encoded);
        errdefer allocator.free(der);
        try result.certs.append(allocator, der);
    }
    if (result.certs.items.len == 0) return error.NoTrustAnchors;
    return result;
}

fn loadDisallowed(allocator: Allocator) !Disallowed {
    const name = [10:0]u16{ 'D', 'i', 's', 'a', 'l', 'l', 'o', 'w', 'e', 'd' };
    const handle = crypt32.CertOpenSystemStoreW(.NULL, &name) orelse return error.DisallowedStoreUnavailable;
    defer _ = crypt32.CertCloseStore(handle, .{});

    var result: Disallowed = .{ .allocator = allocator };
    errdefer result.deinit();
    var total_bytes: usize = 0;
    var count: usize = 0;
    var context: ?*crypt32.CERT_CONTEXT = null;
    defer {
        if (context) |cert| _ = crypt32.CertFreeCertificateContext(cert);
    }
    while (true) {
        context = crypt32.CertEnumCertificatesInStore(handle, context);
        const cert = context orelse {
            if (windows.GetLastError() != .CRYPT_E_NOT_FOUND) return error.DisallowedStoreEnumerationFailed;
            break;
        };
        const len: usize = cert.cbCertEncoded;
        if (len == 0 or len > max_cert_bytes or count >= max_certs or
            len > max_total_bytes - total_bytes) return error.DisallowedStoreTooLarge;
        count += 1;
        total_bytes += len;
        try result.add(cert.pbCertEncoded[0..len]);
    }
    return result;
}

fn allowsServerAuth(cert: *const crypt32.CERT_CONTEXT) !bool {
    var size: u32 = 0;
    if (!WinCrypt.CertGetEnhancedKeyUsage(cert, 0, null, &size).toBool()) return error.RootStoreUsageUnavailable;
    if (size < @sizeOf(crypt32.CERT_ENHKEY_USAGE) or size > max_eku_bytes) return error.RootStoreUsageTooLarge;
    var buffer: [max_eku_bytes]u8 align(@alignOf(crypt32.CERT_ENHKEY_USAGE)) = undefined;
    if (!WinCrypt.CertGetEnhancedKeyUsage(cert, 0, @ptrCast(&buffer), &size).toBool()) return error.RootStoreUsageUnavailable;
    if (size < @sizeOf(crypt32.CERT_ENHKEY_USAGE) or size > max_eku_bytes) return error.RootStoreUsageTooLarge;
    const usage: *const crypt32.CERT_ENHKEY_USAGE = @ptrCast(&buffer);
    return serverAuthInUsage(usage, windows.GetLastError());
}

fn serverAuthInUsage(usage: *const crypt32.CERT_ENHKEY_USAGE, last_error: windows.Win32Error) !bool {
    const count: usize = usage.cUsageIdentifier;
    if (count == 0) return last_error == .CRYPT_E_NOT_FOUND;
    if (count > max_eku_oids) return error.RootStoreUsageTooLarge;
    for (usage.rgpszUsageIdentifier[0..count]) |oid| {
        const text = std.mem.span(oid);
        if (std.mem.eql(u8, text, server_auth_oid) or std.mem.eql(u8, text, any_eku_oid)) return true;
    }
    return false;
}

test "outbound trust PEM owns decoded DER and rejects empty or malformed bundles" {
    const testing = std.testing;
    const pem =
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
    var store = try loadPem(testing.allocator, pem);
    defer store.deinit();
    try testing.expectEqual(@as(usize, 2), store.anchors().len);
    try testing.expectEqual(@as(usize, 0), store.disallowed().len);
    try testing.expectEqualSlices(u8, &.{ 0x30, 3, 2, 1, 0 }, store.anchors()[0]);
    try testing.expectEqualSlices(u8, &.{ 0x30, 3, 2, 1, 1 }, store.anchors()[1]);
    try testing.expectError(error.NoTrustAnchors, loadPem(testing.allocator, ""));
    try testing.expectError(error.NoTrustAnchors, loadPem(testing.allocator, "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----"));
}

fn testPemAllocationPath(allocator: Allocator) !void {
    const pem =
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
    var store = try loadPem(allocator, pem);
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 2), store.anchors().len);
}

test "outbound trust PEM allocation failures release every DER allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testPemAllocationPath, .{});
}

test "outbound trust effective EKU distinguishes all, none, and serverAuth" {
    const testing = std.testing;
    const no_oids = [_]windows.LPCSTR{""};
    const none: crypt32.CERT_ENHKEY_USAGE = .{ .cUsageIdentifier = 0, .rgpszUsageIdentifier = &no_oids };
    try testing.expect(try serverAuthInUsage(&none, .CRYPT_E_NOT_FOUND));
    try testing.expect(!try serverAuthInUsage(&none, .SUCCESS));
    try testing.expect(!try serverAuthInUsage(&none, .ACCESS_DENIED));

    const client_only = [_]windows.LPCSTR{"1.3.6.1.5.5.7.3.2"};
    const client: crypt32.CERT_ENHKEY_USAGE = .{ .cUsageIdentifier = 1, .rgpszUsageIdentifier = &client_only };
    try testing.expect(!try serverAuthInUsage(&client, .SUCCESS));

    const server = [_]windows.LPCSTR{"1.3.6.1.5.5.7.3.1"};
    const server_usage: crypt32.CERT_ENHKEY_USAGE = .{ .cUsageIdentifier = 1, .rgpszUsageIdentifier = &server };
    try testing.expect(try serverAuthInUsage(&server_usage, .SUCCESS));

    const any = [_]windows.LPCSTR{"2.5.29.37.0"};
    const any_usage: crypt32.CERT_ENHKEY_USAGE = .{ .cUsageIdentifier = 1, .rgpszUsageIdentifier = &any };
    try testing.expect(try serverAuthInUsage(&any_usage, .SUCCESS));
}

test "outbound trust Disallowed compares exact DER bytes" {
    var store: Store = .{ .allocator = std.testing.allocator, .denied = .{ .allocator = std.testing.allocator } };
    defer store.deinit();
    try store.denied.add(&.{ 0x30, 0x01, 0x41 });
    try store.denied.add(&.{ 0x30, 0x01, 0x41 });
    try std.testing.expect(store.denied.contains(&.{ 0x30, 0x01, 0x41 }));
    try std.testing.expect(!store.denied.contains(&.{ 0x30, 0x01, 0x42 }));
    try std.testing.expect(!store.denied.contains(&.{ 0x30, 0x01 }));
    try std.testing.expectEqual(@as(usize, 1), store.disallowed().len);
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x01, 0x41 }, store.disallowed()[0]);
}

fn testDisallowedAllocationPath(allocator: Allocator) !void {
    var denied: Disallowed = .{ .allocator = allocator };
    defer denied.deinit();
    try denied.add(&.{ 0x30, 0x01, 0x41 });
    try denied.add(&.{ 0x30, 0x01, 0x42 });
    try std.testing.expectEqual(@as(usize, 2), denied.certs.items.len);
}

test "outbound trust Disallowed allocation failures free retained DER" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testDisallowedAllocationPath, .{});
}

test "outbound trust native Windows ROOT is nonempty" {
    if (builtin.os.tag != .windows) return;
    var store = try load(std.testing.allocator, std.testing.io);
    defer store.deinit();
    try std.testing.expect(store.anchors().len > 0);
    for (store.anchors()) |der| {
        try std.testing.expect(der.len > 0);
        try std.testing.expect(!store.denied.contains(der));
    }
    for (store.disallowed()) |der| try std.testing.expect(der.len > 0);
}
