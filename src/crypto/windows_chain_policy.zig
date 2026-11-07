// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Apply Windows' current certificate trust policy to a chain that the
//! pure-Zig TLS verifier has already authenticated. In particular, this
//! checks Windows trust-list restrictions that are not represented by the
//! ROOT store's encoded certificates alone.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const crypt32 = windows.crypt32;
const x509_verify = @import("x509_verify.zig");

const max_chain_certs = 32;
const max_cert_bytes = 256 << 10;
const max_name_bytes = 255;
const server_auth_oid: windows.LPCSTR = "1.3.6.1.5.5.7.3.1";

// Prefix of CERT_CHAIN_CONTEXT from wincrypt.h. Zig's WinCrypt binding uses
// an opaque context because most callers only pass it between APIs.
const ChainContextPrefix = extern struct {
    cbSize: u32,
    TrustStatus: extern struct {
        dwErrorStatus: u32,
        dwInfoStatus: u32,
    },
    cChain: u32,
};

/// The certificates handed to Windows for a pure-Zig `TrustedPath`: the
/// built path (leaf first, then the issuers the path search chose, in path
/// order) followed by the anchor that terminated it, unless the path already
/// ends with that exact anchor. Presented certificates that are not on the
/// path (extraneous, alternate cross-signs) are not offered, so Windows judges
/// the same chain the Zig verifier accepted. Empty when `out` is too small.
pub fn policyCerts(path: *const x509_verify.TrustedPath, out: [][]const u8) []const []const u8 {
    const certs = path.slice();
    const tip_is_anchor = certs.len != 0 and std.mem.eql(u8, certs[certs.len - 1], path.anchor);
    const add_anchor = path.anchor.len != 0 and !tip_is_anchor;
    const n = certs.len + @intFromBool(add_anchor);
    if (certs.len == 0 or n > out.len) return out[0..0];
    @memcpy(out[0..certs.len], certs);
    if (add_anchor) out[certs.len] = path.anchor;
    return out[0..n];
}

/// This is an additional native policy gate, never a substitute for the
/// existing pure-Zig chain, name, and signature checks. It receives the path
/// the Zig verifier built (`x509_verify.buildServerPath`), not the raw
/// presented chain. It does not fetch issuers, roots, or CTLs over the network.
pub fn verify(path: *const x509_verify.TrustedPath, server_name: []const u8) error{BadCertificate}!void {
    if (builtin.os.tag != .windows) return error.BadCertificate;
    var chain_buf: [max_chain_certs][]const u8 = undefined;
    const chain = policyCerts(path, &chain_buf);
    if (chain.len == 0 or chain.len > max_chain_certs or
        server_name.len == 0 or server_name.len > max_name_bytes or
        std.mem.indexOfScalar(u8, server_name, 0) != null) return error.BadCertificate;

    const wide_name = std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, server_name) catch return error.BadCertificate;
    defer std.heap.page_allocator.free(wide_name);

    // The leaf context remains valid until both the chain context and store
    // are released. The additional store supplies only the peer's presented
    // certificates; Windows still chooses trust from its system stores.
    const store = crypt32.CertOpenStore(.MEMORY, .{ .CERT = .ASN, .CMSG = .ASN }, .NULL, .{}, null) orelse return error.BadCertificate;
    defer _ = crypt32.CertCloseStore(store, .{});
    var leaf: ?*const crypt32.CERT_CONTEXT = null;
    defer {
        if (leaf) |context| _ = crypt32.CertFreeCertificateContext(context);
    }
    for (chain, 0..) |der, index| {
        if (der.len == 0 or der.len > max_cert_bytes) return error.BadCertificate;
        var context: ?*const crypt32.CERT_CONTEXT = null;
        if (!crypt32.CertAddEncodedCertificateToStore(
            store,
            .{ .CERT = .ASN, .CMSG = .ASN },
            der.ptr,
            @intCast(der.len),
            .ALWAYS,
            &context,
        ).toBool()) return error.BadCertificate;
        if (index == 0) {
            leaf = context orelse return error.BadCertificate;
        } else if (context) |added| {
            _ = crypt32.CertFreeCertificateContext(added);
        } else return error.BadCertificate;
    }

    const usage_oids = [_]windows.LPCSTR{server_auth_oid};
    const chain_para: crypt32.CERT_CHAIN.PARA = .{
        .RequestedUsage = .{
            .dwType = .AND,
            .Usage = .{
                .cUsageIdentifier = 1,
                .rgpszUsageIdentifier = &usage_oids,
            },
        },
    };
    var native_chain: *const crypt32.CERT_CHAIN.CONTEXT = undefined;
    // CACHE_ONLY_URL_RETRIEVAL (0x4) prevents AIA, CTL, and root URL fetches.
    // DISABLE_AUTH_ROOT_AUTO_UPDATE (0x100) prevents root auto-update; the
    // presented chain already supplies issuers, so disable AIA (0x2000) too.
    const offline_flags: crypt32.CERT_CHAIN = @bitCast(@as(u32, 0x00002104));
    if (!crypt32.CertGetCertificateChain(
        .CURRENT_USER,
        leaf.?,
        null,
        store,
        &chain_para,
        offline_flags,
        null,
        &native_chain,
    ).toBool()) return error.BadCertificate;
    defer crypt32.CertFreeCertificateChain(native_chain);

    const native_status: *const ChainContextPrefix = @ptrCast(@alignCast(native_chain));
    if (native_status.cbSize < @sizeOf(ChainContextPrefix) or native_status.cChain == 0 or
        native_status.TrustStatus.dwErrorStatus != 0) return error.BadCertificate;

    var ssl_policy: crypt32.HTTPSPolicyCallbackData = .{
        .dwAuthType = .SERVER,
        // Windows documents this matcher for DNS/CN names. The pure-Zig
        // verifier already checked an IP literal against iPAddress SAN.
        .pwszServerName = if (isIpLiteral(server_name)) null else wide_name.ptr,
    };
    const policy_para: crypt32.CERT_CHAIN.POLICY.PARA = .{
        .dwFlags = .{},
        .pvExtraPolicyPara = &ssl_policy,
    };
    var policy_status: crypt32.CERT_CHAIN.POLICY.STATUS = .{
        .dwError = .SUCCESS,
        .lChainIndex = -1,
        .lElementIndex = -1,
        .pvExtraPolicyStatus = null,
    };
    if (!crypt32.CertVerifyCertificateChainPolicy(.SSL, native_chain, &policy_para, &policy_status).toBool() or
        policy_status.dwError != .SUCCESS) return error.BadCertificate;
}

fn isIpLiteral(server_name: []const u8) bool {
    const bare = if (server_name.len >= 2 and server_name[0] == '[' and
        server_name[server_name.len - 1] == ']')
        server_name[1 .. server_name.len - 1]
    else
        server_name;
    _ = std.Io.net.IpAddress.parse(bare, 0) catch return false;
    return true;
}

fn testPath(certs: []const []const u8, anchor: []const u8) x509_verify.TrustedPath {
    var path: x509_verify.TrustedPath = .{ .anchor = anchor };
    @memcpy(path.certs[0..certs.len], certs);
    path.len = certs.len;
    return path;
}

test "Windows chain policy rejects missing chain and malformed names" {
    if (builtin.os.tag != .windows) return;
    const testing = std.testing;
    const bad = [_]u8{ 0x30, 0x00 };
    const empty = testPath(&.{}, &.{});
    try testing.expectError(error.BadCertificate, verify(&empty, "example.com"));
    const one = testPath(&.{&bad}, &.{});
    try testing.expectError(error.BadCertificate, verify(&one, ""));
    try testing.expectError(error.BadCertificate, verify(&one, "ex\x00ample.com"));
    try testing.expectError(error.BadCertificate, verify(&one, "\xff"));
}

test "Windows chain policy rejects malformed certificate DER" {
    if (builtin.os.tag != .windows) return;
    const one = testPath(&.{&[_]u8{ 0x30, 0x00 }}, &.{});
    try std.testing.expectError(error.BadCertificate, verify(&one, "example.com"));
}

test "Windows chain policy is fed the built path plus its anchor, not the presented chain" {
    const testing = std.testing;
    var buf: [max_chain_certs][]const u8 = undefined;
    // Path leaf -> inter, anchored at an external root: root is appended.
    const leaf = "leaf";
    const inter = "inter";
    const root = "root";
    const p1 = testPath(&.{ leaf, inter }, root);
    const got1 = policyCerts(&p1, &buf);
    try testing.expectEqual(@as(usize, 3), got1.len);
    try testing.expectEqualStrings(leaf, got1[0]);
    try testing.expectEqualStrings(inter, got1[1]);
    try testing.expectEqualStrings(root, got1[2]);
    // The path tip already IS the configured anchor: not duplicated.
    const p2 = testPath(&.{ leaf, root }, root);
    try testing.expectEqual(@as(usize, 2), policyCerts(&p2, &buf).len);
    // No room, or an empty path: nothing (verify then fails closed).
    try testing.expectEqual(@as(usize, 0), policyCerts(&p1, buf[0..2]).len);
    const p3 = testPath(&.{}, root);
    try testing.expectEqual(@as(usize, 0), policyCerts(&p3, &buf).len);
    // On non-Windows hosts the gate itself always fails closed.
    if (builtin.os.tag != .windows) try testing.expectError(error.BadCertificate, verify(&p1, "example.com"));
}

test "Windows chain policy distinguishes IP literals from DNS names" {
    const testing = std.testing;
    try testing.expect(isIpLiteral("192.0.2.1"));
    try testing.expect(isIpLiteral("2001:db8::1"));
    try testing.expect(isIpLiteral("[2001:db8::1]"));
    try testing.expect(!isIpLiteral("example.com"));
    try testing.expect(!isIpLiteral("192.0.2.999"));
    try testing.expect(!isIpLiteral("example.com:443"));
}
