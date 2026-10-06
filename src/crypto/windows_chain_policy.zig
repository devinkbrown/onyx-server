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

/// This is an additional native policy gate, never a substitute for the
/// existing pure-Zig chain, name, and signature checks. It does not fetch
/// issuers, roots, or CTLs over the network.
pub fn verify(chain: []const []const u8, server_name: []const u8) error{BadCertificate}!void {
    if (builtin.os.tag != .windows) return error.BadCertificate;
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

test "Windows chain policy rejects missing chain and malformed names" {
    if (builtin.os.tag != .windows) return;
    const testing = std.testing;
    try testing.expectError(error.BadCertificate, verify(&.{}, "example.com"));
    try testing.expectError(error.BadCertificate, verify(&.{&.{ 0x30, 0x00 }}, ""));
    try testing.expectError(error.BadCertificate, verify(&.{&.{ 0x30, 0x00 }}, "ex\x00ample.com"));
    try testing.expectError(error.BadCertificate, verify(&.{&.{ 0x30, 0x00 }}, "\xff"));
}

test "Windows chain policy rejects malformed certificate DER" {
    if (builtin.os.tag != .windows) return;
    try std.testing.expectError(error.BadCertificate, verify(&.{&.{ 0x30, 0x00 }}, "example.com"));
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
