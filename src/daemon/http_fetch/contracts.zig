// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound HTTP errors and caller-owned request policy.

const std = @import("std");
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const tls12_client = @import("../../crypto/tls12_client.zig");
const sct = @import("../../crypto/sct.zig");

pub const Error = error{
    BadUrl,
    NoNameservers,
    HostNotFound,
    ResolveTimeout,
    ConnectFailed,
    ConnectTimeout,
    SocketUnavailable,
    ConnectionClosed,
    RecvTimeout,
    ResponseTooLarge,
} || std.mem.Allocator.Error || tls_client.Error || tls12_client.Error;

pub const Options = struct {
    /// Trust anchors (DER certs) for TLS verification; required when `url.tls`
    /// unless `insecure_skip_verify` is set.
    trust_anchors: []const []const u8 = &.{},
    /// Exact DER certificates that must never appear in the presented chain.
    /// Windows outbound HTTPS supplies its Disallowed store here.
    disallowed_certs: []const []const u8 = &.{},
    /// Require the Windows native HTTPS chain and CTL policy in addition to
    /// the Zig verifier. Production daemon HTTPS sets this with system roots.
    windows_chain_policy: bool = false,
    /// Skip server-certificate verification (TLS transport only). Intended as a
    /// documented escape hatch for public read-only feeds when a usable system
    /// CA bundle is unavailable; off by default.
    insecure_skip_verify: bool = false,
    /// Set after the first TCP connection succeeds. A caller may retry a
    /// different address only while this remains false; later failures could
    /// follow TLS or application bytes on the wire.
    connect_established: ?*bool = null,
    connect_timeout_ms: u31 = 5000,
    recv_timeout_ms: u31 = 10000,
    max_response_bytes: usize = 512 * 1024,
    /// Optional leaf CRL (DER) forwarded to both TLS clients. Empty/absent is
    /// the historical fail-open ACME/HTTPS posture.
    crl: ?[]const u8 = null,
    /// When true AND `crl` is set, an unusable CRL fails the handshake closed.
    require_crl: bool = false,
    /// Optional pinned CT logs for the TLS 1.3 client. Empty (default) skips
    /// the SCT path so ACME/HTTPS stay byte-identical. TLS 1.2 has no SCT
    /// wire; these fields are ignored on the 1.2 fallback.
    ct_logs: []const sct.CtLog = &.{},
    enforce_sct: bool = false,
    require_sct: u8 = 0,
};

/// Both address families for `host`, from one wait per nameserver. IPv4 and
/// IPv6 literals skip DNS. A nameserver of either family is queried; A and
/// AAAA share the timeout instead of walking the resolver twice.
pub const HostFamilies = struct {
    v4: ?[4]u8 = null,
    v6: ?[16]u8 = null,
};
