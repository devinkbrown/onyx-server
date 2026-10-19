// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic host/IP cloaking. Hierarchical cloaks are v2. The public
//! opaque cloak (plain and epoch) is v3: one 128-bit token, no subnet or geo.
//!
//! Every cloak segment is a keyed HMAC-SHA256 token over a *cumulative prefix*
//! of the real address. The hierarchical full-address token is 64 bits (16 hex) so two
//! distinct addresses never collide to the same cloak in practice; the coarser
//! subnet-prefix tokens are 32 bits (8 hex). Because each segment depends only
//! on the prefix up to that point:
//!
//!   * the SAME real input + key always yields the SAME cloak (deterministic),
//!   * a different key yields a completely different cloak (unlinkable),
//!   * two addresses in the same subnet SHARE the broad-prefix segments and
//!     differ in the specific ones, so subnet bans keep working without ever
//!     exposing the raw address.
//!
//! GeoIP context (ISO country + origin AS number) is MIXED IN as two visible,
//! ban-able labels (`a<asn>.<cc>`) between the masked IP tokens and the `ip`
//! marker — so an oper can `*.us.ip.<net>` (ban a country) or `*.a13335.*.ip.<net>`
//! (ban an ASN) while the exact address stays masked. Unknown geo renders the
//! placeholders `a0` / `xx`, keeping a stable shape.
//!
//! Shapes produced (with the default `ircxnet` suffix):
//!
//!   IPv4  `a.b.c.d`      -> `<f/32>.<t/24>.<t/16>.<t/8>.a<asn>.<cc>.ip.ircxnet`
//!   IPv6  `2001:db8::1`  -> `<f/128>.<t/64>.<t/56>.<t/48>.<t/32>.a<asn>.<cc>.ip6.ircxnet`
//!   opaque (max privacy) -> `<32 hex>.opq.<suffix>` (v3, 128 bits, no subnet/geo)
//!   anon epoch           -> `<32 hex>.opq.<suffix>` (`cloakOpaqueEpochV3`)
//!   rDNS  `dsl-1.isp.com`-> `ircxnet-<token>.isp.com`
//!   acct  `Kain`@`IRCXNet`-> `kain.users.ircxnet` (no key needed)
//!
//! The most specific token comes FIRST (leftmost), matching DNS semantics
//! where the rightmost labels are the broadest: masking the leading labels
//! while keeping a shared tail is exactly what makes wildcard bans coherent.
const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);
const Net = std.Io.net;

pub const key_len = 32;
pub const tag_len = std.crypto.hash.sha2.Sha256.digest_length;
pub const max_hostname_len = 253;
pub const max_cloak_len = max_hostname_len;

/// Hex digits per 32-bit subnet-prefix cloak token.
pub const token_hex_len = 8;
/// Hex digits for the wide, collision-resistant full-address token (64 bits).
/// A 32-bit token birthday-collides around 65k distinct addresses; 64 bits
/// pushes that past 4 billion, so two real addresses effectively never share a
/// cloak.
pub const full_token_hex_len = 16;
/// Hex digits for the v3 public opaque token (128 bits, one DNS label).
/// The v2 64-bit token stays for ban grace. v3 is what anonymous users show.
pub const wide_token_hex_len = 32;

/// Default network-identifying suffix carried by every cloaked host so users
/// and opers can tell at a glance that a host is cloaked. Configurable via
/// `[cloak] suffix`.
pub const default_suffix = "onyx";

/// Label between the account name and the network in account cloaks
/// (`<account>.users.<network>`).
pub const account_subdomain = "users";

/// Marker label placed before the suffix in an opaque (max-privacy) cloak.
pub const opaque_marker = "opq";

/// Placeholder country label when GeoIP has no answer (ISO reserves `xx` for
/// private use, so it never collides with a real code).
pub const unknown_country = "xx";

pub const CloakError = error{
    InvalidKey,
    InvalidHostname,
    InvalidAccount,
    OutputTooSmall,
};

/// Fixed-width key material for address cloaking.
///
/// The fixed 32-byte shape keeps the HMAC key path simple and gives callers a
/// single place to wipe key bytes when rotating or tearing down server state.
pub const SecretKey = struct {
    bytes: [key_len]u8,

    pub fn init(bytes: [key_len]u8) SecretKey {
        return .{ .bytes = bytes };
    }

    pub fn fromSlice(bytes: []const u8) CloakError!SecretKey {
        if (bytes.len != key_len) return error.InvalidKey;
        return .{ .bytes = bytes[0..key_len].* };
    }

    pub fn declassify(self: *const SecretKey) [key_len]u8 {
        return self.bytes;
    }

    pub fn wipe(self: *SecretKey) void {
        secureZero(&self.bytes);
    }
};

/// GeoIP context mixed into an IP cloak as visible, ban-able labels. Both fields
/// are optional; missing values render the stable `a0` / `xx` placeholders.
pub const Geo = struct {
    /// ISO-3166-1 alpha-2 country code (any case); non-letters are dropped and
    /// anything that is not exactly two letters renders as `xx`.
    country: []const u8 = "",
    /// Origin Autonomous System number; 0 means unknown (renders `a0`).
    asn: u32 = 0,

    pub const none: Geo = .{};
};

/// Formatting options for cloak output.
pub const Options = struct {
    /// Network-identifying suffix appended to IP cloaks (`....ip.<suffix>`)
    /// and used as the token-label prefix for hostname cloaks
    /// (`<suffix>-<token>.<domain>`). Must be hostname-safe.
    suffix: []const u8 = default_suffix,
};

/// Class of address recognized by `classify`.
pub const AddressKind = enum {
    ipv4,
    ipv6,
    hostname,
};

/// Return how `address` will be cloaked.
pub fn classify(address: []const u8) AddressKind {
    const parsed = Net.IpAddress.parse(address, 0) catch return .hostname;
    return switch (parsed) {
        .ip4 => .ipv4,
        .ip6 => .ipv6,
    };
}

/// Cloak an IPv4, IPv6, or resolved hostname into caller-provided storage,
/// mixing in `geo` for IP addresses (ignored for hostnames).
pub fn cloak(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    geo: Geo,
    options: Options,
) CloakError![]const u8 {
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        return switch (parsed) {
            .ip4 => |ip4| cloakIPv4(out, key, ip4.bytes, geo, options),
            .ip6 => |ip6| cloakIPv6(out, key, ip6.bytes, geo, options),
        };
    } else |_| {
        return cloakHostname(out, key, address, options);
    }
}

/// Cloak an IP address into an OPAQUE (max-privacy) cloak: a single 64-bit token
/// over the full address plus the `opq` marker — no subnet hierarchy and no geo,
/// so nothing about the address (not even country/ASN or which users share a
/// subnet) leaks. The cost is that opaque cloaks cannot be subnet-banned.
pub fn cloakOpaque(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    options: Options,
) CloakError![]const u8 {
    var full: [full_token_hex_len]u8 = undefined;
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        switch (parsed) {
            .ip4 => |ip4| token64(&full, key, "ip4/v2/opq|", ip4.bytes[0..4]),
            .ip6 => |ip6| token64(&full, key, "ip6/v2/opq|", ip6.bytes[0..16]),
        }
    } else |_| return error.InvalidHostname;
    return std.fmt.bufPrint(out, "{s}.{s}.{s}", .{ &full, opaque_marker, options.suffix }) catch error.OutputTooSmall;
}

/// Cloak an IP into an OPAQUE cloak that ROTATES with `epoch`: a single 64-bit
/// token over the full address plus the current epoch counter, then the `opq`
/// marker and network suffix. Serves two anonymity goals for *unauthenticated*
/// clients: the epoch salt makes the same address unlinkable across epochs
/// (retiring forever-linkability of a static-IP anonymous user), and the opaque
/// single-token form leaks no subnet co-membership. `epoch` is a PUBLIC
/// wall-clock rotation counter supplied by the caller; a fixed `epoch`
/// degenerates to a stable opaque cloak. Cannot be subnet-banned (by design —
/// anonymous moderation shifts to account bans + registration friction). A
/// distinct domain tag (`opqe`) keeps these tokens in their own key-separated
/// family, so an epoch cloak never equals the plain `cloakOpaque` token.
pub fn cloakOpaqueEpoch(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    epoch: u64,
    options: Options,
) CloakError![]const u8 {
    var full: [full_token_hex_len]u8 = undefined;
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        switch (parsed) {
            .ip4 => |ip4| token64Epoch(&full, key, "ip4/v2/opqe|", ip4.bytes[0..4], epoch),
            .ip6 => |ip6| token64Epoch(&full, key, "ip6/v2/opqe|", ip6.bytes[0..16], epoch),
        }
    } else |_| return error.InvalidHostname;
    return std.fmt.bufPrint(out, "{s}.{s}.{s}", .{ &full, opaque_marker, options.suffix }) catch error.OutputTooSmall;
}

/// v3 public opaque cloak: 128 bits over the full address, still one token and
/// still no subnet or geo labels. A distinct domain tag keeps it unlinkable to
/// the v2 64-bit token of the same address.
pub fn cloakOpaqueV3(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    options: Options,
) CloakError![]const u8 {
    var full: [wide_token_hex_len]u8 = undefined;
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        switch (parsed) {
            .ip4 => |ip4| token128(&full, key, "ip4/v3/opq|", ip4.bytes[0..4]),
            .ip6 => |ip6| token128(&full, key, "ip6/v3/opq|", ip6.bytes[0..16]),
        }
    } else |_| return error.InvalidHostname;
    return std.fmt.bufPrint(out, "{s}.{s}.{s}", .{ &full, opaque_marker, options.suffix }) catch error.OutputTooSmall;
}

/// v3 epoch opaque cloak. Same privacy shape as `cloakOpaqueEpoch` (no shared
/// subnet label, no geo) with a 128-bit token and a v3 domain tag, so a v2
/// epoch cloak of the same address and epoch never matches it.
pub fn cloakOpaqueEpochV3(
    out: []u8,
    key: *const SecretKey,
    address: []const u8,
    epoch: u64,
    options: Options,
) CloakError![]const u8 {
    var full: [wide_token_hex_len]u8 = undefined;
    if (Net.IpAddress.parse(address, 0)) |parsed| {
        switch (parsed) {
            .ip4 => |ip4| token128Epoch(&full, key, "ip4/v3/opqe|", ip4.bytes[0..4], epoch),
            .ip6 => |ip6| token128Epoch(&full, key, "ip6/v3/opqe|", ip6.bytes[0..16], epoch),
        }
    } else |_| return error.InvalidHostname;
    return std.fmt.bufPrint(out, "{s}.{s}.{s}", .{ &full, opaque_marker, options.suffix }) catch error.OutputTooSmall;
}

/// Cloak raw IPv4 bytes hierarchically: a 64-bit token over the full address,
/// then 32-bit tokens per cumulative prefix (/24, /16, /8), most specific
/// first, then the mixed-in `a<asn>.<cc>` geo labels, the `ip` marker, and the
/// network suffix.
pub fn cloakIPv4(
    out: []u8,
    key: *const SecretKey,
    address: [4]u8,
    geo: Geo,
    options: Options,
) CloakError![]const u8 {
    var t_full: [full_token_hex_len]u8 = undefined;
    var t_24: [token_hex_len]u8 = undefined;
    var t_16: [token_hex_len]u8 = undefined;
    var t_8: [token_hex_len]u8 = undefined;
    token64(&t_full, key, "ip4/v2/32|", address[0..4]);
    token32(&t_24, key, "ip4/v2/24|", address[0..3]);
    token32(&t_16, key, "ip4/v2/16|", address[0..2]);
    token32(&t_8, key, "ip4/v2/8|", address[0..1]);

    var n: usize = 0;
    try append(out, &n, &t_full);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_24);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_16);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_8);
    try appendByte(out, &n, '.');
    try appendGeo(out, &n, geo);
    try append(out, &n, "ip.");
    try append(out, &n, options.suffix);
    return out[0..n];
}

/// Cloak raw IPv6 bytes hierarchically at routing-structure granularity: a
/// 64-bit token over the full address, then 32-bit tokens per cumulative prefix
/// (/64, /56, /48, /32), most specific first, then the mixed-in `a<asn>.<cc>`
/// geo labels, the `ip6` marker, and the network suffix. Two addresses in the
/// same /64 share everything after the first label.
pub fn cloakIPv6(
    out: []u8,
    key: *const SecretKey,
    address: [16]u8,
    geo: Geo,
    options: Options,
) CloakError![]const u8 {
    var t_full: [full_token_hex_len]u8 = undefined;
    var t_64: [token_hex_len]u8 = undefined;
    var t_56: [token_hex_len]u8 = undefined;
    var t_48: [token_hex_len]u8 = undefined;
    var t_32: [token_hex_len]u8 = undefined;
    token64(&t_full, key, "ip6/v2/128|", address[0..16]);
    token32(&t_64, key, "ip6/v2/64|", address[0..8]);
    token32(&t_56, key, "ip6/v2/56|", address[0..7]);
    token32(&t_48, key, "ip6/v2/48|", address[0..6]);
    token32(&t_32, key, "ip6/v2/32|", address[0..4]);

    var n: usize = 0;
    try append(out, &n, &t_full);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_64);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_56);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_48);
    try appendByte(out, &n, '.');
    try append(out, &n, &t_32);
    try appendByte(out, &n, '.');
    try appendGeo(out, &n, geo);
    try append(out, &n, "ip6.");
    try append(out, &n, options.suffix);
    return out[0..n];
}

/// Cloak a resolved hostname: replace every label left of the registrable
/// domain with a single `<suffix>-<token>` label (token = keyed HMAC over the
/// FULL normalized hostname, so two hosts under the same domain are
/// unlinkable to each other and to their real names), keeping the registrable
/// domain + TLD visible so `*.example.com` bans still work.
///
/// A small public-suffix heuristic keeps three labels for multi-part TLDs
/// (`co.uk`, `com.au`, ...). At least one label is always masked: a host that
/// IS its own registrable domain keeps one fewer label. Single-label hosts
/// have no usable domain and fall back to `<suffix>-<token>.<suffix>`.
pub fn cloakHostname(
    out: []u8,
    key: *const SecretKey,
    hostname: []const u8,
    options: Options,
) CloakError![]const u8 {
    var normalized_buf: [max_hostname_len]u8 = undefined;
    const normalized = try normalizeHostname(&normalized_buf, hostname);

    var tok: [token_hex_len]u8 = undefined;
    token32(&tok, key, "host|", normalized);

    var n: usize = 0;
    try append(out, &n, options.suffix);
    try appendByte(out, &n, '-');
    try append(out, &n, &tok);
    try appendByte(out, &n, '.');

    const labels = countLabels(normalized);
    if (labels == 1) {
        try append(out, &n, options.suffix);
    } else {
        try append(out, &n, registrableSuffix(normalized, labels));
    }
    return out[0..n];
}

/// Friendly cloak for a logged-in account: `<account>.users.<network>`,
/// lowercased and sanitized to hostname-safe characters. Stable across
/// restarts and key rotation (no secret involved); the server decides when to
/// present this instead of the IP/host cloak.
pub fn cloakAccount(
    out: []u8,
    account: []const u8,
    network: []const u8,
) CloakError![]const u8 {
    var n: usize = 0;
    try appendSanitizedLabel(out, &n, account, error.InvalidAccount);
    try appendByte(out, &n, '.');
    try append(out, &n, account_subdomain);
    try appendByte(out, &n, '.');
    if (network.len == 0) {
        try append(out, &n, default_suffix);
    } else {
        try appendSanitizedLabel(out, &n, network, error.InvalidHostname);
    }
    return out[0..n];
}

/// Append the mixed-in geo labels `a<asn>.<cc>.` (with a trailing dot). Both
/// render stable placeholders when unknown so the cloak shape never varies:
/// `a0` for an unknown ASN, `xx` for an unknown/invalid country.
fn appendGeo(out: []u8, n: *usize, geo: Geo) CloakError!void {
    try appendByte(out, n, 'a');
    var asn_buf: [10]u8 = undefined;
    const asn_str = std.fmt.bufPrint(&asn_buf, "{d}", .{geo.asn}) catch return error.OutputTooSmall;
    try append(out, n, asn_str);
    try appendByte(out, n, '.');
    try appendCountry(out, n, geo.country);
    try appendByte(out, n, '.');
}

/// Append a 2-letter lowercase country code, or `xx` when the input is not
/// exactly two ASCII letters (covers empty, private-range, and junk input).
fn appendCountry(out: []u8, n: *usize, country: []const u8) CloakError!void {
    if (country.len == 2 and isAsciiLetter(country[0]) and isAsciiLetter(country[1])) {
        try appendByte(out, n, std.ascii.toLower(country[0]));
        try appendByte(out, n, std.ascii.toLower(country[1]));
    } else {
        try append(out, n, unknown_country);
    }
}

fn isAsciiLetter(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

/// Derive one 32-bit cloak token: HMAC-SHA256(key, domain || data) truncated to
/// 4 bytes and rendered as 8 lowercase hex digits. The versioned domain string
/// separates token families so tokens over the same bytes for different scopes
/// (or scheme versions) can never be related.
fn token32(out: *[token_hex_len]u8, key: *const SecretKey, domain: []const u8, data: []const u8) void {
    var tag = macTag(key, domain, data);
    defer secureZero(&tag);
    hexEncode(out, tag[0 .. token_hex_len / 2]);
}

/// Derive one 64-bit collision-resistant token (16 hex) for the full address.
fn token64(out: *[full_token_hex_len]u8, key: *const SecretKey, domain: []const u8, data: []const u8) void {
    var tag = macTag(key, domain, data);
    defer secureZero(&tag);
    hexEncode(out, tag[0 .. full_token_hex_len / 2]);
}

/// Like `token64` but folds a public rotation `epoch` into the MAC, so the same
/// address under the same key rotates to a fresh token each epoch. Used only by
/// the anonymous opaque-cloak path (`cloakOpaqueEpoch`).
fn token64Epoch(out: *[full_token_hex_len]u8, key: *const SecretKey, domain: []const u8, data: []const u8, epoch: u64) void {
    var tag = macTagEpoch(key, domain, data, epoch);
    defer secureZero(&tag);
    hexEncode(out, tag[0 .. full_token_hex_len / 2]);
}

fn token128(out: *[wide_token_hex_len]u8, key: *const SecretKey, domain: []const u8, data: []const u8) void {
    var tag = macTag(key, domain, data);
    defer secureZero(&tag);
    hexEncode(out, tag[0 .. wide_token_hex_len / 2]);
}

fn token128Epoch(out: *[wide_token_hex_len]u8, key: *const SecretKey, domain: []const u8, data: []const u8, epoch: u64) void {
    var tag = macTagEpoch(key, domain, data, epoch);
    defer secureZero(&tag);
    hexEncode(out, tag[0 .. wide_token_hex_len / 2]);
}

/// HMAC-SHA256(key, domain || data). Key bytes are wiped after use.
fn macTag(key: *const SecretKey, domain: []const u8, data: []const u8) [tag_len]u8 {
    return macCore(key, domain, data, null);
}

/// HMAC-SHA256(key, domain || data || epoch_be64). `epoch` is a PUBLIC value (a
/// wall-clock rotation counter), so folding it in adds no secret-dependent
/// branch — the only branch is on its presence, never on the key.
fn macTagEpoch(key: *const SecretKey, domain: []const u8, data: []const u8, epoch: u64) [tag_len]u8 {
    return macCore(key, domain, data, epoch);
}

/// Shared HMAC core. With `epoch == null` this is byte-identical to the plain
/// `HMAC-SHA256(key, domain || data)` used by every non-epoch token, so the
/// account/hierarchical/opaque/hostname paths are provably unchanged. Key bytes
/// are wiped after use.
fn macCore(key: *const SecretKey, domain: []const u8, data: []const u8, epoch: ?u64) [tag_len]u8 {
    var key_bytes = key.declassify();
    defer secureZero(&key_bytes);
    var tag: [tag_len]u8 = undefined;
    var mac = HmacSha256.init(&key_bytes);
    mac.update(domain);
    mac.update(data);
    if (epoch) |e| {
        var ebuf: [8]u8 = undefined;
        std.mem.writeInt(u64, &ebuf, e, .big);
        mac.update(&ebuf);
    }
    mac.final(&tag);
    return tag;
}

fn hexEncode(out: []u8, bytes: []const u8) void {
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex_digit[byte >> 4];
        out[i * 2 + 1] = hex_digit[byte & 0x0f];
    }
}

/// The visible (kept) tail of a multi-label hostname: normally the last two
/// labels, three when the last two look like a multi-part public suffix
/// (both three bytes or fewer, e.g. `co.uk`), clamped so at least one label
/// is always masked.
fn registrableSuffix(normalized: []const u8, labels: usize) []const u8 {
    std.debug.assert(labels >= 2);
    var keep: usize = 2;
    if (labels >= 3) {
        const last = lastLabel(normalized);
        const before = lastLabel(normalized[0 .. normalized.len - last.len - 1]);
        if (last.len <= 3 and before.len <= 3) keep = 3;
    }
    if (keep >= labels) keep = labels - 1;

    // Walk back over `keep` dots from the end to find the suffix start.
    var dots: usize = 0;
    var i = normalized.len;
    while (i > 0) {
        i -= 1;
        if (normalized[i] == '.') {
            dots += 1;
            if (dots == keep) return normalized[i + 1 ..];
        }
    }
    return normalized;
}

fn lastLabel(s: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, s, '.')) |i| return s[i + 1 ..];
    return s;
}

fn normalizeHostname(out: *[max_hostname_len]u8, hostname: []const u8) CloakError![]const u8 {
    if (hostname.len == 0) return error.InvalidHostname;
    var in = hostname;
    if (in[in.len - 1] == '.') {
        in = in[0 .. in.len - 1];
    }
    if (in.len == 0 or in.len > max_hostname_len) return error.InvalidHostname;

    var label_len: usize = 0;
    for (in, 0..) |c, i| {
        if (c == '.') {
            if (label_len == 0) return error.InvalidHostname;
            label_len = 0;
            out[i] = c;
            continue;
        }
        if (!isHostnameByte(c)) return error.InvalidHostname;
        label_len += 1;
        if (label_len > 63) return error.InvalidHostname;
        out[i] = std.ascii.toLower(c);
    }
    if (label_len == 0) return error.InvalidHostname;
    return out[0..in.len];
}

fn countLabels(hostname: []const u8) usize {
    var labels: usize = 1;
    for (hostname) |c| {
        labels += @intFromBool(c == '.');
    }
    return labels;
}

/// Append `value` lowercased with non-hostname bytes mapped to '-', trimmed
/// of leading/trailing '-'. Fails with `empty_err` when nothing usable
/// remains or the resulting label would exceed the DNS label limit.
/// Sanitize `value` into a single hostname label — lowercased, non-hostname
/// bytes mapped to `-`, and leading/trailing `-` trimmed — exactly the transform
/// `cloakAccount` applies to the account label. Returns null when `value` reduces
/// to empty or overflows `out`. Public so callers (e.g. the VHOST CLAIM
/// account-binding) can compare a requested host's leading label against the
/// account apples-to-apples with the friendly `<account>.users.<suffix>` cloak.
pub fn sanitizeLabel(out: []u8, value: []const u8) ?[]const u8 {
    var n: usize = 0;
    appendSanitizedLabel(out, &n, value, error.InvalidAccount) catch return null;
    return out[0..n];
}

fn appendSanitizedLabel(
    out: []u8,
    n: *usize,
    value: []const u8,
    comptime empty_err: CloakError,
) CloakError!void {
    var buf: [63]u8 = undefined;
    var len: usize = 0;
    for (value) |c| {
        const mapped: u8 = if (isHostnameByte(c)) std.ascii.toLower(c) else '-';
        if (len == 0 and mapped == '-') continue; // trim leading
        if (len >= buf.len) return empty_err;
        buf[len] = mapped;
        len += 1;
    }
    while (len > 0 and buf[len - 1] == '-') len -= 1; // trim trailing
    if (len == 0) return empty_err;
    try append(out, n, buf[0..len]);
}

fn append(out: []u8, n: *usize, bytes: []const u8) CloakError!void {
    if (out.len - n.* < bytes.len) return error.OutputTooSmall;
    @memcpy(out[n.*..][0..bytes.len], bytes);
    n.* += bytes.len;
}

fn appendByte(out: []u8, n: *usize, byte: u8) CloakError!void {
    if (out.len - n.* == 0) return error.OutputTooSmall;
    out[n.*] = byte;
    n.* += 1;
}

fn isHostnameByte(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-' => true,
        else => false,
    };
}

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

const hex_digit = "0123456789abcdef";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_key = SecretKey.init([_]u8{
    0x6d, 0x69, 0x7a, 0x75, 0x63, 0x68, 0x69, 0x20,
    0x63, 0x6c, 0x6f, 0x61, 0x6b, 0x20, 0x6b, 0x65,
    0x79, 0x20, 0x76, 0x31, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x21, 0x00,
});

const other_key = SecretKey.init(@as([key_len]u8, @splat(0xa5)));

const geo_us = Geo{ .country = "US", .asn = 13335 };

/// Split a dotted cloak into its labels (test helper).
fn splitLabels(buf: *[16][]const u8, host: []const u8) [][]const u8 {
    var it = std.mem.splitScalar(u8, host, '.');
    var n: usize = 0;
    while (it.next()) |label| {
        buf[n] = label;
        n += 1;
    }
    return buf[0..n];
}

fn isHexToken(label: []const u8, expect_len: usize) bool {
    if (label.len != expect_len) return false;
    for (label) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

test "same IP gets the same stable cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.99", geo_us, .{});
    const cb = try cloak(&b, &test_key, "203.0.113.99", geo_us, .{});
    try testing.expectEqualSlices(u8, ca, cb);
}

test "different IPs get different cloaks" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.99", geo_us, .{});
    const cb = try cloak(&b, &test_key, "203.0.113.100", geo_us, .{});
    try testing.expect(!std.mem.eql(u8, ca, cb));
}

test "IPv4 cloak shape: 64-bit full token, geo labels, no raw octet" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "203.0.113.99", geo_us, .{});

    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, c);
    // <full16>.<t24>.<t16>.<t8>.a13335.us.ip.ircxnet
    try testing.expectEqual(@as(usize, 8), labels.len);
    try testing.expect(isHexToken(labels[0], full_token_hex_len));
    try testing.expect(isHexToken(labels[1], token_hex_len));
    try testing.expect(isHexToken(labels[2], token_hex_len));
    try testing.expect(isHexToken(labels[3], token_hex_len));
    try testing.expectEqualStrings("a13335", labels[4]);
    try testing.expectEqualStrings("us", labels[5]);
    try testing.expectEqualStrings("ip", labels[6]);
    try testing.expectEqualStrings(default_suffix, labels[7]);

    for (labels) |label| {
        try testing.expect(!std.mem.eql(u8, label, "203"));
        try testing.expect(!std.mem.eql(u8, label, "113"));
        try testing.expect(!std.mem.eql(u8, label, "99"));
    }
}

test "IPv4 subnet coherence: same /24 shares upper segments" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.5", geo_us, .{});
    const cb = try cloak(&b, &test_key, "203.0.113.77", geo_us, .{});

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);

    try testing.expect(!std.mem.eql(u8, la[0], lb[0])); // /32 differs
    try testing.expectEqualStrings(la[1], lb[1]); // shared /24
    try testing.expectEqualStrings(la[2], lb[2]); // shared /16
    try testing.expectEqualStrings(la[3], lb[3]); // shared /8
}

test "IPv4 /16 shared but /24 differs" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.5", geo_us, .{});
    const cb = try cloak(&b, &test_key, "203.0.200.5", geo_us, .{});
    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);
    try testing.expect(!std.mem.eql(u8, la[1], lb[1])); // /24 differs
    try testing.expectEqualStrings(la[2], lb[2]); // shared /16
    try testing.expectEqualStrings(la[3], lb[3]); // shared /8
}

test "geo labels ban a country and an ASN via wildcards" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "203.0.113.99", geo_us, .{});
    // Country ban `*.us.ip.onyx`
    try testing.expect(std.mem.endsWith(u8, c, ".us.ip." ++ default_suffix));
    // ASN label present for `*.a13335.*.ip.onyx`
    try testing.expect(std.mem.containsAtLeast(u8, c, 1, ".a13335."));
}

test "unknown geo renders stable a0.xx placeholders" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "203.0.113.99", Geo.none, .{});
    try testing.expect(std.mem.containsAtLeast(u8, c, 1, ".a0.xx.ip."));

    // Junk / wrong-length country also falls back to xx.
    var out2: [max_cloak_len]u8 = undefined;
    const c2 = try cloak(&out2, &test_key, "203.0.113.99", .{ .country = "USA", .asn = 1 }, .{});
    try testing.expect(std.mem.containsAtLeast(u8, c2, 1, ".a1.xx.ip."));
}

test "geo labels do not affect the IP tokens (subnet bans stay geo-independent)" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.99", geo_us, .{});
    const cb = try cloak(&b, &test_key, "203.0.113.99", Geo.none, .{});
    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);
    // The four IP tokens are identical regardless of geo.
    try testing.expectEqualStrings(la[0], lb[0]);
    try testing.expectEqualStrings(la[1], lb[1]);
    try testing.expectEqualStrings(la[2], lb[2]);
    try testing.expectEqualStrings(la[3], lb[3]);
}

test "IPv6 cloak shape, determinism, and /64 / /56 / /48 coherence" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;

    const ca = try cloak(&a, &test_key, "2001:db8:85a3:1:8a2e:370:7334:1234", geo_us, .{});
    const ca2 = try cloak(&a2, &test_key, "2001:db8:85a3:1:8a2e:370:7334:1234", geo_us, .{});
    const cb = try cloak(&b, &test_key, "2001:db8:85a3:1:dead:beef:cafe:1", geo_us, .{}); // same /64
    const cc = try cloak(&c, &test_key, "2001:db8:85a3:ffff:1:2:3:4", geo_us, .{}); // same /48, diff /56/64

    try testing.expectEqualSlices(u8, ca, ca2);

    var la_buf: [16][]const u8 = undefined;
    var lb_buf: [16][]const u8 = undefined;
    var lc_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    const lb = splitLabels(&lb_buf, cb);
    const lc = splitLabels(&lc_buf, cc);

    // <full16>.<t64>.<t56>.<t48>.<t32>.a13335.us.ip6.ircxnet = 9 labels
    try testing.expectEqual(@as(usize, 9), la.len);
    try testing.expect(isHexToken(la[0], full_token_hex_len));
    try testing.expect(isHexToken(la[1], token_hex_len));
    try testing.expectEqualStrings("a13335", la[5]);
    try testing.expectEqualStrings("us", la[6]);
    try testing.expectEqualStrings("ip6", la[7]);
    try testing.expectEqualStrings(default_suffix, la[8]);

    // Same /64: only the full token differs; /64, /56, /48, /32 shared.
    try testing.expect(!std.mem.eql(u8, la[0], lb[0]));
    try testing.expectEqualStrings(la[1], lb[1]);
    try testing.expectEqualStrings(la[2], lb[2]);
    try testing.expectEqualStrings(la[3], lb[3]);
    try testing.expectEqualStrings(la[4], lb[4]);

    // Same /48: /64 and /56 differ, /48 and /32 shared.
    try testing.expect(!std.mem.eql(u8, la[1], lc[1]));
    try testing.expect(!std.mem.eql(u8, la[2], lc[2]));
    try testing.expectEqualStrings(la[3], lc[3]);
    try testing.expectEqualStrings(la[4], lc[4]);
}

test "opaque cloak is one token, no subnet or geo structure" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;

    const ca = try cloakOpaque(&a, &test_key, "203.0.113.5", .{});
    const ca2 = try cloakOpaque(&a2, &test_key, "203.0.113.5", .{});
    const cb = try cloakOpaque(&b, &test_key, "203.0.113.77", .{}); // same /24

    try testing.expectEqualSlices(u8, ca, ca2); // deterministic

    var la_buf: [16][]const u8 = undefined;
    const la = splitLabels(&la_buf, ca);
    try testing.expectEqual(@as(usize, 3), la.len); // <full>.opq.suffix
    try testing.expect(isHexToken(la[0], full_token_hex_len));
    try testing.expectEqualStrings(opaque_marker, la[1]);
    try testing.expectEqualStrings(default_suffix, la[2]);

    // Same /24 shares NOTHING under opaque (no subnet leak).
    try testing.expect(!std.mem.eql(u8, ca, cb));

    // Opaque cloak differs from the structured cloak of the same IP.
    var s: [max_cloak_len]u8 = undefined;
    const structured = try cloak(&s, &test_key, "203.0.113.5", geo_us, .{});
    try testing.expect(!std.mem.eql(u8, ca, structured));
}

test "different secret produces a completely different cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    inline for (.{ "203.0.113.99", "2001:db8::1" }) |addr| {
        const ca = try cloak(&a, &test_key, addr, geo_us, .{});
        const cb = try cloak(&b, &other_key, addr, geo_us, .{});
        try testing.expect(!std.mem.eql(u8, ca, cb));
        var la_buf: [16][]const u8 = undefined;
        var lb_buf: [16][]const u8 = undefined;
        const la = splitLabels(&la_buf, ca);
        const lb = splitLabels(&lb_buf, cb);
        try testing.expect(!std.mem.eql(u8, la[0], lb[0])); // per-key unlinkable
    }
}

test "custom suffix flows through IP + opaque forms" {
    const opts: Options = .{ .suffix = "mynet" };
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "203.0.113.99", geo_us, opts);
    const cb = try cloak(&b, &test_key, "2001:db8::1", geo_us, opts);
    const cc = try cloakOpaque(&c, &test_key, "203.0.113.99", opts);
    try testing.expect(std.mem.endsWith(u8, ca, ".ip.mynet"));
    try testing.expect(std.mem.endsWith(u8, cb, ".ip6.mynet"));
    try testing.expect(std.mem.endsWith(u8, cc, ".opq.mynet"));
}

test "hostnames mask all dynamic labels and preserve the registrable domain" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "Client-123.POOL.Example.Net", Geo.none, .{});
    try testing.expect(std.mem.endsWith(u8, c, ".example.net"));
    try testing.expect(std.mem.startsWith(u8, c, default_suffix ++ "-"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "client-123"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "pool"));
}

test "hostname cloak is deterministic and unlinkable across siblings" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloak(&a, &test_key, "alpha.example.com", Geo.none, .{});
    const cb = try cloak(&b, &test_key, "beta.example.com", Geo.none, .{});
    try testing.expect(!std.mem.eql(u8, ca, cb));
    try testing.expect(std.mem.endsWith(u8, ca, ".example.com"));
}

test "multi-part TLDs keep three labels" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloak(&out, &test_key, "dsl-99.cust.foo.co.uk", Geo.none, .{});
    try testing.expect(std.mem.endsWith(u8, c, ".foo.co.uk"));
    try testing.expect(!std.mem.containsAtLeast(u8, c, 1, "dsl-99"));
}

test "account cloak is friendly, sanitized, and key-free" {
    var out: [max_cloak_len]u8 = undefined;
    const c = try cloakAccount(&out, "Kain", "IRCXNet");
    try testing.expectEqualStrings("kain.users.ircxnet", c);
    const c2 = try cloakAccount(&out, "Some_User!", "IRCXNet");
    try testing.expectEqualStrings("some-user.users.ircxnet", c2);
}

test "account cloak rejects unusable account names" {
    var out: [max_cloak_len]u8 = undefined;
    try testing.expectError(error.InvalidAccount, cloakAccount(&out, "", "net"));
    try testing.expectError(error.InvalidAccount, cloakAccount(&out, "!!!", "net"));
}

test "small output buffers fail cleanly" {
    var out: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, cloak(&out, &test_key, "203.0.113.99", geo_us, .{}));
    try testing.expectError(error.OutputTooSmall, cloakOpaque(&out, &test_key, "203.0.113.99", .{}));
    try testing.expectError(error.OutputTooSmall, cloakAccount(&out, "kain", "ircxnet"));
}

test "opaque epoch cloak: stable within an epoch, rotates across epochs" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const e1a = try cloakOpaqueEpoch(&a, &test_key, "203.0.113.5", 100, .{});
    const e1b = try cloakOpaqueEpoch(&a2, &test_key, "203.0.113.5", 100, .{});
    const e2 = try cloakOpaqueEpoch(&b, &test_key, "203.0.113.5", 101, .{});

    // Same epoch + IP + key => identical (stable within one epoch).
    try testing.expectEqualSlices(u8, e1a, e1b);
    // Different epoch => different cloak (forever-linkability retired).
    try testing.expect(!std.mem.eql(u8, e1a, e2));

    // Still the opaque shape: <full16>.opq.<suffix>.
    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, e1a);
    try testing.expectEqual(@as(usize, 3), labels.len);
    try testing.expect(isHexToken(labels[0], full_token_hex_len));
    try testing.expectEqualStrings(opaque_marker, labels[1]);
    try testing.expectEqualStrings(default_suffix, labels[2]);
}

test "opaque epoch cloak hides subnet co-membership" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ca = try cloakOpaqueEpoch(&a, &test_key, "203.0.113.5", 7, .{});
    const cb = try cloakOpaqueEpoch(&b, &test_key, "203.0.113.77", 7, .{}); // same /24
    // Opaque form shares NOTHING for two addresses in the same /24.
    try testing.expect(!std.mem.eql(u8, ca, cb));
}

test "opaque epoch cloak is a key-separated family from the plain opaque cloak" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const plain = try cloakOpaque(&a, &test_key, "203.0.113.5", .{});
    const epoched = try cloakOpaqueEpoch(&b, &test_key, "203.0.113.5", 0, .{});
    // Distinct domain tag (`opqe`) => even epoch 0 differs from the plain token.
    try testing.expect(!std.mem.eql(u8, plain, epoched));
}

test "opaque epoch cloak: IPv6 rotates and keeps the opaque tail" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const e1 = try cloakOpaqueEpoch(&a, &test_key, "2001:db8::1", 5, .{});
    const e2 = try cloakOpaqueEpoch(&b, &test_key, "2001:db8::1", 6, .{});
    try testing.expect(!std.mem.eql(u8, e1, e2));
    try testing.expect(std.mem.endsWith(u8, e1, ".opq." ++ default_suffix));
}

test "opaque epoch cloak: a different key yields an unlinkable rotation" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    const ka = try cloakOpaqueEpoch(&a, &test_key, "203.0.113.5", 42, .{});
    const kb = try cloakOpaqueEpoch(&b, &other_key, "203.0.113.5", 42, .{});
    try testing.expect(!std.mem.eql(u8, ka, kb));
}

test "opaque epoch cloak: small output buffer fails cleanly" {
    var out: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, cloakOpaqueEpoch(&out, &test_key, "203.0.113.5", 1, .{}));
}

test "v3 opaque cloak is 128 bits and shares nothing with a neighbor or with v2" {
    var a: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;
    const ca = try cloakOpaqueV3(&a, &test_key, "203.0.113.5", .{});
    const cb = try cloakOpaqueV3(&b, &test_key, "203.0.113.77", .{});
    const v2 = try cloakOpaque(&c, &test_key, "203.0.113.5", .{});

    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, ca);
    try testing.expectEqual(@as(usize, 3), labels.len);
    try testing.expect(isHexToken(labels[0], wide_token_hex_len));
    try testing.expectEqualStrings(opaque_marker, labels[1]);
    try testing.expectEqualStrings(default_suffix, labels[2]);
    try testing.expect(!std.mem.eql(u8, ca, cb));
    try testing.expect(!std.mem.eql(u8, ca, v2));
}

test "v3 epoch cloak rotates, hides a shared subnet, and is not the v2 token" {
    var a: [max_cloak_len]u8 = undefined;
    var a2: [max_cloak_len]u8 = undefined;
    var b: [max_cloak_len]u8 = undefined;
    var c: [max_cloak_len]u8 = undefined;
    var d: [max_cloak_len]u8 = undefined;
    const e1 = try cloakOpaqueEpochV3(&a, &test_key, "203.0.113.5", 9, .{});
    const e1b = try cloakOpaqueEpochV3(&a2, &test_key, "203.0.113.5", 9, .{});
    const e2 = try cloakOpaqueEpochV3(&b, &test_key, "203.0.113.5", 10, .{});
    const neighbor = try cloakOpaqueEpochV3(&c, &test_key, "203.0.113.77", 9, .{});
    const v2 = try cloakOpaqueEpoch(&d, &test_key, "203.0.113.5", 9, .{});
    try testing.expectEqualSlices(u8, e1, e1b);
    try testing.expect(!std.mem.eql(u8, e1, e2));
    try testing.expect(!std.mem.eql(u8, e1, neighbor));
    try testing.expect(!std.mem.eql(u8, e1, v2));
    try testing.expect(std.mem.endsWith(u8, e1, ".opq." ++ default_suffix));

    var v6a: [max_cloak_len]u8 = undefined;
    var v6b: [max_cloak_len]u8 = undefined;
    const v6e1 = try cloakOpaqueEpochV3(&v6a, &test_key, "2001:db8::1", 3, .{});
    const v6e2 = try cloakOpaqueEpochV3(&v6b, &test_key, "2001:db8::1", 4, .{});
    try testing.expect(!std.mem.eql(u8, v6e1, v6e2));
    var lbuf: [16][]const u8 = undefined;
    const labels = splitLabels(&lbuf, v6e1);
    try testing.expect(isHexToken(labels[0], wide_token_hex_len));
}

test "v3 epoch cloak rejects a non-address and a short buffer" {
    var out: [max_cloak_len]u8 = undefined;
    try testing.expectError(error.InvalidHostname, cloakOpaqueEpochV3(&out, &test_key, "host.example", 1, .{}));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, cloakOpaqueV3(&tiny, &test_key, "203.0.113.5", .{}));
    try testing.expectError(error.OutputTooSmall, cloakOpaqueEpochV3(&tiny, &test_key, "2001:db8::1", 1, .{}));
}

test "classify recognizes address kinds" {
    try testing.expectEqual(AddressKind.ipv4, classify("198.51.100.7"));
    try testing.expectEqual(AddressKind.ipv6, classify("2001:db8::1"));
    try testing.expectEqual(AddressKind.hostname, classify("host.example.com"));
}

test {
    testing.refAllDecls(@This());
}
