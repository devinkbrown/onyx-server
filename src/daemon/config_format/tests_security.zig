// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration regression tests: security.

const std = @import("std");
const acme_cli = @import("../acme_cli.zig");
const acme_http01_listener = @import("../acme_http01_listener.zig");
const acme_runner = @import("../acme_runner.zig");
const testing = std.testing;
const Config = @import("model.zig").Config;
const acme_default_directory_url = @import("model.zig").acme_default_directory_url;
const parseToml = @import("projection.zig").parseToml;

test "parseToml: [dnsbl] enabled + zones + action project onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[dnsbl]
        \\enabled = true
        \\zones = ["zen.spamhaus.org", "dnsbl.dronebl.org"]
        \\action = "ward"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 2), cfg.dnsbl.zones.len);
    try testing.expectEqualStrings("zen.spamhaus.org", cfg.dnsbl.zones[0]);
    try testing.expectEqualStrings("dnsbl.dronebl.org", cfg.dnsbl.zones[1]);
    try testing.expect(cfg.dnsbl.ward); // action = "ward"
}

test "parseToml: [dnsbl] defaults are disabled, no zones, refuse" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(!cfg.dnsbl.enabled);
    try testing.expectEqual(@as(usize, 0), cfg.dnsbl.zones.len);
    try testing.expect(!cfg.dnsbl.ward);
}

test "parseToml: listen proxy protocol and SASL enabled gate project" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\proxy_protocol = true
        \\trusted_proxies = ["127.0.0.1", "::1"]
        \\[sasl]
        \\enabled = false
        \\realm = "ircxnet"
        \\account_db = "accounts.oro"
        \\allow_anonymous = true
        \\oauth_issuer = "https://issuer.example"
        \\oauth_audience = "onyx"
        \\oauth_account_claim = "preferred_username"
        \\oauth_hmac_key = "test-secret"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.listen.proxy_protocol);
    try testing.expectEqual(@as(usize, 2), cfg.listen.trusted_proxies.len);
    try testing.expectEqualStrings("127.0.0.1", cfg.listen.trusted_proxies[0]);
    try testing.expect(!cfg.sasl.enabled);
    try testing.expect(cfg.sasl.enabled_explicit);
    try testing.expect(cfg.sasl.allow_anonymous);
    try testing.expectEqualStrings("ircxnet", cfg.sasl.realm.?);
    try testing.expectEqualStrings("accounts.oro", cfg.sasl.account_db.?);
    try testing.expectEqualStrings("https://issuer.example", cfg.sasl.oauth_issuer.?);
    try testing.expectEqualStrings("onyx", cfg.sasl.oauth_audience.?);
    try testing.expectEqualStrings("preferred_username", cfg.sasl.oauth_account_claim.?);
    try testing.expectEqualStrings("test-secret", cfg.sasl.oauth_hmac_key.?);

    var omitted = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    , .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.sasl.enabled_explicit);
    try testing.expect(!omitted.sasl.allow_anonymous);
    try testing.expect(!omitted.sasl.oauth_auto_provision);
    try testing.expect(omitted.sasl.oauth_account_claim == null);
}

test "GAP-O11 outbound webhook private targets default off and parse on" {
    const allocator = testing.allocator;
    var omitted = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.webhook.allow_private_targets);
    try testing.expect(!omitted.webhook.enabled);

    var allowed = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[webhook]\nallow_private_targets=true\n", .{});
    defer allowed.deinit(allocator);
    try testing.expect(allowed.webhook.allow_private_targets);
    try testing.expect(!allowed.webhook.enabled);
}

test "GAP-P0b OAuth auto provision config defaults false and accepts true" {
    const allocator = testing.allocator;
    var omitted = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[sasl]\n", .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.sasl.oauth_auto_provision);

    var enabled = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[sasl]\noauth_auto_provision=true\n", .{});
    defer enabled.deinit(allocator);
    try testing.expect(enabled.sasl.oauth_auto_provision);
}

test "parseToml: [sasl] rejects multiple OAuth key sources" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\oauth_hmac_key = "secret"
        \\oauth_pubkey = "{}"
        \\
    ;
    try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
}

test "parseToml: [tls] section projects onto Config" {
    // Arrange
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\port = 7000
        \\cert_path = "/etc/onyx/leaf.pem"
        \\key_path = "/etc/onyx/leaf.key"
        \\dns_name = "irc.example.test"
        \\request_client_cert = true
        \\enable_tls12 = true
        \\enable_resumption = true
        \\early_data_max_size = 16384
        \\raw_public_key = true
        \\ktls = "tx"
        \\[[tls.ech_keys]]
        \\config_path = "/etc/onyx/echconfig.bin"
        \\private_key = "1111111111111111111111111111111111111111111111111111111111111111"
        \\
    ;

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 7000), cfg.tls.port);
    try testing.expectEqualStrings("/etc/onyx/leaf.pem", cfg.tls.cert_path.?);
    try testing.expectEqualStrings("/etc/onyx/leaf.key", cfg.tls.key_path.?);
    try testing.expectEqualStrings("irc.example.test", cfg.tls.dns_name);
    try testing.expect(cfg.tls.request_client_cert);
    // These three keys were declared in the schema but never parsed — a TLS 1.2
    // opt-in (and resumption/0-RTT) was silently ignored. Guard the wiring.
    try testing.expect(cfg.tls.enable_tls12);
    try testing.expect(cfg.tls.enable_resumption);
    try testing.expectEqual(@as(u32, 16384), cfg.tls.early_data_max_size);
    try testing.expect(cfg.tls.raw_public_key);
    try testing.expectEqual(Config.KtlsMode.tx, cfg.tls.ktls);
    try testing.expectEqual(@as(usize, 1), cfg.tls.ech_keys.len);
    try testing.expectEqualStrings("/etc/onyx/echconfig.bin", cfg.tls.ech_keys[0].config_path);
    try testing.expectEqual(@as([32]u8, @splat(0x11)), cfg.tls.ech_keys[0].private_key);
}

test "parseToml: [[tls.ech_keys]] rejects malformed private key" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\[[tls.ech_keys]]
        \\config_path = "/etc/onyx/echconfig.bin"
        \\private_key = "abcd"
        \\
    ;

    try testing.expectError(error.ParseError, parseToml(allocator, text, .{}));
}

test "GAP-K6 parseToml: [[tls.sni]] is the operator certificate list" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\cert_path = "/etc/onyx/default.pem"
        \\key_path = "/etc/onyx/default.key"
        \\[[tls.sni]]
        \\server_names = ["irc.example.test", "*.example.test"]
        \\cert_path = "/etc/onyx/example.pem"
        \\key_path = "/etc/onyx/example.key"
        \\[[tls.sni]]
        \\server_names = ["alt.test"]
        \\cert_path = "/etc/onyx/alt.pem"
        \\key_path = "/etc/onyx/alt.key"
        \\[[tls.ech_keys]]
        \\config_path = "/etc/onyx/echconfig.bin"
        \\private_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), cfg.tls.sni.len);
    try std.testing.expectEqualStrings("irc.example.test", cfg.tls.sni[0].server_names[0]);
    try std.testing.expectEqualStrings("*.example.test", cfg.tls.sni[0].server_names[1]);
    try std.testing.expectEqualStrings("/etc/onyx/example.pem", cfg.tls.sni[0].cert_path);
    try std.testing.expectEqualStrings("alt.test", cfg.tls.sni[1].server_names[0]);
    try std.testing.expectEqual(@as(usize, 1), cfg.tls.ech_keys.len);
    try std.testing.expectEqualStrings("/etc/onyx/echconfig.bin", cfg.tls.ech_keys[0].config_path);
}

test "parseToml: [[tls.sni]] projects additional SNI certs onto Config" {
    // Arrange
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[tls]
        \\enabled = true
        \\cert_path = "/etc/onyx/default.pem"
        \\key_path = "/etc/onyx/default.key"
        \\[[tls.sni]]
        \\server_names = ["irc.example.test", "*.example.test"]
        \\cert_path = "/etc/onyx/example.pem"
        \\key_path = "/etc/onyx/example.key"
        \\[[tls.sni]]
        \\server_names = ["alt.test"]
        \\cert_path = "/etc/onyx/alt.pem"
        \\key_path = "/etc/onyx/alt.key"
        \\
    ;

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert: the default cert is unaffected and both SNI entries parse in order.
    try testing.expectEqualStrings("/etc/onyx/default.pem", cfg.tls.cert_path.?);
    try testing.expectEqual(@as(usize, 2), cfg.tls.sni.len);
    try testing.expectEqual(@as(usize, 2), cfg.tls.sni[0].server_names.len);
    try testing.expectEqualStrings("irc.example.test", cfg.tls.sni[0].server_names[0]);
    try testing.expectEqualStrings("*.example.test", cfg.tls.sni[0].server_names[1]);
    try testing.expectEqualStrings("/etc/onyx/example.pem", cfg.tls.sni[0].cert_path);
    try testing.expectEqualStrings("/etc/onyx/example.key", cfg.tls.sni[0].key_path);
    try testing.expectEqual(@as(usize, 1), cfg.tls.sni[1].server_names.len);
    try testing.expectEqualStrings("alt.test", cfg.tls.sni[1].server_names[0]);
    try testing.expectEqualStrings("/etc/onyx/alt.pem", cfg.tls.sni[1].cert_path);
}

test "parseToml: [[tls.sni]] absent keeps sni empty (byte-identical default path)" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nenabled=true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), cfg.tls.sni.len);
}

test "parseToml: a [[tls.sni]] entry missing required keys is rejected" {
    const allocator = testing.allocator;
    const base = "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nenabled=true\n";
    // Missing key_path.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[\"a.test\"]\ncert_path=\"a.pem\"\n",
        .{},
    ));
    // Missing cert_path.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[\"a.test\"]\nkey_path=\"a.key\"\n",
        .{},
    ));
    // Missing server_names entirely.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\ncert_path=\"a.pem\"\nkey_path=\"a.key\"\n",
        .{},
    ));
    // Empty server_names list.
    try testing.expectError(error.ParseError, parseToml(
        allocator,
        base ++ "[[tls.sni]]\nserver_names=[]\ncert_path=\"a.pem\"\nkey_path=\"a.key\"\n",
        .{},
    ));
}

test "parseToml: ktls mode parses txrx and rejects an unknown value" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nktls = \"txrx\"\n", .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(Config.KtlsMode.txrx, cfg.tls.ktls);
    // An unrecognized mode is a hard config error, not a silent fallback.
    try testing.expectError(error.ParseError, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[tls]\nktls = \"bogus\"\n", .{}));
}

test "parseToml: [tls] omitted keeps secure defaults" {
    // Arrange
    const allocator = testing.allocator;
    const text = "[node]\nid = 1\n[listen]\nirc = 6680\n";

    // Act
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    // Assert
    try testing.expect(!cfg.tls.enabled);
    try testing.expectEqual(@as(u16, 6697), cfg.tls.port);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.cert_path);
    try testing.expectEqual(@as(?[]const u8, null), cfg.tls.key_path);
    try testing.expectEqualStrings("localhost", cfg.tls.dns_name);
    try testing.expectEqual(Config.KtlsMode.off, cfg.tls.ktls);
}

test "parseToml: [acme] section projects onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\enabled = true
        \\directory_url = "https://acme.example/directory"
        \\domain = "irc.example.test"
        \\contact = "mailto:admin@example.test"
        \\renew_before_days = 45
        \\check_interval = "6h"
        \\ca_bundle_path = "/etc/onyx/acme-ca.pem"
        \\ca_bundle_max_bytes = 1048576
        \\challenge_port = 14403
        \\max_steps = 96
        \\debug = true
        \\max_response_bytes = 131072
        \\error_body_preview_bytes = 256
        \\resolv_conf_max_bytes = 32768
        \\dns_port = 5353
        \\http01_listen_backlog = 32
        \\http01_accept_poll = "500ms"
        \\http01_conn_read_timeout = "10s"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);

    try testing.expect(cfg.acme.enabled);
    try testing.expectEqualStrings("https://acme.example/directory", cfg.acme.directory_url);
    try testing.expectEqualStrings("irc.example.test", cfg.acme.domain.?);
    try testing.expectEqualStrings("mailto:admin@example.test", cfg.acme.contact.?);
    try testing.expectEqual(@as(u16, 45), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 6 * 60 * 60 * 1000), cfg.acme.check_interval_ms);
    try testing.expectEqualStrings("/etc/onyx/acme-ca.pem", cfg.acme.ca_bundle_path);
    try testing.expectEqual(@as(u64, 1048576), cfg.acme.ca_bundle_max_bytes);
    try testing.expectEqual(@as(u16, 14403), cfg.acme.challenge_port);
    try testing.expectEqual(@as(u32, 96), cfg.acme.max_steps);
    try testing.expect(cfg.acme.debug);
    try testing.expectEqual(@as(u64, 131072), cfg.acme.max_response_bytes);
    try testing.expectEqual(@as(u64, 256), cfg.acme.error_body_preview_bytes);
    try testing.expectEqual(@as(u64, 32768), cfg.acme.resolv_conf_max_bytes);
    try testing.expectEqual(@as(u16, 5353), cfg.acme.dns_port);
    try testing.expectEqual(@as(u32, 32), cfg.acme.http01_listen_backlog);
    try testing.expectEqual(@as(u32, 500), cfg.acme.http01_accept_poll_ms);
    try testing.expectEqual(@as(u32, 10), cfg.acme.http01_conn_read_timeout_sec);
}

test "parseToml: [acme] omitted keeps renewal disabled defaults and validates ranges" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);

    try testing.expect(!cfg.acme.enabled);
    try testing.expectEqualStrings(acme_default_directory_url, cfg.acme.directory_url);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.domain);
    try testing.expectEqual(@as(?[]const u8, null), cfg.acme.contact);
    try testing.expectEqual(@as(u16, 30), cfg.acme.renew_before_days);
    try testing.expectEqual(@as(u64, 12 * 60 * 60 * 1000), cfg.acme.check_interval_ms);
    try testing.expectEqualStrings(acme_cli.default_ca_bundle, cfg.acme.ca_bundle_path);
    try testing.expectEqual(@as(u64, acme_cli.default_ca_bundle_max_bytes), cfg.acme.ca_bundle_max_bytes);
    try testing.expectEqual(acme_cli.default_challenge_port, cfg.acme.challenge_port);
    try testing.expectEqual(@as(u32, @intCast(acme_runner.default_max_steps)), cfg.acme.max_steps);
    try testing.expect(!cfg.acme.debug);
    try testing.expectEqual(@as(u64, acme_runner.default_max_response_bytes), cfg.acme.max_response_bytes);
    try testing.expectEqual(@as(u64, acme_runner.default_error_body_preview_bytes), cfg.acme.error_body_preview_bytes);
    try testing.expectEqual(@as(u64, acme_runner.default_resolv_conf_max_bytes), cfg.acme.resolv_conf_max_bytes);
    try testing.expectEqual(acme_runner.default_dns_port, cfg.acme.dns_port);
    try testing.expectEqual(@as(u32, acme_http01_listener.default_listen_backlog), cfg.acme.http01_listen_backlog);
    try testing.expectEqual(acme_http01_listener.default_accept_poll_ms, cfg.acme.http01_accept_poll_ms);
    try testing.expectEqual(acme_http01_listener.default_conn_read_timeout_sec, cfg.acme.http01_conn_read_timeout_sec);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 0
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\renew_before_days = 90
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[acme]
        \\check_interval = "0s"
        \\
    , .{}));
}

test "parseToml: [sts] section projects onto Config" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sts]
        \\enabled = true
        \\duration = 604800
        \\port = 7000
        \\preload = true
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 604800), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 7000), cfg.sts.port);
    try testing.expect(cfg.sts.preload);
}

test "parseToml: [sts] omitted keeps secure defaults" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    // STS off by default; never force-upgrade a plaintext deployment.
    try testing.expect(!cfg.sts.enabled);
    try testing.expectEqual(@as(u32, 2_592_000), cfg.sts.duration);
    try testing.expectEqual(@as(u16, 6697), cfg.sts.port);
    try testing.expect(!cfg.sts.preload);
}

test "parseToml: [webauthn] section projects rp_id + origins" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[webauthn]
        \\rp_id = "chat.example"
        \\origins = ["https://chat.example", "https://alt.example:8443"]
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("chat.example", cfg.webauthn.rp_id.?);
    try testing.expectEqual(@as(usize, 2), cfg.webauthn.origins.len);
    try testing.expectEqualStrings("https://chat.example", cfg.webauthn.origins[0]);
    try testing.expectEqualStrings("https://alt.example:8443", cfg.webauthn.origins[1]);
    // Hardening flags default off.
    try testing.expect(!cfg.webauthn.require_uv);
    try testing.expect(!cfg.webauthn.require_attestation);
}

test "parseToml: [webauthn] require_uv + require_attestation project when set" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[webauthn]
        \\rp_id = "chat.example"
        \\origins = ["https://chat.example"]
        \\require_uv = true
        \\require_attestation = true
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.webauthn.require_uv);
    try testing.expect(cfg.webauthn.require_attestation);
}

test "parseToml: [webauthn] omitted leaves the feature inert" {
    const allocator = testing.allocator;
    var cfg = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.webauthn.rp_id == null);
    try testing.expectEqual(@as(usize, 0), cfg.webauthn.origins.len);
    try testing.expect(!cfg.webauthn.require_uv);
    try testing.expect(!cfg.webauthn.require_attestation);
}
