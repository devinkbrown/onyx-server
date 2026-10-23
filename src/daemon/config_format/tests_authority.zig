// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration regression tests: authority.

const std = @import("std");
const crypto_sign = @import("../../crypto/sign.zig");
const node_identity = @import("../node_identity.zig");
const node_short_id = @import("../../crypto/node_short_id.zig");
const wasm_bridge = @import("../../wasm/host/bridge.zig");
const testing = std.testing;
const parseToml = @import("projection.zig").parseToml;

test "parseToml: wasm allowed_caps parses hostcall policy and rejects unknown tokens" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_caps = ["reply", "STORE", "hooks", "net:outbound"]
        \\allowed_intents = ["message-content"]
        \\registry = [{ name = "guard", blake3 = "0000000000000000000000000000000000000000000000000000000000000000", tier = "verified", publisher = "1111111111111111111111111111111111111111111111111111111111111111", signature = "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222" }]
        \\revoked_blake3 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        \\disabled_plugins = ["bad", "bridge-discord.wasm"]
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.wasm.allowed_caps.has(.reply));
    try testing.expect(cfg.wasm.allowed_caps.has(.store));
    try testing.expect(cfg.wasm.allowed_caps.has(.hooks));
    try testing.expect(cfg.wasm.allowed_caps.has(.net_outbound));
    try testing.expect(!cfg.wasm.allowed_caps.has(.time));
    try testing.expect(cfg.wasm.allowed_intents.has(.message_content));
    try testing.expectEqual(@as(usize, 1), cfg.wasm.registry.len);
    try testing.expectEqualStrings("guard", cfg.wasm.registry[0].name);
    try testing.expectEqual(wasm_bridge.TrustTier.verified, cfg.wasm.registry[0].tier);
    try testing.expect(cfg.wasm.registry[0].publisher != null);
    try testing.expect(cfg.wasm.registry[0].signature != null);
    try testing.expectEqual(@as(u8, 0x11), cfg.wasm.registry[0].publisher.?[0]);
    try testing.expectEqual(@as(u8, 0x22), cfg.wasm.registry[0].signature.?[0]);
    try testing.expectEqual(@as(usize, 1), cfg.wasm.revoked_blake3.len);
    try testing.expectEqual(@as(u8, 0xaa), cfg.wasm.revoked_blake3[0][0]);
    try testing.expectEqual(@as(usize, 2), cfg.wasm.disabled_plugins.len);
    try testing.expectEqualStrings("bad", cfg.wasm.disabled_plugins[0]);
    try testing.expectEqualStrings("bridge-discord.wasm", cfg.wasm.disabled_plugins[1]);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_caps = ["reply", "net:inbound"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\allowed_intents = ["plaintext"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\revoked_blake3 = ["aa"]
        \\
    , .{}));

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[wasm]
        \\registry = [{ name = "guard", blake3 = "0000000000000000000000000000000000000000000000000000000000000000", publisher = "1111111111111111111111111111111111111111111111111111111111111111" }]
        \\
    , .{}));
}

test "parseToml: [[opers]] array-of-tables + trust_roots list" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[mesh]
        \\realm = "ircxnet"
        \\mesh_pass = "shared-secret"
        \\trust_roots = ["root-a", "root-b"]
        \\admission_token = "aabbcc"
        \\admission_roots = ["signer-a", "signer-b"]
        \\admission_min_revocation_epoch = 7
        \\connect = ["ircx.us:6900", "[::1]:7900"]
        \\[[opers]]
        \\account = "admin"
        \\class = "netadmin"
        \\[[opers]]
        \\account = "helper"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqualStrings("ircxnet", cfg.mesh.realm);
    try testing.expectEqualStrings("shared-secret", cfg.mesh.mesh_pass.?);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.trust_roots.len);
    try testing.expectEqualStrings("root-b", cfg.mesh.trust_roots[1]);
    try testing.expectEqualStrings("aabbcc", cfg.mesh.admission_token.?);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.admission_roots.len);
    try testing.expectEqualStrings("signer-b", cfg.mesh.admission_roots[1]);
    try testing.expectEqual(@as(u64, 7), cfg.mesh.admission_min_revocation_epoch);
    try testing.expectEqual(@as(usize, 2), cfg.mesh.connect.len);
    try testing.expectEqualStrings("ircx.us:6900", cfg.mesh.connect[0]);
    try testing.expectEqualStrings("[::1]:7900", cfg.mesh.connect[1]);
    try testing.expectEqual(@as(usize, 2), cfg.opers.len);
    try testing.expectEqualStrings("admin", cfg.opers[0].account);
    try testing.expectEqualStrings("netadmin", cfg.opers[0].class);
    try testing.expectEqualStrings("helper", cfg.opers[1].account);
    try testing.expectEqualStrings("", cfg.opers[1].class);
}

test "parseToml: [[opers]] certfp accepts a single string or an array" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[[opers]]
        \\account = "single"
        \\class = "admin"
        \\certfp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\[[opers]]
        \\account = "multi"
        \\class = "admin"
        \\certfp = ["aaaa", "bbbb"]
        \\[[opers]]
        \\account = "none"
        \\class = "admin"
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 3), cfg.opers.len);
    // Single string -> one-element list.
    try testing.expectEqual(@as(usize, 1), cfg.opers[0].certfp.len);
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", cfg.opers[0].certfp[0]);
    // Array -> multi-element list (owned verbatim; validation is at seed time).
    try testing.expectEqual(@as(usize, 2), cfg.opers[1].certfp.len);
    try testing.expectEqualStrings("aaaa", cfg.opers[1].certfp[0]);
    try testing.expectEqualStrings("bbbb", cfg.opers[1].certfp[1]);
    // Omitted -> empty (default), no allocation.
    try testing.expectEqual(@as(usize, 0), cfg.opers[2].certfp.len);
}

test "GAP-O9 two-person rule defaults off and parses on" {
    const allocator = testing.allocator;
    var omitted = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expect(!omitted.oper.two_person_rule);

    var enabled = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[oper]\ntwo_person_rule=true\n", .{});
    defer enabled.deinit(allocator);
    try testing.expect(enabled.oper.two_person_rule);
}

test "OCG2 config freezes exact public authority tuple and account store dependency" {
    const allocator = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB1)));
    const public_key = kp.public_key.toBytes();
    const authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key));
    const public_hex = std.fmt.bytesToHex(public_key, .lower);
    const text = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = {d}
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(text);
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.oper_ocg2.enabled);
    try testing.expectEqual(authority_node_id, cfg.oper_ocg2.authority_node_id);
    try testing.expectEqualSlices(u8, &public_key, &cfg.oper_ocg2.authority_public_key.?);

    const missing_key =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = 1
        \\
    ;
    try testing.expectError(error.MissingOcg2AuthorityPublicKey, parseToml(allocator, missing_key, .{}));

    const missing_store = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = {d}
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(missing_store);
    try testing.expectError(error.Ocg2RequiresAccountStore, parseToml(allocator, missing_store, .{}));

    const wrong_node = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = {d}
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id ^ 1, &public_hex });
    defer allocator.free(wrong_node);
    try testing.expectError(error.Ocg2AuthorityNodeIdMismatch, parseToml(allocator, wrong_node, .{}));

    const undersized_store = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[storage]
        \\max_record_bytes = 65536
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = {d}
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(undersized_store);
    try testing.expectError(
        error.Ocg2StorageRecordLimitTooSmall,
        parseToml(allocator, undersized_store, .{}),
    );

    const private_field = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = {d}
        \\authority_public_key = "{s}"
        \\private_key = "must-never-be-accepted"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(private_field);
    try testing.expectError(error.UnknownOcg2Field, parseToml(allocator, private_field, .{}));

    var high_seed: u16 = 0;
    var high_public_key: [crypto_sign.public_key_len]u8 = undefined;
    var high_node_id: u64 = 0;
    while (high_seed <= std.math.maxInt(u8)) : (high_seed += 1) {
        const high_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(
            @as([32]u8, @splat(@as(u8, @intCast(high_seed)))),
        );
        const candidate_key = high_kp.public_key.toBytes();
        const candidate_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(candidate_key));
        if (candidate_id > std.math.maxInt(i64)) {
            high_public_key = candidate_key;
            high_node_id = candidate_id;
            break;
        }
    }
    try testing.expect(high_node_id > std.math.maxInt(i64));
    const high_public_hex = std.fmt.bytesToHex(high_public_key, .lower);
    const high_id_text = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\authority_node_id = "{x:0>16}"
        \\authority_public_key = "{s}"
        \\
    , .{ high_node_id, &high_public_hex });
    defer allocator.free(high_id_text);
    var high_cfg = try parseToml(allocator, high_id_text, .{});
    defer high_cfg.deinit(allocator);
    try testing.expectEqual(high_node_id, high_cfg.oper_ocg2.authority_node_id);
}

test "parseToml: OCG2 activation flags default off and accept staged projection and minting" {
    const allocator = testing.allocator;
    var defaults = try parseToml(
        allocator,
        "[node]\nid = 1\n[listen]\nirc = 6680\n",
        .{},
    );
    defer defaults.deinit(allocator);
    try testing.expect(!defaults.oper_ocg2.enabled);
    try testing.expect(!defaults.oper_ocg2.projection_enabled);
    try testing.expect(!defaults.oper_ocg2.minting_enabled);

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB2)));
    const public_key = kp.public_key.toBytes();
    const authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key));
    const public_hex = std.fmt.bytesToHex(public_key, .lower);

    const projection_text = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\projection_enabled = true
        \\authority_node_id = "{x:0>16}"
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(projection_text);
    var projection = try parseToml(allocator, projection_text, .{});
    defer projection.deinit(allocator);
    try testing.expect(projection.oper_ocg2.enabled);
    try testing.expect(projection.oper_ocg2.projection_enabled);
    try testing.expect(!projection.oper_ocg2.minting_enabled);

    const minting_text = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\projection_enabled = true
        \\minting_enabled = true
        \\authority_node_id = "{x:0>16}"
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(minting_text);
    var minting = try parseToml(allocator, minting_text, .{});
    defer minting.deinit(allocator);
    try testing.expect(minting.oper_ocg2.enabled);
    try testing.expect(minting.oper_ocg2.projection_enabled);
    try testing.expect(minting.oper_ocg2.minting_enabled);
}

test "parseToml: OCG2 activation flags reject unsafe combinations types and unknown fields" {
    const allocator = testing.allocator;
    try testing.expectError(
        error.Ocg2ProjectionRequiresEnabled,
        parseToml(allocator,
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[oper.ocg2]
            \\projection_enabled = true
            \\
        , .{}),
    );
    try testing.expectError(
        error.Ocg2MintingRequiresEnabled,
        parseToml(allocator,
            \\[node]
            \\id = 1
            \\[listen]
            \\irc = 6680
            \\[oper.ocg2]
            \\projection_enabled = true
            \\minting_enabled = true
            \\
        , .{}),
    );

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB3)));
    const public_key = kp.public_key.toBytes();
    const authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key));
    const public_hex = std.fmt.bytesToHex(public_key, .lower);
    const mint_without_projection = try std.fmt.allocPrint(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sasl]
        \\account_db = "accounts.oro"
        \\[oper.ocg2]
        \\enabled = true
        \\minting_enabled = true
        \\authority_node_id = "{x:0>16}"
        \\authority_public_key = "{s}"
        \\
    , .{ authority_node_id, &public_hex });
    defer allocator.free(mint_without_projection);
    try testing.expectError(
        error.Ocg2MintingRequiresProjection,
        parseToml(allocator, mint_without_projection, .{}),
    );

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[oper.ocg2]
        \\projection_enabled = "yes"
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[oper.ocg2]
        \\minting_enabled = 1
        \\
    , .{}));
    try testing.expectError(error.UnknownOcg2Field, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[oper.ocg2]
        \\projection = true
        \\
    , .{}));
}
