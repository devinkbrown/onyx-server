// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline, public deterministic test fixtures only. Run in a private empty cwd
//! with good/, missing/, altered/, and retired-new/ already created by harness.
const std = @import("std");
const onyx = @import("onyx_server");
const sign = onyx.crypto.sign;
const replica = onyx.daemon.helix.session_replica;
const durable = onyx.daemon.session_group_revoke_durable;
const policy = durable.retired_policy;
const origin = onyx.substrate.undertow.signed_frame.originShortId;

fn wire(a: std.mem.Allocator, kp: *const sign.KeyPair, token: u8, account: []const u8) ![]u8 {
    return replica.encodeOffer(a, .{
        .operation = .group_revoke,
        .token = @splat(token),
        .revision = .{ .epoch = 1000, .sequence = 1000 << 16, .origin_node = origin(kp.public_key) },
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
        .account = account,
    }, kp);
}
fn grant(bytes: []const u8) !policy.Grant {
    const decoded = try replica.decodeOffer(bytes);
    try replica.verifyOffer(decoded);
    return .{ .group_key = durable.groupKeyFor(decoded.offer.token), .issuer_key = decoded.signer, .fact_digest = durable.factDigest(bytes) };
}
fn grantText(a: std.mem.Allocator, g: policy.Grant) ![]u8 {
    return std.fmt.allocPrint(a, "[[mesh.retired_session_group_fences]]\ngroup_key = \"{s}\"\nissuer_key = \"{s}\"\nfact_digest = \"{s}\"\n\n", .{
        std.fmt.bytesToHex(g.group_key, .lower), std.fmt.bytesToHex(g.issuer_key, .lower), std.fmt.bytesToHex(g.fact_digest, .lower),
    });
}
fn write(io: std.Io, path: []const u8, bytes: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes, .flags = .{ .exclusive = true } });
}
pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    var selected = try sign.KeyPair.fromSeed(@splat(46));
    defer selected.deinit();
    var peer = try sign.KeyPair.fromSeed(@splat(47));
    defer peer.deinit();
    var retired = try sign.KeyPair.fromSeed(@splat(45));
    defer retired.deinit();
    const first = try wire(a, &selected, 35, "FixturePrivateAlpha");
    const second = try wire(a, &selected, 36, "FixturePrivateBeta");
    const other = try wire(a, &peer, 37, "FixturePrivatePeer");
    const prior = try wire(a, &retired, 34, "FixturePrivatePrior");
    const changed = try wire(a, &retired, 34, "FixturePrivateAltered");
    const new_retired = try wire(a, &retired, 38, "FixturePrivateNewRetired");
    for ([_][]const u8{ "good", "missing", "altered", "retired-new" }) |name| {
        const path = try std.fmt.allocPrint(a, "{s}/accounts.wal", .{name});
        var db = try onyx.daemon.store.OroStore.open(a, init.io, .cwd(), path);
        defer db.deinit();
        try durable.persist(&db, second); // Deliberately noncanonical insertion order.
        try durable.persist(&db, other);
        if (!std.mem.eql(u8, name, "missing")) try durable.persist(&db, if (std.mem.eql(u8, name, "altered")) changed else prior);
        try durable.persist(&db, first);
        if (std.mem.eql(u8, name, "retired-new")) try durable.persist(&db, new_retired);
    }
    const old_pin = try grantText(a, try grant(prior));
    const config = try std.fmt.allocPrint(a, "[node]\nid=1\npublic_key=\"{s}\"\n[listen]\nirc=6680\n[mesh]\nrealm=\"offline-fixture\"\nrequire_secured=true\nrequire_signed_frames=true\ntrust_roots=[\"{s}\"]\nrelay_v2_activation_epoch=7\nrelay_v2_roster=[\"{s}\",\"{s}\"]\n{s}", .{ std.fmt.bytesToHex(selected.public_key, .lower), std.fmt.bytesToHex(peer.public_key, .lower), std.fmt.bytesToHex(selected.public_key, .lower), std.fmt.bytesToHex(peer.public_key, .lower), old_pin });
    try write(init.io, "candidate.toml", config);
    const expected = try policy.canonicalize(a, &.{ try grant(second), try grant(first) });
    const expected_text = try std.mem.concat(a, u8, &.{ try grantText(a, expected[0]), try grantText(a, expected[1]) });
    try write(init.io, "expected.toml", expected_text);
    const manifest = try std.fmt.allocPrint(a, "selected=\"{s}\"\nretired=\"{s}\"\nexpected_grants=2\nsource_facts=4\ntoken_bytes={d}\n", .{
        std.fmt.bytesToHex(selected.public_key, .lower), std.fmt.bytesToHex(retired.public_key, .lower), @sizeOf(replica.Token),
    });
    try write(init.io, "manifest.toml", manifest);
}
