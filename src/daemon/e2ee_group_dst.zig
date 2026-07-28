// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic distributed fault coverage for E2EEGROUP mesh authority.
//!
//! The live daemon and secured-link tests cover command parsing, capability
//! negotiation, encrypted framing, and retry scheduling. This campaign drives
//! the exact authority transaction across three distinct nodes while a B-C
//! partition holds custody, then heals the link and adopts B's metadata-only
//! Helix checkpoint before all ACK / ACK_CONFIRM obligations settle.

const std = @import("std");

const authority_mod = @import("e2ee_group_mesh_authority.zig");
const sign = @import("../crypto/sign.zig");
const group_relay = @import("../substrate/undertow/e2ee_group_relay.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

const testing = std.testing;

const node_a: u64 = 1;
const node_b: u64 = 2;
const node_c: u64 = 3;

const config = authority_mod.Config{
    .replay = .{
        .window_size = 4,
        .max_origins = 4,
        .exact_history_size = 8,
    },
    .max_outbox_entries = 8,
    .max_receipts = 8,
};

fn expectAccepted(result: authority_mod.AdmitWithCustody) !void {
    try testing.expectEqual(
        std.meta.Tag(authority_mod.Admission).accepted,
        std.meta.activeTag(result.admission),
    );
}

fn verify(
    authority: *authority_mod.Authority,
    record: group_relay.RelayRecord,
) !authority_mod.VerifiedRecord {
    return switch (try authority.verifyRecord(record, 0, 0)) {
        .verified => |identity| identity,
        else => error.TestUnexpectedResult,
    };
}

test "E2EEGROUP DST three-node partition heal and Helix adopt converge exactly once" {
    const seeds = [_]u8{ 0x31, 0x72, 0xb4, 0xf5 };

    for (seeds) |seed| {
        var signing_key = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed)));
        defer signing_key.deinit();

        var origin_pubkey: [group_relay.pubkey_len]u8 = undefined;
        var origin_sig: [group_relay.sig_len]u8 = undefined;
        var record = group_relay.RelayRecord{
            .kind = .commit,
            .channel = "#dst-secure",
            .source_prefix = "alice!user@a.invalid",
            .account = "alice",
            .from_device = "phone",
            .payload = "REVURVJNSU5JU1RJQw",
            .origin_node = signed_frame.originShortId(signing_key.public_key),
            .hlc = 10 + seed,
        };
        try group_relay.stampOrigin(
            testing.allocator,
            &record,
            &signing_key,
            &origin_pubkey,
            &origin_sig,
        );
        const wire = try group_relay.encode(testing.allocator, record);
        defer testing.allocator.free(wire);

        var a = try authority_mod.Authority.init(testing.allocator, config);
        defer a.deinit();
        var b = try authority_mod.Authority.init(testing.allocator, config);
        defer b.deinit();
        var c = try authority_mod.Authority.init(testing.allocator, config);
        defer c.deinit();

        const at_a = try verify(&a, record);
        try expectAccepted(try a.admitAuthorizedWithCustody(at_a, &.{node_b}, wire));
        try testing.expectEqual(@as(usize, 1), a.custodyLen());
        try testing.expectEqual(@as(usize, 1), a.pendingLen());

        const at_b = try verify(&b, record);
        try expectAccepted(try b.admitAuthorizedWithCustodyAndIngress(
            at_b,
            &.{node_c},
            wire,
            node_a,
            1000,
        ));
        try testing.expectEqual(@as(usize, 1), b.custodyLen());
        try testing.expectEqual(@as(usize, 1), b.receiptLen());
        try testing.expectEqual(@as(usize, 1), b.pendingLen());

        // B-C is partitioned: exact wire custody remains in RAM and Helix must
        // fail closed rather than sealing or dropping the opaque control.
        try testing.expectError(
            error.CustodyOutstanding,
            b.encodeCheckpoint(testing.allocator),
        );

        // A duplicate from the ingress side during the partition is acknowledged
        // by the same authority identity and never creates a second C obligation.
        const duplicate = try b.admitAuthorizedWithCustodyAndIngress(
            at_b,
            &.{node_c},
            wire,
            node_a,
            2000,
        );
        try testing.expectEqual(
            std.meta.Tag(authority_mod.Admission).duplicate,
            std.meta.activeTag(duplicate.admission),
        );
        try testing.expectEqual(@as(usize, 1), b.custodyLen());
        try testing.expectEqual(@as(usize, 1), b.receiptLen());

        // Heal B-C. C accepts once and retains only its ingress receipt.
        const at_c = try verify(&c, record);
        try expectAccepted(try c.admitAuthorizedWithCustodyAndIngress(
            at_c,
            &.{},
            wire,
            node_b,
            3000,
        ));
        try testing.expectEqual(@as(usize, 0), c.custodyLen());
        try testing.expectEqual(@as(usize, 1), c.receiptLen());
        try testing.expectEqual(@as(usize, 1), c.pendingLen());

        // C's ACK releases B's opaque custody. B can now Helix-seal its pending
        // identity + ingress receipt, and the successor adopts without payload.
        try testing.expect(try b.acknowledgeKnown(
            node_c,
            at_b.relay_id,
            at_b.origin_pubkey,
            at_b.hlc,
        ));
        try testing.expectEqual(@as(usize, 0), b.custodyLen());
        const checkpoint = try b.encodeCheckpoint(testing.allocator);
        defer testing.allocator.free(checkpoint);
        try testing.expect(std.mem.indexOf(u8, checkpoint, record.payload) == null);

        var successor = try authority_mod.Authority.decodeCheckpoint(
            testing.allocator,
            config,
            checkpoint,
        );
        defer successor.deinit();
        try testing.expectEqual(@as(usize, 0), successor.custodyLen());
        try testing.expectEqual(@as(usize, 1), successor.receiptLen());
        try testing.expectEqual(@as(usize, 1), successor.pendingLen());

        // Complete the immediate-hop receipt chain after B's upgrade.
        try testing.expect(try a.acknowledgeKnown(
            node_b,
            at_a.relay_id,
            at_a.origin_pubkey,
            at_a.hlc,
        ));
        try testing.expect(try successor.confirmReceiptKnown(
            node_a,
            at_b.relay_id,
            at_b.origin_pubkey,
            at_b.hlc,
        ));
        try testing.expect(try c.confirmReceiptKnown(
            node_b,
            at_c.relay_id,
            at_c.origin_pubkey,
            at_c.hlc,
        ));

        try testing.expectEqual(@as(usize, 0), a.pendingLen());
        try testing.expectEqual(@as(usize, 0), successor.pendingLen());
        try testing.expectEqual(@as(usize, 0), c.pendingLen());
        try testing.expectEqual(@as(usize, 0), successor.receiptLen());
        try testing.expectEqual(@as(usize, 0), c.receiptLen());

        // Replays after convergence remain exact duplicates at every node.
        for ([_]*authority_mod.Authority{ &a, &successor, &c }) |node| {
            const identity = try verify(node, record);
            const replay = try node.admitAuthorizedWithCustody(identity, &.{}, wire);
            try testing.expectEqual(
                std.meta.Tag(authority_mod.Admission).duplicate,
                std.meta.activeTag(replay.admission),
            );
            try testing.expectEqual(@as(usize, 0), node.custodyLen());
            try testing.expectEqual(@as(usize, 0), node.pendingLen());
        }
    }
}
