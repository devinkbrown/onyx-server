// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for the live TLS record layers.
//!
//! TLS 1.3: `tls_record.sealRecord`/`openRecord`, the implementation every
//! protected record in `tls_server.zig` goes through, across all three suites.
//! TLS 1.2: `proto/tls12_record.zig`, the AEAD record sealer used by the DTLS
//! 1.2 media plane.
const std = @import("std");
const tls_record = @import("tls_record.zig");
const tls12_record = @import("../proto/tls12_record.zig");

const seed: u64 = 0x544c_535f_5052_4f50;
const record_iterations: usize = 48;
const max_records_per_iteration: usize = 96;
const max_plaintext_len: usize = 256;
const max_padding_len: usize = 32;

const tls13_algs = .{
    tls_record.AeadAlg.aes128_gcm,
    tls_record.AeadAlg.aes256_gcm,
    tls_record.AeadAlg.chacha20_poly1305,
};
const inner_content_types = [_]tls_record.ContentType{ .alert, .handshake, .application_data };
const tls12_content_types = [_]tls12_record.ContentType{ .change_cipher_spec, .alert, .handshake, .application_data };

test "fuzzed TLS 1.3 records round-trip at every sequence for every suite" {
    inline for (tls13_algs) |alg| {
        const A = tls_record.Aead(alg);
        var prng = std.Random.DefaultPrng.init(seed ^ 0x3133_5254 ^ @backingInt(alg));
        const random = prng.random();
        var plaintext: [max_plaintext_len]u8 = undefined;
        var inner: [max_plaintext_len + 1 + max_padding_len]u8 = undefined;
        var record_buf: [tls_record.record_header_len + inner.len + A.tag_length]u8 = undefined;
        var opened_buf: [inner.len]u8 = undefined;

        for (0..record_iterations) |_| {
            var key: A.Key = undefined;
            var iv: tls_record.Nonce96 = undefined;
            random.bytes(&key);
            random.bytes(&iv);
            var cipher = A.init(key);
            defer cipher.deinit();
            const first_seq = random.int(u64) >> 1;
            const record_count = random.intRangeAtMost(usize, 1, max_records_per_iteration);

            for (0..record_count) |i| {
                const seq = first_seq + i;
                const plaintext_len = random.intRangeAtMost(usize, 0, plaintext.len);
                const padding_len = random.intRangeAtMost(usize, 0, max_padding_len);
                random.bytes(plaintext[0..plaintext_len]);
                const content_type = inner_content_types[random.uintLessThan(usize, inner_content_types.len)];

                const record = try tls_record.sealRecord(alg, &cipher, iv, seq, content_type, plaintext[0..plaintext_len], padding_len, &inner, &record_buf);
                try std.testing.expectEqual(tls_record.record_header_len + plaintext_len + 1 + padding_len + A.tag_length, record.len);
                try std.testing.expectEqualSlices(u8, &tls_record.makeAdditionalData(@intCast(record.len - tls_record.record_header_len)), record[0..tls_record.record_header_len]);

                const opened = try tls_record.openRecord(alg, &cipher, iv, seq, record, &opened_buf);
                try std.testing.expectEqual(content_type, opened.content_type);
                try std.testing.expectEqual(padding_len, opened.padding_len);
                try std.testing.expectEqualSlices(u8, plaintext[0..plaintext_len], opened.content);
            }
        }
    }
}

test "tampered TLS 1.3 records fail closed for every suite" {
    inline for (tls13_algs) |alg| {
        const A = tls_record.Aead(alg);
        var prng = std.Random.DefaultPrng.init(seed ^ 0x5441_4d50 ^ @backingInt(alg));
        const random = prng.random();
        var plaintext: [max_plaintext_len]u8 = undefined;
        var inner: [max_plaintext_len + 1]u8 = undefined;
        var record_buf: [tls_record.record_header_len + inner.len + A.tag_length]u8 = undefined;
        var opened_buf: [inner.len]u8 = undefined;

        var key: A.Key = undefined;
        var iv: tls_record.Nonce96 = undefined;
        random.bytes(&key);
        random.bytes(&iv);
        var cipher = A.init(key);
        defer cipher.deinit();

        for (0..max_records_per_iteration) |seq_index| {
            const seq: u64 = @intCast(seq_index);
            const plaintext_len = random.intRangeAtMost(usize, 1, plaintext.len);
            random.bytes(plaintext[0..plaintext_len]);
            const content_type = inner_content_types[random.uintLessThan(usize, inner_content_types.len)];
            const record = try tls_record.sealRecord(alg, &cipher, iv, seq, content_type, plaintext[0..plaintext_len], 0, &inner, &record_buf);

            var open_seq = seq;
            var open_iv = iv;
            switch (random.intRangeAtMost(u8, 0, 3)) {
                // Ciphertext or tag byte (everything after the header).
                0 => record[random.intRangeAtMost(usize, tls_record.record_header_len, record.len - 1)] ^= @as(u8, 1) << random.int(u3),
                // A different sequence number (replay/reorder).
                1 => open_seq = seq + random.intRangeAtMost(u64, 1, 1 << 20),
                // A different static IV (wrong traffic key epoch).
                2 => open_iv[random.uintLessThan(usize, open_iv.len)] ^= 0x01,
                // A truncated record whose header was rewritten to match.
                3 => {
                    const cut = random.intRangeAtMost(usize, 1, record.len - tls_record.record_header_len - 1);
                    const short = record[0 .. record.len - cut];
                    short[0..tls_record.record_header_len].* = tls_record.makeAdditionalData(@intCast(short.len - tls_record.record_header_len));
                    if (tls_record.openRecord(alg, &cipher, iv, seq, short, &opened_buf)) |_| {
                        return error.TestUnexpectedResult;
                    } else |err| switch (err) {
                        error.AuthFailed, error.BadRecordHeader => {},
                        else => return err,
                    }
                    continue;
                },
                else => unreachable,
            }
            try std.testing.expectError(error.AuthFailed, tls_record.openRecord(alg, &cipher, open_iv, open_seq, record, &opened_buf));
        }
    }
}

test "fuzzed TLS 1.2 AEAD records round-trip and bind sequence, type and version" {
    const Aes = tls12_record.Aes128Gcm;
    const ChaCha = tls12_record.ChaCha;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5245_434f_5244_5254);
    const random = prng.random();
    var plaintext: [max_plaintext_len]u8 = undefined;
    var wire: [tls12_record.explicit_nonce_len + max_plaintext_len + 16]u8 = undefined;
    var opened: [max_plaintext_len]u8 = undefined;

    for (0..record_iterations) |_| {
        var aes_key: Aes.Key = undefined;
        var salt: Aes.Salt = undefined;
        var chacha_key: ChaCha.Key = undefined;
        var write_iv: ChaCha.WriteIv = undefined;
        random.bytes(&aes_key);
        random.bytes(&salt);
        random.bytes(&chacha_key);
        random.bytes(&write_iv);
        const record_count = random.intRangeAtMost(usize, 1, max_records_per_iteration);

        for (0..record_count) |i| {
            const seq: u64 = @intCast(i);
            const plaintext_len = random.intRangeAtMost(usize, 0, plaintext.len);
            random.bytes(plaintext[0..plaintext_len]);
            const content_type = tls12_content_types[random.uintLessThan(usize, tls12_content_types.len)];
            const other_type = tls12_content_types[(@backingInt(content_type) - 20 + 1) % tls12_content_types.len];
            const pt = plaintext[0..plaintext_len];

            const aes_rec = try Aes.Sealer.seal(&wire, pt, content_type, 0x0303, seq, aes_key, salt);
            try std.testing.expectEqual(seq, std.mem.readInt(u64, aes_rec[0..8], .big));
            try std.testing.expectEqualSlices(u8, pt, try Aes.Opener.open(&opened, aes_rec, content_type, 0x0303, seq, aes_key, salt));
            try std.testing.expectError(error.AuthFailed, Aes.Opener.open(&opened, aes_rec, content_type, 0x0303, seq + 1, aes_key, salt));
            try std.testing.expectError(error.AuthFailed, Aes.Opener.open(&opened, aes_rec, other_type, 0x0303, seq, aes_key, salt));
            try std.testing.expectError(error.AuthFailed, Aes.Opener.open(&opened, aes_rec, content_type, 0xfefd, seq, aes_key, salt));

            const chacha_rec = try ChaCha.Sealer.seal(&wire, pt, content_type, 0x0303, seq, chacha_key, write_iv);
            try std.testing.expectEqual(plaintext_len + ChaCha.tag_length, chacha_rec.len);
            try std.testing.expectEqualSlices(u8, pt, try ChaCha.Opener.open(&opened, chacha_rec, content_type, 0x0303, seq, chacha_key, write_iv));
            try std.testing.expectError(error.AuthFailed, ChaCha.Opener.open(&opened, chacha_rec, content_type, 0x0303, seq + 1, chacha_key, write_iv));
            try std.testing.expectError(error.AuthFailed, ChaCha.Opener.open(&opened, chacha_rec, other_type, 0x0303, seq, chacha_key, write_iv));
        }
    }
}

test "tampered TLS 1.2 AEAD records fail closed" {
    const Aes = tls12_record.Aes256Gcm;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5441_4d50_4552_4544);
    const random = prng.random();
    var plaintext: [max_plaintext_len]u8 = undefined;
    var wire: [tls12_record.explicit_nonce_len + max_plaintext_len + 16]u8 = undefined;
    var opened: [max_plaintext_len]u8 = undefined;

    var key: Aes.Key = undefined;
    var salt: Aes.Salt = undefined;
    random.bytes(&key);
    random.bytes(&salt);

    for (0..max_records_per_iteration) |i| {
        const seq: u64 = @intCast(i);
        const plaintext_len = random.intRangeAtMost(usize, 1, plaintext.len);
        random.bytes(plaintext[0..plaintext_len]);
        const rec = try Aes.Sealer.seal(&wire, plaintext[0..plaintext_len], .application_data, 0x0303, seq, key, salt);
        // Any byte: explicit nonce, ciphertext or tag.
        wire[random.uintLessThan(usize, rec.len)] ^= @as(u8, 1) << random.int(u3);
        try std.testing.expectError(error.AuthFailed, Aes.Opener.open(&opened, rec, .application_data, 0x0303, seq, key, salt));
    }
}

test {
    std.testing.refAllDecls(@This());
}
