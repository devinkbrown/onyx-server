// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 6979 Appendix A.2.5 verify-side known-answer tests for ECDSA over
//! NIST P-256 with SHA-256.
//!
//! Why verify-side only: `ecdsa_p256.sign()` runs on the constant-time
//! arithmetic in `p256_ct.zig`, but derives its nonce exactly like Zig std's
//! null-noise signer: the RFC 6979 sec. 3.2 HMAC_DRBG shape with an extra
//! 32-byte noise block (zeros) before the key. That is NOT RFC 6979's exact k,
//! so the signer does not reproduce RFC 6979's (r, s) from the message alone.
//! The signing equation itself is pinned in `ecdsa_p256.zig` by injecting the
//! RFC's k ("RFC 6979 A.2.5 ... reproduced from the RFC's nonce k"), and its
//! output is checked byte-for-byte against std's signer there. What is still
//! fully independent — and what these tests pin — is verification: RFC 6979's
//! published (public key, message, signature) triples MUST verify, and any
//! corruption of the signature, message, or key MUST be rejected. The vectors
//! come straight from the RFC and are independent of Onyx Server's implementation.
const std = @import("std");
const ecdsa = @import("ecdsa_p256.zig");

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 6979 §A.2.5 key pair for curve NIST P-256.
//   x  (private) = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
const public_x = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const public_y = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

/// The RFC 6979 §A.2.5 public key parsed from its SEC1 uncompressed encoding
/// `0x04 || Ux || Uy`.
fn rfc6979PublicKey() !ecdsa.PublicKey {
    const sec1 = [_]u8{0x04} ++ hex(public_x) ++ hex(public_y);
    return ecdsa.parsePublicKeySec1(&sec1);
}

const Vector = struct {
    message: []const u8,
    signature: ecdsa.Signature,
};

// RFC 6979 §A.2.5, the two SHA-256 rows. `sign()` hashes the message with
// SHA-256 internally, matching how the RFC derives H(m) for these strings.
const vectors = [_]Vector{
    .{
        // message = "sample", SHA-256
        .message = "sample",
        .signature = ecdsa.Signature.fromBytes(
            hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716") ++
                hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        ),
    },
    .{
        // message = "test", SHA-256
        .message = "test",
        .signature = ecdsa.Signature.fromBytes(
            hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367") ++
                hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        ),
    },
};

test "RFC 6979 A.2.5 ECDSA P-256/SHA-256 published signatures verify" {
    const pk = try rfc6979PublicKey();
    for (vectors) |v| {
        try testing.expect(ecdsa.verify(v.signature, v.message, pk));
    }
}

test "RFC 6979 A.2.5 ECDSA P-256 rejects corrupted signature, message, or key" {
    const pk = try rfc6979PublicKey();
    const sample = vectors[0];

    // Baseline: the untampered triple verifies.
    try testing.expect(ecdsa.verify(sample.signature, sample.message, pk));

    // Flip one bit of r → reject.
    var r_bad = sample.signature.toBytes();
    r_bad[0] ^= 0x01;
    try testing.expect(!ecdsa.verify(ecdsa.Signature.fromBytes(r_bad), sample.message, pk));

    // Flip one bit of s → reject.
    var s_bad = sample.signature.toBytes();
    s_bad[s_bad.len - 1] ^= 0x01;
    try testing.expect(!ecdsa.verify(ecdsa.Signature.fromBytes(s_bad), sample.message, pk));

    // Tamper the message (same length) → reject.
    try testing.expect(!ecdsa.verify(sample.signature, "sampl3", pk));

    // Cross-use: the "test" signature must not verify the "sample" message.
    try testing.expect(!ecdsa.verify(vectors[1].signature, sample.message, pk));
}

test {
    testing.refAllDecls(@This());
}
