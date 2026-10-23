// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Small adapters for Zig 0.17 standard-library API changes.
const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const IdentityElementError = std.crypto.errors.IdentityElementError;

/// Zig 0.17 development snapshots returned an error union here; stable 0.17
/// guarantees key generation and returns the key pair directly. Keeping the
/// normalized error-union shape lets callers preserve their existing mapping.
pub fn x25519GenerateDeterministic(seed: [X25519.seed_length]u8) IdentityElementError!X25519.KeyPair {
    return X25519.KeyPair.generateDeterministic(seed);
}

/// Normalize recoverPublicKey's development-snapshot error union and stable
/// value return to one error-union API.
pub fn x25519RecoverPublicKey(secret: [X25519.secret_length]u8) IdentityElementError![X25519.public_length]u8 {
    return X25519.recoverPublicKey(secret);
}
