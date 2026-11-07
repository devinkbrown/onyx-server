// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor enc` — passphrase file encryption with an AEAD only. There is no
//! unauthenticated mode and no openssl-enc compatibility (that format has no
//! integrity and a weak KDF). The passphrase comes from a file, never argv.
//!
//! Key derivation: Argon2id v19 (RFC 9106) over the passphrase with a fresh
//! 16-byte salt; default cost t=3, m=64 MiB, p=4 (RFC 9106 §4, second
//! recommended option). The 32-byte output is the AEAD key.
//!
//! Container `ARMORENC` version 1 (all integers big-endian):
//!
//!     off len  field
//!       0   8  magic "ARMORENC"
//!       8   1  version = 1
//!       9   1  aead: 1 = ChaCha20-Poly1305 (RFC 8439), 2 = AES-256-GCM (SP 800-38D)
//!      10   1  kdf:  1 = Argon2id v19
//!      11   1  log2(chunk size), 10..24 (writer uses 16 = 64 KiB)
//!      12   4  argon2 t (iterations)
//!      16   4  argon2 m (KiB)
//!      20   4  argon2 p (lanes)
//!      24  16  salt
//!      40   7  nonce prefix (random)
//!      47      chunks
//!
//! The plaintext is cut into chunks of exactly C bytes followed by one final
//! chunk of 0..C-1 bytes, so the final chunk always exists and the layout is
//! unambiguous. Each chunk is sealed independently (the STREAM construction of
//! Hoang–Reyhanitabar–Rogaway–Vizár, "Online Authenticated-Encryption and its
//! Nonce-Reuse Misuse-Resistance", CRYPTO 2015):
//!
//!     nonce_i = prefix(7) || uint32 i || final_flag(1)   (0x01 only on the last)
//!     aad     = the 47-byte header
//!     chunk_i = AEAD-Seal(key, nonce_i, aad, plaintext_i) = ciphertext || tag(16)
//!
//! Binding the header as AAD authenticates the version, algorithm, KDF cost,
//! salt and prefix; the counter defeats reordering; the final flag defeats
//! truncation and extension. Decryption authenticates every chunk before any
//! plaintext is released.

const std = @import("std");
const onyx_server = @import("onyx_server");
const common = @import("common.zig");

const argon2_kdf = onyx_server.crypto.argon2_kdf;
const aead = onyx_server.crypto.aead;

const Allocator = std.mem.Allocator;
const Writer = common.Writer;

pub const magic = "ARMORENC";
pub const version: u8 = 1;
pub const header_len: usize = 47;
pub const tag_len: usize = 16;
pub const salt_len: usize = 16;
pub const nonce_prefix_len: usize = 7;
pub const default_chunk_log2: u8 = 16;
/// Whole-input cap: `enc` works in memory so nothing is released unverified.
pub const max_input_bytes: usize = 256 * 1024 * 1024;
pub const max_passphrase_bytes: usize = 4096;

/// RFC 9106 §4 second recommended option.
pub const default_kdf: argon2_kdf.Params = .{ .t = 3, .m = 64 * 1024, .p = 4 };

/// Decrypt-side KDF bounds: a hostile header must not be able to demand
/// excessive memory or time before authentication. `enc` itself only ever
/// writes `default_kdf` (64 MiB, t=3, p=4); the caps leave 16x headroom on
/// memory while bounding an attacker-supplied file to one 1 GiB allocation.
pub const max_kdf_t: u32 = 16;
pub const max_kdf_m: u32 = 1024 * 1024; // KiB = 1 GiB
pub const max_kdf_p: u32 = 16;
comptime {
    // Files `enc` writes must always decrypt.
    std.debug.assert(default_kdf.t <= max_kdf_t and default_kdf.m <= max_kdf_m and default_kdf.p <= max_kdf_p);
}

pub const Cipher = enum(u8) {
    chacha20_poly1305 = 1,
    aes256_gcm = 2,

    pub fn parse(text: []const u8) common.Error!Cipher {
        if (std.mem.eql(u8, text, "chacha20-poly1305")) return .chacha20_poly1305;
        if (std.mem.eql(u8, text, "aes-256-gcm")) return .aes256_gcm;
        return error.Usage;
    }

    pub fn name(self: Cipher) []const u8 {
        return switch (self) {
            .chacha20_poly1305 => "chacha20-poly1305",
            .aes256_gcm => "aes-256-gcm",
        };
    }
};

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    BadKdfParams,
    Truncated,
    /// Wrong passphrase, or the file was modified, reordered, or truncated.
    AuthFailed,
    EmptyPassphrase,
    InputTooLarge,
};

pub const Options = struct {
    decrypt: bool = false,
    in_path: []const u8 = "-",
    out_path: []const u8 = "-",
    pass_path: ?[]const u8 = null,
    cipher: Cipher = .chacha20_poly1305,
    /// Not on the command line (tests use cheap parameters).
    kdf: argon2_kdf.Params = default_kdf,
};

pub fn usage(w: *Writer) Writer.Error!void {
    try w.writeAll(
        \\usage: armor enc (-e|-d) -pass file:<path> [-in <file>] [-out <file>] [-cipher <aead>]
        \\  -e / -d              encrypt (default) / decrypt
        \\  -pass file:<path>    read the passphrase from a file (one trailing newline stripped)
        \\  -passfile <path>     same as -pass file:<path>
        \\  -in <file>           input (default stdin)
        \\  -out <file>          output, written mode 0600 (default stdout)
        \\  -cipher <aead>       chacha20-poly1305 (default) or aes-256-gcm
        \\
        \\Authenticated (AEAD) only; Argon2id t=3 m=64MiB p=4. Never put a passphrase on argv.
        \\
    );
}

pub fn parseArgs(args: []const []const u8) common.Error!Options {
    var opts = Options{};
    var cur = common.ArgCursor{ .args = args };
    while (cur.next()) |a| {
        if (std.mem.eql(u8, a, "-e")) {
            opts.decrypt = false;
        } else if (std.mem.eql(u8, a, "-d")) {
            opts.decrypt = true;
        } else if (std.mem.eql(u8, a, "-in")) {
            opts.in_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-out")) {
            opts.out_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-cipher")) {
            opts.cipher = try Cipher.parse(try cur.value());
        } else if (std.mem.eql(u8, a, "-passfile")) {
            opts.pass_path = try cur.value();
        } else if (std.mem.eql(u8, a, "-pass")) {
            // Only file: is accepted. `pass:<secret>` would expose the
            // passphrase to every local user through /proc/*/cmdline.
            const v = try cur.value();
            if (!std.mem.startsWith(u8, v, "file:") or v.len == "file:".len) return error.Usage;
            opts.pass_path = v["file:".len..];
        } else {
            return error.Usage;
        }
    }
    if (opts.pass_path == null) return error.Usage;
    return opts;
}

/// Read the passphrase file, stripping one trailing "\n" or "\r\n".
pub fn readPassphrase(gpa: Allocator, io: std.Io, path: []const u8) ![]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_passphrase_bytes));
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    var len = raw.len;
    if (len > 0 and raw[len - 1] == '\n') len -= 1;
    if (len > 0 and raw[len - 1] == '\r') len -= 1;
    if (len == 0) return error.EmptyPassphrase;
    return gpa.dupe(u8, raw[0..len]);
}

pub fn run(gpa: Allocator, io: std.Io, opts: Options, out: *Writer) !void {
    const pass = try readPassphrase(gpa, io, opts.pass_path orelse return error.Usage);
    defer {
        std.crypto.secureZero(u8, pass);
        gpa.free(pass);
    }
    const input = try readAll(gpa, io, opts.in_path);
    defer {
        std.crypto.secureZero(u8, input);
        gpa.free(input);
    }
    const result = if (opts.decrypt)
        try decrypt(gpa, input, pass)
    else
        try encrypt(gpa, io, input, pass, opts.cipher, opts.kdf, default_chunk_log2);
    defer {
        std.crypto.secureZero(u8, result);
        gpa.free(result);
    }
    if (std.mem.eql(u8, opts.out_path, "-")) {
        try out.writeAll(result);
    } else {
        try common.writeKeyFile(io, std.Io.Dir.cwd(), opts.out_path, result);
    }
}

fn readAll(gpa: Allocator, io: std.Io, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) {
        var rbuf: [4096]u8 = undefined;
        var fr = std.Io.File.stdin().readerStreaming(io, &rbuf);
        return fr.interface.allocRemaining(gpa, .limited(max_input_bytes)) catch |err| switch (err) {
            error.StreamTooLong => error.InputTooLarge,
            else => err,
        };
    }
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_input_bytes)) catch |err| switch (err) {
        error.StreamTooLong => error.InputTooLarge,
        else => err,
    };
}

pub fn sealedLen(plain_len: usize, chunk_log2: u8) usize {
    const c = @as(usize, 1) << @intCast(chunk_log2);
    return header_len + (plain_len / c + 1) * tag_len + plain_len;
}

/// Encrypt `plaintext` under a key derived from `pass`. Caller owns the result.
pub fn encrypt(
    gpa: Allocator,
    io: std.Io,
    plaintext: []const u8,
    pass: []const u8,
    cipher: Cipher,
    kdf: argon2_kdf.Params,
    chunk_log2: u8,
) ![]u8 {
    if (pass.len == 0) return error.EmptyPassphrase;
    if (chunk_log2 < 10 or chunk_log2 > 24) return error.BadKdfParams;
    try checkKdf(kdf.t, kdf.m, kdf.p);

    const out = try gpa.alloc(u8, sealedLen(plaintext.len, chunk_log2));
    errdefer gpa.free(out);
    const header = out[0..header_len];
    @memcpy(header[0..8], magic);
    header[8] = version;
    header[9] = @backingInt(cipher);
    header[10] = 1;
    header[11] = chunk_log2;
    std.mem.writeInt(u32, header[12..16], kdf.t, .big);
    std.mem.writeInt(u32, header[16..20], kdf.m, .big);
    std.mem.writeInt(u32, header[20..24], kdf.p, .big);
    try io.randomSecure(header[24 .. 24 + salt_len + nonce_prefix_len]);

    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try argon2_kdf.deriveKey(gpa, &key, pass, header[24..40], kdf);

    switch (cipher) {
        inline else => |c| sealChunks(aeadFor(c), &key, header, plaintext, out[header_len..], chunk_log2),
    }
    return out;
}

/// Decrypt a container. Every chunk authenticates before the result is
/// returned; any failure returns an error and no plaintext.
pub fn decrypt(gpa: Allocator, sealed: []const u8, pass: []const u8) ![]u8 {
    if (pass.len == 0) return error.EmptyPassphrase;
    if (sealed.len < header_len) return error.Truncated;
    const header = sealed[0..header_len];
    if (!std.mem.eql(u8, header[0..8], magic)) return error.BadMagic;
    if (header[8] != version) return error.UnsupportedVersion;
    const cipher: Cipher = switch (header[9]) {
        1 => .chacha20_poly1305,
        2 => .aes256_gcm,
        else => return error.UnsupportedAlgorithm,
    };
    if (header[10] != 1) return error.UnsupportedAlgorithm;
    const chunk_log2 = header[11];
    if (chunk_log2 < 10 or chunk_log2 > 24) return error.BadKdfParams;
    const t = std.mem.readInt(u32, header[12..16], .big);
    const m = std.mem.readInt(u32, header[16..20], .big);
    const p = std.mem.readInt(u32, header[20..24], .big);
    try checkKdf(t, m, p);

    const c = @as(usize, 1) << @intCast(chunk_log2);
    const body = sealed[header_len..];
    const rem = body.len % (c + tag_len);
    if (rem < tag_len) return error.Truncated;
    const plain_len = body.len - (body.len / (c + tag_len) + 1) * tag_len;

    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try argon2_kdf.deriveKey(gpa, &key, pass, header[24..40], .{ .t = t, .m = m, .p = @intCast(p) });

    const out = try gpa.alloc(u8, plain_len);
    errdefer {
        std.crypto.secureZero(u8, out);
        gpa.free(out);
    }
    switch (cipher) {
        inline else => |ci| try openChunks(aeadFor(ci), &key, header, body, out, chunk_log2),
    }
    return out;
}

fn checkKdf(t: u32, m: u32, p: u32) Error!void {
    if (t == 0 or t > max_kdf_t) return error.BadKdfParams;
    if (p == 0 or p > max_kdf_p) return error.BadKdfParams;
    // RFC 9106 §3.1: m >= 8 * p KiB.
    if (m < 8 * p or m > max_kdf_m) return error.BadKdfParams;
}

fn aeadFor(comptime c: Cipher) type {
    return switch (c) {
        .chacha20_poly1305 => aead.Aead(.chacha20_poly1305),
        .aes256_gcm => aead.Aead(.aes256_gcm),
    };
}

fn chunkNonce(header: *const [header_len]u8, index: u32, final: bool) [12]u8 {
    var n: [12]u8 = undefined;
    @memcpy(n[0..nonce_prefix_len], header[40..47]);
    std.mem.writeInt(u32, n[7..11], index, .big);
    n[11] = @intFromBool(final);
    return n;
}

fn sealChunks(comptime A: type, key: *const [32]u8, header: *const [header_len]u8, plaintext: []const u8, out: []u8, chunk_log2: u8) void {
    const c = @as(usize, 1) << @intCast(chunk_log2);
    var cipher = A.init(key.*);
    defer cipher.deinit();
    var off: usize = 0;
    var wr: usize = 0;
    var index: u32 = 0;
    while (true) : (index += 1) {
        const left = plaintext.len - off;
        const final = left < c;
        const take = if (final) left else c;
        const pt = plaintext[off..][0..take];
        const tag = cipher.seal(chunkNonce(header, index, final), header, pt, out[wr..][0..take]) catch unreachable;
        @memcpy(out[wr + take ..][0..tag_len], &tag);
        off += take;
        wr += take + tag_len;
        if (final) break;
    }
    std.debug.assert(wr == out.len);
}

fn openChunks(comptime A: type, key: *const [32]u8, header: *const [header_len]u8, body: []const u8, out: []u8, chunk_log2: u8) !void {
    const c = @as(usize, 1) << @intCast(chunk_log2);
    var cipher = A.init(key.*);
    defer cipher.deinit();
    var rd: usize = 0;
    var wr: usize = 0;
    var index: u32 = 0;
    while (true) {
        const left = body.len - rd;
        const final = left < c + tag_len;
        const take = if (final) left - tag_len else c;
        const ct = body[rd..][0..take];
        const tag = body[rd + take ..][0..tag_len].*;
        cipher.open(chunkNonce(header, index, final), header, ct, tag, out[wr..][0..take]) catch return error.AuthFailed;
        rd += take + tag_len;
        wr += take;
        if (final) break;
        index = std.math.add(u32, index, 1) catch return error.Truncated;
    }
}

const testing = std.testing;
const fast_kdf: argon2_kdf.Params = .{ .t = 1, .m = 64, .p = 1 };

test "armorcli enc parseArgs refuses argv passphrases" {
    try testing.expectError(error.Usage, parseArgs(&.{"-e"}));
    try testing.expectError(error.Usage, parseArgs(&.{ "-pass", "pass:hunter2" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-pass", "env:X" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-pass", "file:" }));
    try testing.expectError(error.Usage, parseArgs(&.{ "-pass", "file:p", "-cipher", "aes-128-cbc" }));
    const o = try parseArgs(&.{ "-d", "-pass", "file:pw.txt", "-cipher", "aes-256-gcm", "-in", "a", "-out", "b" });
    try testing.expect(o.decrypt);
    try testing.expectEqualStrings("pw.txt", o.pass_path.?);
    try testing.expectEqual(Cipher.aes256_gcm, o.cipher);
    const p = try parseArgs(&.{ "-passfile", "x" });
    try testing.expect(!p.decrypt);
}

test "armorcli enc round-trips both AEADs across chunk boundaries" {
    const gpa = testing.allocator;
    const sizes = [_]usize{ 0, 1, 1023, 1024, 1025, 4096, 5000 };
    for ([_]Cipher{ .chacha20_poly1305, .aes256_gcm }) |cipher| {
        for (sizes) |n| {
            const pt = try gpa.alloc(u8, n);
            defer gpa.free(pt);
            for (pt, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
            const sealed = try encrypt(gpa, testing.io, pt, "correct horse", cipher, fast_kdf, 10);
            defer gpa.free(sealed);
            try testing.expectEqual(sealedLen(n, 10), sealed.len);
            try testing.expectEqualStrings(magic, sealed[0..8]);
            try testing.expectEqual(@backingInt(cipher), sealed[9]);
            const back = try decrypt(gpa, sealed, "correct horse");
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, pt, back);
        }
    }
}

test "armorcli enc rejects tamper, truncation, extension, reorder, and wrong passphrase" {
    const gpa = testing.allocator;
    var pt: [3000]u8 = undefined; // 3000 bytes => chunks of 1024, 1024, 952
    for (&pt, 0..) |*b, i| b.* = '0' + @as(u8, @intCast(i % 10));
    const sealed = try encrypt(gpa, testing.io, &pt, "pw", .chacha20_poly1305, fast_kdf, 10);
    defer gpa.free(sealed);

    try testing.expectError(error.AuthFailed, decrypt(gpa, sealed, "pW"));

    const copy = try gpa.dupe(u8, sealed);
    defer gpa.free(copy);
    // Every single-byte flip, header included, must fail closed.
    const probes = [_]usize{ 9, 12, 30, 44, header_len, header_len + 1030, copy.len - 1 };
    for (probes) |i| {
        @memcpy(copy, sealed);
        copy[i] ^= 0x01;
        if (decrypt(gpa, copy, "pw")) |leak| {
            gpa.free(leak);
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    // Dropping the final chunk: the new tail is a non-final chunk.
    const chunk = 1024 + tag_len;
    try testing.expectError(error.Truncated, decrypt(gpa, sealed[0 .. header_len + 2 * chunk], "pw"));
    // Truncating inside the final chunk.
    try testing.expectError(error.AuthFailed, decrypt(gpa, sealed[0 .. sealed.len - 1], "pw"));
    try testing.expectError(error.Truncated, decrypt(gpa, sealed[0 .. header_len + chunk + 3], "pw"));
    try testing.expectError(error.Truncated, decrypt(gpa, sealed[0..10], "pw"));

    // Swapping the two full chunks.
    @memcpy(copy, sealed);
    @memcpy(copy[header_len..][0..chunk], sealed[header_len + chunk ..][0..chunk]);
    @memcpy(copy[header_len + chunk ..][0..chunk], sealed[header_len..][0..chunk]);
    try testing.expectError(error.AuthFailed, decrypt(gpa, copy, "pw"));

    // Appending bytes changes where the final chunk sits.
    const longer = try gpa.alloc(u8, sealed.len + tag_len);
    defer gpa.free(longer);
    @memcpy(longer[0..sealed.len], sealed);
    @memset(longer[sealed.len..], 0);
    try testing.expectError(error.AuthFailed, decrypt(gpa, longer, "pw"));

    // Hostile KDF cost and unknown versions are refused before any KDF work.
    @memcpy(copy, sealed);
    std.mem.writeInt(u32, copy[16..20], 0xffff_ffff, .big);
    try testing.expectError(error.BadKdfParams, decrypt(gpa, copy, "pw"));
    // Just over each cap: m > 1 GiB, t > 16, p > 16.
    @memcpy(copy, sealed);
    std.mem.writeInt(u32, copy[16..20], max_kdf_m + 1, .big);
    try testing.expectError(error.BadKdfParams, decrypt(gpa, copy, "pw"));
    @memcpy(copy, sealed);
    std.mem.writeInt(u32, copy[16..20], 4 * 1024 * 1024, .big); // 4 GiB, accepted before
    try testing.expectError(error.BadKdfParams, decrypt(gpa, copy, "pw"));
    @memcpy(copy, sealed);
    std.mem.writeInt(u32, copy[12..16], max_kdf_t + 1, .big);
    try testing.expectError(error.BadKdfParams, decrypt(gpa, copy, "pw"));
    @memcpy(copy, sealed);
    std.mem.writeInt(u32, copy[20..24], max_kdf_p + 1, .big);
    try testing.expectError(error.BadKdfParams, decrypt(gpa, copy, "pw"));
    @memcpy(copy, sealed);
    copy[8] = 2;
    try testing.expectError(error.UnsupportedVersion, decrypt(gpa, copy, "pw"));
    @memcpy(copy, sealed);
    copy[0] = 'X';
    try testing.expectError(error.BadMagic, decrypt(gpa, copy, "pw"));
}

test "armorcli enc run encrypts and decrypts files with a passphrase file" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "pw", .data = "s3cret passphrase\r\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "empty", .data = "\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "plain", .data = "attack at dawn" });
    var paths: [5][]u8 = undefined;
    const names = [_][]const u8{ "pw", "plain", "sealed", "back", "empty" };
    for (names, 0..) |n, i| paths[i] = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, n });
    defer for (paths) |p| gpa.free(p);

    var aw = Writer.Allocating.init(gpa);
    defer aw.deinit();
    try run(gpa, io, .{ .pass_path = paths[0], .in_path = paths[1], .out_path = paths[2], .kdf = fast_kdf }, &aw.writer);
    try run(gpa, io, .{ .decrypt = true, .pass_path = paths[0], .in_path = paths[2], .out_path = "-" }, &aw.writer);
    try testing.expectEqualStrings("attack at dawn", aw.written());

    const pw = try readPassphrase(gpa, io, paths[0]);
    defer gpa.free(pw);
    try testing.expectEqualStrings("s3cret passphrase", pw);
    try testing.expectError(error.EmptyPassphrase, run(gpa, io, .{ .pass_path = paths[4], .in_path = paths[1], .kdf = fast_kdf }, &aw.writer));
}
