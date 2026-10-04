// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux kTLS (kernel TLS offload) — Phase 0 foundation.
//!
//! Pure encoders + constants for the kernel TLS ULP, with NO syscalls and NO
//! live wiring. This is the byte-layout half of `docs/dev/tls-design/ktls.md`
//! Phase 0: the `SOL_TLS`/`TLS_TX` sockopt constants, the per-cipher
//! `tls12_crypto_info_*` struct geometry (Linux UAPI `include/uapi/linux/tls.h`),
//! a serializer that produces the exact bytes `setsockopt(SOL_TLS, TLS_TX, …)`
//! expects, and the TLS 1.3 static-IV → salt/iv split.
//!
//! Scope discipline:
//!   * **Authoritative + unit-tested here:** the sockopt constants, the cipher
//!     geometry, the `crypto_info` byte layout (field order iv‖key‖salt‖rec_seq
//!     after the 4-byte `tls_crypto_info` header), the big-endian `rec_seq`
//!     encoding, and the TLS 1.3 nonce split (salt = static_iv[0..4],
//!     iv = static_iv[4..12] for AES-GCM; salt-less, iv = the full 12-byte IV for
//!     ChaCha20-Poly1305 — RFC 8446 §5.3, matching how the kernel XORs the record
//!     sequence into the `iv` field).
//!   * **Deferred to Phase 1** (needs a real kernel round-trip to validate):
//!     the TLS 1.2 explicit-nonce derivation, the `TCP_ULP` attach + `setsockopt`
//!     calls, the boot-time per-suite capability probe, and the getsockopt-seq
//!     liveness self-test. Those are intentionally NOT in this module.
//!
//! The daemon is 64-bit little-endian only (x86_64 / aarch64); the `u16`
//! `version`/`cipher_type` fields are encoded in native (little) endianness,
//! exactly as the kernel reads the C struct.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const native_endian = builtin.cpu.arch.endian();

// ── Socket option constants (Linux UAPI) ────────────────────────────────────
/// `IPPROTO_TCP` — the level at which `TCP_ULP` is set.
pub const SOL_TCP: u32 = 6;
/// `SOL_TLS` — the level for `TLS_TX` / `TLS_RX` after the ULP is attached.
pub const SOL_TLS: u32 = 282;
/// `TCP_ULP` — attach an Upper Layer Protocol (value "tls"). One-way/permanent.
pub const TCP_ULP: u32 = 31;
/// `TLS_TX` / `TLS_RX` sockopt names under `SOL_TLS`.
pub const TLS_TX: u32 = 1;
pub const TLS_RX: u32 = 2;
/// The ULP name passed to `setsockopt(SOL_TCP, TCP_ULP, …)`.
pub const ulp_name = "tls";

/// TLS protocol versions as the kernel `tls_crypto_info.version` field wants them.
pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;

/// Kernel `tls_crypto_info.cipher_type` registry values.
pub const CipherType = enum(u16) {
    aes_gcm_128 = 51,
    aes_gcm_256 = 52,
    chacha20_poly1305 = 54,

    pub fn toInt(self: CipherType) u16 {
        return @intFromEnum(self);
    }
};

/// Fixed 4-byte `tls_crypto_info` header (version + cipher_type) preceding every
/// cipher-specific body.
pub const crypto_info_header_len: usize = 4;
/// Every kTLS cipher uses an 8-byte record sequence number.
pub const rec_seq_len: usize = 8;

/// The AEAD suites Onyx Server can offload, with their kernel geometry. Sizes are the
/// `TLS_CIPHER_*_{IV,KEY,SALT,REC_SEQ}_SIZE` constants from the UAPI header.
pub const Cipher = enum {
    aes_gcm_128,
    aes_gcm_256,
    chacha20_poly1305,

    pub fn cipherType(self: Cipher) CipherType {
        return switch (self) {
            .aes_gcm_128 => .aes_gcm_128,
            .aes_gcm_256 => .aes_gcm_256,
            .chacha20_poly1305 => .chacha20_poly1305,
        };
    }

    /// `iv` field length (the trailing nonce half the kernel XORs the seq into).
    pub fn ivLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128, .aes_gcm_256 => 8,
            .chacha20_poly1305 => 12,
        };
    }

    pub fn keyLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128 => 16,
            .aes_gcm_256, .chacha20_poly1305 => 32,
        };
    }

    /// `salt` field length (the fixed nonce prefix; zero for ChaCha20-Poly1305).
    pub fn saltLen(self: Cipher) usize {
        return switch (self) {
            .aes_gcm_128, .aes_gcm_256 => 4,
            .chacha20_poly1305 => 0,
        };
    }

    /// Total serialized `tls12_crypto_info_*` size for this cipher.
    pub fn cryptoInfoLen(self: Cipher) usize {
        return crypto_info_header_len + self.ivLen() + self.keyLen() + self.saltLen() + rec_seq_len;
    }
};

/// The largest serialized `crypto_info` across all supported ciphers — a caller
/// can stack-allocate this and pass a sub-slice to `encode`.
pub const max_crypto_info_len: usize = crypto_info_header_len + 12 + 32 + 4 + rec_seq_len; // 60

pub const Error = error{
    /// A component slice length did not match the cipher's geometry.
    BadLength,
    /// The output buffer was smaller than `cipher.cryptoInfoLen()`.
    NoSpaceLeft,
};

/// A decomposed kTLS `crypto_info`, ready to serialize for `setsockopt`.
pub const CryptoInfo = struct {
    /// `TLS_1_2_VERSION` or `TLS_1_3_VERSION`.
    version: u16,
    cipher: Cipher,
    /// `saltLen()` bytes (the fixed nonce prefix; empty for ChaCha20-Poly1305).
    salt: []const u8,
    /// `ivLen()` bytes.
    iv: []const u8,
    /// `keyLen()` bytes.
    key: []const u8,
    /// The initial record sequence number, big-endian (see `seqToBytes`).
    rec_seq: [rec_seq_len]u8,

    pub fn encodedLen(self: CryptoInfo) usize {
        return self.cipher.cryptoInfoLen();
    }

    /// Serialize into `out` and return the written prefix. Field order matches the
    /// kernel `tls12_crypto_info_*` struct exactly: `{u16 version, u16 cipher_type}`
    /// (native-endian) then `iv`, `key`, `salt`, `rec_seq` as raw bytes.
    pub fn encode(self: CryptoInfo, out: []u8) Error![]u8 {
        if (self.salt.len != self.cipher.saltLen() or
            self.iv.len != self.cipher.ivLen() or
            self.key.len != self.cipher.keyLen())
        {
            return error.BadLength;
        }
        const total = self.encodedLen();
        if (out.len < total) return error.NoSpaceLeft;

        std.mem.writeInt(u16, out[0..2], self.version, native_endian);
        std.mem.writeInt(u16, out[2..4], self.cipher.cipherType().toInt(), native_endian);
        var p: usize = crypto_info_header_len;
        @memcpy(out[p..][0..self.iv.len], self.iv);
        p += self.iv.len;
        @memcpy(out[p..][0..self.key.len], self.key);
        p += self.key.len;
        @memcpy(out[p..][0..self.salt.len], self.salt);
        p += self.salt.len;
        @memcpy(out[p..][0..rec_seq_len], &self.rec_seq);
        p += rec_seq_len;
        return out[0..p];
    }
};

/// Encode a record sequence number as the kernel's 8-byte big-endian `rec_seq`.
pub fn seqToBytes(seq: u64) [rec_seq_len]u8 {
    var b: [rec_seq_len]u8 = undefined;
    std.mem.writeInt(u64, &b, seq, .big);
    return b;
}

/// Build the TLS 1.3 `CryptoInfo` from a completed handshake's traffic material.
/// `static_iv` is the 12-byte TLS 1.3 write IV (`TrafficKeys.iv`), `key` the
/// traffic key, `seq` the current write sequence number. Per RFC 8446 §5.3 the
/// kernel forms each record nonce as `static_iv XOR (0^4 ‖ seq)`, which the AEAD
/// UAPI expresses as salt = the fixed leading bytes, iv = the trailing bytes the
/// seq is XORed into: AES-GCM splits 12 → salt(4)‖iv(8); ChaCha20-Poly1305 has
/// no salt and the whole 12-byte IV is the `iv` field.
pub fn tls13CryptoInfo(cipher: Cipher, static_iv: []const u8, key: []const u8, seq: u64) Error!CryptoInfo {
    if (static_iv.len != 12) return error.BadLength;
    if (key.len != cipher.keyLen()) return error.BadLength;
    const salt_len = cipher.saltLen();
    return .{
        .version = TLS_1_3_VERSION,
        .cipher = cipher,
        .salt = static_iv[0..salt_len],
        .iv = static_iv[salt_len..],
        .key = key,
        .rec_seq = seqToBytes(seq),
    };
}

// ── Boot-time capability probe (design Phase 0) ─────────────────────────────
// A no-syscall-per-cipher check of whether the running kernel offers the TLS
// ULP at all. The per-suite TLS_TX/RX acceptance probe + the setsockopt attach
// primitives are Phase 1 (they need an ESTABLISHED socket and a deploy-kernel
// round-trip), and are intentionally not here.

/// Path the kernel exposes its available TCP ULPs at.
pub const available_ulp_path = "/proc/sys/net/ipv4/tcp_available_ulp";

/// True when the space/newline-separated ULP list (the contents of
/// `available_ulp_path`) offers the `tls` ULP — i.e. the kernel has CONFIG_TLS
/// and kTLS can be attached. Matches whole tokens, never a substring.
pub fn ulpAvailable(available_ulp_contents: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, available_ulp_contents, " \t\r\n");
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, ulp_name)) return true;
    }
    return false;
}

/// Boot-time probe: does the running kernel offer the TLS ULP? Reads
/// `available_ulp_path`. Returns false on non-Linux or any read error (⇒ kTLS
/// unavailable — the daemon simply keeps terminating TLS in userspace). This is
/// the check that answers "is this deploy kernel kTLS-capable?" from the logs.
pub fn probeUlpSupport() bool {
    if (builtin.os.tag != .linux) return false;
    const rc = linux.open(available_ulp_path, .{ .ACCMODE = .RDONLY }, 0);
    if (posix.errno(rc) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer {
        _ = linux.close(fd);
    }
    var buf: [256]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const r = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(r)) {
            .SUCCESS => {
                const n: usize = @intCast(r);
                if (n == 0) break;
                total += n;
            },
            .INTR => continue,
            else => return false,
        }
    }
    return ulpAvailable(buf[0..total]);
}

// ── Attach primitives (used by the Phase 1 send-seam; validated here) ────────

pub const AttachError = error{
    /// The kernel refused the TLS ULP (no CONFIG_TLS, or non-Linux).
    KtlsUlpUnsupported,
    /// The kernel refused the TX crypto state (unsupported suite/kernel, or the
    /// socket was not ESTABLISHED).
    KtlsTxUnsupported,
    /// The kernel refused the RX crypto state (as `KtlsTxUnsupported`, RX side).
    KtlsRxUnsupported,
};

/// Attach the TLS ULP to `fd` (`setsockopt(SOL_TCP, TCP_ULP, "tls")`). One-way
/// and permanent; the socket must be TCP. `TLS_TX`/`TLS_RX` additionally require
/// it to be ESTABLISHED.
pub fn attachUlp(fd: linux.fd_t) AttachError!void {
    if (builtin.os.tag != .linux) return error.KtlsUlpUnsupported;
    const rc = linux.setsockopt(fd, @intCast(SOL_TCP), TCP_ULP, ulp_name.ptr, @intCast(ulp_name.len));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        // The TLS ULP is already attached — we only ever attach "tls", so EEXIST
        // means a prior direction (TX before RX on the same conn) already did it.
        .EXIST => {},
        else => return error.KtlsUlpUnsupported,
    }
}

/// Install the server→client TX crypto state (`setsockopt(SOL_TLS, TLS_TX)`) from
/// an already-encoded `crypto_info` (see `CryptoInfo.encode`). Requires
/// `attachUlp` first and an ESTABLISHED socket; thereafter the kernel encrypts
/// plaintext written to `fd`.
pub fn attachTx(fd: linux.fd_t, crypto_info: []const u8) AttachError!void {
    if (builtin.os.tag != .linux) return error.KtlsTxUnsupported;
    const rc = linux.setsockopt(fd, @intCast(SOL_TLS), TLS_TX, crypto_info.ptr, @intCast(crypto_info.len));
    if (posix.errno(rc) != .SUCCESS) return error.KtlsTxUnsupported;
}

/// Install the client→server RX crypto state (`setsockopt(SOL_TLS, TLS_RX)`) from
/// an already-encoded `crypto_info`. Requires `attachUlp` first and an
/// ESTABLISHED socket; thereafter the kernel decrypts inbound records and
/// `recv()` returns plaintext application data (control records must be read via
/// `recvmsg` + a `TLS_GET_RECORD_TYPE` cmsg — the recv-path wiring for that is a
/// later phase).
pub fn attachRx(fd: linux.fd_t, crypto_info: []const u8) AttachError!void {
    if (builtin.os.tag != .linux) return error.KtlsRxUnsupported;
    const rc = linux.setsockopt(fd, @intCast(SOL_TLS), TLS_RX, crypto_info.ptr, @intCast(crypto_info.len));
    if (posix.errno(rc) != .SUCCESS) return error.KtlsRxUnsupported;
}

// ── Control-record demux (recvmsg + TLS_GET_RECORD_TYPE cmsg) ────────────────
//
// On a kTLS-RX-offloaded socket the kernel decrypts inbound records and a plain
// `recv()` returns *application_data* plaintext. A kernel-decrypted TLS *control*
// record (KeyUpdate / close_notify) cannot be conveyed by a plain `recv()` — the
// content type has nowhere to go — so the kernel rejects it with `EIO`. The record
// stays queued; a `recvmsg()` that supplies a `SOL_TLS` control buffer then both
// delivers the record's (decrypted) payload AND reports its TLS content type out
// of band via a `TLS_GET_RECORD_TYPE` control message. This is the recv path an
// offloaded conn must use to demux control records instead of dropping.

/// `SOL_TLS` cmsg types (Linux UAPI `include/uapi/linux/tls.h`). `TLS_GET_RECORD_TYPE`
/// is the ancillary message the kernel attaches to a `recvmsg` carrying a record's
/// 1-byte TLS content type; `TLS_SET_RECORD_TYPE` is its TX twin (unused — the
/// daemon never emits control records over kTLS).
pub const TLS_SET_RECORD_TYPE: u32 = 1;
pub const TLS_GET_RECORD_TYPE: u32 = 2;

/// TLS record content types (RFC 8446 §5.1) — the byte the kernel places in the
/// `TLS_GET_RECORD_TYPE` cmsg. `application_data` is the fast-path type a plain
/// `recv` returns; the rest are control records surfaced only via `recvmsg`.
pub const RecordType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

/// TLS alert description for an orderly shutdown (RFC 8446 §6.1) — the payload of
/// a benign `alert` control record.
pub const alert_close_notify: u8 = 0;

/// The daemon runs LP64 only (x86_64 / aarch64), so `CMSG_ALIGN` rounds to 8.
const cmsg_align_to: usize = @sizeOf(usize);
inline fn cmsgAlign(n: usize) usize {
    return (n + cmsg_align_to - 1) & ~(cmsg_align_to - 1);
}
/// `sizeof(struct cmsghdr)` — the fixed `{len,level,type}` ancillary header.
pub const cmsg_hdr_len: usize = @sizeOf(linux.cmsghdr);
/// `CMSG_SPACE(1)`: the control buffer size for one single-byte
/// `TLS_GET_RECORD_TYPE` cmsg (aligned header + one aligned data byte).
pub const cmsg_space_record_type: usize = cmsgAlign(cmsg_hdr_len) + cmsgAlign(1);

pub const RecvError = error{
    /// No record is immediately available (`EAGAIN`/`EWOULDBLOCK`) — only when the
    /// caller passed `MSG.DONTWAIT`.
    WouldBlock,
    /// The peer closed the TCP connection (`recvmsg` returned 0).
    Eof,
    /// The kernel cannot decrypt the next record with the installed RX key: a
    /// KeyUpdate rotated the peer's send key and the RX `crypto_info` was not
    /// re-installed (`EKEYEXPIRED`). Distinct from a hard error so the caller can
    /// tell "needs rekey" from a genuine fault.
    NeedsRekey,
    /// `recvmsg` failed for any other reason (a real socket error).
    RecvFailed,
    MalformedControl,
};

/// One record read off a kTLS-RX socket: the kernel-decrypted `plaintext` (a
/// prefix of the caller's buffer) plus the TLS content `record_type` the kernel
/// reported out of band.
pub const RecordRead = struct {
    record_type: u8,
    plaintext: []u8,
    metadata_present: bool,
    end_of_record: bool,
};

/// Strict ancillary admission. Absence is distinct from corrupted metadata;
/// CTRUNC, duplicate TLS metadata and noncanonical payload length are errors.
fn parseRecordTypeCmsg(msg: *const linux.msghdr) error{MalformedControl}!?u8 {
    if (msg.flags & (linux.MSG.CTRUNC | linux.MSG.TRUNC) != 0) return error.MalformedControl;
    if (msg.controllen == 0) return null;
    const control = msg.control orelse return error.MalformedControl;
    const base: [*]const u8 = @ptrCast(control);
    var off: usize = 0;
    var found: ?u8 = null;
    while (off < msg.controllen) {
        if (msg.controllen - off < cmsg_hdr_len) return error.MalformedControl;
        const hdr: *align(cmsg_align_to) const linux.cmsghdr = @ptrCast(@alignCast(base + off));
        const clen = hdr.len;
        if (clen < cmsg_hdr_len or clen > msg.controllen - off) return error.MalformedControl;
        if (hdr.level == @as(i32, @intCast(SOL_TLS)) and hdr.type == @as(i32, @intCast(TLS_GET_RECORD_TYPE))) {
            if (found != null or clen != cmsgAlign(cmsg_hdr_len) + 1) return error.MalformedControl;
            found = base[off + cmsgAlign(cmsg_hdr_len)];
        }
        // The final cmsg may omit alignment padding from controllen.
        if (clen == msg.controllen - off) break;
        const step = cmsgAlign(clen);
        if (step > msg.controllen - off) return error.MalformedControl;
        off += step;
    }
    return found;
}

/// Do one `recvmsg(fd)` that also reads the out-of-band TLS record content type
/// from a `TLS_GET_RECORD_TYPE` control message. Application-data records land in
/// `buf` exactly as a plain `recv` would return them (`record_type` =
/// application_data(23), whether or not the kernel attached a cmsg); a *control*
/// record that a plain `recv` rejects with `EIO` is delivered here with its true
/// `record_type` (handshake(22) for a KeyUpdate, alert(21) for close_notify).
/// `flags` should include `MSG.DONTWAIT` on the non-blocking reactor path.
pub fn recvmsgRecordType(fd: linux.fd_t, buf: []u8, flags: u32) RecvError!RecordRead {
    // kTLS RX is Linux-only. The body references linux cmsg/recvmsg APIs and the
    // `EKEYEXPIRED` errno, neither of which exists on foreign targets, so gate the
    // whole body at comptime: on Linux it is analyzed and runs exactly as before;
    // on a cross-compiled test build it is compile-gated out. (Reached only by the
    // kTLS RX drive path, which is itself Linux-only.)
    if (comptime builtin.os.tag == .linux) {
        var iov = [_]posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
        var cbuf: [cmsg_space_record_type]u8 align(@alignOf(linux.cmsghdr)) = undefined;
        while (true) {
            var msg = linux.msghdr{
                .name = null,
                .namelen = 0,
                .iov = &iov,
                .iovlen = 1,
                .control = &cbuf,
                .controllen = cbuf.len,
                .flags = 0,
            };
            const rc = linux.recvmsg(fd, &msg, flags);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    const metadata = try parseRecordTypeCmsg(&msg);
                    if (n == 0 and metadata == null) return error.Eof;
                    return .{ .record_type = metadata orelse @intFromEnum(RecordType.application_data), .plaintext = buf[0..n], .metadata_present = metadata != null, .end_of_record = msg.flags & linux.MSG.EOR != 0 };
                },
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .KEYEXPIRED => return error.NeedsRekey,
                else => return error.RecvFailed,
            }
        }
    } else return error.RecvFailed;
}

/// Owned full tuple returned by TLS_RX/TLS_TX. Key bytes never escape logs or
/// survive the caller turn without explicit snapshot custody.
pub const KernelTuple = struct {
    bytes: [max_crypto_info_len]u8 = @splat(0),
    len: usize,

    pub fn wipe(self: *KernelTuple) void {
        std.crypto.secureZero(u8, &self.bytes);
    }
    pub fn encoded(self: *const KernelTuple) []const u8 {
        return self.bytes[0..self.len];
    }
    pub fn sequence(self: *const KernelTuple) u64 {
        return std.mem.readInt(u64, self.bytes[self.len - 8 ..][0..8], .big);
    }
    pub fn validateEpoch(self: *const KernelTuple, expected: []const u8) ControlError!void {
        if (expected.len != self.len or self.len < 8 or
            std.crypto.timing_safe.compare(u8, self.bytes[0 .. self.len - 8], expected[0 .. expected.len - 8], .big) != .eq) return error.TupleMismatch;
    }
};

pub const Direction = enum { tx, rx };
pub const ControlError = error{ Unsupported, GetFailed, TupleMismatch, BadLength, WouldBlock, SendFailed };

pub fn getTuple(fd: linux.fd_t, direction: Direction, cipher: Cipher) ControlError!KernelTuple {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    var tuple: KernelTuple = .{ .len = cipher.cryptoInfoLen() };
    errdefer tuple.wipe();
    var len: linux.socklen_t = @intCast(tuple.len);
    const rc = linux.getsockopt(fd, @intCast(SOL_TLS), if (direction == .tx) TLS_TX else TLS_RX, &tuple.bytes, &len);
    if (posix.errno(rc) != .SUCCESS) return error.GetFailed;
    if (len != tuple.len or std.mem.readInt(u16, tuple.bytes[0..2], native_endian) != TLS_1_3_VERSION or
        std.mem.readInt(u16, tuple.bytes[2..4], native_endian) != cipher.cipherType().toInt()) return error.TupleMismatch;
    return tuple;
}

/// Emit one old-epoch typed control fragment. Each accepted fragment is one
/// handshake/alert record; the physical owner tracks the accepted prefix.
pub fn sendControl(fd: linux.fd_t, record_type: RecordType, bytes: []const u8) ControlError!usize {
    if (comptime builtin.os.tag != .linux) return error.Unsupported;
    if (bytes.len == 0 or (record_type != .handshake and record_type != .alert)) return error.BadLength;
    var cbuf: [cmsg_space_record_type]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const hdr: *linux.cmsghdr = @ptrCast(&cbuf);
    hdr.* = .{ .len = cmsgAlign(cmsg_hdr_len) + 1, .level = @intCast(SOL_TLS), .type = @intCast(TLS_SET_RECORD_TYPE) };
    cbuf[cmsgAlign(cmsg_hdr_len)] = @intFromEnum(record_type);
    var iov = [_]posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    const msg: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &cbuf, .controllen = cbuf.len, .flags = 0 };
    while (true) {
        const rc = linux.sendmsg(fd, &msg, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0 or rc > bytes.len) return error.SendFailed;
                return rc;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => return error.SendFailed,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "cipher geometry matches the Linux UAPI sizes" {
    try testing.expectEqual(@as(u16, 51), Cipher.aes_gcm_128.cipherType().toInt());
    try testing.expectEqual(@as(u16, 52), Cipher.aes_gcm_256.cipherType().toInt());
    try testing.expectEqual(@as(u16, 54), Cipher.chacha20_poly1305.cipherType().toInt());

    // {iv, key, salt} sizes and the total struct length per cipher.
    try testing.expectEqual(@as(usize, 40), Cipher.aes_gcm_128.cryptoInfoLen()); // 4+8+16+4+8
    try testing.expectEqual(@as(usize, 56), Cipher.aes_gcm_256.cryptoInfoLen()); // 4+8+32+4+8
    try testing.expectEqual(@as(usize, 56), Cipher.chacha20_poly1305.cryptoInfoLen()); // 4+12+32+0+8
    try testing.expect(Cipher.aes_gcm_128.cryptoInfoLen() <= max_crypto_info_len);
    try testing.expect(Cipher.aes_gcm_256.cryptoInfoLen() <= max_crypto_info_len);
    try testing.expect(Cipher.chacha20_poly1305.cryptoInfoLen() <= max_crypto_info_len);
}

test "seqToBytes encodes big-endian" {
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, &seqToBytes(0));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }, &seqToBytes(1));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, &seqToBytes(0x0123456789abcdef));
}

test "encode lays out AES-GCM-128 exactly as the kernel struct" {
    const key = @as([16]u8, @splat(0xAA));
    const iv = @as([8]u8, @splat(0xBB));
    const salt = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const info = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &salt,
        .iv = &iv,
        .key = &key,
        .rec_seq = seqToBytes(7),
    };
    var buf: [max_crypto_info_len]u8 = undefined;
    const out = try info.encode(&buf);

    try testing.expectEqual(@as(usize, 40), out.len);
    // header: version then cipher_type, native-endian.
    try testing.expectEqual(TLS_1_3_VERSION, std.mem.readInt(u16, out[0..2], native_endian));
    try testing.expectEqual(@as(u16, 51), std.mem.readInt(u16, out[2..4], native_endian));
    // body: iv (8) ‖ key (16) ‖ salt (4) ‖ rec_seq (8).
    try testing.expectEqualSlices(u8, &iv, out[4..12]);
    try testing.expectEqualSlices(u8, &key, out[12..28]);
    try testing.expectEqualSlices(u8, &salt, out[28..32]);
    try testing.expectEqualSlices(u8, &seqToBytes(7), out[32..40]);
}

test "encode rejects mismatched component lengths and a short buffer" {
    const info = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &[_]u8{ 1, 2, 3 }, // wrong: needs 4
        .iv = &@as([8]u8, @splat(0)),
        .key = &@as([16]u8, @splat(0)),
        .rec_seq = seqToBytes(0),
    };
    var buf: [max_crypto_info_len]u8 = undefined;
    try testing.expectError(error.BadLength, info.encode(&buf));

    const ok = CryptoInfo{
        .version = TLS_1_3_VERSION,
        .cipher = .aes_gcm_128,
        .salt = &[_]u8{ 1, 2, 3, 4 },
        .iv = &@as([8]u8, @splat(0)),
        .key = &@as([16]u8, @splat(0)),
        .rec_seq = seqToBytes(0),
    };
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, ok.encode(&tiny));
}

test "tls13CryptoInfo splits the AES-GCM static IV into salt(4)+iv(8)" {
    var static_iv: [12]u8 = undefined;
    for (&static_iv, 0..) |*b, i| b.* = @intCast(i + 1); // 01 02 … 0c
    const key = @as([16]u8, @splat(0xCC));

    const info = try tls13CryptoInfo(.aes_gcm_128, &static_iv, &key, 42);
    try testing.expectEqual(TLS_1_3_VERSION, info.version);
    try testing.expectEqualSlices(u8, static_iv[0..4], info.salt); // 01 02 03 04
    try testing.expectEqualSlices(u8, static_iv[4..12], info.iv); // 05 … 0c
    try testing.expectEqualSlices(u8, &key, info.key);
    try testing.expectEqualSlices(u8, &seqToBytes(42), &info.rec_seq);

    // It also encodes to the full struct.
    var buf: [max_crypto_info_len]u8 = undefined;
    const out = try info.encode(&buf);
    try testing.expectEqual(@as(usize, 40), out.len);
}

test "tls13CryptoInfo gives ChaCha20-Poly1305 no salt and the full 12-byte IV" {
    var static_iv: [12]u8 = undefined;
    for (&static_iv, 0..) |*b, i| b.* = @intCast(0xF0 + i);
    const key = @as([32]u8, @splat(0xDD));

    const info = try tls13CryptoInfo(.chacha20_poly1305, &static_iv, &key, 3);
    try testing.expectEqual(@as(usize, 0), info.salt.len);
    try testing.expectEqualSlices(u8, &static_iv, info.iv); // all 12 bytes
    try testing.expectEqual(@as(usize, 56), info.encodedLen());
}

test "tls13CryptoInfo rejects a wrong IV or key length" {
    const key = @as([16]u8, @splat(0));
    try testing.expectError(error.BadLength, tls13CryptoInfo(.aes_gcm_128, &@as([11]u8, @splat(0)), &key, 0));
    try testing.expectError(error.BadLength, tls13CryptoInfo(.aes_gcm_128, &@as([12]u8, @splat(0)), &@as([15]u8, @splat(0)), 0));
}

test "ulpAvailable matches the tls ULP token exactly" {
    // The real /proc/sys/net/ipv4/tcp_available_ulp shape on a CONFIG_TLS kernel.
    try testing.expect(ulpAvailable("espintcp mptcp tls\n"));
    try testing.expect(ulpAvailable("tls"));
    try testing.expect(ulpAvailable("tls mptcp"));
    // No tls ULP.
    try testing.expect(!ulpAvailable("espintcp mptcp\n"));
    try testing.expect(!ulpAvailable(""));
    // Whole-token match only — no substring false positives.
    try testing.expect(!ulpAvailable("tlsx notls\n"));
}

test "parseRecordTypeCmsg reads the TLS_GET_RECORD_TYPE content byte" {
    // Hand-build the exact control-buffer shape the kernel writes for one
    // TLS_GET_RECORD_TYPE cmsg: a cmsghdr {CMSG_LEN(1), SOL_TLS, TLS_GET_RECORD_TYPE}
    // followed (after CMSG_ALIGN(sizeof cmsghdr)) by a single content-type byte.
    var cbuf: [cmsg_space_record_type]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const hdr: *linux.cmsghdr = @ptrCast(@alignCast(&cbuf));
    const cmsg_len = cmsgAlign(cmsg_hdr_len) + 1; // CMSG_LEN(1)
    hdr.len = cmsg_len;
    hdr.level = @intCast(SOL_TLS);
    hdr.type = @intCast(TLS_GET_RECORD_TYPE);
    cbuf[cmsgAlign(cmsg_hdr_len)] = @intFromEnum(RecordType.handshake);

    var iov = [_]posix.iovec{.{ .base = undefined, .len = 0 }};
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cbuf,
        .controllen = cmsg_len,
        .flags = 0,
    };
    // The handshake(22) content type is parsed out of the ancillary data.
    try testing.expectEqual(@as(?u8, @intFromEnum(RecordType.handshake)), try parseRecordTypeCmsg(&msg));

    // No control data ⇒ null (the caller then treats the read as application_data,
    // matching a plain recv of app plaintext).
    msg.controllen = 0;
    try testing.expectEqual(@as(?u8, null), try parseRecordTypeCmsg(&msg));

    // A truncated cmsg is a fatal metadata error, never application data.
    msg.controllen = cmsg_len;
    msg.flags = linux.MSG.CTRUNC;
    try testing.expectError(error.MalformedControl, parseRecordTypeCmsg(&msg));

    // A cmsg for a different (level,type) is ignored ⇒ null.
    msg.flags = 0;
    hdr.type = @intCast(TLS_SET_RECORD_TYPE);
    try testing.expectEqual(@as(?u8, null), try parseRecordTypeCmsg(&msg));
}

test "parseRecordTypeCmsg rejects a data-less matching cmsg instead of reading the next header" {
    // A matching TLS_GET_RECORD_TYPE cmsg carrying ONLY its header (len ==
    // sizeof(cmsghdr), no content byte) must not be trusted: the content byte
    // would otherwise be read from base+CMSG_ALIGN(hdr), which — when another
    // cmsg follows — is the first byte of that next cmsg's header, not a record
    // type. Today's kernel always writes CMSG_LEN(1); this guards a future or
    // refactor regression that emits a header-only SOL_TLS cmsg.
    var cbuf: [64]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
    const base: [*]u8 = &cbuf;

    // cmsg[0]: matching (level,type) but header-only — carries no content byte.
    const hdr0: *linux.cmsghdr = @ptrCast(@alignCast(base));
    hdr0.len = cmsg_hdr_len; // header only, NOT CMSG_LEN(1)
    hdr0.level = @intCast(SOL_TLS);
    hdr0.type = @intCast(TLS_GET_RECORD_TYPE);

    // cmsg[1]: a following cmsg whose first header byte (its len low byte, LE) is
    // a plausible record type (handshake=22) — exactly the value the pre-fix read
    // returned by misreading this adjacent header as ancillary content.
    const next_off = cmsgAlign(cmsg_hdr_len);
    const hdr1: *linux.cmsghdr = @ptrCast(@alignCast(base + next_off));
    hdr1.len = @intFromEnum(RecordType.handshake); // low byte == 22
    hdr1.level = 0;
    hdr1.type = 0;

    var iov = [_]posix.iovec{.{ .base = undefined, .len = 0 }};
    const msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cbuf,
        .controllen = next_off + cmsg_hdr_len, // both headers fully in-bounds
        .flags = 0,
    };
    // Fail closed instead of reading the following header as a type.
    try testing.expectError(error.MalformedControl, parseRecordTypeCmsg(&msg));
}

test "cmsg geometry matches the LP64 CMSG_* macros" {
    // sizeof(struct cmsghdr) == 16, CMSG_ALIGN rounds to 8, CMSG_SPACE(1) == 24.
    try testing.expectEqual(@as(usize, 16), cmsg_hdr_len);
    try testing.expectEqual(@as(usize, 16), cmsgAlign(cmsg_hdr_len));
    try testing.expectEqual(@as(usize, 24), cmsg_space_record_type);
    try testing.expectEqual(@as(usize, 8), cmsgAlign(1));
    try testing.expectEqual(@as(u32, 2), TLS_GET_RECORD_TYPE);
    // The content-type registry values the kernel reports in the cmsg.
    try testing.expectEqual(@as(u8, 21), @intFromEnum(RecordType.alert));
    try testing.expectEqual(@as(u8, 22), @intFromEnum(RecordType.handshake));
    try testing.expectEqual(@as(u8, 23), @intFromEnum(RecordType.application_data));
}

/// Establish an ESTABLISHED loopback TCP pair, attach the TLS ULP to the server
/// end, and install our encoded TLS 1.3 `crypto_info` for `cipher` via TLS_TX —
/// asserting the running kernel ACCEPTS the struct (a wrong size/version/
/// cipher_type/field-order would EINVAL). Skips (not fails) when sockets or the
/// TLS ULP are unavailable (sandbox / no CONFIG_TLS); a rejected but supported
/// suite surfaces as `error.KtlsTxUnsupported`.
fn tcpSocketOrSkip() !linux.fd_t {
    const rc = linux.socket(posix.AF.INET, posix.SOCK.STREAM, linux.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SkipZigTest;
    return @intCast(rc);
}

fn expectKernelAcceptsTx(cipher: Cipher, key_len: usize) !void {
    const listen_fd = try tcpSocketOrSkip();
    defer _ = linux.close(listen_fd);
    var addr = linux.sockaddr.in{
        .port = 0, // kernel-assigned ephemeral port
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001), // 127.0.0.1
    };
    if (posix.errno(linux.bind(listen_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    if (posix.errno(linux.listen(listen_fd, 1)) != .SUCCESS) return error.SkipZigTest;
    // Read the assigned port back into `addr` for the client connect.
    var storage: posix.sockaddr.storage = undefined;
    var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (posix.errno(linux.getsockname(listen_fd, @ptrCast(&storage), &slen)) != .SUCCESS) return error.SkipZigTest;
    addr.port = (@as(*const linux.sockaddr.in, @ptrCast(@alignCast(&storage)))).port;

    const client_fd = try tcpSocketOrSkip();
    defer _ = linux.close(client_fd);
    if (posix.errno(linux.connect(client_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.SkipZigTest;
    const accept_rc = linux.accept4(listen_fd, null, null, 0);
    if (posix.errno(accept_rc) != .SUCCESS) return error.SkipZigTest;
    const server_fd: linux.fd_t = @intCast(accept_rc);
    defer _ = linux.close(server_fd);

    attachUlp(server_fd) catch return error.SkipZigTest; // no CONFIG_TLS ⇒ skip

    var static_iv = @as([12]u8, @splat(0xAB));
    var key = @as([32]u8, @splat(0xCD));
    const info = try tls13CryptoInfo(cipher, &static_iv, key[0..key_len], 0);
    var enc: [max_crypto_info_len]u8 = undefined;
    const encoded = try info.encode(&enc);
    try attachTx(server_fd, encoded); // the kernel validates the struct here
}

test "kernel accepts our encoded crypto_info via TLS_TX (validates layout vs real kernel)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // AES-GCM-128 + TLS 1.3 is available on any kTLS-capable kernel (≥5.1); its
    // acceptance validates the crypto_info header + field order + rec_seq layout.
    // A rejection here is a real layout bug (not a missing cipher), so it fails.
    try expectKernelAcceptsTx(.aes_gcm_128, 16);
    // AES-GCM-256 (≥5.2) and ChaCha20-Poly1305 (≥5.11) may be absent on older
    // kernels — validate their layout where supported, tolerate genuine absence.
    expectKernelAcceptsTx(.aes_gcm_256, 32) catch |e| if (e != error.KtlsTxUnsupported) return e;
    expectKernelAcceptsTx(.chacha20_poly1305, 32) catch |e| if (e != error.KtlsTxUnsupported) return e;
}
