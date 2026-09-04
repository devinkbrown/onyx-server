// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared plumbing for the `armor` command-line toolkit: capped input loading
//! (file or stdin), PEM/DER auto-detection, hex/fingerprint formatting, OID
//! pretty-naming, and the 0o600 private-key file writer. Every helper is a
//! thin front-end over the existing substrate (src/proto/pem.zig,
//! src/crypto/x509.zig) — no crypto is implemented here.

const std = @import("std");
const builtin = @import("builtin");
const onyx_server = @import("onyx_server");

const pem = onyx_server.proto.pem;
const x509 = onyx_server.crypto.x509;

const Allocator = std.mem.Allocator;
pub const Writer = std.Io.Writer;

/// Cap on any input file/stdin read. Matches the substrate's own DER ceiling
/// (x509.MaxDerLen = 1 MiB) so nothing the parsers reject is ever buffered.
pub const max_input_bytes: usize = x509.MaxDerLen;

/// Toolkit-level failures shared by every subcommand. `Usage` maps to exit 2,
/// `NotImplemented` to exit 3; anything else is an operation failure (exit 1).
pub const Error = error{
    Usage,
    NotImplemented,
};

/// Read a whole input, capped at `max_input_bytes`. `"-"` reads stdin, the way
/// openssl treats a missing `-in`. The returned buffer is owned by the caller.
pub fn readInput(gpa: Allocator, io: std.Io, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) {
        var rbuf: [4096]u8 = undefined;
        var fr = std.Io.File.stdin().readerStreaming(io, &rbuf);
        return fr.interface.allocRemaining(gpa, .limited(max_input_bytes));
    }
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_input_bytes));
}

/// Input encoding selector, mirroring openssl's `-inform`/`-outform`.
pub const Form = enum {
    auto,
    pem,
    der,

    pub fn parse(text: []const u8) Error!Form {
        if (std.mem.eql(u8, text, "pem") or std.mem.eql(u8, text, "PEM")) return .pem;
        if (std.mem.eql(u8, text, "der") or std.mem.eql(u8, text, "DER")) return .der;
        return error.Usage;
    }
};

/// Decode `text` to DER: PEM (first block with `label`) when the input looks
/// like PEM or `-inform pem` forces it, otherwise the raw bytes are the DER.
/// The result is always an owned copy so callers can free `text` independently.
pub fn loadDer(gpa: Allocator, text: []const u8, label: []const u8, form: Form) ![]u8 {
    const looks_pem = std.mem.indexOf(u8, text, "-----BEGIN ") != null;
    const use_pem = switch (form) {
        .pem => true,
        .der => false,
        .auto => looks_pem,
    };
    if (use_pem) {
        const buf = try gpa.alloc(u8, text.len); // decoded DER is always smaller than the PEM
        errdefer gpa.free(buf);
        const der = try pem.decode(text, label, buf);
        const owned = try gpa.dupe(u8, der);
        gpa.free(buf);
        return owned;
    }
    return gpa.dupe(u8, text);
}

/// Append lowercase hex of `bytes` to `w`.
pub fn writeHex(w: *Writer, bytes: []const u8) Writer.Error!void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

/// Append uppercase colon-separated hex (openssl fingerprint style) to `w`.
pub fn writeColonHex(w: *Writer, bytes: []const u8) Writer.Error!void {
    for (bytes, 0..) |b, i| {
        if (i != 0) try w.writeByte(':');
        try w.print("{X:0>2}", .{b});
    }
}

/// Human name for the signature/key AlgorithmIdentifier OIDs the Armor stack
/// emits or accepts. Display-only; identity decisions always compare raw OIDs.
pub fn oidName(oid: []const u8) []const u8 {
    const Named = struct { oid: []const u8, name: []const u8 };
    const table = [_]Named{
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }, .name = "ecdsa-with-SHA256" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 }, .name = "ecdsa-with-SHA384" },
        .{ .oid = &.{ 0x2b, 0x65, 0x70 }, .name = "Ed25519" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, .name = "sha256WithRSAEncryption" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c }, .name = "sha384WithRSAEncryption" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d }, .name = "sha512WithRSAEncryption" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a }, .name = "rsassa-pss" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }, .name = "id-ecPublicKey" },
        .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }, .name = "rsaEncryption" },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, entry.oid, oid)) return entry.name;
    }
    return "unknown";
}

/// Append the dotted-decimal rendering of a DER OID value to `w` (fail-closed:
/// a malformed/overlong arc renders as `<bad-oid>` rather than trapping).
pub fn writeOidDotted(w: *Writer, oid: []const u8) Writer.Error!void {
    if (oid.len == 0) return w.writeAll("<bad-oid>");
    try w.print("{d}.{d}", .{ oid[0] / 40, oid[0] % 40 });
    var arc: u64 = 0;
    var i: usize = 1;
    while (i < oid.len) : (i += 1) {
        const b = oid[i];
        if (arc > (std.math.maxInt(u64) >> 7)) return w.writeAll(".<bad-oid>");
        arc = (arc << 7) | (b & 0x7f);
        if (b & 0x80 == 0) {
            try w.print(".{d}", .{arc});
            arc = 0;
        }
    }
    if (arc != 0) try w.writeAll(".<bad-oid>"); // trailing continuation byte
}

/// Owner-only (0o600) permissions for private-key files, umask-monotonic.
/// Mirrors the daemon's ACME key writer (src/daemon/acme_runner.zig
/// `key_file_perms`), which is file-private there — exporting it is a noted
/// substrate gap.
pub const key_file_perms: std.Io.File.Permissions = if (std.posix.mode_t == u0 or builtin.os.tag == .windows)
    .default_file
else
    .fromMode(0o600);

/// Atomically write private-key `data` to `dir/path` with 0o600 perms
/// (temp-file + rename; the fresh inode carries the restrictive mode, so a
/// re-generated key is never observable group/world-readable).
pub fn writeKeyFile(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = true, .permissions = key_file_perms });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Atomically write public `data` (certs, CSRs) with default permissions.
pub fn writePublicFile(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    var atomic = try dir.createFileAtomic(io, path, .{ .replace = true, .permissions = .default_file });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

/// Wall-clock Unix seconds for validity checks (substrate seam; never a raw
/// syscall in portable code).
pub fn wallClockSeconds() i64 {
    return @divTrunc(onyx_server.substrate.platform.realtimeMillis(), 1000);
}

/// Decode a hex serial (`44`, `0x44`, `01:02`) to owned DER INTEGER contents.
/// Fail-closed: empty, odd-length, or non-hex input is `error.Usage`.
pub fn parseHexSerial(gpa: Allocator, text: []const u8) ![]u8 {
    var start: usize = 0;
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) start = 2;
    var nibble_count: usize = 0;
    for (text[start..]) |c| {
        if (c == ':' or c == ' ') continue;
        nibble_count += 1;
    }
    if (nibble_count == 0 or nibble_count % 2 != 0) return error.Usage;
    const out = try gpa.alloc(u8, nibble_count / 2);
    errdefer gpa.free(out);
    var hex_buf: [256]u8 = undefined;
    if (nibble_count > hex_buf.len) return error.Usage;
    var i: usize = 0;
    for (text[start..]) |c| {
        if (c == ':' or c == ' ') continue;
        hex_buf[i] = c;
        i += 1;
    }
    _ = std.fmt.hexToBytes(out, hex_buf[0..i]) catch return error.Usage;
    return out;
}

/// Tiny forward-only argument cursor shared by the subcommand parsers.
pub const ArgCursor = struct {
    args: []const []const u8,
    i: usize = 0,

    pub fn next(self: *ArgCursor) ?[]const u8 {
        if (self.i >= self.args.len) return null;
        const a = self.args[self.i];
        self.i += 1;
        return a;
    }

    /// The value following a `--flag value` pair; `error.Usage` when absent.
    pub fn value(self: *ArgCursor) Error![]const u8 {
        return self.next() orelse error.Usage;
    }
};

const testing = std.testing;

test "armorcli loadDer decodes a PEM block and passes DER through" {
    const gpa = testing.allocator;
    // Arrange: a tiny DER SEQUENCE wrapped in a PEM block.
    const der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x2a };
    var pem_buf: [256]u8 = undefined;
    const pem_text = try pem.encode(&pem_buf, "CERTIFICATE", &der);

    // Act
    const from_pem = try loadDer(gpa, pem_text, "CERTIFICATE", .auto);
    defer gpa.free(from_pem);
    const from_der = try loadDer(gpa, &der, "CERTIFICATE", .auto);
    defer gpa.free(from_der);

    // Assert
    try testing.expectEqualSlices(u8, &der, from_pem);
    try testing.expectEqualSlices(u8, &der, from_der);
}

test "armorcli loadDer fails closed on a PEM block with the wrong label" {
    const gpa = testing.allocator;
    const text = "-----BEGIN PRIVATE KEY-----\nMAMCASo=\n-----END PRIVATE KEY-----\n";
    try testing.expectError(error.BeginNotFound, loadDer(gpa, text, "CERTIFICATE", .auto));
}

test "armorcli oid helpers render known and unknown OIDs" {
    var aw = Writer.Allocating.init(testing.allocator);
    defer aw.deinit();

    const ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    try testing.expectEqualStrings("ecdsa-with-SHA256", oidName(&ecdsa_sha256));
    try testing.expectEqualStrings("unknown", oidName(&.{ 0x55, 0x1d, 0x0e }));

    try writeOidDotted(&aw.writer, &ecdsa_sha256);
    try testing.expectEqualStrings("1.2.840.10045.4.3.2", aw.written());

    // A trailing continuation byte must render fail-closed, not trap.
    aw.clearRetainingCapacity();
    try writeOidDotted(&aw.writer, &.{ 0x2a, 0x86 });
    try testing.expect(std.mem.endsWith(u8, aw.written(), "<bad-oid>"));
}

test "armorcli parseHexSerial accepts 0x, colon, and bare hex" {
    const gpa = testing.allocator;
    const a = try parseHexSerial(gpa, "44");
    defer gpa.free(a);
    try testing.expectEqualSlices(u8, &.{0x44}, a);
    const b = try parseHexSerial(gpa, "0x0102");
    defer gpa.free(b);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, b);
    const c = try parseHexSerial(gpa, "01:02:03");
    defer gpa.free(c);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, c);
    try testing.expectError(error.Usage, parseHexSerial(gpa, ""));
    try testing.expectError(error.Usage, parseHexSerial(gpa, "4"));
    try testing.expectError(error.Usage, parseHexSerial(gpa, "zz"));
}

test "armorcli writeKeyFile writes the private key owner-only (0o600)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;

    // Pin umask for a deterministic mode; the runner is single-threaded here.
    const old_umask = std.os.linux.syscall1(.umask, 0o022);
    defer _ = std.os.linux.syscall1(.umask, old_umask);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeKeyFile(io, tmp.dir, "test.key", "-----BEGIN EC PRIVATE KEY-----\ns\n-----END EC PRIVATE KEY-----\n");

    const st = try tmp.dir.statFile(io, "test.key", .{});
    const mode = st.permissions.toMode() & 0o777;
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), mode);
    try testing.expectEqual(@as(std.posix.mode_t, 0), mode & 0o077);
}
