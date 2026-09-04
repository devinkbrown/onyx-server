// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic property and fuzz-style tests for the X.509 DER parser.
const std = @import("std");
const x509 = @import("x509.zig");

const seed: u64 = 0x4d495a5543485835;
const arbitrary_iterations: usize = 3200;
const structured_iterations: usize = 500;
const max_random_len: usize = 1536;

const BuilderError = error{OutputTooSmall};

const DerBuilder = struct {
    buf: []u8,
    pos: usize = 0,

    fn init(buf: []u8) DerBuilder {
        return .{ .buf = buf };
    }

    fn finish(self: DerBuilder) []const u8 {
        return self.buf[0..self.pos];
    }

    fn ensure(self: DerBuilder, n: usize) BuilderError!void {
        if (self.buf.len - self.pos < n) return error.OutputTooSmall;
    }

    fn byte(self: *DerBuilder, value: u8) BuilderError!void {
        try self.ensure(1);
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn bytes(self: *DerBuilder, value: []const u8) BuilderError!void {
        try self.ensure(value.len);
        @memcpy(self.buf[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn len(self: *DerBuilder, value_len: usize) BuilderError!void {
        if (value_len < 128) {
            try self.byte(@intCast(value_len));
        } else if (value_len <= 0xff) {
            try self.bytes(&.{ 0x81, @intCast(value_len) });
        } else if (value_len <= 0xffff) {
            try self.bytes(&.{ 0x82, @intCast(value_len >> 8), @intCast(value_len & 0xff) });
        } else {
            return error.OutputTooSmall;
        }
    }

    fn tlv(self: *DerBuilder, tag: u8, value: []const u8) BuilderError!void {
        try self.byte(tag);
        try self.len(value.len);
        try self.bytes(value);
    }
};

test "parse accepts arbitrary bytes or returns typed X.509 errors" {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var input: [max_random_len]u8 = undefined;

    for (0..arbitrary_iterations) |iteration| {
        const len = randomInputLen(random, iteration, input.len);
        fillAttackerDerBytes(random, input[0..len], iteration);
        try parseOkOrTypedError(input[0..len]);
    }
}

test "structured corrupt certificates stay fail-closed" {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x51504f50);
    const random = prng.random();
    var cert_buf: [512]u8 = undefined;
    var work: [cert_buf.len]u8 = undefined;
    const cert = try buildCertificate(&cert_buf, true);

    for (0..structured_iterations) |iteration| {
        @memcpy(work[0..cert.len], cert);
        const mutated = mutateCertificate(random, work[0..cert.len], iteration);
        try parseOkOrTypedError(mutated);
    }
}

test "hand-crafted valid-ish DER certificates parse and keep slices in input" {
    var minimal_buf: [256]u8 = undefined;
    var san_buf: [512]u8 = undefined;

    const minimal = try buildCertificate(&minimal_buf, false);
    const minimal_cert = try x509.parse(minimal);
    try expectCertificateSlicesWithin(minimal, minimal_cert);
    try std.testing.expectEqual(@as(usize, 0), minimal_cert.san_dns_count);
    try std.testing.expectEqual(@as(usize, 0), minimal_cert.san_ip_count);
    try std.testing.expect(!minimal_cert.basic_constraints_ca);

    const with_san = try buildCertificate(&san_buf, true);
    const cert = try x509.parse(with_san);
    try expectCertificateSlicesWithin(with_san, cert);
    try std.testing.expectEqualSlices(u8, &.{ 0x2b, 0x65, 0x70 }, cert.signature_algorithm_oid);
    try std.testing.expectEqualSlices(u8, "onyx.test", cert.san_dns[0]);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, cert.san_ips[0].slice());
    try std.testing.expect(cert.basic_constraints_ca);
}

test "deeply nested DER TLV fails over MaxDepth without stack growth" {
    var nested_a: [128]u8 = undefined;
    var nested_b: [128]u8 = undefined;
    const nested = try buildNestedSequences(&nested_a, &nested_b, x509.MaxDepth + 1);

    var reader = x509.DerReader.init(nested);
    var accepted_depth: usize = 0;
    while (true) {
        const tlv = try reader.readExpected(x509.Tag.sequence);
        const child = reader.child(tlv) catch |err| {
            try std.testing.expectEqual(error.OverDepth, err);
            break;
        };
        accepted_depth += 1;
        reader = child;
    }
    try std.testing.expectEqual(@as(usize, x509.MaxDepth), accepted_depth);

    try parseOkOrTypedError(nested);
}

test "length fields beyond the buffer error cleanly" {
    const short_forms = [_][]const u8{
        &.{ 0x30, 0x03, 0x02, 0x01 },
        &.{ 0x04, 0x81, 0x80 },
        &.{ 0x30, 0x82, 0x01, 0x00, 0x02 },
    };

    for (short_forms) |fixture| {
        var reader = x509.DerReader.init(fixture);
        try std.testing.expectError(error.Truncated, reader.readTlv());
        try parseOkOrTypedError(fixture);
    }

    var indefinite = x509.DerReader.init(&.{ 0x30, 0x80 });
    try std.testing.expectError(error.IndefiniteLength, indefinite.readTlv());
    try parseOkOrTypedError(&.{ 0x30, 0x80 });
}

test "all truncated prefixes of valid-ish certificates return typed errors" {
    var minimal_buf: [256]u8 = undefined;
    var san_buf: [512]u8 = undefined;
    const fixtures = [_][]const u8{
        try buildCertificate(&minimal_buf, false),
        try buildCertificate(&san_buf, true),
    };

    for (fixtures) |fixture| {
        var len: usize = 0;
        while (len < fixture.len) : (len += 1) {
            const parsed = x509.parse(fixture[0..len]);
            if (parsed) |cert| {
                try expectCertificateSlicesWithin(fixture[0..len], cert);
                return error.TestUnexpectedResult;
            } else |err| {
                expectX509Error(err);
            }
        }
    }
}

fn parseOkOrTypedError(input: []const u8) !void {
    const cert = x509.parse(input) catch |err| {
        expectX509Error(err);
        return;
    };
    try expectCertificateSlicesWithin(input, cert);
}

fn expectX509Error(err: x509.Error) void {
    switch (err) {
        error.EmptyInput,
        error.Oversize,
        error.OverDepth,
        error.Truncated,
        error.TrailingData,
        error.UnsupportedTag,
        error.InvalidTag,
        error.InvalidLength,
        error.NonCanonicalLength,
        error.IndefiniteLength,
        error.InvalidInteger,
        error.InvalidBitString,
        error.InvalidOid,
        error.InvalidBoolean,
        error.InvalidTime,
        error.InvalidCertificate,
        error.MissingField,
        error.TooManySan,
        error.InvalidName,
        error.InvalidIpAddress,
        error.PemBeginMissing,
        error.PemEndMissing,
        error.PemInvalidBase64,
        error.OutputTooSmall,
        error.UnsupportedKey,
        error.InvalidKey,
        error.UnsupportedCriticalExtension,
        => {},
    }
}

fn expectCertificateSlicesWithin(input: []const u8, cert: x509.Certificate) !void {
    try expectSliceWithin(input, cert.der);
    try expectSliceWithin(input, cert.tbs_der);
    try expectSliceWithin(input, cert.spki_der);
    try expectSliceWithin(input, cert.spki_value);
    try expectSliceWithin(input, cert.not_before.bytes);
    try expectSliceWithin(input, cert.not_after.bytes);
    try expectSliceWithin(input, cert.signature_algorithm_oid);

    try std.testing.expect(cert.san_dns_count <= cert.san_dns.len);
    try std.testing.expect(cert.san_ip_count <= cert.san_ips.len);
    for (cert.san_dns[0..cert.san_dns_count]) |name| {
        try expectSliceWithin(input, name);
    }
    for (cert.san_ips[0..cert.san_ip_count]) |ip| {
        try std.testing.expect(ip.len == 4 or ip.len == 16);
    }
}

fn expectSliceWithin(owner: []const u8, slice: []const u8) !void {
    const owner_start = @intFromPtr(owner.ptr);
    const owner_end = owner_start + owner.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;

    try std.testing.expect(slice_start >= owner_start);
    try std.testing.expect(slice_start <= owner_end);
    try std.testing.expect(slice_end >= slice_start);
    try std.testing.expect(slice_end <= owner_end);
}

fn randomInputLen(random: std.Random, iteration: usize, max_len: usize) usize {
    return switch (iteration % 23) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 127,
        6 => 128,
        7 => 129,
        8 => 255,
        9 => 256,
        10 => max_len,
        else => random.intRangeAtMost(usize, 0, max_len),
    };
}

fn fillAttackerDerBytes(random: std.Random, out: []u8, iteration: usize) void {
    random.bytes(out);
    if (out.len == 0) return;

    const tags = [_]u8{
        x509.Tag.sequence,
        x509.Tag.integer,
        x509.Tag.bit_string,
        x509.Tag.octet_string,
        x509.Tag.oid,
        x509.Tag.utc_time,
        x509.Tag.generalized_time,
        x509.Tag.context_0_constructed,
        x509.Tag.context_3_constructed,
        0x1f,
        0xff,
    };
    out[0] = tags[iteration % tags.len];

    if (out.len >= 2) {
        out[1] = switch (iteration % 13) {
            0 => 0,
            1 => 1,
            2 => 0x7f,
            3 => 0x80,
            4 => 0x81,
            5 => 0x82,
            6 => 0xff,
            else => random.int(u8),
        };
    }
    if (out.len >= 4 and iteration % 5 == 0) {
        out[2] = 0x01;
        out[3] = 0x00;
    }
    if (out.len >= 16 and iteration % 7 == 0) {
        const prefix = [_]u8{ 0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x01, 0x17, 0x0d, '2', '6', '0', '6', '0', '2', 'Z' };
        @memcpy(out[0..prefix.len], prefix[0..]);
    }
}

fn mutateCertificate(random: std.Random, cert: []u8, iteration: usize) []const u8 {
    const len = switch (iteration % 19) {
        0 => 0,
        1 => 1,
        2 => cert.len - 1,
        3 => cert.len / 2,
        else => cert.len,
    };
    if (len == 0) return cert[0..0];

    const edits = 1 + random.uintLessThan(usize, 8);
    var i: usize = 0;
    while (i < edits) : (i += 1) {
        const pos = random.uintLessThan(usize, len);
        cert[pos] = switch ((iteration + i) % 12) {
            0 => x509.Tag.sequence,
            1 => x509.Tag.integer,
            2 => x509.Tag.bit_string,
            3 => x509.Tag.oid,
            4 => 0x80,
            5 => 0x81,
            6 => 0x82,
            7 => 0xff,
            8 => 0x00,
            else => random.int(u8),
        };
    }
    return cert[0..len];
}

fn buildCertificate(out: []u8, with_extensions: bool) BuilderError![]const u8 {
    var alg_buf: [16]u8 = undefined;
    const alg = try buildAlgorithm(&alg_buf);

    var validity_buf: [40]u8 = undefined;
    const validity = try buildValidity(&validity_buf);

    var spki_buf: [32]u8 = undefined;
    const spki = try buildSpki(&spki_buf, alg);

    var tbs_body_buf: [384]u8 = undefined;
    var tbs_body = DerBuilder.init(&tbs_body_buf);
    try tbs_body.tlv(x509.Tag.integer, &.{0x01});
    try tbs_body.bytes(alg);
    try tbs_body.tlv(x509.Tag.sequence, &.{});
    try tbs_body.bytes(validity);
    try tbs_body.tlv(x509.Tag.sequence, &.{});
    try tbs_body.bytes(spki);
    if (with_extensions) {
        var ext_buf: [160]u8 = undefined;
        try tbs_body.bytes(try buildExtensions(&ext_buf));
    }

    var tbs_buf: [448]u8 = undefined;
    var tbs_builder = DerBuilder.init(&tbs_buf);
    try tbs_builder.tlv(x509.Tag.sequence, tbs_body.finish());
    const tbs = tbs_builder.finish();

    var cert_body_buf: [512]u8 = undefined;
    var cert_body = DerBuilder.init(&cert_body_buf);
    try cert_body.bytes(tbs);
    try cert_body.bytes(alg);
    try cert_body.tlv(x509.Tag.bit_string, &.{0x00});

    var cert = DerBuilder.init(out);
    try cert.tlv(x509.Tag.sequence, cert_body.finish());
    return cert.finish();
}

fn buildAlgorithm(out: []u8) BuilderError![]const u8 {
    var body_buf: [8]u8 = undefined;
    var body = DerBuilder.init(&body_buf);
    try body.tlv(x509.Tag.oid, &.{ 0x2b, 0x65, 0x70 });

    var alg = DerBuilder.init(out);
    try alg.tlv(x509.Tag.sequence, body.finish());
    return alg.finish();
}

fn buildValidity(out: []u8) BuilderError![]const u8 {
    var body_buf: [36]u8 = undefined;
    var body = DerBuilder.init(&body_buf);
    try body.tlv(x509.Tag.utc_time, "260602000000Z");
    try body.tlv(x509.Tag.utc_time, "270602000000Z");

    var validity = DerBuilder.init(out);
    try validity.tlv(x509.Tag.sequence, body.finish());
    return validity.finish();
}

fn buildSpki(out: []u8, alg: []const u8) BuilderError![]const u8 {
    var body_buf: [32]u8 = undefined;
    var body = DerBuilder.init(&body_buf);
    try body.bytes(alg);
    try body.tlv(x509.Tag.bit_string, &.{0x00});

    var spki = DerBuilder.init(out);
    try spki.tlv(x509.Tag.sequence, body.finish());
    return spki.finish();
}

fn buildExtensions(out: []u8) BuilderError![]const u8 {
    var san_ext_buf: [80]u8 = undefined;
    var basic_ext_buf: [48]u8 = undefined;

    var extensions_body_buf: [128]u8 = undefined;
    var extensions_body = DerBuilder.init(&extensions_body_buf);
    try extensions_body.bytes(try buildSubjectAltNameExtension(&san_ext_buf));
    try extensions_body.bytes(try buildBasicConstraintsExtension(&basic_ext_buf));

    var sequence_buf: [144]u8 = undefined;
    var sequence = DerBuilder.init(&sequence_buf);
    try sequence.tlv(x509.Tag.sequence, extensions_body.finish());

    var explicit = DerBuilder.init(out);
    try explicit.tlv(x509.Tag.context_3_constructed, sequence.finish());
    return explicit.finish();
}

fn buildSubjectAltNameExtension(out: []u8) BuilderError![]const u8 {
    var names_body_buf: [48]u8 = undefined;
    var names_body = DerBuilder.init(&names_body_buf);
    try names_body.tlv(x509.Tag.san_dns_name, "onyx.test");
    try names_body.tlv(x509.Tag.san_ip_address, &.{ 127, 0, 0, 1 });

    var names_seq_buf: [56]u8 = undefined;
    var names_seq = DerBuilder.init(&names_seq_buf);
    try names_seq.tlv(x509.Tag.sequence, names_body.finish());

    var ext_body_buf: [72]u8 = undefined;
    var ext_body = DerBuilder.init(&ext_body_buf);
    try ext_body.tlv(x509.Tag.oid, &.{ 0x55, 0x1d, 0x11 });
    try ext_body.tlv(x509.Tag.octet_string, names_seq.finish());

    var ext = DerBuilder.init(out);
    try ext.tlv(x509.Tag.sequence, ext_body.finish());
    return ext.finish();
}

fn buildBasicConstraintsExtension(out: []u8) BuilderError![]const u8 {
    var inner_body_buf: [8]u8 = undefined;
    var inner_body = DerBuilder.init(&inner_body_buf);
    try inner_body.tlv(x509.Tag.boolean, &.{0xff});

    var inner_seq_buf: [12]u8 = undefined;
    var inner_seq = DerBuilder.init(&inner_seq_buf);
    try inner_seq.tlv(x509.Tag.sequence, inner_body.finish());

    var ext_body_buf: [32]u8 = undefined;
    var ext_body = DerBuilder.init(&ext_body_buf);
    try ext_body.tlv(x509.Tag.oid, &.{ 0x55, 0x1d, 0x13 });
    try ext_body.tlv(x509.Tag.boolean, &.{0xff});
    try ext_body.tlv(x509.Tag.octet_string, inner_seq.finish());

    var ext = DerBuilder.init(out);
    try ext.tlv(x509.Tag.sequence, ext_body.finish());
    return ext.finish();
}

fn buildNestedSequences(a: []u8, b: []u8, depth: usize) BuilderError![]const u8 {
    var first = DerBuilder.init(a);
    try first.tlv(x509.Tag.sequence, &.{});
    var current = first.finish();
    var use_a = false;

    var i: usize = 0;
    while (i < depth) : (i += 1) {
        var next = DerBuilder.init(if (use_a) a else b);
        try next.tlv(x509.Tag.sequence, current);
        current = next.finish();
        use_a = !use_a;
    }
    return current;
}
