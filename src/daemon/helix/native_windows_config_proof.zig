// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded transcript of the exact config source a Windows Helix candidate
//! must reproduce. This is source evidence, not permission to send READY: the
//! server must also compare its current effective policy after any REHASH.
const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const domain = "onyx/helix/windows-config-source/v1\x00";
pub const Digest = [Sha256.digest_length]u8;
pub const max_source_bytes: usize = 1 << 20;
pub const max_path_bytes: usize = 32 << 10;
pub const max_resolution_name_bytes: usize = 4 << 10;
pub const max_resolution_value_bytes: usize = 1 << 20;
pub const max_resolution_records: u32 = 4096;
pub const max_resolution_transcript_bytes: usize = 16 << 20;
pub const max_effective_material_bytes: usize = 64 << 20;
pub const max_effective_material_records: u32 = 8192;

pub const Error = error{
    InvalidPath,
    SourceTooLarge,
    ResolutionTooLarge,
    TooManyResolutions,
    AlreadyFinished,
    MaterialTooLarge,
};

const Kind = enum(u8) { source = 1, environment = 2, file = 3 };

/// A caller passes the canonical absolute path returned by realPathFileAlloc
/// for the same file whose `source` bytes were parsed. The original source and
/// every resolved value are consumed directly; only the digest is retained.
pub const Builder = struct {
    hash: Sha256,
    resolutions: u32 = 0,
    resolution_bytes: usize = 0,
    finished: bool = false,

    pub fn initCanonical(path: []const u8, source: []const u8) Error!Builder {
        if (path.len == 0 or path.len > max_path_bytes or !std.fs.path.isAbsolute(path) or
            std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
        if (source.len > max_source_bytes) return error.SourceTooLarge;
        var self = Builder{ .hash = Sha256.init(.{}) };
        self.hash.update(domain);
        self.record(.source, 0, path, source);
        return self;
    }

    pub fn recordEnvironment(self: *Builder, name: []const u8, value: []const u8) Error!void {
        try self.recordResolution(.environment, name, value);
    }

    pub fn recordFile(self: *Builder, path: []const u8, value: []const u8) Error!void {
        try self.recordResolution(.file, path, value);
    }

    fn recordResolution(self: *Builder, kind: Kind, name: []const u8, value: []const u8) Error!void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0 or name.len > max_resolution_name_bytes or
            std.mem.indexOfScalar(u8, name, 0) != null or
            value.len > max_resolution_value_bytes) return error.ResolutionTooLarge;
        if (self.resolutions >= max_resolution_records) return error.TooManyResolutions;
        const added = std.math.add(usize, name.len, value.len) catch return error.ResolutionTooLarge;
        if (added > max_resolution_transcript_bytes - self.resolution_bytes) return error.ResolutionTooLarge;
        self.record(kind, self.resolutions + 1, name, value);
        self.resolutions += 1;
        self.resolution_bytes += added;
    }

    fn record(self: *Builder, kind: Kind, ordinal: u32, name: []const u8, value: []const u8) void {
        var header: [21]u8 = undefined;
        header[0] = @intFromEnum(kind);
        std.mem.writeInt(u32, header[1..5], ordinal, .big);
        std.mem.writeInt(u64, header[5..13], @intCast(name.len), .big);
        std.mem.writeInt(u64, header[13..21], @intCast(value.len), .big);
        self.hash.update(&header);
        self.hash.update(name);
        self.hash.update(value);
    }

    pub fn finish(self: *Builder) Error!Digest {
        if (self.finished) return error.AlreadyFinished;
        var trailer: [12]u8 = undefined;
        std.mem.writeInt(u32, trailer[0..4], self.resolutions, .big);
        std.mem.writeInt(u64, trailer[4..12], @intCast(self.resolution_bytes), .big);
        self.hash.update(&trailer);
        var digest: Digest = undefined;
        self.hash.final(&digest);
        self.deinit();
        return digest;
    }

    pub fn deinit(self: *Builder) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.hash));
        self.finished = true;
    }
};

/// A second commitment covers material loaded after TOML parsing, such as
/// certificate files and persistent keys. Frame every field and keep the
/// source digest as the first input; no process build/version enters either
/// transcript, so an otherwise compatible new image can reproduce it.
pub const EffectiveBuilder = struct {
    pub const Kind = enum(u8) { tls = 1, ech = 2, vapid = 3, node = 4, cloak = 5, oauth = 6, geoip = 7 };

    hash: Sha256,
    records: u32 = 0,
    bytes: usize = 0,
    finished: bool = false,

    pub fn init(source_digest: Digest) EffectiveBuilder {
        var self = EffectiveBuilder{ .hash = Sha256.init(.{}) };
        self.hash.update("onyx/helix/windows-effective-config/v1\x00");
        self.hash.update(&source_digest);
        return self;
    }

    pub fn record(self: *EffectiveBuilder, kind: EffectiveBuilder.Kind, name: []const u8, value: []const u8) Error!void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0 or name.len > max_resolution_name_bytes or
            std.mem.indexOfScalar(u8, name, 0) != null or
            value.len > max_resolution_value_bytes) return error.MaterialTooLarge;
        if (self.records >= max_effective_material_records) return error.MaterialTooLarge;
        const added = std.math.add(usize, name.len, value.len) catch return error.MaterialTooLarge;
        if (added > max_effective_material_bytes - self.bytes) return error.MaterialTooLarge;
        var header: [21]u8 = undefined;
        header[0] = @intFromEnum(kind);
        std.mem.writeInt(u32, header[1..5], self.records + 1, .big);
        std.mem.writeInt(u64, header[5..13], @intCast(name.len), .big);
        std.mem.writeInt(u64, header[13..21], @intCast(value.len), .big);
        self.hash.update(&header);
        self.hash.update(name);
        self.hash.update(value);
        self.records += 1;
        self.bytes += added;
    }

    pub fn recordCount(self: *EffectiveBuilder, kind: EffectiveBuilder.Kind, name: []const u8, count: usize) Error!void {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, @intCast(count), .big);
        try self.record(kind, name, &encoded);
    }

    pub fn finish(self: *EffectiveBuilder) Error!Digest {
        if (self.finished) return error.AlreadyFinished;
        var trailer: [12]u8 = undefined;
        std.mem.writeInt(u32, trailer[0..4], self.records, .big);
        std.mem.writeInt(u64, trailer[4..12], @intCast(self.bytes), .big);
        self.hash.update(&trailer);
        var digest: Digest = undefined;
        self.hash.final(&digest);
        self.deinit();
        return digest;
    }

    pub fn deinit(self: *EffectiveBuilder) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.hash));
        self.finished = true;
    }
};

/// Bind a new, fully observed source transcript to the external material
/// loaded at boot. The latter is an EffectiveBuilder transcript with a zero
/// source input, so it cannot be forged by editing TOML during REHASH.
pub fn rebaseEffectiveDigest(source_digest: Digest, static_material_digest: Digest) Digest {
    var hash = Sha256.init(.{});
    hash.update("onyx/helix/windows-effective-rebase/v1\x00");
    hash.update(&source_digest);
    hash.update(&static_material_digest);
    var digest: Digest = undefined;
    hash.final(&digest);
    return digest;
}

test "Windows Helix rebased proof binds source and pinned external material" {
    const a = rebaseEffectiveDigest(@splat(0x11), @splat(0x22));
    const changed_source = rebaseEffectiveDigest(@splat(0x12), @splat(0x22));
    const changed_material = rebaseEffectiveDigest(@splat(0x11), @splat(0x23));
    try std.testing.expectEqual(a, rebaseEffectiveDigest(@splat(0x11), @splat(0x22)));
    try std.testing.expect(!std.mem.eql(u8, &a, &changed_source));
    try std.testing.expect(!std.mem.eql(u8, &a, &changed_material));
}

/// Commit the exact bytes pinned as the live city/ASN databases. An absent pair
/// adds no records, preserving the proof of existing Windows deployments whose
/// GeoIP feature is disabled. The caller must retain the same bytes for the
/// whole server lifetime; reopening a path after this proof would be a TOCTOU.
pub fn recordGeoipMaterial(proof: *EffectiveBuilder, city: ?[]const u8, asn: ?[]const u8) Error!void {
    if (city == null and asn == null) return;
    try proof.recordCount(.geoip, "city-present", @intFromBool(city != null));
    if (city) |bytes| {
        var digest: Digest = undefined;
        Sha256.hash(bytes, &digest, .{});
        try proof.recordCount(.geoip, "city-byte-count", bytes.len);
        try proof.record(.geoip, "city-sha256", &digest);
    }
    try proof.recordCount(.geoip, "asn-present", @intFromBool(asn != null));
    if (asn) |bytes| {
        var digest: Digest = undefined;
        Sha256.hash(bytes, &digest, .{});
        try proof.recordCount(.geoip, "asn-byte-count", bytes.len);
        try proof.record(.geoip, "asn-sha256", &digest);
    }
}

test "Windows GeoIP effective proof binds pinned bytes and preserves absent proof" {
    const source: Digest = @splat(7);
    var old = EffectiveBuilder.init(source);
    const old_digest = try old.finish();
    var absent = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&absent, null, null);
    try std.testing.expectEqual(old_digest, try absent.finish());
    var first = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&first, "city-a", "asn-a");
    const first_digest = try first.finish();
    var same = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&same, "city-a", "asn-a");
    try std.testing.expectEqual(first_digest, try same.finish());
    var changed_city = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&changed_city, "city-b", "asn-a");
    const changed_city_digest = try changed_city.finish();
    try std.testing.expect(!std.mem.eql(u8, &first_digest, &changed_city_digest));
    var changed_asn = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&changed_asn, "city-a", "asn-b");
    const changed_asn_digest = try changed_asn.finish();
    try std.testing.expect(!std.mem.eql(u8, &first_digest, &changed_asn_digest));
    var missing_asn = EffectiveBuilder.init(source);
    try recordGeoipMaterial(&missing_asn, "city-a", null);
    const missing_asn_digest = try missing_asn.finish();
    try std.testing.expect(!std.mem.eql(u8, &first_digest, &missing_asn_digest));
}

fn testPath() []const u8 {
    return if (@import("builtin").os.tag == .windows) "C:\\onyx\\server.toml" else "/onyx/server.toml";
}

test "Windows Helix source proof is stable across builds and binds ordered substitutions" {
    var first = try Builder.initCanonical(testPath(), "[node]\nid=1\n");
    try first.recordEnvironment("ONYX_SECRET", "alpha");
    try first.recordFile("secret.txt", "beta");
    const digest = try first.finish();

    var same = try Builder.initCanonical(testPath(), "[node]\nid=1\n");
    try same.recordEnvironment("ONYX_SECRET", "alpha");
    try same.recordFile("secret.txt", "beta");
    try std.testing.expectEqual(digest, try same.finish());

    var reordered = try Builder.initCanonical(testPath(), "[node]\nid=1\n");
    try reordered.recordFile("secret.txt", "beta");
    try reordered.recordEnvironment("ONYX_SECRET", "alpha");
    const reordered_digest = try reordered.finish();
    try std.testing.expect(!std.mem.eql(u8, &digest, &reordered_digest));

    var changed = try Builder.initCanonical(testPath(), "[node]\nid=1\n");
    try changed.recordEnvironment("ONYX_SECRET", "alpha");
    try changed.recordFile("secret.txt", "other");
    const changed_digest = try changed.finish();
    try std.testing.expect(!std.mem.eql(u8, &digest, &changed_digest));
}

test "Windows Helix source proof frames path source kind and value boundaries" {
    var a = try Builder.initCanonical(testPath(), "ab");
    try a.recordEnvironment("c", "de");
    const a_digest = try a.finish();

    const other_path = if (@import("builtin").os.tag == .windows) "C:\\onyx\\other.toml" else "/onyx/other.toml";
    var path_changed = try Builder.initCanonical(other_path, "ab");
    try path_changed.recordEnvironment("c", "de");
    const path_digest = try path_changed.finish();
    try std.testing.expect(!std.mem.eql(u8, &a_digest, &path_digest));

    var source_changed = try Builder.initCanonical(testPath(), "abc");
    try source_changed.recordEnvironment("c", "de");
    const source_digest = try source_changed.finish();
    try std.testing.expect(!std.mem.eql(u8, &a_digest, &source_digest));

    var split_changed = try Builder.initCanonical(testPath(), "ab");
    try split_changed.recordEnvironment("cd", "e");
    const split_digest = try split_changed.finish();
    try std.testing.expect(!std.mem.eql(u8, &a_digest, &split_digest));

    var kind_changed = try Builder.initCanonical(testPath(), "ab");
    try kind_changed.recordFile("c", "de");
    const kind_digest = try kind_changed.finish();
    try std.testing.expect(!std.mem.eql(u8, &a_digest, &kind_digest));
}

test "Windows Helix source proof bounds input and is one-use" {
    try std.testing.expectError(error.InvalidPath, Builder.initCanonical("relative.toml", ""));
    const source = try std.testing.allocator.alloc(u8, max_source_bytes + 1);
    defer std.testing.allocator.free(source);
    try std.testing.expectError(error.SourceTooLarge, Builder.initCanonical(testPath(), source));

    var proof = try Builder.initCanonical(testPath(), "");
    defer proof.deinit();
    try std.testing.expectError(error.ResolutionTooLarge, proof.recordEnvironment("", "x"));
    try proof.recordEnvironment("X", "y");
    _ = try proof.finish();
    try std.testing.expectError(error.AlreadyFinished, proof.finish());
    try std.testing.expectError(error.AlreadyFinished, proof.recordFile("x", "y"));
}

test "Windows Helix effective proof binds loaded material and source without build version" {
    const source: Digest = @splat(0x53);
    var first = EffectiveBuilder.init(source);
    try first.record(.tls, "leaf", "certificate");
    try first.record(.vapid, "scalar", "secret");
    const expected = try first.finish();

    var same = EffectiveBuilder.init(source);
    try same.record(.tls, "leaf", "certificate");
    try same.record(.vapid, "scalar", "secret");
    try std.testing.expectEqual(expected, try same.finish());

    var changed_source = EffectiveBuilder.init(@splat(0x54));
    try changed_source.record(.tls, "leaf", "certificate");
    try changed_source.record(.vapid, "scalar", "secret");
    const changed_source_digest = try changed_source.finish();
    try std.testing.expect(!std.mem.eql(u8, &expected, &changed_source_digest));

    var changed_material = EffectiveBuilder.init(source);
    try changed_material.record(.tls, "leaf", "certificate");
    try changed_material.record(.vapid, "scalar", "other");
    const changed_material_digest = try changed_material.finish();
    try std.testing.expect(!std.mem.eql(u8, &expected, &changed_material_digest));

    var reordered = EffectiveBuilder.init(source);
    try reordered.record(.vapid, "scalar", "secret");
    try reordered.record(.tls, "leaf", "certificate");
    const reordered_digest = try reordered.finish();
    try std.testing.expect(!std.mem.eql(u8, &expected, &reordered_digest));
}
