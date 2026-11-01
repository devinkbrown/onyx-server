// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const Allocator = std.mem.Allocator;
const array_to_bitset_threshold = 4096;
const bitset_words = 1024;
const chunk_span = 1 << 16;

/// A compact u32 set using Roaring-style 16-bit chunk containers.
///
/// This intentionally implements only array and bitset containers. Roaring run
/// containers are omitted to keep this module small and dependency-free; dense
/// contiguous ranges are represented by bitsets once a chunk crosses the normal
/// 4096-value threshold.
pub const Bitmap = struct {
    allocator: Allocator,
    containers: std.AutoHashMap(u16, Container),

    pub fn init(allocator: Allocator) Bitmap {
        return .{
            .allocator = allocator,
            .containers = std.AutoHashMap(u16, Container).init(allocator),
        };
    }

    pub fn deinit(self: *Bitmap) void {
        var it = self.containers.valueIterator();
        while (it.next()) |container| container.deinit(self.allocator);
        self.containers.deinit();
        self.* = undefined;
    }

    pub fn add(self: *Bitmap, value: u32) !bool {
        const high = highBits(value);
        const low = lowBits(value);
        var entry = try self.containers.getOrPut(high);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .array = .{} };
        }
        errdefer if (!entry.found_existing) {
            entry.value_ptr.deinit(self.allocator);
            _ = self.containers.remove(high);
        };
        return entry.value_ptr.add(self.allocator, low);
    }

    pub fn remove(self: *Bitmap, value: u32) !bool {
        const high = highBits(value);
        const low = lowBits(value);
        const container = self.containers.getPtr(high) orelse return false;
        const removed = try container.remove(self.allocator, low);
        if (removed and container.cardinality() == 0) {
            container.deinit(self.allocator);
            _ = self.containers.remove(high);
        }
        return removed;
    }

    pub fn contains(self: *const Bitmap, value: u32) bool {
        const container = self.containers.getPtr(highBits(value)) orelse return false;
        return container.contains(lowBits(value));
    }

    pub fn cardinality(self: *const Bitmap) u64 {
        var total: u64 = 0;
        var it = self.containers.valueIterator();
        while (it.next()) |container| total += container.cardinality();
        return total;
    }

    pub fn iterator(self: *const Bitmap) Iterator {
        return .{ .bitmap = self };
    }

    pub fn setUnion(allocator: Allocator, a: *const Bitmap, b: *const Bitmap) !Bitmap {
        var out = Bitmap.init(allocator);
        errdefer out.deinit();

        var a_it = a.iterator();
        while (a_it.next()) |value| _ = try out.add(value);

        var b_it = b.iterator();
        while (b_it.next()) |value| _ = try out.add(value);

        return out;
    }

    pub fn setIntersection(allocator: Allocator, a: *const Bitmap, b: *const Bitmap) !Bitmap {
        var out = Bitmap.init(allocator);
        errdefer out.deinit();

        const smaller = if (a.cardinality() <= b.cardinality()) a else b;
        const larger = if (smaller == a) b else a;
        var it = smaller.iterator();
        while (it.next()) |value| {
            if (larger.contains(value)) _ = try out.add(value);
        }

        return out;
    }

    pub fn setDifference(allocator: Allocator, a: *const Bitmap, b: *const Bitmap) !Bitmap {
        var out = Bitmap.init(allocator);
        errdefer out.deinit();

        var it = a.iterator();
        while (it.next()) |value| {
            if (!b.contains(value)) _ = try out.add(value);
        }

        return out;
    }
};

pub const Iterator = struct {
    bitmap: *const Bitmap,
    next_value: u64 = 0,
    done: bool = false,

    pub fn next(self: *Iterator) ?u32 {
        return self.nextImpl(false, null);
    }

    // The counted instantiation lets tests bound actual map probes without
    // adding counters or allocation to production iterators.
    fn nextImpl(self: *Iterator, comptime count_probes: bool, probes: ?*usize) ?u32 {
        if (self.done or self.next_value > std.math.maxInt(u32)) return null;
        if (self.bitmap.containers.count() == 0) {
            self.done = true;
            return null;
        }

        var high: u32 = @intCast(self.next_value >> 16);
        var low = lowBits(@intCast(self.next_value));
        while (high <= std.math.maxInt(u16)) {
            // Probe each high key at most once while crossing gaps. Scanning the
            // hash map for the next chunk on every value is quadratic for sparse
            // sets, and repeats the same scan for every value in a dense chunk.
            if (count_probes) probes.?.* += 1;
            if (self.bitmap.containers.getPtr(@intCast(high))) |container| {
                if (container.firstAtLeast(low)) |found_low| {
                    const value = (high << 16) | @as(u32, found_low);
                    self.next_value = @as(u64, value) + 1;
                    return value;
                }
            }
            high += 1;
            low = 0;
            // A fixed-size fallback avoids probing large empty gaps for tiny
            // sets. For C containers, at most C+1 searches inspect C keys
            // apiece, plus at most C+1 exhausted/missing chunk probes. Capping C
            // at 512 bounds this work; larger sets use the high-key domain above.
            if (self.bitmap.containers.count() <= 512) {
                var next_high: u32 = chunk_span;
                var keys = self.bitmap.containers.keyIterator();
                while (keys.next()) |key| {
                    if (count_probes) probes.?.* += 1;
                    if (key.* >= high and key.* < next_high) next_high = key.*;
                }
                high = next_high;
            }
        }

        self.done = true;
        return null;
    }
};

const Container = union(enum) {
    array: ArrayContainer,
    bitset: BitsetContainer,

    fn deinit(self: *Container, allocator: Allocator) void {
        switch (self.*) {
            .array => |*array| array.deinit(allocator),
            .bitset => {},
        }
    }

    fn add(self: *Container, allocator: Allocator, value: u16) !bool {
        switch (self.*) {
            .array => |*array| {
                const inserted = try array.add(allocator, value);
                if (array.cardinality() > array_to_bitset_threshold) {
                    var bitset = BitsetContainer.empty();
                    for (array.values.items) |item| _ = bitset.add(item);
                    array.deinit(allocator);
                    self.* = .{ .bitset = bitset };
                }
                return inserted;
            },
            .bitset => |*bitset| return bitset.add(value),
        }
    }

    fn remove(self: *Container, allocator: Allocator, value: u16) !bool {
        switch (self.*) {
            .array => |*array| return array.remove(value),
            .bitset => |*bitset| {
                const removed = bitset.remove(value);
                if (removed and bitset.cardinality() <= array_to_bitset_threshold) {
                    const array = try ArrayContainer.fromBitset(allocator, bitset);
                    bitset.* = undefined;
                    self.* = .{ .array = array };
                }
                return removed;
            },
        }
    }

    fn contains(self: *const Container, value: u16) bool {
        return switch (self.*) {
            .array => |*array| array.contains(value),
            .bitset => |*bitset| bitset.contains(value),
        };
    }

    fn cardinality(self: *const Container) u64 {
        return switch (self.*) {
            .array => |*array| array.cardinality(),
            .bitset => |*bitset| bitset.cardinality(),
        };
    }

    fn firstAtLeast(self: *const Container, value: u16) ?u16 {
        return switch (self.*) {
            .array => |*array| array.firstAtLeast(value),
            .bitset => |*bitset| bitset.firstAtLeast(value),
        };
    }
};

const ArrayContainer = struct {
    values: std.ArrayList(u16) = .empty,

    fn deinit(self: *ArrayContainer, allocator: Allocator) void {
        self.values.deinit(allocator);
        self.* = undefined;
    }

    fn add(self: *ArrayContainer, allocator: Allocator, value: u16) !bool {
        const index = self.lowerBound(value);
        if (index < self.values.items.len and self.values.items[index] == value) return false;
        try self.values.insert(allocator, index, value);
        return true;
    }

    fn remove(self: *ArrayContainer, value: u16) bool {
        const index = self.lowerBound(value);
        if (index == self.values.items.len or self.values.items[index] != value) return false;
        _ = self.values.orderedRemove(index);
        return true;
    }

    fn contains(self: ArrayContainer, value: u16) bool {
        const index = self.lowerBound(value);
        return index < self.values.items.len and self.values.items[index] == value;
    }

    fn cardinality(self: ArrayContainer) u64 {
        return self.values.items.len;
    }

    fn firstAtLeast(self: ArrayContainer, value: u16) ?u16 {
        const index = self.lowerBound(value);
        if (index == self.values.items.len) return null;
        return self.values.items[index];
    }

    fn lowerBound(self: ArrayContainer, value: u16) usize {
        var lo: usize = 0;
        var hi = self.values.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.values.items[mid] < value) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    fn fromBitset(allocator: Allocator, bitset: *const BitsetContainer) !ArrayContainer {
        var out: ArrayContainer = .{};
        errdefer out.deinit(allocator);
        try out.values.ensureTotalCapacity(allocator, @intCast(bitset.cardinality()));

        var next_low: u16 = 0;
        while (bitset.firstAtLeast(next_low)) |value| {
            try out.values.append(allocator, value);
            if (value == std.math.maxInt(u16)) break;
            next_low = value + 1;
        }

        return out;
    }
};

const BitsetContainer = struct {
    words: [bitset_words]u64,
    count: u32,

    fn empty() BitsetContainer {
        return .{
            .words = @as([bitset_words]u64, @splat(0)),
            .count = 0,
        };
    }

    fn add(self: *BitsetContainer, value: u16) bool {
        const idx = wordIndex(value);
        const bit = wordBit(value);
        if ((self.words[idx] & bit) != 0) return false;
        self.words[idx] |= bit;
        self.count += 1;
        return true;
    }

    fn remove(self: *BitsetContainer, value: u16) bool {
        const idx = wordIndex(value);
        const bit = wordBit(value);
        if ((self.words[idx] & bit) == 0) return false;
        self.words[idx] &= ~bit;
        self.count -= 1;
        return true;
    }

    fn contains(self: *const BitsetContainer, value: u16) bool {
        return (self.words[wordIndex(value)] & wordBit(value)) != 0;
    }

    fn cardinality(self: *const BitsetContainer) u64 {
        return self.count;
    }

    fn firstAtLeast(self: *const BitsetContainer, value: u16) ?u16 {
        var idx = wordIndex(value);
        var word = self.words[idx] & (@as(u64, std.math.maxInt(u64)) << bitShift(value));
        while (true) : (idx += 1) {
            if (word != 0) {
                const bit: u6 = @intCast(@ctz(word));
                return @intCast(idx * 64 + @as(usize, bit));
            }
            if (idx + 1 == bitset_words) return null;
            word = self.words[idx + 1];
        }
    }
};

fn highBits(value: u32) u16 {
    return @intCast(value >> 16);
}

fn lowBits(value: u32) u16 {
    return @truncate(value);
}

fn wordIndex(value: u16) usize {
    return @as(usize, value) >> 6;
}

fn bitShift(value: u16) u6 {
    return @intCast(value & 63);
}

fn wordBit(value: u16) u64 {
    return @as(u64, 1) << bitShift(value);
}

fn expectContainerTag(bitmap: *const Bitmap, high: u16, expected: std.meta.Tag(Container)) !void {
    const container = bitmap.containers.get(high) orelse return error.MissingContainer;
    try std.testing.expectEqual(expected, std.meta.activeTag(container));
}

fn expectBitmapEqualsOracle(bitmap: *const Bitmap, oracle: *const std.AutoHashMap(u32, void)) !void {
    try std.testing.expectEqual(@as(u64, @intCast(oracle.count())), bitmap.cardinality());

    var oracle_it = oracle.keyIterator();
    while (oracle_it.next()) |key| {
        try std.testing.expect(bitmap.contains(key.*));
    }

    var seen: u64 = 0;
    var bitmap_it = bitmap.iterator();
    while (bitmap_it.next()) |value| {
        try std.testing.expect(oracle.contains(value));
        seen += 1;
    }
    try std.testing.expectEqual(@as(u64, @intCast(oracle.count())), seen);
}

fn oracleUnion(
    allocator: Allocator,
    a: *const std.AutoHashMap(u32, void),
    b: *const std.AutoHashMap(u32, void),
) !std.AutoHashMap(u32, void) {
    var out = std.AutoHashMap(u32, void).init(allocator);
    errdefer out.deinit();

    var a_it = a.keyIterator();
    while (a_it.next()) |key| try out.put(key.*, {});
    var b_it = b.keyIterator();
    while (b_it.next()) |key| try out.put(key.*, {});

    return out;
}

fn oracleIntersection(
    allocator: Allocator,
    a: *const std.AutoHashMap(u32, void),
    b: *const std.AutoHashMap(u32, void),
) !std.AutoHashMap(u32, void) {
    var out = std.AutoHashMap(u32, void).init(allocator);
    errdefer out.deinit();

    var a_it = a.keyIterator();
    while (a_it.next()) |key| {
        if (b.contains(key.*)) try out.put(key.*, {});
    }

    return out;
}

fn oracleDifference(
    allocator: Allocator,
    a: *const std.AutoHashMap(u32, void),
    b: *const std.AutoHashMap(u32, void),
) !std.AutoHashMap(u32, void) {
    var out = std.AutoHashMap(u32, void).init(allocator);
    errdefer out.deinit();

    var a_it = a.keyIterator();
    while (a_it.next()) |key| {
        if (!b.contains(key.*)) try out.put(key.*, {});
    }

    return out;
}

test "add contains and remove across chunks" {
    const allocator = std.testing.allocator;
    var bitmap = Bitmap.init(allocator);
    defer bitmap.deinit();

    try std.testing.expect(!bitmap.contains(0));
    try std.testing.expect(try bitmap.add(0));
    try std.testing.expect(!try bitmap.add(0));
    try std.testing.expect(try bitmap.add(1));
    try std.testing.expect(try bitmap.add(65535));
    try std.testing.expect(try bitmap.add(65536));
    try std.testing.expect(try bitmap.add(std.math.maxInt(u32)));

    try std.testing.expect(bitmap.contains(0));
    try std.testing.expect(bitmap.contains(1));
    try std.testing.expect(bitmap.contains(65535));
    try std.testing.expect(bitmap.contains(65536));
    try std.testing.expect(bitmap.contains(std.math.maxInt(u32)));
    try std.testing.expect(!bitmap.contains(65537));
    try std.testing.expectEqual(@as(u64, 5), bitmap.cardinality());

    try std.testing.expect(try bitmap.remove(65535));
    try std.testing.expect(!try bitmap.remove(65535));
    try std.testing.expect(!bitmap.contains(65535));
    try std.testing.expectEqual(@as(u64, 4), bitmap.cardinality());
}

test "cardinality ignores duplicate adds and empty removals" {
    const allocator = std.testing.allocator;
    var bitmap = Bitmap.init(allocator);
    defer bitmap.deinit();

    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        try std.testing.expect(try bitmap.add(i * 13));
        try std.testing.expect(!try bitmap.add(i * 13));
    }

    try std.testing.expectEqual(@as(u64, 5000), bitmap.cardinality());
    try std.testing.expect(!try bitmap.remove(12));
    try std.testing.expectEqual(@as(u64, 5000), bitmap.cardinality());
}

test "containers promote above and demote at the threshold" {
    const allocator = std.testing.allocator;
    var bitmap = Bitmap.init(allocator);
    defer bitmap.deinit();

    var low: u32 = 0;
    while (low < array_to_bitset_threshold) : (low += 1) {
        try std.testing.expect(try bitmap.add(low));
    }
    try expectContainerTag(&bitmap, 0, .array);
    try std.testing.expectEqual(@as(u64, array_to_bitset_threshold), bitmap.cardinality());

    try std.testing.expect(try bitmap.add(array_to_bitset_threshold));
    try expectContainerTag(&bitmap, 0, .bitset);
    try std.testing.expectEqual(@as(u64, array_to_bitset_threshold + 1), bitmap.cardinality());

    try std.testing.expect(try bitmap.remove(array_to_bitset_threshold));
    try expectContainerTag(&bitmap, 0, .array);
    try std.testing.expectEqual(@as(u64, array_to_bitset_threshold), bitmap.cardinality());
}

test "ascending iteration visits every value in order" {
    const allocator = std.testing.allocator;
    var bitmap = Bitmap.init(allocator);
    defer bitmap.deinit();

    const values = [_]u32{
        std.math.maxInt(u32),
        65536 + 2,
        0,
        65535,
        3,
        65536,
        2,
    };
    for (values) |value| _ = try bitmap.add(value);

    const expected = [_]u32{
        0,
        2,
        3,
        65535,
        65536,
        65536 + 2,
        std.math.maxInt(u32),
    };

    var it = bitmap.iterator();
    for (expected) |value| {
        try std.testing.expectEqual(value, it.next().?);
    }
    try std.testing.expectEqual(@as(?u32, null), it.next());
}

test "empty bitmap and u32 edge behavior" {
    const allocator = std.testing.allocator;
    var bitmap = Bitmap.init(allocator);
    defer bitmap.deinit();

    try std.testing.expectEqual(@as(u64, 0), bitmap.cardinality());
    try std.testing.expect(!bitmap.contains(0));
    try std.testing.expect(!try bitmap.remove(0));
    var empty_it = bitmap.iterator();
    try std.testing.expectEqual(@as(?u32, null), empty_it.next());

    try std.testing.expect(try bitmap.add(std.math.maxInt(u32)));
    try std.testing.expect(bitmap.contains(std.math.maxInt(u32)));
    var edge_it = bitmap.iterator();
    try std.testing.expectEqual(std.math.maxInt(u32), edge_it.next().?);
    try std.testing.expectEqual(@as(?u32, null), edge_it.next());
    try std.testing.expect(try bitmap.remove(std.math.maxInt(u32)));
    try std.testing.expectEqual(@as(u64, 0), bitmap.cardinality());
}

test "set operations match random AutoHashMap oracle" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x726f_6172_696e_6731);
    const random = prng.random();

    var a = Bitmap.init(allocator);
    defer a.deinit();
    var b = Bitmap.init(allocator);
    defer b.deinit();

    var oracle_a = std.AutoHashMap(u32, void).init(allocator);
    defer oracle_a.deinit();
    var oracle_b = std.AutoHashMap(u32, void).init(allocator);
    defer oracle_b.deinit();

    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        const dense_a: u32 = @intCast(i % 5000);
        const dense_b: u32 = @intCast(2500 + (i % 5000));
        const sparse_a = random.int(u32);
        const sparse_b = random.int(u32);

        _ = try a.add(dense_a);
        try oracle_a.put(dense_a, {});
        _ = try b.add(dense_b);
        try oracle_b.put(dense_b, {});

        _ = try a.add(sparse_a);
        try oracle_a.put(sparse_a, {});
        _ = try b.add(sparse_b);
        try oracle_b.put(sparse_b, {});
    }

    try expectBitmapEqualsOracle(&a, &oracle_a);
    try expectBitmapEqualsOracle(&b, &oracle_b);

    var expected_union = try oracleUnion(allocator, &oracle_a, &oracle_b);
    defer expected_union.deinit();
    var actual_union = try Bitmap.setUnion(allocator, &a, &b);
    defer actual_union.deinit();
    try expectBitmapEqualsOracle(&actual_union, &expected_union);

    var expected_intersection = try oracleIntersection(allocator, &oracle_a, &oracle_b);
    defer expected_intersection.deinit();
    var actual_intersection = try Bitmap.setIntersection(allocator, &a, &b);
    defer actual_intersection.deinit();
    try expectBitmapEqualsOracle(&actual_intersection, &expected_intersection);

    var expected_difference = try oracleDifference(allocator, &oracle_a, &oracle_b);
    defer expected_difference.deinit();
    var actual_difference = try Bitmap.setDifference(allocator, &a, &b);
    defer actual_difference.deinit();
    try expectBitmapEqualsOracle(&actual_difference, &expected_difference);
}

test "iteration bounds map probes across dense chunks and sparse high keys" {
    var bitmap = Bitmap.init(std.testing.allocator);
    defer bitmap.deinit();

    // A promoted dense chunk, many separate sparse chunks, and both u32 ends.
    var value: u32 = 0;
    while (value < 5000) : (value += 1) _ = try bitmap.add(value);
    var high: u32 = 1;
    while (high < 1024) : (high += 1) _ = try bitmap.add(high << 16);
    _ = try bitmap.add(std.math.maxInt(u32));

    var it = bitmap.iterator();
    var probes: usize = 0;
    var seen: u64 = 0;
    var previous: ?u32 = null;
    while (it.nextImpl(true, &probes)) |found| {
        if (previous) |last| try std.testing.expect(found > last);
        try std.testing.expect(bitmap.contains(found));
        previous = found;
        seen += 1;
    }
    try std.testing.expectEqual(bitmap.cardinality(), seen);
    try std.testing.expectEqual(std.math.maxInt(u32), previous.?);
    // Each emitted value needs one probe; crossing the entire high-key domain
    // needs at most one additional probe per key, independent of container count.
    try std.testing.expect(probes <= chunk_span + seen);
    const final_probes = probes;
    try std.testing.expectEqual(@as(?u32, null), it.nextImpl(true, &probes));
    try std.testing.expectEqual(final_probes, probes);
}

test "tiny and empty iteration avoid scanning the high-key domain" {
    var bitmap = Bitmap.init(std.testing.allocator);
    defer bitmap.deinit();

    var probes: usize = 0;
    var empty_it = bitmap.iterator();
    try std.testing.expectEqual(@as(?u32, null), empty_it.nextImpl(true, &probes));
    try std.testing.expectEqual(@as(usize, 0), probes);

    _ = try bitmap.add(1);
    _ = try bitmap.add(std.math.maxInt(u32));
    var it = bitmap.iterator();
    try std.testing.expectEqual(@as(?u32, 1), it.nextImpl(true, &probes));
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32)), it.nextImpl(true, &probes));
    try std.testing.expectEqual(@as(?u32, null), it.nextImpl(true, &probes));
    try std.testing.expect(probes <= 6);
}

test "medium sparse iteration skips high-key gaps with bounded key visits" {
    var bitmap = Bitmap.init(std.testing.allocator);
    defer bitmap.deinit();
    var high: u32 = 0;
    while (high < 65) : (high += 1) _ = try bitmap.add((high * 1023) << 16);

    var it = bitmap.iterator();
    var probes: usize = 0;
    high = 0;
    while (high < 65) : (high += 1) {
        try std.testing.expectEqual(@as(?u32, (high * 1023) << 16), it.nextImpl(true, &probes));
    }
    try std.testing.expectEqual(@as(?u32, null), it.nextImpl(true, &probes));
    const count: usize = bitmap.containers.count();
    // Count both direct probes and key visits. This distribution spans almost
    // the full high-key domain, so a domain scan would exceed this bound.
    try std.testing.expect(probes <= count * (count + 3));
}
