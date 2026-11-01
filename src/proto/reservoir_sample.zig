// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-capacity Algorithm R reservoir sampling.
//!
//! This module keeps `k` uniformly selected items from a stream whose final
//! length is not known ahead of time. It is pure state transition logic: callers
//! provide the random source, and the sampler never allocates.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("reservoir sampling requires a 64-bit target");
}

/// Configuration for a fixed-capacity reservoir sampler.
pub const Params = struct {
    /// Number of items retained from the observed stream.
    sample_count: usize = 64,
};

/// Errors returned while advancing the stream.
pub const ReservoirSampleError = error{
    /// The stream counter exhausted its 64-bit range.
    StreamTooLong,
};

/// Outcome of offering one item to the reservoir.
pub const OfferResult = enum(u2) {
    /// The reservoir was not full, so the item was appended.
    inserted = 0,
    /// The reservoir was full, and the item replaced an existing sample.
    replaced = 1,
    /// The reservoir was full, and the item was not selected.
    skipped = 2,

    /// Convert an encoded result value into an offer result.
    pub fn fromCode(encoded: u2) ?OfferResult {
        return switch (encoded) {
            0 => .inserted,
            1 => .replaced,
            2 => .skipped,
            3 => null,
        };
    }

    /// Return the compact encoded value for this offer result.
    pub fn code(self: OfferResult) u2 {
        return @backingInt(self);
    }
};

/// Build a fixed-capacity Algorithm R sampler for `Item`.
pub fn ReservoirSample(comptime Item: type, comptime params: Params) type {
    comptime {
        if (params.sample_count == 0) @compileError("reservoir sampling needs at least one slot");
    }

    return struct {
        const Self = @This();

        /// Retained sample slots. Only `samples[0..len]` are initialized.
        samples: [params.sample_count]Item = undefined,
        /// Number of initialized slots in `samples`.
        len: usize = 0,
        /// Number of stream items observed so far.
        seen: u64 = 0,

        /// Construct an empty sampler.
        pub fn init() Self {
            return .{};
        }

        /// Release sampler resources.
        ///
        /// The sampler owns no heap memory, so this exists for lifecycle
        /// symmetry with sibling modules.
        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        /// Remove all retained samples and reset stream accounting.
        pub fn clear(self: *Self) void {
            self.len = 0;
            self.seen = 0;
        }

        /// Offer one stream item to the reservoir.
        ///
        /// Until the reservoir is full, items are appended. After that, the
        /// item replaces a uniformly selected existing slot with probability
        /// `k / seen`, where `seen` includes this item.
        pub fn offer(self: *Self, item: Item, random: std.Random) ReservoirSampleError!OfferResult {
            const next_seen = std.math.add(u64, self.seen, 1) catch return error.StreamTooLong;
            self.seen = next_seen;

            if (self.len < self.samples.len) {
                self.samples[self.len] = item;
                self.len += 1;
                return .inserted;
            }

            const replacement = random.uintLessThan(u64, self.seen);
            if (replacement < self.samples.len) {
                self.samples[@intCast(replacement)] = item;
                return .replaced;
            }

            return .skipped;
        }

        /// Return initialized retained samples in reservoir slot order.
        pub fn items(self: *const Self) []const Item {
            return self.samples[0..self.len];
        }

        /// Return the fixed reservoir capacity.
        pub fn capacity(self: *const Self) usize {
            _ = self;
            return params.sample_count;
        }

        /// Return the current number of retained samples.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Return the number of stream items observed so far.
        pub fn totalSeen(self: *const Self) u64 {
            return self.seen;
        }

        /// Return true once the reservoir has initialized every slot.
        pub fn isFull(self: *const Self) bool {
            return self.len == self.samples.len;
        }

        /// Return the retained item at `index`, or null when the slot is empty.
        pub fn slot(self: *const Self, index: usize) ?Item {
            if (index >= self.len) return null;
            return self.samples[index];
        }
    };
}

const testing = std.testing;

test "offer fills reservoir until it reaches k" {
    // Arrange.
    const allocator = testing.allocator;
    const expected = try allocator.alloc(u16, 3);
    defer allocator.free(expected);
    expected[0] = 11;
    expected[1] = 22;
    expected[2] = 33;

    const Sampler = ReservoirSample(u16, .{ .sample_count = 3 });
    var sampler = Sampler.init();
    defer sampler.deinit();
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3031);
    const random = prng.random();

    // Act.
    const first = try sampler.offer(expected[0], random);
    const second = try sampler.offer(expected[1], random);
    const third = try sampler.offer(expected[2], random);

    // Assert.
    try testing.expectEqual(OfferResult.inserted, first);
    try testing.expectEqual(OfferResult.inserted, second);
    try testing.expectEqual(OfferResult.inserted, third);
    try testing.expectEqual(@as(usize, 3), sampler.capacity());
    try testing.expectEqual(@as(usize, 3), sampler.count());
    try testing.expectEqual(@as(u64, 3), sampler.totalSeen());
    try testing.expect(sampler.isFull());
    try testing.expectEqualSlices(u16, expected, sampler.items());
}

test "offer keeps every item when k is at least the stream length" {
    // Arrange.
    const allocator = testing.allocator;
    const stream = try allocator.alloc(u8, 5);
    defer allocator.free(stream);
    for (stream, 0..) |*value, index| {
        value.* = @intCast(index + 1);
    }

    const Sampler = ReservoirSample(u8, .{ .sample_count = 8 });
    var sampler = Sampler.init();
    defer sampler.deinit();
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3032);
    const random = prng.random();

    // Act.
    for (stream) |value| {
        try testing.expectEqual(OfferResult.inserted, try sampler.offer(value, random));
    }

    // Assert.
    try testing.expect(!sampler.isFull());
    try testing.expectEqual(@as(usize, 5), sampler.count());
    try testing.expectEqual(@as(u64, 5), sampler.totalSeen());
    try testing.expectEqualSlices(u8, stream, sampler.items());
    try testing.expectEqual(@as(?u8, null), sampler.slot(5));
}

test "offer replaces the newest item at roughly uniform probability" {
    // Arrange.
    const allocator = testing.allocator;
    const trials: usize = 20_000;
    const stream_len: usize = 10;
    const retained_counts = try allocator.alloc(usize, stream_len);
    defer allocator.free(retained_counts);
    @memset(retained_counts, 0);

    const Sampler = ReservoirSample(u8, .{ .sample_count = 1 });
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3033);
    const random = prng.random();

    // Act.
    for (0..trials) |_| {
        var sampler = Sampler.init();
        defer sampler.deinit();

        for (0..stream_len) |index| {
            _ = try sampler.offer(@intCast(index), random);
        }

        retained_counts[sampler.items()[0]] += 1;
    }

    // Assert.
    for (retained_counts) |count| {
        try testing.expect(count > trials / 20);
        try testing.expect(count < trials / 5);
    }
}

test "offer reports replacements and skips after reservoir is full" {
    // Arrange.
    const allocator = testing.allocator;
    const outcomes = try allocator.alloc(usize, 3);
    defer allocator.free(outcomes);
    @memset(outcomes, 0);

    const Sampler = ReservoirSample(u64, .{ .sample_count = 2 });
    var sampler = Sampler.init();
    defer sampler.deinit();
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3034);
    const random = prng.random();

    // Act.
    for (0..256) |index| {
        const result = try sampler.offer(@intCast(index), random);
        outcomes[result.code()] += 1;
    }

    // Assert.
    try testing.expectEqual(@as(usize, 2), outcomes[OfferResult.inserted.code()]);
    try testing.expect(outcomes[OfferResult.replaced.code()] > 0);
    try testing.expect(outcomes[OfferResult.skipped.code()] > 0);
    try testing.expectEqual(@as(usize, 2), sampler.count());
    try testing.expectEqual(@as(u64, 256), sampler.totalSeen());
}

test "clear removes retained samples and restarts stream accounting" {
    // Arrange.
    const allocator = testing.allocator;
    const values = try allocator.alloc(u32, 2);
    defer allocator.free(values);
    values[0] = 7;
    values[1] = 9;

    const Sampler = ReservoirSample(u32, .{ .sample_count = 2 });
    var sampler = Sampler.init();
    defer sampler.deinit();
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3035);
    const random = prng.random();

    // Act.
    _ = try sampler.offer(values[0], random);
    _ = try sampler.offer(values[1], random);
    sampler.clear();

    // Assert.
    try testing.expectEqual(@as(usize, 0), sampler.count());
    try testing.expectEqual(@as(u64, 0), sampler.totalSeen());
    try testing.expect(!sampler.isFull());
    try testing.expectEqual(@as(?u32, null), sampler.slot(0));
}

test "offer rejects stream counter overflow" {
    // Arrange.
    const allocator = testing.allocator;
    const values = try allocator.alloc(u8, 1);
    defer allocator.free(values);
    values[0] = 1;

    const Sampler = ReservoirSample(u8, .{ .sample_count = 1 });
    var sampler = Sampler.init();
    defer sampler.deinit();
    sampler.seen = std.math.maxInt(u64);
    var prng = std.Random.DefaultPrng.init(0x7265_7365_7276_3036);
    const random = prng.random();

    // Act and assert.
    try testing.expectError(error.StreamTooLong, sampler.offer(values[0], random));
}

test "offer result codes round-trip known values" {
    // Arrange.
    const allocator = testing.allocator;
    const results = try allocator.alloc(OfferResult, 3);
    defer allocator.free(results);
    results[0] = .inserted;
    results[1] = .replaced;
    results[2] = .skipped;

    // Act and assert.
    for (results) |result| {
        try testing.expectEqual(result, OfferResult.fromCode(result.code()).?);
    }
    try testing.expectEqual(@as(?OfferResult, null), OfferResult.fromCode(3));
}
