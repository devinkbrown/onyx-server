// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! audio_mix.zig — N-participant mono f32 conference audio mixer.
//!
//! Features:
//!   - Per-participant gain
//!   - Soft limiter (tanh-based) to prevent clipping (output |sample| < 1.0)
//!   - N-1 mixdown: mixFor(id) returns sum of all *other* participants
//!   - Full mixAll() returning sum of all participants
//!   - Active speaker detection via short-time energy gate
//!
//! All memory is caller-managed via an Allocator. Frames are fixed-size slices
//! of f32 samples (mono). Every participant must submit frames of the same
//! length (frame_size set at Mixer init time).

const std = @import("std");
const toml = @import("../proto/toml.zig");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayListUnmanaged;
const AutoHashMap = std.AutoHashMap;

/// Documented mixer defaults (historically caller-supplied / hardcoded).
pub const default_energy_threshold: f32 = 1e-6;
pub const default_frame_size_samples: usize = 960;
pub const default_gain: f32 = 1.0;

/// Runtime-tunable mixer configuration. Defaults equal the historical values;
/// `applyToml` overlays the `[media.audio]` section.
pub const Config = struct {
    energy_threshold: f32 = default_energy_threshold,
    frame_size_samples: usize = default_frame_size_samples,
    default_gain: f32 = default_gain,
};

/// Overlay `[media.audio]` keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getFloat("media.audio.energy_threshold")) |v| cfg.energy_threshold = @floatCast(v);
    if (doc.getUint("media.audio.frame_size_samples")) |v| cfg.frame_size_samples = @intCast(v);
    if (doc.getFloat("media.audio.default_gain")) |v| cfg.default_gain = @floatCast(v);
}

/// Soft limiter: maps any finite real input to the open interval (-1, 1).
/// Uses the algebraic sigmoid x / (1 + |x|), which:
///   - is strictly monotone
///   - satisfies |f(x)| < 1 for all finite x
///   - is smooth everywhere and passes through the origin with slope 1
///   - never saturates to exactly ±1.0 in IEEE 754 f32 arithmetic
inline fn softLimit(x: f32) f32 {
    return x / (1.0 + @abs(x));
}

pub const ParticipantId = u32;

/// Per-participant state stored inside the mixer.
const Participant = struct {
    id: ParticipantId,
    gain: f32,
    /// Latest submitted frame (owned slice, length == mixer.frame_size).
    frame: []f32,
    /// Whether this participant is considered an active speaker this cycle.
    active: bool,
};

/// Short-time energy of a frame (mean square).
fn frameEnergy(samples: []const f32) f32 {
    if (samples.len == 0) return 0.0;
    var sum: f32 = 0.0;
    for (samples) |s| sum += s * s;
    return sum / @as(f32, @floatFromInt(samples.len));
}

/// Conference audio mixer.
pub const Mixer = struct {
    allocator: Allocator,
    frame_size: usize,
    /// Energy threshold below which a participant is considered silent.
    energy_threshold: f32,
    /// Initial per-participant gain applied on join.
    default_gain: f32,
    /// Ordered list of participants (order stable for determinism).
    participants: ArrayList(Participant),

    /// Initialise a mixer.
    /// `frame_size`        — number of f32 samples per frame.
    /// `energy_threshold`  — RMS² gate; 1e-6 is a reasonable default.
    /// New participants join at `default_gain` (1.0).
    pub fn init(allocator: Allocator, frame_size: usize, energy_threshold: f32) Mixer {
        return .{
            .allocator = allocator,
            .frame_size = frame_size,
            .energy_threshold = energy_threshold,
            .default_gain = default_gain,
            .participants = .empty,
        };
    }

    /// Initialise a mixer from a `Config` (frame size, energy gate, join gain).
    pub fn initConfig(allocator: Allocator, config: Config) Mixer {
        return .{
            .allocator = allocator,
            .frame_size = config.frame_size_samples,
            .energy_threshold = config.energy_threshold,
            .default_gain = config.default_gain,
            .participants = .empty,
        };
    }

    pub fn deinit(self: *Mixer) void {
        for (self.participants.items) |p| {
            self.allocator.free(p.frame);
        }
        self.participants.deinit(self.allocator);
    }

    /// Add a participant. Returns error.AlreadyExists if id is duplicate.
    /// Default gain is 1.0.
    pub fn addParticipant(self: *Mixer, id: ParticipantId) !void {
        for (self.participants.items) |p| {
            if (p.id == id) return error.AlreadyExists;
        }
        const frame = try self.allocator.alloc(f32, self.frame_size);
        @memset(frame, 0.0);
        try self.participants.append(self.allocator, .{
            .id = id,
            .gain = self.default_gain,
            .frame = frame,
            .active = false,
        });
    }

    /// Remove a participant and free their frame buffer.
    pub fn removeParticipant(self: *Mixer, id: ParticipantId) !void {
        for (self.participants.items, 0..) |p, i| {
            if (p.id == id) {
                self.allocator.free(p.frame);
                _ = self.participants.swapRemove(i);
                return;
            }
        }
        return error.NotFound;
    }

    /// Set per-participant gain (linear amplitude multiplier, must be >= 0).
    pub fn setGain(self: *Mixer, id: ParticipantId, gain: f32) !void {
        for (self.participants.items) |*p| {
            if (p.id == id) {
                p.gain = gain;
                return;
            }
        }
        return error.NotFound;
    }

    /// Submit one frame of audio for a participant.
    /// `samples` must have exactly `frame_size` elements.
    /// The mixer copies the data; caller may reuse the slice immediately.
    /// Also updates the active-speaker flag for this participant.
    pub fn submitFrame(self: *Mixer, id: ParticipantId, samples: []const f32) !void {
        if (samples.len != self.frame_size) return error.FrameSizeMismatch;
        for (self.participants.items) |*p| {
            if (p.id == id) {
                // Apply gain and store.
                for (samples, 0..) |s, i| {
                    const mixed = s * p.gain;
                    p.frame[i] = if (std.math.isFinite(mixed)) mixed else 0.0;
                }
                p.active = frameEnergy(p.frame) >= self.energy_threshold;
                return;
            }
        }
        return error.NotFound;
    }

    /// Return the N-1 mix for participant `id`: sum of all other participants'
    /// most-recently submitted (gain-scaled) frames, passed through the soft
    /// limiter. Result is written into `out`, which must be `frame_size` long.
    pub fn mixFor(self: *const Mixer, id: ParticipantId, out: []f32) !void {
        if (out.len != self.frame_size) return error.FrameSizeMismatch;
        var found = false;
        @memset(out, 0.0);
        for (self.participants.items) |p| {
            if (p.id == id) {
                found = true;
                continue; // exclude self
            }
            for (p.frame, 0..) |s, i| {
                out[i] += s;
            }
        }
        if (!found) return error.NotFound;
        // Apply soft limiter.
        for (out) |*s| s.* = softLimit(s.*);
    }

    /// Return the full mix of all participants, soft-limited. Result is written
    /// into `out`, which must be `frame_size` long.
    pub fn mixAll(self: *const Mixer, out: []f32) !void {
        if (out.len != self.frame_size) return error.FrameSizeMismatch;
        @memset(out, 0.0);
        for (self.participants.items) |p| {
            for (p.frame, 0..) |s, i| {
                out[i] += s;
            }
        }
        for (out) |*s| s.* = softLimit(s.*);
    }

    /// Fill `buf` with the IDs of participants whose energy exceeds the gate.
    /// Returns the number of active speakers written.
    pub fn activeSpeakers(self: *const Mixer, buf: []ParticipantId) usize {
        var n: usize = 0;
        for (self.participants.items) |p| {
            if (p.active) {
                if (n < buf.len) {
                    buf[n] = p.id;
                    n += 1;
                }
            }
        }
        return n;
    }

    /// Return participant count.
    pub fn count(self: *const Mixer) usize {
        return self.participants.items.len;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "addParticipant and count" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    try mx.addParticipant(2);
    try std.testing.expectEqual(@as(usize, 2), mx.count());
}

test "addParticipant duplicate returns error" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    try std.testing.expectError(error.AlreadyExists, mx.addParticipant(1));
}

test "removeParticipant" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(10);
    try mx.addParticipant(20);
    try mx.removeParticipant(10);
    try std.testing.expectEqual(@as(usize, 1), mx.count());
    try std.testing.expectError(error.NotFound, mx.removeParticipant(10));
}

test "submitFrame FrameSizeMismatch" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    const bad: [3]f32 = .{ 0.1, 0.2, 0.3 };
    try std.testing.expectError(error.FrameSizeMismatch, mx.submitFrame(1, &bad));
}

test "mixFor excludes own audio and includes others" {
    // 3 participants a=1, b=2, c=3.
    // a sends 0.1, b sends 0.2, c sends 0.3 (all 4 samples identical).
    // mixFor(a) should be soft_limit(0.2+0.3) per sample.
    // mixFor(b) should be soft_limit(0.1+0.3) per sample.
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    try mx.addParticipant(2);
    try mx.addParticipant(3);

    const fa: [4]f32 = .{ 0.1, 0.1, 0.1, 0.1 };
    const fb: [4]f32 = .{ 0.2, 0.2, 0.2, 0.2 };
    const fc: [4]f32 = .{ 0.3, 0.3, 0.3, 0.3 };
    try mx.submitFrame(1, &fa);
    try mx.submitFrame(2, &fb);
    try mx.submitFrame(3, &fc);

    var out: [4]f32 = undefined;

    // mix for a: b+c = 0.5 => softLimit(0.5)
    try mx.mixFor(1, &out);
    const expected_a = softLimit(0.5);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected_a, s, 1e-6);
    }

    // mix for b: a+c = 0.4 => softLimit(0.4)
    try mx.mixFor(2, &out);
    const expected_b = softLimit(0.4);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected_b, s, 1e-6);
    }

    // mix for c: a+b = 0.3 => softLimit(0.3)
    try mx.mixFor(3, &out);
    const expected_c = softLimit(0.3);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected_c, s, 1e-6);
    }
}

test "soft limiter keeps |sample| < 1.0 under many loud streams" {
    // 20 participants each submitting a full-scale +1.0 signal.
    // Sum pre-limit = 20.0; tanh(20.0) ≈ 1.0 but strictly < 1.0.
    const alloc = std.testing.allocator;
    const N = 20;
    const FS = 8;
    var mx = Mixer.init(alloc, FS, 1e-6);
    defer mx.deinit();

    var i: u32 = 0;
    while (i < N) : (i += 1) {
        try mx.addParticipant(i);
        const loud = @as([FS]f32, @splat(1.0));
        try mx.submitFrame(i, &loud);
    }

    var out: [FS]f32 = undefined;
    try mx.mixAll(&out);
    for (out) |s| {
        try std.testing.expect(@abs(s) < 1.0);
    }

    // N-1 mix for participant 0: 19 streams of 1.0 => still < 1.0
    try mx.mixFor(0, &out);
    for (out) |s| {
        try std.testing.expect(@abs(s) < 1.0);
    }
}

test "gain is applied before mixing" {
    // participant 2 has gain 0.5; mixFor(1) should see 0.5*frame_2.
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    try mx.addParticipant(2);

    try mx.setGain(2, 0.5);

    const f1: [4]f32 = .{ 0.0, 0.0, 0.0, 0.0 };
    const f2: [4]f32 = .{ 0.8, 0.8, 0.8, 0.8 };
    try mx.submitFrame(1, &f1);
    try mx.submitFrame(2, &f2);

    var out: [4]f32 = undefined;
    try mx.mixFor(1, &out);
    // only participant 2 contributes, gain=0.5 => raw = 0.4, softLimit(0.4)
    const expected = softLimit(0.4);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected, s, 1e-6);
    }
}

test "silent participant does not change the mix" {
    // b is always silent (zero frame). Mix for a with b silent == mix without b.
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1); // a
    try mx.addParticipant(2); // b — silent
    try mx.addParticipant(3); // c

    const fa: [4]f32 = .{ 0.4, 0.4, 0.4, 0.4 };
    const fb: [4]f32 = .{ 0.0, 0.0, 0.0, 0.0 };
    const fc: [4]f32 = .{ 0.3, 0.3, 0.3, 0.3 };
    try mx.submitFrame(1, &fa);
    try mx.submitFrame(2, &fb);
    try mx.submitFrame(3, &fc);

    var out: [4]f32 = undefined;
    // mix for a = softLimit(fb + fc) = softLimit(0.0 + 0.3) = softLimit(0.3)
    try mx.mixFor(1, &out);
    const expected = softLimit(0.3);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected, s, 1e-6);
    }
}

test "active speaker gate" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 0.01); // threshold = 0.01
    defer mx.deinit();

    try mx.addParticipant(1);
    try mx.addParticipant(2);
    try mx.addParticipant(3);

    // participant 1: loud, participant 2: loud, participant 3: silent
    const loud: [4]f32 = .{ 0.5, 0.5, 0.5, 0.5 }; // energy = 0.25 > 0.01
    const silent: [4]f32 = .{ 0.0, 0.0, 0.0, 0.0 };
    try mx.submitFrame(1, &loud);
    try mx.submitFrame(2, &loud);
    try mx.submitFrame(3, &silent);

    var ids: [4]ParticipantId = undefined;
    const n = mx.activeSpeakers(&ids);
    try std.testing.expectEqual(@as(usize, 2), n);
    // Both active IDs should be 1 or 2, not 3.
    for (ids[0..n]) |id| {
        try std.testing.expect(id == 1 or id == 2);
    }
}

test "active speaker updates after re-submit" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 0.01);
    defer mx.deinit();

    try mx.addParticipant(7);

    const loud: [4]f32 = .{ 0.5, 0.5, 0.5, 0.5 };
    const silent: [4]f32 = .{ 0.0, 0.0, 0.0, 0.0 };

    try mx.submitFrame(7, &loud);
    var ids: [4]ParticipantId = undefined;
    var n = mx.activeSpeakers(&ids);
    try std.testing.expectEqual(@as(usize, 1), n);

    try mx.submitFrame(7, &silent);
    n = mx.activeSpeakers(&ids);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "mixAll includes all participants" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 2, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(1);
    try mx.addParticipant(2);

    const f1: [2]f32 = .{ 0.2, 0.2 };
    const f2: [2]f32 = .{ 0.3, 0.3 };
    try mx.submitFrame(1, &f1);
    try mx.submitFrame(2, &f2);

    var out: [2]f32 = undefined;
    try mx.mixAll(&out);
    const expected = softLimit(0.5);
    for (out) |s| {
        try std.testing.expectApproxEqAbs(expected, s, 1e-6);
    }
}

test "mixFor with only one participant returns silence" {
    // Only one participant: their N-1 mix is always zero (no others).
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();

    try mx.addParticipant(42);
    const f: [4]f32 = .{ 0.9, 0.8, 0.7, 0.6 };
    try mx.submitFrame(42, &f);

    var out: [4]f32 = undefined;
    try mx.mixFor(42, &out);
    // softLimit(0.0) = 0.0
    for (out) |s| {
        try std.testing.expectApproxEqAbs(0.0, s, 1e-6);
    }
}

test "setGain unknown participant returns error" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();
    try std.testing.expectError(error.NotFound, mx.setGain(99, 0.5));
}

test "mixFor and mixAll FrameSizeMismatch on wrong output buffer" {
    const alloc = std.testing.allocator;
    var mx = Mixer.init(alloc, 4, 1e-6);
    defer mx.deinit();
    try mx.addParticipant(1);

    var short: [2]f32 = undefined;
    try std.testing.expectError(error.FrameSizeMismatch, mx.mixFor(1, &short));
    try std.testing.expectError(error.FrameSizeMismatch, mx.mixAll(&short));
}

test "deterministic: same input always produces same output" {
    const alloc = std.testing.allocator;
    var mx1 = Mixer.init(alloc, 4, 1e-6);
    defer mx1.deinit();
    var mx2 = Mixer.init(alloc, 4, 1e-6);
    defer mx2.deinit();

    const ids = [_]u32{ 1, 2, 3 };
    const frames = [_][4]f32{
        .{ 0.1, 0.2, 0.3, 0.4 },
        .{ 0.5, 0.6, 0.7, 0.8 },
        .{ 0.9, 0.8, 0.7, 0.6 },
    };

    for (ids, 0..) |id, j| {
        try mx1.addParticipant(id);
        try mx1.submitFrame(id, &frames[j]);
        try mx2.addParticipant(id);
        try mx2.submitFrame(id, &frames[j]);
    }

    var o1: [4]f32 = undefined;
    var o2: [4]f32 = undefined;
    try mx1.mixFor(1, &o1);
    try mx2.mixFor(1, &o2);
    for (o1, 0..) |s, i| {
        try std.testing.expectApproxEqAbs(s, o2[i], 1e-7);
    }
}

test "applyToml defaults match historical mixer values" {
    var doc = try toml.parse(std.testing.allocator, "");
    defer doc.deinit(std.testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try std.testing.expectEqual(default_energy_threshold, cfg.energy_threshold);
    try std.testing.expectEqual(default_frame_size_samples, cfg.frame_size_samples);
    try std.testing.expectEqual(default_gain, cfg.default_gain);
}

test "applyToml overlays media.audio keys and drives mixer init" {
    const src =
        \\[media.audio]
        \\energy_threshold = 0.01
        \\frame_size_samples = 4
        \\default_gain = 0.5
    ;
    var doc = try toml.parse(std.testing.allocator, src);
    defer doc.deinit(std.testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try std.testing.expectApproxEqAbs(@as(f32, 0.01), cfg.energy_threshold, 1e-9);
    try std.testing.expectEqual(@as(usize, 4), cfg.frame_size_samples);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), cfg.default_gain, 1e-9);

    var mx = Mixer.initConfig(std.testing.allocator, cfg);
    defer mx.deinit();
    try std.testing.expectEqual(@as(usize, 4), mx.frame_size);
    try mx.addParticipant(1);
    // New participant joins at the configured default gain (0.5): a 0.8 frame
    // mixes down to 0.4 before the soft limiter.
    const f: [4]f32 = .{ 0.8, 0.8, 0.8, 0.8 };
    try mx.addParticipant(2);
    try mx.submitFrame(2, &f);
    var out: [4]f32 = undefined;
    try mx.mixFor(1, &out);
    const expected = softLimit(0.4);
    for (out) |s| try std.testing.expectApproxEqAbs(expected, s, 1e-6);
}
