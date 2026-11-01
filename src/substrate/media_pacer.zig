// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free media send pacer.
//!
//! Callers supply a monotonic microsecond clock. The pacer never reads time
//! itself and keeps all accounting in integer byte budgets.

const std = @import("std");

const us_per_sec: u128 = 1_000_000;

fn ceilDivU128(n: u128, d: u128) u128 {
    std.debug.assert(d > 0);
    if (n == 0) return 0;
    return (n - 1) / d + 1;
}

pub const Pacer = struct {
    target_bps: u64,
    budget_bytes: i64,
    last_us: i64,
    max_burst_bytes: u32,

    pub fn init(target_bps: u64, max_burst_bytes: u32, now_us: i64) Pacer {
        return .{
            .target_bps = target_bps,
            .budget_bytes = max_burst_bytes,
            .last_us = now_us,
            .max_burst_bytes = max_burst_bytes,
        };
    }

    pub fn setTarget(self: *Pacer, bps: u64) void {
        self.target_bps = bps;
    }

    fn byteRate(self: Pacer) u64 {
        return self.target_bps / 8;
    }

    const Refilled = struct {
        budget_bytes: i64,
        last_us: i64,
    };

    fn refilled(self: Pacer, now_us: i64) Refilled {
        if (now_us <= self.last_us) {
            return .{ .budget_bytes = self.budget_bytes, .last_us = self.last_us };
        }

        const elapsed_us: u64 = @intCast(now_us - self.last_us);
        const bytes_per_sec = self.byteRate();
        if (bytes_per_sec == 0) {
            return .{ .budget_bytes = self.budget_bytes, .last_us = self.last_us };
        }

        const added_u128 = (@as(u128, bytes_per_sec) * @as(u128, elapsed_us)) / us_per_sec;
        const added: i128 = @intCast(added_u128);
        const cap: i128 = @intCast(self.max_burst_bytes);
        const next = @as(i128, self.budget_bytes) + added;

        if (next >= cap) {
            return .{ .budget_bytes = @intCast(cap), .last_us = now_us };
        }

        const used_us = (added_u128 * us_per_sec) / @as(u128, bytes_per_sec);
        return .{
            .budget_bytes = @intCast(next),
            .last_us = self.last_us + @as(i64, @intCast(used_us)),
        };
    }

    fn refill(self: *Pacer, now_us: i64) void {
        const next = self.refilled(now_us);
        self.budget_bytes = next.budget_bytes;
        self.last_us = next.last_us;
    }

    /// Refill the bucket up to now and return whether a packet of `size` bytes
    /// may be sent now; if yes, debit it.
    pub fn tryConsume(self: *Pacer, size: u32, now_us: i64) bool {
        self.refill(now_us);
        if (size == 0) return true;
        if (self.budget_bytes <= 0) return false;

        self.budget_bytes -= @intCast(size);
        return true;
    }

    /// Microseconds until `size` bytes could be sent (0 if now).
    pub fn delayUntilUs(self: *const Pacer, size: u32, now_us: i64) i64 {
        if (size == 0) return 0;

        const budget = self.refilled(now_us).budget_bytes;
        if (budget > 0) return 0;

        const bytes_per_sec = self.byteRate();
        if (bytes_per_sec == 0) return std.math.maxInt(i64);

        const deficit: u128 = @intCast(1 - budget);
        const wait_us = ceilDivU128(deficit * us_per_sec, bytes_per_sec);
        if (wait_us > std.math.maxInt(i64)) return std.math.maxInt(i64);
        return @intCast(wait_us);
    }
};

/// Priority-aware media pacer: audio > control > video.
///
/// Each class owns a separate `Pacer` bucket at its own rate, so a video
/// burst can only spend video tokens and can never debit audio or control.
/// Video is further bounded on both sides: accrual caps at the video burst
/// bucket (as in `Pacer.refill`), and a video grant that would push the
/// video budget below `-max_video_debt_bytes` is denied without debiting,
/// so `videoDebtBytes()` never exceeds that named cap.
///
/// `nextClass` picks the highest-priority pending class that is grantable
/// now. Because buckets are separate and queued video is never picked
/// ahead of grantable audio or control, queued video adds no delay to
/// control at all — stronger than the one-audio-quantum bound
/// (`audio_quantum_bytes` records the caller's audio quantum) — and a
/// video grant already issued cannot delay control either, since it does
/// not touch the control bucket.
pub const PriorityPacer = struct {
    audio: Pacer,
    control: Pacer,
    video: Pacer,
    max_video_debt_bytes: u32,
    audio_quantum_bytes: u32,

    pub const Class = enum { audio, control, video };

    /// Pending packet size per class; zero means nothing queued.
    pub const Pending = struct {
        audio: u32 = 0,
        control: u32 = 0,
        video: u32 = 0,
    };

    pub fn init(
        audio_bps: u64,
        control_bps: u64,
        video_bps: u64,
        audio_burst_bytes: u32,
        control_burst_bytes: u32,
        video_burst_bytes: u32,
        max_video_debt_bytes: u32,
        audio_quantum_bytes: u32,
        now_us: i64,
    ) PriorityPacer {
        return .{
            .audio = Pacer.init(audio_bps, audio_burst_bytes, now_us),
            .control = Pacer.init(control_bps, control_burst_bytes, now_us),
            .video = Pacer.init(video_bps, video_burst_bytes, now_us),
            .max_video_debt_bytes = max_video_debt_bytes,
            .audio_quantum_bytes = audio_quantum_bytes,
        };
    }

    fn pacerFor(self: *PriorityPacer, class: Class) *Pacer {
        return switch (class) {
            .audio => &self.audio,
            .control => &self.control,
            .video => &self.video,
        };
    }

    fn pacerForConst(self: *const PriorityPacer, class: Class) *const Pacer {
        return switch (class) {
            .audio => &self.audio,
            .control => &self.control,
            .video => &self.video,
        };
    }

    /// Like `Pacer.tryConsume`, except video grants are denied without
    /// debiting when they would exceed `max_video_debt_bytes` of debt.
    pub fn tryConsume(self: *PriorityPacer, class: Class, size: u32, now_us: i64) bool {
        if (class != .video) return self.pacerFor(class).tryConsume(size, now_us);
        if (size == 0) return true;

        self.video.refill(now_us);
        if (self.video.budget_bytes <= 0) return false;
        const next_budget = @as(i128, self.video.budget_bytes) - @as(i128, size);
        if (next_budget < -@as(i128, self.max_video_debt_bytes)) return false;
        self.video.budget_bytes = @intCast(next_budget);
        return true;
    }

    pub fn delayUntilUs(self: *const PriorityPacer, class: Class, size: u32, now_us: i64) i64 {
        if (class != .video) return self.pacerForConst(class).delayUntilUs(size, now_us);
        if (size == 0) return 0;

        const budget = self.video.refilled(now_us).budget_bytes;
        // Smallest budget that may grant: positive (as in `Pacer`) and
        // within the debt cap after debiting `size`.
        const needed: i128 = @max(1, @as(i128, size) - @as(i128, self.max_video_debt_bytes));
        if (@as(i128, budget) >= needed) return 0;

        const bytes_per_sec = self.video.byteRate();
        if (bytes_per_sec == 0) return std.math.maxInt(i64);
        const deficit: u128 = @intCast(needed - @as(i128, budget));
        const wait_us = ceilDivU128(deficit * us_per_sec, bytes_per_sec);
        if (wait_us > std.math.maxInt(i64)) return std.math.maxInt(i64);
        return @intCast(wait_us);
    }

    /// Highest-priority pending class grantable now, or null if none is.
    pub fn nextClass(self: *const PriorityPacer, pending: Pending, now_us: i64) ?Class {
        if (pending.audio != 0 and self.delayUntilUs(.audio, pending.audio, now_us) == 0) return .audio;
        if (pending.control != 0 and self.delayUntilUs(.control, pending.control, now_us) == 0) return .control;
        if (pending.video != 0 and self.delayUntilUs(.video, pending.video, now_us) == 0) return .video;
        return null;
    }

    pub fn videoDebtBytes(self: *const PriorityPacer) u64 {
        if (self.video.budget_bytes >= 0) return 0;
        return @intCast(-self.video.budget_bytes);
    }
};

const testing = std.testing;

test "media pacer: initial packet passes then immediate second packet is paced" {
    var pacer = Pacer.init(1_000_000, 600, 0);

    try testing.expect(pacer.tryConsume(1200, 0));
    try testing.expectEqual(@as(i64, -600), pacer.budget_bytes);
    try testing.expect(!pacer.tryConsume(1200, 0));

    const delay_us = pacer.delayUntilUs(1200, 0);
    try testing.expect(delay_us > 0);
    try testing.expect(!pacer.tryConsume(1200, delay_us - 1));
    try testing.expect(pacer.tryConsume(1200, delay_us));
}

test "media pacer: sustained simulated throughput stays near target" {
    var pacer = Pacer.init(1_000_000, 1500, 0);
    var now_us: i64 = 0;
    var sent: u64 = 0;

    while (now_us < 1_000_000) {
        if (pacer.tryConsume(1000, now_us)) {
            sent += 1000;
        } else {
            const delay_us = pacer.delayUntilUs(1000, now_us);
            try testing.expect(delay_us > 0);
            now_us += delay_us;
        }
    }

    const target_bytes_per_sec = 1_000_000 / 8;
    try testing.expect(sent >= target_bytes_per_sec);
    try testing.expect(sent <= target_bytes_per_sec + pacer.max_burst_bytes + 1000);
}

test "media pacer: setTarget changes recovery rate" {
    var pacer = Pacer.init(1_000_000, 600, 0);
    try testing.expect(pacer.tryConsume(1200, 0));

    const one_mbps_delay = pacer.delayUntilUs(1200, 0);
    pacer.setTarget(2_000_000);
    const two_mbps_delay = pacer.delayUntilUs(1200, 0);

    try testing.expect(two_mbps_delay > 0);
    try testing.expect(two_mbps_delay < one_mbps_delay);
    try testing.expect(!pacer.tryConsume(1200, two_mbps_delay - 1));
    try testing.expect(pacer.tryConsume(1200, two_mbps_delay));
}

test "media pacer priority: audio keeps its rate under sustained video overload" {
    var pp = PriorityPacer.init(800_000, 800_000, 8_000_000, 1_000, 1_000, 1_500, 1_500, 200, 0);
    var now_us: i64 = 0;
    var audio_sent: u64 = 0;

    while (now_us < 1_000_000) {
        _ = pp.tryConsume(.video, 10_000, now_us);
        try testing.expect(pp.videoDebtBytes() <= pp.max_video_debt_bytes);
        if (pp.tryConsume(.audio, 200, now_us)) {
            audio_sent += 200;
        } else {
            const delay_us = pp.delayUntilUs(.audio, 200, now_us);
            try testing.expect(delay_us > 0);
            now_us += delay_us;
        }
    }

    const audio_target = 800_000 / 8;
    try testing.expect(audio_sent >= audio_target);
    try testing.expect(audio_sent <= audio_target + 1_000 + 200);
}

test "media pacer priority: control preempts queued video" {
    var pp = PriorityPacer.init(800_000, 800_000, 8_000_000, 1_000, 1_000, 1_500, 1_500, 200, 0);

    try testing.expectEqual(
        @as(?PriorityPacer.Class, .control),
        pp.nextClass(.{ .video = 1_200, .control = 200 }, 0),
    );
    try testing.expectEqual(
        @as(?PriorityPacer.Class, .audio),
        pp.nextClass(.{ .video = 1_200, .control = 200, .audio = 200 }, 0),
    );
    // Queued video contributes no delay to control: control is grantable now.
    try testing.expectEqual(@as(i64, 0), pp.delayUntilUs(.control, 200, 0));
    try testing.expect(pp.tryConsume(.control, 200, 0));
    try testing.expectEqual(
        @as(?PriorityPacer.Class, .video),
        pp.nextClass(.{ .video = 1_200 }, 0),
    );
    try testing.expectEqual(
        @as(?PriorityPacer.Class, null),
        pp.nextClass(.{}, 0),
    );
}

test "media pacer priority: video debt never exceeds named cap" {
    const cap: u32 = 1_000;
    var pp = PriorityPacer.init(800_000, 800_000, 8_000_000, 1_000, 1_000, 600, cap, 200, 0);

    // A grant that would push debt past the cap is denied without debiting.
    try testing.expect(!pp.tryConsume(.video, 5_000, 0));
    try testing.expectEqual(@as(u64, 0), pp.videoDebtBytes());
    try testing.expectEqual(@as(i64, 600), pp.video.budget_bytes);

    try testing.expect(pp.tryConsume(.video, 1_200, 0));
    try testing.expectEqual(@as(u64, 600), pp.videoDebtBytes());

    var now_us: i64 = 0;
    while (now_us < 1_000_000) : (now_us += 1_000) {
        _ = pp.tryConsume(.video, 10_000, now_us);
        try testing.expect(pp.videoDebtBytes() <= cap);
        // Accrual is likewise bounded by the video burst bucket.
        try testing.expect(pp.video.budget_bytes <= 600);
    }
}

test "media pacer: refill caps at max burst" {
    var pacer = Pacer.init(1_000_000, 900, 0);

    try testing.expect(pacer.tryConsume(500, 0));
    try testing.expectEqual(@as(i64, 400), pacer.budget_bytes);

    try testing.expect(pacer.tryConsume(100, 1_000_000));
    try testing.expectEqual(@as(i64, 800), pacer.budget_bytes);
}
