// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Isolated Linux NOP workload; tools/bench_sqpoll.py builds and measures it.
//! READY/GO and RESULT/ACK keep all worker tasks alive across CPU snapshots.
const std = @import("std");
const linux = std.os.linux;
const ringlane = @import("onyx").daemon.ringlane;

const Context = struct {
    ring: *ringlane.Ring,
    index: u64,
    burst: bool,
    batch: u32,
    duration_ms: u64,
    start: *std.atomic.Value(bool),
    release: *std.atomic.Value(bool),
    done: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,
    completed: u64 = 0,
    latency_ns: [256]u64 = undefined,
    samples: usize = 0,
};

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("bench_sqpoll: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn now() !u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return error.ClockFailed;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleep(ns: u64) void {
    var ts = linux.timespec{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    while (linux.errno(linux.nanosleep(&ts, &ts)) == .INTR) {}
}

fn write(bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(1, bytes[sent..].ptr, bytes.len - sent);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return error.OutputClosed else {
                sent += rc;
            },
            .INTR => continue,
            else => return error.OutputFailed,
        }
    }
}

fn emit(comptime fmt: []const u8, args: anytype) !void {
    var buf: [1024]u8 = undefined;
    try write(try std.fmt.bufPrint(&buf, fmt, args));
}

fn command(expected: []const u8) !void {
    var buf: [8]u8 = undefined;
    var used: usize = 0;
    while (used < buf.len) {
        const rc = linux.read(0, buf[used..].ptr, 1);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return error.InputClosed,
            .INTR => continue,
            else => return error.InputFailed,
        }
        used += 1;
        if (buf[used - 1] == '\n') {
            if (!std.mem.eql(u8, buf[0 .. used - 1], expected)) return error.BadCommand;
            return;
        }
    }
    return error.BadCommand;
}

fn batch(ring: *ringlane.Ring, first: u64, count: u32) !void {
    var seen: [256]bool = @splat(false);
    for (0..count) |offset| _ = try ring.inner.nop(first + offset);
    _ = try ring.submitAndWait(1);
    var received: u32 = 0;
    var cqes: [256]linux.io_uring_cqe = undefined;
    while (received < count) {
        const n = try ring.inner.copy_cqes(&cqes, 0);
        if (n == 0) {
            _ = try ring.submitAndWait(1);
            continue;
        }
        for (cqes[0..n]) |cqe| {
            if (cqe.res != 0 or cqe.flags != 0) return error.BadCompletion;
            if (cqe.user_data < first or cqe.user_data - first >= count) return error.UnexpectedCompletion;
            const index: usize = @intCast(cqe.user_data - first);
            if (seen[index]) return error.DuplicateCompletion;
            seen[index] = true;
            received += 1;
        }
    }
    if (ring.inner.cq.overflow.* != 0) return error.CompletionOverflow;
    if (try ring.inner.copy_cqes(&cqes, 0) != 0) return error.ExtraCompletion;
}

fn workload(ctx: *Context) !void {
    const begin = try now();
    const deadline = begin + ctx.duration_ms * std.time.ns_per_ms;
    var next_burst = begin;
    var sequence: u64 = (ctx.index + 1) << 60;
    var rounds: u64 = 0;
    while (if (ctx.burst) rounds < ctx.duration_ms / 250 else try now() < deadline) {
        if (ctx.burst) {
            const stamp = try now();
            if (stamp < next_burst) {
                sleep(next_burst - stamp);
                continue;
            }
        }
        const submitted = try now();
        try batch(ctx.ring, sequence, ctx.batch);
        const finished = try now();
        if (ctx.burst) {
            if (ctx.samples == ctx.latency_ns.len) return error.TooManySamples;
            ctx.latency_ns[ctx.samples] = finished - submitted;
            ctx.samples += 1;
            next_burst += 250 * std.time.ns_per_ms;
        }
        sequence += ctx.batch;
        ctx.completed += ctx.batch;
        rounds += 1;
    }
    // Include the idle tail of the last burst in the CPU accounting window.
    if (ctx.burst) {
        const finished = try now();
        if (finished < deadline) sleep(deadline - finished);
    }
}

fn thread(ctx: *Context) void {
    while (!ctx.start.load(.acquire)) sleep(std.time.ns_per_ms);
    workload(ctx) catch |err| {
        ctx.err = err;
    };
    ctx.done.store(true, .release);
    // Preserve task accounting until the external sampler takes its end sample.
    while (!ctx.release.load(.acquire)) sleep(std.time.ns_per_ms);
}

fn run(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const idle = try std.fmt.parseInt(u32, args.next() orelse return error.BadArguments, 10);
    const rings_n = try std.fmt.parseInt(usize, args.next() orelse return error.BadArguments, 10);
    const scenario = args.next() orelse return error.BadArguments;
    const burst = std.mem.eql(u8, scenario, "burst");
    if (!burst and !std.mem.eql(u8, scenario, "continuous")) return error.BadArguments;
    const batch_n = try std.fmt.parseInt(u32, args.next() orelse return error.BadArguments, 10);
    const duration = try std.fmt.parseInt(u64, args.next() orelse return error.BadArguments, 10);
    if ((rings_n != 1 and rings_n != 4) or (batch_n != 32 and batch_n != 256) or duration < 250 or duration > 60_000 or duration % 250 != 0 or idle > 60_000) return error.BadArguments;
    if (args.next() != null) return error.BadArguments;

    var rings: [4]ringlane.Ring = undefined;
    var opened: usize = 0;
    defer for (rings[0..opened]) |*ring| ring.deinit();
    while (opened < rings_n) : (opened += 1) {
        rings[opened] = ringlane.Ring.init(512, .{ .sqpoll = idle != 0, .sqpoll_idle_ms = if (idle == 0) 1000 else idle }) catch |err| {
            if (ringlane.isUnsupportedInitError(err)) {
                try emit("{{\"status\":\"unsupported\",\"reason\":\"{s}\"}}\n", .{@errorName(err)});
                std.process.exit(77);
            }
            return err;
        };
    }
    var wake_observed: usize = 0;
    if (idle != 0) {
        sleep((@as(u64, idle) + 100) * std.time.ns_per_ms);
        for (rings[0..opened]) |*ring| {
            const limit = try now() + 2 * std.time.ns_per_s;
            while ((@atomicLoad(u32, ring.inner.sq.flags, .acquire) & linux.IORING_SQ_NEED_WAKEUP) == 0) {
                if (try now() >= limit) return error.WakeupNotObserved;
                sleep(std.time.ns_per_ms);
            }
            wake_observed += 1;
            try batch(ring, 1, 1);
        }
    }

    var start: std.atomic.Value(bool) = .init(false);
    var release: std.atomic.Value(bool) = .init(false);
    var contexts: [4]Context = undefined;
    var threads: [4]std.Thread = undefined;
    var spawned: usize = 0;
    defer {
        start.store(true, .release);
        release.store(true, .release);
        for (threads[0..spawned]) |handle| handle.join();
    }
    for (rings[0..opened], 0..) |*ring, index| {
        contexts[index] = .{ .ring = ring, .index = index, .burst = burst, .batch = batch_n, .duration_ms = duration, .start = &start, .release = &release };
        threads[index] = try std.Thread.spawn(.{}, thread, .{&contexts[index]});
        spawned += 1;
    }
    try emit("{{\"status\":\"ready\",\"pid\":{d},\"wake_observed\":{d},\"rings\":{d}}}\n", .{ linux.getpid(), wake_observed, rings_n });
    try command("GO");
    const begin = try now();
    start.store(true, .release);
    for (contexts[0..opened]) |*ctx| while (!ctx.done.load(.acquire)) sleep(std.time.ns_per_ms);
    const elapsed = try now() - begin;
    var completed: u64 = 0;
    var failure: ?anyerror = null;
    for (contexts[0..opened]) |ctx| {
        completed += ctx.completed;
        if (ctx.err) |err| failure = err;
    }
    try emit("{{\"status\":\"{s}\",\"reason\":\"{s}\",\"completed\":{d},\"elapsed_ns\":{d},\"latency_ns\":[", .{ if (failure == null) "ok" else "failed", if (failure) |err| @errorName(err) else "", completed, elapsed });
    var first = true;
    for (contexts[0..opened]) |ctx| {
        for (ctx.latency_ns[0..ctx.samples]) |sample| {
            if (!first) try write(",");
            first = false;
            try emit("{d}", .{sample});
        }
    }
    try write("]}\n");
    try command("ACK");
    if (failure != null) return error.MeasurementFailed;
}
