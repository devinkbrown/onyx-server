//! Simple verbose test runner for long Onyx Server suites.
//!
//! Zig's build-system test runner uses the std.zig.Server protocol and usually
//! prints only after the test artifact exits. That is great for compact logs but
//! poor for multi-minute daemon suites. This runner is intentionally simple:
//! print every test name before it runs, then report OK/SKIP/FAIL immediately.

const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

const slowest_limit = 10;

const SlowTest = struct {
    name: []const u8 = "",
    ns: u64 = 0,
};

var log_err_count: usize = 0;
var fba_buffer: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = .init(&fba_buffer);

pub const std_options: std.Options = .{
    .logFn = log,
};

pub fn main(init: std.process.Init.Minimal) void {
    @disableInstrumentation();

    const args = init.args.toSlice(fba.allocator()) catch |err| {
        std.debug.panic("unable to parse command line args: {t}", .{err});
    };
    var filters: [64][]const u8 = undefined;
    var filter_count: usize = 0;
    var list_only = false;
    var shard_count: usize = 1;
    var shard_index: usize = 0;
    var group: Group = .all;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch
                std.debug.panic("unable to parse --seed command line argument: {s}", .{arg});
        } else if (std.mem.startsWith(u8, arg, "--cache-dir=")) {
            // Accepted for compatibility with Zig's test invocation. This runner
            // does not drive coverage-guided fuzzing, so the cache path is unused.
        } else if (std.mem.startsWith(u8, arg, "--test-filter=")) {
            const filter = arg["--test-filter=".len..];
            if (filter.len == 0 or filter_count == filters.len) {
                std.debug.print("expected nonempty --test-filter (maximum {d} filters)\n", .{filters.len});
                std.process.exit(2);
            }
            filters[filter_count] = filter;
            filter_count += 1;
        } else if (std.mem.startsWith(u8, arg, "--test-shard-count=")) {
            shard_count = std.fmt.parseUnsigned(usize, arg["--test-shard-count=".len..], 10) catch 0;
        } else if (std.mem.startsWith(u8, arg, "--test-shard-index=")) {
            shard_index = std.fmt.parseUnsigned(usize, arg["--test-shard-index=".len..], 10) catch std.math.maxInt(usize);
        } else if (std.mem.startsWith(u8, arg, "--test-group=")) {
            group = std.meta.stringToEnum(Group, arg["--test-group=".len..]) orelse {
                std.debug.print("invalid test group\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, arg, "--list-tests")) {
            list_only = true;
        } else {
            std.debug.panic("unrecognized verbose-test-runner argument: {s}", .{arg});
        }
    }

    if (shard_count == 0 or shard_index >= shard_count) {
        std.debug.print("invalid test shard: index must be smaller than positive count\n", .{});
        std.process.exit(2);
    }
    const tests = builtin.test_functions;
    const selected_filters = filters[0..filter_count];
    var matched_count: usize = 0;
    for (tests) |test_fn| {
        if (selected(test_fn.name, selected_filters, group, shard_index, shard_count)) matched_count += 1;
    }
    std.debug.print("test selection: {d} discovered; {d} matched; {d} excluded\n", .{
        tests.len, matched_count, tests.len - matched_count,
    });
    if (matched_count == 0) {
        std.debug.print("no tests matched; refusing empty success\n", .{});
        std.process.exit(2);
    }
    if (list_only) {
        for (tests) |test_fn| {
            if (selected(test_fn.name, selected_filters, group, shard_index, shard_count)) std.debug.print("{s}\n", .{test_fn.name});
        }
        std.debug.print("listed {d} tests; executed 0\n", .{matched_count});
        return;
    }
    var executed_count: usize = 0;
    var ok_count: usize = 0;
    var skip_count: usize = 0;
    var fail_count: usize = 0;
    var leak_count: usize = 0;
    var total_ns: u64 = 0;
    var slowest: [slowest_limit]SlowTest = @splat(.{});

    for (tests) |test_fn| {
        if (!selected(test_fn.name, selected_filters, group, shard_index, shard_count)) continue;
        executed_count += 1;
        testing.allocator_instance = .init(std.heap.page_allocator, .{
            .canary = 0xc3a701ba,
            .check_write_after_free = true,
        });
        testing.io_instance = .init(testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });
        testing.log_level = .warn;
        testing.environ = init.environ;

        std.debug.print("[{d}/{d}] {s} ... ", .{ executed_count, matched_count, test_fn.name });
        const started_ns = monotonicNanos();
        if (test_fn.func()) |_| {
            const elapsed_ns = monotonicNanos() - started_ns;
            total_ns += elapsed_ns;
            recordSlow(&slowest, test_fn.name, elapsed_ns);
            ok_count += 1;
            std.debug.print("OK ({f})\n", .{fmtDuration(elapsed_ns)});
        } else |err| switch (err) {
            error.SkipZigTest => {
                const elapsed_ns = monotonicNanos() - started_ns;
                total_ns += elapsed_ns;
                recordSlow(&slowest, test_fn.name, elapsed_ns);
                skip_count += 1;
                std.debug.print("SKIP ({f})\n", .{fmtDuration(elapsed_ns)});
            },
            else => {
                const elapsed_ns = monotonicNanos() - started_ns;
                total_ns += elapsed_ns;
                recordSlow(&slowest, test_fn.name, elapsed_ns);
                fail_count += 1;
                std.debug.print("FAIL ({t}, {f})\n", .{ err, fmtDuration(elapsed_ns) });
                if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            },
        }

        testing.io_instance.deinit();
        if (testing.allocator_instance.deinit() != 0) leak_count += 1;
    }

    std.debug.print(
        "verbose test summary: {d} passed; {d} skipped; {d} failed; {d} leaked; {d} log errors; elapsed {f}\n",
        .{ ok_count, skip_count, fail_count, leak_count, log_err_count, fmtDuration(total_ns) },
    );
    std.debug.print("executed {d} tests; excluded {d} tests\n", .{ executed_count, tests.len - matched_count });
    if (executed_count != 0) {
        std.debug.print("slowest tests:\n", .{});
        for (slowest) |entry| {
            if (entry.ns <= 0) break;
            std.debug.print("  {f}  {s}\n", .{ fmtDuration(entry.ns), entry.name });
        }
    }

    if (fail_count != 0 or leak_count != 0 or log_err_count != 0) std.process.exit(1);
}

const Group = enum { all, parallel, serial };

// Only source-audited arithmetic/hash primitives can share the runtime lane.
// Daemon, transport, filesystem and unknown tests retain their original order.
fn parallelSafe(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "crypto.") and
        !std.mem.startsWith(u8, name, "crypto.tls.test.") and
        !std.mem.startsWith(u8, name, "crypto.tls_server.test.");
}

fn selected(name: []const u8, filters: []const []const u8, group: Group, shard_index: usize, shard_count: usize) bool {
    if (!matches(name, filters)) return false;
    if (group != .all and parallelSafe(name) != (group == .parallel)) return false;
    return std.hash.Wyhash.hash(0, name) % shard_count == shard_index;
}

// Multiple runtime filters form a union, exactly like Zig compile filters.
// Anonymous import anchors do not bypass explicit runtime selection.
fn matches(name: []const u8, filters: []const []const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |filter| {
        if (std.mem.indexOf(u8, name, filter) != null) return true;
    }
    return false;
}

fn recordSlow(slowest: *[slowest_limit]SlowTest, name: []const u8, ns: u64) void {
    if (ns <= slowest[slowest.len - 1].ns) return;

    var pos: usize = 0;
    while (pos < slowest.len and ns <= slowest[pos].ns) : (pos += 1) {}

    var i: usize = slowest.len - 1;
    while (i > pos) : (i -= 1) {
        slowest[i] = slowest[i - 1];
    }
    slowest[pos] = .{ .name = name, .ns = ns };
}

fn monotonicNanos() u64 {
    switch (builtin.os.tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            var freq: i64 = 0;
            var cnt: i64 = 0;
            _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
            _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&cnt);
            if (freq == 0) return 0;
            return @intCast(@divTrunc(@as(i128, cnt) * 1_000_000_000, @as(i128, freq)));
        },
        else => {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn nsFrom(sec: i64, nsec: i64) u64 {
    return @as(u64, @intCast(sec)) * 1_000_000_000 + @as(u64, @intCast(nsec));
}

fn fmtDuration(ns: u64) DurationFormat {
    return .{ .ns = ns };
}

const DurationFormat = struct {
    ns: u64,

    pub fn format(self: DurationFormat, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const ns_per_us: u64 = std.time.ns_per_us;
        const ns_per_ms: u64 = std.time.ns_per_ms;
        const ns_per_s: u64 = std.time.ns_per_s;
        if (self.ns < ns_per_ms) {
            try writer.print("{d}us", .{@divTrunc(self.ns + ns_per_us - 1, ns_per_us)});
        } else if (self.ns < ns_per_s) {
            try writer.print("{d}ms", .{@divTrunc(self.ns + ns_per_ms - 1, ns_per_ms)});
        } else {
            try writer.print("{d}.{d:0>3}s", .{
                @divTrunc(self.ns, ns_per_s),
                @divTrunc(@mod(self.ns, ns_per_s), ns_per_ms),
            });
        }
    }
};

fn log(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@backingInt(message_level) <= @backingInt(std.log.Level.err)) {
        log_err_count += 1;
    }
    std.debug.print(
        "{s}: ({s}): " ++ format ++ "\n",
        .{ @tagName(message_level), @tagName(scope) } ++ args,
    );
}

pub fn fuzz(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), *std.testing.Smith) anyerror!void,
    options: testing.FuzzInputOptions,
) anyerror!void {
    @disableInstrumentation();
    if (builtin.fuzz) @panic("verbose_test_runner does not drive coverage-guided fuzzing; use `zig build fuzz --fuzz`");

    for (options.corpus) |input| {
        var smith: testing.Smith = .{ .in = input };
        try testOne(context, &smith);
    }

    var smith: testing.Smith = .{ .in = "" };
    try testOne(context, &smith);
}
