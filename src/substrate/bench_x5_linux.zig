// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux body of the GAP-X5 bench. Imported only from `bench_x5.zig` on Linux,
//! so a non-Linux build of that entry point does not compile `server.zig`.

const std = @import("std");
const builtin = @import("builtin");
const onyx = @import("onyx_server");

const linux = std.os.linux;
const server = onyx.daemon.server;
const client_model = onyx.daemon.client;
const msgtags = onyx.proto.msgtags;
const cap = onyx.proto.cap;
const capsule = onyx.daemon.helix.capsule;
const ConnState = server.ConnState;

const command = "zig build bench-gap-x5 -- -o docs/audit/bench-gap-x5.md";
const privmsg_line = ":nick!user@host.example PRIVMSG #channel :hello there";
const widths = [_]usize{ 1, 10, 100, 1000, 4096 };
const required_widths = 4;
const sample_count = 25;
const exit_invariant: u8 = 3;

const Row = struct {
    width: usize,
    samples: usize = 0,
    msgs: usize = 0,
    min_ns: f64 = 0,
    p50_ns: f64 = 0,
    p99_ns: f64 = 0,
    measured: bool = false,
};

const Report = struct {
    buf: [16384]u8 = undefined,
    len: usize = 0,

    fn append(self: *Report, bytes: []const u8) void {
        if (self.len + bytes.len > self.buf.len) fail("report buffer is full");
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn print(self: *Report, comptime fmt: []const u8, args: anytype) void {
        var tmp: [8192]u8 = undefined;
        const written = std.fmt.bufPrint(&tmp, fmt, args) catch fail("report format failed");
        self.append(written);
    }
};

pub fn main(init: std.process.Init) !void {
    var path_buf: [1024]u8 = undefined;
    const out_path = outputPath(init, &path_buf);
    var report = Report{};
    const bytes = measure(&report);
    std.debug.print("{s}", .{bytes});
    if (out_path) |path| {
        writeFile(path, bytes) catch |err| {
            std.debug.print("GAP-X5: could not write {s}: {s}\n", .{ path, @errorName(err) });
            std.process.exit(1);
        };
    }
}

fn measure(report: *Report) []const u8 {
    const conn_bytes = @sizeOf(ConnState);
    const slot_bytes = @sizeOf(client_model.Table(ConnState, client_model.ClientId).Slot);
    const recv_bytes = @sizeOf(@FieldType(ConnState, "recv_buf"));
    const line_bytes = @sizeOf(@FieldType(ConnState, "line_buf"));
    const send_bytes = @sizeOf(@FieldType(ConnState, "send_buf"));
    const proxy_bytes = @sizeOf(@FieldType(ConnState, "proxy_buf"));
    const deliver_bytes = @sizeOf(onyx.daemon.reactor_fabric.DeliverBuf);

    var clients_current: u16 = 0;
    var clients_min: u16 = 0;
    var clients_max: u16 = 0;
    var found_clients = false;
    for (capsule.registry) |desc| {
        if (desc.kind != .clients) continue;
        clients_current = desc.current_version;
        clients_min = desc.min_supported;
        clients_max = desc.max_supported;
        found_clients = true;
        break;
    }
    if (!found_clients) fail("clients capsule descriptor is missing");

    // A fresh connection must not hide heap behind the struct size.
    {
        const probe = ConnState.init(-1);
        if (probe.send_overflow.items.len != 0 or probe.recv_overflow.items.len != 0 or
            probe.session_list_cache.rows.items.len != 0)
            fail("fresh ConnState allocated before any fan-out");
        if (probe.tls != null or probe.ws != null or probe.reply_capture != null)
            fail("fresh ConnState is not a plaintext connection");
    }

    var rows: [widths.len]Row = undefined;
    for (widths, 0..) |width, i| {
        rows[i] = measureWidth(width, i < required_widths);
    }

    report.print(
        \\# GAP-X5 hot path
        \\
        \\Every number in the table below was produced by this command and no other:
        \\
        \\```sh
        \\{s}
        \\```
        \\
        \\Bytes per connection is `@sizeOf(ConnState)`, the object stored in the
        \\client table. The slot size adds the generation and freelist word the
        \\table reserves around that object. Fresh `ConnState.init` leaves the
        \\SendQ overflow, the RecvQ overflow, and the session-list cache empty,
        \\so those heaps contribute 0 bytes. This is not RSS per client.
        \\
        \\No shrink was applied in this run. The after column is `none`, which
        \\means unmeasured, not a second copy of the before number. The Helix
        \\clients capsule was not edited. A shrink that changes that capsule is
        \\a version bump.
        \\
        \\The fan-out row is single-threaded. It builds four cap variants once
        \\per message with `composeOutbound`, then `enqueuePlainFanout` copies
        \\the matching variant into each connection's inline SendQ. That is
        \\`appendToConn` on a plaintext connection. `send_len` is cleared after
        \\each message so the sample stays on the inline path; overflow stayed
        \\empty. Those four composes are inside each message and the elapsed
        \\time is divided by the recipient count, so the width-1 figure
        \\includes all four composes. It is not a multi-shard scaling claim,
        \\and it is not the end-to-end socket RTT from `bench-live`.
        \\
        \\## Provenance
        \\
        \\| field | value |
        \\| --- | --- |
        \\| version | `{s}` |
        \\| commit | `{s}` |
        \\| optimize | `{s}` |
        \\| zig | `{s}` |
        \\| arch/os | `{s}-{s}` |
        \\| cpus | {d} |
        \\
    , .{
        command,
        onyx.version,
        onyx.git_commit,
        @tagName(builtin.mode),
        builtin.zig_version_string,
        @tagName(builtin.cpu.arch),
        @tagName(builtin.os.tag),
        std.Thread.getCpuCount() catch 0,
    });
    appendHost(report);

    report.print(
        \\
        \\## Before any shrink
        \\
        \\| quantity | before | after shrink |
        \\| --- | ---: | --- |
        \\| bytes per connection (`ConnState`) | {d} | none |
        \\| bytes per connection (client-table slot) | {d} | none |
        \\| `recv_buf` bytes | {d} | none |
        \\| `line_buf` bytes | {d} | none |
        \\| `send_buf` bytes | {d} | none |
        \\| `proxy_buf` bytes | {d} | none |
        \\| `DeliverBuf` bytes (cross-shard pool slot, not per connection) | {d} | none |
        \\| clients capsule current / min / max | {d} / {d} / {d} | unchanged |
        \\
        \\`DeliverBuf` is named here and was not resized.
        \\
        \\## Microseconds per fan-out recipient
        \\
        \\| width | samples | msgs/sample | min us/recipient | p50 us/recipient | p99 us/recipient | p50 ns/recipient | after shrink |
        \\| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
        \\
    , .{
        conn_bytes,
        slot_bytes,
        recv_bytes,
        line_bytes,
        send_bytes,
        proxy_bytes,
        deliver_bytes,
        clients_current,
        clients_min,
        clients_max,
    });

    for (rows) |row| {
        if (!row.measured) {
            report.print("| {d} |  |  |  |  |  |  | none |\n", .{row.width});
            continue;
        }
        report.print(
            "| {d} | {d} | {d} | {d:.3} | {d:.3} | {d:.3} | {d:.1} | none |\n",
            .{
                row.width,
                row.samples,
                row.msgs,
                row.min_ns / 1000.0,
                row.p50_ns / 1000.0,
                row.p99_ns / 1000.0,
                row.p50_ns,
            },
        );
    }
    report.append(
        \\
        \\Blank cells are unmeasured, not zero. `p50 us/recipient` is the median
        \\sample's nanoseconds per recipient divided by 1000.
        \\
    );
    return report.buf[0..report.len];
}

fn measureWidth(width: usize, required: bool) Row {
    const conns = std.heap.page_allocator.alloc(ConnState, width) catch {
        if (required) fail("connection table allocation failed");
        return .{ .width = width };
    };
    defer std.heap.page_allocator.free(conns);

    for (conns) |*conn| {
        conn.* = ConnState.init(-1);
        conn.overflow_allocator = std.heap.page_allocator;
    }

    var variant_buf: [4][1024]u8 = undefined;
    var variant_len: [4]usize = @splat(0);
    const tags = outboundTags(1);
    const builds = composeVariants(&variant_buf, &variant_len, tags);
    if (builds != 4) fail("fan-out did not build exactly four cap variants");
    deliverVariants(conns, &variant_buf, &variant_len);
    verifyDelivered(conns, &variant_buf, &variant_len);
    resetSend(conns);

    const msgs = @max(@as(usize, 4), 4096 / width);
    var samples: [sample_count]u64 = undefined;
    var round: usize = 0;
    while (round < sample_count + 1) : (round += 1) {
        const t0 = monotonicNanos();
        var message: usize = 0;
        while (message < msgs) : (message += 1) {
            const built = composeVariants(&variant_buf, &variant_len, outboundTags(message + 1));
            if (built != 4) fail("timed fan-out lost a cap variant");
            deliverVariants(conns, &variant_buf, &variant_len);
            resetSend(conns);
        }
        const t1 = monotonicNanos();
        if (round != 0) samples[round - 1] = t1 - t0;
    }
    for (conns) |*conn| {
        if (conn.send_overflow.items.len != 0) fail("fan-out spilled to the SendQ heap");
        if (conn.send_len != 0) fail("fan-out left the inline SendQ dirty");
    }

    std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
    const ops = @as(f64, @floatFromInt(@as(u64, msgs) * @as(u64, width)));
    return .{
        .width = width,
        .samples = sample_count,
        .msgs = msgs,
        .min_ns = @as(f64, @floatFromInt(samples[0])) / ops,
        .p50_ns = @as(f64, @floatFromInt(samples[sample_count / 2])) / ops,
        .p99_ns = @as(f64, @floatFromInt(samples[percentileIndex(sample_count, 99)])) / ops,
        .measured = true,
    };
}

fn outboundTags(counter: usize) msgtags.OutboundTags {
    return .{
        .server_time_millis = 1_783_000_000_000,
        .account = "nick",
        .msgid = .{ .counter = counter, .rng = 0x5eed_1234_5678_9abc },
        .bot = true,
    };
}

fn variantCaps(v: usize) cap.CapSet {
    var set = cap.CapSet.empty();
    if (v >= 1) set.add(.server_time);
    if (v >= 2) set.add(.msgid);
    if (v >= 3) {
        set.add(.account_tag);
        set.add(.bot);
    }
    return set;
}

fn composeVariants(bufs: *[4][1024]u8, lens: *[4]usize, tags: msgtags.OutboundTags) usize {
    var builds: usize = 0;
    for (0..4) |v| {
        const got = msgtags.composeOutbound(
            msgtags.default_config,
            variantCaps(v),
            tags,
            privmsg_line,
            &bufs[v],
        ) catch fail("composeOutbound failed");
        lens[v] = got.len;
        builds += 1;
        std.mem.doNotOptimizeAway(got.len);
    }
    return builds;
}

fn deliverVariants(conns: []ConnState, bufs: *const [4][1024]u8, lens: *const [4]usize) void {
    for (conns, 0..) |*conn, i| {
        const v = i % 4;
        const line = bufs[v][0..lens[v]];
        server.enqueuePlainFanout(conn, line) catch fail("enqueuePlainFanout failed");
        std.mem.doNotOptimizeAway(conn.send_buf[conn.send_len - 1]);
    }
}

fn verifyDelivered(conns: []ConnState, bufs: *const [4][1024]u8, lens: *const [4]usize) void {
    const n = @min(conns.len, 4);
    for (conns[0..n], 0..) |*conn, i| {
        const v = i % 4;
        const want = bufs[v][0..lens[v]];
        if (conn.send_len != want.len) fail("fan-out send_len does not match the composed line");
        if (!std.mem.eql(u8, conn.send_buf[0..conn.send_len], want))
            fail("fan-out bytes do not match the composed line");
        if (conn.send_overflow.items.len != 0) fail("self-check spilled to the SendQ heap");
    }
}

fn resetSend(conns: []ConnState) void {
    for (conns) |*conn| {
        conn.send_len = 0;
        conn.send_offset = 0;
    }
}

fn appendHost(report: *Report) void {
    var host_buf: [256]u8 = undefined;
    var kern_buf: [256]u8 = undefined;
    var load_buf: [128]u8 = undefined;
    var cpu_buf: [4096]u8 = undefined;
    const host = readFile("/proc/sys/kernel/hostname", &host_buf);
    const kernel = readFile("/proc/sys/kernel/osrelease", &kern_buf);
    const load = readFile("/proc/loadavg", &load_buf);
    const cpu_raw = readFile("/proc/cpuinfo", &cpu_buf);
    const cpu = cpuModel(cpu_raw);

    report.append("| captured | ");
    appendUtc(report);
    report.print(" |\n| host | `{s}` |\n| kernel | Linux {s} |\n| cpu | {s} |\n| load avg | {s} |\n", .{
        trimLine(host),
        trimLine(kernel),
        cpu,
        firstField(load),
    });
}

fn appendUtc(report: *Report) void {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.REALTIME, &ts);
    if (ts.sec < 0) {
        report.append("unknown");
        return;
    }
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(ts.sec) };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch.getDaySeconds();
    const secs = day_secs.secs % 60;
    report.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        secs,
    });
}

fn outputPath(init: std.process.Init, buf: []u8) ?[]const u8 {
    var it = init.minimal.args.iterate();
    _ = it.next(); // argv0
    while (it.next()) |arg| {
        const path = if (std.mem.eql(u8, arg, "-o"))
            it.next() orelse fail("-o needs a path")
        else if (std.mem.startsWith(u8, arg, "-o="))
            arg["-o=".len..]
        else
            continue;
        if (path.len == 0 or path.len > buf.len) fail("-o path is empty or too long");
        @memcpy(buf[0..path.len], path);
        return buf[0..path.len];
    }
    return null;
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    var zpath: [1024]u8 = undefined;
    const path_z = std.fmt.bufPrintSentinel(&zpath, "{s}", .{path}, 0) catch return error.NameTooLong;
    const rc = linux.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o644);
    if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const n = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (linux.errno(n) != .SUCCESS) return error.Unexpected;
        const wrote: usize = @intCast(n);
        if (wrote == 0) return error.Unexpected;
        off += wrote;
    }
}

fn readFile(path: [*:0]const u8, buf: []u8) []const u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return "";
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    const n = linux.read(fd, buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return "";
    return buf[0..@intCast(n)];
}

fn trimLine(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t\r\n");
}

fn firstField(bytes: []const u8) []const u8 {
    const trimmed = trimLine(bytes);
    var end: usize = 0;
    var fields: usize = 0;
    for (trimmed, 0..) |ch, i| {
        if (ch != ' ') continue;
        fields += 1;
        if (fields == 3) {
            end = i;
            break;
        }
    }
    if (end == 0) return if (trimmed.len == 0) "unknown" else trimmed;
    return trimmed[0..end];
}

fn cpuModel(bytes: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "model name")) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len != 0) return name;
    }
    return "unknown";
}

fn monotonicNanos() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn percentileIndex(len: usize, p: usize) usize {
    if (len == 0) return 0;
    const idx = (len * p) / 100;
    return if (idx >= len) len - 1 else idx;
}

fn fail(comptime what: []const u8) noreturn {
    std.debug.print("\n[bench-gap-x5] INVARIANT VIOLATED: {s}\n", .{what});
    std.process.exit(exit_invariant);
}
