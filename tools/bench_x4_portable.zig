// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GAP-X4 measurement for a portable onyx-server. Same client recipe as
//! tools/bench_live.py: 4 clients, numeric 001, numeric 366, 16 PRIVMSG
//! samples, RSS from `ps`. SQPOLL and TLS are reported as unmeasured cells.
//! This reactor has no io_uring SQPOLL and no TLS listener.

const std = @import("std");

const clients_n: usize = 4;
const samples_n: usize = 16;
const channel = "#bench";

const Cell = struct {
    sqpoll: bool,
    tls: []const u8,
    shards: u8,
};

const cells = [_]Cell{
    .{ .sqpoll = false, .tls = "off", .shards = 1 },
    .{ .sqpoll = false, .tls = "off", .shards = 4 },
    .{ .sqpoll = false, .tls = "userspace", .shards = 1 },
    .{ .sqpoll = false, .tls = "userspace", .shards = 4 },
    .{ .sqpoll = true, .tls = "off", .shards = 1 },
    .{ .sqpoll = true, .tls = "off", .shards = 4 },
    .{ .sqpoll = true, .tls = "userspace", .shards = 1 },
    .{ .sqpoll = true, .tls = "userspace", .shards = 4 },
};

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        std.debug.print("bench_x4_portable: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const bin = args.next() orelse {
        std.debug.print("usage: bench_x4_portable ONYX_SERVER\n", .{});
        std.process.exit(2);
    };
    const dir = "/tmp/x4-portable";
    if (std.c.mkdir(dir, 0o755) != 0 and std.c.errno(-1) != .EXIST) return error.MakeDir;
    std.debug.print("GAP-X4 portable bench\n", .{});
    std.debug.print("binary={s}\n", .{bin});
    std.debug.print("work={s}\n", .{dir});
    _ = try shellTo(init, "uname -srm > \"$1\" 2>&1", &.{dir ++ "/uname.txt"});
    _ = try shellTo(init, "sysctl -n hw.model > \"$1\" 2>&1", &.{dir ++ "/cpu.txt"});
    _ = try shellTo(init, "sysctl -n vm.loadavg > \"$1\" 2>&1", &.{dir ++ "/load.txt"});
    try catFile("uname", dir ++ "/uname.txt");
    try catFile("cpu", dir ++ "/cpu.txt");
    try catFile("load", dir ++ "/load.txt");
    std.debug.print("clients={d} privmsg_samples={d}\n", .{ clients_n, samples_n });

    for (cells) |cell| {
        if (cell.sqpoll) {
            emitSkip(cell, "SQPOLL is Linux io_uring; this reactor is kqueue");
            continue;
        }
        if (!std.mem.eql(u8, cell.tls, "off")) {
            emitSkip(cell, "portable reactor does not serve a TLS listener");
            continue;
        }
        measure(init, bin, dir, cell) catch |err| {
            std.debug.print("CELL sqpoll=false tls=off shards={d} error={s}\n", .{ cell.shards, @errorName(err) });
        };
    }
    std.debug.print("GAP-X4 portable bench done\n", .{});
}

fn emitSkip(cell: Cell, why: []const u8) void {
    std.debug.print(
        "CELL sqpoll={s} tls={s} shards={d} register_ms= join_ms= privmsg_ms= rss_idle= rss_loaded= rss_per= note= error={s}\n",
        .{ boolText(cell.sqpoll), cell.tls, cell.shards, why },
    );
}

fn measure(init: std.process.Init, bin: []const u8, dir: []const u8, cell: Cell) !void {
    var conf_buf: [128]u8 = undefined;
    var log_buf: [128]u8 = undefined;
    const conf = try std.fmt.bufPrintSentinel(&conf_buf, "{s}/cell-s{d}.toml", .{ dir, cell.shards }, 0);
    const log = try std.fmt.bufPrintSentinel(&log_buf, "{s}/cell-s{d}.log", .{ dir, cell.shards }, 0);
    const irc = try freePort();
    try writeConf(conf, irc, cell.shards);

    var check_buf: [128]u8 = undefined;
    const check_log = try std.fmt.bufPrintSentinel(&check_buf, "{s}/check.log", .{dir}, 0);
    const check_rc = try shellTo(init, "exec \"$1\" --check-config \"$2\" > \"$3\" 2>&1", &.{ bin, conf, check_log });
    if (check_rc != 0) {
        std.debug.print("CELL sqpoll=false tls=off shards={d} error=check-config:{d}\n", .{ cell.shards, check_rc });
        try printAllow(check_log);
        return;
    }

    const child = try std.process.spawn(init.io, .{
        .argv = &.{ "/bin/sh", "-c", "exec \"$1\" \"$2\" > \"$3\" 2>&1", "sh", bin, conf, log },
        .cwd = .{ .path = dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const pid = child.id orelse return error.Spawn;
    var reaped = false;
    defer {
        if (!reaped) {
            _ = std.c.kill(pid, .TERM);
            var st: c_int = 0;
            _ = std.c.waitpid(pid, &st, 0);
        }
    }
    errdefer printAllow(log) catch {};

    if (!try waitListen(irc, pid, &reaped)) {
        std.debug.print("CELL sqpoll=false tls=off shards={d} error=listen-timeout\n", .{cell.shards});
        try printAllow(log);
        return;
    }
    const idle = try rssOf(init, dir, pid);
    var reg_ns: [clients_n]i128 = undefined;
    var join_ns: [clients_n]i128 = undefined;
    var fds: [clients_n]std.c.fd_t = @splat(-1);
    defer {
        for (fds) |fd| {
            if (fd >= 0) _ = std.c.close(fd);
        }
    }
    for (&fds, 0..) |*slot, i| {
        const t0 = nowNs();
        slot.* = try dial(irc);
        var line: [64]u8 = undefined;
        const reg = try std.fmt.bufPrint(&line, "NICK b{d}\r\nUSER b{d} 0 * :bench\r\n", .{ i, i });
        try sendAll(slot.*, reg);
        try recvUntil(slot.*, " 001 ");
        reg_ns[i] = nowNs() - t0;
    }
    for (fds, 0..) |fd, i| {
        const t0 = nowNs();
        try sendAll(fd, "JOIN #bench\r\n");
        try recvUntil(fd, " 366 ");
        join_ns[i] = nowNs() - t0;
    }
    const loaded = try rssOf(init, dir, pid);
    var msg_ns: [samples_n]i128 = undefined;
    var n: usize = 0;
    while (n < samples_n) : (n += 1) {
        var line: [96]u8 = undefined;
        const token = try std.fmt.bufPrint(&line, "p{d}", .{n});
        var out: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&out, "PRIVMSG {s} :{s}\r\n", .{ channel, token });
        var needle_buf: [32]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buf, ":{s}\r\n", .{token});
        const t0 = nowNs();
        try sendAll(fds[0], msg);
        try recvUntil(fds[clients_n - 1], needle);
        msg_ns[n] = nowNs() - t0;
    }
    const note = if (cell.shards == 1)
        "kqueue one poller; ring_entries is not a queue depth; client and server TCP_NODELAY"
    else
        "kqueue one poller; num_shards does not add a poller; ring_entries is not a queue depth; client and server TCP_NODELAY";
    const delta: f64 = @floatFromInt(@as(i64, @intCast(loaded)) - @as(i64, @intCast(idle)));
    const per = delta / @as(f64, @floatFromInt(clients_n));
    std.debug.print(
        "CELL sqpoll=false tls=off shards={d} register_ms={d:.2} join_ms={d:.2} privmsg_ms={d:.2} rss_idle={d} rss_loaded={d} rss_per={d:.1} note={s} error=\n",
        .{ cell.shards, ms(median(&reg_ns)), ms(median(&join_ns)), ms(median(&msg_ns)), idle, loaded, per, note },
    );
    try printAllow(log);
}

fn waitListen(port: u16, pid: std.c.pid_t, reaped: *bool) !bool {
    var spins: u8 = 0;
    while (spins < 80) : (spins += 1) {
        if (pollReaped(pid)) {
            reaped.* = true;
            return false;
        }
        const fd = dial(port) catch {
            sleepMs(100);
            continue;
        };
        _ = std.c.close(fd);
        return true;
    }
    return false;
}

fn pollReaped(pid: std.c.pid_t) bool {
    var status: c_int = 0;
    return std.c.waitpid(pid, &status, std.c.W.NOHANG) == pid;
}

fn dial(port: u16) !std.c.fd_t {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    var addr = std.c.sockaddr.in{
        .family = std.c.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0) {
        _ = std.c.close(fd);
        return error.ConnectFailed;
    }
    // FreeBSD Nagle holds the next small PRIVMSG until delayed ACK, because
    // the daemon does not echo that command to the sender. Linux clients in
    // tools/bench_live.py do not need this.
    var nodelay: i32 = 1;
    _ = std.c.setsockopt(fd, 6, 1, &nodelay, @sizeOf(i32));
    var tv = std.c.timeval{ .sec = 4, .usec = 0 };
    _ = std.c.setsockopt(fd, std.c.SOL.SOCKET, std.c.SO.RCVTIMEO, &tv, @sizeOf(@TypeOf(tv)));
    return fd;
}

fn freePort() !u16 {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, std.c.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    defer _ = std.c.close(fd);
    var addr = std.c.sockaddr.in{
        .family = std.c.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    if (std.c.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) != 0) return error.SocketFailed;
    var len: std.c.socklen_t = @sizeOf(@TypeOf(addr));
    if (std.c.getsockname(fd, @ptrCast(&addr), &len) != 0) return error.SocketFailed;
    const port = std.mem.bigToNative(u16, addr.port);
    if (port == 0 or port == 6667 or port == 6680 or port == 6697 or port == 8080 or port == 17667) return error.ForbiddenPort;
    return port;
}

fn sendAll(fd: std.c.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.send(fd, bytes[off..].ptr, bytes.len - off, 0);
        if (n > 0) {
            off += @intCast(n);
            continue;
        }
        if (std.c.errno(n) == .INTR) continue;
        return error.SendFailed;
    }
}

fn recvUntil(fd: std.c.fd_t, needle: []const u8) !void {
    var acc: [8192]u8 = undefined;
    var n: usize = 0;
    const deadline = nowNs() + 4_000_000_000;
    while (nowNs() < deadline and n < acc.len) {
        const got = std.c.recv(fd, acc[n..].ptr, acc.len - n, 0);
        if (got > 0) {
            n += @intCast(got);
            if (std.mem.indexOf(u8, acc[0..n], needle) != null) return;
            continue;
        }
        const err = std.c.errno(got);
        if (err == .INTR or err == .AGAIN) continue;
        return error.RecvFailed;
    }
    return error.Timeout;
}

fn writeConf(path: [:0]const u8, port: u16, shards: u8) !void {
    const fd = std.c.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    var buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf,
        \\[node]
        \\id = 1
        \\[listen]
        \\host = "127.0.0.1"
        \\irc = {d}
        \\[limits]
        \\num_shards = {d}
        \\[io]
        \\ring_entries = 32
        \\cqe_batch = 256
        \\sqpoll = false
        \\
    , .{ port, shards });
    var off: usize = 0;
    while (off < text.len) {
        const n = std.c.write(fd, text[off..].ptr, text.len - off);
        if (n > 0) {
            off += @intCast(n);
            continue;
        }
        if (std.c.errno(n) == .INTR) continue;
        return error.WriteFailed;
    }
}

fn rssOf(init: std.process.Init, dir: []const u8, pid: std.c.pid_t) !u64 {
    var pid_buf: [32]u8 = undefined;
    const pid_txt = try std.fmt.bufPrintSentinel(&pid_buf, "{d}", .{pid}, 0);
    var out_buf: [128]u8 = undefined;
    const out = try std.fmt.bufPrintSentinel(&out_buf, "{s}/rss.txt", .{dir}, 0);
    _ = try shellTo(init, "ps -o rss= -p \"$1\" > \"$2\" 2>&1", &.{ pid_txt, out });
    const fd = std.c.open(out, .{}, @as(std.c.mode_t, 0));
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.c.read(fd, &buf, buf.len);
    if (n <= 0) return error.RssFailed;
    const text = std.mem.trim(u8, buf[0..@intCast(n)], " \t\r\n");
    return std.fmt.parseInt(u64, text, 10) catch return error.RssFailed;
}

fn shellTo(init: std.process.Init, script: [:0]const u8, args: []const []const u8) !u8 {
    var argv: [8][]const u8 = undefined;
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = script;
    argv[3] = "sh";
    var n: usize = 4;
    for (args) |arg| {
        if (n >= argv.len) return error.TooManyArgs;
        argv[n] = arg;
        n += 1;
    }
    var child = try std.process.spawn(init.io, .{
        .argv = argv[0..n],
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(init.io);
    return switch (term) {
        .exited => |code| code,
        else => 255,
    };
}

fn catFile(label: []const u8, path: [:0]const u8) !void {
    const fd = std.c.open(path, .{}, @as(std.c.mode_t, 0));
    if (fd < 0) return;
    defer _ = std.c.close(fd);
    var buf: [256]u8 = undefined;
    const n = std.c.read(fd, &buf, buf.len);
    if (n <= 0) return;
    const text = std.mem.trim(u8, buf[0..@intCast(n)], " \t\r\n");
    std.debug.print("{s}={s}\n", .{ label, text });
}

fn printAllow(path: [:0]const u8) !void {
    const fd = std.c.open(path, .{}, @as(std.c.mode_t, 0));
    if (fd < 0) return;
    defer _ = std.c.close(fd);
    var buf: [4096]u8 = undefined;
    const n = std.c.read(fd, &buf, buf.len);
    if (n <= 0) return;
    var it = std.mem.splitScalar(u8, buf[0..@intCast(n)], '\n');
    while (it.next()) |line| {
        if (std.mem.indexOf(u8, line, "Onyx Server") != null or
            std.mem.indexOf(u8, line, "listening on") != null or
            std.mem.indexOf(u8, line, "loaded config") != null or
            std.mem.indexOf(u8, line, "fatal") != null or
            std.mem.indexOf(u8, line, "GAP-X") != null or
            std.mem.indexOf(u8, line, "kqueue") != null)
        {
            std.debug.print("LOG {s}\n", .{line});
        }
    }
}

fn nowNs() i128 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

fn sleepMs(millis: u64) void {
    var req = std.c.timespec{
        .sec = @intCast(millis / 1000),
        .nsec = @intCast((millis % 1000) * 1_000_000),
    };
    _ = std.c.nanosleep(&req, null);
}

fn median(xs: []i128) i128 {
    var tmp: [16]i128 = undefined;
    const n = xs.len;
    @memcpy(tmp[0..n], xs);
    var i: usize = 1;
    while (i < n) : (i += 1) {
        const key = tmp[i];
        var j: usize = i;
        while (j > 0 and tmp[j - 1] > key) : (j -= 1) tmp[j] = tmp[j - 1];
        tmp[j] = key;
    }
    if (n % 2 == 1) return tmp[n / 2];
    return @divTrunc(tmp[n / 2 - 1] + tmp[n / 2], 2);
}

fn ms(ns: i128) f64 {
    return @as(f64, @floatFromInt(ns)) / 1_000_000.0;
}

fn boolText(v: bool) []const u8 {
    return if (v) "true" else "false";
}
