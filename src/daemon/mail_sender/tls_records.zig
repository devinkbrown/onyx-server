// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SMTP TLS record framing and fatal-alert transport.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const tls_client = @import("../../crypto/tls_client.zig");
const tls_client_failure = @import("../tls_client_failure.zig");
const http_fetch = @import("../http_fetch.zig");
const Socket = @import("native_io.zig").Socket;

pub fn sendTlsFatal(fd: Socket, client: *tls_client.Client, failure: tls_client.Error) void {
    tls_client_failure.sendFatal(fd, client, failure);
}

// ---- TLS record framing (mirrors http_fetch) --------------------------------

pub fn frameRecordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const len = (@as(usize, buf[3]) << 8) | @as(usize, buf[4]);
    const total = 5 + len;
    if (buf.len < total) return null;
    return total;
}

pub fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const rem = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..rem], list.items[n..]);
    list.shrinkRetainingCapacity(rem);
}
