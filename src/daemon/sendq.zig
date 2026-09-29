// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connection SendQ: inline buffer plus heap overflow.
//!
//! The kernel only ever reads the fixed inline buffer. Overflow is refilled
//! into that buffer on send completion, and an armed send is never compacted.
//! Callers pass the live connection; these functions are the daemon's queue.

const std = @import("std");

/// Bytes waiting in this connection's SendQ. Inline tail plus overflow.
pub fn backlog(conn: anytype) u64 {
    const inline_queued = conn.send_len -| conn.send_offset;
    return std.math.add(u64, inline_queued, conn.send_overflow.items.len) catch std.math.maxInt(u64);
}

pub fn rawAppend(conn: anytype, bytes: []const u8) error{OutputTooSmall}!void {
    // Enforce the configured ceiling before BOTH the inline and overflow paths.
    // The old fast path admitted up to the full 8 KiB inline buffer even when a
    // connection class configured a smaller SendQ. Keep every addition checked:
    // attacker-controlled lengths must fail closed rather than wrap the bound.
    const inline_queued = conn.send_len - conn.send_offset;
    const queued = std.math.add(usize, inline_queued, conn.send_overflow.items.len) catch return error.OutputTooSmall;
    if (queued > conn.sendq_cap or bytes.len > conn.sendq_cap - queued) return error.OutputTooSmall;

    // Fast path: with nothing already spilled to overflow, reclaim the sent prefix
    // [0, send_offset) by sliding the unsent tail to the front, then use the inline
    // buffer if it fits. NEVER compact while a send SQE is armed: the kernel is
    // still reading send_buf[send_offset..send_len] for the in-flight zero-copy
    // send, so moving those bytes would corrupt the wire.
    if (conn.send_overflow.items.len == 0) {
        if (conn.send_len + bytes.len > conn.send_buf.len and conn.send_offset > 0 and !conn.send_armed) {
            const tail = conn.send_len - conn.send_offset;
            std.mem.copyForwards(u8, conn.send_buf[0..tail], conn.send_buf[conn.send_offset..conn.send_len]);
            conn.send_len = tail;
            conn.send_offset = 0;
        }
        if (conn.send_len + bytes.len <= conn.send_buf.len) {
            @memcpy(conn.send_buf[conn.send_len .. conn.send_len + bytes.len], bytes);
            conn.send_len += bytes.len;
            return;
        }
    }
    // Overflow (real SendQ): the inline buffer is full or busy, so spill to the heap
    // queue — refilled into the inline buffer on send-completion (the kernel only
    // ever reads the fixed inline buffer, so this never moves an armed buffer).
    conn.send_overflow.appendSlice(conn.overflow_allocator, bytes) catch return error.OutputTooSmall;
}

/// Reserve the exact SendQ storage needed by one already-sized secured record
/// before advancing the link's AEAD send counter. Once this succeeds,
/// `rawAppend` cannot fail for capacity or allocation, so replay never has
/// to leave counter-owning ciphertext in a shared SecuredLink outbound buffer.
pub fn reserve(conn: anytype, bytes_len: usize) error{OutputTooSmall}!void {
    const inline_queued = conn.send_len - conn.send_offset;
    const queued = std.math.add(usize, inline_queued, conn.send_overflow.items.len) catch
        return error.OutputTooSmall;
    if (queued > conn.sendq_cap or bytes_len > conn.sendq_cap - queued)
        return error.OutputTooSmall;

    if (conn.send_overflow.items.len == 0) {
        if (conn.send_len + bytes_len <= conn.send_buf.len) return;
        if (!conn.send_armed and conn.send_offset != 0 and
            inline_queued + bytes_len <= conn.send_buf.len) return;
    }
    conn.send_overflow.ensureUnusedCapacity(conn.overflow_allocator, bytes_len) catch
        return error.OutputTooSmall;
}

/// Refill the drained inline `send_buf` with the next chunk of the SendQ overflow.
/// Called from the send-completion handler with nothing armed, so writing the
/// inline buffer is safe. The overflow heap is freed entirely once fully drained
/// so a one-off burst never pins memory.
pub fn refill(conn: anytype) void {
    if (conn.send_overflow.items.len == 0) return;
    const n = @min(conn.send_buf.len, conn.send_overflow.items.len);
    @memcpy(conn.send_buf[0..n], conn.send_overflow.items[0..n]);
    conn.send_len = n;
    conn.send_offset = 0;
    if (n == conn.send_overflow.items.len) {
        conn.send_overflow.clearAndFree(conn.overflow_allocator);
    } else {
        const remaining = conn.send_overflow.items.len - n;
        std.mem.copyForwards(u8, conn.send_overflow.items[0..remaining], conn.send_overflow.items[n..]);
        conn.send_overflow.items.len = remaining;
    }
}
