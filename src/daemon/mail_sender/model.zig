// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned queued mail, retained failure custody, and checkpoint record types.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const store_mod = @import("../store.zig");
const runtime_pause = @import("../runtime_pause.zig");
const journal_custody = @import("../mesh_presence_lease.zig");

/// One queued message; the three strings are allocator-owned copies.
pub const Job = struct {
    to: []u8,
    subject: []u8,
    body: []u8,

    pub fn free(self: Job, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.to);
        std.crypto.secureZero(u8, self.subject);
        std.crypto.secureZero(u8, self.body);
        allocator.free(self.to);
        allocator.free(self.subject);
        allocator.free(self.body);
    }
};

/// Stable error names are carried as checked bytes, never compiler anyerror
/// ordinals. A pending outcome owns the original whole job until resolution.
pub const FailedMessage = struct {
    job: Job,
    sequence: u64,
    error_name: [128]u8 = @splat(0),
    error_len: u8 = 0,
    pub fn name(self: *const FailedMessage) []const u8 {
        return self.error_name[0..self.error_len];
    }
    pub fn validate(self: *const FailedMessage, sequence: u64) !void {
        if (self.sequence == 0 or self.sequence != sequence or self.error_len == 0 or self.error_len > self.error_name.len) return error.InvalidState;
        for (self.name()) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidState;
        for (self.error_name[self.error_len..]) |c| if (c != 0) return error.InvalidState;
    }
};

pub const FileCut = struct { identity: journal_custody.Identity, length: u64, digest: [32]u8 };

pub const JournalCut = struct { wal: FileCut, snapshot: ?FileCut };

/// Full Windows file IDs and byte digests for the private failure journal.
/// This cut is only valid after the source worker parks and producers freeze.
pub const PrivateFileCut = struct {
    identity: store_mod.WindowsFileIdInfo,
    length: u64,
    digest: [32]u8,
};

pub const PrivateWalCut = struct {
    parent: store_mod.WindowsFileIdInfo,
    name_digest: [32]u8,
    wal: PrivateFileCut,
    snapshot: ?PrivateFileCut,
};

pub const PrivateWalStage = struct {
    expected: PrivateWalCut,
    wal: std.Io.File,
    snapshot: ?std.Io.File,
};

pub const PendingFailure = struct {
    message: FailedMessage,
    journal: ?*store_mod.OroStore = null,
    cut: ?JournalCut = null,
};

pub const ProducerFence = runtime_pause.ProducerFence;

pub const Execution = enum(u8) { unstarted, paused };

pub const QueuedMessage = Job;

pub fn cloneJob(allocator: std.mem.Allocator, job: Job) !Job {
    const to = try allocator.dupe(u8, job.to);
    errdefer {
        std.crypto.secureZero(u8, to);
        allocator.free(to);
    }
    const subject = try allocator.dupe(u8, job.subject);
    errdefer {
        std.crypto.secureZero(u8, subject);
        allocator.free(subject);
    }
    const body = try allocator.dupe(u8, job.body);
    return .{ .to = to, .subject = subject, .body = body };
}

pub fn jobBytes(initial: usize, job: Job) !usize {
    var bytes = std.math.add(usize, initial, @sizeOf(Job)) catch return error.Capacity;
    bytes = std.math.add(usize, bytes, job.to.len) catch return error.Capacity;
    bytes = std.math.add(usize, bytes, job.subject.len) catch return error.Capacity;
    return std.math.add(usize, bytes, job.body.len) catch return error.Capacity;
}
