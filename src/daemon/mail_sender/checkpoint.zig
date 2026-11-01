// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mail snapshot validation and owned-payload cleanup.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");
const Config = @import("config.zig").Config;
const configDigest = @import("config.zig").configDigest;
const job_capacity = @import("limits.zig").job_capacity;
const Job = @import("model.zig").Job;
const FailedMessage = @import("model.zig").FailedMessage;
const JournalCut = @import("model.zig").JournalCut;
const Execution = @import("model.zig").Execution;
const QueuedMessage = @import("model.zig").QueuedMessage;
const jobBytes = @import("model.zig").jobBytes;

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    jobs: []QueuedMessage,
    failure_seq: u64,
    config_digest: [32]u8,
    execution: Execution,
    pending_failure: ?FailedMessage = null,
    journal_cut: ?JournalCut = null,
    pub fn deinit(self: *Snapshot) void {
        for (self.jobs) |job| job.free(self.allocator);
        if (self.pending_failure) |message| message.job.free(self.allocator);
        self.allocator.free(self.jobs);
        self.* = undefined;
    }
    pub fn validate(self: *const Snapshot, config: Config, max_bytes: usize) !void {
        if (self.jobs.len > job_capacity) return error.InvalidState;
        if (!std.mem.eql(u8, &self.config_digest, &try configDigest(config))) return error.ConfigMismatch;
        var bytes = @sizeOf(Snapshot) + self.jobs.len * @sizeOf(Job);
        for (self.jobs) |job| {
            bytes = std.math.add(usize, bytes, job.to.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.subject.len) catch return error.Capacity;
            bytes = std.math.add(usize, bytes, job.body.len) catch return error.Capacity;
        }
        if (self.pending_failure) |message| {
            try message.validate(self.failure_seq);
            if (config.failure_wal == null) return error.InvalidState;
            bytes = try jobBytes(bytes, message.job);
        } else if (self.journal_cut != null) return error.InvalidState;
        if (bytes > max_bytes) return error.Capacity;
    }
};
