// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mail queue, message, I/O, and worker limits.

const std = @import("std");
const smtp_client = @import("../../proto/smtp_client.zig");

pub const dormant_spawn_options: std.Thread.SpawnConfig = .{};

pub const job_capacity: usize = 64; // bounded ring; enqueue drops past this

pub const max_queued_jobs: usize = job_capacity;

pub const io_timeout_ms: u31 = 15000; // per-job connect + recv/send timeout

pub const max_message_len: usize = 16 * 1024; // assembled RFC 5322 message cap

pub const max_body_len: usize = 12 * 1024; // body truncated to fit under the cap

pub const max_tls_record: usize = 16 * 1024 + 512; // largest framed TLS record

pub const max_smtp_iterations: usize = 256; // loop bound so a bad relay can't hang us

pub const max_job_ms: i64 = 60_000; // hard per-job wall-clock budget (H2: bounds total time)
