// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background SMTP sender facade. The worker owns accepted mail and failures;
//! configuration, snapshots, journals, messages, and transports have typed modules.

pub const runtime_pause = @import("runtime_pause.zig");
pub const dormant_spawn_options = @import("mail_sender/limits.zig").dormant_spawn_options;
pub const max_queued_jobs = @import("mail_sender/limits.zig").max_queued_jobs;
pub const Config = @import("mail_sender/config.zig").Config;
pub const FailedMessage = @import("mail_sender/model.zig").FailedMessage;
pub const FileCut = @import("mail_sender/model.zig").FileCut;
pub const JournalCut = @import("mail_sender/model.zig").JournalCut;
pub const PrivateFileCut = @import("mail_sender/model.zig").PrivateFileCut;
pub const PrivateWalCut = @import("mail_sender/model.zig").PrivateWalCut;
pub const ProducerFence = @import("mail_sender/model.zig").ProducerFence;
pub const Sender = @import("mail_sender/core.zig").Sender;
pub const Execution = @import("mail_sender/model.zig").Execution;
pub const QueuedMessage = @import("mail_sender/model.zig").QueuedMessage;
pub const Snapshot = @import("mail_sender/checkpoint.zig").Snapshot;
pub const configDigest = @import("mail_sender/config.zig").configDigest;

test {
    _ = @import("mail_sender/tests_delivery.zig");
    _ = @import("mail_sender/tests_windows.zig");
    _ = @import("mail_sender/tests_queue.zig");
    _ = @import("mail_sender/tests_message.zig");
    _ = @import("mail_sender/tests_resolution.zig");
    _ = @import("mail_sender/tests_transport.zig");
    _ = @import("mail_sender/tests_snapshot.zig");
    _ = @import("mail_sender/tests_custody.zig");
}
