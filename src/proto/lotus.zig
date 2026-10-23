// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lotus: pure in-memory IRC message history rings.
//!
//! This module performs no I/O. It owns duplicated target keys and message
//! strings, bounds target count and per-target history length at comptime, and
//! returns borrowed read views that remain valid until the next mutation.
//! The implementation lives in `lotus/`, with retention, owned messages, and
//! checkpoint grammar separated behind this stable public entry point.

const types = @import("lotus/types.zig");
const store = @import("lotus/store.zig");

pub const ContentHash = types.ContentHash;
pub const Params = types.Params;
pub const InputMessage = types.InputMessage;
pub const ExactInputMessage = types.ExactInputMessage;
pub const Message = types.Message;
pub const AppendResult = types.AppendResult;
pub const ExactOnceResult = types.ExactOnceResult;
pub const Error = types.Error;
pub const CheckpointError = types.CheckpointError;
pub const Lotus = store.Lotus;
pub const HistoryStore = store.HistoryStore;

test {
    _ = @import("lotus/history_tests.zig");
    _ = @import("lotus/exact_once_tests.zig");
    _ = @import("lotus/checkpoint_tests.zig");
}
