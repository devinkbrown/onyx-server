// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! History configuration, borrowed messages, and exact-once result contracts.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub const ContentHash = [Blake3.digest_length]u8;

pub const Params = struct {
    max_targets: usize,
    max_per_target: usize,
    max_text: usize,
    max_target: usize = 1024,
    max_msgid: usize = 1024,
    max_sender: usize = 1024,
    max_command: usize = 64,
    max_client_tags: usize = 8 * 1024,
    max_checkpoint_bytes: usize = 64 * 1024 * 1024,
};

pub const InputMessage = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    /// IRC command this history entry replays as. "PRIVMSG"/"NOTICE" are ordinary
    /// messages; anything else (e.g. "TOPIC") is a draft/event-playback event,
    /// replayed only to clients that negotiated `event-playback`. The store
    /// owns a duplicate, so restored checkpoint commands never borrow the
    /// checkpoint buffer.
    command: []const u8 = "PRIVMSG",
    /// Sanitized client-only tag segment for TAGMSG history replay, without the
    /// leading '@'. Null for entries that do not carry client tags.
    client_tags: ?[]const u8 = null,
};

/// Complete retained state used by conflict-aware mesh ingestion. `text` is
/// the current text after any edit and `tombstone` is the current redaction
/// state; both therefore participate in exact-duplicate classification.
pub const ExactInputMessage = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    command: []const u8 = "PRIVMSG",
    client_tags: ?[]const u8 = null,
    tombstone: bool = false,
};

pub const Message = struct {
    hash: ContentHash = @splat(0),
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    tombstone: bool,
    command: []const u8 = "PRIVMSG",
    client_tags: ?[]const u8 = null,
};

pub const AppendResult = struct {
    evicted: bool,
    target_len: usize,
};

pub const ExactOnceResult = union(enum) {
    inserted: AppendResult,
    exact_duplicate,
    equivocation,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidTarget,
    TargetLimitExceeded,
    TargetTooLong,
    MsgidTooLong,
    SenderTooLong,
    CommandTooLong,
    ClientTagsTooLong,
    /// Retaining this mutation would make the canonical checkpoint exceed the
    /// concrete store's configured byte limit. The store is unchanged.
    CheckpointCapacityExceeded,
    TextTooLong,
    OutputTooSmall,
    NotFound,
};

pub const CheckpointError = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    ConfigMismatch,
    CapacityExceeded,
    CheckpointTooLarge,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    NonCanonicalOrder,
    InvalidField,
    InvalidHash,
};

pub fn exactInput(self: ExactInputMessage) InputMessage {
    return .{
        .msgid = self.msgid,
        .sender = self.sender,
        .text = self.text,
        .timestamp = self.timestamp,
        .command = self.command,
        .client_tags = self.client_tags,
    };
}
