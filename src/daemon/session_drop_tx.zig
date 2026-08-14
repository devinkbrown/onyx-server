// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded transaction journal for cross-reactor `SESSION DROP`.
//!
//! The journal is the authoritative in-process state. Mailbox controls contain
//! only a generational `TxId` and are therefore disposable wake hints: a full
//! mailbox cannot lose transaction state or expose a resume credential.
//!
//! Callers serialize journal access with the daemon's World write lock. No lock,
//! borrowed slice, or prepared World ticket is retained here between turns.

const std = @import("std");
const client = @import("client.zig");
const attachment_id = @import("attachment_id.zig");

pub const capacity: usize = 256;
pub const account_capacity: usize = client.MAX_ACCOUNT_BYTES;
pub const nick_capacity: usize = client.MAX_NICK_BYTES;
pub const SessionClientId = u64;
pub const Token = [16]u8;
pub const AttachmentId = attachment_id.AttachmentId;
pub const Sid = [16]u8;
pub const DropReservationId = u64;

/// Exact physical-row identity copied from the requester's LIST snapshot. The
/// daemon converts its SessionStore selector into this transport-independent
/// image at admission; keeping the journal standalone permits direct tests and
/// prevents the transaction protocol from importing the entire Store.
pub const ExactSelector = struct {
    client: SessionClientId,
    token: Token,
    signon_ms: i64,
    attachment_id: ?AttachmentId = null,
};

/// Generational slot identity. `slot_plus_one == 0` is the invalid sentinel;
/// retaining the generation outside the securely erased Entry makes controls
/// from a reaped transaction harmless after the slot is reused.
pub const TxId = packed struct(u64) {
    slot_plus_one: u32 = 0,
    generation: u32 = 0,

    pub const invalid: TxId = .{};

    pub fn isValid(self: TxId) bool {
        return self.slot_plus_one != 0 and
            self.slot_plus_one <= capacity and
            self.generation != 0;
    }

    pub fn raw(self: TxId) u64 {
        return @bitCast(self);
    }

    pub fn fromRaw(value: u64) ?TxId {
        const id: TxId = @bitCast(value);
        return if (id.isValid()) id else null;
    }

    fn slotIndex(self: TxId) usize {
        std.debug.assert(self.isValid());
        return @as(usize, self.slot_plus_one - 1);
    }
};

/// Secret-free control record suitable for a bounded MPMC mailbox.
pub const Control = extern struct {
    tx_raw: u64,

    pub fn init(id: TxId) ?Control {
        if (!id.isValid()) return null;
        return .{ .tx_raw = id.raw() };
    }

    pub fn txId(self: Control) ?TxId {
        return TxId.fromRaw(self.tx_raw);
    }
};

pub const ReplyKey = union(enum) {
    ordinal: usize,
    sid: Sid,
};

pub const State = enum(u8) {
    free,
    target_pending,
    successor_pending,
    commit_pending,
    committing,
    committed,
    abort_pending,
    aborted,

    pub fn isPrecommit(self: State) bool {
        return switch (self) {
            .target_pending, .successor_pending, .commit_pending => true,
            else => false,
        };
    }

    pub fn isTerminal(self: State) bool {
        return self == .committed or self == .aborted;
    }
};

pub const TerminalResult = enum(u8) {
    removed,
    stale_list,
    temporarily_unavailable,
    requester_gone,
    target_gone,
    cancelled,
    timed_out,
};

pub const ReservationRole = enum(u8) {
    target,
    successor,
};

pub const InlineText = struct {
    bytes: [account_capacity]u8 = @splat(0),
    len: u8 = 0,

    fn set(self: *InlineText, value: []const u8, fold_ascii: bool) error{TextTooLong}!void {
        if (value.len > self.bytes.len) return error.TextTooLong;
        for (value, 0..) |byte, index| {
            self.bytes[index] = if (fold_ascii) std.ascii.toLower(byte) else byte;
        }
        self.len = @intCast(value.len);
    }

    pub fn slice(self: *const InlineText) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const BeginArgs = struct {
    requester: client.ClientId,
    account: []const u8,
    target: ExactSelector,
    target_nick: []const u8,
    reply: ReplyKey,
    deadline_ms: u64,
};

pub const BeginError = error{
    JournalFull,
    AccountTooLong,
    NickTooLong,
    InvalidRequester,
};

pub const TransitionError = error{
    StaleTransaction,
    InvalidState,
    MissingTargetReservation,
    MissingSuccessor,
    MissingSuccessorReservation,
};

pub const ReleaseResult = enum {
    released,
    already_clear,
};

/// Inline transaction image. Account and nick bytes are owned; selectors copy
/// their token/AID bytes. Nothing in an Entry borrows parser, connection, or
/// SessionStore memory.
pub const Entry = struct {
    id: TxId = .invalid,
    state: State = .free,
    requester: client.ClientId = .invalid,
    account: InlineText = .{},
    target: ExactSelector = .{
        .client = 0,
        .token = @splat(0),
        .signon_ms = 0,
        .attachment_id = null,
    },
    target_nick: InlineText = .{},
    successor: ?ExactSelector = null,
    reply: ReplyKey = .{ .ordinal = 0 },
    deadline_ms: u64 = 0,
    target_reserved: bool = false,
    successor_reserved: bool = false,
    reply_pending: bool = false,
    result: ?TerminalResult = null,

    pub fn accountName(self: *const Entry) []const u8 {
        return self.account.slice();
    }

    pub fn targetNick(self: *const Entry) []const u8 {
        return self.target_nick.slice();
    }

    pub fn hasReservations(self: *const Entry) bool {
        return self.target_reserved or self.successor_reserved;
    }

    /// Abort results are consumable while owner cleanup remains pending. The
    /// slot itself is retained until both reservations are gone.
    pub fn terminalResult(self: *const Entry) ?TerminalResult {
        return switch (self.state) {
            .committed, .abort_pending, .aborted => self.result,
            else => null,
        };
    }
};

const Slot = struct {
    generation: u32 = 0,
    occupied: bool = false,
    entry: Entry = .{},
};

pub const Journal = struct {
    slots: [capacity]Slot = @splat(.{}),
    active_count: usize = 0,
    allocation_cursor: usize = 0,

    pub fn init() Journal {
        return .{};
    }

    pub fn deinit(self: *Journal) void {
        for (&self.slots) |*slot| {
            if (slot.occupied) std.crypto.secureZero(u8, std.mem.asBytes(&slot.entry));
        }
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = .{};
    }

    pub fn activeCount(self: *const Journal) usize {
        return self.active_count;
    }

    pub fn begin(self: *Journal, args: BeginArgs) BeginError!TxId {
        if (args.requester.isNone()) return error.InvalidRequester;
        if (args.account.len > account_capacity) return error.AccountTooLong;
        if (args.target_nick.len > nick_capacity) return error.NickTooLong;

        var offset: usize = 0;
        while (offset < capacity) : (offset += 1) {
            const index = (self.allocation_cursor + offset) % capacity;
            const slot = &self.slots[index];
            if (slot.occupied) continue;

            slot.generation +%= 1;
            if (slot.generation == 0) slot.generation = 1;
            const id = TxId{
                .slot_plus_one = @intCast(index + 1),
                .generation = slot.generation,
            };
            var entry = Entry{
                .id = id,
                .state = .target_pending,
                .requester = args.requester,
                .target = args.target,
                .reply = args.reply,
                .deadline_ms = args.deadline_ms,
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&entry));
            entry.account.set(args.account, true) catch return error.AccountTooLong;
            entry.target_nick.set(args.target_nick, false) catch return error.NickTooLong;
            slot.entry = entry;
            slot.occupied = true;
            self.active_count += 1;
            self.allocation_cursor = (index + 1) % capacity;
            return id;
        }
        return error.JournalFull;
    }

    pub fn get(self: *Journal, id: TxId) ?*Entry {
        if (!id.isValid()) return null;
        const slot = &self.slots[id.slotIndex()];
        if (!slot.occupied or slot.generation != id.generation) return null;
        return &slot.entry;
    }

    pub fn getConst(self: *const Journal, id: TxId) ?*const Entry {
        if (!id.isValid()) return null;
        const slot = &self.slots[id.slotIndex()];
        if (!slot.occupied or slot.generation != id.generation) return null;
        return &slot.entry;
    }

    fn require(self: *Journal, id: TxId) TransitionError!*Entry {
        return self.get(id) orelse error.StaleTransaction;
    }

    pub fn activeIdsInto(self: *const Journal, out: []TxId) []const TxId {
        var count: usize = 0;
        for (&self.slots) |*slot| {
            if (!slot.occupied) continue;
            if (count == out.len) break;
            out[count] = slot.entry.id;
            count += 1;
        }
        return out[0..count];
    }

    pub fn markTargetReserved(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state != .target_pending) return error.InvalidState;
        entry.target_reserved = true;
    }

    /// Advance a final-row transaction after the target owner has proved that
    /// no attached exact-token successor requires attestation.
    pub fn markCommitPending(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state == .commit_pending and entry.successor == null) return;
        if (entry.state != .target_pending) return error.InvalidState;
        if (!entry.target_reserved) return error.MissingTargetReservation;
        if (entry.successor != null) return error.InvalidState;
        entry.state = .commit_pending;
    }

    pub fn setSuccessorPending(self: *Journal, id: TxId, successor: ExactSelector) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state == .successor_pending) {
            if (exactSelectorEql(entry.successor orelse return error.MissingSuccessor, successor)) return;
            return error.InvalidState;
        }
        if (entry.state != .target_pending) return error.InvalidState;
        if (!entry.target_reserved) return error.MissingTargetReservation;
        entry.successor = successor;
        entry.state = .successor_pending;
    }

    pub fn markSuccessorReserved(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state == .commit_pending and entry.successor_reserved) return;
        if (entry.state != .successor_pending) return error.InvalidState;
        if (!entry.target_reserved) return error.MissingTargetReservation;
        if (entry.successor == null) return error.MissingSuccessor;
        entry.successor_reserved = true;
        entry.state = .commit_pending;
    }

    pub fn beginCommit(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state == .committing) return;
        if (entry.state != .commit_pending) return error.InvalidState;
        if (!entry.target_reserved) return error.MissingTargetReservation;
        if (entry.successor != null and !entry.successor_reserved)
            return error.MissingSuccessorReservation;
        entry.state = .committing;
    }

    /// Publish success only after the Store CAS, allocation-free World commit,
    /// and target handoff latches have all completed. The target reservation is
    /// consumed by the successful Store row removal before this call.
    pub fn markCommitted(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.state == .committed) return;
        if (entry.state != .committing) return error.InvalidState;
        if (entry.target_reserved) return error.InvalidState;
        entry.state = .committed;
        entry.result = .removed;
        entry.reply_pending = true;
    }

    /// Recover a failed target Store CAS before the linearization point. The
    /// target reservation must still be held, proving that no row was removed;
    /// after that reservation is consumed this transition is forbidden.
    pub fn failCommitBeforeLinearization(
        self: *Journal,
        id: TxId,
        result: TerminalResult,
    ) TransitionError!void {
        if (result == .removed) return error.InvalidState;
        const entry = try self.require(id);
        if (entry.state != .committing or !entry.target_reserved)
            return error.InvalidState;
        entry.state = .abort_pending;
        entry.result = result;
        entry.reply_pending = true;
    }

    /// The first precommit failure wins. Duplicate cancellation controls are
    /// idempotent; committing and committed work is irreversible.
    pub fn requestAbort(self: *Journal, id: TxId, result: TerminalResult) TransitionError!void {
        if (result == .removed) return error.InvalidState;
        const entry = try self.require(id);
        switch (entry.state) {
            .target_pending, .successor_pending, .commit_pending => {
                entry.state = .abort_pending;
                entry.result = result;
                entry.reply_pending = true;
                if (!entry.hasReservations()) entry.state = .aborted;
            },
            .abort_pending, .aborted => return,
            else => return error.InvalidState,
        }
    }

    pub fn markReservationReleased(self: *Journal, id: TxId, role: ReservationRole) TransitionError!ReleaseResult {
        const entry = try self.require(id);
        const reserved = switch (role) {
            .target => &entry.target_reserved,
            .successor => &entry.successor_reserved,
        };
        if (!reserved.*) return .already_clear;
        reserved.* = false;
        if (entry.state == .abort_pending and !entry.hasReservations()) entry.state = .aborted;
        return .released;
    }

    pub fn markResultConsumed(self: *Journal, id: TxId) TransitionError!void {
        const entry = try self.require(id);
        if (entry.terminalResult() == null) return error.InvalidState;
        entry.reply_pending = false;
    }

    pub fn isExpired(self: *const Journal, id: TxId, now_ms: u64) bool {
        const entry = self.getConst(id) orelse return false;
        return entry.state.isPrecommit() and now_ms >= entry.deadline_ms;
    }

    /// Transition an expired precommit transaction exactly once. Returns false
    /// for an unexpired, committing, terminal, or already-aborting transaction.
    pub fn expire(self: *Journal, id: TxId, now_ms: u64) TransitionError!bool {
        if (!self.isExpired(id, now_ms)) {
            _ = try self.require(id);
            return false;
        }
        try self.requestAbort(id, .timed_out);
        return true;
    }

    /// Reap only after the requester consumed (or abandoned) its result and all
    /// owner reservations are gone. Every secret-bearing Entry byte is erased;
    /// the non-secret generation remains in Slot for late-control rejection.
    pub fn reapIfDone(self: *Journal, id: TxId) bool {
        const entry = self.get(id) orelse return false;
        if (!entry.state.isTerminal() or entry.reply_pending or entry.hasReservations()) return false;
        const slot = &self.slots[id.slotIndex()];
        std.crypto.secureZero(u8, std.mem.asBytes(&slot.entry));
        slot.occupied = false;
        std.debug.assert(self.active_count != 0);
        self.active_count -= 1;
        return true;
    }
};

pub fn reservationId(id: TxId) DropReservationId {
    return if (id.isValid()) id.raw() else 0;
}

fn exactSelectorEql(a: ExactSelector, b: ExactSelector) bool {
    const aid_matches = if (a.attachment_id) |aid|
        b.attachment_id != null and aid.eql(b.attachment_id.?)
    else
        b.attachment_id == null;
    return a.client == b.client and
        a.signon_ms == b.signon_ms and
        aid_matches and
        std.crypto.timing_safe.eql(Token, a.token, b.token);
}

const testing = std.testing;

fn testRequester(slot: u20) client.ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 1 };
}

fn testSelector(client_id: SessionClientId, byte: u8) ExactSelector {
    return .{
        .client = client_id,
        .token = @splat(byte),
        .signon_ms = 1234 + @as(i64, @intCast(client_id)),
    };
}

fn testBegin(journal: *Journal, client_id: SessionClientId) !TxId {
    return journal.begin(.{
        .requester = testRequester(@intCast(client_id % 1000)),
        .account = "KaIn",
        .target = testSelector(client_id, @truncate(client_id + 1)),
        .target_nick = "Target",
        .reply = .{ .ordinal = 2 },
        .deadline_ms = 100,
    });
}

test "journal owns folded account target and secret-free generational control" {
    var journal = Journal.init();
    defer journal.deinit();
    const id = try testBegin(&journal, 4);
    const entry = journal.get(id).?;
    try testing.expectEqualStrings("kain", entry.accountName());
    try testing.expectEqualStrings("Target", entry.targetNick());
    try testing.expectEqual(@as(usize, 1), journal.activeCount());
    try testing.expectEqual(id.raw(), reservationId(id));
    const control = Control.init(id).?;
    try testing.expect(control.txId().?.raw() == id.raw());
    try testing.expect(Control.init(.invalid) == null);
    try testing.expect((Control{ .tx_raw = 0 }).txId() == null);
}

test "final-row state machine rejects skipped phases and publishes once" {
    var journal = Journal.init();
    defer journal.deinit();
    const id = try testBegin(&journal, 1);

    try testing.expectError(error.MissingTargetReservation, journal.markCommitPending(id));
    try testing.expectError(error.InvalidState, journal.beginCommit(id));
    try journal.markTargetReserved(id);
    try journal.markTargetReserved(id);
    try journal.markCommitPending(id);
    try journal.markCommitPending(id);
    try journal.beginCommit(id);
    try journal.beginCommit(id);
    try testing.expectError(error.InvalidState, journal.requestAbort(id, .cancelled));
    try testing.expectEqual(ReleaseResult.released, try journal.markReservationReleased(id, .target));
    try journal.markCommitted(id);
    try journal.markCommitted(id);
    try testing.expectEqual(TerminalResult.removed, journal.get(id).?.terminalResult().?);
    try testing.expect(!journal.reapIfDone(id));
    try journal.markResultConsumed(id);
    try journal.markResultConsumed(id);
    try testing.expect(journal.reapIfDone(id));
}

test "successor state machine requires both exact reservations" {
    var journal = Journal.init();
    defer journal.deinit();
    const id = try testBegin(&journal, 2);
    const successor = testSelector(9, 0x99);

    try testing.expectError(error.MissingTargetReservation, journal.setSuccessorPending(id, successor));
    try journal.markTargetReserved(id);
    try journal.setSuccessorPending(id, successor);
    try journal.setSuccessorPending(id, successor);
    try testing.expectError(error.InvalidState, journal.setSuccessorPending(id, testSelector(10, 0x55)));
    try testing.expectError(error.InvalidState, journal.beginCommit(id));
    try journal.markSuccessorReserved(id);
    try journal.markSuccessorReserved(id);
    try journal.beginCommit(id);
    try testing.expectEqual(ReleaseResult.released, try journal.markReservationReleased(id, .target));
    try journal.markCommitted(id);
    try testing.expect(!journal.reapIfDone(id));
    try testing.expectEqual(ReleaseResult.released, try journal.markReservationReleased(id, .successor));
    try testing.expectEqual(ReleaseResult.already_clear, try journal.markReservationReleased(id, .successor));
    try journal.markResultConsumed(id);
    try testing.expect(journal.reapIfDone(id));
}

test "failed Store CAS aborts committing work only before linearization" {
    var journal = Journal.init();
    defer journal.deinit();
    const id = try testBegin(&journal, 31);
    try journal.markTargetReserved(id);
    try journal.markCommitPending(id);
    try journal.beginCommit(id);

    try testing.expectError(
        error.InvalidState,
        journal.failCommitBeforeLinearization(id, .removed),
    );
    try journal.failCommitBeforeLinearization(id, .target_gone);
    try testing.expectEqual(State.abort_pending, journal.get(id).?.state);
    try testing.expectEqual(TerminalResult.target_gone, journal.get(id).?.terminalResult().?);
    try testing.expect(journal.get(id).?.reply_pending);
    try testing.expectError(
        error.InvalidState,
        journal.failCommitBeforeLinearization(id, .timed_out),
    );
    try testing.expectEqual(
        ReleaseResult.released,
        try journal.markReservationReleased(id, .target),
    );
    try testing.expectEqual(State.aborted, journal.get(id).?.state);
    try journal.markResultConsumed(id);
    try testing.expect(journal.reapIfDone(id));

    const linearized = try testBegin(&journal, 32);
    try journal.markTargetReserved(linearized);
    try journal.markCommitPending(linearized);
    try journal.beginCommit(linearized);
    _ = try journal.markReservationReleased(linearized, .target);
    try testing.expectError(
        error.InvalidState,
        journal.failCommitBeforeLinearization(linearized, .target_gone),
    );
}

test "abort result is consumable before distributed cleanup and first cause wins" {
    var journal = Journal.init();
    defer journal.deinit();
    const id = try testBegin(&journal, 3);
    try journal.markTargetReserved(id);
    try journal.setSuccessorPending(id, testSelector(8, 0x88));
    try journal.markSuccessorReserved(id);

    try journal.requestAbort(id, .target_gone);
    try journal.requestAbort(id, .timed_out);
    try testing.expectEqual(TerminalResult.target_gone, journal.get(id).?.terminalResult().?);
    try journal.markResultConsumed(id);
    try testing.expect(!journal.reapIfDone(id));
    _ = try journal.markReservationReleased(id, .target);
    try testing.expectEqual(State.abort_pending, journal.get(id).?.state);
    _ = try journal.markReservationReleased(id, .successor);
    try testing.expectEqual(State.aborted, journal.get(id).?.state);
    try testing.expect(journal.reapIfDone(id));
}

test "deadline expires only precommit work and boundary is inclusive" {
    var journal = Journal.init();
    defer journal.deinit();
    const early = try testBegin(&journal, 11);
    try testing.expect(!journal.isExpired(early, 99));
    try testing.expect(!(try journal.expire(early, 99)));
    try testing.expect(journal.isExpired(early, 100));
    try testing.expect(try journal.expire(early, 100));
    try testing.expectEqual(TerminalResult.timed_out, journal.get(early).?.terminalResult().?);
    try testing.expect(!(try journal.expire(early, 100)));

    const committing = try testBegin(&journal, 12);
    try journal.markTargetReserved(committing);
    try journal.markCommitPending(committing);
    try journal.beginCommit(committing);
    try testing.expect(!journal.isExpired(committing, 1000));
    try testing.expect(!(try journal.expire(committing, 1000)));
}

test "reap securely erases entry and late generation cannot reach reused slot" {
    var journal = Journal.init();
    defer journal.deinit();
    journal.allocation_cursor = 0;
    const old = try testBegin(&journal, 21);
    try journal.requestAbort(old, .cancelled);
    try journal.markResultConsumed(old);
    try testing.expect(journal.reapIfDone(old));

    const old_index = old.slotIndex();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&journal.slots[old_index].entry), 0));
    journal.allocation_cursor = old_index;
    const replacement = try testBegin(&journal, 22);
    try testing.expectEqual(old.slot_plus_one, replacement.slot_plus_one);
    try testing.expect(old.generation != replacement.generation);
    try testing.expect(journal.get(old) == null);
    try testing.expectError(error.StaleTransaction, journal.markTargetReserved(old));
    try testing.expect(journal.get(replacement) != null);
}

test "journal capacity is exact and active id snapshot is bounded" {
    var journal = Journal.init();
    defer journal.deinit();
    var ids: [capacity]TxId = undefined;
    for (0..capacity) |index| ids[index] = try testBegin(&journal, @intCast(index + 1));
    try testing.expectEqual(capacity, journal.activeCount());
    try testing.expectError(error.JournalFull, testBegin(&journal, 999));

    var short: [7]TxId = undefined;
    try testing.expectEqual(@as(usize, short.len), journal.activeIdsInto(&short).len);
    for (short) |id| try testing.expect(journal.get(id) != null);
}

test "begin rejects invalid identities and oversized inline text without admission" {
    var journal = Journal.init();
    defer journal.deinit();
    var long: [account_capacity + 1]u8 = @splat('x');
    const base = BeginArgs{
        .requester = testRequester(1),
        .account = "acct",
        .target = testSelector(1, 1),
        .target_nick = "nick",
        .reply = .{ .ordinal = 1 },
        .deadline_ms = 1,
    };
    var args = base;
    args.requester = .invalid;
    try testing.expectError(error.InvalidRequester, journal.begin(args));
    args = base;
    args.account = &long;
    try testing.expectError(error.AccountTooLong, journal.begin(args));
    args = base;
    args.target_nick = &long;
    try testing.expectError(error.NickTooLong, journal.begin(args));
    try testing.expectEqual(@as(usize, 0), journal.activeCount());
    std.crypto.secureZero(u8, &long);
}
