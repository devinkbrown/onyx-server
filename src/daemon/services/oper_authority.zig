// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper authority.

const std = @import("std");
const sign = @import("../../crypto/sign.zig");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const oper_session_provenance = @import("../oper_session_provenance.zig");
const ocg2_reconcile_schedule = @import("../ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("../ocg2_reconcile_workset.zig");
const oper_cred_share = @import("../../proto/oper_cred_share.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const Config = @import("records.zig").Config;
const canonicalAccount = @import("records.zig").canonicalAccount;
const DurableOperActivationError = @import("contracts.zig").DurableOperActivationError;
const DurableOperLookup = @import("contracts.zig").DurableOperLookup;
const DurableOperGrantCopy = @import("contracts.zig").DurableOperGrantCopy;
const DurableOperTransactionCopy = @import("contracts.zig").DurableOperTransactionCopy;
const DurableOperTransaction = @import("contracts.zig").DurableOperTransaction;
const DurableOperReconcileObservation = @import("contracts.zig").DurableOperReconcileObservation;
const DurableOperMergeOutcome = @import("contracts.zig").DurableOperMergeOutcome;
const DurableOperRevisionOutcome = @import("contracts.zig").DurableOperRevisionOutcome;
const DurableOperTransactionsResult = @import("contracts.zig").DurableOperTransactionsResult;
const DurableOperAuthorityMatch = @import("contracts.zig").DurableOperAuthorityMatch;
const AfterCopyHook = @import("oper_shared.zig").AfterCopyHook;
const ocg2ReconcileExpectedValid = @import("oper_shared.zig").ocg2ReconcileExpectedValid;
const ocg2ReconcileIdentityMatches = @import("oper_shared.zig").ocg2ReconcileIdentityMatches;
const ocg2ReconcileLiveMatchesCopy = @import("oper_shared.zig").ocg2ReconcileLiveMatchesCopy;
const oper_availability_domain = @import("oper_availability.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    durable_oper_authority_state: *?*durable_oper_authority.State,
    durable_oper_availability_epoch: *u64,

    /// Attach only a state restored or cold-initialized from this exact
    /// Services OroStore. Services borrows the state; the process owner must
    /// keep it alive until after Services is no longer reachable.
    pub fn activateDurableOperAuthority(
        self: Context,
        state: *durable_oper_authority.State,
    ) DurableOperActivationError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.durable_oper_authority_state.* != null) return error.AlreadyActive;
        // An exact but not-yet-reserved image is attachable solely so the
        // inactive reservation API can cross its first durable cut.  A state
        // that was already authorized and then poisoned remains fatal.
        if (!state.servingAvailable() and state.securityTimeAuthorized())
            return error.AuthorityUnavailable;
        const marker = self.store.*.get(.props, durable_oper_authority.marker_key) orelse
            return error.MissingDurableMarker;
        try durable_oper_authority.validateMarker(marker, state.authority());
        const durable_snapshot = self.store.*.get(.props, durable_oper_authority.snapshot_key) orelse
            return error.MissingDurableSnapshot;
        if (state.snapshot().len == 0 or !std.mem.eql(u8, state.snapshot(), durable_snapshot))
            return error.DurableSnapshotMismatch;
        self.durable_oper_authority_state.* = state;
    }

    /// Inspect the durable OCG2 authority image under the Services read lock.
    /// Every successful grant result is copied into fixed inline storage before
    /// the lock is released; callers never receive a borrowed RecordView or
    /// durable-state slice. OCG2 remains an inactive authority image: this API
    /// only reports typed state for the Step 5 reconciler.
    pub fn inspectDurableOperAuthority(
        self: Context,
        account: []const u8,
        now_ms: u64,
    ) oper_session_provenance.DurableOperLookup {
        return self.inspectDurableOperAuthorityInner(account, now_ms, null);
    }

    /// Inspect the exact latest durable transaction, including terminal
    /// tombstone/equivocation identities.  The returned copy owns no borrowed
    /// slices and is safe after the Services read lock is released.  This API
    /// is diagnostic only; it does not participate in session authorization.
    pub fn inspectDurableOperTransaction(
        self: Context,
        account: []const u8,
        now_ms: u64,
    ) DurableOperTransaction {
        return self.inspectDurableOperTransactionInner(account, now_ms, null);
    }

    /// Reinspect one C4 work item against the attached serving durable image.
    /// Validation of `work.expected` happens before any lock or state slice.
    /// Crypto and C3 classification run on a fixed copy outside the lock.
    pub fn inspectReconcileWork(
        self: Context,
        work: ocg2_reconcile_workset.WorkItem,
        security_now_ms: u64,
    ) DurableOperReconcileObservation {
        return self.inspectDurableOperReconcileWorkInner(work, security_now_ms, null);
    }

    pub fn inspectDurableOperReconcileWorkInner(
        self: Context,
        work: ocg2_reconcile_workset.WorkItem,
        security_now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) DurableOperReconcileObservation {
        if (!ocg2ReconcileExpectedValid(work.expected, security_now_ms)) return .invalid_work;
        const account = work.expected.account_buf[0..work.expected.account_len];

        var attempt: usize = 0;
        while (attempt < 2) : (attempt += 1) {
            var copy: durable_oper_authority.TransactionCopy = undefined;
            var state_identity: *durable_oper_authority.State = undefined;
            var availability_epoch: u64 = 0;
            var copied = false;

            {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                const state = self.durable_oper_authority_state.* orelse return .disabled;
                if (!state.servingAvailable()) return .authority_unavailable;
                const record = state.latest(account) orelse return .authority_unavailable;
                if (durable_oper_authority.copyTransaction(state.authority(), record)) |exact| {
                    copy = exact;
                    state_identity = state;
                    availability_epoch = self.durable_oper_availability_epoch.*;
                    copied = true;
                } else if (attempt != 0) {
                    return .authority_unavailable;
                }
            }

            if (!copied) continue;
            if (after_copy) |hook| hook.callback(hook.context);

            var hint_slot: [1]ocg2_reconcile_schedule.ReinspectHint = undefined;
            const copies = [_]durable_oper_authority.TransactionCopy{copy};
            const classified = switch (ocg2_reconcile_schedule.build(&copies, security_now_ms, &hint_slot)) {
                .complete => hint_slot[0],
                .invalid, .insufficient_output => {
                    if (self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch) or attempt != 0)
                        return .authority_unavailable;
                    continue;
                },
            };

            const identity_match = ocg2ReconcileIdentityMatches(work.expected, classified);
            var grant: ?DurableOperGrantCopy = null;
            if (identity_match and classified.phase == .active) {
                const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(copy.authority_pubkey) catch {
                    if (self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch) or attempt != 0)
                        return .authority_unavailable;
                    continue;
                };
                const fields = oper_cred_share.verifyOcg2(
                    copy.signedWire(),
                    public_key,
                    copy.authority_node_id,
                    security_now_ms,
                ) catch {
                    if (self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch) or attempt != 0)
                        return .authority_unavailable;
                    continue;
                };
                if (!std.mem.eql(u8, fields.account, copy.account()) or
                    fields.revision != copy.revision or fields.kind != copy.kind or
                    fields.issued_ms != copy.issued_ms or fields.expiry_ms != copy.expiry_ms or
                    fields.authority_node_id != copy.authority_node_id or
                    !std.mem.eql(u8, &fields.authority_pubkey, &copy.authority_pubkey))
                {
                    if (self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch) or attempt != 0)
                        return .authority_unavailable;
                    continue;
                }
                grant = DurableOperGrantCopy.copyFromVerified(
                    fields.account,
                    fields.class,
                    fields.title,
                    fields.privilege_bits,
                    copy.revision,
                    copy.digest,
                    copy.authority_node_id,
                    copy.authority_pubkey,
                    copy.issued_ms,
                    copy.expiry_ms,
                    copy.kind,
                    copy.equivocation,
                    copy.signedWire(),
                );
                if (grant == null) {
                    if (self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch) or attempt != 0)
                        return .authority_unavailable;
                    continue;
                }
            }

            if (!self.ocg2ReconcileCopyStillLive(account, &copy, state_identity, availability_epoch)) {
                if (attempt == 0) continue;
                return .authority_unavailable;
            }
            if (!identity_match) return .superseded;
            return switch (classified.phase) {
                .not_yet_valid => .matched_not_yet_valid,
                .active => .{ .matched_active = grant.? },
                .expired => .matched_expired,
                .tombstone => .matched_tombstone,
                .equivocation => .matched_equivocation,
            };
        }
        return .authority_unavailable;
    }

    pub fn ocg2ReconcileCopyStillLive(
        self: Context,
        account: []const u8,
        copy: *const durable_oper_authority.TransactionCopy,
        state_identity: *durable_oper_authority.State,
        availability_epoch: u64,
    ) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const state = self.durable_oper_authority_state.* orelse return false;
        return ocg2ReconcileLiveMatchesCopy(
            state,
            availability_epoch,
            self.durable_oper_availability_epoch.*,
            state_identity,
            account,
            copy,
        );
    }

    pub fn inspectDurableOperTransactionInner(
        self: Context,
        account: []const u8,
        now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) DurableOperTransaction {
        const canonical = canonicalAccount(account) catch return .absent;
        var attempt: usize = 0;
        while (attempt < 2) : (attempt += 1) {
            var account_buf: [durable_oper_authority.max_account_len]u8 = @splat(0);
            var wire_buf: [durable_oper_authority.max_wire_len]u8 = undefined;
            var wire_len: usize = 0;
            var revision: u64 = 0;
            var issued_ms: u64 = 0;
            var expiry_ms: u64 = 0;
            var digest: [durable_oper_authority.digest_len]u8 = undefined;
            var conflict_digest: [durable_oper_authority.digest_len]u8 = undefined;
            var kind: oper_cred_share.Ocg2Kind = .grant;
            var equivocation = false;
            var authority: durable_oper_authority.Config = undefined;
            var state_identity: *durable_oper_authority.State = undefined;
            var availability_epoch: u64 = 0;
            var status: enum { active, tombstone, equivocation } = .active;

            {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                const state = self.durable_oper_authority_state.* orelse return .disabled;
                if (!state.servingAvailable()) return .unavailable;
                const record = state.latest(canonical.asSlice()) orelse return .absent;
                // A grant that is not effective is intentionally not exposed
                // as active.  Step5's lookup retains its richer expiry state.
                if (!record.equivocation and record.kind == .grant and !record.effective(now_ms)) return .absent;
                if (record.equivocation) {
                    status = .equivocation;
                } else if (record.kind == .tombstone) {
                    status = .tombstone;
                }
                if (record.account.len > account_buf.len or record.wire.len == 0 or record.wire.len > wire_buf.len)
                    return .unavailable;
                @memcpy(account_buf[0..record.account.len], record.account);
                wire_len = record.wire.len;
                @memcpy(wire_buf[0..wire_len], record.wire);
                revision = record.revision;
                issued_ms = record.issued_ms;
                expiry_ms = record.expiry_ms;
                digest = record.digest;
                conflict_digest = record.conflict_digest;
                kind = record.kind;
                equivocation = record.equivocation;
                authority = state.authority();
                state_identity = state;
                availability_epoch = self.durable_oper_availability_epoch.*;
            }

            if (after_copy) |hook| hook.callback(hook.context);

            const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(authority.authority_pubkey) catch return .unavailable;
            // Terminal copies remain inspectable even after grant expiry.  Use
            // the signed issue time for structural verification in those
            // cases; active grants retain the caller's current-time check.
            const verify_now = if (status == .active) now_ms else issued_ms;
            const fields = oper_cred_share.verifyOcg2(wire_buf[0..wire_len], public_key, authority.authority_node_id, verify_now) catch return .unavailable;
            if (!std.mem.eql(u8, fields.account, account_buf[0..canonical.len]) or
                fields.revision != revision or fields.kind != kind or
                fields.issued_ms != issued_ms or fields.expiry_ms != expiry_ms or
                fields.authority_node_id != authority.authority_node_id or
                !std.mem.eql(u8, &fields.authority_pubkey, &authority.authority_pubkey))
                return .unavailable;

            var tuple_stable = false;
            {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                const state = self.durable_oper_authority_state.* orelse return .unavailable;
                const latest = state.latest(canonical.asSlice()) orelse {
                    if (attempt == 0) continue;
                    return .unavailable;
                };
                tuple_stable = state == state_identity and state.servingAvailable() and
                    self.durable_oper_availability_epoch.* == availability_epoch and
                    latest.revision == revision and std.mem.eql(u8, &latest.digest, &digest) and
                    std.mem.eql(u8, &latest.conflict_digest, &conflict_digest) and
                    latest.kind == kind and latest.equivocation == equivocation and
                    latest.issued_ms == issued_ms and latest.expiry_ms == expiry_ms and
                    std.mem.eql(u8, latest.account, account_buf[0..canonical.len]) and
                    std.mem.eql(u8, latest.wire, wire_buf[0..wire_len]);
            }
            if (!tuple_stable) continue;

            const copy = durable_oper_authority.copyTransaction(authority, .{
                .account = account_buf[0..canonical.len],
                .revision = revision,
                .kind = kind,
                .issued_ms = issued_ms,
                .expiry_ms = expiry_ms,
                .digest = digest,
                .conflict_digest = conflict_digest,
                .equivocation = equivocation,
                .wire = wire_buf[0..wire_len],
            }) orelse return .unavailable;
            return switch (status) {
                .active => .{ .active = copy },
                .tombstone => .{ .tombstone = copy },
                .equivocation => .{ .equivocation = copy },
            };
        }
        return .unavailable;
    }

    pub fn inspectDurableOperAuthorityInner(
        self: Context,
        account: []const u8,
        now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) oper_session_provenance.DurableOperLookup {
        const canonical = canonicalAccount(account) catch return .absent;
        // Crypto is intentionally outside the Services lock.  At most one
        // retry is allowed after the exact latest-record tuple check; a second
        // instability fails closed instead of returning a predecessor grant.
        var attempt: usize = 0;
        while (attempt < 2) : (attempt += 1) {
            var wire_buf: [durable_oper_authority.max_wire_len]u8 = undefined;
            var wire_len: usize = 0;
            var authority_node_id: u64 = 0;
            var authority_pubkey: [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8 = undefined;
            var revision: u64 = 0;
            var digest: [durable_oper_authority.digest_len]u8 = undefined;
            var issued_ms: u64 = 0;
            var expiry_ms: u64 = 0;
            var kind: oper_cred_share.Ocg2Kind = .grant;
            var equivocation = false;
            var state_identity: *durable_oper_authority.State = undefined;
            var availability_epoch: u64 = 0;

            {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                const state = self.durable_oper_authority_state.* orelse return .disabled;
                if (!state.servingAvailable()) return .unavailable;
                state_identity = state;
                availability_epoch = self.durable_oper_availability_epoch.*;
                const record = state.latest(canonical.asSlice()) orelse return .absent;
                kind = record.kind;
                equivocation = record.equivocation;
                if (equivocation) return .equivocation;
                if (kind == .tombstone) return .tombstone;
                if (record.issued_ms > now_ms) return .not_yet_valid;
                if (now_ms >= record.expiry_ms) return .expired;
                if (record.wire.len > wire_buf.len) return .unavailable;
                const authority = state.authority();
                authority_node_id = authority.authority_node_id;
                authority_pubkey = authority.authority_pubkey;
                revision = record.revision;
                digest = record.digest;
                issued_ms = record.issued_ms;
                expiry_ms = record.expiry_ms;
                wire_len = record.wire.len;
                @memcpy(wire_buf[0..wire_len], record.wire);
            }

            if (after_copy) |hook| hook.callback(hook.context);

            const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(authority_pubkey) catch return .unavailable;
            const fields = oper_cred_share.verifyOcg2(wire_buf[0..wire_len], public_key, authority_node_id, now_ms) catch return .unavailable;
            if (!std.mem.eql(u8, fields.account, canonical.asSlice()) or
                fields.kind != kind or fields.revision != revision or fields.issued_ms != issued_ms or
                fields.expiry_ms != expiry_ms or fields.authority_node_id != authority_node_id or
                !std.mem.eql(u8, &fields.authority_pubkey, &authority_pubkey))
                return .unavailable;

            var tuple_stable = false;
            {
                self.lock.lockShared();
                defer self.lock.unlockShared();
                const state = self.durable_oper_authority_state.* orelse return .unavailable;
                const latest = state.latest(canonical.asSlice()) orelse {
                    if (attempt == 0) continue;
                    return .unavailable;
                };
                tuple_stable = state == state_identity and state.servingAvailable() and
                    self.durable_oper_availability_epoch.* == availability_epoch and
                    latest.revision == revision and std.mem.eql(u8, &latest.digest, &digest) and latest.kind == kind and
                    latest.equivocation == equivocation and latest.issued_ms == issued_ms and
                    latest.expiry_ms == expiry_ms;
            }
            if (!tuple_stable) continue;

            const copy = oper_session_provenance.DurableOperGrantCopy.copyFromVerified(
                fields.account,
                fields.class,
                fields.title,
                fields.privilege_bits,
                revision,
                digest,
                authority_node_id,
                authority_pubkey,
                issued_ms,
                expiry_ms,
                kind,
                equivocation,
                wire_buf[0..wire_len],
            ) orelse return .unavailable;
            return .{ .active = copy };
        }
        return .unavailable;
    }

    /// Persist one already-signed OCG2 authority record. Every state allocation,
    /// snapshot byte, and OroStore reservation precedes the durable cut.
    pub fn commitDurableOperRecord(self: Context, wire: []const u8, now_ms: u64) DurableOperMergeOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (!state.servingAvailable()) return .unavailable;
        const prepared = state.prepareMerge(wire, now_ms) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.CapacityExceeded, error.BoundsExceeded => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.GenerationExhausted => .{ .preadmission = .exhausted },
            error.StateDestroyed => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_state };
            },
            else => .{ .preadmission = .invalid_record },
        };
        var update = switch (prepared) {
            .stale => return .stale,
            .replay => return .replay,
            .update => |value| value,
        };
        defer update.abort();
        var durable_put = self.store.*.preparePut(.props, durable_oper_authority.snapshot_key, update.snapshot()) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.RecordTooLarge => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.SequenceExhausted => .{ .preadmission = .exhausted },
            error.IoAmbiguous => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .ambiguous_store };
            },
            error.StorePoisoned => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_store };
            },
            else => .{ .preadmission = .store_failure },
        };
        defer durable_put.abort();
        durable_put.commit() catch |err| {
            self.markDurableOperUnavailableLocked(state);
            return switch (err) {
                error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
                else => .{ .restart_required = .fatal_store },
            };
        };
        const disposition = update.disposition;
        if (!update.commitIntoChecked(state)) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        return if (disposition == .equivocation) .equivocation_committed else .committed;
    }

    /// Exclusive, allocation-free diagnostic listing of every latest durable
    /// OCG2 transaction.  Fixed copies only; never a privilege grant.  An
    /// invariant failure poisons the inactive image.
    pub fn copyDurableOperTransactions(
        self: Context,
        out: []DurableOperTransactionCopy,
    ) DurableOperTransactionsResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (state.destroyed) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        if (!state.servingAvailable() and state.securityTimeAuthorized()) return .unavailable;
        const copied = state.copyTransactions(out) catch |err| return switch (err) {
            error.CapacityExceeded => .{ .preadmission = .capacity },
            error.InvalidRecord => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_state };
            },
        };
        return .{ .copied = copied };
    }

    /// Durably allocate an authority-side revision. The revision is returned
    /// only after the prepared snapshot crosses the store cut; no wire producer
    /// exists here, preventing precommit transmission by construction.
    pub fn allocateDurableOperRevision(self: Context, account: []const u8) DurableOperRevisionOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (!state.servingAvailable()) return .unavailable;
        var prepared = state.prepareRevision(account) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.CapacityExceeded, error.BoundsExceeded => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.GenerationExhausted => .{ .preadmission = .exhausted },
            error.StateDestroyed => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_state };
            },
            else => .{ .preadmission = .invalid_record },
        };
        defer prepared.update.abort();
        var durable_put = self.store.*.preparePut(.props, durable_oper_authority.snapshot_key, prepared.update.snapshot()) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.RecordTooLarge => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.SequenceExhausted => .{ .preadmission = .exhausted },
            error.IoAmbiguous => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .ambiguous_store };
            },
            error.StorePoisoned => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_store };
            },
            else => .{ .preadmission = .store_failure },
        };
        defer durable_put.abort();
        durable_put.commit() catch |err| {
            self.markDurableOperUnavailableLocked(state);
            return switch (err) {
                error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
                else => .{ .restart_required = .fatal_store },
            };
        };
        const revision = prepared.revision;
        if (!prepared.update.commitIntoChecked(state)) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        return .{ .committed = revision };
    }

    /// Exact public-tuple + reservation match for the inactive durable
    /// authority. Ready requires attachment, serving availability, an
    /// authorized security reservation, and a constant-time full public-key
    /// match together with the short-id. This is not a privilege grant.
    pub fn matchDurableOperAuthority(
        self: Context,
        expected: durable_oper_authority.Config,
    ) DurableOperAuthorityMatch {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (!state.servingAvailable() or !state.securityTimeAuthorized()) return .unavailable;
        if (expected.authority_node_id == 0) return .mismatch;
        const actual = state.authority();
        const node_ok = actual.authority_node_id == expected.authority_node_id;
        const key_ok = std.crypto.timing_safe.eql(
            @TypeOf(actual.authority_pubkey),
            actual.authority_pubkey,
            expected.authority_pubkey,
        );
        if (!node_ok or !key_ok) return .mismatch;
        return .ready;
    }

    /// One-way exclusive poison of durable operator authority. Advances the
    /// availability epoch. There is no matching re-enable on this process.
    pub fn failClosedDurableOperAuthority(self: Context) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return;
        self.markDurableOperUnavailableLocked(state);
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn markDurableOperUnavailableLocked(
        self: Context,
        state: *durable_oper_authority.State,
    ) void {
        return (oper_availability_domain.Context{ .lock = self.lock, .durable_oper_authority_state = self.durable_oper_authority_state, .durable_oper_availability_epoch = self.durable_oper_availability_epoch }).markDurableOperUnavailableLocked(state);
    }
};
