// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Device facts.

const std = @import("std");
const durable_credential_props = @import("../durable_credential_props.zig");
const key_transparency = @import("../key_transparency.zig");
const entity_prop_event = @import("../../proto/entity_prop_event.zig");
const e2ee_policy = @import("../../proto/e2ee_policy.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const canonicalAccount = @import("records.zig").canonicalAccount;
const DurableDeviceFactKeyTransparency = @import("contracts.zig").DurableDeviceFactKeyTransparency;
const DurableDeviceFactOutcome = @import("contracts.zig").DurableDeviceFactOutcome;
const KeyTransparencyRecordError = @import("contracts.zig").KeyTransparencyRecordError;
const key_transparency_domain = @import("key_transparency.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    key_transparency: *const ?*key_transparency.KeyTransparencyLog,
    durable_credential_props_state: *const ?*durable_credential_props.State,

    /// Commit one locally-authored `e2ee.device.*` fact across the DPROP1
    /// in-memory image and its sole OroStore snapshot row.
    ///
    /// All fallible DPROP allocations and OroStore reservations happen before
    /// the durable cut. A successful prepared-store commit is immediately
    /// followed by the allocation-free DPROP swap. An ambiguous store result
    /// is never retried here: the poisoned store must be reopened so WAL replay
    /// decides whether the candidate crossed the durability boundary. The
    /// exact-fact key-transparency append is observational and best-effort.
    pub fn commitLocalDurableDeviceFact(
        self: Context,
        event: entity_prop_event.EntityPropEvent,
    ) DurableDeviceFactOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.durable_credential_props_state.* orelse return .disabled;
        const canonical = canonicalAccount(event.entity) catch return .{ .preadmission = .invalid_fact };
        if (!std.mem.eql(u8, event.entity, canonical.asSlice()) or
            !std.mem.eql(u8, event.owner, canonical.asSlice()))
        {
            return .{ .preadmission = .invalid_fact };
        }
        const prepared_outcome = state.prepare(event) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.CapacityExceeded, error.BoundsExceeded => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.GenerationExhausted => .{ .preadmission = .exhausted },
            error.StateDestroyed, error.StateMismatch, error.PreparedAlreadyConsumed => .{ .restart_required = .fatal_state },
            else => .{ .preadmission = .invalid_fact },
        };

        var update = switch (prepared_outcome) {
            .stale => return .stale,
            .replay => return .replay,
            .equivocation => return .equivocation,
            .update => |prepared| prepared,
        };
        defer update.abort();

        var durable_put = self.store.*.preparePut(
            .props,
            durable_credential_props.store_key,
            update.snapshot(),
        ) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.RecordTooLarge => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.SequenceExhausted => .{ .preadmission = .exhausted },
            error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
            error.StorePoisoned => .{ .restart_required = .fatal_store },
            else => .{ .preadmission = .store_failure },
        };
        defer durable_put.abort();

        durable_put.commit() catch |err| return switch (err) {
            error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
            else => .{ .restart_required = .fatal_store },
        };
        update.commitInto(state);

        const kt_status: DurableDeviceFactKeyTransparency = if (self.key_transparency.* == null)
            .disabled
        else if (self.commitKeyTransparencyHashed(
            event.entity,
            .e2ee_device,
            if (event.present) .bind else .delete,
            event.key[e2ee_policy.device_prop_prefix.len..],
            key_transparency.factObservationHash(.{
                .account = event.entity,
                .kind = .e2ee_device,
                .action = if (event.present) .bind else .delete,
                .key_id = event.key[e2ee_policy.device_prop_prefix.len..],
                .hlc = event.hlc,
                .origin_node = event.origin_node,
                .origin_pubkey = event.origin_pubkey,
            }, event.value),
            key_transparency.observationTimestampMs(event.hlc),
        ))
            .recorded
        else |_|
            .unavailable;

        return .{ .committed = .{ .key_transparency = kt_status } };
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn commitKeyTransparencyHashed(
        self: Context,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        key_hash: key_transparency.Hash,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        return (key_transparency_domain.Context{ .store = self.store, .lock = self.lock, .key_transparency = self.key_transparency }).commitKeyTransparencyHashed(account, kind, action, key_id, key_hash, timestamp_ms);
    }
};
