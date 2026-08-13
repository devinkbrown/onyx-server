// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DPROP1 — the standalone durable credential-property image.
//!
//! This module deliberately has no store, daemon, mesh, or I/O dependency. It
//! owns the bounded, canonical state image that a later integration lane may
//! put under `dprop1:snapshot`. Only user `e2ee.device.*` properties authored
//! by this node are admitted. The origin signature authenticates the fact's
//! structure; this leaf also enforces the configured local-origin authority.

const std = @import("std");

const sign = @import("../crypto/sign.zig");
const e2ee_device_directory = @import("../proto/e2ee_device_directory.zig");
const e2ee_policy = @import("../proto/e2ee_policy.zig");
const entity_prop_event = @import("../proto/entity_prop_event.zig");
const key_transparency = @import("key_transparency.zig");

const Blake3 = std.crypto.hash.Blake3;

/// The exact DPROP1 envelope is:
///
///     "DPROP1" || version:u8 || count:u32le ||
///       (event_len:u32le || canonical ENTITY_PROP bytes)* ||
///       blake3("onyx-server-dprop1-snapshot-v1" || 0x00 || above)
///
/// The six-byte magic is intentionally visible in a hexdump, while the
/// separate version byte leaves the framing extensible without changing the
/// magic. Every integer is little-endian, matching the ENTITY_PROP codec.
pub const magic = "DPROP1";
pub const version: u8 = 1;
pub const max_facts: usize = 8_192;
pub const max_snapshot_bytes: usize = 8 * 1024 * 1024;
pub const max_facts_per_account: usize = 64;
pub const checksum_len = Blake3.digest_length;
pub const header_len = magic.len + 1 + 4;
pub const trailer_len = checksum_len;
pub const checksum_domain = "onyx-server-dprop1-snapshot-v1";

/// The sole OroStore property row reserved for the DPROP1 image.
pub const store_key = "dprop1:snapshot";

/// OroStore's mutation payload is a ten-byte mutation header followed by the
/// key and value bytes.  Keep the admission bound here in lockstep with that
/// framing so the later integration lane can preflight without guessing.
const store_payload_header_len: usize = 10;
const store_record_header_len: usize = 8;

fn checkedConstAdd(comptime left: usize, comptime right: usize, comptime label: []const u8) usize {
    return std.math.add(usize, left, right) catch @compileError(label);
}

pub const max_store_payload_bytes: usize = checkedConstAdd(
    checkedConstAdd(store_payload_header_len, store_key.len, "DPROP1 store payload header/key bound overflow"),
    max_snapshot_bytes,
    "DPROP1 store payload bound overflow",
);

/// Full WAL record bytes: the store's eight-byte record header plus the
/// worst-case mutation payload above.
pub const max_store_wal_record_bytes: usize = checkedConstAdd(
    store_record_header_len,
    max_store_payload_bytes,
    "DPROP1 WAL record bound overflow",
);

pub const Config = struct {
    local_origin_node: u64,
};

const max_event_wire_len: usize =
    1 + 1 + 8 + 8 +
    (2 + entity_prop_event.max_entity_len) +
    (2 + entity_prop_event.max_key_len) +
    (2 + entity_prop_event.max_value_len) +
    (2 + entity_prop_event.max_owner_len) +
    1 + entity_prop_event.pubkey_len + entity_prop_event.sig_len;

pub const Error = error{
    BadMagic,
    BadVersion,
    BadChecksum,
    Truncated,
    TrailingBytes,
    NonCanonical,
    InvalidFact,
    InvalidNamespace,
    InvalidAccount,
    InvalidOwner,
    InvalidClock,
    InvalidSignature,
    InvalidOrigin,
    InvalidCredential,
    InvalidTombstone,
    InvalidAuthorityConfig,
    BoundsExceeded,
    CapacityExceeded,
    PreparedMutationActive,
    PreparedAlreadyConsumed,
    StateMismatch,
    StateDestroyed,
    GenerationExhausted,
    Equivocation,
};

pub const PrepareError = Error || std.mem.Allocator.Error;

/// Input fact type for `State.prepare`; this alias keeps the DPROP surface
/// explicit without introducing a second event representation.
pub const Fact = entity_prop_event.EntityPropEvent;

/// A read-only view into one fact retained by a State. All slices remain valid
/// until the next successful commit or State.deinit.
pub const FactView = struct {
    present: bool,
    hlc: u64,
    origin_node: u64,
    entity: []const u8,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    origin_pubkey: []const u8,
    origin_sig: []const u8,

    pub fn event(self: FactView) entity_prop_event.EntityPropEvent {
        return .{
            .present = self.present,
            .kind = .user,
            .origin_node = self.origin_node,
            .hlc = self.hlc,
            .entity = self.entity,
            .key = self.key,
            .value = self.value,
            .owner = self.owner,
            .origin_pubkey = self.origin_pubkey,
            .origin_sig = self.origin_sig,
        };
    }
};

const OwnedFact = struct {
    present: bool,
    hlc: u64,
    origin_node: u64,
    entity: []u8,
    key: []u8,
    value: []u8,
    owner: []u8,
    origin_pubkey: []u8,
    origin_sig: []u8,

    fn fromEvent(allocator: std.mem.Allocator, ev: entity_prop_event.EntityPropEvent) !OwnedFact {
        var out = OwnedFact{
            .present = ev.present,
            .hlc = ev.hlc,
            .origin_node = ev.origin_node,
            .entity = &.{},
            .key = &.{},
            .value = &.{},
            .owner = &.{},
            .origin_pubkey = &.{},
            .origin_sig = &.{},
        };
        errdefer out.deinit(allocator);
        out.entity = try allocator.dupe(u8, ev.entity);
        out.key = try allocator.dupe(u8, ev.key);
        out.value = try allocator.dupe(u8, ev.value);
        out.owner = try allocator.dupe(u8, ev.owner);
        out.origin_pubkey = try allocator.dupe(u8, ev.origin_pubkey);
        out.origin_sig = try allocator.dupe(u8, ev.origin_sig);
        return out;
    }

    fn clone(self: *const OwnedFact, allocator: std.mem.Allocator) !OwnedFact {
        return fromEvent(allocator, self.event());
    }

    fn event(self: *const OwnedFact) entity_prop_event.EntityPropEvent {
        return .{
            .present = self.present,
            .kind = .user,
            .origin_node = self.origin_node,
            .hlc = self.hlc,
            .entity = self.entity,
            .key = self.key,
            .value = self.value,
            .owner = self.owner,
            .origin_pubkey = self.origin_pubkey,
            .origin_sig = self.origin_sig,
        };
    }

    fn view(self: *const OwnedFact) FactView {
        return .{
            .present = self.present,
            .hlc = self.hlc,
            .origin_node = self.origin_node,
            .entity = self.entity,
            .key = self.key,
            .value = self.value,
            .owner = self.owner,
            .origin_pubkey = self.origin_pubkey,
            .origin_sig = self.origin_sig,
        };
    }

    fn deinit(self: *OwnedFact, allocator: std.mem.Allocator) void {
        allocator.free(self.entity);
        allocator.free(self.key);
        allocator.free(self.value);
        allocator.free(self.owner);
        allocator.free(self.origin_pubkey);
        allocator.free(self.origin_sig);
        self.* = undefined;
    }
};

const ActivePrepared = struct {
    expected_epoch: u64,
    generation: u64,
    replacement: std.ArrayListUnmanaged(OwnedFact),
    snapshot_bytes: []u8,
    next_max_hlc: u64,

    fn deinit(self: *ActivePrepared, allocator: std.mem.Allocator) void {
        deinitFacts(allocator, &self.replacement);
        allocator.free(self.snapshot_bytes);
        self.* = undefined;
    }
};

pub const State = struct {
    allocator: std.mem.Allocator,
    config: Config,
    facts: std.ArrayListUnmanaged(OwnedFact) = .empty,
    snapshot_bytes: []u8 = &.{},
    max_hlc_value: u64 = 0,
    mutation_epoch: u64 = 0,
    next_generation: u64 = 0,
    active_prepared: ?ActivePrepared = null,
    prepared_active: bool = false,
    destroyed: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!State {
        if (config.local_origin_node == 0) return error.InvalidAuthorityConfig;
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *State) void {
        if (self.destroyed) return;
        if (self.active_prepared) |*active| active.deinit(self.allocator);
        self.active_prepared = null;
        self.prepared_active = false;
        self.releaseFacts();
        self.allocator.free(self.snapshot_bytes);
        self.snapshot_bytes = &.{};
        self.destroyed = true;
    }

    pub fn count(self: *const State) usize {
        return self.facts.items.len;
    }

    pub fn maxHlc(self: *const State) u64 {
        return self.max_hlc_value;
    }

    /// Returns the immutable local authority captured when this state was
    /// initialized. This is allocation-free and does not expose mutable config.
    pub fn localOriginNode(self: *const State) u64 {
        return self.config.local_origin_node;
    }

    pub fn snapshot(self: *const State) []const u8 {
        return self.snapshot_bytes;
    }

    pub fn get(self: *const State, account: []const u8, key: []const u8) ?FactView {
        const index = lowerBound(self.facts.items, account, key);
        if (index == self.facts.items.len) return null;
        const fact = &self.facts.items[index];
        if (!sameKey(fact, account, key)) return null;
        return fact.view();
    }

    /// Return a bounded read-only view of the canonical sorted fact at
    /// `index`.  Out-of-range indices are deliberately inert for callers that
    /// are walking a restored image without a separate count race.
    pub fn factAt(self: *const State, index: usize) ?FactView {
        if (index >= self.facts.items.len) return null;
        return self.facts.items[index].view();
    }

    pub fn prepare(self: *State, incoming: entity_prop_event.EntityPropEvent) PrepareError!PrepareOutcome {
        if (self.destroyed) return error.StateDestroyed;
        if (self.prepared_active) return error.PreparedMutationActive;
        try validateFact(self.allocator, self.config, incoming);

        const key_index = lowerBound(self.facts.items, incoming.entity, incoming.key);
        if (key_index < self.facts.items.len and sameKey(&self.facts.items[key_index], incoming.entity, incoming.key)) {
            const existing = &self.facts.items[key_index];
            const revision_cmp = compareRevision(incoming.hlc, existing.hlc);
            if (revision_cmp == .lt) return .stale;
            if (revision_cmp == .eq) {
                if (sameEvent(existing.event(), incoming)) return .replay;
                return .equivocation;
            }
        } else {
            if (self.facts.items.len >= max_facts) return error.CapacityExceeded;
            if (accountFactCount(self.facts.items, incoming.entity) >= max_facts_per_account)
                return error.CapacityExceeded;
        }

        self.prepared_active = true;
        errdefer self.prepared_active = false;

        var replacement: std.ArrayListUnmanaged(OwnedFact) = .empty;
        errdefer deinitFacts(self.allocator, &replacement);
        try replacement.ensureTotalCapacity(self.allocator, self.facts.items.len + @intFromBool(key_index == self.facts.items.len or !sameKey(&self.facts.items[key_index], incoming.entity, incoming.key)));
        for (self.facts.items, 0..) |*fact, index| {
            if (index == key_index and sameKey(fact, incoming.entity, incoming.key)) {
                const staged = try OwnedFact.fromEvent(self.allocator, incoming);
                replacement.appendAssumeCapacity(staged);
            } else {
                const staged = try fact.clone(self.allocator);
                replacement.appendAssumeCapacity(staged);
            }
        }
        if (key_index == self.facts.items.len or !sameKey(&self.facts.items[key_index], incoming.entity, incoming.key)) {
            // The source is already sorted, so insert at the lower-bound slot.
            const staged = try OwnedFact.fromEvent(self.allocator, incoming);
            replacement.appendAssumeCapacity(staged);
            var cursor = replacement.items.len - 1;
            while (cursor > key_index) : (cursor -= 1) replacement.items[cursor] = replacement.items[cursor - 1];
            replacement.items[key_index] = staged;
        }

        const generation = if (self.next_generation == std.math.maxInt(u64)) return error.GenerationExhausted else self.next_generation + 1;
        self.next_generation = generation;
        const next_max_hlc = @max(self.max_hlc_value, incoming.hlc);
        const snap = try encodeFacts(self.allocator, replacement.items);
        self.active_prepared = .{
            .expected_epoch = self.mutation_epoch,
            .generation = generation,
            .replacement = replacement,
            .snapshot_bytes = snap,
            .next_max_hlc = next_max_hlc,
        };
        self.prepared_active = true;
        return .{ .update = .{
            .state = self,
            .generation = generation,
        } };
    }

    fn releaseFacts(self: *State) void {
        deinitFacts(self.allocator, &self.facts);
        self.facts = .empty;
    }
};

pub const PrepareOutcome = union(enum) {
    stale,
    replay,
    equivocation,
    update: PreparedUpdate,
};

pub const PreparedUpdate = struct {
    state: *State,
    generation: u64,

    pub fn snapshot(self: *const PreparedUpdate) []const u8 {
        if (self.state.destroyed) return &.{};
        if (self.state.active_prepared) |active| {
            if (active.generation == self.generation) return active.snapshot_bytes;
        }
        return &.{};
    }

    /// Swap the fully allocated replacement into `state`. There are no fallible
    /// operations after this point; freeing the old image is allocation-free.
    pub fn commitInto(self: *PreparedUpdate, state: *State) void {
        if (self.state != state or state.destroyed) return;
        const active_view = state.active_prepared orelse return;
        if (active_view.generation != self.generation or state.mutation_epoch != active_view.expected_epoch) return;
        const active = state.active_prepared.?;
        state.active_prepared = null;
        state.prepared_active = false;
        var old_facts = state.facts;
        const old_snapshot = state.snapshot_bytes;
        state.facts = active.replacement;
        state.snapshot_bytes = active.snapshot_bytes;
        state.max_hlc_value = active.next_max_hlc;
        state.mutation_epoch +%= 1;

        deinitFacts(state.allocator, &old_facts);
        state.allocator.free(old_snapshot);
    }

    pub fn abort(self: *PreparedUpdate) void {
        if (self.state.destroyed) return;
        const active_view = self.state.active_prepared orelse return;
        if (active_view.generation != self.generation) return;
        var active = self.state.active_prepared.?;
        self.state.active_prepared = null;
        self.state.prepared_active = false;
        active.deinit(self.state.allocator);
    }

    pub fn deinit(self: *PreparedUpdate) void {
        self.abort();
        self.* = undefined;
    }
};

pub fn encode(allocator: std.mem.Allocator, state: *const State) ![]u8 {
    return encodeFacts(allocator, state.facts.items);
}

pub fn decode(allocator: std.mem.Allocator, config: Config, bytes: []const u8) !(State) {
    if (bytes.len < header_len + trailer_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.BadVersion;
    if (bytes.len > max_snapshot_bytes) return error.BoundsExceeded;

    const body_end = bytes.len - trailer_len;

    const count = std.mem.readInt(u32, bytes[magic.len + 1 ..][0..4], .little);
    if (count > max_facts) return error.CapacityExceeded;

    // First pass is framing-only. This deliberately performs no event decode,
    // semantic admission, or record allocation before the checksum is known.
    var offset: usize = header_len;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        if (body_end - offset < 4) return error.Truncated;
        const event_len = std.mem.readInt(u32, bytes[offset..][0..4], .little);
        offset += 4;
        if (event_len == 0 or event_len > max_event_wire_len) return error.BoundsExceeded;
        const len: usize = @intCast(event_len);
        if (body_end - offset < len) return error.Truncated;
        offset += len;
    }
    if (offset != body_end) return error.TrailingBytes;
    var expected: [checksum_len]u8 = undefined;
    checksum(bytes[0..body_end], &expected);
    if (!std.mem.eql(u8, &expected, bytes[body_end..])) return error.BadChecksum;

    var state = try State.init(allocator, config);
    errdefer state.deinit();
    try state.facts.ensureTotalCapacity(allocator, @intCast(count));
    offset = header_len;
    var previous_account: []const u8 = "";
    var previous_key: []const u8 = "";
    var have_previous = false;
    index = 0;
    while (index < count) : (index += 1) {
        const event_len = std.mem.readInt(u32, bytes[offset..][0..4], .little);
        offset += 4;
        const len: usize = @intCast(event_len);
        const wire = bytes[offset .. offset + len];
        offset += len;
        const event = entity_prop_event.decode(wire) catch return error.InvalidFact;
        var canonical_buf: [max_event_wire_len]u8 = undefined;
        const canonical = canonicalEvent(event, &canonical_buf) catch return error.InvalidFact;
        if (!std.mem.eql(u8, wire, canonical)) return error.NonCanonical;
        try validateFact(allocator, config, event);
        if (have_previous and compareKey(previous_account, previous_key, event.entity, event.key) != .lt)
            return error.NonCanonical;
        if (accountFactCount(state.facts.items, event.entity) >= max_facts_per_account)
            return error.CapacityExceeded;
        previous_account = event.entity;
        previous_key = event.key;
        have_previous = true;
        const owned = try OwnedFact.fromEvent(allocator, event);
        state.facts.appendAssumeCapacity(owned);
        state.max_hlc_value = @max(state.max_hlc_value, event.hlc);
    }
    state.snapshot_bytes = try allocator.dupe(u8, bytes);
    return state;
}

fn encodeFacts(allocator: std.mem.Allocator, facts: []const OwnedFact) ![]u8 {
    if (facts.len > max_facts) return error.CapacityExceeded;
    var account: []const u8 = "";
    var account_count: usize = 0;
    var total: usize = header_len + trailer_len;
    for (facts) |*fact| {
        if (!std.mem.eql(u8, account, fact.entity)) {
            account = fact.entity;
            account_count = 0;
        }
        account_count += 1;
        if (account_count > max_facts_per_account) return error.CapacityExceeded;
        const len = entity_prop_event.encodedLen(fact.event()) catch return error.InvalidFact;
        if (len > max_event_wire_len) return error.BoundsExceeded;
        total = std.math.add(usize, total, 4 + len) catch return error.BoundsExceeded;
    }
    if (total > max_snapshot_bytes) return error.BoundsExceeded;
    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);
    @memcpy(out[0..magic.len], magic);
    out[magic.len] = version;
    std.mem.writeInt(u32, out[magic.len + 1 ..][0..4], @intCast(facts.len), .little);
    var offset: usize = header_len;
    for (facts) |*fact| {
        var event_buf: [max_event_wire_len]u8 = undefined;
        const wire = canonicalEvent(fact.event(), &event_buf) catch return error.InvalidFact;
        std.mem.writeInt(u32, out[offset..][0..4], @intCast(wire.len), .little);
        offset += 4;
        @memcpy(out[offset..][0..wire.len], wire);
        offset += wire.len;
    }
    var checksum_bytes: [checksum_len]u8 = undefined;
    checksum(out[0..offset], &checksum_bytes);
    @memcpy(out[offset..][0..checksum_len], &checksum_bytes);
    return out;
}

fn canonicalEvent(ev: entity_prop_event.EntityPropEvent, out: *[max_event_wire_len]u8) ![]const u8 {
    const len = try entity_prop_event.encodedLen(ev);
    if (len > out.len) return error.BoundsExceeded;
    return try entity_prop_event.encode(ev, out[0..]);
}

fn validateFact(allocator: std.mem.Allocator, config: Config, ev: entity_prop_event.EntityPropEvent) PrepareError!void {
    if (ev.kind != .user) return error.InvalidFact;
    if (ev.hlc == 0 or ev.hlc == std.math.maxInt(u64)) return error.InvalidClock;
    if (ev.origin_node != config.local_origin_node) return error.InvalidOrigin;
    if (ev.entity.len > key_transparency.max_account_len) return error.InvalidAccount;
    key_transparency.validateAccount(ev.entity) catch return error.InvalidAccount;
    if (ev.key.len == 0) return error.InvalidNamespace;
    if (!e2ee_policy.isDevicePropKey(ev.key)) return error.InvalidNamespace;
    if (!ev.present and ev.value.len != 0) return error.InvalidTombstone;
    if (ev.present) try validateCredentialValue(ev.key, ev.value);
    if (!validOwner(ev.owner)) return error.InvalidOwner;
    if (ev.origin_pubkey.len != entity_prop_event.pubkey_len or ev.origin_sig.len != entity_prop_event.sig_len)
        return error.InvalidSignature;
    var canonical_buf: [max_event_wire_len]u8 = undefined;
    _ = canonicalEvent(ev, &canonical_buf) catch return error.InvalidFact;
    const outcome = entity_prop_event.verifyOrigin(allocator, ev) catch |err| return err;
    if (outcome != .verified) return error.InvalidSignature;
}

fn validateCredentialValue(key: []const u8, value: []const u8) Error!void {
    const device_id = key[e2ee_policy.device_prop_prefix.len..];
    const separator = std.mem.indexOfScalar(u8, value, ':') orelse return error.InvalidCredential;
    if (separator == 0 or separator + 1 >= value.len) return error.InvalidCredential;
    const algorithm = value[0..separator];
    const public_key = value[separator + 1 ..];
    // PROP keys are deliberately ASCII-folded before reaching DPROP1. The
    // stored-boundary validator preserves exact ODD1 payload validation while
    // matching that folded key to its mixed-case base64url-derived wire id.
    e2ee_policy.validateStoredAdvertisement(device_id, algorithm, public_key) catch
        return error.InvalidCredential;
    var canonical_buf: [e2ee_policy.max_device_value_len]u8 = undefined;
    const canonical = e2ee_policy.deviceValue(algorithm, public_key, &canonical_buf) orelse return error.InvalidCredential;
    if (!std.mem.eql(u8, canonical, value)) return error.InvalidCredential;
}

fn validOwner(owner: []const u8) bool {
    if (owner.len == 0 or owner.len > entity_prop_event.max_owner_len) return false;
    for (owner) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ':' or byte == ';') return false;
    }
    return true;
}

fn compareKey(a_account: []const u8, a_key: []const u8, b_account: []const u8, b_key: []const u8) std.math.Order {
    const account_order = std.mem.order(u8, a_account, b_account);
    if (account_order != .eq) return account_order;
    return std.mem.order(u8, a_key, b_key);
}

fn accountFactCount(facts: []const OwnedFact, account: []const u8) usize {
    var count: usize = 0;
    for (facts) |fact| {
        if (std.mem.eql(u8, fact.entity, account)) count += 1;
    }
    return count;
}

fn lowerBound(facts: []const OwnedFact, account: []const u8, key: []const u8) usize {
    var lo: usize = 0;
    var hi = facts.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (compareKey(facts[mid].entity, facts[mid].key, account, key) == .lt) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn sameKey(fact: *const OwnedFact, account: []const u8, key: []const u8) bool {
    return std.mem.eql(u8, fact.entity, account) and std.mem.eql(u8, fact.key, key);
}

fn compareRevision(a_hlc: u64, b_hlc: u64) std.math.Order {
    // DPROP1's frozen clock is HLC-only. An equal HLC is never resolved by
    // origin-node tie breaking: byte-identical facts replay, while any byte
    // difference (including origin/signature) is an equivocation.
    if (a_hlc < b_hlc) return .lt;
    if (a_hlc > b_hlc) return .gt;
    return .eq;
}

fn sameEvent(a: entity_prop_event.EntityPropEvent, b: entity_prop_event.EntityPropEvent) bool {
    var a_buf: [max_event_wire_len]u8 = undefined;
    var b_buf: [max_event_wire_len]u8 = undefined;
    const a_wire = canonicalEvent(a, &a_buf) catch return false;
    const b_wire = canonicalEvent(b, &b_buf) catch return false;
    return std.mem.eql(u8, a_wire, b_wire);
}

fn deinitFacts(allocator: std.mem.Allocator, facts: *std.ArrayListUnmanaged(OwnedFact)) void {
    for (facts.items) |*fact| fact.deinit(allocator);
    facts.deinit(allocator);
}

fn checksum(envelope_without_checksum: []const u8, out: []u8) void {
    std.debug.assert(out.len >= checksum_len);
    var h = Blake3.init(.{});
    h.update(checksum_domain);
    h.update(&[_]u8{0});
    h.update(envelope_without_checksum);
    h.final(out[0..checksum_len]);
}

fn reframeWires(allocator: std.mem.Allocator, wires: []const []const u8) ![]u8 {
    if (wires.len > max_facts) return error.CapacityExceeded;
    var total: usize = header_len + trailer_len;
    for (wires) |wire| total = try std.math.add(usize, total, 4 + wire.len);
    if (total > max_snapshot_bytes) return error.BoundsExceeded;
    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);
    @memcpy(out[0..magic.len], magic);
    out[magic.len] = version;
    std.mem.writeInt(u32, out[magic.len + 1 ..][0..4], @intCast(wires.len), .little);
    var offset: usize = header_len;
    for (wires) |wire| {
        std.mem.writeInt(u32, out[offset..][0..4], @intCast(wire.len), .little);
        offset += 4;
        @memcpy(out[offset..][0..wire.len], wire);
        offset += wire.len;
    }
    var checksum_bytes: [checksum_len]u8 = undefined;
    checksum(out[0..offset], &checksum_bytes);
    @memcpy(out[offset..], &checksum_bytes);
    return out;
}

fn testKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

fn testOrigin(seed_byte: u8) !u64 {
    const kp = try testKeyPair(seed_byte);
    return entity_prop_event.originShortId(kp.public_key);
}

fn signedEvent(seed_byte: u8, account: []const u8, key: []const u8, hlc: u64, present: bool, value: []const u8) !entity_prop_event.EntityPropEvent {
    const kp = try testKeyPair(seed_byte);
    const public_key = kp.public_key;
    const origin = entity_prop_event.originShortId(public_key);
    var ev = entity_prop_event.EntityPropEvent{
        .present = present,
        .kind = .user,
        .origin_node = origin,
        .hlc = hlc,
        .entity = account,
        .key = key,
        .value = value,
        .owner = "local",
    };
    const transcript = try entity_prop_event.originTranscript(std.testing.allocator, ev);
    defer std.testing.allocator.free(transcript);
    const sig = try kp.signCtx(entity_prop_event.sign_domain, transcript);
    // Test backing is intentionally leaked to the caller's test arena only for
    // the duration of this helper; callers copy into State immediately.
    const pk = try std.testing.allocator.dupe(u8, &public_key);
    const signature = try std.testing.allocator.dupe(u8, &sig);
    ev.origin_pubkey = pk;
    ev.origin_sig = signature;
    return ev;
}

test "DPROP1 empty image has deterministic framing and KAT" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = 1 });
    defer state.deinit();
    const image = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(image);
    try std.testing.expectEqual(@as(usize, header_len + trailer_len), image.len);
    try std.testing.expectEqualStrings("DPROP1", image[0..6]);
    try std.testing.expectEqual(@as(u8, 1), image[6]);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, image[7..11], .little));
    const expected_hex = "4450524f5031010000000095d016941c6786187cbd0e2dc0a48c9177e78c6217cd4f5f7c58af76838a3a0e";
    var image_fixed: [header_len + trailer_len]u8 = undefined;
    @memcpy(&image_fixed, image);
    try std.testing.expectEqualStrings(expected_hex, &std.fmt.bytesToHex(image_fixed, .lower));
}

test "DPROP1 empty state exposes exact immutable local origin" {
    const local_origin_node: u64 = 0x1020_3040_5060_7080;
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = local_origin_node });
    defer state.deinit();

    try std.testing.expectEqual(@as(usize, 0), state.count());
    try std.testing.expectEqual(local_origin_node, state.localOriginNode());
}

test "DPROP1 integration API exposes exact store bounds and bounded factAt" {
    try std.testing.expectEqualStrings("dprop1:snapshot", store_key);
    try std.testing.expectEqual(@as(usize, 8_388_633), max_store_payload_bytes);
    try std.testing.expectEqual(@as(usize, 8_388_641), max_store_wal_record_bytes);
    try std.testing.expectEqual(@as(usize, 10 + store_key.len + max_snapshot_bytes), max_store_payload_bytes);
    try std.testing.expectEqual(@as(usize, 8 + max_store_payload_bytes), max_store_wal_record_bytes);

    const event = try signedEvent(0x17, "alice", "e2ee.device.phone", 7, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(event.origin_pubkey);
    defer std.testing.allocator.free(event.origin_sig);
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    defer state.deinit();
    try std.testing.expect(state.factAt(0) == null);

    var prepared = try state.prepare(event);
    switch (prepared) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }

    const view = state.factAt(0) orelse return error.TestUnexpectedResult;
    try std.testing.expect(view.present);
    try std.testing.expectEqual(@as(u64, 7), view.hlc);
    try std.testing.expectEqualStrings("alice", view.entity);
    try std.testing.expectEqualStrings("e2ee.device.phone", view.key);
    try std.testing.expectEqualStrings("mls-x25519:abcd+/=", view.value);
    try std.testing.expect(state.factAt(1) == null);
    try std.testing.expect(state.factAt(std.math.maxInt(usize)) == null);
}

test "DPROP1 signed facts round-trip sorted and restore max HLC" {
    const first = try signedEvent(0x11, "alice", "e2ee.device.phone", 10, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(first.origin_pubkey);
    defer std.testing.allocator.free(first.origin_sig);
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = first.origin_node });
    defer state.deinit();
    var prepared = try state.prepare(first);
    switch (prepared) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const second = try signedEvent(0x11, "alice", "e2ee.device.laptop", 11, true, "mls-x25519:efgh+/=");
    defer std.testing.allocator.free(second.origin_pubkey);
    defer std.testing.allocator.free(second.origin_sig);
    var prepared2 = try state.prepare(second);
    switch (prepared2) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const image = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(image);
    var restored = try decode(std.testing.allocator, .{ .local_origin_node = first.origin_node }, image);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.count());
    try std.testing.expectEqual(@as(u64, 11), restored.maxHlc());
    try std.testing.expectEqualStrings("mls-x25519:efgh+/=", restored.get("alice", "e2ee.device.laptop").?.value);
}

test "DPROP1 validates legacy and folded stored-key ODD1 device material" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0x61) });
    defer state.deinit();

    const odd1_value = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}:{s}",
        .{ e2ee_device_directory.stored_algorithm, e2ee_device_directory.kat_wire },
    );
    defer std.testing.allocator.free(odd1_value);
    // The PROP store folds this key; the mixed-case canonical wire id was
    // already checked before that projection was created.
    const odd_event = try signedEvent(0x61, "alice", "e2ee.device.ogc1-mpeycfzdqv8bz2wubf_ukd", 12, true, odd1_value);
    defer std.testing.allocator.free(odd_event.origin_pubkey);
    defer std.testing.allocator.free(odd_event.origin_sig);
    var odd_prepare = try state.prepare(odd_event);
    switch (odd_prepare) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 1), state.count());

    const unrelated_odd = try signedEvent(0x61, "alice", "e2ee.device.ogc1-aaaaaaaaaaaaaaaaaaaaaa", 13, true, odd1_value);
    defer std.testing.allocator.free(unrelated_odd.origin_pubkey);
    defer std.testing.allocator.free(unrelated_odd.origin_sig);
    try std.testing.expectError(error.InvalidCredential, state.prepare(unrelated_odd));

    const invalid_legacy = try signedEvent(0x61, "alice", "e2ee.device.bad", 14, true, "mls-x25519:not canonical");
    defer std.testing.allocator.free(invalid_legacy.origin_pubkey);
    defer std.testing.allocator.free(invalid_legacy.origin_sig);
    try std.testing.expectError(error.InvalidCredential, state.prepare(invalid_legacy));
}

test "DPROP1 LWW stale replay and equivocation outcomes" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0x31) });
    defer state.deinit();
    const base = try signedEvent(0x31, "alice", "e2ee.device.phone", 20, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(base.origin_pubkey);
    defer std.testing.allocator.free(base.origin_sig);
    var p = try state.prepare(base);
    switch (p) {
        .update => |*u| {
            defer u.deinit();
            u.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const replay = try state.prepare(base);
    try std.testing.expect(replay == .replay);
    const stale = try signedEvent(0x31, "alice", "e2ee.device.phone", 19, true, "mls-x25519:old+/=");
    defer std.testing.allocator.free(stale.origin_pubkey);
    defer std.testing.allocator.free(stale.origin_sig);
    const stale_result = try state.prepare(stale);
    try std.testing.expect(stale_result == .stale);
    const equiv = try signedEvent(0x31, "alice", "e2ee.device.phone", 20, true, "mls-x25519:different+/=");
    defer std.testing.allocator.free(equiv.origin_pubkey);
    defer std.testing.allocator.free(equiv.origin_sig);
    const equiv_result = try state.prepare(equiv);
    try std.testing.expect(equiv_result == .equivocation);
    const foreign = try signedEvent(0x32, "alice", "e2ee.device.phone", 20, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(foreign.origin_pubkey);
    defer std.testing.allocator.free(foreign.origin_sig);
    try std.testing.expectError(error.InvalidOrigin, state.prepare(foreign));
}

test "DPROP1 tombstone replaces and rejects nonempty delete" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0x41) });
    defer state.deinit();
    const put = try signedEvent(0x41, "alice", "e2ee.device.phone", 30, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(put.origin_pubkey);
    defer std.testing.allocator.free(put.origin_sig);
    var p = try state.prepare(put);
    switch (p) {
        .update => |*u| {
            defer u.deinit();
            u.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const del = try signedEvent(0x41, "alice", "e2ee.device.phone", 31, false, "");
    defer std.testing.allocator.free(del.origin_pubkey);
    defer std.testing.allocator.free(del.origin_sig);
    var d = try state.prepare(del);
    switch (d) {
        .update => |*u| {
            defer u.deinit();
            u.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!state.get("alice", "e2ee.device.phone").?.present);
    var bad = del;
    bad.value = "not-empty";
    try std.testing.expectError(error.InvalidTombstone, state.prepare(bad));
}

test "DPROP1 malformed prefix trailing checksum and canonical inputs fail closed" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = 1 });
    defer state.deinit();
    const image = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(image);
    var bad_magic = try std.testing.allocator.dupe(u8, image);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] = 'X';
    try std.testing.expectError(error.BadMagic, decode(std.testing.allocator, .{ .local_origin_node = 1 }, bad_magic));
    var bad_checksum = try std.testing.allocator.dupe(u8, image);
    defer std.testing.allocator.free(bad_checksum);
    bad_checksum[bad_checksum.len - 1] ^= 1;
    try std.testing.expectError(error.BadChecksum, decode(std.testing.allocator, .{ .local_origin_node = 1 }, bad_checksum));
    try std.testing.expectError(error.Truncated, decode(std.testing.allocator, .{ .local_origin_node = 1 }, image[0 .. image.len - 1]));
}

test "DPROP1 rejects noncredential namespace and unsigned event" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = 1 });
    defer state.deinit();
    const bad = entity_prop_event.EntityPropEvent{
        .present = true,
        .kind = .user,
        .origin_node = 1,
        .hlc = 1,
        .entity = "alice",
        .key = "STATUS",
        .value = "x",
        .owner = "local",
    };
    try std.testing.expectError(error.InvalidNamespace, state.prepare(bad));
}

test "DPROP1 prepared update is invisible until commit and abort is exact" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0x71) });
    defer state.deinit();
    const event = try signedEvent(0x71, "alice", "e2ee.device.phone", 41, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(event.origin_pubkey);
    defer std.testing.allocator.free(event.origin_sig);
    var prepared = try state.prepare(event);
    switch (prepared) {
        .update => |*update| {
            defer update.deinit();
            var copied = update.*;
            try std.testing.expectEqual(@as(usize, 0), state.count());
            try std.testing.expect(state.get("alice", "e2ee.device.phone") == null);
            try std.testing.expect(copied.snapshot().len > 0);
            try std.testing.expectError(error.PreparedMutationActive, state.prepare(event));
            update.abort();
            copied.commitInto(&state);
            copied.deinit();
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), state.count());
    var second = try state.prepare(event);
    switch (second) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), state.count());
    try std.testing.expectEqual(@as(u64, 41), state.maxHlc());

    var doomed = try State.init(std.testing.allocator, .{ .local_origin_node = event.origin_node });
    var outstanding = try doomed.prepare(event);
    switch (outstanding) {
        .update => |*update| {
            var copied = update.*;
            doomed.deinit();
            try std.testing.expectEqual(@as(usize, 0), copied.snapshot().len);
            copied.abort();
            copied.deinit();
            update.deinit();
        },
        else => return error.TestUnexpectedResult,
    }
}

test "DPROP1 decoder rejects duplicate, unsorted, proper-prefix, and trailing records" {
    const first = try signedEvent(0x81, "alice", "e2ee.device.phone", 51, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(first.origin_pubkey);
    defer std.testing.allocator.free(first.origin_sig);
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = first.origin_node });
    defer state.deinit();
    var p1 = try state.prepare(first);
    switch (p1) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const second = try signedEvent(0x81, "alice", "e2ee.device.tablet", 52, true, "mls-x25519:efgh+/=");
    defer std.testing.allocator.free(second.origin_pubkey);
    defer std.testing.allocator.free(second.origin_sig);
    var p2 = try state.prepare(second);
    switch (p2) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const canonical_image = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(canonical_image);
    const body_end = canonical_image.len - trailer_len;
    var offset = header_len;
    const first_len = std.mem.readInt(u32, canonical_image[offset..][0..4], .little);
    offset += 4 + @as(usize, @intCast(first_len));
    const second_len = std.mem.readInt(u32, canonical_image[offset..][0..4], .little);
    const second_start = offset + 4;
    const first_wire = canonical_image[header_len + 4 ..][0..@intCast(first_len)];
    const second_wire = canonical_image[second_start..][0..@intCast(second_len)];
    const duplicate = try reframeWires(std.testing.allocator, &.{ first_wire, first_wire });
    defer std.testing.allocator.free(duplicate);
    try std.testing.expectError(error.NonCanonical, decode(std.testing.allocator, .{ .local_origin_node = first.origin_node }, duplicate));
    const unsorted = try reframeWires(std.testing.allocator, &.{ second_wire, first_wire });
    defer std.testing.allocator.free(unsorted);
    try std.testing.expectError(error.NonCanonical, decode(std.testing.allocator, .{ .local_origin_node = first.origin_node }, unsorted));
    var trailing = try std.testing.allocator.alloc(u8, body_end + 1 + trailer_len);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..body_end], canonical_image[0..body_end]);
    trailing[body_end] = 0;
    checksum(trailing[0 .. body_end + 1], trailing[body_end + 1 ..][0..trailer_len]);
    try std.testing.expectError(error.TrailingBytes, decode(std.testing.allocator, .{ .local_origin_node = first.origin_node }, trailing));
    try std.testing.expectError(error.Truncated, decode(std.testing.allocator, .{ .local_origin_node = first.origin_node }, canonical_image[0 .. canonical_image.len - 1]));
}

test "DPROP1 decoder enforces count bound before body allocation" {
    var image: [header_len + trailer_len]u8 = undefined;
    @memcpy(image[0..magic.len], magic);
    image[magic.len] = version;
    std.mem.writeInt(u32, image[magic.len + 1 ..][0..4], @intCast(max_facts + 1), .little);
    checksum(image[0..header_len], image[header_len..]);
    try std.testing.expectError(error.CapacityExceeded, decode(std.testing.allocator, .{ .local_origin_node = 1 }, &image));
}

test "DPROP1 enforces the per-account cap but permits replacement at cap" {
    const local_origin_node = try testOrigin(0xd1);
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = local_origin_node });
    defer state.deinit();

    var index: usize = 0;
    while (index < max_facts_per_account) : (index += 1) {
        const key = try std.fmt.allocPrint(std.testing.allocator, "e2ee.device.d{d}", .{index});
        defer std.testing.allocator.free(key);
        const event = try signedEvent(0xd1, "alice", key, 200 + index, true, "mls-x25519:abcd+/=");
        defer std.testing.allocator.free(event.origin_pubkey);
        defer std.testing.allocator.free(event.origin_sig);
        var prepared = try state.prepare(event);
        switch (prepared) {
            .update => |*update| {
                defer update.deinit();
                update.commitInto(&state);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(max_facts_per_account, state.count());

    const new_key = "e2ee.device.d64";
    const over_cap = try signedEvent(0xd1, "alice", new_key, 300, true, "mls-x25519:efgh+/=");
    defer std.testing.allocator.free(over_cap.origin_pubkey);
    defer std.testing.allocator.free(over_cap.origin_sig);
    try std.testing.expectError(error.CapacityExceeded, state.prepare(over_cap));

    const replacement = try signedEvent(0xd1, "alice", "e2ee.device.d0", 301, true, "mls-x25519:efgh+/=");
    defer std.testing.allocator.free(replacement.origin_pubkey);
    defer std.testing.allocator.free(replacement.origin_sig);
    var replacement_prepared = try state.prepare(replacement);
    switch (replacement_prepared) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(max_facts_per_account, state.count());
    try std.testing.expectEqualStrings("mls-x25519:efgh+/=", state.get("alice", "e2ee.device.d0").?.value);

    const image = try encode(std.testing.allocator, &state);
    defer std.testing.allocator.free(image);
    var restored = try decode(std.testing.allocator, .{ .local_origin_node = local_origin_node }, image);
    defer restored.deinit();
    try std.testing.expectEqual(max_facts_per_account, restored.count());
    try std.testing.expectEqualStrings("mls-x25519:efgh+/=", restored.get("alice", "e2ee.device.d0").?.value);
}

test "DPROP1 rejects zero local-origin configuration" {
    try std.testing.expectError(error.InvalidAuthorityConfig, State.init(std.testing.allocator, .{ .local_origin_node = 0 }));
    var valid = try State.init(std.testing.allocator, .{ .local_origin_node = 1 });
    defer valid.deinit();
    const image = try encode(std.testing.allocator, &valid);
    defer std.testing.allocator.free(image);
    try std.testing.expectError(error.InvalidAuthorityConfig, decode(std.testing.allocator, .{ .local_origin_node = 0 }, image));
}

test "DPROP1 tombstones prevent stale resurrection and reject foreign origin" {
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0xa1) });
    defer state.deinit();
    const put = try signedEvent(0xa1, "alice", "e2ee.device.phone", 70, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(put.origin_pubkey);
    defer std.testing.allocator.free(put.origin_sig);
    var first = try state.prepare(put);
    switch (first) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const tomb = try signedEvent(0xa1, "alice", "e2ee.device.phone", 71, false, "");
    defer std.testing.allocator.free(tomb.origin_pubkey);
    defer std.testing.allocator.free(tomb.origin_sig);
    var second = try state.prepare(tomb);
    switch (second) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&state);
        },
        else => return error.TestUnexpectedResult,
    }
    const stale = try signedEvent(0xa1, "alice", "e2ee.device.phone", 70, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(stale.origin_pubkey);
    defer std.testing.allocator.free(stale.origin_sig);
    try std.testing.expect((try state.prepare(stale)) == .stale);
    const foreign = try signedEvent(0xa2, "alice", "e2ee.device.phone", 72, true, "mls-x25519:foreign+/=");
    defer std.testing.allocator.free(foreign.origin_pubkey);
    defer std.testing.allocator.free(foreign.origin_sig);
    try std.testing.expectError(error.InvalidOrigin, state.prepare(foreign));
    try std.testing.expect(!state.get("alice", "e2ee.device.phone").?.present);
}

test "DPROP1 signed fact validation is fail-closed for clock account owner origin and tamper" {
    const base = try signedEvent(0xb1, "alice", "e2ee.device.phone", 80, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(base.origin_pubkey);
    defer std.testing.allocator.free(base.origin_sig);
    var state = try State.init(std.testing.allocator, .{ .local_origin_node = base.origin_node });
    defer state.deinit();
    var bad_clock = base;
    bad_clock.hlc = 0;
    try std.testing.expectError(error.InvalidClock, state.prepare(bad_clock));
    var bad_account = base;
    bad_account.entity = "Alice";
    try std.testing.expectError(error.InvalidAccount, state.prepare(bad_account));
    var bad_owner = base;
    bad_owner.owner = "bad owner";
    try std.testing.expectError(error.InvalidOwner, state.prepare(bad_owner));
    var bad_origin = base;
    bad_origin.origin_node +%= 1;
    try std.testing.expectError(error.InvalidOrigin, state.prepare(bad_origin));
    var tampered = base;
    tampered.value = "mls-x25519:tampered+/=";
    try std.testing.expectError(error.InvalidSignature, state.prepare(tampered));
}

test "DPROP1 decode is allocation-failure atomic" {
    var source = try State.init(std.testing.allocator, .{ .local_origin_node = try testOrigin(0xc1) });
    defer source.deinit();
    const event = try signedEvent(0xc1, "alice", "e2ee.device.phone", 90, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(event.origin_pubkey);
    defer std.testing.allocator.free(event.origin_sig);
    var prepared = try source.prepare(event);
    switch (prepared) {
        .update => |*update| {
            defer update.deinit();
            update.commitInto(&source);
        },
        else => return error.TestUnexpectedResult,
    }
    const image = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(image);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) anyerror!void {
            var state = decode(allocator, .{ .local_origin_node = try testOrigin(0xc1) }, bytes) catch |err| return err;
            defer state.deinit();
            try std.testing.expectEqual(@as(usize, 1), state.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{image});
}

test "DPROP1 prepare is allocation-failure atomic" {
    const event = try signedEvent(0x91, "alice", "e2ee.device.phone", 61, true, "mls-x25519:abcd+/=");
    defer std.testing.allocator.free(event.origin_pubkey);
    defer std.testing.allocator.free(event.origin_sig);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, ev: entity_prop_event.EntityPropEvent) anyerror!void {
            var state = try State.init(allocator, .{ .local_origin_node = ev.origin_node });
            defer state.deinit();
            var result = state.prepare(ev) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(@as(usize, 0), state.count());
                try std.testing.expect(!state.prepared_active);
                return err;
            };
            switch (result) {
                .update => |*update| {
                    defer update.deinit();
                    update.commitInto(&state);
                },
                else => return error.TestUnexpectedResult,
            }
            try std.testing.expectEqual(@as(usize, 1), state.count());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{event});
}
