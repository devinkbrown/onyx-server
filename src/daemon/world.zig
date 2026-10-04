// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-server chat world state.
//!
//! This module intentionally models only local daemon state: nick ownership,
//! channel membership, and channel topics. It has no S2S/CRDT responsibilities.
const std = @import("std");
const rwlock = @import("../substrate/rwlock.zig");
const ebr = @import("../substrate/ebr.zig");
const world_rcu = @import("world_rcu.zig");

/// Lazily-created RCU mirror of the nick registry (the lock-free read path).
/// Heap-allocated so the EBR domain has a stable address: registered writer and
/// per-thread reader participants plus the registry's borrowed `&domain` must
/// stay valid after the owning `World` is moved (World.init returns by value).
/// Activated lazily and, once live, drives EVERY nick read (`findNick`) and collision check — the read
/// hot path is lock-free at the registry level and case-insensitive (RFC1459-ish
/// ASCII casemapping; "Alice" and "alice" are the same nick). `client_nicks`
/// remains the authoritative id->nick reverse index; the RCU registry is
/// authoritative for nick->id.
const RcuNickState = struct {
    domain: ebr.Domain,
    generation: usize,
    /// Writer-side participant used for CoW publish/retire. Readers must never
    /// share it; they use a per-thread participant from `rcuReaderParticipant`.
    writer_participant: *ebr.Participant,
    nicks: world_rcu.NickRegistry,
};

/// Marker value stored in the RCU channel-existence mirror. The mirror only
/// answers "does this channel name exist?" (lock-free, case-insensitive); the
/// authoritative `Channel` records live in `World.channels`. We store the
/// channel OID as a witness so the value type is a plain integer (no dangling
/// pointer into the rehash-prone `channels` map).
const RcuChannelState = struct {
    domain: ebr.Domain,
    generation: usize,
    /// Writer-side participant used for CoW publish/retire. Readers must never
    /// share it; they use a per-thread participant from `rcuReaderParticipant`.
    writer_participant: *ebr.Participant,
    /// channel name -> OID witness (existence set).
    names: world_rcu.ChannelRegistry(u32),
    /// One membership set per live channel, keyed by case-folded channel name.
    /// The MembershipSet values are heap-allocated for stable addresses (the
    /// AutoHashMap may rehash). All share the same EBR `domain`; writers use
    /// `writer_participant`, and readers use per-thread participants.
    members: std.StringHashMapUnmanaged(*world_rcu.MembershipSet) = .empty,
};

const rcu_tls_slot_count: usize = ebr.max_participants;

const RcuTlsEntry = struct {
    domain: ?*ebr.Domain = null,
    generation: usize = 0,
    participant: ?*ebr.Participant = null,
};

threadlocal var rcu_tls_entries: [rcu_tls_slot_count]RcuTlsEntry = @splat(.{});
var rcu_generation = std.atomic.Value(usize).init(1);

fn nextRcuGeneration() usize {
    return rcu_generation.fetchAdd(1, .monotonic);
}

fn rcuReaderParticipant(domain: *ebr.Domain, generation: usize) ebr.RegisterError!*ebr.Participant {
    var free_slot: ?usize = null;
    for (&rcu_tls_entries, 0..) |*entry, i| {
        if (entry.participant) |p| {
            if (entry.domain == domain and entry.generation == generation) return p;
        } else if (free_slot == null) {
            free_slot = i;
        }
    }

    const idx = free_slot orelse return error.TooManyParticipants;
    const p = try domain.register();
    rcu_tls_entries[idx] = .{
        .domain = domain,
        .generation = generation,
        .participant = p,
    };
    return p;
}

fn rcuForgetThreadParticipants(domain: *ebr.Domain, generation: usize) void {
    for (&rcu_tls_entries) |*entry| {
        if (entry.participant) |p| {
            if (entry.domain == domain and entry.generation == generation) {
                p.unregister();
                entry.* = .{};
            }
        }
    }
}

/// Opaque client handle value used by the local server world.
pub const ClientId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: ClientId = .{
        .shard = std.math.maxInt(u12),
        .slot = std.math.maxInt(u20),
        .gen = std.math.maxInt(u32),
    };

    pub fn eql(self: ClientId, other: ClientId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }
};

fn clientIdInSet(client: ClientId, clients: []const ClientId) bool {
    for (clients) |candidate| {
        if (client.eql(candidate)) return true;
    }
    return false;
}

pub const WorldError = std.mem.Allocator.Error || error{
    NickInUse,
    InvalidOwnerSet,
    InvalidUnion,
    InvalidGraph,
    NoSuchChannel,
    NotOnChannel,
    NoSuchNick,
    UnsupportedMode,
    InvalidMask,
    /// A channel list mode (+b/+e/+I/+Z) is at its `max_list_entries` cap.
    ListFull,
};

pub const MessageTarget = union(enum) {
    channel: []const u8,
    nick: ClientId,
};

/// ASCII case-insensitive hash-map context for `[]const u8` keys, matching the
/// RCU registries' `CaseInsensitiveBytesContext`. Used for the authoritative
/// `channels` map so that channel-name lookups (`getPtr`/`get`/`contains`) agree
/// with the case-insensitive RCU existence/membership mirrors — JOIN "#Room"
/// then PART "#room" must hit the same channel.
const CiStringContext = struct {
    pub fn hash(_: CiStringContext, key: []const u8) u64 {
        var h = std.hash.Wyhash.init(0);
        for (key) |c| {
            const lc = std.ascii.toLower(c);
            h.update(std.mem.asBytes(&lc));
        }
        return h.final();
    }
    pub fn eql(_: CiStringContext, a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
        }
        return true;
    }
};

/// Case-insensitive `[]const u8`-keyed hash map (channel names).
fn CiStringHashMap(comptime V: type) type {
    return std.HashMap([]const u8, V, CiStringContext, std.hash_map.default_max_load_percentage);
}

const chanmode = @import("chanmode.zig");
const chanmode_ext = @import("../proto/chanmode_ext.zig");
const listx = @import("../proto/listx.zig");
const extban = @import("../proto/extban.zig");

/// Per-member channel status modes (op @, voice + — no halfop) keyed by client.
const MemberMap = std.AutoHashMap(ClientId, chanmode.MemberModes);
const InviteMap = std.AutoHashMapUnmanaged(ClientId, void);
pub const MemberIterator = MemberMap.KeyIterator;
pub const MemberMode = chanmode.MemberMode;
pub const MemberModes = chanmode.MemberModes;
pub const ChannelMode = chanmode.ChannelMode;

/// One exact per-channel membership image for `restoreMembersBatchExisting`.
/// Channel names borrow caller storage for the duration of the call.
pub const MemberRestore = struct {
    channel: []const u8,
    modes: MemberModes,
};

const Channel = struct {
    allocator: std.mem.Allocator,
    members: MemberMap,
    topic: ?[]u8 = null,
    topic_setter: ?[]u8 = null,
    topic_time: i64 = 0,
    /// Channel-level flag modes (i/m/n/t/s).
    modes: chanmode.ChannelModes = chanmode.ChannelModes.empty(),
    /// +k key — allocator-owned heap (safe across HashMap rehash; never a
    /// self-slice). Null = no key.
    key: ?[]u8 = null,
    /// +l member limit. Null = unlimited.
    limit: ?u32 = null,
    /// +b ban masks (nick!user@host globs), allocator-owned with setter metadata.
    bans: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +e ban-exception masks: a match here overrides a +b ban on JOIN.
    exempts: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +I invite-exception masks: a match here lets a user bypass +i on JOIN.
    invex: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +Z quiet (MUTE) masks: a match suppresses *speech* (not join), like a
    /// ban that only mutes. Honors +e exempts.
    mutes: std.ArrayListUnmanaged(ListEntry) = .empty,
    /// +j join throttle: at most `throttle_joins` joins per `throttle_secs`
    /// window (0 = disabled). `throttle_times` is a bounded ring of recent
    /// successful join timestamps (ms) used to enforce the window.
    throttle_joins: u16 = 0,
    throttle_secs: u32 = 0,
    throttle_times: std.ArrayListUnmanaged(i64) = .empty,
    /// Last time (ms) a join-throttle denial raised a raid alert on this channel.
    /// Rate-limits the oper alert to one per throttle window so a sustained raid
    /// does not spam the Event Spine. 0 = never alerted.
    throttle_alert_ms: i64 = 0,
    /// Pending invitations (INVITE) that satisfy +i, by client id.
    invites: InviteMap = .empty,
    /// +f forward target: when a join here is refused (+i/+k/+b/+l), the user is
    /// redirected to JOIN this channel instead. Allocator-owned; null = no forward.
    forward: ?[]u8 = null,
    /// +p private (shown but flagged) and +h IRCX HIDDEN (omitted from LIST).
    private: bool = false,
    hidden: bool = false,
    /// IRCX extended channel flags (AUTHONLY/AUDITORIUM/NOWHISPER/etc.) that have
    /// no slot in the base ChannelModes letter set.
    ext_modes: chanmode_ext.ExtChannelFlags = chanmode_ext.ExtChannelFlags.empty(),
    /// IRCX object id, assigned once at creation (0 = unset). Surfaced as the
    /// channel OID built-in property.
    oid: u32 = 0,
    /// Unix seconds when the channel was created (0 = unset). Surfaced as the
    /// IRCX CREATION built-in property. Sourced from World.clock_unix.
    created_unix: i64 = 0,

    fn init(allocator: std.mem.Allocator) Channel {
        return .{
            .allocator = allocator,
            .members = MemberMap.init(allocator),
            .modes = defaultChannelModes(),
        };
    }

    fn deinit(self: *Channel) void {
        if (self.topic) |topic| self.allocator.free(topic);
        if (self.topic_setter) |setter| self.allocator.free(setter);
        if (self.key) |k| self.allocator.free(k);
        if (self.forward) |f| self.allocator.free(f);
        for (self.bans.items) |*b| b.deinit(self.allocator);
        self.bans.deinit(self.allocator);
        for (self.exempts.items) |*e| e.deinit(self.allocator);
        self.exempts.deinit(self.allocator);
        for (self.invex.items) |*i| i.deinit(self.allocator);
        self.invex.deinit(self.allocator);
        for (self.mutes.items) |*m| m.deinit(self.allocator);
        self.mutes.deinit(self.allocator);
        self.throttle_times.deinit(self.allocator);
        self.invites.deinit(self.allocator);
        self.members.deinit();
        self.* = undefined;
    }

    fn setTopic(self: *Channel, topic: []const u8, setter: []const u8, set_at: i64) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(owned);
        const owned_setter = try self.allocator.dupe(u8, setter);
        if (self.topic) |old| self.allocator.free(old);
        if (self.topic_setter) |old| self.allocator.free(old);
        self.topic = owned;
        self.topic_setter = owned_setter;
        self.topic_time = set_at;
    }
};

fn defaultChannelModes() chanmode.ChannelModes {
    var modes = chanmode.ChannelModes.empty();
    modes.no_external = true;
    modes.topic_ops = true;
    return modes;
}

const checkpoint_base_mode_mask: u16 = (1 << 14) - 1;
const checkpoint_ext_mode_mask: u32 = (1 << 20) - 1;

fn checkpointBaseModeBits(modes: chanmode.ChannelModes) u16 {
    var bits: u16 = 0;
    if (modes.invite_only) bits |= 1 << 0;
    if (modes.moderated) bits |= 1 << 1;
    if (modes.no_external) bits |= 1 << 2;
    if (modes.topic_ops) bits |= 1 << 3;
    if (modes.secret) bits |= 1 << 4;
    if (modes.no_ctcp) bits |= 1 << 5;
    if (modes.no_notice) bits |= 1 << 6;
    if (modes.no_nick) bits |= 1 << 7;
    if (modes.free_invite) bits |= 1 << 8;
    if (modes.tls_only) bits |= 1 << 9;
    if (modes.mod_reg) bits |= 1 << 10;
    if (modes.news_wire) bits |= 1 << 11;
    if (modes.oper_only) bits |= 1 << 12;
    if (modes.admin_only) bits |= 1 << 13;
    return bits;
}

fn checkpointBaseModes(bits: u16) ?chanmode.ChannelModes {
    if ((bits & ~checkpoint_base_mode_mask) != 0) return null;
    var modes = chanmode.ChannelModes.empty();
    modes.invite_only = (bits & (1 << 0)) != 0;
    modes.moderated = (bits & (1 << 1)) != 0;
    modes.no_external = (bits & (1 << 2)) != 0;
    modes.topic_ops = (bits & (1 << 3)) != 0;
    modes.secret = (bits & (1 << 4)) != 0;
    modes.no_ctcp = (bits & (1 << 5)) != 0;
    modes.no_notice = (bits & (1 << 6)) != 0;
    modes.no_nick = (bits & (1 << 7)) != 0;
    modes.free_invite = (bits & (1 << 8)) != 0;
    modes.tls_only = (bits & (1 << 9)) != 0;
    modes.mod_reg = (bits & (1 << 10)) != 0;
    modes.news_wire = (bits & (1 << 11)) != 0;
    modes.oper_only = (bits & (1 << 12)) != 0;
    modes.admin_only = (bits & (1 << 13)) != 0;
    return modes;
}

pub const ListEntry = struct {
    mask: []u8,
    setter: []u8,
    set_at: i64,

    fn init(allocator: std.mem.Allocator, mask: []const u8, setter: []const u8, set_at: i64) std.mem.Allocator.Error!ListEntry {
        const owned_mask = try allocator.dupe(u8, mask);
        errdefer allocator.free(owned_mask);
        const owned_setter = try allocator.dupe(u8, setter);
        return .{ .mask = owned_mask, .setter = owned_setter, .set_at = set_at };
    }

    fn deinit(self: *ListEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.mask);
        allocator.free(self.setter);
        self.* = undefined;
    }
};

fn deinitListEntries(allocator: std.mem.Allocator, list: *std.ArrayListUnmanaged(ListEntry)) void {
    for (list.items) |*entry| entry.deinit(allocator);
    list.deinit(allocator);
    list.* = .empty;
}

fn restoreCheckpointList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(ListEntry),
    source: []const World.CheckpointListEntry,
) std.mem.Allocator.Error!void {
    try list.ensureTotalCapacity(allocator, source.len);
    for (source) |entry| {
        var owned = try ListEntry.init(allocator, entry.mask, entry.setter, entry.set_at);
        list.appendAssumeCapacity(owned);
        owned = undefined;
    }
}

pub const TopicInfo = struct {
    text: []const u8,
    setter: []const u8,
    set_at: i64,
};

/// Owned local nick/channel registry.
pub const World = struct {
    allocator: std.mem.Allocator,
    /// Per-channel cap on each list mode (+b/+e/+I/+Z); set from config at boot.
    max_list_entries: usize = 100,
    channels: CiStringHashMap(Channel),
    nicks: std.StringHashMap(ClientId),
    client_nicks: std.AutoHashMap(ClientId, []u8),
    /// Monotonic IRCX object-id source. Each newly-created channel gets the next
    /// value; starts at 1 so 0 means "unset" (never a real OID).
    next_oid: u32 = 1,
    /// Current wall-clock time in unix seconds, refreshed by the server before
    /// dispatch so `ensureChannel` can stamp a channel's CREATION time without the
    /// pure world taking a clock dependency. 0 until first set.
    clock_unix: i64 = 0,
    /// Lazily-activated RCU mirror of `nicks` (lock-free reads). Null until the
    /// first `findNickRcu`; once active, `registerNick`/`unregisterNick` keep it
    /// in sync. The authoritative map is still `nicks` — this is the parallel
    /// read path being validated ahead of the live flip (see
    /// docs/planning/24-multithreading.md, world.zig adoption map).
    rcu_nicks: ?*RcuNickState = null,
    rcu_nick_writes_since_advance: usize = 0,
    /// Lazily-activated RCU mirror of channel existence + per-channel membership
    /// (lock-free reads for `channelExists`/`isMember`). Null until the first
    /// channel is created; once active, `ensureChannel`/`removeChannel`/`join`/
    /// `part`/`removeClient` keep it in sync. Case-insensitive end-to-end.
    rcu_channels: ?*RcuChannelState = null,
    rcu_channel_writes_since_advance: usize = 0,
    /// Guards all of the maps above for the multi-reactor model: lookups take the
    /// read lock, mutations (join/part/nick/mode/rename/remove) the write lock.
    /// Every mutation — and its allocation — happens under the exclusive lock, so
    /// the allocator is never touched concurrently; reads are concurrent and
    /// allocation-free. Uncontended with a single reactor (the current default),
    /// so the live single-thread path pays only a couple of atomics. The World
    /// owns the lock so it travels with the data it guards; callers (the reactor
    /// loop) bracket world access with lockRead/lockWrite — see
    /// docs/planning/24-multithreading.md (Phase B).
    lock: rwlock.RwLock = .{},
    // Only opaque handles cross the World boundary; payload custody stays here.
    registered_stages: ?*RegisteredChannelRegistry = null,

    pub fn lockRead(self: *World) void {
        self.lock.lockShared();
    }
    pub fn unlockRead(self: *World) void {
        self.lock.unlockShared();
    }
    pub fn lockWrite(self: *World) void {
        self.lock.lockExclusive();
    }
    pub fn unlockWrite(self: *World) void {
        self.lock.unlockExclusive();
    }

    /// Nick behavior selected by the authority-aware caller. World verifies
    /// exact ownership but deliberately does not infer account/session policy.
    pub const SessionNickDisposition = union(enum) {
        /// Collapse all aliases owned by the exact claimant set onto the
        /// restored nick, with this exact-token client as its sole lookup
        /// owner. This is deliberately separate from the newly-restored
        /// transport that receives memberships.
        claim_exact: ClientId,
        /// Keep an independently-authorized owner of the restored display nick
        /// and remove every alias owned by the exact claimant set.
        preserve_foreign: ClientId,
    };

    /// Fully prepared World half of a logical-session restore. The caller must
    /// hold World's write lock from `prepareSessionRestore` through commit or
    /// abort. Preparation owns every fallible allocation and holds the relevant
    /// RCU writer locks; commit is void and allocation-free.
    pub const PreparedSessionRestore = struct {
        const ExistingMember = struct {
            name: []const u8,
            channel: *Channel,
            set: *world_rcu.MembershipSet,
            modes: MemberModes,
            insert_name: bool,
        };

        /// One claimant membership absent from the exact desired image. Name
        /// and pointers borrow stable World/RCU storage while the caller holds
        /// World's write lock through commit or abort.
        const RemovedMember = struct {
            name: []const u8,
            channel: ?*Channel,
            set: ?*world_rcu.MembershipSet,
            fallback_present: bool,
            rcu_present: bool,
            cleanup_channel: bool,
            remove_name: bool,
        };

        const MemberStage = union(enum) {
            add: world_rcu.MembershipSet.StagedAdd,
            remove: world_rcu.MembershipSet.StagedRemove,

            fn commit(self: *MemberStage) void {
                switch (self.*) {
                    .add => |*stage| stage.commit(),
                    .remove => |*stage| stage.commit(),
                }
            }

            fn abort(self: *MemberStage) void {
                switch (self.*) {
                    .add => |*stage| stage.abort(),
                    .remove => |*stage| stage.abort(),
                }
            }
        };

        const MemberLockPlan = struct {
            set: *world_rcu.MembershipSet,
            action: union(enum) {
                add: usize,
                remove: usize,
            },

            fn lessThan(_: void, a: @This(), b: @This()) bool {
                return @intFromPtr(a.set) < @intFromPtr(b.set);
            }
        };

        const NewChannel = struct {
            owned_name: []u8,
            folded_name: []u8,
            channel: Channel,
            set: *world_rcu.MembershipSet,
            oid: u32,
            insert_name: bool,

            fn init(
                allocator: std.mem.Allocator,
                c: *RcuChannelState,
                name: []const u8,
                restore_client: ClientId,
                modes: MemberModes,
                oid: u32,
                created_unix: i64,
                insert_name: bool,
            ) !NewChannel {
                const owned_name = try allocator.dupe(u8, name);
                errdefer allocator.free(owned_name);
                var folded_buf: [foldBufLen]u8 = undefined;
                const folded_name = try allocator.dupe(u8, foldName(name, &folded_buf));
                errdefer allocator.free(folded_name);
                var channel = Channel.init(allocator);
                errdefer channel.deinit();
                try channel.members.put(restore_client, modes);
                channel.oid = oid;
                channel.created_unix = created_unix;
                const set = try allocator.create(world_rcu.MembershipSet);
                errdefer allocator.destroy(set);
                set.* = try world_rcu.MembershipSet.initWithOne(allocator, &c.domain, @bitCast(restore_client));
                return .{
                    .owned_name = owned_name,
                    .folded_name = folded_name,
                    .channel = channel,
                    .set = set,
                    .oid = oid,
                    .insert_name = insert_name,
                };
            }

            fn deinit(self: *NewChannel, allocator: std.mem.Allocator) void {
                self.channel.deinit();
                self.set.deinit();
                allocator.destroy(self.set);
                allocator.free(self.folded_name);
                allocator.free(self.owned_name);
            }
        };

        /// A fallback-backed desired channel whose RCU membership set was lost.
        /// The complete fallback image is rebuilt off-map and pointer-moved at
        /// commit, so preparation remains inert and allocation failure cannot
        /// publish a partial set.
        const RebuiltSet = struct {
            folded_name: []u8,
            set: *world_rcu.MembershipSet,

            fn init(
                allocator: std.mem.Allocator,
                c: *RcuChannelState,
                name: []const u8,
                channel: *Channel,
                restore_client: ClientId,
            ) !RebuiltSet {
                var folded_buf: [foldBufLen]u8 = undefined;
                const folded_name = try allocator.dupe(u8, foldName(name, &folded_buf));
                errdefer allocator.free(folded_name);
                const id_count = channel.members.count() + @intFromBool(!channel.members.contains(restore_client));
                const ids = try allocator.alloc(world_rcu.ClientId, id_count);
                defer allocator.free(ids);
                var next: usize = 0;
                var it = channel.members.keyIterator();
                while (it.next()) |id| {
                    ids[next] = @bitCast(id.*);
                    next += 1;
                }
                if (!channel.members.contains(restore_client)) {
                    ids[next] = @bitCast(restore_client);
                    next += 1;
                }
                std.debug.assert(next == ids.len);
                const set = try allocator.create(world_rcu.MembershipSet);
                errdefer allocator.destroy(set);
                set.* = try world_rcu.MembershipSet.initFromSlice(allocator, &c.domain, ids);
                return .{ .folded_name = folded_name, .set = set };
            }

            fn deinit(self: *RebuiltSet, allocator: std.mem.Allocator) void {
                self.set.deinit();
                allocator.destroy(self.set);
                allocator.free(self.folded_name);
            }
        };

        /// A desired channel whose fallback record was lost while its RCU name
        /// and membership set survived. Unknown keeper modes are reconstructed
        /// conservatively empty; only the claimant receives the exact snapshot
        /// modes supplied by the restore capsule.
        const AdoptedChannel = struct {
            owned_name: []u8,
            channel: Channel,
            set: *world_rcu.MembershipSet,

            fn init(
                allocator: std.mem.Allocator,
                c: *RcuChannelState,
                name: []const u8,
                set: *world_rcu.MembershipSet,
                restore_client: ClientId,
                modes: MemberModes,
                oid: u32,
                created_unix: i64,
            ) !AdoptedChannel {
                const owned_name = try allocator.dupe(u8, name);
                errdefer allocator.free(owned_name);
                var channel = Channel.init(allocator);
                errdefer channel.deinit();
                const ids = try allocator.alloc(world_rcu.ClientId, set.count(c.writer_participant));
                defer allocator.free(ids);
                const Collector = struct {
                    ids: []world_rcu.ClientId,
                    next: usize = 0,

                    fn append(ctx: *@This(), id: world_rcu.ClientId) void {
                        ctx.ids[ctx.next] = id;
                        ctx.next += 1;
                    }
                };
                var collector = Collector{ .ids = ids };
                set.iterate(c.writer_participant, &collector, Collector.append);
                std.debug.assert(collector.next == ids.len);
                for (ids) |id| try channel.members.put(@bitCast(id), MemberModes.empty());
                try channel.members.put(restore_client, modes);
                channel.oid = oid;
                channel.created_unix = created_unix;
                return .{ .owned_name = owned_name, .channel = channel, .set = set };
            }

            fn deinit(self: *AdoptedChannel, allocator: std.mem.Allocator) void {
                self.channel.deinit();
                allocator.free(self.owned_name);
            }
        };

        const NickStage = union(enum) {
            claim: world_rcu.NickRegistry.StagedReplaceRemovingValues,
            preserve: world_rcu.NickRegistry.StagedRemoveValuesPreservingKey,

            fn commit(self: *NickStage) void {
                switch (self.*) {
                    .claim => |*stage| stage.commit(),
                    .preserve => |*stage| stage.commit(),
                }
            }

            fn abort(self: *NickStage) void {
                switch (self.*) {
                    .claim => |*stage| stage.abort(),
                    .preserve => |*stage| stage.abort(),
                }
            }
        };

        world: *World,
        restore_client: ClientId,
        disposition: SessionNickDisposition,
        exact_clients: []ClientId,
        owned_target: []u8,
        nick_rcu: *RcuNickState,
        owns_nick_rcu: bool,
        nick_stage: ?NickStage = null,
        channel_rcu: ?*RcuChannelState = null,
        owns_channel_rcu: bool = false,
        channel_name_stage: ?world_rcu.ChannelRegistry(u32).StagedEditBatch = null,
        existing_members: []ExistingMember,
        existing_count: usize = 0,
        removed_members: []RemovedMember,
        removed_count: usize = 0,
        member_stages: []MemberStage,
        member_stage_count: usize = 0,
        member_reservation: ?*ebr.Participant.RetireReservation = null,
        new_channels: []NewChannel,
        new_count: usize = 0,
        rebuilt_sets: []RebuiltSet,
        rebuilt_count: usize = 0,
        adopted_channels: []AdoptedChannel,
        adopted_count: usize = 0,
        next_oid_after: u32,
        active: bool = true,

        /// Discard every staged snapshot and off-map record. Calling abort
        /// after commit is harmless, which makes `defer prepared.abort()` safe.
        pub fn abort(self: *PreparedSessionRestore) void {
            if (!self.active) return;
            // Reverse the global acquisition order: nick registry -> sorted
            // membership sets -> channel registry.
            if (self.channel_name_stage) |*stage| stage.abort();
            while (self.member_stage_count != 0) {
                self.member_stage_count -= 1;
                self.member_stages[self.member_stage_count].abort();
            }
            if (self.member_reservation) |reservation| {
                reservation.finish();
                self.world.allocator.destroy(reservation);
                self.member_reservation = null;
            }
            if (self.nick_stage) |*stage| stage.abort();
            for (self.new_channels[0..self.new_count]) |*new_channel|
                new_channel.deinit(self.world.allocator);
            for (self.adopted_channels[0..self.adopted_count]) |*channel|
                channel.deinit(self.world.allocator);
            for (self.rebuilt_sets[0..self.rebuilt_count]) |*set|
                set.deinit(self.world.allocator);
            if (self.owns_channel_rcu) self.world.destroyDetachedRcuChannelState(self.channel_rcu.?);
            if (self.owns_nick_rcu) self.world.destroyDetachedRcuNickState(self.nick_rcu);
            self.world.allocator.free(self.new_channels);
            self.world.allocator.free(self.adopted_channels);
            self.world.allocator.free(self.rebuilt_sets);
            self.world.allocator.free(self.member_stages);
            self.world.allocator.free(self.removed_members);
            self.world.allocator.free(self.existing_members);
            self.world.allocator.free(self.owned_target);
            self.world.allocator.free(self.exact_clients);
            self.active = false;
        }

        /// Install the complete prepared image. Every operation below is an
        /// assume-capacity insertion, release-store, retire into reserved
        /// storage, free, or scalar update; none can allocate or fail.
        pub fn commit(self: *PreparedSessionRestore) void {
            std.debug.assert(self.active);
            const world = self.world;

            // Mutable fallback membership state is capacity-reserved.
            for (self.existing_members[0..self.existing_count]) |entry| {
                const member = entry.channel.members.getOrPutAssumeCapacity(self.restore_client);
                member.value_ptr.* = entry.modes;
            }
            for (self.removed_members[0..self.removed_count]) |entry| {
                if (!entry.cleanup_channel and entry.fallback_present)
                    _ = entry.channel.?.members.remove(self.restore_client);
            }
            if (self.channel_rcu) |c| {
                for (self.rebuilt_sets[0..self.rebuilt_count]) |set|
                    c.members.putAssumeCapacityNoClobber(set.folded_name, set.set);
                for (self.new_channels[0..self.new_count]) |new_channel| {
                    c.members.putAssumeCapacityNoClobber(new_channel.folded_name, new_channel.set);
                    world.channels.putAssumeCapacityNoClobber(new_channel.owned_name, new_channel.channel);
                }
                for (self.adopted_channels[0..self.adopted_count]) |channel|
                    world.channels.putAssumeCapacityNoClobber(channel.owned_name, channel.channel);
            }
            world.next_oid = self.next_oid_after;

            // Mutable fallback nick indexes mirror the selected disposition.
            for (self.exact_clients) |client| {
                if (world.client_nicks.fetchRemove(client)) |removed| {
                    _ = world.nicks.remove(removed.value);
                    world.allocator.free(removed.value);
                }
            }
            switch (self.disposition) {
                .claim_exact => |nick_owner| {
                    world.nicks.putAssumeCapacity(self.owned_target, nick_owner);
                    world.client_nicks.putAssumeCapacity(nick_owner, self.owned_target);
                },
                .preserve_foreign => world.allocator.free(self.owned_target),
            }

            for (self.member_stages[0..self.member_stage_count]) |*stage| stage.commit();
            if (self.channel_name_stage) |*stage| stage.commit();
            if (self.member_reservation) |reservation| {
                reservation.finish();
                world.allocator.destroy(reservation);
                self.member_reservation = null;
            }
            if (self.nick_stage) |*stage| stage.commit();

            if (self.owns_channel_rcu) world.rcu_channels = self.channel_rcu.?;
            if (self.owns_nick_rcu) world.rcu_nicks = self.nick_rcu;
            if (self.channel_rcu) |c| {
                for (0..self.member_stage_count) |_| world.noteRcuChannelWrite(c);
                if (self.channel_name_stage != null) world.noteRcuChannelWrite(c);
                if (self.rebuilt_count != 0) world.noteRcuChannelWrite(c);
                if (self.new_count != 0) world.noteRcuChannelWrite(c);
            }
            world.noteRcuNickWrite(self.nick_rcu);

            // Existence is already unpublished. Reclaim only omitted ephemeral
            // channels proven empty in BOTH fallback and RCU views; any keeper
            // in either view forced cleanup_channel=false above.
            for (self.removed_members[0..self.removed_count]) |entry| {
                if (!entry.cleanup_channel) continue;
                if (self.channel_rcu) |c| world.rcuDropMembership(c, entry.name);
                if (entry.channel != null) world.removeFallbackChannel(entry.name);
            }

            world.allocator.free(self.new_channels);
            world.allocator.free(self.adopted_channels);
            world.allocator.free(self.rebuilt_sets);
            world.allocator.free(self.member_stages);
            world.allocator.free(self.removed_members);
            world.allocator.free(self.existing_members);
            world.allocator.free(self.exact_clients);
            self.active = false;
        }
    };

    pub fn init(allocator: std.mem.Allocator) World {
        return .{
            .allocator = allocator,
            .channels = CiStringHashMap(Channel).init(allocator),
            .nicks = std.StringHashMap(ClientId).init(allocator),
            .client_nicks = std.AutoHashMap(ClientId, []u8).init(allocator),
        };
    }

    pub fn deinit(self: *World) void {
        // Caller has stopped admission and joined every World borrower.
        if (self.registered_stages) |registry| {
            const r = registeredRegistryBacking(registry);
            std.debug.assert(r.world == self and r.active == null);
            var token = r.tokens;
            while (token) |b| {
                token = b.next_token;
                std.debug.assert(!b.active);
                self.allocator.free(b.target_name);
                self.allocator.destroy(b);
            }
            self.allocator.destroy(r);
            self.registered_stages = null;
        }
        var channel_it = self.channels.iterator();
        while (channel_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit();
        }
        self.channels.deinit();

        self.nicks.deinit();

        var nick_it = self.client_nicks.iterator();
        while (nick_it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.client_nicks.deinit();

        if (self.rcu_nicks) |r| {
            // Order: free the live snapshot, drain retired boxes/keys from the
            // domain limbo, unregister the reader slot, then tear down the
            // (now-quiescent) domain and free the heap state.
            r.nicks.deinit();
            r.domain.drainAll();
            r.writer_participant.unregister();
            rcuForgetThreadParticipants(&r.domain, r.generation);
            r.domain.deinit();
            self.allocator.destroy(r);
        }

        if (self.rcu_channels) |c| {
            // Free every per-channel membership set's live snapshot, then the
            // name-existence registry, before draining the shared domain. Same
            // proven order as the nick mirror: registries → drain → unregister
            // → domain deinit → destroy.
            var mit = c.members.iterator();
            while (mit.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.free(entry.key_ptr.*);
                self.allocator.destroy(entry.value_ptr.*);
            }
            c.members.deinit(self.allocator);
            c.names.deinit();
            c.domain.drainAll();
            c.writer_participant.unregister();
            rcuForgetThreadParticipants(&c.domain, c.generation);
            c.domain.deinit();
            self.allocator.destroy(c);
        }
        self.* = undefined;
    }

    /// Activate (once) and return the lazy RCU nick mirror. Heap-allocated for a
    /// stable EBR-domain address; see `RcuNickState`.
    fn createRcuNickState(self: *World) !*RcuNickState {
        const r = try self.allocator.create(RcuNickState);
        errdefer self.allocator.destroy(r);
        r.domain = ebr.Domain.init(self.allocator);
        errdefer r.domain.deinit();
        r.generation = nextRcuGeneration();
        r.writer_participant = r.domain.register() catch return error.OutOfMemory;
        errdefer r.writer_participant.unregister();
        r.nicks = try world_rcu.NickRegistry.init(self.allocator, &r.domain);
        return r;
    }

    fn destroyDetachedRcuNickState(self: *World, r: *RcuNickState) void {
        r.nicks.deinit();
        r.domain.drainAll();
        r.writer_participant.unregister();
        r.domain.deinit();
        self.allocator.destroy(r);
    }

    fn ensureRcuNicks(self: *World) !*RcuNickState {
        if (self.rcu_nicks) |r| return r;
        const r = try self.createRcuNickState();
        self.rcu_nicks = r;
        return r;
    }

    /// Activate (once) and return the lazy RCU channel/membership mirror.
    fn createRcuChannelState(self: *World) !*RcuChannelState {
        const c = try self.allocator.create(RcuChannelState);
        errdefer self.allocator.destroy(c);
        c.domain = ebr.Domain.init(self.allocator);
        errdefer c.domain.deinit();
        c.generation = nextRcuGeneration();
        c.writer_participant = c.domain.register() catch return error.OutOfMemory;
        errdefer c.writer_participant.unregister();
        c.names = try world_rcu.ChannelRegistry(u32).init(self.allocator, &c.domain);
        errdefer c.names.deinit();
        c.members = .empty;
        return c;
    }

    fn destroyDetachedRcuChannelState(self: *World, c: *RcuChannelState) void {
        std.debug.assert(c.members.count() == 0);
        c.members.deinit(self.allocator);
        c.names.deinit();
        c.domain.drainAll();
        c.writer_participant.unregister();
        c.domain.deinit();
        self.allocator.destroy(c);
    }

    fn ensureRcuChannels(self: *World) !*RcuChannelState {
        if (self.rcu_channels) |c| return c;
        const c = try self.createRcuChannelState();
        self.rcu_channels = c;
        return c;
    }

    fn noteRcuNickWrite(self: *World, r: *RcuNickState) void {
        if (self.rcu_nick_writes_since_advance < rcuAdvanceWriteInterval)
            self.rcu_nick_writes_since_advance += 1;
        if (self.rcu_nick_writes_since_advance < rcuAdvanceWriteInterval) return;
        if (advanceRcuDomainIfIdle(&r.domain))
            self.rcu_nick_writes_since_advance = 0;
    }

    fn noteRcuChannelWrite(self: *World, c: *RcuChannelState) void {
        if (self.rcu_channel_writes_since_advance < rcuAdvanceWriteInterval)
            self.rcu_channel_writes_since_advance += 1;
        if (self.rcu_channel_writes_since_advance < rcuAdvanceWriteInterval) return;
        if (advanceRcuDomainIfIdle(&c.domain))
            self.rcu_channel_writes_since_advance = 0;
    }

    /// Get (creating if absent) the per-channel RCU membership set for `name`.
    /// Keyed by the case-folded channel name so "#X" and "#x" share one set.
    fn rcuMembershipSet(self: *World, c: *RcuChannelState, name: []const u8) !*world_rcu.MembershipSet {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        if (c.members.get(folded)) |set| return set;

        const owned_key = try self.allocator.dupe(u8, folded);
        errdefer self.allocator.free(owned_key);
        const set = try self.allocator.create(world_rcu.MembershipSet);
        errdefer self.allocator.destroy(set);
        set.* = try world_rcu.MembershipSet.init(self.allocator, &c.domain);
        errdefer set.deinit();
        try c.members.put(self.allocator, owned_key, set);
        return set;
    }

    /// Return the existing per-channel RCU membership set for `name`, or null if
    /// none has been created. Does not allocate.
    fn rcuMembershipGet(c: *RcuChannelState, name: []const u8) ?*world_rcu.MembershipSet {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        return c.members.get(folded);
    }

    /// Re-key the per-channel membership set from `old` to `new` (channel
    /// rename). Membership is unchanged, so we move the set pointer to the new
    /// folded key. If the folded keys coincide, nothing to do.
    fn rcuRenameMembership(self: *World, c: *RcuChannelState, old: []const u8, new: []const u8) void {
        var ob: [foldBufLen]u8 = undefined;
        var nb: [foldBufLen]u8 = undefined;
        const of = foldName(old, &ob);
        const nf = foldName(new, &nb);
        if (std.mem.eql(u8, of, nf)) return;

        const kv = c.members.fetchRemove(of) orelse return;
        // Free the moved-out old key; install the set under a freshly-duped new
        // key. On dupe/put failure the set is dropped (best-effort) rather than
        // leaked under the wrong key.
        self.allocator.free(kv.key);
        const new_owned = self.allocator.dupe(u8, nf) catch {
            kv.value.deinit();
            self.allocator.destroy(kv.value);
            return;
        };
        // If a set already lives under the new key (case-fold collision), drop it
        // first so we don't leak.
        if (c.members.fetchRemove(nf)) |existing| {
            existing.value.deinit();
            self.allocator.free(existing.key);
            self.allocator.destroy(existing.value);
        }
        c.members.put(self.allocator, new_owned, kv.value) catch {
            self.allocator.free(new_owned);
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        };
    }

    /// Drop the per-channel RCU membership set for `name` (channel removed).
    fn rcuDropMembership(self: *World, c: *RcuChannelState, name: []const u8) void {
        var key_buf: [foldBufLen]u8 = undefined;
        const folded = foldName(name, &key_buf);
        if (c.members.fetchRemove(folded)) |kv| {
            kv.value.deinit();
            self.allocator.free(kv.key);
            self.allocator.destroy(kv.value);
        }
    }

    /// Rollback-owned nick projection. Caller retains World's write lock until
    /// commit/abort; the ticket owns the RCU writer lock and detached activation.
    /// Memberships and physical attachment identity are never inferred from nick.
    pub const PreparedIdentity = struct {
        world: *World,
        exact: []ClientId,
        target: ?[]u8 = null,
        disposition: ?SessionNickDisposition = null,
        rcu: ?*RcuNickState = null,
        owns_rcu: bool = false,
        stage: ?PreparedSessionRestore.NickStage = null,
        remove_stage: ?world_rcu.NickRegistry.StagedEditBatch = null,
        reservation: ?*ebr.Participant.RetireReservation = null,
        changed: bool = true,
        active: bool = true,

        pub fn abort(self: *PreparedIdentity) void {
            if (!self.active) return;
            if (self.stage) |*stage| stage.abort();
            if (self.remove_stage) |*stage| stage.abort();
            self.finishReservation();
            if (self.owns_rcu) self.world.destroyDetachedRcuNickState(self.rcu.?);
            if (self.target) |target| self.world.allocator.free(target);
            self.world.allocator.free(self.exact);
            self.active = false;
        }

        fn finishReservation(self: *PreparedIdentity) void {
            if (self.reservation) |reservation| {
                reservation.finish();
                self.world.allocator.destroy(reservation);
                self.reservation = null;
            }
        }

        /// All capacity, persistent snapshots and retirement storage are owned.
        /// Publication has no allocation/error path. Abort after commit is safe.
        pub fn commit(self: *PreparedIdentity) void {
            std.debug.assert(self.active);
            const world = self.world;
            if (self.changed) {
                for (self.exact) |client| {
                    if (world.client_nicks.fetchRemove(client)) |removed| {
                        _ = world.nicks.remove(removed.value);
                        world.allocator.free(removed.value);
                    }
                }
                if (self.disposition) |disposition| switch (disposition) {
                    .claim_exact => |owner| {
                        world.nicks.putAssumeCapacity(self.target.?, owner);
                        world.client_nicks.putAssumeCapacity(owner, self.target.?);
                    },
                    .preserve_foreign => world.allocator.free(self.target.?),
                };
                if (self.stage) |*stage| stage.commit();
                if (self.remove_stage) |*stage| stage.commit();
                self.finishReservation();
                if (self.owns_rcu) world.rcu_nicks = self.rcu.?;
                if (self.rcu) |r| world.noteRcuNickWrite(r);
            }
            world.allocator.free(self.exact);
            self.active = false;
        }
    };

    fn detachedNickMirror(self: *World) WorldError!*RcuNickState {
        const r = try self.createRcuNickState();
        errdefer self.destroyDetachedRcuNickState(r);
        var it = self.nicks.iterator();
        while (it.next()) |entry| try r.nicks.set(r.writer_participant, entry.key_ptr.*, @bitCast(entry.value_ptr.*));
        return r;
    }

    /// Exact logical-owner policy remains an explicit caller decision. This
    /// changes only nick indexes, preserving every attachment's memberships.
    pub fn prepareExactSessionNickOwner(self: *World, target: []const u8, exact_clients: []const ClientId, disposition: SessionNickDisposition) WorldError!PreparedIdentity {
        for (exact_clients, 0..) |client, i| {
            if (clientIdInSet(client, exact_clients[0..i])) return error.InvalidOwnerSet;
        }
        switch (disposition) {
            .claim_exact => |owner| if (!clientIdInSet(owner, exact_clients)) return error.InvalidOwnerSet,
            .preserve_foreign => |owner| if (clientIdInSet(owner, exact_clients)) return error.InvalidOwnerSet,
        }
        for (exact_clients) |client| try self.validateFallbackNickOwner(client);
        var prepared = PreparedIdentity{ .world = self, .exact = &.{}, .disposition = disposition };
        errdefer prepared.abort();
        var aliases: usize = 0;
        var already_exact = false;
        for (exact_clients) |client| {
            const current = self.client_nicks.get(client) orelse continue;
            aliases += 1;
            if (disposition == .claim_exact and client.eql(disposition.claim_exact) and std.mem.eql(u8, current, target)) already_exact = true;
        }
        const Counter = struct {
            exact: []const ClientId,
            count: usize = 0,
            fn append(ctx: *@This(), _: []const u8, bits: world_rcu.ClientId) void {
                if (clientIdInSet(@bitCast(bits), ctx.exact)) ctx.count += 1;
            }
        };
        var counter = Counter{ .exact = exact_clients };
        if (self.rcu_nicks) |r| r.nicks.iterate(r.writer_participant, &counter, Counter.append);
        if (disposition == .preserve_foreign and aliases == 0 and counter.count == 0) {
            const owner = self.findNickFallback(target) orelse return error.NickInUse;
            if (!owner.eql(disposition.preserve_foreign)) return error.NickInUse;
            if (self.rcu_nicks) |r| {
                const bits = r.nicks.lookup(r.writer_participant, target) orelse return error.NickInUse;
                if (!(@as(ClientId, @bitCast(bits))).eql(owner)) return error.NickInUse;
            }
            prepared.changed = false;
            return prepared;
        }
        if (aliases == 1 and already_exact and counter.count == 1) {
            if (self.rcu_nicks) |r| {
                if (r.nicks.lookup(r.writer_participant, target)) |bits| {
                    if ((@as(ClientId, @bitCast(bits))).eql(disposition.claim_exact)) {
                        prepared.changed = false;
                        return prepared;
                    }
                }
            }
        }
        switch (disposition) {
            .claim_exact => if (self.findNickFallback(target)) |owner| {
                if (!clientIdInSet(owner, exact_clients)) return error.NickInUse;
            },
            .preserve_foreign => |foreign| {
                const owner = self.findNickFallback(target) orelse return error.NickInUse;
                if (!owner.eql(foreign)) return error.NickInUse;
            },
        }
        prepared.exact = try self.allocator.dupe(ClientId, exact_clients);
        prepared.target = try self.allocator.dupe(u8, target);
        prepared.rcu = if (self.rcu_nicks) |r| r else try self.detachedNickMirror();
        prepared.owns_rcu = self.rcu_nicks == null;
        const r = prepared.rcu.?;
        const ids = try self.allocator.alloc(world_rcu.ClientId, exact_clients.len);
        defer self.allocator.free(ids);
        for (exact_clients, ids) |client, *id| id.* = @bitCast(client);
        try self.nicks.ensureUnusedCapacity(1);
        try self.client_nicks.ensureUnusedCapacity(1);
        const stage: PreparedSessionRestore.NickStage = switch (disposition) {
            .claim_exact => |owner| .{ .claim = (try r.nicks.stageReplaceRemovingValues(r.writer_participant, target, @bitCast(owner), ids)) orelse return error.NickInUse },
            .preserve_foreign => |foreign| .{ .preserve = (try r.nicks.stageRemoveValuesPreservingKey(r.writer_participant, target, @bitCast(foreign), ids)) orelse return error.NickInUse },
        };
        prepared.stage = stage;
        return prepared;
    }

    pub fn preparePhysicalIdentityRegister(self: *World, client: ClientId, nick: []const u8) WorldError!PreparedIdentity {
        return self.prepareExactSessionNickOwner(nick, &.{client}, .{ .claim_exact = client });
    }

    pub fn preparePhysicalIdentityRename(self: *World, client: ClientId, nick: []const u8) WorldError!PreparedIdentity {
        return self.preparePhysicalIdentityRegister(client, nick);
    }

    fn validateFallbackNickOwner(self: *World, client: ClientId) WorldError!void {
        if (self.client_nicks.get(client)) |reverse| {
            const forward = self.nicks.getEntry(reverse) orelse return error.InvalidOwnerSet;
            if (!forward.value_ptr.eql(client) or forward.key_ptr.ptr != reverse.ptr) return error.InvalidOwnerSet;
        }
        // An orphan fallback key has no proven string owner. Reject before
        // publication rather than silently leaking/freeing arbitrary storage.
        var fallback = self.nicks.iterator();
        while (fallback.next()) |entry| {
            if (!entry.value_ptr.eql(client)) continue;
            const reverse = self.client_nicks.get(client) orelse return error.InvalidOwnerSet;
            if (!std.mem.eql(u8, reverse, entry.key_ptr.*)) return error.InvalidOwnerSet;
        }
    }

    fn preparePhysicalNickRemove(self: *World, client: ClientId) WorldError!PreparedIdentity {
        try self.validateFallbackNickOwner(client);
        var prepared = PreparedIdentity{ .world = self, .exact = try self.allocator.dupe(ClientId, &.{client}), .rcu = self.rcu_nicks };
        errdefer prepared.abort();
        if (self.rcu_nicks) |r| {
            const keys = try self.allocator.alloc([]const u8, r.nicks.count(r.writer_participant));
            defer self.allocator.free(keys);
            const Collector = struct {
                client: world_rcu.ClientId,
                keys: [][]const u8,
                count: usize = 0,
                fn append(ctx: *@This(), key: []const u8, value: world_rcu.ClientId) void {
                    if (value != ctx.client) return;
                    ctx.keys[ctx.count] = key;
                    ctx.count += 1;
                }
            };
            var collector = Collector{ .client = @bitCast(client), .keys = keys };
            // Borrowed keys stay alive: World's graph lock excludes writers,
            // and the subsequent stage retains the source snapshot's keys.
            r.nicks.iterate(r.writer_participant, &collector, Collector.append);
            if (collector.count != 0) {
                const reservation = try self.allocator.create(ebr.Participant.RetireReservation);
                reservation.* = r.writer_participant.reserveRetireCapacity(1) catch |err| {
                    self.allocator.destroy(reservation);
                    return err;
                };
                prepared.reservation = reservation;
                const stage = (try r.nicks.stageEditBatchReserved(reservation, keys[0..collector.count], &.{})) orelse return error.InvalidOwnerSet;
                prepared.remove_stage = stage;
            }
        }
        return prepared;
    }

    pub const DepartureNick = struct {
        target: []const u8,
        disposition: SessionNickDisposition,
    };

    /// Explicit physical contributors, supplied by the session authority owner.
    /// expected_union proves no new authority: it asserts the complete graph
    /// union derived here, including keeper-only channels and exact known flags.
    pub const PhysicalDepartureSpec = struct {
        source: ClientId,
        keeper: ?ClientId,
        exact_clients: []const ClientId,
        nick: ?DepartureNick = null,
        expected_union: ?[]const MemberRestore = null,
    };

    const DepartureChannel = struct {
        name: []const u8,
        channel: ?*Channel,
        set: ?*world_rcu.MembershipSet,
        source_rcu: bool,
        add_keeper_rcu: bool,
        union_member: bool,
        union_modes: MemberModes,
        cleanup: bool,
        remove_name: bool,
        insert_name: bool,
        rebuilt: ?struct { key: []u8, set: *world_rcu.MembershipSet } = null,

        fn lessThan(_: void, a: *DepartureChannel, b: *DepartureChannel) bool {
            return @intFromPtr(a.set.?) < @intFromPtr(b.set.?);
        }
    };

    /// One graph-lock-owned departure. Nick -> sorted unique membership sets ->
    /// channel names are held through commit/abort. Every root and retirement
    /// allocation precedes publication. The caller must not unlock World while
    /// this ticket is active. Unlocked RCU reads do not provide a global cut.
    pub const PreparedPhysicalDeparture = struct {
        world: *World,
        source: ClientId,
        keeper: ?ClientId,
        nick: PreparedIdentity,
        channel_rcu: ?*RcuChannelState,
        channels: []DepartureChannel,
        channel_count: usize = 0,
        stages: []world_rcu.MembershipSet.StagedEdit,
        stage_count: usize = 0,
        names: ?world_rcu.ChannelRegistry(u32).StagedEditBatch = null,
        reservation: ?*ebr.Participant.RetireReservation = null,
        active: bool = true,

        fn finishReservation(self: *PreparedPhysicalDeparture) void {
            if (self.reservation) |reservation| {
                reservation.finish();
                self.world.allocator.destroy(reservation);
                self.reservation = null;
            }
        }

        pub fn abort(self: *PreparedPhysicalDeparture) void {
            if (!self.active) return;
            if (self.names) |*names| names.abort();
            while (self.stage_count != 0) {
                self.stage_count -= 1;
                self.stages[self.stage_count].abort();
            }
            self.finishReservation();
            for (self.channels[0..self.channel_count]) |entry| if (entry.rebuilt) |rebuilt| {
                rebuilt.set.deinit();
                self.world.allocator.destroy(rebuilt.set);
                self.world.allocator.free(rebuilt.key);
            };
            self.nick.abort();
            self.world.allocator.free(self.stages);
            self.world.allocator.free(self.channels);
            self.active = false;
        }

        pub fn commit(self: *PreparedPhysicalDeparture) void {
            std.debug.assert(self.active);
            const world = self.world;
            var it = world.channels.valueIterator();
            while (it.next()) |channel| _ = channel.invites.remove(self.source);
            for (self.channels[0..self.channel_count]) |entry| {
                if (entry.channel) |channel| {
                    _ = channel.members.remove(self.source);
                    if (self.keeper) |keeper| if (entry.union_member) {
                        channel.members.putAssumeCapacity(keeper, entry.union_modes);
                    };
                }
                if (entry.rebuilt) |rebuilt| {
                    self.channel_rcu.?.members.putAssumeCapacity(rebuilt.key, rebuilt.set);
                }
            }
            for (self.stages[0..self.stage_count]) |*stage| stage.commit();
            if (self.names) |*names| names.commit();
            self.finishReservation();
            self.nick.commit();
            for (self.channels[0..self.channel_count]) |entry| {
                if (!entry.cleanup) continue;
                if (self.channel_rcu) |c| world.rcuDropMembership(c, entry.name);
                world.removeFallbackChannel(entry.name);
            }
            // Retire reservations must be consumed before epoch maintenance.
            if (self.channel_rcu) |c| {
                for (0..self.stage_count) |_| world.noteRcuChannelWrite(c);
                if (self.names != null) world.noteRcuChannelWrite(c);
            }
            world.allocator.free(self.stages);
            world.allocator.free(self.channels);
            self.active = false;
        }
    };

    pub const PreparedIdentityRemove = PreparedPhysicalDeparture;

    pub fn preparePhysicalIdentityRemove(self: *World, client: ClientId) WorldError!PreparedIdentityRemove {
        return self.preparePhysicalDeparture(.{ .source = client, .keeper = null, .exact_clients = &.{client} });
    }

    fn deriveDepartureChannel(self: *World, spec: PhysicalDepartureSpec, name: []const u8, channel: ?*Channel, set: ?*world_rcu.MembershipSet) WorldError!DepartureChannel {
        if (name.len > foldBufLen) return error.InvalidGraph;
        const c = self.rcu_channels;
        var union_member = false;
        var modes = MemberModes.empty();
        for (spec.exact_clients) |id| {
            const fallback = if (channel) |ch| ch.members.get(id) else null;
            const in_rcu = if (set) |s| s.contains(c.?.writer_participant, @bitCast(id)) else false;
            union_member = union_member or fallback != null or in_rcu;
            if (fallback) |flags| modes.bits |= flags.bits;
        }
        const source_fallback = if (channel) |ch| ch.members.contains(spec.source) else false;
        const source_rcu = if (set) |s| s.contains(c.?.writer_participant, @bitCast(spec.source)) else false;
        const add_keeper = if (spec.keeper) |keeper| union_member and (if (set) |s| !s.contains(c.?.writer_participant, @bitCast(keeper)) else false) else false;
        const fallback_final = if (channel) |ch| ch.members.count() - @intFromBool(source_fallback) + @intFromBool(spec.keeper != null and union_member and !ch.members.contains(spec.keeper.?)) else 0;
        const rcu_final = if (set) |s| s.count(c.?.writer_participant) - @intFromBool(source_rcu) + @intFromBool(add_keeper) else fallback_final;
        const cleanup = if (channel) |ch| !ch.ext_modes.has(.registered) and fallback_final == 0 and rcu_final == 0 else false;
        const affected = union_member or source_fallback or source_rcu or cleanup;
        const oid = if (c) |state| state.names.lookup(state.writer_participant, name) else null;
        if (affected and channel != null and oid != null and oid.? != channel.?.oid) return error.InvalidGraph;
        if (affected and !cleanup and channel != null and c != null and oid == null) {
            if (channel.?.oid == 0) return error.InvalidGraph;
            // Off-map candidates and foreign fallback records may both lack a
            // names witness. The full predecessor owns each OID, not just the
            // currently published names root or this ticket's selected rows.
            var fallback_owners = self.channels.valueIterator();
            while (fallback_owners.next()) |other| {
                if (other != channel.? and other.oid == channel.?.oid) return error.InvalidGraph;
            }
            const Witness = struct {
                oid: u32,
                found: bool = false,
                fn inspect(ctx: *@This(), _: []const u8, existing: u32) void {
                    if (existing == ctx.oid) ctx.found = true;
                }
            };
            var witness = Witness{ .oid = channel.?.oid };
            c.?.names.iterate(c.?.writer_participant, &witness, Witness.inspect);
            if (witness.found) return error.InvalidGraph;
        }
        return .{ .name = name, .channel = channel, .set = set, .source_rcu = source_rcu, .add_keeper_rcu = add_keeper, .union_member = union_member, .union_modes = modes, .cleanup = cleanup, .remove_name = cleanup and oid != null, .insert_name = affected and !cleanup and channel != null and c != null and oid == null };
    }

    pub fn preparePhysicalDeparture(self: *World, spec: PhysicalDepartureSpec) WorldError!PreparedPhysicalDeparture {
        var source_found = false;
        var keeper_found = false;
        for (spec.exact_clients, 0..) |id, i| {
            for (spec.exact_clients[0..i]) |prior| if (id.eql(prior)) return error.InvalidOwnerSet;
            source_found = source_found or id.eql(spec.source);
            keeper_found = keeper_found or (spec.keeper != null and id.eql(spec.keeper.?));
            try self.validateFallbackNickOwner(id);
        }
        if (!source_found) return error.InvalidOwnerSet;
        if (spec.keeper) |keeper| {
            if (keeper.eql(spec.source) or !keeper_found) return error.InvalidOwnerSet;
        } else if (spec.exact_clients.len != 1 or spec.nick != null or (spec.expected_union != null and spec.expected_union.?.len != 0)) return error.InvalidOwnerSet;
        if (spec.nick) |nick| switch (nick.disposition) {
            .claim_exact => |chosen| if (!chosen.eql(spec.keeper.?)) return error.InvalidOwnerSet,
            .preserve_foreign => |foreign| for (spec.exact_clients) |id| if (id.eql(foreign)) return error.InvalidOwnerSet,
        };
        // Reject shared set ownership globally before taking any set lock, even
        // when just one of the corrupt aliases would otherwise be affected.
        const c = self.rcu_channels;
        if (c) |state| {
            const owners = try self.allocator.alloc(*world_rcu.MembershipSet, state.members.count());
            defer self.allocator.free(owners);
            var members = state.members.iterator();
            for (owners) |*owner| {
                const entry = members.next().?;
                if (entry.key_ptr.len > foldBufLen) return error.InvalidGraph;
                var buf: [foldBufLen]u8 = undefined;
                if (!std.mem.eql(u8, entry.key_ptr.*, foldName(entry.key_ptr.*, &buf))) return error.InvalidGraph;
                owner.* = entry.value_ptr.*;
            }
            const Order = struct {
                fn less(_: void, a: *world_rcu.MembershipSet, b: *world_rcu.MembershipSet) bool {
                    return @intFromPtr(a) < @intFromPtr(b);
                }
            };
            std.mem.sort(*world_rcu.MembershipSet, owners, {}, Order.less);
            for (owners, 0..) |owner, i| if (i != 0 and owner == owners[i - 1]) return error.InvalidGraph;
        }
        var nick = if (spec.nick) |selected| try self.prepareExactSessionNickOwner(selected.target, spec.exact_clients, selected.disposition) else try self.preparePhysicalNickRemove(spec.source);
        var owns_nick = true;
        errdefer if (owns_nick) nick.abort();
        const capacity = std.math.add(usize, self.channels.count(), if (c) |state| state.members.count() else 0) catch return error.OutOfMemory;
        const channels = try self.allocator.alloc(DepartureChannel, capacity);
        var owns_channels = true;
        errdefer if (owns_channels) self.allocator.free(channels);
        const stages = try self.allocator.alloc(world_rcu.MembershipSet.StagedEdit, capacity);
        var prepared = PreparedPhysicalDeparture{ .world = self, .source = spec.source, .keeper = spec.keeper, .nick = nick, .channel_rcu = c, .channels = channels, .stages = stages };
        owns_nick = false;
        owns_channels = false;
        errdefer prepared.abort();
        var fallback = self.channels.iterator();
        while (fallback.next()) |entry| {
            if (entry.key_ptr.len > foldBufLen) return error.InvalidGraph;
            const set = if (c) |state| rcuMembershipGet(state, entry.key_ptr.*) else null;
            const delta = try self.deriveDepartureChannel(spec, entry.key_ptr.*, entry.value_ptr, set);
            if (!delta.union_member and !delta.cleanup) continue;
            channels[prepared.channel_count] = delta;
            prepared.channel_count += 1;
        }
        if (c) |state| {
            var members = state.members.iterator();
            while (members.next()) |entry| {
                if (self.channels.contains(entry.key_ptr.*)) continue;
                const delta = try self.deriveDepartureChannel(spec, entry.key_ptr.*, null, entry.value_ptr.*);
                if (!delta.union_member) continue;
                channels[prepared.channel_count] = delta;
                prepared.channel_count += 1;
            }
        }
        if (if (spec.keeper != null) spec.expected_union else null) |expected| {
            var count: usize = 0;
            for (channels[0..prepared.channel_count]) |entry| if (entry.union_member) {
                count += 1;
            };
            if (expected.len != count) return error.InvalidUnion;
            for (expected, 0..) |row, i| {
                if (row.channel.len > foldBufLen) return error.InvalidUnion;
                for (expected[0..i]) |prior| if (std.ascii.eqlIgnoreCase(prior.channel, row.channel)) return error.InvalidUnion;
                var found = false;
                for (channels[0..prepared.channel_count]) |entry| {
                    if (!entry.union_member or !std.ascii.eqlIgnoreCase(entry.name, row.channel)) continue;
                    if (entry.union_modes.bits != row.modes.bits) return error.InvalidUnion;
                    found = true;
                    break;
                }
                if (!found) return error.InvalidUnion;
            }
        }
        const locks = try self.allocator.alloc(*DepartureChannel, prepared.channel_count);
        defer self.allocator.free(locks);
        var lock_count: usize = 0;
        var remove_count: usize = 0;
        var insert_count: usize = 0;
        var rebuild_count: usize = 0;
        for (channels[0..prepared.channel_count]) |*entry| {
            if (entry.channel) |channel| if (spec.keeper) |keeper| if (entry.union_member and !channel.members.contains(keeper)) {
                const final_count = channel.members.count() + 1 - @intFromBool(channel.members.contains(spec.source));
                try channel.members.ensureTotalCapacity(@intCast(final_count));
            };
            if (entry.set != null and (entry.source_rcu or entry.add_keeper_rcu)) {
                locks[lock_count] = entry;
                lock_count += 1;
            }
            if (entry.remove_name) remove_count += 1;
            if (entry.insert_name) insert_count += 1;
            if (c != null and entry.channel != null and entry.set == null and !entry.cleanup) rebuild_count += 1;
        }
        if (rebuild_count != 0) try c.?.members.ensureUnusedCapacity(self.allocator, @intCast(rebuild_count));
        for (channels[0..prepared.channel_count]) |*entry| {
            if (c == null or entry.channel == null or entry.set != null or entry.cleanup) continue;
            const channel = entry.channel.?;
            var buf: [foldBufLen]u8 = undefined;
            const key = try self.allocator.dupe(u8, foldName(entry.name, &buf));
            errdefer self.allocator.free(key);
            const ids = try self.allocator.alloc(world_rcu.ClientId, channel.members.count() + 1);
            defer self.allocator.free(ids);
            var count: usize = 0;
            var member_it = channel.members.keyIterator();
            while (member_it.next()) |id| {
                if (id.eql(spec.source)) continue;
                ids[count] = @bitCast(id.*);
                count += 1;
            }
            if (spec.keeper) |keeper| if (entry.union_member and !channel.members.contains(keeper)) {
                ids[count] = @bitCast(keeper);
                count += 1;
            };
            const set = try self.allocator.create(world_rcu.MembershipSet);
            errdefer self.allocator.destroy(set);
            set.* = try world_rcu.MembershipSet.initFromSlice(self.allocator, &c.?.domain, ids[0..count]);
            entry.rebuilt = .{ .key = key, .set = set };
        }
        std.mem.sort(*DepartureChannel, locks[0..lock_count], {}, DepartureChannel.lessThan);
        if (lock_count != 0 or remove_count != 0 or insert_count != 0) {
            const reservation = try self.allocator.create(ebr.Participant.RetireReservation);
            reservation.* = c.?.writer_participant.reserveRetireCapacity(lock_count + @intFromBool(remove_count != 0 or insert_count != 0)) catch |err| {
                self.allocator.destroy(reservation);
                return err;
            };
            prepared.reservation = reservation;
        }
        for (locks[0..lock_count]) |entry| {
            const removals: []const world_rcu.ClientId = if (entry.source_rcu) &.{@bitCast(spec.source)} else &.{};
            const additions: []const world_rcu.ClientId = if (entry.add_keeper_rcu) &.{@bitCast(spec.keeper.?)} else &.{};
            const stage = (entry.set.?.stageEditReserved(prepared.reservation.?, removals, additions) catch |err| switch (err) {
                error.InvalidEdit => return error.InvalidGraph,
                error.OutOfMemory => return error.OutOfMemory,
            }) orelse return error.InvalidGraph;
            stages[prepared.stage_count] = stage;
            prepared.stage_count += 1;
        }
        if (remove_count != 0 or insert_count != 0) {
            const removals = try self.allocator.alloc([]const u8, remove_count);
            defer self.allocator.free(removals);
            const additions = try self.allocator.alloc(world_rcu.ChannelRegistry(u32).Insert, insert_count);
            defer self.allocator.free(additions);
            var ri: usize = 0;
            var ai: usize = 0;
            for (channels[0..prepared.channel_count]) |entry| {
                if (entry.remove_name) {
                    removals[ri] = entry.name;
                    ri += 1;
                }
                if (entry.insert_name) {
                    additions[ai] = .{ .key = entry.name, .value = entry.channel.?.oid };
                    ai += 1;
                }
            }
            const stage = (try c.?.names.stageEditBatchReserved(prepared.reservation.?, removals, additions)) orelse return error.InvalidGraph;
            prepared.names = stage;
        }
        return prepared;
    }

    /// Register `nick` for `client`, rejecting collisions. Collision detection
    /// is CASE-INSENSITIVE (RFC1459-ish ASCII casemapping): registering "Alice"
    /// then "alice" is a collision, not two entries. The RCU registry is the
    /// authoritative nick->id source (lock-free reads); `client_nicks` is the
    /// authoritative id->nick reverse index and `nicks` is kept as a consistent
    /// case-sensitive fallback mirror.
    pub fn registerNick(self: *World, nick: []const u8, client: ClientId) WorldError!void {
        var prepared = try self.preparePhysicalIdentityRegister(client, nick);
        defer prepared.abort();
        prepared.commit();
    }

    /// Remove any nick owned by `client`.
    pub fn unregisterNick(self: *World, client: ClientId) void {
        if (self.client_nicks.fetchRemove(client)) |removed| {
            // Remove from the authoritative RCU map using the nick string before
            // it is freed below.
            if (self.rcu_nicks) |r| {
                r.nicks.remove(r.writer_participant, removed.value) catch {};
                self.noteRcuNickWrite(r);
            }
            _ = self.nicks.remove(removed.value);
            self.allocator.free(removed.value);
        }
    }

    /// Atomically collapse every nick alias owned by one exact logical-session
    /// client set onto `target`, with `chosen` as the sole lookup owner. The RCU
    /// mirror publishes one immutable replacement snapshot; the fallback maps
    /// are capacity-reserved and their target storage is owned before that
    /// publish. A foreign target, OOM, or malformed owner set therefore leaves
    /// all three indexes unchanged. Returns false only for an exact idempotent
    /// no-op (same sole owner and display spelling).
    pub fn replaceExactSessionNickOwner(
        self: *World,
        target: []const u8,
        chosen: ClientId,
        exact_clients: []const ClientId,
    ) WorldError!bool {
        var prepared = try self.prepareExactSessionNickOwner(target, exact_clients, .{ .claim_exact = chosen });
        defer prepared.abort();
        const changed = prepared.changed;
        prepared.commit();
        return changed;
    }

    /// Atomically retire every World alias owned by one exact logical session
    /// while preserving an independently-authorized foreign owner of `target`.
    /// This is the same-account/distinct-token shared-display exception: the
    /// foreign token remains the sole global lookup owner and the attaching
    /// token cannot leave its previous nick(s) reachable.
    pub fn relinquishExactSessionNickOwners(
        self: *World,
        target: []const u8,
        foreign_owner: ClientId,
        exact_clients: []const ClientId,
    ) WorldError!bool {
        var prepared = try self.prepareExactSessionNickOwner(target, exact_clients, .{ .preserve_foreign = foreign_owner });
        defer prepared.abort();
        const changed = prepared.changed;
        prepared.commit();
        return changed;
    }

    /// Atomically hand an existing nick's primary lookup ownership from one live
    /// transport to another without taking the identity offline. The owned nick
    /// string is moved between reverse-index keys (not copied), the forward maps
    /// are updated in place, and the RCU registry flips directly from `from` to
    /// `to`; observers can therefore never see an intermediate missing nick.
    pub fn transferNick(self: *World, from: ClientId, to: ClientId) WorldError!bool {
        if (from.eql(to)) return self.client_nicks.contains(from);
        if (self.client_nicks.contains(to)) return false;
        const nick = self.client_nicks.get(from) orelse return false;
        const forward = self.nicks.getEntry(nick) orelse return false;
        if (!forward.value_ptr.*.eql(from)) return false;

        // Reserve the reverse-index slot before mutating any authoritative view;
        // everything after the RCU set is allocation-free.
        try self.client_nicks.ensureUnusedCapacity(1);
        const r = try self.ensureRcuNicks();
        const current = r.nicks.lookup(r.writer_participant, nick) orelse return false;
        if (!(@as(ClientId, @bitCast(current))).eql(from)) return false;
        try r.nicks.set(r.writer_participant, nick, @bitCast(to));
        self.noteRcuNickWrite(r);

        forward.value_ptr.* = to;
        const removed = self.client_nicks.fetchRemove(from) orelse unreachable;
        self.client_nicks.putAssumeCapacity(to, removed.value);
        return true;
    }

    pub fn nickOf(self: *const World, client: ClientId) ?[]const u8 {
        return self.client_nicks.get(client);
    }

    fn findNickFallback(self: *const World, nick: []const u8) ?ClientId {
        if (self.nicks.get(nick)) |id| return id;
        var it = self.nicks.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, nick)) return entry.value_ptr.*;
        }
        return null;
    }

    /// Look up the owner of `nick` (CASE-INSENSITIVE). Reads from the lock-free
    /// RCU registry when active (the common case after any nick registers);
    /// falls back to the case-sensitive `nicks` map only when the mirror has
    /// never been activated. `rcu_nicks` is a pointer, so we can pin and look up
    /// through it even from `*const World`.
    pub fn findNick(self: *const World, nick: []const u8) ?ClientId {
        if (self.rcu_nicks) |r| {
            const p = rcuReaderParticipant(&r.domain, r.generation) catch return self.findNickFallback(nick);
            if (r.nicks.lookup(p, nick)) |id| return @as(ClientId, @bitCast(id));
            return null;
        }
        return self.findNickFallback(nick);
    }

    /// Lock-free nick lookup via the RCU mirror (activates it on first use).
    /// Retained for callers that want to force the RCU path; `findNick` now uses
    /// the same registry once active.
    pub fn findNickRcu(self: *World, nick: []const u8) !?ClientId {
        const r = try self.ensureRcuNicks();
        const p = try rcuReaderParticipant(&r.domain, r.generation);
        if (r.nicks.lookup(p, nick)) |id| return @as(ClientId, @bitCast(id));
        return null;
    }

    /// Join a channel. Returns true when membership was newly added.
    pub fn join(self: *World, name: []const u8, client: ClientId) WorldError!bool {
        var logically_present = if (self.channels.getPtr(name)) |channel|
            channel.members.contains(client)
        else
            false;
        if (!logically_present) {
            if (self.rcu_channels) |c| {
                if (rcuMembershipGet(c, name)) |set| {
                    logically_present = set.contains(c.writer_participant, @bitCast(client));
                }
            }
        }
        if (self.channels.getPtr(name)) |channel| {
            if (channel.members.get(client)) |modes| {
                _ = try self.ensureMemberPresentExact(name, client, modes);
                return false;
            }
        }
        const fallback_founding = if (self.channels.getPtr(name)) |channel|
            channel.members.count() == 0 and !channel.ext_modes.has(.registered)
        else
            true;
        const rcu_founding = if (self.rcu_channels) |c|
            if (rcuMembershipGet(c, name)) |set| set.count(c.writer_participant) == 0 else true
        else
            true;
        const founding = fallback_founding and rcu_founding;
        _ = try self.ensureMemberPresentExact(
            name,
            client,
            if (founding) MemberModes.fromModes(&.{.founder}) else MemberModes.empty(),
        );
        return !logically_present;
    }

    /// Re-attach `client` to `name` with EXACT `modes` (Helix UPGRADE carry-over).
    /// Ensures the channel exists and sets the member's status modes verbatim,
    /// bypassing the founder-on-first-join rule so restored state is faithful.
    pub fn restoreMember(self: *World, name: []const u8, client: ClientId, modes: MemberModes) WorldError!void {
        _ = try self.ensureMemberPresentExact(name, client, modes);
    }

    /// Converge one exact membership to present in the fallback and RCU views.
    /// Existing channels stage every fallible publication before updating modes
    /// or inserting into the fallback map. Absent channels are constructed
    /// entirely off-map and installed only after their existence publication
    /// is prepared, so OOM cannot expose a half-joined member or empty shell.
    fn ensureMemberPresentExact(
        self: *World,
        name: []const u8,
        client: ClientId,
        modes: MemberModes,
    ) WorldError!bool {
        if (self.channels.getEntry(name)) |entry| {
            const c = self.rcu_channels orelse return error.NoSuchChannel;
            const fallback_modes = entry.value_ptr.members.get(client);
            if (fallback_modes == null) try entry.value_ptr.members.ensureUnusedCapacity(1);

            var owned_folded: ?[]u8 = null;
            var detached_set: ?*world_rcu.MembershipSet = null;
            var detached_set_initialized = false;
            defer if (detached_set) |membership| {
                if (detached_set_initialized) membership.deinit();
                self.allocator.destroy(membership);
            };
            defer if (owned_folded) |key| self.allocator.free(key);
            var set = rcuMembershipGet(c, entry.key_ptr.*);
            if (set == null) {
                try c.members.ensureUnusedCapacity(self.allocator, 1);
                var folded_buf: [foldBufLen]u8 = undefined;
                owned_folded = try self.allocator.dupe(u8, foldName(entry.key_ptr.*, &folded_buf));
                detached_set = try self.allocator.create(world_rcu.MembershipSet);
                const id_count = entry.value_ptr.members.count() + @intFromBool(fallback_modes == null);
                const ids = try self.allocator.alloc(world_rcu.ClientId, id_count);
                defer self.allocator.free(ids);
                var id_index: usize = 0;
                var id_it = entry.value_ptr.members.keyIterator();
                while (id_it.next()) |id| {
                    ids[id_index] = @bitCast(id.*);
                    id_index += 1;
                }
                if (fallback_modes == null) {
                    ids[id_index] = @bitCast(client);
                    id_index += 1;
                }
                std.debug.assert(id_index == ids.len);
                detached_set.?.* = try world_rcu.MembershipSet.initFromSlice(
                    self.allocator,
                    &c.domain,
                    ids,
                );
                detached_set_initialized = true;
                set = detached_set;
            }

            const rcu_member_present = detached_set != null or
                set.?.contains(c.writer_participant, @bitCast(client));
            const rcu_name_present = c.names.lookup(c.writer_participant, entry.key_ptr.*) != null;
            const retire_count = @as(usize, @intFromBool(!rcu_member_present and detached_set == null)) +
                @as(usize, @intFromBool(!rcu_name_present));
            var reservation: ?ebr.Participant.RetireReservation = if (retire_count != 0)
                try c.writer_participant.reserveRetireCapacity(retire_count)
            else
                null;
            defer if (reservation) |*active_reservation| active_reservation.finish();

            var member_stage: ?world_rcu.MembershipSet.StagedAdd = null;
            var name_stage: ?world_rcu.ChannelRegistry(u32).StagedInsertAbsentBatch = null;
            var committed = false;
            defer if (!committed) {
                if (name_stage) |*stage| stage.abort();
                if (member_stage) |*stage| stage.abort();
            };
            if (!rcu_member_present and detached_set == null) {
                member_stage = try set.?.stageAddReserved(&reservation.?, @bitCast(client));
            }
            if (!rcu_name_present) {
                const inserts = [_]world_rcu.ChannelRegistry(u32).Insert{
                    .{ .key = entry.key_ptr.*, .value = entry.value_ptr.oid },
                };
                name_stage = (try c.names.stageInsertAbsentBatchReserved(&reservation.?, &inserts)) orelse
                    return error.NoSuchChannel;
            }

            // Allocation-free commit boundary.
            const fallback = entry.value_ptr.members.getOrPutAssumeCapacity(client);
            fallback.value_ptr.* = modes;
            if (detached_set) |membership| {
                c.members.putAssumeCapacityNoClobber(owned_folded.?, membership);
                detached_set = null;
                owned_folded = null;
            }
            if (member_stage) |*stage| stage.commit();
            if (name_stage) |*stage| stage.commit();
            if (reservation) |*active_reservation| {
                active_reservation.finish();
                reservation = null;
            }
            if (member_stage != null) self.noteRcuChannelWrite(c);
            if (name_stage != null) self.noteRcuChannelWrite(c);
            committed = true;
            return fallback_modes == null or fallback_modes.?.bits != modes.bits or
                !rcu_member_present or !rcu_name_present;
        }

        try self.channels.ensureUnusedCapacity(1);
        const c = self.rcu_channels orelse try self.createRcuChannelState();
        const owns_channel_rcu = self.rcu_channels == null;
        var owns_channel_state = owns_channel_rcu;
        errdefer if (owns_channel_state) self.destroyDetachedRcuChannelState(c);
        const existing_set = rcuMembershipGet(c, name);
        const existing_oid = c.names.lookup(c.writer_participant, name);
        if (existing_set == null) try c.members.ensureUnusedCapacity(self.allocator, 1);

        var channel = Channel.init(self.allocator);
        var owns_channel = true;
        errdefer if (owns_channel) channel.deinit();
        if (existing_set) |set| {
            const rcu_count = set.count(c.writer_participant);
            const ids = try self.allocator.alloc(world_rcu.ClientId, rcu_count);
            defer self.allocator.free(ids);
            const Collector = struct {
                ids: []world_rcu.ClientId,
                next: usize = 0,

                fn append(ctx: *@This(), id: world_rcu.ClientId) void {
                    ctx.ids[ctx.next] = id;
                    ctx.next += 1;
                }
            };
            var collector = Collector{ .ids = ids };
            set.iterate(c.writer_participant, &collector, Collector.append);
            std.debug.assert(collector.next == ids.len);
            for (ids) |id| try channel.members.put(@bitCast(id), MemberModes.empty());
        }
        try channel.members.put(client, modes);
        channel.oid = existing_oid orelse self.next_oid;
        channel.created_unix = self.clock_unix;
        const owned_name = try self.allocator.dupe(u8, name);
        var owns_name = true;
        errdefer if (owns_name) self.allocator.free(owned_name);

        var owned_folded: ?[]u8 = null;
        var detached_set: ?*world_rcu.MembershipSet = null;
        var detached_set_initialized = false;
        defer if (detached_set) |set| {
            if (detached_set_initialized) set.deinit();
            self.allocator.destroy(set);
        };
        defer if (owned_folded) |key| self.allocator.free(key);
        if (existing_set == null) {
            var folded_buf: [foldBufLen]u8 = undefined;
            owned_folded = try self.allocator.dupe(u8, foldName(name, &folded_buf));
            detached_set = try self.allocator.create(world_rcu.MembershipSet);
            detached_set.?.* = try world_rcu.MembershipSet.initWithOne(
                self.allocator,
                &c.domain,
                @bitCast(client),
            );
            detached_set_initialized = true;
        }

        const rcu_member_present = if (existing_set) |set|
            set.contains(c.writer_participant, @bitCast(client))
        else
            true;
        const retire_count = @as(usize, @intFromBool(existing_set != null and !rcu_member_present)) +
            @as(usize, @intFromBool(existing_oid == null));
        var reservation: ?ebr.Participant.RetireReservation = if (retire_count != 0)
            try c.writer_participant.reserveRetireCapacity(retire_count)
        else
            null;
        defer if (reservation) |*active_reservation| active_reservation.finish();
        var member_stage: ?world_rcu.MembershipSet.StagedAdd = null;
        var name_stage: ?world_rcu.ChannelRegistry(u32).StagedInsertAbsentBatch = null;
        var committed = false;
        defer if (!committed) {
            if (name_stage) |*stage| stage.abort();
            if (member_stage) |*stage| stage.abort();
        };
        if (existing_set != null and !rcu_member_present) {
            member_stage = try existing_set.?.stageAddReserved(&reservation.?, @bitCast(client));
        }
        if (existing_oid == null) {
            const inserts = [_]world_rcu.ChannelRegistry(u32).Insert{
                .{ .key = owned_name, .value = channel.oid },
            };
            name_stage = (try c.names.stageInsertAbsentBatchReserved(&reservation.?, &inserts)) orelse
                return error.NoSuchChannel;
        }

        if (detached_set) |set| {
            c.members.putAssumeCapacityNoClobber(owned_folded.?, set);
            detached_set = null;
            owned_folded = null;
        }
        self.channels.putAssumeCapacityNoClobber(owned_name, channel);
        owns_name = false;
        owns_channel = false;
        // `ensureChannel` publishes the RCU name before its final fallback
        // commit. Adopting that exact in-flight OID must also consume it, or
        // the next genuinely new channel would receive a duplicate OID.
        if (existing_oid == null or existing_oid.? == self.next_oid) self.next_oid +%= 1;
        if (member_stage) |*stage| stage.commit();
        if (name_stage) |*stage| stage.commit();
        if (reservation) |*active_reservation| {
            active_reservation.finish();
            reservation = null;
        }
        if (member_stage != null) self.noteRcuChannelWrite(c);
        if (name_stage != null) self.noteRcuChannelWrite(c);
        committed = true;
        if (owns_channel_rcu) {
            self.rcu_channels = c;
            owns_channel_state = false;
        }
        return true;
    }

    /// Prepare a failure-atomic exact logical-session World restore. Desired
    /// channels are added/repaired with exact modes, claimant memberships absent
    /// from the desired image are removed, and independently connected sibling
    /// clients remain untouched. Absent or one-sided channels are constructed
    /// off-map; no nick, channel, membership, OID, or lazy-RCU pointer changes
    /// semantically until `commit`.
    pub fn prepareSessionRestore(
        self: *World,
        target: []const u8,
        restore_client: ClientId,
        exact_clients: []const ClientId,
        disposition: SessionNickDisposition,
        restores: []const MemberRestore,
    ) WorldError!PreparedSessionRestore {
        if (!clientIdInSet(restore_client, exact_clients)) return error.InvalidOwnerSet;
        switch (disposition) {
            .claim_exact => |nick_owner| {
                if (!clientIdInSet(nick_owner, exact_clients)) return error.InvalidOwnerSet;
            },
            .preserve_foreign => |foreign| {
                if (clientIdInSet(foreign, exact_clients)) return error.InvalidOwnerSet;
            },
        }

        const RestoreKind = enum { fallback, rcu_only, name_only, new };
        const CanonicalRestore = struct {
            name: []const u8,
            modes: MemberModes,
            kind: RestoreKind = .new,
        };
        const OidSet = struct {
            fn contains(oids: []const u32, candidate: u32) bool {
                for (oids) |oid| {
                    if (oid == candidate) return true;
                }
                return false;
            }

            fn skipKnown(oids: []const u32, candidate: *u32) void {
                while (contains(oids, candidate.*)) candidate.* +%= 1;
            }

            fn reserveAfterKnown(oids: []const u32, candidate: *u32) void {
                const start = candidate.*;
                var furthest: ?u32 = null;
                for (oids) |oid| {
                    if (oid < start) continue;
                    if (furthest == null or oid > furthest.?) furthest = oid;
                }
                if (furthest) |oid| candidate.* = oid +% 1;
                skipKnown(oids, candidate);
            }
        };
        const canonical_storage = try self.allocator.alloc(CanonicalRestore, restores.len);
        defer self.allocator.free(canonical_storage);
        var canonical_count: usize = 0;
        const ci: CiStringContext = .{};
        for (restores) |restore| {
            var duplicate: ?usize = null;
            for (canonical_storage[0..canonical_count], 0..) |entry, i| {
                if (ci.eql(entry.name, restore.channel)) {
                    duplicate = i;
                    break;
                }
            }
            if (duplicate) |i| {
                // The last exact mode image wins, matching batch restore.
                canonical_storage[i].modes = restore.modes;
            } else {
                canonical_storage[canonical_count] = .{
                    .name = restore.channel,
                    .modes = restore.modes,
                };
                canonical_count += 1;
            }
        }
        var fallback_count: usize = 0;
        var adopted_count: usize = 0;
        var new_count: usize = 0;
        for (canonical_storage[0..canonical_count]) |*entry| {
            if (self.channels.contains(entry.name)) {
                entry.kind = .fallback;
                fallback_count += 1;
            } else if (self.rcu_channels) |c| {
                if (rcuMembershipGet(c, entry.name) != null) {
                    entry.kind = .rcu_only;
                    adopted_count += 1;
                } else if (c.names.lookup(c.writer_participant, entry.name) != null) {
                    entry.kind = .name_only;
                    new_count += 1;
                } else {
                    entry.kind = .new;
                    new_count += 1;
                }
            } else {
                entry.kind = .new;
                new_count += 1;
            }
        }
        const existing_count = fallback_count + adopted_count;

        // Capacity changes are not semantic entries. Reserve before capturing
        // pointers because channels-map growth may rehash Channel values.
        try self.channels.ensureUnusedCapacity(@intCast(new_count + adopted_count));
        switch (disposition) {
            .claim_exact => {
                try self.nicks.ensureUnusedCapacity(1);
                try self.client_nicks.ensureUnusedCapacity(1);
            },
            .preserve_foreign => {},
        }

        const nick_rcu = self.rcu_nicks orelse try self.createRcuNickState();
        const owns_nick_rcu = self.rcu_nicks == null;
        var owns_nick_state = true;
        errdefer if (owns_nick_rcu and owns_nick_state) self.destroyDetachedRcuNickState(nick_rcu);

        // An empty desired image must still remove stale claimant membership
        // from an already-active RCU projection, but must not create a lazy
        // channel state solely to represent absence.
        const channel_rcu: ?*RcuChannelState = if (canonical_count != 0)
            (self.rcu_channels orelse try self.createRcuChannelState())
        else
            self.rcu_channels;
        const owns_channel_rcu = channel_rcu != null and self.rcu_channels == null;
        var owns_channel_state = true;
        errdefer if (owns_channel_rcu and owns_channel_state) self.destroyDetachedRcuChannelState(channel_rcu.?);
        var rebuild_count: usize = 0;
        if (channel_rcu) |c| {
            for (canonical_storage[0..canonical_count]) |entry| {
                if (entry.kind == .fallback and rcuMembershipGet(c, entry.name) == null)
                    rebuild_count += 1;
            }
            try c.members.ensureUnusedCapacity(self.allocator, @intCast(new_count + rebuild_count));
        }

        // Fail closed on an impossible mirror collision (or on the historical
        // fold-buffer truncation edge) instead of overwriting an unrelated set.
        for (canonical_storage[0..canonical_count], 0..) |entry, i| {
            if (entry.kind != .new) continue;
            var folded_buf: [foldBufLen]u8 = undefined;
            const folded = foldName(entry.name, &folded_buf);
            if (channel_rcu.?.members.contains(folded)) return error.NoSuchChannel;
            for (canonical_storage[0..i]) |prior| {
                if (prior.kind != .new) continue;
                var prior_buf: [foldBufLen]u8 = undefined;
                if (std.mem.eql(u8, foldName(prior.name, &prior_buf), folded))
                    return error.NoSuchChannel;
            }
        }

        // Reserve every current fallback/RCU existence OID before constructing
        // any new channel. This includes omitted channels that survive because
        // of a sibling/foreign keeper or +r; desired-only scanning could reuse
        // their stale current-next OID and create a duplicate.
        const rcu_name_count = if (channel_rcu) |c|
            c.names.count(c.writer_participant)
        else
            0;
        const known_oids_storage = try self.allocator.alloc(u32, self.channels.count() + rcu_name_count);
        defer self.allocator.free(known_oids_storage);
        var known_oid_count: usize = 0;
        var current_channels = self.channels.valueIterator();
        while (current_channels.next()) |channel| {
            known_oids_storage[known_oid_count] = channel.oid;
            known_oid_count += 1;
        }
        if (channel_rcu) |c| {
            const Collector = struct {
                storage: []u32,
                count: *usize,

                fn append(ctx: *@This(), _: []const u8, oid: u32) void {
                    ctx.storage[ctx.count.*] = oid;
                    ctx.count.* += 1;
                }
            };
            var collector = Collector{ .storage = known_oids_storage, .count = &known_oid_count };
            c.names.iterate(c.writer_participant, &collector, Collector.append);
        }
        std.debug.assert(known_oid_count <= known_oids_storage.len);
        const known_oids = known_oids_storage[0..known_oid_count];
        var reserved_next_oid = self.next_oid;
        OidSet.reserveAfterKnown(known_oids, &reserved_next_oid);

        const exact_owned = try self.allocator.dupe(ClientId, exact_clients);
        var owns_exact = true;
        errdefer if (owns_exact) self.allocator.free(exact_owned);
        const owned_target = try self.allocator.dupe(u8, target);
        var owns_target = true;
        errdefer if (owns_target) self.allocator.free(owned_target);
        const existing_members = try self.allocator.alloc(PreparedSessionRestore.ExistingMember, existing_count);
        var owns_existing = true;
        errdefer if (owns_existing) self.allocator.free(existing_members);
        const removal_capacity = self.channels.count() + if (channel_rcu) |c| c.members.count() else 0;
        const removed_members = try self.allocator.alloc(PreparedSessionRestore.RemovedMember, removal_capacity);
        var owns_removed = true;
        errdefer if (owns_removed) self.allocator.free(removed_members);
        const member_stages = try self.allocator.alloc(
            PreparedSessionRestore.MemberStage,
            existing_count + removal_capacity,
        );
        var owns_stages = true;
        errdefer if (owns_stages) self.allocator.free(member_stages);
        const new_channels = try self.allocator.alloc(PreparedSessionRestore.NewChannel, new_count);
        var owns_new = true;
        errdefer if (owns_new) self.allocator.free(new_channels);
        const rebuilt_sets = try self.allocator.alloc(PreparedSessionRestore.RebuiltSet, rebuild_count);
        var owns_rebuilt = true;
        errdefer if (owns_rebuilt) self.allocator.free(rebuilt_sets);
        const adopted_channels = try self.allocator.alloc(PreparedSessionRestore.AdoptedChannel, adopted_count);
        var owns_adopted = true;
        errdefer if (owns_adopted) self.allocator.free(adopted_channels);

        var prepared = PreparedSessionRestore{
            .world = self,
            .restore_client = restore_client,
            .disposition = disposition,
            .exact_clients = exact_owned,
            .owned_target = owned_target,
            .nick_rcu = nick_rcu,
            .owns_nick_rcu = owns_nick_rcu,
            .channel_rcu = channel_rcu,
            .owns_channel_rcu = owns_channel_rcu,
            .existing_members = existing_members,
            .removed_members = removed_members,
            .member_stages = member_stages,
            .new_channels = new_channels,
            .rebuilt_sets = rebuilt_sets,
            .adopted_channels = adopted_channels,
            .next_oid_after = reserved_next_oid,
        };
        owns_nick_state = false;
        owns_channel_state = false;
        owns_exact = false;
        owns_target = false;
        owns_existing = false;
        owns_removed = false;
        owns_stages = false;
        owns_new = false;
        owns_rebuilt = false;
        owns_adopted = false;
        errdefer prepared.abort();

        // Populate all fallback/off-map records before taking an RCU writer
        // lock. Existing set pointers are stable after the capacity reserve.
        for (canonical_storage[0..canonical_count]) |entry| {
            switch (entry.kind) {
                .fallback => {
                    const channel_entry = self.channels.getEntry(entry.name) orelse return error.NoSuchChannel;
                    const set = rcuMembershipGet(channel_rcu.?, channel_entry.key_ptr.*) orelse blk: {
                        rebuilt_sets[prepared.rebuilt_count] = try PreparedSessionRestore.RebuiltSet.init(
                            self.allocator,
                            channel_rcu.?,
                            channel_entry.key_ptr.*,
                            channel_entry.value_ptr,
                            restore_client,
                        );
                        const rebuilt = rebuilt_sets[prepared.rebuilt_count].set;
                        prepared.rebuilt_count += 1;
                        break :blk rebuilt;
                    };
                    if (!channel_entry.value_ptr.members.contains(restore_client))
                        try channel_entry.value_ptr.members.ensureUnusedCapacity(1);
                    existing_members[prepared.existing_count] = .{
                        .name = channel_entry.key_ptr.*,
                        .channel = channel_entry.value_ptr,
                        .set = set,
                        .modes = entry.modes,
                        .insert_name = channel_rcu.?.names.lookup(
                            channel_rcu.?.writer_participant,
                            channel_entry.key_ptr.*,
                        ) == null,
                    };
                    prepared.existing_count += 1;
                },
                .rcu_only => {
                    const set = rcuMembershipGet(channel_rcu.?, entry.name) orelse return error.NoSuchChannel;
                    const existing_oid = channel_rcu.?.names.lookup(channel_rcu.?.writer_participant, entry.name);
                    const oid = existing_oid orelse prepared.next_oid_after;
                    adopted_channels[prepared.adopted_count] = try PreparedSessionRestore.AdoptedChannel.init(
                        self.allocator,
                        channel_rcu.?,
                        entry.name,
                        set,
                        restore_client,
                        entry.modes,
                        oid,
                        self.clock_unix,
                    );
                    const adopted = &adopted_channels[prepared.adopted_count];
                    prepared.adopted_count += 1;
                    existing_members[prepared.existing_count] = .{
                        .name = adopted.owned_name,
                        .channel = &adopted.channel,
                        .set = set,
                        .modes = entry.modes,
                        .insert_name = existing_oid == null,
                    };
                    prepared.existing_count += 1;
                    if (existing_oid == null) {
                        prepared.next_oid_after +%= 1;
                        OidSet.skipKnown(known_oids, &prepared.next_oid_after);
                    }
                },
                .name_only, .new => {
                    const existing_oid = if (entry.kind == .name_only)
                        channel_rcu.?.names.lookup(channel_rcu.?.writer_participant, entry.name)
                    else
                        null;
                    const oid = existing_oid orelse prepared.next_oid_after;
                    new_channels[prepared.new_count] = try PreparedSessionRestore.NewChannel.init(
                        self.allocator,
                        channel_rcu.?,
                        entry.name,
                        restore_client,
                        entry.modes,
                        oid,
                        self.clock_unix,
                        existing_oid == null,
                    );
                    prepared.new_count += 1;
                    if (existing_oid == null) {
                        prepared.next_oid_after +%= 1;
                        OidSet.skipKnown(known_oids, &prepared.next_oid_after);
                    }
                },
            }
        }

        const Desired = struct {
            fn contains(entries: []const CanonicalRestore, context: CiStringContext, name: []const u8) bool {
                for (entries) |entry| {
                    if (context.eql(entry.name, name)) return true;
                }
                return false;
            }
        };
        const desired = canonical_storage[0..canonical_count];

        // Full replacement removes only the reconnecting claimant from every
        // channel omitted by the desired image. Other exact-token attachments
        // are ordinary keepers here and must remain independently connected.
        var channel_it = self.channels.iterator();
        while (channel_it.next()) |entry| {
            if (Desired.contains(desired, ci, entry.key_ptr.*)) continue;
            const set = if (channel_rcu) |c| rcuMembershipGet(c, entry.key_ptr.*) else null;
            const fallback_present = entry.value_ptr.members.contains(restore_client);
            const rcu_present = if (set) |membership|
                membership.contains(channel_rcu.?.writer_participant, @bitCast(restore_client))
            else
                false;
            if (!fallback_present and !rcu_present) continue;

            const fallback_empty_after = !entry.value_ptr.ext_modes.has(.registered) and
                entry.value_ptr.members.count() == @intFromBool(fallback_present);
            const rcu_empty_after = if (set) |membership|
                membership.count(channel_rcu.?.writer_participant) == @intFromBool(rcu_present)
            else
                true;
            const cleanup_channel = fallback_empty_after and rcu_empty_after;
            removed_members[prepared.removed_count] = .{
                .name = entry.key_ptr.*,
                .channel = entry.value_ptr,
                .set = set,
                .fallback_present = fallback_present,
                .rcu_present = rcu_present,
                .cleanup_channel = cleanup_channel,
                .remove_name = cleanup_channel and channel_rcu != null and
                    channel_rcu.?.names.lookup(channel_rcu.?.writer_participant, entry.key_ptr.*) != null,
            };
            prepared.removed_count += 1;
        }

        // Repair the RCU-only half of an interrupted cleanup too. Case-folded
        // keys are valid channel lookup names, and fallback-backed sets were
        // already handled above.
        if (channel_rcu) |c| {
            var rcu_it = c.members.iterator();
            while (rcu_it.next()) |entry| {
                if (self.channels.contains(entry.key_ptr.*)) continue;
                if (Desired.contains(desired, ci, entry.key_ptr.*)) continue;
                const membership = entry.value_ptr.*;
                const rcu_present = membership.contains(c.writer_participant, @bitCast(restore_client));
                if (!rcu_present) continue;
                removed_members[prepared.removed_count] = .{
                    .name = entry.key_ptr.*,
                    .channel = null,
                    .set = membership,
                    .fallback_present = false,
                    .rcu_present = true,
                    // Without fallback metadata we cannot prove the channel was
                    // ephemeral rather than registered. Remove the claimant but
                    // preserve even an empty RCU-only entity conservatively.
                    .cleanup_channel = false,
                    .remove_name = false,
                };
                prepared.removed_count += 1;
            }
        }

        const lock_plan = try self.allocator.alloc(
            PreparedSessionRestore.MemberLockPlan,
            prepared.existing_count + prepared.removed_count,
        );
        defer self.allocator.free(lock_plan);
        var lock_plan_count: usize = 0;
        for (existing_members[0..prepared.existing_count], 0..) |entry, i| {
            lock_plan[lock_plan_count] = .{ .set = entry.set, .action = .{ .add = i } };
            lock_plan_count += 1;
        }
        for (removed_members[0..prepared.removed_count], 0..) |entry, i| {
            if (!entry.rcu_present) continue;
            lock_plan[lock_plan_count] = .{ .set = entry.set.?, .action = .{ .remove = i } };
            lock_plan_count += 1;
        }
        std.mem.sort(
            PreparedSessionRestore.MemberLockPlan,
            lock_plan[0..lock_plan_count],
            {},
            PreparedSessionRestore.MemberLockPlan.lessThan,
        );

        // Validate the mutable fallback owner before acquiring the matching
        // RCU registry lock. The RCU stage repeats the same exact check.
        switch (disposition) {
            .claim_exact => {
                if (self.findNickFallback(target)) |owner| {
                    if (!clientIdInSet(owner, exact_clients)) return error.NickInUse;
                }
            },
            .preserve_foreign => |foreign| {
                const owner = self.findNickFallback(target) orelse return error.NickInUse;
                if (!owner.eql(foreign)) return error.NickInUse;
            },
        }
        const rcu_clients = try self.allocator.alloc(world_rcu.ClientId, exact_clients.len);
        defer self.allocator.free(rcu_clients);
        for (exact_clients, rcu_clients) |client, *rcu_client| rcu_client.* = @bitCast(client);

        const nick_stage: PreparedSessionRestore.NickStage = switch (disposition) {
            .claim_exact => |nick_owner| .{ .claim = (try nick_rcu.nicks.stageReplaceRemovingValues(
                nick_rcu.writer_participant,
                target,
                @bitCast(nick_owner),
                rcu_clients,
            )) orelse return error.NickInUse },
            .preserve_foreign => |foreign| .{ .preserve = (try nick_rcu.nicks.stageRemoveValuesPreservingKey(
                nick_rcu.writer_participant,
                target,
                @bitCast(foreign),
                rcu_clients,
            )) orelse return error.NickInUse },
        };
        prepared.nick_stage = nick_stage;

        var remove_name_count: usize = 0;
        for (removed_members[0..prepared.removed_count]) |entry| {
            if (entry.remove_name) remove_name_count += 1;
        }
        var existing_name_insert_count: usize = 0;
        for (existing_members[0..prepared.existing_count]) |entry| {
            if (entry.insert_name) existing_name_insert_count += 1;
        }
        var new_name_insert_count: usize = 0;
        for (new_channels[0..prepared.new_count]) |channel| {
            if (channel.insert_name) new_name_insert_count += 1;
        }
        const name_insert_count = new_name_insert_count + existing_name_insert_count;
        const has_name_edit = name_insert_count != 0 or remove_name_count != 0;
        const channel_retire_count = lock_plan_count + @intFromBool(has_name_edit);
        if (channel_retire_count != 0) {
            const reservation = try self.allocator.create(ebr.Participant.RetireReservation);
            reservation.* = channel_rcu.?.writer_participant.reserveRetireCapacity(channel_retire_count) catch |err| {
                self.allocator.destroy(reservation);
                return err;
            };
            prepared.member_reservation = reservation;
        }

        // Global writer-lock order: nick registry, unique MembershipSets in
        // ascending address order, then the channel existence registry.
        for (lock_plan[0..lock_plan_count]) |plan| {
            switch (plan.action) {
                .add => {
                    if (try plan.set.stageAddReserved(
                        prepared.member_reservation.?,
                        @bitCast(restore_client),
                    )) |stage| {
                        member_stages[prepared.member_stage_count] = .{ .add = stage };
                        prepared.member_stage_count += 1;
                    }
                },
                .remove => {
                    if (try plan.set.stageRemoveReserved(
                        prepared.member_reservation.?,
                        @bitCast(restore_client),
                    )) |stage| {
                        member_stages[prepared.member_stage_count] = .{ .remove = stage };
                        prepared.member_stage_count += 1;
                    }
                },
            }
        }

        if (has_name_edit) {
            const removals = try self.allocator.alloc([]const u8, remove_name_count);
            defer self.allocator.free(removals);
            var removal_index: usize = 0;
            for (removed_members[0..prepared.removed_count]) |entry| {
                if (!entry.remove_name) continue;
                removals[removal_index] = entry.name;
                removal_index += 1;
            }
            std.debug.assert(removal_index == removals.len);

            const inserts = try self.allocator.alloc(
                world_rcu.ChannelRegistry(u32).Insert,
                name_insert_count,
            );
            defer self.allocator.free(inserts);
            var insert_index: usize = 0;
            for (new_channels[0..prepared.new_count]) |new_channel| {
                if (!new_channel.insert_name) continue;
                inserts[insert_index] = .{ .key = new_channel.owned_name, .value = new_channel.oid };
                insert_index += 1;
            }
            for (existing_members[0..prepared.existing_count]) |entry| {
                if (!entry.insert_name) continue;
                inserts[insert_index] = .{ .key = entry.name, .value = entry.channel.oid };
                insert_index += 1;
            }
            std.debug.assert(insert_index == inserts.len);
            const channel_name_stage = (try channel_rcu.?.names.stageEditBatchReserved(
                prepared.member_reservation.?,
                removals,
                inserts,
            )) orelse return error.NoSuchChannel;
            prepared.channel_name_stage = channel_name_stage;
        }
        return prepared;
    }

    /// Failure-atomically restore one client across an exact batch of channels
    /// that already exist. Every fallback member-map capacity, immutable RCU
    /// membership snapshot, publication box, and EBR retire slot is prepared
    /// before the first semantic mutation. Therefore OutOfMemory leaves all
    /// membership and mode state unchanged; after the commit boundary no step
    /// can fail. Duplicate channel names use the last supplied mode image.
    ///
    /// This deliberately requires existing channels: session handoff merges
    /// authority into channels the departing attachment already occupies. New
    /// channel creation has a separate existence-registry transaction and must
    /// not be smuggled into this no-partial-membership primitive.
    pub fn restoreMembersBatchExisting(
        self: *World,
        client: ClientId,
        restores: []const MemberRestore,
    ) WorldError!bool {
        if (restores.len == 0) return false;
        const c = self.rcu_channels orelse return error.NoSuchChannel;

        const Entry = struct {
            channel: *Channel,
            set: *world_rcu.MembershipSet,
            modes: MemberModes,

            fn lessThan(_: void, a: @This(), b: @This()) bool {
                return @intFromPtr(a.set) < @intFromPtr(b.set);
            }
        };

        const entries = try self.allocator.alloc(Entry, restores.len);
        defer self.allocator.free(entries);
        var entry_count: usize = 0;
        for (restores) |restore| {
            const channel_entry = self.channels.getEntry(restore.channel) orelse return error.NoSuchChannel;
            const set = rcuMembershipGet(c, channel_entry.key_ptr.*) orelse return error.NoSuchChannel;
            var duplicate: ?usize = null;
            for (entries[0..entry_count], 0..) |entry, i| {
                if (entry.channel == channel_entry.value_ptr) {
                    duplicate = i;
                    break;
                }
            }
            if (duplicate) |i| {
                entries[i].modes = restore.modes;
            } else {
                entries[entry_count] = .{
                    .channel = channel_entry.value_ptr,
                    .set = set,
                    .modes = restore.modes,
                };
                entry_count += 1;
            }
        }
        const active_entries = entries[0..entry_count];
        std.mem.sort(Entry, active_entries, {}, Entry.lessThan);

        // Reserve authoritative map capacity before holding any RCU writer
        // locks. Capacity growth is not a semantic membership mutation.
        for (active_entries) |entry| {
            if (!entry.channel.members.contains(client))
                try entry.channel.members.ensureUnusedCapacity(1);
        }

        const staged = try self.allocator.alloc(world_rcu.MembershipSet.StagedAdd, entry_count);
        defer self.allocator.free(staged);
        // stageAdd also reserves one slot for standalone use. This aggregate
        // reservation is what makes a sequence of commits no-allocation: none
        // of the staged retires has entered the limbo bag yet.
        var reservation = try c.writer_participant.reserveRetireCapacity(entry_count);
        defer reservation.finish();

        var staged_count: usize = 0;
        var committed = false;
        defer if (!committed) {
            while (staged_count != 0) {
                staged_count -= 1;
                staged[staged_count].abort();
            }
        };

        var changed = false;
        for (active_entries) |entry| {
            const old_modes = entry.channel.members.get(client);
            if (old_modes == null or old_modes.?.bits != entry.modes.bits) changed = true;
            if (try entry.set.stageAddReserved(&reservation, @bitCast(client))) |prepared| {
                staged[staged_count] = prepared;
                staged_count += 1;
                changed = true;
            }
        }

        // Commit the fallback maps first using pre-reserved capacity, then
        // publish each already-built RCU snapshot. No allocation or error path
        // remains beyond this point, so the operation is failure-atomic.
        for (active_entries) |entry| {
            const member = entry.channel.members.getOrPutAssumeCapacity(client);
            member.value_ptr.* = entry.modes;
        }
        for (staged[0..staged_count]) |*prepared| {
            prepared.commit();
        }
        // Epoch advancement must happen only after every pre-reserved retire is
        // enqueued. Advancing between commits could select a different limbo
        // bag than the one reserved above and reintroduce a post-publication
        // allocation panic.
        for (0..staged_count) |_| self.noteRcuChannelWrite(c);
        committed = true;
        return changed;
    }

    /// Idempotently converge one membership to absent in both the mutable
    /// World map and the lock-free RCU projection. All fallible RCU snapshots
    /// are staged before either view changes, so OutOfMemory preserves the
    /// pre-call state (including any pre-existing one-sided divergence) and a
    /// retry can safely finish the repair.
    ///
    /// When the removal empties an ephemeral channel, the membership and RCU
    /// existence removals are prepared together. Only after both publications
    /// commit do we free the fallback Channel and its per-channel RCU set. A
    /// missing fallback channel is treated as an interrupted prior cleanup and
    /// retries the same RCU teardown instead of returning early.
    pub fn ensureMemberAbsent(
        self: *World,
        name: []const u8,
        client: ClientId,
    ) WorldError!bool {
        const channel_entry = self.channels.getEntry(name);
        const fallback_member_present = if (channel_entry) |entry|
            entry.value_ptr.members.contains(client)
        else
            false;
        const fallback_cleanup_candidate = if (channel_entry) |entry|
            !entry.value_ptr.ext_modes.has(.registered) and
                entry.value_ptr.members.count() == @intFromBool(fallback_member_present)
        else
            true;

        const c = self.rcu_channels orelse {
            if (channel_entry) |entry| {
                if (fallback_cleanup_candidate) {
                    self.removeFallbackChannel(name);
                } else if (fallback_member_present) {
                    _ = entry.value_ptr.members.remove(client);
                }
            }
            return channel_entry != null and (fallback_member_present or fallback_cleanup_candidate);
        };

        const set = rcuMembershipGet(c, name);
        const rcu_member_present = if (set) |membership|
            membership.contains(c.writer_participant, @bitCast(client))
        else
            false;
        // Never tear down an RCU-only channel while unrelated projected
        // members remain. Such a channel is an explicit divergence repair in
        // progress: remove only the requested member and preserve its name/set
        // so a later present-side repair can reconstruct fallback state.
        const rcu_empty_after = if (set) |membership|
            membership.count(c.writer_participant) == @intFromBool(rcu_member_present)
        else
            true;
        const cleanup_channel = fallback_cleanup_candidate and rcu_empty_after;
        const rcu_name_present = cleanup_channel and c.names.lookup(c.writer_participant, name) != null;

        const retire_count: usize = @as(usize, @intFromBool(rcu_member_present)) +
            2 * @as(usize, @intFromBool(rcu_name_present));
        var reservation: ?ebr.Participant.RetireReservation = if (retire_count != 0)
            try c.writer_participant.reserveRetireCapacity(retire_count)
        else
            null;
        defer if (reservation) |*active_reservation| active_reservation.finish();

        var member_stage: ?world_rcu.MembershipSet.StagedRemove = null;
        var name_stage: ?world_rcu.ChannelRegistry(u32).StagedRemove = null;
        var committed = false;
        defer if (!committed) {
            // Reverse the deterministic membership-set -> existence-registry
            // lock order used below.
            if (name_stage) |*stage| stage.abort();
            if (member_stage) |*stage| stage.abort();
        };

        if (rcu_member_present) {
            member_stage = try set.?.stageRemoveReserved(&reservation.?, @bitCast(client));
        }
        if (rcu_name_present) {
            name_stage = try c.names.stageRemoveReserved(&reservation.?, name);
        }

        // No allocation or error path remains beyond this boundary.
        if (member_stage) |*stage| {
            stage.commit();
        }
        if (name_stage) |*stage| {
            stage.commit();
        }
        // Release the shared epoch pin only after every staged retire entered
        // its reserved bag, then account the publications/advance the domain.
        if (reservation) |*active_reservation| {
            active_reservation.finish();
            reservation = null;
        }
        if (member_stage != null) self.noteRcuChannelWrite(c);
        if (name_stage != null) self.noteRcuChannelWrite(c);

        if (cleanup_channel) {
            // The existence publication is already absent (or was absent on
            // entry), so no reader can discover a live channel through it while
            // the fallback record and per-channel set are reclaimed.
            self.removeFallbackChannel(name);
            self.rcuDropMembership(c, name);
        } else if (fallback_member_present) {
            _ = channel_entry.?.value_ptr.members.remove(client);
        }
        committed = true;
        return fallback_member_present or rcu_member_present or
            (cleanup_channel and (channel_entry != null or set != null or rcu_name_present));
    }

    /// One failure-atomic logical-session handoff transaction: merge the
    /// supplied exact membership union into `chosen` and collapse every nick
    /// alias in `exact_clients` onto `target`/`chosen`. Both fallback maps and
    /// every RCU snapshot are fully staged before mutation; an allocation or
    /// collision leaves nick ownership, modes, and all memberships unchanged.
    /// Channels must already exist, matching a live departing attachment.
    pub fn handoffExactSessionIdentity(
        self: *World,
        target: []const u8,
        chosen: ClientId,
        exact_clients: []const ClientId,
        restores: []const MemberRestore,
    ) WorldError!bool {
        if (!clientIdInSet(chosen, exact_clients)) return error.InvalidOwnerSet;

        const MemberEntry = struct {
            channel: *Channel,
            set: *world_rcu.MembershipSet,
            modes: MemberModes,

            fn lessThan(_: void, a: @This(), b: @This()) bool {
                return @intFromPtr(a.set) < @intFromPtr(b.set);
            }
        };

        const member_entries = try self.allocator.alloc(MemberEntry, restores.len);
        defer self.allocator.free(member_entries);
        var member_count: usize = 0;
        const channel_rcu = if (restores.len != 0) self.rcu_channels orelse return error.NoSuchChannel else null;
        for (restores) |restore| {
            const channel_entry = self.channels.getEntry(restore.channel) orelse return error.NoSuchChannel;
            const set = rcuMembershipGet(channel_rcu.?, channel_entry.key_ptr.*) orelse return error.NoSuchChannel;
            var duplicate: ?usize = null;
            for (member_entries[0..member_count], 0..) |entry, i| {
                if (entry.channel == channel_entry.value_ptr) {
                    duplicate = i;
                    break;
                }
            }
            if (duplicate) |i| {
                member_entries[i].modes = restore.modes;
            } else {
                member_entries[member_count] = .{
                    .channel = channel_entry.value_ptr,
                    .set = set,
                    .modes = restore.modes,
                };
                member_count += 1;
            }
        }
        const active_members = member_entries[0..member_count];
        std.mem.sort(MemberEntry, active_members, {}, MemberEntry.lessThan);
        for (active_members) |entry| {
            if (!entry.channel.members.contains(chosen))
                try entry.channel.members.ensureUnusedCapacity(1);
        }

        const nick_rcu = try self.ensureRcuNicks();
        if (nick_rcu.nicks.lookup(nick_rcu.writer_participant, target)) |bits| {
            const owner: ClientId = @bitCast(bits);
            if (!clientIdInSet(owner, exact_clients)) return error.NickInUse;
        }
        if (self.findNickFallback(target)) |owner| {
            if (!clientIdInSet(owner, exact_clients)) return error.NickInUse;
        }

        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        const rcu_clients = try self.allocator.alloc(world_rcu.ClientId, exact_clients.len);
        defer self.allocator.free(rcu_clients);
        for (exact_clients, rcu_clients) |client, *rcu_client| rcu_client.* = @bitCast(client);
        try self.nicks.ensureUnusedCapacity(1);
        try self.client_nicks.ensureUnusedCapacity(1);
        const member_stages = try self.allocator.alloc(world_rcu.MembershipSet.StagedAdd, member_count);
        defer self.allocator.free(member_stages);

        // Lock order is global and deterministic: nick registry first, then
        // unique MembershipSets in ascending address order. Every combined
        // handoff follows this order; ordinary single-registry writers never
        // hold one lock while acquiring another.
        var nick_stage = (try nick_rcu.nicks.stageReplaceRemovingValues(
            nick_rcu.writer_participant,
            target,
            @bitCast(chosen),
            rcu_clients,
        )) orelse return error.NickInUse;
        var nick_committed = false;
        defer if (!nick_committed) nick_stage.abort();

        var member_reservation = if (channel_rcu) |c|
            try c.writer_participant.reserveRetireCapacity(member_count)
        else
            null;
        defer if (member_reservation) |*reservation| reservation.finish();
        var member_stage_count: usize = 0;
        var members_committed = false;
        defer if (!members_committed) {
            while (member_stage_count != 0) {
                member_stage_count -= 1;
                member_stages[member_stage_count].abort();
            }
        };

        // The staged nick replacement always installs a fresh exact owner/key,
        // even when every requested membership mode was already present.
        var changed = true;
        for (active_members) |entry| {
            const old_modes = entry.channel.members.get(chosen);
            if (old_modes == null or old_modes.?.bits != entry.modes.bits) changed = true;
            if (try entry.set.stageAddReserved(&member_reservation.?, @bitCast(chosen))) |prepared| {
                member_stages[member_stage_count] = prepared;
                member_stage_count += 1;
                changed = true;
            }
        }

        // No operation below can allocate or return an error.
        for (active_members) |entry| {
            const member = entry.channel.members.getOrPutAssumeCapacity(chosen);
            member.value_ptr.* = entry.modes;
        }
        for (exact_clients) |client| {
            if (self.client_nicks.fetchRemove(client)) |removed| {
                _ = self.nicks.remove(removed.value);
                self.allocator.free(removed.value);
                changed = true;
            }
        }
        self.nicks.putAssumeCapacity(owned_target, chosen);
        self.client_nicks.putAssumeCapacity(chosen, owned_target);

        for (member_stages[0..member_stage_count]) |*prepared| prepared.commit();
        members_committed = true;
        nick_stage.commit();
        nick_committed = true;
        if (channel_rcu) |c| {
            for (0..member_stage_count) |_| self.noteRcuChannelWrite(c);
        }
        self.noteRcuNickWrite(nick_rcu);
        return changed;
    }

    /// Status modes for `client` in `name`, or null if not a member / no channel.
    pub fn memberModes(self: *World, name: []const u8, client: ClientId) ?MemberModes {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.get(client);
    }

    /// Resolve `nick`'s status modes within `name` by NICK (case-insensitive
    /// ASCII casemapping), without a ClientId in hand. Iterates the channel's
    /// member set and maps each member's ClientId back to its display nick via
    /// `client_nicks`. Returns null when the channel has no such member or no
    /// such channel. Only LOCAL members are stored in the world member
    /// set — remote mesh members live in the per-link route roster — so a remote
    /// sender will not resolve here; callers that must enforce policy against a
    /// remote actor consult the link roster separately.
    pub fn memberModesByNick(self: *World, name: []const u8, nick: []const u8) ?MemberModes {
        const channel = self.channels.getPtr(name) orelse return null;
        var it = channel.members.iterator();
        while (it.next()) |entry| {
            const member_nick = self.client_nicks.get(entry.key_ptr.*) orelse continue;
            if (std.ascii.eqlIgnoreCase(member_nick, nick)) return entry.value_ptr.*;
        }
        return null;
    }

    /// Whether `nick` is a (LOCAL) member of `name`, resolved by NICK
    /// (case-insensitive). Mirrors `memberModesByNick`'s resolution; see its note
    /// on remote members.
    pub fn isMemberByNick(self: *World, name: []const u8, nick: []const u8) bool {
        return self.memberModesByNick(name, nick) != null;
    }

    /// Set or clear one status mode for a member. Returns true if it changed.
    pub fn setMemberMode(
        self: *World,
        name: []const u8,
        client: ClientId,
        mode: MemberMode,
        on: bool,
    ) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const entry = channel.members.getEntry(client) orelse return error.NotOnChannel;
        const before = entry.value_ptr.contains(mode);
        if (on) entry.value_ptr.add(mode) else entry.value_ptr.remove(mode);
        return before != on;
    }

    /// Whether channel flag `mode` (i/m/n/t/s) is set. False if no such channel.
    pub fn channelHasFlag(self: *World, name: []const u8, mode: ChannelMode) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.modes.containsFlag(mode);
    }

    /// Whether an IRCX extended channel flag is set.
    pub fn channelHasExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.ext_modes.has(flag);
    }

    /// The channel's IRCX extended flag set (empty if no such channel).
    pub fn channelExtModes(self: *World, name: []const u8) chanmode_ext.ExtChannelFlags {
        const channel = self.channels.getPtr(name) orelse return chanmode_ext.ExtChannelFlags.empty();
        return channel.ext_modes;
    }

    /// Mark a channel REGISTERED (+r) on behalf of services, materializing an
    /// empty persistent channel if it does not exist yet. A +r channel survives
    /// when its last member leaves (see `part`/`removeClient`), so registering an
    /// unoccupied channel keeps it reserved. Clearing +r leaves the (possibly
    /// empty) channel in place; the next part/disconnect reclaims it normally.
    pub fn markRegistered(self: *World, name: []const u8, on: bool) std.mem.Allocator.Error!bool {
        const channel = try self.ensureChannel(name);
        const before = channel.ext_modes.has(.registered);
        if (on) channel.ext_modes.set(.registered) else channel.ext_modes.clear(.registered);
        return before != on;
    }

    /// Retained, one-shot source handle. Aliases consume the SAME private payload;
    /// no fields, stage IDs or payload getters cross this boundary. The creator
    /// keeps the original write acquisition through terminal publication. Core
    /// validates readiness before WAL and excludes intervening World mutations.
    /// Tokens have a finite owner budget and remain distinct until real quiescent
    /// World destruction; callers must never use a handle after that destruction.
    pub const PreparedRegisteredChannel = opaque {
        pub fn requireOriginalWorld(self: *const PreparedRegisteredChannel, world: *World, creator: std.Thread.Id, acquisition: u64) !void {
            const b = registeredChannelBacking(self);
            if (b.creator != std.Thread.getCurrentId()) return error.ChannelStageWrongCaller;
            if (b.world != world or b.creator != creator or b.acquisition != acquisition) return error.ChannelStageSourceMismatch;
            // Identity validation intentionally also works for a genuine cold
            // interrupted/MAX lane; the original Core supplies that proof.
            try world.lock.requireExclusiveHeldByCurrentThread();
            try b.requireActive();
        }

        pub fn requireReady(self: *const PreparedRegisteredChannel) !void {
            const b = registeredChannelBacking(self);
            try b.requireCaller();
            try b.requirePlacement();
        }

        pub fn bindOriginalCoreScope(self: *PreparedRegisteredChannel, scope: *@import("server.zig").ManagedLeasedWorldScope) !void {
            try self.requireReady();
            const b = registeredChannelBacking(self);
            if (b.core_scope != null) return error.ChannelStageAlreadyBound;
            try scope.bindOriginalRegisteredChannelStage(self);
            b.core_scope = scope;
        }

        pub fn requireColdCancellation(self: *PreparedRegisteredChannel, scope: *@import("server.zig").ManagedLeasedWorldScope) !void {
            const b = registeredChannelBacking(self);
            if (b.creator != std.Thread.getCurrentId()) return error.ChannelStageWrongCaller;
            try b.world.lock.requireExclusiveHeldByCurrentThread();
            try b.requireActive();
            if (b.core_scope != scope) return error.ChannelStageScopeMismatch;
            try scope.requireOriginalRegisteredChannelColdCancellation(self);
        }

        pub fn abortForColdCore(self: *PreparedRegisteredChannel, scope: *@import("server.zig").ManagedLeasedWorldScope) !void {
            try self.requireColdCancellation(scope);
            const b = registeredChannelBacking(self);
            b.discardUnpublished();
            b.retire();
        }

        /// No allocation/I/O/callback follows this source-prevalidated lexical
        /// cut. A private coordinator must not mutate World after requireReady
        /// and before its synced batch plus this terminal publication.
        pub fn commit(self: *PreparedRegisteredChannel) void {
            self.requireReady() catch @panic("original channel World stage not ready");
            const b = registeredChannelBacking(self);
            const world = b.world;
            if (b.existing != null) {
                // requirePlacement resolves and validates the CURRENT entry
                // before any old pointer is dereferenced.
                const channel = world.channels.getPtr(b.target_name).?;
                if (b.on) channel.ext_modes.set(.registered) else channel.ext_modes.clear(.registered);
            } else if (b.new_channel) |channel| {
                const c = b.channel_rcu.?;
                c.members.putAssumeCapacityNoClobber(b.member_key.?, b.member_set.?);
                world.channels.putAssumeCapacityNoClobber(b.owned_name.?, channel);
                b.member_key = null;
                b.member_set = null;
                b.owned_name = null;
                b.new_channel = null;
                world.next_oid = b.next_oid_after;
                b.names.?.commit();
                b.names = null;
                if (b.owns_rcu) world.rcu_channels = c;
                b.owns_rcu = false;
                world.noteRcuChannelWrite(c);
            }
            b.finishReservation();
            b.retire();
        }

        /// Logical conflict does not prevent freeing original UNPUBLISHED
        /// resources. Ordinary abort still requires the exact creator/lane.
        pub fn abort(self: *PreparedRegisteredChannel) void {
            const b = registeredChannelBacking(self);
            if (b.creator != std.Thread.getCurrentId()) @panic("original channel stage creator lost before abort");
            if (!b.active) return;
            b.requireCaller() catch @panic("original channel World acquisition lost before abort");
            b.discardUnpublished();
            b.retire();
        }
    };

    const RegisteredChannelRegistry = opaque {};
    const RegisteredChannelRegistryBacking = struct {
        world: *World,
        active: ?*RegisteredChannelBacking = null,
        tokens: ?*RegisteredChannelBacking = null,
        issued: usize = 0,
    };
    const max_registered_channel_tokens = 4096;

    fn registeredRegistryBacking(handle: *RegisteredChannelRegistry) *RegisteredChannelRegistryBacking {
        return @ptrCast(@alignCast(handle));
    }
    fn registeredChannelBacking(handle: *const PreparedRegisteredChannel) *RegisteredChannelBacking {
        return @ptrCast(@alignCast(@constCast(handle)));
    }
    pub fn requireNoActiveRegisteredChannelStage(self: *World) !void {
        try self.lock.requireExclusiveHeldByCurrentThread();
        if (self.registered_stages) |handle| {
            const r = registeredRegistryBacking(handle);
            if (r.world != self) return error.ChannelStageSourceMismatch;
            if (r.active != null) return error.ChannelStageActive;
        }
    }

    const RegisteredChannelBacking = struct {
        world: *World,
        creator: std.Thread.Id,
        acquisition: u64,
        on: bool,
        next_token: ?*RegisteredChannelBacking = null,
        target_name: []u8,
        target_oid: ?u32,
        original_capacity: u32 = 0,
        original_count: u32 = 0,
        original_next_oid: u32,
        original_rcu: ?*RcuChannelState,
        original_names_root: ?usize,
        original_member_set: ?*world_rcu.MembershipSet,
        original_member_root: ?usize,
        original_registered: bool,
        existing: ?*Channel = null,
        new_channel: ?Channel = null,
        owned_name: ?[]u8 = null,
        member_key: ?[]u8 = null,
        member_set: ?*world_rcu.MembershipSet = null,
        channel_rcu: ?*RcuChannelState = null,
        owns_rcu: bool = false,
        names: ?world_rcu.ChannelRegistry(u32).StagedInsertAbsentBatch = null,
        reservation: ?*ebr.Participant.RetireReservation = null,
        next_oid_after: u32,
        active: bool = false,
        core_scope: ?*@import("server.zig").ManagedLeasedWorldScope = null,

        fn requireActive(self: *const RegisteredChannelBacking) !void {
            const r = registeredRegistryBacking(self.world.registered_stages orelse return error.ConsumedChannelStage);
            if (r.world != self.world or !self.active or r.active != self) return error.ConsumedChannelStage;
        }
        fn requireCaller(self: *const RegisteredChannelBacking) !void {
            if (self.creator != std.Thread.getCurrentId()) return error.ChannelStageWrongCaller;
            // Only the exact creator retires this token; stale creator aliases
            // fail without touching a successor's mutable registry or lane.
            if (!self.active) return error.ConsumedChannelStage;
            try self.world.lock.requireExclusiveAcquisitionByCurrentThread(self.acquisition);
            try self.requireActive();
        }
        fn requirePlacement(self: *const RegisteredChannelBacking) !void {
            const w = self.world;
            if (w.channels.capacity() != self.original_capacity or w.channels.count() != self.original_count or
                w.next_oid != self.original_next_oid or w.rcu_channels != self.original_rcu) return error.ChannelStageConflict;
            const entry = w.channels.getEntry(self.target_name);
            if (self.existing) |original| {
                const current = entry orelse return error.ChannelStageConflict;
                if (current.value_ptr != original or !std.mem.eql(u8, current.key_ptr.*, self.target_name) or
                    current.value_ptr.oid != self.target_oid.? or current.value_ptr.ext_modes.has(.registered) != self.original_registered)
                    return error.ChannelStageConflict;
                var others = w.channels.iterator();
                while (others.next()) |other| {
                    if (other.value_ptr != current.value_ptr and other.value_ptr.oid == self.target_oid.?) return error.ChannelStageConflict;
                }
            } else if (entry != null) return error.ChannelStageConflict;
            if (w.rcu_channels) |c| {
                if (@intFromPtr(c.names.published.load(.acquire)) != self.original_names_root.?) return error.ChannelStageConflict;
                const set = rcuMembershipGet(c, self.target_name);
                if (set != self.original_member_set) return error.ChannelStageConflict;
                if (set) |members| {
                    if (@intFromPtr(members.published.load(.acquire)) != self.original_member_root.?) return error.ChannelStageConflict;
                }
            }
        }
        fn retire(self: *RegisteredChannelBacking) void {
            const r = registeredRegistryBacking(self.world.registered_stages.?);
            std.debug.assert(r.active == self and self.active);
            r.active = null;
            self.active = false;
        }
        fn finishReservation(self: *RegisteredChannelBacking) void {
            if (self.reservation) |reservation| {
                reservation.finish();
                self.world.allocator.destroy(reservation);
                self.reservation = null;
            }
        }

        fn discardUnpublished(self: *RegisteredChannelBacking) void {
            if (self.names) |*names| names.abort();
            self.names = null;
            self.finishReservation();
            if (self.new_channel) |*channel| channel.deinit();
            self.new_channel = null;
            if (self.owned_name) |name| self.world.allocator.free(name);
            self.owned_name = null;
            if (self.member_set) |set| {
                set.deinit();
                self.world.allocator.destroy(set);
            }
            self.member_set = null;
            if (self.member_key) |key| self.world.allocator.free(key);
            self.member_key = null;
            if (self.owns_rcu) self.world.destroyUnpublishedRegisteredRcu(self.channel_rcu.?);
            self.owns_rcu = false;
        }
    };

    /// Prepare +r without changing logical maps, mirrors, memberships, flags
    /// or OIDs. Capacity growth is allowed; no name/root is published. Drop of
    /// an absent channel only funds custody metadata; it never materializes a channel.
    /// Divergent fallback/RCU state and nonrepresentable successor OIDs refuse.
    pub fn prepareRegisteredChannel(self: *World, name: []const u8, on: bool) !*PreparedRegisteredChannel {
        const acquisition = try self.lock.captureExclusiveAcquisitionForCurrentThread();
        try self.requireNoActiveRegisteredChannelStage();
        if (!isChannelName(name) or name.len > foldBufLen) return error.InvalidChannel;
        for (name) |byte| if (byte <= ' ' or byte == ',' or byte == 127) return error.InvalidChannel;
        const registry = if (self.registered_stages) |handle| registeredRegistryBacking(handle) else blk: {
            const r = try self.allocator.create(RegisteredChannelRegistryBacking);
            r.* = .{ .world = self };
            self.registered_stages = @ptrCast(r);
            break :blk r;
        };
        if (registry.issued == max_registered_channel_tokens) return error.ChannelStageCapacity;
        const prepared = try self.allocator.create(RegisteredChannelBacking);
        errdefer self.allocator.destroy(prepared);
        const target = try self.allocator.dupe(u8, if (self.channels.getEntry(name)) |entry| entry.key_ptr.* else name);
        errdefer self.allocator.free(target);
        const existing = self.channels.getPtr(name);
        const original_set = if (self.rcu_channels) |c| rcuMembershipGet(c, name) else null;
        prepared.* = .{
            .world = self,
            .creator = std.Thread.getCurrentId(),
            .acquisition = acquisition,
            .on = on,
            .existing = existing,
            .target_name = target,
            .target_oid = if (existing) |channel| channel.oid else null,
            .original_next_oid = self.next_oid,
            .original_rcu = self.rcu_channels,
            .original_names_root = if (self.rcu_channels) |c| @intFromPtr(c.names.published.load(.acquire)) else null,
            .original_member_set = original_set,
            .original_member_root = if (original_set) |set| @intFromPtr(set.published.load(.acquire)) else null,
            .original_registered = if (existing) |channel| channel.ext_modes.has(.registered) else false,
            .next_oid_after = self.next_oid,
        };
        errdefer prepared.discardUnpublished();
        if (existing) |channel| {
            if (channel.oid == 0) return error.InvalidGraph;
            var others = self.channels.valueIterator();
            while (others.next()) |other| {
                if (other != channel and other.oid == channel.oid) return error.InvalidGraph;
            }
        }

        if (self.rcu_channels) |c| {
            const mirror_oid = c.names.lookup(c.writer_participant, name);
            const mirror_members = rcuMembershipGet(c, name);
            if (prepared.existing) |channel| {
                if (channel.oid == 0 or mirror_oid == null or mirror_oid.? != channel.oid or mirror_members == null or
                    mirror_members.?.count(c.writer_participant) != channel.members.count()) return error.InvalidGraph;
                var members = channel.members.keyIterator();
                while (members.next()) |id| {
                    if (!mirror_members.?.contains(c.writer_participant, @bitCast(id.*))) return error.InvalidGraph;
                }
            } else if (mirror_oid != null or mirror_members != null) return error.InvalidGraph;
        }

        if (prepared.existing == null and on) {
            if (self.next_oid == 0) return error.ObjectIdExhausted;
            var greatest: u32 = 0;
            var channels = self.channels.valueIterator();
            while (channels.next()) |channel| {
                if (channel.oid == 0) return error.InvalidGraph;
                greatest = @max(greatest, channel.oid);
            }
            if (self.rcu_channels) |c| {
                const Oids = struct {
                    fn append(maximum: *u32, _: []const u8, oid: u32) void {
                        maximum.* = @max(maximum.*, oid);
                    }
                };
                c.names.iterate(c.writer_participant, &greatest, Oids.append);
            }
            const after_known = std.math.add(u32, greatest, 1) catch return error.ObjectIdExhausted;
            const oid = @max(self.next_oid, after_known);
            prepared.next_oid_after = std.math.add(u32, oid, 1) catch return error.ObjectIdExhausted;
            try self.channels.ensureUnusedCapacity(1);
            const c = self.rcu_channels orelse try self.prepareRegisteredRcuImage();
            prepared.channel_rcu = c;
            prepared.owns_rcu = self.rcu_channels == null;
            try c.members.ensureUnusedCapacity(self.allocator, 1);
            prepared.owned_name = try self.allocator.dupe(u8, name);
            var folded_buf: [foldBufLen]u8 = undefined;
            prepared.member_key = try self.allocator.dupe(u8, foldName(name, &folded_buf));
            if (c.members.contains(prepared.member_key.?)) return error.InvalidGraph;
            const set = try self.allocator.create(world_rcu.MembershipSet);
            set.* = world_rcu.MembershipSet.init(self.allocator, &c.domain) catch |err| {
                self.allocator.destroy(set);
                return err;
            };
            prepared.member_set = set;
            var channel = Channel.init(self.allocator);
            channel.oid = oid;
            channel.created_unix = self.clock_unix;
            channel.ext_modes.set(.registered);
            prepared.new_channel = channel;
            const reservation = try self.allocator.create(ebr.Participant.RetireReservation);
            reservation.* = c.writer_participant.reserveRetireCapacity(1) catch |err| {
                self.allocator.destroy(reservation);
                return err;
            };
            prepared.reservation = reservation;
            const inserts = [_]world_rcu.ChannelRegistry(u32).Insert{.{ .key = prepared.owned_name.?, .value = oid }};
            prepared.names = (try c.names.stageInsertAbsentBatchReserved(reservation, &inserts)) orelse return error.InvalidGraph;
        }
        prepared.original_capacity = self.channels.capacity();
        prepared.original_count = self.channels.count();
        prepared.next_token = registry.tokens;
        registry.tokens = prepared;
        registry.issued += 1;
        registry.active = prepared;
        prepared.active = true;
        return @ptrCast(prepared);
    }

    /// Build a complete private mirror when legacy fallback records exist but
    /// the lazy RCU image is inactive. Publishing a target-only image would hide
    /// unrelated channels and their memberships from lock-free readers.
    fn prepareRegisteredRcuImage(self: *World) !*RcuChannelState {
        const c = try self.createRcuChannelState();
        errdefer self.destroyUnpublishedRegisteredRcu(c);
        var channels = self.channels.iterator();
        while (channels.next()) |entry| {
            const name = entry.key_ptr.*;
            if (name.len > foldBufLen) return error.InvalidGraph;
            const set = try self.allocator.create(world_rcu.MembershipSet);
            set.* = world_rcu.MembershipSet.init(self.allocator, &c.domain) catch |err| {
                self.allocator.destroy(set);
                return err;
            };
            var owned_set = true;
            errdefer if (owned_set) {
                set.deinit();
                self.allocator.destroy(set);
            };
            var members = entry.value_ptr.members.keyIterator();
            while (members.next()) |id| try set.add(c.writer_participant, @bitCast(id.*));
            var folded_buf: [foldBufLen]u8 = undefined;
            const key = try self.allocator.dupe(u8, foldName(name, &folded_buf));
            var owned_key = true;
            errdefer if (owned_key) self.allocator.free(key);
            try c.members.put(self.allocator, key, set);
            owned_set = false;
            owned_key = false;
            try c.names.set(c.writer_participant, name, entry.value_ptr.oid);
        }
        return c;
    }

    fn destroyUnpublishedRegisteredRcu(self: *World, c: *RcuChannelState) void {
        var members = c.members.iterator();
        while (members.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        c.members.clearRetainingCapacity();
        self.destroyDetachedRcuChannelState(c);
    }

    /// Set or clear an IRCX extended channel flag. Returns true if it changed.
    pub fn setChannelExtFlag(self: *World, name: []const u8, flag: chanmode_ext.ExtChannelFlag, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.ext_modes.has(flag);
        if (on) channel.ext_modes.set(flag) else channel.ext_modes.clear(flag);
        return before != on;
    }

    /// Set or clear a channel flag mode (i/m/n/t/s). Returns true if it changed.
    pub fn setChannelFlag(self: *World, name: []const u8, mode: ChannelMode, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.modes.containsFlag(mode);
        switch (mode) {
            .invite_only => channel.modes.invite_only = on,
            .moderated => channel.modes.moderated = on,
            .no_external => channel.modes.no_external = on,
            .topic_ops => channel.modes.topic_ops = on,
            .secret => channel.modes.secret = on,
            .no_ctcp => channel.modes.no_ctcp = on,
            .no_notice => channel.modes.no_notice = on,
            .no_nick => channel.modes.no_nick = on,
            .free_invite => channel.modes.free_invite = on,
            .tls_only => channel.modes.tls_only = on,
            .mod_reg => channel.modes.mod_reg = on,
            .news_wire => channel.modes.news_wire = on,
            .oper_only => channel.modes.oper_only = on,
            .admin_only => channel.modes.admin_only = on,
            else => return error.UnsupportedMode, // not a flag mode (b/e/I/k/l)
        }
        return before != on;
    }

    /// Set (`key != null`) or clear the +k channel key. New key is heap-owned;
    /// any prior key is freed.
    pub fn setChannelKey(self: *World, name: []const u8, key: ?[]const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const owned = if (key) |k| try self.allocator.dupe(u8, k) else null;
        if (channel.key) |old| self.allocator.free(old);
        channel.key = owned;
    }

    pub fn channelKey(self: *World, name: []const u8) ?[]const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.key;
    }

    /// Set (`limit != null`) or clear the +l member limit.
    pub fn setChannelLimit(self: *World, name: []const u8, limit: ?u32) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.limit = limit;
    }

    pub fn channelLimit(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.limit;
    }

    /// The IRCX object id assigned to `name` at creation (null if no such channel).
    /// Unix-seconds creation time assigned to `name` at creation (null if no such
    /// channel; 0 if created before the server set a clock). IRCX CREATION prop.
    pub fn channelCreatedUnix(self: *World, name: []const u8) ?i64 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.created_unix;
    }

    pub fn channelOid(self: *World, name: []const u8) ?u32 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.oid;
    }

    fn cloneListEntries(self: *World, src: []const ListEntry) WorldError!std.ArrayListUnmanaged(ListEntry) {
        var out: std.ArrayListUnmanaged(ListEntry) = .empty;
        errdefer deinitListEntries(self.allocator, &out);
        for (src) |entry| {
            var copy = try ListEntry.init(self.allocator, entry.mask, entry.setter, entry.set_at);
            out.append(self.allocator, copy) catch |err| {
                copy.deinit(self.allocator);
                return err;
            };
        }
        return out;
    }

    pub const PreparedCloneTemplate = struct {
        world: *World,
        dst: []u8,
        template: Channel,
        active: bool = true,

        pub fn abort(self: *PreparedCloneTemplate) void {
            if (!self.active) return;
            self.template.deinit();
            self.world.allocator.free(self.dst);
            self.active = false;
        }

        /// Seat the first member through World's existing failure-atomic JOIN,
        /// then install every pre-owned template field without allocation. A JOIN
        /// error leaves no destination entity; success has no later error path.
        pub fn commitSeated(
            self: *PreparedCloneTemplate,
            client: ClientId,
            modes: MemberModes,
        ) WorldError!void {
            std.debug.assert(self.active);
            std.debug.assert(!self.world.channelExists(self.dst));
            const newly_joined = try self.world.join(self.dst, client);
            std.debug.assert(newly_joined);
            const destination = self.world.channels.getPtr(self.dst) orelse unreachable;
            const member_modes = destination.members.getPtr(client) orelse unreachable;
            member_modes.* = modes;

            const members = destination.members;
            destination.members = MemberMap.init(self.world.allocator);
            const oid = destination.oid;
            const created_unix = destination.created_unix;
            destination.deinit();
            self.template.members.deinit();
            self.template.members = members;
            self.template.oid = oid;
            self.template.created_unix = created_unix;
            destination.* = self.template;
            self.template = Channel.init(self.world.allocator);
            self.world.allocator.free(self.dst);
            self.active = false;
        }
    };

    /// Own a complete clone template off-map. No destination existence or member
    /// state is published until PreparedCloneTemplate.commitSeated succeeds.
    pub fn prepareCloneTemplate(self: *World, src: []const u8, dst: []const u8) WorldError!?PreparedCloneTemplate {
        if (self.channels.getPtr(src) == null) return error.NoSuchChannel;
        if (self.channelExists(dst)) return null;

        const owned_dst = try self.allocator.dupe(u8, dst);
        errdefer self.allocator.free(owned_dst);
        const tmpl = self.channels.getPtr(src).?;
        var template = Channel.init(self.allocator);
        errdefer template.deinit();
        template.modes = tmpl.modes;
        template.limit = tmpl.limit;
        template.private = tmpl.private;
        template.hidden = tmpl.hidden;
        template.throttle_joins = tmpl.throttle_joins;
        template.throttle_secs = tmpl.throttle_secs;
        template.ext_modes = tmpl.ext_modes;
        template.ext_modes.set(.clone);
        template.ext_modes.clear(.cloneable);
        template.key = if (tmpl.key) |key| try self.allocator.dupe(u8, key) else null;
        template.forward = if (tmpl.forward) |forward| try self.allocator.dupe(u8, forward) else null;
        template.topic = if (tmpl.topic) |topic_text| try self.allocator.dupe(u8, topic_text) else null;
        template.topic_setter = if (tmpl.topic_setter) |setter| try self.allocator.dupe(u8, setter) else null;
        template.topic_time = tmpl.topic_time;
        template.bans = try self.cloneListEntries(tmpl.bans.items);
        template.exempts = try self.cloneListEntries(tmpl.exempts.items);
        template.invex = try self.cloneListEntries(tmpl.invex.items);
        template.mutes = try self.cloneListEntries(tmpl.mutes.items);
        return .{ .world = self, .dst = owned_dst, .template = template };
    }

    /// IRCX CLONE: create `dst` as a portable room/template clone of `src`,
    /// copying channel-level modes, limit/key/forward/throttle configuration,
    /// topic metadata, list-mode masks, and ext flags, while marking the new
    /// channel `+E` (clone) but not `+d` (a clone is not itself a cloneable
    /// template, so clones never recurse). Membership and pending invites are not
    /// copied — the clone starts empty with a fresh OID. Returns false if `dst`
    /// already exists; `error.NoSuchChannel` if `src` does not.
    pub fn cloneChannel(self: *World, src: []const u8, dst: []const u8) WorldError!bool {
        if (self.channels.getPtr(src) == null) return error.NoSuchChannel;
        if (self.channels.contains(dst)) return false;

        // Snapshot the template fields BEFORE ensureChannel: getOrPut may rehash
        // and invalidate a pointer into the map.
        const tmpl = self.channels.getPtr(src).?;
        const modes = tmpl.modes;
        const limit = tmpl.limit;
        const private = tmpl.private;
        const hidden = tmpl.hidden;
        const throttle_joins = tmpl.throttle_joins;
        const throttle_secs = tmpl.throttle_secs;
        var ext = tmpl.ext_modes;
        const key_copy: ?[]u8 = if (tmpl.key) |k| try self.allocator.dupe(u8, k) else null;
        errdefer if (key_copy) |k| self.allocator.free(k);
        const forward_copy: ?[]u8 = if (tmpl.forward) |f| try self.allocator.dupe(u8, f) else null;
        errdefer if (forward_copy) |f| self.allocator.free(f);
        const topic_copy: ?[]u8 = if (tmpl.topic) |t| try self.allocator.dupe(u8, t) else null;
        errdefer if (topic_copy) |t| self.allocator.free(t);
        const topic_setter_copy: ?[]u8 = if (tmpl.topic_setter) |s| try self.allocator.dupe(u8, s) else null;
        errdefer if (topic_setter_copy) |s| self.allocator.free(s);
        const topic_time = tmpl.topic_time;
        var bans_copy = try self.cloneListEntries(tmpl.bans.items);
        errdefer deinitListEntries(self.allocator, &bans_copy);
        var exempts_copy = try self.cloneListEntries(tmpl.exempts.items);
        errdefer deinitListEntries(self.allocator, &exempts_copy);
        var invex_copy = try self.cloneListEntries(tmpl.invex.items);
        errdefer deinitListEntries(self.allocator, &invex_copy);
        var mutes_copy = try self.cloneListEntries(tmpl.mutes.items);
        errdefer deinitListEntries(self.allocator, &mutes_copy);

        const clone = try self.ensureChannel(dst);
        clone.modes = modes;
        clone.limit = limit;
        clone.private = private;
        clone.hidden = hidden;
        clone.throttle_joins = throttle_joins;
        clone.throttle_secs = throttle_secs;
        ext.set(.clone);
        ext.clear(.cloneable);
        clone.ext_modes = ext;
        clone.key = key_copy;
        clone.forward = forward_copy;
        clone.topic = topic_copy;
        clone.topic_setter = topic_setter_copy;
        clone.topic_time = topic_time;
        clone.bans = bans_copy;
        clone.exempts = exempts_copy;
        clone.invex = invex_copy;
        clone.mutes = mutes_copy;
        return true;
    }

    /// Rename a channel in place (draft/channel-rename): rekey the existing
    /// Channel value from `old` to `new`, preserving membership, modes, bans,
    /// topic, OID, and creation time. Returns false if `new` already exists;
    /// `error.NoSuchChannel` if `old` does not. The Channel carries no internal
    /// name, so a map rekey is a complete rename.
    pub fn renameChannel(self: *World, old: []const u8, new: []const u8) WorldError!bool {
        if (!self.channels.contains(old)) return error.NoSuchChannel;
        if (self.channels.contains(new)) return false;

        const oid = if (self.channels.getPtr(old)) |ch| ch.oid else 0;

        const new_key = try self.allocator.dupe(u8, new);
        errdefer self.allocator.free(new_key);
        const kv = self.channels.fetchRemove(old).?; // {key, value}
        self.channels.put(new_key, kv.value) catch |e| {
            // Re-insert under the original key so the channel is never lost.
            self.channels.put(kv.key, kv.value) catch {};
            return e;
        };
        self.allocator.free(kv.key);

        // Keep the RCU mirrors in step: re-key existence (same OID) and move the
        // membership set to the new folded key. Best-effort; the authoritative
        // store is `channels`.
        if (self.rcu_channels) |c| {
            self.rcuRenameMembership(c, old, new);
            // Existence: drop the old folded name only if it no longer maps to a
            // live channel (case-fold may coincide with `new`), then publish new.
            var ob: [foldBufLen]u8 = undefined;
            var nb: [foldBufLen]u8 = undefined;
            const of = foldName(old, &ob);
            const nf = foldName(new, &nb);
            if (!std.mem.eql(u8, of, nf)) {
                c.names.remove(c.writer_participant, old) catch {};
                self.noteRcuChannelWrite(c);
            }
            c.names.set(c.writer_participant, new, oid) catch {};
            self.noteRcuChannelWrite(c);
        }
        return true;
    }

    /// +p private channel flag.
    pub fn setPrivate(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.private;
        channel.private = on;
        return before != on;
    }
    pub fn isPrivate(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.private;
    }

    /// +h IRCX HIDDEN channel flag (omit from LIST).
    pub fn setHidden(self: *World, name: []const u8, on: bool) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const before = channel.hidden;
        channel.hidden = on;
        return before != on;
    }
    pub fn isHidden(self: *World, name: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.hidden;
    }

    pub fn memberCount(self: *World, name: []const u8) usize {
        const channel = self.channels.getPtr(name) orelse return 0;
        return channel.members.count();
    }

    /// Add a +b ban mask. Returns true if newly added (false if already present).
    pub fn addBan(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.bans, mask, setter, set_at);
    }

    /// Remove a +b ban mask. Returns true if it existed.
    pub fn removeBan(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        for (channel.bans.items, 0..) |*b, idx| {
            if (std.mem.eql(u8, b.mask, mask)) {
                b.deinit(self.allocator);
                _ = channel.bans.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    /// Ban masks for RPL_BANLIST, or null if no such channel.
    pub fn bansOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.bans.items;
    }

    fn listAddMask(
        self: *World,
        list: *std.ArrayListUnmanaged(ListEntry),
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
    ) WorldError!bool {
        try validateListMask(mask);
        for (list.items) |m| {
            if (std.mem.eql(u8, m.mask, mask)) return false;
        }
        // Cap channel list modes to bound memory and resist ban-list flooding.
        if (list.items.len >= self.max_list_entries) return error.ListFull;
        const entry = try ListEntry.init(self.allocator, mask, setter, set_at);
        errdefer {
            var rollback = entry;
            rollback.deinit(self.allocator);
        }
        try list.append(self.allocator, entry);
        return true;
    }

    fn listRemoveMask(self: *World, list: *std.ArrayListUnmanaged(ListEntry), mask: []const u8) bool {
        for (list.items, 0..) |*m, idx| {
            if (std.mem.eql(u8, m.mask, mask)) {
                m.deinit(self.allocator);
                _ = list.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    fn validateListMask(mask: []const u8) WorldError!void {
        if (mask.len != 0 and mask[0] == '$') {
            _ = extban.parse(mask) catch return error.InvalidMask;
        }
    }

    fn listMatches(list: []const ListEntry, hostmask: []const u8) bool {
        for (list) |m| {
            if (listx.globMatch(m.mask, hostmask)) return true;
        }
        return false;
    }

    /// Client view used for extended-ban (`$a:`/`$r:`/`$g:`/`$c:`/`$~...`)
    /// evaluation. Re-exported from the extban parser so callers build one place.
    pub const BanContext = extban.ClientContext;

    const ExtbanMutePolicy = enum { include, exclude, only };

    /// Like `listMatches`, but each entry may be an extended ban. Plain masks
    /// fall through to a host glob against `ctx.host` (the full nick!user@host
    /// prefix), preserving classic +b/+e/+I/+Z behavior; `$`-prefixed entries
    /// match account/realname/country/channel/negation. Malformed `$` entries
    /// are rejected when stored; any legacy malformed `$` state is ignored rather
    /// than downgraded to a host glob.
    fn listMatchesCtx(list: []const ListEntry, ctx: extban.ClientContext, mute_policy: ExtbanMutePolicy) bool {
        for (list) |m| {
            if (extban.parse(m.mask)) |matcher| {
                const is_mute = matcher.rootMatchKind() == .mute;
                switch (mute_policy) {
                    .include => {},
                    .exclude => if (is_mute) continue,
                    .only => if (!is_mute) continue,
                }
                if (matcher.matches(ctx)) return true;
            } else |_| {
                if (m.mask.len != 0 and m.mask[0] == '$') continue;
                if (mute_policy == .only) continue;
                if (listx.globMatch(m.mask, ctx.host)) return true;
            }
        }
        return false;
    }

    /// +e ban-exception list operations.
    pub fn addExempt(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.exempts, mask, setter, set_at);
    }
    pub fn removeExempt(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.exempts, mask);
    }
    pub fn exemptsOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.exempts.items;
    }
    pub fn isExempt(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.exempts.items, hostmask);
    }

    /// +I invite-exception list operations.
    pub fn addInvex(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.invex, mask, setter, set_at);
    }
    pub fn removeInvex(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.invex, mask);
    }
    pub fn invexOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.invex.items;
    }
    pub fn isInvexed(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatches(channel.invex.items, hostmask);
    }

    /// +Z quiet (MUTE) list operations.
    pub fn addMute(self: *World, name: []const u8, mask: []const u8, setter: []const u8, set_at: i64) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listAddMask(&channel.mutes, mask, setter, set_at);
    }
    pub fn removeMute(self: *World, name: []const u8, mask: []const u8) WorldError!bool {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        return self.listRemoveMask(&channel.mutes, mask);
    }
    pub fn mutesOf(self: *World, name: []const u8) ?[]const ListEntry {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.mutes.items;
    }
    /// Whether `hostmask` is quieted (+Z) and not saved by a +e exempt.
    pub fn isMuted(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatches(channel.exempts.items, hostmask)) return false;
        return listMatches(channel.mutes.items, hostmask);
    }

    /// +f forward target. `target == null` clears it. Owns a duped copy.
    pub fn setForward(self: *World, name: []const u8, target: ?[]const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        const owned = if (target) |t| try self.allocator.dupe(u8, t) else null;
        if (channel.forward) |old| self.allocator.free(old);
        channel.forward = owned;
    }
    /// The +f forward target for `name`, or null when unset / no such channel.
    pub fn forwardOf(self: *World, name: []const u8) ?[]const u8 {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.forward;
    }

    /// Outcome of a join against the throttle window. `throttled_alert` means the
    /// join was denied AND this is the first denial in the current window, so the
    /// caller should raise a one-shot raid alert (the per-channel alert timestamp
    /// has already been stamped).
    pub const ThrottleResult = enum { admitted, throttled, throttled_alert };

    /// +j join-throttle config.
    pub fn setThrottle(self: *World, name: []const u8, joins: u16, secs: u32) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.throttle_joins = joins;
        channel.throttle_secs = secs;
        channel.throttle_times.clearRetainingCapacity();
        channel.throttle_alert_ms = 0;
    }
    pub fn clearThrottle(self: *World, name: []const u8) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        channel.throttle_joins = 0;
        channel.throttle_secs = 0;
        channel.throttle_times.clearRetainingCapacity();
        channel.throttle_alert_ms = 0;
    }
    /// Returns the active throttle as {joins, secs}, or null when disabled.
    pub fn throttleOf(self: *World, name: []const u8) ?struct { joins: u16, secs: u32 } {
        const channel = self.channels.getPtr(name) orelse return null;
        if (channel.throttle_joins == 0) return null;
        return .{ .joins = channel.throttle_joins, .secs = channel.throttle_secs };
    }
    /// Admit one join against the join-throttle window. The effective rate is the
    /// channel's explicit +j when set, otherwise the network default
    /// (`default_joins`/`default_secs`, 0 = no default) — so a server-wide raid
    /// guard reuses the exact same machinery as the per-channel mode. Prunes
    /// expired timestamps, then denies without recording if the window is full,
    /// else records `now` and admits. A denial stamps `throttle_alert_ms` once per
    /// window and reports `.throttled_alert` so the caller can fire a raid alert.
    pub fn throttleAdmit(self: *World, name: []const u8, now_ms: i64, default_joins: u16, default_secs: u32) ThrottleResult {
        const channel = self.channels.getPtr(name) orelse return .admitted;
        const explicit = channel.throttle_joins != 0;
        const joins: u16 = if (explicit) channel.throttle_joins else default_joins;
        const secs: u32 = if (explicit) channel.throttle_secs else default_secs;
        if (joins == 0 or secs == 0) return .admitted;
        const window_ms: i64 = @as(i64, secs) * 1000;
        // Prune timestamps outside the window (compact in place).
        var kept: usize = 0;
        for (channel.throttle_times.items) |ts| {
            if (now_ms - ts < window_ms) {
                channel.throttle_times.items[kept] = ts;
                kept += 1;
            }
        }
        channel.throttle_times.shrinkRetainingCapacity(kept);
        if (channel.throttle_times.items.len >= joins) {
            // Window full: deny. Alert at most once per window per channel.
            if (channel.throttle_alert_ms == 0 or now_ms - channel.throttle_alert_ms >= window_ms) {
                channel.throttle_alert_ms = now_ms;
                return .throttled_alert;
            }
            return .throttled;
        }
        channel.throttle_times.append(self.allocator, now_ms) catch return .admitted; // alloc fail: fail-open
        return .admitted;
    }

    /// Whether `hostmask` (nick!user@host) matches any +b entry (case-insensitive
    /// glob via listx.globMatch).
    pub fn isBanned(self: *World, name: []const u8, hostmask: []const u8) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        // A +e ban-exception match overrides any +b ban.
        if (listMatches(channel.exempts.items, hostmask)) return false;
        return listMatches(channel.bans.items, hostmask);
    }

    /// Extended-ban-aware +b check: `ctx.host` carries the full nick!user@host
    /// prefix (so plain masks behave exactly as `isBanned`), while `$`-typed
    /// bans match the richer context. A matching +e exception (also extban-aware)
    /// overrides the ban.
    pub fn isBannedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatchesCtx(channel.exempts.items, ctx, .exclude)) return false;
        return listMatchesCtx(channel.bans.items, ctx, .exclude);
    }

    /// Extended-ban-aware +Z quiet check (mirrors `isMuted`).
    pub fn isMutedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        if (listMatchesCtx(channel.exempts.items, ctx, .include)) return false;
        return listMatchesCtx(channel.mutes.items, ctx, .include) or
            listMatchesCtx(channel.bans.items, ctx, .only);
    }

    /// Extended-ban-aware +I invite-exception check (mirrors `isInvexed`).
    pub fn isInvexedCtx(self: *World, name: []const u8, ctx: extban.ClientContext) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return listMatchesCtx(channel.invex.items, ctx, .include);
    }

    /// Record an INVITE so the target may bypass +i.
    pub fn addInvite(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.invites.put(self.allocator, client, {});
    }

    /// Whether `client` holds a pending invite (does not consume it).
    pub fn hasInvite(self: *World, name: []const u8, client: ClientId) bool {
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.invites.contains(client);
    }

    /// Render the active channel flag modes as a "+imnt"-style string into `out`.
    pub fn channelModeString(self: *World, name: []const u8, out: []u8) []const u8 {
        const channel = self.channels.getPtr(name) orelse {
            if (out.len >= 1) {
                out[0] = '+';
                return out[0..1];
            }
            return out[0..0];
        };
        var n: usize = 0;
        if (n < out.len) {
            out[n] = '+';
            n += 1;
        }
        const flags = [_]struct { m: ChannelMode, c: u8 }{
            .{ .m = .invite_only, .c = 'i' },
            .{ .m = .moderated, .c = 'm' },
            .{ .m = .no_external, .c = 'n' },
            .{ .m = .topic_ops, .c = 't' },
            .{ .m = .secret, .c = 's' },
            .{ .m = .no_ctcp, .c = 'C' },
            .{ .m = .no_notice, .c = 'T' },
            .{ .m = .no_nick, .c = 'N' },
            .{ .m = .free_invite, .c = 'g' },
            .{ .m = .tls_only, .c = 'S' },
            .{ .m = .mod_reg, .c = 'M' },
            .{ .m = .news_wire, .c = 'W' },
            .{ .m = .oper_only, .c = 'O' },
            .{ .m = .admin_only, .c = 'A' },
        };
        for (flags) |f| {
            if (channel.modes.containsFlag(f.m) and n < out.len) {
                out[n] = f.c;
                n += 1;
            }
        }
        if (channel.private and n < out.len) {
            out[n] = 'p';
            n += 1;
        }
        if (channel.hidden and n < out.len) {
            out[n] = 'h';
            n += 1;
        }
        return out[0..n];
    }

    /// Part a channel, deleting it when the last member leaves.
    pub fn part(self: *World, name: []const u8, client: ClientId) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        if (!channel.members.contains(client)) return error.NotOnChannel;
        _ = try self.ensureMemberAbsent(name, client);
    }

    /// Whether `client` is a member of `name` (CASE-INSENSITIVE channel name).
    /// Reads the lock-free RCU membership set when active; falls back to the
    /// authoritative member map otherwise.
    pub fn isMember(self: *World, name: []const u8, client: ClientId) bool {
        if (self.rcu_channels) |c| {
            const p = rcuReaderParticipant(&c.domain, c.generation) catch {
                const channel = self.channels.getPtr(name) orelse return false;
                return channel.members.contains(client);
            };
            if (rcuMembershipGet(c, name)) |set|
                return set.contains(p, @bitCast(client));
            return false;
        }
        const channel = self.channels.getPtr(name) orelse return false;
        return channel.members.contains(client);
    }

    /// Whether `name` exists (CASE-INSENSITIVE). Reads the lock-free RCU
    /// existence mirror when active; falls back to the case-sensitive map
    /// otherwise. `rcu_channels` is a pointer so this works through `*const`.
    pub fn channelExists(self: *const World, name: []const u8) bool {
        if (self.rcu_channels) |c| {
            const p = rcuReaderParticipant(&c.domain, c.generation) catch return self.channels.contains(name);
            return c.names.lookup(p, name) != null;
        }
        return self.channels.contains(name);
    }

    pub fn channelCount(self: *const World) usize {
        return self.channels.count();
    }

    /// Count of locally-owned registered nicks. The `nicks`/RCU map holds only
    /// LOCAL clients (remote mesh users are projected per-channel, never
    /// registered here), so this is the node-wide local user count. It reads
    /// through the lock-free RCU registry with a per-thread reader participant,
    /// so it is safe to call from ANY reactor shard — unlike iterating a single
    /// reactor's connection set, which only sees that shard's clients. Used by
    /// LUSERS/MAP so their counts are consistent regardless of which shard the
    /// querying client landed on under multithreading.
    pub fn localNickCount(self: *World) usize {
        const r = self.ensureRcuNicks() catch return self.nicks.count();
        const p = rcuReaderParticipant(&r.domain, r.generation) catch return self.nicks.count();
        return r.nicks.count(p);
    }

    /// Materialize an empty channel so remote mesh-owned list state (+b/+e/+I)
    /// can be stored before any local user joins it. Joining later still grants
    /// founder status because the member set is empty.
    pub fn ensureRemoteListChannel(self: *World, name: []const u8) WorldError!void {
        _ = try self.ensureChannel(name);
    }

    /// Read-only view of a channel for LIST.
    pub const ChannelView = struct {
        name: []const u8,
        members: usize,
        topic: []const u8,
        secret: bool,
        hidden: bool,
        /// Wall-clock unix seconds the channel was created (0 = unset).
        created_unix: i64,
        /// Wall-clock unix seconds the topic was last set (0 = no topic/unset).
        topic_time: i64,
        /// Whether the channel carries the registered (+r) ext flag.
        registered: bool,
    };

    pub const ChannelViewIterator = struct {
        inner: CiStringHashMap(Channel).Iterator,

        pub fn next(self: *ChannelViewIterator) ?ChannelView {
            if (self.inner.next()) |entry| {
                return .{
                    .name = entry.key_ptr.*,
                    .members = entry.value_ptr.members.count(),
                    .topic = entry.value_ptr.topic orelse "",
                    .secret = entry.value_ptr.modes.secret,
                    .hidden = entry.value_ptr.hidden,
                    .created_unix = entry.value_ptr.created_unix,
                    .topic_time = entry.value_ptr.topic_time,
                    .registered = entry.value_ptr.ext_modes.has(.registered),
                };
            }
            return null;
        }
    };

    pub fn channelIterator(self: *World) ChannelViewIterator {
        return .{ .inner = self.channels.iterator() };
    }

    /// Every logical field of one channel that participates in a Helix world
    /// checkpoint. Slices borrow World storage and are valid only while the
    /// caller keeps the World read-locked and does not mutate it.
    pub const CheckpointChannelView = struct {
        name: []const u8,
        topic: ?[]const u8,
        topic_setter: ?[]const u8,
        topic_time: i64,
        base_mode_bits: u16,
        ext_mode_bits: u32,
        private: bool,
        hidden: bool,
        key: ?[]const u8,
        limit: ?u32,
        forward: ?[]const u8,
        oid: u32,
        created_unix: i64,
        bans: []const ListEntry,
        exempts: []const ListEntry,
        invex: []const ListEntry,
        mutes: []const ListEntry,
        throttle_joins: u16,
        throttle_secs: u32,
        throttle_times: []const i64,
        throttle_alert_ms: i64,
        member_count: usize,
        invite_count: usize,
    };

    pub const CheckpointChannelIterator = struct {
        inner: CiStringHashMap(Channel).Iterator,

        pub fn next(self: *CheckpointChannelIterator) ?CheckpointChannelView {
            const entry = self.inner.next() orelse return null;
            const channel = entry.value_ptr;
            return .{
                .name = entry.key_ptr.*,
                .topic = channel.topic,
                .topic_setter = channel.topic_setter,
                .topic_time = channel.topic_time,
                .base_mode_bits = checkpointBaseModeBits(channel.modes),
                .ext_mode_bits = @bitCast(channel.ext_modes),
                .private = channel.private,
                .hidden = channel.hidden,
                .key = channel.key,
                .limit = channel.limit,
                .forward = channel.forward,
                .oid = channel.oid,
                .created_unix = channel.created_unix,
                .bans = channel.bans.items,
                .exempts = channel.exempts.items,
                .invex = channel.invex.items,
                .mutes = channel.mutes.items,
                .throttle_joins = channel.throttle_joins,
                .throttle_secs = channel.throttle_secs,
                .throttle_times = channel.throttle_times.items,
                .throttle_alert_ms = channel.throttle_alert_ms,
                .member_count = channel.members.count(),
                .invite_count = channel.invites.count(),
            };
        }
    };

    /// Checkpoint traversal intentionally exposes no ClientId on the wire.
    /// A missing reverse nick is a corrupt live invariant and must fail the
    /// upgrade rather than silently dropping the member or invite.
    pub const CheckpointRelationError = error{MissingClientNick};

    pub const CheckpointMemberView = struct {
        nick: []const u8,
        modes: MemberModes,
    };

    /// Raw process-local relation used only while constructing a Helix
    /// checkpoint.  A reusable logical session deliberately has one global
    /// nick lookup owner but may have several real channel-member transports;
    /// those sibling ids therefore need the server's ConnState resolver rather
    /// than the single-owner `client_nicks` mirror.
    pub const CheckpointMemberIdView = struct {
        client: ClientId,
        modes: MemberModes,
    };

    pub const CheckpointMemberIdIterator = struct {
        inner: MemberMap.Iterator,

        pub fn next(self: *CheckpointMemberIdIterator) ?CheckpointMemberIdView {
            const entry = self.inner.next() orelse return null;
            return .{ .client = entry.key_ptr.*, .modes = entry.value_ptr.* };
        }
    };

    pub const CheckpointMemberIterator = struct {
        world: *World,
        inner: MemberMap.Iterator,

        pub fn next(self: *CheckpointMemberIterator) CheckpointRelationError!?CheckpointMemberView {
            const entry = self.inner.next() orelse return null;
            const nick = self.world.client_nicks.get(entry.key_ptr.*) orelse
                return error.MissingClientNick;
            return .{ .nick = nick, .modes = entry.value_ptr.* };
        }
    };

    pub const CheckpointInviteIterator = struct {
        world: *World,
        inner: InviteMap.Iterator,

        pub fn next(self: *CheckpointInviteIterator) CheckpointRelationError!?[]const u8 {
            const entry = self.inner.next() orelse return null;
            return self.world.client_nicks.get(entry.key_ptr.*) orelse
                error.MissingClientNick;
        }
    };

    pub const CheckpointInviteIdIterator = struct {
        inner: InviteMap.Iterator,

        pub fn next(self: *CheckpointInviteIdIterator) ?ClientId {
            const entry = self.inner.next() orelse return null;
            return entry.key_ptr.*;
        }
    };

    pub fn checkpointChannelIterator(self: *World) CheckpointChannelIterator {
        return .{ .inner = self.channels.iterator() };
    }

    pub fn checkpointMemberIterator(self: *World, name: []const u8) ?CheckpointMemberIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return .{ .world = self, .inner = channel.members.iterator() };
    }

    pub fn checkpointMemberIdIterator(self: *World, name: []const u8) ?CheckpointMemberIdIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return .{ .inner = channel.members.iterator() };
    }

    pub fn checkpointInviteIterator(self: *World, name: []const u8) ?CheckpointInviteIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return .{ .world = self, .inner = channel.invites.iterator() };
    }

    pub fn checkpointInviteIdIterator(self: *World, name: []const u8) ?CheckpointInviteIdIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return .{ .inner = channel.invites.iterator() };
    }

    pub fn checkpointNextOid(self: *const World) u32 {
        return self.next_oid;
    }

    pub fn checkpointClockUnix(self: *const World) i64 {
        return self.clock_unix;
    }

    pub fn checkpointMaxListEntries(self: *const World) usize {
        return self.max_list_entries;
    }

    pub const CheckpointListEntry = struct {
        mask: []const u8,
        setter: []const u8,
        set_at: i64,
    };

    /// Borrowed decoded input used only while constructing a detached World.
    /// Memberships and invites are deliberately absent: their ClientIds change
    /// at exec and are applied later from the codec's opaque physical join-key
    /// expectations (the live daemon uses inherited socket fds).
    pub const CheckpointChannelState = struct {
        name: []const u8,
        topic: ?[]const u8,
        topic_setter: ?[]const u8,
        topic_time: i64,
        base_mode_bits: u16,
        ext_mode_bits: u32,
        private: bool,
        hidden: bool,
        key: ?[]const u8,
        limit: ?u32,
        forward: ?[]const u8,
        oid: u32,
        created_unix: i64,
        bans: []const CheckpointListEntry,
        exempts: []const CheckpointListEntry,
        invex: []const CheckpointListEntry,
        mutes: []const CheckpointListEntry,
        throttle_joins: u16,
        throttle_secs: u32,
        throttle_times: []const i64,
        throttle_alert_ms: i64,
    };

    pub const CheckpointRestoreError = std.mem.Allocator.Error || error{
        ActiveWorld,
        DuplicateChannel,
        InvalidChannelName,
        InvalidModeBits,
        ListFull,
    };

    /// Set the World-wide scalars on a fresh, detached replacement image.
    /// Refusing an already-active World prevents a decoder from publishing a
    /// half-restored image through existing RCU mirrors.
    pub fn initializeCheckpointImage(
        self: *World,
        max_list_entries: usize,
        next_oid: u32,
        clock_unix: i64,
    ) CheckpointRestoreError!void {
        if (self.channels.count() != 0 or self.nicks.count() != 0 or
            self.client_nicks.count() != 0 or self.rcu_nicks != null or
            self.rcu_channels != null)
            return error.ActiveWorld;
        self.max_list_entries = max_list_entries;
        self.next_oid = next_oid;
        self.clock_unix = clock_unix;
    }

    /// Add one fully-owned channel to a fresh detached checkpoint image. The
    /// channel's RCU existence and empty-membership mirrors are built here too,
    /// so successor relation application can immediately call restoreMember.
    /// This detached image is the atomicity boundary: the outer decoder destroys
    /// the complete image on any error and publishes it only after full decode.
    pub fn restoreCheckpointChannel(
        self: *World,
        state: CheckpointChannelState,
    ) CheckpointRestoreError![]const u8 {
        if (self.nicks.count() != 0 or self.client_nicks.count() != 0 or self.rcu_nicks != null)
            return error.ActiveWorld;
        if (!isChannelName(state.name)) return error.InvalidChannelName;
        if (self.channels.contains(state.name)) return error.DuplicateChannel;
        if (state.bans.len > self.max_list_entries or
            state.exempts.len > self.max_list_entries or
            state.invex.len > self.max_list_entries or
            state.mutes.len > self.max_list_entries)
            return error.ListFull;

        var channel = Channel.init(self.allocator);
        errdefer channel.deinit();
        channel.modes = checkpointBaseModes(state.base_mode_bits) orelse
            return error.InvalidModeBits;
        if ((state.ext_mode_bits & ~checkpoint_ext_mode_mask) != 0)
            return error.InvalidModeBits;
        channel.ext_modes = @bitCast(state.ext_mode_bits);
        channel.private = state.private;
        channel.hidden = state.hidden;
        channel.topic = if (state.topic) |value| try self.allocator.dupe(u8, value) else null;
        channel.topic_setter = if (state.topic_setter) |value| try self.allocator.dupe(u8, value) else null;
        channel.topic_time = state.topic_time;
        channel.key = if (state.key) |value| try self.allocator.dupe(u8, value) else null;
        channel.limit = state.limit;
        channel.forward = if (state.forward) |value| try self.allocator.dupe(u8, value) else null;
        channel.oid = state.oid;
        channel.created_unix = state.created_unix;
        try restoreCheckpointList(self.allocator, &channel.bans, state.bans);
        try restoreCheckpointList(self.allocator, &channel.exempts, state.exempts);
        try restoreCheckpointList(self.allocator, &channel.invex, state.invex);
        try restoreCheckpointList(self.allocator, &channel.mutes, state.mutes);
        channel.throttle_joins = state.throttle_joins;
        channel.throttle_secs = state.throttle_secs;
        try channel.throttle_times.appendSlice(self.allocator, state.throttle_times);
        channel.throttle_alert_ms = state.throttle_alert_ms;

        // Build the authoritative map entry and both RCU mirrors through the
        // normal failure-safe creation path. Its provisional OID consumption is
        // undone because the checkpoint's scalar and per-channel OID are exact.
        const checkpoint_next_oid = self.next_oid;
        const destination = try self.ensureChannel(state.name);
        destination.deinit();
        destination.* = channel;
        channel = Channel.init(self.allocator);
        self.next_oid = checkpoint_next_oid;
        const c = self.rcu_channels orelse unreachable;
        try c.names.set(c.writer_participant, state.name, state.oid);
        self.noteRcuChannelWrite(c);
        return self.channels.getEntry(state.name).?.key_ptr.*;
    }

    /// Fill `out` with the names of channels `client` is a member of (scan; no
    /// reverse index yet). Returns the count written, capped at `out.len`.
    /// Channel-name slices borrow from world storage and stay valid until the
    /// channel is removed.
    /// Count how many channels `client` is a member of (no buffer needed).
    pub fn channelCountOf(self: *World, client: ClientId) usize {
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.members.contains(client)) n += 1;
        }
        return n;
    }

    pub fn channelsOf(self: *World, client: ClientId, out: [][]const u8) usize {
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (n >= out.len) break;
            if (entry.value_ptr.members.contains(client)) {
                out[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        return n;
    }

    pub fn memberIterator(self: *World, name: []const u8) ?MemberIterator {
        const channel = self.channels.getPtr(name) orelse return null;
        return channel.members.keyIterator();
    }

    pub fn setTopic(self: *World, name: []const u8, text: []const u8, setter: []const u8, set_at: i64) WorldError!void {
        const channel = self.channels.getPtr(name) orelse return error.NoSuchChannel;
        try channel.setTopic(text, setter, set_at);
    }

    pub fn topic(self: *const World, name: []const u8) ?[]const u8 {
        const channel = self.channels.get(name) orelse return null;
        return channel.topic;
    }

    pub fn topicInfo(self: *const World, name: []const u8) ?TopicInfo {
        const channel = self.channels.get(name) orelse return null;
        const text = channel.topic orelse return null;
        return .{
            .text = text,
            .setter = channel.topic_setter orelse "",
            .set_at = channel.topic_time,
        };
    }

    pub fn resolveMessageTarget(self: *World, target: []const u8) WorldError!MessageTarget {
        if (isChannelName(target)) {
            const entry = self.channels.getEntry(target) orelse return error.NoSuchChannel;
            return .{ .channel = entry.key_ptr.* };
        }

        if (self.findNick(target)) |client| {
            return .{ .nick = client };
        }
        return error.NoSuchNick;
    }

    /// Remove `client` from all registries and channels.
    pub fn removeClient(self: *World, client: ClientId) void {
        self.unregisterNick(client);

        while (true) {
            var empty_channel: ?[]const u8 = null;
            var it = self.channels.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.members.remove(client)) {
                    // Mirror the membership removal for channels that survive;
                    // removed channels have their whole set dropped below.
                    if (self.rcu_channels) |c| {
                        if (rcuMembershipGet(c, entry.key_ptr.*)) |set| {
                            set.remove(c.writer_participant, @bitCast(client)) catch {};
                            self.noteRcuChannelWrite(c);
                        }
                    }
                }
                // Registered (+r) channels persist across empty; only reclaim
                // ephemeral channels on the last member's disconnect.
                if (entry.value_ptr.members.count() == 0 and
                    !entry.value_ptr.ext_modes.has(.registered))
                {
                    empty_channel = entry.key_ptr.*;
                    break;
                }
            }
            if (empty_channel) |name| {
                self.removeChannel(name);
            } else {
                break;
            }
        }
    }

    fn ensureChannel(self: *World, name: []const u8) std.mem.Allocator.Error!*Channel {
        const entry = try self.channels.getOrPut(name);
        if (entry.found_existing) return entry.value_ptr;

        var owned_name: ?[]u8 = null;
        errdefer {
            if (owned_name) |owned| self.allocator.free(owned);
            self.channels.removeByPtr(entry.key_ptr);
        }
        owned_name = try self.allocator.dupe(u8, name);
        const oid = self.next_oid;

        // Activate + populate the RCU existence mirror BEFORE finalising the map
        // entry, so a mirror-alloc failure rolls back cleanly (errdefer above).
        const c = try self.ensureRcuChannels();
        try c.names.set(c.writer_participant, name, oid);
        self.noteRcuChannelWrite(c);
        errdefer {
            c.names.remove(c.writer_participant, name) catch {};
            self.noteRcuChannelWrite(c);
        }
        // Pre-create the (empty) membership set so isMember/joins are mirrored.
        _ = try self.rcuMembershipSet(c, name);

        entry.key_ptr.* = owned_name.?;
        entry.value_ptr.* = Channel.init(self.allocator);
        entry.value_ptr.oid = oid;
        entry.value_ptr.created_unix = self.clock_unix;
        self.next_oid +%= 1;
        return entry.value_ptr;
    }

    fn removeChannel(self: *World, name: []const u8) void {
        if (self.channels.getEntry(name)) |entry| {
            const owned_name = entry.key_ptr.*;
            entry.value_ptr.deinit();
            self.channels.removeByPtr(entry.key_ptr);
            // Tear down the RCU mirrors for this channel (existence + members).
            if (self.rcu_channels) |c| {
                c.names.remove(c.writer_participant, owned_name) catch {};
                self.noteRcuChannelWrite(c);
                self.rcuDropMembership(c, owned_name);
            }
            self.allocator.free(owned_name);
        }
    }

    /// Remove only the authoritative fallback record. RCU teardown must have
    /// already converged (or never have been activated) before this is called.
    fn removeFallbackChannel(self: *World, name: []const u8) void {
        if (self.channels.getEntry(name)) |entry| {
            const owned_name = entry.key_ptr.*;
            entry.value_ptr.deinit();
            self.channels.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_name);
        }
    }
};

/// Max length of a name we case-fold into a stack buffer. Channel and nick
/// names are far shorter in practice; longer names truncate-fold (still
/// deterministic, only an academic edge case for absurd lengths).
const foldBufLen = 256;
const rcuAdvanceWriteInterval: usize = 64;
const rcuAdvancePasses: usize = 3;

test "World prepared registration preserves old owner when first allocation fails" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer world.deinit();
    const client = testClient(200);
    try world.registerNick("Before", client);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, world.registerNick("After", client));
    try std.testing.expectEqualStrings("Before", world.nickOf(client).?);
    try std.testing.expectEqual(@as(?ClientId, client), world.findNick("before"));
    try std.testing.expect(world.findNick("after") == null);
}

test "World prepared identity rename and exact logical nick ownership preserve memberships and foreign policy" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = testClient(201);
    const b = testClient(202);
    const foreign = testClient(203);
    try world.registerNick("Old", a);
    try world.registerNick("Alias", b);
    try world.registerNick("Foreign", foreign);
    try world.restoreMember("#Room", a, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#Room", b, MemberModes.fromModes(&.{.voice}));
    var aborted = try world.preparePhysicalIdentityRename(a, "New");
    try std.testing.expectEqualStrings("Old", world.nickOf(a).?);
    try std.testing.expect(world.findNick("new") == null);
    aborted.abort();
    aborted.abort();
    var renamed = try world.preparePhysicalIdentityRename(a, "OLD");
    defer renamed.abort();
    renamed.commit();
    try std.testing.expectEqualStrings("OLD", world.nickOf(a).?);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#room", a).?.bits);
    try std.testing.expect(world.isMember("#ROOM", a));
    try std.testing.expectError(error.NickInUse, world.preparePhysicalIdentityRegister(b, "old"));
    var shared = try world.prepareExactSessionNickOwner("OLD", &.{ a, b }, .{ .claim_exact = b });
    defer shared.abort();
    try std.testing.expectEqual(@as(?ClientId, a), world.findNick("old"));
    shared.commit();
    try std.testing.expect(world.nickOf(a) == null);
    try std.testing.expectEqual(@as(?ClientId, b), world.findNick("old"));
    try std.testing.expect(world.findNick("alias") == null);
    try std.testing.expect(world.isMember("#room", a));
    try std.testing.expect(world.isMember("#room", b));
    var preserved = try world.prepareExactSessionNickOwner("Foreign", &.{ a, b }, .{ .preserve_foreign = foreign });
    defer preserved.abort();
    preserved.commit();
    try std.testing.expect(world.nickOf(b) == null);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("foreign"));
    try std.testing.expect(world.isMember("#room", a));
    try std.testing.expect(world.isMember("#room", b));
    try std.testing.expectError(error.InvalidOwnerSet, world.prepareExactSessionNickOwner("Foreign", &.{ a, a }, .{ .claim_exact = a }));
    try std.testing.expectError(error.InvalidOwnerSet, world.prepareExactSessionNickOwner("Foreign", &.{ a, foreign }, .{ .preserve_foreign = foreign }));
}

test "World prepared exact nick noops remove RCU only aliases and registration exact spelling allocates nothing" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer world.deinit();
    const a = testClient(204);
    const b = testClient(205);
    const foreign = testClient(206);
    try world.registerNick("Chosen", a);
    try world.registerNick("Foreign", foreign);
    const r = world.rcu_nicks.?;
    try r.nicks.set(r.writer_participant, "Ghost", @bitCast(b));
    var claimed = try world.prepareExactSessionNickOwner("Chosen", &.{ a, b }, .{ .claim_exact = a });
    defer claimed.abort();
    try std.testing.expect(claimed.changed);
    try std.testing.expectEqual(@as(?ClientId, b), world.findNick("ghost"));
    claimed.commit();
    try std.testing.expect(world.findNick("ghost") == null);
    try r.nicks.set(r.writer_participant, "Ghost", @bitCast(b));
    var preserved = try world.prepareExactSessionNickOwner("Foreign", &.{b}, .{ .preserve_foreign = foreign });
    defer preserved.abort();
    try std.testing.expect(preserved.changed);
    preserved.commit();
    try std.testing.expect(world.findNick("ghost") == null);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("foreign"));
    const count = failing.allocations;
    failing.fail_index = failing.alloc_index;
    try world.registerNick("Chosen", a);
    try std.testing.expectEqual(count, failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
}

fn worldPreparedRemoveFixture(world: *World, client: ClientId, keeper: ClientId) !void {
    try world.registerNick("Departing", client);
    try world.registerNick("Keeper", keeper);
    try world.restoreMember("#Ephemeral", client, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#Registered", client, MemberModes.fromModes(&.{.voice}));
    _ = try world.markRegistered("#Registered", true);
    _ = try world.markRegistered("#EmptyRegistered", true);
    try world.restoreMember("#Shared", client, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#Shared", keeper, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#RcuOnly", client, MemberModes.empty());
    world.removeFallbackChannel("#RcuOnly");
    try world.channels.getPtr("#Shared").?.invites.put(world.allocator, client, {});
    try world.channels.getPtr("#Shared").?.invites.put(world.allocator, keeper, {});
    try world.channels.getPtr("#EmptyRegistered").?.invites.put(world.allocator, client, {});
    // Interrupted historical unregister can leave a nick alias with no reverse.
    try world.rcu_nicks.?.nicks.set(world.rcu_nicks.?.writer_participant, "Ghost", @bitCast(client));
}

fn worldPreparedRemoveBefore(world: *World, client: ClientId, keeper: ClientId) !void {
    try std.testing.expectEqualStrings("Departing", world.nickOf(client).?);
    try std.testing.expectEqual(@as(?ClientId, client), world.findNick("departing"));
    try std.testing.expectEqual(@as(?ClientId, client), world.findNick("ghost"));
    for ([_][]const u8{ "#ephemeral", "#registered", "#shared", "#rcuonly" }) |name| try std.testing.expect(world.isMember(name, client));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#EPHEMERAL", client).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#shared", client).?.bits);
    try std.testing.expect(world.isMember("#shared", keeper));
    try std.testing.expect(world.channels.getPtr("#Shared").?.invites.contains(client));
    try std.testing.expect(world.channels.getPtr("#EmptyRegistered").?.invites.contains(client));
}

fn worldPreparedRemoveAfter(world: *World, client: ClientId, keeper: ClientId) !void {
    try std.testing.expect(world.nickOf(client) == null);
    try std.testing.expect(world.findNick("departing") == null);
    try std.testing.expect(world.findNick("ghost") == null);
    try std.testing.expectEqual(@as(?ClientId, keeper), world.findNick("keeper"));
    try std.testing.expect(!world.channels.contains("#ephemeral"));
    try std.testing.expect(!world.channelExists("#EPHEMERAL"));
    for ([_][]const u8{ "#registered", "#shared", "#rcuonly" }) |name| {
        try std.testing.expect(world.channelExists(name));
        try std.testing.expect(!world.isMember(name, client));
    }
    try std.testing.expectEqual(@as(usize, 0), world.channels.getPtr("#registered").?.members.count());
    try std.testing.expect(world.channelExists("#emptyregistered"));
    try std.testing.expect(!world.channels.getPtr("#EmptyRegistered").?.invites.contains(client));
    const shared = world.channels.getPtr("#shared").?;
    try std.testing.expect(!shared.members.contains(client));
    try std.testing.expect(!shared.invites.contains(client));
    try std.testing.expect(shared.invites.contains(keeper));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, shared.members.get(keeper).?.bits);
    try std.testing.expect(world.isMember("#shared", keeper));
}

test "World prepared physical removal abort is inert and commit cleans members invites ephemeral and RCU only aliases" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const client = testClient(207);
    const keeper = testClient(208);
    try worldPreparedRemoveFixture(&world, client, keeper);
    var aborted = try world.preparePhysicalIdentityRemove(client);
    try worldPreparedRemoveBefore(&world, client, keeper);
    aborted.abort();
    aborted.abort();
    try worldPreparedRemoveBefore(&world, client, keeper);
    var prepared = try world.preparePhysicalIdentityRemove(client);
    defer prepared.abort();
    prepared.commit();
    try worldPreparedRemoveAfter(&world, client, keeper);
    var repeated = try world.preparePhysicalIdentityRemove(client);
    defer repeated.abort();
    repeated.commit();
    try worldPreparedRemoveAfter(&world, client, keeper);
}

test "World prepared physical removal exhaustive allocation failure rollback retry and allocation free commit" {
    const client = testClient(209);
    const keeper = testClient(210);
    var index: usize = 0;
    while (index < 10000) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var world = World.init(failing.allocator());
        defer world.deinit();
        try worldPreparedRemoveFixture(&world, client, keeper);
        const nick_root = world.rcu_nicks.?.nicks.published.load(.acquire);
        const channel_root = world.rcu_channels.?.names.published.load(.acquire);
        failing.fail_index = failing.alloc_index + index;
        var prepared = world.preparePhysicalIdentityRemove(client) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(nick_root, world.rcu_nicks.?.nicks.published.load(.acquire));
            try std.testing.expectEqual(channel_root, world.rcu_channels.?.names.published.load(.acquire));
            try worldPreparedRemoveBefore(&world, client, keeper);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try world.preparePhysicalIdentityRemove(client);
            defer retry.abort();
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            retry.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try worldPreparedRemoveAfter(&world, client, keeper);
            continue;
        };
        defer prepared.abort();
        try std.testing.expect(!failing.has_induced_failure);
        const allocations = failing.allocations;
        failing.fail_index = failing.alloc_index;
        prepared.commit();
        try std.testing.expectEqual(allocations, failing.allocations);
        try std.testing.expect(!failing.has_induced_failure);
        try worldPreparedRemoveAfter(&world, client, keeper);
        try std.testing.expect(index > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "World prepared physical nick exhaustive allocation rollback detached activation retry and no fail commit" {
    for ([_]bool{ false, true }) |rename| {
        var index: usize = 0;
        while (index < 10000) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var world = World.init(failing.allocator());
            defer world.deinit();
            const client = testClient(211);
            if (rename) {
                try world.registerNick("Before", client);
                try world.restoreMember("#Room", client, MemberModes.fromModes(&.{.op}));
            }
            const old_rcu = world.rcu_nicks;
            const old_root = if (old_rcu) |r| r.nicks.published.load(.acquire) else null;
            failing.fail_index = failing.alloc_index + index;
            var prepared = world.preparePhysicalIdentityRegister(client, "After") catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(old_rcu, world.rcu_nicks);
                if (old_rcu) |r| try std.testing.expectEqual(old_root, r.nicks.published.load(.acquire));
                if (rename) {
                    try std.testing.expectEqualStrings("Before", world.nickOf(client).?);
                    try std.testing.expectEqual(@as(?ClientId, client), world.findNick("before"));
                    try std.testing.expect(world.isMember("#room", client));
                } else {
                    try std.testing.expect(world.nickOf(client) == null);
                    try std.testing.expectEqual(@as(usize, 0), world.nicks.count());
                }
                failing.fail_index = std.math.maxInt(usize);
                var retry = try world.preparePhysicalIdentityRegister(client, "After");
                defer retry.abort();
                const allocations = failing.allocations;
                failing.fail_index = failing.alloc_index;
                retry.commit();
                try std.testing.expectEqual(allocations, failing.allocations);
                try std.testing.expectEqual(@as(?ClientId, client), world.findNick("after"));
                if (rename) try std.testing.expect(world.isMember("#room", client));
                continue;
            };
            defer prepared.abort();
            try std.testing.expectEqual(old_rcu, world.rcu_nicks);
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            prepared.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(?ClientId, client), world.findNick("after"));
            try std.testing.expect(world.findNick("before") == null);
            if (rename) try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#Room", client).?.bits);
            break;
        }
        try std.testing.expect(index > 0 and index < 10000);
    }
}

test "World prepared removal handles channel less nick owner and membership only attachment independently" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const nick_owner = testClient(212);
    const member_only = testClient(213);
    const sibling = testClient(214);
    try world.registerNick("SharedDisplay", nick_owner);
    try world.restoreMember("#Physical", member_only, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#Physical", sibling, MemberModes.fromModes(&.{.op}));
    var owner_remove = try world.preparePhysicalIdentityRemove(nick_owner);
    defer owner_remove.abort();
    owner_remove.commit();
    try std.testing.expect(world.findNick("shareddisplay") == null);
    try std.testing.expect(world.isMember("#physical", member_only));
    try std.testing.expect(world.isMember("#physical", sibling));
    var member_remove = try world.preparePhysicalIdentityRemove(member_only);
    defer member_remove.abort();
    member_remove.commit();
    try std.testing.expect(!world.isMember("#physical", member_only));
    try std.testing.expect(world.isMember("#physical", sibling));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#physical", sibling).?.bits);
}

test "World prepared nick transactions reject orphan fallback and mismatched reverse before publication" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const client = testClient(215);
    const sibling = testClient(216);
    try world.registerNick("Owned", client);
    try world.registerNick("Sibling", sibling);
    const reverse = world.client_nicks.fetchRemove(client).?;
    defer world.client_nicks.putAssumeCapacity(client, reverse.value);
    const root = world.rcu_nicks.?.nicks.published.load(.acquire);
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalIdentityRegister(client, "New"));
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalIdentityRemove(client));
    try std.testing.expectEqual(root, world.rcu_nicks.?.nicks.published.load(.acquire));
    try std.testing.expectEqual(@as(?ClientId, client), world.findNick("owned"));
    world.client_nicks.putAssumeCapacity(client, world.client_nicks.get(sibling).?);
    defer _ = world.client_nicks.remove(client);
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalIdentityRename(client, "New"));
    try std.testing.expectEqual(@as(?ClientId, sibling), world.findNick("sibling"));
}

test "World prepared exact logical claim and foreign preservation sweep all allocation failures" {
    for ([_]bool{ false, true }) |preserve| {
        var index: usize = 0;
        while (index < 10000) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var world = World.init(failing.allocator());
            defer world.deinit();
            const a = testClient(217);
            const b = testClient(218);
            const foreign = testClient(219);
            try world.registerNick("First", a);
            try world.registerNick("Second", b);
            try world.registerNick("Foreign", foreign);
            try world.restoreMember("#Room", a, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#Room", b, MemberModes.fromModes(&.{.voice}));
            const target = if (preserve) "Foreign" else "Unified";
            const disposition: World.SessionNickDisposition = if (preserve) .{ .preserve_foreign = foreign } else .{ .claim_exact = b };
            const root = world.rcu_nicks.?.nicks.published.load(.acquire);
            failing.fail_index = failing.alloc_index + index;
            var prepared = world.prepareExactSessionNickOwner(target, &.{ a, b }, disposition) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(root, world.rcu_nicks.?.nicks.published.load(.acquire));
                try std.testing.expectEqualStrings("First", world.nickOf(a).?);
                try std.testing.expectEqualStrings("Second", world.nickOf(b).?);
                try std.testing.expectEqual(@as(?ClientId, a), world.findNick("first"));
                try std.testing.expectEqual(@as(?ClientId, b), world.findNick("second"));
                try std.testing.expect(world.isMember("#room", a));
                try std.testing.expect(world.isMember("#room", b));
                failing.fail_index = std.math.maxInt(usize);
                var retry = try world.prepareExactSessionNickOwner(target, &.{ a, b }, disposition);
                defer retry.abort();
                const allocations = failing.allocations;
                failing.fail_index = failing.alloc_index;
                retry.commit();
                try std.testing.expectEqual(allocations, failing.allocations);
                try std.testing.expectEqual(@as(?ClientId, if (preserve) foreign else b), world.findNick(target));
                try std.testing.expect(world.findNick("first") == null and world.findNick("second") == null);
                try std.testing.expect(world.isMember("#room", a) and world.isMember("#room", b));
                continue;
            };
            defer prepared.abort();
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            prepared.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(?ClientId, if (preserve) foreign else b), world.findNick(target));
            try std.testing.expect(world.findNick("first") == null and world.findNick("second") == null);
            try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#Room", a).?.bits);
            try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#Room", b).?.bits);
            break;
        }
        try std.testing.expect(index > 0 and index < 10000);
    }
}

fn advanceRcuDomainIfIdle(domain: *ebr.Domain) bool {
    if (!rcuDomainIdle(domain)) return false;
    var advanced = false;
    var pass: usize = 0;
    while (pass < rcuAdvancePasses) : (pass += 1) {
        if (!rcuDomainIdle(domain)) return advanced;
        advanced = domain.advance() or advanced;
    }
    return advanced;
}

fn rcuDomainIdle(domain: *ebr.Domain) bool {
    const n = domain.participant_count.load(.acquire);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (domain.participants[i].active.load(.acquire)) return false;
    }
    return true;
}

/// ASCII-lowercase `name` into `buf`, returning the folded slice. Used to key
/// the per-channel membership-set map case-insensitively, mirroring the
/// `CaseInsensitiveBytesContext` casemapping the RCU registries use.
fn foldName(name: []const u8, buf: []u8) []const u8 {
    const n = @min(name.len, buf.len);
    for (name[0..n], 0..) |ch, i| buf[i] = std.ascii.toLower(ch);
    return buf[0..n];
}

/// A valid channel name begins with a recognised channel sigil:
///   `#`  — standard (network-wide) channel
///   `&`  — local channel (RFC1459)
///   `%#` / `%&` — IRCX UTF8 channel (the `%` marks a UTF8-named variant)
/// The IRCX `^` UTF8→hex display form is intentionally NOT accepted yet (it needs
/// a transliteration layer; tracked separately).
pub fn isChannelName(name: []const u8) bool {
    if (name.len == 0) return false;
    return switch (name[0]) {
        '#', '&' => true,
        '%' => name.len >= 2 and (name[1] == '#' or name[1] == '&'),
        else => false,
    };
}

fn testClient(slot: u20) ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 1 };
}

test "channelCountOf counts a client's memberships" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = testClient(1);
    try std.testing.expectEqual(@as(usize, 0), world.channelCountOf(a));
    _ = try world.join("#one", a);
    _ = try world.join("#two", a);
    _ = try world.join("#two", a); // re-join is a no-op
    try std.testing.expectEqual(@as(usize, 2), world.channelCountOf(a));
    _ = world.part("#one", a) catch {};
    try std.testing.expectEqual(@as(usize, 1), world.channelCountOf(a));
}

test "restoreMembersBatchExisting commits fallback and RCU membership together" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const owner = testClient(1);
    const restored = testClient(2);
    _ = try world.join("#one", owner);
    _ = try world.join("#two", owner);
    try world.restoreMember("#one", restored, MemberModes.empty());

    const changes = [_]MemberRestore{
        .{ .channel = "#one", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#two", .modes = MemberModes.fromModes(&.{.voice}) },
        // Case-folded duplicate: last exact mode image wins.
        .{ .channel = "#TWO", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
    };
    try std.testing.expect(try world.restoreMembersBatchExisting(restored, &changes));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#ONE", restored).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#two", restored).?.bits);
    try std.testing.expect(world.isMember("#one", restored));
    try std.testing.expect(world.isMember("#TWO", restored));
    try std.testing.expect(!(try world.restoreMembersBatchExisting(restored, &changes)));
    try std.testing.expectError(
        error.NoSuchChannel,
        world.restoreMembersBatchExisting(restored, &.{.{ .channel = "#missing", .modes = MemberModes.empty() }}),
    );
}

test "restoreMembersBatchExisting leaves no partial membership on any allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const owner = testClient(11);
            const restored = testClient(12);
            _ = try world.join("#old", owner);
            _ = try world.join("#new-a", owner);
            _ = try world.join("#new-b", owner);
            try world.restoreMember("#old", restored, MemberModes.fromModes(&.{.voice}));

            const changes = [_]MemberRestore{
                .{ .channel = "#old", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#new-a", .modes = MemberModes.fromModes(&.{.voice}) },
                .{ .channel = "#new-b", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
            };
            const result = world.restoreMembersBatchExisting(restored, &changes);
            if (result) |changed| {
                try std.testing.expect(changed);
                try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#old", restored).?.bits);
                try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#new-a", restored).?.bits);
                try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#new-b", restored).?.bits);
                try std.testing.expect(world.isMember("#old", restored));
                try std.testing.expect(world.isMember("#new-a", restored));
                try std.testing.expect(world.isMember("#new-b", restored));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    // Check both the mutable fallback maps and lock-free RCU
                    // reads: neither representation may expose a partial batch.
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#old", restored).?.bits);
                    try std.testing.expect(world.memberModes("#new-a", restored) == null);
                    try std.testing.expect(world.memberModes("#new-b", restored) == null);
                    try std.testing.expect(world.isMember("#old", restored));
                    try std.testing.expect(!world.isMember("#new-a", restored));
                    try std.testing.expect(!world.isMember("#new-b", restored));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "restoreMembersBatchExisting repairs fallback and RCU one-sided divergence" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const owner = testClient(13);
    const restored = testClient(14);
    _ = try world.join("#fallback-only", owner);
    _ = try world.join("#rcu-only", owner);
    try world.restoreMember("#fallback-only", restored, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#rcu-only", restored, MemberModes.fromModes(&.{.voice}));

    const c = world.rcu_channels.?;
    const fallback_set = World.rcuMembershipGet(c, "#fallback-only").?;
    try fallback_set.remove(c.writer_participant, @bitCast(restored));
    _ = world.channels.getPtr("#rcu-only").?.members.remove(restored);
    try std.testing.expect(world.channels.getPtr("#fallback-only").?.members.contains(restored));
    try std.testing.expect(!world.isMember("#fallback-only", restored));
    try std.testing.expect(!world.channels.getPtr("#rcu-only").?.members.contains(restored));
    try std.testing.expect(world.isMember("#rcu-only", restored));

    const restores = [_]MemberRestore{
        .{ .channel = "#fallback-only", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#rcu-only", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
    };
    try std.testing.expect(try world.restoreMembersBatchExisting(restored, &restores));
    try std.testing.expect(world.isMember("#fallback-only", restored));
    try std.testing.expect(world.isMember("#rcu-only", restored));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#fallback-only", restored).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#rcu-only", restored).?.bits);
    try std.testing.expect(!(try world.restoreMembersBatchExisting(restored, &restores)));
}

test "ensureMemberAbsent repairs either divergence direction and stale channels idempotently" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const target = testClient(15);
    const keeper = testClient(16);
    const second_keeper = testClient(17);
    _ = try world.join("#survives", target);
    _ = try world.join("#survives", keeper);
    _ = try world.join("#survives", second_keeper);

    // Fallback already absent, RCU still present: retry must not return early.
    _ = world.channels.getPtr("#survives").?.members.remove(target);
    try std.testing.expect(world.isMember("#survives", target));
    try std.testing.expect(try world.ensureMemberAbsent("#survives", target));
    try std.testing.expect(!world.isMember("#survives", target));
    try std.testing.expect(!world.channels.getPtr("#survives").?.members.contains(target));
    try std.testing.expect(!(try world.ensureMemberAbsent("#survives", target)));

    // RCU already absent, fallback still present: the fallback removal still
    // completes without requiring a new RCU publication.
    const c = world.rcu_channels.?;
    const set = World.rcuMembershipGet(c, "#survives").?;
    try set.remove(c.writer_participant, @bitCast(keeper));
    try std.testing.expect(world.channels.getPtr("#survives").?.members.contains(keeper));
    try std.testing.expect(!world.isMember("#survives", keeper));
    try std.testing.expect(try world.ensureMemberAbsent("#survives", keeper));
    try std.testing.expect(!world.channels.getPtr("#survives").?.members.contains(keeper));
    try std.testing.expect(world.channelExists("#survives"));

    // Simulate an interrupted old cleanup that freed fallback state first.
    _ = try world.join("#stale", target);
    const stale_set = World.rcuMembershipGet(c, "#stale").?;
    world.removeFallbackChannel("#stale");
    try std.testing.expect(!world.channels.contains("#stale"));
    try std.testing.expect(c.names.lookup(c.writer_participant, "#stale") != null);
    try std.testing.expect(stale_set.contains(c.writer_participant, @bitCast(target)));
    try std.testing.expect(try world.ensureMemberAbsent("#stale", target));
    try std.testing.expect(c.names.lookup(c.writer_participant, "#stale") == null);
    try std.testing.expect(World.rcuMembershipGet(c, "#stale") == null);
    try std.testing.expect(!(try world.ensureMemberAbsent("#stale", target)));

    // A stale RCU-only channel with another member must not be torn down just
    // because the requested target is absent from fallback state.
    _ = try world.join("#stale-shared", target);
    _ = try world.join("#stale-shared", keeper);
    world.removeFallbackChannel("#stale-shared");
    try std.testing.expect(try world.ensureMemberAbsent("#stale-shared", target));
    const shared_set = World.rcuMembershipGet(c, "#stale-shared").?;
    try std.testing.expect(c.names.lookup(c.writer_participant, "#stale-shared") != null);
    try std.testing.expect(!shared_set.contains(c.writer_participant, @bitCast(target)));
    try std.testing.expect(shared_set.contains(c.writer_participant, @bitCast(keeper)));
    // Present-side recovery reconstructs fallback from the complete RCU image
    // and reports no duplicate logical JOIN for the already-present keeper.
    try std.testing.expect(!(try world.join("#stale-shared", keeper)));
    try std.testing.expect(world.channels.getPtr("#stale-shared").?.members.contains(keeper));
    try std.testing.expect(world.isMember("#stale-shared", keeper));
}

test "ensureMemberAbsent surviving-channel removal is failure-atomic on every allocation" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const target = testClient(18);
            const keeper = testClient(19);
            _ = try world.join("#survives", target);
            _ = try world.join("#survives", keeper);

            const result = world.ensureMemberAbsent("#survives", target);
            if (result) |changed| {
                try std.testing.expect(changed);
                try std.testing.expect(!world.channels.getPtr("#survives").?.members.contains(target));
                try std.testing.expect(!world.isMember("#survives", target));
                try std.testing.expect(world.isMember("#survives", keeper));
                try std.testing.expect(!(try world.ensureMemberAbsent("#survives", target)));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(world.channels.getPtr("#survives").?.members.contains(target));
                    try std.testing.expect(world.isMember("#survives", target));
                    try std.testing.expect(world.isMember("#survives", keeper));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "ensureMemberAbsent keeps an empty registered channel and retry repairs induced OOM" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer world.deinit();
    const target = testClient(20);
    _ = try world.join("#registered", target);
    _ = try world.setChannelExtFlag("#registered", .registered, true);

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, world.ensureMemberAbsent("#registered", target));
    try std.testing.expect(world.channels.getPtr("#registered").?.members.contains(target));
    try std.testing.expect(world.isMember("#registered", target));

    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expect(try world.ensureMemberAbsent("#registered", target));
    try std.testing.expect(world.channels.contains("#registered"));
    try std.testing.expect(world.channelExists("#registered"));
    try std.testing.expect(world.channelHasExtFlag("#registered", .registered));
    try std.testing.expect(!world.isMember("#registered", target));
    try std.testing.expect(!(try world.ensureMemberAbsent("#registered", target)));
}

test "join repairs fallback-only membership and is failure-atomic on every allocation" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const owner = testClient(21);
            const target = testClient(22);
            _ = try world.join("#repair", owner);
            try world.restoreMember("#repair", target, MemberModes.fromModes(&.{.voice}));
            const c = world.rcu_channels.?;
            const set = World.rcuMembershipGet(c, "#repair").?;
            try set.remove(c.writer_participant, @bitCast(target));
            try std.testing.expect(world.channels.getPtr("#repair").?.members.contains(target));
            try std.testing.expect(!world.isMember("#repair", target));

            const result = world.join("#repair", target);
            if (result) |newly_joined| {
                // Fallback already held the member, so recovery is silent and
                // cannot emit a duplicate logical JOIN.
                try std.testing.expect(!newly_joined);
                try std.testing.expect(world.channels.getPtr("#repair").?.members.contains(target));
                try std.testing.expect(world.isMember("#repair", target));
                try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#repair", target).?.bits);
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(world.channels.getPtr("#repair").?.members.contains(target));
                    try std.testing.expect(!world.isMember("#repair", target));
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#repair", target).?.bits);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "join rebuilds a missing RCU set from every fallback member on every allocation boundary" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const owner = testClient(25);
            const target = testClient(26);
            _ = try world.join("#missing-set", owner);
            try world.restoreMember("#missing-set", target, MemberModes.fromModes(&.{.voice}));
            const c = world.rcu_channels.?;
            world.rcuDropMembership(c, "#missing-set");
            try std.testing.expect(World.rcuMembershipGet(c, "#missing-set") == null);

            const result = world.join("#missing-set", target);
            if (result) |newly_joined| {
                try std.testing.expect(!newly_joined);
                const repaired = World.rcuMembershipGet(c, "#missing-set").?;
                try std.testing.expect(repaired.contains(c.writer_participant, @bitCast(owner)));
                try std.testing.expect(repaired.contains(c.writer_participant, @bitCast(target)));
                try std.testing.expect(world.isMember("#missing-set", owner));
                try std.testing.expect(world.isMember("#missing-set", target));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(World.rcuMembershipGet(c, "#missing-set") == null);
                    try std.testing.expect(world.channels.getPtr("#missing-set").?.members.contains(owner));
                    try std.testing.expect(world.channels.getPtr("#missing-set").?.members.contains(target));
                    try std.testing.expect(c.names.lookup(c.writer_participant, "#missing-set") != null);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "join reconstructs stale RCU-only channel without duplicate JOIN on every allocation boundary" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const target = testClient(27);
            const keeper = testClient(28);
            _ = try world.join("#rcu-only", target);
            _ = try world.join("#rcu-only", keeper);
            const c = world.rcu_channels.?;
            const oid = c.names.lookup(c.writer_participant, "#rcu-only").?;
            world.removeFallbackChannel("#rcu-only");

            const result = world.join("#rcu-only", target);
            if (result) |newly_joined| {
                try std.testing.expect(!newly_joined);
                try std.testing.expectEqual(oid, world.channelOid("#rcu-only").?);
                try std.testing.expect(world.channels.getPtr("#rcu-only").?.members.contains(target));
                try std.testing.expect(world.channels.getPtr("#rcu-only").?.members.contains(keeper));
                try std.testing.expect(world.isMember("#rcu-only", target));
                try std.testing.expect(world.isMember("#rcu-only", keeper));
                // Fallback status modes were lost with the stale record. RCU
                // membership proves presence, not founder authority, so repair
                // must reconstruct both clients conservatively unprivileged.
                try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#rcu-only", target).?.bits);
                try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#rcu-only", keeper).?.bits);
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(!world.channels.contains("#rcu-only"));
                    const stale = World.rcuMembershipGet(c, "#rcu-only").?;
                    try std.testing.expect(stale.contains(c.writer_participant, @bitCast(target)));
                    try std.testing.expect(stale.contains(c.writer_participant, @bitCast(keeper)));
                    try std.testing.expectEqual(oid, c.names.lookup(c.writer_participant, "#rcu-only").?);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "join does not grant founder when only RCU keepers survive" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const keeper = testClient(29);
    const target = testClient(30);
    _ = try world.join("#rcu-keeper", keeper);
    const c = world.rcu_channels.?;
    world.removeFallbackChannel("#rcu-keeper");
    try std.testing.expect(World.rcuMembershipGet(c, "#rcu-keeper").?.contains(
        c.writer_participant,
        @bitCast(keeper),
    ));

    try std.testing.expect(try world.join("#rcu-keeper", target));
    try std.testing.expect(world.isMember("#rcu-keeper", keeper));
    try std.testing.expect(world.isMember("#rcu-keeper", target));
    try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#rcu-keeper", keeper).?.bits);
    try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#rcu-keeper", target).?.bits);
}

test "stale RCU name adoption consumes its partially published OID" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const stale_member = testClient(31);
    const fresh_member = testClient(32);
    const c = try world.ensureRcuChannels();
    const stale_oid = world.next_oid;

    // Model ensureChannel after publishing the name but before creating the
    // membership set/fallback record and advancing next_oid.
    try c.names.set(c.writer_participant, "#stale-name", stale_oid);
    world.noteRcuChannelWrite(c);
    try std.testing.expect(World.rcuMembershipGet(c, "#stale-name") == null);
    try std.testing.expect(!world.channels.contains("#stale-name"));

    try world.restoreMember("#stale-name", stale_member, MemberModes.empty());
    try std.testing.expectEqual(stale_oid, world.channelOid("#stale-name").?);
    try std.testing.expectEqual(stale_oid +% 1, world.next_oid);

    _ = try world.join("#fresh", fresh_member);
    const fresh_oid = world.channelOid("#fresh").?;
    try std.testing.expectEqual(stale_oid +% 1, fresh_oid);
    try std.testing.expect(stale_oid != fresh_oid);
}

test "restoreMember creates no empty shell on allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const target = testClient(23);
            const result = world.restoreMember("#new", target, MemberModes.fromModes(&.{.op}));
            if (result) |_| {
                try std.testing.expect(world.channels.contains("#new"));
                try std.testing.expect(world.channelExists("#new"));
                try std.testing.expect(world.isMember("#new", target));
                try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#new", target).?.bits);
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(!world.channels.contains("#new"));
                    try std.testing.expect(!world.channelExists("#new"));
                    try std.testing.expect(world.rcu_channels == null);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "part stages empty ephemeral teardown and surfaces every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const target = testClient(24);
            _ = try world.join("#ephemeral", target);

            const result = world.part("#ephemeral", target);
            if (result) |_| {
                try std.testing.expect(!world.channels.contains("#ephemeral"));
                try std.testing.expect(!world.channelExists("#ephemeral"));
                try std.testing.expect(World.rcuMembershipGet(world.rcu_channels.?, "#ephemeral") == null);
                try std.testing.expect(!(try world.ensureMemberAbsent("#ephemeral", target)));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    const c = world.rcu_channels.?;
                    try std.testing.expect(world.channels.getPtr("#ephemeral").?.members.contains(target));
                    try std.testing.expect(world.isMember("#ephemeral", target));
                    try std.testing.expect(c.names.lookup(c.writer_participant, "#ephemeral") != null);
                    try std.testing.expect(World.rcuMembershipGet(c, "#ephemeral") != null);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "handoffExactSessionIdentity commits nick and membership union together" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const owner = testClient(21);
    const successor = testClient(22);
    try world.registerNick("Shared", owner);
    try world.registerNick("Temporary", successor);
    world.unregisterNick(successor);
    try world.restoreMember("#one", owner, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#two", owner, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#two", successor, MemberModes.fromModes(&.{.voice}));

    const exact = [_]ClientId{ owner, successor };
    const membership_union = [_]MemberRestore{
        .{ .channel = "#one", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#two", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
    };
    try std.testing.expect(try world.handoffExactSessionIdentity("Shared", successor, &exact, &membership_union));
    try std.testing.expect(world.nickOf(owner) == null);
    try std.testing.expectEqualStrings("Shared", world.nickOf(successor).?);
    try std.testing.expectEqual(@as(?ClientId, successor), world.findNick("sHaReD"));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#one", successor).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#two", successor).?.bits);
    try std.testing.expect(world.isMember("#one", successor));
    try std.testing.expect(world.isMember("#two", successor));
}

test "handoffExactSessionIdentity leaves nick and every membership unchanged on allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const owner = testClient(31);
            const successor = testClient(32);
            try world.registerNick("FailSafe", owner);
            try world.registerNick("Temporary", successor);
            world.unregisterNick(successor);
            try world.restoreMember("#old", owner, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#old", successor, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#new-a", owner, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#new-b", owner, MemberModes.fromModes(&.{.voice}));

            const exact = [_]ClientId{ owner, successor };
            const membership_union = [_]MemberRestore{
                .{ .channel = "#old", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
                .{ .channel = "#new-a", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#new-b", .modes = MemberModes.fromModes(&.{.voice}) },
            };
            const result = world.handoffExactSessionIdentity("FailSafe", successor, &exact, &membership_union);
            if (result) |changed| {
                try std.testing.expect(changed);
                try std.testing.expect(world.nickOf(owner) == null);
                try std.testing.expectEqualStrings("FailSafe", world.nickOf(successor).?);
                try std.testing.expectEqual(@as(?ClientId, successor), world.findNick("failsafe"));
                try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#old", successor).?.bits);
                try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#new-a", successor).?.bits);
                try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#new-b", successor).?.bits);
                try std.testing.expect(world.isMember("#new-a", successor));
                try std.testing.expect(world.isMember("#new-b", successor));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    // Forward/reverse nick indexes and their RCU projection all
                    // remain on the departing owner.
                    try std.testing.expectEqualStrings("FailSafe", world.nickOf(owner).?);
                    try std.testing.expect(world.nickOf(successor) == null);
                    try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("FAILSAFE"));
                    // Existing successor modes and every absent membership are
                    // unchanged in both fallback and lock-free RCU views.
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#old", successor).?.bits);
                    try std.testing.expect(world.memberModes("#new-a", successor) == null);
                    try std.testing.expect(world.memberModes("#new-b", successor) == null);
                    try std.testing.expect(world.isMember("#old", successor));
                    try std.testing.expect(!world.isMember("#new-a", successor));
                    try std.testing.expect(!world.isMember("#new-b", successor));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "PreparedSessionRestore claim is inert until commit and creates absent channels exactly" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer world.deinit();
    world.clock_unix = 1234;
    const owner = testClient(41);
    const claimant = testClient(42);
    const unrelated = testClient(43);
    try world.registerNick("Carry", owner);
    try world.registerNick("Temporary", claimant);
    try world.registerNick("Unrelated", unrelated);
    try world.restoreMember("#old", owner, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#old", claimant, MemberModes.fromModes(&.{.voice}));
    try world.setTopic("#old", "unchanged", "setter", 77);

    const exact = [_]ClientId{ owner, claimant };
    const restores = [_]MemberRestore{
        .{ .channel = "#old", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
        .{ .channel = "#new-a", .modes = MemberModes.fromModes(&.{.voice}) },
        // Case-folded duplicate: last exact image wins.
        .{ .channel = "#NEW-A", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#new-b", .modes = MemberModes.empty() },
    };
    var prepared = try world.prepareSessionRestore(
        "Carry",
        claimant,
        &exact,
        .{ .claim_exact = owner },
        &restores,
    );
    defer prepared.abort();

    // Preparation owns all allocations and locks but exposes no semantic state.
    try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("carry"));
    try std.testing.expectEqualStrings("Temporary", world.nickOf(claimant).?);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#old", claimant).?.bits);
    try std.testing.expectEqualStrings("unchanged", world.topic("#old").?);
    try std.testing.expect(!world.channelExists("#new-a"));
    try std.testing.expect(!world.isMember("#new-a", claimant));
    try std.testing.expectEqual(@as(u32, 2), world.next_oid);

    failing.fail_index = failing.alloc_index;
    prepared.commit();
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqualStrings("Carry", world.nickOf(owner).?);
    try std.testing.expect(world.nickOf(claimant) == null);
    try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("CARRY"));
    try std.testing.expectEqualStrings("Unrelated", world.nickOf(unrelated).?);
    try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#old", claimant).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#new-a", claimant).?.bits);
    try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#NEW-B", claimant).?.bits);
    try std.testing.expect(world.channelExists("#NEW-A"));
    try std.testing.expect(world.isMember("#new-a", claimant));
    try std.testing.expect(world.isMember("#new-b", claimant));
    try std.testing.expectEqual(@as(?u32, 2), world.channelOid("#new-a"));
    try std.testing.expectEqual(@as(?u32, 3), world.channelOid("#new-b"));
    try std.testing.expectEqual(@as(u32, 4), world.next_oid);
    try std.testing.expectEqualStrings("unchanged", world.topic("#old").?);
}

test "PreparedSessionRestore preserve_foreign validates authority and aborts cleanly" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const first = testClient(51);
    const claimant = testClient(52);
    const foreign = testClient(53);
    const wrong = testClient(54);
    try world.registerNick("AliasA", first);
    try world.registerNick("AliasB", claimant);
    try world.registerNick("Shared", foreign);
    try world.registerNick("Wrong", wrong);
    const exact = [_]ClientId{ first, claimant };
    const restores = [_]MemberRestore{
        .{ .channel = "#created", .modes = MemberModes.fromModes(&.{.voice}) },
    };

    try std.testing.expectError(
        error.InvalidOwnerSet,
        world.prepareSessionRestore("Shared", claimant, &exact, .{ .preserve_foreign = first }, &restores),
    );
    try std.testing.expectError(
        error.InvalidOwnerSet,
        world.prepareSessionRestore("Shared", claimant, &exact, .{ .claim_exact = wrong }, &restores),
    );
    try std.testing.expectError(
        error.NickInUse,
        world.prepareSessionRestore("Shared", claimant, &exact, .{ .preserve_foreign = wrong }, &restores),
    );

    var aborted = try world.prepareSessionRestore(
        "Shared",
        claimant,
        &exact,
        .{ .preserve_foreign = foreign },
        &restores,
    );
    aborted.abort();
    try std.testing.expectEqualStrings("AliasA", world.nickOf(first).?);
    try std.testing.expectEqualStrings("AliasB", world.nickOf(claimant).?);
    try std.testing.expectEqualStrings("Shared", world.nickOf(foreign).?);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("shared"));
    try std.testing.expect(!world.channelExists("#created"));

    var committed = try world.prepareSessionRestore(
        "Shared",
        claimant,
        &exact,
        .{ .preserve_foreign = foreign },
        &restores,
    );
    defer committed.abort();
    committed.commit();
    try std.testing.expect(world.nickOf(first) == null);
    try std.testing.expect(world.nickOf(claimant) == null);
    try std.testing.expectEqualStrings("Shared", world.nickOf(foreign).?);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("SHARED"));
    try std.testing.expect(world.isMember("#created", claimant));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#created", claimant).?.bits);
}

test "PreparedSessionRestore exactly replaces claimant channels while preserving every keeper" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const claimant = testClient(81);
    const sibling = testClient(82);
    const foreign = testClient(83);
    try world.registerNick("Claimant", claimant);
    try world.registerNick("Sibling", sibling);
    try world.restoreMember("#desired", claimant, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#survives", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#survives", sibling, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#survives", foreign, MemberModes.empty());
    try world.restoreMember("#drop", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#registered", claimant, MemberModes.fromModes(&.{.voice}));
    _ = try world.setChannelExtFlag("#registered", .registered, true);
    try world.restoreMember("#sibling-only", sibling, MemberModes.fromModes(&.{.op}));
    const survives_oid = world.channelOid("#survives").?;
    const exact = [_]ClientId{ claimant, sibling };
    const desired = [_]MemberRestore{
        .{ .channel = "#desired", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#new", .modes = MemberModes.fromModes(&.{.voice}) },
    };

    // Abort proves that both membership removals and the mixed existence edit
    // remain observationally inert throughout preparation.
    var aborted = try world.prepareSessionRestore(
        "Claimant",
        claimant,
        &exact,
        .{ .claim_exact = claimant },
        &desired,
    );
    try std.testing.expect(world.isMember("#drop", claimant));
    try std.testing.expect(world.isMember("#survives", claimant));
    try std.testing.expect(world.isMember("#registered", claimant));
    try std.testing.expect(!world.channelExists("#new"));
    aborted.abort();
    try std.testing.expect(world.isMember("#drop", claimant));
    try std.testing.expect(world.isMember("#survives", claimant));
    try std.testing.expect(world.isMember("#registered", claimant));
    try std.testing.expect(!world.channelExists("#new"));

    var prepared = try world.prepareSessionRestore(
        "Claimant",
        claimant,
        &exact,
        .{ .claim_exact = claimant },
        &desired,
    );
    defer prepared.abort();
    prepared.commit();

    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#desired", claimant).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#new", claimant).?.bits);
    try std.testing.expect(!world.isMember("#survives", claimant));
    try std.testing.expect(world.isMember("#survives", sibling));
    try std.testing.expect(world.isMember("#survives", foreign));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#survives", sibling).?.bits);
    try std.testing.expectEqual(survives_oid, world.channelOid("#survives").?);
    try std.testing.expect(!world.channelExists("#drop"));
    try std.testing.expect(World.rcuMembershipGet(world.rcu_channels.?, "#drop") == null);
    try std.testing.expect(world.channelExists("#registered"));
    try std.testing.expect(world.channelHasExtFlag("#registered", .registered));
    try std.testing.expect(!world.isMember("#registered", claimant));
    try std.testing.expect(world.isMember("#sibling-only", sibling));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#sibling-only", sibling).?.bits);
}

test "PreparedSessionRestore repairs desired fallback-only and RCU-only channels atomically" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const claimant = testClient(89);
    const keeper = testClient(90);
    try world.registerNick("DesiredRepair", claimant);
    try world.restoreMember("#fallback-only", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#fallback-only", keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#rcu-only", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#rcu-only", keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#name-only", claimant, MemberModes.fromModes(&.{.op}));
    const c = world.rcu_channels.?;
    const rcu_only_oid = world.channelOid("#rcu-only").?;
    const name_only_oid = world.channelOid("#name-only").?;
    world.rcuDropMembership(c, "#fallback-only");
    world.removeFallbackChannel("#rcu-only");
    world.removeFallbackChannel("#name-only");
    world.rcuDropMembership(c, "#name-only");
    try std.testing.expect(World.rcuMembershipGet(c, "#fallback-only") == null);
    try std.testing.expect(!world.channels.contains("#rcu-only"));
    try std.testing.expect(!world.channels.contains("#name-only"));
    try std.testing.expect(World.rcuMembershipGet(c, "#name-only") == null);
    try std.testing.expectEqual(name_only_oid, c.names.lookup(c.writer_participant, "#name-only").?);

    const exact = [_]ClientId{claimant};
    const desired = [_]MemberRestore{
        .{ .channel = "#fallback-only", .modes = MemberModes.fromModes(&.{.voice}) },
        .{ .channel = "#rcu-only", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#name-only", .modes = MemberModes.fromModes(&.{.voice}) },
    };
    var prepared = try world.prepareSessionRestore(
        "DesiredRepair",
        claimant,
        &exact,
        .{ .claim_exact = claimant },
        &desired,
    );
    defer prepared.abort();
    // Both one-sided images remain untouched until the common commit boundary.
    try std.testing.expect(World.rcuMembershipGet(c, "#fallback-only") == null);
    try std.testing.expect(!world.channels.contains("#rcu-only"));
    try std.testing.expect(!world.channels.contains("#name-only"));
    prepared.commit();

    const rebuilt = World.rcuMembershipGet(c, "#fallback-only").?;
    try std.testing.expect(rebuilt.contains(c.writer_participant, @bitCast(claimant)));
    try std.testing.expect(rebuilt.contains(c.writer_participant, @bitCast(keeper)));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#fallback-only", claimant).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#fallback-only", keeper).?.bits);

    try std.testing.expect(world.channels.contains("#rcu-only"));
    try std.testing.expectEqual(rcu_only_oid, world.channelOid("#rcu-only").?);
    try std.testing.expect(world.isMember("#rcu-only", claimant));
    try std.testing.expect(world.isMember("#rcu-only", keeper));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#rcu-only", claimant).?.bits);
    try std.testing.expectEqual(MemberModes.empty().bits, world.memberModes("#rcu-only", keeper).?.bits);
    try std.testing.expectEqual(name_only_oid, world.channelOid("#name-only").?);
    try std.testing.expect(world.isMember("#name-only", claimant));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#name-only", claimant).?.bits);
}

test "PreparedSessionRestore reserves divergent desired OIDs before input-ordered new channels" {
    {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        const claimant = testClient(91);
        try world.registerNick("FallbackOid", claimant);
        try world.restoreMember("#fallback-only", claimant, MemberModes.fromModes(&.{.op}));
        const c = world.rcu_channels.?;
        const existing_oid = world.channelOid("#fallback-only").?;
        world.rcuDropMembership(c, "#fallback-only");
        world.next_oid = existing_oid;
        const exact = [_]ClientId{claimant};
        const desired = [_]MemberRestore{
            .{ .channel = "#new-first", .modes = MemberModes.empty() },
            .{ .channel = "#fallback-only", .modes = MemberModes.fromModes(&.{.voice}) },
        };
        var prepared = try world.prepareSessionRestore(
            "FallbackOid",
            claimant,
            &exact,
            .{ .claim_exact = claimant },
            &desired,
        );
        defer prepared.abort();
        prepared.commit();
        const new_oid = world.channelOid("#new-first").?;
        try std.testing.expect(existing_oid != new_oid);
        try std.testing.expect(new_oid > existing_oid);
        try std.testing.expectEqual(new_oid +% 1, world.next_oid);
    }

    {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        const claimant = testClient(92);
        try world.registerNick("RcuOid", claimant);
        try world.restoreMember("#rcu-only", claimant, MemberModes.fromModes(&.{.op}));
        const existing_oid = world.channelOid("#rcu-only").?;
        world.removeFallbackChannel("#rcu-only");
        world.next_oid = existing_oid;
        const exact = [_]ClientId{claimant};
        const desired = [_]MemberRestore{
            .{ .channel = "#new-first", .modes = MemberModes.empty() },
            .{ .channel = "#rcu-only", .modes = MemberModes.fromModes(&.{.voice}) },
        };
        var prepared = try world.prepareSessionRestore(
            "RcuOid",
            claimant,
            &exact,
            .{ .claim_exact = claimant },
            &desired,
        );
        defer prepared.abort();
        prepared.commit();
        const new_oid = world.channelOid("#new-first").?;
        try std.testing.expectEqual(existing_oid, world.channelOid("#rcu-only").?);
        try std.testing.expect(existing_oid != new_oid);
        try std.testing.expect(new_oid > existing_oid);
        try std.testing.expectEqual(new_oid +% 1, world.next_oid);
    }

    {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        const claimant = testClient(93);
        const sibling = testClient(94);
        try world.registerNick("KeeperOid", claimant);
        try world.restoreMember("#keeper", claimant, MemberModes.fromModes(&.{.op}));
        try world.restoreMember("#keeper", sibling, MemberModes.fromModes(&.{.voice}));
        const keeper_oid = world.channelOid("#keeper").?;
        world.next_oid = keeper_oid;
        const exact = [_]ClientId{claimant};
        const desired = [_]MemberRestore{
            .{ .channel = "#new", .modes = MemberModes.empty() },
        };
        var prepared = try world.prepareSessionRestore(
            "KeeperOid",
            claimant,
            &exact,
            .{ .claim_exact = claimant },
            &desired,
        );
        defer prepared.abort();
        prepared.commit();
        const new_oid = world.channelOid("#new").?;
        try std.testing.expect(!world.isMember("#keeper", claimant));
        try std.testing.expect(world.isMember("#keeper", sibling));
        try std.testing.expectEqual(keeper_oid, world.channelOid("#keeper").?);
        try std.testing.expect(new_oid > keeper_oid);
        try std.testing.expectEqual(new_oid +% 1, world.next_oid);
    }
}

test "PreparedSessionRestore exact replacement repairs removal divergence without dropping RCU keepers" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const claimant = testClient(84);
    const keeper = testClient(85);
    try world.registerNick("Diverged", claimant);
    try world.restoreMember("#desired", claimant, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#fallback-only", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#fallback-only", keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#rcu-only", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#rcu-only", keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#stale-shared", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#stale-shared", keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#stale-drop", claimant, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#stale-registered", claimant, MemberModes.fromModes(&.{.op}));
    _ = try world.setChannelExtFlag("#stale-registered", .registered, true);

    const c = world.rcu_channels.?;
    try World.rcuMembershipGet(c, "#fallback-only").?.remove(c.writer_participant, @bitCast(claimant));
    _ = world.channels.getPtr("#rcu-only").?.members.remove(claimant);
    world.removeFallbackChannel("#stale-shared");
    world.removeFallbackChannel("#stale-drop");
    world.removeFallbackChannel("#stale-registered");

    const exact = [_]ClientId{claimant};
    const desired = [_]MemberRestore{
        .{ .channel = "#desired", .modes = MemberModes.fromModes(&.{.op}) },
    };
    var prepared = try world.prepareSessionRestore(
        "Diverged",
        claimant,
        &exact,
        .{ .claim_exact = claimant },
        &desired,
    );
    defer prepared.abort();
    prepared.commit();

    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#desired", claimant).?.bits);
    try std.testing.expect(!world.channels.getPtr("#fallback-only").?.members.contains(claimant));
    try std.testing.expect(!world.isMember("#fallback-only", claimant));
    try std.testing.expect(world.isMember("#fallback-only", keeper));
    try std.testing.expect(!world.channels.getPtr("#rcu-only").?.members.contains(claimant));
    try std.testing.expect(!world.isMember("#rcu-only", claimant));
    try std.testing.expect(world.isMember("#rcu-only", keeper));

    try std.testing.expect(!world.channels.contains("#stale-shared"));
    try std.testing.expect(world.channelExists("#stale-shared"));
    const shared_set = World.rcuMembershipGet(c, "#stale-shared").?;
    try std.testing.expect(!shared_set.contains(c.writer_participant, @bitCast(claimant)));
    try std.testing.expect(shared_set.contains(c.writer_participant, @bitCast(keeper)));
    // With fallback metadata gone, even an empty RCU-only set may have belonged
    // to a registered channel. Preserve the entity conservatively for both the
    // explicitly registered case and the metadata-unknown ordinary case.
    try std.testing.expect(world.channelExists("#stale-drop"));
    try std.testing.expectEqual(@as(usize, 0), World.rcuMembershipGet(c, "#stale-drop").?.count(c.writer_participant));
    try std.testing.expect(world.channelExists("#stale-registered"));
    try std.testing.expectEqual(@as(usize, 0), World.rcuMembershipGet(c, "#stale-registered").?.count(c.writer_participant));
}

test "PreparedSessionRestore empty desired removes fallback-only claimant without activating channel RCU" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const claimant = testClient(86);
    try world.registerNick("FallbackOnly", claimant);

    const owned_name = try world.allocator.dupe(u8, "#fallback-only");
    var owns_name = true;
    errdefer if (owns_name) world.allocator.free(owned_name);
    var channel = Channel.init(world.allocator);
    var owns_channel = true;
    errdefer if (owns_channel) channel.deinit();
    try channel.members.put(claimant, MemberModes.fromModes(&.{.op}));
    channel.oid = world.next_oid;
    try world.channels.put(owned_name, channel);
    owns_name = false;
    owns_channel = false;
    world.next_oid +%= 1;
    try std.testing.expect(world.rcu_channels == null);

    const exact = [_]ClientId{claimant};
    var prepared = try world.prepareSessionRestore(
        "FallbackOnly",
        claimant,
        &exact,
        .{ .claim_exact = claimant },
        &.{},
    );
    defer prepared.abort();
    try std.testing.expect(prepared.channel_rcu == null);
    try std.testing.expect(world.rcu_channels == null);
    try std.testing.expect(world.channels.getPtr("#fallback-only").?.members.contains(claimant));
    prepared.commit();
    try std.testing.expect(world.rcu_channels == null);
    try std.testing.expect(!world.channels.contains("#fallback-only"));
}

test "PreparedSessionRestore exact replacement is failure-atomic on every allocation" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const claimant = testClient(87);
            const sibling = testClient(88);
            try world.registerNick("Atomic", claimant);
            try world.registerNick("SiblingAtomic", sibling);
            try world.restoreMember("#desired", claimant, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#survives", claimant, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#survives", sibling, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#drop", claimant, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#registered", claimant, MemberModes.fromModes(&.{.voice}));
            _ = try world.setChannelExtFlag("#registered", .registered, true);
            try world.restoreMember("#fallback-desired", claimant, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#fallback-desired", sibling, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#rcu-desired", claimant, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#rcu-desired", sibling, MemberModes.fromModes(&.{.op}));
            const c = world.rcu_channels.?;
            const rcu_desired_oid = world.channelOid("#rcu-desired").?;
            world.rcuDropMembership(c, "#fallback-desired");
            world.removeFallbackChannel("#rcu-desired");
            const oid_before = world.next_oid;
            const channel_rcu_before = world.rcu_channels;
            const exact = [_]ClientId{ claimant, sibling };
            const desired = [_]MemberRestore{
                .{ .channel = "#desired", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#new", .modes = MemberModes.fromModes(&.{.voice}) },
                .{ .channel = "#fallback-desired", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#rcu-desired", .modes = MemberModes.fromModes(&.{.voice}) },
            };

            const result = world.prepareSessionRestore(
                "Atomic",
                claimant,
                &exact,
                .{ .claim_exact = claimant },
                &desired,
            );
            if (result) |value| {
                var prepared = value;
                defer prepared.abort();
                try std.testing.expect(world.isMember("#survives", claimant));
                try std.testing.expect(world.isMember("#drop", claimant));
                try std.testing.expect(world.isMember("#registered", claimant));
                try std.testing.expect(!world.channelExists("#new"));
                try std.testing.expect(World.rcuMembershipGet(c, "#fallback-desired") == null);
                try std.testing.expect(!world.channels.contains("#rcu-desired"));
                prepared.commit();
                try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#desired", claimant).?.bits);
                try std.testing.expect(world.isMember("#new", claimant));
                try std.testing.expect(!world.isMember("#survives", claimant));
                try std.testing.expect(world.isMember("#survives", sibling));
                try std.testing.expect(!world.channelExists("#drop"));
                try std.testing.expect(world.channelExists("#registered"));
                try std.testing.expect(!world.isMember("#registered", claimant));
                try std.testing.expect(world.isMember("#fallback-desired", claimant));
                try std.testing.expect(world.isMember("#fallback-desired", sibling));
                try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#fallback-desired", claimant).?.bits);
                try std.testing.expect(world.isMember("#rcu-desired", claimant));
                try std.testing.expect(world.isMember("#rcu-desired", sibling));
                try std.testing.expectEqual(rcu_desired_oid, world.channelOid("#rcu-desired").?);
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(world.rcu_channels == channel_rcu_before);
                    try std.testing.expectEqual(oid_before, world.next_oid);
                    try std.testing.expectEqualStrings("Atomic", world.nickOf(claimant).?);
                    try std.testing.expectEqualStrings("SiblingAtomic", world.nickOf(sibling).?);
                    try std.testing.expectEqual(@as(?ClientId, claimant), world.findNick("atomic"));
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#desired", claimant).?.bits);
                    try std.testing.expect(world.isMember("#survives", claimant));
                    try std.testing.expect(world.isMember("#survives", sibling));
                    try std.testing.expect(world.isMember("#drop", claimant));
                    try std.testing.expect(world.channelExists("#drop"));
                    try std.testing.expect(world.isMember("#registered", claimant));
                    try std.testing.expect(world.channelHasExtFlag("#registered", .registered));
                    try std.testing.expect(!world.channelExists("#new"));
                    try std.testing.expect(World.rcuMembershipGet(c, "#fallback-desired") == null);
                    try std.testing.expect(world.channels.getPtr("#fallback-desired").?.members.contains(claimant));
                    try std.testing.expect(world.channels.getPtr("#fallback-desired").?.members.contains(sibling));
                    try std.testing.expect(!world.channels.contains("#rcu-desired"));
                    const stale = World.rcuMembershipGet(c, "#rcu-desired").?;
                    try std.testing.expect(stale.contains(c.writer_participant, @bitCast(claimant)));
                    try std.testing.expect(stale.contains(c.writer_participant, @bitCast(sibling)));
                    try std.testing.expectEqual(rcu_desired_oid, c.names.lookup(c.writer_participant, "#rcu-desired").?);
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "PreparedSessionRestore preserves every active World invariant on allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const owner = testClient(61);
            const claimant = testClient(62);
            const unrelated = testClient(63);
            try world.registerNick("Stable", owner);
            try world.registerNick("Device", claimant);
            try world.registerNick("Other", unrelated);
            try world.restoreMember("#old", owner, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#old", claimant, MemberModes.fromModes(&.{.voice}));
            try world.restoreMember("#other", unrelated, MemberModes.fromModes(&.{.founder}));
            try world.setTopic("#old", "stable topic", "setter", 88);
            const oid_before = world.next_oid;
            const nick_rcu_before = world.rcu_nicks;
            const channel_rcu_before = world.rcu_channels;
            const exact = [_]ClientId{ owner, claimant };
            const restores = [_]MemberRestore{
                .{ .channel = "#old", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
                .{ .channel = "#missing-a", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#missing-b", .modes = MemberModes.fromModes(&.{.voice}) },
            };

            const result = world.prepareSessionRestore(
                "Stable",
                claimant,
                &exact,
                .{ .claim_exact = owner },
                &restores,
            );
            if (result) |value| {
                var prepared = value;
                defer prepared.abort();
                // Even a fully successful prepare is observationally inert.
                try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("STABLE"));
                try std.testing.expectEqualStrings("Device", world.nickOf(claimant).?);
                try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#old", claimant).?.bits);
                try std.testing.expect(!world.channelExists("#missing-a"));
                try std.testing.expect(!world.channelExists("#missing-b"));
                prepared.commit();
                try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("stable"));
                try std.testing.expect(world.isMember("#missing-a", claimant));
                try std.testing.expect(world.isMember("#missing-b", claimant));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(world.rcu_nicks == nick_rcu_before);
                    try std.testing.expect(world.rcu_channels == channel_rcu_before);
                    try std.testing.expectEqual(oid_before, world.next_oid);
                    try std.testing.expectEqualStrings("Stable", world.nickOf(owner).?);
                    try std.testing.expectEqualStrings("Device", world.nickOf(claimant).?);
                    try std.testing.expectEqualStrings("Other", world.nickOf(unrelated).?);
                    try std.testing.expectEqual(@as(?ClientId, owner), world.findNick("stable"));
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#old", claimant).?.bits);
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#old", owner).?.bits);
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.founder}).bits, world.memberModes("#other", unrelated).?.bits);
                    try std.testing.expectEqualStrings("stable topic", world.topic("#old").?);
                    try std.testing.expect(!world.channelExists("#missing-a"));
                    try std.testing.expect(!world.channelExists("#missing-b"));
                    try std.testing.expect(!world.isMember("#missing-a", claimant));
                    try std.testing.expect(!world.isMember("#missing-b", claimant));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "PreparedSessionRestore preserve_foreign is failure-atomic on every allocation" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            const primary = testClient(66);
            const claimant = testClient(67);
            const foreign = testClient(68);
            try world.registerNick("PrimaryAlias", primary);
            try world.registerNick("ClaimantAlias", claimant);
            try world.registerNick("SharedDisplay", foreign);
            try world.restoreMember("#existing", claimant, MemberModes.fromModes(&.{.voice}));
            const exact = [_]ClientId{ primary, claimant };
            const restores = [_]MemberRestore{
                .{ .channel = "#existing", .modes = MemberModes.fromModes(&.{.op}) },
                .{ .channel = "#new", .modes = MemberModes.fromModes(&.{.voice}) },
            };
            const oid_before = world.next_oid;

            const result = world.prepareSessionRestore(
                "SharedDisplay",
                claimant,
                &exact,
                .{ .preserve_foreign = foreign },
                &restores,
            );
            if (result) |value| {
                var prepared = value;
                defer prepared.abort();
                try std.testing.expectEqualStrings("PrimaryAlias", world.nickOf(primary).?);
                try std.testing.expectEqualStrings("ClaimantAlias", world.nickOf(claimant).?);
                try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("shareddisplay"));
                try std.testing.expect(!world.channelExists("#new"));
                prepared.commit();
                try std.testing.expect(world.nickOf(primary) == null);
                try std.testing.expect(world.nickOf(claimant) == null);
                try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("SHAREDDISPLAY"));
                try std.testing.expect(world.isMember("#new", claimant));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expectEqual(oid_before, world.next_oid);
                    try std.testing.expectEqualStrings("PrimaryAlias", world.nickOf(primary).?);
                    try std.testing.expectEqualStrings("ClaimantAlias", world.nickOf(claimant).?);
                    try std.testing.expectEqualStrings("SharedDisplay", world.nickOf(foreign).?);
                    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("shareddisplay"));
                    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#existing", claimant).?.bits);
                    try std.testing.expect(!world.channelExists("#new"));
                    try std.testing.expect(!world.isMember("#new", claimant));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "PreparedSessionRestore leaves an empty World's lazy RCU state detached on every failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var world = World.init(allocator);
            defer world.deinit();
            world.clock_unix = 900;
            const claimant = testClient(71);
            const exact = [_]ClientId{claimant};
            const restores = [_]MemberRestore{
                .{ .channel = "#first", .modes = MemberModes.fromModes(&.{.voice}) },
                .{ .channel = "#second", .modes = MemberModes.empty() },
            };
            const result = world.prepareSessionRestore(
                "Fresh",
                claimant,
                &exact,
                .{ .claim_exact = claimant },
                &restores,
            );
            if (result) |value| {
                var prepared = value;
                defer prepared.abort();
                try std.testing.expect(world.rcu_nicks == null);
                try std.testing.expect(world.rcu_channels == null);
                try std.testing.expectEqual(@as(usize, 0), world.channelCount());
                try std.testing.expectEqual(@as(u32, 1), world.next_oid);
                prepared.commit();
                try std.testing.expect(world.rcu_nicks != null);
                try std.testing.expect(world.rcu_channels != null);
                try std.testing.expectEqual(@as(?ClientId, claimant), world.findNick("fresh"));
                try std.testing.expect(world.isMember("#first", claimant));
                try std.testing.expect(world.isMember("#second", claimant));
            } else |err| switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(world.rcu_nicks == null);
                    try std.testing.expect(world.rcu_channels == null);
                    try std.testing.expectEqual(@as(usize, 0), world.channelCount());
                    try std.testing.expectEqual(@as(u32, 1), world.next_oid);
                    try std.testing.expect(world.findNickFallback("Fresh") == null);
                    try std.testing.expect(!world.channelExists("#first"));
                    try std.testing.expect(!world.channelExists("#second"));
                    return error.OutOfMemory;
                },
                else => return err,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Exercise.run, .{});
}

test "channel list modes are capped at max_list_entries" {
    var world = World.init(std.testing.allocator);
    world.max_list_entries = 2;
    defer world.deinit();
    _ = try world.join("#c", testClient(1)); // creates the channel

    try std.testing.expect(try world.addBan("#c", "a!*@*", "setter", 1));
    try std.testing.expect(try world.addBan("#c", "b!*@*", "setter", 2));
    try std.testing.expectError(error.ListFull, world.addBan("#c", "c!*@*", "setter", 3));
    // Each list mode has its own independent cap.
    try std.testing.expect(try world.addExempt("#c", "e1!*@*", "setter", 1));
    try std.testing.expect(try world.addExempt("#c", "e2!*@*", "setter", 2));
    try std.testing.expectError(error.ListFull, world.addExempt("#c", "e3!*@*", "setter", 3));
    // A duplicate is a no-op (false), not a cap error.
    try std.testing.expect(!try world.addBan("#c", "a!*@*", "setter", 4));
}

test "isChannelName accepts #, &, and %#/%& but not bare names or ^" {
    try std.testing.expect(isChannelName("#chan"));
    try std.testing.expect(isChannelName("&local"));
    try std.testing.expect(isChannelName("%#utf8"));
    try std.testing.expect(isChannelName("%&utf8local"));
    // Rejections: empty, plain nick, bare %, and the deferred ^ form.
    try std.testing.expect(!isChannelName(""));
    try std.testing.expect(!isChannelName("nick"));
    try std.testing.expect(!isChannelName("%"));
    try std.testing.expect(!isChannelName("%nope"));
    try std.testing.expect(!isChannelName("^hexchan"));
}

test "nick registry rejects collisions and supports lookup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);
    try world.registerNick("A", a);

    try std.testing.expectEqual(a, world.findNick("A").?);
    try std.testing.expectEqualStrings("A", world.nickOf(a).?);
    try std.testing.expectError(error.NickInUse, world.registerNick("A", b));

    world.unregisterNick(a);
    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expectEqual(@as(?[]const u8, null), world.nickOf(a));
}

test "join part and membership cleanup" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try std.testing.expect(try world.join("#x", a));
    try std.testing.expect(!try world.join("#x", a));
    try std.testing.expect(try world.join("#x", b));
    try std.testing.expect(world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expectEqual(@as(usize, 1), world.channelCount());

    try world.part("#x", a);
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));

    try world.part("#x", b);
    try std.testing.expect(!world.channelExists("#x"));
    try std.testing.expectEqual(@as(usize, 0), world.channelCount());
}

test "registered (+r) channels persist across empty; part and disconnect keep them" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try std.testing.expect(try world.join("#reg", a));
    try std.testing.expect(try world.join("#reg", b));
    _ = try world.setChannelExtFlag("#reg", .registered, true);

    // Last member parting must NOT reclaim a registered channel.
    try world.part("#reg", a);
    try world.part("#reg", b);
    try std.testing.expect(world.channelExists("#reg"));
    try std.testing.expect(world.channelHasExtFlag("#reg", .registered));

    // Disconnect path likewise preserves it.
    try std.testing.expect(try world.join("#reg", a));
    world.removeClient(a);
    try std.testing.expect(world.channelExists("#reg"));

    // An unregistered channel beside it is still reclaimed on empty.
    try std.testing.expect(try world.join("#eph", b));
    world.removeClient(b);
    try std.testing.expect(!world.channelExists("#eph"));
}

test "channels receive monotonic, stable, unique IRCX object ids" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(try world.join("#first", a));
    try std.testing.expect(try world.join("#second", a));

    const oid1 = world.channelOid("#first").?;
    const oid2 = world.channelOid("#second").?;
    try std.testing.expectEqual(@as(u32, 1), oid1); // counter starts at 1
    try std.testing.expectEqual(@as(u32, 2), oid2);
    try std.testing.expect(oid1 != oid2);

    // OID is stable across further membership churn on the same channel.
    const b = testClient(2);
    try std.testing.expect(try world.join("#first", b));
    try std.testing.expectEqual(oid1, world.channelOid("#first").?);

    // Unknown channel has no OID.
    try std.testing.expect(world.channelOid("#nope") == null);
}

const PreparedCloneTestFixture = struct {
    fn owner() ClientId {
        return testClient(101);
    }

    fn sourceMember() ClientId {
        return testClient(102);
    }

    fn invited() ClientId {
        return testClient(103);
    }

    fn seated() ClientId {
        return testClient(104);
    }

    fn install(world: *World) !u32 {
        world.clock_unix = 111;
        try std.testing.expect(try world.join("#prepared-template", owner()));
        try world.restoreMember(
            "#prepared-template",
            owner(),
            MemberModes.fromModes(&.{ .founder, .op }),
        );
        try std.testing.expect(try world.join("#prepared-template", sourceMember()));
        try world.restoreMember(
            "#prepared-template",
            sourceMember(),
            MemberModes.fromModes(&.{.voice}),
        );
        try std.testing.expect(try world.setChannelFlag("#prepared-template", .invite_only, true));
        try std.testing.expect(try world.setChannelFlag("#prepared-template", .moderated, true));
        try std.testing.expect(try world.setChannelFlag("#prepared-template", .secret, true));
        try std.testing.expect(try world.setPrivate("#prepared-template", true));
        try std.testing.expect(try world.setHidden("#prepared-template", true));
        try world.setChannelLimit("#prepared-template", 42);
        try world.setChannelKey("#prepared-template", "sekret");
        try world.setForward("#prepared-template", "#overflow");
        try world.setThrottle("#prepared-template", 3, 10);
        try world.setTopic("#prepared-template", "portable topic", "A!alice@localhost", 1234);
        try std.testing.expect(try world.addBan("#prepared-template", "bad!*@*", "ban-setter", 1));
        try std.testing.expect(try world.addExempt("#prepared-template", "bad!vip@*", "exempt-setter", 2));
        try std.testing.expect(try world.addInvex("#prepared-template", "friend!*@*", "invex-setter", 3));
        try std.testing.expect(try world.addMute("#prepared-template", "loud!*@*", "mute-setter", 4));
        try std.testing.expect(try world.setChannelExtFlag("#prepared-template", .cloneable, true));
        try std.testing.expect(try world.setChannelExtFlag("#prepared-template", .auditorium, true));
        try world.addInvite("#prepared-template", invited());
        return world.channelOid("#prepared-template") orelse error.TestUnexpectedResult;
    }

    fn expectSourceUnchanged(world: *World, oid: u32, expected_next_oid: u32) !void {
        try std.testing.expect(world.channels.contains("#prepared-template"));
        try std.testing.expect(world.channelExists("#PREPARED-TEMPLATE"));
        try std.testing.expectEqual(@as(usize, 2), world.memberCount("#prepared-template"));
        try std.testing.expect(world.isMember("#prepared-template", owner()));
        try std.testing.expect(world.isMember("#prepared-template", sourceMember()));
        try std.testing.expectEqual(
            MemberModes.fromModes(&.{ .founder, .op }).bits,
            world.memberModes("#prepared-template", owner()).?.bits,
        );
        try std.testing.expectEqual(
            MemberModes.fromModes(&.{.voice}).bits,
            world.memberModes("#prepared-template", sourceMember()).?.bits,
        );
        try std.testing.expect(world.channelHasFlag("#prepared-template", .invite_only));
        try std.testing.expect(world.channelHasFlag("#prepared-template", .moderated));
        try std.testing.expect(world.channelHasFlag("#prepared-template", .secret));
        try std.testing.expect(world.isPrivate("#prepared-template"));
        try std.testing.expect(world.isHidden("#prepared-template"));
        try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#prepared-template"));
        try std.testing.expectEqualStrings("sekret", world.channelKey("#prepared-template").?);
        try std.testing.expectEqualStrings("#overflow", world.forwardOf("#prepared-template").?);
        try std.testing.expectEqual(@as(u16, 3), world.throttleOf("#prepared-template").?.joins);
        try std.testing.expectEqual(@as(u32, 10), world.throttleOf("#prepared-template").?.secs);
        const topic = world.topicInfo("#prepared-template").?;
        try std.testing.expectEqualStrings("portable topic", topic.text);
        try std.testing.expectEqualStrings("A!alice@localhost", topic.setter);
        try std.testing.expectEqual(@as(i64, 1234), topic.set_at);
        try expectPreparedCloneLists(world, "#prepared-template");
        try std.testing.expect(world.channelHasExtFlag("#prepared-template", .cloneable));
        try std.testing.expect(!world.channelHasExtFlag("#prepared-template", .clone));
        try std.testing.expect(world.channelHasExtFlag("#prepared-template", .auditorium));
        try std.testing.expect(world.hasInvite("#prepared-template", invited()));
        try std.testing.expectEqual(oid, world.channelOid("#prepared-template").?);
        try std.testing.expectEqual(@as(i64, 111), world.channelCreatedUnix("#prepared-template").?);
        try std.testing.expectEqual(expected_next_oid, world.next_oid);
    }

    fn expectCommittedDestination(world: *World, source_oid: u32) !void {
        try std.testing.expect(world.channels.contains("#prepared-clone"));
        try std.testing.expect(world.channelExists("#PREPARED-CLONE"));
        try std.testing.expectEqual(@as(usize, 1), world.memberCount("#prepared-clone"));
        try std.testing.expect(world.isMember("#prepared-clone", seated()));
        try std.testing.expect(world.channels.getPtr("#prepared-clone").?.members.contains(seated()));
        try std.testing.expect(!world.isMember("#prepared-clone", owner()));
        try std.testing.expect(!world.isMember("#prepared-clone", sourceMember()));
        try std.testing.expectEqual(
            MemberModes.fromModes(&.{ .owner, .voice }).bits,
            world.memberModes("#prepared-clone", seated()).?.bits,
        );
        try std.testing.expect(world.channelHasFlag("#prepared-clone", .invite_only));
        try std.testing.expect(world.channelHasFlag("#prepared-clone", .moderated));
        try std.testing.expect(world.channelHasFlag("#prepared-clone", .secret));
        try std.testing.expect(world.isPrivate("#prepared-clone"));
        try std.testing.expect(world.isHidden("#prepared-clone"));
        try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#prepared-clone"));
        try std.testing.expectEqualStrings("sekret", world.channelKey("#prepared-clone").?);
        try std.testing.expectEqualStrings("#overflow", world.forwardOf("#prepared-clone").?);
        try std.testing.expectEqual(@as(u16, 3), world.throttleOf("#prepared-clone").?.joins);
        try std.testing.expectEqual(@as(u32, 10), world.throttleOf("#prepared-clone").?.secs);
        const topic = world.topicInfo("#prepared-clone").?;
        try std.testing.expectEqualStrings("portable topic", topic.text);
        try std.testing.expectEqualStrings("A!alice@localhost", topic.setter);
        try std.testing.expectEqual(@as(i64, 1234), topic.set_at);
        try expectPreparedCloneLists(world, "#prepared-clone");
        try std.testing.expect(world.channelHasExtFlag("#prepared-clone", .clone));
        try std.testing.expect(!world.channelHasExtFlag("#prepared-clone", .cloneable));
        try std.testing.expect(world.channelHasExtFlag("#prepared-clone", .auditorium));
        try std.testing.expect(!world.hasInvite("#prepared-clone", invited()));
        try std.testing.expect(world.channelOid("#prepared-clone").? != source_oid);
        try std.testing.expectEqual(source_oid +% 1, world.channelOid("#prepared-clone").?);
        try std.testing.expectEqual(@as(i64, 222), world.channelCreatedUnix("#prepared-clone").?);
        try std.testing.expectEqual(source_oid +% 2, world.next_oid);
    }
};

fn expectPreparedCloneLists(world: *World, channel: []const u8) !void {
    const bans = world.bansOf(channel).?;
    try std.testing.expectEqual(@as(usize, 1), bans.len);
    try std.testing.expectEqualStrings("bad!*@*", bans[0].mask);
    try std.testing.expectEqualStrings("ban-setter", bans[0].setter);
    try std.testing.expectEqual(@as(i64, 1), bans[0].set_at);
    const exempts = world.exemptsOf(channel).?;
    try std.testing.expectEqual(@as(usize, 1), exempts.len);
    try std.testing.expectEqualStrings("bad!vip@*", exempts[0].mask);
    try std.testing.expectEqualStrings("exempt-setter", exempts[0].setter);
    try std.testing.expectEqual(@as(i64, 2), exempts[0].set_at);
    const invex = world.invexOf(channel).?;
    try std.testing.expectEqual(@as(usize, 1), invex.len);
    try std.testing.expectEqualStrings("friend!*@*", invex[0].mask);
    try std.testing.expectEqualStrings("invex-setter", invex[0].setter);
    try std.testing.expectEqual(@as(i64, 3), invex[0].set_at);
    const mutes = world.mutesOf(channel).?;
    try std.testing.expectEqual(@as(usize, 1), mutes.len);
    try std.testing.expectEqualStrings("loud!*@*", mutes[0].mask);
    try std.testing.expectEqualStrings("mute-setter", mutes[0].setter);
    try std.testing.expectEqual(@as(i64, 4), mutes[0].set_at);
}

test "prepared clone abort is idempotent and publishes no destination" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const source_oid = try PreparedCloneTestFixture.install(&world);
    var prepared = (try world.prepareCloneTemplate("#prepared-template", "#prepared-clone")) orelse
        return error.TestUnexpectedResult;
    prepared.abort();
    prepared.abort();
    try std.testing.expect(!world.channels.contains("#prepared-clone"));
    try std.testing.expect(!world.channelExists("#PREPARED-CLONE"));
    try std.testing.expectEqual(@as(usize, 1), world.channelCount());
    try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 1);
}

test "prepared clone missing source and existing destination do not mutate world" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const source_oid = try PreparedCloneTestFixture.install(&world);
    try std.testing.expectError(
        error.NoSuchChannel,
        world.prepareCloneTemplate("#missing", "#prepared-clone"),
    );
    try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 1);

    const existing = testClient(105);
    try std.testing.expect(try world.join("#prepared-clone", existing));
    const existing_oid = world.channelOid("#prepared-clone").?;
    try std.testing.expect((try world.prepareCloneTemplate("#prepared-template", "#PREPARED-CLONE")) == null);
    try std.testing.expectEqual(existing_oid, world.channelOid("#prepared-clone").?);
    try std.testing.expectEqual(@as(usize, 1), world.memberCount("#prepared-clone"));
    try std.testing.expect(world.isMember("#prepared-clone", existing));
    try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 2);
}

test "prepared clone prepare and seated commit are atomic on every allocation boundary" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 256);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var world = World.init(failing.allocator());
        const source_oid = try PreparedCloneTestFixture.install(&world);
        world.clock_unix = 222;

        failing.fail_index = failing.alloc_index + fail_offset;
        var prepared = (world.prepareCloneTemplate("#prepared-template", "#prepared-clone") catch |err| {
            failing.fail_index = std.math.maxInt(usize);
            switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(!world.channels.contains("#prepared-clone"));
                    try std.testing.expect(!world.channelExists("#PREPARED-CLONE"));
                    try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 1);
                    world.deinit();
                    continue;
                },
                else => {
                    world.deinit();
                    return err;
                },
            }
        }) orelse {
            world.deinit();
            return error.TestUnexpectedResult;
        };
        prepared.commitSeated(
            PreparedCloneTestFixture.seated(),
            MemberModes.fromModes(&.{ .owner, .voice }),
        ) catch |err| {
            failing.fail_index = std.math.maxInt(usize);
            prepared.abort();
            switch (err) {
                error.OutOfMemory => {
                    try std.testing.expect(!world.channels.contains("#prepared-clone"));
                    try std.testing.expect(!world.channelExists("#PREPARED-CLONE"));
                    try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 1);
                    world.deinit();
                    continue;
                },
                else => {
                    world.deinit();
                    return err;
                },
            }
        };
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expect(!failing.has_induced_failure);
        prepared.abort();
        try PreparedCloneTestFixture.expectSourceUnchanged(&world, source_oid, source_oid +% 2);
        try PreparedCloneTestFixture.expectCommittedDestination(&world, source_oid);
        world.deinit();
        break;
    }
}

test "cloneChannel copies portable room template state and marks the clone +E with a fresh OID" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(try world.join("#tmpl", a));
    try std.testing.expect(try world.setChannelFlag("#tmpl", .moderated, true));
    try world.setChannelLimit("#tmpl", 42);
    try world.setChannelKey("#tmpl", "sekret");
    try world.setForward("#tmpl", "#overflow");
    try world.setThrottle("#tmpl", 3, 10);
    try world.setTopic("#tmpl", "portable topic", "A!alice@localhost", 1234);
    try std.testing.expect(try world.addBan("#tmpl", "bad!*@*", "setter", 1));
    try std.testing.expect(try world.addExempt("#tmpl", "bad!vip@*", "setter", 2));
    try std.testing.expect(try world.addInvex("#tmpl", "friend!*@*", "setter", 3));
    try std.testing.expect(try world.addMute("#tmpl", "loud!*@*", "setter", 4));
    try std.testing.expect(try world.setChannelExtFlag("#tmpl", .cloneable, true));
    const tmpl_oid = world.channelOid("#tmpl").?;

    try std.testing.expect(try world.cloneChannel("#tmpl", "#tmpl1"));

    // Template state copied; clone is +E and not +d; OID is distinct; membership empty.
    try std.testing.expect(world.channelHasFlag("#tmpl1", .moderated));
    try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#tmpl1"));
    try std.testing.expectEqualStrings("#overflow", world.forwardOf("#tmpl1").?);
    try std.testing.expectEqual(@as(u16, 3), world.throttleOf("#tmpl1").?.joins);
    try std.testing.expectEqual(@as(u32, 10), world.throttleOf("#tmpl1").?.secs);
    const topic = world.topicInfo("#tmpl1").?;
    try std.testing.expectEqualStrings("portable topic", topic.text);
    try std.testing.expectEqualStrings("A!alice@localhost", topic.setter);
    try std.testing.expectEqual(@as(i64, 1234), topic.set_at);
    try std.testing.expectEqual(@as(usize, 1), world.bansOf("#tmpl1").?.len);
    try std.testing.expectEqualStrings("bad!*@*", world.bansOf("#tmpl1").?[0].mask);
    try std.testing.expectEqual(@as(usize, 1), world.exemptsOf("#tmpl1").?.len);
    try std.testing.expectEqualStrings("bad!vip@*", world.exemptsOf("#tmpl1").?[0].mask);
    try std.testing.expectEqual(@as(usize, 1), world.invexOf("#tmpl1").?.len);
    try std.testing.expectEqualStrings("friend!*@*", world.invexOf("#tmpl1").?[0].mask);
    try std.testing.expectEqual(@as(usize, 1), world.mutesOf("#tmpl1").?.len);
    try std.testing.expectEqualStrings("loud!*@*", world.mutesOf("#tmpl1").?[0].mask);
    try std.testing.expect(world.channelHasExtFlag("#tmpl1", .clone));
    try std.testing.expect(!world.channelHasExtFlag("#tmpl1", .cloneable));
    try std.testing.expect(world.channelOid("#tmpl1").? != tmpl_oid);
    try std.testing.expectEqual(@as(usize, 0), world.memberCount("#tmpl1"));

    // Cloning onto an existing name is a no-op (false); cloning a missing source errors.
    try std.testing.expect(!try world.cloneChannel("#tmpl", "#tmpl1"));
    try std.testing.expectError(error.NoSuchChannel, world.cloneChannel("#nope", "#x"));
}

test "removeClient drops all channel memberships and nick ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    try world.registerNick("A", a);
    try world.registerNick("B", b);
    _ = try world.join("#x", a);
    _ = try world.join("#x", b);
    _ = try world.join("#y", a);

    world.removeClient(a);

    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("A"));
    try std.testing.expect(!world.isMember("#x", a));
    try std.testing.expect(world.isMember("#x", b));
    try std.testing.expect(!world.channelExists("#y"));
}

test "message target resolution distinguishes channel and nick targets" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try world.registerNick("A", a);
    _ = try world.join("#x", a);

    const channel = try world.resolveMessageTarget("#x");
    try std.testing.expectEqualStrings("#x", channel.channel);

    const nick = try world.resolveMessageTarget("A");
    try std.testing.expectEqual(a, nick.nick);

    try std.testing.expectError(error.NoSuchChannel, world.resolveMessageTarget("#missing"));
    try std.testing.expectError(error.NoSuchNick, world.resolveMessageTarget("missing"));
}

test "topics are owned and released" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#x", a);
    try world.setTopic("#x", "first topic", "A!alice@localhost", 10);
    try std.testing.expectEqualStrings("first topic", world.topic("#x").?);
    var info = world.topicInfo("#x").?;
    try std.testing.expectEqualStrings("A!alice@localhost", info.setter);
    try std.testing.expectEqual(@as(i64, 10), info.set_at);
    try world.setTopic("#x", "second topic", "B!bob@localhost", 20);
    try std.testing.expectEqualStrings("second topic", world.topic("#x").?);
    info = world.topicInfo("#x").?;
    try std.testing.expectEqualStrings("B!bob@localhost", info.setter);
    try std.testing.expectEqual(@as(i64, 20), info.set_at);
}

test "first joiner founds the channel as operator; later joiners have no status" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const founder = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const second = ClientId{ .shard = 0, .slot = 2, .gen = 1 };

    _ = try world.join("#x", founder);
    _ = try world.join("#x", second);

    try std.testing.expect(world.memberModes("#x", founder).?.contains(.founder));
    try std.testing.expect(world.memberModes("#x", founder).?.isOperator());
    try std.testing.expect(!world.memberModes("#x", second).?.contains(.founder));
    try std.testing.expectEqual(@as(u8, '!'), world.memberModes("#x", founder).?.highestPrefix());
    try std.testing.expectEqual(@as(u8, 0), world.memberModes("#x", second).?.highestPrefix());
}

test "an existing (mesh-projected) channel entity with no local members still founds the first local joiner" {
    // Regression: founder-by-creation keys on the LOCAL member count, not on
    // channel existence. A mesh relink re-materializes the channel ENTITY from a
    // peer's roster (remote members live in the link roster, not the local member
    // set), so `channelExists` is already true while the local member set is empty.
    // The first LOCAL joiner is therefore still founded — which is why the JOIN
    // handler must strip an override admin's founder based on the grant actually
    // happening, NOT on a `creating = !channelExists` gate (that gate is false here
    // and silently let the admin keep +Q after a restart).
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    try world.ensureRemoteListChannel("#root");
    try std.testing.expect(world.channelExists("#root")); // entity exists ...
    try std.testing.expectEqual(@as(usize, 0), world.memberCount("#root")); // ... but 0 local members

    const admin = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    try std.testing.expect(try world.join("#root", admin)); // newly joined
    // Despite the pre-existing entity, the empty local member set founds the joiner.
    try std.testing.expect(world.memberModes("#root", admin).?.contains(.founder));

    // And the handler's remedy — clearing founder — works on this member.
    try std.testing.expect(try world.setMemberMode("#root", admin, .founder, false));
    try std.testing.expect(!world.memberModes("#root", admin).?.contains(.founder));
}

test "setMemberMode adds and removes status and reports change" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a); // a founds (op)
    _ = try world.join("#x", b);

    try std.testing.expect(try world.setMemberMode("#x", b, .voice, true));
    try std.testing.expect(world.memberModes("#x", b).?.contains(.voice));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setMemberMode("#x", b, .voice, true)));
    try std.testing.expect(try world.setMemberMode("#x", b, .voice, false));
    try std.testing.expect(!world.memberModes("#x", b).?.contains(.voice));

    try std.testing.expectError(error.NotOnChannel, world.setMemberMode("#x", ClientId{ .shard = 0, .slot = 9, .gen = 1 }, .op, true));
    try std.testing.expect(world.memberModes("#nope", a) == null);
}

test "memberModesByNick / isMemberByNick resolve local members case-insensitively" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    try world.registerNick("Alice", a); // founder of #x
    try world.registerNick("Bob", b);
    _ = try world.join("#x", a);
    _ = try world.join("#x", b);
    try std.testing.expect(try world.setMemberMode("#x", b, .voice, true));

    // Founder a resolves with founder/operator status; case-insensitive lookup.
    try std.testing.expect(world.memberModesByNick("#x", "alice").?.isOperator());
    try std.testing.expect(world.isMemberByNick("#x", "ALICE"));
    // b resolves with voice and is a member but not operator.
    try std.testing.expect(world.memberModesByNick("#x", "bob").?.contains(.voice));
    try std.testing.expect(!world.memberModesByNick("#x", "bob").?.isOperator());
    try std.testing.expect(world.isMemberByNick("#x", "Bob"));

    // A nick not in the channel — and an unknown channel — both resolve to null.
    try std.testing.expect(world.memberModesByNick("#x", "carol") == null);
    try std.testing.expect(!world.isMemberByNick("#x", "carol"));
    try std.testing.expect(world.memberModesByNick("#nope", "alice") == null);
}

test "channel key, limit, bans, and invites with ownership" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);

    // Key: set, replace (frees old), clear (frees).
    try world.setChannelKey("#x", "first");
    try std.testing.expectEqualStrings("first", world.channelKey("#x").?);
    try world.setChannelKey("#x", "second");
    try std.testing.expectEqualStrings("second", world.channelKey("#x").?);
    try world.setChannelKey("#x", null);
    try std.testing.expect(world.channelKey("#x") == null);

    // Limit.
    try std.testing.expect(world.channelLimit("#x") == null);
    try world.setChannelLimit("#x", 42);
    try std.testing.expectEqual(@as(?u32, 42), world.channelLimit("#x"));

    // Bans: add (dedup), match (glob, case-insensitive), remove.
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 1));
    try std.testing.expect(!(try world.addBan("#x", "bad!*@*", "setter", 1))); // dup
    try std.testing.expect(world.isBanned("#x", "BAD!user@host"));
    try std.testing.expect(!world.isBanned("#x", "good!user@host"));
    try std.testing.expectEqual(@as(usize, 1), world.bansOf("#x").?.len);
    try std.testing.expect(try world.removeBan("#x", "bad!*@*"));
    try std.testing.expect(!world.isBanned("#x", "BAD!user@host"));

    // +e exemption overrides a +b ban; +I invite-exception list is independent.
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 2));
    try std.testing.expect(world.isBanned("#x", "bad!u@h"));
    try std.testing.expect(try world.addExempt("#x", "bad!vip@*", "setter", 3));
    try std.testing.expect(!world.isBanned("#x", "bad!vip@h")); // exempt wins
    try std.testing.expect(world.isBanned("#x", "bad!other@h")); // still banned
    try std.testing.expectEqual(@as(usize, 1), world.exemptsOf("#x").?.len);
    try std.testing.expect(try world.removeExempt("#x", "bad!vip@*"));
    try std.testing.expect(world.isBanned("#x", "bad!vip@h")); // ban back in force
    try std.testing.expect(try world.addInvex("#x", "friend!*@*", "setter", 4));
    try std.testing.expect(world.isInvexed("#x", "FRIEND!u@h"));
    try std.testing.expectEqual(@as(usize, 1), world.invexOf("#x").?.len);

    // Invites.
    try std.testing.expect(!world.hasInvite("#x", b));
    try world.addInvite("#x", b);
    try std.testing.expect(world.hasInvite("#x", b));

    // memberCount tracks membership.
    try std.testing.expectEqual(@as(usize, 1), world.memberCount("#x"));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelKey("#nope", "k"));
}

test "renameChannel rekeys in place, preserving membership and bans" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#old", a);
    try world.setTopic("#old", "hello", "setter", 1);
    try std.testing.expect(try world.addBan("#old", "bad!*@*", "setter", 1));

    // Rename moves everything to the new key.
    try std.testing.expect(try world.renameChannel("#old", "#new"));
    try std.testing.expect(!world.channelExists("#old"));
    try std.testing.expect(world.channelExists("#new"));
    try std.testing.expect(world.isMember("#new", a));
    try std.testing.expect(world.isBanned("#new", "bad!u@h"));

    // Renaming onto an existing channel fails (false); missing source errors.
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#taken", b);
    try std.testing.expect(!(try world.renameChannel("#new", "#taken")));
    try std.testing.expectError(error.NoSuchChannel, world.renameChannel("#ghost", "#x"));
}

test "extended bans match account, realname, channel, and negation" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#x", a);

    // Plain mask via the ctx path still globs the host prefix (back-compat).
    try std.testing.expect(try world.addBan("#x", "bad!*@*", "setter", 1));
    try std.testing.expect(world.isBannedCtx("#x", .{ .host = "bad!u@h" }));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .host = "ok!u@h" }));
    try std.testing.expect(try world.removeBan("#x", "bad!*@*"));

    // $a: account ban.
    try std.testing.expect(try world.addBan("#x", "$a:spammer", "setter", 2));
    try std.testing.expect(world.isBannedCtx("#x", .{ .account = "spammer", .host = "x!y@z" }));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .account = "good", .host = "x!y@z" }));
    // Unauthenticated client never matches an account ban.
    try std.testing.expect(!world.isBannedCtx("#x", .{ .host = "x!y@z" }));

    // $r: realname glob; $e exemption (also extban-aware) overrides.
    try std.testing.expect(try world.addBan("#x", "$r:*bot*", "setter", 3));
    try std.testing.expect(world.isBannedCtx("#x", .{ .realname = "evil bot 9000", .host = "x!y@z" }));
    try std.testing.expect(try world.addExempt("#x", "$a:trusted", "setter", 4));
    try std.testing.expect(!world.isBannedCtx("#x", .{ .account = "trusted", .realname = "evil bot", .host = "x!y@z" }));

    // $c: channel ban — banned when present in #secret.
    try std.testing.expect(try world.addBan("#x", "$c:#secret", "setter", 5));
    const chans = [_][]const u8{"#secret"};
    try std.testing.expect(world.isBannedCtx("#x", .{ .host = "n!u@h", .channels = &chans }));
    // $~a: negated account ban (matches everyone NOT logged in as alice).
    try std.testing.expect(try world.addMute("#x", "$~a:alice", "setter", 6));
    try std.testing.expect(!world.isMutedCtx("#x", .{ .account = "alice", .host = "x!y@z" }));
    try std.testing.expect(world.isMutedCtx("#x", .{ .account = "bob", .host = "x!y@z" }));
}

test "$m extban in +b is a speech mute, not a join ban" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    _ = try world.join("#m", testClient(1));

    try std.testing.expect(try world.addBan("#m", "$m:muted!*@*", "setter", 1));

    const target = World.BanContext{ .host = "muted!user@example.test" };
    try std.testing.expect(!world.isBannedCtx("#m", target));
    try std.testing.expect(world.isMutedCtx("#m", target));

    const other = World.BanContext{ .host = "speaker!user@example.test" };
    try std.testing.expect(!world.isBannedCtx("#m", other));
    try std.testing.expect(!world.isMutedCtx("#m", other));
}

test "$z extban honors secure client context" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    _ = try world.join("#tls", testClient(1));

    try std.testing.expect(try world.addBan("#tls", "$z", "setter", 1));

    try std.testing.expect(!world.isBannedCtx("#tls", .{ .host = "plain!u@h", .secure = false }));
    try std.testing.expect(world.isBannedCtx("#tls", .{ .host = "secure!u@h", .secure = true }));
}

test "malformed extended bans are rejected before storage" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    _ = try world.join("#x", testClient(1));

    try std.testing.expectError(error.InvalidMask, world.addBan("#x", "$x:value", "setter", 1));
    // An empty pattern after the `$z:` / `$o:` delimiter is still rejected so a
    // stored mask cannot silently match everything (or nothing).
    try std.testing.expectError(error.InvalidMask, world.addBan("#x", "$z:", "setter", 2));
    try std.testing.expectError(error.InvalidMask, world.addExempt("#x", "$o:", "setter", 3));
    try std.testing.expectEqual(@as(usize, 0), world.bansOf("#x").?.len);
    try std.testing.expectEqual(@as(usize, 0), world.exemptsOf("#x").?.len);
}

test "$z certfp extban stores and matches the exact fingerprint" {
    const fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const other = "0000000000000000000000000000000000000000000000000000000000000000";

    var world = World.init(std.testing.allocator);
    defer world.deinit();
    _ = try world.join("#z", testClient(1));

    // Patterned `$z:<fp>` now stores successfully (no InvalidMask).
    try std.testing.expect(try world.addBan("#z", "$z:" ++ fp, "setter", 1));

    // The matching certfp is banned; a different certfp and a non-TLS client
    // (null certfp) are not.
    try std.testing.expect(world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = fp }));
    try std.testing.expect(!world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = other }));
    try std.testing.expect(!world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = false, .certfp = null }));
    try std.testing.expect(!world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = null }));

    // Add a broad host ban so the different-certfp client is otherwise caught,
    // then verify a fingerprint-specific exception `+e $z:<fp>` lets only the
    // matching client through.
    try std.testing.expect(try world.addBan("#z", "n!*@*", "setter", 2));
    try std.testing.expect(world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = other }));
    try std.testing.expect(try world.addExempt("#z", "$z:" ++ fp, "setter", 3));
    // The matching certfp is now exempt from the host ban.
    try std.testing.expect(!world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = fp }));
    // The different-certfp client is still caught by the host ban (the
    // exception is fingerprint-specific).
    try std.testing.expect(world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = true, .certfp = other }));
    // A non-TLS client with that host is also still banned and not exempted.
    try std.testing.expect(world.isBannedCtx("#z", .{ .host = "n!u@h", .secure = false, .certfp = null }));
}

test "channel flag modes set, query, and render" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#x", a);

    try std.testing.expect(!world.channelHasFlag("#x", .moderated));
    try std.testing.expect(try world.setChannelFlag("#x", .moderated, true));
    try std.testing.expect(!(try world.setChannelFlag("#x", .topic_ops, true)));
    try std.testing.expect(world.channelHasFlag("#x", .moderated));
    // Idempotent set reports no change.
    try std.testing.expect(!(try world.setChannelFlag("#x", .moderated, true)));

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("+mnt", world.channelModeString("#x", &buf));

    try std.testing.expect(try world.setChannelFlag("#x", .moderated, false));
    try std.testing.expectEqualStrings("+nt", world.channelModeString("#x", &buf));
    try std.testing.expectError(error.NoSuchChannel, world.setChannelFlag("#nope", .secret, true));
}

test "+Z quiet (MUTE) list: add, match, exempt override, remove" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#z", a);

    // Empty list mutes nobody.
    try std.testing.expect(!world.isMuted("#z", "loud!u@h"));

    // Add (dedup), glob + case-insensitive match.
    try std.testing.expect(try world.addMute("#z", "loud!*@*", "setter", 1));
    try std.testing.expect(!(try world.addMute("#z", "loud!*@*", "setter", 1))); // dup
    try std.testing.expect(world.isMuted("#z", "LOUD!user@host"));
    try std.testing.expect(!world.isMuted("#z", "quiet!user@host"));
    try std.testing.expectEqual(@as(usize, 1), world.mutesOf("#z").?.len);

    // A +e exempt overrides a +Z quiet, mirroring +b/+e semantics.
    try std.testing.expect(try world.addExempt("#z", "loud!vip@*", "setter", 2));
    try std.testing.expect(!world.isMuted("#z", "loud!vip@host")); // exempt wins
    try std.testing.expect(world.isMuted("#z", "loud!other@host")); // still muted

    // Remove returns to un-muted.
    try std.testing.expect(try world.removeMute("#z", "loud!*@*"));
    try std.testing.expect(!world.isMuted("#z", "loud!other@host"));
    try std.testing.expectError(error.NoSuchChannel, world.addMute("#nope", "x!*@*", "setter", 1));
}

test "+j join throttle: token bucket admits up to N per window, then denies" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#j", a);

    // Disabled by default (no +j, no network default): every join admitted.
    try std.testing.expect(world.throttleOf("#j") == null);
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 0, 0, 0));

    // Configure 2 joins per 10 seconds.
    try world.setThrottle("#j", 2, 10);
    const cfg = world.throttleOf("#j").?;
    try std.testing.expectEqual(@as(u16, 2), cfg.joins);
    try std.testing.expectEqual(@as(u32, 10), cfg.secs);

    // First two joins in the window are admitted; the third is denied. The first
    // denial in a window reports throttled_alert (one-shot), later ones throttled.
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 1000, 0, 0));
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 2000, 0, 0));
    try std.testing.expectEqual(World.ThrottleResult.throttled_alert, world.throttleAdmit("#j", 3000, 0, 0));
    try std.testing.expectEqual(World.ThrottleResult.throttled, world.throttleAdmit("#j", 3500, 0, 0));

    // After the window elapses, old timestamps prune and joins admit again.
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 13000, 0, 0)); // 1000ms entry expired
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 13500, 0, 0)); // 2000ms entry expired
    try std.testing.expectEqual(World.ThrottleResult.throttled_alert, world.throttleAdmit("#j", 14000, 0, 0)); // window full, new alert window

    // Clearing the +j mode disables the per-channel throttle entirely.
    try world.clearThrottle("#j");
    try std.testing.expect(world.throttleOf("#j") == null);
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#j", 99999, 0, 0));
    try std.testing.expectError(error.NoSuchChannel, world.setThrottle("#nope", 1, 1));
}

test "join throttle: network default applies to channels without explicit +j" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#r", a);

    // No +j set, but a network default of 2 joins / 5s applies and alerts once.
    try std.testing.expect(world.throttleOf("#r") == null); // mode still reads as unset
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#r", 0, 2, 5));
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#r", 100, 2, 5));
    try std.testing.expectEqual(World.ThrottleResult.throttled_alert, world.throttleAdmit("#r", 200, 2, 5));
    try std.testing.expectEqual(World.ThrottleResult.throttled, world.throttleAdmit("#r", 300, 2, 5));

    // An explicit +j overrides the network default (tighter or looser).
    try world.setThrottle("#r", 1, 5);
    try std.testing.expectEqual(World.ThrottleResult.admitted, world.throttleAdmit("#r", 10000, 2, 5));
    try std.testing.expectEqual(World.ThrottleResult.throttled_alert, world.throttleAdmit("#r", 10100, 2, 5));
}

test "+f forward target: set (owned dupe), read, replace, clear" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    _ = try world.join("#f", a);

    try std.testing.expect(world.forwardOf("#f") == null);
    try world.setForward("#f", "#overflow");
    try std.testing.expectEqualStrings("#overflow", world.forwardOf("#f").?);
    // Replace frees the old dupe and stores the new one.
    try world.setForward("#f", "#lobby");
    try std.testing.expectEqualStrings("#lobby", world.forwardOf("#f").?);
    // Clear frees the dupe.
    try world.setForward("#f", null);
    try std.testing.expect(world.forwardOf("#f") == null);
    try std.testing.expectError(error.NoSuchChannel, world.setForward("#nope", "#x"));
}

test "channelsOf lists a client's channels" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const a = ClientId{ .shard = 0, .slot = 1, .gen = 1 };
    const b = ClientId{ .shard = 0, .slot = 2, .gen = 1 };
    _ = try world.join("#x", a);
    _ = try world.join("#y", a);
    _ = try world.join("#x", b);

    var buf: [8][]const u8 = undefined;
    const n = world.channelsOf(a, &buf);
    try std.testing.expectEqual(@as(usize, 2), n);
    // both #x and #y present (order is map-dependent)
    var seen_x = false;
    var seen_y = false;
    for (buf[0..n]) |c| {
        if (std.mem.eql(u8, c, "#x")) seen_x = true;
        if (std.mem.eql(u8, c, "#y")) seen_y = true;
    }
    try std.testing.expect(seen_x and seen_y);
    try std.testing.expectEqual(@as(usize, 1), world.channelsOf(b, &buf));
}

const MtCtx = struct {
    world: *World,
    client: ClientId,
    nick: []const u8,
    iters: u64,

    fn writer(ctx: *MtCtx) void {
        // Register once, then hammer join/part on a shared channel — every
        // mutation (and its allocation) under the exclusive write lock.
        ctx.world.lockWrite();
        ctx.world.registerNick(ctx.nick, ctx.client) catch {};
        ctx.world.unlockWrite();
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.world.lockWrite();
            _ = ctx.world.join("#mt", ctx.client) catch {};
            ctx.world.part("#mt", ctx.client) catch {};
            ctx.world.unlockWrite();
        }
    }

    fn reader(ctx: *MtCtx) void {
        var i: u64 = 0;
        while (i < ctx.iters) : (i += 1) {
            ctx.world.lockRead();
            std.mem.doNotOptimizeAway(ctx.world.nickOf(ctx.client));
            ctx.world.unlockRead();
        }
    }
};

test "World mutations + reads are race-free under its RwLock" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const writers = 4;
    const iters: u64 = 3000;
    var nick_bufs: [writers][8]u8 = undefined;
    var ctxs: [writers]MtCtx = undefined;
    for (0..writers) |i| {
        const nick = std.fmt.bufPrint(&nick_bufs[i], "n{d}", .{i}) catch unreachable;
        ctxs[i] = .{
            .world = &world,
            .client = ClientId{ .shard = 0, .slot = @intCast(i + 1), .gen = 1 },
            .nick = nick,
            .iters = iters,
        };
    }

    var threads: [writers * 2]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, MtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, MtCtx.reader, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    // Each writer registered exactly one (distinct) nick; all joins were paired
    // with parts, so the shared channel ends empty. Consistency proves the lock
    // serialised every mutation without corruption.
    try std.testing.expectEqual(@as(usize, writers), world.nicks.count());
    try std.testing.expectEqual(@as(usize, 0), world.memberCount("#mt"));
    for (0..writers) |i| {
        try std.testing.expectEqualStrings(ctxs[i].nick, world.nickOf(ctxs[i].client).?);
    }
}

test "RCU nick mirror matches the authoritative map" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    // Activate the mirror before registering so registerNick keeps it in sync.
    _ = try world.ensureRcuNicks();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    const bob: ClientId = .{ .shard = 0, .slot = 2, .gen = 1 };
    try world.registerNick("Alice", alice);
    try world.registerNick("Bob", bob);

    // Hits agree with the authoritative map (exact case, apples-to-apples).
    try std.testing.expectEqual(world.findNick("Alice"), try world.findNickRcu("Alice"));
    try std.testing.expectEqual(world.findNick("Bob"), try world.findNickRcu("Bob"));
    try std.testing.expectEqual(@as(?ClientId, alice), try world.findNickRcu("Alice"));

    // Miss is a miss in both.
    try std.testing.expect((try world.findNickRcu("nobody")) == null);

    // Unregister keeps the mirror in sync.
    world.unregisterNick(alice);
    try std.testing.expect((try world.findNickRcu("Alice")) == null);
    try std.testing.expectEqual(@as(?ClientId, bob), try world.findNickRcu("Bob"));

    // Case-insensitive RCU lookup (an intended refinement over the case-sensitive
    // authoritative map; reconciled at the live flip).
    try std.testing.expectEqual(@as(?ClientId, bob), try world.findNickRcu("bob"));
}

test "findNick is case-insensitive once the RCU mirror is live" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    try world.registerNick("Alice", alice); // activates the mirror

    // Every casing of the registered nick resolves to the same owner.
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("Alice"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("alice"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("ALICE"));
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("aLiCe"));
    // Unknown nick still misses.
    try std.testing.expectEqual(@as(?ClientId, null), world.findNick("bob"));
}

test "nick collisions are case-insensitive (Alice then alice collides)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const alice: ClientId = .{ .shard = 0, .slot = 1, .gen = 1 };
    const mallory: ClientId = .{ .shard = 0, .slot = 2, .gen = 1 };

    try world.registerNick("Alice", alice);
    // A different client cannot take any casing of an in-use nick.
    try std.testing.expectError(error.NickInUse, world.registerNick("alice", mallory));
    try std.testing.expectError(error.NickInUse, world.registerNick("ALICE", mallory));

    // The original owner may re-assert / change the case of their own nick.
    try world.registerNick("ALICE", alice);
    try std.testing.expectEqualStrings("ALICE", world.nickOf(alice).?);
    try std.testing.expectEqual(@as(?ClientId, alice), world.findNick("alice"));

    // Releasing frees the (case-insensitive) name for someone else.
    world.unregisterNick(alice);
    try world.registerNick("alice", mallory);
    try std.testing.expectEqual(@as(?ClientId, mallory), world.findNick("Alice"));
}

test "transferNick hands a live identity to a sibling without an offline gap" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const primary = testClient(1);
    const sibling = testClient(2);
    try world.registerNick("Kain", primary);

    try std.testing.expect(try world.transferNick(primary, sibling));
    try std.testing.expect(world.nickOf(primary) == null);
    try std.testing.expectEqualStrings("Kain", world.nickOf(sibling).?);
    try std.testing.expectEqual(@as(?ClientId, sibling), world.findNick("kain"));
    try std.testing.expect(!(try world.transferNick(primary, sibling)));
}

test "exact session nick owner transaction removes sibling aliases and rejects foreign collision" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const primary = testClient(11);
    const sibling = testClient(12);
    const foreign = testClient(13);
    try world.registerNick("DeviceA", primary);
    try world.registerNick("DeviceB", sibling);
    try world.registerNick("Taken", foreign);
    const exact = [_]ClientId{ primary, sibling };

    try std.testing.expect(try world.replaceExactSessionNickOwner("Unified", sibling, &exact));
    try std.testing.expect(world.nickOf(primary) == null);
    try std.testing.expectEqualStrings("Unified", world.nickOf(sibling).?);
    try std.testing.expectEqual(@as(?ClientId, null), world.findNickFallback("devicea"));
    try std.testing.expectEqual(@as(?ClientId, null), world.findNickFallback("DEVICEB"));
    try std.testing.expectEqual(@as(?ClientId, sibling), world.findNickFallback("unified"));
    try std.testing.expectEqual(@as(?ClientId, sibling), world.findNick("UNIFIED"));

    // Exact idempotence does not publish another snapshot or allocate.
    try std.testing.expect(!(try world.replaceExactSessionNickOwner("Unified", sibling, &exact)));

    // An unrelated owner is preserved and every exact-session index remains
    // byte-for-byte unchanged on collision.
    try std.testing.expectError(error.NickInUse, world.replaceExactSessionNickOwner("tAkEn", primary, &exact));
    try std.testing.expect(world.nickOf(primary) == null);
    try std.testing.expectEqualStrings("Unified", world.nickOf(sibling).?);
    try std.testing.expectEqualStrings("Taken", world.nickOf(foreign).?);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("TAKEN"));

    try std.testing.expect(try world.relinquishExactSessionNickOwners("taken", foreign, &exact));
    try std.testing.expect(world.nickOf(primary) == null);
    try std.testing.expect(world.nickOf(sibling) == null);
    try std.testing.expectEqualStrings("Taken", world.nickOf(foreign).?);
    try std.testing.expectEqual(@as(?ClientId, foreign), world.findNick("tAkEn"));
}

test "exact session nick owner transaction is unchanged on every allocation failure" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var world = World.init(failing.allocator());
        const primary = testClient(21);
        const sibling = testClient(22);
        const foreign = testClient(23);
        try world.registerNick("OldPrimary", primary);
        try world.registerNick("OldSibling", sibling);
        try world.registerNick("Foreign", foreign);
        const exact = [_]ClientId{ primary, sibling };

        // Inject only after the fixture exists. PersistentMap's unrelated
        // setup-time OOM paths are tested in its own module; this loop walks
        // every allocation made by the World/RCU transaction itself.
        failing.fail_index = failing.alloc_index + fail_offset;
        const result = world.replaceExactSessionNickOwner("Unified", primary, &exact);
        failing.fail_index = std.math.maxInt(usize);

        if (result) |changed| {
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expect(changed);
            try std.testing.expectEqualStrings("Unified", world.nickOf(primary).?);
            try std.testing.expect(world.nickOf(sibling) == null);
            try std.testing.expectEqualStrings("Foreign", world.nickOf(foreign).?);
            const rcu_owner = world.rcu_nicks.?.nicks.lookup(world.rcu_nicks.?.writer_participant, "uNiFiEd") orelse return error.TestUnexpectedResult;
            try std.testing.expect(primary.eql(@as(ClientId, @bitCast(rcu_owner))));
            world.deinit();
            break;
        } else |err| switch (err) {
            error.OutOfMemory => {
                try std.testing.expectEqualStrings("OldPrimary", world.nickOf(primary).?);
                try std.testing.expectEqualStrings("OldSibling", world.nickOf(sibling).?);
                try std.testing.expectEqualStrings("Foreign", world.nickOf(foreign).?);
                try std.testing.expectEqual(@as(?ClientId, primary), world.findNickFallback("oldprimary"));
                try std.testing.expectEqual(@as(?ClientId, sibling), world.findNickFallback("oldsibling"));
                try std.testing.expectEqual(@as(?ClientId, foreign), world.findNickFallback("foreign"));
                try std.testing.expectEqual(@as(?ClientId, null), world.findNickFallback("unified"));
                try std.testing.expect(world.rcu_nicks.?.nicks.lookup(world.rcu_nicks.?.writer_participant, "Unified") == null);
                world.deinit();
            },
            else => {
                world.deinit();
                return err;
            },
        }
    }
}

test "channelExists mirror matches the authoritative map (case-insensitive)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    try std.testing.expect(!world.channelExists("#room"));

    _ = try world.join("#Room", a); // creates the channel + activates mirror

    // Existence is case-insensitive and agrees across casings.
    try std.testing.expect(world.channelExists("#Room"));
    try std.testing.expect(world.channelExists("#room"));
    try std.testing.expect(world.channelExists("#ROOM"));
    try std.testing.expect(!world.channelExists("#other"));

    // Emptying the channel reclaims it from the mirror too.
    try world.part("#room", a);
    try std.testing.expect(!world.channelExists("#Room"));
    try std.testing.expect(!world.channelExists("#room"));
}

test "isMember mirror matches authoritative membership (case-insensitive)" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    const b = testClient(2);

    _ = try world.join("#Chan", a);
    _ = try world.join("#chan", b); // same channel, different casing

    // Both members are visible through any casing of the channel name.
    try std.testing.expect(world.isMember("#Chan", a));
    try std.testing.expect(world.isMember("#CHAN", a));
    try std.testing.expect(world.isMember("#chan", b));
    try std.testing.expect(!world.isMember("#chan", testClient(9)));
    try std.testing.expect(!world.isMember("#nope", a));

    // Part removes from the mirror; the other member stays.
    try world.part("#chan", a);
    try std.testing.expect(!world.isMember("#Chan", a));
    try std.testing.expect(world.isMember("#Chan", b));

    // Disconnect path clears membership too.
    world.removeClient(b);
    try std.testing.expect(!world.channelExists("#chan"));
    try std.testing.expect(!world.isMember("#chan", b));
}

test "registered channel keeps RCU membership across empty, then reclaims" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#reg", a);
    _ = try world.setChannelExtFlag("#reg", .registered, true);

    // Last member leaves: registered channel persists (mirror still says exists),
    // but the member is gone from the membership mirror.
    try world.part("#reg", a);
    try std.testing.expect(world.channelExists("#reg"));
    try std.testing.expect(!world.isMember("#reg", a));

    // Re-join repopulates the mirror.
    _ = try world.join("#REG", a);
    try std.testing.expect(world.isMember("#reg", a));
}

test "renameChannel keeps RCU existence and membership mirrors in step" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();

    const a = testClient(1);
    _ = try world.join("#old", a);
    try std.testing.expect(try world.renameChannel("#old", "#new"));

    try std.testing.expect(!world.channelExists("#old"));
    try std.testing.expect(world.channelExists("#new"));
    try std.testing.expect(world.channelExists("#NEW"));
    try std.testing.expect(world.isMember("#new", a));
    try std.testing.expect(!world.isMember("#old", a));
}

test "World compound causal handoff followed by late removal OOM must leave predecessor intact" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer world.deinit();
    const source = testClient(900);
    const keeper = testClient(901);
    try world.registerNick("Shared", source);
    try world.restoreMember("#Only", source, MemberModes.fromModes(&.{.op}));
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, world.preparePhysicalDeparture(.{ .source = source, .keeper = keeper, .exact_clients = &.{ source, keeper }, .nick = .{ .target = "Shared", .disposition = .{ .claim_exact = keeper } } }));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(?ClientId, source), world.findNick("Shared"));
    try std.testing.expect(!world.isMember("#Only", keeper));
}

const compound_source = testClient(910);
const compound_keeper = testClient(911);
const compound_third = testClient(912);
const compound_foreign = testClient(913);

fn compoundFixture(world: *World, divergent: bool) !void {
    try world.registerNick("Shared", compound_source);
    try world.registerNick("Third", compound_third);
    try world.registerNick("Foreign", compound_foreign);
    try world.restoreMember("#Shared", compound_source, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#Shared", compound_keeper, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#Shared", compound_foreign, MemberModes.fromModes(&.{.owner}));
    try world.restoreMember("#SourceOnly", compound_source, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#KeeperOnly", compound_keeper, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#ThirdOnly", compound_third, MemberModes.fromModes(&.{.voice}));
    try world.restoreMember("#ForeignOnly", compound_foreign, MemberModes.fromModes(&.{.owner}));
    _ = try world.markRegistered("#RegisteredEmpty", true);
    _ = try world.markRegistered("#Empty", true);
    _ = try world.markRegistered("#Empty", false);
    try world.channels.getPtr("#RegisteredEmpty").?.invites.put(world.allocator, compound_source, {});
    try world.channels.getPtr("#ForeignOnly").?.invites.put(world.allocator, compound_source, {});
    try world.channels.getPtr("#ForeignOnly").?.invites.put(world.allocator, compound_keeper, {});
    const metadata = world.channels.getPtr("#SourceOnly").?;
    try metadata.setTopic("persistent subject-only channel", "operator", 91234);
    metadata.key = try world.allocator.dupe(u8, "channel-key");
    metadata.forward = try world.allocator.dupe(u8, "#ForeignOnly");
    metadata.limit = 7;
    metadata.private = true;
    metadata.hidden = true;
    metadata.throttle_joins = 3;
    metadata.throttle_secs = 9;
    metadata.throttle_alert_ms = 999;
    try metadata.throttle_times.append(world.allocator, 81234);
    const ban = try ListEntry.init(world.allocator, "*!*@blocked", "operator", 41234);
    metadata.bans.append(world.allocator, ban) catch |err| {
        var owned = ban;
        owned.deinit(world.allocator);
        return err;
    };
    if (divergent) {
        const c = world.rcu_channels.?;
        world.rcuDropMembership(c, "#SourceOnly");
        try c.names.remove(c.writer_participant, "#SourceOnly");
        try world.restoreMember("#RcuOnly", compound_source, MemberModes.fromModes(&.{.op}));
        world.removeFallbackChannel("#RcuOnly");
        try world.restoreMember("#RcuGap", compound_source, MemberModes.fromModes(&.{.op}));
        _ = world.channels.getPtr("#RcuGap").?.members.remove(compound_source);
        try world.restoreMember("#FallbackGap", compound_source, MemberModes.fromModes(&.{.op}));
        try World.rcuMembershipGet(c, "#FallbackGap").?.remove(c.writer_participant, @bitCast(compound_source));
        const n = world.rcu_nicks.?;
        try n.nicks.set(n.writer_participant, "Ghost", @bitCast(compound_source));
    }
}

fn compoundSpec(policy: u2) World.PhysicalDepartureSpec {
    return .{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper, compound_third }, .nick = switch (policy) {
        0 => .{ .target = "Shared", .disposition = .{ .claim_exact = compound_keeper } },
        1 => .{ .target = "Foreign", .disposition = .{ .preserve_foreign = compound_foreign } },
        else => null,
    } };
}

fn compoundBefore(world: *World, divergent: bool) !void {
    try std.testing.expectEqual(@as(?ClientId, compound_source), world.findNick("Shared"));
    try std.testing.expectEqual(@as(?ClientId, compound_third), world.findNick("Third"));
    try std.testing.expect(world.channels.getPtr("#Shared").?.members.contains(compound_source));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#Shared", compound_keeper).?.bits);
    try std.testing.expect(!world.channels.getPtr("#SourceOnly").?.members.contains(compound_keeper));
    try std.testing.expect(!world.isMember("#ThirdOnly", compound_keeper));
    try std.testing.expect(world.channels.getPtr("#ForeignOnly").?.invites.contains(compound_source));
    try std.testing.expect(world.channelExists("#Empty"));
    if (divergent) {
        try std.testing.expect(World.rcuMembershipGet(world.rcu_channels.?, "#SourceOnly") == null);
        try std.testing.expect(!world.channelExists("#SourceOnly"));
        try std.testing.expectEqual(@as(?ClientId, compound_source), world.findNick("Ghost"));
        try std.testing.expect(!world.channels.contains("#RcuOnly"));
        try std.testing.expect(world.isMember("#RcuOnly", compound_source));
        try std.testing.expect(!world.channels.getPtr("#RcuGap").?.members.contains(compound_source));
    }
}

fn compoundAfter(world: *World, divergent: bool, policy: u2) !void {
    try std.testing.expect(world.nickOf(compound_source) == null);
    try std.testing.expect(world.findNick("Ghost") == null);
    try std.testing.expectEqual(@as(?ClientId, compound_foreign), world.findNick("Foreign"));
    if (policy == 0) {
        try std.testing.expectEqual(@as(?ClientId, compound_keeper), world.findNick("Shared"));
        try std.testing.expect(world.findNick("Third") == null);
    } else {
        try std.testing.expect(world.findNick("Shared") == null);
        try std.testing.expectEqual(if (policy == 1) @as(?ClientId, null) else @as(?ClientId, compound_third), world.findNick("Third"));
    }
    try std.testing.expectEqual(MemberModes.fromModes(&.{ .op, .voice }).bits, world.memberModes("#Shared", compound_keeper).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.owner}).bits, world.memberModes("#Shared", compound_foreign).?.bits);
    for ([_][]const u8{ "#Shared", "#SourceOnly", "#KeeperOnly", "#ThirdOnly" }) |name| {
        try std.testing.expect(world.isMember(name, compound_keeper));
        try std.testing.expect(!world.isMember(name, compound_source));
    }
    try std.testing.expect(world.isMember("#ThirdOnly", compound_third));
    try std.testing.expect(!world.isMember("#ForeignOnly", compound_keeper));
    try std.testing.expect(!world.channels.getPtr("#ForeignOnly").?.invites.contains(compound_source));
    try std.testing.expect(world.channels.getPtr("#ForeignOnly").?.invites.contains(compound_keeper));
    try std.testing.expect(world.channelExists("#RegisteredEmpty"));
    try std.testing.expect(!world.channels.getPtr("#RegisteredEmpty").?.invites.contains(compound_source));
    try std.testing.expect(!world.channelExists("#Empty"));
    if (divergent) {
        try std.testing.expect(!world.channels.contains("#RcuOnly"));
        try std.testing.expect(world.isMember("#RcuOnly", compound_keeper));
        try std.testing.expect(!world.isMember("#RcuOnly", compound_source));
        try std.testing.expectEqual(@as(u8, 0), world.memberModes("#RcuGap", compound_keeper).?.bits);
        try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, world.memberModes("#FallbackGap", compound_keeper).?.bits);
    }
}

test "World compound departure derives complete OR union preserves metadata and aborts atomically" {
    for ([_]bool{ false, true }) |divergent| for ([_]u2{ 0, 1, 2 }) |policy| {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        try compoundFixture(&world, divergent);
        const metadata = compoundMetadataDigest(world.channels.getPtr("#SourceOnly").?);
        const oid = world.channels.getPtr("#SourceOnly").?.oid;
        const created = world.channels.getPtr("#SourceOnly").?.created_unix;
        var aborted = try world.preparePhysicalDeparture(compoundSpec(policy));
        try compoundBefore(&world, divergent);
        aborted.abort();
        aborted.abort();
        try compoundBefore(&world, divergent);
        var prepared = try world.preparePhysicalDeparture(compoundSpec(policy));
        defer prepared.abort();
        prepared.commit();
        try compoundAfter(&world, divergent, policy);
        try std.testing.expectEqual(oid, world.channels.getPtr("#SourceOnly").?.oid);
        try std.testing.expectEqual(created, world.channels.getPtr("#SourceOnly").?.created_unix);
        try std.testing.expectEqual(metadata, compoundMetadataDigest(world.channels.getPtr("#SourceOnly").?));
        var again = try world.preparePhysicalDeparture(compoundSpec(policy));
        defer again.abort();
        again.commit();
        try compoundAfter(&world, divergent, policy);
    };
}

test "World compound departure union assertions and exact owner sets reject invented authority" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try compoundFixture(&world, false);
    const root = world.rcu_nicks.?.nicks.published.load(.acquire);
    var spec = compoundSpec(0);
    spec.expected_union = &.{.{ .channel = "#Shared", .modes = MemberModes.fromModes(&.{ .op, .voice }) }};
    try std.testing.expectError(error.InvalidUnion, world.preparePhysicalDeparture(spec));
    const good = [_]MemberRestore{
        .{ .channel = "#shared", .modes = MemberModes.fromModes(&.{ .op, .voice }) },
        .{ .channel = "#SourceOnly", .modes = MemberModes.fromModes(&.{.voice}) },
        .{ .channel = "#KeeperOnly", .modes = MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#ThirdOnly", .modes = MemberModes.fromModes(&.{.voice}) },
    };
    var wrong = good;
    wrong[3].channel = "#SHARED";
    spec.expected_union = &wrong;
    try std.testing.expectError(error.InvalidUnion, world.preparePhysicalDeparture(spec));
    wrong = good;
    wrong[0].modes = MemberModes.fromModes(&.{.owner});
    try std.testing.expectError(error.InvalidUnion, world.preparePhysicalDeparture(spec));
    wrong = good;
    wrong[3].channel = "#Extra";
    try std.testing.expectError(error.InvalidUnion, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.exact_clients = &.{ compound_source, compound_keeper, compound_keeper };
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.keeper = compound_source;
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.nick.?.disposition = .{ .claim_exact = compound_third };
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.nick.?.disposition = .{ .preserve_foreign = compound_foreign };
    try std.testing.expectError(error.NickInUse, world.preparePhysicalDeparture(spec));
    try std.testing.expectEqual(root, world.rcu_nicks.?.nicks.published.load(.acquire));
    try compoundBefore(&world, false);
    spec = compoundSpec(0);
    spec.expected_union = &good;
    var accepted = try world.preparePhysicalDeparture(spec);
    defer accepted.abort();
    accepted.commit();
    try compoundAfter(&world, false, 0);
}

test "World compound departure exhaustive OOM rollback every root retry and allocation armed commit" {
    for ([_]bool{ false, true }) |divergent| for ([_]u2{ 0, 1, 2 }) |policy| {
        var index: usize = 0;
        while (index < 10000) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var world = World.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                world.deinit();
            }
            try compoundFixture(&world, divergent);
            const c = world.rcu_channels.?;
            const nick_root = world.rcu_nicks.?.nicks.published.load(.acquire);
            const names_root = c.names.published.load(.acquire);
            const Capture = struct { set: *world_rcu.MembershipSet, root: usize };
            const roots = try std.testing.allocator.alloc(Capture, c.members.count());
            defer std.testing.allocator.free(roots);
            var it = c.members.valueIterator();
            for (roots) |*capture| {
                const set = it.next().?.*;
                capture.* = .{ .set = set, .root = @intFromPtr(set.published.load(.acquire)) };
            }
            const fallback_digest = compoundFallbackDigest(&world);
            failing.fail_index = failing.alloc_index + index;
            var prepared = world.preparePhysicalDeparture(compoundSpec(policy)) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(nick_root, world.rcu_nicks.?.nicks.published.load(.acquire));
                try std.testing.expectEqual(names_root, c.names.published.load(.acquire));
                for (roots) |capture| try std.testing.expectEqual(capture.root, @intFromPtr(capture.set.published.load(.acquire)));
                try compoundBefore(&world, divergent);
                try std.testing.expectEqual(fallback_digest, compoundFallbackDigest(&world));
                failing.fail_index = std.math.maxInt(usize);
                var retry = try world.preparePhysicalDeparture(compoundSpec(policy));
                defer retry.abort();
                const allocations = failing.allocations;
                failing.fail_index = failing.alloc_index;
                retry.commit();
                try std.testing.expectEqual(allocations, failing.allocations);
                try compoundAfter(&world, divergent, policy);
                continue;
            };
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            prepared.abort();
            prepared.abort();
            try std.testing.expectEqual(fallback_digest, compoundFallbackDigest(&world));
            try std.testing.expectEqual(allocations, failing.allocations);
            try std.testing.expect(!failing.has_induced_failure);
            try compoundBefore(&world, divergent);
            failing.fail_index = std.math.maxInt(usize);
            var success = try world.preparePhysicalDeparture(compoundSpec(policy));
            defer success.abort();
            failing.fail_index = failing.alloc_index;
            const before_commit = failing.allocations;
            success.commit();
            try std.testing.expectEqual(before_commit, failing.allocations);
            try compoundAfter(&world, divergent, policy);
            try std.testing.expect(index > 0);
            break;
        }
        try std.testing.expect(index < 10000);
    };
}

test "World compound departure pair contributes only pair and leaves unrelated exact attachment untouched" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try compoundFixture(&world, false);
    var spec = compoundSpec(2);
    spec.exact_clients = &.{ compound_source, compound_keeper };
    var prepared = try world.preparePhysicalDeparture(spec);
    defer prepared.abort();
    prepared.commit();
    try std.testing.expect(world.isMember("#ThirdOnly", compound_third));
    try std.testing.expect(!world.isMember("#ThirdOnly", compound_keeper));
    try std.testing.expectEqual(@as(?ClientId, compound_third), world.findNick("Third"));
    try std.testing.expect(world.isMember("#SourceOnly", compound_keeper));
}

test "World compound departure rejects graph alias long names and contradictory name OID before publication" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try compoundFixture(&world, false);
    const c = world.rcu_channels.?;
    const nick_root = world.rcu_nicks.?.nicks.published.load(.acquire);
    const oid = world.channels.getPtr("#SourceOnly").?.oid;
    try c.names.set(c.writer_participant, "#SourceOnly", oid + 1);
    try std.testing.expectError(error.InvalidGraph, world.preparePhysicalDeparture(compoundSpec(0)));
    try c.names.set(c.writer_participant, "#SourceOnly", oid);
    const alias = try world.allocator.dupe(u8, "#alias");
    try c.members.put(world.allocator, alias, World.rcuMembershipGet(c, "#Shared").?);
    try std.testing.expectError(error.InvalidGraph, world.preparePhysicalDeparture(compoundSpec(0)));
    _ = c.members.remove(alias);
    world.allocator.free(alias);
    var too_long: [foldBufLen + 1]u8 = @splat('x');
    too_long[0] = '#';
    const long_key = try world.allocator.dupe(u8, &too_long);
    try c.members.put(world.allocator, long_key, World.rcuMembershipGet(c, "#Shared").?);
    try std.testing.expectError(error.InvalidGraph, world.preparePhysicalDeparture(compoundSpec(0)));
    _ = c.members.remove(long_key);
    world.allocator.free(long_key);
    // A missing name cannot claim the identity of an unrelated names-only entity.
    try c.names.remove(c.writer_participant, "#SourceOnly");
    try c.names.set(c.writer_participant, "#NamesOnly", oid);
    try std.testing.expectError(error.InvalidGraph, world.preparePhysicalDeparture(compoundSpec(0)));
    try c.names.remove(c.writer_participant, "#NamesOnly");
    try c.names.set(c.writer_participant, "#SourceOnly", oid);
    try std.testing.expectEqual(nick_root, world.rcu_nicks.?.nicks.published.load(.acquire));
    try compoundBefore(&world, false);
}

test "World compound departure RCU only entity stays empty names only survives and foreign RCU prevents deletion" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    const source = compound_source;
    try world.restoreMember("#RcuOnly", source, MemberModes.empty());
    const c = world.rcu_channels.?;
    world.removeFallbackChannel("#RcuOnly");
    try c.names.set(c.writer_participant, "#NamesOnly", 99000);
    try world.restoreMember("#ForeignGap", source, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#ForeignGap", compound_foreign, MemberModes.fromModes(&.{.voice}));
    _ = world.channels.getPtr("#ForeignGap").?.members.remove(compound_foreign);
    var prepared = try world.preparePhysicalDeparture(.{ .source = source, .keeper = null, .exact_clients = &.{source}, .expected_union = &.{} });
    defer prepared.abort();
    prepared.commit();
    try std.testing.expect(!world.channels.contains("#RcuOnly"));
    try std.testing.expect(World.rcuMembershipGet(c, "#RcuOnly") != null);
    try std.testing.expectEqual(@as(usize, 0), World.rcuMembershipGet(c, "#RcuOnly").?.count(c.writer_participant));
    try std.testing.expect(world.channelExists("#NamesOnly"));
    try std.testing.expect(World.rcuMembershipGet(c, "#NamesOnly") == null);
    try std.testing.expect(world.channels.contains("#ForeignGap"));
    try std.testing.expect(world.isMember("#ForeignGap", compound_foreign));
    try std.testing.expectEqual(@as(usize, 0), world.channels.getPtr("#ForeignGap").?.members.count());
}

fn compoundFallbackOnlyFixture(world: *World) !void {
    // Construct the supported globally inactive mirror case directly; every
    // fallback row still owns its canonical Channel metadata and key storage.
    const key = try world.allocator.dupe(u8, "#Dormant");
    errdefer world.allocator.free(key);
    var channel = Channel.init(world.allocator);
    errdefer channel.deinit();
    channel.oid = 810;
    channel.created_unix = 12345;
    try channel.members.put(compound_source, MemberModes.fromModes(&.{.op}));
    try channel.members.put(compound_foreign, MemberModes.fromModes(&.{.voice}));
    try channel.invites.put(world.allocator, compound_source, {});
    try world.channels.put(key, channel);
}

test "World compound departure inactive RCU exhaustive OOM abort and keeper commit do not activate partial mirror" {
    var index: usize = 0;
    while (index < 10000) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var world = World.init(failing.allocator());
        defer {
            failing.fail_index = std.math.maxInt(usize);
            world.deinit();
        }
        try compoundFallbackOnlyFixture(&world);
        const spec = World.PhysicalDepartureSpec{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper } };
        failing.fail_index = failing.alloc_index + index;
        var prepared = world.preparePhysicalDeparture(spec) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(world.rcu_channels == null and world.rcu_nicks == null);
            const channel = world.channels.getPtr("#Dormant").?;
            try std.testing.expect(channel.members.contains(compound_source));
            try std.testing.expect(!channel.members.contains(compound_keeper));
            try std.testing.expect(channel.invites.contains(compound_source));
            failing.fail_index = std.math.maxInt(usize);
            var retry = try world.preparePhysicalDeparture(spec);
            defer retry.abort();
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            retry.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try std.testing.expect(world.rcu_channels == null and world.rcu_nicks == null);
            try std.testing.expect(!channel.members.contains(compound_source));
            try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, channel.members.get(compound_keeper).?.bits);
            try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, channel.members.get(compound_foreign).?.bits);
            continue;
        };
        prepared.abort();
        prepared.abort();
        try std.testing.expect(world.rcu_channels == null and world.rcu_nicks == null);
        try std.testing.expect(world.channels.getPtr("#Dormant").?.members.contains(compound_source));
        try std.testing.expect(index > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "World compound departure missing set final rebuild preserves foreign and names OID" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try world.restoreMember("#Mixed", compound_source, MemberModes.fromModes(&.{.op}));
    try world.restoreMember("#Mixed", compound_foreign, MemberModes.fromModes(&.{.voice}));
    const c = world.rcu_channels.?;
    const oid = world.channels.getPtr("#Mixed").?.oid;
    world.rcuDropMembership(c, "#Mixed");
    try c.names.remove(c.writer_participant, "#Mixed");
    var prepared = try world.preparePhysicalDeparture(.{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper } });
    defer prepared.abort();
    try std.testing.expect(World.rcuMembershipGet(c, "#Mixed") == null);
    prepared.commit();
    try std.testing.expect(!world.isMember("#Mixed", compound_source));
    try std.testing.expect(world.isMember("#Mixed", compound_keeper));
    try std.testing.expect(world.isMember("#Mixed", compound_foreign));
    try std.testing.expectEqual(oid, c.names.lookup(c.writer_participant, "#Mixed").?);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#Mixed", compound_foreign).?.bits);
}

// Capacity and hash table layout may change on failed reservation; logical
// ownership, memberships/modes, metadata and invitation capabilities may not.
fn compoundMetadataDigest(channel: *const Channel) u64 {
    var hash = std.hash.Wyhash.init(0);
    inline for (.{ "topic", "topic_setter", "key", "forward" }) |field| {
        const bytes = @field(channel, field);
        hash.update(&.{@intFromBool(bytes != null)});
        if (bytes) |value| {
            const len = value.len;
            hash.update(std.mem.asBytes(&len));
            hash.update(value);
        }
    }
    inline for (.{ "topic_time", "throttle_joins", "throttle_secs", "throttle_alert_ms", "private", "hidden", "oid", "created_unix" }) |field| {
        const value = @field(channel, field);
        hash.update(std.mem.asBytes(&value));
    }
    const limit = channel.limit orelse 0;
    hash.update(&.{@intFromBool(channel.limit != null)});
    hash.update(std.mem.asBytes(&limit));
    const base = checkpointBaseModeBits(channel.modes);
    hash.update(std.mem.asBytes(&base));
    const extended: u32 = @bitCast(channel.ext_modes);
    hash.update(std.mem.asBytes(&extended));
    inline for (.{ "bans", "exempts", "invex", "mutes" }) |field| {
        const list = @field(channel, field).items;
        const len = list.len;
        hash.update(std.mem.asBytes(&len));
        for (list) |row| {
            hash.update(row.mask);
            hash.update(row.setter);
            hash.update(std.mem.asBytes(&row.set_at));
        }
    }
    hash.update(std.mem.sliceAsBytes(channel.throttle_times.items));
    return hash.final();
}

fn compoundFallbackDigest(world: *World) u64 {
    var sum: u64 = 0;
    var it = world.channels.iterator();
    while (it.next()) |entry| {
        var hash = std.hash.Wyhash.init(compoundMetadataDigest(entry.value_ptr));
        hash.update(entry.key_ptr.*);
        var members = entry.value_ptr.members.iterator();
        var member_sum: u64 = 0;
        while (members.next()) |row| {
            const id: u64 = @bitCast(row.key_ptr.*);
            var member = std.hash.Wyhash.init(id);
            member.update(&.{row.value_ptr.bits});
            member_sum +%= member.final();
        }
        hash.update(std.mem.asBytes(&member_sum));
        var invites = entry.value_ptr.invites.keyIterator();
        var invite_sum: u64 = 0;
        while (invites.next()) |id| {
            const bits: u64 = @bitCast(id.*);
            invite_sum +%= std.hash.Wyhash.hash(0, std.mem.asBytes(&bits));
        }
        hash.update(std.mem.asBytes(&invite_sum));
        const member_count = entry.value_ptr.members.count();
        const invite_count = entry.value_ptr.invites.count();
        hash.update(std.mem.asBytes(&member_count));
        hash.update(std.mem.asBytes(&invite_count));
        sum +%= hash.final();
    }
    return sum;
}

const RegisteredStageTestCut = struct {
    const Root = struct { set: *world_rcu.MembershipSet, root: usize };
    fallback: u64,
    channel_count: usize,
    next_oid: u32,
    rcu: ?*RcuChannelState,
    names_root: ?usize,
    member_count: usize,
    writes: usize,
    roots: []Root,

    fn capture(world: *World) !RegisteredStageTestCut {
        const c = world.rcu_channels;
        const roots = try std.testing.allocator.alloc(Root, if (c) |mirror| mirror.members.count() else 0);
        if (c) |mirror| {
            var it = mirror.members.valueIterator();
            for (roots) |*root| {
                const set = it.next().?.*;
                root.* = .{ .set = set, .root = @intFromPtr(set.published.load(.acquire)) };
            }
        }
        return .{
            .fallback = compoundFallbackDigest(world),
            .channel_count = world.channels.count(),
            .next_oid = world.next_oid,
            .rcu = c,
            .names_root = if (c) |mirror| @intFromPtr(mirror.names.published.load(.acquire)) else null,
            .member_count = if (c) |mirror| mirror.members.count() else 0,
            .writes = world.rcu_channel_writes_since_advance,
            .roots = roots,
        };
    }
    fn deinit(self: RegisteredStageTestCut) void {
        std.testing.allocator.free(self.roots);
    }
    fn expectUnchanged(self: RegisteredStageTestCut, world: *World) !void {
        try std.testing.expectEqual(self.fallback, compoundFallbackDigest(world));
        try std.testing.expectEqual(self.channel_count, world.channels.count());
        try std.testing.expectEqual(self.next_oid, world.next_oid);
        try std.testing.expect(self.rcu == world.rcu_channels);
        try std.testing.expectEqual(self.writes, world.rcu_channel_writes_since_advance);
        if (self.rcu) |mirror| {
            try std.testing.expectEqual(self.names_root.?, @intFromPtr(mirror.names.published.load(.acquire)));
            try std.testing.expectEqual(self.member_count, mirror.members.count());
        }
        for (self.roots) |root| try std.testing.expectEqual(root.root, @intFromPtr(root.set.published.load(.acquire)));
    }
};

const RegisteredStageCase = enum { empty, active, dormant, existing, drop, absent_drop };

fn registeredStageFixture(world: *World, case: RegisteredStageCase) !void {
    world.clock_unix = 123456;
    switch (case) {
        .empty, .absent_drop => {},
        .dormant => try compoundFallbackOnlyFixture(world),
        .active, .existing, .drop => {
            try world.restoreMember("#Keeper", compound_source, MemberModes.fromModes(&.{.op}));
            try world.restoreMember("#Keeper", compound_foreign, MemberModes.fromModes(&.{.voice}));
            const channel = world.channels.getPtr("#Keeper").?;
            try channel.setTopic("original topic", "original setter", 12345);
            channel.key = try world.allocator.dupe(u8, "original key");
            channel.private = true;
            try channel.invites.put(world.allocator, compound_keeper, {});
            if (case == .drop) channel.ext_modes.set(.registered);
        },
    }
}

fn registeredStageOutcome(world: *World, case: RegisteredStageCase) !void {
    const target = if (case == .existing or case == .drop) "#Keeper" else "#New";
    if (case == .absent_drop) {
        try std.testing.expect(world.channels.count() == 0 and world.rcu_channels == null and world.next_oid == 1);
        return;
    }
    try std.testing.expect(world.channelExists(target));
    try std.testing.expectEqual(case != .drop, world.channelHasExtFlag(target, .registered));
    if (case == .active or case == .existing or case == .drop) {
        try std.testing.expect(world.isMember("#keeper", compound_source) and world.isMember("#KEEPER", compound_foreign));
        const keeper = world.channels.getPtr("#Keeper").?;
        try std.testing.expectEqualStrings("original topic", keeper.topic.?);
        try std.testing.expectEqualStrings("original setter", keeper.topic_setter.?);
        try std.testing.expectEqualStrings("original key", keeper.key.?);
        try std.testing.expectEqual(MemberModes.fromModes(&.{.op}).bits, keeper.members.get(compound_source).?.bits);
        try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, keeper.members.get(compound_foreign).?.bits);
        try std.testing.expect(keeper.private and keeper.invites.contains(compound_keeper));
    } else if (case == .dormant) {
        try std.testing.expect(world.channelExists("#DORMANT"));
        try std.testing.expect(world.isMember("#dormant", compound_source) and world.isMember("#Dormant", compound_foreign));
        try std.testing.expectEqual(@as(?u32, 810), world.channelOid("#Dormant"));
        try std.testing.expectEqual(@as(?u32, 811), world.channelOid("#New"));
        try std.testing.expect(world.channels.getPtr("#Dormant").?.invites.contains(compound_source));
    }
    if (case == .empty or case == .active or case == .dormant) {
        try std.testing.expectEqual(@as(usize, 0), world.channels.getPtr("#new").?.members.count());
        try std.testing.expectEqual(@as(?i64, 123456), world.channelCreatedUnix("#new"));
    }
}

test "World registered channel staged exhaustive OOM exact logical rollback retry and zero allocation terminal commit" {
    for (std.enums.values(RegisteredStageCase)) |case| {
        var index: usize = 0;
        var finished = false;
        while (index < 1000) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var world = World.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                world.deinit();
            }
            world.lockWrite();
            defer world.unlockWrite();
            try registeredStageFixture(&world, case);
            const before = try RegisteredStageTestCut.capture(&world);
            defer before.deinit();
            const target = if (case == .existing or case == .drop) "#kEEPER" else "#New";
            const on = case != .drop and case != .absent_drop;
            failing.fail_index = failing.alloc_index + index;
            const prepared = world.prepareRegisteredChannel(target, on) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                try world.requireNoActiveRegisteredChannelStage();
                try before.expectUnchanged(&world);
                failing.fail_index = std.math.maxInt(usize);
                const retry = try world.prepareRegisteredChannel(target, on);
                defer retry.abort();
                try retry.requireReady();
                try before.expectUnchanged(&world);
                const allocations = failing.allocations;
                failing.fail_index = failing.alloc_index;
                retry.commit();
                try std.testing.expectEqual(allocations, failing.allocations);
                failing.fail_index = std.math.maxInt(usize);
                try registeredStageOutcome(&world, case);
                continue;
            };
            defer prepared.abort();
            try before.expectUnchanged(&world);
            try std.testing.expectError(error.ChannelStageActive, world.prepareRegisteredChannel("#Nested", true));
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            prepared.abort();
            prepared.abort();
            try std.testing.expectEqual(allocations, failing.allocations);
            try before.expectUnchanged(&world);
            failing.fail_index = std.math.maxInt(usize);
            const retry = try world.prepareRegisteredChannel(target, on);
            defer retry.abort();
            const before_commit = failing.allocations;
            failing.fail_index = failing.alloc_index;
            retry.commit();
            try std.testing.expectEqual(before_commit, failing.allocations);
            failing.fail_index = std.math.maxInt(usize);
            try registeredStageOutcome(&world, case);
            if (case == .empty or case == .active or case == .dormant) try std.testing.expect(index > 0);
            finished = true;
            break;
        }
        try std.testing.expect(finished);
        std.debug.print("registered channel source case={s} actual prepare OOM boundaries={}\n", .{ @tagName(case), index });
    }
}

test "World registered channel stage rejects invalid name divergent projection and nonwrap OID without publication" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, world.prepareRegisteredChannel("#New", true));
    world.lockWrite();
    defer world.unlockWrite();
    try registeredStageFixture(&world, .active);
    try std.testing.expectError(error.InvalidChannel, world.prepareRegisteredChannel("#Bad Name", true));
    world.next_oid = std.math.maxInt(u32);
    const before = try RegisteredStageTestCut.capture(&world);
    defer before.deinit();
    try std.testing.expectError(error.ObjectIdExhausted, world.prepareRegisteredChannel("#New", true));
    try before.expectUnchanged(&world);
    world.next_oid = 0;
    try std.testing.expectError(error.ObjectIdExhausted, world.prepareRegisteredChannel("#New", true));
    world.next_oid = 2;
    const c = world.rcu_channels.?;
    try c.names.set(c.writer_participant, "#Keeper", 999);
    const divergent = try RegisteredStageTestCut.capture(&world);
    defer divergent.deinit();
    try std.testing.expectError(error.InvalidGraph, world.prepareRegisteredChannel("#KEEPER", true));
    try divergent.expectUnchanged(&world);
    try c.names.set(c.writer_participant, "#Keeper", world.channels.getPtr("#Keeper").?.oid);
    world.next_oid = std.math.maxInt(u32) - 1;
    const last = try world.prepareRegisteredChannel("#Last", true);
    defer last.abort();
    last.commit();
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32) - 1), world.channelOid("#Last"));
    try std.testing.expectEqual(std.math.maxInt(u32), world.next_oid);
    try std.testing.expectError(error.ObjectIdExhausted, world.prepareRegisteredChannel("#NeverWrap", true));
    const existing = try world.prepareRegisteredChannel("#Keeper", true);
    defer existing.abort();
    existing.commit();
    try std.testing.expect(world.channelHasExtFlag("#Keeper", .registered));
}

test "World registered channel stage owns caller name and stale opaque alias cannot bind a successor" {
    comptime {
        if (@typeInfo(World.PreparedRegisteredChannel) != .@"opaque") @compileError("channel payload must be opaque");
        const Registry = @typeInfo(@TypeOf(@as(World, undefined).registered_stages)).optional.child;
        if (@typeInfo(@typeInfo(Registry).pointer.child) != .@"opaque") @compileError("registry payload must be opaque");
        if (@hasDecl(World.PreparedRegisteredChannel, "backing") or @hasDecl(World.PreparedRegisteredChannel, "identity"))
            @compileError("no public source payload or numeric authority getter");
    }
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    var input = [_]u8{ '#', 'N', 'e', 'w' };
    const prepared = try world.prepareRegisteredChannel(&input, true);
    defer prepared.abort();
    const stale = prepared;
    input[1] = 'X';
    prepared.commit();
    try std.testing.expect(world.channelExists("#New") and !world.channelExists("#Xew"));
    const successor = try world.prepareRegisteredChannel("#Next", true);
    defer successor.abort();
    try std.testing.expectError(error.ConsumedChannelStage, stale.requireReady());
    successor.commit();
    try std.testing.expect(world.channelExists("#Next"));
}

test "World registered channel stage real child cannot validate creator custody and caller joins before abort" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    world.lockWrite();
    defer world.unlockWrite();
    const prepared = try world.prepareRegisteredChannel("#Private", true);
    defer prepared.abort();
    const before = try RegisteredStageTestCut.capture(&world);
    defer before.deinit();
    const Child = struct {
        fn run(plan: *const World.PreparedRegisteredChannel, result: *std.atomic.Value(u8), returned: *std.Io.Event) void {
            defer returned.set(std.testing.io);
            plan.requireReady() catch |err| {
                result.store(if (err == error.ChannelStageWrongCaller) 1 else 2, .release);
                return;
            };
            result.store(3, .release);
        }
    };
    var result = std.atomic.Value(u8).init(0);
    var returned: std.Io.Event = .unset;
    const child = try std.Thread.spawn(.{}, Child.run, .{ prepared, &result, &returned });
    const returned_deadline: std.Io.Clock.Timestamp = .{
        .clock = .awake,
        .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(5000)),
    };
    // Never unwind borrowed World/plan/context or blindly join a child whose
    // callback has not proven return. Timeout terminates this failing process.
    returned.waitTimeout(std.testing.io, .{ .deadline = returned_deadline }) catch
        @panic("registered channel child did not return before deadline; borrowed source retained");
    // The event proves callback completion; the actual join releases caller
    // stack/thread custody before any borrowed source can be freed.
    child.join();
    try std.testing.expectEqual(@as(u8, 1), result.load(.acquire));
    try before.expectUnchanged(&world);
    try prepared.requireReady();
    prepared.abort();
    try before.expectUnchanged(&world);
}

test "World registered channel opaque stage same acquisition rename delete and map growth conflict abort preserves surviving graph" {
    const Mutation = enum { rename, delete, growth };
    for (std.enums.values(Mutation)) |mutation| {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        world.lockWrite();
        defer world.unlockWrite();
        try registeredStageFixture(&world, .active);
        const plan = try world.prepareRegisteredChannel("#kEEPER", true);
        defer plan.abort();
        try plan.requireReady();
        switch (mutation) {
            .rename => try std.testing.expect(try world.renameChannel("#Keeper", "#Moved")),
            .delete => world.removeChannel("#Keeper"),
            .growth => {
                // The same original lock acquisition does not keep a map entry
                // address stable. Exercise real map relocation without a mock.
                const capacity = world.channels.capacity();
                try world.channels.ensureTotalCapacity(capacity + 100);
                try std.testing.expect(world.channels.capacity() != capacity);
            },
        }
        const after_mutation = try RegisteredStageTestCut.capture(&world);
        defer after_mutation.deinit();
        try std.testing.expectError(error.ChannelStageConflict, plan.requireReady());
        plan.abort();
        try after_mutation.expectUnchanged(&world);
        try world.requireNoActiveRegisteredChannelStage();
        try std.testing.expectError(error.ConsumedChannelStage, plan.requireReady());
        const target = if (mutation == .rename) "#Moved" else "#Keeper";
        const retry = try world.prepareRegisteredChannel(target, true);
        defer retry.abort();
        try retry.requireReady();
        retry.commit();
        try std.testing.expect(world.channelHasExtFlag(target, .registered));
        if (mutation != .delete) {
            try std.testing.expect(world.isMember(target, compound_source) and world.isMember(target, compound_foreign));
            try std.testing.expectEqualStrings("original topic", world.channels.getPtr(target).?.topic.?);
        }
    }
}

test "World registered channel opaque aliases retire only original unpublished resources and finite budget refuses before allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var world = World.init(failing.allocator());
    defer {
        failing.fail_index = std.math.maxInt(usize);
        world.deinit();
    }
    world.lockWrite();
    defer world.unlockWrite();
    const before = try RegisteredStageTestCut.capture(&world);
    defer before.deinit();
    const original = try world.prepareRegisteredChannel("#Private", true);
    const alias = original;
    try std.testing.expect(original == alias);
    const allocations = failing.allocations;
    failing.fail_index = failing.alloc_index;
    alias.abort();
    original.abort();
    try std.testing.expectEqual(allocations, failing.allocations);
    try before.expectUnchanged(&world);
    failing.fail_index = std.math.maxInt(usize);
    var remaining: usize = World.max_registered_channel_tokens - 1;
    while (remaining != 0) : (remaining -= 1) {
        const next = try world.prepareRegisteredChannel("#Absent", false);
        try std.testing.expect(next != original);
        try std.testing.expectError(error.ConsumedChannelStage, alias.requireReady());
        next.abort();
    }
    try before.expectUnchanged(&world);
    const before_budget = failing.allocations;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.ChannelStageCapacity, world.prepareRegisteredChannel("#Beyond", true));
    try std.testing.expectEqual(before_budget, failing.allocations);
    try before.expectUnchanged(&world);
    try world.requireNoActiveRegisteredChannelStage();
    try std.testing.expectError(error.ConsumedChannelStage, original.requireReady());
    // A separate real World has a separate fresh budget. No old token may be
    // used after its original World's actual quiescent destruction.
    var fresh = World.init(std.testing.allocator);
    defer fresh.deinit();
    fresh.lockWrite();
    defer fresh.unlockWrite();
    const first = try fresh.prepareRegisteredChannel("#Fresh", false);
    first.abort();
}

fn compoundNoKeeperAfter(world: *World) !void {
    try std.testing.expect(world.nickOf(compound_source) == null);
    try std.testing.expect(world.findNick("Ghost") == null);
    try std.testing.expectEqual(@as(?ClientId, compound_third), world.findNick("Third"));
    try std.testing.expectEqual(MemberModes.fromModes(&.{.voice}).bits, world.memberModes("#Shared", compound_keeper).?.bits);
    try std.testing.expectEqual(MemberModes.fromModes(&.{.owner}).bits, world.memberModes("#Shared", compound_foreign).?.bits);
    for ([_][]const u8{ "#SourceOnly", "#RcuGap", "#FallbackGap", "#Empty" }) |name| try std.testing.expect(!world.channelExists(name));
    try std.testing.expect(world.isMember("#ThirdOnly", compound_third));
    try std.testing.expect(!world.isMember("#ThirdOnly", compound_keeper));
    try std.testing.expect(!world.channels.getPtr("#ForeignOnly").?.invites.contains(compound_source));
    try std.testing.expect(world.channels.getPtr("#ForeignOnly").?.invites.contains(compound_keeper));
    try std.testing.expect(world.channelExists("#RegisteredEmpty"));
    try std.testing.expect(!world.channels.getPtr("#RegisteredEmpty").?.invites.contains(compound_source));
    try std.testing.expect(world.channelExists("#RcuOnly"));
    try std.testing.expect(!world.channels.contains("#RcuOnly"));
    try std.testing.expect(!world.isMember("#RcuOnly", compound_source));
}

test "World compound departure no keeper divergent graph exhaustive OOM restores exact logical image" {
    var index: usize = 0;
    while (index < 10000) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var world = World.init(failing.allocator());
        defer {
            failing.fail_index = std.math.maxInt(usize);
            world.deinit();
        }
        try compoundFixture(&world, true);
        const old_digest = compoundFallbackDigest(&world);
        const old_nicks = world.rcu_nicks.?.nicks.published.load(.acquire);
        const old_names = world.rcu_channels.?.names.published.load(.acquire);
        const spec = World.PhysicalDepartureSpec{ .source = compound_source, .keeper = null, .exact_clients = &.{compound_source} };
        failing.fail_index = failing.alloc_index + index;
        var prepared = world.preparePhysicalDeparture(spec) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqual(old_digest, compoundFallbackDigest(&world));
            try std.testing.expectEqual(old_nicks, world.rcu_nicks.?.nicks.published.load(.acquire));
            try std.testing.expectEqual(old_names, world.rcu_channels.?.names.published.load(.acquire));
            try compoundBefore(&world, true);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try world.preparePhysicalDeparture(spec);
            defer retry.abort();
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            retry.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try compoundNoKeeperAfter(&world);
            continue;
        };
        failing.fail_index = failing.alloc_index;
        prepared.abort();
        prepared.abort();
        try std.testing.expectEqual(old_digest, compoundFallbackDigest(&world));
        try std.testing.expect(!failing.has_induced_failure);
        failing.fail_index = std.math.maxInt(usize);
        var success = try world.preparePhysicalDeparture(spec);
        defer success.abort();
        failing.fail_index = failing.alloc_index;
        const allocations = failing.allocations;
        success.commit();
        try std.testing.expectEqual(allocations, failing.allocations);
        try compoundNoKeeperAfter(&world);
        try std.testing.expect(index > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "World compound departure rejects missing contributor keeper and invalid no keeper shapes" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try compoundFixture(&world, false);
    const digest = compoundFallbackDigest(&world);
    var spec = compoundSpec(0);
    spec.exact_clients = &.{ compound_keeper, compound_third };
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.exact_clients = &.{ compound_source, compound_third };
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec = compoundSpec(0);
    spec.keeper = null;
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec.exact_clients = &.{compound_source};
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    spec.nick = null;
    spec.expected_union = &.{.{ .channel = "#Shared", .modes = MemberModes.empty() }};
    try std.testing.expectError(error.InvalidOwnerSet, world.preparePhysicalDeparture(spec));
    try std.testing.expectEqual(digest, compoundFallbackDigest(&world));
    try compoundBefore(&world, false);
}

test "World compound departure RCU only contributor cannot claim unknown privilege in expected union" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try world.restoreMember("#KnownMetadata", compound_source, MemberModes.fromModes(&.{.op}));
    _ = world.channels.getPtr("#KnownMetadata").?.members.remove(compound_source);
    const before = compoundFallbackDigest(&world);
    var spec = World.PhysicalDepartureSpec{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper }, .expected_union = &.{.{ .channel = "#KnownMetadata", .modes = MemberModes.fromModes(&.{.op}) }} };
    try std.testing.expectError(error.InvalidUnion, world.preparePhysicalDeparture(spec));
    try std.testing.expectEqual(before, compoundFallbackDigest(&world));
    spec.expected_union = &.{.{ .channel = "#KNOWNMETADATA", .modes = MemberModes.empty() }};
    var prepared = try world.preparePhysicalDeparture(spec);
    defer prepared.abort();
    prepared.commit();
    try std.testing.expectEqual(@as(u8, 0), world.memberModes("#KnownMetadata", compound_keeper).?.bits);
    try std.testing.expect(!world.isMember("#KnownMetadata", compound_source));
}

test "World compound departure secondary attachment removes its RCU aliases and leaves sole keeper nickname reachable" {
    var world = World.init(std.testing.allocator);
    defer world.deinit();
    try world.registerNick("Shared", compound_keeper);
    const n = world.rcu_nicks.?;
    try n.nicks.set(n.writer_participant, "Ghost", @bitCast(compound_source));
    try world.restoreMember("#Secondary", compound_source, MemberModes.fromModes(&.{.voice}));
    var prepared = try world.preparePhysicalDeparture(.{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper }, .nick = .{ .target = "Shared", .disposition = .{ .claim_exact = compound_keeper } } });
    defer prepared.abort();
    try std.testing.expectEqual(@as(?ClientId, compound_keeper), world.findNick("Shared"));
    try std.testing.expectEqual(@as(?ClientId, compound_source), world.findNick("Ghost"));
    prepared.commit();
    try std.testing.expectEqual(@as(?ClientId, compound_keeper), world.findNick("Shared"));
    try std.testing.expect(world.findNick("Ghost") == null);
    try std.testing.expect(world.isMember("#Secondary", compound_keeper));
    try std.testing.expect(!world.isMember("#Secondary", compound_source));
}

test "World compound missing name candidates reject duplicate fallback OID including unaffected foreign owner" {
    for ([_]bool{ false, true }) |foreign| {
        var world = World.init(std.testing.allocator);
        defer world.deinit();
        try world.restoreMember("#First", compound_source, MemberModes.fromModes(&.{.op}));
        try world.restoreMember("#Second", if (foreign) compound_foreign else compound_source, MemberModes.fromModes(&.{.voice}));
        const c = world.rcu_channels.?;
        world.channels.getPtr("#Second").?.oid = world.channels.getPtr("#First").?.oid;
        try c.names.remove(c.writer_participant, "#First");
        try c.names.remove(c.writer_participant, "#Second");
        const digest = compoundFallbackDigest(&world);
        const names = c.names.published.load(.acquire);
        const Attempt = struct {
            fn prepare(target: *World) !void {
                var ticket = try target.preparePhysicalDeparture(.{ .source = compound_source, .keeper = compound_keeper, .exact_clients = &.{ compound_source, compound_keeper } });
                defer ticket.abort();
            }
        };
        try std.testing.expectError(error.InvalidGraph, Attempt.prepare(&world));
        try std.testing.expectEqual(digest, compoundFallbackDigest(&world));
        try std.testing.expectEqual(names, c.names.published.load(.acquire));
    }
}
