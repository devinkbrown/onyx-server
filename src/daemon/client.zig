// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client, channel, and membership data model.
//!
//! Hot-path identities use inline fixed-capacity buffers. These fields own
//! their bytes and do not borrow caller slices. Channel member maps and mask
//! lists allocate through the allocator passed to `Channel.init`, and must be
//! released with `Channel.deinit`.
const std = @import("std");

pub const ModelError = std.mem.Allocator.Error || error{
    OutOfSlots,
    TextTooLong,
};

pub const MAX_NICK_BYTES: usize = 64;
pub const MAX_UID_BYTES: usize = 16;
pub const MAX_ACCOUNT_BYTES: usize = 64;
pub const MAX_REALNAME_BYTES: usize = 256;
pub const MAX_HOST_BYTES: usize = 255;
pub const MAX_CHANNEL_NAME_BYTES: usize = 128;
pub const MAX_TOPIC_BYTES: usize = 512;
pub const MAX_MASK_BYTES: usize = 256;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_OPER_CLASS_BYTES: usize = 64;

const invalid_shard = std.math.maxInt(u12);
const invalid_slot = std.math.maxInt(u20);
const invalid_gen = std.math.maxInt(u32);

/// Opaque generational handle for a client slab entry.
pub const ClientId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: ClientId = .{
        .shard = invalid_shard,
        .slot = invalid_slot,
        .gen = invalid_gen,
    };
    pub const none = invalid;

    pub fn eql(self: ClientId, other: ClientId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }

    pub fn isNone(self: ClientId) bool {
        return self.eql(invalid);
    }
};

/// Opaque generational handle for a channel slab entry.
pub const ChannelId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: ChannelId = .{
        .shard = invalid_shard,
        .slot = invalid_slot,
        .gen = invalid_gen,
    };
    pub const none = invalid;

    pub fn eql(self: ChannelId, other: ChannelId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }

    pub fn isNone(self: ChannelId) bool {
        return self.eql(invalid);
    }
};

/// Opaque generational handle for a client/channel membership entry.
pub const MembershipId = packed struct {
    shard: u12,
    slot: u20,
    gen: u32,

    pub const invalid: MembershipId = .{
        .shard = invalid_shard,
        .slot = invalid_slot,
        .gen = invalid_gen,
    };
    pub const none = invalid;

    pub fn eql(self: MembershipId, other: MembershipId) bool {
        return self.shard == other.shard and
            self.slot == other.slot and
            self.gen == other.gen;
    }

    pub fn isNone(self: MembershipId) bool {
        return self.eql(invalid);
    }
};

/// Inline, owned byte string with a fixed maximum size.
pub fn FixedString(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        bytes: [capacity]u8 = @splat(0),
        len: usize = 0,

        pub fn empty() Self {
            return .{};
        }

        pub fn init(value: []const u8) ModelError!Self {
            var self = Self.empty();
            try self.set(value);
            return self;
        }

        pub fn set(self: *Self, value: []const u8) ModelError!void {
            if (value.len > capacity) return error.TextTooLong;
            @memcpy(self.bytes[0..value.len], value);
            self.len = value.len;
        }

        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn eql(self: *const Self, value: []const u8) bool {
            return std.mem.eql(u8, self.slice(), value);
        }
    };
}

pub const NickName = FixedString(MAX_NICK_BYTES);
pub const UserId = FixedString(MAX_UID_BYTES);
pub const AccountName = FixedString(MAX_ACCOUNT_BYTES);
pub const RealName = FixedString(MAX_REALNAME_BYTES);
pub const HostName = FixedString(MAX_HOST_BYTES);
pub const ChannelName = FixedString(MAX_CHANNEL_NAME_BYTES);
pub const TopicText = FixedString(MAX_TOPIC_BYTES);
pub const MaskText = FixedString(MAX_MASK_BYTES);
pub const LabelText = FixedString(MAX_LABEL_BYTES);
pub const OperClassName = FixedString(MAX_OPER_CLASS_BYTES);

/// Stable identity state. All string fields are owned inline buffers.
pub const Identity = struct {
    nick: NickName = .empty(),
    uid: UserId = .empty(),
    account: ?AccountName = null,
    realname: RealName = .empty(),
    visible_host: HostName = .empty(),
    cloaked_host: HostName = .empty(),

    pub fn init(args: IdentityInit) ModelError!Identity {
        return .{
            .nick = try NickName.init(args.nick),
            .uid = try UserId.init(args.uid),
            .account = if (args.account) |account| try AccountName.init(account) else null,
            .realname = try RealName.init(args.realname),
            .visible_host = try HostName.init(args.visible_host),
            .cloaked_host = try HostName.init(args.cloaked_host),
        };
    }
};

pub const IdentityInit = struct {
    nick: []const u8 = "",
    uid: []const u8 = "",
    account: ?[]const u8 = null,
    realname: []const u8 = "",
    visible_host: []const u8 = "",
    cloaked_host: []const u8 = "",
};

pub const Transport = enum {
    unknown,
    tcp,
    tls,
    websocket,
    undertow,
};

pub const AddressFamily = enum {
    none,
    ipv4,
    ipv6,
    unix,
};

pub const SocketAddress = struct {
    family: AddressFamily = .none,
    bytes: [16]u8 = @splat(0),
    port: u16 = 0,
};

pub const TlsState = enum {
    none,
    handshaking,
    active,
    closing,
};

pub const WebSocketState = enum {
    none,
    opening,
    active,
    closing,
};

/// Transport state. Queues are represented by watermarks until Ringlane lands.
pub const Connection = struct {
    transport: Transport = .unknown,
    fd: ?i32 = null,
    local_addr: SocketAddress = .{},
    peer_addr: SocketAddress = .{},
    tls: TlsState = .none,
    websocket: WebSocketState = .none,
    send_queue_bytes: usize = 0,
    recv_queue_bytes: usize = 0,
    connected_at_ms: i64 = 0,
    last_activity_ms: i64 = 0,
};

pub const PreregState = enum {
    fresh,
    pass_seen,
    nick_seen,
    user_seen,
    registered,
    closing,
};

pub const CapState = enum {
    idle,
    negotiating,
    complete,
};

pub const SaslState = enum {
    idle,
    authenticating,
    complete,
    failed,
};

pub const Registration = struct {
    prereg: PreregState = .fresh,
    cap: CapState = .idle,
    sasl: SaslState = .idle,
    cap_requested_bits: u128 = 0,
    cap_ack_bits: u128 = 0,
    registration_time_ms: i64 = 0,
};

pub const Permissions = struct {
    oper_class: ?OperClassName = null,
    services_access_bits: u128 = 0,
    ircx_flags: u128 = 0,
    // Oper broadcast reach is no longer a boolean perm: WALLOPS/GLOBOPS are
    // BANNED (clean-room mandate). Opers receive notifications by subscribing
    // to Event Spine categories (see daemon/event_spine.zig).
};

pub const Rate = struct {
    flood_tokens: u32 = 0,
    spam_score: u32 = 0,
    command_tokens: u32 = 0,
    last_refill_ms: i64 = 0,
    penalty_ms: i64 = 0,
};

pub const Protocol = struct {
    negotiated_caps: u128 = 0,
    active_label: ?LabelText = null,
    batch_depth: u16 = 0,
    multiline_bytes: usize = 0,
    echo_message: bool = false,
    labeled_response: bool = false,
};

pub const Client = struct {
    identity: Identity = .{},
    connection: Connection = .{},
    registration: Registration = .{},
    permissions: Permissions = .{},
    rate: Rate = .{},
    protocol: Protocol = .{},

    pub fn init(identity: IdentityInit) ModelError!Client {
        return .{ .identity = try Identity.init(identity) };
    }
};

pub const ChannelModes = struct {
    bits: u128 = 0,

    pub fn set(self: *ChannelModes, bit: u7) void {
        self.bits |= (@as(u128, 1) << bit);
    }

    pub fn unset(self: *ChannelModes, bit: u7) void {
        self.bits &= ~(@as(u128, 1) << bit);
    }

    pub fn has(self: ChannelModes, bit: u7) bool {
        return (self.bits & (@as(u128, 1) << bit)) != 0;
    }
};

// Wire channel-member status, highest first: founder (+Q !, Onyx Server) > owner
// (+q ., IRCX) > op (+o @) > voice (+v +). No halfop tier (IRCX `+h` is
// the HIDDEN channel mode). PREFIX=(Qqov)!.@+.
pub const MemberPrefix = packed struct {
    voice: bool = false,
    op: bool = false,
    owner: bool = false,
    founder: bool = false,
    reserved: u4 = 0,

    pub const none: MemberPrefix = .{};

    pub fn rank(self: MemberPrefix) u8 {
        if (self.founder) return 5;
        if (self.owner) return 4;
        if (self.op) return 3;
        if (self.voice) return 1;
        return 0;
    }
};

pub const ChannelMember = struct {
    membership: MembershipId = MembershipId.none,
    prefix: MemberPrefix = .none,
    joined_at_ms: i64 = 0,
};

pub const MaskEntry = struct {
    mask: MaskText = .empty(),
    set_by: ClientId = ClientId.none,
    set_at_ms: i64 = 0,

    pub fn init(mask: []const u8, set_by: ClientId, set_at_ms: i64) ModelError!MaskEntry {
        return .{
            .mask = try MaskText.init(mask),
            .set_by = set_by,
            .set_at_ms = set_at_ms,
        };
    }
};

pub const HistoryCursor = struct {
    last_seq: u64 = 0,
};

/// Channel state. Member maps and mask arrays own allocator-backed storage.
pub const Channel = struct {
    allocator: std.mem.Allocator,
    name: ChannelName,
    topic: TopicText = .empty(),
    modes: ChannelModes = .{},
    members: std.AutoHashMap(ClientId, ChannelMember),
    bans: std.ArrayList(MaskEntry) = .empty,
    exceptions: std.ArrayList(MaskEntry) = .empty,
    invite_exceptions: std.ArrayList(MaskEntry) = .empty,
    history: HistoryCursor = .{},

    pub fn init(allocator: std.mem.Allocator, name: []const u8) ModelError!Channel {
        return .{
            .allocator = allocator,
            .name = try ChannelName.init(name),
            .members = std.AutoHashMap(ClientId, ChannelMember).init(allocator),
        };
    }

    pub fn deinit(self: *Channel) void {
        self.members.deinit();
        self.bans.deinit(self.allocator);
        self.exceptions.deinit(self.allocator);
        self.invite_exceptions.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn setTopic(self: *Channel, topic: []const u8) ModelError!void {
        try self.topic.set(topic);
    }

    pub fn addMember(
        self: *Channel,
        client: ClientId,
        membership: MembershipId,
        prefix: MemberPrefix,
        joined_at_ms: i64,
    ) ModelError!void {
        try self.members.put(client, .{
            .membership = membership,
            .prefix = prefix,
            .joined_at_ms = joined_at_ms,
        });
    }

    pub fn member(self: *Channel, client: ClientId) ?*ChannelMember {
        return self.members.getPtr(client);
    }

    pub fn removeMember(self: *Channel, client: ClientId) bool {
        return self.members.remove(client);
    }

    pub fn addBan(self: *Channel, mask: []const u8, set_by: ClientId, set_at_ms: i64) ModelError!void {
        try self.bans.append(self.allocator, try MaskEntry.init(mask, set_by, set_at_ms));
    }

    pub fn addException(self: *Channel, mask: []const u8, set_by: ClientId, set_at_ms: i64) ModelError!void {
        try self.exceptions.append(self.allocator, try MaskEntry.init(mask, set_by, set_at_ms));
    }

    pub fn addInviteException(self: *Channel, mask: []const u8, set_by: ClientId, set_at_ms: i64) ModelError!void {
        try self.invite_exceptions.append(self.allocator, try MaskEntry.init(mask, set_by, set_at_ms));
    }
};

/// Generational slab table.
///
/// `free` invalidates outstanding ids by bumping the slot generation before
/// returning the slot to the freelist. The table does not call `deinit` on
/// stored values; callers must release any value-owned resources before freeing
/// a slot or deinitializing the table.
pub fn Table(comptime T: type, comptime Id: type) type {
    return struct {
        const Self = @This();
        pub const Slot = struct {
            value: T = undefined,
            gen: u32 = 1,
            occupied: bool = false,
            next_free: ?u20 = null,
        };

        allocator: std.mem.Allocator,
        shard: u12,
        slots: std.ArrayList(Slot) = .empty,
        free_head: ?u20 = null,
        live_count: usize = 0,

        pub fn init(allocator: std.mem.Allocator, shard: u12) Self {
            return .{
                .allocator = allocator,
                .shard = shard,
            };
        }

        pub fn deinit(self: *Self) void {
            self.slots.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn alloc(self: *Self, value: T) ModelError!Id {
            const slot_index = if (self.free_head) |head| blk: {
                var slot = &self.slots.items[head];
                self.free_head = slot.next_free;
                slot.next_free = null;
                break :blk head;
            } else blk: {
                if (self.slots.items.len >= invalid_slot) return error.OutOfSlots;
                const next: u20 = @intCast(self.slots.items.len);
                try self.slots.append(self.allocator, .{});
                break :blk next;
            };

            var slot = &self.slots.items[slot_index];
            slot.value = value;
            slot.occupied = true;
            self.live_count += 1;

            return .{
                .shard = self.shard,
                .slot = slot_index,
                .gen = slot.gen,
            };
        }

        pub fn free(self: *Self, id: Id) bool {
            const slot = self.validSlot(id) orelse return false;

            slot.occupied = false;
            slot.gen +%= 1;
            slot.next_free = self.free_head;
            self.free_head = id.slot;
            self.live_count -= 1;
            return true;
        }

        pub fn get(self: *Self, id: Id) ?*T {
            const slot = self.validSlot(id) orelse return null;
            return &slot.value;
        }

        pub fn len(self: *const Self) usize {
            return self.live_count;
        }

        /// Pre-reserve slot capacity so the backing array never reallocates while
        /// in use. Critical when `T` holds buffers referenced by in-flight async
        /// I/O (e.g. io_uring recv/send into a ConnState): a realloc would move
        /// those buffers and the kernel would write into freed memory. Callers
        /// that reserve must also cap live entries at `n`.
        pub fn reserve(self: *Self, n: usize) ModelError!void {
            try self.slots.ensureTotalCapacity(self.allocator, n);
        }

        /// Iterates live entries, yielding `{ id, value }`. Stable across reads
        /// (no mutation during iteration). Used by fan-out commands (WALLOPS,
        /// away-notify, oper notices) that must reach every connected client.
        pub const Entry = struct { id: Id, value: *T };

        pub const Iterator = struct {
            table: *Self,
            cursor: usize = 0,

            pub fn next(self: *Iterator) ?Entry {
                while (self.cursor < self.table.slots.items.len) {
                    const idx = self.cursor;
                    self.cursor += 1;
                    const slot = &self.table.slots.items[idx];
                    if (!slot.occupied) continue;
                    return .{
                        .id = .{ .shard = self.table.shard, .slot = @intCast(idx), .gen = slot.gen },
                        .value = &slot.value,
                    };
                }
                return null;
            }
        };

        pub fn iterator(self: *Self) Iterator {
            return .{ .table = self };
        }

        fn validSlot(self: *Self, id: Id) ?*Slot {
            if (id.eql(Id.invalid)) return null;
            if (id.shard != self.shard) return null;
            if (@as(usize, id.slot) >= self.slots.items.len) return null;

            const slot = &self.slots.items[id.slot];
            if (!slot.occupied) return null;
            if (slot.gen != id.gen) return null;
            return slot;
        }
    };
}

test "generational id reuse rejects stale handles" {
    var table = Table(Client, ClientId).init(std.testing.allocator, 7);
    defer table.deinit();

    const first = try table.alloc(try Client.init(.{ .nick = "old" }));
    try std.testing.expect(table.get(first) != null);
    try std.testing.expect(table.free(first));

    const second = try table.alloc(try Client.init(.{ .nick = "new" }));
    try std.testing.expectEqual(first.slot, second.slot);
    try std.testing.expect(first.gen != second.gen);
    try std.testing.expectEqual(@as(?*Client, null), table.get(first));
    try std.testing.expect(table.get(second) != null);
}

test "basic client and channel create lookup free" {
    var clients = Table(Client, ClientId).init(std.testing.allocator, 1);
    defer clients.deinit();

    var channels = Table(Channel, ChannelId).init(std.testing.allocator, 1);
    defer channels.deinit();

    var memberships = Table(ChannelMember, MembershipId).init(std.testing.allocator, 1);
    defer memberships.deinit();

    const client_id = try clients.alloc(try Client.init(.{
        .nick = "kain",
        .uid = "AAAAAA",
        .account = "kain",
        .realname = "Kain",
        .visible_host = "user.example",
        .cloaked_host = "cloak.example",
    }));
    const membership_id = try memberships.alloc(.{});
    const channel_id = try channels.alloc(try Channel.init(std.testing.allocator, "#onyx"));

    const client = clients.get(client_id).?;
    try std.testing.expect(client.identity.nick.eql("kain"));
    try std.testing.expect(client.identity.account.?.eql("kain"));

    const channel = channels.get(channel_id).?;
    try channel.setTopic("client/channel model");
    try channel.addMember(client_id, membership_id, .{ .op = true }, 42);
    try channel.addBan("*!*@bad.example", client_id, 43);

    try std.testing.expect(channel.name.eql("#onyx"));
    try std.testing.expect(channel.topic.eql("client/channel model"));
    try std.testing.expectEqual(@as(usize, 1), channel.members.count());
    try std.testing.expectEqual(@as(usize, 1), channel.bans.items.len);
    try std.testing.expectEqual(@as(u8, 3), channel.member(client_id).?.prefix.rank());

    channel.deinit();
    try std.testing.expect(channels.free(channel_id));
    try std.testing.expect(memberships.free(membership_id));
    try std.testing.expect(clients.free(client_id));

    try std.testing.expectEqual(@as(?*Channel, null), channels.get(channel_id));
    try std.testing.expectEqual(@as(?*ChannelMember, null), memberships.get(membership_id));
    try std.testing.expectEqual(@as(?*Client, null), clients.get(client_id));
}

test "fixed strings reject oversize values" {
    var nick = NickName.empty();
    try nick.set("valid");
    try std.testing.expect(nick.eql("valid"));

    const too_long = &@as([(MAX_NICK_BYTES + 1)]u8, @splat('x'));
    try std.testing.expectError(error.TextTooLong, nick.set(too_long));
    try std.testing.expect(nick.eql("valid"));
}
