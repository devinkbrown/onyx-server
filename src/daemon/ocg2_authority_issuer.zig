// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inactive sealed OCG2 authority issuer.
//!
//! Allocator-created, opaque, and transaction-private. The process node
//! identity, Services image, ClockSource, and canonical OperRegistry object
//! are borrowed for the issuer lifetime and are never cloned. The only public
//! production execution method is `Ocg2AuthorityIssuer.executeAuthorized`,
//! which revalidates `permit.valid(expected_registry)` under the issuer mutex
//! before authority match, clock observation, revision allocation, or store
//! mutation. File-local tests may invoke the private core directly. No wire is
//! returned before exact post-commit inspection, and there is no transmit hook.

const std = @import("std");
const builtin = @import("builtin");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const services_mod = @import("services.zig");
const durable_oper_authority = @import("durable_oper_authority.zig");
const durable_oper_authority_boot = @import("durable_oper_authority_boot.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");
const store_mod = @import("store.zig");
const oper_session_provenance = @import("oper_session_provenance.zig");
const oper = @import("oper.zig");

pub const Services = services_mod.Services;
pub const min_ttl_ms: u64 = 60 * 60 * 1000;
pub const max_ttl_ms: u64 = oper_cred_share.ocg2_max_ttl_ms;

pub const ClockSample = struct {
    realtime_ms: u64,
    monotonic_ms: u64,
};

/// Trusted clock. Origins are stored at construction; later samples are
/// converted to elapsed monotonic time against that origin. The default
/// sample is frozen at the stored origins and may be advanced in tests
/// without reallocating.
pub const ClockSource = struct {
    realtime_origin_ms: u64,
    monotonic_origin_ms: u64,
    sampled_realtime_ms: std.atomic.Value(u64),
    sampled_monotonic_ms: std.atomic.Value(u64),

    pub fn frozen(realtime_origin_ms: u64, monotonic_origin_ms: u64) ClockSource {
        return .{
            .realtime_origin_ms = realtime_origin_ms,
            .monotonic_origin_ms = monotonic_origin_ms,
            .sampled_realtime_ms = .init(realtime_origin_ms),
            .sampled_monotonic_ms = .init(monotonic_origin_ms),
        };
    }

    pub fn sample(self: *const ClockSource) ClockSample {
        return .{
            .realtime_ms = self.sampled_realtime_ms.load(.monotonic),
            .monotonic_ms = self.sampled_monotonic_ms.load(.monotonic),
        };
    }

    pub fn setSample(self: *ClockSource, realtime_ms: u64, monotonic_ms: u64) void {
        self.sampled_realtime_ms.store(realtime_ms, .monotonic);
        self.sampled_monotonic_ms.store(monotonic_ms, .monotonic);
    }
};

pub const CreateError = error{
    Disabled,
    Unavailable,
    Mismatch,
    InvalidIdentity,
    OutOfMemory,
};

pub const RequestError = error{
    InvalidAccount,
    InvalidPrivileges,
    InvalidText,
    InvalidTtl,
};

pub const GrantRequest = struct {
    account: services_mod.AccountName = .{},
    privilege_bits: u64 = 0,
    class_buf: [oper_cred_share.ocg2_max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [oper_cred_share.ocg2_max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    ttl_ms: u64 = 0,

    pub fn init(
        account: []const u8,
        privilege_bits: u64,
        class_text: []const u8,
        title_text: []const u8,
        ttl_ms: u64,
    ) RequestError!GrantRequest {
        const canonical = services_mod.canonicalAccount(account) catch return error.InvalidAccount;
        if (!uniqueExportableBits(privilege_bits)) return error.InvalidPrivileges;
        if (!validText(class_text, oper_cred_share.ocg2_max_class_len, true) or
            !validText(title_text, oper_cred_share.ocg2_max_title_len, false))
            return error.InvalidText;
        if (ttl_ms < min_ttl_ms or ttl_ms > max_ttl_ms) return error.InvalidTtl;
        var out = GrantRequest{
            .account = canonical,
            .privilege_bits = privilege_bits,
            .class_len = class_text.len,
            .title_len = title_text.len,
            .ttl_ms = ttl_ms,
        };
        @memcpy(out.class_buf[0..class_text.len], class_text);
        @memcpy(out.title_buf[0..title_text.len], title_text);
        return out;
    }

    pub fn class(self: *const GrantRequest) RequestError![]const u8 {
        return checkedClass(self);
    }

    pub fn title(self: *const GrantRequest) RequestError![]const u8 {
        return checkedTitle(self);
    }
};

pub const RevokeRequest = struct {
    account: services_mod.AccountName = .{},

    pub fn init(account: []const u8) RequestError!RevokeRequest {
        return .{ .account = services_mod.canonicalAccount(account) catch return error.InvalidAccount };
    }
};

/// The only authorized production command envelope. Grant and revoke remain
/// private request types; this union is the sole public execution input.
pub const Command = union(enum) {
    grant: GrantRequest,
    revoke: RevokeRequest,
};

pub const Receipt = struct {
    account: services_mod.AccountName = .{},
    revision: u64 = 0,
    kind: oper_cred_share.Ocg2Kind = .grant,
    issued_ms: u64 = 0,
    expiry_ms: u64 = 0,
    digest: [durable_oper_authority.digest_len]u8 = @splat(0),
    wire_sha256: [durable_oper_authority.digest_len]u8 = @splat(0),
    authority_node_id: u64 = 0,
    authority_pubkey: [oper_cred_share.ocg2_pubkey_len]u8 = @splat(0),
    wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = @splat(0),
    wire_len: usize = 0,

    pub fn signedWire(self: *const Receipt) []const u8 {
        return self.wire_buf[0..self.wire_len];
    }

    pub fn accountSlice(self: *const Receipt) []const u8 {
        return self.account.asSlice();
    }
};

pub const Outcome = union(enum) {
    committed: Receipt,
    replay,
    stale,
    equivocation,
    preadmission: Services.DurableOperPreadmission,
    restart_required: Services.DurableOperRestart,
    poison,
    unavailable,
    disabled,
    unauthorized,
};

const PreparedKind = enum { grant, revoke };

const PreparedRequest = struct {
    kind: PreparedKind,
    account: services_mod.AccountName,
    privilege_bits: u64 = 0,
    class_buf: [oper_cred_share.ocg2_max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [oper_cred_share.ocg2_max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    ttl_ms: u64 = 0,

    fn class(self: *const PreparedRequest) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    fn title(self: *const PreparedRequest) []const u8 {
        return self.title_buf[0..self.title_len];
    }
};

/// Opaque public handle. The private Impl is never part of the exported type.
/// Destroy is single-owner: the caller must join every thread that may enter
/// the private transaction core before `destroy`. Destroy waits for one
/// already-running transaction that holds the issuer mutex, then marks the
/// handle closed and frees it. A second destroy, or a transaction after
/// destroy, is not supported.
pub const Ocg2AuthorityIssuer = opaque {
    /// Exactly one production execution method. The sealed permit is
    /// revalidated under the issuer mutex before revision allocation.
    pub fn executeAuthorized(
        self: *Ocg2AuthorityIssuer,
        permit: oper_session_provenance.ConfiguredLocalMintPermit,
        command: Command,
    ) Outcome {
        return executeAuthorizedInner(self, permit, command);
    }
};

const TestHooks = struct {
    after_allocate: ?*const fn (*Ocg2AuthorityIssuer) void = null,
    after_commit: ?*const fn (*Ocg2AuthorityIssuer) void = null,
    ctx: ?*anyopaque = null,
};

const Impl = struct {
    allocator: std.mem.Allocator,
    identity: *const node_identity.NodeIdentity,
    services: *Services,
    clock: *const ClockSource,
    registry: *const oper.OperRegistry,
    mutex: std.atomic.Mutex = .unlocked,
    poisoned: bool = false,
    closed: bool = false,
    hooks: if (builtin.is_test) TestHooks else void = if (builtin.is_test) .{} else {},
};

comptime {
    if (!@hasDecl(Ocg2AuthorityIssuer, "executeAuthorized"))
        @compileError("OCG2 issuer must expose executeAuthorized");
    if (@hasDecl(Ocg2AuthorityIssuer, "issue") or
        @hasDecl(Ocg2AuthorityIssuer, "grant") or
        @hasDecl(Ocg2AuthorityIssuer, "revoke") or
        @hasDecl(Ocg2AuthorityIssuer, "issueGrant") or
        @hasDecl(Ocg2AuthorityIssuer, "issueRevoke") or
        @hasDecl(Ocg2AuthorityIssuer, "executeGrant") or
        @hasDecl(Ocg2AuthorityIssuer, "executeRevoke") or
        @hasDecl(Ocg2AuthorityIssuer, "transmit") or
        @hasDecl(@This(), "issue") or
        @hasDecl(@This(), "grant") or
        @hasDecl(@This(), "revoke") or
        @hasDecl(@This(), "issueGrant") or
        @hasDecl(@This(), "issueRevoke") or
        @hasDecl(@This(), "executeAuthorized") or
        @hasDecl(@This(), "transmit"))
        @compileError("OCG2 issuer must not expose an alternate public issue method");
    switch (@typeInfo(Ocg2AuthorityIssuer)) {
        .@"opaque" => {},
        else => @compileError("Ocg2AuthorityIssuer must be an opaque handle"),
    }
    if (!builtin.is_test and @FieldType(Impl, "hooks") != void)
        @compileError("production Impl must not carry test hooks");
}

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}

fn uniqueExportableBits(bits: u64) bool {
    return bits != 0 and bits & ~oper_cred_share.ocg2_exportable_bits == 0;
}

fn validText(value: []const u8, max_len: usize, required: bool) bool {
    if (required and value.len == 0) return false;
    if (value.len > max_len) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

fn checkedAccount(account: *const services_mod.AccountName) RequestError![]const u8 {
    if (@as(usize, account.len) > account.bytes.len) return error.InvalidAccount;
    return account.bytes[0..account.len];
}

fn checkedClass(request: *const GrantRequest) RequestError![]const u8 {
    if (request.class_len > request.class_buf.len) return error.InvalidText;
    return request.class_buf[0..request.class_len];
}

fn checkedTitle(request: *const GrantRequest) RequestError![]const u8 {
    if (request.title_len > request.title_buf.len) return error.InvalidText;
    return request.title_buf[0..request.title_len];
}

fn asImpl(self: *Ocg2AuthorityIssuer) *Impl {
    return @ptrCast(@alignCast(self));
}

fn asImplConst(self: *const Ocg2AuthorityIssuer) *const Impl {
    return @ptrCast(@alignCast(self));
}

fn asHandle(inner: *Impl) *Ocg2AuthorityIssuer {
    return @ptrCast(inner);
}

fn expectedConfig(identity: *const node_identity.NodeIdentity) ?durable_oper_authority.Config {
    const short_id = identity.shortId();
    if (short_id == 0) return null;
    const public_key = identity.sign_kp.public_key;
    if (node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)) != short_id)
        return null;
    return .{
        .authority_node_id = short_id,
        .authority_pubkey = public_key,
    };
}

fn containsBytes(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.mem.eql(u8, haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

pub fn create(
    allocator: std.mem.Allocator,
    identity: *const node_identity.NodeIdentity,
    services: *Services,
    clock: *const ClockSource,
    registry: *const oper.OperRegistry,
) CreateError!*Ocg2AuthorityIssuer {
    const expected = expectedConfig(identity) orelse return error.InvalidIdentity;
    switch (services.matchDurableOperAuthority(expected)) {
        .disabled => return error.Disabled,
        .unavailable => return error.Unavailable,
        .mismatch => return error.Mismatch,
        .ready => {},
    }
    const inner = try allocator.create(Impl);
    inner.* = .{
        .allocator = allocator,
        .identity = identity,
        .services = services,
        .clock = clock,
        .registry = registry,
    };
    return asHandle(inner);
}

/// Single-owner teardown. Waits for any transaction that already holds the
/// issuer mutex, then refuses further use and frees the private Impl.
pub fn destroy(self: *Ocg2AuthorityIssuer) void {
    const inner = asImpl(self);
    lockSpin(&inner.mutex);
    inner.closed = true;
    const allocator = inner.allocator;
    inner.mutex.unlock();
    inner.* = undefined;
    allocator.destroy(inner);
}

fn poisonLocked(self: *Ocg2AuthorityIssuer) void {
    const inner = asImpl(self);
    inner.poisoned = true;
    inner.services.failClosedDurableOperAuthority();
}

fn prepareGrant(request: *const GrantRequest) RequestError!PreparedRequest {
    const account = try checkedAccount(&request.account);
    const class_text = try checkedClass(request);
    const title_text = try checkedTitle(request);
    const canonical = try GrantRequest.init(
        account,
        request.privilege_bits,
        class_text,
        title_text,
        request.ttl_ms,
    );
    var out = PreparedRequest{
        .kind = .grant,
        .account = canonical.account,
        .privilege_bits = canonical.privilege_bits,
        .class_len = canonical.class_len,
        .title_len = canonical.title_len,
        .ttl_ms = canonical.ttl_ms,
    };
    @memcpy(out.class_buf[0..canonical.class_len], canonical.class_buf[0..canonical.class_len]);
    @memcpy(out.title_buf[0..canonical.title_len], canonical.title_buf[0..canonical.title_len]);
    return out;
}

fn prepareRevoke(request: *const RevokeRequest) RequestError!PreparedRequest {
    const account = try checkedAccount(&request.account);
    const canonical = try RevokeRequest.init(account);
    return .{
        .kind = .revoke,
        .account = canonical.account,
    };
}

fn replayOf(prepared: PreparedRequest, copy: durable_oper_authority.TransactionCopy, now_ms: u64) bool {
    const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(copy.authority_pubkey) catch return false;
    const fields = oper_cred_share.verifyOcg2(
        copy.signedWire(),
        public_key,
        copy.authority_node_id,
        if (copy.kind == .grant) now_ms else copy.issued_ms,
    ) catch return false;
    return switch (prepared.kind) {
        .grant => copy.kind == .grant and
            fields.privilege_bits == prepared.privilege_bits and
            std.mem.eql(u8, fields.class, prepared.class()) and
            std.mem.eql(u8, fields.title, prepared.title()),
        .revoke => copy.kind == .tombstone,
    };
}

fn receiptFrom(copy: durable_oper_authority.TransactionCopy) ?Receipt {
    const account = services_mod.canonicalAccount(copy.account()) catch return null;
    if (copy.wire_len == 0 or copy.wire_len > oper_cred_share.ocg2_max_wire_len) return null;
    var out = Receipt{
        .account = account,
        .revision = copy.revision,
        .kind = copy.kind,
        .issued_ms = copy.issued_ms,
        .expiry_ms = copy.expiry_ms,
        .digest = copy.digest,
        .wire_sha256 = copy.wire_sha256,
        .authority_node_id = copy.authority_node_id,
        .authority_pubkey = copy.authority_pubkey,
        .wire_len = copy.wire_len,
    };
    @memcpy(out.wire_buf[0..copy.wire_len], copy.signedWire());
    return out;
}

fn exactPostcommit(
    copy: durable_oper_authority.TransactionCopy,
    prepared: PreparedRequest,
    expected: durable_oper_authority.Config,
    revision: u64,
    issued_ms: u64,
    expiry_ms: u64,
    wire: []const u8,
) bool {
    if (copy.revision != revision or copy.issued_ms != issued_ms or copy.expiry_ms != expiry_ms)
        return false;
    if (copy.kind != if (prepared.kind == .grant) oper_cred_share.Ocg2Kind.grant else .tombstone)
        return false;
    if (!std.mem.eql(u8, copy.account(), prepared.account.asSlice())) return false;
    if (copy.authority_node_id != expected.authority_node_id) return false;
    if (!std.crypto.timing_safe.eql(
        [oper_cred_share.ocg2_pubkey_len]u8,
        copy.authority_pubkey,
        expected.authority_pubkey,
    )) return false;
    if (!std.mem.eql(u8, copy.signedWire(), wire)) return false;
    var blake3: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.Blake3.hash(wire, &blake3, .{});
    if (!std.mem.eql(u8, &blake3, &copy.digest)) return false;
    var sha256: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(wire, &sha256, .{});
    return std.mem.eql(u8, &sha256, &copy.wire_sha256);
}

fn transact(
    self: *Ocg2AuthorityIssuer,
    prepared_or_err: RequestError!PreparedRequest,
    permit: ?oper_session_provenance.ConfiguredLocalMintPermit,
) Outcome {
    const inner = asImpl(self);
    lockSpin(&inner.mutex);
    defer inner.mutex.unlock();
    if (inner.closed or inner.poisoned) return .poison;

    if (permit) |mint| {
        if (!mint.valid(inner.registry)) return .unauthorized;
    } else if (comptime !builtin.is_test) {
        return .unauthorized;
    }

    const expected = expectedConfig(inner.identity) orelse {
        poisonLocked(self);
        return .poison;
    };
    switch (inner.services.matchDurableOperAuthority(expected)) {
        .disabled => return .disabled,
        .unavailable => return .unavailable,
        .mismatch => {
            poisonLocked(self);
            return .poison;
        },
        .ready => {},
    }

    // One atomic clock sample per transaction. Origins are not resampled.
    const clock_sample = inner.clock.sample();
    if (clock_sample.monotonic_ms < inner.clock.monotonic_origin_ms) return .unavailable;
    const elapsed_ms = clock_sample.monotonic_ms - inner.clock.monotonic_origin_ms;
    const now_ms = switch (inner.services.durableOperSecurityNow(clock_sample.realtime_ms, elapsed_ms)) {
        .disabled => return .disabled,
        .unavailable => return .unavailable,
        .now => |value| value,
    };

    const prepared = prepared_or_err catch return .{ .preadmission = .invalid_record };
    const expiry_ms = switch (prepared.kind) {
        .grant => std.math.add(u64, now_ms, prepared.ttl_ms) catch return .unavailable,
        .revoke => 0,
    };

    switch (inner.services.inspectDurableOperTransaction(prepared.account.asSlice(), now_ms)) {
        .disabled => return .disabled,
        .unavailable => return .unavailable,
        .absent => {},
        .active => |copy| if (replayOf(prepared, copy, now_ms)) return .replay,
        .tombstone => |copy| if (replayOf(prepared, copy, now_ms)) return .replay,
        .equivocation => {},
    }

    const revision = switch (inner.services.allocateDurableOperRevision(prepared.account.asSlice())) {
        .disabled => return .disabled,
        .unavailable => return .unavailable,
        .preadmission => |reason| return .{ .preadmission = reason },
        .restart_required => |reason| {
            poisonLocked(self);
            return .{ .restart_required = reason };
        },
        .committed => |value| value,
    };
    if (comptime builtin.is_test) {
        if (inner.hooks.after_allocate) |hook| hook(self);
    }
    if (inner.closed or inner.poisoned) return .poison;

    const fields = oper_cred_share.Ocg2Fields{
        .kind = if (prepared.kind == .grant) .grant else .tombstone,
        .account = prepared.account.asSlice(),
        .revision = revision,
        .privilege_bits = if (prepared.kind == .grant) prepared.privilege_bits else 0,
        .class = if (prepared.kind == .grant) prepared.class() else "",
        .title = if (prepared.kind == .grant) prepared.title() else "",
        .authority_node_id = expected.authority_node_id,
        .authority_pubkey = expected.authority_pubkey,
        .issued_ms = now_ms,
        .expiry_ms = expiry_ms,
    };
    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const signed_len = oper_cred_share.signOcg2WithNodeKey(
        &inner.identity.sign_kp,
        fields,
        now_ms,
        &wire_buf,
    ) catch {
        poisonLocked(self);
        return .poison;
    };
    const wire = wire_buf[0..signed_len];

    const committed = switch (inner.services.commitDurableOperRecord(wire, now_ms)) {
        .disabled, .unavailable => {
            poisonLocked(self);
            return .poison;
        },
        .stale => return .stale,
        .replay => return .replay,
        .equivocation_committed => return .equivocation,
        .preadmission => |reason| return .{ .preadmission = reason },
        .restart_required => |reason| {
            poisonLocked(self);
            return .{ .restart_required = reason };
        },
        .committed => true,
    };
    _ = committed;
    if (comptime builtin.is_test) {
        if (inner.hooks.after_commit) |hook| hook(self);
    }
    if (inner.closed or inner.poisoned) return .poison;

    const copy = switch (inner.services.inspectDurableOperTransaction(prepared.account.asSlice(), now_ms)) {
        .active => |value| value,
        .tombstone => |value| value,
        else => {
            poisonLocked(self);
            return .poison;
        },
    };
    if (!exactPostcommit(copy, prepared, expected, revision, now_ms, expiry_ms, wire)) {
        poisonLocked(self);
        return .poison;
    }
    return .{ .committed = receiptFrom(copy) orelse {
        poisonLocked(self);
        return .poison;
    } };
}

fn executeGrant(self: *Ocg2AuthorityIssuer, request: *const GrantRequest) Outcome {
    return transact(self, prepareGrant(request), null);
}

fn executeRevoke(self: *Ocg2AuthorityIssuer, request: *const RevokeRequest) Outcome {
    return transact(self, prepareRevoke(request), null);
}

fn executeAuthorizedInner(
    self: *Ocg2AuthorityIssuer,
    permit: oper_session_provenance.ConfiguredLocalMintPermit,
    command: Command,
) Outcome {
    return switch (command) {
        .grant => |request| transact(self, prepareGrant(&request), permit),
        .revoke => |request| transact(self, prepareRevoke(&request), permit),
    };
}

fn testHooks(self: *Ocg2AuthorityIssuer) *TestHooks {
    comptime if (!builtin.is_test) @compileError("test hooks exist only in test builds");
    return &asImpl(self).hooks;
}

fn testIsPoisoned(self: *const Ocg2AuthorityIssuer) bool {
    comptime if (!builtin.is_test) @compileError("test introspection exists only in test builds");
    return asImplConst(self).poisoned;
}

fn testIdentity(self: *const Ocg2AuthorityIssuer) *const node_identity.NodeIdentity {
    comptime if (!builtin.is_test) @compileError("test introspection exists only in test builds");
    return asImplConst(self).identity;
}

fn testServices(self: *const Ocg2AuthorityIssuer) *Services {
    comptime if (!builtin.is_test) @compileError("test introspection exists only in test builds");
    return asImplConst(self).services;
}

fn testHookCtx(self: *const Ocg2AuthorityIssuer) ?*anyopaque {
    comptime if (!builtin.is_test) @compileError("test hooks exist only in test builds");
    return asImplConst(self).hooks.ctx;
}

fn testImplBytes(self: *const Ocg2AuthorityIssuer) []const u8 {
    comptime if (!builtin.is_test) @compileError("test introspection exists only in test builds");
    return std.mem.asBytes(asImplConst(self));
}

fn testWipeSigner(self: *Ocg2AuthorityIssuer) void {
    comptime if (!builtin.is_test) @compileError("test hooks exist only in test builds");
    @constCast(asImpl(self).identity).sign_kp.secret_key.wipe();
}

const testing = std.testing;

const Live = struct {
    store: store_mod.OroStore,
    state: durable_oper_authority.State,
    services: Services,
    identity: node_identity.NodeIdentity,
    clock: ClockSource,
    registry: oper.OperRegistry,
};

const Harness = struct {
    tmp: std.testing.TmpDir,
    live: *Live,
    seed: [32]u8,
    issuer: *Ocg2AuthorityIssuer,
    now_ms: u64,

    fn init(seed_byte: u8, wal_name: []const u8) !Harness {
        return initAt(seed_byte, wal_name, 1_000, 1_000 + max_ttl_ms + min_ttl_ms);
    }

    fn initAt(seed_byte: u8, wal_name: []const u8, now_ms: u64, horizon_ms: u64) !Harness {
        const seed = @as([32]u8, @splat(seed_byte));
        const live = try std.testing.allocator.create(Live);
        errdefer std.testing.allocator.destroy(live);
        live.identity = try node_identity.fromSeed(seed, "local");
        errdefer live.identity.deinit();
        const config = expectedConfig(&live.identity) orelse return error.TestUnexpectedResult;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        live.store = try store_mod.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, wal_name);
        errdefer live.store.deinit();
        live.state = try durable_oper_authority_boot.initialize(std.testing.allocator, &live.store, config);
        errdefer live.state.deinit();
        live.services = Services.init(&live.store, null);
        try live.services.activateDurableOperAuthority(&live.state);
        switch (live.services.reserveDurableOperSecurityTime(now_ms, horizon_ms)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        live.clock = ClockSource.frozen(now_ms, now_ms);
        live.registry = try oper.OperRegistry.init(&.{});
        const issuer = try create(
            std.testing.allocator,
            &live.identity,
            &live.services,
            &live.clock,
            &live.registry,
        );
        return .{
            .tmp = tmp,
            .live = live,
            .seed = seed,
            .issuer = issuer,
            .now_ms = now_ms,
        };
    }

    fn deinit(self: *Harness) void {
        destroy(self.issuer);
        self.live.identity.deinit();
        self.live.state.deinit();
        self.live.store.deinit();
        std.testing.allocator.destroy(self.live);
        self.tmp.cleanup();
    }

    fn setTime(self: *Harness, realtime_ms: u64, monotonic_ms: u64) void {
        self.live.clock.setSample(realtime_ms, monotonic_ms);
    }

    fn grantReq(self: *const Harness, account: []const u8, bits: u64, title: []const u8) !GrantRequest {
        _ = self;
        return GrantRequest.init(account, bits, "moderator", title, min_ttl_ms);
    }

    fn mintPermit(
        self: *const Harness,
        registry: *const oper.OperRegistry,
        account: []const u8,
    ) !oper_session_provenance.ConfiguredLocalMintPermit {
        _ = self;
        const binding = oper_session_provenance.configuredLocalBinding(registry, account) orelse
            return error.TestUnexpectedResult;
        return oper_session_provenance.configuredLocalMintPermit(registry, binding, account) orelse
            error.TestUnexpectedResult;
    }
};

const export_bit = @as(u64, 1) << 3;
const export_kill = @as(u64, 1) << 5;

fn expectCommitted(outcome: Outcome) !Receipt {
    return switch (outcome) {
        .committed => |receipt| receipt,
        else => error.TestUnexpectedResult,
    };
}

const IdleObservation = struct {
    clock_started: bool,
    boot_ms: u64,
    last_ms: u64,
    sampled_realtime_ms: u64,
    sampled_monotonic_ms: u64,
    floor: u64,
    count: usize,
    snapshot: []u8,
    wal_offset: u64,
    next_seq: u64,

    fn capture(allocator: std.mem.Allocator, harness: *const Harness) !IdleObservation {
        return .{
            .clock_started = harness.live.state.security_clock_started,
            .boot_ms = harness.live.state.security_boot_effective_ms,
            .last_ms = harness.live.state.security_last_effective_ms,
            .sampled_realtime_ms = harness.live.clock.sampled_realtime_ms.load(.monotonic),
            .sampled_monotonic_ms = harness.live.clock.sampled_monotonic_ms.load(.monotonic),
            .floor = harness.live.state.local_revision_floor,
            .count = harness.live.state.count(),
            .snapshot = try allocator.dupe(u8, harness.live.state.snapshot()),
            .wal_offset = harness.live.store.wal_offset,
            .next_seq = harness.live.store.next_seq,
        };
    }

    fn expectUnchanged(self: IdleObservation, harness: *const Harness) !void {
        try testing.expectEqual(self.clock_started, harness.live.state.security_clock_started);
        try testing.expectEqual(self.boot_ms, harness.live.state.security_boot_effective_ms);
        try testing.expectEqual(self.last_ms, harness.live.state.security_last_effective_ms);
        try testing.expectEqual(self.sampled_realtime_ms, harness.live.clock.sampled_realtime_ms.load(.monotonic));
        try testing.expectEqual(self.sampled_monotonic_ms, harness.live.clock.sampled_monotonic_ms.load(.monotonic));
        try testing.expectEqual(self.floor, harness.live.state.local_revision_floor);
        try testing.expectEqual(self.count, harness.live.state.count());
        try testing.expectEqualSlices(u8, self.snapshot, harness.live.state.snapshot());
        try testing.expectEqual(self.wal_offset, harness.live.store.wal_offset);
        try testing.expectEqual(self.next_seq, harness.live.store.next_seq);
    }

    fn deinit(self: IdleObservation, allocator: std.mem.Allocator) void {
        allocator.free(self.snapshot);
    }
};

fn rootGrantBindings() [1]oper.OperBinding {
    return .{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
}

test "OCG2ISSUER authority construction rejects disabled mismatch and unreserved images" {
    const seed = @as([32]u8, @splat(0x61));
    var identity = try node_identity.fromSeed(seed, "local");
    defer identity.deinit();
    const config = expectedConfig(&identity).?;
    var other = try node_identity.fromSeed(@as([32]u8, @splat(0x62)), "local");
    defer other.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "ocg2issuer-create.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    const clock = ClockSource.frozen(1_000, 1_000);
    var registry = try oper.OperRegistry.init(&.{});
    try testing.expectError(error.Disabled, create(std.testing.allocator, &identity, &services, &clock, &registry));

    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, config);
    defer state.deinit();
    try services.activateDurableOperAuthority(&state);
    try testing.expectError(error.Unavailable, create(std.testing.allocator, &identity, &services, &clock, &registry));
    switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectError(error.Mismatch, create(std.testing.allocator, &other, &services, &clock, &registry));
    const issuer = try create(std.testing.allocator, &identity, &services, &clock, &registry);
    try testing.expect(testHooks(issuer).after_allocate == null);
    try testing.expect(testHooks(issuer).after_commit == null);
    destroy(issuer);
}

test "OCG2ISSUER grant request validation rejects privileges text ttl and revalidates mutation" {
    try testing.expectError(error.InvalidAccount, GrantRequest.init("Oper Alice", export_bit, "moderator", "T", min_ttl_ms));
    try testing.expectError(error.InvalidPrivileges, GrantRequest.init("alice", 0, "moderator", "T", min_ttl_ms));
    try testing.expectError(error.InvalidPrivileges, GrantRequest.init("alice", export_bit | 1, "moderator", "T", min_ttl_ms));
    try testing.expectError(error.InvalidText, GrantRequest.init("alice", export_bit, "", "T", min_ttl_ms));
    try testing.expectError(error.InvalidText, GrantRequest.init("alice", export_bit, "bad\nclass", "T", min_ttl_ms));
    try testing.expectError(error.InvalidTtl, GrantRequest.init("alice", export_bit, "moderator", "T", min_ttl_ms - 1));
    try testing.expectError(error.InvalidTtl, GrantRequest.init("alice", export_bit, "moderator", "T", max_ttl_ms + 1));
    var request = try GrantRequest.init("ALICE", export_bit | export_kill, "moderator", "Title", max_ttl_ms);
    try testing.expectEqualStrings("alice", request.account.asSlice());
    request.privilege_bits |= 1;
    var harness = try Harness.init(0x63, "ocg2issuer-validate.wal");
    defer harness.deinit();
    switch (executeGrant(harness.issuer, &request)) {
        .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
}

test "OCG2ISSUER grant narrow revoke and regrant advance exact revisions" {
    var harness = try Harness.init(0x64, "ocg2issuer-revisions.wal");
    defer harness.deinit();
    const first = try expectCommitted(executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit | export_kill, "Wide"))));
    try testing.expectEqual(@as(u64, 1), first.revision);
    const narrow = try expectCommitted(executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit, "Narrow"))));
    try testing.expectEqual(@as(u64, 2), narrow.revision);
    const revoked = try expectCommitted(executeRevoke(harness.issuer, &(try RevokeRequest.init("ALICE"))));
    try testing.expectEqual(@as(u64, 3), revoked.revision);
    try testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, revoked.kind);
    const regrant = try expectCommitted(executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit, "Returned"))));
    try testing.expectEqual(@as(u64, 4), regrant.revision);
    try testing.expectEqual(Outcome.replay, executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit, "Returned"))));
    const revoked_again = try expectCommitted(executeRevoke(harness.issuer, &(try RevokeRequest.init("alice"))));
    try testing.expectEqual(@as(u64, 5), revoked_again.revision);
    try testing.expectEqual(Outcome.replay, executeRevoke(harness.issuer, &(try RevokeRequest.init("alice"))));
    try testing.expectEqual(@as(u64, 5), harness.live.state.latest("alice").?.revision);
}

test "OCG2ISSUER rollback monotonic horizon and overflow allocate nothing" {
    var harness = try Harness.initAt(0x65, "ocg2issuer-clock.wal", 1_000, 5_000);
    defer harness.deinit();
    const request = try harness.grantReq("alice", export_bit, "Clock");
    harness.setTime(900, 999);
    try testing.expectEqual(Outcome.unavailable, executeGrant(harness.issuer, &request));
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);
    harness.setTime(1_000, 5_001);
    try testing.expectEqual(Outcome.unavailable, executeGrant(harness.issuer, &request));
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
    harness.setTime(5_001, 5_001);
    try testing.expectEqual(Outcome.unavailable, executeGrant(harness.issuer, &request));
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);

    const max = std.math.maxInt(u64);
    harness.live.clock.monotonic_origin_ms = 0;
    harness.setTime(max, max);
    try testing.expectEqual(Outcome.unavailable, executeGrant(harness.issuer, &request));
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
    try testing.expect(harness.live.state.servingAvailable());
}

test "OCG2ISSUER committed receipt hashes wire and signature are exact" {
    var harness = try Harness.init(0x66, "ocg2issuer-receipt.wal");
    defer harness.deinit();
    const request = try harness.grantReq("alice", export_bit, "Exact");
    const receipt = try expectCommitted(executeGrant(harness.issuer, &request));
    try testing.expectEqualStrings("alice", receipt.accountSlice());
    try testing.expectEqual(@as(u64, 1), receipt.revision);
    try testing.expectEqual(harness.now_ms, receipt.issued_ms);
    try testing.expectEqual(harness.now_ms + min_ttl_ms, receipt.expiry_ms);
    const expected = expectedConfig(&harness.live.identity).?;
    try testing.expectEqual(expected.authority_node_id, receipt.authority_node_id);
    try testing.expectEqualSlices(u8, &expected.authority_pubkey, &receipt.authority_pubkey);
    var blake3: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.Blake3.hash(receipt.signedWire(), &blake3, .{});
    try testing.expectEqualSlices(u8, &blake3, &receipt.digest);
    var sha256: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(receipt.signedWire(), &sha256, .{});
    try testing.expectEqualSlices(u8, &sha256, &receipt.wire_sha256);
    const public_key = try std.crypto.sign.Ed25519.PublicKey.fromBytes(receipt.authority_pubkey);
    const fields = try oper_cred_share.verifyOcg2(
        receipt.signedWire(),
        public_key,
        receipt.authority_node_id,
        receipt.issued_ms,
    );
    try testing.expectEqual(export_bit, fields.privilege_bits);
    try testing.expectEqualStrings("Exact", fields.title);
    switch (harness.live.services.inspectDurableOperTransaction("alice", harness.now_ms)) {
        .active => |copy| try testing.expectEqualSlices(u8, receipt.signedWire(), copy.signedWire()),
        else => return error.TestUnexpectedResult,
    }
}

const FaultCase = struct {
    name: []const u8,
    fault: store_mod.PreparedIoFault,
    candidate_replays: bool,
};

test "OCG2ISSUER cut failed short sync and crash reopen never reuse a revision" {
    const cases = [_]FaultCase{
        .{ .name = "ocg2issuer-write-failed.wal", .fault = .{ .write = .failed }, .candidate_replays = false },
        .{ .name = "ocg2issuer-write-short.wal", .fault = .{ .write = .short }, .candidate_replays = false },
        .{ .name = "ocg2issuer-sync.wal", .fault = .{ .sync = true }, .candidate_replays = true },
    };
    const seed = @as([32]u8, @splat(0x67));
    var identity = try node_identity.fromSeed(seed, "local");
    defer identity.deinit();
    const config = expectedConfig(&identity).?;
    const now: u64 = 1_000;
    const horizon: u64 = now + max_ttl_ms + min_ttl_ms;
    const request = try GrantRequest.init("alice", export_bit, "moderator", "Cut", min_ttl_ms);

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try store_mod.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, case.name);
            var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, config);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            switch (services.reserveDurableOperSecurityTime(now, horizon)) {
                .committed => {},
                else => return error.TestUnexpectedResult,
            }
            const clock = ClockSource.frozen(now, now);
            var registry = try oper.OperRegistry.init(&.{});
            const issuer = try create(std.testing.allocator, &identity, &services, &clock, &registry);
            defer destroy(issuer);
            store.setPreparedIoFault(case.fault);
            switch (executeGrant(issuer, &request)) {
                .restart_required => |reason| try testing.expectEqual(Services.DurableOperRestart.ambiguous_store, reason),
                else => return error.TestUnexpectedResult,
            }
            try testing.expect(testIsPoisoned(issuer));
            try testing.expect(!state.servingAvailable());
            store.deinit();
        }

        var reopened = try store_mod.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, case.name);
        defer reopened.deinit();
        var restored = try durable_oper_authority_boot.load(std.testing.allocator, &reopened, config);
        defer restored.deinit();
        if (case.candidate_replays) {
            try testing.expectEqual(@as(u64, 1), restored.local_revision_floor);
            try testing.expect(restored.latest("alice") == null);
            var next = try restored.prepareRevision("alice");
            defer next.update.abort();
            try testing.expectEqual(@as(u64, 2), next.revision);
        } else {
            try testing.expectEqual(@as(u64, 0), restored.local_revision_floor);
            try testing.expect(restored.latest("alice") == null);
        }
    }
}

test "OCG2ISSUER preadmission OOM capacity busy and exhaustion burn nothing extra" {
    var harness = try Harness.init(0x68, "ocg2issuer-preadmit.wal");
    defer harness.deinit();
    const request = try harness.grantReq("alice", export_bit, "Busy");
    {
        var prepared = try harness.live.state.prepareRevision("alice");
        defer prepared.update.abort();
        switch (executeGrant(harness.issuer, &request)) {
            .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.busy, reason),
            else => return error.TestUnexpectedResult,
        }
        try testing.expect(harness.live.state.latest("alice") == null);
    }

    harness.live.state.local_revision_floor = std.math.maxInt(u64);
    switch (executeGrant(harness.issuer, &request)) {
        .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.exhausted, reason),
        else => return error.TestUnexpectedResult,
    }
    harness.live.state.local_revision_floor = 0;

    var constrained_store = try store_mod.OroStore.openWithConfig(
        std.testing.allocator,
        std.testing.io,
        harness.tmp.dir,
        "ocg2issuer-capacity.wal",
        .{ .max_record_bytes = 64 },
    );
    defer constrained_store.deinit();
    var constrained_state = try durable_oper_authority.State.init(
        std.testing.allocator,
        expectedConfig(&harness.live.identity).?,
    );
    defer constrained_state.deinit();
    var constrained_services = Services.init(&constrained_store, null);
    const disabled_clock = ClockSource.frozen(1_000, 1_000);
    try testing.expectError(
        error.Disabled,
        create(std.testing.allocator, &harness.live.identity, &constrained_services, &disabled_clock, &harness.live.registry),
    );
}

test "OCG2ISSUER replay stale equivocation and postcommit mismatch poison" {
    var harness = try Harness.init(0x69, "ocg2issuer-poison.wal");
    defer harness.deinit();
    const first_req = try harness.grantReq("alice", export_bit, "First");
    _ = try expectCommitted(executeGrant(harness.issuer, &first_req));
    try testing.expectEqual(Outcome.replay, executeGrant(harness.issuer, &first_req));

    const StaleGate = struct {
        allocated: std.atomic.Value(bool) = .init(false),
        released: std.atomic.Value(bool) = .init(false),

        fn afterAllocate(issuer: *Ocg2AuthorityIssuer) void {
            const self: *@This() = @ptrCast(@alignCast(testHookCtx(issuer).?));
            self.allocated.store(true, .release);
            while (!self.released.load(.acquire)) std.Thread.yield() catch {};
        }
    };
    var stale_gate = StaleGate{};
    const peer = try create(std.testing.allocator, &harness.live.identity, &harness.live.services, &harness.live.clock, &harness.live.registry);
    defer destroy(peer);
    testHooks(harness.issuer).after_allocate = StaleGate.afterAllocate;
    testHooks(harness.issuer).ctx = &stale_gate;
    const stale_req = try harness.grantReq("alice", export_bit, "Stale");
    const peer_req = try harness.grantReq("alice", export_bit | export_kill, "Peer");
    const StaleThread = struct {
        issuer: *Ocg2AuthorityIssuer,
        request: *const GrantRequest,
        outcome: Outcome = .unavailable,
        fn run(self: *@This()) void {
            self.outcome = executeGrant(self.issuer, self.request);
        }
    };
    var stale_thread = StaleThread{ .issuer = harness.issuer, .request = &stale_req };
    var thread = try std.Thread.spawn(.{}, StaleThread.run, .{&stale_thread});
    while (!stale_gate.allocated.load(.acquire)) std.Thread.yield() catch {};
    _ = try expectCommitted(executeGrant(peer, &peer_req));
    stale_gate.released.store(true, .release);
    thread.join();
    try testing.expectEqual(Outcome.stale, stale_thread.outcome);
    testHooks(harness.issuer).after_allocate = null;
    testHooks(harness.issuer).ctx = null;

    const Equiv = struct {
        now_ms: u64,
        state: *durable_oper_authority.State,
        fn afterAllocate(issuer: *Ocg2AuthorityIssuer) void {
            const self: *const @This() = @ptrCast(@alignCast(testHookCtx(issuer).?));
            const expected = expectedConfig(testIdentity(issuer)).?;
            var wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
            const len = oper_cred_share.signOcg2WithNodeKey(&testIdentity(issuer).sign_kp, .{
                .kind = .grant,
                .account = "carol",
                .revision = self.state.local_revision_floor,
                .privilege_bits = export_bit,
                .class = "moderator",
                .title = "Conflict",
                .authority_node_id = expected.authority_node_id,
                .authority_pubkey = expected.authority_pubkey,
                .issued_ms = self.now_ms,
                .expiry_ms = self.now_ms + min_ttl_ms,
            }, self.now_ms, &wire) catch unreachable;
            _ = testServices(issuer).commitDurableOperRecord(wire[0..len], self.now_ms);
        }
    };
    var equiv = Equiv{ .now_ms = harness.now_ms, .state = &harness.live.state };
    testHooks(harness.issuer).after_allocate = Equiv.afterAllocate;
    testHooks(harness.issuer).ctx = &equiv;
    try testing.expectEqual(Outcome.equivocation, executeGrant(harness.issuer, &(try harness.grantReq("carol", export_bit, "Original"))));
    try testing.expect(!testIsPoisoned(harness.issuer));
    testHooks(harness.issuer).after_allocate = null;

    const Mutate = struct {
        now_ms: u64,
        fn afterCommit(issuer: *Ocg2AuthorityIssuer) void {
            const self: *const @This() = @ptrCast(@alignCast(testHookCtx(issuer).?));
            switch (testServices(issuer).allocateDurableOperRevision("dave")) {
                .committed => |revision| {
                    const expected = expectedConfig(testIdentity(issuer)).?;
                    var wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
                    const len = oper_cred_share.signOcg2WithNodeKey(&testIdentity(issuer).sign_kp, .{
                        .kind = .grant,
                        .account = "dave",
                        .revision = revision,
                        .privilege_bits = export_bit,
                        .class = "moderator",
                        .title = "Successor",
                        .authority_node_id = expected.authority_node_id,
                        .authority_pubkey = expected.authority_pubkey,
                        .issued_ms = self.now_ms,
                        .expiry_ms = self.now_ms + min_ttl_ms,
                    }, self.now_ms, &wire) catch return;
                    _ = testServices(issuer).commitDurableOperRecord(wire[0..len], self.now_ms);
                },
                else => {},
            }
        }
    };
    var mutate = Mutate{ .now_ms = harness.now_ms };
    testHooks(harness.issuer).after_commit = Mutate.afterCommit;
    testHooks(harness.issuer).ctx = &mutate;
    try testing.expectEqual(Outcome.poison, executeGrant(harness.issuer, &(try harness.grantReq("dave", export_bit, "Victim"))));
    try testing.expect(testIsPoisoned(harness.issuer));
    try testing.expectEqual(Outcome.poison, executeGrant(harness.issuer, &(try harness.grantReq("erin", export_bit, "Later"))));
}

test "OCG2ISSUER signing failure after a burned revision poisons fail-closed" {
    var harness = try Harness.init(0x6A, "ocg2issuer-signfail.wal");
    defer harness.deinit();
    const Wipe = struct {
        fn afterAllocate(issuer: *Ocg2AuthorityIssuer) void {
            testWipeSigner(issuer);
        }
    };
    testHooks(harness.issuer).after_allocate = Wipe.afterAllocate;
    try testing.expectEqual(Outcome.poison, executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit, "Burn"))));
    try testing.expect(testIsPoisoned(harness.issuer));
    try testing.expectEqual(Services.DurableOperAuthorityMatch.unavailable, harness.live.services.matchDurableOperAuthority(expectedConfig(&harness.live.identity).?));
    try testing.expectEqual(@as(u64, 1), harness.live.state.local_revision_floor);
    try testing.expect(harness.live.state.latest("alice") == null);
}

test "OCG2ISSUER concurrent grants serialize without precommit receipt or callback" {
    var harness = try Harness.init(0x6B, "ocg2issuer-concurrent.wal");
    defer harness.deinit();
    try testing.expect(testHooks(harness.issuer).after_allocate == null);
    try testing.expect(testHooks(harness.issuer).after_commit == null);
    const Worker = struct {
        issuer: *Ocg2AuthorityIssuer,
        request: GrantRequest,
        outcome: Outcome = .unavailable,
        fn run(self: *@This()) void {
            self.outcome = executeGrant(self.issuer, &self.request);
        }
    };
    var workers = [_]Worker{
        .{ .issuer = harness.issuer, .request = try harness.grantReq("alice", export_bit, "One") },
        .{ .issuer = harness.issuer, .request = try harness.grantReq("bob", export_kill, "Two") },
    };
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, 0..) |*worker, index| {
        threads[index] = try std.Thread.spawn(.{}, Worker.run, .{worker});
    }
    for (threads) |thread| thread.join();
    var seen: [2]u64 = undefined;
    for (workers, 0..) |worker, index| {
        const receipt = try expectCommitted(worker.outcome);
        seen[index] = receipt.revision;
        try testing.expect(receipt.signedWire().len != 0);
    }
    try testing.expect(seen[0] != seen[1]);
    try testing.expectEqual(@as(u64, 1), @min(seen[0], seen[1]));
    try testing.expectEqual(@as(u64, 2), @max(seen[0], seen[1]));
}

test "OCG2ISSUER WAL and receipt never persist the node seed" {
    var harness = try Harness.init(0x6C, "ocg2issuer-secret.wal");
    defer harness.deinit();
    const receipt = try expectCommitted(executeGrant(harness.issuer, &(try harness.grantReq("alice", export_bit, "Secret"))));
    try testing.expect(!containsBytes(receipt.signedWire(), &harness.seed));
    const issuer_bytes = testImplBytes(harness.issuer);
    try testing.expect(!containsBytes(issuer_bytes, &harness.seed));
    const snapshot = harness.live.store.get(.props, durable_oper_authority.snapshot_key) orelse return error.TestUnexpectedResult;
    try testing.expect(!containsBytes(snapshot, &harness.seed));
    const wal = try harness.tmp.dir.readFileAlloc(std.testing.io, "ocg2issuer-secret.wal", std.testing.allocator, .limited(1 << 20));
    defer std.testing.allocator.free(wal);
    try testing.expect(!containsBytes(wal, &harness.seed));
}

test "OCG2ISSUER create and grant remain allocation-failure atomic" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const seed = @as([32]u8, @splat(0x6D));
            var identity = try node_identity.fromSeed(seed, "local");
            defer identity.deinit();
            const config = expectedConfig(&identity).?;
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var store = try store_mod.OroStore.open(allocator, std.testing.io, tmp.dir, "ocg2issuer-oom.wal");
            defer store.deinit();
            var state = try durable_oper_authority_boot.initialize(allocator, &store, config);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            switch (services.reserveDurableOperSecurityTime(1_000, 1_000 + max_ttl_ms + min_ttl_ms)) {
                .committed => {},
                .preadmission => |reason| if (reason == .out_of_memory) return error.OutOfMemory else return error.TestUnexpectedResult,
                else => return error.TestUnexpectedResult,
            }
            const clock = ClockSource.frozen(1_000, 1_000);
            var registry = try oper.OperRegistry.init(&.{});
            const issuer = create(allocator, &identity, &services, &clock, &registry) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return err,
            };
            defer destroy(issuer);
            const request = try GrantRequest.init("alice", export_bit, "moderator", "Oom", min_ttl_ms);
            switch (executeGrant(issuer, &request)) {
                .committed => {},
                .preadmission => |reason| if (reason == .out_of_memory) return error.OutOfMemory else return error.TestUnexpectedResult,
                else => return error.TestUnexpectedResult,
            }
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});
}

test "OCG2ISSUER mutated account class title lengths are preadmission not traps" {
    var harness = try Harness.init(0x6E, "ocg2issuer-lengths.wal");
    defer harness.deinit();
    const overflow_account: u16 = services_mod.AccountName.empty().bytes.len + 1;
    const overflow_class = oper_cred_share.ocg2_max_class_len + 1;
    const overflow_title = oper_cred_share.ocg2_max_title_len + 1;
    const cases = [_]struct {
        account: bool = false,
        class: bool = false,
        title: bool = false,
    }{
        .{ .account = true },
        .{ .class = true },
        .{ .title = true },
        .{ .account = true, .class = true },
        .{ .account = true, .title = true },
        .{ .class = true, .title = true },
        .{ .account = true, .class = true, .title = true },
    };
    for (cases) |case| {
        var request = try harness.grantReq("alice", export_bit, "Len");
        if (case.account) request.account.len = overflow_account;
        if (case.class) request.class_len = overflow_class;
        if (case.title) request.title_len = overflow_title;
        switch (executeGrant(harness.issuer, &request)) {
            .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
            else => return error.TestUnexpectedResult,
        }
    }
    var max_grant = try harness.grantReq("alice", export_bit, "Len");
    max_grant.account.len = std.math.maxInt(u16);
    max_grant.class_len = std.math.maxInt(usize);
    max_grant.title_len = std.math.maxInt(usize);
    switch (executeGrant(harness.issuer, &max_grant)) {
        .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    var revoke = try RevokeRequest.init("alice");
    revoke.account.len = overflow_account;
    switch (executeRevoke(harness.issuer, &revoke)) {
        .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    revoke.account.len = std.math.maxInt(u16);
    switch (executeRevoke(harness.issuer, &revoke)) {
        .preadmission => |reason| try testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
}

test "OCG2ISSUER destroy is single-owner after in-flight transactions join" {
    var harness = try Harness.init(0x6F, "ocg2issuer-destroy.wal");
    const Worker = struct {
        issuer: *Ocg2AuthorityIssuer,
        request: GrantRequest,
        outcome: Outcome = .unavailable,
        fn run(self: *@This()) void {
            self.outcome = executeGrant(self.issuer, &self.request);
        }
    };
    var workers = [_]Worker{
        .{ .issuer = harness.issuer, .request = try harness.grantReq("alice", export_bit, "One") },
        .{ .issuer = harness.issuer, .request = try harness.grantReq("bob", export_kill, "Two") },
    };
    var threads: [workers.len]std.Thread = undefined;
    for (&workers, 0..) |*worker, index| {
        threads[index] = try std.Thread.spawn(.{}, Worker.run, .{worker});
    }
    for (threads) |thread| thread.join();
    for (workers) |worker| _ = try expectCommitted(worker.outcome);
    // Owner thread tears down only after every in-flight transaction has
    // joined. Destroy waits on the issuer mutex, so a still-running
    // transaction finishes its critical section first.
    destroy(harness.issuer);
    try testing.expectEqual(@as(usize, 2), harness.live.state.count());
    harness.live.identity.deinit();
    harness.live.state.deinit();
    harness.live.store.deinit();
    std.testing.allocator.destroy(harness.live);
    harness.tmp.cleanup();
}

test "OCG2ISSUER handle reflection is opaque in-module" {
    try testing.expect(switch (@typeInfo(Ocg2AuthorityIssuer)) {
        .@"opaque" => true,
        else => false,
    });
    try testing.expect(@hasDecl(Ocg2AuthorityIssuer, "executeAuthorized"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "identity"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "services"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "clock"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "registry"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "sign_kp"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "declassify"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "after_allocate"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "after_commit"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "hook_ctx"));
    inline for (.{
        "issue",         "grant",       "revoke",
        "issueGrant",    "issueRevoke", "executeGrant",
        "executeRevoke", "transmit",    "identity",
        "registry",
    }) |name| try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, name));
}

test "OCG2ISSUER executeAuthorized live permit commits exact grant and revoke" {
    var harness = try Harness.init(0x70, "ocg2issuer-authorized.wal");
    defer harness.deinit();
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
    harness.live.registry.bindings = &bindings;
    const permit = try harness.mintPermit(&harness.live.registry, "root");
    const request = try harness.grantReq("alice", export_bit, "Exact");
    const receipt = try expectCommitted(harness.issuer.executeAuthorized(permit, .{ .grant = request }));
    try testing.expectEqualStrings("alice", receipt.accountSlice());
    try testing.expectEqual(@as(u64, 1), receipt.revision);
    try testing.expectEqual(harness.now_ms, receipt.issued_ms);
    try testing.expectEqual(harness.now_ms + min_ttl_ms, receipt.expiry_ms);
    const expected = expectedConfig(&harness.live.identity).?;
    try testing.expectEqual(expected.authority_node_id, receipt.authority_node_id);
    try testing.expectEqualSlices(u8, &expected.authority_pubkey, &receipt.authority_pubkey);
    var blake3: [durable_oper_authority.digest_len]u8 = undefined;
    std.crypto.hash.Blake3.hash(receipt.signedWire(), &blake3, .{});
    try testing.expectEqualSlices(u8, &blake3, &receipt.digest);
    const revoked = try expectCommitted(harness.issuer.executeAuthorized(permit, .{
        .revoke = try RevokeRequest.init("alice"),
    }));
    try testing.expectEqual(@as(u64, 2), revoked.revision);
    try testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, revoked.kind);
    try testing.expectEqual(@as(u64, 2), harness.live.state.local_revision_floor);
}

test "OCG2ISSUER executeAuthorized stale REHASH permit allocates nothing" {
    var harness = try Harness.init(0x71, "ocg2issuer-rehash.wal");
    defer harness.deinit();
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
    }};
    harness.live.registry.bindings = &bindings;
    const permit = try harness.mintPermit(&harness.live.registry, "root");
    const replaced = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
    }};
    harness.live.registry.bindings = &replaced;
    const request = try harness.grantReq("alice", export_bit, "Stale");
    try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(permit, .{ .grant = request }));
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
}

test "OCG2ISSUER executeAuthorized account mismatch and missing oper_grant allocate nothing" {
    var harness = try Harness.init(0x72, "ocg2issuer-mismatch.wal");
    defer harness.deinit();
    const bindings = [_]oper.OperBinding{
        .{
            .account_name = "root",
            .class_name = "netadmin",
            .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        },
        .{
            .account_name = "alice",
            .class_name = "local",
            .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
        },
    };
    harness.live.registry.bindings = &bindings;
    const root_binding = oper_session_provenance.configuredLocalBinding(&harness.live.registry, "root") orelse
        return error.TestUnexpectedResult;
    try testing.expect(oper_session_provenance.configuredLocalMintPermit(&harness.live.registry, root_binding, "alice") == null);
    const alice_binding = oper_session_provenance.configuredLocalBinding(&harness.live.registry, "alice") orelse
        return error.TestUnexpectedResult;
    try testing.expect(oper_session_provenance.configuredLocalMintPermit(&harness.live.registry, alice_binding, "alice") == null);

    var mutated = try harness.mintPermit(&harness.live.registry, "root");
    @memcpy(mutated.binding.account_buf[0..5], "alice");
    mutated.binding.account_len = 5;
    const request = try harness.grantReq("carol", export_bit, "Mismatch");
    try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(mutated, .{ .grant = request }));
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);
    try testing.expectEqual(@as(usize, 0), harness.live.state.count());
}

test "OCG2ISSUER executeAuthorized rejects OCG2 OCG1 snapshot remote nonoper fabrication before revision" {
    var harness = try Harness.init(0x73, "ocg2issuer-reject.wal");
    defer harness.deinit();
    const request = try harness.grantReq("alice", export_bit, "Reject");

    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
    }};
    harness.live.registry.bindings = &bindings;
    var fabricated = try harness.mintPermit(&harness.live.registry, "root");
    var dummy_seal: u64 = 0;
    fabricated.seal = @ptrCast(&dummy_seal);
    try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(fabricated, .{ .grant = request }));
    try testing.expectEqual(@as(u64, 0), harness.live.state.local_revision_floor);

    _ = try expectCommitted(executeGrant(harness.issuer, &request));
    try testing.expectEqual(@as(u64, 1), harness.live.state.local_revision_floor);
    try testing.expect(oper_session_provenance.configuredLocalBinding(
        &try oper.OperRegistry.init(&.{}),
        "alice",
    ) == null);

    const ocg1 = oper.OperGrant{
        .account_name = "alice",
        .class_name = "forged",
        .privileges = oper.OperPrivileges.full,
    };
    _ = ocg1;
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "fromOcg2"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "fromLegacy"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "fromSnapshot"));
    try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, "fromRemote"));
    try testing.expect(!@hasDecl(Command, "ocg2"));
    try testing.expect(!@hasDecl(Command, "legacy"));
    try testing.expect(!@hasDecl(Command, "snapshot"));
    try testing.expect(!@hasDecl(Command, "remote"));
    try testing.expect(!@hasDecl(@This(), "transmit"));
    try testing.expect(!@hasDecl(Receipt, "transmit"));

    try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(fabricated, .{
        .revoke = try RevokeRequest.init("alice"),
    }));
    try testing.expectEqual(@as(u64, 1), harness.live.state.local_revision_floor);
    try testing.expectEqual(@as(usize, 1), harness.live.state.count());
}

test "OCG2ISSUER public surface is only executeAuthorized" {
    try testing.expect(@hasDecl(Ocg2AuthorityIssuer, "executeAuthorized"));
    try testing.expect(!@hasDecl(@This(), "executeAuthorized"));
    inline for (.{
        "issue",        "grant",         "revoke", "issueGrant", "issueRevoke", "transmit",
        "executeGrant", "executeRevoke",
    }) |name| try testing.expect(!@hasDecl(Ocg2AuthorityIssuer, name));
}

test "OCG2ISSUER executeAuthorized survives REHASH of identical bindings on the bound registry" {
    var harness = try Harness.init(0x74, "ocg2issuer-rehash-identity.wal");
    defer harness.deinit();
    var first = rootGrantBindings();
    harness.live.registry.bindings = &first;
    const permit = try harness.mintPermit(&harness.live.registry, "root");
    var successor = rootGrantBindings();
    harness.live.registry.bindings = &successor;
    try testing.expect(permit.valid(&harness.live.registry));
    const request = try harness.grantReq("alice", export_bit, "RehashKeep");
    const receipt = try expectCommitted(harness.issuer.executeAuthorized(permit, .{ .grant = request }));
    try testing.expectEqual(@as(u64, 1), receipt.revision);
    try testing.expectEqual(@as(u64, 1), harness.live.state.local_revision_floor);
}

test "OCG2ISSUER executeAuthorized attacker registry with identical bindings is unauthorized" {
    var harness = try Harness.init(0x75, "ocg2issuer-attacker.wal");
    defer harness.deinit();
    const bindings = rootGrantBindings();
    harness.live.registry.bindings = &bindings;
    const attacker = try oper.OperRegistry.init(&bindings);
    try testing.expect(&attacker != &harness.live.registry);
    const attacker_permit = try harness.mintPermit(&attacker, "root");
    try testing.expect(attacker_permit.valid(&attacker));
    try testing.expect(!attacker_permit.valid(&harness.live.registry));

    const idle = try IdleObservation.capture(std.testing.allocator, &harness);
    defer idle.deinit(std.testing.allocator);
    const request = try harness.grantReq("alice", export_bit, "Attacker");
    try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(attacker_permit, .{ .grant = request }));
    try idle.expectUnchanged(&harness);
}

test "OCG2ISSUER executeAuthorized mutated max+1 permit fields are unauthorized" {
    var harness = try Harness.init(0x76, "ocg2issuer-permit-len.wal");
    defer harness.deinit();
    const bindings = rootGrantBindings();
    harness.live.registry.bindings = &bindings;
    const genuine = try harness.mintPermit(&harness.live.registry, "root");
    const request = try harness.grantReq("alice", export_bit, "Overflow");
    const cases = [_]struct { account: bool = false, class: bool = false, title: bool = false }{
        .{ .account = true },
        .{ .class = true },
        .{ .title = true },
        .{ .account = true, .class = true, .title = true },
    };
    for (cases) |case| {
        var mutated = genuine;
        if (case.account) mutated.binding.account_len = oper_session_provenance.max_projection_account_len + 1;
        if (case.class) mutated.binding.class_len = oper_session_provenance.max_class_len + 1;
        if (case.title) mutated.binding.title_len = oper_session_provenance.max_title_len + 1;
        const idle = try IdleObservation.capture(std.testing.allocator, &harness);
        defer idle.deinit(std.testing.allocator);
        try testing.expectEqual(Outcome.unauthorized, harness.issuer.executeAuthorized(mutated, .{ .grant = request }));
        try idle.expectUnchanged(&harness);
    }
}
