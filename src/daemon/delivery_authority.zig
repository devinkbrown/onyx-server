// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Leased, source-owned local signed Event Spine and downstream delivery cut.
//! This prerequisite is not installed in Server. It owns the original Guard,
//! History and outputs; a consumer must route ALL active authority accesses here.
//! Peer admission, graph/World registration, HTTP acknowledgements and Helix
//! transfer are deliberately absent. No supplied boolean authenticates them.
//! The caller's real Io backend must outlive this owner and all its loans.
const std = @import("std");
const builtin = @import("builtin");
const store_mod = @import("store.zig");
const lease_mod = @import("mesh_presence_lease.zig");
const os_runtime = @import("os_runtime.zig");
const sign = @import("../crypto/sign.zig");
const oper = @import("../proto/oper_event.zig");
const guard_mod = @import("event_spine_replay_guard.zig");
const history_mod = @import("event_history.zig");
const spine = @import("event_spine.zig");
const http = @import("http_fetch.zig");
const lock_mod = @import("../substrate/rwlock.zig");
const services_mod = @import("services.zig");
const server_mod = @import("server.zig");

const History = history_mod.EventHistory(512);
pub const max_deliveries = 8;
pub const max_destinations = 8;
pub const max_url = 512;
pub const max_secret = 128;
const max_body = 8192;
const keys = [_][]const u8{ "oda\x00esg2", "oda\x00oeh1", "oda\x00deliveries", "oda\x00head" };
const head_domain = "onyx_server.delivery-authority.head.v1";
const head_prefix = 4 + 1 + 32 + 32 + 32 + 16 + 16 + 8 + 8 + 32 + 3 * 32;
const head_len = head_prefix + sign.signature_len;

pub const Config = struct {
    replay: guard_mod.Config = .{},
    storage: store_mod.Config = .{ .changefeed_capacity = 0 },
    /// Finite lifetime budget for unique loan/plan identities, including
    /// consumed handles. Exhaustion requires explicit quiescence/close and a
    /// real cold owner; production graph rotation is not implemented here.
    max_issued_tokens: usize = 4096,
};
pub const Context = struct {
    origin: sign.PublicKey,
    config_digest: [32]u8,
    canonical_name: []const u8,
};
/// Only actual protected storage-open inputs. Core supplies its own retained
/// Io, allocator, normalized policy and full signing identity.
pub const ProtectedStorage = struct { dir: std.Io.Dir, name: []const u8 };
pub const DestinationInput = struct { url: []const u8, secret: []const u8 };
pub const Observation = struct {
    generation: u64,
    logical_store_id: [16]u8,
    /// Source-generated immutable application epoch; NOT rotating WAL epoch.
    logical_store_epoch: [16]u8,
    max_accepted_hlc: u64,
    pending_deliveries: usize,
    poisoned: bool,
};

pub const Authority = opaque {
    pub fn initialize(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, context: Context, key: *const sign.KeyPair, config: Config) !*Authority {
        return create(allocator, io, dir, name, context, key, config, false);
    }
    /// Existing state and lease are open-only. Authenticate the complete OLD
    /// package before preparing any cold WAL recovery publication.
    pub fn openCold(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, context: Context, key: *const sign.KeyPair, config: Config) !*Authority {
        return create(allocator, io, dir, name, context, key, config, true);
    }
    pub fn observe(self: *Authority) !Observation {
        const b = backing(self);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        return b.observation();
    }
    /// Creator-lifetime view of the exact original leased context. The handle
    /// expires at Authority.close; attached Services loans pin that close.
    pub fn stateContext(self: *Authority) *StateContext {
        return @ptrCast(backing(self).state);
    }
    /// The source issues one-shot loans. A live loan prevents mutation/close;
    /// returned slices remain borrowed only until release. Tokens are retained
    /// until close so a stale handle cannot become a newer loan or plan.
    pub fn borrow(self: *Authority) !*ReadBorrow {
        const b = backing(self);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        if (b.active != null) return error.MutationActive;
        try b.requireTokenBudget();
        const loan = try b.allocator.create(ReadToken);
        loan.* = .{ .owner = b, .next = b.read_tokens };
        b.read_tokens = loan;
        b.read_count += 1;
        b.issued_tokens += 1;
        return @ptrCast(loan);
    }
    /// Local signed authorship only. Full key, derived node id, canonical
    /// origin and real signature are checked. Caller strings/flags cannot
    /// authorize peer authorship; that needs a genuine registry source seam.
    pub fn prepareEvent(self: *Authority, event: oper.SignedOperEventV2, destinations: []const DestinationInput, now_ms: u64, key: *const sign.KeyPair) !*Prepared {
        const b = backing(self);
        const transaction = try b.acquireTransaction();
        errdefer transaction.release();
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try b.writable(key);
        try b.validateEvent(event);
        if (destinations.len > max_destinations) return error.Capacity;
        var candidate = try b.candidate();
        errdefer candidate.deinit(b.allocator);
        const id = switch (try candidate.guard.admit(event, now_ms, 5 * 60 * 1000)) {
            .accepted => |id| id,
            .duplicate => return error.Duplicate,
            else => return error.AdmissionRejected,
        };
        const inserted = try candidate.history.ingestStableEvent(.{
            .event_id = id,
            .category = event.category,
            .severity = event.severity,
            .origin_ts_unix_ms = std.math.cast(i64, event.originTimeMs()) orelse return error.InvalidClock,
            .origin = event.origin_server,
            .message = event.message,
        });
        if (inserted != .inserted) return error.HistoryConflict;
        if (destinations.len != 0) {
            if (candidate.image.count == max_deliveries) return error.Capacity;
            var delivery = try Delivery.fromEvent(b.allocator, event, destinations);
            errdefer delivery.deinit(b.allocator);
            candidate.image.items[candidate.image.count] = delivery;
            candidate.image.count += 1;
        }
        candidate.max_hlc = @max(candidate.max_hlc, event.hlc);
        return try b.prepare(candidate, key, id, transaction);
    }
    /// Storage progress ONLY. The HTTP consumer must independently establish
    /// an actual accepted response. This method never mints an HTTP receipt.
    /// Exact immutable output is released only after successor WAL sync.
    pub fn prepareProgress(self: *Authority, id: oper.EventId, destination: usize, key: *const sign.KeyPair) !*Prepared {
        const b = backing(self);
        const transaction = try b.acquireTransaction();
        errdefer transaction.release();
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try b.writable(key);
        var candidate = try b.candidate();
        errdefer candidate.deinit(b.allocator);
        const index = for (candidate.image.items[0..candidate.image.count], 0..) |delivery, i| {
            if (std.mem.eql(u8, &delivery.?.id, &id)) break i;
        } else return error.UnknownDelivery;
        const delivery = &candidate.image.items[index].?;
        if (destination != delivery.cursor) return error.InvalidProgress;
        delivery.cursor += 1;
        if (delivery.cursor == delivery.destination_count) {
            delivery.deinit(b.allocator);
            for (index..candidate.image.count - 1) |i| candidate.image.items[i] = candidate.image.items[i + 1];
            candidate.image.count -= 1;
            candidate.image.items[candidate.image.count] = null;
        }
        return try b.prepare(candidate, key, null, transaction);
    }
    /// Close durable source custody, not a service STOPPED receipt. Pending
    /// outputs remain in the synced journal for an actual cold owner. An
    /// unresolved candidate must first be explicitly aborted; poison remains.
    /// The creator must stop external admission and actually join every caller
    /// before close. A child using borrowed views holds its original loan until
    /// its actual Thread.join. This mutex does not observe arbitrary queued
    /// callers. All handles expire on close; invoking them afterward is invalid.
    pub fn close(self: *Authority) !void {
        const b = backing(self);
        b.gate.lockExclusive();
        if (b.active != null or b.read_count != 0 or b.state.services_loan != null or b.state.authority_entries != 0 or b.state.core_stage != null) {
            b.gate.unlockExclusive();
            return error.SourceBorrowed;
        }
        b.gate.unlockExclusive();
        destroy(b);
    }
};

/// Original leased Store custody. This bounded prerequisite exposes only a
/// closed named Services dispatch and a genuine Core staging pin. World/live
/// installation remains separate; no Services/Store pointer or callback escapes.
pub const StateContext = opaque {
    /// The original Core's private issuer selects every authentication input.
    /// No caller Context, digest, key, Store or Services pointer crosses this
    /// factory. Install transfers exact opaque owners, not graph/World authority.
    pub fn provisionForCore(stage: *server_mod.ManagedLeasedCoreStage, storage: ProtectedStorage) !void {
        const owner = try stage.provisionOriginalAuthority(storage);
        try installCoreSources(stage, owner);
    }
    pub fn recoverForCore(stage: *server_mod.ManagedLeasedCoreStage, storage: ProtectedStorage) !void {
        const owner = try stage.recoverOriginalAuthority(storage);
        try installCoreSources(stage, owner);
    }

    fn installCoreSources(stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority) !void {
        var loan: ?*ServicesLoan = null;
        errdefer {
            // The original Core remains pinned through this synchronous return.
            // Its source abort removes callbacks/borrows before either free.
            stage.abortInstallation(owner, loan) catch @panic("Core source installation abort");
            releaseCoreSources(stage, owner, loan) catch @panic("Core source registration release");
            if (loan) |original| original.close() catch @panic("Core source Services close");
            owner.close() catch @panic("Core source Authority close");
        }
        loan = try stage.attachOriginalServices(owner);
        try validateCoreSources(stage, owner, loan.?);
        // Failure precedes ownership transfer. On success Core becomes the sole
        // creator/cleanup owner, and every leaf errdefer is disarmed.
        try stage.installOriginalSources(owner, loan.?);
    }

    /// Core first proves that it issued these exact owners. This leaf joins the
    /// actual private Store/Services/mutex/context and protected source before
    /// pinning that stable issuer. Equal hashes or foreign owners cannot bind.
    pub fn validateCoreSources(stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority, loan: *ServicesLoan) !void {
        try stage.requireOriginalSources(owner, loan);
        const b = backing(owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const context = b.state;
        const original = servicesToken(loan);
        if (original.context != context or context.services_loan != original) return error.SourceIdentityMismatch;
        try original.validate();
        if (context.core_stage) |previous| if (previous != stage) return error.SourceIdentityMismatch;
        if (original.calls != 0 or context.authority_entries != 0 or b.active != null or b.read_count != 0) return error.SourceBorrowed;
        if (!original.lock.tryLockExclusive()) return error.SourceBorrowed;
        defer original.lock.unlockExclusive();
        if (context.store.preparedWritesPoisoned()) return error.StorePoisoned;
        try b.validateSource();
        context.core_stage = stage;
    }

    /// Core proves its actual unpublished/canceled/joined disposal barrier;
    /// leaf counters alone never prove external admission closure or joins.
    /// Release precedes Loan.close and Authority.close. Poison does not prevent
    /// disposal after real quiescence, but pending plans/readers retain custody.
    pub fn releaseCoreSources(stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority, loan: ?*ServicesLoan) !void {
        try stage.requireOriginalSources(owner, loan);
        try stage.requireSourceRelease(owner, loan);
        const b = backing(owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try requireCoreReleaseableLocked(stage, b, loan);
        b.state.core_stage = null;
    }

    /// Preflight actual custody before Core removes its original placement.
    /// This grants no receipt and releases nothing. Core keeps real admission
    /// closed and final release repeats every check before dropping its pin.
    pub fn requireCoreReleaseable(stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority, loan: ?*ServicesLoan) !void {
        try stage.requireOriginalSources(owner, loan);
        try stage.requireSourceRelease(owner, loan);
        const b = backing(owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try requireCoreReleaseableLocked(stage, b, loan);
    }

    /// Select only the actual original uncommitted candidate. The source Core
    /// must independently prove its cold barrier and distinct held World lane;
    /// no caller-selected plan, generation, boolean or replacement is accepted.
    pub fn cancelCorePreparedForCold(stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority, loan: ?*ServicesLoan) !void {
        try stage.requireOriginalSources(owner, loan);
        const b = backing(owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        if (b.state.core_stage != stage) return error.SourceIdentityMismatch;
        const original: ?*ServicesLoan = if (b.state.services_loan) |value| @ptrCast(value) else null;
        if (loan != original) return error.SourceIdentityMismatch;
        const token = b.active orelse return error.NoPreparedPlan;
        try Prepared.cancelAfterCoreQuiescenceUnderGate(@ptrCast(token), stage, owner);
    }

    fn requireCoreReleaseableLocked(stage: *server_mod.ManagedLeasedCoreStage, b: *Backing, loan: ?*ServicesLoan) !void {
        const context = b.state;
        if (context.core_stage) |original| if (original != stage) return error.SourceIdentityMismatch;
        if (context.authority_entries != 0 or b.active != null or b.read_count != 0) return error.SourceBorrowed;
        if (loan) |original| {
            const token = servicesToken(original);
            if (token.context != context or context.services_loan != token) return error.SourceIdentityMismatch;
            try token.validate();
            if (token.calls != 0) return error.SourceBorrowed;
            if (!token.lock.tryLockExclusive()) return error.SourceBorrowed;
            defer token.lock.unlockExclusive();
        } else {
            if (context.services_loan != null) return error.SourceIdentityMismatch;
        }
    }

    pub fn attachServices(self: *StateContext, config: services_mod.Config) !*ServicesLoan {
        const context = stateBacking(self);
        const b = context.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        if (config.pbkdf2_rounds == 0 or config.password_min_len > config.password_max_len) return error.InvalidConfig;
        if (context.services_loan != null) return error.ServicesAlreadyAttached;
        if (b.active != null or context.authority_entries != 0) return error.SourceBorrowed;
        if (context.store.preparedWritesPoisoned()) return error.StorePoisoned;
        try b.requireTokenBudget();
        const services = try b.allocator.create(services_mod.Services);
        errdefer b.allocator.destroy(services);
        const loan = try b.allocator.create(ServicesLoanToken);
        errdefer b.allocator.destroy(loan);
        services.* = services_mod.Services.initWithConfig(&context.store, null, config);
        services.bound_state_context = self;
        loan.* = .{ .context = context, .services = services, .lock = &services.lock, .next = context.services_tokens };
        context.services_tokens = loan;
        context.services_loan = loan;
        b.issued_tokens += 1;
        return @ptrCast(loan);
    }
};

/// Persistent original-context loan held by the creator through actual caller
/// joins. All results are typed values or owned copies; no source pointer or
/// caller-selected callback can escape. close requires stopped admission and
/// actual caller joins, and refuses outstanding source calls/prepared plans.
pub const ServicesLoan = opaque {
    pub fn registerAccount(self: *ServicesLoan, name: []const u8, password: []const u8, scratch: []u8) !services_mod.CommandResult {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.registerAccount(name, password, scratch);
    }
    pub fn identifyAccount(self: *ServicesLoan, name: []const u8, password: []const u8) !services_mod.CommandResult {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.identifyAccount(name, password);
    }
    pub fn accountInfo(self: *ServicesLoan, name: []const u8) !services_mod.CommandResult {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.accountInfo(name);
    }
    pub fn authenticationAvailable(self: *ServicesLoan) !bool {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return services.authenticationAvailable();
    }
    pub fn webpushPut(self: *ServicesLoan, account: []const u8, blob: []const u8) !void {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.webpushPutStrict(account, blob);
    }
    pub fn webpushGetAllocStrict(self: *ServicesLoan, allocator: std.mem.Allocator, account: []const u8) !?[]u8 {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.webpushGetAllocStrict(allocator, account);
    }
    pub fn webpushPruneDeadUntil(self: *ServicesLoan, allocator: std.mem.Allocator, endpoints: []const []const u8, deadline: std.Io.Clock.Timestamp) !services_mod.Services.WebpushPruneResult {
        const loan = servicesToken(self);
        const services = try loan.begin();
        defer loan.finish();
        return try services.webpushPruneDeadUntil(allocator, endpoints, deadline);
    }
    pub fn close(self: *ServicesLoan) !void {
        const loan = servicesToken(self);
        const b = loan.context.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try loan.validate();
        if (loan.calls != 0 or loan.context.authority_entries != 0 or b.active != null or loan.context.core_stage != null) return error.SourceBorrowed;
        loan.context.services_loan = null;
        loan.released = true;
        std.crypto.secureZero(u8, std.mem.asBytes(loan.services));
        b.allocator.destroy(loan.services);
    }
};

pub const DeliveryView = struct {
    id: oper.EventId,
    signed_wire: []const u8,
    body: []const u8,
    destination: usize,
    url: []const u8,
    secret: []const u8,
};
pub const ReadBorrow = opaque {
    pub fn observe(self: *ReadBorrow) !Observation {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        return token.owner.observation();
    }
    pub fn delivery(self: *ReadBorrow, index: usize) !DeliveryView {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        const image = &token.owner.image;
        if (index >= image.count) return error.UnknownDelivery;
        const value = &image.items[index].?;
        const destination = value.destinations[value.cursor].?;
        return .{ .id = value.id, .signed_wire = value.wire, .body = value.body, .destination = value.cursor, .url = destination.url, .secret = destination.secret };
    }
    pub fn collectHistory(self: *ReadBorrow, category: ?u8, min_severity: u8, out: []history_mod.StoredEvent) !usize {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        return token.owner.history.collect(category, min_severity, out);
    }
    pub fn guardCheckpoint(self: *ReadBorrow, allocator: std.mem.Allocator) ![]u8 {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        return token.owner.guard.encodeCheckpoint(allocator);
    }
    pub fn historyCheckpoint(self: *ReadBorrow, allocator: std.mem.Allocator) ![]u8 {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        return encodeHistory(allocator, &token.owner.history);
    }
    pub fn release(self: *ReadBorrow) !void {
        const token = readToken(self);
        token.owner.gate.lockExclusive();
        defer token.owner.gate.unlockExclusive();
        try token.validate();
        token.released = true;
        token.owner.read_count -= 1;
    }
};
pub const Prepared = opaque {
    /// Exact source placement only; this does not authenticate a World lane.
    /// The original Core uses this closed check before its terminal wrappers.
    pub fn requireOriginalCore(self: *Prepared, stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority) !void {
        const token = preparedToken(self);
        const b = token.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try token.validate();
        if (backing(owner) != b or b.state.core_stage != stage or token.transaction.world_scope == null) return error.SourceIdentityMismatch;
    }
    /// No I/O/allocator failure can publish RAM before the actual WAL sync.
    /// A sync-ambiguous candidate stays source-owned until explicit abort/close.
    pub fn commit(self: *Prepared) !?oper.EventId {
        const token = preparedToken(self);
        const b = token.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try token.validate();
        try token.transaction.requireCaller();
        if (token.transaction.world_scope) |scope| try scope.requireNoActiveRegisteredChannelStage();
        if (b.state.store.preparedWritesPoisoned()) return error.StorePoisoned;
        try b.validateSource();
        if (!std.mem.eql(u8, &token.previous, &b.head_digest)) return error.PredecessorMismatch;
        try token.batch.commit();
        // All images/typed history publication were prepared before sync.
        std.mem.swap(guard_mod.Guard, &b.guard, &token.candidate.?.guard);
        b.history.publishCheckpoint(token.history_state.?);
        std.mem.swap(Image, &b.image, &token.candidate.?.image);
        b.head = token.head;
        b.head_digest = digest(&token.head_bytes);
        token.state = .committed;
        b.active = null;
        token.candidate.?.deinit(b.allocator);
        token.candidate = null;
        b.allocator.destroy(token.history_state.?);
        token.history_state = null;
        token.encoded.deinit();
        // Still under the context gate. Actual Services calls can acquire the
        // shared original mutex only after every publication above completes.
        token.transaction.releaseUnderGate();
        return token.event_id;
    }
    pub fn abort(self: *Prepared) !void {
        const token = preparedToken(self);
        const b = token.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try token.validate();
        try token.transaction.requireCaller();
        if (token.transaction.world_scope) |scope| try scope.requireNoActiveRegisteredChannelStage();
        token.batch.abort();
        token.candidate.?.deinit(b.allocator);
        token.candidate = null;
        b.allocator.destroy(token.history_state.?);
        token.history_state = null;
        token.encoded.deinit();
        token.state = .aborted;
        b.active = null;
        token.transaction.releaseUnderGate();
    }

    /// A lost original World acquisition cannot authorize commit or ordinary
    /// abort again. Only the genuine unpublished original Core may discard its
    /// exact candidate after proving cold quiescence and a distinct source lane.
    /// This never writes a successor or clears original Store poison.
    fn cancelAfterCoreQuiescenceUnderGate(self: *Prepared, stage: *server_mod.ManagedLeasedCoreStage, owner: *Authority) !void {
        const token = preparedToken(self);
        const b = token.owner;
        try token.validate();
        if (backing(owner) != b or b.state.core_stage != stage) return error.SourceIdentityMismatch;
        if (token.transaction.thread != std.Thread.getCurrentId()) return error.TransactionWrongCaller;
        const scope = token.transaction.world_scope orelse return error.CoreSourceRequired;
        const loan: ?*ServicesLoan = if (token.transaction.services) |original| @ptrCast(original) else null;
        try scope.requireColdCancellation(stage, owner, loan);
        try scope.requireNoActiveRegisteredChannelStage();
        token.batch.abort();
        token.candidate.?.deinit(b.allocator);
        token.candidate = null;
        b.allocator.destroy(token.history_state.?);
        token.history_state = null;
        token.encoded.deinit();
        token.state = .aborted;
        b.active = null;
        token.transaction.releaseAfterColdCancellationUnderGate();
    }
};

/// Stable original leased Store context. Its mutable Store never escapes.
/// Sharing it with Services requires actual World/source registration and the
/// original Services lock; an independent authority mutex is insufficient.
const State = struct {
    owner: *Backing,
    io: std.Io,
    dir: std.Io.Dir,
    directory_identity: DirectoryIdentity,
    lease: std.Io.File,
    lease_identity: lease_mod.Identity,
    store: store_mod.OroStore,
    services_loan: ?*ServicesLoanToken = null,
    services_tokens: ?*ServicesLoanToken = null,
    core_stage: ?*server_mod.ManagedLeasedCoreStage = null,
    authority_entries: usize = 0,
};
const Backing = struct {
    allocator: std.mem.Allocator,
    gate: lock_mod.RwLock = .{},
    state: *State,
    context: Context,
    config: Config,
    guard: guard_mod.Guard,
    history: History = .{},
    image: Image = .{},
    head: Head,
    head_digest: [32]u8,
    active: ?*PreparedToken = null,
    prepared_tokens: ?*PreparedToken = null,
    read_tokens: ?*ReadToken = null,
    read_count: usize = 0,
    issued_tokens: usize = 0,

    fn observation(self: *Backing) !Observation {
        // A closed dispatch call can mutate the original Store under the real
        // Services lock. Do not sample its poison scalar under an unrelated
        // gate while such a call exists. New entrants require this gate too.
        if (self.state.services_loan) |loan| if (loan.calls != 0) return error.ServiceCallActive;
        return .{ .generation = self.head.generation, .logical_store_id = self.head.store_id, .logical_store_epoch = self.head.logical_epoch, .max_accepted_hlc = self.head.max_hlc, .pending_deliveries = self.image.count, .poisoned = self.state.store.preparedWritesPoisoned() };
    }
    fn validateEvent(self: *const Backing, event: oper.SignedOperEventV2) !void {
        if (!std.mem.eql(u8, event.origin_pubkey, &self.context.origin) or
            event.origin_node != oper.originShortId(self.context.origin) or
            !std.mem.eql(u8, event.origin_server, self.context.canonical_name)) return error.OriginMismatch;
        if (oper.verifyOrigin(event) != .verified) return error.InvalidSignature;
        if (event.category >= history_mod.category_count or event.severity >= history_mod.severity_count or
            event.origin_server.len > history_mod.max_origin_len or event.message.len > history_mod.max_message_len) return error.InvalidEvent;
        _ = std.math.cast(i64, event.originTimeMs()) orelse return error.InvalidClock;
    }
    fn validateSource(self: *Backing) !void {
        if (!std.meta.eql(self.state.directory_identity, try protectedDirectory(self.state.dir))) return error.IdentityMismatch;
        const actual = try lease_mod.validateInherited(self.allocator, self.state.io, self.state.dir, self.state.store.wal_path, self.state.lease, self.state.lease_identity);
        if (!std.meta.eql(actual, self.state.lease_identity)) return error.IdentityMismatch;
        if (!std.mem.eql(u8, &self.head_digest, &digest(self.state.store.get(.props, keys[3]) orelse return error.MissingState))) return error.PredecessorMismatch;
    }
    fn writable(self: *Backing, key: *const sign.KeyPair) !void {
        try requireKey(self.context, key);
        if (self.state.store.preparedWritesPoisoned()) return error.StorePoisoned;
        if (self.active != null) return error.MutationActive;
        if (self.read_count != 0) return error.SourceBorrowed;
        try self.requireTokenBudget();
        try self.validateSource();
    }
    fn requireTokenBudget(self: *const Backing) !void {
        if (self.issued_tokens >= self.config.max_issued_tokens) return error.TokenCapacity;
    }
    fn acquireTransaction(self: *Backing) !TransactionPin {
        self.gate.lockExclusive();
        if (current_services_loan != null) {
            self.gate.unlockExclusive();
            return error.ServicesTransactionActive;
        }
        if (self.active != null) {
            self.gate.unlockExclusive();
            return error.MutationActive;
        }
        const world_scope = if (self.state.core_stage) |stage| blk: {
            const loan: ?*ServicesLoan = if (self.state.services_loan) |original| @ptrCast(original) else null;
            break :blk stage.reserveOriginalWorldScope(@ptrCast(self), loan) catch |err| {
                self.gate.unlockExclusive();
                return err;
            };
        } else null;
        const pin: TransactionPin = .{ .owner = self, .services = self.state.services_loan, .thread = std.Thread.getCurrentId(), .world_scope = world_scope };
        self.state.authority_entries = std.math.add(usize, self.state.authority_entries, 1) catch {
            if (world_scope) |scope| scope.releaseAfterTerminal();
            self.gate.unlockExclusive();
            return error.SourceCapacity;
        };
        self.gate.unlockExclusive();
        if (pin.services) |loan| loan.lock.lockExclusive();
        return pin;
    }
    fn candidate(self: *Backing) !*Candidate {
        const value = try self.allocator.create(Candidate);
        errdefer self.allocator.destroy(value);
        const guard_bytes = try self.guard.encodeCheckpoint(self.allocator);
        defer self.allocator.free(guard_bytes);
        var guard = try guard_mod.Guard.decodeCheckpoint(self.allocator, self.config.replay, guard_bytes);
        errdefer guard.deinit();
        const history_bytes = try encodeHistory(self.allocator, &self.history);
        defer self.allocator.free(history_bytes);
        const history_state = History.restoreHelixCheckpoint(history_bytes) orelse return error.InvalidHistory;
        var image = try self.image.clone(self.allocator);
        errdefer image.deinit(self.allocator);
        value.* = .{ .guard = guard, .image = image, .max_hlc = self.head.max_hlc };
        value.history.publishCheckpoint(&history_state);
        return value;
    }
    fn prepare(self: *Backing, candidate_: *Candidate, key: *const sign.KeyPair, event_id: ?oper.EventId, transaction: TransactionPin) !*Prepared {
        const token = try self.allocator.create(PreparedToken);
        errdefer self.allocator.destroy(token);
        var encoded = try Encoded.fromCandidate(self.allocator, candidate_);
        errdefer encoded.deinit();
        const state = try self.allocator.create(History.CheckpointState);
        errdefer self.allocator.destroy(state);
        state.* = History.restoreHelixCheckpoint(encoded.history) orelse return error.InvalidHistory;
        var head = self.head;
        head.generation = try std.math.add(u64, head.generation, 1);
        head.previous = self.head_digest;
        head.max_hlc = candidate_.max_hlc;
        head.images = .{ digest(encoded.guard), digest(encoded.history), digest(encoded.deliveries) };
        const bytes = try head.encode(key);
        const mutations = encoded.mutations(&bytes);
        var batch = try self.state.store.prepareBatch(&mutations);
        errdefer batch.abort();
        token.* = .{ .owner = self, .next = self.prepared_tokens, .candidate = candidate_, .encoded = encoded, .history_state = state, .head = head, .head_bytes = bytes, .previous = self.head_digest, .batch = batch, .event_id = event_id, .transaction = transaction };
        self.prepared_tokens = token;
        self.active = token;
        self.issued_tokens += 1;
        return @ptrCast(token);
    }
};
const Candidate = struct {
    guard: guard_mod.Guard,
    history: History = .{},
    image: Image,
    max_hlc: u64,
    fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
        self.guard.deinit();
        self.image.deinit(allocator);
        allocator.destroy(self);
    }
};
const ReadToken = struct {
    owner: *Backing,
    next: ?*ReadToken,
    released: bool = false,
    fn validate(self: *const ReadToken) !void {
        if (self.released) return error.ConsumedLoan;
    }
};
const PreparedToken = struct {
    owner: *Backing,
    next: ?*PreparedToken,
    state: enum { prepared, committed, aborted } = .prepared,
    candidate: ?*Candidate,
    encoded: Encoded,
    history_state: ?*History.CheckpointState,
    head: Head,
    head_bytes: [head_len]u8,
    previous: [32]u8,
    batch: store_mod.PreparedBatch,
    event_id: ?oper.EventId,
    transaction: TransactionPin,
    fn validate(self: *const PreparedToken) !void {
        if (self.state != .prepared or self.owner.active != self) return error.ConsumedPlan;
    }
};
const TransactionPin = struct {
    owner: *Backing,
    services: ?*ServicesLoanToken,
    thread: std.Thread.Id,
    world_scope: ?*server_mod.ManagedLeasedWorldScope = null,
    fn requireCaller(self: TransactionPin) !void {
        if (self.thread != std.Thread.getCurrentId()) return error.TransactionWrongCaller;
        if (self.world_scope) |scope| {
            const stage = self.owner.state.core_stage orelse return error.SourceIdentityMismatch;
            const loan: ?*ServicesLoan = if (self.services) |original| @ptrCast(original) else null;
            try scope.requireOriginalAcquisition(stage, @ptrCast(self.owner), loan);
        }
    }
    fn releaseUnderGate(self: TransactionPin) void {
        if (self.world_scope) |scope| scope.releaseAfterTerminal();
        self.owner.state.authority_entries -= 1;
        if (self.services) |loan| loan.lock.unlockExclusive();
    }
    fn releaseAfterColdCancellationUnderGate(self: TransactionPin) void {
        self.world_scope.?.releaseAfterColdCancellation();
        self.owner.state.authority_entries -= 1;
        if (self.services) |loan| loan.lock.unlockExclusive();
    }
    fn release(self: TransactionPin) void {
        self.owner.gate.lockExclusive();
        defer self.owner.gate.unlockExclusive();
        self.releaseUnderGate();
    }
};
const ServicesLoanToken = struct {
    context: *State,
    services: *services_mod.Services,
    lock: *lock_mod.RwLock,
    next: ?*ServicesLoanToken,
    released: bool = false,
    calls: usize = 0,
    test_entered: if (builtin.is_test) ?*std.Io.Event else void = if (builtin.is_test) null else {},
    fn validate(self: *const ServicesLoanToken) !void {
        if (self.released or self.context.services_loan != self) return error.ConsumedLoan;
        if (self.services.bound_state_context != @as(*StateContext, @ptrCast(self.context)) or self.services.store != &self.context.store or self.lock != &self.services.lock) return error.SourceIdentityMismatch;
    }
    fn begin(self: *ServicesLoanToken) !*services_mod.Services {
        const b = self.context.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate();
        if (self.context.core_stage) |stage| try stage.requireOriginalWorldWrite(@ptrCast(b), @ptrCast(self));
        if (current_services_loan != null) return error.ServicesCallReentered;
        if (b.active) |plan| if (plan.transaction.services == self and plan.transaction.thread == std.Thread.getCurrentId()) return error.ServicesTransactionActive;
        self.calls = try std.math.add(usize, self.calls, 1);
        current_services_loan = self;
        if (builtin.is_test) if (self.test_entered) |event| event.set(self.context.io);
        return self.services;
    }
    fn finish(self: *ServicesLoanToken) void {
        const b = self.context.owner;
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        std.debug.assert(current_services_loan == self);
        current_services_loan = null;
        self.calls -= 1;
    }
};
// Conservative source-entered named-call scope, not a lock/readiness receipt.
// Actual locking is performed by the original private Services method itself.
threadlocal var current_services_loan: ?*ServicesLoanToken = null;
fn stateBacking(context: *StateContext) *State {
    return @ptrCast(@alignCast(context));
}
fn servicesToken(loan: *ServicesLoan) *ServicesLoanToken {
    return @ptrCast(@alignCast(loan));
}
fn backing(owner: *Authority) *Backing {
    return @ptrCast(@alignCast(owner));
}
fn readToken(owner: *ReadBorrow) *ReadToken {
    return @ptrCast(@alignCast(owner));
}
fn preparedToken(owner: *Prepared) *PreparedToken {
    return @ptrCast(@alignCast(owner));
}

const Destination = struct {
    url: []u8,
    secret: []u8,
    fn deinit(self: *Destination, a: std.mem.Allocator) void {
        a.free(self.url);
        std.crypto.secureZero(u8, self.secret);
        a.free(self.secret);
    }
};
const Delivery = struct {
    id: oper.EventId,
    wire: []u8,
    body: []u8,
    destinations: [max_destinations]?Destination = @splat(null),
    destination_count: usize = 0,
    cursor: usize = 0,
    fn deinit(self: *Delivery, a: std.mem.Allocator) void {
        a.free(self.wire);
        a.free(self.body);
        for (&self.destinations) |*item| if (item.*) |*destination| destination.deinit(a);
        self.* = undefined;
    }
    fn fromEvent(a: std.mem.Allocator, event: oper.SignedOperEventV2, destinations: []const DestinationInput) !Delivery {
        const wire = try a.alloc(u8, try oper.encodedLenV2(event));
        errdefer a.free(wire);
        _ = try oper.encodeV2(event, wire);
        const body = try renderBody(a, event);
        errdefer a.free(body);
        var result: Delivery = .{ .id = try oper.eventId(event), .wire = wire, .body = body };
        errdefer for (&result.destinations) |*item| if (item.*) |*destination| destination.deinit(a);
        for (destinations) |input| {
            try validateDestination(input);
            for (result.destinations[0..result.destination_count]) |prior| if (std.mem.eql(u8, prior.?.url, input.url)) return error.DuplicateDestination;
            const url = try a.dupe(u8, input.url);
            errdefer a.free(url);
            const secret = try a.dupe(u8, input.secret);
            result.destinations[result.destination_count] = .{ .url = url, .secret = secret };
            result.destination_count += 1;
        }
        return result;
    }
};
const Image = struct {
    items: [max_deliveries]?Delivery = @splat(null),
    count: usize = 0,
    fn deinit(self: *Image, a: std.mem.Allocator) void {
        for (self.items[0..self.count]) |*item| item.*.?.deinit(a);
        self.* = .{};
    }
    fn clone(self: *const Image, a: std.mem.Allocator) !Image {
        const bytes = try self.encode(a);
        defer {
            std.crypto.secureZero(u8, bytes);
            a.free(bytes);
        }
        return decodeImage(a, bytes);
    }
    fn encode(self: *const Image, a: std.mem.Allocator) ![]u8 {
        return self.encodeAllocating(a) catch |err| switch (err) {
            error.WriteFailed => error.OutOfMemory,
            else => err,
        };
    }
    fn encodeAllocating(self: *const Image, a: std.mem.Allocator) ![]u8 {
        var writer = std.Io.Writer.Allocating.init(a);
        errdefer {
            std.crypto.secureZero(u8, writer.written());
            writer.deinit();
        }
        try writer.writer.writeAll("ODI1");
        try writer.writer.writeByte(@intCast(self.count));
        for (self.items[0..self.count]) |item| {
            const delivery = item.?;
            try writeBytes(&writer.writer, delivery.wire);
            try writeBytes(&writer.writer, delivery.body);
            try writer.writer.writeByte(@intCast(delivery.destination_count));
            try writer.writer.writeByte(@intCast(delivery.cursor));
            for (delivery.destinations[0..delivery.destination_count]) |destination| {
                try writeBytes(&writer.writer, destination.?.url);
                try writeBytes(&writer.writer, destination.?.secret);
            }
        }
        return writer.toOwnedSlice();
    }
};
const Encoded = struct {
    a: std.mem.Allocator,
    guard: []u8,
    history: []u8,
    deliveries: []u8,
    fn fromCandidate(a: std.mem.Allocator, candidate: *Candidate) !Encoded {
        const guard = try candidate.guard.encodeCheckpoint(a);
        errdefer a.free(guard);
        const history = try encodeHistory(a, &candidate.history);
        errdefer a.free(history);
        const deliveries = try candidate.image.encode(a);
        return .{ .a = a, .guard = guard, .history = history, .deliveries = deliveries };
    }
    fn deinit(self: *Encoded) void {
        self.a.free(self.guard);
        self.a.free(self.history);
        std.crypto.secureZero(u8, self.deliveries);
        self.a.free(self.deliveries);
    }
    fn mutations(self: *const Encoded, head: *const [head_len]u8) [4]store_mod.BatchMutation {
        return .{
            .{ .family = .props, .kind = .put, .key = keys[0], .value = self.guard },
            .{ .family = .props, .kind = .put, .key = keys[1], .value = self.history },
            .{ .family = .props, .kind = .put, .key = keys[2], .value = self.deliveries },
            .{ .family = .props, .kind = .put, .key = keys[3], .value = head },
        };
    }
};
const Head = struct {
    origin: sign.PublicKey,
    config_digest: [32]u8,
    name_digest: [32]u8,
    store_id: [16]u8,
    logical_epoch: [16]u8,
    generation: u64,
    max_hlc: u64,
    previous: [32]u8,
    images: [3][32]u8,
    fn encode(self: Head, key: *const sign.KeyPair) ![head_len]u8 {
        if (!std.mem.eql(u8, &self.origin, &key.public_key)) return error.ContextMismatch;
        var out: [head_len]u8 = undefined;
        @memcpy(out[0..4], "ODH1");
        out[4] = 1;
        var index: usize = 5;
        for ([_][]const u8{ &self.origin, &self.config_digest, &self.name_digest, &self.store_id, &self.logical_epoch }) |field| {
            @memcpy(out[index..][0..field.len], field);
            index += field.len;
        }
        std.mem.writeInt(u64, out[index..][0..8], self.generation, .big);
        index += 8;
        std.mem.writeInt(u64, out[index..][0..8], self.max_hlc, .big);
        index += 8;
        @memcpy(out[index..][0..32], &self.previous);
        index += 32;
        for (self.images) |field| {
            @memcpy(out[index..][0..32], &field);
            index += 32;
        }
        std.debug.assert(index == head_prefix);
        @memcpy(out[head_prefix..], &try key.signCtx(head_domain, out[0..head_prefix]));
        return out;
    }
    fn decode(bytes: []const u8, context: Context) !Head {
        if (bytes.len != head_len or !std.mem.eql(u8, bytes[0..4], "ODH1") or bytes[4] != 1) return error.InvalidHead;
        if (!(try sign.verifyCtx(head_domain, bytes[0..head_prefix], bytes[head_prefix..][0..sign.signature_len].*, context.origin))) return error.InvalidSignature;
        var cursor: Cursor = .{ .bytes = bytes, .index = 5 };
        const origin = (try cursor.take(32))[0..32].*;
        const config_digest = (try cursor.take(32))[0..32].*;
        const name_digest = (try cursor.take(32))[0..32].*;
        if (!std.mem.eql(u8, &origin, &context.origin) or !std.mem.eql(u8, &config_digest, &context.config_digest) or !std.mem.eql(u8, &name_digest, &digest(context.canonical_name))) return error.ContextMismatch;
        const store_id = (try cursor.take(16))[0..16].*;
        const logical_epoch = (try cursor.take(16))[0..16].*;
        const generation = std.mem.readInt(u64, (try cursor.take(8))[0..8], .big);
        const max_hlc = std.mem.readInt(u64, (try cursor.take(8))[0..8], .big);
        const previous = (try cursor.take(32))[0..32].*;
        var images: [3][32]u8 = undefined;
        for (&images) |*field| field.* = (try cursor.take(32))[0..32].*;
        if (generation == 0 or allZero(&store_id) or allZero(&logical_epoch) or (generation == 1) != allZero(&previous)) return error.InvalidHead;
        return .{ .origin = origin, .config_digest = config_digest, .name_digest = name_digest, .store_id = store_id, .logical_epoch = logical_epoch, .generation = generation, .max_hlc = max_hlc, .previous = previous, .images = images };
    }
};

const Cursor = struct {
    bytes: []const u8,
    index: usize = 0,
    fn take(self: *Cursor, count: usize) ![]const u8 {
        if (count > self.bytes.len - self.index) return error.Truncated;
        const out = self.bytes[self.index..][0..count];
        self.index += count;
        return out;
    }
    fn byte(self: *Cursor) !u8 {
        return (try self.take(1))[0];
    }
    fn field(self: *Cursor, limit: usize) ![]const u8 {
        const count = std.mem.readInt(u32, (try self.take(4))[0..4], .big);
        if (count > limit) return error.Capacity;
        return self.take(count);
    }
};
fn writeBytes(writer: *std.Io.Writer, bytes: []const u8) !void {
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, std.math.cast(u32, bytes.len) orelse return error.Capacity, .big);
    try writer.writeAll(&count);
    try writer.writeAll(bytes);
}
fn digest(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &out, .{});
    return out;
}
fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}
fn requireKey(context: Context, key: *const sign.KeyPair) !void {
    if (!std.mem.eql(u8, &context.origin, &key.public_key) or allZero(&context.config_digest)) return error.ContextMismatch;
    if (context.canonical_name.len == 0 or context.canonical_name.len > history_mod.max_origin_len) return error.InvalidOrigin;
    for (context.canonical_name) |byte| if (byte <= 0x20 or byte >= 0x7f) return error.InvalidOrigin;
}
fn validateDestination(input: DestinationInput) !void {
    if (input.url.len == 0 or input.url.len > max_url or input.secret.len == 0 or input.secret.len > max_secret) return error.InvalidDestination;
    for (input.url) |byte| if (byte <= 0x20 or byte == 0x7f) return error.InvalidDestination;
    _ = http.parseUrl(input.url) catch return error.InvalidDestination;
}
fn quote(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    const hex = "0123456789abcdef";
    for (text) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        0...9, 11, 12, 14...31 => {
            const part = [_]u8{ '\\', 'u', '0', '0', hex[byte >> 4], hex[byte & 15] };
            try writer.writeAll(&part);
        },
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}
fn renderBody(a: std.mem.Allocator, event: oper.SignedOperEventV2) ![]u8 {
    return renderBodyAllocating(a, event) catch |err| switch (err) {
        error.WriteFailed => error.OutOfMemory,
        else => err,
    };
}
fn renderBodyAllocating(a: std.mem.Allocator, event: oper.SignedOperEventV2) ![]u8 {
    if (event.category >= history_mod.category_count or event.severity >= history_mod.severity_count) return error.InvalidEvent;
    const category: spine.EventCategory = @enumFromInt(event.category);
    const severity: spine.EventSeverity = @enumFromInt(event.severity);
    var writer = std.Io.Writer.Allocating.init(a);
    errdefer writer.deinit();
    try writer.writer.writeAll("{\"category\":");
    try quote(&writer.writer, category.code());
    try writer.writer.writeAll(",\"severity\":");
    try quote(&writer.writer, severity.token());
    try writer.writer.writeAll(",\"server\":");
    try quote(&writer.writer, event.origin_server);
    try writer.writer.writeAll(",\"message\":");
    try quote(&writer.writer, event.message);
    try writer.writer.writeByte('}');
    if (writer.written().len > max_body) return error.Capacity;
    return writer.toOwnedSlice();
}
fn encodeHistory(a: std.mem.Allocator, history: *History) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    errdefer writer.deinit();
    history.serializeInto(&writer.writer) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
        else => return err,
    };
    return writer.toOwnedSlice();
}
fn decodeImage(a: std.mem.Allocator, bytes: []const u8) !Image {
    var cursor: Cursor = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try cursor.take(4), "ODI1")) return error.InvalidImage;
    const count = try cursor.byte();
    if (count > max_deliveries) return error.Capacity;
    var image: Image = .{};
    errdefer image.deinit(a);
    for (0..count) |_| {
        const wire_bytes = try cursor.field(4096);
        const event = try oper.decodeV2(wire_bytes);
        if (oper.verifyOrigin(event) != .verified) return error.InvalidSignature;
        const body_bytes = try cursor.field(max_body);
        const canonical_body = try renderBody(a, event);
        defer a.free(canonical_body);
        if (!std.mem.eql(u8, body_bytes, canonical_body)) return error.InvalidBody;
        const destination_count = try cursor.byte();
        const progress = try cursor.byte();
        if (destination_count == 0 or destination_count > max_destinations or progress >= destination_count) return error.InvalidProgress;
        var inputs: [max_destinations]DestinationInput = undefined;
        for (inputs[0..destination_count]) |*input| {
            input.* = .{ .url = try cursor.field(max_url), .secret = try cursor.field(max_secret) };
            try validateDestination(input.*);
        }
        var delivery = try Delivery.fromEvent(a, event, inputs[0..destination_count]);
        errdefer delivery.deinit(a);
        if (!std.mem.eql(u8, delivery.wire, wire_bytes)) return error.NoncanonicalImage;
        for (image.items[0..image.count]) |prior| if (std.mem.eql(u8, &prior.?.id, &delivery.id)) return error.DuplicateDelivery;
        delivery.cursor = progress;
        image.items[image.count] = delivery;
        image.count += 1;
    }
    if (cursor.index != bytes.len) return error.TrailingBytes;
    return image;
}
fn validateRelation(a: std.mem.Allocator, context: Context, head: Head, candidate: *Candidate) !void {
    const origins = try candidate.guard.inner.orderedOriginPubkeys(a);
    defer a.free(origins);
    for (origins) |origin| if (!std.mem.eql(u8, &origin, &context.origin)) return error.PeerBindingRequired;
    if (candidate.guard.inner.origins.get(context.origin)) |origin| {
        if (origin.entries.items.len == 0 or head.max_hlc == 0 or origin.entries.items[origin.entries.items.len - 1].hlc != head.max_hlc) return error.InconsistentPackage;
    } else if (head.max_hlc != 0) return error.InconsistentPackage;
    const history_bytes = try encodeHistory(a, &candidate.history);
    defer a.free(history_bytes);
    const checkpoint = History.restoreHelixCheckpoint(history_bytes) orelse return error.InvalidHistory;
    if ((origins.len == 0) != (checkpoint.count == 0)) return error.InconsistentPackage;
    for (0..checkpoint.count) |i| {
        const event = checkpoint.items[(checkpoint.start + i) % 512];
        if (!event.has_event_id or event.category >= history_mod.category_count or event.severity >= history_mod.severity_count or
            event.ts_unix_ms < 0 or !std.mem.eql(u8, event.origin(), context.canonical_name)) return error.InvalidHistory;
        if (@as(u64, @intCast(event.ts_unix_ms)) > head.max_hlc >> 16) return error.InvalidHistory;
        if (candidate.guard.inner.origins.get(context.origin)) |origin| {
            for (origin.entries.items) |entry| {
                if (std.mem.eql(u8, &entry.relay_id, &event.event_id) and
                    @as(u64, @intCast(event.ts_unix_ms)) != entry.hlc >> 16) return error.InconsistentPackage;
            }
        }
    }
    for (candidate.image.items[0..candidate.image.count]) |delivery| {
        const event = try oper.decodeV2(delivery.?.wire);
        if (!std.mem.eql(u8, event.origin_pubkey, &context.origin) or event.origin_node != oper.originShortId(context.origin) or
            !std.mem.eql(u8, event.origin_server, context.canonical_name) or event.hlc > head.max_hlc) return error.OriginMismatch;
        // Beyond-window admission proof is the authenticated whole head/image,
        // not the guard's watermark by itself. Unseen/equivocating output is
        // impossible in this source's prepared publication and is refused.
        switch (candidate.guard.inner.probeIdentity(context.origin, event.hlc, delivery.?.id)) {
            .duplicate, .retired => {},
            else => return error.InconsistentPackage,
        }
        // History may legitimately evict an older pending output. Every
        // overlap, however, must describe the exact same signed event; a
        // valid signed head cannot excuse contradictory typed source rows.
        for (0..checkpoint.count) |i| {
            const stored = checkpoint.items[(checkpoint.start + i) % 512];
            if (!std.mem.eql(u8, &stored.event_id, &delivery.?.id)) continue;
            if (stored.category != event.category or stored.severity != event.severity or
                stored.ts_unix_ms != (std.math.cast(i64, event.originTimeMs()) orelse return error.InvalidClock) or
                !std.mem.eql(u8, stored.origin(), event.origin_server) or
                !std.mem.eql(u8, stored.message(), event.message)) return error.InconsistentPackage;
        }
    }
    if (checkpoint.count == 0 and (head.max_hlc != 0 or candidate.image.count != 0)) return error.InconsistentPackage;
}
fn restoreCandidate(a: std.mem.Allocator, store: *const store_mod.OroStore, context: Context, config: Config) !struct { candidate: *Candidate, head: Head, head_digest: [32]u8 } {
    const head_bytes = store.get(.props, keys[3]) orelse return error.MissingState;
    const head = try Head.decode(head_bytes, context);
    const rows = [_][]const u8{
        store.get(.props, keys[0]) orelse return error.MissingState,
        store.get(.props, keys[1]) orelse return error.MissingState,
        store.get(.props, keys[2]) orelse return error.MissingState,
    };
    for (rows, head.images) |row, expected| if (!std.mem.eql(u8, &expected, &digest(row))) return error.ImageMismatch;
    const value = try a.create(Candidate);
    errdefer a.destroy(value);
    var guard = try guard_mod.Guard.decodeCheckpoint(a, config.replay, rows[0]);
    errdefer guard.deinit();
    const history = History.restoreHelixCheckpoint(rows[1]) orelse return error.InvalidHistory;
    var image = try decodeImage(a, rows[2]);
    errdefer image.deinit(a);
    value.* = .{ .guard = guard, .image = image, .max_hlc = head.max_hlc };
    value.history.publishCheckpoint(&history);
    try validateRelation(a, context, head, value);
    return .{ .candidate = value, .head = head, .head_digest = digest(head_bytes) };
}

const DirectoryIdentity = struct { device: u64, inode: u64, inode_high: u64 = 0 };
// Native handle observation precedes every creation/write. Store's atomic
// files may use default modes; the held, exact private directory protects
// secrets before those bytes exist. This leaf does not claim every snapshot
// has a private file mode on POSIX.
fn protectedDirectory(dir: std.Io.Dir) !DirectoryIdentity {
    const posix = std.posix;
    if (comptime builtin.os.tag == .windows) {
        const identity = try os_runtime.requirePrivateDirectoryHandleWindows(dir);
        return .{ .device = identity.volume_serial, .inode = identity.file_id_low, .inode_high = identity.file_id_high };
    } else if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        while (true) switch (linux.errno(linux.statx(dir.handle, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .INO = true }, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if (!stat.mask.TYPE or !stat.mask.MODE or !stat.mask.UID or !stat.mask.INO or (stat.mode & posix.S.IFMT) != posix.S.IFDIR or
            stat.mode & 0o7777 != 0o700 or stat.uid != linux.geteuid()) return error.UnprotectedDirectory;
        return .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino };
    } else if (comptime builtin.os.tag == .openbsd) {
        var stat: posix.Stat = undefined;
        while (true) switch (posix.errno(posix.system.fstat(dir.handle, &stat))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.StatFailed,
        };
        if ((stat.mode & posix.S.IFMT) != posix.S.IFDIR or stat.mode & 0o7777 != 0o700 or stat.uid != posix.system.geteuid()) return error.UnprotectedDirectory;
        return .{ .device = @as(@Int(.unsigned, @bitSizeOf(@TypeOf(stat.dev))), @bitCast(stat.dev)), .inode = @intCast(stat.ino) };
    } else return error.Unsupported;
}

test "delivery authority: Windows held private directory validates exact ACL and full identity" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const first = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "first");
    defer first.close(std.testing.io);
    const second = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "second");
    defer second.close(std.testing.io);
    const first_identity = try protectedDirectory(first);
    const duplicate = try first.openDir(std.testing.io, ".", .{});
    defer duplicate.close(std.testing.io);
    try std.testing.expectEqualDeep(first_identity, try protectedDirectory(duplicate));
    try std.testing.expect(!std.meta.eql(first_identity, try protectedDirectory(second)));
    var changed_high = first_identity;
    changed_high.inode_high ^= 1;
    try std.testing.expect(!std.meta.eql(first_identity, changed_high));

    try tmp.dir.rename("first", tmp.dir, "moved", std.testing.io);
    const replacement = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "first");
    defer replacement.close(std.testing.io);
    try std.testing.expectEqualDeep(first_identity, try protectedDirectory(first));
    try std.testing.expect(!std.meta.eql(first_identity, try protectedDirectory(replacement)));
    const named = try tmp.dir.openDir(std.testing.io, "first", .{});
    defer named.close(std.testing.io);
    try std.testing.expectEqualDeep(try protectedDirectory(replacement), try protectedDirectory(named));

    const regular = try tmp.dir.createFile(std.testing.io, "regular", .{});
    defer regular.close(std.testing.io);
    try std.testing.expectError(error.InsecurePermissions, protectedDirectory(.{ .handle = regular.handle }));
    try tmp.dir.createDir(std.testing.io, "ordinary", .default_dir);
    const ordinary = try tmp.dir.openDir(std.testing.io, "ordinary", .{});
    defer ordinary.close(std.testing.io);
    try std.testing.expectError(error.InsecurePermissions, protectedDirectory(ordinary));
}
fn validateName(name: []const u8) !void {
    if (name.len == 0 or name.len > 128 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidName;
    for (name) |byte| if (byte == '/' or byte == '\\' or byte <= 0x20 or byte >= 0x7f or (builtin.os.tag == .windows and byte == ':')) return error.InvalidName;
}
fn existingNamespace(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8) !bool {
    const snapshot = try std.mem.concat(a, u8, &.{ name, ".snap" });
    defer a.free(snapshot);
    for ([_][]const u8{ name, snapshot }) |path| {
        if (store_mod.openColdExisting(io, dir, path, .read_only)) |file| {
            file.close(io);
            return true;
        } else |err| if (err != error.FileNotFound) return err;
    }
    return false;
}
fn acquireLease(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, cold: bool) !std.Io.File {
    try validateName(name);
    const path = try std.mem.concat(a, u8, &.{ name, ".lock" });
    defer a.free(path);
    const file = if (cold)
        try store_mod.openColdExisting(io, dir, path, .read_write)
    else if (comptime builtin.os.tag == .windows)
        dir.createFile(io, path, .{ .read = true, .truncate = false, .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => try store_mod.openColdExisting(io, dir, path, .read_write),
            else => return err,
        }
    else
        dir.createFile(io, path, .{ .read = true, .truncate = false, .exclusive = true, .permissions = .fromMode(0o600) }) catch |err| switch (err) {
            error.PathAlreadyExists => try store_mod.openColdExisting(io, dir, path, .read_write),
            else => return err,
        };
    errdefer file.close(io);
    const identity = try lease_mod.statRegular(file.handle);
    if (comptime builtin.os.tag == .windows) {
        // A private parent must never bless a lock file moved in with a broad
        // ACL. Reject it before either cold custody or a marker write.
        try os_runtime.requireInheritedPrivateFileWindows(file);
        if (!try file.tryLock(io, .exclusive)) return error.WouldBlock;
        // Reopen the configured path without following a reparse point. The
        // marker is written only after full 128-bit identity and path agree.
        const configured = try store_mod.openColdExisting(io, dir, path, .read_only);
        defer configured.close(io);
        if (!std.meta.eql(identity, try lease_mod.statRegular(configured.handle))) return error.IdentityMismatch;
        if (cold) {
            // The locked byte is required as local custody proof. EOF is not
            // evidence of ownership, and a cold open never repairs the file.
            _ = try lease_mod.validateInherited(a, io, dir, name, file, identity);
        } else {
            if ((try file.stat(io)).size == 0) {
                try file.writePositionalAll(io, "L", 0);
                try file.sync(io);
            }
            _ = try lease_mod.validateInherited(a, io, dir, name, file, identity);
        }
    } else {
        try lease_mod.reaffirmExclusive(file.handle);
        _ = try lease_mod.validateInherited(a, io, dir, name, file, identity);
    }
    return file;
}

const WindowsLeaseTest = if (builtin.os.tag == .windows) struct {
    extern "kernel32" fn CreateHardLinkW(new_name: [*:0]const u16, existing_name: [*:0]const u16, security: ?*anyopaque) callconv(.winapi) i32;
} else struct {};

test "delivery authority Windows local cold lease never creates or repairs a marker" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    try std.testing.expectError(error.FileNotFound, acquireLease(std.testing.allocator, std.testing.io, private, "cold.wal", true));
    try std.testing.expectError(error.FileNotFound, store_mod.openColdExisting(std.testing.io, private, "cold.wal.lock", .read_only));
    const empty = try private.createFile(std.testing.io, "cold.wal.lock", .{ .read = true });
    defer empty.close(std.testing.io);
    try std.testing.expectError(error.LockFailed, acquireLease(std.testing.allocator, std.testing.io, private, "cold.wal", true));
    try std.testing.expectEqual(@as(u64, 0), (try empty.stat(std.testing.io)).size);
    const provisioned = try acquireLease(std.testing.allocator, std.testing.io, private, "cold.wal", false);
    defer provisioned.close(std.testing.io);
    try std.testing.expectEqual(@as(u64, 1), (try provisioned.stat(std.testing.io)).size);
}

test "delivery authority Windows local lease contention and cold marker preservation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    {
        const existing = try private.createFile(std.testing.io, "kept.wal.lock", .{ .read = true });
        defer existing.close(std.testing.io);
        try existing.writePositionalAll(std.testing.io, "Q", 0);
    }
    {
        const owner = try acquireLease(std.testing.allocator, std.testing.io, private, "kept.wal", false);
        defer owner.close(std.testing.io);
        var byte: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try owner.readPositionalAll(std.testing.io, &byte, 0));
        try std.testing.expectEqual(@as(u8, 'Q'), byte[0]);
        try std.testing.expectError(error.WouldBlock, acquireLease(std.testing.allocator, std.testing.io, private, "kept.wal", true));
        try std.testing.expectError(error.WouldBlock, acquireLease(std.testing.allocator, std.testing.io, private, "kept.wal", false));
        try std.testing.expectEqual(@as(u64, 1), (try owner.stat(std.testing.io)).size);
    }
    const cold = try acquireLease(std.testing.allocator, std.testing.io, private, "kept.wal", true);
    defer cold.close(std.testing.io);
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try cold.readPositionalAll(std.testing.io, &byte, 0));
    try std.testing.expectEqual(@as(u8, 'Q'), byte[0]);
    try std.testing.expectEqual(@as(u64, 1), (try cold.stat(std.testing.io)).size);
}

test "delivery authority Windows local lease rejects wrong path type hardlink and ADS" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const owner = try acquireLease(std.testing.allocator, std.testing.io, private, "good.wal", false);
    defer owner.close(std.testing.io);
    const identity = try lease_mod.statRegular(owner.handle);
    try std.testing.expectError(error.FileNotFound, lease_mod.validateInherited(std.testing.allocator, std.testing.io, private, "missing.wal", owner, identity));
    const other = try acquireLease(std.testing.allocator, std.testing.io, private, "other.wal", false);
    defer other.close(std.testing.io);
    try std.testing.expectError(error.IdentityMismatch, lease_mod.validateInherited(std.testing.allocator, std.testing.io, private, "other.wal", owner, identity));
    var wrong = identity;
    wrong.inode_high ^= 1;
    try std.testing.expectError(error.IdentityMismatch, lease_mod.validateInherited(std.testing.allocator, std.testing.io, private, "good.wal", owner, wrong));
    try private.createDir(std.testing.io, "folder.wal.lock", .default_dir);
    try std.testing.expectError(error.NotRegular, acquireLease(std.testing.allocator, std.testing.io, private, "folder.wal", true));
    try std.testing.expectError(error.InvalidName, acquireLease(std.testing.allocator, std.testing.io, private, "good.wal:stream", false));
    try std.testing.expectError(error.InvalidName, acquireLease(std.testing.allocator, std.testing.io, private, "good.wal:stream", true));

    const target = try private.createFile(std.testing.io, "target.wal.lock", .{ .read = true });
    defer target.close(std.testing.io);
    const target_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/private/target.wal.lock", .{&tmp.sub_path});
    defer std.testing.allocator.free(target_path);
    const alias_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/private/alias.wal.lock", .{&tmp.sub_path});
    defer std.testing.allocator.free(alias_path);
    const target_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, target_path);
    defer std.testing.allocator.free(target_w);
    const alias_w = try std.unicode.utf8ToUtf16LeAllocZ(std.testing.allocator, alias_path);
    defer std.testing.allocator.free(alias_w);
    try std.testing.expect(WindowsLeaseTest.CreateHardLinkW(alias_w.ptr, target_w.ptr, null) != 0);
    try std.testing.expectError(error.NotRegular, acquireLease(std.testing.allocator, std.testing.io, private, "alias.wal", false));
    try std.testing.expectEqual(@as(u64, 0), (try target.stat(std.testing.io)).size);
}

test "delivery authority Windows local lease rejects configured path rebind" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const owner = try acquireLease(std.testing.allocator, std.testing.io, private, "held.wal", false);
    defer owner.close(std.testing.io);
    const identity = try lease_mod.statRegular(owner.handle);
    try private.rename("held.wal.lock", private, "moved.wal.lock", std.testing.io);
    try std.testing.expectError(error.FileNotFound, lease_mod.validateInherited(std.testing.allocator, std.testing.io, private, "held.wal", owner, identity));
    const replacement = try private.createFile(std.testing.io, "held.wal.lock", .{ .read = true });
    defer replacement.close(std.testing.io);
    try replacement.writePositionalAll(std.testing.io, "R", 0);
    try std.testing.expectError(error.IdentityMismatch, lease_mod.validateInherited(std.testing.allocator, std.testing.io, private, "held.wal", owner, identity));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try owner.readPositionalAll(std.testing.io, &byte, 0));
    try std.testing.expectEqual(@as(u8, 'L'), byte[0]);
}

test "delivery authority Windows local lease refuses symlink before marker write" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    const target = try private.createFile(std.testing.io, "target.wal.lock", .{ .read = true });
    defer target.close(std.testing.io);
    private.symLink(std.testing.io, "target.wal.lock", "alias.wal.lock", .{}) catch |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    if (acquireLease(std.testing.allocator, std.testing.io, private, "alias.wal", false)) |unexpected| {
        unexpected.close(std.testing.io);
        return error.TestUnexpectedResult;
    } else |_| {}
    try std.testing.expectEqual(@as(u64, 0), (try target.stat(std.testing.io)).size);
}

test "delivery authority Windows local lease rejects broad ACL before any marker mutation" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    for ([_]struct { name: []const u8, cold: bool, bytes: []const u8 }{
        .{ .name = "provision.wal", .cold = false, .bytes = "" },
        .{ .name = "cold.wal", .cold = true, .bytes = "Q" },
    }) |scenario| {
        const lock_name = try std.mem.concat(std.testing.allocator, u8, &.{ scenario.name, ".lock" });
        defer std.testing.allocator.free(lock_name);
        {
            const broad = try tmp.dir.createFile(std.testing.io, lock_name, .{ .read = true });
            defer broad.close(std.testing.io);
            if (scenario.bytes.len != 0) try broad.writePositionalAll(std.testing.io, scenario.bytes, 0);
        }
        try tmp.dir.rename(lock_name, private, lock_name, std.testing.io);
        try std.testing.expectError(error.InsecurePermissions, acquireLease(std.testing.allocator, std.testing.io, private, scenario.name, scenario.cold));
        const unchanged = try private.readFileAlloc(std.testing.io, lock_name, std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualSlices(u8, scenario.bytes, unchanged);
    }
}
fn create(a: std.mem.Allocator, io: std.Io, input_dir: std.Io.Dir, name: []const u8, input_context: Context, key: *const sign.KeyPair, config: Config, cold: bool) !*Authority {
    if (config.max_issued_tokens == 0) return error.InvalidConfig;
    try requireKey(input_context, key);
    try validateName(name);
    _ = try protectedDirectory(input_dir);
    const dir = try input_dir.openDir(io, ".", .{});
    errdefer dir.close(io);
    const directory_identity = try protectedDirectory(dir);
    if (!cold and try existingNamespace(a, io, dir, name)) return error.AlreadyInitialized;
    const lease = try acquireLease(a, io, dir, name, cold);
    errdefer lease.close(io);
    const lease_identity = try lease_mod.statRegular(lease.handle);
    if (!cold and try existingNamespace(a, io, dir, name)) return error.AlreadyInitialized;
    const b = try a.create(Backing);
    errdefer a.destroy(b);
    const context_owner = try a.create(State);
    errdefer a.destroy(context_owner);
    const origin_name = try a.dupe(u8, input_context.canonical_name);
    errdefer a.free(origin_name);
    var context = input_context;
    context.canonical_name = origin_name;
    if (cold) {
        var recovery = try store_mod.ColdRecoveryStage.open(a, io, dir, name, lease, config.storage);
        defer recovery.deinit();
        const old = try restoreCandidate(a, recovery.view(), context, config);
        errdefer old.candidate.deinit(a);
        var encoded = try Encoded.fromCandidate(a, old.candidate);
        defer encoded.deinit();
        const history = History.restoreHelixCheckpoint(encoded.history) orelse return error.InvalidHistory;
        var head = old.head;
        head.generation = try std.math.add(u64, head.generation, 1);
        head.previous = old.head_digest;
        head.images = .{ digest(encoded.guard), digest(encoded.history), digest(encoded.deliveries) };
        const head_bytes = try head.encode(key);
        const mutations = encoded.mutations(&head_bytes);
        // Windows publishes an already-synced complete successor epoch. The
        // ordinary append lane remains unavailable there; refuse an unknown
        // tail rather than authorize an incomplete application cut.
        var batch = if (comptime builtin.os.tag == .windows)
            try recovery.prepareCompleteBatch(&mutations)
        else
            try recovery.prepareBatch(&mutations);
        defer batch.abort();
        if (!std.meta.eql(directory_identity, try protectedDirectory(dir))) return error.IdentityMismatch;
        try recovery.validate();
        try batch.commit();
        const store = recovery.takeCommittedStore();
        // Source fields move only while unpublished and before any borrowed
        // Services/graph can exist. The final Store address is b.state.store.
        context_owner.* = .{ .owner = b, .io = io, .dir = dir, .directory_identity = directory_identity, .lease = lease, .lease_identity = lease_identity, .store = store };
        b.* = .{ .allocator = a, .state = context_owner, .context = context, .config = config, .guard = old.candidate.guard, .image = old.candidate.image, .head = head, .head_digest = digest(&head_bytes) };
        b.history.publishCheckpoint(&history);
        a.destroy(old.candidate);
    } else {
        var provisioning = try store_mod.FirstProvisionStage.init(a, io, dir, name, lease, config.storage);
        defer provisioning.deinit();
        const candidate = try a.create(Candidate);
        errdefer a.destroy(candidate);
        var guard = try guard_mod.Guard.init(a, config.replay);
        errdefer guard.deinit();
        candidate.* = .{ .guard = guard, .image = .{}, .max_hlc = 0 };
        var encoded = try Encoded.fromCandidate(a, candidate);
        defer encoded.deinit();
        var store_id: [16]u8 = undefined;
        io.random(&store_id);
        var logical_epoch: [16]u8 = undefined;
        io.random(&logical_epoch);
        if (allZero(&store_id) or allZero(&logical_epoch)) return error.InvalidIdentity;
        const head: Head = .{ .origin = context.origin, .config_digest = context.config_digest, .name_digest = digest(context.canonical_name), .store_id = store_id, .logical_epoch = logical_epoch, .generation = 1, .max_hlc = 0, .previous = @splat(0), .images = .{ digest(encoded.guard), digest(encoded.history), digest(encoded.deliveries) } };
        const head_bytes = try head.encode(key);
        const mutations = encoded.mutations(&head_bytes);
        try provisioning.prepareBatch(&mutations);
        if (!std.meta.eql(directory_identity, try protectedDirectory(dir))) return error.IdentityMismatch;
        try provisioning.commit();
        const store = provisioning.takeCommittedStore();
        context_owner.* = .{ .owner = b, .io = io, .dir = dir, .directory_identity = directory_identity, .lease = lease, .lease_identity = lease_identity, .store = store };
        b.* = .{ .allocator = a, .state = context_owner, .context = context, .config = config, .guard = guard, .image = .{}, .head = head, .head_digest = digest(&head_bytes) };
        a.destroy(candidate);
    }
    return @ptrCast(b);
}
fn destroy(b: *Backing) void {
    const a = b.allocator;
    var services = b.state.services_tokens;
    while (services) |token| {
        services = token.next;
        a.destroy(token);
    }
    b.guard.deinit();
    b.image.deinit(a);
    b.state.store.deinit();
    b.state.lease.close(b.state.io);
    b.state.dir.close(b.state.io);
    a.destroy(b.state);
    a.free(b.context.canonical_name);
    var read = b.read_tokens;
    while (read) |token| {
        read = token.next;
        a.destroy(token);
    }
    var plan = b.prepared_tokens;
    while (plan) |token| {
        plan = token.next;
        a.destroy(token);
    }
    a.destroy(b);
}

const test_destinations = [_]DestinationInput{
    .{ .url = "https://delivery.example.test/one", .secret = "first original secret" },
    .{ .url = "https://delivery.example.test/two", .secret = "second original secret" },
};
fn testContext(key: *const sign.KeyPair) Context {
    return .{ .origin = key.public_key, .config_digest = @splat(41), .canonical_name = "node.example.test" };
}
const TestEvent = struct {
    public_key: sign.PublicKey,
    signature: sign.Signature,
    hlc: u64,
    fn init(key: *const sign.KeyPair, hlc: u64) !TestEvent {
        var result: TestEvent = .{ .public_key = key.public_key, .signature = undefined, .hlc = hlc };
        var signed_event = result.event();
        try oper.stampOrigin(&signed_event, key, &result.public_key, &result.signature);
        return result;
    }
    fn event(self: *const TestEvent) oper.SignedOperEventV2 {
        return .{ .category = @intFromEnum(spine.EventCategory.service), .severity = @intFromEnum(spine.EventSeverity.warn), .origin_node = oper.originShortId(self.public_key), .hlc = self.hlc, .origin_server = "node.example.test", .subject = "retained source output", .message = "exact original \"message\"", .origin_pubkey = &self.public_key, .origin_sig = &self.signature };
    }
};
fn testDirectory(dir: std.Io.Dir) !void {
    // `Permissions.fromMode` does not exist on Windows; callers skip via this.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    try testDirectoryPermissions(dir, .fromMode(0o700));
}
fn testDirectoryPermissions(dir: std.Io.Dir, permissions: std.Io.File.Permissions) !void {
    // Linux tmpDir's original handle is O_PATH; fchmod requires a genuine
    // readable directory descriptor. Keep the original directory identity.
    const owned = try dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer owned.close(std.testing.io);
    try owned.setPermissions(std.testing.io, permissions);
}
fn testCommit(owner: *Authority, event: *const TestEvent, outputs: []const DestinationInput, key: *const sign.KeyPair) !oper.EventId {
    const plan = try owner.prepareEvent(event.event(), outputs, 1000, key);
    return (try plan.commit()) orelse return error.ExpectedEventId;
}
const TestCut = struct {
    rows: [4][]u8,
    guard: []u8,
    history: []u8,
    wal: []u8,
    generation: u64,
    sequence: u64,
    wal_offset: u64,
    fn capture(owner: *Authority) !TestCut {
        const a = std.testing.allocator;
        const b = backing(owner);
        var rows: [4][]u8 = undefined;
        var count: usize = 0;
        errdefer for (rows[0..count]) |row| a.free(row);
        for (keys, &rows) |key, *row| {
            row.* = try a.dupe(u8, b.state.store.get(.props, key).?);
            count += 1;
        }
        const guard = try b.guard.encodeCheckpoint(a);
        errdefer a.free(guard);
        const history = try encodeHistory(a, &b.history);
        errdefer a.free(history);
        const wal = try b.state.dir.readFileAlloc(b.state.io, b.state.store.wal_path, a, .unlimited);
        return .{ .rows = rows, .guard = guard, .history = history, .wal = wal, .generation = b.head.generation, .sequence = b.state.store.next_seq, .wal_offset = b.state.store.wal_offset };
    }
    fn deinit(self: *TestCut) void {
        const a = std.testing.allocator;
        for (self.rows) |row| {
            std.crypto.secureZero(u8, row);
            a.free(row);
        }
        a.free(self.guard);
        a.free(self.history);
        std.crypto.secureZero(u8, self.wal);
        a.free(self.wal);
    }
    fn expectUnchanged(self: *const TestCut, owner: *Authority, wal_exact: bool) !void {
        var actual = try capture(owner);
        defer actual.deinit();
        for (self.rows, actual.rows) |left, right| try std.testing.expectEqualSlices(u8, left, right);
        try std.testing.expectEqualSlices(u8, self.guard, actual.guard);
        try std.testing.expectEqualSlices(u8, self.history, actual.history);
        try std.testing.expectEqual(self.generation, actual.generation);
        try std.testing.expectEqual(self.sequence, actual.sequence);
        try std.testing.expectEqual(self.wal_offset, actual.wal_offset);
        if (wal_exact) try std.testing.expectEqualSlices(u8, self.wal, actual.wal);
    }
};

test "delivery authority: actual leased four-row admission progress and original immutable destinations survive real cold reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(81));
    defer key.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    var original: Observation = undefined;
    const id = blk: {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "delivery.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("original source close");
        try std.testing.expectEqual(@as(u64, 5), backing(owner).state.store.next_seq);
        original = try owner.observe();
        const id = try testCommit(owner, &event, &test_destinations, &key);
        const loan = try owner.borrow();
        const output = try loan.delivery(0);
        try std.testing.expectEqualSlices(u8, &id, &output.id);
        try std.testing.expectEqualStrings(test_destinations[0].url, output.url);
        try std.testing.expectEqualStrings(test_destinations[0].secret, output.secret);
        try std.testing.expect(std.mem.indexOf(u8, output.body, "\\\"message\\\"") != null);
        try std.testing.expectError(error.SourceBorrowed, owner.prepareProgress(id, 0, &key));
        try std.testing.expectError(error.SourceBorrowed, owner.close());
        try loan.release();
        try std.testing.expectError(error.ConsumedLoan, loan.release());
        const progress = try owner.prepareProgress(id, 0, &key);
        try std.testing.expectError(error.SourceBorrowed, owner.close());
        try std.testing.expect((try progress.commit()) == null);
        try std.testing.expectError(error.ConsumedPlan, progress.commit());
        try std.testing.expectError(error.Duplicate, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
        break :blk id;
    };
    const cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "delivery.wal", testContext(&key), &key, .{});
    defer cold.close() catch @panic("cold source close");
    const observation = try cold.observe();
    try std.testing.expectEqualSlices(u8, &original.logical_store_id, &observation.logical_store_id);
    try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &observation.logical_store_epoch);
    const loan = try cold.borrow();
    const output = try loan.delivery(0);
    try std.testing.expectEqual(@as(usize, 1), output.destination);
    try std.testing.expectEqualStrings(test_destinations[1].url, output.url);
    try std.testing.expectEqualStrings(test_destinations[1].secret, output.secret);
    var events: [2]history_mod.StoredEvent = undefined;
    try std.testing.expectEqual(@as(usize, 1), try loan.collectHistory(null, 0, &events));
    try std.testing.expectEqualSlices(u8, &id, &events[0].event_id);
    try loan.release();
    const finished = try cold.prepareProgress(id, 1, &key);
    _ = try finished.commit();
    try std.testing.expectEqual(@as(usize, 0), (try cold.observe()).pending_deliveries);
}

test "delivery authority Windows private first provision and complete cold recovery retain signed delivery" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var key = try sign.KeyPair.fromSeed(@splat(81));
    defer key.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    var original: Observation = undefined;
    const id = blk: {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("Windows original source close");
        original = try owner.observe();
        const accepted = try testCommit(owner, &event, &test_destinations, &key);
        const loan = try owner.borrow();
        const output = try loan.delivery(0);
        try std.testing.expectEqualSlices(u8, &accepted, &output.id);
        try std.testing.expectEqualStrings(test_destinations[0].url, output.url);
        try std.testing.expectEqualStrings(test_destinations[0].secret, output.secret);
        try loan.release();
        break :blk accepted;
    };
    {
        const cold = try Authority.openCold(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
        defer cold.close() catch @panic("Windows cold source close");
        const observation = try cold.observe();
        try std.testing.expectEqualSlices(u8, &original.logical_store_id, &observation.logical_store_id);
        try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &observation.logical_store_epoch);
        try std.testing.expectError(error.Duplicate, cold.prepareEvent(event.event(), &test_destinations, 1000, &key));
        const loan = try cold.borrow();
        const output = try loan.delivery(0);
        try std.testing.expectEqual(@as(usize, 0), output.destination);
        try std.testing.expectEqualStrings(test_destinations[0].url, output.url);
        try loan.release();
        const progress = try cold.prepareProgress(id, 0, &key);
        _ = try progress.commit();
    }
    const restart = try Authority.openCold(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
    defer restart.close() catch @panic("Windows restart source close");
    const loan = try restart.borrow();
    const output = try loan.delivery(0);
    try std.testing.expectEqual(@as(usize, 1), output.destination);
    try std.testing.expectEqualStrings(test_destinations[1].url, output.url);
    try loan.release();
}

test "delivery authority Windows cold reopen retains compacted signed state" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var key = try sign.KeyPair.fromSeed(@splat(82));
    defer key.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    const id = blk: {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("Windows compacted source close");
        const accepted = try testCommit(owner, &event, &test_destinations, &key);
        try backing(owner).state.store.snapshotAndTruncate();
        break :blk accepted;
    };
    const cold = try Authority.openCold(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
    defer cold.close() catch @panic("Windows compacted cold source close");
    const loan = try cold.borrow();
    const output = try loan.delivery(0);
    try std.testing.expectEqualSlices(u8, &id, &output.id);
    try std.testing.expectEqualStrings(test_destinations[0].url, output.url);
    try loan.release();
    try std.testing.expectError(error.Duplicate, cold.prepareEvent(event.event(), &test_destinations, 1000, &key));
}

test "delivery authority Windows cold reopen rejects unknown WAL tail unchanged" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    defer private.close(std.testing.io);
    var key = try sign.KeyPair.fromSeed(@splat(83));
    defer key.deinit();
    {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("Windows original source close");
    }
    const wal = try store_mod.openColdExisting(std.testing.io, private, "delivery.wal", .read_write);
    const end = (try wal.stat(std.testing.io)).size;
    try wal.writePositionalAll(std.testing.io, "unknown tail", end);
    try wal.sync(std.testing.io);
    wal.close(std.testing.io);
    const before = try private.readFileAlloc(std.testing.io, "delivery.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectError(error.SnapshotCoverageMismatch, Authority.openCold(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{}));
    const after = try private.readFileAlloc(std.testing.io, "delivery.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "delivery authority Windows cold refuses permissive WAL and snapshot before reading" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    for ([_][]const u8{ "delivery.wal", "delivery.wal.snap" }) |target| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const private = try os_runtime.createPrivateDirectoryWindows(tmp.dir, "private");
        defer private.close(std.testing.io);
        var key = try sign.KeyPair.fromSeed(@splat(84));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        {
            const owner = try Authority.initialize(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{});
            defer owner.close() catch @panic("Windows original source close");
            _ = try testCommit(owner, &event, &test_destinations, &key);
            try backing(owner).state.store.snapshotAndTruncate();
        }
        const original = try private.readFileAlloc(std.testing.io, target, std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(original);
        try private.deleteFile(std.testing.io, target);
        const permissive = try private.createFile(std.testing.io, target, .{ .read = true });
        try permissive.writePositionalAll(std.testing.io, original, 0);
        try permissive.sync(std.testing.io);
        permissive.close(std.testing.io);
        try std.testing.expectError(error.InsecurePermissions, os_runtime.openExistingPrivateWindows(private, target, .verify_only));
        try std.testing.expectError(error.InsecurePermissions, Authority.openCold(std.testing.allocator, std.testing.io, private, "delivery.wal", testContext(&key), &key, .{}));
        const unchanged = try private.readFileAlloc(std.testing.io, target, std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(unchanged);
        try std.testing.expectEqualSlices(u8, original, unchanged);
    }
}

test "delivery authority: every live event staging allocation failure preserves exact source four rows and same-owner retry" {
    var failures: usize = 0;
    for (0..512) |index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(82));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "oom.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("OOM source close");
        var before = try TestCut.capture(owner);
        defer before.deinit();
        failing.fail_index = failing.alloc_index + index;
        const attempt = owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        if (attempt) |plan| {
            failing.fail_index = std.math.maxInt(usize);
            _ = try plan.commit();
            try std.testing.expect(failures > 0);
            std.debug.print("delivery authority: {d} event allocation failures with original-source retry\n", .{failures});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try before.expectUnchanged(owner, true);
            try std.testing.expect(backing(owner).active == null and !(try owner.observe()).poisoned);
            _ = try testCommit(owner, &event, &test_destinations, &key);
            failures += 1;
        }
    }
    return error.FailureSweepIncomplete;
}

test "delivery authority: every progress allocation failure retains exact original output pointer and synced cursor for same-owner retry" {
    var failures: usize = 0;
    for (0..512) |index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(83));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "progress.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("progress source close");
        const id = try testCommit(owner, &event, &test_destinations, &key);
        const original = backing(owner).image.items[0].?.wire.ptr;
        var before = try TestCut.capture(owner);
        defer before.deinit();
        failing.fail_index = failing.alloc_index + index;
        if (owner.prepareProgress(id, 0, &key)) |plan| {
            failing.fail_index = std.math.maxInt(usize);
            _ = try plan.commit();
            try std.testing.expect(failures > 0);
            std.debug.print("delivery authority: {d} progress allocation failures retaining original output\n", .{failures});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try before.expectUnchanged(owner, true);
            try std.testing.expect(backing(owner).image.items[0].?.wire.ptr == original);
            try std.testing.expectEqual(@as(usize, 0), backing(owner).image.items[0].?.cursor);
            const retry = try owner.prepareProgress(id, 0, &key);
            _ = try retry.commit();
            try std.testing.expectEqual(@as(usize, 1), backing(owner).image.items[0].?.cursor);
            failures += 1;
        }
    }
    return error.FailureSweepIncomplete;
}

test "delivery authority: failed short and uncertain sync retain unpublished candidate poison original Store and require actual cold ownership" {
    const cases = [_]struct { fault: store_mod.PreparedIoFault, recovered: usize }{
        .{ .fault = .{ .write = .failed }, .recovered = 0 },
        .{ .fault = .{ .write = .short }, .recovered = 0 },
        .{ .fault = .{ .sync = true }, .recovered = 1 },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(84));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        {
            const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "uncertain.wal", testContext(&key), &key, .{});
            defer owner.close() catch @panic("uncertain source close");
            var before = try TestCut.capture(owner);
            defer before.deinit();
            const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
            backing(owner).state.store.setPreparedIoFault(case.fault);
            try std.testing.expectError(error.IoAmbiguous, plan.commit());
            try before.expectUnchanged(owner, false);
            try std.testing.expect((try owner.observe()).poisoned);
            try std.testing.expect(backing(owner).active == preparedToken(plan) and preparedToken(plan).candidate.?.image.count == 1);
            try std.testing.expectError(error.SourceBorrowed, owner.close());
            try std.testing.expectError(error.StorePoisoned, plan.commit());
            try plan.abort();
            try std.testing.expectError(error.StorePoisoned, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
        }
        const cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "uncertain.wal", testContext(&key), &key, .{});
        defer cold.close() catch @panic("recovered source close");
        try std.testing.expectEqual(case.recovered, (try cold.observe()).pending_deliveries);
        if (case.recovered == 0) _ = try testCommit(cold, &event, &test_destinations, &key) else try std.testing.expectError(error.Duplicate, cold.prepareEvent(event.event(), &test_destinations, 1000, &key));
    }
}

test "delivery authority: strict cold authenticates every row before publication and refuses even signed malformed typed image" {
    for (0..5) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(85));
        defer key.deinit();
        {
            const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "bad.wal", testContext(&key), &key, .{});
            defer owner.close() catch @panic("tampered source close");
            const b = backing(owner);
            if (fault < 4) {
                const original = b.state.store.get(.props, keys[fault]).?;
                const changed = try std.testing.allocator.dupe(u8, original);
                defer std.testing.allocator.free(changed);
                changed[changed.len - 1] ^= 1;
                var batch = try b.state.store.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = keys[fault], .value = changed }});
                defer batch.deinit();
                try batch.commit();
            } else {
                const malformed = "ODI1\x01";
                var head = b.head;
                head.images[2] = digest(malformed);
                const signed_head = try head.encode(&key);
                var batch = try b.state.store.prepareBatch(&.{
                    .{ .family = .props, .kind = .put, .key = keys[2], .value = malformed },
                    .{ .family = .props, .kind = .put, .key = keys[3], .value = &signed_head },
                });
                defer batch.deinit();
                try batch.commit();
            }
        }
        const before = try tmp.dir.readFileAlloc(std.testing.io, "bad.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        if (Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "bad.wal", testContext(&key), &key, .{})) |unexpected| {
            try unexpected.close();
            return error.ExpectedColdRefusal;
        } else |err| try std.testing.expect(err == error.ImageMismatch or err == error.InvalidSignature or err == error.Truncated or err == error.SignatureVerificationFailed);
        const after = try tmp.dir.readFileAlloc(std.testing.io, "bad.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }
}

test "delivery authority: real automatic physical WAL compaction preserves immutable logical epoch and retired pending exact event on cold replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(86));
    defer key.deinit();
    const config: Config = .{ .replay = .{ .window_size = 4, .max_origins = 1 }, .storage = .{ .max_wal_bytes = 32768, .changefeed_capacity = 0 } };
    var first: Observation = undefined;
    var first_id: oper.EventId = undefined;
    {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "compact.wal", testContext(&key), &key, config);
        defer owner.close() catch @panic("compacted source close");
        first = try owner.observe();
        const initial_physical = backing(owner).state.store.wal_epoch;
        for (0..32) |index| {
            const event = try TestEvent.init(&key, (1000 << 16) + index);
            const id = try testCommit(owner, &event, if (index == 0) &test_destinations else &.{}, &key);
            if (index == 0) first_id = id;
        }
        try std.testing.expect(!std.mem.eql(u8, &initial_physical, &backing(owner).state.store.wal_epoch));
        try std.testing.expectEqual(@as(usize, 1), (try owner.observe()).pending_deliveries);
    }
    const cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "compact.wal", testContext(&key), &key, config);
    defer cold.close() catch @panic("compacted cold source close");
    const recovered = try cold.observe();
    try std.testing.expectEqualSlices(u8, &first.logical_store_id, &recovered.logical_store_id);
    try std.testing.expectEqualSlices(u8, &first.logical_store_epoch, &recovered.logical_store_epoch);
    const loan = try cold.borrow();
    const output = try loan.delivery(0);
    try std.testing.expectEqualSlices(u8, &first_id, &output.id);
    try std.testing.expectEqualStrings(test_destinations[0].secret, output.secret);
    try loan.release();
}

test "delivery authority: protected real directory full source context missing lease and peer admission fail closed before mutation" {
    // `Permissions.fromMode` does not exist on Windows.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(87));
    defer key.deinit();
    try testDirectoryPermissions(tmp.dir, .fromMode(0o755));
    try std.testing.expectError(error.UnprotectedDirectory, Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", testContext(&key), &key, .{}));
    try std.testing.expect(!(try existingNamespace(std.testing.allocator, std.testing.io, tmp.dir, "context.wal")));
    try testDirectory(tmp.dir);
    {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("context source close");
        var before = try TestCut.capture(owner);
        defer before.deinit();
        var peer = try sign.KeyPair.fromSeed(@splat(88));
        defer peer.deinit();
        const foreign = try TestEvent.init(&peer, 1000 << 16);
        try std.testing.expectError(error.OriginMismatch, owner.prepareEvent(foreign.event(), &test_destinations, 1000, &key));
        try before.expectUnchanged(owner, true);
        try std.testing.expectError(error.WouldBlock, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", testContext(&key), &key, .{}));
    }
    var changed = testContext(&key);
    changed.config_digest[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", changed, &key, .{}));
    changed = testContext(&key);
    changed.canonical_name = "other.example.test";
    try std.testing.expectError(error.ContextMismatch, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", changed, &key, .{}));
    try tmp.dir.deleteFile(std.testing.io, "context.wal.lock");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "context.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectError(error.FileNotFound, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "context.wal", testContext(&key), &key, .{}));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "context.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

fn constructorAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, cold: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var before: ?TestCut = null;
    defer if (before) |*cut| cut.deinit();
    var old: ?Observation = null;
    if (cold) {
        const seed = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "constructor.wal", testContext(key), key, .{});
        defer seed.close() catch @panic("constructor seed close");
        const event = try TestEvent.init(key, 1000 << 16);
        _ = try testCommit(seed, &event, &test_destinations, key);
        before = try TestCut.capture(seed);
        old = try seed.observe();
    }
    const owner = (if (cold)
        Authority.openCold(allocator, std.testing.io, tmp.dir, "constructor.wal", testContext(key), key, .{})
    else
        Authority.initialize(allocator, std.testing.io, tmp.dir, "constructor.wal", testContext(key), key, .{})) catch |err| {
        if (err == error.OutOfMemory) {
            if (before) |cut| {
                const bytes = try tmp.dir.readFileAlloc(std.testing.io, "constructor.wal", std.testing.allocator, .unlimited);
                defer std.testing.allocator.free(bytes);
                try std.testing.expectEqualSlices(u8, cut.wal, bytes);
                var inspection = try store_mod.OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "constructor.wal", .{ .changefeed_capacity = 0 });
                defer inspection.deinit();
                for (keys, cut.rows) |name, value| try std.testing.expectEqualSlices(u8, value, inspection.get(.props, name).?);
            } else try std.testing.expect(!(try existingNamespace(std.testing.allocator, std.testing.io, tmp.dir, "constructor.wal")));
            const retry = if (cold)
                try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "constructor.wal", testContext(key), key, .{})
            else
                try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "constructor.wal", testContext(key), key, .{});
            defer retry.close() catch @panic("constructor retry close");
            const observed = try retry.observe();
            try std.testing.expectEqual(if (cold) @as(usize, 1) else 0, observed.pending_deliveries);
            if (old) |original| {
                try std.testing.expectEqual(original.generation + 1, observed.generation);
                try std.testing.expectEqualSlices(u8, &original.logical_store_id, &observed.logical_store_id);
                try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &observed.logical_store_epoch);
            }
        }
        return err;
    };
    defer owner.close() catch @panic("constructor successful source close");
    const observed = try owner.observe();
    try std.testing.expectEqual(if (cold) @as(usize, 1) else 0, observed.pending_deliveries);
    if (old) |original| {
        try std.testing.expectEqual(original.generation + 1, observed.generation);
        try std.testing.expectEqualSlices(u8, &original.logical_store_id, &observed.logical_store_id);
        try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &observed.logical_store_epoch);
    }
}

test "delivery authority: every provision and strict cold constructor allocation failure retains original disk cut and actual leased retry" {
    var key = try sign.KeyPair.fromSeed(@splat(89));
    defer key.deinit();
    for ([_]bool{ false, true }) |cold| try std.testing.checkAllAllocationFailures(std.testing.allocator, constructorAllocationScenario, .{ &key, cold });
}

test "delivery authority: every commit validation allocation failure retains original source and exact prepared candidate for same-plan retry" {
    var failures: usize = 0;
    for (0..128) |index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(90));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .resize_fail_index = 0 });
        const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "commit.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("commit source close");
        var before = try TestCut.capture(owner);
        defer before.deinit();
        const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        const original_candidate = preparedToken(plan).candidate.?;
        failing.fail_index = failing.alloc_index + index;
        if (plan.commit()) |_| {
            try std.testing.expect(failures > 0);
            std.debug.print("delivery authority: {d} commit validation allocation failures retaining original plan\n", .{failures});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try before.expectUnchanged(owner, true);
            try std.testing.expect(backing(owner).active == preparedToken(plan));
            try std.testing.expect(preparedToken(plan).candidate.? == original_candidate);
            try std.testing.expect(!(try owner.observe()).poisoned);
            _ = try plan.commit();
            try std.testing.expectEqual(@as(usize, 1), (try owner.observe()).pending_deliveries);
            failures += 1;
        }
    }
    return error.FailureSweepIncomplete;
}

test "delivery authority: finite source token budget refuses before allocations or mutation preserves stale handles and allows actual cold new owner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(91));
    defer key.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    const config: Config = .{ .max_issued_tokens = 3 };
    var id: oper.EventId = undefined;
    {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "budget.wal", testContext(&key), &key, config);
        defer owner.close() catch @panic("budget source close");
        const loan = try owner.borrow();
        try loan.release();
        const old_plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        try old_plan.abort();
        const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        try std.testing.expect(old_plan != plan);
        id = (try plan.commit()).?;
        try std.testing.expectError(error.ConsumedLoan, loan.observe());
        try std.testing.expectError(error.ConsumedPlan, old_plan.commit());
        try std.testing.expectError(error.ConsumedPlan, plan.commit());
        var before = try TestCut.capture(owner);
        defer before.deinit();
        const allocation_index = failing.alloc_index;
        failing.fail_index = allocation_index;
        try std.testing.expectError(error.TokenCapacity, owner.borrow());
        try std.testing.expectError(error.TokenCapacity, owner.prepareProgress(id, 0, &key));
        try std.testing.expectError(error.TokenCapacity, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
        try std.testing.expectEqual(allocation_index, failing.alloc_index);
        try std.testing.expectEqual(@as(usize, 3), backing(owner).issued_tokens);
        try before.expectUnchanged(owner, true);
    }
    const cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "budget.wal", testContext(&key), &key, config);
    defer cold.close() catch @panic("budget cold source close");
    try std.testing.expectEqual(@as(usize, 0), backing(cold).issued_tokens);
    const loan = try cold.borrow();
    const output = try loan.delivery(0);
    try std.testing.expectEqualSlices(u8, &id, &output.id);
    try loan.release();
    const progress = try cold.prepareProgress(id, 0, &key);
    _ = try progress.commit();
    try std.testing.expectEqual(@as(usize, 1), backing(cold).image.items[0].?.cursor);
}

test "delivery authority: valid signed head with contradictory typed history or Guard maximum refuses actual cold publication" {
    for (0..5) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(92));
        defer key.deinit();
        const event = try TestEvent.init(&key, 1000 << 16);
        {
            const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "contradiction.wal", testContext(&key), &key, .{});
            defer owner.close() catch @panic("contradictory source close");
            _ = try testCommit(owner, &event, &test_destinations, &key);
            const b = backing(owner);
            const original = try encodeHistory(std.testing.allocator, &b.history);
            defer std.testing.allocator.free(original);
            const checkpoint = try std.testing.allocator.create(History.CheckpointState);
            defer std.testing.allocator.destroy(checkpoint);
            checkpoint.* = History.restoreHelixCheckpoint(original).?;
            const retained = &checkpoint.items[checkpoint.start];
            switch (fault) {
                0 => retained.category = @intCast((retained.category + 1) % history_mod.category_count),
                1 => retained.severity = @intCast((retained.severity + 1) % history_mod.severity_count),
                2 => retained.ts_unix_ms -= 1,
                3 => retained.msg_buf[0] ^= 1,
                4 => {},
                else => unreachable,
            }
            const changed_history = try std.testing.allocator.create(History);
            defer std.testing.allocator.destroy(changed_history);
            changed_history.* = .{};
            changed_history.publishCheckpoint(checkpoint);
            const changed = try encodeHistory(std.testing.allocator, changed_history);
            defer std.testing.allocator.free(changed);
            var head = b.head;
            head.images[1] = digest(changed);
            if (fault == 4) head.max_hlc += 1;
            const signed_head = try head.encode(&key);
            // Adversarial fixture writes real synced typed rows and a valid
            // signature; the production authority exposes no raw Store loan.
            var batch = try b.state.store.prepareBatch(&.{
                .{ .family = .props, .kind = .put, .key = keys[1], .value = changed },
                .{ .family = .props, .kind = .put, .key = keys[3], .value = &signed_head },
            });
            defer batch.abort();
            try batch.commit();
        }
        const before = try tmp.dir.readFileAlloc(std.testing.io, "contradiction.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        try std.testing.expectError(error.InconsistentPackage, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "contradiction.wal", testContext(&key), &key, .{}));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "contradiction.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
    }
}

test "delivery authority: signed empty Guard and zero head cannot erase real HLC one history on actual cold reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(93));
    defer key.deinit();
    {
        const empty = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "empty.wal", testContext(&key), &key, .{});
        try empty.close();
        const cold_empty = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "empty.wal", testContext(&key), &key, .{});
        defer cold_empty.close() catch @panic("empty cold source close");
        try std.testing.expectEqual(@as(u64, 0), (try cold_empty.observe()).max_accepted_hlc);
    }
    {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "erase.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("erase source close");
        const event = try TestEvent.init(&key, 1);
        _ = try testCommit(owner, &event, &.{}, &key);
        const b = backing(owner);
        var empty_guard = try guard_mod.Guard.init(std.testing.allocator, .{});
        defer empty_guard.deinit();
        const encoded = try empty_guard.encodeCheckpoint(std.testing.allocator);
        defer std.testing.allocator.free(encoded);
        var head = b.head;
        head.max_hlc = 0;
        head.images[0] = digest(encoded);
        const signed_head = try head.encode(&key);
        var batch = try b.state.store.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = keys[0], .value = encoded },
            .{ .family = .props, .kind = .put, .key = keys[3], .value = &signed_head },
        });
        defer batch.abort();
        try batch.commit();
    }
    const before = try tmp.dir.readFileAlloc(std.testing.io, "erase.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectError(error.InconsistentPackage, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "erase.wal", testContext(&key), &key, .{}));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "erase.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

const shared_services_config: services_mod.Config = .{ .pbkdf2_rounds = 1 };
const SharedServiceCall = struct {
    failure: ?anyerror = null,
    done: std.Io.Event = .unset,
    fn run(loan: *ServicesLoan, result: *SharedServiceCall) void {
        _ = loan.accountInfo("alice") catch |err| {
            result.failure = err;
            result.done.set(std.testing.io);
            return;
        };
        result.done.set(std.testing.io);
    }
};

const SharedMutation = enum {
    register,
    replace_webpush,
    delete_webpush,

    fn apply(self: SharedMutation, loan: *ServicesLoan) !void {
        switch (self) {
            .register => {
                var scratch: [4096]u8 = undefined;
                _ = try loan.registerAccount("bob", "test-password", &scratch);
            },
            .replace_webpush => try loan.webpushPut("alice", "replacement image"),
            .delete_webpush => try loan.webpushPut("alice", ""),
        }
    }

    fn expectLive(self: SharedMutation, loan: *ServicesLoan, successor: bool) !void {
        if (self == .register) {
            if (successor) {
                _ = try loan.identifyAccount("bob", "test-password");
            } else try std.testing.expectError(error.NotFound, loan.accountInfo("bob"));
        }
        const value = try loan.webpushGetAllocStrict(std.testing.allocator, "alice");
        defer if (value) |bytes| std.testing.allocator.free(bytes);
        if (self == .delete_webpush and successor) {
            try std.testing.expect(value == null);
        } else {
            try std.testing.expectEqualStrings(if (self == .replace_webpush and successor) "replacement image" else "original image", value.?);
        }
    }
};

fn seedSharedMutation(loan: *ServicesLoan) !void {
    var scratch: [4096]u8 = undefined;
    _ = try loan.registerAccount("alice", "test-password", &scratch);
    try loan.webpushPut("alice", "original image");
}

test "delivery authority: named shared mutations sweep all staging allocations before synced publication with exact rollback and same-source retry" {
    for (std.enums.values(SharedMutation)) |mutation| {
        var failures: usize = 0;
        for (0..128) |index| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            try testDirectory(tmp.dir);
            var key = try sign.KeyPair.fromSeed(@splat(99));
            defer key.deinit();
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "shared-oom.wal", testContext(&key), &key, .{});
            defer owner.close() catch @panic("shared OOM owner close");
            const loan = try owner.stateContext().attachServices(shared_services_config);
            defer loan.close() catch @panic("shared OOM loan close");
            try seedSharedMutation(loan);
            const context = backing(owner).state;
            const service = servicesToken(loan).services;
            var before = try TestCut.capture(owner);
            defer before.deinit();
            failing.fail_index = failing.alloc_index + index;
            const result = mutation.apply(loan);
            failing.fail_index = std.math.maxInt(usize);
            if (result) |_| {
                try std.testing.expect(failures != 0);
                try mutation.expectLive(loan, true);
                std.debug.print("shared {s} staging sweep: {d} OOM cuts\n", .{ @tagName(mutation), failures });
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                failures += 1;
                try std.testing.expect(backing(owner).state == context and servicesToken(loan).services == service);
                try std.testing.expect(!(try owner.observe()).poisoned);
                try before.expectUnchanged(owner, true);
                try mutation.expectLive(loan, false);
                try mutation.apply(loan);
                try mutation.expectLive(loan, true);
            }
            if (index == 127) return error.MissingSuccessfulAllocationCut;
        }
    }
}

test "delivery authority: named shared prepared mutations retain original live source on write or sync uncertainty and authenticate actual cold outcome" {
    const faults = [_]store_mod.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } };
    for (std.enums.values(SharedMutation)) |mutation| {
        for (faults, 0..) |fault, fault_index| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            try testDirectory(tmp.dir);
            var key = try sign.KeyPair.fromSeed(@splat(100));
            defer key.deinit();
            const event = try TestEvent.init(&key, 1000 << 16);
            var original: Observation = undefined;
            {
                const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "shared-io.wal", testContext(&key), &key, .{});
                defer owner.close() catch @panic("shared IO owner close");
                const loan = try owner.stateContext().attachServices(shared_services_config);
                defer loan.close() catch @panic("shared IO loan close");
                try seedSharedMutation(loan);
                const context = backing(owner).state;
                const service = servicesToken(loan).services;
                const original_value = context.store.get(.props, "wps\x00alice").?;
                original = try owner.observe();
                var before = try TestCut.capture(owner);
                defer before.deinit();
                context.store.setPreparedIoFault(fault);
                try std.testing.expectError(error.IoAmbiguous, mutation.apply(loan));
                try std.testing.expect(backing(owner).state == context and servicesToken(loan).services == service);
                try std.testing.expect((try owner.observe()).poisoned);
                try before.expectUnchanged(owner, false);
                const retained = context.store.get(.props, "wps\x00alice").?;
                try std.testing.expect(retained.ptr == original_value.ptr);
                try std.testing.expectEqualStrings("original image", retained);
                try std.testing.expect(context.store.get(.accounts, "bob") == null);
                try std.testing.expect(!(try loan.authenticationAvailable()));
                try std.testing.expectError(error.StorePoisoned, loan.identifyAccount("alice", "test-password"));
                try std.testing.expectError(error.StorePoisoned, loan.webpushGetAllocStrict(std.testing.allocator, "alice"));
                try std.testing.expectError(error.StorePoisoned, mutation.apply(loan));
                try std.testing.expectError(error.StorePoisoned, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
            }
            const recovered = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "shared-io.wal", testContext(&key), &key, .{});
            defer recovered.close() catch @panic("shared IO cold close");
            const loan = try recovered.stateContext().attachServices(shared_services_config);
            defer loan.close() catch @panic("shared IO cold loan close");
            const actual = try recovered.observe();
            try std.testing.expectEqualSlices(u8, &original.logical_store_id, &actual.logical_store_id);
            try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &actual.logical_store_epoch);
            try std.testing.expectEqual(try std.math.add(u64, original.generation, 1), actual.generation);
            try mutation.expectLive(loan, fault_index == 2);
            if (fault_index != 2) try mutation.apply(loan);
            try mutation.expectLive(loan, true);
            _ = try testCommit(recovered, &event, &test_destinations, &key);
        }
    }
}

test "delivery authority: closed Services loan uses original leased Store and real mutex continuously through commit or abort and actual caller join" {
    for ([_]bool{ false, true }) |abort| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(94));
        defer key.deinit();
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "shared.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("shared authority close");
        const loan = try owner.stateContext().attachServices(shared_services_config);
        var loan_closed = false;
        defer if (!loan_closed) loan.close() catch @panic("shared Services close");
        const source = servicesToken(loan);
        try std.testing.expect(source.services.store == &backing(owner).state.store);
        try std.testing.expect(source.lock == &source.services.lock);
        try std.testing.expectError(error.BoundStateRequiresTransaction, source.services.legacyStore());
        try std.testing.expectError(error.ServicesAlreadyAttached, owner.stateContext().attachServices(shared_services_config));
        try std.testing.expectError(error.SourceBorrowed, owner.close());
        var scratch: [4096]u8 = undefined;
        _ = try loan.registerAccount("alice", "test-password", &scratch);
        _ = try loan.identifyAccount("alice", "test-password");
        try std.testing.expect(try loan.authenticationAvailable());
        const event = try TestEvent.init(&key, 1000 << 16);
        var before = try TestCut.capture(owner);
        defer before.deinit();
        const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        var consumed = false;
        defer if (!consumed) plan.abort() catch @panic("shared plan abort");
        const acquired = source.lock.tryLockExclusive();
        if (acquired) source.lock.unlockExclusive();
        try std.testing.expect(!acquired);
        try std.testing.expectError(error.ServicesTransactionActive, loan.identifyAccount("alice", "test-password"));
        try std.testing.expectError(error.MutationActive, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
        try std.testing.expectError(error.SourceBorrowed, loan.close());
        var entered: std.Io.Event = .unset;
        source.test_entered = &entered;
        var call: SharedServiceCall = .{};
        const caller = try std.Thread.spawn(.{}, SharedServiceCall.run, .{ loan, &call });
        var joined = false;
        defer if (!joined) {
            if (!consumed) {
                plan.abort() catch @panic("shared emergency abort");
                consumed = true;
            }
            caller.join();
        };
        const enter_deadline: std.Io.Clock.Timestamp = .{
            .clock = .awake,
            .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(5000)),
        };
        try entered.waitTimeout(std.testing.io, .{ .deadline = enter_deadline });
        backing(owner).gate.lockExclusive();
        const pending_calls = source.calls;
        backing(owner).gate.unlockExclusive();
        try std.testing.expectEqual(@as(usize, 1), pending_calls);
        try std.testing.expect(!call.done.isSet());
        try std.testing.expectError(error.SourceBorrowed, loan.close());
        try std.testing.expectError(error.ServiceCallActive, owner.observe());
        if (abort) {
            try plan.abort();
        } else _ = try plan.commit();
        consumed = true;
        caller.join();
        joined = true;
        source.test_entered = null;
        try std.testing.expect(call.failure == null and call.done.isSet());
        if (abort) {
            try before.expectUnchanged(owner, true);
            _ = try testCommit(owner, &event, &test_destinations, &key);
        }
        try std.testing.expectEqual(@as(usize, 1), (try owner.observe()).pending_deliveries);
        try loan.close();
        loan_closed = true;
        try std.testing.expectError(error.ConsumedLoan, loan.accountInfo("alice"));
    }
}

test "delivery authority: caller rejected before source entry times out bounded observer then aborts original plan and joins actual caller" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(101));
    defer key.deinit();
    const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "shared-entry.wal", testContext(&key), &key, .{});
    defer owner.close() catch @panic("shared entry owner close");
    const stale = try owner.stateContext().attachServices(shared_services_config);
    try stale.close();
    const loan = try owner.stateContext().attachServices(shared_services_config);
    defer loan.close() catch @panic("shared entry loan close");
    try seedSharedMutation(loan);
    var before = try TestCut.capture(owner);
    defer before.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
    var consumed = false;
    defer if (!consumed) plan.abort() catch @panic("shared entry plan abort");
    var entered: std.Io.Event = .unset;
    servicesToken(stale).test_entered = &entered;
    var call: SharedServiceCall = .{};
    const caller = try std.Thread.spawn(.{}, SharedServiceCall.run, .{ stale, &call });
    var joined = false;
    defer if (!joined) {
        if (!consumed) {
            plan.abort() catch @panic("shared entry emergency abort");
            consumed = true;
        }
        caller.join();
    };
    const returned_deadline: std.Io.Clock.Timestamp = .{
        .clock = .awake,
        .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(5000)),
    };
    try call.done.waitTimeout(std.testing.io, .{ .deadline = returned_deadline });
    // The actual caller rejected the stale capability before source admission;
    // no test-entered event can arrive. The observer must still reach cleanup.
    const entry_deadline: std.Io.Clock.Timestamp = .{
        .clock = .awake,
        .raw = std.Io.Clock.awake.now(std.testing.io).addDuration(.fromMilliseconds(20)),
    };
    try std.testing.expectError(error.Timeout, entered.waitTimeout(std.testing.io, .{ .deadline = entry_deadline }));
    try plan.abort();
    consumed = true;
    caller.join();
    joined = true;
    servicesToken(stale).test_entered = null;
    try std.testing.expectEqual(error.ConsumedLoan, call.failure.?);
    try before.expectUnchanged(owner, true);
    _ = try testCommit(owner, &event, &test_destinations, &key);
}

test "delivery authority: named Services and original signed output survive same-store cold recovery while poison cannot replace original custody" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(95));
    defer key.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    var original: Observation = undefined;
    var id: oper.EventId = undefined;
    {
        const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "shared-cold.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("shared poisoned authority close");
        const loan = try owner.stateContext().attachServices(shared_services_config);
        defer loan.close() catch @panic("shared poisoned Services close");
        var scratch: [4096]u8 = undefined;
        _ = try loan.registerAccount("alice", "test-password", &scratch);
        try loan.webpushPut("alice", "original malformed blob retained as data");
        const blob = (try loan.webpushGetAllocStrict(std.testing.allocator, "alice")).?;
        defer std.testing.allocator.free(blob);
        try std.testing.expectEqualStrings("original malformed blob retained as data", blob);
        original = try owner.observe();
        const context = backing(owner).state;
        const services = servicesToken(loan).services;
        const plan = try owner.prepareEvent(event.event(), &test_destinations, 1000, &key);
        id = preparedToken(plan).event_id.?;
        context.store.setPreparedIoFault(.{ .sync = true });
        try std.testing.expectError(error.IoAmbiguous, plan.commit());
        try std.testing.expect(backing(owner).state == context and servicesToken(loan).services == services);
        try std.testing.expectError(error.SourceBorrowed, loan.close());
        try std.testing.expectError(error.SourceBorrowed, owner.close());
        const acquired = services.lock.tryLockExclusive();
        if (acquired) services.lock.unlockExclusive();
        try std.testing.expect(!acquired);
        try plan.abort();
        try std.testing.expect(!(try loan.authenticationAvailable()));
        try std.testing.expectError(error.StorePoisoned, loan.identifyAccount("alice", "test-password"));
        try std.testing.expectError(error.StorePoisoned, loan.webpushGetAllocStrict(std.testing.allocator, "alice"));
        try std.testing.expectError(error.StorePoisoned, loan.webpushPut("alice", "replacement refused"));
    }
    const cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "shared-cold.wal", testContext(&key), &key, .{});
    defer cold.close() catch @panic("shared cold authority close");
    const loan = try cold.stateContext().attachServices(shared_services_config);
    defer loan.close() catch @panic("shared cold Services close");
    _ = try loan.identifyAccount("alice", "test-password");
    const observation = try cold.observe();
    try std.testing.expectEqualSlices(u8, &original.logical_store_id, &observation.logical_store_id);
    try std.testing.expectEqualSlices(u8, &original.logical_store_epoch, &observation.logical_store_epoch);
    try std.testing.expectEqual(@as(usize, 1), observation.pending_deliveries);
    const output = try cold.borrow();
    try std.testing.expectEqualSlices(u8, &id, &(try output.delivery(0)).id);
    try output.release();
    const blob = (try loan.webpushGetAllocStrict(std.testing.allocator, "alice")).?;
    defer std.testing.allocator.free(blob);
    try std.testing.expectEqualStrings("original malformed blob retained as data", blob);
}

test "delivery authority: closed Services factory allocation failures preserve original context and source budget with same-owner retry" {
    var failures: usize = 0;
    for (0..64) |index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try testDirectory(tmp.dir);
        var key = try sign.KeyPair.fromSeed(@splat(96));
        defer key.deinit();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "factory.wal", testContext(&key), &key, .{});
        defer owner.close() catch @panic("factory authority close");
        const original_context = backing(owner).state;
        const original_budget = backing(owner).issued_tokens;
        var before = try TestCut.capture(owner);
        defer before.deinit();
        failing.fail_index = failing.alloc_index + index;
        if (owner.stateContext().attachServices(shared_services_config)) |loan| {
            try loan.close();
            try std.testing.expect(failures > 0);
            std.debug.print("delivery authority: {d} closed Services factory allocation failures with same-context retry\n", .{failures});
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failing.fail_index = std.math.maxInt(usize);
            try before.expectUnchanged(owner, true);
            try std.testing.expect(backing(owner).state == original_context and original_context.services_loan == null);
            try std.testing.expectEqual(original_budget, backing(owner).issued_tokens);
            const retry = try owner.stateContext().attachServices(shared_services_config);
            try retry.close();
            failures += 1;
        }
    }
    return error.FailureSweepIncomplete;
}

test "delivery authority: source-entered named Services scope refuses nested loan and authority calls without touching original journal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var key = try sign.KeyPair.fromSeed(@splat(97));
    defer key.deinit();
    const owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "nested.wal", testContext(&key), &key, .{});
    defer owner.close() catch @panic("nested authority close");
    const loan = try owner.stateContext().attachServices(shared_services_config);
    defer loan.close() catch @panic("nested Services close");
    var before = try TestCut.capture(owner);
    defer before.deinit();
    const event = try TestEvent.init(&key, 1000 << 16);
    const token = servicesToken(loan);
    _ = try token.begin();
    {
        defer token.finish();
        try std.testing.expectError(error.ServicesCallReentered, loan.accountInfo("alice"));
        try std.testing.expectError(error.ServicesTransactionActive, owner.prepareEvent(event.event(), &test_destinations, 1000, &key));
        try std.testing.expectError(error.SourceBorrowed, loan.close());
    }
    try before.expectUnchanged(owner, true);
    _ = try testCommit(owner, &event, &test_destinations, &key);
}

fn leasedLeafCore(dir: std.Io.Dir, name: []const u8, mode: server_mod.ManagedLeasedMode, identity: *@import("node_identity.zig").NodeIdentity, resolver: *@import("rdns.zig").Resolver) !*server_mod.ManagedCore {
    return server_mod.ManagedCore.createLeasedCold(std.testing.allocator, std.testing.io, .{
        .config = .{ .host = "127.0.0.1", .port = 0, .num_shards = 1, .max_clients = 16, .server_name = "node.example.test", .node_identity = identity, .sasl_enabled = true, .crypto_io = std.testing.io },
        .parsed = .{ .sasl = .{ .enabled = true, .account_db = name }, .accounts = .{ .pbkdf2_rounds = 1 } },
    }, .{ .mode = mode, .storage = .{ .dir = dir, .name = name } }, .{ .rdns = resolver, .dnsbl = null, .mail = null, .webpush = null });
}

test "delivery authority: genuine Core factory registers original private context Store and Services mutex and refuses tampered placement without WAL mutation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var identity = try @import("node_identity.zig").fromSeed(@splat(102), "leased-leaf");
    defer identity.deinit();
    var resolver = try @import("rdns.zig").Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
    defer resolver.deinit();
    const core = try leasedLeafCore(tmp.dir, "core-leaf.wal", .provision, &identity, &resolver);
    defer core.discardLeasedCold() catch @panic("leased leaf Core close");
    try server_mod.ManagedCoreFixture.requireLeasedDirectCloseRefusal(core);
    // Resolve the private original through an actual source-issued read loan,
    // never a forged Stage or an externally supplied hash/owner receipt.
    const read = try server_mod.ManagedCoreFixture.borrowLeasedAuthority(core);
    var read_released = false;
    defer if (!read_released) read.release() catch @panic("leased leaf read release");
    const b = readToken(read).owner;
    const owner: *Authority = @ptrCast(b);
    const context = b.state;
    const original = context.services_loan.?;
    const loan: *ServicesLoan = @ptrCast(original);
    const stage = context.core_stage.?;
    try std.testing.expect(original.context == context and original.services.store == &context.store and original.lock == &original.services.lock);
    try std.testing.expectError(error.SourceBorrowed, StateContext.requireCoreReleaseable(stage, owner, loan));
    try read.release();
    read_released = true;
    var before = try TestCut.capture(owner);
    defer before.deinit();
    var foreign_mutex: lock_mod.RwLock = .{};
    const actual_mutex = original.lock;
    original.lock = &foreign_mutex;
    var restored = false;
    defer {
        if (!restored) original.lock = actual_mutex;
    }
    try std.testing.expectError(error.SourceIdentityMismatch, StateContext.validateCoreSources(stage, owner, loan));
    try std.testing.expectError(error.SourceIdentityMismatch, StateContext.requireCoreReleaseable(stage, owner, loan));
    try before.expectUnchanged(owner, true);
    original.lock = actual_mutex;
    restored = true;
    try StateContext.validateCoreSources(stage, owner, loan);
    try server_mod.ManagedCoreFixture.requireLeasedForeignRefusal(core, .{ .dir = tmp.dir, .name = "foreign-leaf.wal" });
    try before.expectUnchanged(owner, true);
    var run: @import("reactor_pool.zig").RunFlag = .init(true);
    try std.testing.expectError(error.ClosedAuthorityNotIntegrated, core.prepareColdResources(&run));
    try before.expectUnchanged(owner, true);
}

test "delivery authority: genuine Core source pin preserves original placement through real prepared plan disposal refusal and strict cold output replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var identity = try @import("node_identity.zig").fromSeed(@splat(103), "leased-leaf");
    defer identity.deinit();
    var resolver = try @import("rdns.zig").Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
    defer resolver.deinit();
    const event = try TestEvent.init(&identity.sign_kp, 1000 << 16);
    const core = try leasedLeafCore(tmp.dir, "core-plan.wal", .provision, &identity, &resolver);
    var discarded = false;
    defer if (!discarded) core.discardLeasedCold() catch @panic("leased plan Core close");
    const plan = try server_mod.ManagedCoreFixture.prepareLeasedEvent(core, event.event(), &test_destinations, 1000);
    var consumed = false;
    defer if (!consumed) server_mod.ManagedCoreFixture.abortLeasedEvent(core, plan) catch @panic("leased plan abort");
    const token = preparedToken(plan);
    const b = token.owner;
    const owner: *Authority = @ptrCast(b);
    const context = b.state;
    const original = context.services_loan.?;
    const stage = context.core_stage.?;
    var before = try TestCut.capture(owner);
    defer before.deinit();
    try std.testing.expectError(error.SourceBorrowed, core.discardLeasedCold());
    try std.testing.expect(context.core_stage == stage and context.services_loan == original);
    try before.expectUnchanged(owner, true);
    const id = (try server_mod.ManagedCoreFixture.commitLeasedEvent(core, plan)).?;
    consumed = true;
    // Once the actual plan releases its original lock, a source-issued helper
    // must still recognize the same installed placement after refused cleanup.
    try server_mod.ManagedCoreFixture.requireLeasedDirectCloseRefusal(core);
    try core.discardLeasedCold();
    discarded = true;
    const recovered = try leasedLeafCore(tmp.dir, "core-plan.wal", .recover, &identity, &resolver);
    defer recovered.discardLeasedCold() catch @panic("leased cold Core close");
    const read = try server_mod.ManagedCoreFixture.borrowLeasedAuthority(recovered);
    defer read.release() catch @panic("leased cold read release");
    const output = try read.delivery(0);
    try std.testing.expectEqualSlices(u8, &id, &output.id);
    try std.testing.expectEqualStrings(test_destinations[0].url, output.url);
    try std.testing.expectEqualStrings(test_destinations[0].secret, output.secret);
    var history: [2]history_mod.StoredEvent = undefined;
    try std.testing.expectEqual(@as(usize, 1), try read.collectHistory(null, 0, &history));
    try std.testing.expectEqualSlices(u8, &id, &history[0].event_id);
}

test "delivery authority: original Core World acquisition loss and real reacquisition retain exact candidate and mutex until distinct cold cancellation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try testDirectory(tmp.dir);
    var identity = try @import("node_identity.zig").fromSeed(@splat(104), "leased-leaf");
    defer identity.deinit();
    var resolver = try @import("rdns.zig").Resolver.initConfigured(std.testing.allocator, std.testing.io, .{});
    defer resolver.deinit();
    const event = try TestEvent.init(&identity.sign_kp, 1000 << 16);
    const core = try leasedLeafCore(tmp.dir, "core-world.wal", .provision, &identity, &resolver);
    defer core.discardLeasedCold() catch @panic("leased World Core close");
    const plan = try server_mod.ManagedCoreFixture.prepareLeasedEvent(core, event.event(), &test_destinations, 1000);
    var lost = false;
    var consumed = false;
    defer {
        if (!consumed) {
            if (lost) core.cancelLeasedColdPreparation() catch @panic("leased interrupted plan cancellation") else server_mod.ManagedCoreFixture.abortLeasedEvent(core, plan) catch @panic("leased World plan abort");
        }
    }
    const token = preparedToken(plan);
    const b = token.owner;
    const owner: *Authority = @ptrCast(b);
    const candidate = token.candidate.?;
    const scope = token.transaction.world_scope.?;
    const original_services = b.state.services_loan.?;
    var before = try TestCut.capture(owner);
    defer before.deinit();

    try std.testing.expectError(error.WorldAcquisitionNotInterrupted, core.cancelLeasedColdPreparation());
    try before.expectUnchanged(owner, true);
    try server_mod.ManagedCoreFixture.releaseLeasedEventWorld(core, plan);
    lost = true;
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, plan.commit());
    try std.testing.expectError(error.ExclusiveLockNotHeldByCaller, plan.abort());
    try before.expectUnchanged(owner, true);
    try std.testing.expect(b.active == token and token.candidate == candidate and token.transaction.world_scope == scope);
    try std.testing.expectEqual(@as(usize, 1), b.state.authority_entries);
    try std.testing.expect(!original_services.lock.tryLockExclusive());

    // This helper acquires the actual original World anew and invokes BOTH
    // terminal methods. Its genuine new acquisition must not revive the plan.
    try server_mod.ManagedCoreFixture.requireLeasedReacquisitionRefusal(core, plan);
    try before.expectUnchanged(owner, true);
    try std.testing.expect(b.active == token and token.candidate == candidate and token.transaction.world_scope == scope);
    try std.testing.expect(!original_services.lock.tryLockExclusive());
    try std.testing.expectError(error.SourceBorrowed, core.discardLeasedCold());

    try core.cancelLeasedColdPreparation();
    consumed = true;
    try before.expectUnchanged(owner, true);
    try std.testing.expect(b.active == null and token.candidate == null);
    try std.testing.expectEqual(@as(usize, 0), b.state.authority_entries);
    try std.testing.expect(original_services.lock.tryLockExclusive());
    original_services.lock.unlockExclusive();
    try std.testing.expectError(error.ConsumedPlan, plan.commit());
    try std.testing.expectError(error.ConsumedPlan, plan.abort());

    // Cancellation did not consume replay identity or publish any output.
    // A new genuine source scope admits the same signed event once.
    const retry = try server_mod.ManagedCoreFixture.prepareLeasedEvent(core, event.event(), &test_destinations, 1000);
    var retried = false;
    defer if (!retried) server_mod.ManagedCoreFixture.abortLeasedEvent(core, retry) catch @panic("leased World retry abort");
    const id = (try server_mod.ManagedCoreFixture.commitLeasedEvent(core, retry)).?;
    retried = true;
    const expected_id = try oper.eventId(event.event());
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}
