//! Unadvertised bounded transactional assembly. No socket, peer or routing authority.
//! Caller owns one external lock through prepare/commit and the presence oracle.
//! Originals stay immutable; a decoded/retained chunk is not a recoverable receipt.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const codec = @import("../proto/guest_membership_snapshot.zig");
const presence = @import("../proto/mesh_presence_v3.zig");

pub const AssemblyLimits = struct {
    subjects: usize,
    manifests: usize,
    retained_bytes: usize,
    /// Includes the published state plus the complete unpublished candidate.
    peak_bytes: usize,
    channels: u64,
    chunks: u64,
    work_per_operation: u64,
    signature_attempts: usize,
    lifetime_ms: i64,
};
pub const Error = codec.Error || presence.Error || std.mem.Allocator.Error || error{
    BudgetExceeded,
    Overflow,
    NeedManifest,
    Expired,
    Incomplete,
    Quarantined,
    StalePrepared,
    BindingMismatch,
    GenerationExhausted,
};
pub const Subject = struct { origin: sign.PublicKey, guest: presence.GuestId };
pub const CurrentPresence = struct { wire: []const u8, generation: u64 };
/// This callback must read the actual authenticated currently admitted LIVE
/// presence owner AND unchanged visible nick winner under the same external cut.
/// Return null on expiry, quit, quarantine or an ambiguous/nonvisible winner.
/// Self-signed input is not a source. No live implementation is installed by this foundation.
pub const CurrentPresenceSource = struct {
    context: *anyopaque,
    read_fn: *const fn (*anyopaque, Subject, i64) ?CurrentPresence,
    fn read(self: CurrentPresenceSource, subject: Subject, now: i64) ?CurrentPresence {
        return self.read_fn(self.context, subject, now);
    }
};
pub const Disposition = enum { retained, duplicate, obsolete, quarantined, completed, expired };
const Chunk = struct { wire: []u8 };
const Entry = struct {
    wire: []u8 = &.{},
    id: codec.ManifestID = @splat(0),
    chunks: []Chunk = &.{},
    stream: ?[]u8 = null,
    // Prefunded negative witness; no allocation is needed to revoke authority.
    conflict_low: [32]u8 = @splat(0),
    conflict_high: [32]u8 = @splat(0),
    quarantined: bool = false,
    born_ms: i64 = 0,
    fn manifest(self: Entry) codec.DecodedManifest {
        return codec.decodeManifest(self.wire) catch unreachable;
    }
    fn deinit(self: *Entry, a: std.mem.Allocator) void {
        a.free(self.wire);
        for (self.chunks) |chunk| a.free(chunk.wire);
        a.free(self.chunks);
        if (self.stream) |value| a.free(value);
        self.* = .{};
    }
    fn clone(self: Entry, a: std.mem.Allocator) !Entry {
        var result = Entry{ .id = self.id, .quarantined = self.quarantined, .born_ms = self.born_ms, .conflict_low = self.conflict_low, .conflict_high = self.conflict_high };
        errdefer result.deinit(a);
        result.wire = try a.dupe(u8, self.wire);
        result.chunks = try a.alloc(Chunk, self.chunks.len);
        for (result.chunks) |*chunk| chunk.* = .{ .wire = &.{} };
        for (self.chunks, result.chunks) |old, *new| new.wire = try a.dupe(u8, old.wire);
        if (self.stream) |value| result.stream = try a.dupe(u8, value);
        return result;
    }
};
const State = struct {
    entries: []Entry = &.{},
    bytes_cache: usize = 0,
    reserved_cache: usize = 0,
    fn deinit(self: *State, a: std.mem.Allocator) void {
        for (self.entries) |*entry| entry.deinit(a);
        a.free(self.entries);
        self.* = .{};
    }
    fn bytes(self: State) Error!usize {
        return self.bytes_cache;
    }
    fn reserved(self: State) Error!usize {
        return self.reserved_cache;
    }
    /// Only unpublished, fully funded candidates are traversed here. Live
    /// operation preflight reads cached totals in O(1), before signature work.
    fn recount(self: *State) Error!void {
        var actual = try mul(self.entries.len, @sizeOf(Entry));
        var reserved_bytes: usize = 0;
        for (self.entries) |entry| {
            actual = try add(actual, entry.wire.len);
            actual = try add(actual, try mul(entry.chunks.len, @sizeOf(Chunk)));
            for (entry.chunks) |chunk| actual = try add(actual, chunk.wire.len);
            if (entry.stream) |value| actual = try add(actual, value.len);
            reserved_bytes = try add(reserved_bytes, try reservation(entry.manifest().record));
        }
        self.bytes_cache = actual;
        self.reserved_cache = reserved_bytes;
    }
    fn clone(self: State, a: std.mem.Allocator, extra: usize) !State {
        const rows = try a.alloc(Entry, try add(self.entries.len, extra));
        for (rows) |*entry| entry.* = .{};
        var result = State{ .entries = rows };
        errdefer result.deinit(a);
        for (self.entries, rows[0..self.entries.len]) |old, *new| new.* = try old.clone(a);
        return result;
    }
};
fn add(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.Overflow;
}
fn mul(a: usize, b: usize) Error!usize {
    return std.math.mul(usize, a, b) catch error.Overflow;
}
fn reservation(m: codec.Manifest) Error!usize {
    const bytes = std.math.cast(usize, m.encoded_bytes) orelse return error.Overflow;
    const chunks = std.math.cast(usize, m.chunk_count) orelse return error.Overflow;
    // Reserve originals, their exact sparse-index capacity, the complete owned
    // stream and the inline negative marker included in Entry before admission.
    var result = try add(@sizeOf(Entry), codec.manifest_wire_len);
    result = try add(result, try mul(bytes, 2));
    result = try add(result, try mul(chunks, codec.chunk_overhead + @sizeOf(Chunk)));
    return result;
}
fn sameSubject(m: codec.Manifest, s: Subject) bool {
    return std.mem.eql(u8, &m.origin, &s.origin) and std.mem.eql(u8, &m.guest, &s.guest);
}
fn subjectOf(m: codec.Manifest) Subject {
    return .{ .origin = m.origin, .guest = m.guest };
}
fn sameBody(a: []const u8, b: []const u8) bool {
    return a.len == b.len and a.len >= sign.signature_len and
        std.mem.eql(u8, a[0 .. a.len - sign.signature_len], b[0 .. b.len - sign.signature_len]);
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    limits: AssemblyLimits,
    generation: u64 = 1,
    security_generation: u64 = 1,
    terminal: bool = false,
    // Includes all unpublished candidates AND old states retained after swaps.
    // Credit is returned only after their storage has actually been freed.
    outstanding_reserved: usize = 0,
    state: State = .{},
    pub fn init(a: std.mem.Allocator, limits: AssemblyLimits) Store {
        return .{ .allocator = a, .limits = limits };
    }
    pub fn deinit(self: *Store) void {
        std.debug.assert(self.outstanding_reserved == 0);
        self.state.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn retainedBytes(self: *const Store) Error!usize {
        return self.state.bytes();
    }
    pub fn reservedBytes(self: *const Store) Error!usize {
        return add(try self.state.reserved(), self.outstanding_reserved);
    }
    fn fresh(self: *const Store, e: Entry, now: i64) bool {
        // A completed manifest has no lease of its own. Current admitted
        // presence alone governs its positive authority; lifetime bounds only
        // unfinished assembly, never extends a presence lease.
        return e.stream != null or (self.limits.lifetime_ms > 0 and now >= e.born_ms and now - e.born_ms < self.limits.lifetime_ms);
    }
    fn find(self: *const Store, origin: sign.PublicKey, id: codec.ManifestID) ?usize {
        for (self.state.entries, 0..) |entry, n| {
            const m = entry.manifest().record;
            if (std.mem.eql(u8, &entry.id, &id) and std.mem.eql(u8, &m.origin, &origin)) return n;
        }
        return null;
    }
    fn budget(self: *const Store, extra: usize, work: usize) Error!void {
        if (self.terminal or self.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
        const old = try self.state.reserved();
        const next = try add(old, extra);
        if (next > self.limits.retained_bytes or try add(try add(old, self.outstanding_reserved), next) > self.limits.peak_bytes or
            try add(work, try self.state.bytes()) > self.limits.work_per_operation or self.limits.lifetime_ms <= 0) return error.BudgetExceeded;
    }
    fn unchanged(self: *Store, disposition: Disposition) Prepared {
        return .{ .owner = self, .generation = self.generation, .security_generation = self.security_generation, .disposition = disposition };
    }
    fn staged(self: *Store, next: State, disposition: Disposition) Prepared {
        var owned = next;
        owned.recount() catch unreachable;
        const credit = owned.reserved_cache;
        const old_credit = self.state.reserved_cache;
        std.debug.assert(credit <= self.limits.retained_bytes);
        std.debug.assert(self.state.reserved_cache + self.outstanding_reserved + credit <= self.limits.peak_bytes);
        // budget() already reserved this complete candidate against every other
        // outstanding handle; no allocation/failure follows this ownership cut.
        self.outstanding_reserved += credit;
        return .{ .owner = self, .generation = self.generation, .security_generation = self.security_generation, .disposition = disposition, .next = owned, .credit = credit, .old_credit = old_credit };
    }
    pub fn reserveManifest(self: *Store, original: []const u8, roots: []const sign.PublicKey, now: i64) Error!Prepared {
        if (now < 0) return error.InvalidField;
        if (self.terminal or self.limits.signature_attempts == 0) return error.BudgetExceeded;
        const verify_work = try add(original.len, try mul(roots.len, @sizeOf(sign.PublicKey)));
        const census_work = try add(verify_work, try mul(self.state.entries.len, self.state.entries.len));
        if (try add(census_work, try self.state.bytes()) > self.limits.work_per_operation) return error.BudgetExceeded;
        const decoded = try codec.decodeManifest(original);
        try decoded.verify(roots);
        const m = decoded.record;
        const id = try decoded.id();
        var known = false;
        var newer = false;
        var channels: u64 = m.channel_count;
        var chunks: u64 = m.chunk_count;
        var subjects: usize = 0;
        for (self.state.entries, 0..) |entry, n| {
            const prior = entry.manifest().record;
            var first = true;
            for (self.state.entries[0..n]) |before| if (sameSubject(before.manifest().record, subjectOf(prior))) {
                first = false;
                break;
            };
            if (first) subjects = try add(subjects, 1);
            if (!sameSubject(prior, subjectOf(m))) continue;
            known = true;
            if (entry.quarantined) return error.Quarantined;
            if (prior.membership_revision == m.membership_revision) {
                if (std.mem.eql(u8, &entry.id, &id)) return self.unchanged(.duplicate);
                return self.quarantineVerified(n, entry.wire, original);
            }
            newer = newer or prior.membership_revision > m.membership_revision;
        }
        if (newer) return self.unchanged(.obsolete);
        for (self.state.entries) |entry| {
            const prior = entry.manifest().record;
            channels = std.math.add(u64, channels, prior.channel_count) catch return error.Overflow;
            chunks = std.math.add(u64, chunks, prior.chunk_count) catch return error.Overflow;
        }
        if (channels > self.limits.channels or chunks > self.limits.chunks or m.encoded_bytes > std.math.maxInt(usize)) return error.BudgetExceeded;
        if ((!known and subjects >= self.limits.subjects) or self.state.entries.len >= self.limits.manifests) return error.BudgetExceeded;
        try self.budget(try reservation(m), original.len);
        var next = try self.state.clone(self.allocator, 1);
        errdefer next.deinit(self.allocator);
        next.entries[next.entries.len - 1] = .{ .wire = try self.allocator.dupe(u8, original), .id = id, .born_ms = now };
        return self.staged(next, .retained);
    }
    /// Verified contradictions revoke positive authority even when ordinary
    /// generation is exhausted or a previously prepared clone will be aborted.
    /// Marker storage was reserved in Entry at original admission.
    fn quarantineVerified(self: *Store, index: usize, first: []const u8, incoming: []const u8) Prepared {
        const subject = subjectOf(self.state.entries[index].manifest().record);
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(first[0 .. first.len - sign.signature_len], &a, .{});
        std.crypto.hash.Blake3.hash(incoming[0 .. incoming.len - sign.signature_len], &b, .{});
        const order = std.mem.order(u8, &a, &b);
        for (self.state.entries) |*entry| if (sameSubject(entry.manifest().record, subject)) {
            entry.quarantined = true;
            entry.conflict_low = if (order == .gt) b else a;
            entry.conflict_high = if (order == .gt) a else b;
        };
        if (self.security_generation == std.math.maxInt(u64)) self.terminal = true else self.security_generation += 1;
        return self.unchanged(.quarantined);
    }
    pub fn acceptChunk(self: *Store, original: []const u8, roots: []const sign.PublicKey, now: i64) Error!Prepared {
        if (self.terminal or self.limits.signature_attempts == 0) return error.BudgetExceeded;
        const verify_work = try add(original.len, try mul(roots.len, @sizeOf(sign.PublicKey)));
        if (try add(verify_work, try self.state.bytes()) > self.limits.work_per_operation) return error.BudgetExceeded;
        const decoded = try codec.decodeChunk(original);
        try decoded.verify(roots);
        const index = self.find(decoded.record.origin, decoded.record.manifest_id) orelse return error.NeedManifest;
        const old = self.state.entries[index];
        if (old.quarantined) return error.Quarantined;
        if (!self.fresh(old, now)) return error.Expired;
        try decoded.requireManifest(old.manifest());
        for (old.chunks) |chunk| {
            const prior = (try codec.decodeChunk(chunk.wire)).record;
            if (prior.index != decoded.record.index) continue;
            if (sameBody(chunk.wire, original)) return self.unchanged(.duplicate);
            return self.quarantineVerified(index, chunk.wire, original);
        }
        try self.budget(0, original.len);
        // This temporary index copy is included in peak accounting before allocation.
        const index_bytes = try mul(old.chunks.len, @sizeOf(Chunk));
        if (try add(try add(try self.state.bytes(), try self.state.bytes()), try add(try add(index_bytes, self.outstanding_reserved), try add(@sizeOf(Chunk), original.len))) > self.limits.peak_bytes) return error.BudgetExceeded;
        var next = try self.state.clone(self.allocator, 0);
        errdefer next.deinit(self.allocator);
        const entry = &next.entries[index];
        const rows = try self.allocator.alloc(Chunk, try add(entry.chunks.len, 1));
        errdefer self.allocator.free(rows);
        @memcpy(rows[0..entry.chunks.len], entry.chunks);
        rows[entry.chunks.len] = .{ .wire = try self.allocator.dupe(u8, original) };
        self.allocator.free(entry.chunks);
        entry.chunks = rows;
        return self.staged(next, .retained);
    }
    fn binding(self: *const Store, entry: Entry, source: CurrentPresenceSource, now: i64) Error!CurrentPresence {
        if (entry.quarantined) return error.Quarantined;
        if (!self.fresh(entry, now)) return error.Expired;
        if (self.terminal) return error.Quarantined;
        const current = source.read(subjectOf(entry.manifest().record), now) orelse return error.BindingMismatch;
        const r = (try presence.decode(current.wire)).record;
        if (current.generation == 0 or r.operation != .present or now < 0 or r.expires_ms <= now or
            !presence.matchesManifest(r, entry.manifest())) return error.BindingMismatch;
        return current;
    }
    pub fn prepareComplete(self: *Store, origin: sign.PublicKey, id: codec.ManifestID, source: CurrentPresenceSource, now: i64) Error!Prepared {
        if (try self.state.bytes() > self.limits.work_per_operation) return error.BudgetExceeded;
        const index = self.find(origin, id) orelse return error.NeedManifest;
        const old = self.state.entries[index];
        const bound = try self.binding(old, source, now);
        if (old.stream != null) return self.unchanged(.duplicate);
        const m = old.manifest().record;
        if (old.chunks.len != m.chunk_count) return error.Incomplete;
        const len = std.math.cast(usize, m.encoded_bytes) orelse return error.Overflow;
        try self.budget(0, try add(len, old.chunks.len));
        var next = try self.state.clone(self.allocator, 0);
        errdefer next.deinit(self.allocator);
        const stream = try self.allocator.alloc(u8, len);
        next.entries[index].stream = stream;
        for (old.chunks) |chunk| {
            const c = (try codec.decodeChunk(chunk.wire)).record;
            const off = std.math.cast(usize, c.offset) orelse return error.Overflow;
            const end = try add(off, c.payload.len);
            if (end > stream.len) return error.BadReference;
            @memcpy(stream[off..end], c.payload);
        }
        try codec.validateSet(stream, m);
        var result = self.staged(next, .completed);
        result.presence_generation = bound.generation;
        result.binding_index = index;
        return result;
    }
    /// Every positive read reselects the owner's current reference. Missing newer
    /// complete state never falls through to a cached old complete set. The
    /// returned immutable stream borrows Store until its next commit/deinit;
    /// consume/copy it while retaining the same external owner lock.
    pub fn membership(self: *const Store, subject: Subject, source: CurrentPresenceSource, now: i64) ?[]const u8 {
        if (self.terminal) return null;
        const current = source.read(subject, now) orelse return null;
        const r = (presence.decode(current.wire) catch return null).record;
        if (!std.mem.eql(u8, &r.origin, &subject.origin) or !std.mem.eql(u8, &r.guest, &subject.guest)) return null;
        const index = self.find(subject.origin, r.manifest_id) orelse return null;
        const e = self.state.entries[index];
        _ = self.binding(e, source, now) catch return null;
        return e.stream;
    }
};

pub const Prepared = struct {
    owner: *Store,
    generation: u64,
    security_generation: u64,
    disposition: Disposition,
    next: ?State = null,
    credit: usize = 0,
    old_credit: usize = 0,
    presence_generation: u64 = 0,
    binding_index: usize = 0,
    done: bool = false,
    /// Validation can refuse stale ownership; after it succeeds, publication is
    /// one no-fail swap. Caller retains the same external lock throughout.
    pub fn commit(self: *Prepared, now_ms: i64, current_source: ?CurrentPresenceSource) Error!Disposition {
        if (self.done) return error.StalePrepared;
        self.done = true;
        if (self.owner.generation != self.generation or self.owner.terminal or
            self.owner.security_generation != self.security_generation) return error.StalePrepared;
        if (self.presence_generation != 0) {
            const source = current_source orelse return error.BindingMismatch;
            const current = try self.owner.binding(self.next.?.entries[self.binding_index], source, now_ms);
            if (current.generation != self.presence_generation) return error.BindingMismatch;
        }
        if (self.next) |*next| {
            std.mem.swap(State, &self.owner.state, next);
            self.owner.outstanding_reserved -= self.credit;
            self.owner.outstanding_reserved += self.old_credit;
            self.credit = self.old_credit;
            self.owner.generation += 1;
        }
        self.done = true;
        return self.disposition;
    }
    /// Also releases the old state after a committed swap, outside publication.
    pub fn abort(self: *Prepared) void {
        if (self.next) |*next| next.deinit(self.owner.allocator);
        self.owner.outstanding_reserved -= self.credit;
        self.credit = 0;
        self.next = null;
        self.done = true;
    }
};

fn testLimits() AssemblyLimits {
    return .{ .subjects = 8, .manifests = 16, .retained_bytes = 8 * 1024 * 1024, .peak_bytes = 32 * 1024 * 1024, .channels = 2000, .chunks = 64, .work_per_operation = 64 * 1024 * 1024, .signature_attempts = 1, .lifetime_ms = 500 };
}
fn testManifest(key: *const sign.KeyPair, stream: []const u8, count: u64, revision: u64) codec.Manifest {
    return .{ .origin = key.public_key, .guest = presence.guestId(.{ .epoch = 1, .counter = 1 }) catch unreachable, .claim_hlc = 1, .claim_revision = 1, .routing_class = .true_guest, .class_revision = 1, .membership_revision = revision, .scope = 1, .channel_count = count, .encoded_bytes = @intCast(stream.len), .chunk_payload_bytes = codec.chunk_payload_bytes, .chunk_count = codec.chunkCount(@intCast(stream.len)), .set_digest = codec.setDigest(stream) };
}
fn testPresence(key: *const sign.KeyPair, m: codec.DecodedManifest, out: []u8) ![]const u8 {
    return presence.encode(.{ .operation = .present, .origin = m.record.origin, .guest = m.record.guest, .revision = 5, .routing_class = m.record.routing_class, .class_revision = m.record.class_revision, .claim_hlc = m.record.claim_hlc, .claim_revision = m.record.claim_revision, .issued_ms = 1000, .expires_ms = 2000, .nick = "PhysicalGuest", .username = "guest", .host = "public.cloak", .realname = "Public identity", .server = "origin.test", .description = "Public server", .membership_revision = m.record.membership_revision, .manifest_id = try m.id() }, key, out);
}
const TestSource = struct {
    wire: []const u8,
    generation: u64 = 1,
    visible: bool = true,
    fn read(ctx: *anyopaque, subject: Subject, now: i64) ?CurrentPresence {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const r = (presence.decode(self.wire) catch return null).record;
        if (!self.visible or r.operation != .present or r.expires_ms <= now or
            !std.mem.eql(u8, &r.origin, &subject.origin) or !std.mem.eql(u8, &r.guest, &subject.guest)) return null;
        return .{ .wire = self.wire, .generation = self.generation };
    }
    fn source(self: *@This()) CurrentPresenceSource {
        return .{ .context = self, .read_fn = read };
    }
};
fn acceptManifestTest(store: *Store, wire: []const u8, key: *const sign.KeyPair) !void {
    var plan = try store.reserveManifest(wire, &.{key.public_key}, 1000);
    defer plan.abort();
    _ = try plan.commit(1000, null);
}
fn acceptChunkTest(store: *Store, key: *const sign.KeyPair, id: codec.ManifestID, stream: []const u8, index: u64) !void {
    const off: usize = @intCast(index * codec.chunk_payload_bytes);
    const len = @min(stream.len - off, codec.chunk_payload_bytes);
    var buf: [codec.chunk_overhead + codec.chunk_payload_bytes]u8 = undefined;
    const wire = try codec.encodeChunk(.{ .origin = key.public_key, .manifest_id = id, .index = index, .offset = off, .payload = stream[off..][0..len] }, key, &buf);
    var plan = try store.acceptChunk(wire, &.{key.public_key}, 1000);
    defer plan.abort();
    _ = try plan.commit(1000, null);
}
fn completeTest(store: *Store, key: *const sign.KeyPair, manifest: codec.DecodedManifest, source: *TestSource) !void {
    var plan = try store.prepareComplete(key.public_key, try manifest.id(), source.source(), 1000);
    defer plan.abort();
    _ = try plan.commit(1000, source.source());
}

test "guest membership assembly empty current binding no old fallback and live expiry" {
    var key = try sign.KeyPair.fromSeed(@splat(21));
    defer key.deinit();
    var store = Store.init(std.testing.allocator, testLimits());
    defer store.deinit();
    var bytes: [codec.manifest_wire_len]u8 = undefined;
    const manifest = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &bytes));
    try acceptManifestTest(&store, manifest.wire, &key);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, manifest, &pbuf) };
    try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1000) == null);
    try completeTest(&store, &key, manifest, &source);
    try std.testing.expectEqual(@as(usize, 0), store.membership(subjectOf(manifest.record), source.source(), 1000).?.len);
    // Completed manifest lifetime is only the CURRENT presence lifetime.
    try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1900) != null);
    try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 2000) == null);
    source.visible = false;
    try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1000) == null);
    source.visible = true;
    var newer = (try presence.decode(source.wire)).record;
    newer.membership_revision += 1;
    newer.manifest_id = @splat(9);
    var newer_buf: [presence.max_wire_len]u8 = undefined;
    source.wire = try presence.encode(newer, &key, &newer_buf);
    source.generation += 1;
    try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1000) == null);
    try std.testing.expect(store.state.entries[0].stream != null);
}

test "guest membership assembly reverse multichunk boundary streams and duplicate custody" {
    var key = try sign.KeyPair.fromSeed(@splat(22));
    defer key.deinit();
    const a = std.testing.allocator;
    const stream = try a.alloc(u8, 400 * 258);
    defer a.free(stream);
    for (0..400) |n| {
        const pos = n * 258;
        std.mem.writeInt(u16, stream[pos..][0..2], 256, .big);
        const name = stream[pos + 2 ..][0..256];
        @memset(name, 'a');
        name[0] = '#';
        var digits: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&digits, "{d:0>6}", .{n});
        @memcpy(name[1..][0..text.len], text);
    }
    try codec.validateStream(stream, 400);
    var tracker = PeakAllocator{ .child = a };
    var store = Store.init(tracker.allocator(), testLimits());
    defer store.deinit();
    var mbuf: [codec.manifest_wire_len]u8 = undefined;
    const manifest = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, stream, 400, 1), &key, &mbuf));
    const id = try manifest.id();
    try acceptManifestTest(&store, manifest.wire, &key);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, manifest, &pbuf) };
    for (0..@as(usize, @intCast(manifest.record.chunk_count))) |n| {
        try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1000) == null);
        try acceptChunkTest(&store, &key, id, stream, manifest.record.chunk_count - 1 - n);
        try std.testing.expect(tracker.peak <= store.limits.peak_bytes);
    }
    const before = try store.retainedBytes();
    const generation = store.generation;
    try acceptChunkTest(&store, &key, id, stream, 0);
    try std.testing.expectEqual(before, try store.retainedBytes());
    try std.testing.expectEqual(generation, store.generation);
    try completeTest(&store, &key, manifest, &source);
    try std.testing.expectEqualSlices(u8, stream, store.membership(subjectOf(manifest.record), source.source(), 1000).?);
}

test "guest membership verified conflict revokes without allocation and invalidates old plans" {
    var key = try sign.KeyPair.fromSeed(@splat(23));
    defer key.deinit();
    const a = std.testing.allocator;
    var store = Store.init(a, testLimits());
    defer store.deinit();
    var oldbuf: [codec.manifest_wire_len]u8 = undefined;
    const old = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &oldbuf));
    try acceptManifestTest(&store, old.wire, &key);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, old, &pbuf) };
    try completeTest(&store, &key, old, &source);
    var nextbuf: [codec.manifest_wire_len]u8 = undefined;
    const next = try codec.encodeManifest(testManifest(&key, "", 0, 2), &key, &nextbuf);
    var stale = try store.reserveManifest(next, &.{key.public_key}, 1000);
    defer stale.abort();
    var conflicting = old.record;
    conflicting.claim_hlc += 1;
    var badbuf: [codec.manifest_wire_len]u8 = undefined;
    const conflict = try codec.encodeManifest(conflicting, &key, &badbuf);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    store.allocator = fail.allocator();
    var negative = try store.reserveManifest(conflict, &.{key.public_key}, 1000);
    negative.abort();
    store.allocator = a;
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expect(store.membership(subjectOf(old.record), source.source(), 1000) == null);
    try std.testing.expectError(error.StalePrepared, stale.commit(1000, null));
    try std.testing.expectEqualSlices(u8, old.wire, store.state.entries[0].wire);
}

test "guest membership each zero budget refuses independently and origin approval precedes copying" {
    var key = try sign.KeyPair.fromSeed(@splat(24));
    defer key.deinit();
    var buf: [codec.manifest_wire_len]u8 = undefined;
    const wire = try codec.encodeManifest(testManifest(&key, "\x00\x02#a", 1, 1), &key, &buf);
    inline for (.{ "subjects", "manifests", "retained_bytes", "peak_bytes", "channels", "chunks", "work_per_operation", "signature_attempts", "lifetime_ms" }) |field| {
        var limits = testLimits();
        @field(limits, field) = 0;
        var store = Store.init(std.testing.allocator, limits);
        defer store.deinit();
        try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(wire, &.{key.public_key}, 1000));
        try std.testing.expectEqual(@as(usize, 0), store.state.entries.len);
    }
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var store = Store.init(fail.allocator(), testLimits());
    defer store.deinit();
    try std.testing.expectError(error.UnapprovedOrigin, store.reserveManifest(wire, &.{}, 1000));
    try std.testing.expect(!fail.has_induced_failure);
}

fn assemblyOomCampaign(a: std.mem.Allocator) !void {
    var key = try sign.KeyPair.fromSeed(@splat(25));
    defer key.deinit();
    var store = Store.init(a, testLimits());
    defer store.deinit();
    const stream = "\x00\x02#a";
    var buf: [codec.manifest_wire_len]u8 = undefined;
    const manifest = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, stream, 1, 1), &key, &buf));
    try acceptManifestTest(&store, manifest.wire, &key);
    const old_generation = store.generation;
    const old_bytes = try store.retainedBytes();
    acceptChunkTest(&store, &key, try manifest.id(), stream, 0) catch |err| {
        try std.testing.expectEqual(old_generation, store.generation);
        try std.testing.expectEqual(old_bytes, try store.retainedBytes());
        try std.testing.expectEqual(@as(usize, 0), store.state.entries[0].chunks.len);
        return err;
    };
    const chunk_generation = store.generation;
    const chunk_bytes = try store.retainedBytes();
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, manifest, &pbuf) };
    completeTest(&store, &key, manifest, &source) catch |err| {
        try std.testing.expectEqual(chunk_generation, store.generation);
        try std.testing.expectEqual(chunk_bytes, try store.retainedBytes());
        try std.testing.expect(store.state.entries[0].stream == null);
        try std.testing.expect(store.membership(subjectOf(manifest.record), source.source(), 1000) == null);
        return err;
    };
    try std.testing.expectEqualSlices(u8, stream, store.membership(subjectOf(manifest.record), source.source(), 1000).?);
}
test "guest membership every normal allocation failure preserves accepted custody and permits retry" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, assemblyOomCampaign, .{});
}

test "guest membership conflict cut survives generation exhaustion and stale live binding cannot commit" {
    var key = try sign.KeyPair.fromSeed(@splat(26));
    defer key.deinit();
    var store = Store.init(std.testing.allocator, testLimits());
    defer store.deinit();
    var buf: [codec.manifest_wire_len]u8 = undefined;
    const m = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &buf));
    try acceptManifestTest(&store, m.wire, &key);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, m, &pbuf) };
    var pending = try store.prepareComplete(key.public_key, try m.id(), source.source(), 1000);
    defer pending.abort();
    source.generation += 1;
    try std.testing.expectError(error.BindingMismatch, pending.commit(1000, source.source()));
    try std.testing.expectError(error.StalePrepared, pending.commit(1000, source.source()));
    pending.abort();
    try completeTest(&store, &key, m, &source);
    var changed = m.record;
    changed.class_revision += 1;
    var other: [codec.manifest_wire_len]u8 = undefined;
    const conflict = try codec.encodeManifest(changed, &key, &other);
    store.generation = std.math.maxInt(u64);
    store.security_generation = std.math.maxInt(u64);
    var plan = try store.reserveManifest(conflict, &.{key.public_key}, 1000);
    plan.abort();
    try std.testing.expect(store.terminal);
    try std.testing.expect(store.membership(subjectOf(m.record), source.source(), 1000) == null);
}

test "guest membership invalid complete stream and wrong subject never grant partial authority" {
    var key = try sign.KeyPair.fromSeed(@splat(27));
    defer key.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(28));
    defer other.deinit();
    var store = Store.init(std.testing.allocator, testLimits());
    defer store.deinit();
    const stream = "\x00\x02&a";
    var mbuf: [codec.manifest_wire_len]u8 = undefined;
    const m = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, stream, 1, 1), &key, &mbuf));
    try acceptManifestTest(&store, m.wire, &key);
    var cbuf: [codec.chunk_overhead + 4]u8 = undefined;
    const wrong = try codec.encodeChunk(.{ .origin = other.public_key, .manifest_id = try m.id(), .index = 0, .offset = 0, .payload = stream }, &other, &cbuf);
    try std.testing.expectError(error.NeedManifest, store.acceptChunk(wrong, &.{other.public_key}, 1000));
    try acceptChunkTest(&store, &key, try m.id(), stream, 0);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, m, &pbuf) };
    const generation = store.generation;
    try std.testing.expectError(error.InvalidSet, store.prepareComplete(key.public_key, try m.id(), source.source(), 1000));
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expect(store.membership(subjectOf(m.record), source.source(), 1000) == null);
    try std.testing.expectError(error.Expired, store.prepareComplete(key.public_key, try m.id(), source.source(), 1600));
}

test "guest membership aggregates declared credits and normal generation never wraps" {
    var key = try sign.KeyPair.fromSeed(@splat(29));
    defer key.deinit();
    var limits = testLimits();
    limits.channels = 1;
    limits.chunks = 1;
    var store = Store.init(std.testing.allocator, limits);
    defer store.deinit();
    var a: [codec.manifest_wire_len]u8 = undefined;
    var b: [codec.manifest_wire_len]u8 = undefined;
    const first = try codec.encodeManifest(testManifest(&key, "\x00\x02#a", 1, 1), &key, &a);
    try acceptManifestTest(&store, first, &key);
    const next = try codec.encodeManifest(testManifest(&key, "\x00\x02#b", 1, 2), &key, &b);
    try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(next, &.{key.public_key}, 1000));
    store.limits = testLimits();
    store.generation = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, store.reserveManifest(next, &.{key.public_key}, 1000));
}

fn alternateSignature(comptime domain: []const u8, key: *const sign.KeyPair, wire: []u8) !void {
    // Use the existing frozen dual-verify transcript; no new crypto semantics.
    const magic = "onyx-ed25519ctx-v1";
    const end = wire.len - sign.signature_len;
    const input = try std.testing.allocator.alloc(u8, magic.len + 1 + domain.len + end);
    defer std.testing.allocator.free(input);
    @memcpy(input[0..magic.len], magic);
    input[magic.len] = @intCast(domain.len);
    @memcpy(input[magic.len + 1 ..][0..domain.len], domain);
    @memcpy(input[magic.len + 1 + domain.len ..], wire[0..end]);
    const sig = try key.sign(input);
    @memcpy(wire[end..], &sig);
}
test "guest membership valid alternate signature is a body duplicate and preserves first original" {
    var key = try sign.KeyPair.fromSeed(@splat(30));
    defer key.deinit();
    var store = Store.init(std.testing.allocator, testLimits());
    defer store.deinit();
    var original: [codec.manifest_wire_len]u8 = undefined;
    const wire = try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &original);
    try acceptManifestTest(&store, wire, &key);
    var alternate = original;
    try alternateSignature(codec.manifest_domain, &key, &alternate);
    try (try codec.decodeManifest(&alternate)).verify(&.{key.public_key});
    try std.testing.expect(!std.mem.eql(u8, &original, &alternate));
    var duplicate = try store.reserveManifest(&alternate, &.{key.public_key}, 1000);
    defer duplicate.abort();
    try std.testing.expectEqual(Disposition.duplicate, try duplicate.commit(1000, null));
    try std.testing.expectEqualSlices(u8, &original, store.state.entries[0].wire);
}

test "guest membership current claim class and reference mismatches cannot activate cached sets" {
    var key = try sign.KeyPair.fromSeed(@splat(31));
    defer key.deinit();
    var store = Store.init(std.testing.allocator, testLimits());
    defer store.deinit();
    var mbuf: [codec.manifest_wire_len]u8 = undefined;
    const m = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &mbuf));
    try acceptManifestTest(&store, m.wire, &key);
    var pbuf: [presence.max_wire_len]u8 = undefined;
    var source = TestSource{ .wire = try testPresence(&key, m, &pbuf) };
    try completeTest(&store, &key, m, &source);
    const original = (try presence.decode(source.wire)).record;
    inline for (.{ "claim_hlc", "claim_revision", "class_revision", "membership_revision" }) |field| {
        var changed = original;
        @field(changed, field) += 1;
        var changed_buf: [presence.max_wire_len]u8 = undefined;
        source.wire = try presence.encode(changed, &key, &changed_buf);
        try std.testing.expect(store.membership(subjectOf(m.record), source.source(), 1000) == null);
    }
    var changed = original;
    changed.routing_class = .authenticated_untracked;
    var changed_buf: [presence.max_wire_len]u8 = undefined;
    source.wire = try presence.encode(changed, &key, &changed_buf);
    try std.testing.expect(store.membership(subjectOf(m.record), source.source(), 1000) == null);
}

test "guest membership valid index conflicts revoke without allocation and canonicalize witness pair" {
    var key = try sign.KeyPair.fromSeed(@splat(32));
    defer key.deinit();
    var reference: ?[2][32]u8 = null;
    for ([_]bool{ false, true }) |reverse| {
        const a = std.testing.allocator;
        var store = Store.init(a, testLimits());
        defer store.deinit();
        const stream = "\x00\x02#a";
        var mbuf: [codec.manifest_wire_len]u8 = undefined;
        const m = try codec.decodeManifest(try codec.encodeManifest(testManifest(&key, stream, 1, 1), &key, &mbuf));
        try acceptManifestTest(&store, m.wire, &key);
        const first = if (reverse) "\x00\x02#b" else stream;
        const second = if (reverse) stream else "\x00\x02#b";
        try acceptChunkTest(&store, &key, try m.id(), first, 0);
        var cbuf: [codec.chunk_overhead + 4]u8 = undefined;
        const wire = try codec.encodeChunk(.{ .origin = key.public_key, .manifest_id = try m.id(), .index = 0, .offset = 0, .payload = second }, &key, &cbuf);
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        store.allocator = fail.allocator();
        var plan = try store.acceptChunk(wire, &.{key.public_key}, 1000);
        plan.abort();
        store.allocator = a;
        try std.testing.expect(!fail.has_induced_failure);
        try std.testing.expect(store.state.entries[0].quarantined);
        const witnesses = [2][32]u8{ store.state.entries[0].conflict_low, store.state.entries[0].conflict_high };
        if (reference) |old| try std.testing.expectEqualDeep(old, witnesses) else reference = witnesses;
    }
}

const PeakAllocator = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    allocations: usize = 0,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const bytes = self.child.rawAlloc(len, alignment, ra) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        self.allocations += 1;
        return bytes;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.live -= bytes.len;
        self.child.rawFree(bytes, alignment, ra);
    }
};
test "guest membership exact peak retains every simultaneous clone and conflict-stale credit" {
    var key = try sign.KeyPair.fromSeed(@splat(33));
    defer key.deinit();
    var tracker = PeakAllocator{ .child = std.testing.allocator };
    {
        var store = Store.init(tracker.allocator(), testLimits());
        defer store.deinit();
        var m1: [codec.manifest_wire_len]u8 = undefined;
        var m2: [codec.manifest_wire_len]u8 = undefined;
        var m3: [codec.manifest_wire_len]u8 = undefined;
        const first = try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &m1);
        const second = try codec.encodeManifest(testManifest(&key, "", 0, 2), &key, &m2);
        const third = try codec.encodeManifest(testManifest(&key, "", 0, 3), &key, &m3);
        try acceptManifestTest(&store, first, &key);
        const row = store.state.reserved_cache;
        try std.testing.expectEqual(row, tracker.live);
        store.limits.peak_bytes = 5 * row;
        var p = try store.reserveManifest(second, &.{key.public_key}, 1000);
        defer p.abort();
        var q = try store.reserveManifest(third, &.{key.public_key}, 1000);
        defer q.abort();
        try std.testing.expectEqual(store.limits.peak_bytes, tracker.peak);
        try std.testing.expectEqual(4 * row, store.outstanding_reserved);
        const allocations = tracker.allocations;
        try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(third, &.{key.public_key}, 1000));
        try std.testing.expectEqual(allocations, tracker.allocations);
        var conflict = (try codec.decodeManifest(first)).record;
        conflict.claim_hlc += 1;
        var cbuf: [codec.manifest_wire_len]u8 = undefined;
        var negative = try store.reserveManifest(try codec.encodeManifest(conflict, &key, &cbuf), &.{key.public_key}, 1000);
        negative.abort();
        try std.testing.expectEqual(allocations, tracker.allocations);
        try std.testing.expectError(error.StalePrepared, p.commit(1000, null));
        try std.testing.expectEqual(4 * row, store.outstanding_reserved);
        p.abort();
        try std.testing.expectEqual(2 * row, store.outstanding_reserved);
        p.abort();
        try std.testing.expectEqual(2 * row, store.outstanding_reserved);
        q.abort();
        try std.testing.expectEqual(@as(usize, 0), store.outstanding_reserved);
        try std.testing.expectEqual(row, tracker.live);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.live);
}
test "guest membership commit holds old credit until free before another preparation" {
    var key = try sign.KeyPair.fromSeed(@splat(34));
    defer key.deinit();
    var tracker = PeakAllocator{ .child = std.testing.allocator };
    {
        var store = Store.init(tracker.allocator(), testLimits());
        defer store.deinit();
        var a: [codec.manifest_wire_len]u8 = undefined;
        var b: [codec.manifest_wire_len]u8 = undefined;
        var c: [codec.manifest_wire_len]u8 = undefined;
        try acceptManifestTest(&store, try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &a), &key);
        const row = store.state.reserved_cache;
        store.limits.peak_bytes = 5 * row;
        var p = try store.reserveManifest(try codec.encodeManifest(testManifest(&key, "", 0, 2), &key, &b), &.{key.public_key}, 1000);
        defer p.abort();
        _ = try p.commit(1000, null);
        try std.testing.expectEqual(row, store.outstanding_reserved);
        try std.testing.expectEqual(3 * row, tracker.live);
        const third = try codec.encodeManifest(testManifest(&key, "", 0, 3), &key, &c);
        const allocations = tracker.allocations;
        try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(third, &.{key.public_key}, 1000));
        try std.testing.expectEqual(allocations, tracker.allocations);
        p.abort();
        try std.testing.expectEqual(2 * row, tracker.live);
        var q = try store.reserveManifest(third, &.{key.public_key}, 1000);
        defer q.abort();
        try std.testing.expectEqual(store.limits.peak_bytes, tracker.peak);
        q.abort();
        try std.testing.expectEqual(@as(usize, 0), store.outstanding_reserved);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.live);
}

test "guest membership distinct subjects and chunk credits are independent aggregate bounds" {
    var key = try sign.KeyPair.fromSeed(@splat(35));
    defer key.deinit();
    var limits = testLimits();
    limits.subjects = 1;
    var store = Store.init(std.testing.allocator, limits);
    defer store.deinit();
    var a: [codec.manifest_wire_len]u8 = undefined;
    var b: [codec.manifest_wire_len]u8 = undefined;
    try acceptManifestTest(&store, try codec.encodeManifest(testManifest(&key, "", 0, 1), &key, &a), &key);
    var other = testManifest(&key, "", 0, 1);
    other.guest = try presence.guestId(.{ .epoch = 1, .counter = 2 });
    try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(try codec.encodeManifest(other, &key, &b), &.{key.public_key}, 1000));
    store.limits = testLimits();
    store.limits.chunks = 0;
    const nonempty = testManifest(&key, "\x00\x02#a", 1, 2);
    try std.testing.expectError(error.BudgetExceeded, store.reserveManifest(try codec.encodeManifest(nonempty, &key, &b), &.{key.public_key}, 1000));
    try std.testing.expectEqual(@as(usize, 1), store.state.entries.len);
}
