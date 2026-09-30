// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account SCRAM-SHA-256 + SCRAM-SHA-512 credential store for the Onyx Server
//! IRC daemon.
//!
//! The account database (see `services.zig`) only persists a PBKDF2 password
//! hash, which is enough to verify PLAIN but carries no SCRAM-specific material.
//! A SCRAM-SHA-256 exchange (RFC 5802 / RFC 7677) instead needs, per account, a
//! `{salt, iteration_count, StoredKey, ServerKey}` tuple so the server can run
//! the challenge/response without ever seeing the cleartext password again.
//!
//! This module owns that tuple in memory. It mirrors the account store rather
//! than persisting: the daemon repopulates it as accounts register (and could
//! backfill on load), so a restart simply re-derives nothing — clients must
//! re-register or re-identify to seed credentials. Keeping it in memory avoids
//! widening the on-disk account record format while still letting a live
//! SCRAM-SHA-256 exchange complete against a registered account.
//!
//! Storage uses an unmanaged map keyed by the canonical (lowercased) account
//! name. The map owns every key and the variable-length salt bytes; the
//! fixed-size StoredKey/ServerKey digests are stored inline by value. All bytes
//! are duplicated on insert and freed on overwrite or teardown.

const std = @import("std");

const sasl = @import("../proto/sasl.zig");
const scram512 = @import("../proto/sasl_scram512_server.zig");
const mechrouter = @import("../proto/sasl_mechrouter.zig");
const crypto_random = @import("../crypto/random.zig");
const rwlock = @import("../substrate/rwlock.zig");

/// SCRAM-SHA-256 digest length (StoredKey / ServerKey size), in bytes.
/// Derived from `ScramRecord` so it tracks the canonical record definition.
pub const digest_len = @typeInfo(@FieldType(sasl.ScramRecord, "stored_key")).array.len;

/// SCRAM-SHA-512 digest length (StoredKey / ServerKey size), in bytes. Derived
/// from the SHA-512 responder's `Credential` so it tracks that definition.
pub const digest512_len = scram512.digest_len;

/// Salt length, in bytes, generated for new SCRAM credentials. 16 bytes matches
/// the account store's PBKDF2 salt width and exceeds the RFC's minimum.
pub const salt_len: usize = 16;

/// PBKDF2-HMAC-SHA256 iteration count used when deriving SCRAM credentials.
/// RFC 7677 mandates a minimum of 4096; the higher default here matches the
/// account store's password-hashing cost so SCRAM is no weaker than PLAIN.
pub const default_iterations: u32 = 100_000;

/// Errors surfaced when deriving or storing SCRAM credentials.
pub const ScramStoreError = error{
    /// Kernel entropy was unavailable while generating a salt.
    EntropyFailed,
    /// PBKDF2/HMAC key derivation rejected the parameters.
    DeriveFailed,
    /// The account name was empty or exceeded the supported length.
    InvalidAccount,
    /// Allocation failed while duplicating the key or salt.
    OutOfMemory,
};

/// Maximum supported account-name length. Matches the account store's
/// `account_max` so any registrable account name fits.
const MAX_ACCOUNT_LEN: usize = 32;

/// Capacity of the ring that briefly retains salt duplicates handed back by
/// `lookup`/`lookup512`. A returned `salt` borrows store-owned memory because a
/// concurrent overwrite (e.g. a password change on the same account) can free
/// the entry's own salt once the lookup lock is released. The SASL exchange,
/// however, consumes that salt SYNCHRONOUSLY and without blocking inside a
/// single `Router.receive()` call — it is base64-encoded into the server-first
/// message immediately and is never retained across client messages — so a
/// returned dupe is live only for a brief, lock-free window on one thread.
///
/// The store therefore keeps at most this many recent dupes and frees the
/// oldest when the ring recycles a slot. This bounds what was a process-lifetime
/// leak: `lookup` duplicated the salt into an ever-growing list freed only at
/// `deinit`, so any client that could begin a SASL-SCRAM exchange (no auth
/// required — the salt is returned before proof verification) leaked one dupe
/// per start. The capacity vastly exceeds the number of reactor threads that can
/// be mid-exchange at once, so a recycled slot is always past its consumer's
/// synchronous window.
const salt_ring_capacity: usize = 512;

/// One account's stored SCRAM material. The salt is an owned, heap-allocated
/// slice; the digests are inline fixed arrays.
///
/// SHA-512 material (`stored_key_512` / `server_key_512`) is derived from the
/// SAME password, salt, and iteration count as the SHA-256 set, so no second
/// salt is needed. `has_512` distinguishes an account that was provisioned with
/// SHA-512 from one loaded from an old (SHA-256-only) durable record: when
/// false, a SHA-512 lookup returns null and SCRAM-SHA-512 is simply not offered
/// until the account is re-provisioned.
const Entry = struct {
    salt: []u8,
    iterations: u32,
    stored_key: [digest_len]u8,
    server_key: [digest_len]u8,
    has_512: bool = false,
    stored_key_512: [digest512_len]u8 = @splat(0),
    server_key_512: [digest512_len]u8 = @splat(0),
};

/// In-memory registry of per-account SCRAM-SHA-256 credentials.
pub const ScramStore = struct {
    allocator: std.mem.Allocator,
    /// Maps canonical account name -> SCRAM material. Keys and salt bytes owned.
    entries: std.StringHashMapUnmanaged(Entry),
    /// Bounded ring of recently-returned salt dupes (see `salt_ring_capacity`).
    /// Each returned `lookup` salt lives here only until the ring recycles its
    /// slot, replacing the old process-lifetime retention.
    lookup_salts: [salt_ring_capacity]?[]u8 = @splat(null),
    lookup_salt_head: usize = 0,
    lock: rwlock.RwLock = .{},
    /// Optional durable backfill source consulted by `resolve` on a miss.
    loader: ?Loader = null,

    /// Create an empty store backed by `allocator`.
    pub fn init(allocator: std.mem.Allocator) ScramStore {
        return .{ .allocator = allocator, .entries = .empty };
    }

    /// Free every owned key and salt, then the backing table. The store must
    /// not be used after this call.
    pub fn deinit(self: *ScramStore) void {
        {
            self.lock.lockExclusive();
            defer self.lock.unlockExclusive();

            var it = self.entries.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                // Scrub the salt before release: it is not secret on its own, but
                // co-locating zeroization with key material keeps the policy local.
                secureZero(entry.value_ptr.salt);
                self.allocator.free(entry.value_ptr.salt);
                secureZero(&entry.value_ptr.stored_key);
                secureZero(&entry.value_ptr.server_key);
                secureZero(&entry.value_ptr.stored_key_512);
                secureZero(&entry.value_ptr.server_key_512);
            }
            self.entries.deinit(self.allocator);
            for (self.lookup_salts) |maybe_salt| {
                if (maybe_salt) |salt| {
                    secureZero(salt);
                    self.allocator.free(salt);
                }
            }
        }
        self.* = undefined;
    }

    /// Retain a store-owned salt dupe in the bounded ring, freeing (and
    /// scrubbing) whatever dupe its slot recycles. The caller must hold the
    /// exclusive lock. Never fails — the ring is fixed-size, so a returned
    /// `lookup` never has to unwind a failed retain.
    fn retainLookupSalt(self: *ScramStore, salt: []u8) void {
        if (self.lookup_salts[self.lookup_salt_head]) |old| {
            secureZero(old);
            self.allocator.free(old);
        }
        self.lookup_salts[self.lookup_salt_head] = salt;
        self.lookup_salt_head = (self.lookup_salt_head + 1) % salt_ring_capacity;
    }

    /// Derive SCRAM-SHA-256 credentials for `account` from `password` using a
    /// freshly generated salt and `default_iterations`, then store them. An
    /// existing entry for the same account is overwritten (its prior salt and
    /// digests are freed/scrubbed first). The cleartext password is never
    /// retained.
    ///
    /// The salt is drawn from Linux `getrandom(2)` via the crypto entropy layer
    /// — never `std.crypto.random` — so it is suitable for credential material.
    pub fn deriveAndStore(
        self: *ScramStore,
        account: []const u8,
        password: []const u8,
    ) ScramStoreError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        var salt: [salt_len]u8 = undefined;
        crypto_random.fillOsEntropy(&salt) catch return error.EntropyFailed;
        defer secureZero(&salt);

        try self.storeWithSaltUnlocked(account, password, &salt, default_iterations);
    }

    /// Derive and store SCRAM credentials using a caller-supplied salt and
    /// iteration count. Exposed primarily for deterministic tests and for
    /// callers that must reuse a salt; production registration should prefer
    /// `deriveAndStore`, which generates a fresh salt.
    pub fn storeWithSalt(
        self: *ScramStore,
        account: []const u8,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
    ) ScramStoreError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        try self.storeWithSaltUnlocked(account, password, salt, iterations);
    }

    fn storeWithSaltUnlocked(
        self: *ScramStore,
        account: []const u8,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
    ) ScramStoreError!void {
        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        // Derive into a temporary record; the salt slice borrows the caller's
        // buffer only for the duration of derivation.
        const record = sasl.recordFromPassword(password, salt, iterations) catch
            return error.DeriveFailed;

        // Derive the SHA-512 SCRAM keys from the SAME password/salt/iterations
        // (RFC 5802 with SHA-512). Reuses the proven SHA-512 responder so no
        // SCRAM math is hand-rolled here. The intermediate `ClientKey` and
        // `SaltedPassword` are wiped by `ScramKeys.wipe`.
        var keys512 = scram512.deriveScramKeys(password, salt, iterations) catch
            return error.DeriveFailed;
        defer keys512.wipe();

        // Duplicate the salt into store-owned memory before touching the map so
        // a failure leaves existing state intact.
        const owned_salt = self.allocator.dupe(u8, salt) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_salt);

        const new_entry = Entry{
            .salt = owned_salt,
            .iterations = iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
            .has_512 = true,
            .stored_key_512 = keys512.stored_key,
            .server_key_512 = keys512.server_key,
        };

        if (self.entries.getEntry(account)) |existing| {
            // Overwrite in place: scrub and free the prior salt/digests, keep
            // the map's owned key.
            secureZero(existing.value_ptr.salt);
            self.allocator.free(existing.value_ptr.salt);
            secureZero(&existing.value_ptr.stored_key);
            secureZero(&existing.value_ptr.server_key);
            secureZero(&existing.value_ptr.stored_key_512);
            secureZero(&existing.value_ptr.server_key_512);
            existing.value_ptr.* = new_entry;
            return;
        }

        const owned_key = self.allocator.dupe(u8, account) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_key);
        try self.entries.put(self.allocator, owned_key, new_entry);
    }

    /// Insert a PRECOMPUTED SCRAM record (salt, iterations, stored_key,
    /// server_key) directly, WITHOUT re-deriving from a password. Used to
    /// repopulate the store from durable storage after a restart. Overwrites any
    /// existing entry for the account.
    ///
    /// The SHA-256-only `sasl.ScramRecord` carries no SHA-512 material, so the
    /// imported entry has `has_512 = false` and SCRAM-SHA-512 stays unavailable
    /// for it until re-provisioned. Use `importFullRecord` to restore SHA-512
    /// material from a durable record that includes it.
    pub fn importRecord(self: *ScramStore, account: []const u8, record: sasl.ScramRecord) ScramStoreError!void {
        return self.importFullRecord(account, .{
            .salt = record.salt,
            .iterations = record.iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
        });
    }

    /// Insert a precomputed record that may additionally carry SHA-512 SCRAM
    /// material. Used by the durable-store backfill loader so a SCRAM-SHA-512
    /// login resolves after a restart. Overwrites any existing entry.
    pub fn importFullRecord(self: *ScramStore, account: []const u8, record: FullRecord) ScramStoreError!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;

        const owned_salt = self.allocator.dupe(u8, record.salt) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_salt);

        const new_entry = Entry{
            .salt = owned_salt,
            .iterations = record.iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
            .has_512 = record.has_512,
            .stored_key_512 = record.stored_key_512,
            .server_key_512 = record.server_key_512,
        };

        if (self.entries.getEntry(account)) |existing| {
            secureZero(existing.value_ptr.salt);
            self.allocator.free(existing.value_ptr.salt);
            secureZero(&existing.value_ptr.stored_key);
            secureZero(&existing.value_ptr.server_key);
            secureZero(&existing.value_ptr.stored_key_512);
            secureZero(&existing.value_ptr.server_key_512);
            existing.value_ptr.* = new_entry;
            return;
        }

        const owned_key = self.allocator.dupe(u8, account) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_key);
        try self.entries.put(self.allocator, owned_key, new_entry);
    }

    /// Reserves a credential replacement while retaining the exclusive lock.
    /// The caller may commit its durable account transaction before publishing
    /// this candidate. Commit and abort allocate nothing. Do not copy an active
    /// prepared import, or call back into this store until it is consumed.
    pub fn prepareImportFullRecord(self: *ScramStore, account: []const u8, record: FullRecord) ScramStoreError!PreparedImport {
        self.lock.lockExclusive();
        errdefer self.lock.unlockExclusive();
        if (account.len == 0 or account.len > MAX_ACCOUNT_LEN) return error.InvalidAccount;
        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        for (key) |*ch| ch.* = std.ascii.toLower(ch.*);
        const salt = try self.allocator.dupe(u8, record.salt);
        errdefer {
            secureZero(salt);
            self.allocator.free(salt);
        }
        if (!self.entries.contains(key)) try self.entries.ensureUnusedCapacity(self.allocator, 1);
        return .{
            .store = self,
            .key = key,
            .entry = .{
                .salt = salt,
                .iterations = record.iterations,
                .stored_key = record.stored_key,
                .server_key = record.server_key,
                .has_512 = record.has_512,
                .stored_key_512 = record.stored_key_512,
                .server_key_512 = record.server_key_512,
            },
        };
    }

    pub const PreparedImport = struct {
        store: ?*ScramStore,
        key: []u8,
        entry: Entry,

        pub fn commit(self: *PreparedImport) void {
            const store = self.store orelse return;
            if (store.entries.getEntry(self.key)) |old| {
                wipeEntry(store.allocator, old.value_ptr);
                old.value_ptr.* = self.entry;
                store.allocator.free(self.key);
            } else {
                store.entries.putAssumeCapacityNoClobber(self.key, self.entry);
            }
            self.store = null;
            // The map owns the candidate now; clear the token's digest copies.
            secureZero(std.mem.asBytes(&self.entry));
            store.lock.unlockExclusive();
        }

        pub fn abort(self: *PreparedImport) void {
            const store = self.store orelse return;
            wipeEntry(store.allocator, &self.entry);
            store.allocator.free(self.key);
            self.store = null;
            store.lock.unlockExclusive();
        }

        pub fn deinit(self: *PreparedImport) void {
            self.abort();
        }

        fn wipeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
            secureZero(entry.salt);
            allocator.free(entry.salt);
            secureZero(std.mem.asBytes(entry));
        }
    };

    /// A precomputed credential record carrying BOTH the SHA-256 SCRAM material
    /// and, when `has_512` is set, the SHA-512 material derived from the same
    /// password/salt/iterations. The `salt` slice borrows caller memory; copy it
    /// if it must outlive the call. This is the durable-record shape used to
    /// restore SCRAM-SHA-512 across a restart.
    pub const FullRecord = struct {
        salt: []const u8,
        iterations: u32,
        stored_key: [digest_len]u8,
        server_key: [digest_len]u8,
        has_512: bool = false,
        stored_key_512: [digest512_len]u8 = @splat(0),
        server_key_512: [digest512_len]u8 = @splat(0),

        /// View the SHA-256 portion as the legacy `sasl.ScramRecord`.
        pub fn sha256(self: FullRecord) sasl.ScramRecord {
            return .{
                .salt = self.salt,
                .iterations = self.iterations,
                .stored_key = self.stored_key,
                .server_key = self.server_key,
            };
        }

        /// View the SHA-512 portion as a `scram512.Credential`, or null when this
        /// record carries no SHA-512 material.
        pub fn sha512(self: FullRecord) ?scram512.Credential {
            if (!self.has_512) return null;
            return .{
                .salt = self.salt,
                .iterations = self.iterations,
                .stored_key = self.stored_key_512,
                .server_key = self.server_key_512,
            };
        }
    };

    /// Backfill source for `resolve`: when an account is missing from the live
    /// store, `loadFn` is consulted (e.g. a durable on-disk mirror). It must
    /// protect the source record through import into the destination, ordering
    /// publication against password reset. No borrowed source bytes escape.
    /// The callback runs without this store's lock; source locks precede SCRAM.
    pub const Loader = struct {
        ptr: *anyopaque,
        loadFn: *const fn (ptr: *anyopaque, account: []const u8, destination: *ScramStore) bool,
    };

    /// Attach (or clear) the backfill loader consulted on a `resolve` miss.
    pub fn setLoader(self: *ScramStore, loader: ?Loader) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        self.loader = loader;
    }

    /// Backfill the account from the durable loader on a live-store miss, caching
    /// the loaded record. Returns true when the entry now exists in the live
    /// store. Shared by the SHA-256 and SHA-512 resolve paths.
    fn backfill(self: *ScramStore, account: []const u8) bool {
        const loader = blk: {
            self.lock.lockShared();
            defer self.lock.unlockShared();
            break :blk self.loader;
        } orelse return false;
        return loader.loadFn(loader.ptr, account, self);
    }

    /// Resolve SCRAM-SHA-256 credentials for `account`: the live store first,
    /// then the backfill loader (caching a hit). This is the path the mechrouter
    /// uses, so a SCRAM login works after a restart even before any in-memory
    /// entry exists. Returns null when unknown everywhere.
    pub fn resolve(self: *ScramStore, account: []const u8) ?sasl.ScramRecord {
        if (self.lookup(account)) |r| return r;
        if (!self.backfill(account)) return null;
        return self.lookup(account);
    }

    /// Resolve SCRAM-SHA-512 credentials for `account`: live store first, then
    /// the backfill loader. Returns null when the account is unknown OR when it
    /// has no SHA-512 material (e.g. an account loaded from an old SHA-256-only
    /// durable record, until it is re-provisioned).
    pub fn resolve512(self: *ScramStore, account: []const u8) ?scram512.Credential {
        if (self.lookup512(account)) |r| return r;
        if (!self.backfill(account)) return null;
        return self.lookup512(account);
    }

    /// Number of bytes `serializeRecord` writes for a SHA-256-only record: u32
    /// iterations, u16 salt length, the salt, then the two SHA-256 digests.
    pub const serialized_v1_max = 4 + 2 + salt_len + digest_len + digest_len;

    /// Maximum bytes `serializeRecord` writes for a record that also carries
    /// SHA-512 material: the v1 layout plus a 1-byte version marker and the two
    /// SHA-512 digests.
    pub const serialized_max = serialized_v1_max + 1 + digest512_len + digest512_len;

    /// Version marker that follows the SHA-256 portion when SHA-512 material is
    /// appended. Old (v1) records simply end after the SHA-256 digests, so a
    /// reader distinguishes them by length: this byte is only present when there
    /// are trailing SHA-512 bytes.
    const scram512_marker: u8 = 0x02;

    /// Serialize a SHA-256-only record (no SHA-512 material). Kept for callers
    /// that hold only a legacy `sasl.ScramRecord`. Produces v1 bytes.
    pub fn serializeRecord(record: sasl.ScramRecord, out: []u8) ?[]const u8 {
        return serializeFullRecord(.{
            .salt = record.salt,
            .iterations = record.iterations,
            .stored_key = record.stored_key,
            .server_key = record.server_key,
        }, out);
    }

    /// Serialize a full record into `out`, appending the SHA-512 block only when
    /// `record.has_512` is set. v1 (SHA-256-only) bytes remain byte-identical to
    /// the historical format, so old readers and old records interoperate.
    pub fn serializeFullRecord(record: FullRecord, out: []u8) ?[]const u8 {
        const base = 6 + record.salt.len + digest_len + digest_len;
        const sha512_block: usize = if (record.has_512) 1 + digest512_len + digest512_len else 0;
        const total = base + sha512_block;
        if (record.salt.len > std.math.maxInt(u16) or out.len < total) return null;
        std.mem.writeInt(u32, out[0..4], record.iterations, .big);
        std.mem.writeInt(u16, out[4..6], @intCast(record.salt.len), .big);
        var off: usize = 6;
        @memcpy(out[off..][0..record.salt.len], record.salt);
        off += record.salt.len;
        @memcpy(out[off..][0..digest_len], &record.stored_key);
        off += digest_len;
        @memcpy(out[off..][0..digest_len], &record.server_key);
        off += digest_len;
        if (record.has_512) {
            out[off] = scram512_marker;
            off += 1;
            @memcpy(out[off..][0..digest512_len], &record.stored_key_512);
            off += digest512_len;
            @memcpy(out[off..][0..digest512_len], &record.server_key_512);
            off += digest512_len;
        }
        return out[0..off];
    }

    /// Parse SHA-256 bytes produced by `serializeRecord`/`serializeFullRecord`.
    /// The returned record's `salt` borrows `bytes`. Null on malformed input.
    /// SHA-512 trailing bytes (if any) are ignored by this view.
    pub fn deserializeRecord(bytes: []const u8) ?sasl.ScramRecord {
        const full = deserializeFullRecord(bytes) orelse return null;
        return full.sha256();
    }

    /// Parse bytes produced by `serializeFullRecord` into a `FullRecord`. Old
    /// (v1) records parse with `has_512 = false`; records with the SHA-512 block
    /// parse it through. The returned record's `salt` borrows `bytes`. Null on
    /// malformed input.
    pub fn deserializeFullRecord(bytes: []const u8) ?FullRecord {
        if (bytes.len < 6) return null;
        const iterations = std.mem.readInt(u32, bytes[0..4], .big);
        const sl = std.mem.readInt(u16, bytes[4..6], .big);
        const base = 6 + @as(usize, sl) + digest_len + digest_len;
        if (bytes.len < base) return null;
        var rec = FullRecord{
            .salt = bytes[6 .. 6 + sl],
            .iterations = iterations,
            .stored_key = undefined,
            .server_key = undefined,
        };
        @memcpy(&rec.stored_key, bytes[6 + sl ..][0..digest_len]);
        @memcpy(&rec.server_key, bytes[6 + sl + digest_len ..][0..digest_len]);

        // Optional SHA-512 block: present iff the version marker plus two SHA-512
        // digests follow. A truncated trailer is treated as SHA-256-only rather
        // than rejected, so a partially-written record still authenticates PLAIN
        // and SCRAM-SHA-256.
        const want_512 = base + 1 + digest512_len + digest512_len;
        if (bytes.len >= want_512 and bytes[base] == scram512_marker) {
            rec.has_512 = true;
            var off = base + 1;
            @memcpy(&rec.stored_key_512, bytes[off..][0..digest512_len]);
            off += digest512_len;
            @memcpy(&rec.server_key_512, bytes[off..][0..digest512_len]);
        }
        return rec;
    }

    /// Look up SCRAM-SHA-256 credentials for `account`. The returned `ScramRecord`
    /// borrows a store-owned `salt` valid for the caller's synchronous use during
    /// the SASL exchange; the store keeps it only briefly in a bounded ring (see
    /// `salt_ring_capacity`), not for the process lifetime. Returns null for an
    /// unknown account or allocation failure.
    pub fn lookup(self: *const ScramStore, account: []const u8) ?sasl.ScramRecord {
        const self_mut = @constCast(self);
        self_mut.lock.lockExclusive();
        defer self_mut.lock.unlockExclusive();

        const entry = self_mut.entries.get(account) orelse return null;
        const salt = self_mut.allocator.dupe(u8, entry.salt) catch return null;
        self_mut.retainLookupSalt(salt);
        return .{
            .salt = salt,
            .iterations = entry.iterations,
            .stored_key = entry.stored_key,
            .server_key = entry.server_key,
        };
    }

    /// Look up SCRAM-SHA-512 credentials for `account`. Returns null for an
    /// unknown account, an account with no SHA-512 material, or allocation
    /// failure. The returned `salt` borrows store-owned memory kept only briefly
    /// in the bounded ring (same lifetime contract as `lookup`), not for the
    /// process lifetime.
    pub fn lookup512(self: *const ScramStore, account: []const u8) ?scram512.Credential {
        const self_mut = @constCast(self);
        self_mut.lock.lockExclusive();
        defer self_mut.lock.unlockExclusive();

        const entry = self_mut.entries.get(account) orelse return null;
        if (!entry.has_512) return null;
        const salt = self_mut.allocator.dupe(u8, entry.salt) catch return null;
        self_mut.retainLookupSalt(salt);
        return .{
            .salt = salt,
            .iterations = entry.iterations,
            .stored_key = entry.stored_key_512,
            .server_key = entry.server_key_512,
        };
    }

    /// Adapter exposing this store as the mechrouter's SCRAM-SHA-256 credential
    /// source. The returned fat pointer borrows `self`, so the `ScramStore` must
    /// outlive every connection that copies it (own it alongside the `Server`).
    pub fn scram256Lookup(self: *ScramStore) mechrouter.Scram256Lookup {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        return .{ .ptr = self, .lookupFn = lookupThunk };
    }

    fn lookupThunk(ptr: *anyopaque, username: []const u8) ?sasl.ScramRecord {
        const self: *ScramStore = @ptrCast(@alignCast(ptr));
        return self.resolve(username);
    }

    /// Adapter exposing this store as the mechrouter's SCRAM-SHA-512 credential
    /// source. Mirrors `scram256Lookup`. The returned fat pointer borrows `self`,
    /// so the `ScramStore` must outlive every connection that copies it. The
    /// lookup yields null for accounts with no SHA-512 material, so the mechrouter
    /// only advertises/serves SCRAM-SHA-512 for accounts that were provisioned
    /// with it.
    pub fn scram512Lookup(self: *ScramStore) mechrouter.Scram512Lookup {
        self.lock.lockShared();
        defer self.lock.unlockShared();

        return .{ .ptr = self, .lookupFn = lookup512Thunk };
    }

    fn lookup512Thunk(ptr: *anyopaque, username: []const u8) ?scram512.Credential {
        const self: *ScramStore = @ptrCast(@alignCast(ptr));
        return self.resolve512(username);
    }
};

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

test "SCRAM prepared import allocation failures preserve credentials and retry" {
    const old: ScramStore.FullRecord = .{
        .salt = "previous-salt",
        .iterations = 4096,
        .stored_key = @splat(1),
        .server_key = @splat(2),
        .has_512 = true,
        .stored_key_512 = @splat(3),
        .server_key_512 = @splat(4),
    };
    var next = old;
    next.salt = "next-salt";
    next.stored_key = @splat(5);
    next.server_key_512 = @splat(6);
    for ([_]bool{ false, true }) |replace| {
        var failure_index: usize = 0;
        while (true) : (failure_index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = ScramStore.init(failing.allocator());
            defer store.deinit();
            if (replace) try store.importFullRecord("alice", old);
            const original_salt = if (store.entries.get("alice")) |entry| entry.salt.ptr else null;
            failing.fail_index = failing.alloc_index + failure_index;
            failing.resize_fail_index = 0;
            var prepared = store.prepareImportFullRecord("ALICE", next) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expectEqual(@as(u32, if (replace) 1 else 0), store.entries.count());
                if (replace) {
                    const entry = store.entries.get("alice").?;
                    try std.testing.expect(entry.salt.ptr == original_salt.?);
                    try std.testing.expectEqualSlices(u8, old.salt, entry.salt);
                    try std.testing.expectEqualSlices(u8, &old.stored_key, &entry.stored_key);
                    try std.testing.expectEqualSlices(u8, &old.server_key_512, &entry.server_key_512);
                }
                failing.fail_index = std.math.maxInt(usize);
                var retry = try store.prepareImportFullRecord("ALICE", next);
                const allocations = failing.alloc_index;
                retry.commit();
                retry.deinit();
                try std.testing.expectEqual(allocations, failing.alloc_index);
                try std.testing.expectEqualSlices(u8, next.salt, store.entries.get("alice").?.salt);
                continue;
            };
            const allocations = failing.alloc_index;
            prepared.commit();
            prepared.deinit();
            try std.testing.expectEqual(allocations, failing.alloc_index);
            const entry = store.entries.get("alice").?;
            try std.testing.expectEqualSlices(u8, next.salt, entry.salt);
            try std.testing.expectEqualSlices(u8, &next.stored_key, &entry.stored_key);
            try std.testing.expectEqualSlices(u8, &next.server_key_512, &entry.server_key_512);
            try std.testing.expect(failure_index >= 2);
            break;
        }
    }
}

test "SCRAM prepared import abort preserves prior credential and unlocks" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    const old: ScramStore.FullRecord = .{
        .salt = "previous-salt",
        .iterations = 4096,
        .stored_key = @splat(1),
        .server_key = @splat(2),
    };
    try store.importFullRecord("alice", old);
    const original_salt = store.entries.get("alice").?.salt.ptr;
    var replacement = old;
    replacement.salt = "replacement";
    var prepared = try store.prepareImportFullRecord("alice", replacement);
    prepared.abort();
    prepared.deinit();
    const entry = store.entries.get("alice").?;
    try std.testing.expect(entry.salt.ptr == original_salt);
    try std.testing.expectEqualSlices(u8, old.salt, entry.salt);
    try std.testing.expect(store.lookup("alice") != null);
    var insertion = try store.prepareImportFullRecord("bob", replacement);
    insertion.deinit();
    try std.testing.expect(store.lookup("bob") == null);
    try std.testing.expect(store.lookup("alice") != null);
}

test "deriveAndStore then lookup returns SCRAM material for the account" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    // Act
    try store.deriveAndStore("alice", "correct horse battery staple");
    const record = store.lookup("alice");

    // Assert
    try std.testing.expect(record != null);
    try std.testing.expectEqual(@as(usize, salt_len), record.?.salt.len);
    try std.testing.expectEqual(default_iterations, record.?.iterations);
    try std.testing.expect(store.lookup("nobody") == null);
}

test "storeWithSalt is deterministic for a fixed salt and iteration count" {
    // Arrange
    var store_a = ScramStore.init(std.testing.allocator);
    defer store_a.deinit();
    var store_b = ScramStore.init(std.testing.allocator);
    defer store_b.deinit();
    const salt = "fixed-scram-salt";

    // Act
    try store_a.storeWithSalt("alice", "pencil", salt, 4096);
    try store_b.storeWithSalt("alice", "pencil", salt, 4096);
    const rec_a = store_a.lookup("alice").?;
    const rec_b = store_b.lookup("alice").?;

    // Assert
    try std.testing.expectEqualSlices(u8, &rec_a.stored_key, &rec_b.stored_key);
    try std.testing.expectEqualSlices(u8, &rec_a.server_key, &rec_b.server_key);
}

test "deriveAndStore overwrites an existing account in place" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "first password value");
    const first = store.lookup("alice").?;
    var first_stored = first.stored_key;

    // Act: re-deriving with a new password (and fresh salt) replaces the entry.
    try store.deriveAndStore("alice", "second password value");
    const second = store.lookup("alice").?;

    // Assert
    try std.testing.expectEqual(@as(u32, 1), store.entries.count());
    try std.testing.expect(!std.mem.eql(u8, &first_stored, &second.stored_key));
}

test "empty or oversize account names are rejected" {
    // Arrange
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    const too_long = &@as([(MAX_ACCOUNT_LEN + 1)]u8, @splat('x'));

    // Act / Assert
    try std.testing.expectError(error.InvalidAccount, store.deriveAndStore("", "password value here"));
    try std.testing.expectError(error.InvalidAccount, store.deriveAndStore(too_long, "password value here"));
}

const ScramMtCtx = struct {
    store: *ScramStore,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn writer(ctx: *ScramMtCtx) void {
        var name_buf: [MAX_ACCOUNT_LEN]u8 = undefined;
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const name = std.fmt.bufPrint(&name_buf, "scram{d}_{d}", .{ ctx.writer_id, i }) catch unreachable;
            var salt = @as([salt_len]u8, @splat(@intCast(ctx.writer_id * ctx.iters + i + 1)));
            ctx.store.storeWithSalt(name, "thread password value", &salt, 4096) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
        }
    }

    fn reader(ctx: *ScramMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            const record = ctx.store.lookup("seed") orelse {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (record.salt.len != salt_len or record.iterations != 4096) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            std.mem.doNotOptimizeAway(record.stored_key);
        }
    }
};

test "ScramStore concurrent writers and readers preserve entries" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    const seed_salt = @as([salt_len]u8, @splat(0xA5));
    try store.storeWithSalt("seed", "thread password value", &seed_salt, 4096);

    const writers = 4;
    const readers = 4;
    const iters = 24;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]ScramMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .store = &store, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ScramMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, ScramMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1 + writers * iters), store.entries.count());
    for (0..writers) |w| {
        var name_buf: [MAX_ACCOUNT_LEN]u8 = undefined;
        for (0..iters) |i| {
            const name = std.fmt.bufPrint(&name_buf, "scram{d}_{d}", .{ w, i }) catch unreachable;
            try std.testing.expect(store.lookup(name) != null);
        }
    }
}

test "lookup salt retention is bounded across many SCRAM starts" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "correct horse battery staple");

    // Each SCRAM server-first (a `lookup`) duplicates the salt. Historically
    // every dupe was retained for the process lifetime — an unauthenticated slow
    // leak, since the salt is returned before proof verification. Run far more
    // exchanges than the ring holds and assert retention is capped. The testing
    // allocator additionally proves no dupe leaks at deinit.
    var i: usize = 0;
    while (i < salt_ring_capacity * 4) : (i += 1) {
        const rec = store.lookup("alice") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, salt_len), rec.salt.len);
        const rec512 = store.lookup512("alice") orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, salt_len), rec512.salt.len);
    }

    var held: usize = 0;
    for (store.lookup_salts) |slot| {
        if (slot != null) held += 1;
    }
    // The ring fills to exactly its capacity and never grows past it, regardless
    // of how many exchanges ran.
    try std.testing.expectEqual(salt_ring_capacity, held);
}

test "serialize/deserialize round-trips a SCRAM record" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "pencil");
    const rec = store.lookup("alice").?;

    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeRecord(rec, &buf).?;
    const back = ScramStore.deserializeRecord(bytes).?;

    try std.testing.expectEqual(rec.iterations, back.iterations);
    try std.testing.expectEqualSlices(u8, rec.salt, back.salt);
    try std.testing.expectEqualSlices(u8, &rec.stored_key, &back.stored_key);
    try std.testing.expectEqualSlices(u8, &rec.server_key, &back.server_key);
    try std.testing.expect(ScramStore.deserializeRecord("short") == null);
}

const TestLoader = struct {
    bytes: []const u8,
    fn load(ptr: *anyopaque, account: []const u8, destination: *ScramStore) bool {
        const self: *TestLoader = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, account, "alice")) return false;
        const record = ScramStore.deserializeFullRecord(self.bytes) orelse return false;
        destination.importFullRecord(account, record) catch return false;
        return true;
    }
};

test "resolve backfills a missing account from the loader, then caches" {
    var src = ScramStore.init(std.testing.allocator);
    defer src.deinit();
    try src.deriveAndStore("alice", "pencil");
    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeRecord(src.lookup("alice").?, &buf).?;

    var cold = ScramStore.init(std.testing.allocator);
    defer cold.deinit();
    var loader = TestLoader{ .bytes = bytes };
    cold.setLoader(.{ .ptr = &loader, .loadFn = TestLoader.load });

    try std.testing.expect(cold.lookup("alice") == null); // not cached yet
    const resolved = cold.resolve("alice").?; // backfills from loader
    try std.testing.expectEqual(src.lookup("alice").?.iterations, resolved.iterations);
    try std.testing.expect(cold.lookup("alice") != null); // now cached in-memory
    try std.testing.expect(cold.resolve("bob") == null); // loader declines
}

test "deriveAndStore provisions both SHA-256 and SHA-512 material" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    try store.deriveAndStore("alice", "correct horse battery staple");

    // SHA-256 lookup yields a 32-byte digest set.
    const rec256 = store.lookup("alice").?;
    try std.testing.expectEqual(@as(usize, digest_len), rec256.stored_key.len);

    // SHA-512 lookup yields a 64-byte digest set over the SAME salt/iterations.
    const rec512 = store.lookup512("alice").?;
    try std.testing.expectEqual(@as(usize, digest512_len), rec512.stored_key.len);
    try std.testing.expectEqual(rec256.iterations, rec512.iterations);
    try std.testing.expectEqualSlices(u8, rec256.salt, rec512.salt);

    // The SHA-512 keys must match a fresh independent derivation from the
    // password and the stored salt — proving correct RFC 5802 (SHA-512) keys.
    var keys = try scram512.deriveScramKeys("correct horse battery staple", rec512.salt, rec512.iterations);
    defer keys.wipe();
    try std.testing.expectEqualSlices(u8, &keys.stored_key, &rec512.stored_key);
    try std.testing.expectEqualSlices(u8, &keys.server_key, &rec512.server_key);

    try std.testing.expect(store.lookup512("nobody") == null);
}

test "storeWithSalt SHA-512 keys are deterministic for a fixed salt" {
    var a = ScramStore.init(std.testing.allocator);
    defer a.deinit();
    var b = ScramStore.init(std.testing.allocator);
    defer b.deinit();

    try a.storeWithSalt("alice", "pencil", "fixed-scram-salt", 4096);
    try b.storeWithSalt("alice", "pencil", "fixed-scram-salt", 4096);

    const ra = a.lookup512("alice").?;
    const rb = b.lookup512("alice").?;
    try std.testing.expectEqualSlices(u8, &ra.stored_key, &rb.stored_key);
    try std.testing.expectEqualSlices(u8, &ra.server_key, &rb.server_key);
}

test "importRecord (SHA-256 only) leaves SCRAM-SHA-512 unavailable" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();

    // A legacy SHA-256-only record (e.g. an old durable record) provides no
    // SHA-512 material, so SCRAM-SHA-512 must not be offered for it.
    var seed = ScramStore.init(std.testing.allocator);
    defer seed.deinit();
    try seed.storeWithSalt("alice", "pencil", "some-fixed-salt0", 4096);
    const rec256 = seed.lookup("alice").?;
    try store.importRecord("alice", rec256);

    try std.testing.expect(store.lookup("alice") != null); // SHA-256 works
    try std.testing.expect(store.lookup512("alice") == null); // SHA-512 absent
}

test "serialize/deserialize round-trips SHA-512 material backward-compatibly" {
    var store = ScramStore.init(std.testing.allocator);
    defer store.deinit();
    try store.deriveAndStore("alice", "pencil");

    const rec256 = store.lookup("alice").?;
    const rec512 = store.lookup512("alice").?;
    const full = ScramStore.FullRecord{
        .salt = rec256.salt,
        .iterations = rec256.iterations,
        .stored_key = rec256.stored_key,
        .server_key = rec256.server_key,
        .has_512 = true,
        .stored_key_512 = rec512.stored_key,
        .server_key_512 = rec512.server_key,
    };

    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeFullRecord(full, &buf).?;
    const back = ScramStore.deserializeFullRecord(bytes).?;
    try std.testing.expect(back.has_512);
    try std.testing.expectEqualSlices(u8, &full.stored_key_512, &back.stored_key_512);
    try std.testing.expectEqualSlices(u8, &full.server_key_512, &back.server_key_512);

    // The SHA-256 view of the SAME bytes still parses (old readers keep working).
    const v1 = ScramStore.deserializeRecord(bytes).?;
    try std.testing.expectEqualSlices(u8, &rec256.stored_key, &v1.stored_key);

    // A v1 (SHA-256-only) serialization carries no SHA-512 block.
    var v1buf: [ScramStore.serialized_v1_max]u8 = undefined;
    const v1bytes = ScramStore.serializeRecord(rec256, &v1buf).?;
    try std.testing.expectEqual(@as(usize, ScramStore.serialized_v1_max), v1bytes.len);
    const v1full = ScramStore.deserializeFullRecord(v1bytes).?;
    try std.testing.expect(!v1full.has_512);
}

test "resolve512 backfills SHA-512 material from the loader, then caches" {
    var src = ScramStore.init(std.testing.allocator);
    defer src.deinit();
    try src.deriveAndStore("alice", "pencil");
    const rec256 = src.lookup("alice").?;
    const rec512 = src.lookup512("alice").?;
    var buf: [ScramStore.serialized_max]u8 = undefined;
    const bytes = ScramStore.serializeFullRecord(.{
        .salt = rec256.salt,
        .iterations = rec256.iterations,
        .stored_key = rec256.stored_key,
        .server_key = rec256.server_key,
        .has_512 = true,
        .stored_key_512 = rec512.stored_key,
        .server_key_512 = rec512.server_key,
    }, &buf).?;

    var cold = ScramStore.init(std.testing.allocator);
    defer cold.deinit();
    var loader = TestLoader{ .bytes = bytes };
    cold.setLoader(.{ .ptr = &loader, .loadFn = TestLoader.load });

    try std.testing.expect(cold.lookup512("alice") == null); // not cached yet
    const resolved = cold.resolve512("alice").?; // backfills from loader
    try std.testing.expectEqualSlices(u8, &rec512.stored_key, &resolved.stored_key);
    try std.testing.expect(cold.lookup512("alice") != null); // now cached
    try std.testing.expect(cold.resolve512("bob") == null); // loader declines
}

test {
    std.testing.refAllDecls(@This());
}
