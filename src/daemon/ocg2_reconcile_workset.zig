// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Inactive allocation-free OCG2 reconciliation workset planner.
//!
//! Converts a previously acknowledged C3 baseline plus a fresh C3 hint
//! inventory into canonical account reinspection work. This leaf is an
//! advisory stale-work guard only: it cannot grant or remove privilege,
//! mutate sessions, own a clock, allocate, perform I/O, persist, emit
//! events, or commit an acknowledgement.

const std = @import("std");
const durable_oper_authority = @import("durable_oper_authority.zig");
const ocg2_reconcile_schedule = @import("ocg2_reconcile_schedule.zig");

const max_account_len = durable_oper_authority.max_account_len;
const digest_len = durable_oper_authority.digest_len;
const Phase = ocg2_reconcile_schedule.Phase;
const ReinspectHint = ocg2_reconcile_schedule.ReinspectHint;

pub const max_entries: usize = durable_oper_authority.max_records;

pub const Cause = enum {
    inventory_added,
    successor,
    equivocation,
    temporal_transition,
};

pub const InvalidReason = enum {
    account_bounds,
    account_order,
    zero_revision,
    inventory_bounds,
    phase_deadline,
    previous_time,
};

pub const BaselineEntry = struct {
    account_buf: [max_account_len]u8 = @splat(0),
    account_len: usize = 0,
    revision: u64 = 0,
    digest: [digest_len]u8 = @splat(0),
    wire_sha256: [digest_len]u8 = @splat(0),
    phase: Phase = .expired,
    next_transition_ms: ?u64 = null,
};

pub const WorkItem = struct {
    cause: Cause = .inventory_added,
    expected: BaselineEntry = .{},
};

pub const Summary = struct {
    candidate_count: usize,
    work_count: usize,
    security_now_ms: u64,
    earliest_transition_ms: ?u64,
};

pub const BuildResult = union(enum) {
    complete: Summary,
    invalid_previous: struct {
        index: usize,
        reason: InvalidReason,
    },
    invalid_current: struct {
        index: usize,
        reason: InvalidReason,
    },
    invalid_cross_generation: struct {
        previous_index: usize,
        current_index: usize,
    },
    security_time_rollback,
    aliasing,
    insufficient_candidate_output: usize,
    insufficient_work_output: usize,
};

const MatchOutcome = union(enum) {
    none,
    work: Cause,
    cross: struct {
        previous_index: usize,
        current_index: usize,
    },
};

comptime {
    if (max_entries != durable_oper_authority.max_records)
        @compileError("S6-C4 max_entries is frozen to durable_oper_authority.max_records");
    if (max_entries != 256)
        @compileError("S6-C4 inventory bound is frozen at 256");
    if (max_account_len != 32)
        @compileError("S6-C4 account bound is frozen to the C2/OCG2 account width");
    if (digest_len != 32)
        @compileError("S6-C4 identity width must match BLAKE3 and SHA-256");

    const build_info = @typeInfo(@TypeOf(build)).@"fn";
    if (build_info.param_types.len != 6)
        @compileError("build has a fixed six-parameter surface");
    if (build_info.param_types[0] != []const BaselineEntry)
        @compileError("build consumes the acknowledged BaselineEntry inventory");
    if (build_info.param_types[1] != ?u64)
        @compileError("build takes optional previous_security_now_ms and owns no clock");
    if (build_info.param_types[2] != []const ReinspectHint)
        @compileError("build consumes the fresh C3 ReinspectHint inventory");
    if (build_info.param_types[3] != u64)
        @compileError("build takes caller-supplied security_now_ms and owns no clock");
    if (build_info.param_types[4] != []BaselineEntry)
        @compileError("build writes inline BaselineEntry candidates only");
    if (build_info.param_types[5] != []WorkItem)
        @compileError("build writes inline WorkItem values only");
    if (build_info.return_type != BuildResult)
        @compileError("build returns BuildResult");
    for (build_info.param_types) |param_type| {
        if (param_type == std.mem.Allocator)
            @compileError("build must stay allocation-free");
    }

    const allowed_entry_fields = .{
        "account_buf",        "account_len", "revision",
        "digest",             "wire_sha256", "phase",
        "next_transition_ms",
    };
    const entry_info = @typeInfo(BaselineEntry).@"struct";
    if (entry_info.field_names.len != allowed_entry_fields.len)
        @compileError("BaselineEntry may only carry advisory identity/deadline fields");
    if (entry_info.decl_names.len != 0)
        @compileError("BaselineEntry must not expose methods or nested public declarations");
    rejectPointers(BaselineEntry);
    for (entry_info.field_names) |name| {
        var allowed = false;
        for (allowed_entry_fields) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed) @compileError("BaselineEntry carries a forbidden field");
    }

    const allowed_work_fields = .{ "cause", "expected" };
    const work_info = @typeInfo(WorkItem).@"struct";
    if (work_info.field_names.len != allowed_work_fields.len)
        @compileError("WorkItem may only carry Cause plus an inline expected BaselineEntry");
    if (work_info.decl_names.len != 0)
        @compileError("WorkItem must not expose methods or nested public declarations");
    rejectPointers(WorkItem);
    for (work_info.field_names) |name| {
        var allowed = false;
        for (allowed_work_fields) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed) @compileError("WorkItem carries a forbidden field");
    }

    rejectPointers(Summary);
    rejectPointers(BuildResult);

    const allowed_public_decls = .{
        "Cause",   "InvalidReason", "BaselineEntry", "WorkItem",
        "Summary", "BuildResult",   "max_entries",   "build",
    };
    const module_decls = @typeInfo(@This()).@"struct".decl_names;
    if (module_decls.len != allowed_public_decls.len)
        @compileError("S6-C4 public surface is an exact eight-declaration allowlist");
    for (module_decls) |name| {
        var allowed = false;
        for (allowed_public_decls) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed)
            @compileError("S6-C4 public surface rejected an undeclared public declaration");
    }

    for (.{
        "apply",        "execute",            "grant",
        "revoke",       "mint",               "transmit",
        "session",      "callback",           "executeAuthorized",
        "Visitor",      "ProjectionData",     "DurableOperLookup",
        "Services",     "Store",              "reconcile",
        "issue",        "issueGrant",         "issueRevoke",
        "executeGrant", "executeRevoke",      "LinuxServer",
        "buildAlloc",   "buildWithAllocator",
    }) |name| {
        if (@hasDecl(@This(), name))
            @compileError("OCG2 reconcile workset must not expose a runtime privilege surface");
    }
}

fn rejectPointers(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("S6-C4 public values must not hold pointers or slices"),
        .optional => |info| rejectPointers(info.child),
        .array => |info| rejectPointers(info.child),
        .@"struct" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        .@"union" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        else => {},
    }
}

fn canonicalAccount(account: []const u8) bool {
    if (account.len == 0 or account.len > max_account_len) return false;
    for (account) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_' or byte == '.' or byte == '-';
        if (!ok) return false;
    }
    return true;
}

fn boundedAccount(buf: *const [max_account_len]u8, len: usize) ?[]const u8 {
    if (len == 0 or len > buf.len or len > max_account_len) return null;
    return buf[0..len];
}

fn isLive(phase: Phase) bool {
    return phase == .not_yet_valid or phase == .active;
}

fn isTerminal(phase: Phase) bool {
    return phase == .expired or phase == .tombstone or phase == .equivocation;
}

fn sameIdentity(left: anytype, right: anytype) bool {
    return std.mem.eql(u8, &left.digest, &right.digest) and
        std.mem.eql(u8, &left.wire_sha256, &right.wire_sha256);
}

fn sameTuple(previous: BaselineEntry, current: BaselineEntry) bool {
    return previous.revision == current.revision and
        sameIdentity(previous, current) and
        previous.phase == current.phase and
        optionalEql(previous.next_transition_ms, current.next_transition_ms);
}

fn optionalEql(left: ?u64, right: ?u64) bool {
    if (left) |left_value| {
        return if (right) |right_value| left_value == right_value else false;
    }
    return right == null;
}

fn permittedTemporal(previous: Phase, current: Phase) bool {
    return (previous == .not_yet_valid and current == .active) or
        (previous == .not_yet_valid and current == .expired) or
        (previous == .active and current == .expired);
}

const ByteRange = struct {
    start: usize,
    end: usize,
};

fn byteRange(comptime T: type, items: []const T) ByteRange {
    if (items.len == 0) return .{ .start = 0, .end = 0 };
    const start = @intFromPtr(items.ptr);
    return .{ .start = start, .end = start + items.len * @sizeOf(T) };
}

fn rangesOverlap(left: ByteRange, right: ByteRange) bool {
    if (left.start == left.end or right.start == right.end) return false;
    return left.start < right.end and right.start < left.end;
}

fn aliased(
    previous: []const BaselineEntry,
    current: []const ReinspectHint,
    candidate_out: []const BaselineEntry,
    work_out: []const WorkItem,
) bool {
    const previous_range = byteRange(BaselineEntry, previous);
    const current_range = byteRange(ReinspectHint, current);
    const candidate_range = byteRange(BaselineEntry, candidate_out);
    const work_range = byteRange(WorkItem, work_out);
    return rangesOverlap(previous_range, current_range) or
        rangesOverlap(previous_range, candidate_range) or
        rangesOverlap(previous_range, work_range) or
        rangesOverlap(current_range, candidate_range) or
        rangesOverlap(current_range, work_range) or
        rangesOverlap(candidate_range, work_range);
}

fn validatePhaseDeadline(phase: Phase, next_transition_ms: ?u64, now_ms: u64) ?InvalidReason {
    if (isLive(phase)) {
        const deadline = next_transition_ms orelse return .phase_deadline;
        if (deadline <= now_ms) return .phase_deadline;
        return null;
    }
    if (isTerminal(phase) and next_transition_ms != null) return .phase_deadline;
    return null;
}

fn validateNamed(
    account_buf: *const [max_account_len]u8,
    account_len: usize,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    now_ms: u64,
    previous_account: ?[]const u8,
) ?InvalidReason {
    const account = boundedAccount(account_buf, account_len) orelse return .account_bounds;
    if (!canonicalAccount(account)) return .account_bounds;
    if (previous_account) |previous| {
        if (std.mem.order(u8, previous, account) != .lt) return .account_order;
    }
    if (revision == 0) return .zero_revision;
    return validatePhaseDeadline(phase, next_transition_ms, now_ms);
}

fn validateInventory(
    comptime kind: enum { previous, current },
    comptime T: type,
    rows: []const T,
    now_ms: u64,
) ?BuildResult {
    if (rows.len > max_entries) {
        return switch (kind) {
            .previous => .{ .invalid_previous = .{ .index = max_entries, .reason = .inventory_bounds } },
            .current => .{ .invalid_current = .{ .index = max_entries, .reason = .inventory_bounds } },
        };
    }
    var previous_account: ?[]const u8 = null;
    var first: ?BuildResult = null;
    for (rows, 0..) |*row, index| {
        if (validateNamed(
            &row.account_buf,
            row.account_len,
            row.revision,
            row.phase,
            row.next_transition_ms,
            now_ms,
            previous_account,
        )) |reason| {
            if (first == null) {
                first = switch (kind) {
                    .previous => .{ .invalid_previous = .{ .index = index, .reason = reason } },
                    .current => .{ .invalid_current = .{ .index = index, .reason = reason } },
                };
            }
        }
        if (boundedAccount(&row.account_buf, row.account_len)) |account| {
            if (canonicalAccount(account)) previous_account = account;
        }
    }
    return first;
}

fn entryFromHint(hint: ReinspectHint) BaselineEntry {
    var entry = BaselineEntry{
        .revision = hint.revision,
        .digest = hint.digest,
        .wire_sha256 = hint.wire_sha256,
        .phase = hint.phase,
        .next_transition_ms = hint.next_transition_ms,
        .account_len = hint.account_len,
    };
    const account = boundedAccount(&hint.account_buf, hint.account_len).?;
    @memcpy(entry.account_buf[0..account.len], account);
    return entry;
}

fn accountOf(entry: anytype) []const u8 {
    return boundedAccount(&entry.account_buf, entry.account_len).?;
}

fn matchSameAccount(
    previous: BaselineEntry,
    current: BaselineEntry,
    previous_index: usize,
    current_index: usize,
    security_now_ms: u64,
) MatchOutcome {
    if (current.revision < previous.revision) {
        return .{ .cross = .{ .previous_index = previous_index, .current_index = current_index } };
    }
    if (current.revision > previous.revision) {
        if (current.phase == .equivocation and previous.phase != .equivocation)
            return .{ .work = .equivocation };
        return .{ .work = .successor };
    }
    if (!sameIdentity(previous, current)) {
        if (current.phase == .equivocation) return .{ .work = .equivocation };
        return .{ .cross = .{ .previous_index = previous_index, .current_index = current_index } };
    }
    if (sameTuple(previous, current)) return .none;
    if (current.phase == .equivocation and previous.phase != .equivocation)
        return .{ .work = .equivocation };
    if (permittedTemporal(previous.phase, current.phase)) {
        const deadline = previous.next_transition_ms orelse
            return .{ .cross = .{ .previous_index = previous_index, .current_index = current_index } };
        if (deadline <= security_now_ms) return .{ .work = .temporal_transition };
    }
    return .{ .cross = .{ .previous_index = previous_index, .current_index = current_index } };
}

fn earliestFuture(candidates: []const BaselineEntry, security_now_ms: u64) ?u64 {
    var earliest: ?u64 = null;
    for (candidates) |entry| {
        if (entry.next_transition_ms) |deadline| {
            if (deadline > security_now_ms) {
                earliest = if (earliest) |current|
                    if (deadline < current) deadline else current
                else
                    deadline;
            }
        }
    }
    return earliest;
}

/// Build advisory reinspection work from an acknowledged C3 baseline and a
/// fresh C3 hint inventory. Validation and alias checks complete before any
/// output write. Any failure leaves both destinations byte-for-byte untouched.
pub fn build(
    previous: []const BaselineEntry,
    previous_security_now_ms: ?u64,
    current: []const ocg2_reconcile_schedule.ReinspectHint,
    security_now_ms: u64,
    candidate_out: []BaselineEntry,
    work_out: []WorkItem,
) BuildResult {
    if (previous.len > max_entries)
        return .{ .invalid_previous = .{ .index = max_entries, .reason = .inventory_bounds } };
    if (current.len > max_entries)
        return .{ .invalid_current = .{ .index = max_entries, .reason = .inventory_bounds } };
    if (previous_security_now_ms == null and previous.len != 0)
        return .{ .invalid_previous = .{ .index = 0, .reason = .previous_time } };

    if (previous_security_now_ms) |previous_now| {
        if (validateInventory(.previous, BaselineEntry, previous, previous_now)) |invalid|
            return invalid;
    } else if (validateInventory(.previous, BaselineEntry, previous, 0)) |invalid| {
        return invalid;
    }
    if (validateInventory(.current, ReinspectHint, current, security_now_ms)) |invalid|
        return invalid;
    if (previous_security_now_ms) |previous_now| {
        if (security_now_ms < previous_now) return .security_time_rollback;
    }

    var planned_candidates: [max_entries]BaselineEntry = undefined;
    for (current, 0..) |hint, index| {
        planned_candidates[index] = entryFromHint(hint);
    }
    const planned_view = planned_candidates[0..current.len];

    var planned_work: [max_entries]WorkItem = undefined;
    var work_count: usize = 0;
    var first_cross: ?BuildResult = null;
    var previous_index: usize = 0;
    var current_index: usize = 0;
    while (previous_index < previous.len or current_index < current.len) {
        if (previous_index == previous.len) {
            planned_work[work_count] = .{
                .cause = .inventory_added,
                .expected = planned_view[current_index],
            };
            work_count += 1;
            current_index += 1;
            continue;
        }
        if (current_index == current.len) {
            if (first_cross == null) {
                first_cross = .{ .invalid_cross_generation = .{
                    .previous_index = previous_index,
                    .current_index = current_index,
                } };
            }
            break;
        }
        switch (std.mem.order(u8, accountOf(previous[previous_index]), accountOf(planned_view[current_index]))) {
            .lt => {
                if (first_cross == null) {
                    first_cross = .{ .invalid_cross_generation = .{
                        .previous_index = previous_index,
                        .current_index = current_index,
                    } };
                }
                break;
            },
            .gt => {
                planned_work[work_count] = .{
                    .cause = .inventory_added,
                    .expected = planned_view[current_index],
                };
                work_count += 1;
                current_index += 1;
            },
            .eq => {
                switch (matchSameAccount(
                    previous[previous_index],
                    planned_view[current_index],
                    previous_index,
                    current_index,
                    security_now_ms,
                )) {
                    .none => {},
                    .work => |cause| {
                        planned_work[work_count] = .{
                            .cause = cause,
                            .expected = planned_view[current_index],
                        };
                        work_count += 1;
                    },
                    .cross => |cross| {
                        if (first_cross == null) {
                            first_cross = .{ .invalid_cross_generation = .{
                                .previous_index = cross.previous_index,
                                .current_index = cross.current_index,
                            } };
                        }
                    },
                }
                previous_index += 1;
                current_index += 1;
            },
        }
    }
    if (first_cross) |result| return result;
    if (aliased(previous, current, candidate_out, work_out)) return .aliasing;
    if (candidate_out.len < current.len)
        return .{ .insufficient_candidate_output = current.len };
    if (work_out.len < work_count)
        return .{ .insufficient_work_output = work_count };

    for (planned_view, 0..) |entry, index| {
        candidate_out[index] = entry;
    }
    for (planned_work[0..work_count], 0..) |item, index| {
        work_out[index] = item;
    }
    return .{
        .complete = .{
            .candidate_count = current.len,
            .work_count = work_count,
            .security_now_ms = security_now_ms,
            .earliest_transition_ms = earliestFuture(planned_view, security_now_ms),
        },
    };
}

const testing = std.testing;
const oper_cred_share = @import("../proto/oper_cred_share.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;
const Sha256 = std.crypto.hash.sha2.Sha256;
const TransactionCopy = durable_oper_authority.TransactionCopy;
const max_wire_len = durable_oper_authority.max_wire_len;

fn makeHint(
    account: []const u8,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    digest_fill: u8,
    sha_fill: u8,
) ReinspectHint {
    var hint = ReinspectHint{
        .revision = revision,
        .phase = phase,
        .next_transition_ms = next_transition_ms,
        .digest = @splat(digest_fill),
        .wire_sha256 = @splat(sha_fill),
        .account_len = account.len,
    };
    @memcpy(hint.account_buf[0..account.len], account);
    return hint;
}

fn makeEntry(
    account: []const u8,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    digest_fill: u8,
    sha_fill: u8,
) BaselineEntry {
    return entryFromHint(makeHint(account, revision, phase, next_transition_ms, digest_fill, sha_fill));
}

fn hintAccount(hint: *const ReinspectHint) []const u8 {
    return hint.account_buf[0..hint.account_len];
}

fn entryAccount(entry: *const BaselineEntry) []const u8 {
    return entry.account_buf[0..entry.account_len];
}

fn expectComplete(
    result: BuildResult,
    candidate_count: usize,
    work_count: usize,
    security_now_ms: u64,
    earliest: ?u64,
) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).complete, std.meta.activeTag(result));
    try testing.expectEqual(candidate_count, result.complete.candidate_count);
    try testing.expectEqual(work_count, result.complete.work_count);
    try testing.expectEqual(security_now_ms, result.complete.security_now_ms);
    try testing.expectEqual(earliest, result.complete.earliest_transition_ms);
}

fn expectInvalidPrevious(result: BuildResult, index: usize, reason: InvalidReason) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).invalid_previous, std.meta.activeTag(result));
    try testing.expectEqual(index, result.invalid_previous.index);
    try testing.expectEqual(reason, result.invalid_previous.reason);
}

fn expectInvalidCurrent(result: BuildResult, index: usize, reason: InvalidReason) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).invalid_current, std.meta.activeTag(result));
    try testing.expectEqual(index, result.invalid_current.index);
    try testing.expectEqual(reason, result.invalid_current.reason);
}

fn expectCross(result: BuildResult, previous_index: usize, current_index: usize) !void {
    try testing.expectEqual(std.meta.Tag(BuildResult).invalid_cross_generation, std.meta.activeTag(result));
    try testing.expectEqual(previous_index, result.invalid_cross_generation.previous_index);
    try testing.expectEqual(current_index, result.invalid_cross_generation.current_index);
}

fn snapshotEntries(entries: []const BaselineEntry) [65536]u8 {
    var out: [65536]u8 = undefined;
    const bytes = std.mem.sliceAsBytes(entries);
    std.debug.assert(bytes.len <= out.len);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

fn snapshotWork(items: []const WorkItem) [65536]u8 {
    var out: [65536]u8 = undefined;
    const bytes = std.mem.sliceAsBytes(items);
    std.debug.assert(bytes.len <= out.len);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

fn expectUntouchedEntries(before: [65536]u8, entries: []const BaselineEntry) !void {
    const bytes = std.mem.sliceAsBytes(entries);
    try testing.expectEqualSlices(u8, before[0..bytes.len], bytes);
}

fn expectUntouchedWork(before: [65536]u8, items: []const WorkItem) !void {
    const bytes = std.mem.sliceAsBytes(items);
    try testing.expectEqualSlices(u8, before[0..bytes.len], bytes);
}

fn expectEntry(
    entry: BaselineEntry,
    account: []const u8,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    digest_fill: u8,
    sha_fill: u8,
) !void {
    try testing.expectEqualStrings(account, entryAccount(&entry));
    try testing.expectEqual(revision, entry.revision);
    try testing.expectEqual(phase, entry.phase);
    try testing.expectEqual(next_transition_ms, entry.next_transition_ms);
    try testing.expectEqualSlices(u8, &@as([digest_len]u8, @splat(digest_fill)), &entry.digest);
    try testing.expectEqualSlices(u8, &@as([digest_len]u8, @splat(sha_fill)), &entry.wire_sha256);
}

fn expectWork(
    item: WorkItem,
    cause: Cause,
    account: []const u8,
    revision: u64,
    phase: Phase,
    next_transition_ms: ?u64,
    digest_fill: u8,
    sha_fill: u8,
) !void {
    try testing.expectEqual(cause, item.cause);
    try expectEntry(item.expected, account, revision, phase, next_transition_ms, digest_fill, sha_fill);
}

fn name256(index: usize) [4]u8 {
    var name = [4]u8{ 'n', '0', '0', '0' };
    var value = index;
    name[3] = '0' + @as(u8, @intCast(value % 10));
    value /= 10;
    name[2] = '0' + @as(u8, @intCast(value % 10));
    value /= 10;
    name[1] = '0' + @as(u8, @intCast(value % 10));
    return name;
}

fn testKey(seed: u8) !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
}

fn testConfig(kp: Ed25519.KeyPair) durable_oper_authority.Config {
    const public_key = kp.public_key.toBytes();
    return .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
}

fn signFields(
    kp: Ed25519.KeyPair,
    fields: oper_cred_share.Ocg2Fields,
    now_ms: u64,
    out: []u8,
) ![]u8 {
    const len = try oper_cred_share.signOcg2(kp, fields, now_ms, out);
    return out[0..len];
}

fn grantFields(
    config: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
    expiry_ms: u64,
    title: []const u8,
) oper_cred_share.Ocg2Fields {
    return .{
        .kind = .grant,
        .account = account,
        .revision = revision,
        .privilege_bits = @as(u64, 1) << 3,
        .class = "moderator",
        .title = title,
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    };
}

fn tombstoneFields(
    config: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
) oper_cred_share.Ocg2Fields {
    return .{
        .kind = .tombstone,
        .account = account,
        .revision = revision,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = 0,
    };
}

fn fillCopy(
    copy: *TransactionCopy,
    config: durable_oper_authority.Config,
    wire: []const u8,
    fields: oper_cred_share.Ocg2Fields,
    equivocation: bool,
    conflict_digest: [digest_len]u8,
) void {
    copy.* = .{
        .revision = fields.revision,
        .kind = fields.kind,
        .issued_ms = fields.issued_ms,
        .expiry_ms = fields.expiry_ms,
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .equivocation = equivocation,
        .conflict_digest = conflict_digest,
    };
    @memcpy(copy.account_buf[0..fields.account.len], fields.account);
    copy.account_len = fields.account.len;
    @memcpy(copy.wire_buf[0..wire.len], wire);
    copy.wire_len = wire.len;
    Blake3.hash(wire, &copy.digest, .{});
    Sha256.hash(wire, &copy.wire_sha256, .{});
}

fn makeCopy(
    kp: Ed25519.KeyPair,
    fields: oper_cred_share.Ocg2Fields,
    equivocation: bool,
    conflict_digest: [digest_len]u8,
) !TransactionCopy {
    var wire_buf: [max_wire_len]u8 = undefined;
    const wire = try signFields(kp, fields, fields.issued_ms, &wire_buf);
    var copy = TransactionCopy{};
    fillCopy(&copy, testConfig(kp), wire, fields, equivocation, conflict_digest);
    return copy;
}

fn testCommit(
    state: *durable_oper_authority.State,
    wire: []const u8,
    now_ms: u64,
) !durable_oper_authority.UpdateDisposition {
    if (!state.securityTimeAuthorized()) {
        const horizon = std.math.add(u64, now_ms, oper_cred_share.ocg2_max_ttl_ms + 1) catch
            std.math.maxInt(u64);
        var reservation = try state.prepareSecurityTimeReservation(now_ms, horizon);
        reservation.update.commitInto(state);
    }
    var outcome = try state.prepareMerge(wire, now_ms);
    return switch (outcome) {
        .update => |*update| blk: {
            const disposition = update.disposition;
            update.commitInto(state);
            break :blk disposition;
        },
        else => error.TestUnexpectedResult,
    };
}

fn hintFromCopy(copy: TransactionCopy, now_ms: u64) !ReinspectHint {
    var out: [1]ReinspectHint = undefined;
    const result = ocg2_reconcile_schedule.build(&.{copy}, now_ms, &out);
    try testing.expectEqual(std.meta.Tag(ocg2_reconcile_schedule.BuildResult).complete, std.meta.activeTag(result));
    return out[0];
}

test "OCG2WORK empty inventories are complete and write nothing" {
    const sentinel_entry = BaselineEntry{ .revision = 0xdead_beef };
    const sentinel_work = WorkItem{ .cause = .successor, .expected = .{ .revision = 0xfeed } };
    var candidates = [_]BaselineEntry{sentinel_entry};
    var work = [_]WorkItem{sentinel_work};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectComplete(build(&.{}, null, &.{}, 0, candidates[0..0], work[0..0]), 0, 0, 0, null);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK initial baseline emits inventory_added for every entry including terminals" {
    const current = [_]ReinspectHint{
        makeHint("alice", 1, .expired, null, 1, 2),
        makeHint("bob", 2, .tombstone, null, 3, 4),
        makeHint("car", 3, .equivocation, null, 5, 6),
        makeHint("zed", 4, .active, 9_000, 7, 8),
    };
    var candidates: [4]BaselineEntry = undefined;
    var work: [4]WorkItem = undefined;
    try expectComplete(build(&.{}, null, &current, 1_000, &candidates, &work), 4, 4, 1_000, 9_000);
    try expectWork(work[0], .inventory_added, "alice", 1, .expired, null, 1, 2);
    try expectWork(work[1], .inventory_added, "bob", 2, .tombstone, null, 3, 4);
    try expectWork(work[2], .inventory_added, "car", 3, .equivocation, null, 5, 6);
    try expectWork(work[3], .inventory_added, "zed", 4, .active, 9_000, 7, 8);
    try expectEntry(candidates[0], "alice", 1, .expired, null, 1, 2);
    try expectEntry(candidates[3], "zed", 4, .active, 9_000, 7, 8);
}

test "OCG2WORK unchanged tuple emits no work and acknowledges candidates" {
    const previous = [_]BaselineEntry{
        makeEntry("alice", 2, .active, 5_000, 9, 10),
        makeEntry("bob", 1, .tombstone, null, 11, 12),
    };
    const current = [_]ReinspectHint{
        makeHint("alice", 2, .active, 5_000, 9, 10),
        makeHint("bob", 1, .tombstone, null, 11, 12),
    };
    const sentinel = WorkItem{ .cause = .successor, .expected = .{ .revision = 77 } };
    var candidates: [2]BaselineEntry = undefined;
    var work = [_]WorkItem{ sentinel, sentinel };
    try expectComplete(build(&previous, 1_000, &current, 1_000, &candidates, &work), 2, 0, 1_000, 5_000);
    try expectEntry(candidates[0], "alice", 2, .active, 5_000, 9, 10);
    try expectEntry(candidates[1], "bob", 1, .tombstone, null, 11, 12);
    try testing.expectEqual(Cause.successor, work[0].cause);
    try testing.expectEqual(@as(u64, 77), work[0].expected.revision);
}

test "OCG2WORK exact issue and expiry are temporal transitions" {
    const previous_issue = [_]BaselineEntry{makeEntry("alice", 1, .not_yet_valid, 1_000, 1, 1)};
    const current_issue = [_]ReinspectHint{makeHint("alice", 1, .active, 5_000, 1, 1)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&previous_issue, 999, &current_issue, 1_000, &candidates, &work), 1, 1, 1_000, 5_000);
    try expectWork(work[0], .temporal_transition, "alice", 1, .active, 5_000, 1, 1);

    const previous_expiry = [_]BaselineEntry{makeEntry("alice", 1, .active, 5_000, 1, 1)};
    const current_expiry = [_]ReinspectHint{makeHint("alice", 1, .expired, null, 1, 1)};
    try expectComplete(build(&previous_expiry, 4_999, &current_expiry, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try expectWork(work[0], .temporal_transition, "alice", 1, .expired, null, 1, 1);
}

test "OCG2WORK direct not_yet_valid to expired is temporal" {
    const previous = [_]BaselineEntry{makeEntry("alice", 1, .not_yet_valid, 1_000, 4, 5)};
    const current = [_]ReinspectHint{makeHint("alice", 1, .expired, null, 4, 5)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&previous, 500, &current, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try expectWork(work[0], .temporal_transition, "alice", 1, .expired, null, 4, 5);
}

test "OCG2WORK same identity may become equivocation without digest change" {
    const previous = [_]BaselineEntry{makeEntry("alice", 3, .active, 8_000, 21, 22)};
    const current = [_]ReinspectHint{makeHint("alice", 3, .equivocation, null, 21, 22)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&previous, 1_000, &current, 1_000, &candidates, &work), 1, 1, 1_000, null);
    try expectWork(work[0], .equivocation, "alice", 3, .equivocation, null, 21, 22);
}

test "OCG2WORK same revision changed identity is valid only as equivocation" {
    const previous = [_]BaselineEntry{makeEntry("alice", 3, .active, 8_000, 21, 22)};
    const rejected = [_]ReinspectHint{makeHint("alice", 3, .active, 8_000, 23, 24)};
    var candidates = [_]BaselineEntry{.{ .revision = 9 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 9 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectCross(build(&previous, 1_000, &rejected, 1_000, &candidates, &work), 0, 0);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);

    const accepted = [_]ReinspectHint{makeHint("alice", 3, .equivocation, null, 23, 24)};
    try expectComplete(build(&previous, 1_000, &accepted, 1_000, &candidates, &work), 1, 1, 1_000, null);
    try expectWork(work[0], .equivocation, "alice", 3, .equivocation, null, 23, 24);
}

test "OCG2WORK higher revision grant narrow tombstone and new equivocation" {
    const previous = [_]BaselineEntry{makeEntry("alice", 1, .active, 9_000, 1, 1)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;

    const grant = [_]ReinspectHint{makeHint("alice", 2, .active, 12_000, 2, 2)};
    try expectComplete(build(&previous, 1_000, &grant, 1_000, &candidates, &work), 1, 1, 1_000, 12_000);
    try expectWork(work[0], .successor, "alice", 2, .active, 12_000, 2, 2);

    const narrow = [_]ReinspectHint{makeHint("alice", 2, .active, 11_000, 3, 3)};
    try expectComplete(build(&previous, 1_000, &narrow, 1_000, &candidates, &work), 1, 1, 1_000, 11_000);
    try expectWork(work[0], .successor, "alice", 2, .active, 11_000, 3, 3);

    const tomb = [_]ReinspectHint{makeHint("alice", 2, .tombstone, null, 4, 4)};
    try expectComplete(build(&previous, 1_000, &tomb, 1_000, &candidates, &work), 1, 1, 1_000, null);
    try expectWork(work[0], .successor, "alice", 2, .tombstone, null, 4, 4);

    const equiv = [_]ReinspectHint{makeHint("alice", 2, .equivocation, null, 5, 5)};
    try expectComplete(build(&previous, 1_000, &equiv, 1_000, &candidates, &work), 1, 1, 1_000, null);
    try expectWork(work[0], .equivocation, "alice", 2, .equivocation, null, 5, 5);
}

test "OCG2WORK successor after terminal phases" {
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;

    const expired = [_]BaselineEntry{makeEntry("alice", 1, .expired, null, 1, 1)};
    const after_expired = [_]ReinspectHint{makeHint("alice", 2, .active, 8_000, 2, 2)};
    try expectComplete(build(&expired, 5_000, &after_expired, 5_000, &candidates, &work), 1, 1, 5_000, 8_000);
    try expectWork(work[0], .successor, "alice", 2, .active, 8_000, 2, 2);

    const tomb = [_]BaselineEntry{makeEntry("bob", 4, .tombstone, null, 3, 3)};
    const after_tomb = [_]ReinspectHint{makeHint("bob", 5, .tombstone, null, 4, 4)};
    try expectComplete(build(&tomb, 5_000, &after_tomb, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try expectWork(work[0], .successor, "bob", 5, .tombstone, null, 4, 4);

    const equiv = [_]BaselineEntry{makeEntry("car", 2, .equivocation, null, 5, 5)};
    const after_equiv = [_]ReinspectHint{makeHint("car", 3, .equivocation, null, 6, 6)};
    try expectComplete(build(&equiv, 5_000, &after_equiv, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try expectWork(work[0], .successor, "car", 3, .equivocation, null, 6, 6);
}

test "OCG2WORK security-time rollback is fail-closed" {
    const previous = [_]BaselineEntry{makeEntry("alice", 1, .active, 5_000, 1, 1)};
    const current = [_]ReinspectHint{makeHint("alice", 1, .active, 5_000, 1, 1)};
    var candidates = [_]BaselineEntry{.{ .revision = 3 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 3 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try testing.expectEqual(
        std.meta.Tag(BuildResult).security_time_rollback,
        std.meta.activeTag(build(&previous, 2_000, &current, 1_999, &candidates, &work)),
    );
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
    try expectComplete(build(&previous, 2_000, &current, 2_000, &candidates, &work), 1, 0, 2_000, 5_000);
}

test "OCG2WORK lower revision is rejected" {
    const previous = [_]BaselineEntry{makeEntry("alice", 5, .active, 9_000, 1, 1)};
    const current = [_]ReinspectHint{makeHint("alice", 4, .active, 9_000, 1, 1)};
    var candidates = [_]BaselineEntry{.{ .revision = 8 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 8 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectCross(build(&previous, 1_000, &current, 1_000, &candidates, &work), 0, 0);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK removal is an invariant failure" {
    const previous = [_]BaselineEntry{
        makeEntry("alice", 1, .active, 5_000, 1, 1),
        makeEntry("bob", 1, .expired, null, 2, 2),
    };
    const current = [_]ReinspectHint{makeHint("alice", 1, .active, 5_000, 1, 1)};
    var candidates = [_]BaselineEntry{.{ .revision = 4 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 4 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectCross(build(&previous, 1_000, &current, 1_000, &candidates, &work), 1, 1);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);

    const middle = [_]ReinspectHint{
        makeHint("alice", 1, .active, 5_000, 1, 1),
        makeHint("car", 1, .expired, null, 3, 3),
    };
    var middle_candidates = [_]BaselineEntry{ .{ .revision = 4 }, .{ .revision = 4 } };
    try expectCross(build(&previous, 1_000, &middle, 1_000, &middle_candidates, &work), 1, 1);
}

test "OCG2WORK malformed noncanonical duplicate and permuted names fail closed" {
    var empty = makeHint("alice", 1, .expired, null, 1, 1);
    empty.account_len = 0;
    var too_long = empty;
    too_long.account_len = max_account_len + 1;
    var overflow = empty;
    overflow.account_len = std.math.maxInt(usize);
    var upper = makeHint("alice", 1, .expired, null, 1, 1);
    upper.account_buf[0] = 'A';
    const duplicate = [_]ReinspectHint{
        makeHint("alice", 1, .expired, null, 1, 1),
        makeHint("alice", 2, .expired, null, 2, 2),
    };
    const permuted = [_]ReinspectHint{
        makeHint("bob", 1, .expired, null, 1, 1),
        makeHint("alice", 1, .expired, null, 2, 2),
    };

    var candidates = [_]BaselineEntry{.{ .revision = 5 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 5 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectInvalidCurrent(build(&.{}, null, &.{empty}, 1_000, &candidates, &work), 0, .account_bounds);
    try expectInvalidCurrent(build(&.{}, null, &.{too_long}, 1_000, &candidates, &work), 0, .account_bounds);
    try expectInvalidCurrent(build(&.{}, null, &.{overflow}, 1_000, &candidates, &work), 0, .account_bounds);
    try expectInvalidCurrent(build(&.{}, null, &.{upper}, 1_000, &candidates, &work), 0, .account_bounds);
    try expectInvalidCurrent(build(&.{}, null, &duplicate, 1_000, &candidates, &work), 1, .account_order);
    try expectInvalidCurrent(build(&.{}, null, &permuted, 1_000, &candidates, &work), 1, .account_order);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);

    var prev_upper = makeEntry("alice", 1, .expired, null, 1, 1);
    prev_upper.account_buf[0] = 'A';
    try expectInvalidPrevious(build(&.{prev_upper}, 1_000, &.{}, 1_000, candidates[0..0], work[0..0]), 0, .account_bounds);
}

test "OCG2WORK zero revision fails closed" {
    var previous = makeEntry("alice", 1, .expired, null, 1, 1);
    previous.revision = 0;
    var current = makeHint("bob", 1, .expired, null, 2, 2);
    current.revision = 0;
    var candidates = [_]BaselineEntry{.{ .revision = 6 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 6 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectInvalidPrevious(build(&.{previous}, 1_000, &.{}, 1_000, candidates[0..0], work[0..0]), 0, .zero_revision);
    try expectInvalidCurrent(build(&.{}, null, &.{current}, 1_000, &candidates, &work), 0, .zero_revision);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK invalid previous and current phase deadlines fail closed" {
    var candidates = [_]BaselineEntry{.{ .revision = 7 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 7 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);

    try expectInvalidPrevious(
        build(&.{makeEntry("alice", 1, .active, null, 1, 1)}, 1_000, &.{}, 1_000, candidates[0..0], work[0..0]),
        0,
        .phase_deadline,
    );
    try expectInvalidPrevious(
        build(&.{makeEntry("alice", 1, .not_yet_valid, 1_000, 1, 1)}, 1_000, &.{}, 1_000, candidates[0..0], work[0..0]),
        0,
        .phase_deadline,
    );
    try expectInvalidPrevious(
        build(&.{makeEntry("alice", 1, .expired, 2_000, 1, 1)}, 1_000, &.{}, 1_000, candidates[0..0], work[0..0]),
        0,
        .phase_deadline,
    );
    try expectInvalidCurrent(
        build(&.{}, null, &.{makeHint("alice", 1, .active, 1_000, 1, 1)}, 1_000, &candidates, &work),
        0,
        .phase_deadline,
    );
    try expectInvalidCurrent(
        build(&.{}, null, &.{makeHint("alice", 1, .not_yet_valid, null, 1, 1)}, 1_000, &candidates, &work),
        0,
        .phase_deadline,
    );
    try expectInvalidCurrent(
        build(&.{}, null, &.{makeHint("alice", 1, .tombstone, 4_000, 1, 1)}, 1_000, &candidates, &work),
        0,
        .phase_deadline,
    );
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK later invalid entry is failure-atomic" {
    const previous = [_]BaselineEntry{
        makeEntry("alice", 1, .active, 5_000, 1, 1),
        makeEntry("bob", 0, .expired, null, 2, 2),
    };
    const current = [_]ReinspectHint{
        makeHint("alice", 1, .active, 5_000, 1, 1),
        makeHint("car", 1, .expired, null, 3, 3),
    };
    var candidates = [_]BaselineEntry{ .{ .revision = 11 }, .{ .revision = 11 } };
    var work = [_]WorkItem{ .{ .expected = .{ .revision = 11 } }, .{ .expected = .{ .revision = 11 } } };
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectInvalidPrevious(build(&previous, 1_000, &current, 1_000, &candidates, &work), 1, .zero_revision);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);

    const later_current = [_]ReinspectHint{
        makeHint("alice", 1, .active, 5_000, 1, 1),
        makeHint("bob", 0, .expired, null, 2, 2),
    };
    const valid_previous = [_]BaselineEntry{makeEntry("alice", 1, .active, 5_000, 1, 1)};
    try expectInvalidCurrent(build(&valid_previous, 1_000, &later_current, 1_000, &candidates, &work), 1, .zero_revision);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK invalid wins over undersized outputs" {
    var bad = makeHint("alice", 1, .expired, null, 1, 1);
    bad.revision = 0;
    var candidates = [_]BaselineEntry{.{ .revision = 12 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 12 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectInvalidCurrent(build(&.{}, null, &.{bad}, 1_000, candidates[0..0], work[0..0]), 0, .zero_revision);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
}

test "OCG2WORK aliasing wins over undersized outputs" {
    var storage: [512]u8 align(@alignOf(WorkItem)) = undefined;
    @memset(&storage, 0x5a);
    const current_slot = std.mem.bytesAsSlice(ReinspectHint, storage[0..@sizeOf(ReinspectHint)]);
    current_slot[0] = makeHint("alice", 1, .expired, null, 1, 1);
    const candidates = std.mem.bytesAsSlice(BaselineEntry, storage[0..@sizeOf(BaselineEntry)]);
    var work = [_]WorkItem{};
    try testing.expectEqual(
        std.meta.Tag(BuildResult).aliasing,
        std.meta.activeTag(build(&.{}, null, current_slot, 1_000, candidates, &work)),
    );
}

test "OCG2WORK exact over and under output capacities" {
    const current = [_]ReinspectHint{
        makeHint("alice", 1, .expired, null, 1, 1),
        makeHint("bob", 1, .expired, null, 2, 2),
    };
    const sentinel_entry = BaselineEntry{ .revision = 13 };
    const sentinel_work = WorkItem{ .cause = .successor, .expected = .{ .revision = 13 } };

    var under_candidates = [_]BaselineEntry{sentinel_entry};
    var under_work = [_]WorkItem{sentinel_work};
    const before_candidates = snapshotEntries(&under_candidates);
    const before_work = snapshotWork(&under_work);
    const under_candidate = build(&.{}, null, &current, 1_000, &under_candidates, &under_work);
    try testing.expectEqual(std.meta.Tag(BuildResult).insufficient_candidate_output, std.meta.activeTag(under_candidate));
    try testing.expectEqual(@as(usize, 2), under_candidate.insufficient_candidate_output);
    try expectUntouchedEntries(before_candidates, &under_candidates);
    try expectUntouchedWork(before_work, &under_work);

    var exact_candidates: [2]BaselineEntry = .{ sentinel_entry, sentinel_entry };
    var exact_work_under = [_]WorkItem{sentinel_work};
    const before_work_under = snapshotWork(&exact_work_under);
    const under_work_result = build(&.{}, null, &current, 1_000, &exact_candidates, &exact_work_under);
    try testing.expectEqual(std.meta.Tag(BuildResult).insufficient_work_output, std.meta.activeTag(under_work_result));
    try testing.expectEqual(@as(usize, 2), under_work_result.insufficient_work_output);
    try expectUntouchedWork(before_work_under, &exact_work_under);

    var exact_work: [2]WorkItem = .{ sentinel_work, sentinel_work };
    try expectComplete(build(&.{}, null, &current, 1_000, &exact_candidates, &exact_work), 2, 2, 1_000, null);

    var over_candidates = [_]BaselineEntry{ sentinel_entry, sentinel_entry, sentinel_entry };
    var over_work = [_]WorkItem{ sentinel_work, sentinel_work, sentinel_work };
    try expectComplete(build(&.{}, null, &current, 1_000, &over_candidates, &over_work), 2, 2, 1_000, null);
    try testing.expectEqual(@as(u64, 13), over_candidates[2].revision);
    try testing.expectEqual(@as(u64, 13), over_work[2].expected.revision);
}

test "OCG2WORK output tails stay untouched" {
    const current = [_]ReinspectHint{makeHint("alice", 1, .active, 4_000, 1, 1)};
    var candidates = [_]BaselineEntry{
        .{ .revision = 1 },
        .{ .revision = 99, .phase = .equivocation },
    };
    var work = [_]WorkItem{
        .{ .expected = .{ .revision = 1 } },
        .{ .cause = .successor, .expected = .{ .revision = 88 } },
    };
    try expectComplete(build(&.{}, null, &current, 1_000, &candidates, &work), 1, 1, 1_000, 4_000);
    try testing.expectEqual(@as(u64, 99), candidates[1].revision);
    try testing.expectEqual(Phase.equivocation, candidates[1].phase);
    try testing.expectEqual(Cause.successor, work[1].cause);
    try testing.expectEqual(@as(u64, 88), work[1].expected.revision);
}

test "OCG2WORK full 256 inventory and over-capacity" {
    var previous: [max_entries]BaselineEntry = undefined;
    var current: [max_entries]ReinspectHint = undefined;
    var extra: [max_entries + 1]ReinspectHint = undefined;
    var i: usize = 0;
    while (i < max_entries) : (i += 1) {
        const name = name256(i);
        previous[i] = makeEntry(&name, 1, .expired, null, 1, 1);
        current[i] = makeHint(&name, 1, .expired, null, 1, 1);
        extra[i] = current[i];
    }
    const overflow_name = name256(max_entries);
    extra[max_entries] = makeHint(&overflow_name, 1, .expired, null, 1, 1);

    var candidates: [max_entries]BaselineEntry = undefined;
    var work: [max_entries]WorkItem = undefined;
    try expectComplete(build(&previous, 1_000, &current, 1_000, &candidates, &work), max_entries, 0, 1_000, null);
    try testing.expectEqualStrings("n000", entryAccount(&candidates[0]));
    try testing.expectEqualStrings("n255", entryAccount(&candidates[max_entries - 1]));

    var overflow_candidates: [max_entries + 1]BaselineEntry = undefined;
    var overflow_work: [max_entries + 1]WorkItem = undefined;
    try expectInvalidCurrent(
        build(&.{}, null, &extra, 1_000, &overflow_candidates, &overflow_work),
        max_entries,
        .inventory_bounds,
    );

    var overflow_previous: [max_entries + 1]BaselineEntry = undefined;
    i = 0;
    while (i <= max_entries) : (i += 1) {
        const name = name256(i);
        overflow_previous[i] = makeEntry(&name, 1, .expired, null, 1, 1);
    }
    try expectInvalidPrevious(
        build(&overflow_previous, 1_000, &.{}, 1_000, overflow_candidates[0..0], overflow_work[0..0]),
        max_entries,
        .inventory_bounds,
    );
}

test "OCG2WORK now at zero and maxInt stay exact" {
    const max_u64 = std.math.maxInt(u64);
    const previous_zero = [_]BaselineEntry{makeEntry("alice", 1, .active, 1, 1, 1)};
    const current_zero = [_]ReinspectHint{makeHint("alice", 1, .active, 1, 1, 1)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&previous_zero, 0, &current_zero, 0, &candidates, &work), 1, 0, 0, 1);

    const expire = [_]ReinspectHint{makeHint("alice", 1, .expired, null, 1, 1)};
    try expectComplete(build(&previous_zero, 0, &expire, 1, &candidates, &work), 1, 1, 1, null);
    try expectWork(work[0], .temporal_transition, "alice", 1, .expired, null, 1, 1);

    const previous_max = [_]BaselineEntry{makeEntry("bob", 1, .not_yet_valid, max_u64, 2, 2)};
    const current_max = [_]ReinspectHint{makeHint("bob", 1, .not_yet_valid, max_u64, 2, 2)};
    try expectComplete(
        build(&previous_max, max_u64 - 1, &current_max, max_u64 - 1, &candidates, &work),
        1,
        0,
        max_u64 - 1,
        max_u64,
    );
    const expired_max = [_]ReinspectHint{makeHint("bob", 1, .expired, null, 2, 2)};
    try expectComplete(build(&previous_max, max_u64 - 1, &expired_max, max_u64, &candidates, &work), 1, 1, max_u64, null);
}

test "OCG2WORK input output aliasing is rejected" {
    var shared = [_]BaselineEntry{makeEntry("alice", 1, .active, 5_000, 1, 1)};
    const current = [_]ReinspectHint{makeHint("alice", 1, .active, 5_000, 1, 1)};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 1 } }};
    try testing.expectEqual(
        std.meta.Tag(BuildResult).aliasing,
        std.meta.activeTag(build(&shared, 1_000, &current, 1_000, &shared, &work)),
    );

    var blob: [1024]u8 align(@alignOf(WorkItem)) = undefined;
    @memset(&blob, 0x3c);
    const hint_slot = std.mem.bytesAsSlice(ReinspectHint, blob[0..@sizeOf(ReinspectHint)]);
    hint_slot[0] = makeHint("alice", 1, .expired, null, 1, 1);
    const candidate_slot = std.mem.bytesAsSlice(BaselineEntry, blob[0..@sizeOf(BaselineEntry)]);
    const work_slot = std.mem.bytesAsSlice(WorkItem, blob[0..@sizeOf(WorkItem)]);
    try testing.expectEqual(
        std.meta.Tag(BuildResult).aliasing,
        std.meta.activeTag(build(&.{}, null, hint_slot, 1_000, candidate_slot, work_slot)),
    );
}

test "OCG2WORK inline copies are independent of inputs" {
    var previous = [_]BaselineEntry{makeEntry("alice", 1, .active, 5_000, 9, 9)};
    var current = [_]ReinspectHint{makeHint("alice", 2, .active, 8_000, 8, 8)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&previous, 1_000, &current, 1_000, &candidates, &work), 1, 1, 1_000, 8_000);
    previous[0].account_buf[0] = 'z';
    previous[0].digest[0] = 0;
    current[0].account_buf[0] = 'y';
    current[0].digest[0] = 0;
    try testing.expectEqualStrings("alice", entryAccount(&candidates[0]));
    try testing.expectEqualStrings("alice", entryAccount(&work[0].expected));
    try testing.expectEqual(@as(u8, 8), candidates[0].digest[0]);
    try testing.expectEqual(@as(u8, 8), work[0].expected.digest[0]);
    try testing.expect(entryAccount(&candidates[0]).ptr != hintAccount(&current[0]).ptr);
    try testing.expect(entryAccount(&work[0].expected).ptr != entryAccount(&previous[0]).ptr);
}

test "OCG2WORK C2 to C3 to C4 integration" {
    const kp = try testKey(0xC4);
    const config = testConfig(kp);
    var state = try durable_oper_authority.State.init(testing.allocator, config);
    defer state.deinit();

    var alice_buf: [max_wire_len]u8 = undefined;
    const alice = try signFields(kp, grantFields(config, "alice", 1, 500, 900, "Expired"), 500, &alice_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, alice, 500));
    var bob_first_buf: [max_wire_len]u8 = undefined;
    const bob_first = try signFields(kp, grantFields(config, "bob", 1, 1_000, 5_000, "First"), 1_000, &bob_first_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, bob_first, 1_000));
    var bob_conflict_buf: [max_wire_len]u8 = undefined;
    const bob_conflict = try signFields(kp, grantFields(config, "bob", 1, 1_000, 5_000, "Conflict"), 1_000, &bob_conflict_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.equivocation, try testCommit(&state, bob_conflict, 1_000));
    var car_buf: [max_wire_len]u8 = undefined;
    const car = try signFields(kp, grantFields(config, "car", 1, 4_000, 9_000, "Future"), 1_000, &car_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, car, 1_000));
    var zed_buf: [max_wire_len]u8 = undefined;
    const zed = try signFields(kp, tombstoneFields(config, "zed", 1, 1_200), 1_200, &zed_buf);
    try testing.expectEqual(durable_oper_authority.UpdateDisposition.successor, try testCommit(&state, zed, 1_200));

    var copies: [4]TransactionCopy = undefined;
    try testing.expectEqual(@as(usize, 4), try state.copyTransactions(&copies));
    var hints: [4]ReinspectHint = undefined;
    const scheduled = ocg2_reconcile_schedule.build(&copies, 1_000, &hints);
    try testing.expectEqual(std.meta.Tag(ocg2_reconcile_schedule.BuildResult).complete, std.meta.activeTag(scheduled));
    try testing.expectEqual(@as(?u64, 4_000), scheduled.complete.earliest_transition_ms);

    var candidates: [4]BaselineEntry = undefined;
    var work: [4]WorkItem = undefined;
    try expectComplete(build(&.{}, null, &hints, 1_000, &candidates, &work), 4, 4, 1_000, 4_000);
    try testing.expectEqual(Cause.inventory_added, work[0].cause);
    try testing.expectEqual(Phase.expired, work[0].expected.phase);
    try testing.expectEqual(Cause.inventory_added, work[1].cause);
    try testing.expectEqual(Phase.equivocation, work[1].expected.phase);
    try testing.expectEqual(Cause.inventory_added, work[2].cause);
    try testing.expectEqual(Phase.not_yet_valid, work[2].expected.phase);
    try testing.expectEqual(Cause.inventory_added, work[3].cause);
    try testing.expectEqual(Phase.tombstone, work[3].expected.phase);

    var later_hints: [4]ReinspectHint = undefined;
    const later = ocg2_reconcile_schedule.build(&copies, 4_000, &later_hints);
    try testing.expectEqual(std.meta.Tag(ocg2_reconcile_schedule.BuildResult).complete, std.meta.activeTag(later));
    var later_candidates: [4]BaselineEntry = undefined;
    var later_work: [4]WorkItem = undefined;
    try expectComplete(build(&candidates, 1_000, &later_hints, 4_000, &later_candidates, &later_work), 4, 1, 4_000, 9_000);
    try testing.expectEqual(Cause.temporal_transition, later_work[0].cause);
    try testing.expectEqualStrings("car", entryAccount(&later_work[0].expected));
    try testing.expectEqual(@as(u64, 1), later_work[0].expected.revision);
    try testing.expectEqual(Phase.active, later_work[0].expected.phase);
    try testing.expectEqual(@as(?u64, 9_000), later_work[0].expected.next_transition_ms);
    try testing.expectEqualSlices(u8, &later_hints[2].digest, &later_work[0].expected.digest);
    try testing.expectEqualSlices(u8, &later_hints[2].wire_sha256, &later_work[0].expected.wire_sha256);
}

test "OCG2WORK C3 boundary rebuild integration" {
    const kp = try testKey(0xC5);
    const config = testConfig(kp);
    const copy = try makeCopy(kp, grantFields(config, "alice", 2, 1_000, 5_000, "Now"), false, @splat(0));

    const before_issue = try hintFromCopy(copy, 999);
    const at_issue = try hintFromCopy(copy, 1_000);
    const before_expiry = try hintFromCopy(copy, 4_999);
    const at_expiry = try hintFromCopy(copy, 5_000);
    try testing.expectEqual(Phase.not_yet_valid, before_issue.phase);
    try testing.expectEqual(Phase.active, at_issue.phase);
    try testing.expectEqual(Phase.active, before_expiry.phase);
    try testing.expectEqual(Phase.expired, at_expiry.phase);

    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    const previous_issue = [_]BaselineEntry{entryFromHint(before_issue)};
    try expectComplete(build(&previous_issue, 999, &.{at_issue}, 1_000, &candidates, &work), 1, 1, 1_000, 5_000);
    try testing.expectEqual(Cause.temporal_transition, work[0].cause);
    try testing.expectEqual(Phase.active, work[0].expected.phase);

    const previous_expiry = [_]BaselineEntry{entryFromHint(before_expiry)};
    try expectComplete(build(&previous_expiry, 4_999, &.{at_expiry}, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try testing.expectEqual(Cause.temporal_transition, work[0].cause);
    try testing.expectEqual(Phase.expired, work[0].expected.phase);

    const skipped = [_]ReinspectHint{at_expiry};
    try expectComplete(build(&previous_issue, 999, &skipped, 5_000, &candidates, &work), 1, 1, 5_000, null);
    try testing.expectEqual(Cause.temporal_transition, work[0].cause);
}

test "OCG2WORK null previous time only with empty previous" {
    const previous = [_]BaselineEntry{makeEntry("alice", 1, .expired, null, 1, 1)};
    var candidates = [_]BaselineEntry{.{ .revision = 14 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 14 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    try expectInvalidPrevious(build(&previous, null, &.{}, 1_000, candidates[0..0], work[0..0]), 0, .previous_time);
    try expectUntouchedEntries(before_candidates, &candidates);
    try expectUntouchedWork(before_work, &work);
    try expectComplete(build(&.{}, null, &.{}, 1_000, candidates[0..0], work[0..0]), 0, 0, 1_000, null);
}

test "OCG2WORK illegal same-identity phase transitions fail closed" {
    const cases = [_]struct {
        previous: BaselineEntry,
        current: ReinspectHint,
        previous_now: u64,
        now: u64,
    }{
        .{
            .previous = makeEntry("alice", 1, .expired, null, 1, 1),
            .current = makeHint("alice", 1, .active, 9_000, 1, 1),
            .previous_now = 6_000,
            .now = 6_000,
        },
        .{
            .previous = makeEntry("alice", 1, .active, 5_000, 1, 1),
            .current = makeHint("alice", 1, .not_yet_valid, 9_000, 1, 1),
            .previous_now = 1_000,
            .now = 1_000,
        },
        .{
            .previous = makeEntry("alice", 1, .tombstone, null, 1, 1),
            .current = makeHint("alice", 1, .expired, null, 1, 1),
            .previous_now = 1_000,
            .now = 1_000,
        },
        .{
            .previous = makeEntry("alice", 1, .equivocation, null, 1, 1),
            .current = makeHint("alice", 1, .active, 9_000, 1, 1),
            .previous_now = 1_000,
            .now = 1_000,
        },
        .{
            .previous = makeEntry("alice", 1, .not_yet_valid, 5_000, 1, 1),
            .current = makeHint("alice", 1, .active, 9_000, 1, 1),
            .previous_now = 1_000,
            .now = 4_999,
        },
    };
    var candidates = [_]BaselineEntry{.{ .revision = 15 }};
    var work = [_]WorkItem{.{ .expected = .{ .revision = 15 } }};
    const before_candidates = snapshotEntries(&candidates);
    const before_work = snapshotWork(&work);
    for (cases) |case| {
        try expectCross(
            build(&.{case.previous}, case.previous_now, &.{case.current}, case.now, &candidates, &work),
            0,
            0,
        );
        try expectUntouchedEntries(before_candidates, &candidates);
        try expectUntouchedWork(before_work, &work);
    }
}

test "OCG2WORK build never allocates" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const unused = failing.allocator();
    _ = unused;
    const current = [_]ReinspectHint{makeHint("alice", 1, .expired, null, 1, 1)};
    var candidates: [1]BaselineEntry = undefined;
    var work: [1]WorkItem = undefined;
    try expectComplete(build(&.{}, null, &current, 1_000, &candidates, &work), 1, 1, 1_000, null);
}

test "OCG2WORK reflection and import boundary stay advisory only" {
    const allowed = .{
        "Cause",   "InvalidReason", "BaselineEntry", "WorkItem",
        "Summary", "BuildResult",   "max_entries",   "build",
    };
    const names = @typeInfo(@This()).@"struct".decl_names;
    try testing.expectEqual(@as(usize, allowed.len), names.len);
    inline for (names) |name| {
        var found = false;
        inline for (allowed) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) found = true;
        }
        try testing.expect(found);
    }
    try testing.expectEqual(@as(usize, 256), max_entries);
    try testing.expectEqual(durable_oper_authority.max_records, max_entries);
    try testing.expectEqual(@as(usize, 0), @typeInfo(BaselineEntry).@"struct".decl_names.len);
    try testing.expectEqual(@as(usize, 0), @typeInfo(WorkItem).@"struct".decl_names.len);
    try testing.expectEqual(@as(usize, 6), @typeInfo(@TypeOf(build)).@"fn".param_types.len);
    inline for (@typeInfo(BaselineEntry).@"struct".field_names) |name| {
        try testing.expect(!std.mem.eql(u8, name, "privilege_bits"));
        try testing.expect(!std.mem.eql(u8, name, "class"));
        try testing.expect(!std.mem.eql(u8, name, "title"));
        try testing.expect(!std.mem.eql(u8, name, "wire"));
        try testing.expect(!std.mem.eql(u8, name, "wire_buf"));
        try testing.expect(!std.mem.eql(u8, name, "authority_pubkey"));
        try testing.expect(!std.mem.eql(u8, name, "allocator"));
        try testing.expect(!std.mem.eql(u8, name, "services"));
        try testing.expect(!std.mem.eql(u8, name, "store"));
        try testing.expect(!std.mem.eql(u8, name, "session"));
        try testing.expect(!std.mem.eql(u8, name, "callback"));
        try testing.expect(!std.mem.eql(u8, name, "projection"));
    }
    inline for (.{
        "apply",          "execute",           "grant",
        "revoke",         "mint",              "transmit",
        "session",        "callback",          "Visitor",
        "ProjectionData", "DurableOperLookup", "Services",
        "Store",          "reconcile",         "executeAuthorized",
        "buildAlloc",
    }) |name| {
        try testing.expect(!@hasDecl(@This(), name));
    }
}
