// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One bounded, redacted diagnostic bundle for a running daemon.
//!
//! The bundle is a single minified JSON document (`schema_version` 1, `kind`
//! "onyx-diagnostic-bundle") built from process-local state only: build
//! identity, build-defined CAP names, connection-diagnostics counters, token
//! publication / media / module counters, the newest flight-recorder events and
//! the newest typed connection-history records.
//!
//! Redaction is allowlist-only. Nothing caller-controlled is copied unless it is
//! proven safe by construction:
//!   * Flight-recorder messages are emitted only when they exactly equal a
//!     static server-literal rule, or (for formatted messages) only the static
//!     template prefix of a matching rule is emitted. Every other message is
//!     replaced by `null` with `msg_match:"redacted"`. Emitted message bytes are
//!     always the rule bytes, never the recorded bytes.
//!   * String field values are never emitted.
//!   * Numeric and boolean field values are emitted unless the key names an
//!     address, identity or credential, in which case the value is `null`.
//!   * Field keys are emitted only when they match `[a-z][a-z0-9_.]*` and are
//!     shorter than the recorder key capacity (a full-capacity key may be a
//!     truncated prefix); every other key is replaced by `<unsafe-key>`.
//!   * Connection-history records are copy-only typed metadata (no nick, peer
//!     address or wire text exists in `diagnostics.Record`).
//!
//! The rendered document is printable ASCII (no control bytes), so it can be
//! split into IRC NOTICE parts that reassemble byte-exact. Building it is
//! read-only with respect to daemon state: allocation failure leaves nothing
//! mutated and frees everything.

const std = @import("std");
const build_info = @import("build_info");
const diagnostics = @import("diagnostics.zig");
const sessions = @import("sessions.zig");
const tracelog = @import("../substrate/trace.zig");
const live_cap_metadata = @import("../proto/live_cap_metadata.zig");

pub const schema_version: u8 = 1;
pub const kind = "onyx-diagnostic-bundle";

/// Hard caps; `Options` are clamped to these.
pub const max_trace_events_limit: usize = 256;
pub const max_connection_records_limit: usize = diagnostics.history_capacity;
/// Defaults sized for an oper NOTICE stream (tens of parts, not hundreds).
pub const default_max_trace_events: usize = 32;
pub const default_max_connection_records: usize = 16;

/// Key bytes accepted verbatim are strictly shorter than the recorder's key
/// capacity: a key of exactly the capacity may have been truncated on record.
pub const max_safe_key_len: usize = tracelog.max_recorded_key_len - 1;
pub const unsafe_key_marker = "<unsafe-key>";

/// NOTICE framing. A part line is "DEBUG BUNDLE <i>/<n> <payload>". With a
/// 64-byte server name and nick this stays under the 512-byte IRC line limit.
pub const max_part_bytes: usize = 320;
pub const part_prefix = "DEBUG BUNDLE ";
pub const max_part_line_bytes: usize = part_prefix.len + 2 * 20 + 2 + max_part_bytes;
pub const max_trailer_bytes: usize = 160;

pub const Error = error{ OutOfMemory, BundleTooLarge };

pub const Match = enum { exact, prefix };

/// One static, server-defined trace message. `prefix` rules cover formatted
/// messages: only `text` is emitted, never the dynamic tail.
pub const MessageRule = struct {
    text: []const u8,
    match: Match = .exact,
};

/// Static literals and static template prefixes of `LinuxServer.traceLog` /
/// `flushFlightRecorder` call sites. A message that drifts from this list is
/// redacted (fail-closed), never echoed.
pub const default_message_rules = [_]MessageRule{
    .{ .text = "CRITICAL DPROP1 durable outcome requires OroStore reopen" },
    .{ .text = "GAP-O3 recorder marker" },
    .{ .text = "MESSAGE_V2 deferred queue exhausted; closing peer feed" },
    .{ .text = "client accepted" },
    .{ .text = "dropped malformed mesh-WARD frame from peer" },
    .{ .text = "dropped malformed mesh-ban filter from peer" },
    .{ .text = "invalid mesh trust root ignored" },
    .{ .text = "mesh trust root pin set refused: duplicate or too many roots" },
    .{ .text = "operator elevated via SASL account" },
    .{ .text = "refused plaintext S2S peer ([mesh].require_secured)" },
    .{ .text = "remote channel mode aggregate ignored local policy flags" },
    .{ .text = "remote channel mode state ignored on mlocked channel" },
    .{ .text = "s2s peer accepted" },
    .{ .text = "s2s peer accepted (activation staged)" },
    .{ .text = "s2s repair applied; requesting full state resync" },
    .{ .text = "s2s secured peer accepted" },
    .{ .text = "s2s secured peer accepted (activation staged)" },
    .{ .text = "s2s secured peer accepted (send staged)" },
    .{ .text = "s2s secured peer preserved across upgrade" },
    .{ .text = "secured link resume refused" },
    .{ .text = "skipped plaintext S2S dial ([mesh].require_secured)" },
    .{ .text = "tls client accepted" },
    .{ .text = "trusted proxy accepted; receive activation staged" },
    .{ .text = "trusted proxy accepted; waiting for PROXY header" },
    .{ .text = "ws client accepted" },
    .{ .text = "reactor giving up after persistent errors" },
    .{ .text = "mooring link dropped" },
    // Static fallbacks of formatted call sites.
    .{ .text = "dropped S2S frame(s) with mismatched origin" },
    .{ .text = "dropped inbound SESSION_REPLICA frames; requesting anti-entropy replay" },
    .{ .text = "dropped relayed message with bad origin signature" },
    .{ .text = "dropped relayed message: sender nick homed on a different node" },
    .{ .text = "dropped relayed message: sender home unknown without portable proof" },
    .{ .text = "dropped ENTITY_PROP with bad origin signature" },
    .{ .text = "dropped ENTITY_PROP identity write: origin is not the account's home" },
    .{ .text = "dropped CHANNEL_PROP with bad origin signature" },
    .{ .text = "failed to apply mesh-WARD from peer" },
    // Static template prefixes of formatted call sites (tail is dynamic).
    .{ .text = "mesh S2S established", .match = .prefix },
    .{ .text = "secured link handshake/feed failed", .match = .prefix },
    .{ .text = "cross-shard delivery dropped under back-pressure", .match = .prefix },
    .{ .text = "dropped relayed", .match = .prefix },
    .{ .text = "dropped ENTITY_PROP", .match = .prefix },
    .{ .text = "dropped ENTITY_PROP identity write", .match = .prefix },
    .{ .text = "quarantined remote ENTITY_PROP identity fact", .match = .prefix },
    .{ .text = "quarantined remote ENTITY_PROP device fact", .match = .prefix },
    .{ .text = "dropped CHANNEL_PROP", .match = .prefix },
    .{ .text = "failed to apply mesh-WARD", .match = .prefix },
    .{ .text = "SESSION DROP control hint missed; journal sweep remains authoritative", .match = .prefix },
};

comptime {
    @setEvalBranchQuota(default_message_rules.len * (tracelog.max_recorded_msg_len + 8));
    for (default_message_rules) |rule| {
        if (!ruleTextSafe(rule.text)) @compileError("unsafe diagnostic bundle message rule: " ++ rule.text);
    }
}

/// Numeric/boolean values whose key contains one of these fragments are
/// redacted: a number can still be an address, port-bound identity, SSRC or
/// credential. Over-redaction is the intended failure mode.
const sensitive_key_fragments = [_][]const u8{
    "addr", "ip",    "host",  "nick",   "account", "user", "token", "secret",
    "pass", "key",   "nonce", "cookie", "cert",    "ssrc", "uid",   "mac",
    "mail", "cloak", "sess",  "auth",
};

/// Plain live counters supplied by the caller; fixed names only.
pub const Counters = struct {
    token_publication: sessions.TokenPublicationStats = .{},
    media_fir_pli_ssrc_dropped: u64 = 0,
    modules_degraded: u64 = 0,
    modules_config_generation: u64 = 0,
    module_hook_unavailable: u64 = 0,
    module_hook_handler_errors: u64 = 0,
};

pub const Options = struct {
    /// Wall-clock milliseconds the bundle is taken at (0 = unknown).
    wall_ms: u64 = 0,
    max_trace_events: usize = default_max_trace_events,
    max_connection_records: usize = default_max_connection_records,
    message_rules: []const MessageRule = &default_message_rules,
};

pub const RedactionStats = struct {
    messages_emitted_exact: u64 = 0,
    messages_emitted_prefix: u64 = 0,
    messages_redacted: u64 = 0,
    string_fields_redacted: u64 = 0,
    numeric_fields_redacted: u64 = 0,
    numeric_fields_emitted: u64 = 0,
    keys_replaced: u64 = 0,
};

/// Owned bundle bytes. `storage` is the single bounded allocation; `len` bytes
/// of it are the document.
pub const Bundle = struct {
    storage: []u8,
    len: usize,
    redaction: RedactionStats,

    pub fn bytes(self: *const Bundle) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn deinit(self: *Bundle, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn parts(self: *const Bundle) PartIterator {
        return PartIterator.init(self.bytes());
    }
};

// ---------------------------------------------------------------------------
// Size bound

const per_field_max: usize = 80;
const per_event_fixed_max: usize = 224 + tracelog.max_recorded_msg_len;
pub const per_event_max: usize = per_event_fixed_max + tracelog.max_fields * per_field_max;
const max_error_name_len: usize = 64;
pub const per_record_max: usize = 448 + max_error_name_len;

pub const header_max: usize = blk: {
    var n: usize = 3072;
    // JSON escaping may expand a byte to `\u00XX`.
    n += 6 * (build_info.version.len + gitCommit().len);
    for (live_cap_metadata.cap_specs) |spec| n += spec.name.len + 40;
    for (@typeInfo(diagnostics.Event).@"enum".field_names) |name| n += name.len + 24;
    for (@typeInfo(sessions.TokenPublicationStats).@"struct".field_names) |name| n += name.len + 48;
    break :blk n;
};

/// Upper bound on the document for the given (clamped) entry counts.
pub fn maxBundleBytes(max_trace_events: usize, max_connection_records: usize) usize {
    const events = @min(max_trace_events, max_trace_events_limit);
    const records = @min(max_connection_records, max_connection_records_limit);
    return header_max + events * per_event_max + records * per_record_max;
}

pub const max_bundle_bytes: usize = maxBundleBytes(max_trace_events_limit, max_connection_records_limit);

fn gitCommit() []const u8 {
    return if (@hasDecl(build_info, "git_commit")) build_info.git_commit else "unknown";
}

// ---------------------------------------------------------------------------
// Redaction primitives

fn ruleTextSafe(text: []const u8) bool {
    if (text.len == 0 or text.len > tracelog.max_recorded_msg_len) return false;
    for (text) |byte| {
        if (byte < 0x20 or byte > 0x7e or byte == '"' or byte == '\\') return false;
    }
    return true;
}

fn isPrefixBoundary(byte: u8) bool {
    return switch (byte) {
        ' ', ':', '(', ';', ',' => true,
        else => false,
    };
}

pub const MessageVerdict = struct {
    match: ?Match,
    text: ?[]const u8,
};

/// Longest matching rule wins; exact matches beat prefix matches. Returned
/// text is always rule bytes. Unsafe caller rules never match.
pub fn classifyMessage(msg: []const u8, rules: []const MessageRule) MessageVerdict {
    var best: ?MessageRule = null;
    for (rules) |rule| {
        if (!ruleTextSafe(rule.text)) continue;
        const hit = switch (rule.match) {
            .exact => std.mem.eql(u8, msg, rule.text),
            .prefix => msg.len > rule.text.len and std.mem.startsWith(u8, msg, rule.text) and isPrefixBoundary(msg[rule.text.len]),
        };
        if (!hit) continue;
        if (rule.match == .exact) return .{ .match = .exact, .text = rule.text };
        if (best == null or rule.text.len > best.?.text.len) best = rule;
    }
    if (best) |rule| return .{ .match = .prefix, .text = rule.text };
    return .{ .match = null, .text = null };
}

pub fn keySafe(key: []const u8) bool {
    if (key.len == 0 or key.len > max_safe_key_len) return false;
    if (key[0] < 'a' or key[0] > 'z') return false;
    for (key) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '_' or byte == '.';
        if (!ok) return false;
    }
    return true;
}

/// Only meaningful for safe keys; unsafe keys are always treated as sensitive.
pub fn keySensitive(key: []const u8) bool {
    if (!keySafe(key)) return true;
    for (sensitive_key_fragments) |fragment| {
        if (std.mem.indexOf(u8, key, fragment) != null) return true;
    }
    return false;
}

fn errorNameSafe(name: []const u8) bool {
    if (name.len == 0 or name.len > max_error_name_len) return false;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    return true;
}

// ---------------------------------------------------------------------------
// Build

/// Build the bundle. `recorder` is a pointer exposing
/// `dump(out: []tracelog.RecordedEvent) []const tracelog.RecordedEvent` (newest
/// `out.len` events, oldest-to-newest), e.g. `*tracelog.FlightRecorder(N)`.
/// Reads only; a held diagnostics history lock is reported as `busy`, never
/// waited on. Returns `BundleTooLarge` (nothing allocated) if the computed
/// bound is ever exceeded.
pub fn build(
    allocator: std.mem.Allocator,
    recorder: anytype,
    diag: *diagnostics.Diagnostics,
    counters: Counters,
    options: Options,
) Error!Bundle {
    const max_events = @min(options.max_trace_events, max_trace_events_limit);
    const max_records = @min(options.max_connection_records, max_connection_records_limit);

    // One extra slot distinguishes "exactly N retained" from "more than N".
    const scratch = try allocator.alloc(tracelog.RecordedEvent, max_events + 1);
    defer allocator.free(scratch);
    const dumped = recorder.dump(scratch);
    const events_truncated = dumped.len > max_events;
    const events = if (events_truncated) dumped[dumped.len - max_events ..] else dumped;

    var history: [diagnostics.history_capacity]diagnostics.Record = undefined;
    var history_busy = false;
    const retained: []const diagnostics.Record = diag.snapshot(&history) catch |err| switch (err) {
        error.Busy => blk: {
            history_busy = true;
            break :blk history[0..0];
        },
    };
    const records_truncated = retained.len > max_records;
    const records = if (records_truncated) retained[retained.len - max_records ..] else retained;

    const capacity = maxBundleBytes(max_events, max_records);
    const storage = try allocator.alloc(u8, capacity);
    errdefer allocator.free(storage);

    var writer: std.Io.Writer = .fixed(storage);
    var redaction: RedactionStats = .{};
    writeDocument(&writer, .{
        .events = events,
        .events_truncated = events_truncated,
        .records = records,
        .records_retained = retained.len,
        .records_truncated = records_truncated,
        .history_busy = history_busy,
        .diag = diag,
        .counters = counters,
        .options = options,
        .max_events = max_events,
        .max_records = max_records,
    }, &redaction) catch return error.BundleTooLarge;

    const len = writer.end;
    // Fail closed: the document must be NOTICE-safe printable ASCII.
    for (storage[0..len]) |byte| if (byte < 0x20 or byte > 0x7e) return error.BundleTooLarge;
    return .{ .storage = storage, .len = len, .redaction = redaction };
}

const DocumentInput = struct {
    events: []const tracelog.RecordedEvent,
    events_truncated: bool,
    records: []const diagnostics.Record,
    records_retained: usize,
    records_truncated: bool,
    history_busy: bool,
    diag: *const diagnostics.Diagnostics,
    counters: Counters,
    options: Options,
    max_events: usize,
    max_records: usize,
};

const Stringify = std.json.Stringify;

fn field(jw: *Stringify, name: []const u8, value: anytype) Stringify.Error!void {
    try jw.objectField(name);
    try jw.write(value);
}

fn writeDocument(writer: *std.Io.Writer, in: DocumentInput, redaction: *RedactionStats) Stringify.Error!void {
    var jw: Stringify = .{ .writer = writer, .options = .{ .escape_unicode = true } };
    try jw.beginObject();
    try field(&jw, "schema_version", schema_version);
    try field(&jw, "kind", kind);
    try field(&jw, "wall_ms", in.options.wall_ms);

    try jw.objectField("build");
    try jw.beginObject();
    try field(&jw, "version", build_info.version);
    try field(&jw, "git_commit", gitCommit());
    try jw.endObject();

    try jw.objectField("capabilities");
    try jw.beginObject();
    try field(&jw, "source", "build-defined");
    try field(&jw, "session_policy_verified", false);
    try jw.objectField("entries");
    try jw.beginArray();
    for (live_cap_metadata.cap_specs) |spec| {
        try jw.beginObject();
        try field(&jw, "name", spec.name);
        try field(&jw, "policy_gated", spec.requires_policy);
        try jw.endObject();
    }
    try jw.endArray();
    try jw.endObject();

    try jw.objectField("counters");
    try jw.beginObject();
    try jw.objectField("connection_events");
    try jw.beginObject();
    inline for (@typeInfo(diagnostics.Event).@"enum".field_names) |name| {
        try field(&jw, name, in.diag.count(@field(diagnostics.Event, name)));
    }
    try jw.endObject();
    try field(&jw, "connection_sink_suppressed", in.diag.sink_suppressed.load(.monotonic));
    try field(&jw, "connection_history_dropped", in.diag.history_dropped.load(.monotonic));
    inline for (@typeInfo(sessions.TokenPublicationStats).@"struct".field_names) |name| {
        try field(&jw, "token_publication_" ++ name, @field(in.counters.token_publication, name));
    }
    try field(&jw, "media_fir_pli_ssrc_dropped", in.counters.media_fir_pli_ssrc_dropped);
    try field(&jw, "modules_degraded", in.counters.modules_degraded);
    try field(&jw, "modules_config_generation", in.counters.modules_config_generation);
    try field(&jw, "module_hook_unavailable", in.counters.module_hook_unavailable);
    try field(&jw, "module_hook_handler_errors", in.counters.module_hook_handler_errors);
    try jw.endObject();

    try jw.objectField("flight_recorder");
    try jw.beginObject();
    try field(&jw, "limit", in.max_events);
    try field(&jw, "emitted", in.events.len);
    try field(&jw, "truncated", in.events_truncated);
    try jw.objectField("events");
    try jw.beginArray();
    for (in.events) |*ev| try writeEvent(&jw, ev, in.options.message_rules, redaction);
    try jw.endArray();
    try jw.endObject();

    try jw.objectField("connection_history");
    try jw.beginObject();
    try field(&jw, "limit", in.max_records);
    try field(&jw, "retained", in.records_retained);
    try field(&jw, "emitted", in.records.len);
    try field(&jw, "truncated", in.records_truncated);
    try field(&jw, "busy", in.history_busy);
    try jw.objectField("records");
    try jw.beginArray();
    for (in.records) |record| try writeRecord(&jw, record);
    try jw.endArray();
    try jw.endObject();

    // Last, so the counts cover every emitted event.
    try jw.objectField("redaction");
    try jw.beginObject();
    try field(&jw, "policy", "allowlist");
    inline for (@typeInfo(RedactionStats).@"struct".field_names) |name| {
        try field(&jw, name, @field(redaction.*, name));
    }
    try jw.endObject();

    try jw.endObject();
}

fn writeEvent(jw: *Stringify, ev: *const tracelog.RecordedEvent, rules: []const MessageRule, redaction: *RedactionStats) Stringify.Error!void {
    try jw.beginObject();
    try field(jw, "level", ev.level.token());
    try field(jw, "category", ev.category.token());
    try field(jw, "category_id", @as(u8, @backingInt(ev.category)));
    try field(jw, "ts_mono_ns", ev.ts_mono_ns);
    try field(jw, "hlc", ev.hlc);
    const verdict = classifyMessage(ev.message(), rules);
    try field(jw, "msg", verdict.text);
    if (verdict.match) |m| {
        try field(jw, "msg_match", @tagName(m));
        switch (m) {
            .exact => redaction.messages_emitted_exact += 1,
            .prefix => redaction.messages_emitted_prefix += 1,
        }
    } else {
        try field(jw, "msg_match", "redacted");
        redaction.messages_redacted += 1;
    }
    try jw.objectField("fields");
    try jw.beginArray();
    for (ev.fields[0..@min(ev.field_count, tracelog.max_fields)]) |*recorded| {
        const key = recorded.key.slice();
        const safe_key = keySafe(key);
        if (!safe_key) redaction.keys_replaced += 1;
        const sensitive = keySensitive(key);
        try jw.beginArray();
        try jw.write(if (safe_key) key else unsafe_key_marker);
        switch (recorded.val) {
            .str => {
                try jw.write("str");
                try jw.write(null);
                redaction.string_fields_redacted += 1;
            },
            inline .uint, .int, .bool => |v, tag| {
                try jw.write(@tagName(tag));
                if (sensitive) {
                    try jw.write(null);
                    redaction.numeric_fields_redacted += 1;
                } else {
                    try jw.write(v);
                    redaction.numeric_fields_emitted += 1;
                }
            },
        }
        try jw.endArray();
    }
    try jw.endArray();
    try jw.endObject();
}

fn writeRecord(jw: *Stringify, record: diagnostics.Record) Stringify.Error!void {
    const c = record.connection;
    try jw.beginObject();
    try field(jw, "seq", record.sequence);
    try field(jw, "wall_ms", record.wall_ms);
    try field(jw, "mono_ms", record.monotonic_ms);
    try field(jw, "event", @tagName(record.event));
    try field(jw, "shard", c.id.shard);
    try field(jw, "slot", c.id.slot);
    try field(jw, "generation", c.id.generation);
    try field(jw, "fd", c.fd);
    try field(jw, "transport", @tagName(c.transport));
    try field(jw, "registered", c.registered);
    try field(jw, "ktls_rx", c.ktls_rx);
    try field(jw, "ktls_tx", c.ktls_tx);
    try field(jw, "queued", c.queued);
    try field(jw, "result", c.result);
    const error_name: []const u8 = if (c.failure) |err| blk: {
        const name = @errorName(err);
        break :blk if (errorNameSafe(name)) name else "other";
    } else "none";
    try field(jw, "error", error_name);
    try field(jw, "reason", @tagName(c.reason));
    try jw.endObject();
}

// ---------------------------------------------------------------------------
// NOTICE chunking

/// Deterministic split into parts of at most `max_part_bytes`. A cut never
/// leaves a part ending or the next part starting with a space (clients may
/// trim trailing whitespace), unless no other cut exists within the window.
pub const PartIterator = struct {
    data: []const u8,
    pos: usize = 0,
    index: usize = 0,
    total: usize,

    pub fn init(data: []const u8) PartIterator {
        var count: usize = 0;
        var pos: usize = 0;
        while (pos < data.len) : (count += 1) pos = cutAt(data, pos);
        return .{ .data = data, .total = count };
    }

    pub const Part = struct {
        index: usize,
        total: usize,
        payload: []const u8,
    };

    pub fn next(self: *PartIterator) ?Part {
        if (self.pos >= self.data.len) return null;
        const end = cutAt(self.data, self.pos);
        const part: Part = .{ .index = self.index, .total = self.total, .payload = self.data[self.pos..end] };
        self.pos = end;
        self.index += 1;
        return part;
    }

    fn cutAt(data: []const u8, start: usize) usize {
        const end = @min(start + max_part_bytes, data.len);
        if (end == data.len) return end;
        var cut = end;
        while (cut > start + 1 and (data[cut - 1] == ' ' or data[cut] == ' ')) cut -= 1;
        return if (data[cut - 1] != ' ' and data[cut] != ' ') cut else end;
    }
};

/// "DEBUG BUNDLE <i>/<n> <payload>", one-based index. Private: only parts
/// produced by `PartIterator` (payload <= `max_part_bytes`) reach it.
fn formatPart(out: *[max_part_line_bytes]u8, part: PartIterator.Part) []const u8 {
    std.debug.assert(part.payload.len <= max_part_bytes);
    return std.fmt.bufPrint(out, part_prefix ++ "{d}/{d} {s}", .{ part.index + 1, part.total, part.payload }) catch unreachable;
}

/// Trailer carrying the part count, byte count and SHA-256 of the document so
/// an operator can verify byte-exact reassembly.
fn formatTrailer(out: *[max_trailer_bytes]u8, bundle: *const Bundle) []const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bundle.bytes(), &digest, .{});
    const total = PartIterator.init(bundle.bytes()).total;
    return std.fmt.bufPrint(out, "End of DEBUG bundle parts={d} bytes={d} sha256={x}", .{ total, bundle.len, &digest }) catch unreachable;
}

// ---------------------------------------------------------------------------
// Oper egress

/// Live counters from a `LinuxServer`-shaped value (the same sources as
/// `refreshMetricsSnapshotFallible`). Read-only.
pub fn countersFrom(server: anytype) Counters {
    return .{
        .token_publication = server.sessions.tokenPublicationStatsSnapshot(),
        .media_fir_pli_ssrc_dropped = server.media_plane.fir_pli_ssrc_budget.dropped,
        .modules_degraded = server.module_runtime.degradedCount(),
        .modules_config_generation = server.module_runtime.generation(),
        .module_hook_unavailable = server.module_runtime.bus.totalUnavailable(),
        .module_hook_handler_errors = server.module_runtime.bus.totalHandlerErrors(),
    };
}

pub const unavailable_oom_notice = "DEBUG bundle unavailable: out of memory; retry";
pub const unavailable_bound_notice = "DEBUG bundle unavailable: size bound exceeded";

/// `DEBUG BUNDLE`: build one bundle and stream it to `conn` as NOTICE parts
/// followed by the verification trailer. The caller has already enforced the
/// oper privilege. Publication is all-or-nothing at build time: when the build
/// fails no bundle bytes are sent, only one fixed notice. `server` needs
/// `allocator`, `trace_recorder`, `diagnostics`, the `countersFrom` sources and
/// `noticeTo(conn, text) !void`. The bundle allocation is freed before return
/// on every path; a `noticeTo` error propagates after cleanup.
pub fn sendNotices(server: anytype, conn: anytype, options: Options) !void {
    var bundle = build(server.allocator, &server.trace_recorder, &server.diagnostics, countersFrom(server), options) catch |err| {
        try server.noticeTo(conn, switch (err) {
            error.OutOfMemory => unavailable_oom_notice,
            error.BundleTooLarge => unavailable_bound_notice,
        });
        return;
    };
    defer bundle.deinit(server.allocator);
    var line: [max_part_line_bytes]u8 = undefined;
    var it = bundle.parts();
    while (it.next()) |part| try server.noticeTo(conn, formatPart(&line, part));
    var trailer: [max_trailer_bytes]u8 = undefined;
    try server.noticeTo(conn, formatTrailer(&trailer, &bundle));
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const TestRecorder = tracelog.FlightRecorder(256);

fn testConnection(slot: u32) diagnostics.Connection {
    return .{
        .id = .{ .shard = 1, .slot = slot, .generation = 3 },
        .fd = 40 + @as(i64, slot),
        .transport = .tls,
        .registered = true,
        .ktls_rx = true,
        .ktls_tx = false,
        .queued = 9,
    };
}

fn emitTest(recorder: *TestRecorder, msg: []const u8, fields: []const tracelog.Field) !void {
    try recorder.write(.{ .level = .warn, .category = .s2s, .ts_mono_ns = 5, .hlc = 6, .msg = msg, .fields = fields });
}

fn parseBundle(bundle: *const Bundle) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, bundle.bytes(), .{});
}

test "diagnostic bundle: includes build version, advertised capability names, all event counters and token/media/module counters" {
    var recorder: TestRecorder = .{};
    try emitTest(&recorder, "client accepted", &.{});
    var diag: diagnostics.Diagnostics = .{};
    _ = diag.record(1, 2, .accepted, testConnection(1));
    _ = diag.record(1, 2, .accepted, testConnection(2));
    _ = diag.record(1, 2, .tls_error, testConnection(3));

    var bundle = try build(testing.allocator, &recorder, &diag, .{
        .token_publication = .{ .rotations_required = 4, .duplicate_publications_suppressed = 5 },
        .media_fir_pli_ssrc_dropped = 6,
        .modules_degraded = 7,
        .modules_config_generation = 8,
        .module_hook_unavailable = 9,
        .module_hook_handler_errors = 10,
    }, .{ .wall_ms = 1234 });
    defer bundle.deinit(testing.allocator);

    const parsed = try parseBundle(&bundle);
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqual(@as(i64, schema_version), root.get("schema_version").?.integer);
    try testing.expectEqualStrings(kind, root.get("kind").?.string);
    try testing.expectEqual(@as(i64, 1234), root.get("wall_ms").?.integer);
    try testing.expectEqualStrings(build_info.version, root.get("build").?.object.get("version").?.string);

    const caps = root.get("capabilities").?.object.get("entries").?.array.items;
    try testing.expectEqual(live_cap_metadata.cap_specs.len, caps.len);
    for (caps, live_cap_metadata.cap_specs) |entry, spec| {
        try testing.expectEqualStrings(spec.name, entry.object.get("name").?.string);
        try testing.expectEqual(spec.requires_policy, entry.object.get("policy_gated").?.bool);
    }

    const counters = root.get("counters").?.object;
    const events = counters.get("connection_events").?.object;
    try testing.expectEqual(diagnostics.event_count, events.count());
    inline for (@typeInfo(diagnostics.Event).@"enum".field_names) |name| {
        try testing.expectEqual(@as(i64, @intCast(diag.count(@field(diagnostics.Event, name)))), events.get(name).?.integer);
    }
    try testing.expectEqual(@as(i64, 2), events.get("accepted").?.integer);
    try testing.expectEqual(@as(i64, 1), events.get("tls_error").?.integer);
    try testing.expectEqual(@as(i64, 4), counters.get("token_publication_rotations_required").?.integer);
    try testing.expectEqual(@as(i64, 5), counters.get("token_publication_duplicate_publications_suppressed").?.integer);
    try testing.expectEqual(@as(i64, 6), counters.get("media_fir_pli_ssrc_dropped").?.integer);
    try testing.expectEqual(@as(i64, 7), counters.get("modules_degraded").?.integer);
    try testing.expectEqual(@as(i64, 8), counters.get("modules_config_generation").?.integer);
    try testing.expectEqual(@as(i64, 9), counters.get("module_hook_unavailable").?.integer);
    try testing.expectEqual(@as(i64, 10), counters.get("module_hook_handler_errors").?.integer);

    const fr = root.get("flight_recorder").?.object;
    try testing.expectEqual(@as(i64, 1), fr.get("emitted").?.integer);
    const ev = fr.get("events").?.array.items[0].object;
    try testing.expectEqualStrings("client accepted", ev.get("msg").?.string);
    try testing.expectEqualStrings("exact", ev.get("msg_match").?.string);
    try testing.expectEqualStrings("warn", ev.get("level").?.string);
    try testing.expectEqualStrings("s2s", ev.get("category").?.string);

    const hist = root.get("connection_history").?.object;
    try testing.expectEqual(@as(i64, 3), hist.get("emitted").?.integer);
    try testing.expect(!hist.get("busy").?.bool);
    const rec = hist.get("records").?.array.items[2].object;
    try testing.expectEqualStrings("tls_error", rec.get("event").?.string);
    try testing.expectEqual(@as(i64, 3), rec.get("slot").?.integer);
}

test "diagnostic bundle canary: nick, IPv4/IPv6 address, account, bearer token, password and cloak secret planted in flight-recorder msg and str fields never appear in output; uint/int/bool fields are preserved; redacted counts are correct" {
    const canaries = [_][]const u8{
        "zqnickcanary",
        "203.0.113.77",
        "2001:db8::beef:77",
        "acctcanary9",
        "sst_0123456789abcdef0123456789abcdef",
        "Bearer eyJcanary.payload.sig",
        "hunter2canary",
        "cloaksecretcanary",
    };
    var recorder: TestRecorder = .{};
    // Formatted messages carrying private data: one has a static prefix rule,
    // the others match nothing.
    try emitTest(&recorder, "mesh S2S established (secured) peer=zqnickcanary", &.{});
    try emitTest(&recorder, "quarantined remote ENTITY_PROP identity fact acctcanary9/identity.key from node 7", &.{});
    try emitTest(&recorder, "client zqnickcanary from 203.0.113.77 / 2001:db8::beef:77 joined", &.{});
    try emitTest(&recorder, "PASS hunter2canary Authorization: Bearer eyJcanary.payload.sig", &.{});
    // Near-miss: exact literal plus a suffix without a template boundary.
    try emitTest(&recorder, "client acceptedzqnickcanary", &.{});
    try emitTest(&recorder, "cloak secret=cloaksecretcanary", &.{
        .{ .key = "nick", .val = .{ .str = "zqnickcanary" } },
        .{ .key = "addr", .val = .{ .str = "203.0.113.77" } },
        .{ .key = "addr6", .val = .{ .str = "2001:db8::beef:77" } },
        .{ .key = "account", .val = .{ .str = "acctcanary9" } },
        .{ .key = "token", .val = .{ .str = "sst_0123456789abcdef0123456789abcdef" } },
        .{ .key = "count", .val = .{ .uint = 4242 } },
        .{ .key = "delta", .val = .{ .int = -17 } },
        .{ .key = "ok", .val = .{ .bool = true } },
    });
    try emitTest(&recorder, "secret=cloaksecretcanary password=hunter2canary", &.{
        .{ .key = "peer_ip", .val = .{ .uint = 0xCB00714D } },
        .{ .key = "ssrc", .val = .{ .uint = 77 } },
        .{ .key = "frames", .val = .{ .uint = 3 } },
    });
    var diag: diagnostics.Diagnostics = .{};
    var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{});
    defer bundle.deinit(testing.allocator);
    const out = bundle.bytes();

    for (canaries) |canary| try testing.expect(std.mem.indexOf(u8, out, canary) == null);
    try testing.expect(std.mem.indexOf(u8, out, "canary") == null);
    try testing.expect(std.mem.indexOf(u8, out, "203.0.113") == null);
    try testing.expect(std.mem.indexOf(u8, out, "2001:db8") == null);
    try testing.expect(std.mem.indexOf(u8, out, "eyJ") == null);

    const parsed = try parseBundle(&bundle);
    defer parsed.deinit();
    const events = parsed.value.object.get("flight_recorder").?.object.get("events").?.array.items;
    try testing.expectEqual(@as(usize, 7), events.len);
    try testing.expectEqualStrings("mesh S2S established", events[0].object.get("msg").?.string);
    try testing.expectEqualStrings("prefix", events[0].object.get("msg_match").?.string);
    try testing.expectEqualStrings("quarantined remote ENTITY_PROP identity fact", events[1].object.get("msg").?.string);
    for (events[2..]) |ev| {
        try testing.expect(ev.object.get("msg").? == .null);
        try testing.expectEqualStrings("redacted", ev.object.get("msg_match").?.string);
    }
    const f5 = events[5].object.get("fields").?.array.items;
    try testing.expectEqual(@as(usize, 8), f5.len);
    for (f5[0..5]) |f| {
        try testing.expectEqualStrings("str", f.array.items[1].string);
        try testing.expect(f.array.items[2] == .null);
    }
    try testing.expectEqualStrings("count", f5[5].array.items[0].string);
    try testing.expectEqual(@as(i64, 4242), f5[5].array.items[2].integer);
    try testing.expectEqual(@as(i64, -17), f5[6].array.items[2].integer);
    try testing.expect(f5[7].array.items[2].bool);
    const f6 = events[6].object.get("fields").?.array.items;
    try testing.expect(f6[0].array.items[2] == .null);
    try testing.expect(f6[1].array.items[2] == .null);
    try testing.expectEqual(@as(i64, 3), f6[2].array.items[2].integer);

    const r = bundle.redaction;
    try testing.expectEqual(@as(u64, 0), r.messages_emitted_exact);
    try testing.expectEqual(@as(u64, 2), r.messages_emitted_prefix);
    try testing.expectEqual(@as(u64, 5), r.messages_redacted);
    try testing.expectEqual(@as(u64, 5), r.string_fields_redacted);
    try testing.expectEqual(@as(u64, 2), r.numeric_fields_redacted);
    try testing.expectEqual(@as(u64, 4), r.numeric_fields_emitted);
    try testing.expectEqual(@as(u64, 0), r.keys_replaced);
    const red = parsed.value.object.get("redaction").?.object;
    try testing.expectEqualStrings("allowlist", red.get("policy").?.string);
    try testing.expectEqual(@as(i64, 5), red.get("messages_redacted").?.integer);
    try testing.expectEqual(@as(i64, 5), red.get("string_fields_redacted").?.integer);
    try testing.expectEqual(@as(i64, 2), red.get("numeric_fields_redacted").?.integer);
}

test "diagnostic bundle: unsafe field keys (spaces, uppercase, overlong, control bytes) are replaced and never echoed" {
    const full_key = "abcdefghijklmnopqrstuvwxyzabcdef"; // recorder capacity: maybe truncated
    comptime std.debug.assert(full_key.len == tracelog.max_recorded_key_len);
    var recorder: TestRecorder = .{};
    try emitTest(&recorder, "client accepted", &.{
        .{ .key = "has space", .val = .{ .uint = 1 } },
        .{ .key = "UpperKey", .val = .{ .uint = 2 } },
        .{ .key = full_key ++ "overflowtail", .val = .{ .uint = 3 } },
        .{ .key = "ctl\r\nPRIVMSG", .val = .{ .uint = 4 } },
        .{ .key = "", .val = .{ .uint = 5 } },
        .{ .key = "9lead", .val = .{ .uint = 6 } },
        .{ .key = "quo\"te", .val = .{ .bool = false } },
        .{ .key = "safe_name.v2", .val = .{ .uint = 8 } },
    });
    var diag: diagnostics.Diagnostics = .{};
    var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{});
    defer bundle.deinit(testing.allocator);
    const out = bundle.bytes();
    for ([_][]const u8{ "has space", "UpperKey", "abcdefghijklmnopqrstuvwxyz", "overflowtail", "ctl", "PRIVMSG", "9lead", "quo" }) |needle| {
        try testing.expect(std.mem.indexOf(u8, out, needle) == null);
    }
    try testing.expectEqual(@as(u64, 7), bundle.redaction.keys_replaced);
    // Unsafe keys are treated as sensitive: their numeric values are dropped too.
    try testing.expectEqual(@as(u64, 7), bundle.redaction.numeric_fields_redacted);
    try testing.expectEqual(@as(u64, 1), bundle.redaction.numeric_fields_emitted);

    const parsed = try parseBundle(&bundle);
    defer parsed.deinit();
    const fields = parsed.value.object.get("flight_recorder").?.object.get("events").?.array.items[0].object.get("fields").?.array.items;
    for (fields[0..7]) |f| {
        try testing.expectEqualStrings(unsafe_key_marker, f.array.items[0].string);
        try testing.expect(f.array.items[2] == .null);
    }
    try testing.expectEqualStrings("safe_name.v2", fields[7].array.items[0].string);
    try testing.expectEqual(@as(i64, 8), fields[7].array.items[2].integer);

    // Boundary: one byte under capacity is accepted verbatim.
    try testing.expect(keySafe(full_key[0..max_safe_key_len]));
    try testing.expect(!keySafe(full_key));
    // Unsafe caller-supplied rules never match (and thus are never echoed).
    const hostile = [_]MessageRule{ .{ .text = "a\"b" }, .{ .text = "x\ny" }, .{ .text = "" }, .{ .text = "", .match = .prefix } };
    try testing.expect(classifyMessage("a\"b", &hostile).match == null);
    try testing.expect(classifyMessage("x\ny", &hostile).match == null);
    try testing.expect(classifyMessage("", &hostile).match == null);
    try testing.expect(classifyMessage(" anything", &hostile).match == null);
}

test "diagnostic bundle: connection traces are bounded to N newest, report truncated, and report history_busy when the diagnostics history lock is held" {
    var recorder: TestRecorder = .{};
    for (0..10) |_| try emitTest(&recorder, "s2s peer accepted", &.{});
    try emitTest(&recorder, "tls client accepted", &.{});
    var diag: diagnostics.Diagnostics = .{};
    for (0..20) |i| _ = diag.record(@intCast(i), 0, .closed, testConnection(@intCast(i)));

    {
        var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{ .max_trace_events = 4, .max_connection_records = 5 });
        defer bundle.deinit(testing.allocator);
        const parsed = try parseBundle(&bundle);
        defer parsed.deinit();
        const fr = parsed.value.object.get("flight_recorder").?.object;
        try testing.expect(fr.get("truncated").?.bool);
        const events = fr.get("events").?.array.items;
        try testing.expectEqual(@as(usize, 4), events.len);
        try testing.expectEqualStrings("tls client accepted", events[3].object.get("msg").?.string);
        const hist = parsed.value.object.get("connection_history").?.object;
        try testing.expect(hist.get("truncated").?.bool);
        try testing.expect(!hist.get("busy").?.bool);
        try testing.expectEqual(@as(i64, 20), hist.get("retained").?.integer);
        const records = hist.get("records").?.array.items;
        try testing.expectEqual(@as(usize, 5), records.len);
        for (records, 15..) |rec, seq| try testing.expectEqual(@as(i64, @intCast(seq)), rec.object.get("seq").?.integer);
    }
    {
        // Exactly N retained is not truncated.
        var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{ .max_trace_events = 11, .max_connection_records = 20 });
        defer bundle.deinit(testing.allocator);
        const parsed = try parseBundle(&bundle);
        defer parsed.deinit();
        try testing.expect(!parsed.value.object.get("flight_recorder").?.object.get("truncated").?.bool);
        try testing.expect(!parsed.value.object.get("connection_history").?.object.get("truncated").?.bool);
    }
    {
        // Oversized options are clamped to the hard caps.
        var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{ .max_trace_events = std.math.maxInt(usize), .max_connection_records = std.math.maxInt(usize) });
        defer bundle.deinit(testing.allocator);
        const parsed = try parseBundle(&bundle);
        defer parsed.deinit();
        try testing.expectEqual(@as(i64, max_trace_events_limit), parsed.value.object.get("flight_recorder").?.object.get("limit").?.integer);
        try testing.expectEqual(@as(i64, max_connection_records_limit), parsed.value.object.get("connection_history").?.object.get("limit").?.integer);
    }
    {
        try testing.expect(diag.history_lock.tryLock());
        defer diag.history_lock.unlock();
        var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{});
        defer bundle.deinit(testing.allocator);
        const parsed = try parseBundle(&bundle);
        defer parsed.deinit();
        const hist = parsed.value.object.get("connection_history").?.object;
        try testing.expect(hist.get("busy").?.bool);
        try testing.expect(!hist.get("truncated").?.bool);
        try testing.expectEqual(@as(usize, 0), hist.get("records").?.array.items.len);
        // Counters are still reported while history is busy.
        try testing.expectEqual(@as(i64, 20), parsed.value.object.get("counters").?.object.get("connection_events").?.object.get("closed").?.integer);
    }
}

fn longestRule() MessageRule {
    var longest: MessageRule = .{ .text = "" };
    for (default_message_rules) |rule| {
        if (rule.text.len > longest.text.len) longest = rule;
    }
    return longest;
}

fn fillWorstCase(recorder: *TestRecorder, diag: *diagnostics.Diagnostics) !void {
    // Longest rule text plus maximal numeric fields with max-length keys.
    const longest = longestRule();
    var msg_buf: [tracelog.max_recorded_msg_len]u8 = undefined;
    const msg = switch (longest.match) {
        .exact => longest.text,
        .prefix => try std.fmt.bufPrint(&msg_buf, "{s} tail", .{longest.text}),
    };
    const key: []const u8 = &@as([max_safe_key_len]u8, @splat('k'));
    var fields: [tracelog.max_fields]tracelog.Field = undefined;
    for (&fields, 0..) |*f, i| f.* = .{ .key = key, .val = if (i % 2 == 0) .{ .uint = std.math.maxInt(u64) } else .{ .int = std.math.minInt(i64) } };
    for (0..512) |_| {
        try recorder.write(.{ .level = .notice, .category = @fromBackingInt(@intCast(255)), .ts_mono_ns = std.math.maxInt(u64), .hlc = std.math.maxInt(u64), .msg = msg, .fields = &fields });
    }
    var connection = testConnection(std.math.maxInt(u32));
    connection.id = .{ .shard = std.math.maxInt(u16), .slot = std.math.maxInt(u32), .generation = std.math.maxInt(u32) };
    connection.fd = std.math.minInt(i64);
    connection.queued = std.math.maxInt(u64);
    connection.result = std.math.minInt(i32);
    connection.failure = error.TlsKernelHandshakeConflictWithAVeryLongDiagnosticErrorNameForBound;
    connection.reason = .input_allocation_failure;
    connection.registered = false;
    for (0..300) |_| _ = diag.record(std.math.maxInt(u64), std.math.maxInt(u64), .tls_kernel_handshake_conflict, connection);
}

test "diagnostic bundle: output is valid JSON parsed by std.json and stays under the comptime max size with full 128/256 rings" {
    var recorder: TestRecorder = .{};
    var diag: diagnostics.Diagnostics = .{};
    try fillWorstCase(&recorder, &diag);
    // Each component stays within its own bound, not only the aggregate.
    var lens: [3]usize = undefined;
    inline for (.{ .{ 0, 0 }, .{ max_trace_events_limit, 0 }, .{ 0, max_connection_records_limit } }, 0..) |limits, i| {
        var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{ .wall_ms = std.math.maxInt(u64), .max_trace_events = limits[0], .max_connection_records = limits[1] });
        defer bundle.deinit(testing.allocator);
        lens[i] = bundle.len;
    }
    try testing.expect(lens[0] <= header_max);
    try testing.expect(lens[1] - lens[0] <= max_trace_events_limit * per_event_max);
    try testing.expect(lens[2] - lens[0] <= max_connection_records_limit * per_record_max);
    inline for (.{
        .{ default_max_trace_events, default_max_connection_records },
        .{ max_trace_events_limit, max_connection_records_limit },
        .{ 0, 0 },
    }) |limits| {
        var bundle = try build(testing.allocator, &recorder, &diag, .{
            .token_publication = .{ .rotations_required = std.math.maxInt(usize), .duplicate_publications_suppressed = std.math.maxInt(usize) },
            .media_fir_pli_ssrc_dropped = std.math.maxInt(u64),
            .modules_degraded = std.math.maxInt(u64),
            .modules_config_generation = std.math.maxInt(u64),
            .module_hook_unavailable = std.math.maxInt(u64),
            .module_hook_handler_errors = std.math.maxInt(u64),
        }, .{ .wall_ms = std.math.maxInt(u64), .max_trace_events = limits[0], .max_connection_records = limits[1] });
        defer bundle.deinit(testing.allocator);
        try testing.expect(bundle.len <= maxBundleBytes(limits[0], limits[1]));
        try testing.expect(bundle.len <= max_bundle_bytes);
        const parsed = try parseBundle(&bundle);
        defer parsed.deinit();
        const fr = parsed.value.object.get("flight_recorder").?.object;
        try testing.expectEqual(@as(usize, limits[0]), fr.get("events").?.array.items.len);
        try testing.expectEqual(limits[0] < max_trace_events_limit, fr.get("truncated").?.bool);
        const hist = parsed.value.object.get("connection_history").?.object;
        try testing.expectEqual(limits[1] < max_connection_records_limit, hist.get("truncated").?.bool);
        try testing.expectEqual(@as(usize, limits[1]), hist.get("records").?.array.items.len);
        try testing.expectEqual(@as(i64, diagnostics.history_capacity), hist.get("retained").?.integer);
        if (limits[0] != 0) {
            const ev = fr.get("events").?.array.items[0].object;
            try testing.expectEqualStrings(longestRule().text, ev.get("msg").?.string);
            try testing.expectEqualStrings("unknown", ev.get("category").?.string);
            try testing.expectEqual(@as(i64, 255), ev.get("category_id").?.integer);
        }
        if (limits[1] != 0) {
            // Overlong error names collapse to a fixed token.
            try testing.expectEqualStrings("other", hist.get("records").?.array.items[0].object.get("error").?.string);
        }
        for (bundle.bytes()) |byte| try testing.expect(byte >= 0x20 and byte <= 0x7e);
    }
}

test "diagnostic bundle: chunkLines produces NOTICE-safe parts under the max line length that reassemble byte-exact" {
    var recorder: TestRecorder = .{};
    var diag: diagnostics.Diagnostics = .{};
    try fillWorstCase(&recorder, &diag);
    // Space-dense messages exercise the no-edge-space cut rule.
    for (0..40) |_| try emitTest(&recorder, "trusted proxy accepted; waiting for PROXY header", &.{});
    var bundle = try build(testing.allocator, &recorder, &diag, .{}, .{ .max_trace_events = 64, .max_connection_records = 8 });
    defer bundle.deinit(testing.allocator);

    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    var it = bundle.parts();
    const total = it.total;
    try testing.expect(total > 1);
    var seen: usize = 0;
    var line: [max_part_line_bytes]u8 = undefined;
    while (it.next()) |part| : (seen += 1) {
        try testing.expectEqual(seen, part.index);
        try testing.expect(part.payload.len > 0 and part.payload.len <= max_part_bytes);
        try testing.expect(part.payload[0] != ' ' and part.payload[part.payload.len - 1] != ' ');
        const text = formatPart(&line, part);
        try testing.expect(text.len <= max_part_line_bytes);
        // 64-byte server name and nick still fit a 512-byte IRC line.
        try testing.expect(1 + 64 + " NOTICE ".len + 64 + " :".len + text.len + 2 <= 512);
        for (text) |byte| try testing.expect(byte >= 0x20 and byte <= 0x7e);
        var prefix_buf: [64]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, part_prefix ++ "{d}/{d} ", .{ seen + 1, total });
        try testing.expect(std.mem.startsWith(u8, text, prefix));
        try joined.appendSlice(testing.allocator, text[prefix.len..]);
    }
    try testing.expectEqual(total, seen);
    try testing.expectEqualSlices(u8, bundle.bytes(), joined.items);

    var trailer_buf: [max_trailer_bytes]u8 = undefined;
    const trailer = formatTrailer(&trailer_buf, &bundle);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(joined.items, &digest, .{});
    var hex_buf: [64]u8 = undefined;
    const hex = try std.fmt.bufPrint(&hex_buf, "{x}", .{&digest});
    try testing.expect(std.mem.endsWith(u8, trailer, hex));

    // Degenerate inputs: empty yields no parts; an all-space window still cuts.
    var empty = PartIterator.init("");
    try testing.expectEqual(@as(usize, 0), empty.total);
    try testing.expect(empty.next() == null);
    const spaces: []const u8 = &@as([max_part_bytes * 2 + 1]u8, @splat(' '));
    var sp = PartIterator.init(spaces);
    var sp_len: usize = 0;
    while (sp.next()) |part| sp_len += part.payload.len;
    try testing.expectEqual(spaces.len, sp_len);
}

fn buildAndFree(allocator: std.mem.Allocator, recorder: *TestRecorder, diag: *diagnostics.Diagnostics) !void {
    var bundle = try build(allocator, recorder, diag, .{}, .{ .max_trace_events = 8, .max_connection_records = 4 });
    bundle.deinit(allocator);
}

test "diagnostic bundle: allocation failure sweep (std.testing.checkAllAllocationFailures) leaks nothing" {
    var recorder: TestRecorder = .{};
    var diag: diagnostics.Diagnostics = .{};
    try emitTest(&recorder, "client accepted", &.{.{ .key = "count", .val = .{ .uint = 1 } }});
    for (0..6) |i| _ = diag.record(@intCast(i), 0, .accepted, testConnection(@intCast(i)));
    try testing.checkAllAllocationFailures(testing.allocator, buildAndFree, .{ &recorder, &diag });

    // Read-only: a failed build leaves daemon diagnostics untouched and a retry
    // after the failure succeeds with identical bytes.
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    const before_dropped = diag.history_dropped.load(.monotonic);
    try testing.expectError(error.OutOfMemory, build(failing.allocator(), &recorder, &diag, .{}, .{}));
    try testing.expectEqual(before_dropped, diag.history_dropped.load(.monotonic));
    try testing.expect(diag.history_lock.tryLock());
    diag.history_lock.unlock();
    var a = try build(testing.allocator, &recorder, &diag, .{}, .{});
    defer a.deinit(testing.allocator);
    var b = try build(testing.allocator, &recorder, &diag, .{}, .{});
    defer b.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, a.bytes(), b.bytes());
}

const FakeOperServer = struct {
    const Sessions = struct {
        stats: sessions.TokenPublicationStats,
        pub fn tokenPublicationStatsSnapshot(self: *const Sessions) sessions.TokenPublicationStats {
            return self.stats;
        }
    };
    const Bus = struct {
        pub fn totalUnavailable(_: *const Bus) u64 {
            return 31;
        }
        pub fn totalHandlerErrors(_: *const Bus) u64 {
            return 32;
        }
    };
    const ModuleRuntime = struct {
        bus: Bus = .{},
        pub fn degradedCount(_: *const ModuleRuntime) usize {
            return 33;
        }
        pub fn generation(_: *const ModuleRuntime) u64 {
            return 34;
        }
    };

    allocator: std.mem.Allocator,
    trace_recorder: TestRecorder = .{},
    diagnostics: diagnostics.Diagnostics = .{},
    sessions: Sessions = .{ .stats = .{ .rotations_required = 35, .duplicate_publications_suppressed = 36 } },
    media_plane: struct { fir_pli_ssrc_budget: struct { dropped: u64 = 37 } = .{} } = .{},
    module_runtime: ModuleRuntime = .{},
    notices: std.ArrayList([]u8) = .empty,
    /// Fail the notice with this index (0-based) with `error.WouldBlock`.
    fail_notice_at: ?usize = null,

    fn deinit(self: *FakeOperServer) void {
        for (self.notices.items) |n| testing.allocator.free(n);
        self.notices.deinit(testing.allocator);
    }

    pub fn noticeTo(self: *FakeOperServer, conn: u8, text: []const u8) !void {
        try testing.expectEqual(@as(u8, 7), conn);
        if (self.fail_notice_at) |at| if (self.notices.items.len == at) return error.WouldBlock;
        try self.notices.append(testing.allocator, try testing.allocator.dupe(u8, text));
    }
};

test "diagnostic bundle: DEBUG BUNDLE oper egress streams live counters as reassemblable parts with a verifying trailer and fails closed" {
    var server: FakeOperServer = .{ .allocator = testing.allocator };
    defer server.deinit();
    try emitTest(&server.trace_recorder, "s2s secured peer accepted", &.{});
    try emitTest(&server.trace_recorder, "client zqnickcanary from 203.0.113.77", &.{.{ .key = "nick", .val = .{ .str = "zqnickcanary" } }});
    _ = server.diagnostics.record(1, 1, .accepted, testConnection(1));

    try sendNotices(&server, @as(u8, 7), .{ .wall_ms = 99 });
    const notices = server.notices.items;
    try testing.expect(notices.len >= 2);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(testing.allocator);
    const total = notices.len - 1;
    for (notices[0..total], 1..) |n, i| {
        var prefix_buf: [64]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, part_prefix ++ "{d}/{d} ", .{ i, total });
        try testing.expect(std.mem.startsWith(u8, n, prefix));
        try testing.expect(n.len <= max_part_line_bytes);
        try joined.appendSlice(testing.allocator, n[prefix.len..]);
    }
    try testing.expect(std.mem.startsWith(u8, notices[total], "End of DEBUG bundle parts="));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(joined.items, &digest, .{});
    var hex_buf: [64]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, notices[total], try std.fmt.bufPrint(&hex_buf, "{x}", .{&digest})));
    for (notices) |n| {
        try testing.expect(std.mem.indexOf(u8, n, "canary") == null);
        try testing.expect(std.mem.indexOf(u8, n, "203.0.113") == null);
    }

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, joined.items, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqual(@as(i64, 99), root.get("wall_ms").?.integer);
    const counters = root.get("counters").?.object;
    try testing.expectEqual(@as(i64, 31), counters.get("module_hook_unavailable").?.integer);
    try testing.expectEqual(@as(i64, 32), counters.get("module_hook_handler_errors").?.integer);
    try testing.expectEqual(@as(i64, 33), counters.get("modules_degraded").?.integer);
    try testing.expectEqual(@as(i64, 34), counters.get("modules_config_generation").?.integer);
    try testing.expectEqual(@as(i64, 35), counters.get("token_publication_rotations_required").?.integer);
    try testing.expectEqual(@as(i64, 36), counters.get("token_publication_duplicate_publications_suppressed").?.integer);
    try testing.expectEqual(@as(i64, 37), counters.get("media_fir_pli_ssrc_dropped").?.integer);
    try testing.expectEqual(@as(i64, 1), counters.get("connection_events").?.object.get("accepted").?.integer);

    // Allocation failure: no bundle bytes are published, one fixed notice is,
    // and nothing leaks (the testing allocator checks on deinit).
    for (0..2) |fail_index| {
        var oom: FakeOperServer = .{ .allocator = undefined };
        defer oom.deinit();
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        oom.allocator = failing.allocator();
        try emitTest(&oom.trace_recorder, "client accepted", &.{});
        try sendNotices(&oom, @as(u8, 7), .{});
        try testing.expectEqual(@as(usize, 1), oom.notices.items.len);
        try testing.expectEqualStrings(unavailable_oom_notice, oom.notices.items[0]);
        try testing.expectEqual(failing.allocations, failing.deallocations);
    }

    // A transport error mid-stream propagates and still frees the bundle.
    var broken: FakeOperServer = .{ .allocator = testing.allocator, .fail_notice_at = 0 };
    defer broken.deinit();
    try testing.expectError(error.WouldBlock, sendNotices(&broken, @as(u8, 7), .{}));
    try testing.expectEqual(@as(usize, 0), broken.notices.items.len);
}
