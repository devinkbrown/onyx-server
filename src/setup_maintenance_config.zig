// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Maintenance configuration edits through the new-install wizard's typed
//! `workflow.Settings`. Pure: no file, process, environment or clock access.
//!
//! The live TOML is projected into `Settings` (plus the reloadable
//! `tls.dns_name`), every edit is validated by `Settings.set`, and a candidate
//! is produced by splicing only the edited value spans or inserting new key
//! lines. Every other source byte is preserved. A candidate is returned only
//! after it re-parses, projects to exactly the edited settings, differs from
//! the live document only at edited paths, and its inverse edits reproduce the
//! live bytes (SHA-256 checked). Anything the line scanner cannot prove it
//! understands fails closed. The daemon's own boot loader and Helix cut stay
//! the final authority; nothing here publishes a file.
const std = @import("std");
const workflow = @import("setup_workflow.zig");
const onyx = @import("onyx_server");
const toml = onyx.proto.toml;
const config_format = onyx.daemon.config_format;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Digest = [32]u8;

pub const Field = enum { hostname, listen_host, irc_port, media_port, node_id, tls_enabled, tls_port, max_clients, tls_dns_name };
pub const Section = enum { network, listen, node, tls, limits };
pub const FieldSet = std.EnumSet(Field);
const all_fields = std.enums.values(Field);
const all_sections = std.enums.values(Section);

pub fn sectionOf(field: Field) Section {
    return switch (field) {
        .hostname => .network,
        .listen_host, .irc_port, .media_port => .listen,
        .node_id => .node,
        .tls_enabled, .tls_port, .tls_dns_name => .tls,
        .max_clients => .limits,
    };
}

pub fn keyOf(field: Field) []const u8 {
    return switch (field) {
        .hostname => "server_name",
        .listen_host => "host",
        .irc_port => "irc",
        .media_port => "media",
        .node_id => "id",
        .tls_enabled => "enabled",
        .tls_port => "port",
        .max_clients => "max_clients",
        .tls_dns_name => "dns_name",
    };
}

/// Exact dotted schema path, as classified by `config_format.configFieldClass`.
pub fn pathOf(field: Field) []const u8 {
    return switch (field) {
        .hostname => "network.server_name",
        .listen_host => "listen.host",
        .irc_port => "listen.irc",
        .media_port => "listen.media",
        .node_id => "node.id",
        .tls_enabled => "tls.enabled",
        .tls_port => "tls.port",
        .max_clients => "limits.max_clients",
        .tls_dns_name => "tls.dns_name",
    };
}

fn sectionNamed(name: []const u8) ?Section {
    for (all_sections) |s| if (std.mem.eql(u8, name, @tagName(s))) return s;
    return null;
}

fn fieldNamed(s: Section, name: []const u8) ?Field {
    for (all_fields) |f| if (sectionOf(f) == s and std.mem.eql(u8, name, keyOf(f))) return f;
    return null;
}

/// Typed maintenance state: the shared wizard settings plus the one
/// maintenance-only reloadable key. Strings are borrowed (see `Plan`).
pub const State = struct {
    settings: workflow.Settings = .{},
    tls_dns_name: []const u8 = "localhost",

    pub fn eqlField(a: State, b: State, field: Field) bool {
        return switch (field) {
            .hostname => std.mem.eql(u8, a.settings.hostname, b.settings.hostname),
            .listen_host => std.mem.eql(u8, a.settings.listen_host, b.settings.listen_host),
            .irc_port => a.settings.irc_port == b.settings.irc_port,
            .media_port => a.settings.media_port == b.settings.media_port,
            .node_id => a.settings.node_id == b.settings.node_id,
            .tls_enabled => a.settings.tls_enabled == b.settings.tls_enabled,
            .tls_port => a.settings.tls_port == b.settings.tls_port,
            .max_clients => a.settings.max_clients == b.settings.max_clients,
            .tls_dns_name => std.mem.eql(u8, a.tls_dns_name, b.tls_dns_name),
        };
    }
};

/// Live TOML seen through the wizard model. Absent keys keep the wizard
/// defaults only so cross-field validation can run; they are never written
/// unless the operator sets them. Indirect (`env:`/`@file:`) or otherwise
/// unrepresentable string values keep a placeholder and refuse edits.
pub const Projection = struct {
    state: State = .{},
    present: FieldSet = .empty,
    indirect: FieldSet = .empty,
    unsupported: FieldSet = .empty,
};

fn isIndirect(raw: []const u8) bool {
    return std.mem.startsWith(u8, raw, "env:") or (raw.len != 0 and raw[0] == '@');
}

fn validListen(raw: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(raw, 1) catch return false;
    return true;
}

fn projectString(doc: *const toml.Document, field: Field, placeholder: []const u8, out: *Projection) ![]const u8 {
    const value = doc.get(pathOf(field)) orelse return placeholder;
    out.present.insert(field);
    if (value.* != .string) return error.LiveConfigType;
    const raw = value.string;
    if (isIndirect(raw)) {
        out.indirect.insert(field);
        return placeholder;
    }
    const valid = if (field == .listen_host) validListen(raw) else workflow.validHostname(raw);
    if (!valid) {
        out.unsupported.insert(field);
        return placeholder;
    }
    return raw;
}

fn projectInt(doc: *const toml.Document, field: Field, min: i64, max: i64, out: *Projection) !?i64 {
    const value = doc.get(pathOf(field)) orelse return null;
    out.present.insert(field);
    if (value.* != .integer) return error.LiveConfigType;
    if (value.integer < min or value.integer > max) return error.LiveConfigRange;
    return value.integer;
}

/// Strict projection of the live document. Wrong types or out-of-range
/// integers fail closed; the result must satisfy `Settings.validate`.
pub fn projectSettings(doc: *const toml.Document) !Projection {
    var out: Projection = .{};
    const defaults: workflow.Settings = .{};
    var s = &out.state.settings;
    s.hostname = try projectString(doc, .hostname, defaults.hostname, &out);
    s.listen_host = try projectString(doc, .listen_host, defaults.listen_host, &out);
    out.state.tls_dns_name = try projectString(doc, .tls_dns_name, "localhost", &out);
    if (try projectInt(doc, .irc_port, 0, 65535, &out)) |v| s.irc_port = @intCast(v);
    if (try projectInt(doc, .media_port, 0, 65535, &out)) |v| s.media_port = @intCast(v);
    if (try projectInt(doc, .tls_port, 0, 65535, &out)) |v| s.tls_port = @intCast(v);
    if (try projectInt(doc, .node_id, 1, std.math.maxInt(i64), &out)) |v| s.node_id = @intCast(v);
    if (try projectInt(doc, .max_clients, 1, 32767, &out)) |v| s.max_clients = @intCast(v);
    if (doc.get(pathOf(.tls_enabled))) |value| {
        out.present.insert(.tls_enabled);
        if (value.* != .boolean) return error.LiveConfigType;
        s.tls_enabled = value.boolean;
    }
    s.validate() catch return error.LiveConfigOutsideWizardModel;
    return out;
}

// ---- Source layout -------------------------------------------------------

pub const Refusal = error{ InlineTable, DottedKey, DuplicateKey, MultiLineValue, ArrayTable, NonScalarValue };
const Span = struct { start: usize, end: usize };
const Location = union(enum) { absent, present: Span, refused: Refusal };
const max_key_segments = 16;
const max_scan_nesting = 256;

const Layout = struct {
    fields: std.EnumArray(Field, Location) = .initFill(.absent),
    /// Insertion offset just after the unique `[section]` header line.
    headers: std.EnumArray(Section, ?usize) = .initFill(null),
    section_refusal: std.EnumArray(Section, ?Refusal) = .initFill(null),
    newline: []const u8 = "\n",

    fn refuseField(self: *Layout, field: Field, why: Refusal) void {
        self.fields.set(field, .{ .refused = why });
    }

    fn refusal(self: *const Layout, field: Field) ?Refusal {
        if (self.section_refusal.get(sectionOf(field))) |why| return why;
        return switch (self.fields.get(field)) {
            .refused => |why| why,
            else => null,
        };
    }
};

const ValueKind = enum { scalar, string, multi_line, array, inline_table };

/// Structural TOML line scanner. It never interprets values; it only finds
/// spans and refuses anything it cannot follow (escaped key names, unknown
/// trailing bytes). The parsed document is cross-checked afterwards.
const Scanner = struct {
    src: []const u8,
    i: usize = 0,

    fn at(self: *const Scanner, offset: usize) ?u8 {
        return if (self.i + offset < self.src.len) self.src[self.i + offset] else null;
    }

    fn skipBlank(self: *Scanner) void {
        while (self.at(0)) |c| {
            if (c != ' ' and c != '\t') break;
            self.i += 1;
        }
    }

    fn skipComment(self: *Scanner) void {
        while (self.at(0)) |c| {
            if (c == '\n') break;
            self.i += 1;
        }
    }

    fn finishLine(self: *Scanner) !void {
        self.skipBlank();
        if (self.at(0) == '#') self.skipComment();
        const c = self.at(0) orelse return;
        if (c == '\n') {
            self.i += 1;
        } else if (c == '\r' and self.at(1) == '\n') {
            self.i += 2;
        } else return error.UnsupportedSyntax;
    }

    fn simpleKey(self: *Scanner) ![]const u8 {
        const c = self.at(0) orelse return error.UnsupportedSyntax;
        if (c == '"' or c == '\'') {
            const start = self.i + 1;
            var j = start;
            while (j < self.src.len and self.src[j] != c) : (j += 1) {
                if (self.src[j] == '\n' or (c == '"' and self.src[j] == '\\')) return error.UnsupportedSyntax;
            }
            if (j >= self.src.len) return error.UnsupportedSyntax;
            self.i = j + 1;
            return self.src[start..j];
        }
        const start = self.i;
        while (self.at(0)) |b| {
            if (!std.ascii.isAlphanumeric(b) and b != '_' and b != '-') break;
            self.i += 1;
        }
        if (self.i == start) return error.UnsupportedSyntax;
        return self.src[start..self.i];
    }

    fn keyPath(self: *Scanner, out: *[max_key_segments][]const u8) !usize {
        var n: usize = 0;
        while (true) {
            self.skipBlank();
            if (n == out.len) return error.UnsupportedSyntax;
            out[n] = try self.simpleKey();
            n += 1;
            self.skipBlank();
            if (self.at(0) != '.') return n;
            self.i += 1;
        }
    }

    fn quoted(self: *Scanner, q: u8) !void {
        self.i += 1;
        while (self.at(0)) |c| {
            if (c == '\n') return error.UnsupportedSyntax;
            if (q == '"' and c == '\\') {
                self.i += 2;
                continue;
            }
            self.i += 1;
            if (c == q) return;
        }
        return error.UnsupportedSyntax;
    }

    fn multiLine(self: *Scanner, q: u8) !void {
        self.i += 3;
        while (self.i < self.src.len) {
            const c = self.src[self.i];
            if (q == '"' and c == '\\') {
                self.i += 2;
                continue;
            }
            if (c == q and self.at(1) == q and self.at(2) == q) {
                self.i += 3;
                // TOML permits one or two quotes adjacent to the delimiter.
                var extra: usize = 0;
                while (extra < 2 and self.at(0) == q) : (extra += 1) self.i += 1;
                return;
            }
            self.i += 1;
        }
        return error.UnsupportedSyntax;
    }

    fn string(self: *Scanner) !ValueKind {
        const q = self.src[self.i];
        if (self.at(1) == q and self.at(2) == q) {
            try self.multiLine(q);
            return .multi_line;
        }
        try self.quoted(q);
        return .string;
    }

    fn nested(self: *Scanner) !void {
        var depth: usize = 0;
        while (self.at(0)) |c| switch (c) {
            '[', '{' => {
                depth += 1;
                if (depth > max_scan_nesting) return error.UnsupportedSyntax;
                self.i += 1;
            },
            ']', '}' => {
                if (depth == 0) return error.UnsupportedSyntax;
                depth -= 1;
                self.i += 1;
                if (depth == 0) return;
            },
            '"', '\'' => _ = try self.string(),
            '#' => self.skipComment(),
            else => self.i += 1,
        };
        return error.UnsupportedSyntax;
    }

    fn scalarEnd(c: u8) bool {
        return c == ' ' or c == '\t' or c == '#' or c == '\n' or c == '\r' or c == ',' or c == ']' or c == '}';
    }

    fn value(self: *Scanner) !ValueKind {
        const c = self.at(0) orelse return error.UnsupportedSyntax;
        switch (c) {
            '"', '\'' => return self.string(),
            '[' => {
                try self.nested();
                return .array;
            },
            '{' => {
                try self.nested();
                return .inline_table;
            },
            else => {},
        }
        const start = self.i;
        while (self.at(0)) |b| {
            if (scalarEnd(b)) break;
            self.i += 1;
        }
        if (self.i == start) return error.UnsupportedSyntax;
        // RFC 3339 permits a space between a local date and its time.
        const v = self.src[start..self.i];
        if (v.len == 10 and v[4] == '-' and v[7] == '-' and self.at(0) == ' ' and self.at(1) != null and std.ascii.isDigit(self.at(1).?)) {
            self.i += 1;
            while (self.at(0)) |b| {
                if (scalarEnd(b)) break;
                self.i += 1;
            }
        }
        return .scalar;
    }
};

const Context = union(enum) { root, ours: Section, other };

fn scan(source: []const u8, doc: *const toml.Document) !Layout {
    var layout: Layout = .{};
    if (std.mem.indexOfScalar(u8, source, '\n')) |nl| {
        if (nl > 0 and source[nl - 1] == '\r') layout.newline = "\r\n";
    }
    var s: Scanner = .{ .src = source };
    var context: Context = .root;
    var segments: [max_key_segments][]const u8 = undefined;
    while (true) {
        s.skipBlank();
        const c = s.at(0) orelse break;
        if (c == '\n' or c == '#' or (c == '\r' and s.at(1) == '\n')) {
            try s.finishLine();
            continue;
        }
        if (c == '[') {
            const array = s.at(1) == '[';
            s.i += if (array) 2 else 1;
            const n = try s.keyPath(&segments);
            if (s.at(0) != ']' or (array and s.at(1) != ']')) return error.UnsupportedSyntax;
            s.i += if (array) 2 else 1;
            try s.finishLine();
            context = .other;
            if (n == 1) if (sectionNamed(segments[0])) |sec| {
                if (array) {
                    layout.section_refusal.set(sec, error.ArrayTable);
                } else if (layout.headers.get(sec) != null) {
                    layout.section_refusal.set(sec, error.DuplicateKey);
                } else {
                    layout.headers.set(sec, s.i);
                    context = .{ .ours = sec };
                }
            };
            continue;
        }
        const n = try s.keyPath(&segments);
        if (s.at(0) != '=') return error.UnsupportedSyntax;
        s.i += 1;
        s.skipBlank();
        const start = s.i;
        const kind = try s.value();
        const span: Span = .{ .start = start, .end = s.i };
        try s.finishLine();
        switch (context) {
            .root => if (sectionNamed(segments[0])) |sec| {
                layout.section_refusal.set(sec, if (n > 1) error.DottedKey else if (kind == .inline_table) error.InlineTable else error.NonScalarValue);
            },
            .ours => |sec| if (fieldNamed(sec, segments[0])) |field| {
                if (n > 1) {
                    layout.refuseField(field, error.DottedKey);
                } else if (layout.fields.get(field) != .absent) {
                    layout.refuseField(field, error.DuplicateKey);
                } else switch (kind) {
                    .scalar, .string => layout.fields.set(field, .{ .present = span }),
                    .multi_line => layout.refuseField(field, error.MultiLineValue),
                    .inline_table => layout.refuseField(field, error.InlineTable),
                    .array => layout.refuseField(field, error.NonScalarValue),
                }
            },
            .other => {},
        }
    }
    // The scanner and the real parser must agree on every modeled key.
    for (all_fields) |field| {
        if (layout.section_refusal.get(sectionOf(field)) != null) continue;
        const in_doc = doc.get(pathOf(field)) != null;
        const in_scan = layout.fields.get(field) != .absent;
        if (in_doc != in_scan) return error.UnsupportedSyntax;
    }
    return layout;
}

// ---- Preview classification --------------------------------------------

pub const Impact = enum {
    live_reload,
    client_disconnect,
    next_process_start,
    /// Outside every proven field list: never guessed reloadable or
    /// Helix-safe, so the preview states the worst case.
    unproven,

    pub fn text(self: Impact) []const u8 {
        return switch (self) {
            .live_reload => "applied live by REHASH; no client disconnect",
            .client_disconnect => "Helix refuses this change; applying it needs a cold restart that disconnects every attached client",
            .next_process_start => "read only at process start; takes effect only in a new process, and the daemon's final guard may refuse it",
            .unproven => "not proven reloadable or Helix-safe; treat as restart_required: a cold restart may disconnect every attached client",
        };
    }
};

fn proven(path: []const u8) bool {
    for (config_format.classified_config_fields) |name| if (std.mem.eql(u8, path, name)) return true;
    return false;
}

/// Impact of changing `path`. `configFieldClass` maps unlisted fields to
/// `startup_only`; only a listed field may claim that narrower impact.
pub fn impactOf(path: []const u8) Impact {
    return switch (config_format.configFieldClass(path)) {
        .reloadable => .live_reload,
        .restart_required => .client_disconnect,
        .startup_only => if (proven(path)) .next_process_start else .unproven,
    };
}

pub const Change = struct {
    field: Field,
    class: config_format.ConfigFieldClass,
    impact: Impact,
    /// Rendered TOML value; null when absent; "(not shown)" when indirect or
    /// unrepresentable in the wizard model.
    before: ?[]const u8,
    after: []const u8,
};

pub const RollbackStep = struct {
    /// Candidate-coordinate offset of the bytes this step removes.
    offset: usize,
    remove_len: usize,
    restore: []const u8,
};

/// Owns every byte through one arena. Nothing in it is partially built: a
/// value exists only after verification and the rollback self-check passed.
pub const Candidate = struct {
    arena: std.heap.ArenaAllocator,
    bytes: []const u8,
    original_sha256: Digest,
    sha256: Digest,
    changes: []const Change,
    rollback_steps: []const RollbackStep,

    pub fn deinit(self: *Candidate) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Apply the inverse edits to exactly this candidate's bytes. Foreign or
    /// modified input is refused; the output digest must equal the live one.
    pub fn rollback(self: *const Candidate, allocator: Allocator, current: []const u8) ![]u8 {
        return applyRollback(allocator, current, self.sha256, self.original_sha256, self.rollback_steps);
    }
};

fn applyRollback(allocator: Allocator, current: []const u8, expected_current: Digest, expected_original: Digest, steps: []const RollbackStep) ![]u8 {
    if (!std.mem.eql(u8, &digest(current), &expected_current)) return error.CandidateMismatch;
    var size: usize = current.len;
    var cursor: usize = 0;
    for (steps) |step| {
        if (step.offset < cursor or step.remove_len > current.len - step.offset) return error.CandidateMismatch;
        cursor = step.offset + step.remove_len;
        size = size - step.remove_len + step.restore.len;
    }
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    var w: usize = 0;
    cursor = 0;
    for (steps) |step| {
        @memcpy(out[w..][0 .. step.offset - cursor], current[cursor..step.offset]);
        w += step.offset - cursor;
        @memcpy(out[w..][0..step.restore.len], step.restore);
        w += step.restore.len;
        cursor = step.offset + step.remove_len;
    }
    @memcpy(out[w..], current[cursor..]);
    if (!std.mem.eql(u8, &digest(out), &expected_original)) return error.RollbackMismatch;
    return out;
}

pub fn digest(bytes: []const u8) Digest {
    var out: Digest = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

const Splice = struct { offset: usize, old_len: usize, new: []const u8 };

// ---- Plan ----------------------------------------------------------------

const string_fields = [_]Field{ .hostname, .listen_host, .tls_dns_name };

/// One maintenance edit session against one exact live source. Owns a copy
/// of the source and its parsed document; edited strings are owned copies.
/// Callers holding inline secrets should pass a wiping allocator.
pub const Plan = struct {
    allocator: Allocator,
    source: []u8,
    doc: toml.Document,
    original: Projection,
    layout: Layout,
    original_sha256: Digest,
    current: State,
    touched: FieldSet = .empty,
    owned: std.EnumArray(Field, ?[]u8) = .initFill(null),

    pub fn init(allocator: Allocator, source: []const u8) !Plan {
        if (source.len == 0 or source.len > config_format.max_config_bytes) return error.InvalidConfigSize;
        const copy = try allocator.dupe(u8, source);
        errdefer {
            std.crypto.secureZero(u8, copy);
            allocator.free(copy);
        }
        var doc = try toml.parse(allocator, copy);
        errdefer doc.deinit(allocator);
        const projection = try projectSettings(&doc);
        const layout = try scan(copy, &doc);
        return .{ .allocator = allocator, .source = copy, .doc = doc, .original = projection, .layout = layout, .original_sha256 = digest(copy), .current = projection.state };
    }

    pub fn deinit(self: *Plan) void {
        self.freeOwned();
        self.doc.deinit(self.allocator);
        std.crypto.secureZero(u8, self.source);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    fn freeOwned(self: *Plan) void {
        for (string_fields) |f| if (self.owned.get(f)) |bytes| {
            self.allocator.free(bytes);
            self.owned.set(f, null);
        };
    }

    /// Drop every pending edit; the live projection becomes current again.
    pub fn discard(self: *Plan) void {
        self.freeOwned();
        self.current = self.original.state;
        self.touched = .empty;
    }

    pub fn changed(self: *const Plan) FieldSet {
        var out: FieldSet = .empty;
        for (all_fields) |f| {
            if (!self.current.eqlField(self.original.state, f) or (self.touched.contains(f) and !self.original.present.contains(f))) out.insert(f);
        }
        return out;
    }

    pub fn pending(self: *const Plan) bool {
        return self.changed().count() != 0;
    }

    fn editable(self: *const Plan, field: Field) !void {
        if (field == .node_id) return error.ImmutableInMaintenance;
        if (self.original.indirect.contains(field)) return error.IndirectValue;
        if (self.original.unsupported.contains(field)) return error.UnsupportedLiveValue;
        if (self.layout.refusal(field)) |why| return why;
    }

    /// Same keys and validation as the new-install wizard (`Settings.set`),
    /// plus `dns-name`. Node identity and bootstrap-account choices are not
    /// maintenance edits. A refused edit leaves every prior choice intact.
    pub fn edit(self: *Plan, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "node-id") or std.mem.eql(u8, key, "account") or std.mem.eql(u8, key, "privileges")) return error.ImmutableInMaintenance;
        const target: Field = if (std.mem.eql(u8, key, "hostname")) .hostname else if (std.mem.eql(u8, key, "listen")) .listen_host else if (std.mem.eql(u8, key, "irc-port")) .irc_port else if (std.mem.eql(u8, key, "media-port")) .media_port else if (std.mem.eql(u8, key, "tls")) .tls_enabled else if (std.mem.eql(u8, key, "tls-port")) .tls_port else if (std.mem.eql(u8, key, "max-clients")) .max_clients else if (std.mem.eql(u8, key, "dns-name")) .tls_dns_name else return error.UnknownSetting;
        const is_string = target == .hostname or target == .listen_host or target == .tls_dns_name;
        var owned: ?[]u8 = if (is_string) try self.allocator.dupe(u8, value) else null;
        errdefer if (owned) |bytes| self.allocator.free(bytes);
        const text = owned orelse value;
        var next = self.current;
        if (target == .tls_dns_name) {
            if (!workflow.validHostname(text)) return error.InvalidHostname;
            next.tls_dns_name = text;
            try next.settings.validate();
        } else try next.settings.set(key, text);
        var touched = self.touched;
        touched.insert(target);
        for (all_fields) |f| {
            if (f == target or !next.eqlField(self.current, f)) {
                try self.editable(f);
                touched.insert(f);
            }
        }
        if (owned) |bytes| {
            if (self.owned.get(target)) |old| self.allocator.free(old);
            self.owned.set(target, bytes);
            owned = null;
        }
        self.current = next;
        self.touched = touched;
    }

    fn render(a: Allocator, state: State, field: Field) ![]const u8 {
        const s = state.settings;
        return switch (field) {
            .hostname => std.json.Stringify.valueAlloc(a, s.hostname, .{}),
            .listen_host => std.json.Stringify.valueAlloc(a, s.listen_host, .{}),
            .tls_dns_name => std.json.Stringify.valueAlloc(a, state.tls_dns_name, .{}),
            .irc_port => std.fmt.allocPrint(a, "{d}", .{s.irc_port}),
            .media_port => std.fmt.allocPrint(a, "{d}", .{s.media_port}),
            .tls_port => std.fmt.allocPrint(a, "{d}", .{s.tls_port}),
            .node_id => std.fmt.allocPrint(a, "{d}", .{s.node_id}),
            .max_clients => if (s.max_clients) |v| std.fmt.allocPrint(a, "{d}", .{v}) else error.InvalidSettings,
            .tls_enabled => a.dupe(u8, if (s.tls_enabled) "true" else "false"),
        };
    }

    /// Build, verify and self-roll-back a candidate. Allocation failure or any
    /// verification failure returns an error with no candidate and no change
    /// to the plan.
    pub fn candidate(self: *const Plan, allocator: Allocator) !Candidate {
        const changes_set = self.changed();
        if (changes_set.count() == 0) return error.NoConfigChanges;
        var arena: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const src = self.source;
        const nl = self.layout.newline;

        var splices: [all_fields.len + all_sections.len + 1]Splice = undefined;
        var count: usize = 0;
        var changes: std.ArrayList(Change) = .empty;
        var eof_head: std.Io.Writer.Allocating = .init(a);
        var eof_tail: std.Io.Writer.Allocating = .init(a);
        for (all_sections) |sec| {
            var lines: std.Io.Writer.Allocating = .init(a);
            for (all_fields) |f| {
                if (sectionOf(f) != sec or !changes_set.contains(f)) continue;
                try self.editable(f);
                const after = try render(a, self.current, f);
                const before: ?[]const u8 = if (!self.original.present.contains(f)) null else if (self.original.indirect.contains(f) or self.original.unsupported.contains(f)) "(not shown)" else try render(a, self.original.state, f);
                const class = config_format.configFieldClass(pathOf(f));
                try changes.append(a, .{ .field = f, .class = class, .impact = impactOf(pathOf(f)), .before = before, .after = after });
                switch (self.layout.fields.get(f)) {
                    .present => |span| {
                        splices[count] = .{ .offset = span.start, .old_len = span.end - span.start, .new = after };
                        count += 1;
                    },
                    .absent => lines.writer.print("{s} = {s}{s}", .{ keyOf(f), after, nl }) catch return error.OutOfMemory,
                    .refused => |why| return why,
                }
            }
            const body = lines.written();
            if (body.len == 0) continue;
            if (self.layout.headers.get(sec)) |offset| {
                if (offset == src.len) {
                    eof_head.writer.writeAll(body) catch return error.OutOfMemory;
                } else {
                    splices[count] = .{ .offset = offset, .old_len = 0, .new = body };
                    count += 1;
                }
            } else eof_tail.writer.print("[{s}]{s}{s}", .{ @tagName(sec), nl, body }) catch return error.OutOfMemory;
        }
        if (eof_head.written().len + eof_tail.written().len != 0) {
            const prefix = if (src.len != 0 and src[src.len - 1] != '\n') nl else "";
            splices[count] = .{ .offset = src.len, .old_len = 0, .new = try std.mem.concat(a, u8, &.{ prefix, eof_head.written(), eof_tail.written() }) };
            count += 1;
        }
        const used = splices[0..count];
        std.mem.sort(Splice, used, {}, struct {
            fn lessThan(_: void, x: Splice, y: Splice) bool {
                return x.offset < y.offset;
            }
        }.lessThan);
        var size: usize = src.len;
        for (used, 0..) |sp, idx| {
            if (idx + 1 < used.len and sp.offset + sp.old_len > used[idx + 1].offset) return error.UnsupportedSyntax;
            size = size - sp.old_len + sp.new.len;
        }
        if (size > config_format.max_config_bytes) return error.InvalidConfigSize;
        const bytes = try a.alloc(u8, size);
        const steps = try a.alloc(RollbackStep, count);
        var w: usize = 0;
        var cursor: usize = 0;
        for (used, steps) |sp, *step| {
            @memcpy(bytes[w..][0 .. sp.offset - cursor], src[cursor..sp.offset]);
            w += sp.offset - cursor;
            step.* = .{ .offset = w, .remove_len = sp.new.len, .restore = try a.dupe(u8, src[sp.offset..][0..sp.old_len]) };
            @memcpy(bytes[w..][0..sp.new.len], sp.new);
            w += sp.new.len;
            cursor = sp.offset + sp.old_len;
        }
        @memcpy(bytes[w..], src[cursor..]);
        try self.verify(a, bytes);
        const candidate_sha = digest(bytes);
        // Self-check: the published inverse must reproduce the live bytes.
        const restored = try applyRollback(a, bytes, candidate_sha, self.original_sha256, steps);
        if (!std.mem.eql(u8, restored, src)) return error.RollbackMismatch;
        return .{ .arena = arena, .bytes = bytes, .original_sha256 = self.original_sha256, .sha256 = candidate_sha, .changes = try changes.toOwnedSlice(a), .rollback_steps = steps };
    }

    /// Re-parse `bytes` and require: projection equals the current edited
    /// settings on edited fields; every other modeled field keeps its live
    /// value, presence and opacity; and the whole document is unchanged
    /// outside edited paths.
    pub fn verify(self: *const Plan, allocator: Allocator, bytes: []const u8) !void {
        var doc = try toml.parse(allocator, bytes);
        defer doc.deinit(allocator);
        const projected = projectSettings(&doc) catch return error.CandidateMismatch;
        const edited = self.changed();
        for (all_fields) |f| {
            if (edited.contains(f)) {
                if (!projected.present.contains(f) or projected.indirect.contains(f) or projected.unsupported.contains(f) or !projected.state.eqlField(self.current, f)) return error.CandidateMismatch;
            } else if (projected.present.contains(f) != self.original.present.contains(f) or
                projected.indirect.contains(f) != self.original.indirect.contains(f) or
                projected.unsupported.contains(f) != self.original.unsupported.contains(f) or
                !projected.state.eqlField(self.original.state, f)) return error.UnexpectedChange;
        }
        try compareNode(&self.doc.root, &doc.root, 0, .root, edited);
    }
};

const max_compare_depth = 64;
const Scope = union(enum) { root, section: Section, other };

fn compareNode(a: ?*const toml.Value, b: ?*const toml.Value, depth: usize, scope: Scope, edited: FieldSet) error{ UnexpectedChange, CandidateTooDeep }!void {
    if (depth > max_compare_depth) return error.CandidateTooDeep;
    const a_table = if (a) |v| v.* == .table else true;
    const b_table = if (b) |v| v.* == .table else true;
    if (a == null and b == null) return;
    if (!a_table or !b_table) {
        if (a == null or b == null or !valueEql(a.?, b.?, 0)) return error.UnexpectedChange;
        return;
    }
    if (a) |table| {
        var it = table.table.iterator();
        while (it.next()) |entry| {
            const child = childScope(scope, entry.key_ptr.*, edited) orelse continue;
            const other = if (b) |t| t.table.getPtr(entry.key_ptr.*) else null;
            try compareNode(entry.value_ptr, other, depth + 1, child, edited);
        }
    }
    if (b) |table| {
        var it = table.table.iterator();
        while (it.next()) |entry| {
            if (a) |t| if (t.table.contains(entry.key_ptr.*)) continue;
            const child = childScope(scope, entry.key_ptr.*, edited) orelse continue;
            try compareNode(null, entry.value_ptr, depth + 1, child, edited);
        }
    }
}

/// Null means the key is an edited modeled field and is checked by projection.
fn childScope(scope: Scope, name: []const u8, edited: FieldSet) ?Scope {
    return switch (scope) {
        .root => if (sectionNamed(name)) |sec| .{ .section = sec } else .other,
        .section => |sec| if (fieldNamed(sec, name)) |f| (if (edited.contains(f)) null else .other) else .other,
        .other => .other,
    };
}

fn valueEql(a: *const toml.Value, b: *const toml.Value, depth: usize) bool {
    if (depth > max_compare_depth or std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
    return switch (a.*) {
        .string => |s| std.mem.eql(u8, s, b.string),
        .integer => |n| n == b.integer,
        .float => |f| @as(u64, @bitCast(f)) == @as(u64, @bitCast(b.float)),
        .boolean => |v| v == b.boolean,
        .array => |items| items.len == b.array.len and for (items, b.array) |*x, *y| {
            if (!valueEql(x, y, depth + 1)) break false;
        } else true,
        .table => |*map| blk: {
            if (map.count() != b.table.count()) break :blk false;
            var it = map.iterator();
            while (it.next()) |entry| {
                const other = b.table.getPtr(entry.key_ptr.*) orelse break :blk false;
                if (!valueEql(entry.value_ptr, other, depth + 1)) break :blk false;
            }
            break :blk true;
        },
    };
}

/// Plain text for the wizard; values are validated hostnames, addresses and
/// integers. Indirect references are never shown. Callers wrap and escape.
pub fn renderPreview(allocator: Allocator, c: *const Candidate) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const w = &out.writer;
    w.writeAll("Configuration preview (nothing written; daemon --check-config and the Helix cut stay authoritative):\n") catch return error.OutOfMemory;
    for (c.changes) |change| {
        w.print("- {s}: {s} -> {s}; {s}; {s}\n", .{ pathOf(change.field), change.before orelse "absent (daemon default)", change.after, @tagName(change.class), change.impact.text() }) catch return error.OutOfMemory;
    }
    w.print("Live sha256 {s}; candidate sha256 {s}.\n", .{ std.fmt.bytesToHex(c.original_sha256, .lower), std.fmt.bytesToHex(c.sha256, .lower) }) catch return error.OutOfMemory;
    w.print("Rollback: {d} inverse edit(s) restore the live bytes exactly (verified sha256 {s}); every other byte is unchanged.\n", .{ c.rollback_steps.len, std.fmt.bytesToHex(c.original_sha256, .lower) }) catch return error.OutOfMemory;
    for (c.rollback_steps) |step| {
        w.print("  at candidate byte {d}: replace {d} byte(s) with {d} live byte(s)\n", .{ step.offset, step.remove_len, step.restore.len }) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice();
}

// ---- Tests -----------------------------------------------------------------

const testing = std.testing;

const live_fixture =
    \\# operator comment kept verbatim
    \\[node]
    \\id = 42 # stable identity
    \\[network]
    \\name = "Onyx"
    \\server_name = "irc.example.test"
    \\[listen]
    \\host   =   "127.0.0.1"   # spacing kept
    \\irc = 6680
    \\[tls]
    \\enabled = true
    \\port = 6697
    \\cert_path = "/etc/onyx/cert.der"
    \\[limits]
    \\nick_delay = 5
    \\[cloak]
    \\secret = "@file:/etc/onyx/cloak.secret"
    \\
;

test "maintenance config projection maps live TOML into workflow.Settings and records absent keys" {
    var doc = try toml.parse(testing.allocator, live_fixture);
    defer doc.deinit(testing.allocator);
    const p = try projectSettings(&doc);
    try testing.expectEqualStrings("irc.example.test", p.state.settings.hostname);
    try testing.expectEqualStrings("127.0.0.1", p.state.settings.listen_host);
    try testing.expectEqual(@as(u16, 6680), p.state.settings.irc_port);
    try testing.expectEqual(@as(u64, 42), p.state.settings.node_id);
    try testing.expect(p.state.settings.tls_enabled);
    try testing.expectEqual(@as(u16, 6697), p.state.settings.tls_port);
    for ([_]Field{ .hostname, .listen_host, .irc_port, .node_id, .tls_enabled, .tls_port }) |f| try testing.expect(p.present.contains(f));
    for ([_]Field{ .media_port, .max_clients, .tls_dns_name }) |f| try testing.expect(!p.present.contains(f));
    try testing.expectEqual(@as(?u31, null), p.state.settings.max_clients);
    try testing.expectEqual(@as(usize, 0), p.indirect.count());

    // Wrong types and out-of-range values fail closed rather than coerce.
    for ([_][]const u8{ "[listen]\nirc = \"6680\"\n", "[listen]\nirc = 70000\n", "[tls]\nenabled = 1\n[listen]\nirc = 1\n", "[limits]\nmax_clients = 0\n[listen]\nirc = 1\n" }) |text| {
        var bad = try toml.parse(testing.allocator, text);
        defer bad.deinit(testing.allocator);
        if (projectSettings(&bad)) |_| return error.TestExpectedError else |err| try testing.expect(err == error.LiveConfigType or err == error.LiveConfigRange);
    }
    // A live config outside the wizard model (no IRC listener) refuses edits.
    var outside = try toml.parse(testing.allocator, "[listen]\nirc = 0\n");
    defer outside.deinit(testing.allocator);
    try testing.expectError(error.LiveConfigOutsideWizardModel, projectSettings(&outside));
}

test "maintenance config edit reuses Settings.set validation and refuses node-id/account/privileges as ImmutableInMaintenance" {
    var plan = try Plan.init(testing.allocator, live_fixture);
    defer plan.deinit();
    for ([_][]const u8{ "node-id", "account", "privileges" }) |key| try testing.expectError(error.ImmutableInMaintenance, plan.edit(key, "7"));
    // Settings.set cross-field validation: the TLS port may not equal IRC.
    try testing.expectError(error.InvalidTlsPort, plan.edit("tls-port", "6680"));
    try testing.expectError(error.InvalidHostname, plan.edit("hostname", "bad host"));
    try testing.expectError(error.InvalidHostname, plan.edit("dns-name", "@file:/etc/x"));
    try testing.expectError(error.InvalidListenAddress, plan.edit("listen", "env:LISTEN"));
    try testing.expectError(error.UnknownSetting, plan.edit("cloak.secret", "x"));
    try testing.expectError(error.InvalidCharacter, plan.edit("irc-port", "x"));
    try testing.expect(!plan.pending());
    try plan.edit("irc-port", "7000");
    try testing.expectError(error.InvalidTlsPort, plan.edit("tls-port", "7000"));
    try testing.expectEqual(@as(u16, 7000), plan.current.settings.irc_port);
    try testing.expectEqual(@as(u16, 6697), plan.current.settings.tls_port);
    try plan.edit("hostname", "irc2.example.test");
    try plan.edit("hostname", "irc3.example.test");
    try testing.expectEqualStrings("irc3.example.test", plan.current.settings.hostname);
    try plan.edit("irc-port", "6680");
    var expected: FieldSet = .empty;
    expected.insert(.hostname);
    try testing.expect(plan.changed().eql(expected));
    plan.discard();
    try testing.expect(!plan.pending());
}

test "maintenance config patch preserves every unrelated byte and re-parse projection equals edited settings" {
    var plan = try Plan.init(testing.allocator, live_fixture);
    defer plan.deinit();
    try plan.edit("irc-port", "7000");
    try plan.edit("listen", "::1");
    try plan.edit("media-port", "5000");
    try plan.edit("dns-name", "irc.example.test");
    try plan.edit("max-clients", "512");
    var c = try plan.candidate(testing.allocator);
    defer c.deinit();
    // `[limits]` exists, so max_clients lands under it rather than a new header.
    const want =
        \\# operator comment kept verbatim
        \\[node]
        \\id = 42 # stable identity
        \\[network]
        \\name = "Onyx"
        \\server_name = "irc.example.test"
        \\[listen]
        \\media = 5000
        \\host   =   "::1"   # spacing kept
        \\irc = 7000
        \\[tls]
        \\dns_name = "irc.example.test"
        \\enabled = true
        \\port = 6697
        \\cert_path = "/etc/onyx/cert.der"
        \\[limits]
        \\max_clients = 512
        \\nick_delay = 5
        \\[cloak]
        \\secret = "@file:/etc/onyx/cloak.secret"
        \\
    ;
    try testing.expectEqualStrings(want, c.bytes);
    var doc = try toml.parse(testing.allocator, c.bytes);
    defer doc.deinit(testing.allocator);
    const p = try projectSettings(&doc);
    for (all_fields) |f| try testing.expect(p.state.eqlField(plan.current, f));

    // Absent sections are appended once; CRLF and a missing final newline are kept.
    var crlf = try Plan.init(testing.allocator, "[listen]\r\nirc = 6680\r\n# tail");
    defer crlf.deinit();
    try crlf.edit("tls-port", "6698");
    var c2 = try crlf.candidate(testing.allocator);
    defer c2.deinit();
    try testing.expectEqualStrings("[listen]\r\nirc = 6680\r\n# tail\r\n[tls]\r\nenabled = true\r\nport = 6698\r\n", c2.bytes);

    // A fake header inside a multi-line string elsewhere is not a section.
    var tricky = try Plan.init(testing.allocator, "[motd]\ntext = \"\"\"\n[listen]\nirc = 1\n\"\"\"\n[listen]\nirc = 6680\n");
    defer tricky.deinit();
    try tricky.edit("irc-port", "6681");
    var c3 = try tricky.candidate(testing.allocator);
    defer c3.deinit();
    try testing.expectEqualStrings("[motd]\ntext = \"\"\"\n[listen]\nirc = 1\n\"\"\"\n[listen]\nirc = 6681\n", c3.bytes);
}

test "maintenance config patch refuses inline tables, dotted keys, duplicate keys, multi-line values and @file/@env indirection on edited keys" {
    const Case = struct { text: []const u8, key: []const u8, value: []const u8, err: anyerror };
    for ([_]Case{
        .{ .text = "listen = { host = \"127.0.0.1\", irc = 6680 }\n", .key = "irc-port", .value = "7000", .err = error.InlineTable },
        .{ .text = "listen.irc = 6680\n", .key = "irc-port", .value = "7000", .err = error.DottedKey },
        .{ .text = "[network]\nserver_name = \"\"\"irc.example.test\"\"\"\n[listen]\nirc = 6680\n", .key = "hostname", .value = "x.test", .err = error.MultiLineValue },
        .{ .text = "[listen]\nirc = 6680\nhost = \"env:ONYX_LISTEN\"\n", .key = "listen", .value = "::1", .err = error.IndirectValue },
        .{ .text = "[listen]\nirc = 6680\n[tls]\ndns_name = \"@file:/etc/onyx/name\"\n", .key = "dns-name", .value = "a.test", .err = error.IndirectValue },
        .{ .text = "[listen]\nirc = 6680\n[[tls]]\nport = 1\n", .key = "tls", .value = "on", .err = error.ArrayTable },
    }) |case| {
        var plan = try Plan.init(testing.allocator, case.text);
        defer plan.deinit();
        try testing.expectError(case.err, plan.edit(case.key, case.value));
        try testing.expect(!plan.pending());
    }
    // Escaped key names are not followed by the scanner: no plan at all.
    try testing.expectError(error.UnsupportedSyntax, Plan.init(testing.allocator, "\"a\\u0041\" = 1\n[listen]\nirc = 6680\n"));
    // Untouched indirection does not block unrelated edits.
    var indirect = try Plan.init(testing.allocator, "[listen]\nirc = 6680\nhost = \"env:ONYX_LISTEN\"\n");
    defer indirect.deinit();
    try indirect.edit("irc-port", "6681");
    var c = try indirect.candidate(testing.allocator);
    defer c.deinit();
    try testing.expectEqualStrings("[listen]\nirc = 6681\nhost = \"env:ONYX_LISTEN\"\n", c.bytes);
    // Duplicate keys are rejected by the parser before any plan exists.
    try testing.expectError(error.DuplicateKey, Plan.init(testing.allocator, "[listen]\nirc = 1\nirc = 2\n"));
    // The parser merges a reopened table; the scanner refuses edits there.
    var reopened = try Plan.init(testing.allocator, "[listen]\nirc = 1\n[listen]\nhost = \"::1\"\n");
    defer reopened.deinit();
    try testing.expectError(error.DuplicateKey, reopened.edit("irc-port", "2"));
    try testing.expectError(error.DuplicateKey, reopened.edit("media-port", "2"));
    try testing.expectEqual(@as(u16, 1), reopened.current.settings.irc_port);
}

test "maintenance config preview classifies listen.irc as restart_required with client disconnect impact and tls.dns_name as reloadable" {
    var plan = try Plan.init(testing.allocator, live_fixture);
    defer plan.deinit();
    try plan.edit("irc-port", "7000");
    try plan.edit("dns-name", "chat.example.test");
    try plan.edit("hostname", "chat.example.test");
    var c = try plan.candidate(testing.allocator);
    defer c.deinit();
    var seen: usize = 0;
    for (c.changes) |change| switch (change.field) {
        .irc_port => {
            try testing.expectEqual(config_format.ConfigFieldClass.restart_required, change.class);
            try testing.expectEqual(Impact.client_disconnect, change.impact);
            try testing.expectEqualStrings("6680", change.before.?);
            seen += 1;
        },
        .tls_dns_name => {
            try testing.expectEqual(config_format.ConfigFieldClass.reloadable, change.class);
            try testing.expectEqual(Impact.live_reload, change.impact);
            try testing.expect(change.before == null);
            seen += 1;
        },
        .hostname => {
            // Unproven fields fail closed to startup_only, never reloadable,
            // and the preview states the restart worst case.
            try testing.expectEqual(config_format.ConfigFieldClass.startup_only, change.class);
            try testing.expectEqual(Impact.unproven, change.impact);
            seen += 1;
        },
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(usize, 3), seen);
    const text = try renderPreview(testing.allocator, &c);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "- listen.irc: 6680 -> 7000; restart_required; Helix refuses") != null);
    try testing.expect(std.mem.indexOf(u8, text, "- tls.dns_name: absent (daemon default) -> \"chat.example.test\"; reloadable") != null);
    try testing.expect(std.mem.indexOf(u8, text, "@file") == null);
    try testing.expect(std.mem.indexOf(u8, text, "- network.server_name: \"irc.example.test\" -> \"chat.example.test\"; startup_only; not proven reloadable") != null);
    // Every modeled field has a stated impact; only listed fields are proven.
    try testing.expectEqual(Impact.next_process_start, impactOf("cloak.secret"));
    try testing.expectEqual(Impact.unproven, impactOf("limits.max_clients"));
    try testing.expectEqual(Impact.unproven, impactOf("listen.irc.x"));
    try testing.expectEqual(Impact.client_disconnect, impactOf("node.id"));
}

test "maintenance config rollback inverse edits reproduce original source byte-for-byte and digests match" {
    var plan = try Plan.init(testing.allocator, live_fixture);
    defer plan.deinit();
    try plan.edit("irc-port", "7000");
    try plan.edit("listen", "0.0.0.0");
    try plan.edit("media-port", "5000");
    try plan.edit("max-clients", "64");
    var c = try plan.candidate(testing.allocator);
    defer c.deinit();
    try testing.expectEqualSlices(u8, &digest(live_fixture), &c.original_sha256);
    try testing.expectEqualSlices(u8, &digest(c.bytes), &c.sha256);
    const restored = try c.rollback(testing.allocator, c.bytes);
    defer testing.allocator.free(restored);
    try testing.expectEqualStrings(live_fixture, restored);
    try testing.expectEqualSlices(u8, &c.original_sha256, &digest(restored));
    // Hostile input: a modified or replayed-foreign candidate is refused.
    const tampered = try testing.allocator.dupe(u8, c.bytes);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 2] ^= 1;
    try testing.expectError(error.CandidateMismatch, c.rollback(testing.allocator, tampered));
    try testing.expectError(error.CandidateMismatch, c.rollback(testing.allocator, live_fixture));
}

test "maintenance config verify refuses candidate where a non-edited classified field changed" {
    var plan = try Plan.init(testing.allocator, live_fixture);
    defer plan.deinit();
    try plan.edit("irc-port", "7000");
    var c = try plan.candidate(testing.allocator);
    defer c.deinit();
    try plan.verify(testing.allocator, c.bytes);
    const cases = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "cert_path = \"/etc/onyx/cert.der\"", .to = "cert_path = \"/etc/onyx/evil.der\"" },
        .{ .from = "nick_delay = 5", .to = "nick_delay = 6" },
        .{ .from = "port = 6697", .to = "port = 6698" },
        .{ .from = "id = 42", .to = "id = 43" },
        .{ .from = "[cloak]", .to = "[cloak]\nprevious_secret = \"x\"" },
    };
    for (cases) |case| {
        const forged = try std.mem.replaceOwned(u8, testing.allocator, c.bytes, case.from, case.to);
        defer testing.allocator.free(forged);
        try testing.expect(!std.mem.eql(u8, forged, c.bytes));
        try testing.expectError(error.UnexpectedChange, plan.verify(testing.allocator, forged));
    }
    // A candidate that drops the edit itself is a mismatch, not success.
    try testing.expectError(error.CandidateMismatch, plan.verify(testing.allocator, live_fixture));
}

fn allocationProbe(allocator: Allocator) !void {
    var plan = try Plan.init(allocator, live_fixture);
    defer plan.deinit();
    try plan.edit("hostname", "chat.example.test");
    try plan.edit("dns-name", "chat.example.test");
    try plan.edit("tls-port", "6698");
    try plan.edit("media-port", "5000");
    try plan.edit("max-clients", "64");
    const before = plan.current;
    var c = plan.candidate(allocator) catch |err| {
        // Failed candidate construction never mutates the plan.
        for (all_fields) |f| try testing.expect(plan.current.eqlField(before, f));
        return err;
    };
    defer c.deinit();
    const restored = try c.rollback(allocator, c.bytes);
    defer allocator.free(restored);
    try testing.expectEqualStrings(live_fixture, restored);
    const text = try renderPreview(allocator, &c);
    allocator.free(text);
}

test "maintenance config allocation failures never yield a partial candidate (checkAllAllocationFailures)" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationProbe, .{});
    // A failed string edit keeps every earlier choice and retries cleanly.
    var failing: std.testing.FailingAllocator = .init(testing.allocator, .{});
    var plan = try Plan.init(failing.allocator(), live_fixture);
    defer plan.deinit();
    try plan.edit("hostname", "first.example.test");
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, plan.edit("hostname", "second.example.test"));
    try testing.expectEqualStrings("first.example.test", plan.current.settings.hostname);
    failing.fail_index = std.math.maxInt(usize);
    try plan.edit("hostname", "second.example.test");
    try testing.expectEqualStrings("second.example.test", plan.current.settings.hostname);
}
