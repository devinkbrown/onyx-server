// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

pub const IceError = error{
    InvalidComponent,
    AddressTooLong,
    InvalidPairIndex,
    InvalidCheckTransition,
    CannotNominatePair,
};

pub const CandidateType = enum {
    host,
    srflx,
    prflx,
    relay,

    pub fn preference(self: CandidateType) u8 {
        return switch (self) {
            .host => 126,
            .prflx => 110,
            .srflx => 100,
            .relay => 0,
        };
    }
};

pub const TransportAddress = struct {
    ip: [16]u8 = @splat(0),
    ip_len: u8 = 0,
    port: u16 = 0,

    pub fn fromBytes(ip: []const u8, port: u16) IceError!TransportAddress {
        if (ip.len > 16) return IceError.AddressTooLong;

        var out: TransportAddress = .{ .port = port };
        @memcpy(out.ip[0..ip.len], ip);
        out.ip_len = @intCast(ip.len);
        return out;
    }

    /// Returns the active IP bytes. Takes `self` by reference: a by-value
    /// receiver would return a slice into the destroyed parameter temporary
    /// (dangling), which made `eql`/`less` compare reused stack garbage.
    pub fn bytes(self: *const TransportAddress) []const u8 {
        return self.ip[0..self.ip_len];
    }

    pub fn eql(a: TransportAddress, b: TransportAddress) bool {
        // Slice directly from the by-value params (live for this call) rather
        // than via a by-value `bytes()` whose result would dangle.
        return a.port == b.port and
            a.ip_len == b.ip_len and
            std.mem.eql(u8, a.ip[0..a.ip_len], b.ip[0..b.ip_len]);
    }

    fn less(a: TransportAddress, b: TransportAddress) bool {
        const ip_order = std.mem.order(u8, a.ip[0..a.ip_len], b.ip[0..b.ip_len]);
        if (ip_order != .eq) return ip_order == .lt;
        return a.port < b.port;
    }
};

pub const Candidate = struct {
    type: CandidateType,
    transport_addr: TransportAddress,
    priority: u32,
    foundation: []const u8,
    local_pref: u16,
    component_id: u16,

    pub fn init(
        candidate_type: CandidateType,
        ip: []const u8,
        port: u16,
        foundation: []const u8,
        local_pref: u16,
        component_id: u16,
    ) IceError!Candidate {
        return .{
            .type = candidate_type,
            .transport_addr = try TransportAddress.fromBytes(ip, port),
            .priority = try candidatePriority(candidate_type, local_pref, component_id),
            .foundation = foundation,
            .local_pref = local_pref,
            .component_id = component_id,
        };
    }

    fn less(a: Candidate, b: Candidate) bool {
        if (a.priority != b.priority) return a.priority > b.priority;

        const foundation_order = std.mem.order(u8, a.foundation, b.foundation);
        if (foundation_order != .eq) return foundation_order == .lt;

        if (!a.transport_addr.eql(b.transport_addr)) return a.transport_addr.less(b.transport_addr);
        if (a.component_id != b.component_id) return a.component_id < b.component_id;
        if (a.local_pref != b.local_pref) return a.local_pref > b.local_pref;
        return @backingInt(a.type) < @backingInt(b.type);
    }
};

pub const Role = enum {
    controlling,
    controlled,
};

pub const CheckState = enum {
    frozen,
    waiting,
    in_progress,
    succeeded,
    failed,
};

pub const CheckResult = enum {
    succeeded,
    failed,
};

pub const IceState = enum {
    checking,
    connected,
    completed,
    failed,
};

pub const CandidatePair = struct {
    local: Candidate,
    remote: Candidate,
    priority: u64,
    state: CheckState = .frozen,
    nominated: bool = false,
    valid: bool = false,

    pub fn init(local: Candidate, remote: Candidate, role: Role) CandidatePair {
        return .{
            .local = local,
            .remote = remote,
            .priority = pairPriority(local, remote, role),
        };
    }
};

pub fn candidatePriority(candidate_type: CandidateType, local_pref: u16, component_id: u16) IceError!u32 {
    if (component_id == 0 or component_id > 256) return IceError.InvalidComponent;

    const type_part = @as(u32, candidate_type.preference()) << 24;
    const local_part = @as(u32, local_pref) << 8;
    const component_part: u32 = @intCast(256 - component_id);
    return type_part + local_part + component_part;
}

pub fn pairPriority(local: Candidate, remote: Candidate, role: Role) u64 {
    const g: u32 = switch (role) {
        .controlling => local.priority,
        .controlled => remote.priority,
    };
    const d: u32 = switch (role) {
        .controlling => remote.priority,
        .controlled => local.priority,
    };

    const low = @min(g, d);
    const high = @max(g, d);
    const tie: u64 = if (g > d) 1 else 0;
    return (@as(u64, low) << 32) + (2 * @as(u64, high)) + tie;
}

pub fn formCandidatePairs(
    allocator: std.mem.Allocator,
    local: []const Candidate,
    remote: []const Candidate,
    role: Role,
) ![]CandidatePair {
    var pairs: std.ArrayList(CandidatePair) = .empty;
    errdefer pairs.deinit(allocator);

    for (local) |local_candidate| {
        for (remote) |remote_candidate| {
            if (local_candidate.component_id != remote_candidate.component_id) continue;
            try pairs.append(allocator, CandidatePair.init(local_candidate, remote_candidate, role));
        }
    }

    const owned = try pairs.toOwnedSlice(allocator);
    orderChecklist(owned);
    return owned;
}

pub fn orderChecklist(pairs: []CandidatePair) void {
    std.mem.sort(CandidatePair, pairs, {}, pairLess);
}

fn pairLess(_: void, a: CandidatePair, b: CandidatePair) bool {
    if (a.priority != b.priority) return a.priority > b.priority;
    if (Candidate.less(a.local, b.local)) return true;
    if (Candidate.less(b.local, a.local)) return false;
    if (Candidate.less(a.remote, b.remote)) return true;
    if (Candidate.less(b.remote, a.remote)) return false;
    return false;
}

pub const Agent = struct {
    allocator: std.mem.Allocator,
    role: Role,
    pairs: []CandidatePair,
    state: IceState,
    selected_pair: ?usize,

    pub fn init(
        allocator: std.mem.Allocator,
        role: Role,
        local: []const Candidate,
        remote: []const Candidate,
    ) !Agent {
        const pairs = try formCandidatePairs(allocator, local, remote, role);
        var out: Agent = .{
            .allocator = allocator,
            .role = role,
            .pairs = pairs,
            .state = .checking,
            .selected_pair = null,
        };
        out.resetChecklist();
        return out;
    }

    pub fn deinit(self: *Agent) void {
        self.allocator.free(self.pairs);
        self.* = undefined;
    }

    pub fn resetChecklist(self: *Agent) void {
        self.state = if (self.pairs.len == 0) .failed else .checking;
        self.selected_pair = null;

        for (self.pairs, 0..) |*pair, index| {
            pair.state = if (index == 0) .waiting else .frozen;
            pair.valid = false;
            pair.nominated = false;
        }
    }

    pub fn startNextCheck(self: *Agent) ?usize {
        if (self.state == .completed or self.state == .failed) return null;

        if (self.findPairWithState(.waiting)) |index| {
            self.pairs[index].state = .in_progress;
            return index;
        }

        if (self.findPairWithState(.frozen)) |index| {
            self.pairs[index].state = .in_progress;
            return index;
        }

        self.refreshTerminalState();
        return null;
    }

    pub fn completeCheck(self: *Agent, index: usize, result: CheckResult, nominate: bool) IceError!void {
        if (index >= self.pairs.len) return IceError.InvalidPairIndex;

        const state = self.pairs[index].state;
        if (state != .in_progress and state != .waiting and state != .frozen) {
            return IceError.InvalidCheckTransition;
        }

        switch (result) {
            .succeeded => {
                self.pairs[index].state = .succeeded;
                self.pairs[index].valid = true;
                if (nominate) {
                    try self.nominatePair(index);
                } else if (self.state != .completed) {
                    self.state = .connected;
                    self.unfreezeNext();
                }
            },
            .failed => {
                self.pairs[index].state = .failed;
                self.unfreezeNext();
                self.refreshTerminalState();
            },
        }
    }

    pub fn nominatePair(self: *Agent, index: usize) IceError!void {
        if (index >= self.pairs.len) return IceError.InvalidPairIndex;
        if (self.pairs[index].state != .succeeded or !self.pairs[index].valid) {
            return IceError.CannotNominatePair;
        }

        self.pairs[index].nominated = true;
        self.selected_pair = index;
        self.state = .completed;
    }

    pub fn selectedPair(self: Agent) ?CandidatePair {
        const index = self.selected_pair orelse return null;
        return self.pairs[index];
    }

    fn findPairWithState(self: Agent, state: CheckState) ?usize {
        for (self.pairs, 0..) |pair, index| {
            if (pair.state == state) return index;
        }
        return null;
    }

    fn unfreezeNext(self: *Agent) void {
        if (self.state == .completed or self.state == .failed) return;
        if (self.findPairWithState(.waiting) != null) return;
        if (self.findPairWithState(.in_progress) != null) return;
        if (self.findPairWithState(.frozen)) |index| {
            self.pairs[index].state = .waiting;
        }
    }

    fn refreshTerminalState(self: *Agent) void {
        if (self.state == .completed) return;

        var has_valid = false;
        var has_checkable = false;
        for (self.pairs) |pair| {
            if (pair.valid) has_valid = true;
            if (pair.state == .frozen or pair.state == .waiting or pair.state == .in_progress) {
                has_checkable = true;
            }
        }

        if (!has_checkable and !has_valid) {
            self.state = .failed;
        } else if (has_valid) {
            self.state = .connected;
        } else {
            self.state = .checking;
        }
    }
};

fn testCandidate(candidate_type: CandidateType, pref: u16, component: u16, foundation: []const u8, port: u16) !Candidate {
    return Candidate.init(candidate_type, &.{ 10, 0, 0, @as(u8, @intCast(port % 250)) }, port, foundation, pref, component);
}

test "priority computation matches RFC 8445 formula" {
    try std.testing.expectEqual(@as(u32, 2_130_706_431), try candidatePriority(.host, 65_535, 1));
    try std.testing.expectEqual((@as(u32, 110) << 24) + (@as(u32, 4_321) << 8) + 254, try candidatePriority(.prflx, 4_321, 2));
    try std.testing.expectEqual(@as(u32, 255), try candidatePriority(.relay, 0, 1));
    try std.testing.expectError(IceError.InvalidComponent, candidatePriority(.host, 1, 0));
    try std.testing.expectError(IceError.InvalidComponent, candidatePriority(.host, 1, 257));

    const host = try candidatePriority(.host, 1, 1);
    const prflx = try candidatePriority(.prflx, 65_535, 1);
    const srflx = try candidatePriority(.srflx, 65_535, 1);
    const relay = try candidatePriority(.relay, 65_535, 1);
    try std.testing.expect(host > prflx);
    try std.testing.expect(prflx > srflx);
    try std.testing.expect(srflx > relay);
}

test "pair priority ordering uses controlling and controlled roles" {
    var local = try Candidate.init(.host, &.{ 192, 0, 2, 1 }, 50_000, "L", 1, 1);
    var remote = try Candidate.init(.srflx, &.{ 198, 51, 100, 1 }, 40_000, "R", 1, 1);
    local.priority = 1_000;
    remote.priority = 2_000;

    const controlling = pairPriority(local, remote, .controlling);
    const controlled = pairPriority(local, remote, .controlled);

    try std.testing.expectEqual((@as(u64, 1_000) << 32) + 4_000, controlling);
    try std.testing.expectEqual((@as(u64, 1_000) << 32) + 4_001, controlled);
    try std.testing.expect(controlled > controlling);
}

test "candidate pair formation filters components and orders checklist by priority" {
    const allocator = std.testing.allocator;
    const local = [_]Candidate{
        try testCandidate(.relay, 10, 1, "relay", 5_001),
        try testCandidate(.host, 10, 1, "host", 5_002),
        try testCandidate(.srflx, 10, 2, "rtcp", 5_003),
    };
    const remote = [_]Candidate{
        try testCandidate(.srflx, 20, 1, "remote1", 6_001),
        try testCandidate(.host, 20, 2, "remote2", 6_002),
    };

    const pairs = try formCandidatePairs(allocator, &local, &remote, .controlling);
    defer allocator.free(pairs);

    try std.testing.expectEqual(@as(usize, 3), pairs.len);
    for (pairs) |pair| {
        try std.testing.expectEqual(pair.local.component_id, pair.remote.component_id);
    }
    try std.testing.expect(pairs[0].priority >= pairs[1].priority);
    try std.testing.expect(pairs[1].priority >= pairs[2].priority);
}

test "check list processes pairs in priority order" {
    const allocator = std.testing.allocator;
    const local = [_]Candidate{
        try testCandidate(.relay, 1, 1, "l3", 5_003),
        try testCandidate(.host, 1, 1, "l1", 5_001),
        try testCandidate(.srflx, 1, 1, "l2", 5_002),
    };
    const remote = [_]Candidate{try testCandidate(.srflx, 1, 1, "r", 6_001)};

    var agent = try Agent.init(allocator, .controlling, &local, &remote);
    defer agent.deinit();

    const first = agent.startNextCheck().?;
    try std.testing.expectEqual(@as(usize, 0), first);
    try std.testing.expectEqual(CandidateType.host, agent.pairs[first].local.type);
    try agent.completeCheck(first, .failed, false);

    const second = agent.startNextCheck().?;
    try std.testing.expectEqual(@as(usize, 1), second);
    try std.testing.expectEqual(CandidateType.srflx, agent.pairs[second].local.type);
    try agent.completeCheck(second, .failed, false);

    const third = agent.startNextCheck().?;
    try std.testing.expectEqual(@as(usize, 2), third);
    try std.testing.expectEqual(CandidateType.relay, agent.pairs[third].local.type);
}

test "succeeded nominated pair moves agent to completed" {
    const allocator = std.testing.allocator;
    const local = [_]Candidate{try testCandidate(.host, 1, 1, "l", 5_001)};
    const remote = [_]Candidate{try testCandidate(.srflx, 1, 1, "r", 6_001)};

    var agent = try Agent.init(allocator, .controlling, &local, &remote);
    defer agent.deinit();

    const index = agent.startNextCheck().?;
    try agent.completeCheck(index, .succeeded, true);

    try std.testing.expectEqual(IceState.completed, agent.state);
    try std.testing.expectEqual(index, agent.selected_pair.?);
    try std.testing.expect(agent.pairs[index].valid);
    try std.testing.expect(agent.pairs[index].nominated);
    try std.testing.expect(agent.selectedPair() != null);
}

test "succeeded non-nominated pair is connected and regular nomination completes" {
    const allocator = std.testing.allocator;
    const local = [_]Candidate{try testCandidate(.host, 1, 1, "l", 5_001)};
    const remote = [_]Candidate{try testCandidate(.srflx, 1, 1, "r", 6_001)};

    var agent = try Agent.init(allocator, .controlling, &local, &remote);
    defer agent.deinit();

    const index = agent.startNextCheck().?;
    try agent.completeCheck(index, .succeeded, false);
    try std.testing.expectEqual(IceState.connected, agent.state);
    try std.testing.expectEqual(@as(?usize, null), agent.selected_pair);

    try agent.nominatePair(index);
    try std.testing.expectEqual(IceState.completed, agent.state);
    try std.testing.expect(agent.pairs[index].nominated);
}

test "all failed checks move agent to failed" {
    const allocator = std.testing.allocator;
    const local = [_]Candidate{
        try testCandidate(.host, 1, 1, "l1", 5_001),
        try testCandidate(.srflx, 1, 1, "l2", 5_002),
    };
    const remote = [_]Candidate{try testCandidate(.srflx, 1, 1, "r", 6_001)};

    var agent = try Agent.init(allocator, .controlling, &local, &remote);
    defer agent.deinit();

    while (agent.startNextCheck()) |index| {
        try agent.completeCheck(index, .failed, false);
    }

    try std.testing.expectEqual(IceState.failed, agent.state);
}

test "ordering is deterministic for equal priorities" {
    const allocator = std.testing.allocator;
    const local_a = try Candidate.init(.host, &.{ 10, 0, 0, 1 }, 5_000, "a", 100, 1);
    const local_b = try Candidate.init(.host, &.{ 10, 0, 0, 2 }, 5_000, "b", 100, 1);
    const remote_a = try Candidate.init(.srflx, &.{ 203, 0, 113, 1 }, 6_000, "a", 100, 1);
    const remote_b = try Candidate.init(.srflx, &.{ 203, 0, 113, 2 }, 6_000, "b", 100, 1);

    const local_forward = [_]Candidate{ local_b, local_a };
    const remote_forward = [_]Candidate{ remote_b, remote_a };
    const local_reverse = [_]Candidate{ local_a, local_b };
    const remote_reverse = [_]Candidate{ remote_a, remote_b };

    const first = try formCandidatePairs(allocator, &local_forward, &remote_forward, .controlling);
    defer allocator.free(first);
    const second = try formCandidatePairs(allocator, &local_reverse, &remote_reverse, .controlling);
    defer allocator.free(second);

    try std.testing.expectEqual(first.len, second.len);
    for (first, second) |a, b| {
        try std.testing.expectEqual(a.priority, b.priority);
        try std.testing.expectEqualStrings(a.local.foundation, b.local.foundation);
        try std.testing.expectEqualStrings(a.remote.foundation, b.remote.foundation);
        try std.testing.expect(a.local.transport_addr.eql(b.local.transport_addr));
        try std.testing.expect(a.remote.transport_addr.eql(b.remote.transport_addr));
    }
}
