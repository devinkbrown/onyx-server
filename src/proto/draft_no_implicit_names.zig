// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 draft/no-implicit-names policy helpers.
//!
//! This module only decides whether the server should send the automatic NAMES
//! burst that normally follows a successful JOIN. Explicit NAMES commands still
//! send NAMES replies.

const std = @import("std");
const numeric = @import("numeric.zig");

/// Capability token advertised and requested by clients for this draft.
pub const CAP_TOKEN: []const u8 = "draft/no-implicit-names";

/// Numerics affected by suppressing the automatic JOIN NAMES burst.
pub const NoImplicitNamesNumeric = enum(u16) {
    RPL_NAMREPLY = 353,
    RPL_ENDOFNAMES = 366,

    /// Return the shared numeric enum value for this module-local numeric.
    pub fn known(self: NoImplicitNamesNumeric) numeric.Numeric {
        return switch (self) {
            .RPL_NAMREPLY => .RPL_NAMREPLY,
            .RPL_ENDOFNAMES => .RPL_ENDOFNAMES,
        };
    }

    /// Return the wire numeric code.
    pub fn code(self: NoImplicitNamesNumeric) u16 {
        return @backingInt(self);
    }
};

/// Compile-time and runtime limits for this policy module.
pub const Params = struct {
    max_cap_token_bytes: usize = 64,
};

/// Errors returned by no-implicit-names validation and decisions.
pub const NoImplicitNamesError = error{
    EmptyCapabilityToken,
    CapabilityTokenTooLong,
    InvalidCapabilityToken,
};

/// Source of the NAMES decision.
pub const NamesSource = enum(u1) {
    implicit_join,
    explicit_names,
};

/// Result of deciding whether to send NAMES replies.
pub const NamesDecision = enum(u1) {
    send,
    suppress,
};

/// Capability state relevant to this policy.
pub const ClientCaps = struct {
    no_implicit_names: bool = false,
};

/// Pure policy for IRCv3 draft/no-implicit-names.
pub const NoImplicitNamesPolicy = struct {
    params: Params,
    cap_token: []const u8,

    /// Create a policy using the default draft capability token.
    pub fn init(params: Params) NoImplicitNamesError!NoImplicitNamesPolicy {
        return initWithToken(params, CAP_TOKEN);
    }

    /// Create a policy using a caller-provided capability token.
    pub fn initWithToken(params: Params, cap_token: []const u8) NoImplicitNamesError!NoImplicitNamesPolicy {
        try validateCapTokenWith(params, cap_token);
        return .{
            .params = params,
            .cap_token = cap_token,
        };
    }

    /// Release policy state.
    pub fn deinit(self: *NoImplicitNamesPolicy) void {
        self.* = undefined;
    }

    /// Return the capability token this policy recognizes.
    pub fn token(self: *const NoImplicitNamesPolicy) []const u8 {
        return self.cap_token;
    }

    /// Return true when `requested` exactly matches this policy's cap token.
    pub fn recognizes(self: *const NoImplicitNamesPolicy, requested: []const u8) NoImplicitNamesError!bool {
        try validateCapTokenWith(self.params, requested);
        return std.mem.eql(u8, requested, self.cap_token);
    }

    /// Decide whether NAMES replies should be sent for the given source.
    pub fn decide(self: *const NoImplicitNamesPolicy, source: NamesSource, caps: ClientCaps) NoImplicitNamesError!NamesDecision {
        try validateCapTokenWith(self.params, self.cap_token);
        return switch (source) {
            .implicit_join => if (caps.no_implicit_names) .suppress else .send,
            .explicit_names => .send,
        };
    }

    /// Return true when the caller should emit NAMES replies.
    pub fn shouldSend(self: *const NoImplicitNamesPolicy, source: NamesSource, caps: ClientCaps) NoImplicitNamesError!bool {
        return switch (try self.decide(source, caps)) {
            .send => true,
            .suppress => false,
        };
    }
};

/// Validate a capability token with default limits.
pub fn validateCapToken(cap_token: []const u8) NoImplicitNamesError!void {
    return validateCapTokenWith(.{}, cap_token);
}

/// Validate a capability token with caller-selected limits.
pub fn validateCapTokenWith(params: Params, cap_token: []const u8) NoImplicitNamesError!void {
    if (cap_token.len == 0) return error.EmptyCapabilityToken;
    if (cap_token.len > params.max_cap_token_bytes) return error.CapabilityTokenTooLong;
    for (cap_token) |byte| {
        switch (byte) {
            0...32, 127, '=' => return error.InvalidCapabilityToken,
            else => {},
        }
    }
}

test "default policy exposes the draft capability token" {
    // Arrange
    const allocator = std.testing.allocator;
    const owned = try allocator.dupe(u8, CAP_TOKEN);
    defer allocator.free(owned);

    var policy = try NoImplicitNamesPolicy.initWithToken(.{}, owned);
    defer policy.deinit();

    // Act
    const token = policy.token();

    // Assert
    try std.testing.expectEqualStrings(CAP_TOKEN, token);
}

test "policy recognizes only the exact capability token" {
    // Arrange
    const allocator = std.testing.allocator;
    const owned = try allocator.dupe(u8, CAP_TOKEN);
    defer allocator.free(owned);

    var policy = try NoImplicitNamesPolicy.initWithToken(.{}, owned);
    defer policy.deinit();

    // Act
    const exact = try policy.recognizes(CAP_TOKEN);
    const different = try policy.recognizes("draft/other-cap");

    // Assert
    try std.testing.expect(exact);
    try std.testing.expect(!different);
}

test "implicit JOIN sends NAMES when client lacks the cap" {
    // Arrange
    var policy = try NoImplicitNamesPolicy.init(.{});
    defer policy.deinit();
    const caps = ClientCaps{ .no_implicit_names = false };

    // Act
    const decision = try policy.decide(.implicit_join, caps);
    const should_send = try policy.shouldSend(.implicit_join, caps);

    // Assert
    try std.testing.expectEqual(NamesDecision.send, decision);
    try std.testing.expect(should_send);
}

test "implicit JOIN suppresses NAMES when client has the cap" {
    // Arrange
    var policy = try NoImplicitNamesPolicy.init(.{});
    defer policy.deinit();
    const caps = ClientCaps{ .no_implicit_names = true };

    // Act
    const decision = try policy.decide(.implicit_join, caps);
    const should_send = try policy.shouldSend(.implicit_join, caps);

    // Assert
    try std.testing.expectEqual(NamesDecision.suppress, decision);
    try std.testing.expect(!should_send);
}

test "explicit NAMES always sends replies even when client has the cap" {
    // Arrange
    var policy = try NoImplicitNamesPolicy.init(.{});
    defer policy.deinit();
    const caps = ClientCaps{ .no_implicit_names = true };

    // Act
    const decision = try policy.decide(.explicit_names, caps);
    const should_send = try policy.shouldSend(.explicit_names, caps);

    // Assert
    try std.testing.expectEqual(NamesDecision.send, decision);
    try std.testing.expect(should_send);
}

test "capability token validation rejects empty whitespace separator and oversized tokens" {
    // Arrange
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, 65);
    defer allocator.free(oversized);
    @memset(oversized, 'a');

    // Act
    const empty_error = validateCapToken("");
    const space_error = validateCapToken("draft/no implicit-names");
    const separator_error = validateCapToken("draft/no-implicit-names=value");
    const oversized_error = validateCapToken(oversized);

    // Assert
    try std.testing.expectError(error.EmptyCapabilityToken, empty_error);
    try std.testing.expectError(error.InvalidCapabilityToken, space_error);
    try std.testing.expectError(error.InvalidCapabilityToken, separator_error);
    try std.testing.expectError(error.CapabilityTokenTooLong, oversized_error);
}

test "custom token limit is enforced during policy creation" {
    // Arrange
    const allocator = std.testing.allocator;
    const token = try allocator.dupe(u8, "draft/no-implicit-names");
    defer allocator.free(token);

    // Act
    const result = NoImplicitNamesPolicy.initWithToken(.{ .max_cap_token_bytes = 8 }, token);

    // Assert
    try std.testing.expectError(error.CapabilityTokenTooLong, result);
}

test "numeric mapping matches shared IRC numerics" {
    // Arrange
    const namreply = NoImplicitNamesNumeric.RPL_NAMREPLY;
    const endofnames = NoImplicitNamesNumeric.RPL_ENDOFNAMES;

    // Act
    const namreply_known = namreply.known();
    const endofnames_known = endofnames.known();

    // Assert
    try std.testing.expectEqual(numeric.Numeric.RPL_NAMREPLY, namreply_known);
    try std.testing.expectEqual(numeric.Numeric.RPL_ENDOFNAMES, endofnames_known);
    try std.testing.expectEqual(@as(u16, 353), namreply.code());
    try std.testing.expectEqual(@as(u16, 366), endofnames.code());
}
