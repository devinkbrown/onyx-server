// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Expressive message metadata tag codec.
//!
//! The wire tag grammar is compact and canonical:
//!
//!     gesture/intensity/facing
//!
//! `gesture` is a stable lowercase token, `intensity` is a decimal integer in
//! the inclusive range 0..100 with no leading zeroes, and `facing` is `left` or
//! `right`.

const std = @import("std");

const max_intensity: u8 = 100;

/// Parser limits for expressive message tag values.
pub const Params = struct {
    /// Maximum accepted byte length for a tag value.
    max_tag_bytes: usize = 32,
};

/// Stable gesture identifiers used by the expressive message tag.
pub const Gesture = enum(u8) {
    neutral = 0,
    happy = 1,
    sad = 2,
    angry = 3,
    shout = 4,
    whisper = 5,
    laugh = 6,
    wave = 7,
    think = 8,
    point = 9,
    love = 10,
    bored = 11,
    scared = 12,
    coy = 13,
};

/// Direction a character pose is facing.
pub const Facing = enum {
    left,
    right,
};

/// Character pose metadata attached to a chat message.
pub const Pose = struct {
    /// Gesture to render for the message.
    gesture: Gesture,
    /// Gesture intensity in the inclusive range 0..100.
    intensity: u8,
    /// Character facing direction.
    facing: Facing,
};

/// Borrowed expressive chat message with pose metadata.
pub const Message = struct {
    /// Borrowed pose metadata for the message.
    pose: Pose,
    /// Borrowed character identifier or display key.
    character: []const u8,
    /// Borrowed message text.
    said: []const u8,
};

/// Errors produced while parsing expressive message tag values.
pub const ParseError = error{
    EmptyTag,
    TagTooLong,
    MissingField,
    TooManyFields,
    InvalidGesture,
    InvalidGestureId,
    InvalidIntensity,
    IntensityOutOfRange,
    InvalidFacing,
};

/// Errors produced while formatting expressive message tag values.
pub const FormatError = error{
    IntensityOutOfRange,
    OutputTooSmall,
};

const GestureSpec = struct {
    gesture: Gesture,
    token: []const u8,
};

const gesture_specs = [_]GestureSpec{
    .{ .gesture = .neutral, .token = "neutral" },
    .{ .gesture = .happy, .token = "happy" },
    .{ .gesture = .sad, .token = "sad" },
    .{ .gesture = .angry, .token = "angry" },
    .{ .gesture = .shout, .token = "shout" },
    .{ .gesture = .whisper, .token = "whisper" },
    .{ .gesture = .laugh, .token = "laugh" },
    .{ .gesture = .wave, .token = "wave" },
    .{ .gesture = .think, .token = "think" },
    .{ .gesture = .point, .token = "point" },
    .{ .gesture = .love, .token = "love" },
    .{ .gesture = .bored, .token = "bored" },
    .{ .gesture = .scared, .token = "scared" },
    .{ .gesture = .coy, .token = "coy" },
};

comptime {
    if (gesture_specs.len != @typeInfo(Gesture).@"enum".field_names.len) {
        @compileError("gesture token table must cover every gesture");
    }
}

/// Return the stable lowercase wire token for a gesture.
pub fn tokenOf(gesture: Gesture) []const u8 {
    return switch (gesture) {
        .neutral => "neutral",
        .happy => "happy",
        .sad => "sad",
        .angry => "angry",
        .shout => "shout",
        .whisper => "whisper",
        .laugh => "laugh",
        .wave => "wave",
        .think => "think",
        .point => "point",
        .love => "love",
        .bored => "bored",
        .scared => "scared",
        .coy => "coy",
    };
}

/// Parse a gesture from a case-insensitive wire token.
pub fn gestureFromToken(token: []const u8) ParseError!Gesture {
    if (token.len == 0) return error.InvalidGesture;

    for (gesture_specs) |spec| {
        if (std.ascii.eqlIgnoreCase(token, spec.token)) return spec.gesture;
    }
    return error.InvalidGesture;
}

/// Return the stable numeric id for a gesture.
pub fn idOf(gesture: Gesture) u8 {
    return @backingInt(gesture);
}

/// Parse a gesture from its stable numeric id.
pub fn gestureFromId(id: u8) ParseError!Gesture {
    for (gesture_specs) |spec| {
        if (idOf(spec.gesture) == id) return spec.gesture;
    }
    return error.InvalidGestureId;
}

/// Return the stable lowercase wire token for a facing direction.
pub fn tokenOfFacing(facing: Facing) []const u8 {
    return switch (facing) {
        .left => "left",
        .right => "right",
    };
}

/// Parse a facing direction from a case-insensitive wire token.
pub fn facingFromToken(token: []const u8) ParseError!Facing {
    if (std.ascii.eqlIgnoreCase(token, "left")) return .left;
    if (std.ascii.eqlIgnoreCase(token, "right")) return .right;
    return error.InvalidFacing;
}

/// Clamp an intensity-like value into the valid pose intensity range.
pub fn clampIntensity(value: u16) u8 {
    if (value > max_intensity) return max_intensity;
    return @intCast(value);
}

/// Parse a tag value using default parser limits.
pub fn parseTag(value: []const u8) ParseError!Pose {
    return parseTagBounded(.{}, value);
}

/// Parse a tag value using caller-provided parser limits.
pub fn parseTagBounded(comptime params: Params, value: []const u8) ParseError!Pose {
    if (value.len == 0) return error.EmptyTag;
    if (value.len > params.max_tag_bytes) return error.TagTooLong;

    var it = std.mem.splitScalar(u8, value, '/');
    const gesture_token = it.next() orelse return error.MissingField;
    const intensity_token = it.next() orelse return error.MissingField;
    const facing_token = it.next() orelse return error.MissingField;
    if (it.next() != null) return error.TooManyFields;

    return .{
        .gesture = try gestureFromToken(gesture_token),
        .intensity = try parseIntensity(intensity_token),
        .facing = try facingFromToken(facing_token),
    };
}

/// Format a pose into a caller-provided buffer using default formatter limits.
pub fn formatTag(pose: Pose, buf: []u8) FormatError![]const u8 {
    return formatTagBounded(.{}, pose, buf);
}

/// Format a pose into a caller-provided buffer using caller-provided limits.
pub fn formatTagBounded(comptime params: Params, pose: Pose, buf: []u8) FormatError![]const u8 {
    if (pose.intensity > max_intensity) return error.IntensityOutOfRange;

    const formatted = std.fmt.bufPrint(
        buf,
        "{s}/{d}/{s}",
        .{ tokenOf(pose.gesture), pose.intensity, tokenOfFacing(pose.facing) },
    ) catch return error.OutputTooSmall;

    if (formatted.len > params.max_tag_bytes) return error.OutputTooSmall;
    return formatted;
}

fn parseIntensity(token: []const u8) ParseError!u8 {
    if (token.len == 0) return error.InvalidIntensity;
    if (token.len > 1 and token[0] == '0') return error.InvalidIntensity;

    var value: u16 = 0;
    for (token) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidIntensity;
        value = value * 10 + @as(u16, byte - '0');
        if (value > max_intensity) return error.IntensityOutOfRange;
    }
    return @intCast(value);
}

test "every gesture round-trips token enum and id" {
    // Arrange
    const cases = gesture_specs;

    // Act and Assert
    for (cases) |case| {
        const token = tokenOf(case.gesture);
        const parsed_from_token = try gestureFromToken(token);
        const parsed_from_upper = try gestureFromToken(upperTokenForTest(token));
        const parsed_from_id = try gestureFromId(idOf(case.gesture));

        try std.testing.expectEqualStrings(case.token, token);
        try std.testing.expectEqual(case.gesture, parsed_from_token);
        try std.testing.expectEqual(case.gesture, parsed_from_upper);
        try std.testing.expectEqual(case.gesture, parsed_from_id);
    }
}

test "pose tag parses and formats with stable canonical bytes" {
    // Arrange
    const input = "happy/75/right";
    var out: [32]u8 = undefined;

    // Act
    const pose = try parseTag(input);
    const formatted = try formatTag(pose, &out);
    const reparsed = try parseTag(formatted);

    // Assert
    try std.testing.expectEqual(Gesture.happy, pose.gesture);
    try std.testing.expectEqual(@as(u8, 75), pose.intensity);
    try std.testing.expectEqual(Facing.right, pose.facing);
    try std.testing.expectEqualStrings(input, formatted);
    try std.testing.expectEqual(pose, reparsed);
}

test "gesture and facing parse case-insensitively but format lowercase" {
    // Arrange
    const input = "WhIsPeR/5/LEFT";
    var out: [32]u8 = undefined;

    // Act
    const pose = try parseTag(input);
    const formatted = try formatTag(pose, &out);

    // Assert
    try std.testing.expectEqual(Gesture.whisper, pose.gesture);
    try std.testing.expectEqual(Facing.left, pose.facing);
    try std.testing.expectEqualStrings("whisper/5/left", formatted);
}

test "intensity clamps through helper and tag parser rejects out of range" {
    // Arrange
    const under = @as(u16, 42);
    const over = @as(u16, 101);

    // Act
    const clamped_under = clampIntensity(under);
    const clamped_over = clampIntensity(over);

    // Assert
    try std.testing.expectEqual(@as(u8, 42), clamped_under);
    try std.testing.expectEqual(@as(u8, 100), clamped_over);
    try std.testing.expectError(error.IntensityOutOfRange, parseTag("happy/101/right"));
    try std.testing.expectError(error.IntensityOutOfRange, formatTag(.{
        .gesture = .happy,
        .intensity = 101,
        .facing = .right,
    }, &[_]u8{}));
}

test "intensity parser rejects empty nonnumeric and noncanonical values" {
    // Arrange
    const empty = "happy//right";
    const nonnumeric = "happy/loud/right";
    const leading_zero = "happy/01/right";

    // Act and Assert
    try std.testing.expectError(error.InvalidIntensity, parseTag(empty));
    try std.testing.expectError(error.InvalidIntensity, parseTag(nonnumeric));
    try std.testing.expectError(error.InvalidIntensity, parseTag(leading_zero));
}

test "bad gesture token and bad facing token return typed errors" {
    // Arrange
    const bad_gesture = "dance/10/right";
    const bad_facing = "happy/10/forward";

    // Act and Assert
    try std.testing.expectError(error.InvalidGesture, parseTag(bad_gesture));
    try std.testing.expectError(error.InvalidFacing, parseTag(bad_facing));
    try std.testing.expectError(error.InvalidGestureId, gestureFromId(200));
}

test "tag grammar rejects missing extra and oversized fields" {
    // Arrange
    const missing = "happy/10";
    const extra = "happy/10/right/extra";
    const oversized = "happy/10/right";

    // Act and Assert
    try std.testing.expectError(error.MissingField, parseTag(missing));
    try std.testing.expectError(error.TooManyFields, parseTag(extra));
    try std.testing.expectError(error.TagTooLong, parseTagBounded(.{ .max_tag_bytes = 4 }, oversized));
}

test "formatting reports small output buffers" {
    // Arrange
    const pose = Pose{ .gesture = .scared, .intensity = 100, .facing = .left };
    var out: [8]u8 = undefined;

    // Act and Assert
    try std.testing.expectError(error.OutputTooSmall, formatTag(pose, &out));
}

test "message stores borrowed slices without ownership transfer" {
    // Arrange
    const allocator = std.testing.allocator;
    const owned_character = try allocator.dupe(u8, "artist");
    defer allocator.free(owned_character);
    const owned_said = try allocator.dupe(u8, "hello");
    defer allocator.free(owned_said);

    // Act
    const message = Message{
        .pose = .{ .gesture = .wave, .intensity = 80, .facing = .right },
        .character = owned_character,
        .said = owned_said,
    };

    // Assert
    try std.testing.expectEqual(Gesture.wave, message.pose.gesture);
    try std.testing.expectEqualStrings("artist", message.character);
    try std.testing.expectEqualStrings("hello", message.said);
}

fn upperTokenForTest(token: []const u8) []const u8 {
    if (std.mem.eql(u8, token, "neutral")) return "NEUTRAL";
    if (std.mem.eql(u8, token, "happy")) return "HAPPY";
    if (std.mem.eql(u8, token, "sad")) return "SAD";
    if (std.mem.eql(u8, token, "angry")) return "ANGRY";
    if (std.mem.eql(u8, token, "shout")) return "SHOUT";
    if (std.mem.eql(u8, token, "whisper")) return "WHISPER";
    if (std.mem.eql(u8, token, "laugh")) return "LAUGH";
    if (std.mem.eql(u8, token, "wave")) return "WAVE";
    if (std.mem.eql(u8, token, "think")) return "THINK";
    if (std.mem.eql(u8, token, "point")) return "POINT";
    if (std.mem.eql(u8, token, "love")) return "LOVE";
    if (std.mem.eql(u8, token, "bored")) return "BORED";
    if (std.mem.eql(u8, token, "scared")) return "SCARED";
    if (std.mem.eql(u8, token, "coy")) return "COY";
    unreachable;
}
