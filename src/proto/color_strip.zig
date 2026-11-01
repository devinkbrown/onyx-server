// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// Formatting control bytes recognized in IRC message text.
pub const Control = enum(u8) {
    bold = 0x02,
    color = 0x03,
    reset = 0x0f,
    monospace = 0x11,
    reverse = 0x16,
    italic = 0x1d,
    strike = 0x1e,
    underline = 0x1f,

    /// Return the control byte for this formatting code.
    pub fn byte(self: Control) u8 {
        return @backingInt(self);
    }

    /// Map one input byte to a known formatting control, if any.
    pub fn fromByte(byte_value: u8) ?Control {
        return switch (byte_value) {
            0x02 => .bold,
            0x03 => .color,
            0x0f => .reset,
            0x11 => .monospace,
            0x16 => .reverse,
            0x1d => .italic,
            0x1e => .strike,
            0x1f => .underline,
            else => null,
        };
    }
};

/// Compile-time limits for formatting strip operations.
pub const Params = struct {
    /// Maximum bytes that a stripped output slice may contain.
    max_output_bytes: usize = 512,
};

/// Errors returned by formatting strip operations.
pub const StripError = error{
    OutputTooSmall,
};

/// Stateless formatter stripper using compile-time limits.
pub fn Stripper(comptime params: Params) type {
    comptime {
        if (params.max_output_bytes == 0) @compileError("color stripper needs output storage");
    }

    return struct {
        const Self = @This();

        /// Construct a stateless stripper.
        pub fn init() Self {
            return .{};
        }

        /// Release resources held by the stripper.
        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        /// Copy input into `out` while removing all recognized formatting codes.
        pub fn strip(self: *const Self, input: []const u8, out: []u8) StripError![]u8 {
            _ = self;
            return stripFormattingWith(params, input, out);
        }

        /// Return true when `input` contains a recognized formatting code.
        pub fn has(self: *const Self, input: []const u8) bool {
            _ = self;
            return hasFormatting(input);
        }

        /// Count visible bytes after recognized formatting codes are removed.
        pub fn len(self: *const Self, input: []const u8) usize {
            _ = self;
            return visibleLen(input);
        }
    };
}

/// Default stateless formatter stripper.
pub const DefaultStripper = Stripper(.{});

/// Copy `input` into `out` while removing recognized formatting codes.
pub fn stripFormatting(input: []const u8, out: []u8) StripError![]u8 {
    return stripFormattingWith(.{}, input, out);
}

/// Copy `input` into `out` using caller-selected output limits.
pub fn stripFormattingWith(comptime params: Params, input: []const u8, out: []u8) StripError![]u8 {
    var read: usize = 0;
    var written: usize = 0;

    while (read < input.len) {
        if (Control.fromByte(input[read])) |control| {
            read = skipControl(input, read, control);
            continue;
        }

        if (written >= out.len or written >= params.max_output_bytes) return error.OutputTooSmall;
        out[written] = input[read];
        written += 1;
        read += 1;
    }

    return out[0..written];
}

/// Return true when `input` contains a recognized formatting code.
pub fn hasFormatting(input: []const u8) bool {
    var index: usize = 0;
    while (index < input.len) {
        if (Control.fromByte(input[index])) |control| {
            _ = skipControl(input, index, control);
            return true;
        }
        index += 1;
    }
    return false;
}

/// Count visible bytes after recognized formatting codes are removed.
pub fn visibleLen(input: []const u8) usize {
    var read: usize = 0;
    var len: usize = 0;

    while (read < input.len) {
        if (Control.fromByte(input[read])) |control| {
            read = skipControl(input, read, control);
            continue;
        }

        len += 1;
        read += 1;
    }

    return len;
}

fn skipControl(input: []const u8, start: usize, control: Control) usize {
    return switch (control) {
        .color => skipColor(input, start + 1),
        .bold, .reset, .monospace, .reverse, .italic, .strike, .underline => start + 1,
    };
}

fn skipColor(input: []const u8, start: usize) usize {
    var index = start;
    const fg_digits = consumeDigits(input, &index);
    if (fg_digits == 0) return index;

    if (index < input.len and input[index] == ',') {
        const comma = index;
        index += 1;
        const bg_digits = consumeDigits(input, &index);
        if (bg_digits == 0) return comma;
    }

    return index;
}

fn consumeDigits(input: []const u8, index: *usize) usize {
    var count: usize = 0;
    while (index.* < input.len and count < 2 and std.ascii.isDigit(input[index.*])) {
        index.* += 1;
        count += 1;
    }
    return count;
}

test "stripFormatting removes toggle controls without allocation leaks" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "a" ++
        [_]u8{Control.bold.byte()} ++ "b" ++
        [_]u8{Control.italic.byte()} ++ "c" ++
        [_]u8{Control.underline.byte()} ++ "d" ++
        [_]u8{Control.strike.byte()} ++ "e" ++
        [_]u8{Control.monospace.byte()} ++ "f" ++
        [_]u8{Control.reverse.byte()} ++ "g" ++
        [_]u8{Control.reset.byte()} ++ "h";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act
    const stripped = try stripFormatting(input, out);

    // Assert
    try std.testing.expectEqualStrings("abcdefgh", stripped);
    try std.testing.expect(hasFormatting(input));
    try std.testing.expectEqual(@as(usize, 8), visibleLen(input));
}

test "stripFormatting removes color with one digit foreground" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "hi " ++ [_]u8{Control.color.byte()} ++ "4red";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act
    const stripped = try stripFormatting(input, out);

    // Assert
    try std.testing.expectEqualStrings("hi red", stripped);
    try std.testing.expectEqual(@as(usize, 6), visibleLen(input));
}

test "stripFormatting removes color with two digit foreground and background" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "a" ++ [_]u8{Control.color.byte()} ++ "12,03paint";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act
    const stripped = try stripFormatting(input, out);

    // Assert
    try std.testing.expectEqualStrings("apaint", stripped);
    try std.testing.expectEqual(@as(usize, 6), visibleLen(input));
}

test "stripFormatting keeps color comma when background digits are absent" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "x" ++ [_]u8{Control.color.byte()} ++ "7, y";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act
    const stripped = try stripFormatting(input, out);

    // Assert
    try std.testing.expectEqualStrings("x, y", stripped);
    try std.testing.expectEqual(@as(usize, 4), visibleLen(input));
}

test "stripFormatting removes bare color control without consuming text digits" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "room " ++ [_]u8{Control.color.byte()} ++ " name";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);

    // Act
    const stripped = try stripFormatting(input, out);

    // Assert
    try std.testing.expectEqualStrings("room  name", stripped);
    try std.testing.expectEqual(@as(usize, 10), visibleLen(input));
}

test "stripFormatting respects output buffer and configured byte bounds" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = "plain";
    const tiny = try allocator.alloc(u8, 4);
    defer allocator.free(tiny);
    const enough = try allocator.alloc(u8, input.len);
    defer allocator.free(enough);

    // Act and assert
    try std.testing.expectError(error.OutputTooSmall, stripFormatting(input, tiny));
    try std.testing.expectError(error.OutputTooSmall, stripFormattingWith(.{ .max_output_bytes = 4 }, input, enough));
}

test "hasFormatting is false for plain text and true for color controls" {
    // Arrange
    const plain = "no decoration";
    const colored = "pre" ++ [_]u8{Control.color.byte()} ++ "01,02post";

    // Act
    const plain_has = hasFormatting(plain);
    const colored_has = hasFormatting(colored);

    // Assert
    try std.testing.expect(!plain_has);
    try std.testing.expect(colored_has);
    try std.testing.expectEqual(@as(usize, plain.len), visibleLen(plain));
    try std.testing.expectEqual(@as(usize, 7), visibleLen(colored));
}

test "DefaultStripper methods mirror module helpers" {
    // Arrange
    const allocator = std.testing.allocator;
    const input = [_]u8{Control.bold.byte()} ++ "bold";
    const out = try allocator.alloc(u8, input.len);
    defer allocator.free(out);
    var stripper = DefaultStripper.init();
    defer stripper.deinit();

    // Act
    const stripped = try stripper.strip(input, out);

    // Assert
    try std.testing.expectEqualStrings("bold", stripped);
    try std.testing.expect(stripper.has(input));
    try std.testing.expectEqual(@as(usize, 4), stripper.len(input));
}

// --- Exploit corpus: hostile mIRC colour bodies. Assert bounded strip work
// and fail-closed OutputTooSmall — never panic / never unbounded scan (CWE-400).

test "exploit: stripFormatting bounds a pathological colour-code flood (fail-closed)" {
    const allocator = std.testing.allocator;
    // Densest colour storm: 0x03 + two fg digits + comma + two bg digits,
    // repeated thousands of times, then a short visible tail. Pure algorithmic-
    // complexity pressure on the colour digit consumer.
    var input = std.ArrayList(u8).empty;
    defer input.deinit(allocator);
    try input.ensureTotalCapacity(allocator, 32 * 1024);
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        try input.append(allocator, Control.color.byte());
        try input.appendSlice(allocator, "12,03");
    }
    try input.appendSlice(allocator, "VISIBLE");

    // visibleLen / hasFormatting must stay O(n) and return without panic.
    try std.testing.expect(hasFormatting(input.items));
    try std.testing.expectEqual(@as(usize, 7), visibleLen(input.items));

    // Default 512-byte policy rejects an oversized visible body after strip
    // when the out buffer is tiny — fail-closed, not partial/corrupt output.
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, stripFormatting(input.items, &tiny));

    // With a large enough buffer + matching max_output_bytes the storm strips
    // cleanly to the visible tail (no colour digits leaked into the payload).
    const out = try allocator.alloc(u8, 64);
    defer allocator.free(out);
    const stripped = try stripFormattingWith(.{ .max_output_bytes = 64 }, input.items, out);
    try std.testing.expectEqualStrings("VISIBLE", stripped);
}

test "exploit: stripFormatting rejects oversize visible body without writing past out" {
    // Visible payload larger than the configured max_output_bytes must error
    // without a partial success that a caller could treat as complete.
    var input: [600]u8 = undefined;
    @memset(&input, 'A');
    input[0] = Control.color.byte();
    input[1] = '0';
    input[2] = '4';
    // After strip: 597 'A's (600 - 3 colour bytes). Default max is 512.
    var out: [600]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, stripFormatting(&input, &out));
    // Explicit high cap succeeds and returns the full visible body.
    const stripped = try stripFormattingWith(.{ .max_output_bytes = 600 }, &input, &out);
    try std.testing.expectEqual(@as(usize, 597), stripped.len);
    try std.testing.expect(std.mem.indexOfScalar(u8, stripped, Control.color.byte()) == null);
}
