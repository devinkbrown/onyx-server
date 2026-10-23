// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration regression tests: limits.

const std = @import("std");
const content_filter_mod = @import("../content_filter.zig");
const services_mod = @import("../services.zig");
const store_mod = @import("../store.zig");
const memo_mod = @import("../memo.zig");
const transcript_mod = @import("../transcript.zig");
const cadence_frame = @import("../../substrate/cadence_frame.zig");
const media_room = @import("../media_room.zig");
const multiline_mod = @import("../../proto/multiline.zig");
const search_index_mod = @import("../search_index.zig");
const testing = std.testing;
const Config = @import("model.zig").Config;
const parseToml = @import("projection.zig").parseToml;

test "parseToml: [accounts] pbkdf2 rounds project with bounded policy range" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 250000
        \\password_min_len = 12
        \\password_max_len = 1024
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 250_000), cfg.accounts.pbkdf2_rounds);
    try testing.expectEqual(@as(u64, 12), cfg.accounts.password_min_len);
    try testing.expectEqual(@as(u64, 1024), cfg.accounts.password_max_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(services_mod.default_pbkdf2_rounds, omitted.accounts.pbkdf2_rounds);
    try testing.expectEqual(@as(u64, services_mod.default_password_min_len), omitted.accounts.password_min_len);
    try testing.expectEqual(@as(u64, services_mod.default_password_max_len), omitted.accounts.password_max_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 9999
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\pbkdf2_rounds = 10000001
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\password_min_len = 65
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[accounts]
        \\password_max_len = 63
        \\
    , .{}));
}

test "parseToml: [bouncer] memo limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\memo_text_max_len = 512
        \\memo_from_max_len = 48
        \\memo_mailbox_depth = 16
        \\memo_max_accounts = 2048
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 512), cfg.bouncer.memo_text_max_len);
    try testing.expectEqual(@as(u64, 48), cfg.bouncer.memo_from_max_len);
    try testing.expectEqual(@as(u64, 16), cfg.bouncer.memo_mailbox_depth);
    try testing.expectEqual(@as(u64, 2048), cfg.bouncer.memo_max_accounts);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, memo_mod.default_max_text_bytes), omitted.bouncer.memo_text_max_len);
    try testing.expectEqual(@as(u64, memo_mod.default_max_from_bytes), omitted.bouncer.memo_from_max_len);
    try testing.expectEqual(@as(u64, memo_mod.default_max_per_account), omitted.bouncer.memo_mailbox_depth);
    try testing.expectEqual(@as(u64, memo_mod.default_max_accounts), omitted.bouncer.memo_max_accounts);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\memo_text_max_len = 63
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[bouncer]
        \\memo_mailbox_depth = 1025
        \\
    , .{}));
}

test "parseToml: [sessions] registry and composite issuance parse with safe defaults" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\max_accounts = 2048
        \\max_per_account = 9
        \\resume_composite_issuance = false
        \\migrate_on_detach = false
        \\max_pending_migrations = 128
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 2048), cfg.sessions.max_accounts);
    try testing.expectEqual(@as(u32, 9), cfg.sessions.max_per_account);
    try testing.expect(!cfg.sessions.resume_composite_issuance);
    try testing.expect(!cfg.sessions.migrate_on_detach);
    try testing.expectEqual(@as(u32, 128), cfg.sessions.max_pending_migrations);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, 65536), omitted.sessions.max_accounts);
    try testing.expectEqual(@as(u32, 64), omitted.sessions.max_per_account);
    try testing.expect(!omitted.sessions.resume_composite_issuance);
    try testing.expect(omitted.sessions.migrate_on_detach);
    try testing.expectEqual(@as(u32, 4096), omitted.sessions.max_pending_migrations);

    var enabled = try parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\resume_composite_issuance = true
        \\
    , .{});
    defer enabled.deinit(allocator);
    try testing.expect(enabled.sessions.resume_composite_issuance);

    // Zero and above-max are hard parse errors, never a silent clamp.
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\max_per_account = 0
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\max_per_account = 65536
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[sessions]
        \\max_accounts = 0
        \\
    , .{}));
}

test "parseToml: [filter] koshi limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_max_patterns = 512
        \\koshi_pattern_max_len = 128
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 512), cfg.filter.koshi_max_patterns);
    try testing.expectEqual(@as(u64, 128), cfg.filter.koshi_pattern_max_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, content_filter_mod.default_max_patterns), omitted.filter.koshi_max_patterns);
    try testing.expectEqual(@as(u64, content_filter_mod.default_max_pattern_len), omitted.filter.koshi_pattern_max_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_max_patterns = 15
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[filter]
        \\koshi_pattern_max_len = 1025
        \\
    , .{}));
}

test "parseToml: [history.search] limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_words = 4096
        \\max_ids_per_word = 128
        \\max_token_bytes = 32
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 4096), cfg.history.search_max_words);
    try testing.expectEqual(@as(u64, 128), cfg.history.search_max_ids_per_word);
    try testing.expectEqual(@as(u64, 32), cfg.history.search_max_token_bytes);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    const defaults = search_index_mod.SearchIndex.Config{};
    try testing.expectEqual(@as(u64, defaults.max_words), omitted.history.search_max_words);
    try testing.expectEqual(@as(u64, defaults.max_ids_per_word), omitted.history.search_max_ids_per_word);
    try testing.expectEqual(@as(u64, defaults.max_token_bytes), omitted.history.search_max_token_bytes);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_words = 255
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_ids_per_word = 15
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[history.search]
        \\max_token_bytes = 257
        \\
    , .{}));
}

test "parseToml: [ircv3] multiline limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_bytes = 8192
        \\multiline_max_lines = 8
        \\multiline_ref_len = 32
        \\multiline_target_len = 64
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u64, 8192), cfg.ircv3.multiline_max_bytes);
    try testing.expectEqual(@as(u64, 8), cfg.ircv3.multiline_max_lines);
    try testing.expectEqual(@as(u64, 32), cfg.ircv3.multiline_ref_len);
    try testing.expectEqual(@as(u64, 64), cfg.ircv3.multiline_target_len);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_bytes), omitted.ircv3.multiline_max_bytes);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_lines), omitted.ircv3.multiline_max_lines);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_ref_len), omitted.ircv3.multiline_ref_len);
    try testing.expectEqual(@as(u64, multiline_mod.default_max_target_len), omitted.ircv3.multiline_target_len);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_bytes = 4095
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_max_lines = 1
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_ref_len = 129
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[ircv3]
        \\multiline_target_len = 7
        \\
    , .{}));
}

test "parseToml: [storage] store limits project with bounded policy ranges" {
    const allocator = testing.allocator;
    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_record_bytes = 131072
        \\max_wal_bytes = 2097152
        \\changefeed_capacity = 128
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(usize, 131072), cfg.storage.max_record_bytes);
    try testing.expectEqual(@as(usize, 2097152), cfg.storage.max_wal_bytes);
    try testing.expectEqual(@as(usize, 128), cfg.storage.changefeed_capacity);

    var omitted = try parseToml(allocator, "[node]\nid = 1\n[listen]\nirc = 6680\n", .{});
    defer omitted.deinit(allocator);
    const store_defaults = store_mod.Config{};
    try testing.expectEqual(store_defaults.max_record_bytes, omitted.storage.max_record_bytes);
    try testing.expectEqual(store_defaults.max_wal_bytes, omitted.storage.max_wal_bytes);
    try testing.expectEqual(store_defaults.changefeed_capacity, omitted.storage.changefeed_capacity);

    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_record_bytes = 65535
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\max_wal_bytes = 4294967297
        \\
    , .{}));
    try testing.expectError(error.ParseError, parseToml(allocator,
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[storage]
        \\changefeed_capacity = 7
        \\
    , .{}));
}

test "parseToml: media.dtls_srtp defaults off and lifts when set" {
    const allocator = testing.allocator;
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expect(!dflt.media.dtls_srtp);

    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\ndtls_srtp = true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.media.dtls_srtp);
}

test "parseToml: media.dtls13 defaults off and lifts independently of dtls_srtp" {
    const allocator = testing.allocator;
    var dflt = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n", .{});
    defer dflt.deinit(allocator);
    try testing.expect(!dflt.media.dtls13);

    var cfg = try parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\ndtls_srtp = true\ndtls13 = true\n", .{});
    defer cfg.deinit(allocator);
    try testing.expect(cfg.media.dtls_srtp);
    try testing.expect(cfg.media.dtls13);
}

test "GAP-V4 config refuses a hidden recorder" {
    const allocator = testing.allocator;
    try testing.expectError(error.HiddenRecorderRefused, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\nhidden_recorder = true\n", .{}));
    try testing.expectError(error.HiddenRecorderRefused, parseToml(allocator, "[node]\nid=1\n[listen]\nirc=6680\n[media]\nrecord_without_consent = true\n", .{}));
}

test "parseToml: media sizing keys default, lift, and validate ranges" {
    const allocator = testing.allocator;
    const base =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\
    ;
    var dflt = try parseToml(allocator, base, .{});
    defer dflt.deinit(allocator);
    try testing.expectEqual(cadence_frame.default_reorder_window_frames, dflt.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, @intCast(media_room.default_max_participants)), dflt.media.max_participants);
    try testing.expectEqual(@as(u64, transcript_mod.max_text_bytes), dflt.media.captions_max_text_bytes);
    try testing.expectEqual(@as(u64, transcript_mod.max_speaker_bytes), dflt.media.captions_max_speaker_bytes);
    try testing.expectEqual(@as(u64, transcript_mod.max_per_channel), dflt.media.captions_ring_depth_per_channel);
    try testing.expectEqual(@as(u64, transcript_mod.max_channels), dflt.media.captions_max_channels);
    try testing.expectEqual(@as(u64, media_room.max_breakout_bytes), dflt.media.sfu_max_breakout_label_bytes);
    try testing.expectEqual(@as(u64, 50), dflt.media.pins_max_per_channel);
    try testing.expectEqual(@as(u64, 64), dflt.media.pins_max_msgid_bytes);
    try testing.expectEqual(@as(u64, 32), dflt.media.reactions_max_token_bytes);

    const text =
        \\[node]
        \\id = 1
        \\[listen]
        \\irc = 6680
        \\[media]
        \\reorder_window_frames = 32
        \\max_participants = 2
        \\captions_max_text_bytes = 512
        \\captions_max_speaker_bytes = 32
        \\captions_ring_depth_per_channel = 16
        \\captions_max_channels = 128
        \\[media.sfu]
        \\max_breakout_label_bytes = 16
        \\[media.pins]
        \\max_per_channel = 10
        \\max_msgid_bytes = 32
        \\[media.reactions]
        \\max_token_bytes = 24
        \\
    ;
    var cfg = try parseToml(allocator, text, .{});
    defer cfg.deinit(allocator);
    try testing.expectEqual(@as(u32, 32), cfg.media.reorder_window_frames);
    try testing.expectEqual(@as(u32, 2), cfg.media.max_participants);
    try testing.expectEqual(@as(u64, 512), cfg.media.captions_max_text_bytes);
    try testing.expectEqual(@as(u64, 32), cfg.media.captions_max_speaker_bytes);
    try testing.expectEqual(@as(u64, 16), cfg.media.captions_ring_depth_per_channel);
    try testing.expectEqual(@as(u64, 128), cfg.media.captions_max_channels);
    try testing.expectEqual(@as(u64, 16), cfg.media.sfu_max_breakout_label_bytes);
    try testing.expectEqual(@as(u64, 10), cfg.media.pins_max_per_channel);
    try testing.expectEqual(@as(u64, 32), cfg.media.pins_max_msgid_bytes);
    try testing.expectEqual(@as(u64, 24), cfg.media.reactions_max_token_bytes);

    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nreorder_window_frames = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\nmax_participants = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_text_bytes = 63\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_speaker_bytes = 15\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_ring_depth_per_channel = 15\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media]\ncaptions_max_channels = 63\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.sfu]\nmax_breakout_label_bytes = 7\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.pins]\nmax_per_channel = 0\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.pins]\nmax_msgid_bytes = 7\n", .{}));
    try testing.expectError(error.ParseError, parseToml(allocator, base ++ "[media.reactions]\nmax_token_bytes = 7\n", .{}));

    const too_wide_window = try std.fmt.allocPrint(allocator, "{s}[media]\nreorder_window_frames = {d}\n", .{ base, cadence_frame.window_cap + 1 });
    defer allocator.free(too_wide_window);
    try testing.expectError(error.ParseError, parseToml(allocator, too_wide_window, .{}));

    const too_many_participants = try std.fmt.allocPrint(allocator, "{s}[media]\nmax_participants = {d}\n", .{ base, media_room.max_participants + 1 });
    defer allocator.free(too_many_participants);
    try testing.expectError(error.ParseError, parseToml(allocator, too_many_participants, .{}));
}
