// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment mappings and rendered-record admission policy.

const std = @import("std");
const ClientId = @import("model.zig").ClientId;
const hard_max_records = @import("model.zig").hard_max_records;
const hard_max_attachments = @import("model.zig").hard_max_attachments;
const hard_max_total_bytes = @import("model.zig").hard_max_total_bytes;
const hard_max_record_bytes = @import("model.zig").hard_max_record_bytes;
const Config = @import("model.zig").Config;
const InitError = @import("model.zig").InitError;
const AttachmentRemap = @import("model.zig").AttachmentRemap;

pub fn mappedClient(mappings: []const AttachmentRemap, old_client: ClientId) ?ClientId {
    var low: usize = 0;
    var high = mappings.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (mappings[middle].old_client < old_client) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low == mappings.len or mappings[low].old_client != old_client) return null;
    return mappings[low].new_client;
}

pub fn validateConfig(config: Config) InitError!void {
    if (config.max_attachments == 0 or config.max_attachments > hard_max_attachments or
        config.max_records == 0 or config.max_records > hard_max_records or
        config.max_attachments > config.max_records or
        config.max_total_bytes == 0 or config.max_total_bytes > hard_max_total_bytes or
        config.max_record_bytes == 0 or config.max_record_bytes > hard_max_record_bytes or
        config.max_record_bytes > config.max_total_bytes) return error.InvalidConfig;
}

pub fn configsEqual(a: Config, b: Config) bool {
    return a.max_attachments == b.max_attachments and
        a.max_records == b.max_records and
        a.max_total_bytes == b.max_total_bytes and
        a.max_record_bytes == b.max_record_bytes;
}

pub fn validRenderedRecord(bytes: []const u8) bool {
    if (bytes.len < 2 or !std.mem.endsWith(u8, bytes, "\r\n")) return false;
    for (bytes[0 .. bytes.len - 2]) |byte| {
        if (byte == 0 or byte == '\r' or byte == '\n') return false;
    }
    return true;
}
