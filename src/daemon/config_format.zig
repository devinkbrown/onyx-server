// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx Server daemon configuration: a typed `Config` projected from standard TOML.
//!
//! The canonical config format is **TOML v1.0** (parsed by `proto/toml.zig`).
//! `parseToml` reads a TOML document and overlays it onto a defaulted `Config`,
//! preserving the daemon's value conventions:
//!   * `env:NAME` / `@file:path` string indirection, resolved via `Resolver`.
//!   * durations as quoted strings: `"500ms"`, `"30s"`, `"5m"`, `"2h"`.
//!   * operators as a TOML array-of-tables: `[[opers]]` with `account`/`class`.
//! A field is overridden only when the document supplies it; otherwise the
//! defaults stand. Required: `[node].id` and `[listen].irc`.

const std = @import("std");
const testing = std.testing;

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("config_format requires a 64-bit target");
}

pub const LookupFn = @import("config_format/contracts.zig").LookupFn;
pub const Resolver = @import("config_format/contracts.zig").Resolver;
pub const acme_default_directory_url = @import("config_format/model.zig").acme_default_directory_url;
pub const Config = @import("config_format/model.zig").Config;
pub const TomlError = @import("config_format/contracts.zig").TomlError;
pub const containsOcg2Intent = @import("config_format/authority.zig").containsOcg2Intent;
pub const parseToml = @import("config_format/projection.zig").parseToml;
pub const ListenerSet = @import("config_format/listeners.zig").ListenerSet;
pub const cold_restart_required_reason = @import("config_format/listeners.zig").cold_restart_required_reason;
pub const listenerSetFromConfig = @import("config_format/listeners.zig").listenerSetFromConfig;
pub const listenerChangeError = @import("config_format/listeners.zig").listenerChangeError;

comptime {
    if (@import("builtin").is_test) {
        _ = @import("config_format/tests_core.zig");
        _ = @import("config_format/tests_authority.zig");
        _ = @import("config_format/tests_security.zig");
        _ = @import("config_format/tests_limits.zig");
        _ = @import("config_format/tests_mesh.zig");
    }
}

test {
    testing.refAllDecls(@This());
}
