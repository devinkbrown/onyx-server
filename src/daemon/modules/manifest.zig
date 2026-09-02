// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SerpentRegistry module manifest — the single place modules are listed.
//!
//! Adding a module is one line here. A disabled module (deleted line) is
//! dead-code-eliminated. Duplicate commands/caps/modes/numerics across modules,
//! missing dependencies, and conflicts are all rejected at COMPILE TIME by
//! `registry.Registry` (it `@compileError`s) — never at runtime. See
//! `docs/planning/17-module-system.md` §2.
const registry = @import("../registry.zig");

const query_info = @import("query_info.zig");
const channel_ops = @import("channel_ops.zig");
const messaging = @import("messaging.zig");
const accounts = @import("accounts.zig");
const ircx = @import("ircx.zig");
const oper_security = @import("oper_security.zig");
const user_query = @import("user_query.zig");
const feature_misc = @import("feature_misc.zig");
const introspect = @import("introspect.zig");
const upgrade = @import("upgrade.zig");
const services_ext = @import("services_ext.zig");
const webhook = @import("webhook.zig");

/// The enabled module set. Order is load/dispatch order for ties.
pub const enabled = [_]registry.Module{
    query_info.module,
    channel_ops.module,
    messaging.module,
    accounts.module,
    ircx.module,
    oper_security.module,
    user_query.module,
    feature_misc.module,
    introspect.module,
    upgrade.module,
    services_ext.module,
    webhook.module,
};

/// Comptime-assembled + comptime-validated live registry. Referencing `Live`
/// from the server forces the validation to run at build time. The branch quota
/// is raised because validation is O(commands^2) over the full command set.
pub const Live = blk: {
    @setEvalBranchQuota(200_000);
    break :blk registry.Registry(&enabled);
};

test {
    // Importing a module file for its `module` declaration does NOT register
    // that file's `test` blocks with the test runner — only an explicit
    // reference does. Without this block every modules/*.zig test silently
    // never runs. Keep one line per enabled module.
    _ = query_info;
    _ = channel_ops;
    _ = messaging;
    _ = accounts;
    _ = ircx;
    _ = oper_security;
    _ = user_query;
    _ = feature_misc;
    _ = introspect;
    _ = upgrade;
    _ = services_ext;
    _ = webhook;
}
