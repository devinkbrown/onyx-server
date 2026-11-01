// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete visible client-identity budgets, distinct from stored rule globs.
//! The daemon binds these values to actual dispatch field capacities at compile
//! time. USER may be absent after restore, so account is a supported ident.
pub const max_nick_bytes: usize = 64;
pub const max_uid_bytes: usize = 16;
pub const max_account_bytes: usize = 64;
pub const max_username_bytes = @max(max_uid_bytes, max_account_bytes);
pub const max_host_bytes: usize = 255;
pub const max_prefix_bytes = max_nick_bytes + max_username_bytes + max_host_bytes + 2;
pub const PrefixBuffer = [max_prefix_bytes]u8;
