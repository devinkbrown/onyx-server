// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process IRC services over OroStore with typed results and no IRC I/O.
//! The owner retains lock and callback identity; domain views borrow bounded state.

pub const OroStore = @import("services/records.zig").OroStore;
pub const ScramStore = @import("services/records.zig").ScramStore;
pub const default_pbkdf2_rounds = @import("services/records.zig").default_pbkdf2_rounds;
pub const default_password_min_len = @import("services/records.zig").default_password_min_len;
pub const default_password_max_len = @import("services/records.zig").default_password_max_len;
pub const password_policy_min_len_max = @import("services/records.zig").password_policy_min_len_max;
pub const password_policy_max_len_min = @import("services/records.zig").password_policy_max_len_min;
pub const password_policy_max_len = @import("services/records.zig").password_policy_max_len;
pub const Config = @import("services/records.zig").Config;
pub const session_token_prefix = @import("services/records.zig").session_token_prefix;
pub const session_token_random_len = @import("services/records.zig").session_token_random_len;
pub const session_token_len = @import("services/records.zig").session_token_len;
pub const default_session_token_ttl_seconds = @import("services/records.zig").default_session_token_ttl_seconds;
pub const channel_access_family = @import("services/records.zig").channel_access_family;
pub const ServiceError = @import("services/records.zig").ServiceError;
pub const StateHook = @import("services/records.zig").StateHook;
pub const InlineText = @import("services/records.zig").InlineText;
pub const AccountName = @import("services/records.zig").AccountName;
pub const ChannelName = @import("services/records.zig").ChannelName;
pub const NickName = @import("services/records.zig").NickName;
pub const Email = @import("services/records.zig").Email;
pub const Mlock = @import("services/records.zig").Mlock;
pub const Mask = @import("services/records.zig").Mask;
pub const Reason = @import("services/records.zig").Reason;
pub const AccessLevel = @import("services/records.zig").AccessLevel;
pub const AccountSetField = @import("services/records.zig").AccountSetField;
pub const ChannelSetField = @import("services/records.zig").ChannelSetField;
pub const AccessAction = @import("services/records.zig").AccessAction;
pub const AkickAction = @import("services/records.zig").AkickAction;
pub const AccountRef = @import("services/records.zig").AccountRef;
pub const ChannelRef = @import("services/records.zig").ChannelRef;
pub const channel_flag_topiclock = @import("services/records.zig").channel_flag_topiclock;
pub const channel_flag_guard = @import("services/records.zig").channel_flag_guard;
pub const channel_flag_private = @import("services/records.zig").channel_flag_private;
pub const account_flag_suspended = @import("services/records.zig").account_flag_suspended;
pub const account_flag_forbidden = @import("services/records.zig").account_flag_forbidden;
pub const account_flag_noexpire = @import("services/records.zig").account_flag_noexpire;
pub const account_flag_enforce_off = @import("services/records.zig").account_flag_enforce_off;
pub const account_flag_secure = @import("services/records.zig").account_flag_secure;
pub const account_flag_passkey_only = @import("services/records.zig").account_flag_passkey_only;
pub const account_flag_oper_stepup = @import("services/records.zig").account_flag_oper_stepup;
pub const account_flags_privileged = @import("services/records.zig").account_flags_privileged;
pub const successor_hold_ms = @import("services/records.zig").successor_hold_ms;
pub const login_audit_cap = @import("services/records.zig").login_audit_cap;
pub const LoginMechanism = @import("services/records.zig").LoginMechanism;
pub const LoginTls = @import("services/records.zig").LoginTls;
pub const LoginAuditEntry = @import("services/records.zig").LoginAuditEntry;
pub const AccountInfo = @import("services/records.zig").AccountInfo;
pub const AccountAdminInfo = @import("services/records.zig").AccountAdminInfo;
pub const ChannelInfo = @import("services/records.zig").ChannelInfo;
pub const GhostInfo = @import("services/records.zig").GhostInfo;
pub const SessionTokenIssue = @import("services/records.zig").SessionTokenIssue;
pub const AccessInfo = @import("services/records.zig").AccessInfo;
pub const AkickInfo = @import("services/records.zig").AkickInfo;
pub const EmailVerifyResult = @import("services/records.zig").EmailVerifyResult;
pub const ReplayWard = @import("services/records.zig").ReplayWard;
pub const ReplaySaccess = @import("services/records.zig").ReplaySaccess;
pub const LiveReplaySummary = @import("services/records.zig").LiveReplaySummary;
pub const LiveReplaySink = @import("services/records.zig").LiveReplaySink;
pub const CommandResult = @import("services/records.zig").CommandResult;
pub const canonicalAccount = @import("services/records.zig").canonicalAccount;
pub const Services = @import("services/core.zig").Services;

comptime {
    if (@import("builtin").is_test) {
        _ = @import("services/test_account_props.zig");
        _ = @import("services/test_accounts.zig");
        _ = @import("services/test_auth_atomic.zig");
        _ = @import("services/test_channels.zig");
        _ = @import("services/test_credentials.zig");
        _ = @import("services/test_device_facts.zig");
        _ = @import("services/test_directory.zig");
        _ = @import("services/test_key_transparency.zig");
        _ = @import("services/test_oper_authority.zig");
        _ = @import("services/test_oper_clock.zig");
        _ = @import("services/test_oper_reconcile.zig");
        _ = @import("services/test_oper_reconcile_races.zig");
        _ = @import("services/test_sessions_mfa.zig");
        _ = @import("services/test_webpush.zig");
    }
}
