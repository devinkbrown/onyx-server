// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! accounts module — account/services command family (register, identify,
//! channel registration, ghost, multi-session). Thin thunks over existing
//! LinuxServer handlers. See 17-module-system.md.
const registry = @import("../registry.zig");
const Core = @import("../module_core.zig").Core;
const I = registry.CommandInvocation;
const accounts_feature = "accounts";

fn register(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRegister(x.conn, x.parsed);
}
fn verify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleVerify(x.conn, x.parsed);
}
fn identify(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIdentify(x.conn, x.parsed);
}
fn totp(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleTotp(x.conn, x.parsed);
}
fn recoverycodes(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRecoveryCodes(x.conn, x.parsed);
}
fn logout(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleLogout(x.id, x.conn);
}
fn drop(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleDrop(x.conn, x.parsed);
}
fn setpass(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSetpass(x.conn, x.parsed);
}
fn resetpass(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleResetpass(x.conn, x.parsed);
}
fn successor(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSuccessor(x.conn, x.parsed);
}
fn accountInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountInfo(x.conn, x.parsed);
}
fn account(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountAdmin(x.conn, x.parsed);
}
fn saslInfo(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSaslInfo(x.conn);
}
fn accountSet(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleAccountSet(x.conn, x.parsed);
}
fn ghost(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleGhost(x.conn, x.parsed);
}
fn recover(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRecover(x.conn, x.parsed);
}
fn release(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRelease(x.conn, x.parsed);
}
fn channel(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleChannel(x.conn, x.parsed);
}
fn session(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSession(x.id, x.conn, x.parsed);
}
fn sessionToken(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleSessionToken(x.conn);
}
fn certAdd(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertAdd(x.conn);
}
fn webauthn(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleWebauthn(x.conn, x.parsed);
}
fn keytrans(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleKeyTrans(x.conn, x.parsed);
}
fn e2eeKey(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleE2eeKey(x.conn, x.parsed);
}
fn e2eeGroup(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleE2eeGroup(x.conn, x.parsed);
}
fn identity(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleIdentity(x.conn, x.parsed);
}
fn certList(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertList(x.conn);
}
fn certDel(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleCertDel(x.conn, x.parsed);
}
fn recognize(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleRecognize(x.conn, x.parsed);
}
fn listchans(c: *anyopaque, _: I) anyerror!void {
    const x = Core.from(c);
    try x.server.handleListchans(x.conn, x.parsed);
}

pub const REGISTER_spec = registry.CommandSpec{ .name = "REGISTER", .feature = accounts_feature, .handler = register };
pub const VERIFY_spec = registry.CommandSpec{ .name = "VERIFY", .feature = accounts_feature, .handler = verify };
pub const IDENTIFY_spec = registry.CommandSpec{ .name = "IDENTIFY", .feature = accounts_feature, .handler = identify };
pub const TOTP_spec = registry.CommandSpec{ .name = "TOTP", .min_params = 1, .feature = accounts_feature, .handler = totp, .summary = "manage two-factor auth (ENROLL|CONFIRM|DISABLE|STATUS)" };
pub const RECOVERYCODES_spec = registry.CommandSpec{ .name = "RECOVERYCODES", .min_params = 1, .feature = accounts_feature, .handler = recoverycodes, .summary = "offline recovery codes (STATUS|GENERATE|CLEAR|LOGIN)" };
pub const LOGOUT_spec = registry.CommandSpec{ .name = "LOGOUT", .feature = accounts_feature, .handler = logout };
pub const DROP_spec = registry.CommandSpec{ .name = "DROP", .feature = accounts_feature, .handler = drop };
pub const SETPASS_spec = registry.CommandSpec{ .name = "SETPASS", .feature = accounts_feature, .handler = setpass, .summary = "change your account password (current + new)" };
pub const RESETPASS_spec = registry.CommandSpec{ .name = "RESETPASS", .min_params = 1, .feature = accounts_feature, .handler = resetpass, .summary = "reset a forgotten password via an emailed code" };
pub const SUCCESSOR_spec = registry.CommandSpec{ .name = "SUCCESSOR", .feature = accounts_feature, .handler = successor, .summary = "set a registered channel's founder successor (SHOW|SET|CLEAR)" };
pub const ACCOUNTINFO_spec = registry.CommandSpec{ .name = "ACCOUNTINFO", .feature = accounts_feature, .handler = accountInfo };
pub const ACCOUNT_spec = registry.CommandSpec{ .name = "ACCOUNT", .access = .oper, .feature = accounts_feature, .handler = account, .summary = "administer account lifecycle flags" };
pub const SASLINFO_spec = registry.CommandSpec{ .name = "SASLINFO", .handler = saslInfo };
pub const ACCOUNTSET_spec = registry.CommandSpec{ .name = "ACCOUNTSET", .feature = accounts_feature, .handler = accountSet };
pub const GHOST_spec = registry.CommandSpec{ .name = "GHOST", .feature = accounts_feature, .handler = ghost };
pub const RECOVER_spec = registry.CommandSpec{ .name = "RECOVER", .feature = accounts_feature, .handler = recover, .summary = "force an unauthenticated holder off your registered nick" };
pub const RELEASE_spec = registry.CommandSpec{ .name = "RELEASE", .feature = accounts_feature, .handler = release, .summary = "drop a server hold on your registered nick" };
pub const CHANNEL_spec = registry.CommandSpec{ .name = "CHANNEL", .feature = accounts_feature, .handler = channel };
pub const CS_spec = registry.CommandSpec{ .name = "CS", .feature = accounts_feature, .handler = channel };
pub const SESSION_spec = registry.CommandSpec{ .name = "SESSION", .feature = accounts_feature, .handler = session };
pub const SESSIONTOKEN_spec = registry.CommandSpec{ .name = "SESSIONTOKEN", .feature = accounts_feature, .handler = sessionToken };
pub const CERTADD_spec = registry.CommandSpec{ .name = "CERTADD", .feature = accounts_feature, .handler = certAdd };
pub const WEBAUTHN_spec = registry.CommandSpec{ .name = "WEBAUTHN", .min_params = 1, .feature = accounts_feature, .handler = webauthn, .summary = "manage passkeys / passwordless login (REGISTER|REGISTER-FINISH|AUTH|AUTH-FINISH|LIST|REMOVE|RENAME|STATUS)" };
pub const KEYTRANS_spec = registry.CommandSpec{ .name = "KEYTRANS", .feature = accounts_feature, .handler = keytrans, .summary = "inspect account credential transparency roots and inclusion proofs" };
pub const E2EEKEY_spec = registry.CommandSpec{ .name = "E2EEKEY", .feature = accounts_feature, .handler = e2eeKey, .summary = "manage public E2EE device keys (ADD|LIST|DEL|STATUS)" };
pub const E2EEGROUP_spec = registry.CommandSpec{ .name = "E2EEGROUP", .min_params = 4, .feature = accounts_feature, .handler = e2eeGroup, .summary = "relay bounded opaque group E2EE control records" };
pub const IDENTITY_spec = registry.CommandSpec{ .name = "IDENTITY", .feature = accounts_feature, .handler = identity, .summary = "manage portable account identity keys (ADD|LIST|DEL|STATUS|VERIFY)" };
pub const CERTLIST_spec = registry.CommandSpec{ .name = "CERTLIST", .feature = accounts_feature, .handler = certList };
pub const CERTDEL_spec = registry.CommandSpec{ .name = "CERTDEL", .feature = accounts_feature, .handler = certDel };
pub const RECOGNIZE_spec = registry.CommandSpec{ .name = "RECOGNIZE", .feature = accounts_feature, .handler = recognize, .summary = "manage your account host-recognition list (ADD|DEL|LIST)" };
pub const LISTCHANS_spec = registry.CommandSpec{ .name = "LISTCHANS", .feature = accounts_feature, .handler = listchans, .summary = "list registered channels where you hold access" };

pub const module = registry.Module{
    .id = "accounts",
    .commands = &.{
        REGISTER_spec,
        VERIFY_spec,
        IDENTIFY_spec,
        TOTP_spec,
        RECOVERYCODES_spec,
        LOGOUT_spec,
        DROP_spec,
        SETPASS_spec,
        RESETPASS_spec,
        SUCCESSOR_spec,
        ACCOUNTINFO_spec,
        ACCOUNT_spec,
        SASLINFO_spec,
        ACCOUNTSET_spec,
        GHOST_spec,
        RECOVER_spec,
        RELEASE_spec,
        CHANNEL_spec,
        CS_spec,
        SESSION_spec,
        SESSIONTOKEN_spec,
        CERTADD_spec,
        CERTLIST_spec,
        CERTDEL_spec,
        WEBAUTHN_spec,
        KEYTRANS_spec,
        E2EEKEY_spec,
        E2EEGROUP_spec,
        IDENTITY_spec,
        RECOGNIZE_spec,
        LISTCHANS_spec,
    },
};

test "accounts commands are feature gated except SASLINFO" {
    const caps = registry.DispatchCaps{ .registered = true, .oper = true, .disabled_features = &.{"accounts"} };

    try @import("std").testing.expect(!registry.commandAvailable(REGISTER_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(CHANNEL_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(SESSIONTOKEN_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(WEBAUTHN_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(KEYTRANS_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(E2EEKEY_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(E2EEGROUP_spec, caps));
    try @import("std").testing.expect(!registry.commandAvailable(IDENTITY_spec, caps));
    try @import("std").testing.expect(registry.commandAvailable(SASLINFO_spec, caps));
}
