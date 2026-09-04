// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `armor` CLI namespace root — one small module per subcommand, each a thin
//! front-end over the Armor crypto substrate (src/crypto/*, src/proto/*).
//! No crypto is implemented under src/cli/.

const std = @import("std");

pub const common = @import("common.zig");
pub const x509_cmd = @import("x509_cmd.zig");
pub const pkey_cmd = @import("pkey_cmd.zig");
pub const req_cmd = @import("req_cmd.zig");
pub const dgst_cmd = @import("dgst_cmd.zig");
pub const verify_cmd = @import("verify_cmd.zig");
pub const rand_cmd = @import("rand_cmd.zig");
pub const ciphers_cmd = @import("ciphers_cmd.zig");
pub const asn1parse_cmd = @import("asn1parse_cmd.zig");
pub const ocsp_cmd = @import("ocsp_cmd.zig");
pub const crl_cmd = @import("crl_cmd.zig");
pub const s_client_cmd = @import("s_client_cmd.zig");
pub const stub_cmds = @import("stub_cmds.zig");

test {
    std.testing.refAllDecls(@This());
    _ = common;
    _ = x509_cmd;
    _ = pkey_cmd;
    _ = req_cmd;
    _ = dgst_cmd;
    _ = verify_cmd;
    _ = rand_cmd;
    _ = ciphers_cmd;
    _ = asn1parse_cmd;
    _ = ocsp_cmd;
    _ = crl_cmd;
    _ = s_client_cmd;
    _ = stub_cmds;
}
