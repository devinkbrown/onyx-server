// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests retained from the mail sender implementation.

const builtin = @import("builtin");
const tls_client_failure = @import("../tls_client_failure.zig");
const sendTlsFatal = @import("tls_records.zig").sendTlsFatal;
const writeAll = @import("native_io.zig").writeAll;

test "TLS client fatal transport: mail_sender socket writer preserves control custody" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try tls_client_failure.testFatalTransportProof(true, writeAll);
}

test "TLS client fatal transport: mail_sender Windows socket writer preserves control custody" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    try tls_client_failure.testWindowsFatalTransportProof(true, sendTlsFatal);
}
