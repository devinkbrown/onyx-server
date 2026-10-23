// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound HTTP facade. Implementation is grouped by request policy,
//! DNS resolution, native I/O, and TLS exchange; public types retain one owner.

pub const Error = @import("http_fetch/contracts.zig").Error;
pub const Url = @import("http_fetch/url.zig").Url;
pub const parseUrl = @import("http_fetch/url.zig").parseUrl;
pub const Options = @import("http_fetch/contracts.zig").Options;
pub const get = @import("http_fetch/client.zig").get;
pub const getAtAddress = @import("http_fetch/client.zig").getAtAddress;
pub const post = @import("http_fetch/client.zig").post;
pub const postSigned = @import("http_fetch/client.zig").postSigned;
pub const postSignedAtAddress = @import("http_fetch/client.zig").postSignedAtAddress;
pub const resolveHostA = @import("http_fetch/resolution.zig").resolveHostA;
pub const resolveHostAAAA = @import("http_fetch/resolution.zig").resolveHostAAAA;
pub const HostFamilies = @import("http_fetch/contracts.zig").HostFamilies;
pub const resolveHostFamilies = @import("http_fetch/resolution.zig").resolveHostFamilies;

test {
    _ = @import("http_fetch/tests_windows_dns.zig");
    _ = @import("http_fetch/tests_windows_http.zig");
    _ = @import("http_fetch/tests_policy.zig");
    _ = @import("http_fetch/tests_native_io.zig");
    _ = @import("http_fetch/tests_dns.zig");
    _ = @import("http_fetch/tests_single_family_dns.zig");
    _ = @import("http_fetch/tests_parallel_dns.zig");
    _ = @import("http_fetch/tests_tls_control.zig");
}
