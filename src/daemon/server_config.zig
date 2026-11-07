// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon runtime configuration and borrowed boot authorities.
//! Parsing, normalization, and lifecycle transitions remain with their owners.

const std = @import("std");
const linux = std.os.linux;
const wasm_abi = @import("../wasm/host/abi.zig");
const wasm_bridge = @import("../wasm/host/bridge.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const relay_v2_activation = @import("relay_v2_activation.zig");
const sasl = @import("../proto/sasl.zig");
const sasl_mechrouter = @import("../proto/sasl_mechrouter.zig");
const multiline = @import("../proto/multiline.zig");
const search_index_mod = @import("search_index.zig");
const s2s_link = @import("s2s_link.zig");
const rdns = @import("rdns.zig");
const dnsbl_resolver = @import("dnsbl_resolver.zig");
const mail_sender = @import("mail_sender.zig");
const protocol_inventory = @import("../proto/protocol_inventory.zig");
const cloak = @import("../proto/cloak.zig");
const content_filter_mod = @import("content_filter.zig");
const media_room = @import("media_room.zig");
const tls_server = @import("../crypto/tls_server.zig");
const memo_mod = @import("memo.zig");
const transcript_mod = @import("transcript.zig");
const node_identity = @import("node_identity.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const rsa_sign = @import("../crypto/rsa_sign.zig");
const oper_mod = @import("oper.zig");
const conn_class = @import("conn_class.zig");
const config_format = @import("config_format.zig");
const services_mod = @import("services.zig");
const ocg2_runtime_mod = @import("ocg2_runtime.zig");
const ocg2_projection_mod = @import("ocg2_projection_runtime.zig");
const audit_trail_mod = @import("audit_trail.zig");
const durable_credential_props = @import("durable_credential_props.zig");
const reactor_mod = @import("../substrate/reactor.zig");
const ringlane = @import("ringlane.zig");
const RingFeatureSet = ringlane.RingFeatures;

const native_upgrade = @import("native_upgrade_contracts.zig");
const ListenerDescriptor = native_upgrade.ListenerDescriptor;
const NativeUpgradeHooks = native_upgrade.NativeUpgradeHooks;
const NativeAdoptBarrier = native_upgrade.NativeAdoptBarrier;

pub const server_name = "onyx.local";

pub const DurableDeviceBoot = union(enum) {
    inactive,
    /// Explicit migration/test mode: remove every legacy device PROP and its
    /// clock without installing a durable authority. Production main never
    /// selects this arm.
    purge_only,
    authoritative: struct {
        /// Strictly restored from the configured account OroStore before the
        /// server is constructed. The owner must outlive both Services and the
        /// server.
        state: *durable_credential_props.State,
        local_origin_node: u64,
    },
};

/// The daemon runtime configuration. This used to be a hand-maintained copy
/// of `server.Config` with no importer; it had already drifted (27 fields
/// missing, including the Armor wave 2a/2b `tls_groups`,
/// `tls_delegated_credentials`, `webtransport_quic` and `geo_news_ca_bundle*`).
/// It is now the live type itself, so it cannot diverge again.
pub const Config = @import("server.zig").Config;

test "server_config.Config is the live server Config, never a drifting copy" {
    comptime std.debug.assert(Config == @import("server.zig").Config);
    inline for (.{ "tls_groups", "tls_delegated_credentials", "webtransport_quic", "geo_news_ca_bundle", "geo_news_ca_bundle_max_bytes" }) |field| {
        try std.testing.expect(@hasField(Config, field));
    }
}
