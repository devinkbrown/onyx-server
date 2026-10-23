// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cross-node route table for UNDERTOW message fan-out.
//!
//! The table is pure state: callers own all I/O decisions and pass allocator
//! ownership in at init. String keys are copied into managed StringHashMaps and
//! released on removal/deinit. This facade preserves the historical import path.
const core = @import("route_table/core.zig");

pub const NodeId = core.NodeId;
pub const SessionToken = core.SessionToken;
pub const NickClaim = core.NickClaim;
pub const LocalNickResolver = core.LocalNickResolver;
pub const NickDecision = core.NickDecision;
pub const Error = core.Error;
pub const Config = core.Config;
pub const MembershipChange = core.MembershipChange;
pub const Member = core.Member;
pub const MemberIdentity = core.MemberIdentity;
pub const SessionTokenReconcileObserver = core.SessionTokenReconcileObserver;
pub const SessionTokenReconcileResult = core.SessionTokenReconcileResult;
pub const SessionTokenNickMatch = core.SessionTokenNickMatch;
pub const ChannelListKind = core.ChannelListKind;
pub const ChannelListEntry = core.ChannelListEntry;
pub const ChannelModeFlags = core.ChannelModeFlags;
pub const TopicClock = core.TopicClock;
pub const TopicView = core.TopicView;
pub const RouteTable = core.RouteTable;

test {
    _ = @import("route_table/tests_basic.zig");
    _ = @import("route_table/tests_membership.zig");
    _ = @import("route_table/tests_collision.zig");
    _ = @import("route_table/tests_convergence.zig");
}
