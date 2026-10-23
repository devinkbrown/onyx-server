// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocator-backed IRCX PROP storage, parsing, and reply rendering.
//! Stable public entry point for the policy, protocol, transactional store, and
//! detached checkpoint codec in `ircx_prop_store/`.

const model = @import("ircx_prop_store/model.zig");
const store = @import("ircx_prop_store/store.zig");
const protocol = @import("ircx_prop_store/protocol.zig");

pub const default_max_entities = model.default_max_entities;
pub const default_max_props_per_entity = model.default_max_props_per_entity;
pub const user_max_props_per_entity = model.user_max_props_per_entity;
pub const default_max_entity_id = model.default_max_entity_id;
pub const default_max_key = model.default_max_key;
pub const default_max_value = model.default_max_value;
pub const default_max_owner_bytes = model.default_max_owner_bytes;
pub const default_max_request_keys = model.default_max_request_keys;
pub const user_profile_max_value = model.user_profile_max_value;
pub const Params = model.Params;
pub const PropError = model.PropError;
pub const PreparedGlobalPurgeError = model.PreparedGlobalPurgeError;
pub const PreparedSetAllocationError = model.PreparedSetAllocationError;
pub const CheckpointError = model.CheckpointError;
pub const prop_checkpoint_max_bytes = model.prop_checkpoint_max_bytes;
pub const EntityKind = model.EntityKind;
pub const Entity = model.Entity;
pub const AccessLevel = model.AccessLevel;
pub const Setter = model.Setter;
pub const ChannelPropKey = model.ChannelPropKey;
pub const ChannelPropInfo = model.ChannelPropInfo;
pub const channelPropKey = model.channelPropKey;
pub const lagSeconds = model.lagSeconds;
pub const channelPropInfo = model.channelPropInfo;
pub const UserProfilePropKey = model.UserProfilePropKey;
pub const UserProfilePropInfo = model.UserProfilePropInfo;
pub const userProfilePropKey = model.userProfilePropKey;
pub const userProfilePropInfo = model.userProfilePropInfo;
pub const EntryView = model.EntryView;
pub const QueryRequest = model.QueryRequest;
pub const MutationRequest = model.MutationRequest;
pub const KeyRequest = model.KeyRequest;
pub const Request = model.Request;
pub const PropStore = store.PropStore;
pub const DefaultStore = store.DefaultStore;
pub const parseLine = protocol.parseLine;
pub const parseLineBounded = protocol.parseLineBounded;
pub const parseParamsBounded = protocol.parseParamsBounded;
pub const buildPropMessage = protocol.buildPropMessage;
pub const buildPropListReply = protocol.buildPropListReply;
pub const buildPropEndReply = protocol.buildPropEndReply;

test {
    _ = @import("ircx_prop_store/mutation_tests.zig");
    _ = @import("ircx_prop_store/protocol_tests.zig");
    _ = @import("ircx_prop_store/clone_tests.zig");
    _ = @import("ircx_prop_store/checkpoint_tests.zig");
}
