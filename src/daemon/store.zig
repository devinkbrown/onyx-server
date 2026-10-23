// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embedded persistence facade. Typed implementation seams live in `store/`.
//! Public APIs and canonical WAL/snapshot formats remain stable.

pub const StoreError = @import("store/contracts.zig").StoreError;
pub const PreparedIoFault = @import("store/contracts.zig").PreparedIoFault;
pub const Config = @import("store/contracts.zig").Config;
pub const AdmissionLimits = @import("store/contracts.zig").AdmissionLimits;
pub const WindowsWalWitness = @import("store/native_files.zig").WindowsWalWitness;
pub const WindowsWalDescriptor = @import("store/native_files.zig").WindowsWalDescriptor;
pub const WindowsWalTransfer = @import("store/native_files.zig").WindowsWalTransfer;
pub const WindowsFileIdInfo = @import("store/native_files.zig").WindowsFileIdInfo;
pub const Family = @import("store/contracts.zig").Family;
pub const MutationKind = @import("store/contracts.zig").MutationKind;
pub const Mutation = @import("store/contracts.zig").Mutation;
pub const ColumnFamily = @import("store/engine.zig").ColumnFamily;
pub const BatchMutation = @import("store/contracts.zig").BatchMutation;
pub const PreparedBatch = @import("store/engine.zig").PreparedBatch;
pub const PreparedPut = @import("store/engine.zig").PreparedPut;
pub const OroStore = @import("store/engine.zig").OroStore;
pub const ColdOpenMode = @import("store/native_files.zig").ColdOpenMode;
pub const openColdExisting = @import("store/native_files.zig").openColdExisting;
pub const FirstProvisionStage = @import("store/checkpoint.zig").FirstProvisionStage;
pub const ColdPublicationFault = @import("store/checkpoint.zig").ColdPublicationFault;
pub const ColdRecoveryStage = @import("store/checkpoint.zig").ColdRecoveryStage;
pub const PreparedColdRecovery = @import("store/checkpoint.zig").PreparedColdRecovery;
pub const SourceAccessError = @import("store/source_owner.zig").SourceAccessError;
pub const SourceIdentity = @import("store/source_owner.zig").SourceIdentity;
pub const AllocatorObservation = @import("store/source_owner.zig").AllocatorObservation;
pub const OwnedCapacityDescriptor = @import("store/source_owner.zig").OwnedCapacityDescriptor;
pub const SourceCustodyView = @import("store/source_owner.zig").SourceCustodyView;
pub const StoreEntryView = @import("store/source_owner.zig").StoreEntryView;
pub const StoreResourceOwner = @import("store/source_owner.zig").StoreResourceOwner;
pub const ResourceOwner = @import("store/source_owner.zig").ResourceOwner;
pub const ReadLease = @import("store/source_owner.zig").ReadLease;
pub const ReadIterator = @import("store/source_owner.zig").ReadIterator;
pub const StoreExclusive = @import("store/source_owner.zig").StoreExclusive;
pub const CatalogCursor = @import("store/source_owner.zig").CatalogCursor;
pub const CreationArgs = @import("store/managed_bridge.zig").CreationArgs;
pub const CreationIdentity = @import("store/managed_bridge.zig").CreationIdentity;
pub const CandidateUse = @import("store/managed_bridge.zig").CandidateUse;
pub const RootKey = @import("store/managed_bridge.zig").RootKey;
pub const RootDescriptor = @import("store/managed_bridge.zig").RootDescriptor;
pub const ManagedBridge = @import("store/managed_bridge.zig").ManagedBridge;

comptime {
    if (@import("builtin").is_test) {
        _ = @import("store/tests_basic.zig");
        _ = @import("store/tests_batch.zig");
        _ = @import("store/tests_checkpoint.zig");
        _ = @import("store/tests_checkpoint_windows.zig");
        _ = @import("store/tests_compaction.zig");
        _ = @import("store/tests_complete_epoch.zig");
        _ = @import("store/tests_custody.zig");
        _ = @import("store/tests_managed_bridge.zig");
        _ = @import("store/tests_native_windows.zig");
        _ = @import("store/tests_ordinary.zig");
        _ = @import("store/tests_prepared.zig");
        _ = @import("store/tests_source_owner.zig");
        _ = @import("store/tests_table.zig");
        _ = @import("store/tests_windows_store.zig");
    }
}
