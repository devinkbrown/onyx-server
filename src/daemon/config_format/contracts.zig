// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Resolver callbacks and parser errors shared by config projection.

const std = @import("std");

/// Indirection callback: given a name (env var) or path (file), return an owned
/// value. Used to resolve `env:NAME` and `@file:path` string values.
pub const LookupFn = *const fn (?*anyopaque, std.mem.Allocator, []const u8) anyerror![]const u8;

pub const Resolver = struct {
    ctx: ?*anyopaque = null,
    env: ?LookupFn = null,
    file: ?LookupFn = null,
};

pub const TomlError = error{
    ParseError,
    HiddenRecorderRefused,
    UnknownOcg2Field,
    MissingOcg2AuthorityNodeId,
    MissingOcg2AuthorityPublicKey,
    InvalidOcg2AuthorityPublicKey,
    Ocg2AuthorityNodeIdMismatch,
    Ocg2RequiresAccountStore,
    Ocg2StorageRecordLimitTooSmall,
    Ocg2StorageWalLimitTooSmall,
    Ocg2ProjectionRequiresEnabled,
    Ocg2MintingRequiresEnabled,
    Ocg2MintingRequiresProjection,
} || std.mem.Allocator.Error;
