// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS wire codec, TTL caches, and bounded native UDP/TCP resolution.
//!
//! Stable public entry point. `dns/wire.zig` owns transport-free validation;
//! `dns/resolver_config.zig` discovers host policy; `dns/resolver.zig` performs
//! bounded lookups on dedicated resolver workers.

const wire = @import("dns/wire.zig");
const cache = @import("dns/cache.zig");
const config = @import("dns/resolver_config.zig");
const resolver = @import("dns/resolver.zig");

pub const max_message_len = wire.max_message_len;
pub const max_domain_text_len = wire.max_domain_text_len;
pub const max_cache_addrs = wire.max_cache_addrs;
pub const class_in = wire.class_in;
pub const EncodeError = wire.EncodeError;
pub const DecodeError = wire.DecodeError;
pub const CacheError = cache.CacheError;
pub const RecordType = wire.RecordType;
pub const Header = wire.Header;
pub const Name = wire.Name;
pub const Address = wire.Address;
pub const Question = wire.Question;
pub const RData = wire.RData;
pub const ResourceRecord = wire.ResourceRecord;
pub const Query = wire.Query;
pub const AnswerData = wire.AnswerData;
pub const Answer = wire.Answer;
pub const BuildMessage = wire.BuildMessage;
pub const max_txt_rdata_len = wire.max_txt_rdata_len;
pub const max_txt_character_string_len = wire.max_txt_character_string_len;
pub const Txt = wire.Txt;
pub const TxtIterator = wire.TxtIterator;
pub const Message = wire.Message;
pub const encodeMessage = wire.encodeMessage;
pub const encodeQuery = wire.encodeQuery;
pub const encodeTxtQuery = wire.encodeTxtQuery;
pub const encodePtrQuery = wire.encodePtrQuery;
pub const parseMessage = wire.parseMessage;
pub const reverseName = wire.reverseName;
pub const HostCacheEntry = cache.HostCacheEntry;
pub const PtrCacheEntry = cache.PtrCacheEntry;
pub const Cache = cache.Cache;
pub const max_nameservers = config.max_nameservers;
pub const ResolveError = resolver.ResolveError;
pub const ResolverConfig = config.ResolverConfig;
pub const parseIpLiteral = config.parseIpLiteral;
pub const parseResolvConf = config.parseResolvConf;
pub const systemResolverConfig = config.systemResolverConfig;
pub const namesEqual = wire.namesEqual;
pub const responseMatchesQuestion = wire.responseMatchesQuestion;
pub const rrMatchesQuestion = wire.rrMatchesQuestion;
pub const responseAnswersFollowCnames = wire.responseAnswersFollowCnames;
pub const forwardConfirms = resolver.forwardConfirms;
pub const resolveForward = resolver.resolveForward;
pub const resolveReverse = resolver.resolveReverse;
pub const resolveConfirmed = resolver.resolveConfirmed;
/// Detailed owned results, including canonical name and validated TTL metadata.
/// The existing ResolverConfig layout is unchanged.
pub const ResolveOptions = @import("dns/query_engine.zig").Options;
pub const ResolveResult = @import("dns/response.zig").Result;
pub const ResolveOutcome = @import("dns/response.zig").Outcome;
pub const LookupError = @import("dns/query_engine.zig").Error;
pub const resolve = @import("dns/query_engine.zig").resolve;
pub const ResultCache = @import("dns/result_cache.zig").Cache;
pub const CachedResolver = @import("dns/cached_resolver.zig").Resolver;

test {
    _ = wire;
    _ = cache;
    _ = config;
    _ = resolver;
    _ = @import("dns/response_tests.zig");
    _ = @import("dns/query_engine.zig");
    _ = @import("dns/query_engine_tests.zig");
    _ = @import("dns/result_cache.zig");
    _ = @import("dns/cached_resolver.zig");
}
