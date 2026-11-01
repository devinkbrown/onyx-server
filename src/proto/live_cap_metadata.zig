// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Immutable live CAP definitions; runtime policy and per-session gates remain in dispatch.

pub const CapId = enum(u6) {
    server_time,
    message_tags,
    echo_message,
    sasl,
    multi_prefix,
    userhost_in_names,
    away_notify,
    setname,
    extended_join,
    account_notify,
    invite_notify,
    account_tag,
    onyx_session_sync,
    onyx_bouncer,
    onyx_topics,
    onyx_e2ee,
    chghost,
    no_implicit_names,
    chathistory,
    message_redaction,
    message_editing,
    read_marker,
    typing,
    react,
    reply,
    batch,
    bot,
    channel_rename,
    extended_monitor,
    account_registration,
    metadata_2,
    standard_replies,
    cap_notify,
    labeled_response,
    pre_away,
    channel_context,
    multiline,
    sts,
    event_playback,
    search,
    account_extban,
    utf8_only,
    netsplit,
    netjoin,
    onyx_2fa,
    onyx_privacy,
};

pub const CapSpec = struct {
    id: CapId,
    name: []const u8,
    value_302: ?[]const u8 = null,
    /// When set, the cap is omitted from CAP LS unless the session supplies a
    /// runtime policy value (see `StsPolicy`). This keeps honesty-gated caps
    /// like `sts` absent from the default build, where no policy is configured.
    requires_policy: bool = false,
};

pub const cap_specs = [_]CapSpec{
    .{ .id = .server_time, .name = "server-time" },
    .{ .id = .message_tags, .name = "message-tags" },
    .{ .id = .echo_message, .name = "echo-message" },
    // handleAuthenticate routes PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, and
    // EXTERNAL through the mechrouter. The live server injects each checker from
    // the account store (PLAIN via PBKDF2, SCRAM-SHA-256/512 via the mirrored
    // credential store + a per-connection nonce, EXTERNAL via the account ⇄
    // certfp bindings over the mutual-TLS client cert). Each fails closed when
    // unconfigured, exactly like PLAIN always has, so advertising them never
    // strands a client. The value actually sent is built per-connection by
    // `writeSaslCapValue`, which lists only the mechanisms live on that session;
    // this static value_302 is the unconfigured fallback and is kept in sync so
    // CAP LS and the 908 mechanism list agree.
    .{ .id = .sasl, .name = "sasl", .value_302 = "PLAIN,EXTERNAL,SCRAM-SHA-256,SCRAM-SHA-512" },
    .{ .id = .multi_prefix, .name = "multi-prefix" },
    .{ .id = .userhost_in_names, .name = "userhost-in-names" },
    .{ .id = .away_notify, .name = "away-notify" },
    .{ .id = .setname, .name = "setname" },
    .{ .id = .extended_join, .name = "extended-join" },
    .{ .id = .invite_notify, .name = "invite-notify" },
    .{ .id = .account_tag, .name = "account-tag" },
    // onyx/session-sync: opt-in sibling-device mirroring for direct
    // PRIVMSG/NOTICE delivery and outgoing DM self-view.
    .{ .id = .onyx_session_sync, .name = "onyx/session-sync" },
    // onyx/bouncer: opt-in to automatic rewind (replay of missed channel
    // history on (re)join, bounded by the client's read marker). Multi-session
    // reclaim (SESSION RESUME) works without it; this only enables auto-replay.
    .{ .id = .onyx_bouncer, .name = "onyx/bouncer" },
    // onyx/topics: opt in to Onyx Server's named-conversation surface. A receiver
    // gets the `+onyx/topic=<label>` client-only tag without needing generic
    // message-tags, and clients can discover the topic-filtered CHATHISTORY path.
    .{ .id = .onyx_topics, .name = "onyx/topics" },
    // onyx/e2ee: opt in to Onyx Server's E2EE control-plane tag. Clients with this
    // cap may send/receive `+onyx/e2ee` on messages, letting required rooms
    // reject plaintext without the daemon decrypting client payloads.
    .{ .id = .onyx_e2ee, .name = "onyx/e2ee" },
    // chghost: receive a native CHGHOST line when a common user's host changes
    // (VHOST). Clients without it see the new host on the user's next message.
    .{ .id = .chghost, .name = "chghost" },
    // no-implicit-names: a capable client suppresses the automatic NAMES burst
    // sent on JOIN (it can still issue NAMES explicitly). Dual-advertised: the
    // spec token is `draft/no-implicit-names`, so list both names (same id) — a
    // spec client REQ-ing the draft token engages the same capability and CAP
    // ACK echoes back whichever token the client requested.
    .{ .id = .no_implicit_names, .name = "no-implicit-names" },
    .{ .id = .no_implicit_names, .name = "draft/no-implicit-names" },
    // The following expose already-live command/relay paths to clients that
    // negotiate them. Each is backed by a verified handler or the client-only
    // message-tag relay, so advertising them cannot strand a client:
    //   draft/chathistory     -> CHATHISTORY command (emits a `chathistory` BATCH)
    //   draft/message-redaction -> REDACT command
    //   draft/message-editing -> EDIT command
    //   draft/read-marker     -> MARKREAD command
    //   draft/typing/react/reply -> relayed as client-only tags on TAGMSG
    //   batch                 -> server emits BATCH (chathistory, netsplit)
    //   bot                   -> +B bot flag surfaced in WHOIS (335)
    .{ .id = .chathistory, .name = "draft/chathistory" },
    // draft/search: SEARCH <target> :<query> -> full-text message search over the
    // CHATHISTORY store; results delivered in a `chathistory` BATCH. Backed by the
    // live `handleSearch` handler + the forward-populated inverted index.
    .{ .id = .search, .name = "draft/search" },
    .{ .id = .message_redaction, .name = "draft/message-redaction" },
    .{ .id = .message_editing, .name = "draft/message-editing" },
    .{ .id = .read_marker, .name = "draft/read-marker" },
    .{ .id = .event_playback, .name = "draft/event-playback" },
    .{ .id = .typing, .name = "draft/typing" },
    .{ .id = .react, .name = "draft/react" },
    .{ .id = .reply, .name = "draft/reply" },
    .{ .id = .batch, .name = "batch" },
    .{ .id = .bot, .name = "bot" },
    // channel-rename: receive a native RENAME line when a common channel is
    // renamed; clients without it get a PART(old)+JOIN(new) fallback.
    .{ .id = .channel_rename, .name = "draft/channel-rename" },
    // extended-monitor: receive AWAY/SETNAME/CHGHOST/ACCOUNT changes for
    // MONITOR'd nicks even without a shared channel.
    .{ .id = .extended_monitor, .name = "extended-monitor" },
    // account-notify: receive an ACCOUNT line when a user in a common channel
    // logs in (IDENTIFY) or out (LOGOUT). The server emits these at the live
    // login/logout sites.
    .{ .id = .account_notify, .name = "account-notify" },
    // account-registration: REGISTER/VERIFY are live; advertising lets compliant
    // clients surface nick/account registration. The `custom-account-name` value
    // signals that REGISTER may name an account distinct from the current nick
    // (`REGISTER <account> ...`), which this server supports. We deliberately do
    // NOT advertise before-connect, because pre-registration REGISTER is not
    // supported (it replies FAIL REGISTER COMPLETE_CONNECTION_REQUIRED).
    .{ .id = .account_registration, .name = "draft/account-registration", .value_302 = "custom-account-name" },
    // metadata-2: METADATA GET/SET/LIST/CLEAR + RPL_KEYVALUE(761)/762/766 are live.
    .{ .id = .metadata_2, .name = "draft/metadata-2" },
    // standard-replies: FAIL/WARN are emitted across the command surface.
    .{ .id = .standard_replies, .name = "standard-replies" },
    // cap-notify: the cap set is static, so CAP NEW/DEL never fire, but advertising
    // signals support and is required before some clients enable other caps.
    .{ .id = .cap_notify, .name = "cap-notify" },
    // labeled-response: when a client tags a command with @label=<x>, the
    // server echoes @label=<x> on the response (a single tagged line, a
    // labeled-response BATCH for multi-line replies, or a bare labeled ACK for
    // commands that emit nothing). Framing lives in proto/labeled_response.zig.
    .{ .id = .labeled_response, .name = "labeled-response" },
    // pre-away: a negotiating client may send AWAY during the registration
    // handshake (before the welcome burst). The away state is applied
    // immediately so the user is already marked away when registration
    // completes. Handled in processLiveLine's pre-registration branch.
    .{ .id = .pre_away, .name = "draft/pre-away" },
    // channel-context: a client-only `+draft/channel-context=<chan>` tag on a
    // direct message marks it as part of a channel's context. Carried by the
    // generic client-tag relay (mergeTags), so advertising is all that's needed.
    .{ .id = .channel_context, .name = "draft/channel-context" },
    // multiline: the server accepts an inbound `BATCH +ref draft/multiline`
    // (PRIVMSG/NOTICE chunks), reassembles it, and delivers the result. Limits
    // are advertised as the cap value and enforced by the per-conn assembler.
    .{ .id = .multiline, .name = "draft/multiline", .value_302 = "max-bytes=40000,max-lines=64" },
    // sts (Strict Transport Security): the modern, config-gated replacement for
    // STARTTLS (which this daemon deliberately never implements). The value is
    // NOT static: it is the wire policy ("duration=<s>,port=<p>[,preload]")
    // produced from operator config and supplied per-session at LS time. With
    // `requires_policy`, the cap is OMITTED entirely until a policy is present,
    // so a default build that has not enabled STS advertises nothing -- never
    // stranding a client by promising TLS that no listener serves.
    .{ .id = .sts, .name = "sts", .requires_policy = true },
    // IRCv3 discovery caps for behavior Onyx Server already implements unconditionally,
    // so clients can negotiate/use them: account-extban=a ($a account bans),
    // utf8-only (the server enforces valid UTF-8 globally), and draft/netsplit +
    // draft/netjoin (netsplit/netjoin are framed as typed BATCHes, gated on `batch`).
    .{ .id = .account_extban, .name = "account-extban", .value_302 = "a" },
    .{ .id = .utf8_only, .name = "utf8-only" },
    .{ .id = .netsplit, .name = "draft/netsplit" },
    .{ .id = .netjoin, .name = "draft/netjoin" },
    // Accounts with 2FA complete login through IDENTIFY. Surface this before
    // clients choose a SASL mechanism, without treating IDENTIFY as one.
    .{ .id = .onyx_2fa, .name = "onyx/2fa", .value_302 = "IDENTIFY" },
    // onyx/privacy: the user and channel modes enforced by this build.
    // umode lists the receive and direct-message privacy letters. cmode lists
    // the extended channel moderation letters. Both sets are live gates.
    .{ .id = .onyx_privacy, .name = "onyx/privacy", .value_302 = "umode=DGIZTVW,cmode=cBK" },
};
