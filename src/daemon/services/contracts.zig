// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Contracts.

const std = @import("std");
const webauthn_creds = @import("../webauthn_creds.zig");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const oper_session_provenance = @import("../oper_session_provenance.zig");
const key_transparency = @import("../key_transparency.zig");
const key_transparency_store = @import("../key_transparency_store.zig");
const mmr = @import("../../substrate/merkle_mountain_range.zig");
const svc_acclist = @import("../svc_acclist.zig");
const account_max = @import("records.zig").account_max;
const channel_max = @import("records.zig").channel_max;

pub const DurableOperActivationError = durable_oper_authority.Error || error{
    AlreadyActive,
    AuthorityUnavailable,
    MissingDurableMarker,
    MissingDurableSnapshot,
    DurableSnapshotMismatch,
};

pub const DurableOperLookup = oper_session_provenance.DurableOperLookup;

pub const DurableOperGrantCopy = oper_session_provenance.DurableOperGrantCopy;

pub const DurableOperTransactionCopy = durable_oper_authority.TransactionCopy;

/// Exact copied durable transaction state.  The terminal variants carry
/// the same fixed-buffer identity as `.active`; none is a runtime grant.
pub const DurableOperTransaction = union(enum) {
    disabled,
    unavailable,
    absent,
    active: DurableOperTransactionCopy,
    tombstone: DurableOperTransactionCopy,
    equivocation: DurableOperTransactionCopy,
};

/// Observation of one C4 expected durable identity.  This is not a grant,
/// revoke, session, or persistence API.  Missing expected records are
/// `authority_unavailable`, never absent.
pub const DurableOperReconcileObservation = union(enum) {
    disabled,
    authority_unavailable,
    invalid_work,
    superseded,
    matched_not_yet_valid,
    matched_expired,
    matched_tombstone,
    matched_equivocation,
    matched_active: DurableOperGrantCopy,
};

pub const DurableOperPreadmission = enum { out_of_memory, invalid_record, capacity, busy, exhausted, store_failure };

pub const DurableOperRestart = enum { ambiguous_store, fatal_store, fatal_state };

pub const DurableOperMergeOutcome = union(enum) {
    disabled,
    unavailable,
    stale,
    replay,
    committed,
    equivocation_committed,
    preadmission: DurableOperPreadmission,
    restart_required: DurableOperRestart,
};

pub const DurableOperRevisionOutcome = union(enum) {
    disabled,
    unavailable,
    committed: u64,
    preadmission: DurableOperPreadmission,
    restart_required: DurableOperRestart,
};

/// Stable public spelling for the restart/fail-closed taxonomy used by
/// all inactive durable-authority cuts.
pub const DurableOperRestartReason = DurableOperRestart;

pub const DurableOperSecurityTimeResult = union(enum) {
    disabled,
    unavailable,
    committed: u64,
    preadmission: DurableOperPreadmission,
    restart_required: DurableOperRestartReason,
};

/// Runtime effective security time.  A missing reservation and a poisoned
/// authority are both unavailable, while disabled remains distinguishable
/// for callers that have not attached the inactive image.
pub const DurableOperSecurityNow = union(enum) {
    disabled,
    unavailable,
    now: u64,
};

pub const durable_oper_security_horizon_renewal_threshold_ms: u64 =
    durable_oper_authority.security_horizon_renewal_threshold_ms;

pub const durable_oper_security_horizon_window_ms: u64 =
    durable_oper_authority.security_horizon_window_ms;

pub const DurableOperSecurityHorizonCopy = struct {
    effective_now_ms: u64,
    security_floor_ms: u64,
    reserved_until_ms: u64,
    remaining_ms: u64,
};

pub const DurableOperSecurityHorizonResult = union(enum) {
    disabled,
    unavailable,
    current: DurableOperSecurityHorizonCopy,
    renewed: DurableOperSecurityHorizonCopy,
    preadmission: DurableOperPreadmission,
    restart_required: DurableOperRestartReason,
};

pub const ProjectedDurableOperSecurity = struct {
    boot_effective_ms: u64,
    effective_ms: u64,
};

pub const DurableOperTransactionsResult = union(enum) {
    disabled,
    unavailable,
    copied: usize,
    preadmission: DurableOperPreadmission,
    restart_required: DurableOperRestartReason,
};

pub const DurableOperAuthorityMatch = enum {
    disabled,
    unavailable,
    mismatch,
    ready,
};

pub const DurableDeviceFactPreadmission = enum {
    out_of_memory,
    invalid_fact,
    capacity,
    busy,
    exhausted,
    store_failure,
};

pub const DurableDeviceFactRestart = enum {
    ambiguous_store,
    fatal_store,
    fatal_state,
};

pub const DurableDeviceFactKeyTransparency = enum {
    disabled,
    recorded,
    unavailable,
};

pub const DurableDeviceFactOutcome = union(enum) {
    disabled,
    stale,
    replay,
    equivocation,
    preadmission: DurableDeviceFactPreadmission,
    committed: struct {
        key_transparency: DurableDeviceFactKeyTransparency,
    },
    restart_required: DurableDeviceFactRestart,
};

pub const KeyTransparencyStatus = struct {
    enabled: bool,
    /// False when the durable log is attached but restore failed closed.
    available: bool = true,
    /// Always observational / node-local until durable PROP state exists.
    semantics: []const u8 = "observational",
    scope: []const u8 = "node-local",
    entries: usize = 0,
    root: key_transparency.Hash = @splat(0),
};

pub const KeyTransparencyProofStep = struct {
    side: mmr.Side,
    hash: key_transparency.Hash,
};

pub const KeyTransparencyProofSnapshot = struct {
    position: usize,
    size: usize,
    root: key_transparency.Hash,
    path: []KeyTransparencyProofStep,
    peaks: []key_transparency.Hash,

    pub fn deinit(self: *KeyTransparencyProofSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.peaks);
        self.* = undefined;
    }
};

pub const KeyTransparencyEventSnapshot = struct {
    position: usize,
    size: usize,
    root: key_transparency.Hash,
    event: key_transparency.OwnedEvent,
};

pub const KeyTransparencyDeviceSnapshot = struct {
    position: usize,
    size: usize,
    root: key_transparency.Hash,
    /// Latest observed action (`bind` / `delete`). Not current/bound state.
    observation: key_transparency.ObservedAction,
    event: key_transparency.OwnedEvent,
};

pub const KeyTransparencyRecordError = key_transparency.CodecError || key_transparency_store.StoreError || error{
    InvalidName,
    Unavailable,
};

pub const ObservationOrigin = struct {
    hlc: u64,
    origin_node: u64,
    origin_pubkey: []const u8 = &.{},
};

// -- WebAuthn (passkey) credentials --------------------------------------
//
// Durable credential storage mirroring the certfp pattern: each credential
// is a `.props` record keyed by its (unique) credential id, plus a per-
// account newline-separated list of credential ids for LIST/allow-list.
// All record encode/decode + validation lives in `webauthn_creds.zig`; these
// methods only serialize store access under the Services lock and copy every
// borrowed value out before releasing it. The durable store IS authoritative
// (no in-memory companion): verification is stateless and the single-use
// challenge lives in per-connection state.

/// A credential looked up by id, with all bytes copied out (valid after the
/// lock is released). `cose_key` holds the raw COSE_Key CBOR public key.
pub const WebauthnCredential = struct {
    account_buf: [account_max]u8 = undefined,
    account_len: usize = 0,
    sign_count: u32 = 0,
    created_unix: i64 = 0,
    cose_key_buf: [webauthn_creds.max_cose_key_bytes]u8 = undefined,
    cose_key_len: usize = 0,
    label_buf: [webauthn_creds.max_label_bytes]u8 = undefined,
    label_len: usize = 0,

    pub fn account(self: *const WebauthnCredential) []const u8 {
        return self.account_buf[0..self.account_len];
    }
    pub fn coseKey(self: *const WebauthnCredential) []const u8 {
        return self.cose_key_buf[0..self.cose_key_len];
    }
    pub fn label(self: *const WebauthnCredential) []const u8 {
        return self.label_buf[0..self.label_len];
    }
};

/// A LIST entry, with credential id + label copied out.
pub const WebauthnListEntry = struct {
    cred_id_buf: [webauthn_creds.max_cred_id_b64]u8 = undefined,
    cred_id_len: usize = 0,
    label_buf: [webauthn_creds.max_label_bytes]u8 = undefined,
    label_len: usize = 0,
    sign_count: u32 = 0,
    created_unix: i64 = 0,

    pub fn credId(self: *const WebauthnListEntry) []const u8 {
        return self.cred_id_buf[0..self.cred_id_len];
    }
    pub fn label(self: *const WebauthnListEntry) []const u8 {
        return self.label_buf[0..self.label_len];
    }
};

// ── Account recognition masks (svc_acclist feature; RECOGNIZE command) ───────
// Per-account hostmask list. Stored as ONE newline-joined value in the `.props`
// family — durable, restart-safe, and isolated from account/channel records
// (so it can never corrupt them). Matching uses `svc_acclist.globMatch`.
pub const recognize_prefix = "rcg\x00";

pub const recognize_max_masks: usize = svc_acclist.default_max_masks;

pub const recognize_mask_max: usize = 128;

pub const recognize_key_max: usize = recognize_prefix.len + account_max;

pub const recognize_value_max: usize = recognize_max_masks * (recognize_mask_max + 1);

pub const RecognizeAdd = enum { added, already_present, list_full, invalid_mask };

// ── Durable account-scoped IRCv3 METADATA (web-client profiles) ─────────────
// The live metadata store (server.metadata) is in-memory; these helpers mirror
// a logged-in user's OWN metadata into the durable `.props` family keyed by
// ACCOUNT, so a profile (avatar/display-name/…) survives a cold restart and is
// restored into the live store on next login. Value = "<vis-token>\x00<value>".
// Isolated key namespace ("mda\x00…") — never touches account/channel records.
pub const metadata_prefix = "mda\x00";

pub const metadata_key_max = 64;

pub const metadata_value_max = 512;

pub const metadata_full_key_max = metadata_prefix.len + account_max + 1 + metadata_key_max;

// ── Durable account-scoped SILENCE (ignore list survives reconnect/restart) ──
// One newline-joined blob per account in `.props` ("sil\x00<account>"). The live
// per-nick `server.silence` store is restored from this at login.
pub const silence_prefix = "sil\x00";

pub const silence_max_masks: usize = 64;

pub const silence_mask_max: usize = 128;

pub const silence_key_max: usize = silence_prefix.len + account_max;

pub const silence_value_max: usize = silence_max_masks * (silence_mask_max + 1);

// ── Durable Web Push subscriptions (per-account blob) ───────────────────────
// One serialized subscription list per account in `.props` ("wps\x00<account>").
// The blob format is owned by daemon/webpush.zig (encodeList/decodeList);
// services just stores it. Same private-namespace rule as TOTP: never
// reachable through the METADATA command surface.
pub const webpush_prefix = "wps\x00";

pub const webpush_key_max = webpush_prefix.len + account_max;

/// 3 subscriptions × (512-byte endpoint + b64url keys + separators), rounded up.
pub const webpush_value_max: usize = 4096;

pub const WebpushPruneResult = struct {
    rows_examined: usize = 0,
    rows_changed: usize = 0,
    subscriptions_removed: usize = 0,
};

pub const WebpushPruneRow = struct {
    key: [webpush_key_max]u8,
    key_len: usize,
    blob: ?[]u8,

    pub fn before(_: void, a: WebpushPruneRow, b: WebpushPruneRow) bool {
        return std.mem.lessThan(u8, a.key[0..a.key_len], b.key[0..b.key_len]);
    }
};

// ── Durable account-scoped TOTP secret (2FA enrollment survives restart) ────
// The base32 shared secret for an account's ACTIVE TOTP enrollment, stored in
// the private `.props` family under "tot\x00<account>". This namespace is
// NEVER exposed via the IRCv3 METADATA command (which reads only the "mda\x00"
// prefix), so the secret is not client-readable — it is server-side state used
// solely to verify a login second factor. Only a confirmed enrollment is
// persisted; a pending (unconfirmed) secret lives only in the in-memory store.
pub const totp_secret_max: usize = 64;

// base32 of up to ~40 raw bytes
pub const totp_prefix = "tot\x00";

pub const totp_key_max: usize = totp_prefix.len + account_max;

// ── Account recovery codes (Era 2 B8) ───────────────────────────────────
// Single-use offline login codes. Stored hashed under props key
// "rcd\x00<account>" (never client-readable via METADATA). Format of value:
// concatenation of remaining 32-byte SHA-256 digests (count = value.len/32).
pub const recovery_code_count: usize = 10;

pub const recovery_code_raw_len: usize = 10;

// printable alnum body (no dashes)
pub const recovery_digest_len: usize = 32;

pub const rcd_prefix = "rcd\x00";

pub const rcd_key_max: usize = rcd_prefix.len + account_max;

pub const rcd_blob_max: usize = recovery_code_count * recovery_digest_len;

// ── Durable per-channel bad-word filter (svc_chanbadwords; CHANBADWORDS) ─────
// One newline-joined pattern blob per channel in `.props` ("cbw\x00<channel>"),
// channel-op managed. A non-op/non-oper channel message containing any pattern
// (case-insensitive substring, via svc_chanbadwords.containsIgnoreCase) is
// blocked. Read straight from the store, so it is correct across restarts.
pub const chanbadword_prefix = "cbw\x00";

pub const chanbadword_max: usize = 64;

pub const chanbadword_pattern_max: usize = 128;

pub const chanbadword_key_max: usize = chanbadword_prefix.len + channel_max;

pub const chanbadword_value_max: usize = chanbadword_max * (chanbadword_pattern_max + 1);

// ── Durable KEEPTOPIC (registered-channel topic survives recreation) ────────
// "ktp\x00<channel>" in `.props`: presence = enabled. The value is one of:
//   • empty            — enabled but nothing saved yet.
//   • legacy text      — a raw topic written by an older build (no metadata).
//   • versioned blob   — [sentinel=0x01][ver=0x01][set_at i64 LE]
//                        [setter_len u16 LE][setter][text]
// Every new save writes a versioned blob, so a topic round-trips exactly
// whatever its bytes (including a leading 0x01). The SOH (0x01) sentinel only
// discriminates a LEGACY (pre-metadata) value from a versioned one. Decode is
// fail-closed and fully bounds-checked: a sentinel-led value whose metadata is
// malformed falls back to the legacy whole-value-is-text interpretation rather
// than crashing or reading OOB. The sole residual ambiguity is an old legacy
// value that both begins with 0x01 and happens to form a self-consistent
// header — it decodes to a wrong setter/set-time (never a crash) for that one
// pre-existing value; new saves are immune.
pub const keeptopic_prefix = "ktp\x00";

pub const keeptopic_key_max: usize = keeptopic_prefix.len + channel_max;

pub const keeptopic_text_max: usize = 512;

// topic TEXT cap (unchanged behaviour)
pub const keeptopic_setter_max: usize = 256;

// setter (nick!user@host) cap
pub const keeptopic_meta_sentinel: u8 = 0x01;

pub const keeptopic_meta_version: u8 = 1;

// sentinel(1) + version(1) + set_at(8) + setter_len(2)
pub const keeptopic_meta_header: usize = 12;

pub const keeptopic_value_max: usize = keeptopic_meta_header + keeptopic_setter_max + keeptopic_text_max;

/// Restored KEEPTOPIC state. `text`/`setter` slice into the caller's out
/// buffers. `setter == null` signals a legacy/metadata-absent value: the
/// caller restores the topic text and falls back to serverName()/now for the
/// setter and set-time. `set_at` is meaningful only when `setter != null`.
pub const KeepTopicRestore = struct {
    text: []const u8,
    setter: ?[]const u8,
    set_at: i64,
};

// ── Durable registered-channel founder successor (svc_successor; SUCCESSOR) ──
// The armed name lives at "suc\x00<channel>". A replacement lives at
// "shp\x00<channel>" as little-endian ready_ms plus the account name, and
// does not replace the armed name until `successor_hold_ms` has elapsed.
// CLEAR during the hold deletes only the replacement. A drop during the
// hold still reads the armed name. The first SET has no armed name, so it
// cannot win a drop until the hold elapses.
pub const successor_prefix = "suc\x00";

pub const successor_pending_prefix = "shp\x00";

pub const successor_key_max: usize = successor_prefix.len + channel_max;

pub const successor_pending_key_max: usize = successor_pending_prefix.len + channel_max;

// ── Durable registered-channel metadata (CHANNEL SET DESC / URL) ────────────
// Free-text channel metadata in `.props` keyed by "<tag>\x00<channel>". DESC
// is a human description; URL is a homepage link. Empty value clears the key.
pub const meta_value_max: usize = 400;

pub const DirectoryReconcile = struct { copied: usize };
