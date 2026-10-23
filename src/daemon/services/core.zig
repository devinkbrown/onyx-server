// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical Services owner and stable operation adapters.

const std = @import("std");
const certfp_bind_mod = @import("../certfp_bind.zig");
const account_verify = @import("../account_verify.zig");
const durable_credential_props = @import("../durable_credential_props.zig");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const oper_session_provenance = @import("../oper_session_provenance.zig");
const ocg2_reconcile_workset = @import("../ocg2_reconcile_workset.zig");
const key_transparency = @import("../key_transparency.zig");
const key_transparency_store = @import("../key_transparency_store.zig");
const entity_prop_event = @import("../../proto/entity_prop_event.zig");
const oper_cred_share = @import("../../proto/oper_cred_share.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const svc_enforce = @import("../svc_enforce.zig");
const delivery_authority = @import("../delivery_authority.zig");
const OroStore = @import("records.zig").OroStore;
const ScramStore = @import("records.zig").ScramStore;
const salt_len = @import("records.zig").salt_len;
const hash_len = @import("records.zig").hash_len;
const Config = @import("records.zig").Config;
const ServiceError = @import("records.zig").ServiceError;
const StateHook = @import("records.zig").StateHook;
const AccountName = @import("records.zig").AccountName;
const Email = @import("records.zig").Email;
const AccessLevel = @import("records.zig").AccessLevel;
const AccountSetField = @import("records.zig").AccountSetField;
const ChannelSetField = @import("records.zig").ChannelSetField;
const AccessAction = @import("records.zig").AccessAction;
const AkickAction = @import("records.zig").AkickAction;
const LoginMechanism = @import("records.zig").LoginMechanism;
const LoginTls = @import("records.zig").LoginTls;
const LoginAuditEntry = @import("records.zig").LoginAuditEntry;
const AccountAdminInfo = @import("records.zig").AccountAdminInfo;
const SessionTokenIssue = @import("records.zig").SessionTokenIssue;
const AccessInfo = @import("records.zig").AccessInfo;
const AkickInfo = @import("records.zig").AkickInfo;
const EmailVerifyResult = @import("records.zig").EmailVerifyResult;
const ReplayWard = @import("records.zig").ReplayWard;
const ReplaySaccess = @import("records.zig").ReplaySaccess;
const LiveReplaySummary = @import("records.zig").LiveReplaySummary;
const LiveReplaySink = @import("records.zig").LiveReplaySink;
const CommandResult = @import("records.zig").CommandResult;
const AccountRecord = @import("records.zig").AccountRecord;
const ChannelRecord = @import("records.zig").ChannelRecord;
const AccessRecord = @import("records.zig").AccessRecord;
const AkickRecord = @import("records.zig").AkickRecord;
const directoryConflicts = @import("records.zig").directoryConflicts;
const copyMissingDirectory = @import("records.zig").copyMissingDirectory;
const validateEmail = @import("records.zig").validateEmail;
const scram_key_max = @import("records.zig").scram_key_max;
const scramKey = @import("records.zig").scramKey;
const accountKey = @import("records.zig").accountKey;
const hashPassword = @import("records.zig").hashPassword;
const encodeAccount = @import("records.zig").encodeAccount;
const AfterCopyHook = @import("oper_shared.zig").AfterCopyHook;
const contracts = @import("contracts.zig");
const account_props_domain = @import("account_props.zig");
const accounts_domain = @import("accounts.zig");
const channel_props_domain = @import("channel_props.zig");
const channels_domain = @import("channels.zig");
const clock_domain = @import("clock.zig");
const credentials_domain = @import("credentials.zig");
const device_facts_domain = @import("device_facts.zig");
const key_transparency_domain = @import("key_transparency.zig");
const mfa_domain = @import("mfa.zig");
const oper_authority_domain = @import("oper_authority.zig");
const oper_availability_domain = @import("oper_availability.zig");
const oper_clock_domain = @import("oper_clock.zig");
const persistence_domain = @import("persistence.zig");
const sessions_domain = @import("sessions.zig");
const webpush_domain = @import("webpush.zig");

pub const Services = struct {
    store: *OroStore,
    /// Set only by the closed StateContext factory. That factory retains this
    /// entire Services object privately; no bound Services/Store pointer leaves
    /// its opaque named-dispatch loan. Core installation remains separate.
    bound_state_context: ?*delivery_authority.StateContext = null,
    state: ?StateHook = null,
    cfg: Config = .{},
    /// Optional SCRAM-SHA-256 credential mirror. When set, account registration
    /// additionally derives and stores `{salt, iters, StoredKey, ServerKey}` so
    /// the daemon can advertise and complete SCRAM-SHA-256. PLAIN remains the
    /// source of truth in the persistent account record; this is an in-memory
    /// companion (see scram_store.zig). Null leaves SCRAM unprovisioned, exactly
    /// matching the historical PLAIN-only behaviour.
    scram: ?*ScramStore = null,
    /// Optional account ⇄ TLS certfp bindings, backing SASL EXTERNAL (CERTADD).
    /// In-memory companion (see certfp_bind.zig); null = EXTERNAL has nothing to
    /// match and fails closed.
    certfp_binds: ?*certfp_bind_mod.CertfpBindStore = null,
    /// Optional node-local observational history for credential facts.
    /// The log must outlive `self`. CERTFP/WebAuthn/E2EE/identity PROP
    /// mutations stay successful when an observational append is unavailable.
    /// A corrupt log stays fail-closed (`unusable`); it is never treated as
    /// current or authoritative device/identity state.
    key_transparency: ?*key_transparency.KeyTransparencyLog = null,
    /// Borrowed durable credential-property image. The owner restores the
    /// DPROP1 snapshot before attachment and must outlive `self`.
    durable_credential_props_state: ?*durable_credential_props.State = null,
    /// Borrowed inactive OCG2 durable authority. No runtime privilege consumer
    /// reads this pointer; it exists only for durable merge/revision APIs.
    durable_oper_authority_state: ?*durable_oper_authority.State = null,
    /// Monotonic security-state epoch. Successful record merges deliberately do
    /// not advance it, so detached reads may return their copied predecessor;
    /// every fail-closed availability transition does advance it.
    durable_oper_availability_epoch: u64 = 0,
    lock: rwlock.RwLock = .{},
    /// Zero uses the wall clock. A non-zero value is a millisecond clock for
    /// the successor hold and the login audit. Atomic so a live server test
    /// can publish it from another thread while the daemon reads it.
    clock_override_ms: std.atomic.Value(u64) = .init(0),

    pub fn init(store: *OroStore, state: ?StateHook) Services {
        return .{ .store = store, .state = state };
    }

    pub fn initWithConfig(store: *OroStore, state: ?StateHook, cfg: Config) Services {
        return .{ .store = store, .state = state, .cfg = cfg };
    }

    /// Compatibility for legacy source helpers only. Bound owners must use
    /// named operations under their original lock; they cannot acquire the
    /// leased Store through this accessor.
    pub fn legacyStore(self: *Services) error{BoundStateRequiresTransaction}!*OroStore {
        if (self.bound_state_context != null) return error.BoundStateRequiresTransaction;
        return self.store;
    }

    /// An ambiguous durable write requires a cold reopen before any new
    /// authentication. The live predecessor cannot establish which TOTP policy
    /// crossed the storage boundary. Existing client attachments are unaffected.
    pub fn authenticationAvailable(self: *const Services) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return !self.store.preparedWritesPoisoned();
    }

    /// Attach a SCRAM credential mirror. Accounts registered after this call
    /// gain SCRAM-SHA-256 material; the store must outlive `self`.
    pub fn attachScramStore(self: *Services, scram: *ScramStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.scram = scram;
        // The gate reads account flags and must not take the SCRAM lock.
        // attach holds this services lock first, then publishes the pointer.
        scram.password_gate = .{ .ptr = self, .allowed = scramPasswordGate };
    }

    fn scramPasswordGate(ptr: *anyopaque, account: []const u8) bool {
        const self: *Services = @ptrCast(@alignCast(ptr));
        return self.passwordMechanismsAllowed(account);
    }

    fn servicesNowMs(self: *const Services) u64 {
        return self.clockView().servicesNowMs();
    }

    pub fn passwordMechanismsAllowed(self: *Services, account: []const u8) bool {
        return self.accountsView().passwordMechanismsAllowed(account);
    }

    /// Attach the account ⇄ certfp binding store (for SASL EXTERNAL / CERTADD).
    /// The store must outlive `self`.
    pub fn attachCertfpBinds(self: *Services, binds: *certfp_bind_mod.CertfpBindStore) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.certfp_binds = binds;
    }

    /// Attach the account credential transparency log and restore any durable
    /// `kt1:` records from the services OroStore. A corrupt or truncated store
    /// marks the log unusable; it is never overwritten with a fresh empty root.
    pub fn attachKeyTransparencyLog(self: *Services, log: *key_transparency.KeyTransparencyLog) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.key_transparency = log;
        key_transparency_store.restore(self.store, log) catch {};
    }

    /// Attach an already-restored DPROP1 image. Services borrows the state;
    /// ownership and destruction remain with the daemon lifecycle.
    pub fn attachDurableCredentialProps(self: *Services, state: *durable_credential_props.State) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        self.durable_credential_props_state = state;
    }

    pub const DurableOperActivationError = contracts.DurableOperActivationError;

    pub fn activateDurableOperAuthority(
        self: *Services,
        state: *durable_oper_authority.State,
    ) DurableOperActivationError!void {
        return self.oper_authorityView().activateDurableOperAuthority(state);
    }

    fn attachDurableOperAuthorityForTest(self: *Services, state: *durable_oper_authority.State) void {
        return self.oper_availabilityView().attachDurableOperAuthorityForTest(state);
    }

    fn attachInactiveDurableOperAuthorityForTest(self: *Services, state: *durable_oper_authority.State) void {
        return self.oper_availabilityView().attachInactiveDurableOperAuthorityForTest(state);
    }

    fn markDurableOperUnavailableLocked(
        self: *Services,
        state: *durable_oper_authority.State,
    ) void {
        return self.oper_availabilityView().markDurableOperUnavailableLocked(state);
    }

    fn markDurableOperUnavailableForTest(self: *Services) void {
        return self.oper_availabilityView().markDurableOperUnavailableForTest();
    }

    pub const DurableOperLookup = contracts.DurableOperLookup;

    pub const DurableOperGrantCopy = contracts.DurableOperGrantCopy;

    pub const DurableOperTransactionCopy = contracts.DurableOperTransactionCopy;

    pub const DurableOperTransaction = contracts.DurableOperTransaction;

    pub fn inspectDurableOperAuthority(
        self: *Services,
        account: []const u8,
        now_ms: u64,
    ) oper_session_provenance.DurableOperLookup {
        return self.oper_authorityView().inspectDurableOperAuthority(account, now_ms);
    }

    pub fn inspectDurableOperTransaction(
        self: *Services,
        account: []const u8,
        now_ms: u64,
    ) DurableOperTransaction {
        return self.oper_authorityView().inspectDurableOperTransaction(account, now_ms);
    }

    pub const DurableOperReconcileObservation = contracts.DurableOperReconcileObservation;

    pub fn inspectDurableOperReconcileWork(
        self: *Services,
        work: ocg2_reconcile_workset.WorkItem,
        security_now_ms: u64,
    ) DurableOperReconcileObservation {
        return self.oper_authorityView().inspectReconcileWork(work, security_now_ms);
    }

    comptime {
        const observe_info = @typeInfo(DurableOperReconcileObservation).@"union";
        const observe_tags = .{
            "disabled",
            "authority_unavailable",
            "invalid_work",
            "superseded",
            "matched_not_yet_valid",
            "matched_expired",
            "matched_tombstone",
            "matched_equivocation",
            "matched_active",
        };
        if (observe_info.field_names.len != observe_tags.len)
            @compileError("DurableOperReconcileObservation tags are frozen");
        for (observe_info.field_names, observe_info.field_types) |name, field_type| {
            var allowed = false;
            for (observe_tags) |tag| {
                if (std.mem.eql(u8, name, tag)) allowed = true;
            }
            if (!allowed) @compileError("DurableOperReconcileObservation carries an undeclared tag");
            if (std.mem.eql(u8, name, "matched_active")) {
                if (field_type != DurableOperGrantCopy)
                    @compileError("matched_active may only carry DurableOperGrantCopy");
            } else if (field_type != void) {
                @compileError("non-active reconcile observations must stay empty");
            }
        }

        const inspect_info = @typeInfo(@TypeOf(inspectDurableOperReconcileWork)).@"fn";
        if (inspect_info.param_types.len != 3)
            @compileError("inspectDurableOperReconcileWork has a fixed (self, work, now) surface");
        if (inspect_info.param_types[1] != ocg2_reconcile_workset.WorkItem)
            @compileError("inspectDurableOperReconcileWork consumes a C4 WorkItem by value");
        if (inspect_info.param_types[2] != u64)
            @compileError("inspectDurableOperReconcileWork takes caller-supplied security_now_ms");
        if (inspect_info.return_type != DurableOperReconcileObservation)
            @compileError("inspectDurableOperReconcileWork returns DurableOperReconcileObservation");
        for (inspect_info.param_types) |param_type| {
            if (param_type == std.mem.Allocator)
                @compileError("inspectDurableOperReconcileWork must stay allocation-free");
        }
    }

    fn inspectDurableOperReconcileWorkInner(
        self: *Services,
        work: ocg2_reconcile_workset.WorkItem,
        security_now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) DurableOperReconcileObservation {
        return self.oper_authorityView().inspectDurableOperReconcileWorkInner(work, security_now_ms, after_copy);
    }

    fn ocg2ReconcileCopyStillLive(
        self: *Services,
        account: []const u8,
        copy: *const durable_oper_authority.TransactionCopy,
        state_identity: *durable_oper_authority.State,
        availability_epoch: u64,
    ) bool {
        return self.oper_authorityView().ocg2ReconcileCopyStillLive(account, copy, state_identity, availability_epoch);
    }

    fn inspectDurableOperTransactionInner(
        self: *Services,
        account: []const u8,
        now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) DurableOperTransaction {
        return self.oper_authorityView().inspectDurableOperTransactionInner(account, now_ms, after_copy);
    }

    fn inspectDurableOperAuthorityInner(
        self: *Services,
        account: []const u8,
        now_ms: u64,
        after_copy: ?AfterCopyHook,
    ) oper_session_provenance.DurableOperLookup {
        return self.oper_authorityView().inspectDurableOperAuthorityInner(account, now_ms, after_copy);
    }

    pub const DurableOperPreadmission = contracts.DurableOperPreadmission;

    pub const DurableOperRestart = contracts.DurableOperRestart;

    pub const DurableOperMergeOutcome = contracts.DurableOperMergeOutcome;

    pub fn commitDurableOperRecord(self: *Services, wire: []const u8, now_ms: u64) DurableOperMergeOutcome {
        return self.oper_authorityView().commitDurableOperRecord(wire, now_ms);
    }

    pub const DurableOperRevisionOutcome = contracts.DurableOperRevisionOutcome;

    pub const DurableOperRestartReason = contracts.DurableOperRestartReason;

    pub const DurableOperSecurityTimeResult = contracts.DurableOperSecurityTimeResult;

    pub const DurableOperSecurityNow = contracts.DurableOperSecurityNow;

    pub fn reserveDurableOperSecurityTime(
        self: *Services,
        raw_now_ms: u64,
        reserve_until_ms: u64,
    ) DurableOperSecurityTimeResult {
        return self.oper_clockView().reserveDurableOperSecurityTime(raw_now_ms, reserve_until_ms);
    }

    pub fn durableOperSecurityNow(
        self: *Services,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) DurableOperSecurityNow {
        return self.oper_clockView().durableOperSecurityNow(raw_realtime_ms, monotonic_elapsed_ms);
    }

    pub const durable_oper_security_horizon_renewal_threshold_ms = contracts.durable_oper_security_horizon_renewal_threshold_ms;

    pub const durable_oper_security_horizon_window_ms = contracts.durable_oper_security_horizon_window_ms;

    comptime {
        if (durable_oper_security_horizon_renewal_threshold_ms != 3_600_000)
            @compileError("S6-C2 renewal threshold is frozen at 3_600_000ms");
        if (durable_oper_security_horizon_window_ms != 90_000_000)
            @compileError("S6-C2 window is frozen at ocg2_max_ttl_ms + threshold");
        if (durable_oper_security_horizon_window_ms !=
            oper_cred_share.ocg2_max_ttl_ms + durable_oper_security_horizon_renewal_threshold_ms)
            @compileError("S6-C2 window must be TTL plus the renewal threshold");
    }

    pub const DurableOperSecurityHorizonCopy = contracts.DurableOperSecurityHorizonCopy;

    pub const DurableOperSecurityHorizonResult = contracts.DurableOperSecurityHorizonResult;

    const ProjectedDurableOperSecurity = contracts.ProjectedDurableOperSecurity;

    fn projectDurableOperSecurityLocked(
        state: *const durable_oper_authority.State,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) error{ FirstSampleRequiresZeroElapsed, ElapsedOverflow }!ProjectedDurableOperSecurity {
        return oper_clock_domain.Context.projectDurableOperSecurityLocked(state, raw_realtime_ms, monotonic_elapsed_ms);
    }

    fn durableOperSecurityHorizonCopy(
        effective_ms: u64,
        floor_ms: u64,
        reserved_until_ms: u64,
    ) DurableOperSecurityHorizonCopy {
        return oper_clock_domain.Context.durableOperSecurityHorizonCopy(effective_ms, floor_ms, reserved_until_ms);
    }

    fn publishDurableOperSecurityAnchorsLocked(
        state: *durable_oper_authority.State,
        projected: ProjectedDurableOperSecurity,
    ) void {
        return oper_clock_domain.Context.publishDurableOperSecurityAnchorsLocked(state, projected);
    }

    pub fn ensureDurableOperSecurityHorizon(
        self: *Services,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) DurableOperSecurityHorizonResult {
        return self.oper_clockView().ensureDurableOperSecurityHorizon(raw_realtime_ms, monotonic_elapsed_ms);
    }

    pub const DurableOperTransactionsResult = contracts.DurableOperTransactionsResult;

    pub fn copyDurableOperTransactions(
        self: *Services,
        out: []DurableOperTransactionCopy,
    ) DurableOperTransactionsResult {
        return self.oper_authorityView().copyDurableOperTransactions(out);
    }

    pub fn allocateDurableOperRevision(self: *Services, account: []const u8) DurableOperRevisionOutcome {
        return self.oper_authorityView().allocateDurableOperRevision(account);
    }

    pub const DurableOperAuthorityMatch = contracts.DurableOperAuthorityMatch;

    pub fn matchDurableOperAuthority(
        self: *Services,
        expected: durable_oper_authority.Config,
    ) DurableOperAuthorityMatch {
        return self.oper_authorityView().matchDurableOperAuthority(expected);
    }

    pub fn failClosedDurableOperAuthority(self: *Services) void {
        return self.oper_authorityView().failClosedDurableOperAuthority();
    }

    pub const DurableDeviceFactPreadmission = contracts.DurableDeviceFactPreadmission;

    pub const DurableDeviceFactRestart = contracts.DurableDeviceFactRestart;

    pub const DurableDeviceFactKeyTransparency = contracts.DurableDeviceFactKeyTransparency;

    pub const DurableDeviceFactOutcome = contracts.DurableDeviceFactOutcome;

    pub fn commitLocalDurableDeviceFact(
        self: *Services,
        event: entity_prop_event.EntityPropEvent,
    ) DurableDeviceFactOutcome {
        return self.device_factsView().commitLocalDurableDeviceFact(event);
    }

    pub const KeyTransparencyStatus = contracts.KeyTransparencyStatus;

    pub const KeyTransparencyProofStep = contracts.KeyTransparencyProofStep;

    pub const KeyTransparencyProofSnapshot = contracts.KeyTransparencyProofSnapshot;

    pub fn keyTransparencyStatus(self: *Services) KeyTransparencyStatus {
        return self.key_transparencyView().keyTransparencyStatus();
    }

    pub fn storeKeyTransparencyHead(self: *Services, head: key_transparency.SignedHead) (error{ Disabled, Unavailable, BadSignature, KeyMismatch, BadHead, StaleHead } || std.mem.Allocator.Error)!void {
        return self.key_transparencyView().storeKeyTransparencyHead(head);
    }

    pub fn keyTransparencyUnsignedLocalHead(self: *Services, node_id: u64) (error{ Disabled, Unavailable, Empty, BadHead } || std.mem.Allocator.Error)!key_transparency.SignedHead {
        return self.key_transparencyView().keyTransparencyUnsignedLocalHead(node_id);
    }

    pub fn keyTransparencyPeerHead(self: *Services, node_id: u64) error{ Disabled, Unavailable }!?key_transparency.SignedHead {
        return self.key_transparencyView().keyTransparencyPeerHead(node_id);
    }

    pub fn keyTransparencyProof(self: *Services, allocator: std.mem.Allocator, position: usize) (std.mem.Allocator.Error || error{ Disabled, Unavailable, IndexOutOfRange })!KeyTransparencyProofSnapshot {
        return self.key_transparencyView().keyTransparencyProof(allocator, position);
    }

    pub const KeyTransparencyEventSnapshot = contracts.KeyTransparencyEventSnapshot;

    pub const KeyTransparencyDeviceSnapshot = contracts.KeyTransparencyDeviceSnapshot;

    pub const KeyTransparencyRecordError = contracts.KeyTransparencyRecordError;

    pub fn keyTransparencyEvent(
        self: *Services,
        position: usize,
    ) error{ Disabled, Unavailable, IndexOutOfRange }!KeyTransparencyEventSnapshot {
        return self.key_transparencyView().keyTransparencyEvent(position);
    }

    pub fn keyTransparencyDevice(
        self: *Services,
        account: []const u8,
        device_id: []const u8,
    ) error{ Disabled, Unavailable, InvalidName, InvalidKeyId, NotFound }!KeyTransparencyDeviceSnapshot {
        return self.key_transparencyView().keyTransparencyDevice(account, device_id);
    }

    pub fn keyTransparencyConsistency(
        self: *Services,
        old_size: usize,
    ) (key_transparency.ConsistencyError || error{Disabled})!key_transparency.PrefixComparison {
        return self.key_transparencyView().keyTransparencyConsistency(old_size);
    }

    pub fn observeKeyTransparencyEvent(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        return self.key_transparencyView().observeKeyTransparencyEvent(account, kind, action, key_id, material, timestamp_ms);
    }

    pub const ObservationOrigin = contracts.ObservationOrigin;

    pub fn observeKeyTransparencyFact(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
        origin: ?ObservationOrigin,
    ) void {
        return self.key_transparencyView().observeKeyTransparencyFact(account, kind, action, key_id, material, timestamp_ms, origin);
    }

    pub fn recordExternalKeyTransparencyEvent(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        return self.key_transparencyView().recordExternalKeyTransparencyEvent(account, kind, action, key_id, material, timestamp_ms);
    }

    pub fn compactStoreForBackup(self: *Services) !void {
        return self.persistenceView().compactStoreForBackup();
    }

    fn validateNewPassword(self: *const Services, password: []const u8) ServiceError!void {
        return self.accountsView().validateNewPassword(password);
    }

    pub fn bindCertfp(self: *Services, account: []const u8, fingerprint: []const u8) certfp_bind_mod.CertfpBindError!void {
        return self.credentialsView().bindCertfp(account, fingerprint);
    }

    pub fn listCertfps(self: *Services, account: []const u8, out: [][]const u8) ServiceError![]const []const u8 {
        return self.credentialsView().listCertfps(account, out);
    }

    pub fn deleteCertfp(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        return self.credentialsView().deleteCertfp(account, fingerprint);
    }

    pub const WebauthnCredential = contracts.WebauthnCredential;

    pub const WebauthnListEntry = contracts.WebauthnListEntry;

    pub fn webauthnBind(
        self: *Services,
        account: []const u8,
        cred_id_b64: []const u8,
        cose_key: []const u8,
        sign_count: u32,
        label: []const u8,
        now_unix: i64,
    ) ServiceError!void {
        return self.credentialsView().webauthnBind(account, cred_id_b64, cose_key, sign_count, label, now_unix);
    }

    pub fn webauthnLookup(self: *Services, cred_id_b64: []const u8, out: *WebauthnCredential) ServiceError!void {
        return self.credentialsView().webauthnLookup(cred_id_b64, out);
    }

    pub fn webauthnUpdateSignCount(self: *Services, cred_id_b64: []const u8, new_count: u32) ServiceError!void {
        return self.credentialsView().webauthnUpdateSignCount(cred_id_b64, new_count);
    }

    pub fn webauthnRename(self: *Services, account: []const u8, cred_id_b64: []const u8, label: []const u8) ServiceError!void {
        return self.credentialsView().webauthnRename(account, cred_id_b64, label);
    }

    pub fn webauthnList(self: *Services, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        return self.credentialsView().webauthnList(account, out);
    }

    pub fn webauthnCredIds(self: *Services, account: []const u8, out: []WebauthnListEntry) ServiceError![]const WebauthnListEntry {
        return self.credentialsView().webauthnCredIds(account, out);
    }

    pub fn webauthnDelete(self: *Services, account: []const u8, id_or_label: []const u8) ServiceError!void {
        return self.credentialsView().webauthnDelete(account, id_or_label);
    }

    pub fn enablePasskeyOnly(self: *Services, account: []const u8, scratch: []u8) ServiceError!void {
        return self.credentialsView().enablePasskeyOnly(account, scratch);
    }

    pub fn operStepUpRequired(self: *Services, account: []const u8) bool {
        return self.credentialsView().operStepUpRequired(account);
    }

    pub fn notePasskeyAuthentication(self: *Services, account: []const u8, scratch: []u8) ServiceError!void {
        return self.credentialsView().notePasskeyAuthentication(account, scratch);
    }

    fn passkeysBoundUnlocked(self: *Services, account: []const u8) bool {
        return self.credentialsView().passkeysBoundUnlocked(account);
    }

    fn persistScram(self: *Services, scram: *ScramStore, account: []const u8) void {
        return self.persistenceView().persistScram(scram, account);
    }

    /// A backfill loader for the SCRAM store that reads this services' durable
    /// mirror, so a SCRAM login resolves after a restart. The shared services
    /// lock covers both reading the durable tuple and publishing its owned
    /// cache copy. A reset cannot retire its salt or publish a successor between
    /// those operations. Lock order remains Services then SCRAM.
    pub fn scramLoader(self: *Services) ScramStore.Loader {
        return .{ .ptr = self, .loadFn = scramLoadThunk };
    }

    fn scramLoadThunk(ptr: *anyopaque, account: []const u8, destination: *ScramStore) bool {
        const self: *Services = @ptrCast(@alignCast(ptr));
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.store.preparedWritesPoisoned()) return false;
        var kb: [scram_key_max]u8 = undefined;
        const key = scramKey(&kb, account) orelse return false;
        const bytes = self.store.family(.props).get(key) orelse return false;
        const full = ScramStore.deserializeFullRecord(bytes) orelse return false;
        destination.importFullRecord(account, full) catch return false;
        return true;
    }

    pub fn accountForCertfp(self: *const Services, fingerprint: []const u8) ?[]const u8 {
        return self.credentialsView().accountForCertfp(fingerprint);
    }

    pub fn issueSessionToken(self: *Services, account: []const u8, now_unix: i64) ServiceError!SessionTokenIssue {
        return self.sessionsView().issueSessionToken(account, now_unix);
    }

    pub fn validateSessionToken(
        self: *Services,
        authcid: []const u8,
        token: []const u8,
        now_unix: i64,
        account_out: []u8,
    ) ?[]const u8 {
        return self.sessionsView().validateSessionToken(authcid, token, now_unix, account_out);
    }

    pub fn revokeSessionTokens(self: *Services, account: []const u8) ServiceError!void {
        return self.sessionsView().revokeSessionTokens(account);
    }

    fn accountForCertfpUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        return self.credentialsView().accountForCertfpUnlocked(fingerprint);
    }

    fn certfpOwnerUnlocked(self: *Services, fingerprint: []const u8) ServiceError![]const u8 {
        return self.credentialsView().certfpOwnerUnlocked(fingerprint);
    }

    pub fn registerAccount(self: *Services, name: []const u8, password: []const u8, scratch: []u8) ServiceError!CommandResult {
        return self.registerAccountWithEmail(name, password, null, false, scratch);
    }

    pub fn registerAccountWithEmail(
        self: *Services,
        name: []const u8,
        password: []const u8,
        email: ?[]const u8,
        email_verified: bool,
        scratch: []u8,
    ) ServiceError!CommandResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        if (self.bound_state_context != null and self.store.preparedWritesPoisoned()) return error.StorePoisoned;
        const key = try accountKey(name);
        if (self.accountForbiddenUnlocked(key.asSlice())) return error.Forbidden;
        if (self.store.family(.accounts).get(key.asSlice()) != null) return error.AlreadyExists;
        try self.validateNewPassword(password);

        var salt: [salt_len]u8 = undefined;
        self.store.io.randomSecure(&salt) catch self.store.io.random(&salt);

        var hash: [hash_len]u8 = undefined;
        try hashPassword(&hash, password, &salt, self.cfg.pbkdf2_rounds);

        const record = AccountRecord{
            .name = AccountName.init(key.asSlice()) catch return error.InvalidName,
            .salt = salt,
            .hash = hash,
            .email = if (email) |value| try validateEmail(value) else Email.empty(),
            .email_verified = email_verified and email != null,
        };
        const encoded = try encodeAccount(record, scratch);
        if (self.bound_state_context != null) {
            // The closed StateContext factory attaches no mutable credential
            // mirror. Stage every Store allocation before durable admission;
            // ambiguous IO keeps the original source poisoned for cold recovery.
            var prepared = try self.store.prepareBatch(&.{
                .{ .family = .accounts, .kind = .put, .key = key.asSlice(), .value = encoded },
            });
            defer prepared.abort();
            try prepared.commit();
        } else try self.store.family(.accounts).put(key.asSlice(), encoded);

        // Mirror the credential into the SCRAM store, if attached, so a
        // SCRAM-SHA-256 exchange can later verify this account. The canonical
        // (lowercased) name is used so SCRAM lookups match the account key. The
        // PLAIN record above is already persisted and authoritative; a SCRAM
        // mirror failure must not roll that back, so failures map to
        // error.InvalidRecord rather than leaving a half-registered account.
        if (self.scram) |scram| {
            scram.deriveAndStore(record.name.asSlice(), password) catch return error.InvalidRecord;
            // Persist the derived SCRAM tuple so a SCRAM-SHA-256 login still works
            // after a restart (the in-memory store is otherwise re-seeded only on
            // a fresh register/identify). Best-effort: a mirror failure must not
            // roll back the already-persisted PLAIN account record.
            self.persistScram(scram, record.name.asSlice());
        }
        return .{ .registered_account = .{ .name = record.name } };
    }

    pub fn setAccountEmailPending(
        self: *Services,
        name: []const u8,
        email: []const u8,
        token: []const u8,
        issued_ms: u64,
        scratch: []u8,
    ) ServiceError!void {
        return self.accountsView().setAccountEmailPending(name, email, token, issued_ms, scratch);
    }

    pub fn beginEmailVerification(
        self: *Services,
        verifies: *account_verify.VerifyStore,
        name: []const u8,
        email: []const u8,
        random_bytes: []const u8,
        issued_ms: u64,
        scratch: []u8,
    ) (ServiceError || account_verify.Error)![]const u8 {
        return self.accountsView().beginEmailVerification(verifies, name, email, random_bytes, issued_ms, scratch);
    }

    pub fn confirmAccountEmail(
        self: *Services,
        name: []const u8,
        token: []const u8,
        now_ms: u64,
        scratch: []u8,
    ) ServiceError!EmailVerifyResult {
        return self.accountsView().confirmAccountEmail(name, token, now_ms, scratch);
    }

    fn loginAuditKey(buf: []u8, account: []const u8) ?[]const u8 {
        return accounts_domain.Context.loginAuditKey(buf, account);
    }

    fn loginMechanismFromByte(byte: u8) ?LoginMechanism {
        return accounts_domain.Context.loginMechanismFromByte(byte);
    }

    fn loginTlsFromByte(byte: u8) ?LoginTls {
        return accounts_domain.Context.loginTlsFromByte(byte);
    }

    fn decodeLoginAuditRecord(raw: []const u8) ?LoginAuditEntry {
        return accounts_domain.Context.decodeLoginAuditRecord(raw);
    }

    pub fn appendLoginAudit(self: *Services, account: []const u8, entry: LoginAuditEntry) ServiceError!void {
        return self.accountsView().appendLoginAudit(account, entry);
    }

    pub fn copyLoginAudit(self: *Services, account: []const u8, out: []LoginAuditEntry) ServiceError![]const LoginAuditEntry {
        return self.accountsView().copyLoginAudit(account, out);
    }

    pub fn identifyAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        return self.accountsView().identifyAccount(name, password);
    }

    pub fn identifyAccountWithAudit(self: *Services, name: []const u8, password: []const u8, entry: LoginAuditEntry) ServiceError!CommandResult {
        return self.accountsView().identifyAccountWithAudit(name, password, entry);
    }

    fn identifyAccountChecked(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        return self.accountsView().identifyAccountChecked(name, password);
    }

    pub fn dropAccount(self: *Services, name: []const u8, password: []const u8) ServiceError!CommandResult {
        return self.accountsView().dropAccount(name, password);
    }

    pub fn changeAccountPassword(
        self: *Services,
        name: []const u8,
        old_password: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        return self.accountsView().changeAccountPassword(name, old_password, new_password, scratch);
    }

    pub fn setAccountPasswordForced(
        self: *Services,
        name: []const u8,
        new_password: []const u8,
        scratch: []u8,
    ) ServiceError!void {
        return self.accountsView().setAccountPasswordForced(name, new_password, scratch);
    }

    pub fn ghostAccount(self: *Services, name: []const u8, password: []const u8, nick: []const u8) ServiceError!CommandResult {
        return self.accountsView().ghostAccount(name, password, nick);
    }

    pub fn setAccount(
        self: *Services,
        name: []const u8,
        password: []const u8,
        field: AccountSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.accountsView().setAccount(name, password, field, scratch);
    }

    pub fn accountInfo(self: *Services, name: []const u8) ServiceError!CommandResult {
        return self.accountsView().accountInfo(name);
    }

    pub fn accountSecurity(self: *Services, name: []const u8, enforce_seconds: u32) svc_enforce.AccountSecurity {
        return self.accountsView().accountSecurity(name, enforce_seconds);
    }

    pub fn setAccountSuspended(self: *Services, name: []const u8, suspended: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        return self.accountsView().setAccountSuspended(name, suspended, scratch);
    }

    pub fn setAccountNoExpire(self: *Services, name: []const u8, noexpire: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        return self.accountsView().setAccountNoExpire(name, noexpire, scratch);
    }

    pub fn setAccountForbidden(self: *Services, name: []const u8, forbidden: bool, scratch: []u8) ServiceError!AccountAdminInfo {
        return self.accountsView().setAccountForbidden(name, forbidden, scratch);
    }

    pub fn adminAccountInfo(self: *Services, name: []const u8) ServiceError!AccountAdminInfo {
        return self.accountsView().adminAccountInfo(name);
    }

    pub fn registerChannel(self: *Services, channel: []const u8, founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        return self.channelsView().registerChannel(channel, founder, scratch);
    }

    pub fn dropChannel(self: *Services, channel: []const u8, actor: []const u8) ServiceError!CommandResult {
        return self.channelsView().dropChannel(channel, actor);
    }

    pub fn transferChannel(self: *Services, channel: []const u8, actor: []const u8, new_founder: []const u8, scratch: []u8) ServiceError!CommandResult {
        return self.channelsView().transferChannel(channel, actor, new_founder, scratch);
    }

    pub fn channelAccess(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.channelsView().channelAccess(channel, actor, target, action, level, scratch);
    }

    pub fn channelAccessList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AccessInfo,
    ) ServiceError![]AccessInfo {
        return self.channelsView().channelAccessList(channel, actor, out);
    }

    fn channelAccessUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        target: []const u8,
        action: AccessAction,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.channelsView().channelAccessUnlocked(channel, actor, target, action, level, scratch);
    }

    pub fn channelAkick(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.channelsView().channelAkick(channel, actor, mask, action, reason, scratch);
    }

    pub fn channelAkickList(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        out: []AkickInfo,
    ) ServiceError![]AkickInfo {
        return self.channelsView().channelAkickList(channel, actor, out);
    }

    fn channelAkickUnlocked(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        mask: []const u8,
        action: AkickAction,
        reason: []const u8,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.channelsView().channelAkickUnlocked(channel, actor, mask, action, reason, scratch);
    }

    pub fn setChannel(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        field: ChannelSetField,
        scratch: []u8,
    ) ServiceError!CommandResult {
        return self.channelsView().setChannel(channel, actor, field, scratch);
    }

    pub fn setChannelFlag(
        self: *Services,
        channel: []const u8,
        actor: []const u8,
        flag: u32,
        on: bool,
        scratch: []u8,
    ) ServiceError!void {
        return self.channelsView().setChannelFlag(channel, actor, flag, on, scratch);
    }

    pub fn channelFlagSet(self: *Services, channel: []const u8, flag: u32) bool {
        return self.channelsView().channelFlagSet(channel, flag);
    }

    pub fn channelInfo(self: *Services, channel: []const u8) ServiceError!CommandResult {
        return self.channelsView().channelInfo(channel);
    }

    pub fn channelAccessLevelFor(self: *Services, channel: []const u8, account: []const u8) ServiceError!?AccessLevel {
        return self.channelsView().channelAccessLevelFor(channel, account);
    }

    pub fn persistWard(self: *Services, ward: ReplayWard, scratch: []u8) ServiceError!void {
        return self.channelsView().persistWard(ward, scratch);
    }

    pub fn deleteWard(self: *Services, match: []const u8, pattern: []const u8, scratch: []u8) ServiceError!void {
        return self.channelsView().deleteWard(match, pattern, scratch);
    }

    pub fn persistSaccess(self: *Services, entry: ReplaySaccess, scratch: []u8) ServiceError!void {
        return self.channelsView().persistSaccess(entry, scratch);
    }

    pub fn deleteSaccess(self: *Services, entry_type: []const u8, mask: []const u8, scratch: []u8) ServiceError!void {
        return self.channelsView().deleteSaccess(entry_type, mask, scratch);
    }

    pub fn clearSaccess(self: *Services, entry_type: ?[]const u8) ServiceError!void {
        return self.channelsView().clearSaccess(entry_type);
    }

    const recognize_prefix = contracts.recognize_prefix;

    const recognize_max_masks = contracts.recognize_max_masks;

    const recognize_mask_max = contracts.recognize_mask_max;

    const recognize_key_max = contracts.recognize_key_max;

    const recognize_value_max = contracts.recognize_value_max;

    pub const RecognizeAdd = contracts.RecognizeAdd;

    fn recognizeKey(buf: []u8, account: []const u8) ?[]const u8 {
        return account_props_domain.Context.recognizeKey(buf, account);
    }

    fn validRecognizeMask(mask: []const u8) bool {
        return account_props_domain.Context.validRecognizeMask(mask);
    }

    pub fn recognizeMatches(self: *Services, account: []const u8, hostmask: []const u8) bool {
        return self.account_propsView().recognizeMatches(account, hostmask);
    }

    pub fn recognizeBlob(self: *Services, account: []const u8, out: []u8) []const u8 {
        return self.account_propsView().recognizeBlob(account, out);
    }

    pub fn recognizeAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!RecognizeAdd {
        return self.account_propsView().recognizeAdd(account, mask);
    }

    pub fn recognizeDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!bool {
        return self.account_propsView().recognizeDel(account, mask);
    }

    const metadata_prefix = contracts.metadata_prefix;

    const metadata_key_max = contracts.metadata_key_max;

    const metadata_value_max = contracts.metadata_value_max;

    const metadata_full_key_max = contracts.metadata_full_key_max;

    fn metadataAccountPrefix(buf: []u8, account: []const u8) ?[]const u8 {
        return account_props_domain.Context.metadataAccountPrefix(buf, account);
    }

    fn metadataKey(buf: []u8, account: []const u8, key: []const u8) ?[]const u8 {
        return account_props_domain.Context.metadataKey(buf, account, key);
    }

    pub fn metadataPut(self: *Services, account: []const u8, key: []const u8, value: []const u8, vis_token: []const u8) ServiceError!void {
        return self.account_propsView().metadataPut(account, key, value, vis_token);
    }

    pub fn metadataDelete(self: *Services, account: []const u8, key: []const u8) ServiceError!void {
        return self.account_propsView().metadataDelete(account, key);
    }

    pub fn metadataForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, []const u8, []const u8) void) void {
        return self.account_propsView().metadataForEach(account, ctx, cb);
    }

    const silence_prefix = contracts.silence_prefix;

    const silence_max_masks = contracts.silence_max_masks;

    const silence_mask_max = contracts.silence_mask_max;

    const silence_key_max = contracts.silence_key_max;

    const silence_value_max = contracts.silence_value_max;

    fn silenceKey(buf: []u8, account: []const u8) ?[]const u8 {
        return account_props_domain.Context.silenceKey(buf, account);
    }

    pub fn silencePersistAdd(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        return self.account_propsView().silencePersistAdd(account, mask);
    }

    pub fn silencePersistDel(self: *Services, account: []const u8, mask: []const u8) ServiceError!void {
        return self.account_propsView().silencePersistDel(account, mask);
    }

    pub fn silenceForEach(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        return self.account_propsView().silenceForEach(account, ctx, cb);
    }

    const webpush_prefix = contracts.webpush_prefix;

    const webpush_key_max = contracts.webpush_key_max;

    pub const webpush_value_max = contracts.webpush_value_max;

    fn webpushKey(buf: []u8, account: []const u8) ?[]const u8 {
        return webpush_domain.Context.webpushKey(buf, account);
    }

    pub fn webpushGetAlloc(self: *Services, allocator: std.mem.Allocator, account: []const u8) ?[]u8 {
        return self.webpushView().webpushGetAlloc(allocator, account);
    }

    pub fn webpushGetAllocStrict(self: *Services, allocator: std.mem.Allocator, account: []const u8) (ServiceError || std.mem.Allocator.Error)!?[]u8 {
        return self.webpushView().webpushGetAllocStrict(allocator, account);
    }

    pub fn webpushPut(self: *Services, account: []const u8, blob: []const u8) ServiceError!void {
        return self.webpushView().webpushPut(account, blob);
    }

    pub fn webpushPutStrict(self: *Services, account: []const u8, blob: []const u8) ServiceError!void {
        return self.webpushView().webpushPutStrict(account, blob);
    }

    pub const WebpushPruneResult = contracts.WebpushPruneResult;

    const WebpushPruneRow = contracts.WebpushPruneRow;

    pub fn webpushPruneDead(self: *Services, allocator: std.mem.Allocator, endpoints: []const []const u8) !WebpushPruneResult {
        return self.webpushView().webpushPruneDead(allocator, endpoints);
    }

    pub fn webpushPruneDeadUntil(self: *Services, allocator: std.mem.Allocator, endpoints: []const []const u8, deadline: std.Io.Clock.Timestamp) !WebpushPruneResult {
        return self.webpushView().webpushPruneDeadUntil(allocator, endpoints, deadline);
    }

    fn requireWebpushPruneDeadline(self: *Services, deadline: ?std.Io.Clock.Timestamp) !void {
        return self.webpushView().requireWebpushPruneDeadline(deadline);
    }

    fn webpushPruneDeadImpl(self: *Services, allocator: std.mem.Allocator, endpoints: []const []const u8, deadline: ?std.Io.Clock.Timestamp) !WebpushPruneResult {
        return self.webpushView().webpushPruneDeadImpl(allocator, endpoints, deadline);
    }

    pub const totp_secret_max = contracts.totp_secret_max;

    const totp_prefix = contracts.totp_prefix;

    const totp_key_max = contracts.totp_key_max;

    fn totpKey(buf: []u8, account: []const u8) ?[]const u8 {
        return mfa_domain.Context.totpKey(buf, account);
    }

    pub fn totpPolicyCommit(self: *Services, account: []const u8, secret_b32: ?[]const u8) ServiceError!void {
        return self.mfaView().totpPolicyCommit(account, secret_b32);
    }

    pub fn totpSecretPut(self: *Services, account: []const u8, secret_b32: []const u8) ServiceError!void {
        return self.mfaView().totpSecretPut(account, secret_b32);
    }

    pub fn totpSecretGet(self: *Services, account: []const u8, out: []u8) ?[]const u8 {
        return self.mfaView().totpSecretGet(account, out);
    }

    pub fn totpSecretDelete(self: *Services, account: []const u8) ServiceError!void {
        return self.mfaView().totpSecretDelete(account);
    }

    pub fn totpEnrolled(self: *Services, account: []const u8) bool {
        return self.mfaView().totpEnrolled(account);
    }

    pub const recovery_code_count = contracts.recovery_code_count;

    pub const recovery_code_raw_len = contracts.recovery_code_raw_len;

    pub const recovery_digest_len = contracts.recovery_digest_len;

    const rcd_prefix = contracts.rcd_prefix;

    const rcd_key_max = contracts.rcd_key_max;

    const rcd_blob_max = contracts.rcd_blob_max;

    fn rcdKey(buf: []u8, account: []const u8) ?[]const u8 {
        return mfa_domain.Context.rcdKey(buf, account);
    }

    fn hashRecoveryCode(out: *[recovery_digest_len]u8, account: []const u8, code: []const u8) void {
        return mfa_domain.Context.hashRecoveryCode(out, account, code);
    }

    pub fn recoveryCodesRemaining(self: *Services, account: []const u8) usize {
        return self.mfaView().recoveryCodesRemaining(account);
    }

    pub fn recoveryCodesReplace(self: *Services, account: []const u8, codes: []const []const u8) ServiceError!void {
        return self.mfaView().recoveryCodesReplace(account, codes);
    }

    pub fn recoveryCodesClear(self: *Services, account: []const u8) ServiceError!void {
        return self.mfaView().recoveryCodesClear(account);
    }

    pub fn recoveryCodeConsume(self: *Services, account: []const u8, code: []const u8) ServiceError!void {
        return self.mfaView().recoveryCodeConsume(account, code);
    }

    pub fn channelsForAccount(self: *Services, account: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, AccessLevel) void) void {
        return self.channelsView().channelsForAccount(account, ctx, cb);
    }

    const chanbadword_prefix = contracts.chanbadword_prefix;

    const chanbadword_max = contracts.chanbadword_max;

    const chanbadword_pattern_max = contracts.chanbadword_pattern_max;

    const chanbadword_key_max = contracts.chanbadword_key_max;

    const chanbadword_value_max = contracts.chanbadword_value_max;

    fn chanBadwordKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.chanBadwordKey(buf, channel);
    }

    pub fn chanBadwordAdd(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        return self.channel_propsView().chanBadwordAdd(channel, pattern);
    }

    pub fn chanBadwordDel(self: *Services, channel: []const u8, pattern: []const u8) ServiceError!bool {
        return self.channel_propsView().chanBadwordDel(channel, pattern);
    }

    pub fn chanBadwordForEach(self: *Services, channel: []const u8, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8) void) void {
        return self.channel_propsView().chanBadwordForEach(channel, ctx, cb);
    }

    pub fn chanBadwordMatches(self: *Services, channel: []const u8, text: []const u8) bool {
        return self.channel_propsView().chanBadwordMatches(channel, text);
    }

    const keeptopic_prefix = contracts.keeptopic_prefix;

    const keeptopic_key_max = contracts.keeptopic_key_max;

    const keeptopic_text_max = contracts.keeptopic_text_max;

    const keeptopic_setter_max = contracts.keeptopic_setter_max;

    const keeptopic_meta_sentinel = contracts.keeptopic_meta_sentinel;

    const keeptopic_meta_version = contracts.keeptopic_meta_version;

    const keeptopic_meta_header = contracts.keeptopic_meta_header;

    const keeptopic_value_max = contracts.keeptopic_value_max;

    pub const KeepTopicRestore = contracts.KeepTopicRestore;

    fn keepTopicKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.keepTopicKey(buf, channel);
    }

    pub fn chanKeepTopicEnable(self: *Services, channel: []const u8, on: bool) ServiceError!void {
        return self.channel_propsView().chanKeepTopicEnable(channel, on);
    }

    pub fn chanKeepTopicSave(
        self: *Services,
        channel: []const u8,
        topic: []const u8,
        setter: []const u8,
        set_at: i64,
    ) ServiceError!void {
        return self.channel_propsView().chanKeepTopicSave(channel, topic, setter, set_at);
    }

    pub fn chanKeepTopicGet(
        self: *Services,
        channel: []const u8,
        text_out: []u8,
        setter_out: []u8,
    ) ?KeepTopicRestore {
        return self.channel_propsView().chanKeepTopicGet(channel, text_out, setter_out);
    }

    fn decodeKeepTopicMeta(blob: []const u8, text_out: []u8, setter_out: []u8) ?KeepTopicRestore {
        return channel_props_domain.Context.decodeKeepTopicMeta(blob, text_out, setter_out);
    }

    const successor_prefix = contracts.successor_prefix;

    const successor_pending_prefix = contracts.successor_pending_prefix;

    const successor_key_max = contracts.successor_key_max;

    const successor_pending_key_max = contracts.successor_pending_key_max;

    fn successorKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.successorKey(buf, channel);
    }

    fn successorPendingKey(buf: []u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.successorPendingKey(buf, channel);
    }

    fn successorPrefixedKey(buf: []u8, prefix: []const u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.successorPrefixedKey(buf, prefix, channel);
    }

    fn promoteReadySuccessorUnlocked(self: *Services, armed_key: []const u8, pending_key: []const u8) ServiceError!void {
        return self.channel_propsView().promoteReadySuccessorUnlocked(armed_key, pending_key);
    }

    fn copyBoundedProp(self: *Services, key: []const u8, dest: []u8) ?[]const u8 {
        return self.channel_propsView().copyBoundedProp(key, dest);
    }

    pub fn channelSuccessorSet(self: *Services, channel: []const u8, account: []const u8) ServiceError!void {
        return self.channel_propsView().channelSuccessorSet(channel, account);
    }

    pub fn channelSuccessorClear(self: *Services, channel: []const u8) ServiceError!void {
        return self.channel_propsView().channelSuccessorClear(channel);
    }

    pub fn channelSuccessorGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.channel_propsView().channelSuccessorGet(channel, out);
    }

    const meta_value_max = contracts.meta_value_max;

    fn metaKey(buf: []u8, tag: []const u8, channel: []const u8) ?[]const u8 {
        return channel_props_domain.Context.metaKey(buf, tag, channel);
    }

    fn chanMetaSet(self: *Services, tag: []const u8, channel: []const u8, value: []const u8) ServiceError!void {
        return self.channel_propsView().chanMetaSet(tag, channel, value);
    }

    fn chanMetaGet(self: *Services, tag: []const u8, channel: []const u8, out: []u8) ?[]const u8 {
        return self.channel_propsView().chanMetaGet(tag, channel, out);
    }

    pub fn chanDescSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.channel_propsView().chanDescSet(channel, value);
    }

    pub fn chanDescGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.channel_propsView().chanDescGet(channel, out);
    }

    pub fn chanUrlSet(self: *Services, channel: []const u8, value: []const u8) ServiceError!void {
        return self.channel_propsView().chanUrlSet(channel, value);
    }

    pub fn chanUrlGet(self: *Services, channel: []const u8, out: []u8) ?[]const u8 {
        return self.channel_propsView().chanUrlGet(channel, out);
    }

    pub fn replayLiveState(self: *Services, sink: LiveReplaySink) ServiceError!LiveReplaySummary {
        return self.channelsView().replayLiveState(sink);
    }

    fn addCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        return self.credentialsView().addCertfpListEntry(account, fingerprint);
    }

    fn removeCertfpListEntry(self: *Services, account: []const u8, fingerprint: []const u8) ServiceError!void {
        return self.credentialsView().removeCertfpListEntry(account, fingerprint);
    }

    fn observationFactHash(
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        origin: ?ObservationOrigin,
    ) key_transparency.Hash {
        return key_transparency_domain.Context.observationFactHash(account, kind, action, key_id, material, origin);
    }

    fn recordKeyTransparency(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) void {
        return self.key_transparencyView().recordKeyTransparency(account, kind, action, key_id, material, timestamp_ms);
    }

    fn commitKeyTransparency(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        material: []const u8,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        return self.key_transparencyView().commitKeyTransparency(account, kind, action, key_id, material, timestamp_ms);
    }

    fn commitKeyTransparencyHashed(
        self: *Services,
        account: []const u8,
        kind: key_transparency.CredentialKind,
        action: key_transparency.Action,
        key_id: []const u8,
        key_hash: key_transparency.Hash,
        timestamp_ms: i64,
    ) KeyTransparencyRecordError!void {
        return self.key_transparencyView().commitKeyTransparencyHashed(account, kind, action, key_id, key_hash, timestamp_ms);
    }

    pub fn accountAuthBlocked(self: *Services, account: []const u8) bool {
        return self.accountsView().accountAuthBlocked(account);
    }

    pub fn accountIsRegistered(self: *Services, account: []const u8) bool {
        return self.accountsView().accountIsRegistered(account);
    }

    fn accountSuspendedUnlocked(self: *Services, account: []const u8) ServiceError!bool {
        return self.persistenceView().accountSuspendedUnlocked(account);
    }

    fn accountForbiddenUnlocked(self: *Services, account: []const u8) bool {
        return self.persistenceView().accountForbiddenUnlocked(account);
    }

    fn loadAccount(self: *Services, name: []const u8) ServiceError!AccountRecord {
        return self.persistenceView().loadAccount(name);
    }

    fn saveAccount(self: *Services, record: AccountRecord, scratch: []u8) ServiceError!void {
        return self.persistenceView().saveAccount(record, scratch);
    }

    fn loadChannel(self: *Services, channel: []const u8) ServiceError!ChannelRecord {
        return self.persistenceView().loadChannel(channel);
    }

    pub fn channelIsRegistered(self: *Services, channel: []const u8) bool {
        return self.persistenceView().channelIsRegistered(channel);
    }

    fn putAccess(
        self: *Services,
        channel: ChannelRecord,
        account: AccountName,
        level: AccessLevel,
        scratch: []u8,
    ) ServiceError!AccessRecord {
        return self.persistenceView().putAccess(channel, account, level, scratch);
    }

    fn loadAccess(self: *Services, channel: ChannelRecord, account: []const u8) ServiceError!AccessRecord {
        return self.persistenceView().loadAccess(channel, account);
    }

    fn loadAkick(self: *Services, channel: ChannelRecord, mask: []const u8) ServiceError!AkickRecord {
        return self.persistenceView().loadAkick(channel, mask);
    }

    fn requireAccess(self: *Services, channel: ChannelRecord, actor: []const u8, needed: AccessLevel) ServiceError!void {
        return self.persistenceView().requireAccess(channel, actor, needed);
    }

    pub const DirectoryReconcile = contracts.DirectoryReconcile;

    /// Copy account verifiers, channel registrations, ACCESS rows, and AKICK
    /// rows that one store lacks. The account bytes are the stored salt and
    /// hash. A key that both stores already hold with different bytes is left
    /// untouched and the call fails closed before any copy.
    pub fn reconcileDirectory(self: *Services, peer: *Services) !DirectoryReconcile {
        if (self == peer or self.store == peer.store) return .{ .copied = 0 };
        const self_first = @intFromPtr(self) <= @intFromPtr(peer);
        if (self_first) {
            self.lock.lockExclusive();
            peer.lock.lockExclusive();
        } else {
            peer.lock.lockExclusive();
            self.lock.lockExclusive();
        }
        defer {
            self.lock.unlockExclusive();
            peer.lock.unlockExclusive();
        }
        if (directoryConflicts(self.store, peer.store)) return error.DirectoryDisagreement;
        const copied = try copyMissingDirectory(self.store, peer.store) + try copyMissingDirectory(peer.store, self.store);
        return .{ .copied = copied };
    }

    fn account_propsView(self: *const Services) account_props_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock) };
    }

    fn accountsView(self: *const Services) accounts_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .cfg = &self.cfg, .scram = &self.scram, .clock_override_ms = &self.clock_override_ms };
    }

    fn channel_propsView(self: *const Services) channel_props_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .clock_override_ms = &self.clock_override_ms };
    }

    fn channelsView(self: *const Services) channels_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .state = &self.state };
    }

    fn clockView(self: *const Services) clock_domain.Context {
        return .{ .store = &self.store, .clock_override_ms = &self.clock_override_ms };
    }

    fn credentialsView(self: *const Services) credentials_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .certfp_binds = &self.certfp_binds, .key_transparency = &self.key_transparency };
    }

    fn device_factsView(self: *const Services) device_facts_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .key_transparency = &self.key_transparency, .durable_credential_props_state = &self.durable_credential_props_state };
    }

    fn key_transparencyView(self: *const Services) key_transparency_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .key_transparency = &self.key_transparency };
    }

    fn mfaView(self: *const Services) mfa_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock) };
    }

    fn oper_authorityView(self: *const Services) oper_authority_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .durable_oper_authority_state = @constCast(&self.durable_oper_authority_state), .durable_oper_availability_epoch = @constCast(&self.durable_oper_availability_epoch) };
    }

    fn oper_availabilityView(self: *const Services) oper_availability_domain.Context {
        return .{ .lock = @constCast(&self.lock), .durable_oper_authority_state = @constCast(&self.durable_oper_authority_state), .durable_oper_availability_epoch = @constCast(&self.durable_oper_availability_epoch) };
    }

    fn oper_clockView(self: *const Services) oper_clock_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock), .durable_oper_authority_state = @constCast(&self.durable_oper_authority_state), .durable_oper_availability_epoch = @constCast(&self.durable_oper_availability_epoch) };
    }

    fn persistenceView(self: *const Services) persistence_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock) };
    }

    fn sessionsView(self: *const Services) sessions_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock) };
    }

    fn webpushView(self: *const Services) webpush_domain.Context {
        return .{ .store = &self.store, .lock = @constCast(&self.lock) };
    }
};

/// Internal seams for white-box tests; these are not exported by services.zig.
pub const Internal = struct {
    pub const scramPasswordGate = Services.scramPasswordGate;
    pub const servicesNowMs = Services.servicesNowMs;
    pub const attachDurableOperAuthorityForTest = Services.attachDurableOperAuthorityForTest;
    pub const attachInactiveDurableOperAuthorityForTest = Services.attachInactiveDurableOperAuthorityForTest;
    pub const markDurableOperUnavailableLocked = Services.markDurableOperUnavailableLocked;
    pub const markDurableOperUnavailableForTest = Services.markDurableOperUnavailableForTest;
    pub const inspectDurableOperReconcileWorkInner = Services.inspectDurableOperReconcileWorkInner;
    pub const ocg2ReconcileCopyStillLive = Services.ocg2ReconcileCopyStillLive;
    pub const inspectDurableOperTransactionInner = Services.inspectDurableOperTransactionInner;
    pub const inspectDurableOperAuthorityInner = Services.inspectDurableOperAuthorityInner;
    pub const projectDurableOperSecurityLocked = Services.projectDurableOperSecurityLocked;
    pub const durableOperSecurityHorizonCopy = Services.durableOperSecurityHorizonCopy;
    pub const publishDurableOperSecurityAnchorsLocked = Services.publishDurableOperSecurityAnchorsLocked;
    pub const validateNewPassword = Services.validateNewPassword;
    pub const passkeysBoundUnlocked = Services.passkeysBoundUnlocked;
    pub const persistScram = Services.persistScram;
    pub const scramLoadThunk = Services.scramLoadThunk;
    pub const accountForCertfpUnlocked = Services.accountForCertfpUnlocked;
    pub const certfpOwnerUnlocked = Services.certfpOwnerUnlocked;
    pub const loginAuditKey = Services.loginAuditKey;
    pub const loginMechanismFromByte = Services.loginMechanismFromByte;
    pub const loginTlsFromByte = Services.loginTlsFromByte;
    pub const decodeLoginAuditRecord = Services.decodeLoginAuditRecord;
    pub const identifyAccountChecked = Services.identifyAccountChecked;
    pub const channelAccessUnlocked = Services.channelAccessUnlocked;
    pub const channelAkickUnlocked = Services.channelAkickUnlocked;
    pub const recognizeKey = Services.recognizeKey;
    pub const validRecognizeMask = Services.validRecognizeMask;
    pub const metadataAccountPrefix = Services.metadataAccountPrefix;
    pub const metadataKey = Services.metadataKey;
    pub const silenceKey = Services.silenceKey;
    pub const webpushKey = Services.webpushKey;
    pub const requireWebpushPruneDeadline = Services.requireWebpushPruneDeadline;
    pub const webpushPruneDeadImpl = Services.webpushPruneDeadImpl;
    pub const totpKey = Services.totpKey;
    pub const rcdKey = Services.rcdKey;
    pub const hashRecoveryCode = Services.hashRecoveryCode;
    pub const chanBadwordKey = Services.chanBadwordKey;
    pub const keepTopicKey = Services.keepTopicKey;
    pub const decodeKeepTopicMeta = Services.decodeKeepTopicMeta;
    pub const successorKey = Services.successorKey;
    pub const successorPendingKey = Services.successorPendingKey;
    pub const successorPrefixedKey = Services.successorPrefixedKey;
    pub const promoteReadySuccessorUnlocked = Services.promoteReadySuccessorUnlocked;
    pub const copyBoundedProp = Services.copyBoundedProp;
    pub const metaKey = Services.metaKey;
    pub const chanMetaSet = Services.chanMetaSet;
    pub const chanMetaGet = Services.chanMetaGet;
    pub const addCertfpListEntry = Services.addCertfpListEntry;
    pub const removeCertfpListEntry = Services.removeCertfpListEntry;
    pub const observationFactHash = Services.observationFactHash;
    pub const recordKeyTransparency = Services.recordKeyTransparency;
    pub const commitKeyTransparency = Services.commitKeyTransparency;
    pub const commitKeyTransparencyHashed = Services.commitKeyTransparencyHashed;
    pub const accountSuspendedUnlocked = Services.accountSuspendedUnlocked;
    pub const accountForbiddenUnlocked = Services.accountForbiddenUnlocked;
    pub const loadAccount = Services.loadAccount;
    pub const saveAccount = Services.saveAccount;
    pub const loadChannel = Services.loadChannel;
    pub const putAccess = Services.putAccess;
    pub const loadAccess = Services.loadAccess;
    pub const loadAkick = Services.loadAkick;
    pub const requireAccess = Services.requireAccess;
    pub const ProjectedDurableOperSecurity = Services.ProjectedDurableOperSecurity;
    pub const recognize_prefix = Services.recognize_prefix;
    pub const recognize_max_masks = Services.recognize_max_masks;
    pub const recognize_mask_max = Services.recognize_mask_max;
    pub const recognize_key_max = Services.recognize_key_max;
    pub const recognize_value_max = Services.recognize_value_max;
    pub const metadata_prefix = Services.metadata_prefix;
    pub const metadata_key_max = Services.metadata_key_max;
    pub const metadata_value_max = Services.metadata_value_max;
    pub const metadata_full_key_max = Services.metadata_full_key_max;
    pub const silence_prefix = Services.silence_prefix;
    pub const silence_max_masks = Services.silence_max_masks;
    pub const silence_mask_max = Services.silence_mask_max;
    pub const silence_key_max = Services.silence_key_max;
    pub const silence_value_max = Services.silence_value_max;
    pub const webpush_prefix = Services.webpush_prefix;
    pub const webpush_key_max = Services.webpush_key_max;
    pub const WebpushPruneRow = Services.WebpushPruneRow;
    pub const totp_prefix = Services.totp_prefix;
    pub const totp_key_max = Services.totp_key_max;
    pub const rcd_prefix = Services.rcd_prefix;
    pub const rcd_key_max = Services.rcd_key_max;
    pub const rcd_blob_max = Services.rcd_blob_max;
    pub const chanbadword_prefix = Services.chanbadword_prefix;
    pub const chanbadword_max = Services.chanbadword_max;
    pub const chanbadword_pattern_max = Services.chanbadword_pattern_max;
    pub const chanbadword_key_max = Services.chanbadword_key_max;
    pub const chanbadword_value_max = Services.chanbadword_value_max;
    pub const keeptopic_prefix = Services.keeptopic_prefix;
    pub const keeptopic_key_max = Services.keeptopic_key_max;
    pub const keeptopic_text_max = Services.keeptopic_text_max;
    pub const keeptopic_setter_max = Services.keeptopic_setter_max;
    pub const keeptopic_meta_sentinel = Services.keeptopic_meta_sentinel;
    pub const keeptopic_meta_version = Services.keeptopic_meta_version;
    pub const keeptopic_meta_header = Services.keeptopic_meta_header;
    pub const keeptopic_value_max = Services.keeptopic_value_max;
    pub const successor_prefix = Services.successor_prefix;
    pub const successor_pending_prefix = Services.successor_pending_prefix;
    pub const successor_key_max = Services.successor_key_max;
    pub const successor_pending_key_max = Services.successor_pending_key_max;
    pub const meta_value_max = Services.meta_value_max;
};
