# Onyx Server 0.5.7 — E2EEGROUP opaque control

**Status:** dual-node production deploy **completed** (2026-07-28). This document
keeps the original pre-deploy product truth below and adds the executed
activation record.

**Not claimed by this document:** client live send/receive integration of OGC1
controls, browser encryption / room-key install, or a published GitHub Release
asset for this cut.

Paired product versions for this cut:

| Component | Version field | New value |
|-----------|---------------|-----------|
| Onyx Server | `build.zig.zon` `.version` | `0.5.7` |
| Onyx client (private package) | `package.json` `version` | `0.1.1` |

---

## Executed dual-node deploy (2026-07-28)

Coordinated maintenance cutover of both dual-node units. Deployed `0.5.6`
predecessors did **not** expose the v2 operator control/metrics, so
`group_authoring_enabled=false` was prepared and validated as the **v2 successor
startup barrier** (not an active quiesce of the still-running old processes).
Fail-closed protection during the version transition was a coordinated full
outage: both predecessor `0.5.6` `onyx-server.service` processes stopped
together before any `0.5.7` successor started; validated `0.5.7+b457c33`
binaries installed only after both predecessors were down; both v2 units started
and mesh/xcap readiness verified; authoring later enabled with a current-version
rolling restart. Procedure reference:
`docs/ops/e2ee-group-authority-v2-activation.md`.

### Immutable live inventory

| Item | Value |
|------|--------|
| Version banner (both nodes) | `Onyx Server 0.5.7+b457c33` |
| Artifact SHA-256 (identical both nodes) | `a867fa71afaaeeda6c6f25b024a995ab8b1436e6b7f9d8b2541f6a1d32d28ed4` |
| Live unit (both nodes) | `onyx-server.service` |
| Nodes | `eshmaki.me`, `ircx.us` |

| | `eshmaki.me` | `ircx.us` |
| --- | --- | --- |
| Live unit | `onyx-server.service` | `onyx-server.service` |
| Banner | `0.5.7+b457c33` | `0.5.7+b457c33` |
| Artifact SHA-256 | `a867fa71afaaeeda6c6f25b024a995ab8b1436e6b7f9d8b2541f6a1d32d28ed4` | same |

### Cutover sequence (facts recorded)

1. Prepared and validated production config with `group_authoring_enabled=false`
   as the **v2 successor startup barrier** (deployed `0.5.6` did not expose this
   control or its metrics; the key did not quiesce running predecessors).
2. Both predecessor `0.5.6` `onyx-server.service` processes **stopped together**
   (coordinated full outage — the fail-closed protection for the version
   transition; not one-node-at-a-time; not Helix USR2 first-rollout path).
3. Validated `0.5.7+b457c33` binaries **installed only after both** predecessors
   were down; production configs (including the successor barrier) validated
   against the installed image.
4. Both v2 units **started** under that successor barrier, then secured mesh
   xcap readiness for current E2EEGROUP verified on the dual-node link.
5. Authoring **enabled later** with a current-version rolling restart (both nodes
   already on `0.5.7+b457c33`).

### Post-activation metrics (each node)

Observed on **both** `eshmaki.me` and `ircx.us` after authoring release:

| Metric / signal | Value |
|-----------------|-------|
| `local_authoring_enabled` | `1` |
| `current_capable_peers` | `1` |
| `required_peers` | `1` |
| `activation_ready` | `1` |
| hop custody (`onyx_e2ee_group_hop_custody` / hop_custody) | `0` |
| ingress receipts (`onyx_e2ee_group_ingress_receipts` / ingress_receipts) | `0` |
| pending (`onyx_e2ee_group_pending` / pending) | `0` |

### Mesh health (both directions)

| Signal | Value |
|--------|-------|
| `links_active` | `1` |
| `peers_up` | `1` |
| `partitioned` | `0` |
| `tcp_active` | `1` |

### Boundaries still true after deploy

| Gap | Reality |
|-----|---------|
| Client store send/open integration | Pure OGC1 codec helpers exist; live client store/wire paths that **send** signed OGC1 controls, **receive** `E2EE.*` records, verify with a trusted directory, and install epoch keys into the browser keyring remain **not** product-wired. This deploy does **not** claim client live send/receive or browser encryption. |
| GitHub Release asset | No GitHub Release asset publication is recorded or claimed by this note. |
| Pairwise welcome key wrapping | Welcome `body` remains reserved for future ciphertext; no owner module encrypts/decrypts welcome bodies as room keys yet. |
| Historical `0.5.6` records | Unchanged (`docs/ops/deploy-v0.5.6-*.md`). |

---

## What this cut prepared (pre-deploy product truth; preserved)

### Server: durable opaque E2EEGROUP control delivery

Onyx Server source already implements an **active** path for authenticated
membership policy and **opaque** group control-record delivery:

- Client command `E2EEGROUP` (IRCX-gated) admits bounded, origin-authenticated
  control records whose trailing payload is **canonical unpadded base64url**.
  The daemon does **not** parse that payload as crypto material, decrypt it, or
  treat it as a group secret.
- Local delivery fans out as channel records
  (`E2EE.KEYPACKAGE` / `E2EE.COMMIT`) or targeted welcome records
  (`E2EE.WELCOME`) to eligible recipients (`onyx/e2ee` negotiated and joined).
- Mesh hop path retains **exact origin-signed wires** in a bounded outbox with
  durable ingress **receipt** metadata (peer + `RelayId` only), replay/equivocation
  authority, and fail-closed capacity. Live custody wires and opaque payloads are
  **not** sealed into Helix checkpoints; authority encode fails closed while hop
  custody remains outstanding.
- Contract surface (shared with the client package):
  `docs/reference/protocol/onyx-client-contract.v1.json` → `group_e2ee`
  (`server_role`: authenticated membership policy and opaque control-record
  delivery only; `persistence`: none for secrets).

This is **delivery and mesh authority for opaque control bytes**, not room-key
escrow and not MLS/RFC 9420 wire interoperability.

### Client: OGC1 signed control payload (staged)

The private Onyx client defines a first **versioned** control payload that rides
the opaque `E2EEGROUP` trailing parameter:

| Item | Value |
|------|--------|
| Magic | ASCII `OGC1` |
| Version | `1` |
| Domain | `ONYX-GROUP-CONTROL-v1` |
| Layout | magic ‖ version ‖ kind ‖ epoch ‖ body_len ‖ body ‖ signer_pub(32) ‖ signature(64) |
| Kinds | `1` key-package, `2` welcome, `3` commit |
| Codec module | `src/lib/e2ee/groupControlPayload.ts` (pure sign/parse/verify) |
| Protocol doc | `docs/protocol/group-e2ee-c1.md` |

Fail-closed trust and metadata boundaries (current design):

1. **Trusted signer is mandatory.** Verification takes an externally supplied
   Ed25519 public key (device directory / pin / enrollment). The wire
   `signer_pub` alone is never account authentication.
2. **Wire `signer_pub` must equal trusted.** Transcript-bound discovery field;
   mismatch rejects.
3. **Outer IRC routing is transcript-bound.** Normalized channel, kind,
   from-device, and welcome targets; metadata substitution fails closed.
4. **Canonical base64url only.** Non-canonical re-encoding fails closed.
5. **Server is not a group member.** No decryptable room secret is required or
   produced for server-side inspection in this format.
6. **No MLS claim.** Kind labels are Onyx control names, not RFC 9420 proof.

Package version bump to `0.1.1` tracks this staged payload + protocol doc truth
for the paired cut. It does **not** assert product-complete room E2EE.

## Explicitly unimplemented / not accepted (product gaps)

These gaps remain after the dual-node server deploy above:

| Gap | Reality |
|-----|---------|
| Pairwise welcome key wrapping | Welcome `body` is reserved for future ciphertext of epoch install material under a recipient device key. No owner module encrypts or decrypts welcome bodies as room keys yet. |
| Client store send/open integration | Pure codec helpers exist; live store/wire paths that **send** signed OGC1 controls, **receive** `E2EE.*` records, verify with a trusted directory, and install epoch keys into the browser keyring are **not** product-wired. |
| Browser encryption / room E2EE product | Not claimed. Server deploy is opaque control delivery + mesh authority only. |
| GitHub Release asset | Not claimed in this note. |

## Document and artifact pointers (facing this version)

- Daemon semver: `build.zig.zon` → `0.5.7` (banner / package truth; git short hash
  appended at build time). Live dual-node banner: `0.5.7+b457c33`.
- Quickstart download links: `README.md`, `docs/guide/00-quickstart.md` → `v0.5.7`
  (link targets only; this note does **not** assert a published Release asset).
- Client package: `/home/kain/onyx/package.json` → `0.1.1`.
- Shared contract: keep client copy byte-identical to
  `docs/reference/protocol/onyx-client-contract.v1.json`
  (gate: `pnpm check:server-contract` in the client repo).
- First EGRG v2 activation procedure / post-status:
  `docs/ops/e2ee-group-authority-v2-activation.md`.

## Operator note

The dual-node `0.5.7+b457c33` cutover is recorded above. Further restarts that
touch E2EEGROUP mesh authority still follow
`docs/ops/e2ee-group-authority-v2-activation.md` (quiesce when mixed-version risk
exists; Helix USR2 EGRG adopt remains a later path, not this first cold path).
