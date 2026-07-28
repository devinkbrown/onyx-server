# Onyx Server 0.5.7 — E2EEGROUP opaque control (pre-deploy release note)

**Status:** pre-deploy preparation only.
**No deployment, dual-node restart, public GitHub release publish, or production
acceptance is claimed by this document.**

Paired product versions for this cut:

| Component | Version field | New value |
|-----------|---------------|-----------|
| Onyx Server | `build.zig.zon` `.version` | `0.5.7` |
| Onyx client (private package) | `package.json` `version` | `0.1.1` |

## What this cut prepares

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

## Explicitly unimplemented / not accepted

| Gap | Reality |
|-----|---------|
| Pairwise welcome key wrapping | Welcome `body` is reserved for future ciphertext of epoch install material under a recipient device key. No owner module encrypts or decrypts welcome bodies as room keys yet. |
| Client store send/open integration | Pure codec helpers exist; live store/wire paths that **send** signed OGC1 controls, **receive** `E2EE.*` records, verify with a trusted directory, and install epoch keys into the browser keyring are **not** product-wired. |
| Production acceptance | No dual-node deploy, mesh health smoke, live E2EEGROUP authoring quiesce/activation, or operator sign-off is recorded for `0.5.7` in this note. Historical `0.5.6` deploy records remain unchanged. |
| First mesh activation of EGRG v2 | Planned cold restart under a mesh-wide E2EEGROUP authoring barrier (`docs/ops/e2ee-group-authority-v2-activation.md`) is **not** executed here. |

## Document and artifact pointers (facing this version)

- Daemon semver: `build.zig.zon` → `0.5.7` (banner / package truth; git short hash appended at build time).
- Quickstart download links: `README.md`, `docs/guide/00-quickstart.md` → `v0.5.7`.
- Client package: `/home/kain/onyx/package.json` → `0.1.1`.
- Shared contract: keep client copy byte-identical to
  `docs/reference/protocol/onyx-client-contract.v1.json`
  (gate: `pnpm check:server-contract` in the client repo).

## Operator note

Do **not** treat publication of this pre-deploy note as a live upgrade. Ship only
after independent release packaging, dual-node acceptance, and an explicit
deploy authorization under the normal release/deploy skills.
