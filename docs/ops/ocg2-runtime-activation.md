# OCG2 runtime activation

OCG2 durable operator authority is deliberately activated in separate stages.
The default configuration is fully disabled and retains the existing configured-local
operator behavior.

## Modes

| Configuration | Boot mode | Current behavior |
| --- | --- | --- |
| `enabled = false` | `disabled` | No OCG2 store activation, allocation, timer work, projection, or minting. |
| `enabled = true` | `observe` | Strictly restore the durable image, establish its security clock, and continuously validate bounded reconciliation work. No live privilege changes. |
| `projection_enabled = true` | `project` | Reserved. This build fails boot because projection is not yet exposed. |
| `minting_enabled = true` | `mint` | Reserved. This build fails boot because minting is not yet exposed. |

Projection requires `enabled = true`. Minting requires both `enabled = true` and
`projection_enabled = true`, and is valid only on the exact configured authority
node. Invalid combinations fail configuration parsing.

## Observe-mode boundary

Observe mode owns fixed 256-entry scratch inventories. Before listeners open it:

1. validates the local public authority role;
2. strictly initializes or restores the durable image;
3. attaches that exact image to account Services;
4. establishes the first durable security horizon with elapsed monotonic time zero;
5. copies, schedules, plans, and reinspects every initial durable transaction.

Only a fully successful initial pass permits the server to start. Retryable store
pressure, an unavailable image, clock failure, or an invariant failure aborts boot.
The observer is heap-allocated only in observe mode.

Reactor 0 advances the observer during ordinary housekeeping using wall-clock time
plus elapsed monotonic time from the exact synchronous boot sample. A successful
pass acknowledges its advisory baseline atomically. Inventory races retry without
acknowledging stale work. Fatal clock or invariant failures poison the durable
authority image and leave the observer permanently failed.

The observer has no session, command, issuer, event, callback, mesh, transmission,
grant, revoke, or projection capability. Existing configured-local and legacy OCG1
operator paths remain unchanged.

## Rollout

1. Deploy the binary everywhere with `[oper.ocg2]` absent or `enabled = false`.
2. Confirm ordinary SASL/operator, mesh, Helix, and restart acceptance.
3. Provision the same public authority tuple and durable storage prerequisites on
   each node, keeping projection and minting false.
4. Enable observe mode one node at a time and confirm the primed boot log plus
   stable housekeeping.
5. Do not enable projection or minting until a later build implements and tests
   their complete fail-closed lifecycle.

Never place an authority private key in the TOML file. The configured tuple is
public-only; authority identity is bound to the already-provisioned node key.
