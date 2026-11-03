# Modes Upgrade — Audit, Conflicts, and Expansion Plan

Audit performed against `c221033` (clean worktree, no in-flight changes).
Every claim below cites `file:line` verified at that commit.

---

## 1. Current mode inventory

### 1.1 User modes — 16 defined + 1 derived (at audit time)

Source: `src/proto/usermode.zig:147-164`. Backing enum `UserMode` was
`enum(u4)` and held exactly 16 variants — **the enum was full**. Storage is
`UmodeSet.bits: u64`.

> Post-change: **17 defined + 1 derived**; `UserMode` is now `enum(u5)` and
> `+I` hide-idle is appended. See §7.4.

| Letter | Mode | Policy |
|---|---|---|
| `i` | invisible | client-settable |
| `B` | bot (IRCv3 `bot`) | client-settable |
| `r` | registered | server-managed |
| `z` | secure-tls | server-managed |
| `D` | deaf | client-settable |
| `g` | callerid | client-settable |
| `C` | no-ctcp | client-settable |
| `x` | cloaked | server-managed |
| `R` | regonly-pm | client-settable |
| `p` | hide-chans | client-settable |
| `Q` | no-forward | client-settable |
| `H` | hide-oper | client-settable |
| `M` | media-tx-deny | server-managed |
| `P` | media-presence-private | client-settable |
| `a` | admin | server-managed |
| `j` | override | client-settable |
| `o` | operator (derived, not in enum) | derived — `usermode.zig:166` |

### 1.2 Channel modes — three separate systems

Onyx has **three** distinct channel-mode systems that all feed one `MODE`
command. This split is the root cause of every conflict in §2.

**(a) Base modes — 19**, `src/daemon/chanmode.zig:99-117`, enum `ChannelMode`:

| Group | Letters |
|---|---|
| A (list) | `b` ban, `e` exempt, `I` invite-exception |
| B (param always) | `k` key |
| C (param on set) | `l` limit |
| D (flag) | `i` `m` `n` `t` `s` `C` `T` `N` `g` `S` `M` `W` `O` `A` |

**(b) World-layer modes — 3**, enforced in `world.zig`, deliberately *not* in
the enum (documented at `src/daemon/dispatch.zig`, the CHANMODES honesty test):

| Letter | Meaning | Group |
|---|---|---|
| `f` | forward target | C |
| `j` | join throttle | C |
| `Z` | quiet (mute list) | A |

**(c) IRCX extended flags — 20**, `src/proto/chanmode_ext.zig:51-72`, stored in
`ExtChannelFlags` — a `packed struct(u32)` (`chanmode_ext.zig:118`):

`p` `h` `s` `m` `t` `i` `n` `u` `a` `f` `d` `E`\* `r`\* `z`\* `x` `w` `V` `U` `F` `D`
(\* = `requires_oper`)

### 1.3 Advertised ISUPPORT

| Token | Value | Source |
|---|---|---|
| `CHANMODES` | `beIZ,k,lfj,imnstCTNMSgWOAVUFD` | `src/proto/protocol_inventory.zig:59` |
| `MAXLIST` | `beIZ:100` (config `[limits] maxlist`) | `src/daemon/server.zig:1513` |
| `PREFIX` | `(YQqov)*!.@+` | `src/daemon/chanmode.zig:405` |

---

## 2. Conflicts

### C1 — Letter `f` means two different things, in two different groups — **live bug** — ✅ RESOLVED (§7.1)

- `+f <target>` = forward target, CHANMODES **group C** (param on set),
  enforced in the world layer.
- `+f` = `NOFORMAT`, an IRCX **flag** (`chanmode_ext.zig:60`).

Both are reachable through the same `MODE` handler: `server.zig` has an
explicit arm for `f`-as-forward, and an `else` arm that resolves unmatched
letters through `chanmode_ext.letterToFlag`. One letter, two storage
locations, two arities. A client cannot tell which `+f` it is looking at, and
`CHANMODES` advertises only the group-C meaning.

**This is the only conflict where two genuinely different features collide on
one letter.** Everything else in this section is duplication or drift.

### C2 — Letters `s` `m` `t` `i` `n` are stored twice

Each of these exists as a base flag (`chanmode.zig`) *and* as an IRCX ext flag
(`chanmode_ext.zig:53-58`) with the same meaning. Two bits, one letter. They
can drift apart (set through one path, read through the other), and any
renderer that walks both tables emits the letter twice.

### C3 — 11 ext flags are enforced but never advertised

`CHANMODES` group D lists `imnstCTNMSgWOAVUFD`. Of the 20 ext flags, only
`V` `U` `F` `D` (plus the five duplicated in C2) appear. Settable but absent
from ISUPPORT:

`p` `h` `u` `a` `f` `d` `E` `r` `z` `x` `w`

A conforming client will not offer these in a mode UI and may reject them as
unknown. This is the mirror image of the usual dishonesty — advertised-but-
unenforced — and the existing honesty test only checks the advertised
direction.

### C4 — `ircx_modex` renders FOUNDER as `~`, ISUPPORT promises `!` — ✅ RESOLVED (§7.3)

`src/proto/ircx_modex.zig:132` sets `status_prefix = '~'` for `FOUNDER`, but
`PREFIX=(YQqov)*!.@+` maps `Q` → `!`.

**Not currently live**: `status_prefix` is written at `ircx_modex.zig:100,132-135`
and read nowhere in `src/`. It is a latent trap — the wrong value is sitting
in an inventory table waiting for someone to wire it up.

### C5 — `isupport.zig` MAXLIST omits the `Z` list

`src/proto/isupport.zig:275` hardcodes `b:100,e:100,I:100` and `:360` formats
`b:{d},e:{d},I:{d}` — both omit `Z`, which *is* a list mode with a limit.

**Not currently live**: `isupport.Builder` is referenced only from its own
property tests (`isupport_props.zig`) and the `proto/root.zig` re-export. The
live token comes from `server.zig:1513`. Same class as C4 — unwired code
carrying a value that is already wrong.

### C6 — `h` is HIDDEN, not halfop (intentional, but a client-compat trap)

Most IRCds use `+h` for halfop. Onyx has **no halfop** and uses lowercase `h`
for the IRCX `HIDDEN` flag (`chanmode_ext.zig:53`). Correct by design; worth
stating explicitly because a client that assumes halfop will mis-render it.

---

## 3. Letter-space budget

Reserved for member prefixes (never available as channel modes): `Y` `Q` `q`
`o` `v`.

**Genuinely free channel letters — 10:** `c` `B` `G` `H` `J` `K` `L` `P` `R` `X`
(`c` is the only free lowercase letter; note case matters — lowercase `h` is
taken by HIDDEN, uppercase `H` is free.)

**Free user letters — plentiful:** lowercase `b c d e f h k l m n q s t u v w y`,
uppercase `A E F G I J K L N O S T U V W X Y Z`.

### 3.1 Hard capacity limits — the constraint that shapes everything

| Space | Used | Ceiling | Cost to exceed |
|---|---|---|---|
| Base channel flags | 14 | **16** (`u16` field, mask `0x3fff`) | `world.zig:284` mask + `world_checkpoint.zig:411` `writeU16` → **serialized length change ⇒ capsule version bump** |
| Ext channel flags | 20 | 32 (`packed struct(u32)`) | mask widen only — **no length change** |
| User modes | 16 | 64 (`UmodeSet.bits: u64`) | widen `UserMode` `u4`→`u5` — **no length change** (`umode_bits` already serialized as `u64`) |

**Only 2 base channel flag slots remain** before the world-checkpoint capsule
needs a version bump plus a version-aware decode and a cross-version test
(§2.2 Helix rule). Extended flags and user modes are the cheap places to grow.

---

## 4. Cross-check: requested modes vs. what already exists

The brief asked for a specific letter list. Most of it is **already
implemented**, and several requested letters are **already taken by a
different feature** — adding them verbatim would create new conflicts, which
is the opposite of the stated goal.

### Channel

| Requested | Reality |
|---|---|
| `+s` secret | Already present — and is conflict **C2** |
| `+p` private | Already present (ext `p`), unadvertised — conflict **C3** |
| `+q` quiet | Already present as **`+Z`**; `q` is a PREFIX letter (owner) |
| `+M` moderated-unregistered | Already present (base `M`) |
| `+u` allow-unauthenticated | Inverse already present (`M` / ext `a` AUTHONLY); `u` = KNOCK |
| `+z` lazy join | `z` = SERVICE (taken) |
| `+E` encrypted-only | `E` = CLONE (taken) |
| `+F` slowmode | `F` = FREETARGET (taken); slowmode genuinely absent |
| `+H` hide joins/parts | Genuinely absent; `H` free |
| `+P` permanent | Genuinely absent; `P` free |
| `+L` large ban list | Absent; `MAXLIST` is config-driven — per-channel override is questionable value |

### User

| Requested | Reality |
|---|---|
| `+D` deaf | Already present |
| `+g` callerid | Already present |
| `+x` hide host | Already present (cloaked) |
| `+B` bot | Already present |
| `+T` no CTCP | Duplicate of existing `+C` |
| `+I` hide idle | **Genuinely absent**, `I` free |

**Net: 5 of 6 requested user modes and 2 of 11 requested channel modes already
ship.** The valuable work is conflict resolution plus a small set of genuinely
new, genuinely enforced modes — not bulk letter allocation.

---

## 5. Mesh propagation

Channel mode state crosses the mesh through `emitRemoteChannelModeState` in
`src/daemon/server.zig` (~line 17400), which concatenates the base mode string
with the ext-flag string. Consequences of §2:

- **C2 duplication** means a letter stored in both tables can be emitted twice
  in one remote state string.
- **C1** means a remote `+f` is ambiguous — the receiver cannot tell forward
  from NOFORMAT without out-of-band knowledge of which table set it.

Both are rendering-level faults that resolve once the letter collision and the
dual storage are fixed; neither requires a new frame type.

---

## 6. Recommended sequence

1. **C1** — move ext `NOFORMAT` off `f` to the free letter `c` (matches the
   common IRC convention for "no colour/formatting"). Leaves `f` = forward,
   unambiguously group C.
2. **Structural guard** — a comptime cross-table assertion that no letter is
   claimed by two of {base, world, ext}. This converts "one letter, one
   meaning" from a convention into a compile error, so C1/C2 cannot regress.
3. **C4, C5** — correct the two wrong values in unwired tables before anyone
   wires them up.
4. **C3** — advertise the enforced ext flags in `CHANMODES`, and extend the
   honesty test to check the reverse direction.
5. **C2** — collapse the duplicated pairs to a single owner. Larger change;
   sequence after the guard exists.
6. **New modes** — user modes first (cheapest: `u4`→`u5`, no capsule impact),
   then ext channel flags (mask widen only). Base channel flags last, and only
   two of them before a capsule version bump is required.

## 7. Changes landed in this pass

### 7.1 C1 resolved — `f` now means exactly one thing

IRCX `NOFORMAT` moved from `f` to the free letter `c`, in all three tables that
carry it: `chanmode_ext.zig:63`, `ircx_modex.zig` (`mode_table`), and
`ircx_modex_cmd.zig`. `f` is now unambiguously the group-C forward target.

`c` was chosen because it is the only free lowercase letter (§3) and matches the
widespread IRC convention of `+c` for "no colour/formatting".

**Migration note:** a client that sent `MODEX #chan +NOFORMAT` is unaffected —
the name is unchanged and is the documented interface. Only the one-byte letter
in the `MODE` echo changed, `+f` → `+c`. Nothing persisted stores the letter:
`ExtChannelFlags` is a positional bitfield, so no capsule or checkpoint carries
the old letter and no migration is required.

### 7.2 Structural guard — one letter, one meaning, enforced at compile time

`src/daemon/dispatch.zig` gained a `comptime` block asserting that no letter is
claimed by two of {base enum, world layer, ext flags}, and that no mode letter
collides with a `PREFIX` member-prefix letter.

The five C2 duplicates are held in an explicit `known_duplicate_mode_letters`
allowlist (`"imnst"`) so the guard can land now and ratchet: collapsing a pair
to a single owner removes its letter from the list, and **nothing can be added
to it without justifying why one letter means two things**. A sixth collision is
now a build failure rather than a review catch.

Verified by deliberate break: reverting NOFORMAT to `f` fails the build with
`IRCX ext mode 'NOFORMAT' claims 'f', already owned by a world-layer mode`.

### 7.3 C4 resolved

`ircx_modex.zig` FOUNDER `status_prefix` corrected `~` → `!`, matching
`PREFIX=(YQqov)*!.@+`. Still an unwired field; fixed so wiring it up later
cannot resurrect the wrong prefix.

### 7.4 New user mode `+I` hide-idle

| Letter | Mode | Policy | Enforcement |
|---|---|---|---|
| `I` | hide-idle | client-settable | `server.zig` `idleHidden()` |

Suppresses `RPL_WHOISIDLE` (317) unless the requester is an operator or the
target themselves — mirroring the existing `+H` `operHidden()` predicate.

The 317 line is **omitted entirely** rather than reported as zero: a zero idle
time is itself an activity signal, so zeroing would leak exactly what the mode
exists to hide.

`UserMode` widened `enum(u4)` → `enum(u5)` to fit the 17th variant. This does
**not** change any serialized length — `UmodeSet.bits` is a `u64` and the Helix
session capsule serializes that `u64`, so no capsule version bump is required.

**Mesh behaviour:** none needed. Remote-user WHOIS already sets
`show_idle = false` unconditionally (`server.zig:20931`) because idle time is
per-connection state the origin node does not replicate. A remote user's idle
is therefore never disclosed with or without `+I`; the mode is meaningful only
against the node holding the connection.

### 7.5 Latent truncation bug fixed (found while widening the catalog)

`RPL_UMODEIS` rendered into a hardcoded `[16]u8` (`server.zig:19902`). The
string is `'+'` + derived `'o'` + one byte per catalog mode, so **16 bytes was
already one short at 16 modes** before this pass — a user with a full mode set
would silently lose trailing letters. `umodeString` bounds every write, so this
truncated rather than overflowing; it was a correctness bug, not memory
unsafety.

Now sized `usermode.MAX_MODE_CHANGES + 2`, matching every other call site, so
the buffer scales with the catalog automatically. Pinned by a regression test
that sets *every* catalog mode plus `+o` and asserts the full-length render.

---

## 8. Client (`/home/kain/onyx`) follow-ups — documentation only

- **PREFIX learning** must parse the 5-tier `(YQqov)*!.@+`, not assume the
  common 2–3 tier set, and must not assume `~` is founder (see C4).
- **Mode UI** should render the ext flags once they are advertised (C3), and
  must treat lowercase `h` as HIDDEN rather than halfop (C6).
- **Store fold** needs to keep base and ext flags distinct so a future
  de-duplication (C2) does not silently drop a bit.
- **`+c` is NOFORMAT** (§7.1), not the `+c` some networks use for something
  else, and it is no longer `+f`. A client that special-cased `+f` as NOFORMAT
  must move that case to `+c`; `+f` is now always a forward target with a
  parameter.
- **`+I` on a user** means "idle hidden" — a WHOIS reply with no 317 line is
  expected, not a parse failure.

---

## 9. Remaining work (not landed here)

Ordered by value. Each is a real gap, deliberately left rather than
half-implemented — a mode with a letter but no enforcement is conflict class
**C3**, which this pass exists to reduce.

| Item | Why it was not landed |
|---|---|
| **C3** — advertise the 11 enforced-but-unadvertised ext flags in `CHANMODES` | Wire-visible ISUPPORT change; deploys client-first. Needs the honesty test extended to check the reverse direction (enforced ⇒ advertised) so it cannot regress. |
| **C2** — collapse `s` `m` `t` `i` `n` dual storage to one owner | The largest change of the set: every read site must be repointed, and the two bits can already disagree in a live channel, so it needs a migration decision about which bit wins. The comptime allowlist (§7.2) holds the line until then. |
| **C5** — `isupport.zig` MAXLIST omits `Z` | Unwired module; fixing it has zero live effect and carries nonzero risk of breaking its property tests. Documented so whoever wires it up starts correct. |
| Slowmode, `+H` hide joins/parts, `+P` permanent | Genuinely absent and genuinely useful (§4). Each needs real enforcement — a rate limiter, a join/part suppression path, a persistence hook — not just a letter. Ext-flag space is available (12 free bits, no capsule impact). |
