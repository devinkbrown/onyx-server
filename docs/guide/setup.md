# Installation setup and preview

Native acceptance tools are available for development builds:

```sh
python3 tools/setup_smoke.py --binary zig-out/bin/onyx-server
python3 tools/setup_tls_smoke.py --binary zig-out/bin/onyx-server
```

The first uses private temporary files and real terminal/headless CLI flows;
it starts no daemon. The second requires a non-root Linux user, starts one
isolated loopback fixture, pins the certificate generated in its own private
bundle, verifies real TLS IRC registration/PONG and wrong-hostname rejection,
then stops the process and deletes its fixtures. Neither changes an installed
service or the system trust store. These checks establish local behavior, not
public DNS/CA reachability, mesh enrollment, or media transport readiness.

`onyx-server setup` offers an interactive new-installation workflow and equivalent
headless profiles, private material provisioning, plus a read-only preview for existing configuration. Every
candidate goes through the daemon's typed TOML loader and shared static startup
checks before a requested artifact can be published. Setup never starts the
daemon or controls a service.

Setup and `doctor` share a `service_environment` report with bounded OpenRC,
systemd and container-marker observations (`present`, `absent`, or `unknown`).
Auto-service guidance uses these observations; an explicit service selection
takes precedence. Marker observations describe the environment, while daemon
readiness comes from separate checks. Conflicting or unavailable manager
evidence keeps automatic guidance conservative.

```sh
# Existing configuration: preserve every source byte.
onyx-server setup /path/to/candidate.toml --service openrc --json

# New installation: review a profile without writing anything.
onyx-server setup --new --profile community --service openrc --json

# Interactive profile selection, help/search, back, review, and cancellation.
onyx-server setup --new --interactive --service openrc --export ./candidate.toml

# Save secret-free choices and resume them later.
onyx-server setup --new --profile media --service openrc --draft ./setup-draft.json
onyx-server setup --resume ./setup-draft.json --interactive --export ./candidate.toml

# Equivalent headless candidate export.
onyx-server setup --new --profile media --service openrc --export ./candidate.toml --json
```

The new-installation profiles are explicit sets of configuration values:

| Value | private | community | media |
| --- | --- | --- | --- |
| `node.id` | 1 | 1 | 1 |
| `network.name` | Onyx | Onyx | Onyx |
| `network.discoverable` | false | false | false |
| `listen.host` | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 |
| `listen.irc` | 6680 | 6680 | 6680 |
| `limits.max_clients` | 128 | 1024 | 128 |
| `media.enabled` | false | false | true |

Other settings retain the authoritative parser's defaults. Without overrides,
these are loopback baselines. A plain preview or `--export` does not provision
secrets, operator authentication, or mesh enrollment. `--bundle` provisions the
private node identity, cloak secret, and persistent TLS material described below.
Review authentication and network trust before public use or joining a mesh. In particular, generated `node.id = 1` is a local baseline,
not an enrollment identity for an existing network. Media enablement is not
proof of working media transport.

Configure the actual node through equivalent flags or interactive `set` commands:

```sh
onyx-server setup --new --profile media --hostname irc.example.test \
  --listen 127.0.0.1 --irc-port 7000 --node-id 17 --tls-port 7001 \
  --max-clients 256 --media-port 7100 --json

# A controller must handle the bidirectional review protocol described below.
# Use an existing directory owned by the intended runtime user as the parent.
onyx-server setup --new --hostname irc.example.test --bundle ./new-private-node --json --review-stdin
```

The editable keys are `hostname`, `listen`, `irc-port`, `node-id`, `tls-port`,
`max-clients`, and `media-port`. Interactive `set tls on`/`set tls off` controls
TLS; headless `--tls` enables it. Hostnames must contain valid DNS labels;
listen addresses must parse as literal IPv4/IPv6. Ports, numeric node IDs, and
capacity values are bounded by the generated configuration schema; enabled IRC
and TLS ports must differ. Final headless settings are validated together, so
flag order does not affect valid port changes. Interactive invalid changes
leave the previous settings intact. Profile descriptions show baseline defaults;
the settings object shows explicit overrides and the review step displays them.

`--max-clients` is an explicit configured limit, not a hardware capacity estimate.
No benchmark-derived claim is made. A configured media port is shown in the same
settings object; UDP/firewall/NAT reachability remains unknown. Setup parses and
validates choices without binding a listener, doing DNS resolution, contacting
an ACME service, or starting synthetic clients.

`--bundle <new-directory>` enables TLS and provisions a complete private candidate
installation in one create-only directory transaction. Its parent must already
exist, belong to the effective user, and reject group/other writes. Run setup
as the intended runtime owner, or arrange a separate authorized ownership change
before service installation. The resulting directory is mode `0700`, with these
mode `0600` files (both subject to umask):

| File | Contract |
| --- | --- |
| `onyx-server.toml` | Ordinary typed configuration; references final absolute material paths. |
| `onyx-server-node.key` | Canonical persisted node seed created by `node_keyfile.loadOrCreate`; implicit startup lookup beside the config preserves it. |
| `cloak.secret` | Fresh 256-bit OS-entropy secret, referenced with `@file:`; no secret appears in config, draft, or output. |
| `tls-cert.der` | Canonical self-signed Ed25519 bootstrap certificate for the configured DNS name. |
| `tls-key.der` | Its private key in the daemon's canonical Ed25519 PKCS#8 format. |
| `accounts.wal` (optional) | Canonical password/SCRAM verifiers for explicitly bootstrapped accounts; no plaintext password. |

The bootstrap certificate requires deliberate client trust or pinning. It is
not a publicly issued certificate. Interactive bundles have a second review
after generation and validation, before publication. It shows the actual public
node key, actual certificate expiry, self-signed provenance, final paths, and
observed directory/file modes from the private stage. Enter `publish` to expose
that exact bundle; `cancel`, `q`, or EOF discards the unpublished stage. The
first `done` accepts the settings and prepares material; it does not publish.

Headless `--bundle` requires `--json --review-stdin`; older unattended bundle
commands fail instead of publishing before material review. A controlling
process must keep stdin and stdout open bidirectionally. Setup emits one compact
JSON line with `mode: "prepared_unpublished_bundle"`, a fresh `review_id`, the
actual staged public node key, certificate subject and expiry, provenance,
final paths and observed permissions. The destination is not published yet.
After inspecting that record, send one JSON line using the same ID, for example
`{"action":"publish","review_id":"<the reviewed id>"}`. `cancel` with that ID,
EOF, malformed input, an ID mismatch or a 60-second deadline discards the stage.
The ID is a correlation value, not a credential. A successful publication emits
a second JSON line containing the normal provisioned plan. If that final
output cannot be written within 60 seconds, setup exits with an error after
publication; the reviewed bundle remains at its destination. Inspect the
destination before retrying. Do not pipe a
prewritten approval into this flow: it cannot know the freshly generated ID.
Password input remains on the separately selected private file or descriptor
(at least 3), so acknowledgement uses stdin independently. A plain preview or
draft has no generated identity or certificate. No review or output includes
secrets or secret-derived digests.
Normal startup derives the mesh routing identity from the persisted seed, so
an explicit numeric `node.id` does not replace that cryptographic identity.
Joining an existing mesh requires its actual realm, shared cloak secret, and
trust/enrollment procedure; a newly generated standalone secret is not a join.

Material is generated in a new private sibling directory using canonical daemon
routines. Setup reloads the persisted seed and certificate/key, checks their
identity and certificate validity, and validates the generated config with the
same typed loader/static validators. The staged cloak resolver resolves only
the one final reference being provisioned. All output allocations finish before
an atomic no-replacement directory rename exposes the bundle. Existing files,
directories, and symlinks at the destination are refused. Failure before publish
cleans staged material; cleanup after underlying filesystem failures is best
effort and any remaining sibling directory stays private. A failed publication
can be retried at a fresh path without changing an existing installation.

The config uses final absolute paths and runs from an arbitrary working directory.
Choose the final directory at provisioning time; moving it later requires a
reviewed path update. A bundle cannot be combined with `--export` or `--draft`.
Preview and draft creation generate no keys. A standalone `--export --tls`
retains the daemon's pathless bootstrap behavior at later startup; choose a
bundle when persistent certificate material is required. All installation and
supervisor actions remain separate from setup publication.

## Network account and operator bootstrap

Account bootstrap is optional and has no default account, password, or operator
role. Supply an explicit account name and, if needed, exact operator privilege
names. With no `--oper-privileges`, the result is an ordinary account with no
operator binding. `none` explicitly selects that account-only behavior.

```sh
onyx-server setup --new --bootstrap-account Alice \
  --oper-privileges server_rehash,audit_read \
  --password-file /owner-private/bootstrap-password --bundle ./private-node --json --review-stdin

# The descriptor carries the password, not the command line or environment.
onyx-server setup --resume ./choices.json --password-fd 3 \
  --bundle ./private-node --json --review-stdin 3</owner-private/bootstrap-password
```

In interactive settings, use `set account Alice`, then
`set privileges server_rehash,audit_read` or `set privileges none`. The password
source must already be supplied with `--password-file` or `--password-fd` when
invoking setup. Do not type a password into the settings command interface.
There is no terminal password prompt and no `--password` value option.

Private-file input uses a held, no-follow regular file owned by the effective
user, with one hard link and no group/other permissions. FIFO/device/symlink
paths are rejected before reading. Descriptor input requires an explicit FD of
at least 3 and rejects terminals; regular files receive the same privacy checks,
and inherited pipes are accepted. A pipe producer must close its writing end
so the bounded reader can finish. Descriptors are borrowed, not closed by setup.
At most 512 password bytes plus one optional LF/CRLF are accepted; intentional
leading/trailing spaces are preserved. Services applies its canonical policy
(currently 8–512 bytes, without NUL/CR/LF). The caller-owned password buffer and
credential scratch are wiped on success and error, before material review.

Preview and draft creation never open/read the password source or provision an
account. Draft version 3 records only account intent and explicit
privilege names alongside other nonsecret settings; no input path/FD, plaintext
password, verifier, salt, or secret-derived digest is saved. Version 1/2 drafts
retain their original account-free semantics. Re-supply the secret source when
resuming for an explicit bundle action. Ordinary TOML export refuses account
intent because it cannot create the required durable account store.

Bundle preparation creates `accounts.wal` privately with mode `0600` inside the
unpublished `0700` directory. It uses the same `OroStore`, `Services.registerAccount`,
PBKDF2 password policy, and SCRAM formats as normal runtime registration. It then
closes and cold-reopens the store, verifies PLAIN authentication, and resolves
both durable SCRAM-SHA-256 and SCRAM-SHA-512 credentials. Registration success
alone is insufficient because the canonical live registration API allows a
best-effort SCRAM mirror. A missing mirror or any failed verification rejects
the entire unpublished stage.

The generated TOML enables SASL and uses a final absolute account WAL path.
Operator intent produces a named explicit privilege group and SASL account
binding, then checks the loaded registry for that exact canonical account and
bit set. No implicit full administrator group is created. Actual material
review includes the account name, verified authentication mechanisms, exact
privilege names, and observed WAL path/mode before `publish`. It never includes
credential hashes or salts. Any store snapshot is included in material review
and stage cleanup. No OS account, installed service, or existing account store
is changed.

Profiles apply only to new candidates. Existing configuration preview accepts
no profile, draft, or export mutation flags. Plan output lists profile values
and the differences from the private baseline; interactive changes show the
difference from the previously selected profile. Candidate files contain
ordinary TOML accepted by `--check-config`; there is no separate configuration
schema.

Interactive mode requires terminal stdin and stdout. Enter `1`/`private`,
`2`/`community`, or `3`/`media`; use `help`, `search <keyword>`, `review`, `back`,
`set <key> <value>`, and `cancel`/`q`. At the settings review, `done` accepts the action requested by flags.
For bundles this prepares private material and opens a separate actual-material
review requiring `publish`; exports and drafts retain their single review. With `--draft`, `save` creates the checkpoint and ends the
interaction. EOF or cancellation publishes nothing. Interactive mode asks only
for these choices, never a password or secret. A terminal's normal input echo
therefore cannot expose a secret requested by setup.

A draft stores a required format version, profile, and service selection.
Version 2 also stores the nonsecret hostname, listener, TLS, capacity, and media
choices. It does not store source configuration, resolved environment variables,
or secrets. Version 1 profile/service drafts decode explicitly with original
default settings; versions 2 and 3 require their settings object. Version 2
remains account-free; version 3 adds nonsecret account/privilege intent. Other
versions fail closed. Resume re-generates the selected TOML and re-validates it with the
current daemon loader. An existing draft can be resumed after interruption;
choices made since the last explicit save are not autosaved. To save a new
checkpoint, supply a fresh `--draft` path. Resume flags cannot override saved choices; interactive navigation can change
the profile and nonsecret settings. `--bundle` explicitly enables TLS.

Artifact publication is currently supported on Linux. Export and draft actions
require explicit paths, create owner-only files with mode `0600` subject to
umask, sync the complete bytes, and atomically publish without replacing an
existing file or symlink. Validation and output allocations complete before
publication. Existing configuration and secrets remain intact on rejection or
allocation failure. Existing artifact paths are refused, including the source
of a resumed draft; select a fresh path. Publication is atomic to readers;
power-loss durability of the directory entry is not guaranteed. After successful
publication, output-stream failure can still leave the complete artifact in
place. Remove the new artifact to discard it; this never rolls back a live
service because setup performs no live installation.

Resume requires the effective user to own the held file, verified through Linux
`statx`; unavailable ownership metadata fails closed. This also applies when
setup runs as root. Resume rejects nonprivate mode bits, symbolic links, files with multiple hard
links, nonfiles, oversized input, unknown fields, incompatible versions, and
invalid enum selections. Store drafts in a directory controlled by the operator.
Resume holds a nonblocking metadata handle before reading the exact regular
file through `/proc/self/fd`; a mounted Linux proc filesystem is required.
Linux publication/resume acceptance does not imply equivalent ACL semantics on
other platforms; those operations fail closed there.

Text and JSON share the same plan. JSON goes to stdout without a startup banner
or terminal escapes; diagnostics go to stderr. Profile/configuration values and
resolved secrets from existing configuration are excluded; supplied paths are
JSON-quoted in text output so terminal controls remain inert. Text uses color
only on a terminal with a nonempty `TERM` other than `dumb`, when `NO_COLOR` is
absent. Redirected preview output is plain text. Interactive mode with `--json`
is rejected; headless flags provide the equivalent final choices and plan.
Exit status is 0 for success/cancellation, 1 for configuration/artifact failures,
and 2 for invalid arguments or unavailable interactive terminals.

`--service auto` uses `/run/openrc` and `/run/systemd/system` as Linux directory
hints. A single marker selects that service plan; absent or ambiguous markers
select foreground. Hints do not establish that the supervisor is running.
Explicit `openrc` and `systemd` plans require Linux. See
[Alpine operation](alpine.md) for packaged paths and service account requirements.

Setup and doctor also expose a typed `service_plan`. Its paths, identities,
argument arrays, working directories, restart policy, and logging describe the
shipped template, not the installed host. OpenRC and systemd templates call
`--check-config` before starting; foreground and the Dockerfile require the
operator to arrange that preflight. The container example uses UID/GID
10001:10001 and `/data`, but a container marker does not prove that example is
installed or running. The interactive review shows these examples before
continuation; auto selection is evaluated from markers at completion. A
foreground start uses `<reviewed-executable> <reviewed-config>` with no
`--foreground` flag. Host paths, account access, supervisor, daemon readiness,
network reachability, and host CPU/memory/bandwidth ceilings remain unknown.
The template config path is not a claim about the candidate path you selected.

Every plan reports readiness as **unknown**. Before first start, run
`--check-config` and `doctor` as the intended runtime user and inspect permissions,
certificates, existing identity, and network settings. After an authorized
start, verify real clients and secured mesh links. Parser success does not prove
filesystem readiness, available resources, or external reachability.

This implements profile selection/navigation, explicit resumable checkpoints,
validated new-candidate export, and canonical private identity/TLS/cloak bundle
provisioning and optional canonical account/operator bootstrap within R1. Mesh enrollment,
reachability rehearsal, live configuration commit, service-managed upgrade
orchestration, and automatic rollback remain roadmap work. Retain compatible
previous artifacts and private configuration/state backups before later
upgrades; follow the release runbook for recovery.

### Maintenance for an existing foreground runtime

The maintenance wizard supports an existing Linux foreground runtime owned by
the current user. Select its PID, configuration, candidate executable, backup,
and a new private verification directory:

```sh
onyx-server setup --maintenance --interactive --linear /private/network.toml \
  --pid 12345 --target /private/onyx-server-next \
  --backup /private/backup --restore-into /private/verify-upgrade
```

Use the actual selected paths and PID. This workflow does not install or control
OpenRC or systemd services, operate another user's daemon, or apply an
environment-based configuration profile.

Review checks the selected artifacts and backup and performs a private restore
drill. The screen explains expected client impact, compatibility limits,
retained recovery material, and cold recovery steps. File checks cannot prove
the running daemon's complete state; its final compatibility guard can still
refuse the upgrade before exec. Apply requires the exact current review ID and
rechecks the pinned inputs. Back, cancel, EOF, and changed inputs do not authorize
an upgrade. Verification scratch remains private and is retained after review;
each subsequent review needs a fresh path.

An action receipt distinguishes staging, signaling, and observed exec. Validate
real clients, secured mesh links, and media after an action; exec alone does not
prove readiness. Keep the previous executable and operation journal identified
by the receipt. Recovery may require stopping the runtime and disconnecting
clients. The restore drill covers the reported OroStore backup scope, not a full
installation: retain configuration, identity keys, and other referenced files
separately. Neither the receipt nor a retained old executable establishes that
a hot downgrade is compatible; rollback is not automatic.

The initial native acceptance covers two existing same-user Linux foreground
runtimes: one successful same-PID upgrade and one realm-change refusal, with
four original TLS connections retaining their physical sockets and responding
afterward. Supervisor-managed and other-user runtimes remain unfinished.

### Linear terminal output

Use `onyx-server setup --interactive --linear` for sequential plain-text output
intended for screen-reader workflows. It emits no ANSI styling or cursor-control
sequences. This mode has not been validated with a particular screen reader.
Help and search cover the existing-network review and configuration fields;
`existing` then `set config <path>` reviews a local file without enrollment or
network contact. Progress labels identify choices and review.

Interactive mode requires terminal input and output and at least 20 columns. If
narrower, widen the terminal or use the noninteractive `setup --new --json` or
`setup <config> --json` preview for redirected output. NO_COLOR and TERM=dumb
also suppress styling; neither suppresses the text or changes the plan.

### Configuration and network assessment

The setup review reports the configured hostname, listen address, IRC/TLS ports,
and media settings from the candidate or validated existing configuration.
DNS-label and numeric-address syntax checks describe the strings only. Address
ownership, port availability, DNS resolution, NAT, relay operation, and public
reachability remain unknown: setup sends no probes and opens no production
listener. A zero media UDP port requests an ephemeral port at startup. Existing
media and native-media ports, advertised host, STUN settings, and WebSocket media
configuration are shown as configured values, not proof that any transport or
fallback works. If the network requires a relay, provision and test a compatible
relay separately.
