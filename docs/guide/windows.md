# Native Windows full daemon

Onyx Server runs its full daemon engine over a native Windows IOCP backend.
Native loopback smoke has verified plaintext IRC registration and messaging,
TLS registration, secure and testing-only plaintext WebSocket, metrics HTTP,
webhook HTTP, trusted PROXY protocol v1/v2, account persistence with TLS SASL
PLAIN, STS, secured three-node mesh messaging, reusable sessions across nodes,
private backup and restore, GeoIP/news cache, WebTransport, media signaling
and UDP forwarding, three-shard plaintext/TLS/WSS fanout, and stats publication.
Windows config preflight validates native listener and companion prerequisites
before binding sockets.

## Requirements

- 64-bit Windows and PowerShell.
- Git for cloning the repository.
- Zig `0.17.0-dev.1282+c0f9b51d8`, the version recorded in `build.zig.zon`.
- Python 3 for the optional process and IRC smoke test.

The build has no third-party package dependencies or C compiler requirement.
The older pinned Zig snapshot is available from the Hexops archive. This
PowerShell block installs it under your LocalAppData, verifies the downloaded
zip against SHA-256
`DF1CA8156908BD51B417265773092DDF41A1D307F0E93B28BB3E8A0B912D0681`,
and adds its `zig.exe` directory to `PATH` for the current terminal session:

```powershell
$zigVersion = '0.17.0-dev.1282+c0f9b51d8'
$archiveName = "zig-x86_64-windows-$zigVersion.zip"
$installRoot = Join-Path $env:LOCALAPPDATA 'OnyxServer\toolchains'
$zigDir = Join-Path $installRoot "zig-x86_64-windows-$zigVersion"
$zigExe = Join-Path $zigDir 'zig.exe'
$download = Join-Path $env:TEMP ('onyx-zig-' + [guid]::NewGuid().ToString('N') + '.zip')
$expectedHash = 'DF1CA8156908BD51B417265773092DDF41A1D307F0E93B28BB3E8A0B912D0681'

if (-not (Test-Path -LiteralPath $zigExe)) {
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
    try {
        $url = "https://pkg.hexops.org/zig/$archiveName"
        Invoke-WebRequest -Uri $url -OutFile $download
        $actualHash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash) { throw "Unexpected Zig archive SHA-256: $actualHash" }
        Expand-Archive -LiteralPath $download -DestinationPath $installRoot
    } finally {
        Remove-Item -LiteralPath $download -ErrorAction SilentlyContinue
    }
}
if (-not (Test-Path -LiteralPath $zigExe)) { throw "zig.exe missing after extraction: $zigExe" }
$env:Path = "$zigDir;$env:Path"
zig version
```

Then clone and build in PowerShell. Other Zig releases need their own build
verification:

```powershell
git clone https://github.com/devinkbrown/onyx-server.git
Set-Location .\onyx-server
zig version
zig build -j1 check -Dtarget=x86_64-windows
zig build -j1 -Dtarget=x86_64-windows
```

`check` performs semantic analysis without producing an executable. The build
places `onyx-server.exe` in `zig-out\bin`.

## Start a local node

Create a disposable run directory outside the checkout. Resolve the executable
before changing directory so the daemon writes its generated node key alongside
the temporary config, rather than into the repository:

```powershell
$serverExe = (Resolve-Path -LiteralPath .\zig-out\bin\onyx-server.exe).Path
$runDir = Join-Path $env:TEMP ('onyx-server-windows-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDir | Out-Null
$configPath = Join-Path $runDir 'onyx-server.local.toml'
@'
[node]
id = 1

[listen]
host = "127.0.0.1"
irc = 16667
'@ | Set-Content -LiteralPath $configPath -Encoding ascii

& $serverExe --check-config $configPath
Push-Location -LiteralPath $runDir
try {
    & $serverExe $configPath
} finally {
    Pop-Location
}
```

Use a separate terminal to connect an IRC client to `127.0.0.1:16667`. Stop
the foreground daemon with Ctrl+C or Ctrl+Break. Both use the cooperative
multi-shard stop path. To remove this disposable node's config and
generated key, verify that the run directory is under the system temporary
directory before deleting it:

```powershell
$resolvedRunDir = [IO.Path]::GetFullPath($runDir)
$tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
if (-not $resolvedRunDir.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove a directory outside TEMP: $resolvedRunDir"
}
Remove-Item -LiteralPath $resolvedRunDir -Recurse -Force
```

The full daemon's plaintext listener accepts concurrent clients and provides
its normal IRC command, CAP, and ISUPPORT handling. The native smoke checks
registration, VERSION, PING/PONG, direct and channel PRIVMSG, JOIN fanout,
NAMES, PART, QUIT fanout, and responsiveness after peer disconnects. Set
`[listen].host` to an IPv4 address and `[listen].irc` to the TCP port.
Windows uses one exclusive listener per port on reactor 0 and hands accepted
sockets to the configured reactor shards before their first IOCP receive. The
three-shard smoke verifies each shard accepts clients and that plaintext, TLS,
and WSS clients exchange channel messages across shards. Configure
`[limits].num_shards` to use more than one shard.

TLS, metrics, and webhook listeners use native Windows sockets. The smoke
starts all three in one disposable process: a TLS client completes registration
and PING/QUIT, `GET /metrics` returns HTTP 200, and a channel founder creates a
webhook binding whose POST reaches another channel member. It verifies the
binding store is written, then cold-restarts the daemon and POSTs through the
restored binding. A valid POST for an unknown binding also returns HTTP 404.
The smoke accepts its temporary self-signed TLS certificate only for this local
test; configure a trusted certificate for other clients.

The native stats smoke checks `stats.json`, `index.html`, per-channel JSON,
and `status.json` as live activity changes, then cold-restarts the daemon and
checks that the channel-stats snapshot restores. Configure `[stats].dir` and/or
`[stats].channel_dir` for these publications.

With `[sts].enabled = true` and TLS enabled, the Windows daemon advertises the
configured STS duration and port on plaintext CAP LS. The native probe
connects to that TLS port and completes registration.

Both `wss://` (with `[tls].enabled = true`) and testing-only `ws://` (with
`[listen].ws_plain = true` and TLS disabled) use the native Windows listener.
The WebSocket smoke checks the HTTP upgrade, selected IRC subprotocol, masked
IRC frames, registration, PING/PONG, direct messaging with a plaintext IRC
client, and QUIT/EOF. Run the two modes separately because a configured TLS
certificate makes the WebSocket listener secure even if `ws_plain` is set.

WebTransport serves QUIC/HTTP/3 over a dual-stack UDP listener and bridges
each browser session to the local IRC listener. Configure `[listen].webtransport`
with TLS enabled and a usable certificate and signing key. A native smoke uses
headless Chrome or Edge to register over WebTransport and send a channel
message to a plain IRC client; it also checks missing-TLS preflight and a held
UDP port causing a fatal bind error. The bridge follows the IRC bind address,
including IPv6 loopback and a specific local IPv4 address. This smoke needs
PowerShell 7, Node.js, and Chrome or Edge.
On Windows, pathless TLS with WebTransport mints a seven-day P-256 bootstrap
leaf with DNS and loopback SANs so a browser can use certificate-hash pinning.
For a long-running public node, configure a managed certificate and key.

The IRC listener accepts PROXY protocol v1/v2 when
`[listen].proxy_protocol = true` and the connecting source IP appears in
`[listen].trusted_proxies`. The native smoke uses loopback as its trusted proxy,
checks that v1 and v2 source addresses appear in the client's self WHOIS 338,
and verifies that malformed or missing headers are disconnected before IRC
registration. Client-facing message prefixes retain the default IP cloak.
Configure `trusted_proxies` to include only proxy addresses you control.

With `[sasl].account_db` configured, the Windows daemon opens the OroStore
account WAL and runs account registration and SASL verification. The native
account smoke registers over TLS, checks the WAL, cold-restarts the daemon,
authenticates the saved account with SASL PLAIN over TLS, checks its account
identity with WHOIS, and verifies that a wrong password is rejected. A native
store test also compacts the WAL into a snapshot and restores it after restart.

The account database's **parent directory must exist with a protected,
inheritable ACL** granting full access only to its owner, SYSTEM, and
Administrators. Create a new directory with that ACL at creation time, before
placing account files in it. From the repository root, for a run directory
already created at `$runDir`:

```powershell
$accountDir = Join-Path $runDir 'accounts-private'
& .\zig-out\bin\onyx-server.exe --init-private-dir $accountDir
```

The command accepts an existing directory only if it already has the required
private ACL. It rejects broad directories instead of changing their permissions.
Set `account_db = "accounts-private/accounts.wal"` in the config and start the
daemon from `$runDir`. Windows preflight rejects a broad account directory,
before opening any account file. On boot, existing WAL and snapshot files are
opened exclusively and their ACLs are verified or hardened before replay; a
retained reader makes boot fail. The daemon also checks that new snapshot
temporary files inherit a private ACL before writing account data. Keep the
directory private throughout the daemon's lifetime.

When `[backup].dir` is configured, `[sasl].enabled` and `account_db` are
required. Create the backup directory with
`onyx-server.exe --init-private-dir <path>` as above. The daemon publishes a
private account snapshot followed by `latest.json`; each snapshot gets a
random suffix so a later backup cannot replace an artifact named by an older
manifest. `--restore-drill <backup-dir> --into <scratch-dir>` requires an
already private scratch directory. The native backup smoke creates an account,
waits for a new set, restores it, and authenticates over TLS from the restored
store.

The secured mesh smoke runs three separate Windows nodes in an A-B-C line and
checks both link health and channel messages across the hub. The session smoke
attaches four and then five physical clients to one token across those nodes,
checks exact per-recipient delivery, cold-restarts the hub, and confirms that
the surviving edge sockets and token continue to work after reconnection. A
cold restart closes the hub's physical sockets. The separate Windows Helix
smoke holds IRC sockets across two consecutive `UPGRADE` process swaps and
checks that the local reusable-session token stays identical. A second smoke
holds TLS IRC and WSS sockets through two swaps and accepts fresh connections
on both secure listeners after each swap.

Web Push requires an enabled account store, a private parent directory for
`[webpush].vapid_key_path`, and a PEM CA bundle at
`[acme].ca_bundle_path`. Windows boot fails if the key or trust bundle cannot
be loaded. The native smoke checks private key preflight, VAPID advertisement,
worker startup, a stored subscription across restart, and an offline memo that
reaches the worker. Its loopback endpoint is rejected by the production SSRF
guard after the worker encrypts the payload. A native Windows module test uses
a pure Zig trusted HTTPS peer to decrypt the POST payload and check 201 and 410
outcomes through the pinned-address request path. Delivery to a real push
service still needs external acceptance.

ACME renewal and the `acme-issue` command use native Windows HTTP-01 and
HTTPS transports. Set `[tls].cert_path`, `[tls].key_path`, `[acme].domain`,
and `[acme].ca_bundle_path` to a PEM trust bundle when enabling renewal.
Create the key file's parent with `onyx-server.exe --init-private-dir <path>`;
preflight refuses a broad parent directory or an unreadable trust bundle.
OCSP stapling uses the same trust bundle and requires an on-disk TLS fullchain
at `[tls].cert_path`. A native Windows module test completes ACME issuance
against a pure Zig loopback CA: it checks the live HTTP-01 challenge, trusted
HTTPS exchange, published fullchain and matching private key, and key ACL. The
disposable daemon smoke checks private preflight, a TLS handshake, both worker
starts, and a CLI error path. Public ACME issuance and live OCSP publication
still require an end-to-end acceptance run.

Configured OCG2 mint, project, and observe modes load the durable authority
from the private account store on Windows. The native smoke initializes it,
restarts the daemon in each mode, and checks that a different valid authority
fails closed before the IRC listener starts. The repository has no daemon
path for issuing OCG2 grants on any platform yet.

OroWasm plugins load from `[wasm].plugin_dir` on Windows. Preflight requires
the directory to exist. A native smoke loads a minimal reply plugin, dispatches
it from IRC, and verifies that a malformed configured plugin aborts boot.

Mail delivery uses a Windows worker and a private failure journal beside the
account WAL. The native smoke registers an account with an email address,
observes the queued verification notice, delivers the message to a local pure
Zig trusted STARTTLS relay, delivers over implicit TLS with AUTH PLAIN, refuses
both modes under a different valid trust anchor, and verifies that a
deliberately closed relay causes a durable failure row. Build the disposable
relay with
`zig build windows-mail-relay`, then run `python -B tools/windows_mail_smoke.py`.
The mail trust store accepts PEM certificate bundles or a DER certificate;
the daemon owns decoded anchors through worker shutdown. Windows relay hostnames
try AAAA when no A address exists or an A address fails before the SMTP
connection is established, and the mail worker can connect over IPv6. A real
remote SMTP relay and its trust policy still need an acceptance test. For an
implicit TLS submission relay, set `[mail].starttls = false` and
`[mail].relay_port = 465`. With `trust_store_path` set and the default
`insecure_skip_verify = false`, configured `user` and `pass` use AUTH PLAIN
inside the verified TLS session.
DNS blocklist lookups use native UDP with a checked worker start; the module
test covers listed and clean answers, and registration policy has a focused
server test.

GeoIP and ASN MMDB files load on Windows, including UTF-8 paths. Preflight
rejects a malformed database before the listener binds. The geo worker starts
with `[geo].enabled = true`, and the native smoke verifies a trusted-PROXY
client's WHOIS country/ASN and a `+W` news reply from a regular cached file.
Set `[geo].news_cache_dir` to an existing directory when using cached news.

Media signaling and both UDP listeners run on Windows with `[media].enabled =
true`, `[listen].media`, and `[listen].native_media`. The native smoke has two
TLS IRC clients complete MEDIA JOIN/OFFER/ANSWER, receives a live authenticated
STUN binding success from the WebRTC listener, and verifies that a Cadence
frame crosses the native listener with its directional MAC and exact payload.
Focused native tests also cover UDP pump restart and idle/live continuity.

The Windows quickstart template selects one shard, loopback-only plaintext IRC
and WebSocket, and an account store in a private directory. From the repository
root, after building the binary:

```powershell
$serverExe = (Resolve-Path .\zig-out\bin\onyx-server.exe).Path
$template = (Resolve-Path .\packaging\onyx-server.windows.quickstart.toml).Path
$runDir = Join-Path $env:TEMP 'onyx-server-quickstart'
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
Copy-Item $template (Join-Path $runDir 'onyx-server.toml')
Push-Location $runDir
try {
    & $serverExe --init-private-dir accounts-private
    & $serverExe --check-config .\onyx-server.toml
    & $serverExe .\onyx-server.toml
} finally {
    Pop-Location
}
```

Connect locally at `irc://127.0.0.1:6667` or `ws://127.0.0.1:8080`.
The quickstart is for local evaluation; configure TLS before sending account
credentials across a network. The native acceptance check is
`python -B tools/windows_quickstart_smoke.py` and uses Python only as a test
harness. The Linux quickstart remains `packaging/onyx-server.quickstart.toml`.
Windows does not provide Linux systemd packaging or the POSIX `USR2` upgrade
signal. Use the operator `UPGRADE` command for its guarded native process
handoff.

## Guarded Windows Helix upgrade

Windows Helix launches a successor from the daemon's executable path by
default. An operator with `server_restart` privilege can select a staged image
with `UPGRADE :C:\\path\\beside-current\\onyx-server-next.exe`. The target must
be a fully qualified local path to an `onyx-server*.exe` in the running image's
directory. Keep that directory writable only by the deployment administrator:
the candidate process starts before its capability challenge, although no
socket or state custody moves until the actual child passes that challenge.
A rejected image leaves the serving process and its clients active. The handoff
transfers authenticated custody of TCP listeners and client or mesh-link
sockets, the metrics listener and snapshot, the webhook listener and binding
store, a WebTransport UDP listener with its Retry/replay and active QUIC state, plus the
private account WAL when configured. The candidate validates
the carried state while inert, then publishes it only after authenticated
COMMIT and predecessor exit. The native smoke first rejects a changed candidate
configuration and proves the predecessor's sockets and WAL remain usable, then
exercises two consecutive swaps with held plaintext IRC sockets, account reads
and writes, and an unchanged local session token. A staged-path smoke selects
two distinct staged filenames in sequence and checks refusal of relative,
malformed, and incompatible paths with held clients and account WAL continuity.
Its `--stage-b-binary` mode requires a different binary hash and exercises one
cross-build swap; a compatible prior build has passed that held-client and WAL
check. A TLS/WSS smoke exercises two swaps with held TLS IRC and WSS sockets,
checks WebSocket control frames,
and opens fresh TLS and WSS connections after each swap.
The native v18 capability challenge requires exact memo inbox custody,
including RAM-only messages and pending durable reconciliation, plus ACME
scheduler, TLS material, TLS replay history, OroWasm, active history listener,
and UDP owner custody. An older candidate is rejected before socket transfer.
If the encoded inbox exceeds the 256 MiB checkpoint limit, UPGRADE refuses
and the current process keeps serving its clients and memos.
The two-node mesh smoke upgrades a node with a held secured Mooring link, keeps
attachments on both nodes connected, and checks exact cross-node deliveries.
A three-node sequence smoke upgrades A and then B while four same-token
attachments across A/B/C keep their physical sockets and exchange exact
channel and direct messages. It requires the 1/2/1 secured-link, TCP, and peer
gauges before and after each swap, then resumes a fifth attachment from C.
The metrics smoke runs continuous `/metrics` scrapes through two swaps and checks held
and fresh IRC clients after each one. The webhook smoke keeps the same endpoint
through two swaps and verifies that one POST reaches each held channel member
exactly once after a rejected candidate and after each committed successor.
The primary two-swap smoke also enables connection-rate and mesh-wide clone
limits, exercising their exact admission checkpoints alongside held clients.
The handoff also carries login lockout scores, nick-delay holds, reverse DNS
and DNSBL cache and pending lookup queues, and raid-shield correlation state
through the authenticated arena. Queued TEMPMODE reversals retain their
deadlines and action order.

`UPGRADE` requires a config file with explicit `[node].secret_key` and
`[cloak].secret`. TLS may use configured files or daemon-generated default
and TLS 1.2 certificates. The predecessor and candidate must reproduce the
same loaded source, ordered `env:` and `@file:` substitutions, static TLS
settings, identity material, and OAuth JWKS bytes. The authenticated TLS
material checkpoint supplies the exact serving certificate and key generations
before COMMIT. A completed `REHASH` retains Windows Helix eligibility when
the canonical config source and every ordered `env:` and `@file:` value still
match startup. TLS 1.3 session tickets, including 0-RTT, and TLS 1.2 tickets
may remain enabled; their current and previous keys and consumed-ticket
history cross the handoff. With
TLS enabled, the reload must succeed and leave the full serving
certificate/key generation and TLS 1.2 leg byte-identical; the authenticated
checkpoint then carries that generation.
With WASM enabled, the checkpoint carries the actual post-REHASH modules and
mutable state, and the candidate revalidates their policy. A changed REHASH,
failed TLS reload, or changed serving TLS material invalidates eligibility for
that process, even if a later REHASH restores the original inputs; a normal
boot is then needed before another upgrade. ACME renewal does not invalidate
the static proof.

For TLS resumption, the authenticated HXRG checkpoint carries the shared replay
ring in chronological order. The successor validates and stages it before COMMIT,
then installs it in the existing guard without allocating or changing its
address. Previously consumed TLS 1.2 tickets and TLS 1.3 early-data binders
remain consumed across sequential swaps. A missing or malformed mandatory
checkpoint aborts adoption.
The native Zig early-data smoke sends IRC registration and PING only in
0-RTT, then replays the identical ClientHello and early records across a swap.
It checks rejection, usable 1-RTT fallback, and fresh-binder acceptance on
both successors. Build its client helper with `zig build windows-helix-early-client`.
The first-flight check observes a predecessor handshake response, not whether it
accepted that exact early payload; the separate pre-swap 0-RTT control proves
acceptance of a fresh flight.

The guarded path carries Web Push worker state, mail queue and private journal
custody, Geo worker cache and pinned GeoIP/ASN databases, channel statistics,
connection-rate windows, network clone counts, and active DRAIN, SLOWMODE,
metadata, moderation, and access policy. Mandatory checkpoints also carry
POLICY generations and the one-step ROLLBACK state, operator challenge policy
and pending two-person approval, account verification and password-reset tokens
and TOTP replay state, account autojoin and nick-group settings, welcome lines,
memo forwarding and ignore lists, and accepted first-message holds. OCSP
checkpoints carry the fetch scheduler and current, pending, and retained staple
state. ACME checkpoints carry the renewal scheduler and exact live default and
TLS 1.2 serving material. The successor checks checkpoint ownership and
configuration identity before COMMIT. Native smokes exercise Web Push, mail,
Geo, POLICY ROLLBACK, account settings, memo preferences, and a pending
password-reset token through two committed swaps. The TLS/WSS smoke exercises
configured ACME and OCSP schedulers; its generated variant preserves the same
default and TLS 1.2 certificates through two swaps. The self-signed fixture
has no issuer or AIA, so these smokes do not verify public ACME issuance or
live OCSP DER publication.
The native Windows OCSP test loads two PEM blocks of the same self-signed
certificate, POSTs to a pure-Zig HTTPS responder, verifies a current signed
response from that issuer, and checks the server's pending-staple handoff. A
separate native server test checks reactor publication into the TLS config,
exclusive expiry, and rejection after leaf rotation. These local tests do not
exercise the timer dispatch, a client wire handshake, or a public responder.

When `[wasm].plugin_dir` is configured, its mandatory checkpoint carries the
authorized plugin source bytes, policy, registration order, mutable linear
memory, and deterministic random state. A native smoke changes the plugin file
after boot and checks that a counter shared by two held IRC clients continues
through a rejected candidate and two committed swaps. Fresh clients also use
the carried module and memory.

An idle configured WebTransport listener transfers its exact UDP socket and
Retry/replay state before READY. The two-swap browser smoke opens a new QUIC
session on the same port after each swap while held IRC and TLS clients remain
connected. For active QUIC sessions, the candidate also restores the paused
connection, HTTP/3 streams, and accepted IRC socket roster before READY. The
active browser smoke keeps the same registered stream and held IRC/TLS clients
across two consecutive swaps. A candidate validates the WebTransport owner
against the source's authenticated serving TLS checkpoint before READY,
including generated bootstrap material.
ACME and REHASH certificate reloads update the WebTransport owner only at an
idle QUIC boundary; a busy owner keeps serving the old generation and the
reload is retried or refused without changing either TLS view.

An enabled, pristine `[media]` graph transfers its original WebRTC and native
media UDP sockets, initial secret state, and native stream key before READY.
An active graph transfers its call rooms, routing graph, bridges, client
attachments, negotiated WebRTC and native physical state, and the same UDP
sockets before READY. The candidate joins all three authenticated media bodies
and publishes them after the adoption commit. The default media smoke holds
TLS clients through two pristine swaps, establishes a call, then verifies ICE
and authenticated native UDP forwarding through a third active swap. Its
`--active` mode keeps the same call, ICE peers, UDP sockets, and MAC-keyed native
traffic across two consecutive active swaps. A configured native-media port
with `[media].enabled = false` binds no UDP owner and requires no socket
handoff. The combined smoke holds an active WebTransport browser stream and an
active native/WebRTC call in the same daemon through two swaps, checking the
browser's exact deliveries and both media transports after each one. An
opened loopback `history_https` listener transfers its listening socket and
pinned TLS runtime settings after REHASH. HXHH carries the scalar policy and
clock. The encrypted HXHL arena carries that listener's ticket keys, exact
certificate/key generation after ACME renewal, and OCSP staple. HXRG preserves
the shared replay ring for 0-RTT handshakes. The candidate checks the complete
TLS configuration before COMMIT. OroWasm plugin directories and media
remain available on ordinary Windows boot under their preflight rules. A live
session-drop transaction, deferred
MESSAGE_V2 authority, or accepted Web Push overflow delivery blocks the
handoff until it settles. An open multiline batch defers the handoff until it
closes.

Windows outbound HTTP hostname lookup uses `GetAddrInfoExW`. The guarded Web
Push and outbound webhook resolvers, along with ACME, fall back from an absent
A answer to AAAA. Link previews, outbound webhooks, and generic outbound HTTP
also try AAAA when an A address fails before the first TCP connection. Webhooks
and link previews connect to the address they screened. Normal webhook
transport errors after connection stop same-turn retries; retained webhook
jobs retain their durable later retry contract. Native
Winsock connects to IPv4 and IPv6 targets, and focused loopback tests cover
plaintext requests and a verified TLS request to a pinned IPv6 address.
HTTPS webhooks and link previews verify peers against the native Windows ROOT
certificate store and reject certificates present in Windows Disallowed; an
unavailable or empty store stops delivery. After Zig verifies the TLS chain,
Windows also applies its SSL chain policy, including cached certificate trust
lists and current system distrust. Chain construction uses cached objects only;
it does not fetch CTLs, roots, or issuers during a handshake. Missing policy
or failed chain checks stop delivery. This path uses Zig and Windows APIs
without OpenSSL.
Enterprise DNS policy and hosts-file variations have not had live acceptance
tests. Socket IDs use generation-safe
slot reuse, so a closed descriptor never becomes valid again. The 30-bit
socket namespace and separate file-handle namespace each have a finite
per-process lifetime. At half of either range, the daemon queues a
connection-preserving Helix rollover into the exact image measured at boot;
failed attempts retry no sooner than 60 seconds later. A staged replacement
image does not enter this automatic path. Manual upgrades retain priority.
If image proof or Helix handoff remains unavailable, the daemon continues
serving until the namespace is exhausted; operators must then arrange a
compatible upgrade while there is remaining headroom. The socket trigger is
roughly 537 million claimed IDs (about 6.2 days at 1,000 registrations per
second).
The dedicated rollover smoke executable has a compile-time-only, PID-bound
trigger. Its native process test checks pinned-image candidate refusal,
the 60-second retry, and a later automatic swap with held clients. This
trigger is absent from the normal daemon and release builds.

## Runtime check

After building, run the full-daemon loopback smoke from the repository root:

```powershell
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --tls --wss --metrics --webhook
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --ws-plain
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --proxy
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --tls --accounts
python -B .\tools\windows_stats_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_sts_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mesh_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_session_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_smoke.py .\zig-out\bin\onyx-server.exe
zig build windows-rollover-smoke-server -Dtarget=x86_64-windows
python -B .\tools\windows_descriptor_rollover_smoke.py .\zig-out\bin\onyx-server-rollover-smoke.exe
python -B .\tools\windows_helix_smoke.py .\zig-out\bin\onyx-server.exe --inert-native-port
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --resumption
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --early-data
zig build windows-helix-early-client
python -B .\tools\windows_helix_early_data_smoke.py .\zig-out\bin\onyx-server.exe --exact-replay
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --resumption-tls12
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --generated
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --negative rotation
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --negative failed-reload
python -B .\tools\windows_helix_metrics_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_webhook_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_mesh_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_wasm_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_wasm_smoke.py .\zig-out\bin\onyx-server.exe --rehash
python -B .\tools\windows_helix_webtransport_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --generated
python -B .\tools\windows_helix_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --active
python -B .\tools\windows_webpush_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_geo_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mail_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_account_flow_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_multishard_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_backup_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webpush_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_ocg2_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_tls_companion_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_wasm_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mail_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_geo_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --ipv6-irc
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --irc-host 127.0.0.2
python -B .\tools\windows_media_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_media_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_media_smoke.py .\zig-out\bin\onyx-server.exe --active
python -B .\tools\windows_helix_combined_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_startup_intent_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe --helix
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe --helix --ctrl-c
```

The script starts the daemon from its own temporary run directory, so its
config, generated node key, and log are cleaned up after each run. The first
command checks TLS, WSS, metrics, and webhook together; the second checks
testing-only plaintext WebSocket without TLS; the third checks trusted PROXY
protocol and header refusal; the fourth checks durable accounts and TLS SASL
PLAIN; the fifth checks stats publication and cold-restart restore. The
remaining commands probe STS, secured mesh, reusable sessions, guarded Helix
swaps with OroWasm memory continuity, private backup and restore, Web Push,
account token continuity, OCG2 authority restore, ACME/OCSP workers, and
OroWasm plugin dispatch. Omit a flag to check a narrower configuration. A
passing build check establishes only that the daemon type-checks for the
Windows target.
The startup-intent smoke verifies that invalid configured keys, trust bundles,
and other security inputs fail preflight. It also verifies that occupied IRC,
TLS, WebSocket, metrics, webhook, and media ports fail startup.

## Windows verification

Run the complete Windows Debug suite, the focused socket, IOCP, entry-point,
and config preflight tests in both Debug and ReleaseSafe, then the native
full-daemon smoke:

```powershell
zig build -j1 test-windows -Dtarget=x86_64-windows --summary all
zig build -j1 test-windows -Dtarget=x86_64-windows -Doptimize=ReleaseSafe --summary all
zig build -j1 test -Dtarget=x86_64-windows --summary all
zig build -j1 test-mod -Dtarget=x86_64-windows '-Dtest-filter=proto.' --summary all
zig build -j1 test-mod -Dtarget=x86_64-windows '-Dtest-filter=daemon.store.test.' --summary all
zig build -j1 test-cli -Dtarget=x86_64-windows --summary all
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --tls --wss --metrics --webhook
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --ws-plain
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --proxy
python -B .\tools\windows_full_daemon_smoke.py .\zig-out\bin\onyx-server.exe --tls --accounts
python -B .\tools\windows_stats_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_sts_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mesh_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_session_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_smoke.py .\zig-out\bin\onyx-server.exe --inert-native-port
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --resumption
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --early-data
zig build windows-helix-early-client
python -B .\tools\windows_helix_early_data_smoke.py .\zig-out\bin\onyx-server.exe --exact-replay
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --resumption-tls12
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --generated
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --negative rotation
python -B .\tools\windows_helix_tls_smoke.py .\zig-out\bin\onyx-server.exe --negative failed-reload
python -B .\tools\windows_helix_metrics_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_webhook_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_mesh_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_wasm_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_wasm_smoke.py .\zig-out\bin\onyx-server.exe --rehash
python -B .\tools\windows_helix_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --active
python -B .\tools\windows_webpush_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_geo_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mail_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_account_flow_helix_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_multishard_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_backup_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_ocg2_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webpush_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_tls_companion_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_wasm_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_mail_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_geo_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --ipv6-irc
python -B .\tools\windows_webtransport_smoke.py .\zig-out\bin\onyx-server.exe --irc-host 127.0.0.2
python -B .\tools\windows_media_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_media_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_helix_media_smoke.py .\zig-out\bin\onyx-server.exe --active
python -B .\tools\windows_helix_combined_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_startup_intent_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe --helix
python -B .\tools\windows_console_stop_smoke.py .\zig-out\bin\onyx-server.exe --helix --ctrl-c
```

The repository pins LF line endings for embedded cryptographic test vectors
and the BoGo expected baseline in `.gitattributes`. This matters on Windows
checkouts with `core.autocrlf`: changing those files to CRLF changes their
literal test data. A fresh clone applies the attributes automatically.

The full Windows Debug suite also runs portable module and CLI tests. Some
tests skip platform-specific Linux/OpenBSD facilities. The process smokes
exercise configured listeners and services that unit tests cannot cover;
the Windows operational limits above remain in force.

If the pinned Zig compiler aborts while lowering the full Windows daemon
through LLVM, `-Dwindows-self-hosted=true` selects Zig's native code generator
for the daemon and Windows test artifacts. Use it with a native Windows host
and matching target architecture:

```powershell
zig build -j1 -Dtarget=x86_64-windows -Doptimize=ReleaseSafe -Dwindows-self-hosted=true
zig build -j1 test-windows -Dtarget=x86_64-windows -Dwindows-self-hosted=true
zig build -j1 test-windows -Dtarget=x86_64-windows -Doptimize=ReleaseSafe -Dwindows-self-hosted=true
zig build -j1 bogo-shim-test -Dtarget=x86_64-windows -Dwindows-self-hosted=true
zig build -j1 package -Dtarget=x86_64-windows -Dwindows-self-hosted=true
```

The build validates and corrects the self-hosted test PE stack
reserve to 64 MiB before each test run. This backend produces larger binaries
and can start more slowly. The in-repo BoGo shim tests use native Winsock and
Onyx's Zig TLS engine; they need no OpenSSL library or executable. The full
unfiltered suite and release gates remain required before shipping; focused
and native gates alone do not establish full Windows support.

For the complete build and test command list, see [Build guide](build.md) and
[Testing guide](testing.md).
