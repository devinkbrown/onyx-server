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
the foreground daemon with Ctrl+C. To remove this disposable node's config and
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
python -B .\tools\windows_private_account_dir.py $accountDir
```

Set `account_db = "accounts-private/accounts.wal"` in the config and start the
daemon from `$runDir`. Windows preflight rejects a broad account directory,
before opening any account file. On boot, existing WAL and snapshot files are
opened exclusively and their ACLs are verified or hardened before replay; a
retained reader makes boot fail. The daemon also checks that new snapshot
temporary files inherit a private ACL before writing account data. Keep the
directory private throughout the daemon's lifetime.

When `[backup].dir` is configured, `[sasl].enabled` and `account_db` are
required. Create the backup directory with
`tools/windows_private_account_dir.py` as above. The daemon publishes a
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
cold restart does not provide Windows Helix process upgrade or preserve the
hub's physical sockets.

Web Push requires an enabled account store, a private parent directory for
`[webpush].vapid_key_path`, and a PEM CA bundle at
`[acme].ca_bundle_path`. Windows boot fails if the key or trust bundle cannot
be loaded. The native smoke checks private key preflight, VAPID advertisement,
worker startup, and stable key identity after restart. Its local endpoint
cannot test delivery because the production SSRF guard refuses loopback push
targets; focused native tests cover the pinned-address HTTPS request path.

ACME renewal and the `acme-issue` command use native Windows HTTP-01 and
HTTPS transports. Set `[tls].cert_path`, `[tls].key_path`, `[acme].domain`,
and `[acme].ca_bundle_path` to a PEM trust bundle when enabling renewal.
Create the key file's parent with `tools/windows_private_account_dir.py`;
preflight refuses a broad parent directory or an unreadable trust bundle.
OCSP stapling uses the same trust bundle and requires an on-disk TLS fullchain
at `[tls].cert_path`. Native module tests cover the HTTP-01 listener, pinned
CA request, private key publication, and worker lifecycle. The disposable
daemon smoke checks private preflight, a TLS handshake, both worker starts,
and a CLI error path. Public ACME issuance and live OCSP publication still
require an end-to-end acceptance run.

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
observes the queued verification notice, and verifies that a deliberately
closed relay causes a durable failure row. A real remote SMTP relay and its
trust policy still need an acceptance test. DNS blocklist lookups use native
UDP with a checked worker start; the module test covers listed and clean
answers, and registration policy has a focused server test.

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

The repository's `packaging/onyx-server.quickstart.toml` selects one shard,
plaintext IRC and WebSocket, and an account store. Its `account_db =
"accounts.db"` points to the current directory, so ordinary Windows checkouts
with broad directory ACLs fail account preflight. To use it on Windows, create
the private account directory above, copy the quickstart config into `$runDir`,
and change the account path to `accounts-private/accounts.db`. The other
quickstart settings pass config preflight. The quickstart is for local
evaluation; configure TLS before sending account credentials across a network.
Windows also does not provide Linux systemd packaging or the
Helix `USR2` hot-upgrade path. Windows socket and private-WAL transfer building
blocks have focused tests, but process upgrade remains disabled until the
candidate's effective configuration and all live resource owners are bound to
one authenticated handoff and a cross-process upgrade smoke passes.

Windows outbound HTTP hostname lookup now uses `GetAddrInfoExW`, but enterprise
DNS policy and hosts-file variations have not had live acceptance tests. Socket
IDs use generation-safe slot reuse, so a closed descriptor never becomes valid
again. The 30-bit namespace still has a lifetime limit of roughly 1.07 billion
IDs per process (about 12.4 days at 1,000 new sockets per second); restart
before reaching that limit.

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
python -B .\tools\windows_startup_intent_smoke.py .\zig-out\bin\onyx-server.exe
```

The script starts the daemon from its own temporary run directory, so its
config, generated node key, and log are cleaned up after each run. The first
command checks TLS, WSS, metrics, and webhook together; the second checks
testing-only plaintext WebSocket without TLS; the third checks trusted PROXY
protocol and header refusal; the fourth checks durable accounts and TLS SASL
PLAIN; the fifth checks stats publication and cold-restart restore. The
remaining commands probe STS, secured mesh, reusable sessions, private
backup/restore, Web Push startup, OCG2 authority restore, and ACME/OCSP worker
startup, and OroWasm plugin dispatch. Omit a flag to check a narrower configuration. A passing build
check alone establishes only that the daemon
type-checks for the Windows target.
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
python -B .\tools\windows_startup_intent_smoke.py .\zig-out\bin\onyx-server.exe
```

The repository pins LF line endings for embedded cryptographic test vectors
and the BoGo expected baseline in `.gitattributes`. This matters on Windows
checkouts with `core.autocrlf`: changing those files to CRLF changes their
literal test data. A fresh clone applies the attributes automatically.

The full Windows Debug suite also runs portable module and CLI tests. Some
tests skip platform-specific Linux/OpenBSD facilities. The process smokes
exercise configured listeners and services that unit tests cannot cover;
the Windows operational limits above remain in force.

For the complete build and test command list, see [Build guide](build.md) and
[Testing guide](testing.md).
