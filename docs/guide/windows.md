# Native Windows build and local IRC smoke

Onyx Server has a native Windows IOCP backend. The Windows daemon uses
`PortableServer` for local, plaintext IRC over IPv4. It is a useful local IRC
server, but it does not yet provide the full Linux/OpenBSD daemon feature set.

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
        $url = "https://pkg.hexops.org/zig/$zigVersion/$archiveName"
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
zig build check -Dtarget=x86_64-windows
zig build -Dtarget=x86_64-windows
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

The portable IRC path supports NICK/USER registration, PING/PONG, JOIN, PART,
NAMES, channel and direct nick PRIVMSG/NOTICE, and NICK/QUIT notifications to
clients sharing a channel. PART removes only the departing member; a client can
rejoin and receive channel messages again. These operations work across
concurrent local clients. Set `[listen].host` to an IPv4 address and
`[listen].irc` to the TCP port; the portable path also applies
`[limits].max_clients`, `nicklen`, `channellen`, and `chanlimit`. Windows IOCP
registration slots grow with demand, so the configured `max_clients` limit
applies within the configuration parser's limits. Replies with large NAMES
rosters are split into IRC-sized lines and sent through a bounded output queue.

The repository's `packaging/onyx-server.quickstart.toml` enables a WebSocket
listener, so it is not a Windows starter config. On Windows, config preflight
rejects unsupported intent with a specific reason before startup. This includes
TLS, WebSocket, STS, mesh links, WebTransport, media, metrics, PROXY protocol,
SASL/account services, webhooks, web push, mail, DNS blocklists, ACME, OCSP,
the weather/news bot, WASM plugins, stats and backup publication, GeoIP, and
OCG2 operator authority. The Windows build also does not provide Linux systemd
packaging or the Helix `USR2` hot-upgrade path.

Windows clients can use the local IRC commands listed above. The portable
runtime does not offer negotiated IRCv3 extensions: `CAP LS` advertises no
capabilities and `CAP REQ` rejects unsupported requests. Its registration
replies use a conservative `004`/`005` profile, without mode letters or tokens
for unimplemented features. This avoids presenting the full daemon's capability
and ISUPPORT inventory to clients that connect to the portable runtime.

## Runtime check

After building, run the loopback smoke test from the repository root:

```powershell
python .\tools\runtime_smoke.py .\zig-out\bin\onyx-server.exe
```

The script starts the daemon from its own temporary run directory, so its
config, generated node key, and log are cleaned up after the run. Its 22 native
Windows checkpoints cover CAP and ISUPPORT accuracy, three-client
registration, PING/PONG, JOIN fanout, direct and channel delivery, outsider
rejection, explicit NAMES, PART and rejoin, invalid nick rejection, NICK and
QUIT fanout, abrupt disconnect fanout, complete multi-line NAMES for a
41-member channel, responsiveness after 40 peers disconnect, registration of
140 concurrent clients, responsiveness before and after those clients quit,
clean socket EOF, and a still-running daemon after the clients leave. A
passing build check alone establishes only that the daemon type-checks for
the Windows target.

## Windows verification

Run the focused Windows socket, IOCP, and entry-point tests in both Debug and
ReleaseSafe, then run the portable protocol tests and runtime smoke:

```powershell
zig build test-windows -Dtarget=x86_64-windows --summary all
zig build test-windows -Dtarget=x86_64-windows -Doptimize=ReleaseSafe --summary all
zig build test-mod -Dtarget=x86_64-windows '-Dtest-filter=runtime capability policy' '-Dtest-filter=limited runtime welcome' --summary all
zig build test-mod -Dtarget=x86_64-windows -Doptimize=ReleaseSafe '-Dtest-filter=runtime capability policy' '-Dtest-filter=limited runtime welcome' --summary all
python .\tools\runtime_smoke.py .\zig-out\bin\onyx-server.exe
```

The repository pins LF line endings for embedded cryptographic test vectors
and the BoGo expected baseline in `.gitattributes`. This matters on Windows
checkouts with `core.autocrlf`: changing those files to CRLF changes their
literal test data. A fresh clone applies the attributes automatically.

The focused commands exercise the supported Windows path. The repository's
unfiltered `zig build test` still includes full-daemon tests that require
Linux/OpenBSD services and transports. Do not use the focused gate as evidence
that TLS, WebSocket, mesh, media, Helix, or the complete server suite works on
Windows.

For the complete build and test command list, see [Build guide](build.md) and
[Testing guide](testing.md).
