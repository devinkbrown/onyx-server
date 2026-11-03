# Armor command-line toolkit

`armor` is the standalone pure-Zig cryptographic toolkit built beside
`onyx-server`; these are host CLI commands, not IRC verbs. The executable is
installed by the ordinary build graph. Source dispatch and exit behavior:
[armor_main.zig](../../src/cli/armor_main.zig), [CLI root](../../src/cli/root.zig),
and [build.zig](../../build.zig). `armor <command> --help` is the exact per-command
usage for the built revision.

## Command status and supported operations

| Command | Current syntax and behavior | Source |
|---|---|---|
| `x509` | `[-in path] [-inform pem|der] [-text] [-fingerprint] [-noout] [-outform pem|der] [-out path]`; inspect/re-encode a certificate and render SHA-256/SPKI fingerprints. | [x509_cmd.zig](../../src/cli/x509_cmd.zig) |
| `genpkey` | `-algorithm ec|ed25519 [-out path]`; generate a supported private key. | [pkey_cmd.zig](../../src/cli/pkey_cmd.zig) |
| `pkey` | `-in path [-noout]`; parse/render the supported private-key representation. | [pkey_cmd.zig](../../src/cli/pkey_cmd.zig) |
| `req` | `-key path -cn name [-dns name]... [-out path]`; generate the implemented certificate request. | [req_cmd.zig](../../src/cli/req_cmd.zig) |
| `dgst` | `[-sha256|-sha384|-sha512] [-hmac-key path] [file]`; digest defaults to SHA-256; HMAC reads its key from a file. | [dgst_cmd.zig](../../src/cli/dgst_cmd.zig) |
| `verify` | `-CAfile bundle [-name dns] [cert]`; verify the supported certificate-chain/hostname policy against explicit anchors. | [verify_cmd.zig](../../src/cli/verify_cmd.zig) |
| `rand` | `[-hex|-base64] [-out path] num`; emit 1..16 MiB of OS-seeded DRBG output. Default output is raw bytes. | [rand_cmd.zig](../../src/cli/rand_cmd.zig) |
| `ciphers` | No arguments; list toolkit cipher information. | [ciphers_cmd.zig](../../src/cli/ciphers_cmd.zig) |
| `asn1parse` | `[-in path] [-inform pem|der] [-label name]`; bounded ASN.1 inspection. | [asn1parse_cmd.zig](../../src/cli/asn1parse_cmd.zig) |
| `ocsp` | `[-in path] [-inform pem|der] [-text] [-noout] [-verify -CAfile bundle] [-serial hex]`; inspect a response or verify its current supported status/issuer policy. | [ocsp_cmd.zig](../../src/cli/ocsp_cmd.zig) |
| `crl` | `[-in path] [-inform pem|der] [-text] [-noout] [-verify -CAfile bundle] [-serial hex] [-at epoch]`; inspect or authenticate a CRL and assess a serial under its freshness policy. | [crl_cmd.zig](../../src/cli/crl_cmd.zig) |
| `s_client` | `-connect host:port -CAfile bundle [-servername dns] [-name dns] [-alpn proto]`; parse options/anchors and initialize the socketless client, then return unsupported (`NotImplemented`, exit 3); no live socket is opened. | [s_client_cmd.zig](../../src/cli/s_client_cmd.zig) |

This is an implemented subset of familiar OpenSSL-style verbs, not full argument
or algorithm parity with OpenSSL. `s_client` has an option parser and in-memory handshake tests but no CLI network
transport. `s_server` and `enc` are named stubs; all three unsupported live operations return
exit 3 rather than silently doing incomplete crypto. Source:
[stub_cmds.zig](../../src/cli/stub_cmds.zig).

## Practical examples

```sh
zig-out/bin/armor ciphers
zig-out/bin/armor rand -hex 32
zig-out/bin/armor dgst -sha256 artifact.bin
zig-out/bin/armor x509 -in fullchain.pem -fingerprint -noout
zig-out/bin/armor verify -CAfile ca-bundle.pem -name irc.example.net leaf.pem
```

The sample random command writes secret bytes to stdout; choose private file
handling when using generated material operationally. Never paste a generated
private key or credential into diagnostics. Certificate inspection and successful
parsing are not trust validation: `x509 -text` does not replace `verify` with
explicit anchors and the expected DNS identity.

The current `s_client -connect ... -CAfile ...` command is **not a live network
diagnostic**: after valid options and anchors load it returns exit `3`. Invalid
options or inputs can fail earlier. In-memory client/server tests prove their
own handshake path, not a CLI connection to the supplied host. Use an actually
implemented TLS client or the project's real daemon TLS smoke harness to verify
a listener; do not cite this unsupported command as network acceptance.

Offline `ocsp`/`crl` inspection is not a general online revocation-fetch service.

## Exit status and verification

| Status | Meaning |
|---|---|
| `0` | Command completed. Check the verb's requested mode: successful parse/print is different from requested trust verification. |
| `1` | Operational, parsing, cryptographic or verification failure. |
| `2` | Invalid/missing command usage. |
| `3` | Explicit unsupported stub. |

Use `zig build test-cli` for focused toolkit verification and the complete
[full-suite gate](../guide/testing.md) for shipping. Crypto library tests,
external TLS interoperability and daemon listener acceptance each have separate
scopes; CLI tests do not automatically certify every standards profile. See
[the crypto architecture](../architecture/crypto.md).
