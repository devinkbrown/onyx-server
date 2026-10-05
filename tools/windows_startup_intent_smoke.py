#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify Windows refuses configured security and listener startup failures.

Usage: python -B tools/windows_startup_intent_smoke.py [zig-out/bin/onyx-server.exe]
"""

import argparse
from contextlib import closing
import os
from pathlib import Path
import socket
import subprocess
import tempfile

from windows_backup_smoke import reserve_ports
from windows_private_account_dir import create_private_directory
from windows_tls_companion_smoke import create_fixture


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "zig-out" / "bin" / "onyx-server.exe"


def base(irc_port, *, tls_port=None):
    lines = ["[node]", "id = 1", "", "[listen]", 'host = "127.0.0.1"', f"irc = {irc_port}", ""]
    if tls_port is not None:
        lines += ["[tls]", "enabled = true", f"port = {tls_port}",
                  'dns_name = "localhost"', 'cert_path = "leaf.pem"',
                  'key_path = "keys-private/server.key"', ""]
    return "\n".join(lines)


def check(binary, run_dir, name, config, *, accepted, expected=""):
    path = run_dir / name
    path.write_text(config, encoding="utf-8")
    result = subprocess.run([str(binary), "--check-config", str(path)], cwd=run_dir,
                            capture_output=True, text=True, timeout=30, check=False)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != accepted or (expected and expected not in output):
        raise AssertionError(f"{name}: unexpected preflight exit={result.returncode}: {output[-4000:]}")
    return path


def boot_refuses(binary, run_dir, path, expected):
    try:
        result = subprocess.run([str(binary), str(path)], cwd=run_dir,
                                capture_output=True, text=True, timeout=12, check=False)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{path.name}: daemon kept serving after configured startup failure") from exc
    output = result.stdout + result.stderr
    if result.returncode == 0 or expected not in output:
        raise AssertionError(f"{path.name}: unexpected boot exit={result.returncode}: {output[-6000:]}")


def hold_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock


def hold_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    return sock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this smoke requires native Windows")
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"binary not found: {binary}")

    with tempfile.TemporaryDirectory(prefix="onyx-intent-windows-") as scratch:
        run_dir = Path(scratch)
        create_private_directory(run_dir / "keys-private")
        create_private_directory(run_dir / "accounts-private")
        create_fixture(run_dir)
        irc_port, tls_port = reserve_ports(2)
        good = base(irc_port, tls_port=tls_port)
        check(binary, run_dir, "valid.toml", good, accepted=True)

        other = run_dir / "other"
        other.mkdir()
        create_private_directory(other / "keys-private")
        create_fixture(other)
        bad_seed = good.replace("id = 1", 'id = 1\nsecret_key = "bad"')
        path = check(binary, run_dir, "bad-node-secret.toml", bad_seed,
                     accepted=False, expected="BadSeed")
        boot_refuses(binary, run_dir, path, "BadSeed")
        print("PASS: malformed configured node secret fails preflight and boot")

        wrong_key = 'other/keys-private/server.key'
        bad_identity = good.replace('key_path = "keys-private/server.key"',
                                    f'key_path = "{wrong_key}"')
        path = check(binary, run_dir, "bad-identity.toml", bad_identity,
                     accepted=False, expected="TlsKeyMismatch")
        boot_refuses(binary, run_dir, path, "TlsKeyMismatch")
        print("PASS: certificate and mismatched private key fail preflight and boot")

        bad_sni_identity = good + '\n[[tls.sni]]\nserver_names = ["extra.test"]\n' + \
            'cert_path = "leaf.pem"\n' + f'key_path = "{wrong_key}"\n'
        check(binary, run_dir, "bad-sni-identity.toml", bad_sni_identity,
              accepted=False, expected="TlsKeyMismatch")
        print("PASS: SNI certificate and mismatched private key fail preflight")

        bad_cert = good.replace('cert_path = "leaf.pem"', 'cert_path = "missing.pem"')
        path = check(binary, run_dir, "bad-cert.toml", bad_cert, accepted=False)
        boot_refuses(binary, run_dir, path, "FileNotFound")
        print("PASS: missing configured TLS certificate fails preflight and boot")

        bad_sni = good + "\n[[tls.sni]]\nserver_names = [\"extra.test\"]\n" + \
            'cert_path = "missing-sni.pem"\nkey_path = "keys-private/server.key"\n'
        check(binary, run_dir, "bad-sni.toml", bad_sni, accepted=False)
        print("PASS: missing configured SNI certificate fails preflight")

        bad_ech = good + "\n[[tls.ech_keys]]\n" + \
            'config_path = "missing-ech.bin"\n' + \
            'private_key = "' + "11" * 32 + '"\n'
        check(binary, run_dir, "bad-ech.toml", bad_ech, accepted=False)
        print("PASS: missing configured ECH config fails preflight")

        (run_dir / "broken-jwks.json").write_text("{broken", encoding="utf-8")
        bad_jwks = good + '\n[sasl]\nenabled = true\noauth_jwks_file = "broken-jwks.json"\n'
        path = check(binary, run_dir, "bad-jwks.toml", bad_jwks, accepted=False)
        boot_refuses(binary, run_dir, path, "InvalidJson")
        print("PASS: malformed configured OAuth JWKS fails preflight and boot")

        bad_sts = good + "\n[sts]\nenabled = true\nduration = 3600\nport = 0\n"
        check(binary, run_dir, "bad-sts.toml", bad_sts, accepted=False)
        print("PASS: unusable configured STS value fails preflight")

        account = '\n[sasl]\nenabled = true\naccount_db = "accounts-private/accounts.wal"\n'
        bad_webpush_trust = base(irc_port) + account + \
            '\n[acme]\nca_bundle_path = "missing-roots.pem"\n' + \
            '\n[webpush]\nenabled = true\nvapid_key_path = "keys-private/vapid.key"\n' + \
            'subject = "mailto:ops@example.test"\n'
        check(binary, run_dir, "bad-webpush-trust.toml", bad_webpush_trust,
              accepted=False, expected="FileNotFound")
        print("PASS: missing configured Web Push trust bundle fails preflight")

        bad_mail_trust = base(irc_port) + account + \
            '\n[mail]\nenabled = true\nrelay_host = "127.0.0.1"\n' + \
            'from = "noreply@example.test"\ntrust_store_path = "missing-mail-roots.pem"\n'
        check(binary, run_dir, "bad-mail-trust.toml", bad_mail_trust,
              accepted=False, expected="FileNotFound")
        print("PASS: missing configured SMTP trust bundle fails preflight")

        with closing(hold_tcp()) as held:
            occupied = held.getsockname()[1]
            path = check(binary, run_dir, "irc-held.toml", base(occupied), accepted=True)
            boot_refuses(binary, run_dir, path, "AddressInUse")
        print("PASS: occupied IRC port fails Windows boot")

        with closing(hold_tcp()) as held:
            occupied = held.getsockname()[1]
            path = check(binary, run_dir, "tls-held.toml", base(irc_port, tls_port=occupied), accepted=True)
            boot_refuses(binary, run_dir, path, "SocketUnavailable")
        print("PASS: occupied TLS port fails Windows boot")

        with closing(hold_tcp()) as held:
            occupied = held.getsockname()[1]
            cfg = base(irc_port).replace(f"irc = {irc_port}",
                                         f"irc = {irc_port}\nws = {occupied}\nws_plain = true")
            path = check(binary, run_dir, "ws-held.toml", cfg, accepted=True)
            boot_refuses(binary, run_dir, path, "SocketUnavailable")
        print("PASS: occupied WebSocket port fails Windows boot")

        with closing(hold_tcp()) as held:
            occupied = held.getsockname()[1]
            cfg = base(irc_port) + f'\n[metrics]\nlisten = {occupied}\nbind = "127.0.0.1"\n'
            path = check(binary, run_dir, "metrics-held.toml", cfg, accepted=True)
            boot_refuses(binary, run_dir, path, "MetricsStartupFailed")
        print("PASS: occupied configured metrics port fails Windows boot")

        with closing(hold_tcp()) as held:
            occupied = held.getsockname()[1]
            cfg = base(irc_port) + f'\n[webhook]\nenabled = true\nlisten = {occupied}\nbind = "127.0.0.1"\n'
            path = check(binary, run_dir, "webhook-held.toml", cfg, accepted=True)
            boot_refuses(binary, run_dir, path, "WebhookStartupFailed")
        print("PASS: occupied configured webhook port fails Windows boot")

        with closing(hold_udp()) as held:
            occupied = held.getsockname()[1]
            native_port = reserve_ports(1)[0]
            cfg = "\n".join([
                "[node]", "id = 1", "", "[listen]", 'host = "127.0.0.1"',
                f"irc = {irc_port}", f"media = {occupied}",
                f"native_media = {native_port}", 'media_host = "127.0.0.1"',
                "", "[media]", "enabled = true", "",
            ])
            path = check(binary, run_dir, "media-held.toml", cfg, accepted=True)
            boot_refuses(binary, run_dir, path, "MediaStartupFailed")
        print("PASS: occupied configured media UDP port fails Windows boot")


if __name__ == "__main__":
    main()
