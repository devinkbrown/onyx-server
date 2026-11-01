#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native offline-export controls; empty baseline, no live service or real keys.

Nonempty signed-fence semantics have separate Zig gates. This fixture does not
establish a complete retirement baseline for any running mesh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import subprocess
import sys
import tempfile

LIMIT = 2 << 20
# Public known-answer keys from src/crypto/sign_kat.zig, never operational keys.
LOCAL = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
PEER = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"


class Failure(Exception):
    pass


def require(value, reason):
    if not value:
        raise Failure(reason)


def limit_files():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def run(binary):
    require(sys.platform == "linux" and os.geteuid() != 0, "requires non-root Linux")
    artifact = hashlib.sha256(binary.read_bytes()).hexdigest()
    cases = 0
    with tempfile.TemporaryDirectory(prefix="onyx-retirement-cli-") as temporary:
        root = Path(temporary)
        closed = root / "closed"
        closed.mkdir(mode=0o700)
        wal = closed / "accounts.wal"
        wal.write_bytes(b"")
        wal.chmod(0o400)
        closed.chmod(0o500)
        marker = "PRIVATE_" + secrets.token_hex(24)
        config = root / (marker + ".toml")
        config.write_text(f'[node]\nid=1\npublic_key="{LOCAL}"\n[listen]\nirc=6680\n'
                          f'[mesh]\nrealm="offline-fixture"\nrequire_secured=true\nrequire_signed_frames=true\n'
                          f'trust_roots=["{PEER}"]\nrelay_v2_activation_epoch=7\nrelay_v2_roster=["{LOCAL}","{PEER}"]\n')
        config.chmod(0o600)
        original = config.read_bytes()

        def invoke(arguments, expected, reason=None):
            nonlocal cases
            paths = [root / f"capture-{cases}.{suffix}" for suffix in ("out", "err")]
            with paths[0].open("xb") as out, paths[1].open("xb") as err:
                for path in paths:
                    path.chmod(0o600)
                result = subprocess.run([str(binary), *arguments], cwd=root,
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        timeout=120, preexec_fn=limit_files,
                                        env={"PATH": os.defpath, "TMPDIR": str(root), "NO_COLOR": "1"})
            require(all(path.stat().st_size < LIMIT for path in paths), "capture exceeded bound")
            stdout, stderr = [path.read_bytes() for path in paths]
            require(result.returncode == expected, f"CLI case {cases} status {result.returncode}, expected {expected}")
            require(marker.encode() not in stdout + stderr, "private candidate path leaked")
            if reason is not None:
                require(stderr == (f"session-fences: export refused ({reason}); "
                                   "no policy content is printed\n").encode(),
                        f"CLI case {cases} refusal reason mismatch")
            cases += 1
            return stdout

        def export(name, *, issuer=LOCAL, expected=0, reason=None):
            output = root / name
            raw = invoke(["session-fences", "export", str(config), "--baseline", str(closed),
                          "--issuer", issuer, "--output", str(output)], expected, reason)
            if expected:
                require(not output.exists(), "failed export published a policy")
                return
            summary = json.loads(raw)
            require(summary.get("mode") == "retirement_policy_exported" and summary.get("grants") == 0,
                    "empty baseline summary mismatch")
            require(output.read_bytes() == b"" and output.stat().st_mode & 0o777 == 0o600,
                    "empty policy publication or privacy mismatch")
            require(summary.get("sha256") == hashlib.sha256(output.read_bytes()).hexdigest(),
                    "published policy hash mismatch")

        try:
            invoke(["session-fences", "export"], 2)
            export("policy.toml")
            policy = root / "policy.toml"
            before = policy.read_bytes()
            invoke(["session-fences", "export", str(config), "--baseline", str(closed),
                    "--issuer", LOCAL, "--output", str(policy)], 1, "PathAlreadyExists")
            require(policy.read_bytes() == before, "existing policy was overwritten")
            export("unknown.toml", issuer="11" * 32, expected=1, reason="IssuerNotActive")
            wal.chmod(0o600)
            export("writable.toml", expected=1, reason="InsecureBaseline")
            writer = os.open(wal, os.O_WRONLY)
            try:
                wal.chmod(0o400)
                export("active-writer.toml", expected=1, reason="ActiveWriter")
            finally:
                os.close(writer)
            closed.chmod(0o700)
            snapshot = closed / "accounts.wal.snap"
            snapshot.symlink_to("accounts.wal")
            closed.chmod(0o500)
            export("symlink.toml", expected=1, reason="InsecureBaseline")
            closed.chmod(0o700)
            snapshot.unlink()
            closed.chmod(0o500)
            export("after-refusal.toml")
            # Exercise the native command's shared bound, not only TOML helpers.
            config.write_bytes(b"#" + b"x" * (1100 * 1024) + b"\n" + original)
            export("large-config.toml")
            config.write_bytes(b"#" + b"x" * (2 * 1024 * 1024) + b"\n" + original)
            export("oversized-config.toml", expected=1, reason="StreamTooLong")
            config.write_bytes(original)
            require(wal.read_bytes() == b"" and wal.stat().st_mode & 0o777 == 0o400,
                    "readonly export changed baseline")
            require(config.read_bytes() == original and sorted(path.name for path in closed.iterdir()) == ["accounts.wal"],
                    "export changed source configuration or baseline namespace")
        finally:
            closed.chmod(0o700)
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == artifact, "artifact changed during fixture")
    return {"artifact_sha256": artifact, "cases": cases,
            "checks": ["empty-private-baseline", "create-only-policy", "selected-active-issuer",
                       "writable-source-refusal", "existing-writer-refusal", "symlink-refusal",
                       "native-over-one-mib-config", "native-two-mib-bound", "readonly"],
            "limitations": ["empty-baseline-only", "no-live-service-or-membership-change",
                            "nonempty-signed-facts-have-separate-module-gates"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.binary.resolve(strict=True)), indent=2))
    except Exception:
        parser.exit(1, "retirement CLI smoke: fixture failed; private captures omitted\n")
