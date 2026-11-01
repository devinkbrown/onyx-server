#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real offline cloak-audit processes against synthetic private checkpoints.

Retains bounded owner-only captures and a fixed-stage result in --work-dir.
The fixture builder is a separate acceptance executable, never a product flag.
No config, sockets, live services, environment credentials, or operational keys.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile

CAPTURE_LIMIT = 2 << 20
CHILD_TIMEOUT = 30
REFUSAL = b"cloak-audit: audit refused\n"
EXPECTED = (["verified_replacement"] * 5 + ["derivation_mismatch", "missing_witness",
            "ambiguous_host_glob", "unsupported_formula", "invalid_witness",
            "already_current", "witness_mismatch"])


class Failure(Exception):
    pass


def require(value, reason):
    if not value:
        raise Failure(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def summary(kinds):
    return b"".join(f"row={i} classification={kind}\n".encode() for i, kind in enumerate(kinds))


def access_rows(data):
    """Independent framing/metadata oracle; native codec checks BLAKE3 itself."""
    header = struct.unpack_from("<4sB3xIHHHHQQQQ", data)
    require(header[0:2] == (b"ACCS", 1), "access_header")
    require(len(data) == 52 + header[2] + 32, "access_length")
    pos = 52
    rows, tombstones = [], []
    for _ in range(header[3]):
        c, m, s, level, has_duration, has_expiry = struct.unpack_from("<6B", data, pos)
        pos += 6
        channel, mask, issuer = data[pos:pos+c], data[pos+c:pos+c+m], data[pos+c+m:pos+c+m+s]
        pos += c + m + s
        values = []
        for present in (has_duration, has_expiry):
            require(present in (0, 1), "access_nullable_tag")
            values.append(struct.unpack_from("<Q", data, pos)[0] if present else None)
            pos += 8 * present
        hlc, origin = struct.unpack_from("<QQ", data, pos)
        pos += 16
        rows.append({"channel": channel, "mask": mask, "issuer": issuer, "level": level,
                     "duration": values[0], "expiry": values[1], "hlc": hlc, "origin": origin})
    for _ in range(header[4]):
        c, m, level = struct.unpack_from("<3B", data, pos)
        pos += 3
        channel, mask = data[pos:pos+c], data[pos+c:pos+c+m]
        pos += c + m
        clocks = struct.unpack_from("<QQQ", data, pos)
        pos += 24
        tombstones.append((channel, mask, level, *clocks))
    require(pos == len(data) - 32, "access_consumption")
    return header, rows, tombstones


class Campaign:
    def __init__(self, binary, generator, root):
        self.binary, self.generator, self.root = binary, generator, root
        self.fixtures = root / "PRIVATE_fixtures"
        self.captures = root / "PRIVATE_captures"
        self.fixtures.mkdir(mode=0o700)
        self.captures.mkdir(mode=0o700)
        self.stage = "initialize"
        self.cases = 0
        self.originals = {}
        self.secret_tokens = []
        self.binary_hash = digest(binary)
        self.generator_hash = digest(generator)

    def unchanged(self):
        for path, (data, mode) in self.originals.items():
            require(path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == mode,
                    "fixture_input_changed")

    def invoke(self, stage, arguments, expected, expected_out=None, *, executable=None,
               stdout_failure=False, file_failure=False):
        self.stage = stage
        require(all(token not in "\0".join(arguments) for token in self.secret_tokens), "secret_in_argv")
        paths = [self.captures / f"{self.cases:03d}-{stage}.{suffix}" for suffix in ("out", "err")]
        for path in paths:
            private_write(path, b"")
        env = {"PATH": os.defpath, "TMPDIR": str(self.root), "NO_COLOR": "1"}
        require(all(token not in "\0".join(env.values()) for token in self.secret_tokens), "secret_in_env")

        def limits():
            os.umask(0o077)
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1 if file_failure else CAPTURE_LIMIT,) * 2)

        try:
            with paths[0].open("rb" if stdout_failure else "wb") as out, paths[1].open("wb") as err:
                result = subprocess.run([str(executable or self.binary), *arguments], cwd=self.root,
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                        timeout=CHILD_TIMEOUT, env=env, preexec_fn=limits)
        except subprocess.TimeoutExpired:
            raise Failure("child_timeout") from None
        except OSError:
            raise Failure("child_launch_failed") from None
        require(all(path.stat().st_size <= CAPTURE_LIMIT for path in paths), "capture_limit")
        stdout, stderr = (path.read_bytes() for path in paths)
        joined = stdout + stderr
        require(all(token.encode() not in joined for token in self.secret_tokens), "secret_in_report")
        require(b"PRIVATE_" not in joined and str(self.root).encode() not in joined, "private_path_in_report")
        require(result.returncode == expected, "child_status")
        if executable is None:
            if expected == 0:
                require(stderr == b"" and stdout == expected_out, "success_report")
            elif expected == 1:
                if file_failure:
                    require(stdout in (b"", expected_out) and stderr in (b"", REFUSAL[:1]), "bounded_disk_refusal")
                else:
                    require(stderr == REFUSAL, "fixed_redacted_refusal")
                    require(stdout in (b"", summary(EXPECTED)), "refusal_report")
            else:
                require(stdout == b"" and stderr.startswith(b"usage: onyx-server cloak-audit "), "grammar_refusal")
        else:
            require(stdout == b"" and stderr == b"", "fixture_builder_report")
        self.cases += 1
        self.unchanged()
        return stdout

    def arguments(self, kind="access", witness="access.witness", output=None, input_name=None):
        args = ["cloak-audit", "--kind", kind, "--input", str(self.fixtures / (input_name or f"{kind}.input")),
                "--witness", str(self.fixtures / witness)]
        if output is not None:
            args.extend(["--checkpoint-output", str(output)])
        return args

    def refuses(self, stage, *, witness="access.witness", kind="access", input_name=None,
                output=None, stdout_failure=False, file_failure=False):
        output = output or self.fixtures / f"refused-{stage}"
        before = set(self.fixtures.iterdir())
        self.invoke(stage, self.arguments(kind, witness, output, input_name), 1,
                    stdout_failure=stdout_failure, file_failure=file_failure)
        require(not output.exists() and not output.is_symlink(), "failed_publication")
        require(set(self.fixtures.iterdir()) == before, "partial_stage_residue")

    def run(self):
        self.invoke("fixture-builder", [str(self.fixtures)], 0, executable=self.generator)
        original_names = {"access.input", "access.expected", "access.witness", "access.missing",
                          "saccess.input", "saccess.witness"}
        require({p.name for p in self.fixtures.iterdir()} == original_names, "fixture_namespace")
        for path in self.fixtures.iterdir():
            require(stat.S_ISREG(path.stat().st_mode) and stat.S_IMODE(path.stat().st_mode) == 0o600,
                    "fixture_privacy")
            self.originals[path] = (path.read_bytes(), 0o600)
        doc = json.loads((self.fixtures / "access.witness").read_text())
        self.secret_tokens = [doc["target"]["key_hex"], "203.0.113.9", "private-issuer", "private-reason"]
        self.secret_tokens.extend({row["key_hex"] for row in doc["witnesses"]})
        self.secret_tokens.extend({row["expected_mask"] for row in doc["witnesses"]})
        # expected_mask="different-mask" and source key labels are private too.
        before_namespace = set(self.fixtures.iterdir())
        self.invoke("default-redacted", self.arguments(), 0, summary(EXPECTED))
        require(set(self.fixtures.iterdir()) == before_namespace, "default_published_artifact")
        output = self.fixtures / "candidate"
        self.invoke("verified-candidate", self.arguments(output=output), 0, summary(EXPECTED))
        actual = output.read_bytes()
        require(actual == (self.fixtures / "access.expected").read_bytes(), "access_candidate_bytes")
        require(stat.S_IMODE(output.stat().st_mode) == 0o600 and output.stat().st_nlink == 1, "published_privacy")
        head_before, before, tomb_before = access_rows((self.fixtures / "access.input").read_bytes())
        head_after, after, tomb_after = access_rows(actual)
        require(head_before[:2] + head_before[3:] == head_after[:2] + head_after[3:] and
                tomb_before == tomb_after and len(tomb_before) == 1, "metadata_header_tombstones")
        require(head_after[2] - head_before[2] ==
                sum(len(new["mask"]) - len(old["mask"]) for old, new in zip(before, after)),
                "body_length_mask_delta")
        require(len(before) == len(after) == 12 and head_before[5:8] == (31, 19, 271) and
                head_before[8:10] == (100, 9), "nonvacuous_source_parameters")
        require(len({row["hlc"] for row in before}) == 12 and all(row["origin"] == 9 for row in before),
                "nonvacuous_clocks")
        require({row["duration"] for row in before} == {None, 0, 30} and
                {row["expiry"] for row in before} == {None, 130} and
                len({row["channel"] for row in before}) == 2, "nonvacuous_expiry_order")
        for index, (old, new) in enumerate(zip(before, after)):
            require({k: v for k, v in old.items() if k != "mask"} ==
                    {k: v for k, v in new.items() if k != "mask"}, "issuer_expiry_clock_order_changed")
            if index < 5:
                require(old["mask"] != new["mask"] and old["mask"].split(b"@")[0] == new["mask"].split(b"@")[0],
                        "verified_scope")
            else:
                require(old == new, "unverified_rule_changed")
        missing = self.fixtures / "missing-candidate"
        kinds = ["missing_witness"] * 12
        kinds[7] = "ambiguous_host_glob"
        self.invoke("missing-witness", self.arguments(witness="access.missing", output=missing), 0, summary(kinds))
        require(missing.read_bytes() == (self.fixtures / "access.input").read_bytes(), "missing_changed")
        soutput = self.fixtures / "saccess-candidate"
        self.invoke("saccess-gap", self.arguments("saccess", "saccess.witness", soutput), 0,
                    summary(["metadata_gap"] * 3))
        require(soutput.read_bytes() == (self.fixtures / "saccess.input").read_bytes(), "saccess_changed")

        for stage, args in [
            ("grammar-empty", ["cloak-audit"]),
            ("grammar-missing-value", self.arguments()[:-1]),
            ("grammar-duplicate", self.arguments() + ["--kind", "access"]),
            ("grammar-unknown", self.arguments() + ["--apply", str(self.fixtures / "forbidden")]),
            ("grammar-trailing", self.arguments() + ["trailing"]),
            ("grammar-relative", ["cloak-audit", "--kind", "access", "--input", "relative", "--witness", str(self.fixtures / "access.witness")]),
        ]:
            self.invoke(stage, args, 2)
        before_files = {p: p.read_bytes() for p in (output, missing, soutput)}
        before_namespace = set(self.fixtures.iterdir())
        self.invoke("existing-output", self.arguments(output=output), 1)
        require(set(self.fixtures.iterdir()) == before_namespace, "existing_output_stage_residue")
        require(all(p.read_bytes() == data for p, data in before_files.items()), "existing_output_changed")
        hard_output = self.fixtures / "hard-output"
        os.link(output, hard_output)
        self.invoke("output-hardlink", self.arguments(output=hard_output), 1)
        require(output.read_bytes() == actual and hard_output.stat().st_ino == output.stat().st_ino,
                "hardlink_target_changed")
        hard_output.unlink()
        link = self.fixtures / "output-link"
        link.symlink_to(output.name)
        self.invoke("output-symlink", self.arguments(output=link), 1)
        require(link.is_symlink() and output.read_bytes() == actual, "symlink_target_changed")
        link.unlink()
        link.symlink_to("access.input")
        self.refuses("input-symlink", input_name=link.name)
        link.unlink()
        link.symlink_to("access.witness")
        self.refuses("witness-symlink", witness=link.name)
        link.unlink()
        alias = self.root / "PRIVATE_alias"
        alias.symlink_to(self.fixtures, target_is_directory=True)
        alias_output = alias / "new-output"
        self.invoke("output-parent-symlink", self.arguments(output=alias_output), 1)
        require(not (self.fixtures / "new-output").exists(), "symlink_parent_publication")
        args = self.arguments()
        args[4] = str(alias / "access.input")
        self.invoke("input-parent-symlink", args, 1)
        alias.unlink()
        hard = self.fixtures / "hard-input"
        os.link(self.fixtures / "access.input", hard)
        self.refuses("input-hardlink", input_name=hard.name)
        hard.unlink()
        os.link(self.fixtures / "access.witness", hard)
        self.refuses("witness-hardlink", witness=hard.name)
        hard.unlink()
        os.mkfifo(self.fixtures / "fifo", 0o600)
        self.refuses("input-fifo", input_name="fifo")
        (self.fixtures / "fifo").unlink()
        (self.fixtures / "directory").mkdir(mode=0o700)
        self.refuses("input-directory", input_name="directory")
        (self.fixtures / "directory").rmdir()
        # Temporarily modify permissions only on test-owned sources; restore
        # before invoking unchanged() so the read-only oracle stays meaningful.
        broad = self.fixtures / "broad-input"
        private_write(broad, (self.fixtures / "access.input").read_bytes())
        broad.chmod(0o644)
        self.refuses("input-broad-mode", input_name=broad.name)
        broad.unlink()
        broad = self.fixtures / "broad-witness"
        private_write(broad, (self.fixtures / "access.witness").read_bytes())
        broad.chmod(0o644)
        self.refuses("witness-broad-mode", witness=broad.name)
        broad.unlink()
        broad_parent = self.root / "PRIVATE_broad"
        broad_parent.mkdir(mode=0o755)
        broad_parent.chmod(0o755)
        self.invoke("output-broad-parent", self.arguments(output=broad_parent / "output"), 1)
        require(not (broad_parent / "output").exists(), "broad_parent_publication")
        private_write(broad_parent / "input", (self.fixtures / "access.input").read_bytes())
        args = self.arguments()
        args[4] = str(broad_parent / "input")
        self.invoke("input-broad-parent", args, 1)

        invalid_docs = {
            "json-malformed": b"private malformed input",
            "json-unknown": json.dumps(dict(doc, apply=True)).encode(),
            "json-duplicate": ("{\"version\":1," + json.dumps(doc)[1:]).encode(),
            "json-trailing": json.dumps(doc).encode() + b" {}",
            "json-version": json.dumps(dict(doc, version=2)).encode(),
            "json-oversize": b" " * ((1 << 20) + 1),
        }
        for label, payload in invalid_docs.items():
            path = self.fixtures / label
            private_write(path, payload)
            self.refuses(label, witness=path.name)
        for field, value in [("target", "g" * 64), ("target", "0" * 63),
                             ("source", "g" * 64), ("source", "0" * 65)]:
            variant = copy.deepcopy(doc)
            node = variant["target"] if field == "target" else variant["witnesses"][0]
            node["key_hex"] = value
            label = f"hex-{field}-{len(value)}-{'invalid' if 'g' in value else 'length'}"
            private_write(self.fixtures / label, json.dumps(variant).encode())
            self.refuses(label, witness=label)
        for label, change in [
            ("rows-order", lambda d: d["witnesses"].reverse()),
            ("rows-outside", lambda d: d["witnesses"][-1].update(row=20)),
            ("rows-limit", lambda d: d["witnesses"][-1].update(row=4096)),
            ("target-cadence", lambda d: d["target"].update(cadence=0)),
        ]:
            variant = copy.deepcopy(doc)
            change(variant)
            private_write(self.fixtures / label, json.dumps(variant).encode())
            self.refuses(label, witness=label)
        private_write(self.fixtures / "bad-checkpoint", b"ACCS malformed private checkpoint")
        self.refuses("checkpoint-malformed", input_name="bad-checkpoint")
        private_write(self.fixtures / "large-checkpoint", b"x" * ((8 << 20) + 1))
        self.refuses("checkpoint-oversize", input_name="large-checkpoint")
        self.refuses("stdout-write-failure", stdout_failure=True)
        self.refuses("checkpoint-write-failure", file_failure=True)
        self.unchanged()
        require(digest(self.binary) == self.binary_hash and digest(self.generator) == self.generator_hash,
                "executable_changed")
        require(self.cases == 44, "campaign_case_count")
        return {"status": "passed", "cases": self.cases, "binary_sha256": self.binary_hash,
                "fixture_sha256": self.generator_hash,
                "checks": ["five-historical-formulas", "arbitrary-key-octets", "redacted-native-reports",
                           "issuer-expiry-clock-tombstone-order", "unknown-provenance-unchanged",
                           "saccess-explicit-metadata-gap", "strict-full-grammar", "create-only-private-artifact",
                           "nofollow-custody", "hardlink-fifo-mode-parent-refusal", "bounded-inputs",
                           "report-and-disk-write-failure-atomic", "source-images-unchanged"],
                "limitations": ["synthetic-offline-state-only", "no-live-apply-or-mesh-authority",
                                "wrong-owner-and-sync-failure-not-injected", "no-adversarial-owner-concurrent-mutation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--generator", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    campaign = None
    root = None
    try:
        require(sys.platform == "linux" and os.geteuid() != 0, "requires_nonroot_linux")
        binary, generator = args.binary.resolve(strict=True), args.generator.resolve(strict=True)
        if args.work_dir:
            root = args.work_dir.absolute()
            root.mkdir(mode=0o700)
        else:
            root = Path(tempfile.mkdtemp(prefix="cloak-audit-native-", dir=Path.cwd() / ".zig-cache"))
        require(stat.S_IMODE(root.stat().st_mode) == 0o700, "private_work_directory")
        campaign = Campaign(binary, generator, root)
        result = campaign.run()
        private_write(root / "result.json", json.dumps(result, indent=2).encode() + b"\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {"status": "failed", "stage": campaign.stage if campaign else "initialize",
                  "reason": str(error) if isinstance(error, Failure) else "fixture_exception"}
        if root is not None:
            try:
                private_write(root / "failure.json", json.dumps(result, sort_keys=True).encode() + b"\n")
            except OSError:
                pass
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
