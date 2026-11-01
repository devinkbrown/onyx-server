#!/usr/bin/env python3
"""Run a gate once and retain conservative, content-bound evidence.

Status is evidence relevance, not release approval. No gate is silently skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = ["src", "etc", "tools", "packaging", "build.zig", "build.zig.zon"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(root: Path, inputs: list[str], command: list[str]) -> str:
    """Hash complete selected trees, execution context, and compiler executable."""
    entries = []
    for name in sorted(set(inputs)):
        base = root / name
        if not base.exists() or base.is_symlink():
            raise ValueError(f"missing or symlink input: {name}")
        paths = sorted(base.rglob("*")) if base.is_dir() else [base]
        for path in paths:
            if path.is_symlink():
                raise ValueError(f"symlink input: {path}")
            if path.is_file():
                entries.append([str(path), path.stat().st_mode & 0o777,
                                digest(path.read_bytes())])
    search_path = os.pathsep.join(str(root / item) for item in
                                  os.environ.get("PATH", os.defpath).split(os.pathsep))
    executable = (str(root / command[0]) if os.sep in command[0] else
                  shutil.which(command[0], path=search_path))
    if executable is None:
        raise ValueError("gate executable not found")
    # Store only the aggregate digest; environment values may contain secrets.
    # The tool invocation identifier changes on every orchestration call and
    # has no build meaning. Keep every other environment input conservative.
    environment = sorted((key, value) for key, value in os.environ.items()
                         if key != "CODEX_TOOL_CALL_ID")
    context = [str(root), platform.platform(), command, environment,
               str(Path(executable).resolve()), digest(Path(executable).read_bytes()), entries]
    return digest(json.dumps(context, sort_keys=True).encode())


# Conservative evidence only; runner summaries and build aggregates overlap.
# Never use these values to determine exit status or receipt relevance.
COUNT_LOG_LIMIT = 16 * 1024 * 1024
AGGREGATE = re.compile(rb"^Build Summary: [0-9]{1,20}/[0-9]{1,20} steps succeeded(?: \([0-9]{1,20} failed\))?; ([0-9]{1,20})/([0-9]{1,20}) tests passed(?: \(([^()]*)\))?$", re.M)
VERBOSE = re.compile(rb"^verbose test summary: ([0-9]{1,20}) passed; ([0-9]{1,20}) skipped; ([0-9]{1,20}) failed; ([0-9]{1,20}) leaked; ([0-9]{1,20}) log errors; elapsed [^\r\n]+$", re.M)

def test_counts(path: Path) -> dict | None:
    with path.open("rb") as stream:
        raw = stream.read(COUNT_LOG_LIMIT + 1)
    if len(raw) > COUNT_LOG_LIMIT:
        return None
    # A malformed or repeated candidate is ambiguous, even if another parses.
    aggregates = [line for line in raw.splitlines() if line.startswith(b"Build Summary:") and b"tests passed" in line]
    verbose = [line for line in raw.splitlines() if line.startswith(b"verbose test summary:")]
    if aggregates:
        if len(aggregates) != 1:
            return None
        match = AGGREGATE.fullmatch(aggregates[0])
        if not match:
            return None
        passed, total = map(int, match.group(1, 2))
        counts = {"skipped": 0, "failed": 0, "crashed": 0}
        details = match.group(3)
        if details:
            seen = set()
            for item in details.split(b", "):
                part = re.fullmatch(rb"([0-9]{1,20}) (skipped|failed|crashed)", item)
                if not part or part.group(2) in seen:
                    return None
                seen.add(part.group(2)); counts[part.group(2).decode()] = int(part.group(1))
        if passed + sum(counts.values()) != total:
            return None
        return dict(scope="build_aggregate", provenance="zig_build_summary", passed=passed, total=total, **counts, leaked=None, log_errors=None)
    if len(verbose) != 1:
        return None
    match = VERBOSE.fullmatch(verbose[0])
    if not match:
        return None
    passed, skipped, failed, leaked, log_errors = map(int, match.groups())
    return dict(scope="single_verbose_runner", provenance="verbose_test_summary", passed=passed,
                total=None, skipped=skipped, failed=failed, crashed=None,
                leaked=leaked, log_errors=log_errors)


def run(root: Path, record: Path, inputs: list[str], command: list[str]) -> int:
    before = snapshot(root, inputs, command)
    record.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    log = record.with_suffix(".log")
    # Never clobber an earlier record/log, including a symlink.
    fd = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as output:
            with log.open("xb") as stream:
                os.chmod(log, 0o600)
                started = time.monotonic()
                result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
            after = snapshot(root, inputs, command)
            data = dict(version=1, root=str(root), inputs=inputs, command=command, source_context=before,
                        unchanged=before == after, exit_code=result.returncode,
                        seconds=round(time.monotonic() - started, 3),
                        log_sha256=digest(log.read_bytes()), test_counts=test_counts(log))
            json.dump(data, output, indent=2)
            output.write("\n")
    except BaseException:
        # An incomplete record is intentionally unusable, never a cached pass.
        raise
    usable = data["unchanged"] and result.returncode == 0
    print(json.dumps(dict(exit_code=result.returncode, unchanged=data["unchanged"],
                          seconds=data["seconds"], log=str(log), reusable=usable)))
    return 0 if usable else 1


def decision(root: Path, record: Path) -> dict:
    """Advise continuation without executing a gate or granting acceptance."""
    data = json.loads(record.read_text())
    if data.get("version") != 1:
        raise ValueError("unsupported evidence record")
    if type(data.get("exit_code")) is not int or type(data.get("unchanged")) is not bool:
        raise ValueError("incomplete evidence record")
    if data["log_sha256"] != digest(record.with_suffix(".log").read_bytes()):
        return dict(action="investigate", reason="evidence_log_changed")
    if not data["unchanged"]:
        return dict(action="investigate", reason="inputs_changed_during_gate")
    if data["source_context"] != snapshot(root, data["inputs"], data["command"]):
        return dict(action="run_changed_context", reason="recorded_context_changed")
    if data["exit_code"] != 0:
        return dict(action="diagnose", reason="unchanged_failure_do_not_repeat")
    return dict(action="reuse", reason="matching_success_inspect_counts_and_supervisor")


def status(root: Path, record: Path) -> int:
    result = decision(root, record)
    messages = {
        "reuse": "CURRENT: inspect counts/skips and supervisor; not release approval",
        "run_changed_context": "CHANGED: record the relevant correction before rerunning",
        "diagnose": "FAILED UNCHANGED: diagnose or obtain independent review; do not repeat",
        "investigate": "UNUSABLE: investigate changed evidence or unstable inputs before rerunning",
    }
    print(messages[result["action"]])
    return 0 if result["action"] == "reuse" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["run", "status", "decision"])
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="source directory and gate working directory (default: this tool's repository)")
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--input", action="append", dest="inputs",
                        help="dependency file/tree; default covers all production/build/tool sources")
    args, command = parser.parse_known_args()
    root = args.root.resolve(strict=True)
    if not root.is_dir():
        parser.error("--root must be a directory")
    if command[:1] == ["--"]:
        command = command[1:]
    if args.action in ("status", "decision"):
        if command or args.inputs:
            parser.error("status/decision take only --root and --record")
        if args.action == "decision":
            result = decision(root, args.record)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["action"] == "reuse" else 1
        return status(root, args.record)
    if not command:
        parser.error("run requires -- executable [arguments]")
    return run(root, args.record, args.inputs or DEFAULT_INPUTS, command)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"gate ledger: {error}", file=sys.stderr)
        sys.exit(2)
