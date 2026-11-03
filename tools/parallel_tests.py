#!/usr/bin/env python3
"""Run one compiled test artifact in bounded, coverage-checked runtime shards."""
import argparse
import hashlib
import json
import os
import math
import signal
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import sys
import time
import threading

STOP = threading.Event()

SUMMARY = re.compile(r"verbose test summary: (\d+) passed; (\d+) skipped; (\d+) failed; (\d+) leaked; (\d+) log errors")
EXECUTED = re.compile(r"executed (\d+) tests; excluded (\d+) tests")


def inventory(binary, args):
    result = subprocess.run([binary, *args, "--list-tests"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # The runner emits only its selection line, exact names, and footer in list mode.
    lines = result.stdout.splitlines()
    if result.returncode == 2 and "no tests matched" in result.stdout:
        return []
    if result.returncode or len(lines) < 2 or not lines[0].startswith("test selection:") or not re.fullmatch(r"listed \d+ tests; executed 0", lines[-1]):
        raise RuntimeError(f"invalid inventory ({result.returncode}): {result.stdout}")
    names = lines[1:-1]
    if len(names) != int(lines[-1].split()[1]):
        raise RuntimeError("inventory count mismatch")
    return names


def run(binary, workers, logs, policy="all", timeout_seconds=3600, seed=0):
    if not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if os.name != "posix":
        raise ValueError("runtime process-group cleanup currently requires POSIX; use the native standard gate")
    logs.mkdir(parents=True, exist_ok=False)
    full = inventory(binary, [])
    if not full:
        raise RuntimeError("empty full inventory")
    if workers == 1:
        candidates = [[]]
    elif policy == "all":
        candidates = [[f"--test-shard-count={workers}", f"--test-shard-index={i}"] for i in range(workers)]
    else:
        candidates = [["--test-group=serial"]] + [
            ["--test-group=parallel", f"--test-shard-count={workers - 1}", f"--test-shard-index={i}"]
            for i in range(workers - 1)]
    shards = [(args, inventory(binary, args)) for args in candidates]
    shards = [(args, names) for args, names in shards if names]
    shards = [(args + [f"--seed={seed}"], names) for args, names in shards]
    combined = Counter(name for _, names in shards for name in names)
    if combined != Counter(full) or any(count != 1 for count in combined.values()):
        raise RuntimeError("shard inventories must be a disjoint exact cover of full inventory")
    (logs / "inventory.txt").write_text("\n".join(full) + "\n")
    for i, (args, names) in enumerate(shards):
        (logs / f"shard-{i}.inventory.txt").write_text("\n".join(names) + "\n")
    metadata = {"binary": binary, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                "workers": workers, "policy": policy, "discovered": len(full),
                "seed": seed, "timeout_seconds": timeout_seconds,
                "shards": [{"args": args, "count": len(names)} for args, names in shards]}
    (logs / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"full inventory verified: {len(full)} cases, shard sizes {[len(names) for _, names in shards]}, logs={logs}", flush=True)
    started = time.monotonic()

    def execute(item):
        index, (args, names) = item
        log = logs / f"shard-{index}.log"
        status = {"index": index, "args": args, "expected": len(names), "log": str(log),
                  "returncode": None, "counts": None, "timed_out": False, "error": None}
        began = time.monotonic()
        last_progress = began
        proc = None
        try:
            with log.open("w") as out:
                proc = subprocess.Popen([binary, *args], stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
                while True:
                    remaining = timeout_seconds - (time.monotonic() - began)
                    if remaining <= 0 or STOP.is_set():
                        status["timed_out"] = remaining <= 0
                        if STOP.is_set():
                            status["error"] = "interrupted; shard group terminated"
                        # The group contains only this shard and its children.
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            pass
                        # Kill descendants even when the leader already exited.
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        proc.wait()
                        break
                    try:
                        proc.wait(timeout=min(1, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() - last_progress < 30:
                            continue
                        last_progress = time.monotonic()
                        with log.open("rb") as current:
                            current.seek(0, 2)
                            current.seek(max(0, current.tell() - 4096))
                            tail = current.read().decode(errors="replace").splitlines()
                        last = tail[-1] if tail else "(no test output yet)"
                        print(f"shard {index} active {time.monotonic() - began:.1f}s: {last}", flush=True)
                status["returncode"] = proc.returncode
            text = log.read_text(errors="replace")
            summaries = SUMMARY.findall(text)
            executions = EXECUTED.findall(text)
            if status["timed_out"]:
                status["error"] = f"shard timeout after {timeout_seconds}s"
            elif status["error"] is not None:
                pass
            elif len(summaries) != 1 or len(executions) != 1:
                status["error"] = "missing terminal counts"
            else:
                counts = tuple(map(int, summaries[0]))
                status["counts"] = counts
                if int(executions[0][0]) != len(names) or sum(counts[:3]) != len(names):
                    status["error"] = "execution count mismatch"
        except OSError as error:
            status["error"] = str(error)
        finally:
            # Also clean accidental surviving children after an abnormal or
            # nominal leader exit. Never signal any other shard's group.
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
        if status["error"] is not None or status["returncode"] != 0:
            with log.open("a") as out:
                out.write(f"\nharness terminal failure: exit={status['returncode']} timed_out={status['timed_out']} error={status['error']}\n")
        status["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        status["elapsed_seconds"] = time.monotonic() - began
        print(f"shard {index} finished: exit={status['returncode']} counts={status['counts']} error={status['error']} log={log}", flush=True)
        return status

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(execute, enumerate(shards)))
    totals = [sum(result["counts"][i] for result in results if result["counts"] is not None) for i in range(5)]
    metadata.update({"results": results, "totals": totals, "elapsed_seconds": time.monotonic() - started})
    (logs / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"full runtime: discovered={len(full)} executed={sum(totals[:3])} passed={totals[0]} skipped={totals[1]} failed={totals[2]} leaked={totals[3]} log_errors={totals[4]} workers={workers} policy={policy} elapsed={time.monotonic() - started:.3f}s logs={logs}", flush=True)
    code = int(any(result["returncode"] != 0 or result["error"] is not None for result in results) or any(totals[2:]))
    metadata["complete"] = all(result["counts"] is not None and result["error"] is None for result in results)
    (logs / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return code, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="+", type=lambda s: str(Path(s).resolve()))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--policy", choices=["conservative", "all"], default="all")
    parser.add_argument("--logs", type=Path, help="new log directory; default: unique .zig-cache/full-suite-runs child")
    parser.add_argument("--timeout", type=float, default=3600, help="maximum runtime seconds per shard (default: 3600)")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0)
    args = parser.parse_args()
    if args.logs is None:
        nonce = os.urandom(6).hex()
        args.logs = Path(".zig-cache/full-suite-runs") / f"{time.time_ns()}-{os.getpid()}-{nonce}"
    print(f"retained full-suite logs: {args.logs}", flush=True)
    if not 0 <= args.seed <= 0xffffffff:
        parser.error("seed must fit unsigned 32 bits")
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _sig, _frame: STOP.set())
    try:
        if len(args.binary) > 1:
            args.logs.mkdir(parents=True, exist_ok=False)
        codes = []
        artifacts = []
        for i, binary in enumerate(args.binary):
            if STOP.is_set():
                return 1
            log_dir = args.logs if len(args.binary) == 1 else args.logs / f"artifact-{i}"
            code, metadata = run(binary, args.workers, log_dir, args.policy, args.timeout, args.seed)
            codes.append(code)
            artifacts.append(metadata)
            passed, skipped, failed, leaked, errors = metadata["totals"]
            print(f"parallel artifact summary: index={i} discovered={metadata['discovered']} executed={passed + skipped + failed} passed={passed} skipped={skipped} failed={failed} leaked={leaked} log_errors={errors} complete={int(metadata['complete'])}", flush=True)
        totals = [sum(artifact["totals"][i] for artifact in artifacts) for i in range(5)]
        passed, skipped, failed, leaked, errors = totals
        discovered = sum(artifact["discovered"] for artifact in artifacts)
        complete = all(artifact["complete"] for artifact in artifacts)
        suite = {"artifacts": artifacts, "totals": totals, "discovered": discovered,
                 "complete": complete, "seed": args.seed, "exit_code": int(any(codes))}
        (args.logs / "suite.json").write_text(json.dumps(suite, indent=2) + "\n")
        print(f"parallel suite summary: artifacts={len(artifacts)} discovered={discovered} executed={passed + skipped + failed} passed={passed} skipped={skipped} failed={failed} leaked={leaked} log_errors={errors} complete={int(complete)}", flush=True)
        return int(any(codes))
    except (RuntimeError, ValueError, OSError) as error:
        print(f"full runtime failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
