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



ROOT_IDENTITIES = ("module", "executable", "cli")
MAX_PROFILE_BYTES = 16 * 1024 * 1024


def parse_durations(text, names):
    """Read runner timings, including cases that print diagnostics mid-line."""
    allowed = set(names)
    found = {}
    current = None
    for line in text.splitlines():
        beginning = re.match(r"^\[\d+/\d+\] (.+) \.\.\. ", line)
        if beginning:
            current = beginning[1]
        finish = re.search(r"(?:^| )(?:OK|SKIP) \((\d+(?:\.\d+)?)(us|ms|s)\)$", line)
        if finish and current in allowed:
            factor = {"us": 1000, "ms": 1_000_000, "s": 1_000_000_000}[finish[2]]
            found[current] = max(1, int(float(finish[1]) * factor))
            current = None
    return found


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate profile key")
        result[key] = value
    return result


def load_profile(path, mode, target):
    if path is None or mode is None or target is None:
        return None
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_PROFILE_BYTES:
            raise ValueError("profile too large")
        profile = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
        if (type(profile.get("version")) is not int or profile.get("version") != 1 or profile.get("mode") != mode or profile.get("target") != target
                or profile.get("complete") is not True or type(profile.get("exit_code")) is not int
                or profile["exit_code"] != 0):
            raise ValueError("profile identity or completion mismatch")
        roots = profile["roots"]
        if not isinstance(roots, list) or len(roots) != 3:
            raise ValueError("profile requires all three roots")
        for identity, root in zip(ROOT_IDENTITIES, roots):
            if root["identity"] != identity or not re.fullmatch(r"[a-f0-9]{64}", root["binary_sha256"]):
                raise ValueError("root identity mismatch")
            counts = root["totals"]
            if (not isinstance(counts, list) or len(counts) != 5
                    or any(type(count) is not int or count < 0 for count in counts)
                    or any(counts[2:]) or type(root["discovered"]) is not int
                    or sum(counts[:3]) != root["discovered"] or root["discovered"] <= 0):
                raise ValueError("profile contains incomplete or failing counts")
            durations = root["durations_ns"]
            if not isinstance(durations, dict) or len(durations) != root["discovered"]:
                raise ValueError("profile timing coverage mismatch")
            if any(not name or any(ch in name for ch in "\r\n\x00") or type(ns) is not int
                   or not 0 < ns <= 86_400_000_000_000 for name, ns in durations.items()):
                raise ValueError("invalid duration")
        return profile
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(f"timings profile unavailable or invalid; using hash shards: {path}", flush=True)
        return None


def profile_path(cache, mode, target):
    if mode is None or target is None:
        return None
    key = hashlib.sha256(json.dumps([mode, target]).encode()).hexdigest()
    return cache / (key + ".json")


def save_profile(path, profile):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + os.urandom(6).hex() + ".tmp")
    try:
        with temporary.open("x") as output:
            json.dump(profile, output, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def complete_profile(suite, mode, target):
    """A scheduling hint only; never creates gate/release acceptance."""
    if suite.get("complete") is not True or type(suite.get("exit_code")) is not int or suite["exit_code"] != 0:
        raise ValueError("only mechanically complete successful suites can provide timings")
    artifacts = suite["artifacts"]
    if len(artifacts) != 3:
        raise ValueError("timings require module, executable, and CLI roots")
    roots = []
    for identity, artifact in zip(ROOT_IDENTITIES, artifacts):
        if (artifact.get("complete") is not True or len(artifact["totals"]) != 5
                or any(type(count) is not int or count < 0 for count in artifact["totals"])
                or any(artifact["totals"][2:])
                or artifact.get("identity", identity) != identity
                or artifact.get("mode", mode) not in (None, mode)
                or artifact.get("target", target) not in (None, target)):
            raise ValueError("incomplete or failing artifact")
        # Older complete receipts predate explicit cwd; their emitted binary
        # path identifies the repository's .zig-cache/o/<hash>/<binary> root.
        cwd = Path(artifact["working_directory"]) if "working_directory" in artifact else Path(artifact["binary"]).parents[3]
        names = None
        timings = {}
        executed = 0
        aggregate = [0] * 5
        for result in artifact["results"]:
            if result["returncode"] != 0 or result.get("error") is not None or result.get("timed_out"):
                raise ValueError("failed shard cannot provide timings")
            log = Path(result["log"])
            if not log.is_absolute():
                log = cwd / log
            raw = log.read_bytes()
            if hashlib.sha256(raw).hexdigest() != result["log_sha256"]:
                raise ValueError("timing evidence log hash mismatch")
            text = raw.decode(errors="replace")
            summaries = SUMMARY.findall(text)
            executions = EXECUTED.findall(text)
            if len(summaries) != 1 or len(executions) != 1:
                raise ValueError("missing terminal timing evidence")
            counts = list(map(int, summaries[0]))
            if counts != list(result["counts"]) or sum(counts[:3]) != int(executions[0][0]) or any(counts[2:]):
                raise ValueError("timing evidence count mismatch")
            executed += int(executions[0][0])
            aggregate = [a + b for a, b in zip(aggregate, counts)]
            current_names = (log.parent / "inventory.txt").read_text().splitlines()
            if names is not None and current_names != names:
                raise ValueError("shards disagree on full inventory")
            names = current_names
            timings.update(parse_durations(text, names))
        if (not names or len(set(names)) != len(names) or len(names) != artifact["discovered"]
                or executed != len(names) or aggregate != artifact["totals"]):
            raise ValueError("incomplete timing inventory")
        observed = sorted(timings.values())
        fallback = observed[len(observed) // 2] if observed else 1_000_000
        roots.append({"identity": identity, "binary_sha256": artifact["binary_sha256"],
                      "discovered": len(names), "totals": artifact["totals"],
                      "durations_ns": {name: timings.get(name, fallback) for name in names}})
    totals = [sum(root["totals"][i] for root in roots) for i in range(5)]
    if suite["totals"] != totals or suite["discovered"] != sum(root["discovered"] for root in roots):
        raise ValueError("suite timing aggregate mismatch")
    return {"version": 1, "mode": mode, "target": target, "complete": True, "exit_code": 0, "roots": roots}


def balanced_names(names, weights, workers):
    observed = sorted(weights.values())
    fallback = observed[len(observed) // 2] if observed else 1_000_000
    buckets = [[] for _ in range(workers)]
    totals = [0] * workers
    for name in sorted(names, key=lambda name: (-weights.get(name, fallback), name)):
        index = min(range(workers), key=lambda i: (totals[i], i))
        buckets[index].append(name)
        totals[index] += weights.get(name, fallback)
    return [sorted(bucket) for bucket in buckets if bucket]


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


def run(binary, workers, logs, policy="all", timeout_seconds=3600, seed=0, weights=None, identity=None, mode=None, target=None):
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
    scheduler = "hash"
    if weights is not None and workers > 1 and policy == "all":
        candidates = []
        for index, names in enumerate(balanced_names(full, weights, workers)):
            manifest = (logs / f"plan-{index}.names").resolve()
            manifest.write_text("\n".join(names) + "\n")
            candidates.append([f"--test-name-file={manifest}"])
        scheduler = "duration"
    elif workers == 1:
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
                "seed": seed, "timeout_seconds": timeout_seconds, "scheduler": scheduler,
                "identity": identity, "mode": mode, "target": target, "working_directory": str(Path.cwd()),
                "shards": [{"args": args, "count": len(names)} for args, names in shards]}
    (logs / "run.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"full inventory verified: scheduler={scheduler} {len(full)} cases, shard sizes {[len(names) for _, names in shards]}, logs={logs}", flush=True)
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
    parser.add_argument("binary", nargs="*", type=lambda s: str(Path(s).resolve()))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--policy", choices=["conservative", "all"], default="all")
    parser.add_argument("--logs", type=Path, help="new log directory; default: unique .zig-cache/full-suite-runs child")
    parser.add_argument("--timeout", type=float, default=3600, help="maximum runtime seconds per shard (default: 3600)")
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--mode", choices=["debug", "safe", "fast", "small"])
    parser.add_argument("--target")
    parser.add_argument("--profile-cache", type=Path, default=Path(".zig-cache/full-suite-profiles"))
    parser.add_argument("--timings-profile", type=Path, help="optional mechanically complete timing profile to import for scheduling")
    parser.add_argument("--import-timings-suite", type=Path, help="convert a complete retained suite.json into a scheduling profile; does not run tests")
    parser.add_argument("--profile-output", type=Path, help="output for --import-timings-suite; defaults to local profile cache")
    args = parser.parse_args()
    cached_profile = profile_path(args.profile_cache, args.mode, args.target)
    if args.import_timings_suite is not None:
        if args.mode is None or args.target is None or args.binary:
            parser.error("timing import requires --mode and --target and no binary arguments")
        try:
            profile = complete_profile(json.loads(args.import_timings_suite.read_text()), args.mode, args.target)
            destination = args.profile_output or cached_profile
            if args.profile_output is not None and destination.exists():
                raise FileExistsError("explicit timing profile output already exists")
            save_profile(destination, profile)
            print(f"saved mechanically complete scheduling hint: {destination}; no release acceptance", flush=True)
            return 0
        except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
            print(f"timing import failed: {error}", file=sys.stderr)
            return 1
    if not args.binary:
        parser.error("at least one test binary is required")
    profile = load_profile(args.timings_profile or cached_profile, args.mode, args.target)
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
            identity = ROOT_IDENTITIES[i] if len(args.binary) == 3 else f"artifact-{i}"
            weights = None
            if profile is not None and identity in ROOT_IDENTITIES:
                weights = profile["roots"][ROOT_IDENTITIES.index(identity)]["durations_ns"]
            code, metadata = run(binary, args.workers, log_dir, args.policy, args.timeout, args.seed,
                                 weights, identity, args.mode, args.target)
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
        if cached_profile is not None and len(artifacts) == 3 and complete and not any(codes) and not any(totals[2:]):
            try:
                save_profile(cached_profile, complete_profile(suite, args.mode, args.target))
                print(f"saved mechanically complete scheduling hint: {cached_profile}; no release acceptance", flush=True)
            except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
                print(f"timing hint not saved: {error}", flush=True)
        print(f"parallel suite summary: artifacts={len(artifacts)} discovered={discovered} executed={passed + skipped + failed} passed={passed} skipped={skipped} failed={failed} leaked={leaked} log_errors={errors} complete={int(complete)}", flush=True)
        return int(any(codes))
    except (RuntimeError, ValueError, OSError) as error:
        print(f"full runtime failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
