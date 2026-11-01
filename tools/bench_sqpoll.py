#!/usr/bin/env python3
"""Build/run isolated production Ringlane NOP benchmarks; never starts a daemon.

Example (after coordinating compiler capacity):
  python3 tools/bench_sqpoll.py --build /path/to/zig --output .zig-cache/sqpoll.json
  python3 tools/bench_sqpoll.py --binary .zig-cache/sqpoll/worker --repetitions 3

The 0 mode means SQPOLL disabled, not a zero kernel idle parameter. Kernel SQ
workers are explicitly included in /proc CPU accounting. READY/GO/RESULT/ACK
keeps all benchmark tasks/rings alive during both CPU snapshots. No sudo, cgroup,
service/config changes, or connections to an existing daemon are used.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import selectors
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["tools/bench_sqpoll.zig", "tools/bench_sqpoll.py", "src/daemon/ringlane.zig", "src/substrate/io/buf_ring.zig"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(zig, out):
    out.mkdir(parents=True, exist_ok=True)
    info = out / "build_info.zig"
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    info.write_text(f"pub const git_commit = {json.dumps(commit)};\npub const version = \"sqpoll-benchmark\";\n")
    binary = out / "worker"
    command = [str(Path(zig).resolve()), "build-exe", "-O", "safe", "--dep", "onyx",
               "-Mroot=tools/bench_sqpoll.zig", "--dep", "build_info", "-Monyx=src/root.zig",
               f"-Mbuild_info={info}", "--cache-dir", str(out / "cache"), f"-femit-bin={binary}"]
    env = dict(os.environ)
    env["TMPDIR"] = str(out / "tmp")
    Path(env["TMPDIR"]).mkdir(exist_ok=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    metadata = {"command": command, "compiler": subprocess.check_output([zig, "version"], text=True).strip(),
                "git_head": commit, "source_sha256": {p: digest(ROOT / p) for p in SOURCES},
                "binary_sha256": digest(binary)}
    binary.with_suffix(".build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return binary


def task_stat(path):
    # comm may contain spaces/parentheses; fields following the final ')' begin
    # at stat field 3. CPU fields are 14/15, starttime is 22.
    content = path.read_text()
    close = content.rfind(")")
    fields = content[close + 2:].split()
    return {"name": content[content.index("(") + 1:close],
            "ticks": int(fields[11]) + int(fields[12]), "starttime": int(fields[19])}


def snapshot(pid, mode, rings, known=None):
    paths = {int(p.name): p / "stat" for p in (Path("/proc") / str(pid) / "task").iterdir()}
    # Kernel-version dependent placement: include SQ workers even if exposed
    # outside the benchmark process's task directory. Match only this child's PID.
    expected_name = f"iou-sqp-{pid}"
    if known is None:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit() or int(p.name) in paths:
                continue
            try:
                if (p / "comm").read_text().strip() == expected_name:
                    paths[int(p.name)] = p / "stat"
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
    else:
        # Reuse verified SQ-worker paths at the end; scanning all of /proc
        # after RESULT would extend the sampled polling window unnecessarily.
        for tid, old in known.items():
            if tid not in paths:
                paths[tid] = Path(old["stat_path"])
    values = {tid: dict(task_stat(path), stat_path=str(path)) for tid, path in paths.items()}
    sq_count = sum(v["name"] == expected_name for v in values.values())
    if mode and sq_count != rings:
        raise RuntimeError(f"CPU coverage invalid: found {sq_count} SQ workers, expected {rings}")
    return values


def line(process, timeout):
    # The worker writes one protocol record then waits for input; no buffered
    # lookahead can conceal a second record from the selector.
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise TimeoutError("benchmark protocol deadline exceeded")
    raw = process.stdout.readline()
    if not raw:
        raise RuntimeError(f"worker exited before protocol record (status={process.poll()})")
    return json.loads(raw)


def percentile(values, q):
    if not values:
        return None
    return sorted(values)[max(0, math.ceil(len(values) * q) - 1)]


def measure(binary, cell, repetition, duration_ms):
    mode, rings, scenario, batch = cell
    record = dict(mode=mode, rings=rings, scenario=scenario, batch=batch, repetition=repetition,
                  duration_ms=duration_ms, load_before=os.getloadavg())
    process = subprocess.Popen([str(binary), str(mode), str(rings), scenario, str(batch), str(duration_ms)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, bufsize=1)
    try:
        ready = line(process, 70)
        if ready["status"] == "unsupported":
            process.wait(timeout=5)
            record.update(status="unsupported", reason=ready["reason"])
            return record
        if ready["status"] != "ready" or ready["pid"] != process.pid:
            raise RuntimeError("invalid READY identity/status")
        if mode and ready["wake_observed"] != rings:
            raise RuntimeError("SQ sleeping-worker wakeup test did not cover every ring")
        before = snapshot(process.pid, mode, rings)
        begin = time.monotonic_ns()
        process.stdin.write("GO\n")
        process.stdin.flush()
        result = line(process, duration_ms / 1000 + 30)
        after = snapshot(process.pid, mode, rings, known=before)
        end = time.monotonic_ns()
        if before.keys() != after.keys():
            raise RuntimeError("CPU task set changed during measurement")
        per_task = []
        for tid, first in before.items():
            last = after[tid]
            if first["starttime"] != last["starttime"] or last["ticks"] < first["ticks"]:
                raise RuntimeError("CPU task identity/counter changed")
            per_task.append(dict(tid=tid, name=last["name"], ticks=last["ticks"] - first["ticks"]))
        process.stdin.write("ACK\n")
        process.stdin.flush()
        status = process.wait(timeout=10)
        if status != 0 or result["status"] != "ok":
            raise RuntimeError(f"worker failed: {result}, exit={status}")
        hz = os.sysconf("SC_CLK_TCK")
        cpu_s = sum(v["ticks"] for v in per_task) / hz
        sq_cpu_s = sum(v["ticks"] for v in per_task if v["name"] == f"iou-sqp-{process.pid}") / hz
        wall_s = (end - begin) / 1e9
        elapsed_s = result["elapsed_ns"] / 1e9
        latencies = result.pop("latency_ns")
        if result["completed"] <= 0 or result["completed"] % batch != 0:
            raise RuntimeError("invalid exact completion total")
        if scenario == "burst" and (result["completed"] != rings * batch * (duration_ms // 250)
                                    or len(latencies) != rings * (duration_ms // 250)):
            raise RuntimeError("burst completion/sample count differs from scheduled workload")
        record.update(result, status="ok", sampled_wall_s=wall_s, cpu_s=cpu_s, sq_cpu_s=sq_cpu_s,
                      core_equivalents=cpu_s / wall_s, operations_per_s=result["completed"] / elapsed_s,
                      cpu_ns_per_operation=cpu_s * 1e9 / result["completed"],
                      burst_p50_ns=percentile(latencies, .5), burst_p99_ns=percentile(latencies, .99),
                      burst_samples=len(latencies), burst_latency_ns=latencies, wake_observed=ready["wake_observed"],
                      cpu_ticks_per_s=hz, cpu_clock_tick_s=1 / hz, cpu_tasks=per_task, load_after=os.getloadavg())
        return record
    except Exception as exc:
        record.update(status="failed", reason=str(exc))
        return record
    finally:
        if process.poll() is None:
            process.kill()  # Only this tool's isolated child, never a daemon.
        process.wait()
        stderr = process.stderr.read()
        if stderr:
            record["stderr"] = stderr
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--build", metavar="ZIG", help="compile the isolated worker, then measure")
    selection.add_argument("--binary", type=Path, help="measure an already built isolated worker")
    parser.add_argument("--directory", type=Path, default=ROOT / ".zig-cache/sqpoll")
    parser.add_argument("--duration-ms", type=int, default=10_000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--modes", type=int, nargs="+", default=[0, 1000, 10])
    parser.add_argument("--rings", type=int, nargs="+", default=[1, 4])
    parser.add_argument("--scenarios", nargs="+", choices=["burst", "continuous"], default=["burst", "continuous"])
    parser.add_argument("--batches", type=int, nargs="+", default=[32, 256])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Linux /proc and io_uring are required; no benchmark was run")
    if not 250 <= args.duration_ms <= 60_000 or args.duration_ms % 250 != 0 or args.repetitions < 1:
        parser.error("duration must be 250..60000ms in 250ms steps and repetitions positive")
    if any(v not in (0, 1000, 10) for v in args.modes) or any(v not in (1, 4) for v in args.rings) or any(v not in (32, 256) for v in args.batches):
        parser.error("modes must be 0/1000/10, rings 1/4, batches 32/256")
    args.directory = args.directory.resolve()
    binary = build(args.build, args.directory) if args.build else args.binary.resolve()
    metadata_path = binary.with_suffix(".build.json")
    build_metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else None
    if build_metadata and build_metadata["binary_sha256"] != digest(binary):
        parser.error("binary no longer matches its build metadata")
    uname = platform.uname()
    report = {"kernel": {k: getattr(uname, k) for k in ("system", "release", "version", "machine")},
              "cpu_accounting": "Sum of benchmark task and verified SQ-worker utime+stime deltas; tick-quantized, so zero means below resolution. Driver CPU excluded.",
              "driver_sha256": digest(Path(__file__)), "binary": str(binary), "binary_sha256": digest(binary),
              "build": build_metadata, "cpu_affinity": sorted(os.sched_getaffinity(0)),
              "started_unix_s": time.time(), "records": [], "medians": []}
    # Alternate mode order within each workload and reverse both workload and
    # mode order on alternating repetitions, avoiding mode/host-load confounding.
    cells = [(rings, scenario, batch) for rings in args.rings for scenario in args.scenarios for batch in args.batches]
    for repetition in range(args.repetitions):
        for index, (rings, scenario, batch) in enumerate(cells if repetition % 2 == 0 else list(reversed(cells))):
            modes = args.modes if (repetition + index) % 2 == 0 else list(reversed(args.modes))
            for mode in modes:
                record = measure(binary, (mode, rings, scenario, batch), repetition, args.duration_ms)
                report["records"].append(record)
                print(json.dumps(record), flush=True)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
    for rings, scenario, batch in cells:
        for mode in args.modes:
            group = [r for r in report["records"] if (r["mode"], r["rings"], r["scenario"], r["batch"]) == (mode, rings, scenario, batch) and r["status"] == "ok"]
            if group:
                metrics = ["operations_per_s", "cpu_s", "sq_cpu_s", "core_equivalents", "cpu_ns_per_operation", "burst_p50_ns", "burst_p99_ns"]
                summary = dict(mode=mode, rings=rings, scenario=scenario, batch=batch, successful_repetitions=len(group))
                summary.update({k: statistics.median(r[k] for r in group if r[k] is not None) for k in metrics if any(r[k] is not None for r in group)})
                report["medians"].append(summary)
    report["finished_unix_s"] = time.time()
    report["status"] = "failed" if any(r["status"] == "failed" for r in report["records"]) else "incomplete" if any(r["status"] != "ok" for r in report["records"]) else "ok"
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "medians": report["medians"]}), flush=True)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
