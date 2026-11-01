#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Private loopback daemon measurements; never touches onyx-server.service.

The retained --sqpoll-phases profile uses a captured artifact, pinned TLS 1.3,
four persistent clients on one shard, exact ordered fanout receipts, and separate
idle/burst/continuous CPU windows including verified SQPOLL workers. It requires
an explicit artifact SHA-256 and JSON destination. --phase-pilot is a reduced
correctness profile, never a throughput baseline.

Legacy 0.7 P0-1 / GAP-X4 modes retain historical latency/RSS measurements rather
than exact delivery acceptance. Every profile boots a private daemon, preflights
its configuration, and avoids ports 6667/6680/6697/8080 and installed services.

Usage:
  python3 tools/bench_live.py --bin CAPTURED_IMAGE --sqpoll-phases --phase-pilot \
    --repetitions 1 --sqpoll-modes 10 --expected-sha256 SHA256 --phase-json pilot.json
  python3 tools/bench_live.py --bin zig-out/bin/onyx-server --quick
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover — non-Unix
    resource = None  # type: ignore[assignment]

HOST = "127.0.0.1"
FORBIDDEN_PORTS = {6667, 6680, 6697, 8080}
CHANNEL = "#bench"
BOOT_S = 8.0


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        port = int(s.getsockname()[1])
    if port in FORBIDDEN_PORTS:
        raise RuntimeError(f"kernel handed forbidden port {port}")
    return port


def rss_kib(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def recv_until(sock: socket.socket, needle: bytes, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if needle in buf:
            break
    return bytes(buf)


def raise_stack_limit() -> None:
    """Debug `LinuxServer.init` can need ~34 MiB of frame; the stock 8 MiB
    stack then SIGSEGVs at `initInPlace`. Raise the soft limit so a Debug
    `zig-out` image can still boot. ReleaseFast fits the default stack."""
    if resource is None:
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
    want = 64 * 1024 * 1024
    cap = hard if hard > 0 else want
    try:
        resource.setrlimit(resource.RLIMIT_STACK, (min(want, cap), hard))
    except (ValueError, OSError):
        pass


def wait_tcp(port: int, timeout: float, proc: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            probe = socket.create_connection((HOST, port), timeout=0.4)
            probe.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def connect(port: int, tls_mode: str, timeout: float) -> socket.socket:
    raw = socket.create_connection((HOST, port), timeout=timeout)
    if tls_mode == "off":
        return raw
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx.wrap_socket(raw, server_hostname="localhost")


def ktls_note(log: Path, tls_mode: str) -> str:
    if tls_mode != "ktls":
        return ""
    try:
        text = log.read_text(errors="replace")
    except OSError:
        return ""
    if "kTLS TX+RX offload ACTIVE" in text or "kTLS TX offload ACTIVE" in text:
        return "ktls-active"
    if "no TLS ULP" in text:
        return "ktls-fallback-userspace"
    return "ktls-unknown"


def register(sock: socket.socket, nick: str, timeout: float) -> None:
    sock.sendall(f"NICK {nick}\r\nUSER {nick} 0 * :bench\r\n".encode())
    welcome = recv_until(sock, b" 001 ", timeout)
    if b" 001 " not in welcome:
        raise RuntimeError(f"no 001 for {nick}: {welcome[:200]!r}")


def write_config(
    path: Path,
    *,
    irc_port: int,
    tls_port: int,
    tls_mode: str,
    shards: int,
    ring_entries: int,
    cqe_batch: int,
    sqpoll: bool,
) -> None:
    tls_block = ""
    if tls_mode != "off":
        ktls = "txrx" if tls_mode == "ktls" else "off"
        tls_block = (
            "[tls]\n"
            "enabled = true\n"
            f"port = {tls_port}\n"
            'dns_name = "localhost"\n'
            f'ktls = "{ktls}"\n'
        )
    path.write_text(
        "[node]\n"
        "id = 1\n"
        "[listen]\n"
        f'host = "{HOST}"\n'
        f"irc = {irc_port}\n"
        f"{tls_block}"
        "[limits]\n"
        f"num_shards = {shards}\n"
        "[io]\n"
        f"ring_entries = {ring_entries}\n"
        f"cqe_batch = {cqe_batch}\n"
        f"sqpoll = {'true' if sqpoll else 'false'}\n",
        encoding="utf-8",
    )


@dataclass
class CellResult:
    tls: str
    shards: int
    ring_entries: int
    cqe_batch: int
    sqpoll: bool
    register_ms: float | None
    join_ms: float | None
    privmsg_ms: float | None
    rss_idle_kib: int | None
    rss_loaded_kib: int | None
    clients: int
    note: str = ""
    error: str | None = None

    def rss_per_client(self) -> float | None:
        if (
            self.rss_idle_kib is None
            or self.rss_loaded_kib is None
            or self.clients <= 0
        ):
            return None
        return (self.rss_loaded_kib - self.rss_idle_kib) / self.clients


def run_cell(
    bin_path: Path,
    work: Path,
    cell: dict,
    *,
    clients: int,
    samples: int,
) -> CellResult:
    tls_mode = cell["tls"]
    sqpoll = bool(cell.get("sqpoll", False))
    irc_port = free_port()
    tls_port = free_port() if tls_mode != "off" else 0
    conf = work / (
        f"cell-{tls_mode}-s{cell['shards']}-sq{int(sqpoll)}-{cell['ring']}-{cell['cqe']}.toml"
    )
    log = conf.with_suffix(".log")
    write_config(
        conf,
        irc_port=irc_port,
        tls_port=tls_port,
        tls_mode=tls_mode,
        shards=cell["shards"],
        ring_entries=cell["ring"],
        cqe_batch=cell["cqe"],
        sqpoll=sqpoll,
    )
    check = subprocess.run(
        [str(bin_path), "--check-config", str(conf)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if check.returncode != 0:
        return CellResult(
            tls_mode,
            cell["shards"],
            cell["ring"],
            cell["cqe"],
            sqpoll,
            None,
            None,
            None,
            None,
            None,
            clients,
            error=f"check-config: {check.stderr or check.stdout}",
        )

    port = tls_port if tls_mode != "off" else irc_port
    with log.open("w", encoding="utf-8") as logf:
        proc = subprocess.Popen(
            [str(bin_path), str(conf)],
            stdout=logf,
            stderr=subprocess.STDOUT,
            cwd=str(work),
            preexec_fn=raise_stack_limit,
        )
    try:
        if proc.poll() is not None or not wait_tcp(port, BOOT_S, proc):
            tail = log.read_text(errors="replace")[-400:]
            why = "daemon exited at boot" if proc.poll() is not None else "listen timeout"
            return CellResult(
                tls_mode,
                cell["shards"],
                cell["ring"],
                cell["cqe"],
                sqpoll,
                None,
                None,
                None,
                None,
                None,
                clients,
                error=f"{why}: {tail}",
            )
        note = ktls_note(log, tls_mode)

        rss_idle = rss_kib(proc.pid)
        socks: list[socket.socket] = []
        register_samples: list[float] = []
        join_samples: list[float] = []
        try:
            for i in range(clients):
                t0 = time.perf_counter()
                s = connect(port, tls_mode, 3.0)
                register(s, f"b{i}", 4.0)
                register_samples.append((time.perf_counter() - t0) * 1000.0)
                t_join = time.perf_counter()
                s.sendall(f"JOIN {CHANNEL}\r\n".encode())
                joined = recv_until(s, b" 366 ", 4.0)
                if b" 366 " not in joined:
                    raise RuntimeError(f"no 366 for {i}: {joined[:200]!r}")
                join_samples.append((time.perf_counter() - t_join) * 1000.0)
                socks.append(s)
            rss_loaded = rss_kib(proc.pid)

            a, b = socks[0], socks[-1]
            privmsg_samples: list[float] = []
            for n in range(samples):
                token = f"p{n}-{time.time_ns()}"
                t0 = time.perf_counter()
                a.sendall(f"PRIVMSG {CHANNEL} :{token}\r\n".encode())
                seen = recv_until(b, token.encode(), 4.0)
                if token.encode() not in seen:
                    raise RuntimeError(f"PRIVMSG not delivered: {seen[:200]!r}")
                privmsg_samples.append((time.perf_counter() - t0) * 1000.0)
            return CellResult(
                tls_mode,
                cell["shards"],
                cell["ring"],
                cell["cqe"],
                sqpoll,
                statistics.median(register_samples),
                statistics.median(join_samples),
                statistics.median(privmsg_samples),
                rss_idle,
                rss_loaded,
                clients,
                note=note,
            )
        finally:
            for s in socks:
                try:
                    s.sendall(b"QUIT :bench\r\n")
                    s.close()
                except OSError:
                    pass
    except Exception as exc:  # noqa: BLE001 — cell failure is a measured outcome
        return CellResult(
            tls_mode,
            cell["shards"],
            cell["ring"],
            cell["cqe"],
            sqpoll,
            None,
            None,
            None,
            None,
            None,
            clients,
            note=ktls_note(log, tls_mode),
            error=str(exc),
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def fmt_ms(v: float | None) -> str:
    return "—" if v is None else f"{v:.2f}"


def fmt_rss(v: float | None) -> str:
    return "—" if v is None else f"{v:.1f}"


def provenance(bin_path: Path) -> list[str]:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root()),
            text=True,
            timeout=5,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    dirty = ""
    try:
        st = subprocess.run(
            ["git", "diff", "--quiet"],
            cwd=str(repo_root()),
            timeout=5,
        )
        if st.returncode != 0:
            dirty = " (dirty tree)"
    except (OSError, subprocess.CalledProcessError):
        pass
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    load = "unknown"
    try:
        load = " ".join(Path("/proc/loadavg").read_text(encoding="utf-8").split()[:3])
    except OSError:
        pass
    return [
        "## Provenance",
        "",
        "| field | value |",
        "| --- | --- |",
        f"| binary | `{bin_path}` |",
        f"| commit | `{commit}`{dirty} |",
        f"| captured | {time.strftime('%Y-%m-%dT%H:%M:%S%z')} |",
        f"| host | {os.uname().nodename} |",
        f"| kernel | {os.uname().sysname} {os.uname().release} |",
        f"| cpu | {cpu} |",
        f"| load avg at start | {load} |",
        "",
    ]


def render(
    results: list[CellResult],
    *,
    clients: int,
    samples: int,
    bin_path: Path,
    title: str,
    command: str,
) -> str:
    lines = [
        f"# {title}",
        "",
        "Every number in the table below was produced by this command and no other:",
        "",
        "```sh",
        command,
        "```",
        "",
        "Throwaway `onyx-server` on 127.0.0.1, kernel-assigned ports, "
        "`--check-config` before each boot. Not a production service unit.",
        "",
        f"clients={clients}  privmsg_samples={samples}",
        "",
        "JOIN p50 is the median time from `JOIN` to numeric 366. PRIVMSG p50 is",
        "the median time from `PRIVMSG` on the first client until the last client",
        "receives that token. RSS idle is before any client; RSS loaded is after",
        "every client has joined.",
        "",
    ]
    lines.extend(provenance(bin_path))
    lines.extend(
        [
            "| sqpoll | tls | shards | ring×cqe | register p50 ms | JOIN p50 ms | PRIVMSG p50 ms | RSS idle KiB | RSS loaded KiB | RSS/client KiB | note | error |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for r in results:
        io = f"{r.ring_entries}×{r.cqe_batch}"
        err = (r.error or "").replace("\n", " ")[:120]
        loaded = "—" if r.rss_loaded_kib is None else str(r.rss_loaded_kib)
        idle = "—" if r.rss_idle_kib is None else str(r.rss_idle_kib)
        lines.append(
            f"| {str(r.sqpoll).lower()} | {r.tls} | {r.shards} | {io} | {fmt_ms(r.register_ms)} | "
            f"{fmt_ms(r.join_ms)} | {fmt_ms(r.privmsg_ms)} | {idle} | {loaded} | "
            f"{fmt_rss(r.rss_per_client())} | {r.note} | {err} |"
        )
    lines.extend(
        [
            "",
            "RSS/client is (loaded − idle) / N after JOIN. A small or negative",
            "delta means the idle image already dwarfs N clients — do not treat",
            "it as a per-conn floor. A blank timing with an error is an unmeasured",
            "cell, not a zero. TLS `userspace` sets `ktls = \"off\"`. The kTLS",
            "`txrx` cell, when present, is configured intent only; the note says",
            "whether the kernel attached ULP. `[io] sqpoll` is set without",
            "`defer_taskrun`.",
            "",
            "This command writes the Linux rows only. A later run keeps an",
            "existing `## FreeBSD` section in the output file. SQPOLL is Linux",
            "io_uring, and the portable reactor does not serve a TLS listener.",
            "",
        ]
    )
    return "\n".join(lines)


def keep_freebsd_section(path: Path, text: str) -> str:
    """Keep a hand-measured FreeBSD section when this Linux command rewrites the file."""
    if not path.is_file():
        return text
    old = path.read_text(encoding="utf-8")
    marker = "\n## FreeBSD"
    at = old.find(marker)
    if at < 0:
        return text
    return text.rstrip() + "\n" + old[at + 1 :]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--bin",
        default=str(repo_root() / "zig-out" / "bin" / "onyx-server"),
        help="onyx-server binary",
    )
    p.add_argument("-o", "--out", help="write the markdown table here")
    p.add_argument(
        "--quick",
        action="store_true",
        help="one plaintext cell (smoke, not a baseline)",
    )
    p.add_argument("--clients", type=int, default=0)
    p.add_argument("--samples", type=int, default=0)
    p.add_argument(
        "--gap-x4",
        action="store_true",
        help="GAP-X4 matrix: SQPOLL on/off × TLS off/userspace × shards 1 and 4",
    )
    p.add_argument("--sqpoll-phases", action="store_true", help="retained pinned-TLS one-shard delivery/CPU profile")
    p.add_argument("--phase-json")
    p.add_argument("--expected-sha256")
    p.add_argument("--phase-pilot", action="store_true", help="small correctness pilot; never a performance baseline")
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--sqpoll-modes", type=int, nargs="+", default=[0, 10, 1000])
    return p.parse_args()


def main() -> int:
    args = parse_args()
    bin_path = Path(args.bin).resolve()
    if not bin_path.is_file():
        print(f"bench_live: binary not found: {bin_path} (run zig build first)", file=sys.stderr)
        return 2

    if args.sqpoll_phases:
        if args.quick or args.gap_x4:
            raise PhaseFailure("retained phases and legacy benchmark matrices are separate profiles")
        return run_phase_matrix(args, bin_path)
    if args.phase_pilot or args.phase_json or args.expected_sha256:
        raise PhaseFailure("phase options require --sqpoll-phases")

    if args.quick and args.gap_x4:
        print("bench_live: --quick and --gap-x4 are different matrices", file=sys.stderr)
        return 2
    if args.gap_x4:
        cells = []
        for sqpoll in (False, True):
            for tls_mode in ("off", "userspace"):
                for shards in (1, 4):
                    cells.append(
                        {
                            "tls": tls_mode,
                            "shards": shards,
                            "ring": 32,
                            "cqe": 256,
                            "sqpoll": sqpoll,
                        }
                    )
        clients = args.clients or 4
        samples = args.samples or 16
        title = "GAP-X4 Linux live bench"
        command = "zig build bench-live -- --gap-x4 -o docs/audit/bench-gap-x4.md"
    elif args.quick:
        cells = [{"tls": "off", "shards": 1, "ring": 32, "cqe": 256, "sqpoll": False}]
        clients = args.clients or 4
        samples = args.samples or 8
        title = "Live-daemon bench — one plaintext cell"
        command = "zig build bench-live -- --quick"
    else:
        cells = [
            {"tls": "off", "shards": 1, "ring": 32, "cqe": 256, "sqpoll": False},
            {"tls": "off", "shards": 2, "ring": 32, "cqe": 256, "sqpoll": False},
            {"tls": "off", "shards": 1, "ring": 128, "cqe": 256, "sqpoll": False},
            {"tls": "off", "shards": 1, "ring": 32, "cqe": 512, "sqpoll": False},
            {"tls": "userspace", "shards": 1, "ring": 32, "cqe": 256, "sqpoll": False},
            {"tls": "ktls", "shards": 1, "ring": 32, "cqe": 256, "sqpoll": False},
        ]
        clients = args.clients or 8
        samples = args.samples or 16
        title = "Live-daemon bench — P0-1 remaining axes"
        command = "zig build bench-live"

    results: list[CellResult] = []
    with tempfile.TemporaryDirectory(prefix="onyx-bench-live-") as tmp:
        work = Path(tmp)
        for cell in cells:
            results.append(
                run_cell(bin_path, work, cell, clients=clients, samples=samples)
            )

    text = render(
        results,
        clients=clients,
        samples=samples,
        bin_path=bin_path,
        title=title,
        command=command,
    )
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        text = keep_freebsd_section(out, text)
        out.write_text(text, encoding="utf-8")
        print(f"bench_live: wrote {out}", file=sys.stderr)

    if args.gap_x4:
        if any(r.error for r in results):
            return 1
        return 0
    required = [r for r in results if r.tls == "off"]
    if any(r.error for r in required):
        return 1
    return 0



# Retained SQPOLL daemon profile. No service, installed configuration or build is changed.
class PhaseFailure(RuntimeError):
    pass


class LineFramer:
    def __init__(self):
        self.pending = b""

    def feed(self, chunk):
        self.pending += chunk
        if len(self.pending) > 65536:
            raise PhaseFailure("receive buffer exceeded bound")
        lines = self.pending.split(b"\r\n")
        self.pending = lines.pop()
        if any(len(line) > 16384 for line in lines) or len(self.pending) > 16384:
            raise PhaseFailure("IRC line exceeded bound")
        return lines


def pinned_context(cert_der):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert_der))
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise PhaseFailure("TLS verification is not mandatory")
    return context


def phase_tls_observation(index, writer):
    """Record negotiated public parameters, never certificate or key material."""
    tls = writer.get_extra_info("ssl_object")
    cipher = tls.cipher() if tls is not None else None
    return dict(client=index, version=tls.version() if tls is not None else None,
                cipher=cipher[0] if cipher else None)


def phase_tls_summary(observations, expected_clients=4):
    def summarize(key):
        values = [item[key] for item in observations]
        known = sorted({value for value in values if value is not None})
        unknown = expected_clients - len(observations) + values.count(None)
        status = "unknown" if not known else "mixed" if len(known) > 1 else "partial" if unknown else "uniform"
        return dict(status=status, values=known, unknown_clients=unknown)
    return dict(clients=observations, version=summarize("version"), cipher=summarize("cipher"))


def phase_latency_percentiles(latencies):
    from bench_sqpoll import percentile
    return dict(latency_p50_ns=percentile(latencies, .5),
                latency_p95_ns=percentile(latencies, .95),
                latency_p99_ns=percentile(latencies, .99))


def phase_payload(run_id, phase, sender, sequence):
    return f"onyxbench:{run_id}:{phase}:{sender}:{sequence}:".encode().ljust(128, b"x")


class DeliveryLedger:
    def __init__(self, run_id, clients=4):
        self.run_id, self.clients = run_id, clients
        self.counts, self.next, self.sent, self.received = {}, {}, {}, {}
        self.latencies = {}
        self.changed = asyncio.Event()

    def add_phase(self, phase, count):
        if phase in self.counts:
            raise PhaseFailure("phase registered twice")
        self.counts[phase], self.received[phase], self.latencies[phase] = count, 0, []
        for sender in range(self.clients):
            for recipient in range(self.clients):
                if sender != recipient:
                    self.next[phase, sender, recipient] = 0

    def authored(self, phase, sender, sequence):
        key = phase, sender, sequence
        if key in self.sent:
            raise PhaseFailure("sender sequence reused")
        self.sent[key] = time.monotonic_ns()

    def receive(self, recipient, line):
        # Parse complete lines, never substring receipts. Tags are legal but do
        # not change the prefix, target, or exact payload identity.
        if line.startswith(b"@"):
            _, _, line = line.partition(b" ")
        parts = line.split(b" ", 3)
        command = parts[1] if line.startswith(b":") and len(parts) > 1 else parts[0]
        if command.upper() != b"PRIVMSG":
            return False
        if not line.startswith(b":") or len(parts) != 4 or parts[2] != CHANNEL.encode() or not parts[3].startswith(b":"):
            raise PhaseFailure("unexpected PRIVMSG target/framing")
        payload = parts[3][1:]
        try:
            magic, run_id, phase_raw, sender_raw, sequence_raw, _ = payload.split(b":", 5)
            phase, sender, sequence = phase_raw.decode("ascii"), int(sender_raw), int(sequence_raw)
        except (ValueError, UnicodeError) as exc:
            raise PhaseFailure("malformed message identity") from exc
        if magic != b"onyxbench" or run_id != self.run_id.encode() or phase not in self.counts:
            raise PhaseFailure("unknown run or phase")
        if not 0 <= sender < self.clients or sender == recipient or not 0 <= sequence < self.counts[phase]:
            raise PhaseFailure("unexpected sender/recipient/sequence")
        if parts[0].split(b"!", 1)[0] != f":lb{sender}".encode():
            raise PhaseFailure("prefix does not match sender identity")
        if payload != phase_payload(self.run_id, phase, sender, sequence):
            raise PhaseFailure("payload changed")
        key = phase, sender, recipient
        if sequence != self.next[key]:
            raise PhaseFailure("duplicate or reordered delivery")
        stamp = self.sent.get((phase, sender, sequence))
        if stamp is None:
            raise PhaseFailure("delivery was not authored")
        self.next[key] += 1
        self.received[phase] += 1
        self.latencies[phase].append(time.monotonic_ns() - stamp)
        self.changed.set()
        return True

    def complete(self, phase):
        return self.received[phase] == self.counts[phase] * self.clients * (self.clients - 1)

    def credit(self, phase, sender, sequence, window):
        return all(self.next[phase, sender, recipient] > sequence - window
                   for recipient in range(self.clients) if recipient != sender)


class PhaseClient:
    def __init__(self, index, reader, writer, ledger, failure):
        self.index, self.reader, self.writer = index, reader, writer
        self.ledger, self.failure = ledger, failure
        self.welcome, self.joined = asyncio.Event(), asyncio.Event()
        self.pending_pongs, self.lines_sent = {}, 0
        self.framer = LineFramer()
        self.task = asyncio.create_task(self.read())

    async def send(self, line):
        if b"\r" in line or b"\n" in line or len(line) > 510:
            raise PhaseFailure("invalid outgoing IRC line")
        self.writer.write(line + b"\r\n")
        self.lines_sent += 1
        await self.writer.drain()

    async def read(self):
        try:
            while True:
                chunk = await self.reader.read(32768)
                if not chunk:
                    raise PhaseFailure("persistent client disconnected")
                for line in self.framer.feed(chunk):
                    if line.split(b" ", 1)[0].upper() == b"PING":
                        if b" " not in line:
                            raise PhaseFailure("malformed PING")
                        await self.send(b"PONG " + line.split(b" ", 1)[1])
                        continue
                    fields = line.split(b" ")
                    command = (fields[1] if line.startswith(b":") and len(fields) > 1 else fields[0]).upper()
                    if command == b"ERROR" or (command.isdigit() and int(command) >= 400 and command != b"422"):
                        raise PhaseFailure("daemon returned protocol error")
                    if command == b"001":
                        self.welcome.set()
                    elif command == b"366" and CHANNEL.encode() in fields:
                        self.joined.set()
                    elif command == b"PONG":
                        marker = line.rsplit(b" :", 1)[-1]
                        future = self.pending_pongs.pop(marker, None)
                        if future is None or future.done():
                            raise PhaseFailure("unexpected or duplicated PONG barrier")
                        future.set_result(None)
                    else:
                        self.ledger.receive(self.index, line)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not self.failure.done():
                self.failure.set_result(exc)

    async def barrier(self, marker):
        if marker in self.pending_pongs:
            raise PhaseFailure("barrier reused")
        future = asyncio.get_running_loop().create_future()
        self.pending_pongs[marker] = future
        await self.send(b"PING :" + marker)
        await future


async def phase_checked(awaitable, failure, timeout=30):
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait([task, failure], timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if failure in done:
            raise failure.result()
        if task not in done:
            raise PhaseFailure("phase deadline expired")
        return await task
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def phase_wait(ledger, condition):
    while not condition():
        ledger.changed.clear()
        if condition():
            return
        await ledger.changed.wait()


def phase_metrics(port, target):
    import urllib.request
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
            lines = response.read(1 << 20).decode().splitlines()
        values = {parts[0]: int(parts[1]) for line in lines if not line.startswith("#")
                  and len(parts := line.split()) == 2 and parts[0] in
                  {"onyx_messages_in_total", "onyx_bytes_in_total", "onyx_bytes_out_total", "onyx_connections_active", "onyx_errors_total"}}
        if values.get("onyx_messages_in_total", -1) >= target and values.get("onyx_connections_active") == 4:
            return values
        time.sleep(.05)
    raise PhaseFailure("metrics did not reach a fresh four-client snapshot")


def phase_cpu_snapshot(pid, mode, known=None):
    from bench_sqpoll import snapshot
    values = snapshot(pid, mode, 1, known=known)
    workers = [v for v in values.values() if v["name"].startswith("iou-sqp-")]
    expected = 1 if mode else 0
    if len(workers) != expected or any(v["name"] != f"iou-sqp-{pid}" for v in workers):
        raise PhaseFailure("SQPOLL mode does not match observed worker custody")
    return values


def phase_verify_cpu_discovery(pid, mode, timed):
    # A cached end snapshot deliberately avoids a global /proc scan in the CPU
    # window. Rediscover afterward: an external SQ worker created mid-phase
    # would otherwise be absent from both cached task dictionaries.
    fresh = phase_cpu_snapshot(pid, mode)
    if fresh.keys() != timed.keys() or any(
            (fresh[t]["starttime"], fresh[t]["name"]) != (timed[t]["starttime"], timed[t]["name"])
            for t in timed):
        raise PhaseFailure("fresh discovery changed CPU task custody")


async def measure_daemon_phases(proc, port, metrics_port, context, hostname, mode, pilot, run_id, tls_observations=None, failure_diagnostic=None):
    failure = asyncio.get_running_loop().create_future()
    ledger = DeliveryLedger(run_id)
    clients = []
    progress = dict(phase="registration", checkpoint="connect", client=0, completed=[])
    try:
        for index in range(4):
            progress.update(checkpoint="connect", client=index)
            # Verification failure propagates; there is no insecure/plain retry.
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                HOST, port, ssl=context, server_hostname=hostname, ssl_handshake_timeout=5), 6)
            client = PhaseClient(index, reader, writer, ledger, failure)
            clients.append(client)
            if tls_observations is not None:
                tls_observations.append(phase_tls_observation(index, writer))
            await client.send(f"NICK lb{index}".encode())
            await client.send(f"USER lb{index} 0 * :retained benchmark".encode())
            progress["checkpoint"] = "welcome"
            await phase_checked(client.welcome.wait(), failure, 8)
            await client.send(f"JOIN {CHANNEL}".encode())
            progress["checkpoint"] = "join"
            await phase_checked(client.joined.wait(), failure, 8)
        async def barriers(phase):
            progress["checkpoint"] = "barriers"
            await phase_checked(asyncio.gather(*(c.barrier(f"{run_id}-{phase}-{c.index}".encode()) for c in clients)), failure, 10)
        async def send_messages(phase, sender, count):
            for sequence in range(count):
                await phase_wait(ledger, lambda: ledger.credit(phase, sender, sequence, 64))
                ledger.authored(phase, sender, sequence)
                await clients[sender].send(b"PRIVMSG " + CHANNEL.encode() + b" :" + phase_payload(run_id, phase, sender, sequence))
        async def finish(phase):
            progress["checkpoint"] = "delivery_drain"
            await phase_wait(ledger, lambda: ledger.complete(phase))
            await barriers(phase)
        progress.update(phase="warmup", checkpoint="send")
        ledger.add_phase("warmup", 8)
        await phase_checked(asyncio.gather(*(send_messages("warmup", i, 8) for i in range(4))), failure)
        await phase_checked(finish("warmup"), failure)
        progress["checkpoint"] = "metrics"
        metrics_before = await asyncio.to_thread(phase_metrics, metrics_port, sum(c.lines_sent for c in clients))
        results = []
        for phase in ("idle", "burst", "continuous"):
            progress.update(phase=phase, checkpoint="cpu_start")
            count = 0 if phase == "idle" else (2 if pilot else 320) if phase == "burst" else (16 if pilot else 16384)
            ledger.add_phase(phase, count)
            before = phase_cpu_snapshot(proc.pid, mode)
            driver_begin, begin = time.process_time_ns(), time.monotonic_ns()
            async def work():
                if phase == "idle":
                    await asyncio.sleep(1 if pilot else 10)
                elif phase == "burst":
                    ticks, width = (2, 1) if pilot else (40, 8)
                    start = asyncio.get_running_loop().time()
                    for tick in range(ticks):
                        await asyncio.sleep(max(0, start + tick * .25 - asyncio.get_running_loop().time()))
                        for sender in range(4):
                            for offset in range(width):
                                sequence = tick * width + offset
                                ledger.authored(phase, sender, sequence)
                                await clients[sender].send(b"PRIVMSG " + CHANNEL.encode() + b" :" + phase_payload(run_id, phase, sender, sequence))
                    await asyncio.sleep(max(0, start + ticks * .25 - asyncio.get_running_loop().time()))
                else:
                    await asyncio.gather(*(send_messages(phase, i, count) for i in range(4)))
                await finish(phase)
            progress["checkpoint"] = "phase_work"
            await phase_checked(work(), failure, 120)
            progress["checkpoint"] = "cpu_end"
            after = phase_cpu_snapshot(proc.pid, mode, known=before)
            elapsed, driver_cpu = time.monotonic_ns() - begin, time.process_time_ns() - driver_begin
            if before.keys() != after.keys() or any(before[t]["starttime"] != after[t]["starttime"] or before[t]["name"] != after[t]["name"] or after[t]["ticks"] < before[t]["ticks"] for t in before):
                raise PhaseFailure("daemon CPU task coverage changed")
            # This discovery is outside both daemon and driver CPU windows.
            phase_verify_cpu_discovery(proc.pid, mode, after)
            tasks = [dict(tid=t, name=after[t]["name"], ticks=after[t]["ticks"] - before[t]["ticks"]) for t in before]
            hz = os.sysconf("SC_CLK_TCK")
            cpu = sum(t["ticks"] for t in tasks) / hz
            sq_cpu = sum(t["ticks"] for t in tasks if t["name"] == f"iou-sqp-{proc.pid}") / hz
            current = await asyncio.to_thread(phase_metrics, metrics_port, sum(c.lines_sent for c in clients))
            delivered = ledger.received[phase]
            results.append(dict(phase=phase, authored=4 * count, delivered=delivered, expected_delivered=12 * count,
                                elapsed_ns=elapsed, daemon_cpu_s=cpu, sq_cpu_s=sq_cpu, driver_cpu_ns=driver_cpu,
                                core_equivalents=cpu / (elapsed / 1e9), delivered_per_s=delivered / (elapsed / 1e9),
                                cpu_ns_per_delivery=cpu * 1e9 / delivered if delivered else None,
                                **phase_latency_percentiles(ledger.latencies[phase]),
                                cpu_clock_tick_s=1 / hz, cpu_tasks=tasks, cpu_discovery_verified=True,
                                protocol_lines_delta=current["onyx_messages_in_total"] - metrics_before["onyx_messages_in_total"],
                                queued_bytes_delta=current["onyx_bytes_out_total"] - metrics_before["onyx_bytes_out_total"]))
            metrics_before = current
            progress["completed"].append(phase)
        progress.update(phase="final", checkpoint="barriers")
        await barriers("final")
        await phase_checked(asyncio.sleep(.25), failure)
        if failure.done() or proc.poll() is not None:
            raise PhaseFailure("late delivery/connection failure")
        if any(c.framer.pending or c.pending_pongs for c in clients):
            raise PhaseFailure("incomplete line or unresolved barrier at final drain")
        return results
    except Exception:
        if failure_diagnostic is not None:
            active = progress["phase"]
            total = ledger.counts.get(active)
            positions = [position for (name, _, _), position in ledger.next.items() if name == active]
            failure_diagnostic.update(
                phase=active, checkpoint=progress["checkpoint"], client_index=progress["client"],
                completed=list(progress["completed"]), clients_created=len(clients),
                welcomed=sum(c.welcome.is_set() for c in clients), joined=sum(c.joined.is_set() for c in clients),
                authored=sum(1 for (name, _, _) in ledger.sent if name == active),
                expected_authored=None if total is None else total * ledger.clients,
                received=ledger.received.get(active),
                expected_received=None if total is None else total * ledger.clients * (ledger.clients - 1),
                streams=len(positions), stream_min=min(positions) if positions else None,
                stream_max=max(positions) if positions else None,
                pending_barriers=sum(len(c.pending_pongs) for c in clients),
                reader_tasks_done=sum(c.task.done() for c in clients),
                read_failure_signaled=failure.done())
        raise
    finally:
        for client in clients:
            client.task.cancel()
        await asyncio.gather(*(c.task for c in clients), return_exceptions=True)
        for client in clients:
            client.writer.close()
        await asyncio.gather(*(c.writer.wait_closed() for c in clients), return_exceptions=True)


def phase_config(base, mode, metrics_port):
    # Only generated fixture templates are changed. Refuse ambiguous sections.
    if base.count("[limits]\n") != 1 or any(section in base for section in ("[io]", "[metrics]", "[stats]", "[class.")):
        raise PhaseFailure("generated bundle shape changed")
    if base.count("[tls]\n") != 1 or "ktls =" in base:
        raise PhaseFailure("generated TLS template shape changed")
    base = base.replace("[tls]\n", '[tls]\nktls = "off"\n', 1)
    return base.replace("[limits]\n", '[limits]\nnum_shards = 1\nsweep_interval = "2s"\n', 1) + (
        f"\n[io]\nring_entries = 512\ncqe_batch = 256\nsqpoll = {'true' if mode else 'false'}\nsqpoll_idle_ms = {mode or 10}\n"
        f'[metrics]\nlisten = {metrics_port}\nbind = "127.0.0.1"\n[stats]\ninterval = "1s"\n'
        '[class.benchmark]\nmatch = ["127.0.0.1/32"]\nsendq = "1M"\nrecvq = "16K"\nflood_exempt = true\n')


def run_phase_matrix(args, binary):
    import hashlib, json, platform
    from alpine_runtime_smoke import stop
    import setup_review_client
    artifact = hashlib.sha256(binary.read_bytes()).hexdigest()
    if not args.expected_sha256 or artifact != args.expected_sha256:
        raise PhaseFailure("explicit captured artifact SHA-256 mismatch")
    if not args.phase_json or args.repetitions < 1 or not args.sqpoll_modes or len(set(args.sqpoll_modes)) != len(args.sqpoll_modes) or any(m not in (0, 10, 1000) for m in args.sqpoll_modes):
        raise PhaseFailure("phase JSON, positive repetitions and valid modes required")
    scratch = repo_root() / ".zig-cache/wave-6/live-benchmark"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = dict(profile="one-shard-pinned-TLS", pilot=args.phase_pilot, artifact_sha256=artifact,
                  kernel=platform.release(), driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  review_helper_sha256=hashlib.sha256(Path(setup_review_client.__file__).read_bytes()).hexdigest(),
                  fixed=dict(clients=4, shards=1, ring=512, cqe=256, payload_bytes=128, window=64,
                             sweep_ms=2000, stats_ms=1000, tls="TLS1.3", ktls="off"), records=[])
    output = Path(args.phase_json)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phases-", dir=scratch) as temporary:
        work = Path(temporary)
        ports = [free_port() for _ in range(3)]
        if len(set(ports)) != 3:
            raise PhaseFailure("fixture ports collided")
        irc, tls, metrics = ports
        hostname, bundle = "benchmark.example.test", work / "bundle"
        def verify_review(stage, review):
            # The controller sees the real stage before its ID-bound publish
            # acknowledgement. Check the public certificate itself, not only
            # the asserted metadata; never render its private companion.
            if review["certificate_subject"] != hostname or review["bootstrap_account"] is not None:
                raise PhaseFailure("unexpected staged identity")
            cert_pem = ssl.DER_cert_to_PEM_cert((stage / "tls-cert.der").read_bytes())
            with tempfile.NamedTemporaryFile(mode="w", dir=work, encoding="ascii") as cert_file:
                cert_file.write(cert_pem)
                cert_file.flush()
                cert = ssl._ssl._test_decode_cert(cert_file.name)
            if ("DNS", hostname) not in cert.get("subjectAltName", ()):
                raise PhaseFailure("staged certificate hostname mismatch")
            if int(ssl.cert_time_to_seconds(cert["notAfter"])) != review["certificate_expires_unix"]:
                raise PhaseFailure("staged certificate expiry mismatch")

        try:
            made, review, _ = setup_review_client.run_review(
                [str(binary), "setup", "--new", "--hostname", hostname, "--listen", HOST,
                 "--irc-port", str(irc), "--tls-port", str(tls), "--bundle", str(bundle), "--json"],
                cwd=work, mutate=verify_review)
        except Exception:
            raise PhaseFailure("private bundle review failed") from None
        if made.returncode != 0 or review is None:
            raise PhaseFailure("private bundle provisioning failed")
        base = (bundle / "onyx-server.toml").read_text()
        credentials = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in bundle.iterdir() if p.is_file()}
        context = pinned_context((bundle / "tls-cert.der").read_bytes())
        for repetition in range(args.repetitions):
            modes = args.sqpoll_modes if repetition % 2 == 0 else list(reversed(args.sqpoll_modes))
            for mode in modes:
                cell = work / f"r{repetition}-m{mode}"
                cell.mkdir(mode=0o700)
                conf = bundle / f"cell-r{repetition}-m{mode}.toml"
                conf.write_text(phase_config(base, mode, metrics))
                conf.chmod(0o600)
                checked = subprocess.run([str(binary), "--check-config", str(conf)], cwd=cell, capture_output=True, timeout=15)
                if checked.returncode != 0:
                    raise PhaseFailure("private phase configuration rejected")
                process = None
                tls_observations = []
                failure_diagnostic = {}
                record = dict(mode=mode, repetition=repetition, load_before=os.getloadavg())
                try:
                    with (cell / "daemon.log").open("wb") as log:
                        process = subprocess.Popen([str(binary), str(conf)], cwd=cell, stdout=log,
                                                   stderr=subprocess.STDOUT, preexec_fn=raise_stack_limit,
                                                   start_new_session=True)
                        if not wait_tcp(irc, BOOT_S, process):
                            raise PhaseFailure("private listener failed startup")
                        record["phases"] = asyncio.run(measure_daemon_phases(process, tls, metrics, context, hostname,
                                                                            mode, args.phase_pilot, f"{repetition:04d}", tls_observations, failure_diagnostic))
                        record["status"] = "ok"
                except Exception as exc:
                    record.update(status="failed", reason=str(exc))
                    if failure_diagnostic:
                        record["diagnostic"] = failure_diagnostic
                finally:
                    if process is not None:
                        stop(process)
                record["tls_observations"] = phase_tls_summary(tls_observations)
                record["load_after"] = os.getloadavg()
                report["records"].append(record)
                output.write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps(record), flush=True)
                if record["status"] != "ok":
                    break
            if any(r["status"] != "ok" for r in report["records"]):
                break
        if artifact != hashlib.sha256(binary.read_bytes()).hexdigest() or any(hashlib.sha256(p.read_bytes()).hexdigest() != expected for p, expected in credentials.items()):
            raise PhaseFailure("captured artifact or private credentials changed")
    report["status"] = "ok" if len(report["records"]) == args.repetitions * len(args.sqpoll_modes) and all(r["status"] == "ok" for r in report["records"]) else "failed"
    output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
