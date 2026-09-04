#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Live-daemon measurement harness for the 0.7 P0-1 axes the offline
`zig build bench` harness cannot see: TLS mode (off / userspace / kTLS
intent), `num_shards`, and `ring_entries` × `cqe_batch`, plus JOIN/PRIVMSG
round-trip and RSS after N registered clients.

Boots a throwaway `onyx-server` on 127.0.0.1 with kernel-assigned ports. Never
binds 6667/6680/6697 and never touches `orochi.service`. `--check-config` runs
before every boot so a bad cell cannot fall through to the daemon defaults.

Usage:
  python3 tools/bench_live.py --bin zig-out/bin/onyx-server --quick
  python3 tools/bench_live.py --bin zig-out/bin/onyx-server -o docs/audit/bench-live-0.7.0-rc.1.md
"""

from __future__ import annotations

import argparse
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
        f"cqe_batch = {cqe_batch}\n",
        encoding="utf-8",
    )


@dataclass
class CellResult:
    tls: str
    shards: int
    ring_entries: int
    cqe_batch: int
    register_ms: float | None
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
    irc_port = free_port()
    tls_port = free_port() if tls_mode != "off" else 0
    conf = work / f"cell-{tls_mode}-{cell['shards']}-{cell['ring']}-{cell['cqe']}.toml"
    log = conf.with_suffix(".log")
    write_config(
        conf,
        irc_port=irc_port,
        tls_port=tls_port,
        tls_mode=tls_mode,
        shards=cell["shards"],
        ring_entries=cell["ring"],
        cqe_batch=cell["cqe"],
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
        try:
            for i in range(clients):
                t0 = time.perf_counter()
                s = connect(port, tls_mode, 3.0)
                register(s, f"b{i}", 4.0)
                register_samples.append((time.perf_counter() - t0) * 1000.0)
                s.sendall(f"JOIN {CHANNEL}\r\n".encode())
                recv_until(s, b" 366 ", 4.0)
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
                statistics.median(register_samples),
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
) -> str:
    lines = [
        "# Live-daemon bench — P0-1 remaining axes",
        "",
        "Throwaway `onyx-server` on 127.0.0.1, kernel-assigned ports, "
        "`--check-config` before each boot. Not `orochi.service`.",
        "",
        f"clients={clients}  privmsg_samples={samples}",
        "",
    ]
    lines.extend(provenance(bin_path))
    lines.extend(
        [
        "| tls | shards | ring×cqe | register p50 ms | PRIVMSG p50 ms | RSS idle KiB | RSS/client KiB | note | error |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for r in results:
        io = f"{r.ring_entries}×{r.cqe_batch}"
        err = (r.error or "").replace("\n", " ")[:80]
        lines.append(
            f"| {r.tls} | {r.shards} | {io} | {fmt_ms(r.register_ms)} | "
            f"{fmt_ms(r.privmsg_ms)} | {r.rss_idle_kib or '—'} | "
            f"{fmt_rss(r.rss_per_client())} | {r.note} | {err} |"
        )
    lines.extend(
        [
            "",
            "RSS/client is (loaded − idle) / N after JOIN. A small or negative",
            "delta means the idle image already dwarfs N clients — do not treat",
            "it as a per-conn floor. kTLS is the configured intent (`txrx`);",
            "the kernel may keep the path in userspace if ULP is absent.",
            "",
        ]
    )
    return "\n".join(lines)


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
    return p.parse_args()


def main() -> int:
    args = parse_args()
    bin_path = Path(args.bin).resolve()
    if not bin_path.is_file():
        print(f"bench_live: binary not found: {bin_path} (run zig build first)", file=sys.stderr)
        return 2

    if args.quick:
        cells = [{"tls": "off", "shards": 1, "ring": 32, "cqe": 256}]
        clients = args.clients or 4
        samples = args.samples or 8
    else:
        cells = [
            {"tls": "off", "shards": 1, "ring": 32, "cqe": 256},
            {"tls": "off", "shards": 2, "ring": 32, "cqe": 256},
            {"tls": "off", "shards": 1, "ring": 128, "cqe": 256},
            {"tls": "off", "shards": 1, "ring": 32, "cqe": 512},
            {"tls": "userspace", "shards": 1, "ring": 32, "cqe": 256},
            {"tls": "ktls", "shards": 1, "ring": 32, "cqe": 256},
        ]
        clients = args.clients or 8
        samples = args.samples or 16

    results: list[CellResult] = []
    with tempfile.TemporaryDirectory(prefix="onyx-bench-live-") as tmp:
        work = Path(tmp)
        for cell in cells:
            results.append(
                run_cell(bin_path, work, cell, clients=clients, samples=samples)
            )

    text = render(results, clients=clients, samples=samples, bin_path=bin_path)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"bench_live: wrote {out}", file=sys.stderr)

    required = [r for r in results if r.tls == "off"]
    if any(r.error for r in required):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
