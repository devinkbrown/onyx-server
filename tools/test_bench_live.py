#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline tests for retained daemon benchmark custody and exact receipts."""
import asyncio
import ssl
import tempfile
import tomllib
from pathlib import Path
import unittest
from unittest import mock

import bench_live as bench


class FramingTests(unittest.TestCase):
    def test_chunk_boundaries_and_retained_tail(self):
        frame = bench.LineFramer()
        self.assertEqual([], frame.feed(b"first\r"))
        self.assertEqual([b"first", b"second"], frame.feed(b"\nsecond\r\nthird"))
        self.assertEqual([b"third"], frame.feed(b"\r\n"))
        self.assertEqual(b"", frame.pending)

    def test_unterminated_and_complete_line_bounds(self):
        for data in (b"x" * 16385, b"x" * 16385 + b"\r\n", b"x" * 65537):
            with self.subTest(length=len(data)):
                with self.assertRaises(bench.PhaseFailure):
                    bench.LineFramer().feed(data)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = bench.DeliveryLedger("0000")
        self.ledger.add_phase("burst", 2)

    def line(self, sender, sequence, phase="burst"):
        return f":lb{sender}!user@host PRIVMSG #bench :".encode() + bench.phase_payload("0000", phase, sender, sequence)

    def author(self, sender, sequence, phase="burst"):
        self.ledger.authored(phase, sender, sequence)

    def test_all_senders_and_recipients_exact_and_ordered(self):
        for sequence in range(2):
            for sender in range(4):
                self.author(sender, sequence)
                for recipient in range(4):
                    if sender != recipient:
                        self.assertTrue(self.ledger.receive(recipient, self.line(sender, sequence)))
        self.assertTrue(self.ledger.complete("burst"))
        self.assertEqual(24, self.ledger.received["burst"])
        self.assertEqual(24, len(self.ledger.latencies["burst"]))

    def test_late_lowercase_or_mixed_case_duplicate_after_complete_rejected(self):
        for sequence in range(2):
            for sender in range(4):
                self.author(sender, sequence)
                for recipient in range(4):
                    if sender != recipient:
                        self.ledger.receive(recipient, self.line(sender, sequence))
        self.assertTrue(self.ledger.complete("burst"))
        self.ledger.add_phase("continuous", 1)
        for spelling in (b"privmsg", b"pRiVmSg"):
            with self.subTest(command=spelling):
                with self.assertRaises(bench.PhaseFailure):
                    self.ledger.receive(1, self.line(0, 0).replace(b"PRIVMSG", spelling))

    def test_valid_case_insensitive_command_and_malformed_message_frames(self):
        self.author(0, 0)
        self.assertTrue(self.ledger.receive(1, self.line(0, 0).replace(b"PRIVMSG", b"pRiVmSg")))
        for line in (b":lb0!u@h privmsg", b":lb0!u@h PrIvMsG #bench",
                     b"privmsg #bench :payload", b":lb0!u@h PRIVMSG #bench payload"):
            with self.subTest(line=line):
                with self.assertRaises(bench.PhaseFailure):
                    self.ledger.receive(2, line)

    def test_missing_recipient_is_not_complete(self):
        for sender in range(4):
            for sequence in range(2):
                self.author(sender, sequence)
                for recipient in range(3):
                    if sender != recipient:
                        self.ledger.receive(recipient, self.line(sender, sequence))
        self.assertFalse(self.ledger.complete("burst"))

    def test_duplicates_are_rejected_after_next_phase_begins(self):
        self.author(0, 0)
        self.ledger.receive(1, self.line(0, 0))
        self.ledger.add_phase("continuous", 1)
        with self.assertRaises(bench.PhaseFailure):
            self.ledger.receive(1, self.line(0, 0))

    def test_reordered_unowned_echo_and_changed_payload_rejected(self):
        self.author(0, 0)
        self.author(0, 1)
        for recipient, line in [(1, self.line(0, 1)), (0, self.line(0, 0)),
                                (1, self.line(0, 0).replace(b":lb0!", b":lb2!")),
                                (1, self.line(0, 0)[:-1] + b"z")]:
            with self.subTest(line=line[:55]):
                with self.assertRaises(bench.PhaseFailure):
                    self.ledger.receive(recipient, line)

    def test_unauthored_message_rejected(self):
        with self.assertRaises(bench.PhaseFailure):
            self.ledger.receive(1, self.line(0, 0))

    def test_credit_requires_every_recipient(self):
        self.author(0, 0)
        self.assertFalse(self.ledger.credit("burst", 0, 64, 64))
        self.ledger.receive(1, self.line(0, 0))
        self.ledger.receive(2, self.line(0, 0))
        self.assertFalse(self.ledger.credit("burst", 0, 64, 64))
        self.ledger.receive(3, self.line(0, 0))
        self.assertTrue(self.ledger.credit("burst", 0, 64, 64))


class PinnedTlsTests(unittest.TestCase):
    def test_pinned_context_requires_verification_hostname_and_tls13(self):
        with mock.patch.object(ssl.SSLContext, "load_verify_locations") as load:
            context = bench.pinned_context(b"fixture DER")
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertTrue(context.check_hostname)
        self.assertEqual(ssl.TLSVersion.TLSv1_3, context.minimum_version)
        self.assertEqual(ssl.TLSVersion.TLSv1_3, context.maximum_version)
        load.assert_called_once()

    def test_malformed_ca_does_not_fall_back_to_system_or_unverified_trust(self):
        with self.assertRaises((ssl.SSLError, ValueError)):
            bench.pinned_context(b"invalid DER")


class PhaseReportingTests(unittest.TestCase):
    def test_percentiles_use_existing_nearest_rank_and_empty_is_unknown(self):
        self.assertEqual(dict(latency_p50_ns=10, latency_p95_ns=19, latency_p99_ns=20),
                         bench.phase_latency_percentiles(list(range(20, 0, -1))))
        self.assertEqual(dict(latency_p50_ns=None, latency_p95_ns=None, latency_p99_ns=None),
                         bench.phase_latency_percentiles([]))

    def test_observation_uses_negotiated_version_and_cipher_name(self):
        tls = mock.Mock()
        tls.version.return_value = "TLSv1.3"
        # The tuple's second element is the cipher protocol, not the negotiated version.
        tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.2", 256)
        writer = mock.Mock()
        writer.get_extra_info.return_value = tls
        self.assertEqual(dict(client=0, version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384"),
                         bench.phase_tls_observation(0, writer))
        writer.get_extra_info.assert_called_once_with("ssl_object")
        writer.get_extra_info.return_value = None
        self.assertEqual(dict(client=1, version=None, cipher=None), bench.phase_tls_observation(1, writer))
        writer.get_extra_info.return_value = tls
        tls.cipher.return_value = None
        self.assertIsNone(bench.phase_tls_observation(2, writer)["cipher"])

    def test_summary_preserves_mixed_partial_and_missing_observations(self):
        clients = [dict(client=0, version="TLSv1.3", cipher="A"),
                   dict(client=1, version="TLSv1.3", cipher="B"),
                   dict(client=2, version=None, cipher=None)]
        summary = bench.phase_tls_summary(clients)
        self.assertEqual(clients, summary["clients"])
        self.assertEqual(dict(status="partial", values=["TLSv1.3"], unknown_clients=2), summary["version"])
        self.assertEqual(dict(status="mixed", values=["A", "B"], unknown_clients=2), summary["cipher"])
        self.assertEqual(dict(status="unknown", values=[], unknown_clients=4), bench.phase_tls_summary([])["version"])
        complete = [dict(client=i, version="TLSv1.3", cipher="A") for i in range(4)]
        self.assertEqual(dict(status="uniform", values=["A"], unknown_clients=0),
                         bench.phase_tls_summary(complete)["cipher"])


class CpuModeCustodyTests(unittest.TestCase):
    def test_off_rejects_sq_worker_before_and_after_window(self):
        clean = {123: {"name": "onyx-server", "ticks": 0, "starttime": 1}}
        rogue = dict(clean)
        rogue[124] = {"name": "iou-sqp-123", "ticks": 1, "starttime": 2}
        with mock.patch("bench_sqpoll.snapshot", return_value=rogue):
            with self.assertRaises(bench.PhaseFailure):
                bench.phase_cpu_snapshot(123, 0)
        with mock.patch("bench_sqpoll.snapshot", side_effect=[clean, rogue]) as sampler:
            before = bench.phase_cpu_snapshot(123, 0)
            with self.assertRaises(bench.PhaseFailure):
                bench.phase_cpu_snapshot(123, 0, known=before)
            self.assertIs(before, sampler.call_args.kwargs["known"])

    def test_external_worker_created_mid_window_is_found_only_by_fresh_scan(self):
        # Exercise the real sampler on a synthetic /proc tree. An external SQ
        # task is absent from /proc/123/task: known=before genuinely misses it.
        for mode in (0, 10):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                proc = Path(directory)
                task_dir = proc / "123" / "task"
                def write_task(path, tid, name):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    fields = ["0"] * 20
                    fields[0], fields[11], fields[19] = "S", "1", str(tid)
                    path.write_text(f"{tid} ({name}) " + " ".join(fields))
                write_task(task_dir / "123" / "stat", 123, "onyx-server")
                if mode:
                    write_task(task_dir / "124" / "stat", 124, "iou-sqp-123")
                def mapped_path(value):
                    return proc if str(value) == "/proc" else Path(value)
                with mock.patch("bench_sqpoll.Path", side_effect=mapped_path):
                    before = bench.phase_cpu_snapshot(123, mode)
                    external = proc / "999"
                    write_task(external / "stat", 999, "iou-sqp-123")
                    (external / "comm").write_text("iou-sqp-123\n")
                    timed = bench.phase_cpu_snapshot(123, mode, known=before)
                    self.assertEqual(before.keys(), timed.keys())
                    self.assertNotIn(999, timed)
                    with self.assertRaises(RuntimeError):
                        bench.phase_verify_cpu_discovery(123, mode, timed)

    def test_fresh_discovery_rejects_added_non_sq_task_and_reused_identity(self):
        timed = {123: {"name": "onyx-server", "starttime": 1}}
        for discovered in ({**timed, 125: {"name": "background", "starttime": 2}},
                           {123: {"name": "onyx-server", "starttime": 99}}):
            with mock.patch("bench_sqpoll.snapshot", return_value=discovered):
                with self.assertRaises(bench.PhaseFailure):
                    bench.phase_verify_cpu_discovery(123, 0, timed)

    def test_enabled_requires_exact_owner_worker(self):
        for tasks in ({123: {"name": "onyx-server"}},
                      {123: {"name": "onyx-server"}, 124: {"name": "iou-sqp-999"}}):
            with mock.patch("bench_sqpoll.snapshot", return_value=tasks):
                with self.assertRaises(bench.PhaseFailure):
                    bench.phase_cpu_snapshot(123, 10)


class AsyncCustodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_certificate_rejection_propagates_without_plain_retry(self):
        rejected = ssl.SSLCertVerificationError("wrong hostname or rogue CA")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with mock.patch.object(asyncio, "open_connection", side_effect=rejected) as connect:
            with self.assertRaises(ssl.SSLCertVerificationError):
                await bench.measure_daemon_phases(None, 1234, 5678, context, "benchmark.example.test", 10, True, "0000")
        self.assertEqual(1, connect.call_count)
        self.assertIs(context, connect.call_args.kwargs["ssl"])
        self.assertEqual("benchmark.example.test", connect.call_args.kwargs["server_hostname"])

    async def test_background_reader_failure_cancels_pending_phase(self):
        failure = asyncio.get_running_loop().create_future()
        failure.set_result(bench.PhaseFailure("duplicate receipt"))
        with self.assertRaises(bench.PhaseFailure):
            await bench.phase_checked(asyncio.sleep(10), failure, .1)

    async def test_barrier_requires_exact_pong_not_substring(self):
        class Writer:
            def write(self, data):
                pass
            async def drain(self):
                pass
        reader = asyncio.StreamReader()
        failure = asyncio.get_running_loop().create_future()
        client = bench.PhaseClient(0, reader, Writer(), bench.DeliveryLedger("0000"), failure)
        barrier = asyncio.create_task(client.barrier(b"marker"))
        await asyncio.sleep(0)
        reader.feed_data(b":server PONG server :not-marker\r\n")
        with self.assertRaises(bench.PhaseFailure):
            await bench.phase_checked(barrier, failure, .2)
        client.task.cancel()
        await asyncio.gather(client.task, return_exceptions=True)


class ConfigTests(unittest.TestCase):
    def test_metrics_uses_supported_listener_key_and_explicit_loopback(self):
        base = '[node]\nid=1\n[limits]\nmax_clients=128\n[tls]\nenabled=true\n'
        for mode in (0, 10, 1000):
            config = tomllib.loads(bench.phase_config(base, mode, 12345))
            self.assertEqual({"listen": 12345, "bind": "127.0.0.1"}, config["metrics"])
            self.assertEqual("1s", config["stats"]["interval"])
            self.assertEqual("2s", config["limits"]["sweep_interval"])

    def test_modes_only_change_explicit_poll_fields(self):
        base = '[node]\nid=1\n[limits]\nmax_clients=128\n[tls]\nenabled=true\n'
        for mode in (0, 10, 1000):
            text = bench.phase_config(base, mode, 12345)
            self.assertIn('ktls = "off"', text)
            self.assertNotIn("txrx", text)
            self.assertIn("num_shards = 1", text)
            self.assertIn(f"sqpoll_idle_ms = {mode or 10}", text)
            self.assertIn(f"sqpoll = {'true' if mode else 'false'}", text)
        with self.assertRaises(bench.PhaseFailure):
            bench.phase_config(base + "[io]\n", 10, 12345)


if __name__ == "__main__":
    unittest.main()
