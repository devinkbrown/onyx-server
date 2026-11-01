#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wire-proof oracle: RFC7677 vector retained in src/proto/sasl_scram.zig."""
import unittest

from scram_fixture import Client, ScramFailure


class ScramFixtureTests(unittest.TestCase):
    def test_rfc7677_proof_and_server_authentication(self):
        client = Client(b"user", b"rOprNGfwEbeRWgbNEkqO")
        first = (b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                 b"s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
        expected = (b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                    b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
        self.assertTrue(client.respond(first, b"pencil") == expected, "known wire proof mismatch")
        client.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
        with self.assertRaisesRegex(ScramFailure, "server proof mismatch"):
            client.verify(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    def test_rejects_bad_nonce_duplicate_attributes_and_unbounded_work(self):
        nonce = b"fixture-client-nonce"
        for first in (b"r=other-nonce,s=eA==,i=1", b"r=" + nonce + b",s=eA==,i=1",
                      b"r=" + nonce + b"server,s=eA==,i=1000001",
                      b"r=" + nonce + b"server,s=eA==,i=1,i=2"):
            with self.assertRaises(ScramFailure):
                Client(b"user", nonce).respond(first, b"fixture-only-password")


if __name__ == "__main__":
    unittest.main()
