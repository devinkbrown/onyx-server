# SPDX-License-Identifier: AGPL-3.0-or-later
"""SCRAM proof calculation for disposable integration fixtures, not credential storage.

Python immutable bytes cannot promise secure erasure. Use generated fixture
passwords only; never include messages, passwords or proofs in failure output.
"""
import base64
import hashlib
import hmac


class ScramFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ScramFailure(message)


def fields(message):
    require(isinstance(message, bytes) and 0 < len(message) <= 2048,
            "SCRAM message exceeds fixture bounds")
    result = {}
    for part in message.split(b","):
        key, separator, value = part.partition(b"=")
        require(separator and len(key) == 1 and key not in result,
                "SCRAM attributes malformed")
        result[key] = value
    return result


def decode(value):
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        raise ScramFailure("SCRAM base64 malformed") from None


class Client:
    def __init__(self, account: bytes, nonce: bytes, digest="sha256"):
        require(digest in ("sha256", "sha512"), "unsupported fixture digest")
        require(0 < len(account) <= 32 and all(c in b"abcdefghijklmnopqrstuvwxyz0123456789_-." for c in account),
                "fixture account must be canonical")
        require(16 <= len(nonce) <= 128 and all(0x21 <= c <= 0x7e and c != 0x2c for c in nonce),
                "fixture nonce malformed")
        self.digest = digest
        self.nonce = nonce
        self.bare = b"n=" + account + b",r=" + nonce
        self.first = b"n,," + self.bare
        self.signature = None

    def respond(self, server_first: bytes, password: bytes) -> bytes:
        require(self.signature is None, "SCRAM fixture challenge already consumed")
        values = fields(server_first)
        require(set(values) == {b"r", b"s", b"i"}, "unsupported SCRAM attributes")
        nonce = values[b"r"]
        require(nonce.startswith(self.nonce) and len(self.nonce) < len(nonce) <= 256,
                "SCRAM nonce mismatch")
        require(all(0x21 <= c <= 0x7e and c != 0x2c for c in nonce), "SCRAM nonce malformed")
        iterations = values[b"i"]
        require(1 <= len(iterations) <= 7 and all(0x30 <= c <= 0x39 for c in iterations),
                "SCRAM iterations malformed")
        count = int(iterations)
        require(1 <= count <= 1_000_000, "SCRAM iterations exceed fixture bounds")
        salt = decode(values[b"s"])
        require(1 <= len(salt) <= 64, "SCRAM salt exceeds fixture bounds")
        salted = hashlib.pbkdf2_hmac(self.digest, password, salt, count)
        client_key = hmac.digest(salted, b"Client Key", self.digest)
        stored_key = hashlib.new(self.digest, client_key).digest()
        final = b"c=biws,r=" + nonce
        auth = self.bare + b"," + server_first + b"," + final
        client_signature = hmac.digest(stored_key, auth, self.digest)
        proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
        server_key = hmac.digest(salted, b"Server Key", self.digest)
        self.signature = hmac.digest(server_key, auth, self.digest)
        return final + b",p=" + base64.b64encode(proof)

    def verify(self, server_final: bytes) -> None:
        require(self.signature is not None, "SCRAM fixture has no expected server proof")
        values = fields(server_final)
        require(set(values) == {b"v"}, "SCRAM server proof missing")
        require(hmac.compare_digest(decode(values[b"v"]), self.signature), "SCRAM server proof mismatch")
