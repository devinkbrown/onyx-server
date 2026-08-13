#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Focused tests for the v2 client/server contract validator."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from typing import Any, Callable


SPEC = importlib.util.spec_from_file_location(
    "check_client_contract", pathlib.Path(__file__).with_name("check-client-contract.py")
)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)

CONTRACT_PATH = checker.default_contract_path()
SOURCE = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def changed(mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    copy_value = copy.deepcopy(SOURCE)
    mutator(copy_value)
    return copy_value


class ContractSemanticsTests(unittest.TestCase):
    def test_checked_in_contract_is_valid(self) -> None:
        self.assertTrue(checker.valid_contract(SOURCE))
        self.assertEqual([], checker.semantic_errors(SOURCE))

    def test_checked_in_contract_file_validates(self) -> None:
        self.assertEqual([], checker.validate_path(CONTRACT_PATH))

    def test_rejects_non_object(self) -> None:
        self.assertFalse(checker.valid_contract([]))

    def test_terra_payload_bound_is_b64url_chars(self) -> None:
        limits = SOURCE["e2ee_group"]["control_command"]["limits"]
        self.assertEqual(4096, limits["payload_b64url_chars"])
        self.assertNotIn("payload_bytes", limits)

    def test_recipient_gate_requires_reusable_session(self) -> None:
        self.assertEqual(
            checker.RECIPIENT_GATE,
            SOURCE["e2ee_group"]["control_command"]["delivery"]["recipient_gate"],
        )

    def test_guest_may_negotiate_but_cannot_author_or_receive(self) -> None:
        guest = SOURCE["eligibility"]["guest"]
        self.assertEqual("allowed", guest["onyx_e2ee_negotiation"])
        self.assertEqual(checker.GUEST_AUTHORING, guest["authoring"])
        self.assertEqual(checker.GUEST_RECIPIENT, guest["recipient"])

    def test_authenticated_cap_without_session_closes(self) -> None:
        auth = SOURCE["eligibility"]["authenticated_no_reusable_session"]
        self.assertTrue(auth["fail_closed"])
        self.assertEqual(checker.AUTH_NEGOTIATION, auth["negotiation"])
        self.assertEqual(checker.AUTH_AUTHORING_DEFENSE, auth["authoring_defense"])
        self.assertEqual(
            checker.REJECTED_VECTOR_FIELDS["authenticated_no_reusable_session"],
            SOURCE["command_vectors"]["rejected"]["authenticated_no_reusable_session"],
        )

    def test_session_resume_keeps_original_join_part_quit_unreplayed(self) -> None:
        split = SOURCE["session"]["replay_live_separation"]
        self.assertEqual(checker.LIVE_COMMANDS, split["live_commands"])
        self.assertEqual(checker.HISTORY_REPLAY, split["history_replay"])
        self.assertEqual(checker.HELIX_E2EE_GROUP, split["helix_e2ee_group"])
        self.assertEqual(checker.SESSION_RESUME_SPLIT, split["session_resume"])

    def test_every_rejected_vector_has_nonempty_line_and_fail(self) -> None:
        self.assertEqual(
            checker.REJECTED_VECTOR_FIELDS,
            SOURCE["command_vectors"]["rejected"],
        )

    def test_accepted_vectors_match_frozen_line_and_delivery(self) -> None:
        self.assertEqual(
            checker.ACCEPTED_VECTOR_FIELDS,
            SOURCE["command_vectors"]["accepted"],
        )

    def test_vendor_mapping_is_exact(self) -> None:
        self.assertEqual(checker.VENDOR_CAPS, SOURCE["capabilities"]["vendor"])

    def test_delivery_is_account_bearing_and_authoring_forms_are_unchanged(self) -> None:
        delivery = SOURCE["e2ee_group"]["control_command"]["delivery"]
        self.assertEqual(checker.CHANNEL_RECORD, delivery["channel_record"])
        self.assertEqual(checker.WELCOME_RECORD, delivery["welcome_record"])
        self.assertNotEqual(checker.ACCOUNTLESS_CHANNEL_RECORD, delivery["channel_record"])
        self.assertNotEqual(checker.ACCOUNTLESS_WELCOME_RECORD, delivery["welcome_record"])
        self.assertEqual(
            list(checker.CONTROL_FORMS),
            SOURCE["e2ee_group"]["control_command"]["forms"],
        )
        self.assertNotIn("<from-account>", SOURCE["e2ee_group"]["control_command"]["forms"][0])
        self.assertIn(
            "alice phone",
            SOURCE["command_vectors"]["accepted"]["key_package_channel"]["delivery"],
        )
        self.assertIn(
            "alice phone Bob tablet",
            SOURCE["command_vectors"]["accepted"]["welcome_targeted"]["delivery"],
        )

    def test_persistence_allows_transient_ads1_and_mesh_custody_only(self) -> None:
        persistence = SOURCE["e2ee_group"]["persistence"]
        self.assertEqual("none", persistence["group_secrets"])
        self.assertEqual("none", persistence["offline_recipient"])
        self.assertEqual("none_durable", persistence["opaque_control_payload"])
        self.assertEqual(
            ["bounded_ads1_attachment_spool", "ram_mesh_hop_custody_until_ack"],
            persistence["allowed_transient"],
        )

    def test_client_inbound_consumes_e2ee_records_not_e2eegroup(self) -> None:
        inbound = SOURCE["client"]["inbound_adapter"]
        self.assertEqual(
            ["E2EE.KEYPACKAGE", "E2EE.COMMIT", "E2EE.WELCOME"],
            inbound["consumes"],
        )
        self.assertEqual("inbound E2EEGROUP", inbound["does_not_consume"])

    def test_status_split_is_frozen(self) -> None:
        self.assertEqual("production_active", SOURCE["server"]["group_control"])
        self.assertEqual("staged_unwired", SOURCE["client"]["group_crypto"])

    def test_session_resume_and_presence_objects_are_exact(self) -> None:
        self.assertEqual(checker.SESSION_RESUME_FIELDS, SOURCE["session"]["resume"])
        self.assertEqual(checker.PRESENCE_QUIT_FIELDS, SOURCE["presence"]["quit"])
        self.assertEqual(checker.PRESENCE_PART_FIELDS, SOURCE["presence"]["part"])


class MutationRejectionTests(unittest.TestCase):
    def test_rejects_semantic_drift(self) -> None:
        cases: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
            ("schema", lambda value: value.__setitem__("schema", "onyx-client-server-contract/v1")),
            ("transport missing", lambda value: value.pop("transport")),
            ("transport nonobject", lambda value: value.__setitem__("transport", ["websocket"])),
            (
                "transport websocket drift",
                lambda value: value["transport"].__setitem__("websocket", "multiple IRC messages per frame"),
            ),
            (
                "content_envelope",
                lambda value: value["e2ee_group"].__setitem__("content_envelope", "TSUMUGI1"),
            ),
            (
                "message_tag",
                lambda value: value["e2ee_group"].__setitem__("message_tag", "+onyx/e2ee=sframe"),
            ),
            (
                "helix_checkpoint",
                lambda value: value["e2ee_group"]["persistence"].__setitem__("helix_checkpoint", "include_payloads"),
            ),
            (
                "inbound adapter status",
                lambda value: value["client"]["inbound_adapter"].__setitem__("status", "production_active"),
            ),
            (
                "inbound adapter missing",
                lambda value: value["client"].pop("inbound_adapter"),
            ),
            (
                "inbound adapter malformed",
                lambda value: value["client"].__setitem__("inbound_adapter", None),
            ),
            (
                "persistence missing",
                lambda value: value["e2ee_group"].pop("persistence"),
            ),
            (
                "persistence malformed",
                lambda value: value["e2ee_group"].__setitem__("persistence", "none"),
            ),
            (
                "e2ee_group malformed",
                lambda value: value.__setitem__("e2ee_group", []),
            ),
            ("revision", lambda value: value.__setitem__("revision", 1)),
            ("server status", lambda value: value["server"].__setitem__("group_control", "staged")),
            ("client status", lambda value: value["client"].__setitem__("group_crypto", "production_active")),
            ("guest negotiation", lambda value: value["eligibility"]["guest"].__setitem__("onyx_e2ee_negotiation", "denied")),
            (
                "session unavailable",
                lambda value: value["eligibility"]["authenticated_no_reusable_session"].__setitem__(
                    "negotiation", "WARN E2EEGROUP TEMPORARILY_UNAVAILABLE"
                ),
            ),
            (
                "authoring defense deleted",
                lambda value: value["eligibility"]["authenticated_no_reusable_session"].pop("authoring_defense"),
            ),
            (
                "authoring defense replayed as success",
                lambda value: value["eligibility"]["authenticated_no_reusable_session"].__setitem__(
                    "authoring_defense", "accepted without a reusable session"
                ),
            ),
            (
                "required caps",
                lambda value: value["capabilities"]["required_for_first_party_client"].remove("draft/chathistory"),
            ),
            (
                "channel limit",
                lambda value: value["e2ee_group"]["control_command"]["limits"].__setitem__("channel_bytes", 64),
            ),
            (
                "device limit",
                lambda value: value["e2ee_group"]["control_command"]["limits"].__setitem__("device_id_bytes", 16),
            ),
            (
                "account limit",
                lambda value: value["e2ee_group"]["control_command"]["limits"].__setitem__("account_bytes", 32),
            ),
            (
                "control command name",
                lambda value: value["e2ee_group"]["control_command"].__setitem__("name", "DATA"),
            ),
            (
                "ircx required",
                lambda value: value["e2ee_group"]["control_command"].__setitem__("ircx_required", False),
            ),
            (
                "cap required",
                lambda value: value["e2ee_group"]["control_command"].__setitem__("cap_required", "message-tags"),
            ),
            (
                "quit mesh marker",
                lambda value: value["presence"]["quit"].__setitem__("mesh_marker", "ONYX-PART"),
            ),
            (
                "session_resume claims replay",
                lambda value: value["session"]["replay_live_separation"].__setitem__(
                    "session_resume", "replay original JOIN/PART/QUIT live commands"
                ),
            ),
            (
                "rejected vector empty line",
                lambda value: value["command_vectors"]["rejected"]["missing_cap"].__setitem__("line", ""),
            ),
            (
                "payload bound",
                lambda value: value["e2ee_group"]["control_command"]["limits"].__setitem__(
                    "payload_b64url_chars", 8192
                ),
            ),
            (
                "payload_bytes alias",
                lambda value: value["e2ee_group"]["control_command"]["limits"].__setitem__("payload_bytes", 4096),
            ),
            (
                "recipient gate",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "recipient_gate", "onyx/e2ee negotiated and locally joined to the channel"
                ),
            ),
            (
                "welcome absence",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "welcome_absence", "queue for later delivery"
                ),
            ),
            ("group secrets", lambda value: value["e2ee_group"].__setitem__("server_secrets", "escrow")),
            (
                "offline recipient persistence",
                lambda value: value["e2ee_group"]["persistence"].__setitem__("offline_recipient", "history"),
            ),
            (
                "transient holds",
                lambda value: value["e2ee_group"]["persistence"].__setitem__("allowed_transient", []),
            ),
            (
                "trusted signer",
                lambda value: value["e2ee_group"]["trusted_signer"].__setitem__("requirement", "wire_signer_pub"),
            ),
            (
                "MLS claim",
                lambda value: value["e2ee_group"].__setitem__(
                    "message_tag_semantics", "RFC 9420 MLS wire interoperability"
                ),
            ),
            (
                "inbound verbs",
                lambda value: value["client"]["inbound_adapter"].__setitem__("consumes", ["E2EEGROUP"]),
            ),
            ("quit scope", lambda value: value["presence"]["quit"].__setitem__("scope", "channel_local")),
            ("part scope", lambda value: value["presence"]["part"].__setitem__("scope", "identity_wide")),
            (
                "resume invariant",
                lambda value: value["session"]["resume"].__setitem__("invariant", "replay JOIN on resume"),
            ),
            (
                "accepted vector name",
                lambda value: value["command_vectors"]["accepted"].pop("commit_channel"),
            ),
            (
                "rejected fail code",
                lambda value: value["command_vectors"]["rejected"]["guest_authoring"].__setitem__(
                    "fail", "FAIL E2EEGROUP TARGET_UNAVAILABLE"
                ),
            ),
            (
                "rejected vector missing fail",
                lambda value: value["command_vectors"]["rejected"]["device_not_owned"].pop("fail"),
            ),
            (
                "negated negotiation still names SESSION_UNAVAILABLE",
                lambda value: value["eligibility"]["authenticated_no_reusable_session"].__setitem__(
                    "negotiation",
                    "does not emit FAIL E2EEGROUP SESSION_UNAVAILABLE; connection never closes",
                ),
            ),
            (
                "negated authoring_defense still names TEMPORARILY_UNAVAILABLE",
                lambda value: value["eligibility"]["authenticated_no_reusable_session"].__setitem__(
                    "authoring_defense",
                    "not TEMPORARILY_UNAVAILABLE; a reusable session is not required",
                ),
            ),
            (
                "negated session_resume still names JOIN/PART/QUIT",
                lambda value: value["session"]["replay_live_separation"].__setitem__(
                    "session_resume",
                    "it is false that original JOIN/PART/QUIT live commands are not replayed",
                ),
            ),
            (
                "negated live_commands still names processLiveLine",
                lambda value: value["session"]["replay_live_separation"].__setitem__(
                    "live_commands",
                    "processLiveLine is not the only client-command admission path",
                ),
            ),
            (
                "negated history_replay still names CHATHISTORY",
                lambda value: value["session"]["replay_live_separation"].__setitem__(
                    "history_replay",
                    "CHATHISTORY and bouncer rewind do not replay stored events; they re-author live commands",
                ),
            ),
            (
                "negated helix_e2ee_group still names metadata",
                lambda value: value["session"]["replay_live_separation"].__setitem__(
                    "helix_e2ee_group",
                    "EGRG Helix checkpoints are not replay metadata only; opaque payloads enter Helix",
                ),
            ),
            (
                "session commands",
                lambda value: value["session"]["commands"].__setitem__(0, "SESSION LIST"),
            ),
            (
                "control forms",
                lambda value: value["e2ee_group"]["control_command"]["forms"].__setitem__(
                    0, "<channel> commit <from-device> :<opaque-base64url>"
                ),
            ),
            (
                "channel delivery record",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "channel_record",
                    ":<source-prefix> E2EEGROUP <channel> <from-device> :<opaque-base64url>",
                ),
            ),
            (
                "welcome delivery record",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "welcome_record",
                    ":<source-prefix> E2EEGROUP WELCOME <channel> <from-device> <to-account> <to-device> :<opaque-base64url>",
                ),
            ),
            (
                "accountless channel delivery",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "channel_record", checker.ACCOUNTLESS_CHANNEL_RECORD
                ),
            ),
            (
                "accountless welcome delivery",
                lambda value: value["e2ee_group"]["control_command"]["delivery"].__setitem__(
                    "welcome_record", checker.ACCOUNTLESS_WELCOME_RECORD
                ),
            ),
            (
                "accountless accepted key-package delivery",
                lambda value: value["command_vectors"]["accepted"]["key_package_channel"].__setitem__(
                    "delivery", ":Alice!alice@localhost E2EE.KEYPACKAGE #secure phone :AQIDBA"
                ),
            ),
            (
                "accountless accepted welcome delivery",
                lambda value: value["command_vectors"]["accepted"]["welcome_targeted"].__setitem__(
                    "delivery",
                    ":Alice!alice@localhost E2EE.WELCOME #secure phone Bob tablet :d2VsY29tZQ",
                ),
            ),
            (
                "control records",
                lambda value: value["e2ee_group"]["control_records"].append("proposal"),
            ),
            (
                "vendor extra key",
                lambda value: value["capabilities"]["vendor"].__setitem__("onyx/media", "calls"),
            ),
            (
                "vendor e2ee description",
                lambda value: value["capabilities"]["vendor"].__setitem__("onyx/e2ee", "permits the +onyx/e2ee message tag"),
            ),
            (
                "accepted vector line",
                lambda value: value["command_vectors"]["accepted"]["commit_channel"].__setitem__(
                    "line", "E2EEGROUP #secure commit phone :AAAAAA"
                ),
            ),
            (
                "accepted vector delivery",
                lambda value: value["command_vectors"]["accepted"]["key_package_channel"].__setitem__(
                    "delivery", ":Alice!alice@localhost E2EEGROUP #secure phone :AQIDBA"
                ),
            ),
            (
                "accepted welcome delivery verb swap",
                lambda value: value["command_vectors"]["accepted"]["welcome_targeted"].__setitem__(
                    "delivery",
                    ":Alice!alice@localhost E2EE.COMMIT #secure phone Bob tablet :d2VsY29tZQ",
                ),
            ),
            (
                "resume live_sibling",
                lambda value: value["session"]["resume"].__setitem__("live_sibling", "disconnect the source"),
            ),
            (
                "resume detached_ghost",
                lambda value: value["session"]["resume"].__setitem__(
                    "detached_ghost", "discard the ghost before restore"
                ),
            ),
            (
                "resume mesh_token",
                lambda value: value["session"]["resume"].__setitem__(
                    "mesh_token", "mesh tokens are one-shot replay nonces"
                ),
            ),
            (
                "resume invariant deleted",
                lambda value: value["session"]["resume"].pop("invariant"),
            ),
            (
                "resume live_sibling deleted",
                lambda value: value["session"]["resume"].pop("live_sibling"),
            ),
            (
                "resume detached_ghost deleted",
                lambda value: value["session"]["resume"].pop("detached_ghost"),
            ),
            (
                "resume mesh_token deleted",
                lambda value: value["session"]["resume"].pop("mesh_token"),
            ),
            (
                "resume object malformed",
                lambda value: value["session"].__setitem__("resume", "not-an-object"),
            ),
            (
                "quit delivery",
                lambda value: value["presence"]["quit"].__setitem__("delivery", "best_effort"),
            ),
            (
                "quit client_visible",
                lambda value: value["presence"]["quit"].__setitem__("client_visible", "one PART per channel"),
            ),
            (
                "quit sibling_attachment",
                lambda value: value["presence"]["quit"].__setitem__(
                    "sibling_attachment", "emit identity-wide QUIT for every sibling"
                ),
            ),
            (
                "quit scope deleted",
                lambda value: value["presence"]["quit"].pop("scope"),
            ),
            (
                "quit delivery deleted",
                lambda value: value["presence"]["quit"].pop("delivery"),
            ),
            (
                "quit mesh_marker deleted",
                lambda value: value["presence"]["quit"].pop("mesh_marker"),
            ),
            (
                "quit client_visible deleted",
                lambda value: value["presence"]["quit"].pop("client_visible"),
            ),
            (
                "quit sibling_attachment deleted",
                lambda value: value["presence"]["quit"].pop("sibling_attachment"),
            ),
            (
                "quit object malformed",
                lambda value: value["presence"].__setitem__("quit", ["identity_wide"]),
            ),
            (
                "part channels",
                lambda value: value["presence"]["part"].__setitem__("channels", "single channel only"),
            ),
            (
                "part intent",
                lambda value: value["presence"]["part"].__setitem__(
                    "intent", "identity-wide withdrawal of every channel"
                ),
            ),
            (
                "part scope deleted",
                lambda value: value["presence"]["part"].pop("scope"),
            ),
            (
                "part channels deleted",
                lambda value: value["presence"]["part"].pop("channels"),
            ),
            (
                "part intent deleted",
                lambda value: value["presence"]["part"].pop("intent"),
            ),
            (
                "part object malformed",
                lambda value: value["presence"].__setitem__("part", None),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                self.assertFalse(checker.valid_contract(changed(mutate)), label)
                self.assertTrue(checker.semantic_errors(changed(mutate)), label)


class ByteDriftTests(unittest.TestCase):
    def test_identical_peer_copy_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            peer = pathlib.Path(tmp) / "onyx-client-contract.v2.json"
            peer.write_bytes(CONTRACT_PATH.read_bytes())
            self.assertIsNone(checker.compare_bytes(CONTRACT_PATH, peer))
            self.assertEqual(0, checker.main([str(peer)]))

    def test_byte_drift_is_rejected_even_when_json_is_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            peer = pathlib.Path(tmp) / "onyx-client-contract.v2.json"
            peer.write_bytes(CONTRACT_PATH.read_bytes() + b"\n")
            self.assertIsNotNone(checker.compare_bytes(CONTRACT_PATH, peer))
            self.assertEqual(1, checker.main([str(peer)]))

    def test_semantic_mutation_is_rejected_before_byte_compare(self) -> None:
        drifted = changed(lambda value: value["server"].__setitem__("group_control", "staged"))
        with tempfile.TemporaryDirectory() as tmp:
            peer = pathlib.Path(tmp) / "bad.json"
            peer.write_text(json.dumps(drifted), encoding="utf-8")
            self.assertFalse(checker.valid_contract(drifted))
            # CLI validates the repo contract first; a valid repo file plus a
            # drifted peer still fails the exact-byte gate.
            self.assertEqual(1, checker.main([str(peer)]))

    def test_cli_without_peer_accepts_repo_contract(self) -> None:
        self.assertEqual(0, checker.main([]))

    def test_missing_repo_local_peer_returns_clean_error(self) -> None:
        missing = CONTRACT_PATH.with_name("onyx-client-contract.v2.no-such-peer.json")
        self.assertFalse(missing.exists())
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = checker.main([str(missing)])
        text = stderr.getvalue()
        self.assertEqual(1, status)
        self.assertIn("error:", text)
        self.assertIn(str(missing), text)
        self.assertNotIn("Traceback", text)
        self.assertIsNotNone(checker.compare_bytes(CONTRACT_PATH, missing))

    def test_unreadable_repo_local_peer_directory_returns_clean_error(self) -> None:
        directory = CONTRACT_PATH.parent
        self.assertTrue(directory.is_dir())
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = checker.main([str(directory)])
        text = stderr.getvalue()
        self.assertEqual(1, status)
        self.assertIn("error:", text)
        self.assertIn(str(directory), text)
        self.assertNotIn("Traceback", text)


if __name__ == "__main__":
    unittest.main()
