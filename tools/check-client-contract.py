#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Semantic validator for the Onyx client/server v2 contract.

Validates required Wave-1 assertions against
``docs/reference/protocol/onyx-client-contract.v2.json``. When a peer
(client-repo) copy is supplied, the two files must be byte-identical.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "onyx-client-server-contract/v2"
REVISION = 2
REQUIRED_CAPS = (
    "message-tags",
    "server-time",
    "batch",
    "labeled-response",
    "echo-message",
    "draft/chathistory",
)
CONTROL_KINDS = ("key-package", "welcome", "commit")
CONTROL_FORMS = (
    "<channel> <key-package|commit> <from-device> :<opaque-base64url>",
    "<channel> welcome <from-device> <to-account> <to-device> :<opaque-base64url>",
)
INBOUND_VERBS = ("E2EE.KEYPACKAGE", "E2EE.COMMIT", "E2EE.WELCOME")
TRANSIENT_PERSISTENCE = (
    "bounded_ads1_attachment_spool",
    "ram_mesh_hop_custody_until_ack",
)
ACCEPTED_VECTORS = (
    "key_package_channel",
    "commit_channel",
    "welcome_targeted",
    "commit_payload_bound",
)
REJECTED_VECTORS = (
    "bad_payload_noncanonical",
    "device_not_owned",
    "welcome_unknown_device",
    "welcome_target_not_in_channel",
    "guest_authoring",
    "missing_cap",
    "missing_ircx",
    "sender_not_on_channel",
    "authenticated_no_reusable_session",
)
SESSION_COMMANDS = (
    "SESSION TOKEN",
    "SESSION MTOKEN",
    "SESSION RESUME <token>",
)
VENDOR_CAPS = {
    "onyx/session-sync": "same-account attachment synchronization",
    "onyx/bouncer": "automatic history rewind",
    "onyx/topics": "named conversation tags and history",
    "onyx/e2ee": "permits the +onyx/e2ee message tag and E2EEGROUP eligibility",
}
GUEST_AUTHORING = "FAIL E2EEGROUP NOT_LOGGED_IN"
GUEST_RECIPIENT = "ineligible; no reusable session row"
AUTH_NEGOTIATION = (
    "FAIL E2EEGROUP SESSION_UNAVAILABLE; connection closes before autojoin or further participation"
)
AUTH_AUTHORING_DEFENSE = (
    "WARN E2EEGROUP TEMPORARILY_UNAVAILABLE; a reusable session is required for group E2EE"
)
RESUME_INVARIANT = (
    "A successful same-account resume preserves the logical attachment without duplicate JOIN or MODE events."
)
SESSION_RESUME_FIELDS = {
    "invariant": RESUME_INVARIANT,
    "live_sibling": "attach without disconnecting the source",
    "detached_ghost": "restore snapshot then replace the ghost; the token remains reusable",
    "mesh_token": "non-local-length hex is a mesh-sealed reclaim credential, not a one-shot replay nonce",
}
PRESENCE_QUIT_FIELDS = {
    "scope": "identity_wide",
    "delivery": "exactly_once",
    "mesh_marker": "ONYX-QUIT",
    "client_visible": "one identity-wide QUIT; per-channel membership withdrawals converge separately",
    "sibling_attachment": "handoff without identity-wide QUIT",
}
PRESENCE_PART_FIELDS = {
    "scope": "channel_local",
    "channels": "comma-separated list with a shared reason",
    "intent": "one-way exact-token withdrawal of the named channels only",
}
LIVE_COMMANDS = "processLiveLine is the only client-command admission path"
HISTORY_REPLAY = (
    "CHATHISTORY and bouncer rewind replay stored events; they do not re-author live commands"
)
HELIX_E2EE_GROUP = (
    "EGRG Helix checkpoints are replay metadata only; opaque payloads and hop-custody wires never enter Helix"
)
SESSION_RESUME_SPLIT = (
    "snapshot or live-sibling attach; original JOIN/PART/QUIT live commands are not replayed"
)
TRUSTED_SIGNER_SEMANTICS = (
    "verification requires an externally supplied trusted Ed25519 public key; "
    "the wire signer_pub must equal that key and is never account authentication by itself"
)
CHANNEL_RECORD = (
    ":<source-prefix> E2EE.KEYPACKAGE|E2EE.COMMIT <channel> <from-account> <from-device> :<opaque-base64url>"
)
WELCOME_RECORD = (
    ":<source-prefix> E2EE.WELCOME <channel> <from-account> <from-device> <to-account> <to-device> :<opaque-base64url>"
)
ACCOUNTLESS_CHANNEL_RECORD = (
    ":<source-prefix> E2EE.KEYPACKAGE|E2EE.COMMIT <channel> <from-device> :<opaque-base64url>"
)
ACCOUNTLESS_WELCOME_RECORD = (
    ":<source-prefix> E2EE.WELCOME <channel> <from-device> <to-account> <to-device> :<opaque-base64url>"
)
RECIPIENT_GATE = (
    "onyx/e2ee negotiated, locally joined to the channel, and attached to a reusable session"
)
WELCOME_ABSENCE = "explicit TARGET_UNAVAILABLE failure; no offline-recipient persistence"
ACCEPTED_VECTOR_FIELDS = {
    "key_package_channel": {
        "line": "E2EEGROUP #secure key-package phone :AQIDBA",
        "delivery": ":Alice!alice@localhost E2EE.KEYPACKAGE #secure alice phone :AQIDBA",
    },
    "commit_channel": {
        "line": "E2EEGROUP #secure commit phone :b3BhcXVl",
        "delivery": ":Alice!alice@localhost E2EE.COMMIT #secure alice phone :b3BhcXVl",
    },
    "welcome_targeted": {
        "line": "E2EEGROUP #secure welcome phone Bob tablet :d2VsY29tZQ",
        "delivery": ":Alice!alice@localhost E2EE.WELCOME #secure alice phone Bob tablet :d2VsY29tZQ",
    },
    "commit_payload_bound": {
        "line": "E2EEGROUP #secure commit phone :<payload>",
        "payload_repeat": {"char": "A", "count": 4096},
        "delivery_verb": "E2EE.COMMIT",
    },
}
REJECTED_VECTOR_FIELDS = {
    "bad_payload_noncanonical": {
        "line": "E2EEGROUP #secure commit phone :not+base64url",
        "fail": "FAIL E2EEGROUP BAD_PAYLOAD",
    },
    "device_not_owned": {
        "line": "E2EEGROUP #secure commit missing :AQIDBA",
        "fail": "FAIL E2EEGROUP DEVICE_NOT_OWNED",
    },
    "welcome_unknown_device": {
        "line": "E2EEGROUP #secure welcome phone bob missing :AQIDBA",
        "fail": "FAIL E2EEGROUP TARGET_UNAVAILABLE",
    },
    "welcome_target_not_in_channel": {
        "line": "E2EEGROUP #secure welcome phone carol laptop :AQIDBA",
        "fail": "FAIL E2EEGROUP TARGET_UNAVAILABLE",
    },
    "guest_authoring": {
        "line": "E2EEGROUP #secure commit phone :AQIDBA",
        "fail": "FAIL E2EEGROUP NOT_LOGGED_IN",
    },
    "missing_cap": {
        "line": "E2EEGROUP #secure commit phone :AQIDBA",
        "fail": "FAIL E2EEGROUP CAP_REQUIRED",
    },
    "missing_ircx": {
        "line": "E2EEGROUP #secure commit phone :AQIDBA",
        "fail": "FAIL E2EEGROUP IRCX_REQUIRED",
    },
    "sender_not_on_channel": {
        "line": "E2EEGROUP #secure commit phone :AQIDBA",
        "fail": "FAIL E2EEGROUP NOT_ON_CHANNEL",
    },
    "authenticated_no_reusable_session": {
        "line": "CAP REQ :onyx/e2ee",
        "fail": "FAIL E2EEGROUP SESSION_UNAVAILABLE",
        "closes_connection": True,
    },
}

CONTRACT_RELATIVE = Path("docs/reference/protocol/onyx-client-contract.v2.json")


def default_contract_path() -> Path:
    return Path(__file__).resolve().parents[1] / CONTRACT_RELATIVE


def load_contract(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _is_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _exact_seq(actual: Any, expected: Sequence[str]) -> bool:
    return (
        isinstance(actual, list)
        and len(actual) == len(expected)
        and all(item == want for item, want in zip(actual, expected))
    )


def _has_named_keys(actual: Any, expected: Sequence[str]) -> bool:
    return _is_mapping(actual) and set(actual) == set(expected)


def semantic_errors(contract: Any) -> list[str]:
    errors: list[str] = []

    def need(ok: bool, message: str) -> None:
        if not ok:
            errors.append(message)

    need(_is_mapping(contract), "contract must be a JSON object")
    if errors:
        return errors

    need(contract.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    need(contract.get("revision") == REVISION, f"revision must be {REVISION}")

    transport = contract.get("transport")
    need(_is_mapping(transport), "transport must be an object")
    if _is_mapping(transport):
        need(
            transport.get("websocket")
            == "one IRC message per frame; no trailing frame bytes",
            "transport.websocket framing is frozen",
        )

    caps = contract.get("capabilities")
    need(_is_mapping(caps), "capabilities must be an object")
    if _is_mapping(caps):
        need(
            _exact_seq(caps.get("required_for_first_party_client"), REQUIRED_CAPS),
            "first-party capability set is frozen",
        )
        vendor = caps.get("vendor")
        need(vendor == VENDOR_CAPS, "vendor capability mapping is frozen")

    server = contract.get("server")
    need(_is_mapping(server), "server must be an object")
    if _is_mapping(server):
        need(server.get("group_control") == "production_active", "server.group_control must be production_active")

    client = contract.get("client")
    need(_is_mapping(client), "client must be an object")
    if _is_mapping(client):
        need(client.get("group_crypto") == "staged_unwired", "client.group_crypto must be staged_unwired")
        inbound = client.get("inbound_adapter")
        need(_is_mapping(inbound), "client.inbound_adapter must be an object")
        if _is_mapping(inbound):
            need(inbound.get("status") == "staged_unwired", "client inbound adapter remains staged_unwired")
            need(_exact_seq(inbound.get("consumes"), INBOUND_VERBS), "inbound adapter must consume E2EE.* verbs")
            need(
                inbound.get("does_not_consume") == "inbound E2EEGROUP",
                "inbound adapter must not consume inbound E2EEGROUP",
            )

    eligibility = contract.get("eligibility")
    need(_is_mapping(eligibility), "eligibility must be an object")
    if _is_mapping(eligibility):
        guest = eligibility.get("guest")
        need(_is_mapping(guest), "eligibility.guest must be an object")
        if _is_mapping(guest):
            need(guest.get("onyx_e2ee_negotiation") == "allowed", "guest onyx/e2ee negotiation must be allowed")
            need(guest.get("reusable_session_required") is False, "guest must not require a reusable session")
            need(guest.get("authoring") == GUEST_AUTHORING, "guest authoring fail is frozen")
            need(guest.get("recipient") == GUEST_RECIPIENT, "guest recipient ineligibility is frozen")
        auth = eligibility.get("authenticated_no_reusable_session")
        need(_is_mapping(auth), "authenticated_no_reusable_session must be an object")
        if _is_mapping(auth):
            need(auth.get("fail_closed") is True, "authenticated no-reusable-session must be fail-closed")
            need(auth.get("negotiation") == AUTH_NEGOTIATION, "authenticated negotiation prose is frozen")
            need(
                auth.get("authoring_defense") == AUTH_AUTHORING_DEFENSE,
                "authenticated authoring_defense prose is frozen",
            )

    session = contract.get("session")
    need(_is_mapping(session), "session must be an object")
    if _is_mapping(session):
        need(_exact_seq(session.get("commands"), SESSION_COMMANDS), "session.commands are frozen")
        need(session.get("resume") == SESSION_RESUME_FIELDS, "session.resume fields are frozen")
        split = session.get("replay_live_separation")
        need(_is_mapping(split), "session.replay_live_separation must be an object")
        if _is_mapping(split):
            need(split.get("live_commands") == LIVE_COMMANDS, "live_commands prose is frozen")
            need(split.get("history_replay") == HISTORY_REPLAY, "history_replay prose is frozen")
            need(split.get("helix_e2ee_group") == HELIX_E2EE_GROUP, "helix_e2ee_group prose is frozen")
            need(split.get("session_resume") == SESSION_RESUME_SPLIT, "session_resume prose is frozen")

    group = contract.get("e2ee_group")
    need(_is_mapping(group), "e2ee_group must be an object")
    if _is_mapping(group):
        need(group.get("content_envelope") == "ONYXROOM1", "content envelope must be ONYXROOM1")
        need(group.get("message_tag") == "+onyx/e2ee=mls", "message tag must be +onyx/e2ee=mls")
        semantics = group.get("message_tag_semantics")
        need(
            semantics
            == "internal MLS-family marker only; does not claim RFC 9420 wire interoperability",
            "MLS-family marker must not claim RFC 9420 interoperability",
        )
        signer = group.get("trusted_signer")
        need(_is_mapping(signer), "trusted_signer must be an object")
        if _is_mapping(signer):
            need(signer.get("requirement") == "mandatory_external", "trusted signer must be mandatory_external")
            need(signer.get("semantics") == TRUSTED_SIGNER_SEMANTICS, "trusted signer semantics are frozen")
        need(group.get("server_secrets") == "none", "server must have no group secrets")
        persistence = group.get("persistence")
        need(_is_mapping(persistence), "persistence must be an object")
        if _is_mapping(persistence):
            need(persistence.get("group_secrets") == "none", "group-secret persistence must be none")
            need(persistence.get("offline_recipient") == "none", "offline-recipient persistence must be none")
            need(
                persistence.get("opaque_control_payload") == "none_durable",
                "opaque control payload must not be durably persisted",
            )
            need(
                _exact_seq(persistence.get("allowed_transient"), TRANSIENT_PERSISTENCE),
                "only bounded ADS1 spool and RAM mesh custody are allowed transient holds",
            )
            need(persistence.get("helix_checkpoint") == "replay_metadata_only", "Helix may seal replay metadata only")
        need(_exact_seq(group.get("control_records"), CONTROL_KINDS), "control record kinds are frozen")
        command = group.get("control_command")
        need(_is_mapping(command), "control_command must be an object")
        if _is_mapping(command):
            need(command.get("name") == "E2EEGROUP", "control command must be E2EEGROUP")
            need(command.get("ircx_required") is True, "E2EEGROUP requires IRCX")
            need(command.get("cap_required") == "onyx/e2ee", "E2EEGROUP requires onyx/e2ee")
            need(_exact_seq(command.get("forms"), CONTROL_FORMS), "E2EEGROUP outer forms are frozen")
            need(
                command.get("payload_encoding") == "canonical base64url without padding",
                "payload encoding must be canonical unpadded base64url",
            )
            limits = command.get("limits")
            need(_is_mapping(limits), "limits must be an object")
            if _is_mapping(limits):
                need(limits.get("channel_bytes") == 128, "channel_bytes must be 128")
                need(limits.get("device_id_bytes") == 32, "device_id_bytes must be 32")
                need(limits.get("account_bytes") == 64, "account_bytes must be 64")
                need(limits.get("payload_b64url_chars") == 4096, "payload_b64url_chars must be 4096")
                need("payload_bytes" not in limits, "payload bound is payload_b64url_chars, not payload_bytes")
            delivery = command.get("delivery")
            need(_is_mapping(delivery), "delivery must be an object")
            if _is_mapping(delivery):
                need(delivery.get("channel_record") == CHANNEL_RECORD, "channel delivery record form is frozen")
                need(delivery.get("welcome_record") == WELCOME_RECORD, "welcome delivery record form is frozen")
                need(
                    delivery.get("channel_record") != ACCOUNTLESS_CHANNEL_RECORD,
                    "channel delivery must include from-account; account-less shape is rejected",
                )
                need(
                    delivery.get("welcome_record") != ACCOUNTLESS_WELCOME_RECORD,
                    "welcome delivery must include from-account before from-device; account-less shape is rejected",
                )
                need(delivery.get("recipient_gate") == RECIPIENT_GATE, "recipient gate prose is frozen")
                need(delivery.get("welcome_absence") == WELCOME_ABSENCE, "welcome absence prose is frozen")

    presence = contract.get("presence")
    need(_is_mapping(presence), "presence must be an object")
    if _is_mapping(presence):
        need(presence.get("quit") == PRESENCE_QUIT_FIELDS, "presence.quit fields are frozen")
        need(presence.get("part") == PRESENCE_PART_FIELDS, "presence.part fields are frozen")

    vectors = contract.get("command_vectors")
    need(_is_mapping(vectors), "command_vectors must be an object")
    if _is_mapping(vectors):
        accepted = vectors.get("accepted")
        rejected = vectors.get("rejected")
        need(_has_named_keys(accepted, ACCEPTED_VECTORS), "accepted command vector names are frozen")
        need(_has_named_keys(rejected, REJECTED_VECTORS), "rejected command vector names are frozen")
        if _is_mapping(accepted):
            for name, expected in ACCEPTED_VECTOR_FIELDS.items():
                item = accepted.get(name)
                need(item == expected, f"accepted.{name} line/delivery fields are frozen")
        if _is_mapping(rejected):
            for name, expected in REJECTED_VECTOR_FIELDS.items():
                item = rejected.get(name)
                need(item == expected, f"rejected.{name} line/fail fields are frozen")

    return errors


def valid_contract(contract: Any) -> bool:
    return not semantic_errors(contract)


def compare_bytes(left: Path, right: Path) -> str | None:
    try:
        left_bytes = left.read_bytes()
    except OSError as exc:
        return f"cannot read {left}: {exc}"
    try:
        right_bytes = right.read_bytes()
    except OSError as exc:
        return f"cannot read peer contract {right}: {exc}"
    if left_bytes == right_bytes:
        return None
    return f"Protocol contract drift: {right} is not byte-identical to {left}"


def validate_path(path: Path) -> list[str]:
    try:
        contract = load_contract(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"cannot load {path}: {exc}"]
    return semantic_errors(contract)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    local = default_contract_path()
    errors = validate_path(local)
    if errors:
        for item in errors:
            print(f"error: {item}", file=sys.stderr)
        print(f"Invalid Onyx protocol contract: {local}", file=sys.stderr)
        return 1

    if args:
        peer = Path(args[0])
        drift = compare_bytes(local, peer)
        if drift:
            print(f"error: {drift}", file=sys.stderr)
            return 1
        print(f"Protocol contract valid: {local} = {peer}")
        return 0

    print(f"Protocol contract valid: {local}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
