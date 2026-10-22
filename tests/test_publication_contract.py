# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the deterministic publication contract."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weft_governance.publication_contract import (  # noqa: E402
    ContractError,
    OwnerAuthorization,
    PublicationAction,
    evaluate_publication,
    hash_public_payload,
)


PAYLOAD = "safe synthetic public payload"
PAYLOAD_SHA = hashlib.sha256(PAYLOAD.encode("utf-8")).hexdigest()


def action(
    action_type: str = "push",
    target: str = "owner/repo main",
    payload_sha: str = PAYLOAD_SHA,
) -> PublicationAction:
    return PublicationAction(
        action_type=action_type,
        target=target,
        payload_sha256=payload_sha,
    )


class PublicationContractTests(unittest.TestCase):
    def test_explicit_push_with_two_target_matches_is_auto_send(self):
        result = evaluate_publication(
            action(),
            OwnerAuthorization(explicit_action=True, matched_targets=2),
        )
        self.assertEqual("AUTO_SEND", result["decision"])
        self.assertEqual("explicit_owner_intent", result["reason"])
        self.assertTrue(result["execution_authorized"])

    def test_push_with_one_target_match_requires_approval(self):
        result = evaluate_publication(
            action(),
            OwnerAuthorization(explicit_action=True, matched_targets=1),
        )
        self.assertEqual("REQUIRE_OWNER_APPROVAL", result["decision"])
        self.assertIn("APPROVE_PUBLIC_ACTION", result["approval_command"])

    def test_commit_can_be_direct_without_target_tokens(self):
        result = evaluate_publication(
            action("commit", "local repository"),
            OwnerAuthorization(explicit_action=True, matched_targets=0),
        )
        self.assertEqual("AUTO_SEND", result["decision"])

    def test_exact_manifest_approval_unlocks_ambiguous_action(self):
        pending = action("comment", "issue #7 owner/repo")
        manifest_hash = pending.manifest_sha256
        result = evaluate_publication(
            pending,
            OwnerAuthorization(
                approved_manifest_sha256=manifest_hash.upper(),
                owner_message_sha256=hashlib.sha256(
                    b"synthetic owner approval"
                ).hexdigest(),
            ),
        )
        self.assertEqual("AUTO_SEND", result["decision"])
        self.assertEqual("approved_exact_manifest", result["reason"])
        self.assertEqual(
            manifest_hash,
            result["owner_authorization"]["approved_manifest_sha256"],
        )

    def test_changed_payload_invalidates_old_manifest_approval(self):
        original = action()
        new_payload_sha = hash_public_payload(PAYLOAD + " changed")
        changed = action(payload_sha=new_payload_sha)
        result = evaluate_publication(
            changed,
            OwnerAuthorization(
                approved_manifest_sha256=original.manifest_sha256
            ),
        )
        self.assertEqual("REQUIRE_OWNER_APPROVAL", result["decision"])

    def test_hard_risk_flags_block_even_with_exact_approval(self):
        pending = action("comment", "issue #7 owner/repo")
        result = evaluate_publication(
            pending,
            OwnerAuthorization(
                approved_manifest_sha256=pending.manifest_sha256
            ),
            risk_flags={"private_source_overlap"},
        )
        self.assertEqual("BLOCK", result["decision"])
        self.assertFalse(result["execution_authorized"])

    def test_sensitive_flags_require_approval_even_with_direct_intent(self):
        result = evaluate_publication(
            action(),
            OwnerAuthorization(explicit_action=True, matched_targets=2),
            risk_flags={"core_material"},
        )
        self.assertEqual("REQUIRE_OWNER_APPROVAL", result["decision"])

    def test_unknown_risk_flag_is_conservative(self):
        result = evaluate_publication(
            action(),
            OwnerAuthorization(explicit_action=True, matched_targets=2),
            risk_flags={"risk_name_from_future_policy"},
        )
        self.assertEqual("REQUIRE_OWNER_APPROVAL", result["decision"])

    def test_content_unavailable_is_absolute_block(self):
        result = evaluate_publication(
            action(),
            OwnerAuthorization(
                explicit_action=True,
                matched_targets=2,
                approved_manifest_sha256=action().manifest_sha256,
            ),
            risk_flags={"content_unavailable"},
        )
        self.assertEqual("BLOCK", result["decision"])

    def test_result_is_stable_and_contains_no_payload(self):
        item = action()
        first = evaluate_publication(
            item,
            OwnerAuthorization(explicit_action=True, matched_targets=2),
        )
        second = evaluate_publication(
            item,
            OwnerAuthorization(explicit_action=True, matched_targets=2),
        )
        self.assertEqual(first, second)
        self.assertNotIn(PAYLOAD, str(first))
        self.assertEqual(PAYLOAD_SHA, first["manifest"]["payload_sha256"])

    def test_invalid_payload_hash_is_rejected(self):
        with self.assertRaises(ContractError):
            action(payload_sha="not-a-hash")

    def test_package_version_is_2_0_0(self):
        import weft_governance

        self.assertEqual("2.0.0", weft_governance.__version__)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        PublicationContractTests
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = "PUBLICATION_CONTRACT_TESTS_" + (
        "PASS" if result.wasSuccessful() else "FAIL"
    )
    print(summary)
    raise SystemExit(0 if result.wasSuccessful() else 1)
