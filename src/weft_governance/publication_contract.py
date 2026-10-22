# -*- coding: utf-8 -*-
# Copyright 2026 The WEFT Project
# SPDX-License-Identifier: Apache-2.0
"""Deterministic public-action authorization contract.

The contract evaluates already-supplied action metadata. It does not inspect
files, call a model, execute commands, store approvals, or contact a network.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable


CONTRACT_SCHEMA = "publication-contract/v1"
POLICY_VERSION = "2.0.0"
APPROVAL_PREFIX = "APPROVE_PUBLIC_ACTION"

ACTION_TYPES = frozenset(
    {
        "commit",
        "push",
        "comment",
        "issue",
        "pull_request",
        "email",
        "upload",
        "publish",
        "visibility",
        "generic",
    }
)

MINIMUM_TARGET_MATCHES = {
    "commit": 0,
    "push": 2,
    "comment": 2,
    "issue": 2,
    "pull_request": 2,
    "email": 1,
    "upload": 1,
    "publish": 1,
    "visibility": 2,
    "generic": 2,
}

HARD_BLOCK_FLAGS = frozenset(
    {
        "content_unavailable",
        "credential_or_secret",
        "gate_bypass",
        "private_source_overlap",
        "scan_incomplete",
    }
)

SENSITIVE_APPROVAL_FLAGS = frozenset(
    {
        "core_material",
        "first_time_target",
        "identity_metadata",
        "scope_ambiguous",
        "unrecoverable_without_owner",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)


class ContractError(ValueError):
    """Raised when publication metadata is structurally invalid."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError("%s must be a non-empty string" % field)
    return value.strip()


def hash_public_payload(payload: str | bytes) -> str:
    """Hash exact public payload bytes without retaining their contents."""
    if isinstance(payload, str):
        data = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        data = payload
    else:
        raise ContractError("payload must be str or bytes")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class PublicationAction:
    """One immutable public action proposed for execution."""

    action_type: str
    target: str
    payload_sha256: str
    source: str = "caller-supplied"

    def __post_init__(self) -> None:
        action_type = _require_nonempty_string(
            self.action_type, "action_type"
        ).lower()
        if action_type not in ACTION_TYPES:
            raise ContractError("unsupported action_type: %s" % action_type)
        object.__setattr__(self, "action_type", action_type)
        object.__setattr__(
            self,
            "target",
            _require_nonempty_string(self.target, "target"),
        )
        payload_sha256 = _require_nonempty_string(
            self.payload_sha256, "payload_sha256"
        ).lower()
        if not _SHA256.fullmatch(payload_sha256):
            raise ContractError("payload_sha256 must be a 64-character SHA256")
        object.__setattr__(self, "payload_sha256", payload_sha256)
        object.__setattr__(
            self,
            "source",
            _require_nonempty_string(self.source, "source"),
        )

    @property
    def required_target_matches(self) -> int:
        return MINIMUM_TARGET_MATCHES[self.action_type]

    def manifest(self) -> dict[str, Any]:
        return {
            "schema_version": CONTRACT_SCHEMA,
            "policy_version": POLICY_VERSION,
            "action_type": self.action_type,
            "target": self.target,
            "payload_sha256": self.payload_sha256,
            "source": self.source,
        }

    @property
    def manifest_sha256(self) -> str:
        return _sha256_text(_canonical_json(self.manifest()))


@dataclass(frozen=True)
class OwnerAuthorization:
    """Owner intent or an already-approved exact manifest hash."""

    explicit_action: bool = False
    matched_targets: int = 0
    approved_manifest_sha256: str | None = None
    owner_message_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.explicit_action, bool):
            raise ContractError("explicit_action must be boolean")
        if not isinstance(self.matched_targets, int) or self.matched_targets < 0:
            raise ContractError("matched_targets must be a non-negative integer")
        for field in ("approved_manifest_sha256", "owner_message_sha256"):
            value = getattr(self, field)
            if value is not None:
                if not _SHA256.fullmatch(value):
                    raise ContractError(
                        "%s must be a 64-character SHA256" % field
                    )
                object.__setattr__(self, field, value.lower())


def _normalize_risk_flags(flags: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for item in flags:
        if not isinstance(item, str) or not item.strip():
            raise ContractError("risk flags must be non-empty strings")
        value = item.strip().lower()
        if value not in normalized:
            normalized.append(value)
    return tuple(sorted(normalized))


def evaluate_publication(
    action: PublicationAction,
    authorization: OwnerAuthorization,
    *,
    risk_flags: Iterable[str] = (),
) -> dict[str, Any]:
    """Return AUTO_SEND, REQUIRE_OWNER_APPROVAL, or BLOCK deterministically."""
    if not isinstance(action, PublicationAction):
        raise ContractError("action must be PublicationAction")
    if not isinstance(authorization, OwnerAuthorization):
        raise ContractError("authorization must be OwnerAuthorization")

    flags = _normalize_risk_flags(risk_flags)
    manifest = action.manifest()
    manifest_sha256 = action.manifest_sha256
    base = {
        "schema_version": CONTRACT_SCHEMA,
        "policy_version": POLICY_VERSION,
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "required_target_matches": action.required_target_matches,
        "risk_flags": list(flags),
        "owner_authorization": {
            "explicit_action": authorization.explicit_action,
            "matched_targets": authorization.matched_targets,
            "owner_message_sha256": authorization.owner_message_sha256,
            "approved_manifest_sha256": (
                authorization.approved_manifest_sha256
            ),
        },
    }

    hard_flags = sorted(set(flags) & HARD_BLOCK_FLAGS)
    if hard_flags:
        return {
            **base,
            "decision": "BLOCK",
            "reason": "hard_risk",
            "hard_risk_flags": hard_flags,
            "approval_command": None,
            "execution_authorized": False,
        }

    if authorization.approved_manifest_sha256 == manifest_sha256:
        return {
            **base,
            "decision": "AUTO_SEND",
            "reason": "approved_exact_manifest",
            "hard_risk_flags": [],
            "approval_command": None,
            "execution_authorized": True,
        }

    known_flags = HARD_BLOCK_FLAGS | SENSITIVE_APPROVAL_FLAGS
    sensitive_flags = sorted(
        (set(flags) & SENSITIVE_APPROVAL_FLAGS)
        | (set(flags) - known_flags)
    )
    if not sensitive_flags and authorization.explicit_action:
        if authorization.matched_targets >= action.required_target_matches:
            return {
                **base,
                "decision": "AUTO_SEND",
                "reason": "explicit_owner_intent",
                "hard_risk_flags": [],
                "approval_command": None,
                "execution_authorized": True,
            }

    return {
        **base,
        "decision": "REQUIRE_OWNER_APPROVAL",
        "reason": (
            "sensitive_risk_flag"
            if sensitive_flags
            else "explicit_owner_approval_required"
        ),
        "hard_risk_flags": [],
        "approval_command": "%s %s" % (APPROVAL_PREFIX, manifest_sha256),
        "execution_authorized": False,
    }
