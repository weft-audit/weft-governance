# -*- coding: utf-8 -*-
# Copyright 2026 The WEFT Project
# SPDX-License-Identifier: Apache-2.0
"""Deterministic trust boundaries for context entering WEFT.

This module classifies already-supplied records. It does not discover files,
call a model, execute commands, or grant capabilities. Project instructions
remain reference data unless the deployment explicitly supplies them as a
trusted core policy source.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


TRUST_BOUNDARY_SCHEMA = "trust-context/v0"
TRUST_BOUNDARY_VERSION = "0.1.0"

CORE_POLICY = "core_policy"
OWNER_INTENT = "owner_intent"
PROJECT_FACT = "project_fact"
PROJECT_INSTRUCTION = "project_instruction"
UNTRUSTED_CONTEXT = "untrusted_context"

TRUST_LEVELS = (
    CORE_POLICY,
    OWNER_INTENT,
    PROJECT_FACT,
    PROJECT_INSTRUCTION,
    UNTRUSTED_CONTEXT,
)
TRUST_RANK = {
    CORE_POLICY: 4,
    OWNER_INTENT: 3,
    PROJECT_FACT: 2,
    PROJECT_INSTRUCTION: 1,
    UNTRUSTED_CONTEXT: 0,
}
DIRECTIVE_LEVELS = frozenset({CORE_POLICY, OWNER_INTENT})
DATA_ONLY_LEVELS = frozenset(
    {PROJECT_FACT, PROJECT_INSTRUCTION, UNTRUSTED_CONTEXT}
)
PROJECT_RECORD_KINDS = frozenset({"fact", "instruction"})
PROJECT_INSTRUCTION_FILES = frozenset(
    {"agents.md", "claude.md", "manifesto.md"}
)
PROTECTED_DIMENSIONS = (
    "core_policy",
    "tool_permissions",
    "network_permissions",
    "filesystem_scope",
    "approval_state",
)


class TrustBoundaryError(ValueError):
    """Raised when the supplied envelope input is structurally invalid."""


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _canonical_source(value: str) -> str:
    source = value.strip().replace("\\", "/")
    while source.startswith("./"):
        source = source[2:]
    return source


def _source_basename(source: str) -> str:
    return source.rsplit("/", 1)[-1].lower()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise TrustBoundaryError("value must be JSON-serializable") from exc


def _record_sequence(value: Any, field: str) -> list[Mapping[str, Any]]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TrustBoundaryError("%s must be a sequence of objects" % field)
    records: list[Mapping[str, Any]] = []
    for index, item in enumerate(value, 1):
        if not isinstance(item, Mapping):
            raise TrustBoundaryError("%s[%d] must be an object" % (field, index))
        records.append(item)
    return records


def _trusted_sources(value: Any) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        return set(), ["trusted_core_sources must be a sequence"]
    sources: set[str] = set()
    for index, item in enumerate(value, 1):
        if not _is_nonempty_str(item):
            errors.append(
                "trusted_core_sources[%d] must be a non-empty string" % index
            )
            continue
        sources.add(_canonical_source(item))
    if not sources:
        errors.append("no trusted core-policy source is configured")
    return sources, errors


def _record_fields(
    record: Mapping[str, Any],
    field: str,
    index: int,
) -> tuple[str | None, str | None, list[str]]:
    errors: list[str] = []
    source_value = record.get("source")
    content = record.get("content")
    if not _is_nonempty_str(source_value):
        errors.append("%s[%d].source must be a non-empty string" % (field, index))
        source = None
    else:
        source = _canonical_source(source_value)
    if not _is_nonempty_str(content):
        errors.append("%s[%d].content must be a non-empty string" % (field, index))
        content = None
    return source, content, errors


def _entry(
    *,
    source: str,
    content: str,
    trust_level: str,
    kind: str,
    requested_capabilities: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    identity = {
        "content_sha256": content_sha256,
        "kind": kind,
        "requested_capabilities": requested_capabilities,
        "source": source,
        "trust_level": trust_level,
    }
    entry_id = hashlib.sha256(
        _canonical_json(identity).encode("utf-8")
    ).hexdigest()[:16]
    directive_eligible = trust_level in DIRECTIVE_LEVELS
    return {
        "entry_id": entry_id,
        "source": source,
        "trust_level": trust_level,
        "trust_rank": TRUST_RANK[trust_level],
        "kind": kind,
        "directive_eligible": directive_eligible,
        "role": "directive" if directive_eligible else "reference_data",
        "content": content,
        "content_sha256": content_sha256,
    }


def _capability_request(
    *,
    entry: Mapping[str, Any],
    requested_capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "source": entry["source"],
        "trust_level": entry["trust_level"],
        "content_sha256": entry["content_sha256"],
        "requested_capabilities": dict(requested_capabilities),
        "applied": False,
    }


def _record_capabilities(
    record: Mapping[str, Any],
    field: str,
    index: int,
) -> tuple[Mapping[str, Any] | None, list[str]]:
    value = record.get("requested_capabilities")
    if value is None:
        return None, []
    if not isinstance(value, Mapping):
        return None, [
            "%s[%d].requested_capabilities must be an object" % (field, index)
        ]
    try:
        _canonical_json(value)
    except TrustBoundaryError:
        return None, [
            "%s[%d].requested_capabilities must be JSON-serializable"
            % (field, index)
        ]
    return value, []


def _dedupe_entries(entries: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for entry in entries:
        unique[entry["entry_id"]] = entry
    return sorted(
        unique.values(),
        key=lambda item: (
            -item["trust_rank"],
            item["source"],
            item["content_sha256"],
            item["kind"],
        ),
    )


def build_context_envelope(
    *,
    core_policies: Sequence[Mapping[str, Any]],
    trusted_core_sources: Sequence[str],
    owner_intent: Mapping[str, Any] | None = None,
    project_records: Sequence[Mapping[str, Any]] = (),
    untrusted_records: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build a deterministic context envelope from supplied records.

    A record becomes a directive only when it is an accepted core policy or
    the owner intent. Project instructions are always reference data, even if
    they request capabilities or claim to replace a higher-level rule.
    """
    errors: list[str] = []
    rejections: list[dict[str, str]] = []
    entries: list[dict[str, Any]] = []
    capability_requests: list[dict[str, Any]] = []

    trusted_sources, trusted_errors = _trusted_sources(trusted_core_sources)
    errors.extend(trusted_errors)

    try:
        core_records = _record_sequence(core_policies, "core_policies")
        project_sequence = _record_sequence(project_records, "project_records")
        untrusted_sequence = _record_sequence(
            untrusted_records, "untrusted_records"
        )
    except TrustBoundaryError as exc:
        errors.append(str(exc))
        core_records = []
        project_sequence = []
        untrusted_sequence = []

    accepted_core_count = 0
    for index, record in enumerate(core_records, 1):
        source, content, record_errors = _record_fields(
            record, "core_policies", index
        )
        errors.extend(record_errors)
        requested, capability_errors = _record_capabilities(
            record, "core_policies", index
        )
        errors.extend(capability_errors)
        if source is None or content is None:
            continue
        if _source_basename(source) in PROJECT_INSTRUCTION_FILES:
            reason = "project_instruction_file_cannot_be_core_policy"
            rejections.append({"source": source, "reason": reason})
            errors.append("core policy rejected for %s: %s" % (source, reason))
            continue
        if source not in trusted_sources:
            reason = "core_policy_source_not_trusted"
            rejections.append({"source": source, "reason": reason})
            errors.append("core policy rejected for %s: %s" % (source, reason))
            continue
        accepted_core_count += 1
        entry = _entry(
            source=source,
            content=content,
            trust_level=CORE_POLICY,
            kind="policy",
            requested_capabilities=requested,
        )
        entries.append(entry)
        if requested is not None:
            capability_requests.append(
                _capability_request(
                    entry=entry, requested_capabilities=requested
                )
            )

    if accepted_core_count == 0:
        errors.append("at least one trusted core policy is required")

    if owner_intent is not None:
        if not isinstance(owner_intent, Mapping):
            errors.append("owner_intent must be an object")
        else:
            source, content, record_errors = _record_fields(
                owner_intent, "owner_intent", 1
            )
            errors.extend(record_errors)
            requested, capability_errors = _record_capabilities(
                owner_intent, "owner_intent", 1
            )
            errors.extend(capability_errors)
            if source is not None and content is not None:
                entry = _entry(
                    source=source,
                    content=content,
                    trust_level=OWNER_INTENT,
                    kind="intent",
                    requested_capabilities=requested,
                )
                entries.append(entry)
                if requested is not None:
                    capability_requests.append(
                        _capability_request(
                            entry=entry, requested_capabilities=requested
                        )
                    )

    for index, record in enumerate(project_sequence, 1):
        source, content, record_errors = _record_fields(
            record, "project_records", index
        )
        errors.extend(record_errors)
        requested, capability_errors = _record_capabilities(
            record, "project_records", index
        )
        errors.extend(capability_errors)
        if source is None or content is None:
            continue
        declared_kind = record.get("kind", "fact")
        if declared_kind not in PROJECT_RECORD_KINDS:
            errors.append(
                "project_records[%d].kind must be fact or instruction" % index
            )
            continue
        if _source_basename(source) in PROJECT_INSTRUCTION_FILES:
            declared_kind = "instruction"
        trust_level = (
            PROJECT_INSTRUCTION
            if declared_kind == "instruction"
            else PROJECT_FACT
        )
        entry = _entry(
            source=source,
            content=content,
            trust_level=trust_level,
            kind=declared_kind,
            requested_capabilities=requested,
        )
        entries.append(entry)
        if requested is not None:
            capability_requests.append(
                _capability_request(
                    entry=entry, requested_capabilities=requested
                )
            )

    for index, record in enumerate(untrusted_sequence, 1):
        source, content, record_errors = _record_fields(
            record, "untrusted_records", index
        )
        errors.extend(record_errors)
        requested, capability_errors = _record_capabilities(
            record, "untrusted_records", index
        )
        errors.extend(capability_errors)
        if source is None or content is None:
            continue
        entry = _entry(
            source=source,
            content=content,
            trust_level=UNTRUSTED_CONTEXT,
            kind="external_context",
            requested_capabilities=requested,
        )
        entries.append(entry)
        if requested is not None:
            capability_requests.append(
                _capability_request(
                    entry=entry, requested_capabilities=requested
                )
            )

    entries = _dedupe_entries(entries)
    capability_requests = sorted(
        capability_requests,
        key=lambda item: (
            -TRUST_RANK[item["trust_level"]],
            item["source"],
            item["content_sha256"],
            _canonical_json(item["requested_capabilities"]),
        ),
    )
    unique_errors: list[str] = []
    for error in errors:
        if error not in unique_errors:
            unique_errors.append(error)
    unique_errors.sort()
    rejections = sorted(
        rejections, key=lambda item: (item["source"], item["reason"])
    )
    directive_entry_ids = [
        entry["entry_id"] for entry in entries if entry["directive_eligible"]
    ]
    reference_entry_ids = [
        entry["entry_id"] for entry in entries if not entry["directive_eligible"]
    ]

    envelope: dict[str, Any] = {
        "schema_version": TRUST_BOUNDARY_SCHEMA,
        "trust_boundary_version": TRUST_BOUNDARY_VERSION,
        "state": "BLOCKED" if unique_errors else "READY",
        "execution_authorized": False,
        "entries": entries,
        "directive_entry_ids": directive_entry_ids,
        "reference_entry_ids": reference_entry_ids,
        "authority": {
            "directive_order": [CORE_POLICY, OWNER_INTENT],
            "directive_levels": [CORE_POLICY, OWNER_INTENT],
            "data_only_levels": [
                PROJECT_FACT,
                PROJECT_INSTRUCTION,
                UNTRUSTED_CONTEXT,
            ],
            "capability_grants_allowed_by_boundary": False,
            "protected_dimensions": list(PROTECTED_DIMENSIONS),
        },
        "capability_guard": {
            "ignored_requests": capability_requests,
            "ignored_request_count": len(capability_requests),
        },
        "validation": {
            "errors": unique_errors,
            "rejected_core_policies": rejections,
            "accepted_core_policy_count": accepted_core_count,
            "model_used": False,
            "files_read": 0,
            "commands_executed": 0,
        },
    }
    envelope["envelope_sha256"] = hashlib.sha256(
        _canonical_json(envelope).encode("utf-8")
    ).hexdigest()
    return envelope
