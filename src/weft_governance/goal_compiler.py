# -*- coding: utf-8 -*-
# Copyright 2026 The WEFT Project
# SPDX-License-Identifier: Apache-2.0
"""Deterministic Goal Compiler V0.

V0 compiles an explicit intent record into a reviewable goal specification.
It does not call a model, inspect project files, execute commands, or grant
approval. Missing facts stay missing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any


INPUT_SCHEMA = "goal-intent/v0"
OUTPUT_SCHEMA = "goal-spec/v0"
COMPILER_VERSION = "0.1.1"
MAX_BLOCKING_QUESTIONS = 3

ALLOWED_SCOPES = frozenset({"this_task", "standing_rule"})
ALLOWED_RISK_LEVELS = frozenset({"low", "medium", "high"})
ALLOWED_APPROVAL_STATUSES = frozenset({"pending", "granted", "denied"})
ALLOWED_VERIFICATION_TYPES = frozenset({"command", "manual"})

MANDATORY_FORBIDDEN_ACTIONS = (
    "读取或写入 .credentials.yaml、密钥文件或任何凭据",
    "修改 config.toml 的 model、model_provider 或密钥字段",
    "修改注册表、hosts 或防火墙",
    "未经所有者逐次批准启动、停止或重启常驻服务",
    "未展示 diff 且未获所有者批准时执行 git commit",
    "未经所有者批准时执行 git push、发布、上传或对外发送",
    "把推测写成事实，或替所有者补写其意图",
)

HARD_REDLINES = (
    ("secret_file", re.compile(r"\.credentials|凭据文件|密钥文件|api[_ -]?key\.txt", re.I)),
    ("registry", re.compile(r"注册表|regedit", re.I)),
    ("hosts_file", re.compile(r"\bhosts\b", re.I)),
    ("firewall", re.compile(r"防火墙|firewall", re.I)),
    ("dangerous_disk", re.compile(r"\bdiskpart\b|\bformat\b|格式化磁盘", re.I)),
    ("destructive_git", re.compile(r"git\s+reset\s+--hard|git\s+push\s+--force", re.I)),
    ("shell_wipe", re.compile(r"rm\s+-rf", re.I)),
    ("system_directory", re.compile(r"c:\\windows|c:\\program files|系统目录", re.I)),
)

SENSITIVE_CONFIG = re.compile(
    r"(?:config\.toml).*(?:model_provider|model|密钥|api[_ -]?key)"
    r"|(?:model_provider|model|密钥|api[_ -]?key).*(?:config\.toml)",
    re.I,
)

SERVICE_CHANGE = re.compile(
    r"(?:启动|停止|重启|启停).{0,8}服务|服务.{0,8}(?:启动|停止|重启|启停)|"
    r"start-service|stop-service|"
    r"restart-service|start-process|stop-process",
    re.I,
)
GIT_COMMIT = re.compile(r"git\s+commit", re.I)
GIT_PUSH = re.compile(r"git\s+push", re.I)
EXTERNAL_WRITE = re.compile(
    r"发布|上传|发送邮件|发邮件|部署|对外提交|push|publish|deploy",
    re.I,
)
DESTRUCTIVE = re.compile(
    r"删除|删掉|移除|clear-content|remove-item|(?:^|\s)del(?:\s|$)",
    re.I,
)


class IntakeError(ValueError):
    """Raised for input that is not a Goal Compiler V0 JSON object."""


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value)


def _texts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if _is_nonempty_str(item)]


def _flatten_task_text(tasks: Any) -> str:
    if not isinstance(tasks, list):
        return ""
    fields: list[str] = []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        for key in ("id", "description", "owner"):
            value = task.get(key)
            if isinstance(value, str):
                fields.append(value)
    return "\n".join(fields)


def _excerpt(text: str, limit: int = 80) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _scan_text(data: dict[str, Any]) -> str:
    intent = data.get("intent")
    goal = data.get("goal")
    parts = []
    if isinstance(intent, dict):
        parts.extend(str(intent.get(key) or "") for key in ("raw_text",))
    if isinstance(goal, dict):
        parts.extend(str(goal.get(key) or "") for key in ("summary", "success_state"))
    parts.append(_flatten_task_text(data.get("tasks")))
    return "\n".join(parts)


def _match_redlines(scan_text: str) -> list[str]:
    matches = [
        rule_name
        for rule_name, pattern in HARD_REDLINES
        if pattern.search(scan_text)
    ]
    if SENSITIVE_CONFIG.search(scan_text):
        matches.append("sensitive_config")
    return sorted(set(matches))


def _path_problem(raw_path: str) -> str | None:
    stripped = raw_path.strip()
    if not stripped:
        return "路径为空"
    if "*" in stripped or "?" in stripped:
        return "写入路径不得包含通配符"
    windows_path = PureWindowsPath(stripped)
    if windows_path.drive and os.name != "nt":
        return "Windows drive paths are not supported on this platform"
    if ".." in re.split(r"[\\/]+", stripped):
        return "路径不得包含 .."
    if windows_path.drive and windows_path == PureWindowsPath(windows_path.anchor):
        return "禁止使用磁盘或文件系统根目录"
    if stripped == "/":
        return "禁止使用文件系统根目录"
    return None


def _absolute_path(raw_path: str, workspace: Path) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        path = workspace / path
    return path.resolve(strict=False)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _approval_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    approvals = data.get("approval_points")
    if not isinstance(approvals, list):
        return []
    return [item for item in approvals if isinstance(item, dict)]


def _approval_status(data: dict[str, Any], phase: str) -> str:
    entries = [
        item for item in _approval_entries(data)
        if item.get("phase") == phase
    ]
    if any(item.get("status") == "denied" for item in entries):
        return "denied"
    if any(item.get("status") == "granted" for item in entries):
        return "granted"
    return "pending"


def _validate_tasks(tasks: Any) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    questions: list[str] = []
    if not _nonempty_list(tasks):
        return [], ["任务表为空：请说明第一步、负责人和依赖。"]

    ids: list[str] = []
    dependencies: dict[str, list[str]] = {}
    for index, task in enumerate(tasks, 1):
        if not isinstance(task, dict):
            errors.append("tasks[%d] 不是对象" % index)
            continue
        task_id = task.get("id")
        if not _is_nonempty_str(task_id):
            errors.append("tasks[%d].id 缺失" % index)
            continue
        if task_id in ids:
            errors.append("任务 ID 重复：%s" % task_id)
        ids.append(task_id)
        dependencies[task_id] = _texts(task.get("depends_on"))
        if not _is_nonempty_str(task.get("description")):
            questions.append("任务 %s 缺少可执行描述。" % task_id)
        if not _is_nonempty_str(task.get("owner")):
            questions.append("任务 %s 没有明确负责人。" % task_id)

    for task_id, deps in dependencies.items():
        unknown = sorted(set(deps) - set(ids))
        if unknown:
            errors.append("任务 %s 引用了不存在的依赖：%s" % (task_id, ", ".join(unknown)))

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> bool:
        if task_id in visiting:
            return True
        if task_id in visited:
            return False
        visiting.add(task_id)
        for dependency in dependencies.get(task_id, []):
            if dependency in dependencies and visit(dependency):
                return True
        visiting.remove(task_id)
        visited.add(task_id)
        return False

    if any(visit(task_id) for task_id in dependencies):
        errors.append("任务依赖存在环")
    return errors, questions


def _validate_verification(items: Any) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    questions: list[str] = []
    if not _nonempty_list(items):
        return errors, ["没有验收项：请给出命令或人工检查标准。"]
    seen: set[str] = set()
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            errors.append("verification[%d] 不是对象" % index)
            continue
        check_id = item.get("id")
        if not _is_nonempty_str(check_id):
            errors.append("verification[%d].id 缺失" % index)
        elif check_id in seen:
            errors.append("验收 ID 重复：%s" % check_id)
        else:
            seen.add(check_id)
        check_type = item.get("type")
        if check_type not in ALLOWED_VERIFICATION_TYPES:
            errors.append("verification[%d].type 必须是 command 或 manual" % index)
        if not _is_nonempty_str(item.get("description")):
            questions.append("验收项 %s 缺少说明。" % (check_id or index))
        if not _is_nonempty_str(item.get("expected")):
            questions.append("验收项 %s 缺少预期结果。" % (check_id or index))
        if check_type == "command" and not _is_nonempty_str(item.get("command")):
            questions.append("命令验收项 %s 缺少实际命令。" % (check_id or index))
    return errors, questions


def _validate_approvals(
    data: dict[str, Any],
    required_phases: set[str],
) -> tuple[list[str], list[str], dict[str, str]]:
    errors: list[str] = []
    questions: list[str] = []
    statuses: dict[str, str] = {}
    approvals = data.get("approval_points")
    if not _nonempty_list(approvals):
        questions.append("没有批准点：下游执行前必须由所有者明确批准。")
        approvals = []

    seen_ids: set[str] = set()
    for index, item in enumerate(approvals, 1):
        if not isinstance(item, dict):
            errors.append("approval_points[%d] 不是对象" % index)
            continue
        approval_id = item.get("id")
        if not _is_nonempty_str(approval_id):
            errors.append("approval_points[%d].id 缺失" % index)
        elif approval_id in seen_ids:
            errors.append("批准点 ID 重复：%s" % approval_id)
        else:
            seen_ids.add(approval_id)
        phase = item.get("phase")
        if not _is_nonempty_str(phase):
            errors.append("approval_points[%d].phase 缺失" % index)
        if item.get("required_from") != "owner":
            errors.append("批准点 %s 的 required_from 必须是 owner" % (approval_id or index))
        status = item.get("status")
        if status not in ALLOWED_APPROVAL_STATUSES:
            errors.append("批准点 %s 的 status 无效" % (approval_id or index))
        if status == "granted" and not _is_nonempty_str(item.get("evidence")):
            questions.append("批准点 %s 标为 granted，但没有批准证据。" % (approval_id or index))

    for phase in sorted(required_phases):
        status = _approval_status(data, phase)
        statuses[phase] = status
        if status == "denied":
            errors.append("所有者已拒绝批准点：%s" % phase)
        elif status == "pending":
            questions.append("缺少所有者已批准证据：%s。" % phase)
    return errors, questions, statuses


def _collect_blocking_questions(
    data: dict[str, Any],
) -> tuple[list[str], list[str], set[str], dict[str, str]]:
    errors: list[str] = []
    questions: list[str] = []
    required_phases: set[str] = {"before_execute"}

    if data.get("schema_version") is None:
        questions.append("缺少 schema_version：调用方没有提供 V0 输入格式。")
    elif data.get("schema_version") != INPUT_SCHEMA:
        errors.append("schema_version 必须为 %s" % INPUT_SCHEMA)
    if not _is_nonempty_str(data.get("intent_id")):
        questions.append("缺少 intent_id：这份规格无法被唯一追踪。")

    intent = data.get("intent")
    if intent is None:
        questions.append("缺少 intent 对象：无法取得所有者原话。")
        intent = {}
    elif not isinstance(intent, dict):
        errors.append("intent 必须是对象")
        intent = {}
    if not _is_nonempty_str(intent.get("raw_text")):
        questions.append("缺少所有者原始意图：不能由编译器代为补写。")
    raw_text = str(intent.get("raw_text") or "").strip()
    if not _is_nonempty_str(intent.get("said_at")):
        questions.append("缺少所有者原话日期：请按 YYYY-MM-DD 补证。")
    if intent.get("scope") is None:
        questions.append("缺少 intent.scope：请确认这是本次任务还是长期规则。")
    elif intent.get("scope") not in ALLOWED_SCOPES:
        errors.append("intent.scope 必须是 this_task 或 standing_rule")

    goal = data.get("goal")
    if goal is None:
        goal = {}
    elif not isinstance(goal, dict):
        errors.append("goal 必须是对象")
        goal = {}
    if not _is_nonempty_str(goal.get("summary")):
        if raw_text:
            questions.append(
                "目标摘要尚未由所有者确认：是否直接采用原话“%s”？"
                "如不采用，请给出改写。" % _excerpt(raw_text)
            )
        else:
            questions.append("目标不明确：请用一句话说明最后要实现什么。")
    if not _is_nonempty_str(goal.get("success_state")):
        questions.append("成功状态不明确：请说明这项任务完成时可观察的结果。")

    for key, label in (
        ("non_goals", "非目标"),
        ("constraints", "已知约束"),
        ("current_state_refs", "当前状态引用"),
        ("read_paths", "读取范围"),
        ("write_paths", "写入范围"),
        ("evidence_paths", "证据路径"),
    ):
        value = data.get(key)
        if not _nonempty_list(value):
            questions.append("%s为空：若这次任务确实不做，请明确填写“无”。" % label)
        elif not _texts(value):
            questions.append("%s没有有效文本。" % label)

    workspace_text = data.get("workspace")
    workspace: Path | None = None
    if not _is_nonempty_str(workspace_text):
        questions.append("缺少工作区：无法判断路径边界。")
    else:
        workspace = Path(workspace_text).resolve(strict=False)

    write_paths = _texts(data.get("write_paths"))
    if write_paths:
        required_phases.add("before_write")
    resolved_write_paths: list[Path] = []
    for raw_path in write_paths:
        problem = _path_problem(raw_path)
        if problem:
            errors.append("写入路径 %r 不安全：%s" % (raw_path, problem))
            continue
        if workspace is None:
            continue
        absolute = _absolute_path(raw_path, workspace)
        resolved_write_paths.append(absolute)
        if not _is_relative_to(absolute, workspace):
            required_phases.add("before_external_write")

    evidence_paths = _texts(data.get("evidence_paths"))
    if workspace is not None:
        for raw_evidence in evidence_paths:
            if raw_evidence.lower() == "stdout":
                continue
            evidence_absolute = _absolute_path(raw_evidence, workspace)
            if not resolved_write_paths:
                if _nonempty_list(data.get("write_paths")):
                    errors.append(
                        "证据路径没有可用的写入范围：%s" % raw_evidence
                    )
                else:
                    questions.append(
                        "证据路径已声明，但写入范围为空：%s" % raw_evidence
                    )
                continue
            if not any(
                _is_relative_to(evidence_absolute, item)
                for item in resolved_write_paths
            ):
                errors.append(
                    "证据路径不在已声明的写入范围内：%s" % raw_evidence
                )

    task_errors, task_questions = _validate_tasks(data.get("tasks"))
    verification_errors, verification_questions = _validate_verification(
        data.get("verification")
    )
    errors.extend(task_errors)
    errors.extend(verification_errors)
    questions.extend(task_questions)
    questions.extend(verification_questions)

    rollback = data.get("rollback")
    if not isinstance(rollback, dict):
        questions.append("缺少回滚方案：没有退路不得进入执行。")
        rollback = {}
    if not _is_nonempty_str(rollback.get("strategy")):
        questions.append("回滚策略为空：请说明失败后如何恢复。")
    if not _is_nonempty_str(rollback.get("verification")):
        questions.append("回滚验证为空：请说明如何确认恢复成功。")

    risk = data.get("risk")
    if risk is None:
        questions.append("缺少风险等级：请声明 low、medium 或 high。")
        risk = {}
    elif not isinstance(risk, dict):
        errors.append("risk 必须是对象")
        risk = {}
    risk_level = risk.get("declared_level")
    if risk_level is None:
        pass
    elif risk_level not in ALLOWED_RISK_LEVELS:
        errors.append("risk.declared_level 必须是 low、medium 或 high")
    if risk_level == "high":
        required_phases.add("before_high_risk")

    assumptions = data.get("assumptions", [])
    if assumptions is not None and not isinstance(assumptions, list):
        errors.append("assumptions 必须是数组")
    elif assumptions:
        questions.append("存在未确认假设：必须由所有者确认后才能继续。")

    scan_text = _scan_text(data)
    redlines = _match_redlines(scan_text)
    if redlines:
        errors.append("命中硬红线：%s" % ", ".join(redlines))
    if SERVICE_CHANGE.search(scan_text):
        required_phases.add("before_service_change")
    if GIT_COMMIT.search(scan_text):
        required_phases.add("before_commit")
    if GIT_PUSH.search(scan_text) or EXTERNAL_WRITE.search(scan_text):
        required_phases.add("before_external_write")
    if DESTRUCTIVE.search(scan_text):
        required_phases.add("before_delete")

    approval_errors, approval_questions, statuses = _validate_approvals(
        data, required_phases
    )
    errors.extend(approval_errors)
    questions.extend(approval_questions)
    return errors, questions, required_phases, statuses


def compile_intent(
    data: dict[str, Any],
    *,
    compiled_at: str | None = None,
) -> dict[str, Any]:
    """Compile one explicit intent record into a goal specification."""
    if not isinstance(data, dict):
        raise IntakeError("intent root must be a JSON object")
    if compiled_at is not None:
        try:
            datetime.fromisoformat(compiled_at)
        except ValueError as exc:
            raise IntakeError("compiled_at must be an ISO-8601 timestamp") from exc

    errors, questions, required_phases, approval_statuses = _collect_blocking_questions(data)
    unique_questions: list[str] = []
    for question in questions:
        if question not in unique_questions:
            unique_questions.append(question)

    if errors:
        state = "BLOCKED"
    elif unique_questions:
        state = "NEEDS_OWNER_INPUT"
    else:
        state = "READY"

    intent = data.get("intent") if isinstance(data.get("intent"), dict) else {}
    raw_text = str(intent.get("raw_text") or "")
    goal = data.get("goal") if isinstance(data.get("goal"), dict) else {}
    rollback = data.get("rollback") if isinstance(data.get("rollback"), dict) else {}
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    redlines = _match_redlines(_scan_text(data))

    return {
        "schema_version": OUTPUT_SCHEMA,
        "compiler_version": COMPILER_VERSION,
        "compiled_at": compiled_at or datetime.now().astimezone().isoformat(timespec="seconds"),
        "state": state,
        "execution_authorized": False,
        "execution_note": (
            "V0只生成规格。即使state=READY，也不会启动执行；"
            "下游必须再次通过工作模式和监视器。"
        ),
        "intent_id": data.get("intent_id"),
        "raw_intent": {
            "text": raw_text,
            "said_at": intent.get("said_at"),
            "scope": intent.get("scope"),
            "sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
        },
        "goal": {
            "summary": goal.get("summary"),
            "success_state": goal.get("success_state"),
        },
        "non_goals": _texts(data.get("non_goals")),
        "assumptions": _texts(data.get("assumptions")),
        "blocking_questions": unique_questions[:MAX_BLOCKING_QUESTIONS],
        "blocking_question_overflow": max(0, len(unique_questions) - MAX_BLOCKING_QUESTIONS),
        "scope": {
            "workspace": data.get("workspace"),
            "read_paths": _texts(data.get("read_paths")),
            "write_paths": _texts(data.get("write_paths")),
            "evidence_paths": _texts(data.get("evidence_paths")),
        },
        "constraints": _texts(data.get("constraints")),
        "current_state_refs": _texts(data.get("current_state_refs")),
        "forbidden_actions": list(MANDATORY_FORBIDDEN_ACTIONS)
        + _texts(data.get("forbidden_actions")),
        "tasks": data.get("tasks") if isinstance(data.get("tasks"), list) else [],
        "verification": (
            data.get("verification")
            if isinstance(data.get("verification"), list)
            else []
        ),
        "rollback": {
            "strategy": rollback.get("strategy"),
            "verification": rollback.get("verification"),
        },
        "approval_points": _approval_entries(data),
        "required_approval_phases": sorted(required_phases),
        "approval_status": approval_statuses,
        "risk": {
            "declared_level": risk.get("declared_level"),
            "matched_redlines": redlines,
        },
        "validation": {
            "errors": errors,
            "warnings": [],
            "schema_valid": not errors,
            "model_used": False,
            "files_read": 0,
            "commands_executed": 0,
        },
        "confidence": {
            "schema": 1.0 if not errors else 0.0,
            "owner_intent_fidelity": None,
            "reason": "V0只验证结构，不证明所有者意图已被正确理解。",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic Goal Compiler V0")
    parser.add_argument(
        "--input",
        required=True,
        help="UTF-8 JSON file, or '-' to read stdin",
    )
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    try:
        if args.input == "-":
            raw_payload = sys.stdin.buffer.read()
            try:
                payload = raw_payload.decode("utf-8-sig")
            except UnicodeDecodeError:
                payload = raw_payload.decode(sys.stdin.encoding or "utf-8")
        else:
            payload = Path(args.input).read_text(encoding="utf-8-sig")
        data = json.loads(payload)
        compiled = compile_intent(data)
    except (OSError, UnicodeError, json.JSONDecodeError, IntakeError) as exc:
        print("GOAL_COMPILER_ERROR: %s" % exc, file=sys.stderr)
        return 2

    print(json.dumps(compiled, ensure_ascii=False, indent=2))
    if compiled["state"] == "BLOCKED":
        return 3
    if compiled["state"] == "NEEDS_OWNER_INPUT":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
