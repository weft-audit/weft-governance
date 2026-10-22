# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for Goal Compiler V0."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weft_governance.goal_compiler import IntakeError, compile_intent  # noqa: E402


def ready_intent() -> dict:
    evidence_path = "examples/smoke-output.json"
    return {
        "schema_version": "goal-intent/v0", "intent_id": "WEFT-2-SAFE-001",
        "intent": {
            "raw_text": "为目标编译器生成一份冒烟输出。",
            "said_at": "2026-01-21", "scope": "this_task",
        },
        "goal": {
            "summary": "生成一份可校验的目标规格样本。",
            "success_state": "样本通过结构校验，且不执行任何下游动作。",
        },
        "non_goals": ["不修改生产代码", "不启动或停止服务"],
        "assumptions": [],
        "workspace": str(Path.cwd()),
        "constraints": ["只使用 Python 标准库", "V0 不执行命令"],
        "current_state_refs": ["目标编译器 V0 已存在，尚未接入工作链"],
        "read_paths": ["README.md"],
        "write_paths": [evidence_path],
        "forbidden_actions": ["不得读取密钥"],
        "tasks": [
            {
                "id": "T1",
                "description": "生成规格样本",
                "owner": "codex",
                "depends_on": [],
            }
        ],
        "verification": [
            {
                "id": "V1",
                "type": "command",
                "description": "运行目标编译器测试",
                "command": "python -m unittest discover -s tests -p test_goal_compiler.py",
                "expected": "GOAL_COMPILER_TESTS_PASS",
            }
        ],
        "evidence_paths": [evidence_path],
        "rollback": {
            "strategy": "删除本次新增的冒烟输出。",
            "verification": "确认目标路径不存在。",
        },
        "approval_points": [
            {
                "id": "A1",
                "phase": "before_execute",
                "required_from": "owner",
                "status": "granted",
                "reason": "允许执行目标编译器 V0 开发任务",
                "evidence": "synthetic test approval",
            },
            {
                "id": "A2",
                "phase": "before_write",
                "required_from": "owner",
                "status": "granted",
                "reason": "允许写入已声明路径",
                "evidence": "synthetic test approval",
            },
        ],
        "risk": {"declared_level": "low"},
    }


class GoalCompilerTests(unittest.TestCase):
    def test_ready_spec_preserves_exact_intent_and_never_authorizes_execution(self):
        intent = ready_intent()
        result = compile_intent(intent, compiled_at="2026-10-21T01:20:00+08:00")
        self.assertEqual("READY", result["state"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(intent["intent"]["raw_text"], result["raw_intent"]["text"])
        self.assertEqual(
            hashlib.sha256(intent["intent"]["raw_text"].encode("utf-8")).hexdigest(),
            result["raw_intent"]["sha256"],
        )
        self.assertFalse(result["validation"]["model_used"])
        self.assertEqual(0, result["validation"]["files_read"])
        self.assertEqual(0, result["validation"]["commands_executed"])

    def test_missing_critical_fields_returns_at_most_three_questions(self):
        intent = ready_intent()
        del intent["verification"]
        del intent["rollback"]
        intent["goal"]["success_state"] = ""
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertLessEqual(len(result["blocking_questions"]), 3)
        self.assertGreater(result["blocking_question_overflow"], 0)

    def test_partial_intake_is_needs_input_not_blocked(self):
        intent = {
            "schema_version": "goal-intent/v0", "intent_id": "GC-V0-PARTIAL-001",
            "intent": {
                "raw_text": "补全目标编译示例",
                "said_at": "2026-01-21", "scope": "this_task",
            },
        }
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertEqual([], result["validation"]["errors"])
        self.assertLessEqual(len(result["blocking_questions"]), 3)

    def test_partial_intake_question_quotes_the_received_intent(self):
        intent = {
            "schema_version": "goal-intent/v0", "intent_id": "GC-V0-CONTEXT-001",
            "intent": {
                "raw_text": "示例任务：补全验收说明（未完成，已有两条草稿）。",
                "said_at": "2026-01-20", "scope": "this_task",
            },
        }
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertIn("示例任务：补全验收说明", result["blocking_questions"][0])

    def test_secret_file_is_blocked_even_with_owner_approval(self):
        intent = ready_intent()
        intent["intent"]["raw_text"] = "读取 .credentials 并总结。"
        intent["tasks"][0]["description"] = "读取 .credentials"
        result = compile_intent(intent)
        self.assertEqual("BLOCKED", result["state"])
        self.assertIn("secret_file", result["risk"]["matched_redlines"])

    def test_unconfirmed_assumption_is_not_promoted_to_fact(self):
        intent = ready_intent()
        intent["assumptions"] = ["所有者允许修改生产配置"]
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertTrue(
            any("假设" in item for item in result["blocking_questions"])
        )

    def test_root_write_path_is_blocked(self):
        intent = ready_intent()
        intent["write_paths"] = ["C:\\"]
        intent["evidence_paths"] = ["C:\\evidence.json"]
        result = compile_intent(intent)
        self.assertEqual("BLOCKED", result["state"])
        self.assertTrue(
            any("根目录" in error for error in result["validation"]["errors"])
        )

    def test_evidence_boundary_is_never_silently_skipped(self):
        intent = ready_intent()
        intent["write_paths"] = ["C:\\"]
        intent["evidence_paths"] = ["C:\\outside\\evidence.json"]
        result = compile_intent(intent)
        self.assertEqual("BLOCKED", result["state"])
        self.assertTrue(
            any("证据路径" in error for error in result["validation"]["errors"])
        )

    def test_service_change_requires_specific_owner_approval(self):
        intent = ready_intent()
        intent["tasks"][0]["description"] = "重启常驻服务并检查端口"
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertEqual(
            "pending",
            result["approval_status"]["before_service_change"],
        )

    def test_high_risk_requires_specific_owner_approval(self):
        intent = ready_intent()
        intent["risk"]["declared_level"] = "high"
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertEqual("pending", result["approval_status"]["before_high_risk"])

    def test_git_commit_requires_specific_owner_approval(self):
        intent = ready_intent()
        intent["tasks"][0]["description"] = "检查后执行 git commit"
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertEqual("pending", result["approval_status"]["before_commit"])

    def test_delete_requires_specific_owner_approval(self):
        intent = ready_intent()
        intent["tasks"][0]["description"] = "删除临时输出文件"
        result = compile_intent(intent)
        self.assertEqual("NEEDS_OWNER_INPUT", result["state"])
        self.assertEqual("pending", result["approval_status"]["before_delete"])

    def test_invalid_compiled_at_is_rejected(self):
        with self.assertRaises(IntakeError):
            compile_intent(ready_intent(), compiled_at="not-an-iso-time")

    def test_task_cycle_is_blocked(self):
        intent = ready_intent()
        intent["tasks"] = [
            {"id": "T1", "description": "甲", "owner": "codex", "depends_on": ["T2"]},
            {"id": "T2", "description": "乙", "owner": "codex", "depends_on": ["T1"]},
        ]
        result = compile_intent(intent)
        self.assertEqual("BLOCKED", result["state"])
        self.assertTrue(any("环" in error for error in result["validation"]["errors"]))

    def test_cli_outputs_json_and_uses_nonzero_exit_for_needs_input(self):
        intent = ready_intent()
        del intent["verification"]
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "src" / "weft_governance" / "goal_compiler.py"),
                "--input",
                "-",
            ],
            input=json.dumps(intent, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )
        self.assertEqual(2, completed.returncode, completed.stderr)
        parsed = json.loads(completed.stdout)
        self.assertEqual("NEEDS_OWNER_INPUT", parsed["state"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GoalCompilerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = "GOAL_COMPILER_TESTS_" + ("PASS" if result.wasSuccessful() else "FAIL")
    print(summary)
    raise SystemExit(0 if result.wasSuccessful() else 1)
