# Copyright 2026 The WEFT Project
# SPDX-License-Identifier: Apache-2.0
"""weft intent and governance primitives."""

from .goal_compiler import compile_intent
from .publication_contract import evaluate_publication
from .trust_boundary import build_context_envelope

__all__ = [
    "build_context_envelope",
    "compile_intent",
    "evaluate_publication",
]
__version__ = "2.0.0"
