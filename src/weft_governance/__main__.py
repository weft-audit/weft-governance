# Copyright 2026 The WEFT Project
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for the weft_governance package."""

from .goal_compiler import main


if __name__ == "__main__":
    raise SystemExit(main())
