"""
Tests for Phase 13 - Branch-Sensitive Taint & Path Merging
===========================================================

Tests that conditional sanitization is path-sensitive:
- If sanitized on branch A, but NOT on branch B -> overall variable remains TAINTED.
- If sanitized on ALL reachable paths -> variable is treated as SANITIZED.
"""

import ast
import pytest
from backend.analysis_context import AnalysisContext, TaintState
from backend.analysis.program_state import ProgramState


def test_conditional_sanitization_path_merging():
    branch_a = ProgramState()
    branch_a.set_sanitized("user_data")

    branch_b = ProgramState()
    branch_b.set_tainted("user_data", TaintState(is_tainted=True, source_file="app.py", source_line=2, source_kind="input()"))

    merged = branch_a.merge(branch_b)

    # Path merging is conservative: IF tainted on ANY reachable branch, merged state is TAINTED!
    assert merged.var_taint["user_data"] is not None
    assert merged.var_taint["user_data"].is_tainted


def test_all_branches_sanitized():
    branch_a = ProgramState()
    branch_a.set_sanitized("user_data")

    branch_b = ProgramState()
    branch_b.set_sanitized("user_data")

    merged = branch_a.merge(branch_b)
    assert merged.var_taint["user_data"] is None
