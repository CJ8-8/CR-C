"""
Tests for Phase 13 - Program State & Lattice System
=====================================================

Tests ProgramState variable tracking, nullability, constant setting, path-sensitive
state merging, and guard evaluation.
"""

import ast
import pytest
from backend.analysis.program_state import ProgramState, Nullability, ValueState
from backend.analysis_context import TaintState


def test_program_state_constant_and_none():
    state = ProgramState()
    state.set_constant("x", 10)
    state.set_none("y")

    assert state.get_constant_value("x") == 10
    assert state.get_nullability("x") == Nullability.NOT_NONE
    assert state.is_definitely_none("y")
    assert state.get_constant_value("y") is None


def test_program_state_branch_merging():
    branch_a = ProgramState()
    branch_a.set_none("val")
    branch_a.set_tainted("data", TaintState(is_tainted=True, source_file="a.py", source_line=1, source_kind="input()"))

    branch_b = ProgramState()
    branch_b.set_constant("val", "hello")
    branch_b.set_sanitized("data")

    merged = branch_a.merge(branch_b)

    # Nullability merged to POSSIBLY_NONE
    assert merged.get_nullability("val") == Nullability.POSSIBLY_NONE

    # Taint merged path-sensitively: IF tainted on ANY branch, merged state is TAINTED!
    assert merged.var_taint["data"] is not None
    assert merged.var_taint["data"].is_tainted


def test_program_state_apply_none_guard():
    state = ProgramState()
    state.set_possibly_none("res")

    test_ast = ast.parse("res is None").body[0].value

    true_state = state.apply_guard(test_ast, true_branch=True)
    false_state = state.apply_guard(test_ast, true_branch=False)

    assert true_state.is_definitely_none("res")
    assert false_state.is_not_none("res")
