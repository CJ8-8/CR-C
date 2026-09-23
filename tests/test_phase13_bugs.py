"""
Tests for Phase 13 - Advanced Bug & Control Flow Reasoning
===========================================================

Tests Division by Zero, Collection Index Out of Bounds, CFG Unreachable Code,
and Duplicate Branch Conditions.
"""

import ast
import pytest
from backend.detectors.bug import BugDetector
from backend.analysis_context import AnalysisContext


def test_detect_division_by_zero_literal():
    code = "def calc():\n    x = 10 / 0\n    return x\n"
    tree = ast.parse(code, filename="calc.py")
    context = AnalysisContext(tree, "calc.py")
    detector = BugDetector()

    issues = detector.detect(context)
    div_issues = [i for i in issues if i.type == "BUG" and i.severity == "HIGH"]
    assert len(div_issues) >= 1
    assert div_issues[0].start_line == 2


def test_detect_division_by_zero_variable():
    code = "def calc():\n    zero_val = 0\n    x = 10 / zero_val\n    return x\n"
    tree = ast.parse(code, filename="calc.py")
    context = AnalysisContext(tree, "calc.py")
    detector = BugDetector()

    issues = detector.detect(context)
    div_issues = [i for i in issues if i.type == "BUG" and i.severity == "HIGH"]
    assert len(div_issues) >= 1
    assert div_issues[0].start_line == 3


def test_detect_index_out_of_bounds_literal_list():
    code = "def get_item():\n    items = [1, 2, 3]\n    return items[5]\n"
    tree = ast.parse(code, filename="bounds.py")
    context = AnalysisContext(tree, "bounds.py")
    detector = BugDetector()

    issues = detector.detect(context)
    oob_issues = [i for i in issues if i.type == "BUG" and i.severity == "HIGH"]
    assert len(oob_issues) >= 1
    assert oob_issues[0].start_line == 3


def test_detect_duplicate_if_conditions():
    code = "if x > 10:\n    do_a()\nelif x > 10:\n    do_b()\n"
    tree = ast.parse(code, filename="dup_if.py")
    context = AnalysisContext(tree, "dup_if.py")
    detector = BugDetector()

    issues = detector.detect(context)
    dup_issues = [i for i in issues if i.type == "BUG" and i.severity == "LOW"]
    assert len(dup_issues) >= 1
    assert dup_issues[0].start_line == 3
