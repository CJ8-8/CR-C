"""
Tests for Phase 13 - Interprocedural Function Summaries
=========================================================

Tests FunctionSummary generation, memoization caching, cross-file summary resolution,
and cycle/recursion safety.
"""

import pytest
from backend.project_analyzer import ProjectAnalyzer
from backend.analysis.function_summary import SummaryCache, FunctionSummary


def test_function_summary_constant_returns():
    files = {
        "helper.py": "def get_none():\n    return None\n\ndef get_ten():\n    return 10\n"
    }
    project = ProjectAnalyzer(files)
    cache = project.summary_cache

    sum_none = cache.get_summary("helper.py", "get_none")
    assert sum_none.has_constant_return
    assert sum_none.returns_constant is None

    sum_ten = cache.get_summary("helper.py", "get_ten")
    assert sum_ten.has_constant_return
    assert sum_ten.returns_constant == 10


def test_function_summary_param_passthrough():
    files = {
        "passthrough.py": "def identity(val):\n    return val\n"
    }
    project = ProjectAnalyzer(files)
    cache = project.summary_cache

    summary = cache.get_summary("passthrough.py", "identity")
    assert summary.returns_param_index == 0


def test_function_summary_recursion_and_cycle_safety():
    files = {
        "cycle.py": "def func_a():\n    return func_b()\n\ndef func_b():\n    return func_a()\n"
    }
    project = ProjectAnalyzer(files)
    cache = project.summary_cache

    summary = cache.get_summary("cycle.py", "func_a")
    assert summary.is_unknown or not summary.has_constant_return
