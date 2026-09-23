"""
Tests for Phase 10 - Performance Detector (Static Heuristics)
"""

import ast
import pytest
from backend.analysis_context import AnalysisContext
from backend.detectors.performance import PerformanceDetector


def test_repeated_regex_compilation_in_loop():
    detector = PerformanceDetector()
    code = """
import re

for item in items:
    pattern = re.compile(r"abc")
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="regex_loop.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "PERFORMANCE"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 4


def test_regex_compilation_outside_loop_not_flagged():
    detector = PerformanceDetector()
    code = """
import re
pattern = re.compile(r"abc")

for item in items:
    pass
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="regex_outside.py")

    issues = detector.detect(context)
    assert len(issues) == 0


def test_inefficient_string_concatenation_in_loop():
    detector = PerformanceDetector()
    code = """
result = ""
for item in items:
    result += str(item)
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="concat.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "PERFORMANCE"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 3


def test_repeated_expensive_call_in_loop():
    detector = PerformanceDetector()
    code = """
for item in items:
    sorted_list = sorted(items)
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="sorted_loop.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "PERFORMANCE"
    assert issues[0].severity == "LOW"


def test_repeated_list_membership_check_in_loop():
    detector = PerformanceDetector()
    code = """
for item in items:
    if item in large_list:
        pass
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="membership.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "PERFORMANCE"
    assert issues[0].severity == "LOW"


def test_repeated_constant_structure_construction_in_loop():
    detector = PerformanceDetector()
    code = """
for item in items:
    pattern = {"a": 1, "b": 2}
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="dict_loop.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "PERFORMANCE"
    assert issues[0].severity == "LOW"


def test_performance_changed_lines_filter():
    detector = PerformanceDetector()
    code = """
for item in items:
    pattern = re.compile(r"abc")
    result += str(item)
    """.strip()

    tree = ast.parse(code)
    # Only line 3 changed
    context = AnalysisContext(tree=tree, file="loop.py", changed_lines={3})

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].start_line == 3
