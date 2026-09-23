"""
Tests for Phase 10 - Extended Bug Detector Rules
"""

import ast
import pytest
from backend.analysis_context import AnalysisContext
from backend.detectors.bug import BugDetector


def test_unreachable_code():
    detector = BugDetector()
    code = """
def calculate():
    return 10
    print("never executed")
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="calc.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 3


def test_constant_condition_if():
    detector = BugDetector()
    code = """
if True:
    do_something()
else:
    do_other()
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="branch.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 1


def test_constant_condition_while():
    detector = BugDetector()
    code = """
while False:
    do_work()
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="loop.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 1


def test_normal_variable_condition_not_flagged():
    detector = BugDetector()
    code = """
if user_value:
    do_something()
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="user.py")

    issues = detector.detect(context)
    assert len(issues) == 0


def test_suspicious_identity_comparison():
    detector = BugDetector()
    code = """
if value is 5:
    pass
if text is "hello":
    pass
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="cmp.py")

    issues = detector.detect(context)
    assert len(issues) == 2
    assert all(i.type == "BUG" for i in issues)
    assert all(i.severity == "MEDIUM" for i in issues)


def test_valid_none_identity_comparison_not_flagged():
    detector = BugDetector()
    code = """
if value is None:
    pass
if a is b:
    pass
if is_valid is True:
    pass
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="valid_cmp.py")

    issues = detector.detect(context)
    assert len(issues) == 0


def test_duplicate_dict_keys():
    detector = BugDetector()
    code = """
data = {
    "name": "Alice",
    "name": "Bob"
}
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="data.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "LOW"


def test_swallowed_exception():
    detector = BugDetector()
    code = """
try:
    risky()
except Exception:
    pass
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="try.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "MEDIUM"


def test_logged_exception_not_flagged_as_swallowed():
    detector = BugDetector()
    code = """
try:
    risky()
except Exception as exc:
    logger.error(exc)
    """.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="try_logging.py")

    issues = detector.detect(context)
    assert len(issues) == 0
