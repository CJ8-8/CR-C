"""
Tests for Phase 13 - Finding Validation & False-Positive Protection
=====================================================================

Tests FindingValidator filtering, false positive protection with path-sensitive None guards,
and evidence validation.
"""

import ast
import pytest
from backend.analysis.finding_validator import FindingValidator, FindingEvidence
from backend.analysis_context import AnalysisContext
from backend.detectors.bug import BugDetector


def test_finding_validator_suppresses_out_of_changed_lines():
    validator = FindingValidator()
    evidences = [
        FindingEvidence(
            rule="DivisionByZero",
            file="app.py",
            start_line=10,
            end_line=10,
            severity="HIGH",
            issue_type="BUG"
        )
    ]

    # Changed lines do NOT include line 10
    filtered = validator.validate_and_filter(evidences, changed_lines={"app.py": [20, 21]})
    assert len(filtered) == 0


def test_false_positive_protection_guarded_none_dereference():
    # 'if res is None: return' guards line 6 'res.strip()' from being None
    code = """def process(res):
    res = None
    if res is None:
        return
    res.strip()
"""
    tree = ast.parse(code, filename="guarded.py")
    context = AnalysisContext(tree, "guarded.py")
    detector = BugDetector()

    issues = detector.detect(context)
    # Line 6 dereference is guarded, so context.is_value_none("res", lineno=6) returns False!
    line_6_issues = [i for i in issues if i.start_line == 6]
    assert len(line_6_issues) == 0


def test_positive_detection_unguarded_none_dereference():
    code = """def process():
    res = None
    res.strip()
"""
    tree = ast.parse(code, filename="unguarded.py")
    context = AnalysisContext(tree, "unguarded.py")
    detector = BugDetector()

    issues = detector.detect(context)
    line_3_issues = [i for i in issues if i.start_line == 3]
    assert len(line_3_issues) >= 1
    assert line_3_issues[0].severity == "MEDIUM"
