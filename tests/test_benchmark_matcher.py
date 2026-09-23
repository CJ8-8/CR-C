"""
Tests for Phase 14 - Finding Matcher
=====================================

Tests matching ground-truth expected findings against predicted Issue objects.
"""

import pytest
from backend.benchmark.matcher import FindingMatcher
from backend.benchmark.models import BenchmarkCase, ExpectedFinding
from backend.schemas import Issue


def test_matcher_exact_and_overlap_matching():
    matcher = FindingMatcher()
    case = BenchmarkCase(
        id="match-01",
        language="python",
        category="SECURITY",
        is_positive=True,
        files={"app.py": "eval(x)"},
        expected_findings=[
            ExpectedFinding(type="SECURITY", severity="HIGH", file="app.py", start_line=2, end_line=2)
        ]
    )

    predicted = [
        Issue(type="SECURITY", severity="HIGH", file="app.py", start_line=2, end_line=2)
    ]

    res = matcher.match_case(case, predicted)
    assert res.status == "TRUE_POSITIVE"
    assert len(res.matched_pairs) == 1
    assert res.matched_pairs[0].is_exact_line
    assert res.matched_pairs[0].is_overlap
    assert res.matched_pairs[0].severity_matches


def test_matcher_type_or_file_mismatch():
    matcher = FindingMatcher()
    case = BenchmarkCase(
        id="match-02",
        language="python",
        category="SECURITY",
        is_positive=True,
        files={"app.py": "eval(x)"},
        expected_findings=[
            ExpectedFinding(type="SECURITY", severity="HIGH", file="app.py", start_line=2, end_line=2)
        ]
    )

    # Wrong file
    predicted = [
        Issue(type="SECURITY", severity="HIGH", file="other.py", start_line=2, end_line=2)
    ]

    res = matcher.match_case(case, predicted)
    assert res.status == "FALSE_NEGATIVE"
    assert len(res.unmatched_expected) == 1
    assert len(res.unmatched_predicted) == 1
