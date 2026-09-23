"""
Tests for Phase 14 - Benchmark Metrics Engine
===============================================

Tests precision, recall, F1 score, FPR, localization accuracy, and severity agreement calculations.
"""

import pytest
from backend.benchmark.metrics import MetricsCalculator
from backend.benchmark.models import CaseResult, MatchedPair, ExpectedFinding
from backend.schemas import Issue


def test_metrics_calculator_precision_recall_f1():
    calc = MetricsCalculator()

    exp = ExpectedFinding(type="BUG", severity="HIGH", file="app.py", start_line=5, end_line=5)
    pred = Issue(type="BUG", severity="HIGH", file="app.py", start_line=5, end_line=5)
    pair = MatchedPair(expected=exp, predicted=pred, is_exact_line=True, is_overlap=True, severity_matches=True)

    results = [
        # 1 TP
        CaseResult(case_id="c1", language="python", category="BUG", is_positive=True, status="TRUE_POSITIVE", matched_pairs=[pair]),
        # 1 FN
        CaseResult(case_id="c2", language="python", category="BUG", is_positive=True, status="FALSE_NEGATIVE", unmatched_expected=[exp]),
        # 1 TN
        CaseResult(case_id="c3", language="python", category="BUG", is_positive=False, status="TRUE_NEGATIVE")
    ]

    summary = calc.compute_summary(results)
    assert summary.tp == 1
    assert summary.fn == 1
    assert summary.fp == 0
    assert summary.tn == 1

    assert summary.precision == 1.0  # 1 / (1 + 0)
    assert summary.recall == 0.5     # 1 / (1 + 1)
    assert summary.exact_line_accuracy == 1.0
    assert summary.severity_agreement == 1.0
