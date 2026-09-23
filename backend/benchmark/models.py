"""
CodeJev Benchmark Data Models - Phase 14
=========================================

Defines data models for benchmark cases, ground-truth findings, case execution results,
finding matches, and accuracy metrics summaries.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from backend.schemas import Issue, DynamicOptions


@dataclass
class ExpectedFinding:
    """
    Ground-truth expected finding defined manually for a benchmark case.
    """
    type: str
    severity: str
    file: str
    start_line: int
    end_line: int


@dataclass
class BenchmarkCase:
    """
    Single ground-truth benchmark case definition.
    """
    id: str
    language: str
    category: str
    is_positive: bool
    files: Dict[str, str]
    changed_lines: Optional[Dict[str, List[int]]] = None
    expected_findings: List[ExpectedFinding] = field(default_factory=list)
    dynamic_options: Optional[DynamicOptions] = None
    description: str = ""


@dataclass
class MatchedPair:
    """
    Represents a match between a ground-truth expected finding and a predicted issue.
    """
    expected: ExpectedFinding
    predicted: Issue
    is_exact_line: bool
    is_overlap: bool
    severity_matches: bool


@dataclass
class CaseResult:
    """
    Result of evaluating CodeJev against a single benchmark case.
    """
    case_id: str
    language: str
    category: str
    is_positive: bool
    status: str  # "TRUE_POSITIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE", "TRUE_NEGATIVE"
    predicted_issues: List[Issue] = field(default_factory=list)
    matched_pairs: List[MatchedPair] = field(default_factory=list)
    unmatched_expected: List[ExpectedFinding] = field(default_factory=list)
    unmatched_predicted: List[Issue] = field(default_factory=list)


@dataclass
class CategoryMetrics:
    """
    Accuracy metrics computed for a specific category or programming language.
    """
    name: str
    total_cases: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float


@dataclass
class MetricsSummary:
    """
    Overall evaluation metrics summary across all benchmark cases.
    """
    total_cases: int
    positive_cases: int
    negative_cases: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    fpr: float
    exact_line_accuracy: float
    overlap_accuracy: float
    wrong_file_rate: float
    severity_agreement: float
    per_language: Dict[str, CategoryMetrics] = field(default_factory=dict)
    per_category: Dict[str, CategoryMetrics] = field(default_factory=dict)
