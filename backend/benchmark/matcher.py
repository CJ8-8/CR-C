"""
CodeJev Finding Matcher - Phase 14
==================================

Compares ground-truth expected findings with CodeJev predicted Issues.
Evaluates exact file match, issue type match, exact line vs. range-overlap localization,
and severity agreement.
"""

from typing import List, Set, Tuple
from backend.schemas import Issue
from backend.benchmark.models import ExpectedFinding, MatchedPair, CaseResult, BenchmarkCase


class FindingMatcher:
    """
    Compares expected ground-truth findings with predicted issues for a single case.
    """
    def match_case(self, case: BenchmarkCase, predicted_issues: List[Issue]) -> CaseResult:
        """
        Matches predicted issues against expected findings for a benchmark case.
        Determines case status (TRUE_POSITIVE, FALSE_POSITIVE, FALSE_NEGATIVE, TRUE_NEGATIVE).
        """
        matched_pairs: List[MatchedPair] = []
        unmatched_expected: List[ExpectedFinding] = list(case.expected_findings)
        unmatched_predicted: List[Issue] = list(predicted_issues)

        # Match expected findings to predicted issues
        used_predicted: Set[int] = set()
        used_expected: Set[int] = set()

        for exp_idx, exp in enumerate(case.expected_findings):
            for pred_idx, pred in enumerate(predicted_issues):
                if pred_idx in used_predicted:
                    continue

                if self._is_finding_match(exp, pred):
                    is_exact = (pred.start_line == exp.start_line and pred.end_line == exp.end_line)
                    is_overlap = self._lines_overlap(exp.start_line, exp.end_line, pred.start_line, pred.end_line)
                    sev_match = (pred.severity.upper() == exp.severity.upper())

                    pair = MatchedPair(
                        expected=exp,
                        predicted=pred,
                        is_exact_line=is_exact,
                        is_overlap=is_overlap,
                        severity_matches=sev_match
                    )
                    matched_pairs.append(pair)
                    used_expected.add(exp_idx)
                    used_predicted.add(pred_idx)
                    break

        # Remaining unmatched
        unmatched_exp_final = [exp for idx, exp in enumerate(case.expected_findings) if idx not in used_expected]
        unmatched_pred_final = [pred for idx, pred in enumerate(predicted_issues) if idx not in used_predicted]

        # Determine overall case status
        status = "TRUE_NEGATIVE"
        if case.is_positive:
            if matched_pairs and not unmatched_exp_final:
                status = "TRUE_POSITIVE"
            else:
                status = "FALSE_NEGATIVE"
        else:
            if predicted_issues:
                status = "FALSE_POSITIVE"
            else:
                status = "TRUE_NEGATIVE"

        return CaseResult(
            case_id=case.id,
            language=case.language,
            category=case.category,
            is_positive=case.is_positive,
            status=status,
            predicted_issues=predicted_issues,
            matched_pairs=matched_pairs,
            unmatched_expected=unmatched_exp_final,
            unmatched_predicted=unmatched_pred_final
        )

    def _is_finding_match(self, exp: ExpectedFinding, pred: Issue) -> bool:
        """Checks if a predicted issue matches an expected finding by file, type, and line overlap."""
        if exp.file != pred.file:
            return False
        if exp.type.upper() != pred.type.upper():
            return False

        return self._lines_overlap(exp.start_line, exp.end_line, pred.start_line, pred.end_line)

    def _lines_overlap(self, start1: int, end1: int, start2: int, end2: int) -> bool:
        """Returns True if line range [start1, end1] overlaps with [start2, end2]."""
        return max(start1, start2) <= min(end1, end2)
