"""
CodeJev Dynamic Result Parser & Finder Integrator - Phase 12
=============================================================

Aggregates dynamic evidence (TestResult, RuntimeResult, FuzzResult) into normalized Issue objects.
Merges dynamic findings with static analysis results, preserving static findings even if dynamic execution finds no issues.
Applies per-file changed_lines filtering and deterministic sorting (file, start_line, severity, type).
"""

from typing import Dict, List, Optional, Set
from backend.schemas import Issue
from backend.dynamic.test_runner import TestResult
from backend.dynamic.runtime_runner import RuntimeResult
from backend.dynamic.fuzz_runner import FuzzResult


class DynamicResultParser:
    """
    Parses and converts dynamic test/runtime/fuzz evidence into public Issue objects.
    """
    def convert_test_results(self, results: List[TestResult]) -> List[Issue]:
        """Converts failed TestResults to BUG / HIGH Issue objects."""
        issues: List[Issue] = []
        for res in results:
            if res.status == "failed" and res.file and res.line:
                issues.append(Issue(
                    type="BUG",
                    severity="HIGH",
                    file=res.file,
                    start_line=res.line,
                    end_line=res.line,
                ))
        return issues

    def convert_runtime_result(self, res: RuntimeResult) -> List[Issue]:
        """Converts RuntimeResult error to BUG / HIGH Issue object."""
        issues: List[Issue] = []
        if res.status == "error" and res.file and res.line:
            issues.append(Issue(
                type="BUG",
                severity="HIGH",
                file=res.file,
                start_line=res.line,
                end_line=res.line,
            ))
        return issues

    def convert_fuzz_result(self, res: FuzzResult) -> List[Issue]:
        """Converts FuzzResult crash to BUG / HIGH Issue object."""
        issues: List[Issue] = []
        if res.status == "crash" and res.file and res.line:
            issues.append(Issue(
                type="BUG",
                severity="HIGH",
                file=res.file,
                start_line=res.line,
                end_line=res.line,
            ))
        return issues

    def combine_and_filter(
        self, 
        static_issues: List[Issue], 
        dynamic_issues: List[Issue], 
        changed_lines: Optional[Dict[str, List[int]]] = None
    ) -> List[Issue]:
        """
        Combines static and dynamic issues, applies per-file changed_lines filtering,
        deduplicates identical findings, and sorts deterministically by (file, start_line, severity, type).
        """
        combined = list(static_issues) + list(dynamic_issues)
        filtered: List[Issue] = []

        for issue in combined:
            file_changed_lines = None
            if changed_lines and issue.file in changed_lines:
                file_changed_lines = set(changed_lines[issue.file])

            # Apply changed_lines filter if set for this file
            if file_changed_lines is not None:
                line_range = set(range(issue.start_line, issue.end_line + 1))
                if not line_range.intersection(file_changed_lines):
                    continue

            filtered.append(issue)

        SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        seen_map = {}
        for issue in filtered:
            key = (issue.file, issue.start_line, issue.end_line, issue.type)
            if key not in seen_map:
                seen_map[key] = issue
            else:
                existing = seen_map[key]
                if SEVERITY_RANK.get(issue.severity.upper(), 0) > SEVERITY_RANK.get(existing.severity.upper(), 0):
                    seen_map[key] = issue

        unique = list(seen_map.values())
        unique.sort(key=lambda x: (x.file, x.start_line, x.severity, x.type))
        return unique
