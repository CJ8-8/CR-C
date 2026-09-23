"""
CodeJev Analyzer Engine - Phase 2 & Phase 3 Prototype
======================================================

NOTE FOR DEVELOPERS & LEARNERS:
This module contains code analysis functions for:
- Phase 2: Full file line-by-line code scanning (`analyze_code`).
- Phase 3: Git diff changed-line problem localization (`analyze_diff`).

Phase 3 uses `diff_parser.py` to parse diff hunks, ensuring that issues
are evaluated and reported ONLY on newly added or modified lines.
"""

from typing import List
from backend.schemas import Issue
from backend.diff_parser import parse_unified_diff


def analyze_code(file: str, code: str) -> List[Issue]:
    """
    Phase 2: Scans a raw full code string line-by-line and returns localized Issue objects.

    Args:
        file (str): The filename being analyzed (e.g. 'auth.py').
        code (str): The full raw source code string.

    Returns:
        List[Issue]: List of localized detected problems with 1-based line numbers.
    """
    issues: List[Issue] = []

    if not code:
        return issues

    lines = code.splitlines()

    for line_number, raw_line in enumerate(lines, start=1):
        _inspect_line_and_append_issues(file, raw_line, line_number, issues)

    return issues


def analyze_diff(file: str, diff_text: str) -> List[Issue]:
    """
    Phase 3: Parses a Git unified diff and scans ONLY newly added/modified lines.

    Args:
        file (str): The filename being analyzed (e.g. 'auth.py').
        diff_text (str): Unified diff format string.

    Returns:
        List[Issue]: List of localized issues on newly added lines.
    """
    issues: List[Issue] = []

    if not diff_text:
        return issues

    # Parse diff hunks to extract only added DiffLine objects
    added_diff_lines = parse_unified_diff(diff_text)

    # Inspect each added line
    for diff_line in added_diff_lines:
        _inspect_line_and_append_issues(
            file=file, 
            raw_line=diff_line.content, 
            line_number=diff_line.line_number, 
            issues=issues
        )

    return issues


def _inspect_line_and_append_issues(
    file: str, 
    raw_line: str, 
    line_number: int, 
    issues: List[Issue]
) -> None:
    """
    Helper function containing temporary prototype rules for pattern matching.
    """
    line_lower = raw_line.lower()

    # -------------------------------------------------------------------------
    # Demo Rule 1: SQL Injection Pattern Detection
    # -------------------------------------------------------------------------
    if "select " in line_lower and "+" in raw_line:
        issues.append(
            Issue(
                type="SECURITY",
                severity="HIGH",
                file=file,
                start_line=line_number,
                end_line=line_number,
            )
        )

    # -------------------------------------------------------------------------
    # Demo Rule 2: Unsafe Dynamic Execution (eval/exec)
    # -------------------------------------------------------------------------
    if "eval(" in line_lower or "exec(" in line_lower:
        issues.append(
            Issue(
                type="SECURITY",
                severity="HIGH",
                file=file,
                start_line=line_number,
                end_line=line_number,
            )
        )

    # -------------------------------------------------------------------------
    # Demo Rule 3: Leftover Debug Statement Detection
    # -------------------------------------------------------------------------
    if 'print("debug"' in line_lower or "print('debug'" in line_lower:
        issues.append(
            Issue(
                type="CODE_QUALITY",
                severity="LOW",
                file=file,
                start_line=line_number,
                end_line=line_number,
            )
        )
