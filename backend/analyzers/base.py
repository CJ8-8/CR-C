"""
Base Language Analyzer Interface - Phase 11
===========================================

Defines the common contract for all language-specific code analyzers.
"""

from typing import List, Optional, Set
from backend.schemas import Issue


class LanguageAnalyzer:
    """
    Abstract base class for language analyzers.
    """
    language: str = "base"

    def analyze(
        self, 
        file: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Analyzes a single source file string and returns localized Issue objects.
        """
        raise NotImplementedError("Subclasses must implement analyze()")

    def is_line_changed(
        self, 
        start_line: int, 
        end_line: int, 
        changed_lines: Optional[Set[int]]
    ) -> bool:
        """
        Helper method checking if the line range [start_line, end_line] overlaps changed_lines.
        """
        if changed_lines is None:
            return True
        node_range = set(range(start_line, end_line + 1))
        return bool(node_range.intersection(changed_lines))
