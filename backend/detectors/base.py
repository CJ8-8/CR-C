"""
Base Detector Interface - Phase 6
==================================

Defines the common interface and line-filtering helper for all CodeJev AST detectors,
accepting AnalysisContext.
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext


class BaseDetector:
    """
    Abstract base class for AST detectors.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        """
        Scans an AST tree using AnalysisContext and returns a list of detected Issue objects.
        """
        raise NotImplementedError("Subclasses must implement detect()")

    def is_line_changed(
        self, 
        start_line: int, 
        end_line: int, 
        changed_lines: Optional[Set[int]]
    ) -> bool:
        """
        Checks if the line range [start_line, end_line] overlaps with changed_lines.
        If changed_lines is None, returns True (no filtering).
        """
        if changed_lines is None:
            return True
        node_range = set(range(start_line, end_line + 1))
        return bool(node_range.intersection(changed_lines))
