"""
Python Language Analyzer - Phase 11
===================================

Wraps the existing Python AST parser, ProjectAnalyzer, and DetectorEngine pipeline.
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analyzers.base import LanguageAnalyzer
from backend.detector_engine import DetectorEngine
from backend.project_analyzer import ProjectAnalyzer


class PythonAnalyzer(LanguageAnalyzer):
    """
    LanguageAnalyzer implementation for Python code files.
    """
    language: str = "python"

    def __init__(self, detector_engine: Optional[DetectorEngine] = None):
        self.detector_engine = detector_engine or DetectorEngine()

    def analyze(
        self, 
        file: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Parses Python code into an AST and runs registered Python AST detectors.
        """
        if not code or not code.strip():
            return []

        try:
            tree = ast.parse(code, filename=file)
        except SyntaxError:
            # Syntax errors are skipped or handled per API convention
            return []

        # Analyze using DetectorEngine
        issues = self.detector_engine.analyze(
            tree=tree,
            file=file,
            changed_lines=changed_lines
        )
        return issues
