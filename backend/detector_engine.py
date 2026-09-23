"""
CodeJev Detector Engine - Phase 7
==================================

Orchestrates registered AST detectors (Security, Code Quality, Bug)
using AnalysisContext for local data-flow and cross-file interprocedural reasoning.
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.project_analyzer import ProjectAnalyzer
from backend.detectors.base import BaseDetector
from backend.detectors.security import SecurityDetector
from backend.detectors.code_quality import CodeQualityDetector
from backend.detectors.bug import BugDetector
from backend.detectors.secrets import SecretsDetector
from backend.detectors.configuration import ConfigurationDetector
from backend.detectors.performance import PerformanceDetector


class DetectorEngine:
    """
    Coordinates execution of all registered AST detectors using AnalysisContext.
    """
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        if detectors is None:
            # Register default detectors
            self.detectors: List[BaseDetector] = [
                SecurityDetector(),
                CodeQualityDetector(),
                BugDetector(),
                SecretsDetector(),
                ConfigurationDetector(),
                PerformanceDetector(),
            ]


        else:
            self.detectors = detectors

    def analyze(
        self, 
        tree: ast.AST, 
        file: str, 
        changed_lines: Optional[Set[int]] = None,
        project_analyzer: Optional[ProjectAnalyzer] = None
    ) -> List[Issue]:
        """
        Runs all registered detectors using AnalysisContext and returns combined Issues.
        """
        context = AnalysisContext(
            tree=tree, 
            file=file, 
            changed_lines=changed_lines, 
            project_analyzer=project_analyzer
        )
        combined_issues: List[Issue] = []

        for detector in self.detectors:
            detected = detector.detect(context=context)
            combined_issues.extend(detected)

        # Deduplicate issues with identical (type, severity, file, start_line, end_line)
        seen = set()
        unique_issues = []
        for issue in combined_issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)

        # Sort issues deterministically by start_line
        unique_issues.sort(key=lambda x: (x.start_line, x.type, x.severity))
        return unique_issues
