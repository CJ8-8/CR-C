"""
Code Quality AST Detector - Phase 10
====================================

Detects code quality concerns using AST syntax & context inspection:
1. Leftover `print(...)` calls
2. Duplicate module or symbol import statements (e.g. import os ... import os)
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector


class CodeQualityDetector(BaseDetector):
    """
    Detector for code quality, leftover debug constructs, and duplicate imports.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        issues: List[Issue] = []
        seen_imports: Set[str] = set()

        for node in ast.walk(context.tree):
            start_line = getattr(node, "lineno", 1)
            end_line = getattr(node, "end_lineno", start_line)

            # -------------------------------------------------------------
            # Rule 1: Leftover print(...) calls
            # -------------------------------------------------------------
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name == "print":
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="CODE_QUALITY",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -------------------------------------------------------------
            # Rule 2: Duplicate Imports (import os ... import os)
            # -------------------------------------------------------------
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imp_key = f"import:{alias.name}:{alias.asname or ''}"
                    if imp_key in seen_imports:
                        if self.is_line_changed(start_line, end_line, context.changed_lines):
                            issues.append(
                                Issue(
                                    type="CODE_QUALITY",
                                    severity="LOW",
                                    file=context.file,
                                    start_line=start_line,
                                    end_line=end_line,
                                )
                            )
                    else:
                        seen_imports.add(imp_key)

            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    imp_key = f"from:{mod}:{alias.name}:{alias.asname or ''}"
                    if imp_key in seen_imports:
                        if self.is_line_changed(start_line, end_line, context.changed_lines):
                            issues.append(
                                Issue(
                                    type="CODE_QUALITY",
                                    severity="LOW",
                                    file=context.file,
                                    start_line=start_line,
                                    end_line=end_line,
                                )
                            )
                    else:
                        seen_imports.add(imp_key)

        # Deduplicate issues with identical (type, severity, file, start_line, end_line)
        seen = set()
        unique: List[Issue] = []
        for issue in issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """Extracts function name for direct calls or method calls."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
