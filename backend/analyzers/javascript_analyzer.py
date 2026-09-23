"""
JavaScript & TypeScript Language Analyzer - Phase 11
=====================================================

Parses JS, JSX, TS, and TSX files into ESTree ASTs using esprima
and orchestrates JavaScript/TypeScript detectors.
"""

import re
import esprima
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analyzers.base import LanguageAnalyzer
from backend.detectors.javascript_security import JavaScriptSecurityDetector
from backend.detectors.javascript_bug import JavaScriptBugDetector
from backend.detectors.javascript_quality import JavaScriptQualityDetector


class JavaScriptAnalyzer(LanguageAnalyzer):
    """
    LanguageAnalyzer implementation for JavaScript and TypeScript code files.
    """
    def __init__(self, language: str = "javascript"):
        self.language = language
        self.security_detector = JavaScriptSecurityDetector()
        self.bug_detector = JavaScriptBugDetector()
        self.quality_detector = JavaScriptQualityDetector()

    def analyze(
        self, 
        file: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Parses JS/TS code into an ESTree AST and runs registered JS/TS detectors.
        """
        if not code or not code.strip():
            return []

        tree = self._parse_js_ts(code)
        if not tree:
            # Syntax/Parse failure -> returns empty list gracefully
            return []

        combined: List[Issue] = []

        # Run JS/TS detectors
        combined.extend(self.security_detector.detect(tree=tree, file=file, changed_lines=changed_lines))
        combined.extend(self.bug_detector.detect(tree=tree, file=file, changed_lines=changed_lines))
        combined.extend(self.quality_detector.detect(tree=tree, file=file, changed_lines=changed_lines))

        # Deduplicate issues
        seen = set()
        unique: List[Issue] = []
        for issue in combined:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        unique.sort(key=lambda x: (x.file, x.start_line, x.severity, x.type))
        return unique

    def _parse_js_ts(self, code: str) -> Optional[object]:
        """Parses JS/TS code string into ESTree AST using esprima."""
        # Attempt 1: Standard parseModule / parseScript
        try:
            return esprima.parseModule(code, loc=True, jsx=True, tolerant=True)
        except Exception:
            try:
                return esprima.parseScript(code, loc=True, jsx=True, tolerant=True)
            except Exception:
                pass

        # Attempt 2: Strip TypeScript type annotations and retry
        try:
            clean_code = re.sub(r':\s*(?:[A-Za-z0-9_<>\[\]|&]+)', '', code)
            clean_code = re.sub(r'\bas\s+[A-Za-z0-9_<>\[\]|&]+', '', clean_code)
            return esprima.parseModule(clean_code, loc=True, jsx=True, tolerant=True)
        except Exception:
            try:
                clean_code = re.sub(r':\s*(?:[A-Za-z0-9_<>\[\]|&]+)', '', code)
                clean_code = re.sub(r'\bas\s+[A-Za-z0-9_<>\[\]|&]+', '', clean_code)
                return esprima.parseScript(clean_code, loc=True, jsx=True, tolerant=True)
            except Exception:
                return None
