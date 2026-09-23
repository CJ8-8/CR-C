"""
CodeJev Configuration Detector - Phase 9
=========================================

Detects insecure configurations and settings:
1. DEBUG = True in production/settings code (HIGH severity)
2. SSL verification disabled (verify=False) in HTTP client calls (HIGH severity)
3. Wildcard CORS origin (allow_origins=["*"]) (MEDIUM severity)
4. Wildcard host binding (host="0.0.0.0") (MEDIUM severity)
"""

import ast
import re
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector


class ConfigurationDetector(BaseDetector):
    """
    AST & Text detector for insecure application configurations and flags.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        """
        Scans AST tree for insecure configuration assignments and method arguments.
        """
        issues: List[Issue] = []

        for node in ast.walk(context.tree):
            start_line = getattr(node, "lineno", 1)
            end_line = getattr(node, "end_lineno", start_line)

            if not self.is_line_changed(start_line, end_line, context.changed_lines):
                continue

            # 1. DEBUG = True assignment
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.upper() == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            issues.append(Issue(
                                type="CONFIGURATION",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            ))

            # 2. HTTP call with verify=False (e.g., requests.get(..., verify=False))
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "verify":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                            issues.append(Issue(
                                type="CONFIGURATION",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            ))

                    # 3. Wildcard CORS: allow_origins=["*"] or allow_origins="*"
                    elif keyword.arg in ["allow_origins", "allow_origin", "cors_origins"]:
                        if self._is_wildcard_cors(keyword.value):
                            issues.append(Issue(
                                type="CONFIGURATION",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            ))

                    # 4. Host binding: host="0.0.0.0"
                    elif keyword.arg == "host":
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value == "0.0.0.0":
                            issues.append(Issue(
                                type="CONFIGURATION",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            ))

        return issues

    def scan_text(
        self, 
        file: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Line-by-line scanner for non-AST configuration files (.env, .ini, .yaml, settings files).
        """
        issues: List[Issue] = []
        lines = code.splitlines()

        debug_pattern = re.compile(r"^\s*DEBUG\s*=\s*True\b", re.IGNORECASE)
        verify_false_pattern = re.compile(r"\bverify\s*=\s*False\b", re.IGNORECASE)
        cors_pattern = re.compile(r"""(?:allow_origins|cors_origins)\s*=\s*(?:\[\s*["']\*["']\s*\]|["']\*["'])""", re.IGNORECASE)
        host_pattern = re.compile(r"""\bhost\s*=\s*["']0\.0\.0\.0["']""", re.IGNORECASE)

        for idx, raw_line in enumerate(lines, start=1):
            if changed_lines is not None and idx not in changed_lines:
                continue

            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if debug_pattern.search(line):
                issues.append(Issue(
                    type="CONFIGURATION",
                    severity="HIGH",
                    file=file,
                    start_line=idx,
                    end_line=idx,
                ))
            elif verify_false_pattern.search(line):
                issues.append(Issue(
                    type="CONFIGURATION",
                    severity="HIGH",
                    file=file,
                    start_line=idx,
                    end_line=idx,
                ))
            elif cors_pattern.search(line):
                issues.append(Issue(
                    type="CONFIGURATION",
                    severity="MEDIUM",
                    file=file,
                    start_line=idx,
                    end_line=idx,
                ))
            elif host_pattern.search(line):
                issues.append(Issue(
                    type="CONFIGURATION",
                    severity="MEDIUM",
                    file=file,
                    start_line=idx,
                    end_line=idx,
                ))

        return issues

    def _is_wildcard_cors(self, val_node: ast.AST) -> bool:
        """Returns True if val_node represents '*' or ['*']."""
        if isinstance(val_node, ast.Constant) and val_node.value == "*":
            return True
        if isinstance(val_node, (ast.List, ast.Tuple, ast.Set)):
            for elt in val_node.elts:
                if isinstance(elt, ast.Constant) and elt.value == "*":
                    return True
        return False
