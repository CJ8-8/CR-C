"""
CodeJev Secrets Detector - Phase 9
===================================

Detects hardcoded sensitive credentials (RSA private keys, AWS keys, GitHub tokens, API keys)
with placeholder exclusion and line localization.
Enforces zero-exposure safety: secret values are NEVER recorded, logged, or returned in Issue payloads.
"""

import ast
import re
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector

# Patterns for explicit secret signatures
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)*PRIVATE\s+KEY-----",
    re.IGNORECASE
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_PATTERN = re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b")
GENERIC_API_KEY_PATTERN = re.compile(r"\b(sk-[a-zA-Z0-9]{32,}|sk_live_[a-zA-Z0-9]{24,})\b")

# Variable names commonly holding hardcoded secrets
SECRET_VAR_NAME_PATTERN = re.compile(
    r"^(?:.*_)?(?:API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_KEY|SECRET|PASSWORD|AUTH_TOKEN|TOKEN)$",
    re.IGNORECASE
)

# Dummy / test placeholders to ignore
PLACEHOLDER_SUBSTRINGS = [
    "your-api-key",
    "your_api_key",
    "your-secret-key",
    "your_secret_key",
    "example",
    "changeme",
    "dummy",
    "placeholder",
    "xxx",
    "00000000-0000-0000-0000-000000000000",
    "your_token",
    "<key>",
    "<secret>",
    "test_key",
    "mock_key",
    "process.env",
]


class SecretsDetector(BaseDetector):
    """
    AST & Text detector for hardcoded secrets and credentials.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        """
        Scans AST tree for string constants and assignments containing hardcoded secrets.
        """
        issues: List[Issue] = []

        for node in ast.walk(context.tree):
            start_line = getattr(node, "lineno", 1)
            end_line = getattr(node, "end_lineno", start_line)

            if not self.is_line_changed(start_line, end_line, context.changed_lines):
                continue

            # Check string constant nodes
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                if self._is_placeholder(val):
                    continue

                if PRIVATE_KEY_PATTERN.search(val):
                    issues.append(Issue(
                        type="SECRET",
                        severity="CRITICAL",
                        file=context.file,
                        start_line=start_line,
                        end_line=end_line,
                    ))
                elif AWS_ACCESS_KEY_PATTERN.search(val) or GITHUB_TOKEN_PATTERN.search(val):
                    issues.append(Issue(
                        type="SECRET",
                        severity="CRITICAL",
                        file=context.file,
                        start_line=start_line,
                        end_line=end_line,
                    ))
                elif GENERIC_API_KEY_PATTERN.search(val):
                    issues.append(Issue(
                        type="SECRET",
                        severity="HIGH",
                        file=context.file,
                        start_line=start_line,
                        end_line=end_line,
                    ))

            # Check variable assignments: SECRET_KEY = "..."
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and SECRET_VAR_NAME_PATTERN.match(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value, str):
                            val = node.value.value
                            if self._is_placeholder(val) or len(val.strip()) < 6:
                                continue
                            
                            # If value didn't match specific critical token regexes above, flag as HIGH secret assignment
                            if not (PRIVATE_KEY_PATTERN.search(val) or AWS_ACCESS_KEY_PATTERN.search(val) or GITHUB_TOKEN_PATTERN.search(val) or GENERIC_API_KEY_PATTERN.search(val)):
                                issues.append(Issue(
                                    type="SECRET",
                                    severity="HIGH",
                                    file=context.file,
                                    start_line=start_line,
                                    end_line=end_line,
                                ))

        # Deduplicate issues for identical file and line range
        seen = set()
        unique: List[Issue] = []
        for issue in issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    def scan_text(
        self, 
        file: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Line-by-line scanner for non-AST text files (.env, .json, .yaml, .txt, etc.).
        """
        issues: List[Issue] = []
        lines = code.splitlines()

        for idx, raw_line in enumerate(lines, start=1):
            if changed_lines is not None and idx not in changed_lines:
                continue

            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if PRIVATE_KEY_PATTERN.search(line):
                if not self._is_placeholder(line):
                    issues.append(Issue(
                        type="SECRET",
                        severity="CRITICAL",
                        file=file,
                        start_line=idx,
                        end_line=idx,
                    ))
            elif AWS_ACCESS_KEY_PATTERN.search(line) or GITHUB_TOKEN_PATTERN.search(line):
                if not self._is_placeholder(line):
                    issues.append(Issue(
                        type="SECRET",
                        severity="CRITICAL",
                        file=file,
                        start_line=idx,
                        end_line=idx,
                    ))
            elif GENERIC_API_KEY_PATTERN.search(line):
                if not self._is_placeholder(line):
                    issues.append(Issue(
                        type="SECRET",
                        severity="HIGH",
                        file=file,
                        start_line=idx,
                        end_line=idx,
                    ))

        return issues

    def _is_placeholder(self, val: str) -> bool:
        """Returns True if string value matches common test/dummy placeholders."""
        lowered = val.lower().strip()
        for placeholder in PLACEHOLDER_SUBSTRINGS:
            if placeholder in lowered:
                return True
        return False
