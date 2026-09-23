"""
Security AST Detector - Phase 8
================================

Detects security vulnerabilities using AST syntax, taint propagation, & context inspection:
1. Calls to `eval(...)`
2. Calls to `exec(...)`
3. Calls with explicit `shell=True` keyword arguments (e.g. `subprocess.run(..., shell=True)`)
4. Dynamic SQL construction / string concatenation passed to database execution methods
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector


class SecurityDetector(BaseDetector):
    """
    Detector for security risks, command injections, dynamic SQL construction, and taint sinks.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        issues: List[Issue] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)

                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)

                # Skip if not on a changed line
                if not self.is_line_changed(start_line, end_line, context.changed_lines):
                    continue

                # 1. Detect eval() and exec() calls
                if func_name in ("eval", "exec"):
                    issues.append(
                        Issue(
                            type="SECURITY",
                            severity="HIGH",
                            file=context.file,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )

                # 2. Detect shell=True command injection sinks
                elif self._has_shell_true_kwarg(node):
                    cmd_arg = node.args[0] if node.args else None
                    # Check if command argument is explicitly sanitized via shlex.quote()
                    is_sanitized = False
                    if cmd_arg:
                        if context._is_shlex_quote(cmd_arg):
                            is_sanitized = True
                        elif isinstance(cmd_arg, ast.Name):
                            for assigned in context.get_assigned_values(cmd_arg.id):
                                if context._is_shlex_quote(assigned):
                                    is_sanitized = True

                    if not is_sanitized:
                        issues.append(
                            Issue(
                                type="SECURITY",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

                # 3. Detect dynamic SQL string concatenation passed to database execution
                elif func_name in ("execute", "executemany") and node.args:
                    first_arg = node.args[0]
                    is_parameterized = len(node.args) > 1 or any(kw.arg in ("params", "parameters") for kw in node.keywords)

                    if not is_parameterized:
                        taint = context.get_node_taint(first_arg)
                        is_dynamic = context.is_dynamic_sql_concatenation(first_arg)
                        if (taint and taint.is_tainted) or is_dynamic:
                            issues.append(
                                Issue(
                                    type="SECURITY",
                                    severity="HIGH",
                                    file=context.file,
                                    start_line=start_line,
                                    end_line=end_line,
                                )
                            )

            # Check standalone assignments like `query = "SELECT..." + user_id`
            elif isinstance(node, ast.Assign):
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)

                if self.is_line_changed(start_line, end_line, context.changed_lines):
                    taint = context.get_node_taint(node.value)
                    is_dynamic = context.is_dynamic_sql_concatenation(node.value)
                    if (taint and taint.is_tainted and is_dynamic) or (is_dynamic and not isinstance(node.value, ast.Call)):
                        issues.append(
                            Issue(
                                type="SECURITY",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

        return issues

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """Extracts function name for direct calls or method calls."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _has_shell_true_kwarg(self, node: ast.Call) -> bool:
        """Returns True if the function call contains a keyword argument shell=True."""
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False
