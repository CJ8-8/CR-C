"""
Bug AST Detector - Phase 10
============================

Detects bug risks using AST syntax & context inspection:
1. Bare except clauses & swallowed exception handlers (except Exception: pass)
2. Mutable default arguments in function definitions
3. Definite None dereferences
4. Unreachable code following return, raise, break, or continue
5. Constant-condition branches (if True:, while False:)
6. Suspicious identity comparison (val is 5, text is "hello")
7. Duplicate dictionary keys ({"a": 1, "a": 2})
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector


class BugDetector(BaseDetector):
    """
    Detector for bug risks, bare excepts, swallowed exceptions, mutable defaults,
    unreachable code, constant conditions, suspicious identity checks, and duplicate dict keys.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        issues: List[Issue] = []

        # -----------------------------------------------------------------
        # Unreachable Code Check across statement blocks
        # -----------------------------------------------------------------
        issues.extend(self._detect_unreachable_code(context))

        for node in ast.walk(context.tree):
            start_line = getattr(node, "lineno", 1)
            end_line = getattr(node, "end_lineno", start_line)

            # -----------------------------------------------------------------
            # Rule A: Bare & Swallowed Except Handler Detection
            # -----------------------------------------------------------------
            if isinstance(node, ast.ExceptHandler):
                if self._is_bare_or_swallowed_except(node):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule B: Mutable Default Arguments Detection
            # -----------------------------------------------------------------
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._has_mutable_default_arg(node):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule C: Definite None Dereference Detection (Path-Sensitive)
            # -----------------------------------------------------------------
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if context.is_value_none(node.value.id, start_line):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            elif isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Name) and context.is_value_none(node.value.id, start_line):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

                # Rule H: Constant Collection Index Out of Bounds Detection (Phase 13)
                if self._is_index_out_of_bounds(node, context):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule G: Division / Modulo by Zero Detection (Phase 13)
            # -----------------------------------------------------------------
            elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                if self._is_zero_divisor(node.right, context):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="HIGH",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule D: Constant-Condition & Duplicate Branch Detection (Phase 13)
            # -----------------------------------------------------------------
            elif isinstance(node, ast.If):
                if self._is_constant_condition(node.test):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )
                # Duplicate condition check in if-elif chain
                dup_cond_issues = self._detect_duplicate_if_conditions(node, context)
                issues.extend(dup_cond_issues)

            elif isinstance(node, ast.While):
                if self._is_constant_condition(node.test):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule E: Suspicious Identity Comparison (val is 5, text is "hello")
            # -----------------------------------------------------------------
            elif isinstance(node, ast.Compare):
                if self._has_suspicious_identity_cmp(node):
                    if self.is_line_changed(start_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="MEDIUM",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -----------------------------------------------------------------
            # Rule F: Duplicate Dictionary Keys ({"a": 1, "a": 2})
            # -----------------------------------------------------------------
            elif isinstance(node, ast.Dict):
                dup_issues = self._detect_duplicate_dict_keys(node, context)
                issues.extend(dup_issues)

        # Deduplicate issues with identical (type, severity, file, start_line, end_line)
        seen = set()
        unique: List[Issue] = []
        for issue in issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    def _detect_unreachable_code(self, context: AnalysisContext) -> List[Issue]:
        """
        Scans all block statement lists (Module, FunctionDef, If, For, While, Try)
        for statements following return, raise, break, or continue in the same block.
        """
        issues: List[Issue] = []

        for parent in ast.walk(context.tree):
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, None)
                if isinstance(block, list):
                    terminated = False
                    for stmt in block:
                        if terminated:
                            st_line = getattr(stmt, "lineno", 1)
                            end_line = getattr(stmt, "end_lineno", st_line)
                            if self.is_line_changed(st_line, end_line, context.changed_lines):
                                issues.append(
                                    Issue(
                                        type="BUG",
                                        severity="LOW",
                                        file=context.file,
                                        start_line=st_line,
                                        end_line=end_line,
                                    )
                                )
                        elif isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                            terminated = True

        return issues

    def _is_bare_or_swallowed_except(self, node: ast.ExceptHandler) -> bool:
        """
        Returns True for bare `except:` or swallowed `except Exception: pass` without logging/re-raising.
        """
        # Bare except:
        if node.type is None:
            return True

        # Check if exception type is Exception or BaseException
        if isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            # Check if body consists solely of pass or pass + return None without logging or re-raising
            if not node.body:
                return True
            
            # If body is purely [pass]
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                return True

            # If body is [pass, return ...]
            if len(node.body) == 2 and isinstance(node.body[0], ast.Pass):
                return True

        return False

    def _is_constant_condition(self, test_node: ast.AST) -> bool:
        """Returns True if test_node is a constant literal (e.g. True, False, 1, 0)."""
        if isinstance(test_node, ast.Constant):
            if isinstance(test_node.value, (bool, int, float, str)):
                return True
        return False

    def _has_suspicious_identity_cmp(self, node: ast.Compare) -> bool:
        """
        Returns True if `is` or `is not` is used with a literal constant that is NOT None/bool.
        """
        for op in node.ops:
            if isinstance(op, (ast.Is, ast.IsNot)):
                # Check left and all comparators
                operands = [node.left] + node.comparators
                for operand in operands:
                    if isinstance(operand, ast.Constant):
                        val = operand.value
                        # Flag if literal is int, float, str, bytes (NOT None, NOT bool)
                        if isinstance(val, (int, float, str, bytes)) and not isinstance(val, bool):
                            return True
        return False

    def _detect_duplicate_dict_keys(self, node: ast.Dict, context: AnalysisContext) -> List[Issue]:
        """Detects duplicate literal keys in a dict literal."""
        issues: List[Issue] = []
        seen_keys: Set[object] = set()

        for key_node, val_node in zip(node.keys, node.values):
            if key_node is not None and isinstance(key_node, ast.Constant):
                k_val = key_node.value
                if k_val in seen_keys:
                    st_line = getattr(key_node, "lineno", node.lineno)
                    end_line = getattr(key_node, "end_lineno", st_line)
                    if self.is_line_changed(st_line, end_line, context.changed_lines):
                        issues.append(
                            Issue(
                                type="BUG",
                                severity="LOW",
                                file=context.file,
                                start_line=st_line,
                                end_line=end_line,
                            )
                        )
                else:
                    seen_keys.add(k_val)

        return issues

    def _has_mutable_default_arg(self, node: ast.FunctionDef) -> bool:
        """Checks if any parameter default in a function definition is a mutable object."""
        defaults = list(node.args.defaults)
        defaults.extend([kw for kw in node.args.kw_defaults if kw is not None])

        for default in defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                return True
            elif isinstance(default, ast.Call):
                func_name = self._get_func_name(default)
                if func_name in ("list", "dict", "set"):
                    return True

        return False

    def _is_zero_divisor(self, divisor_node: ast.AST, context: AnalysisContext) -> bool:
        """Returns True if divisor_node is a constant 0 or variable evaluated to 0."""
        if isinstance(divisor_node, ast.Constant):
            if not isinstance(divisor_node.value, bool) and divisor_node.value == 0:
                return True
        elif isinstance(divisor_node, ast.Name):
            val = context.program_state.get_constant_value(divisor_node.id)
            if val is not None and not isinstance(val, bool) and val == 0:
                return True

            assigned_nodes = context.get_assigned_values(divisor_node.id)
            for assigned in assigned_nodes:
                if isinstance(assigned, ast.Constant) and not isinstance(assigned.value, bool) and assigned.value == 0:
                    return True

        return False

    def _is_index_out_of_bounds(self, node: ast.Subscript, context: AnalysisContext) -> bool:
        """Returns True if node represents a subscript index out of bounds on a literal collection."""
        idx_val = None
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int) and not isinstance(node.slice.value, bool):
            idx_val = node.slice.value
        elif isinstance(node.slice, ast.Name):
            const_val = context.program_state.get_constant_value(node.slice.id)
            if isinstance(const_val, int) and not isinstance(const_val, bool):
                idx_val = const_val

        if idx_val is None:
            return False

        # Collection node can be literal List/Tuple or variable assigned to List/Tuple
        collection_len = None

        if isinstance(node.value, (ast.List, ast.Tuple)):
            collection_len = len(node.value.elts)
        elif isinstance(node.value, ast.Name):
            assigned_nodes = context.get_assigned_values(node.value.id)
            for assigned in assigned_nodes:
                if isinstance(assigned, (ast.List, ast.Tuple)):
                    collection_len = len(assigned.elts)
                    break

        if collection_len is not None:
            if idx_val < 0 or idx_val >= collection_len:
                return True

        return False

    def _detect_duplicate_if_conditions(self, node: ast.If, context: AnalysisContext) -> List[Issue]:
        """Detects duplicate conditions in if-elif chains."""
        issues: List[Issue] = []
        seen_conds: Set[str] = set()

        curr: Optional[ast.AST] = node
        while isinstance(curr, ast.If):
            test_str = ast.dump(curr.test)
            st_line = getattr(curr.test, "lineno", curr.lineno)
            end_line = getattr(curr.test, "end_lineno", st_line)

            if test_str in seen_conds:
                if self.is_line_changed(st_line, end_line, context.changed_lines):
                    issues.append(
                        Issue(
                            type="BUG",
                            severity="LOW",
                            file=context.file,
                            start_line=st_line,
                            end_line=end_line,
                        )
                    )
            else:
                seen_conds.add(test_str)

            if curr.orelse and len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
                curr = curr.orelse[0]
            else:
                break

        return issues

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """Extracts function name for direct calls or method calls."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

