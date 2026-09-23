"""
CodeJev Performance Detector - Phase 10
=========================================

Detects static performance heuristics and repeated operations inside loops:
1. Repeated regex compilation (re.compile inside loops)
2. Inefficient string concatenation in loops (result += str(...))
3. Repeated expensive function calls / collection construction in loops (sorted(), list() inside loops)
4. Repeated list membership checks in loops (item in large_list inside loops)
5. Repeated constant structure construction in loops (literal dict/list in loops)

Note: All performance findings are static heuristics, not measured runtime benchmarks.
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.analysis_context import AnalysisContext
from backend.detectors.base import BaseDetector


class PerformanceDetector(BaseDetector):
    """
    Detector for static performance heuristics inside loops.
    """
    def detect(self, context: AnalysisContext) -> List[Issue]:
        issues: List[Issue] = []

        # Find all loop nodes (For, AsyncFor, While)
        loop_nodes = [node for node in ast.walk(context.tree) if isinstance(node, (ast.For, ast.AsyncFor, ast.While))]

        for loop in loop_nodes:
            # Walk nodes strictly inside loop body/orelse
            for child in self._iter_loop_children(loop):
                start_line = getattr(child, "lineno", loop.lineno)
                end_line = getattr(child, "end_lineno", start_line)

                if not self.is_line_changed(start_line, end_line, context.changed_lines):
                    continue

                # -------------------------------------------------------------
                # 1. Repeated Regex Compilation: re.compile(...) in loop
                # -------------------------------------------------------------
                if isinstance(child, ast.Call):
                    func_name = self._get_call_func_name(child)
                    if func_name in ("re.compile", "compile") and self._is_re_module_call(child):
                        issues.append(
                            Issue(
                                type="PERFORMANCE",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )
                    # -------------------------------------------------------------
                    # 3. Repeated Expensive Call / Construction: sorted(), list(), dict(), set()
                    # -------------------------------------------------------------
                    elif func_name in ("sorted", "list", "dict", "set"):
                        # Avoid flagging simple list(range(...)) if not in loop or if trivial
                        issues.append(
                            Issue(
                                type="PERFORMANCE",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

                # -------------------------------------------------------------
                # 2. Inefficient String Concatenation: target += ...
                # -------------------------------------------------------------
                elif isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                    if isinstance(child.target, ast.Name):
                        issues.append(
                            Issue(
                                type="PERFORMANCE",
                                severity="LOW",
                                file=context.file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

                # -------------------------------------------------------------
                # 4. Repeated List Membership Check: if item in list_var:
                # -------------------------------------------------------------
                elif isinstance(child, ast.Compare):
                    for op in child.ops:
                        if isinstance(op, ast.In):
                            # Check if comparator is a variable (Name)
                            for comp in child.comparators:
                                if isinstance(comp, ast.Name):
                                    issues.append(
                                        Issue(
                                            type="PERFORMANCE",
                                            severity="LOW",
                                            file=context.file,
                                            start_line=start_line,
                                            end_line=end_line,
                                        )
                                    )

                # -------------------------------------------------------------
                # 5. Repeated Constant Structure Construction: dict/list literals in loop assignment
                # -------------------------------------------------------------
                elif isinstance(child, ast.Assign):
                    if isinstance(child.value, (ast.Dict, ast.List)) and len(child.value.keys if isinstance(child.value, ast.Dict) else child.value.elts) > 0:
                        # Ensure it contains constant values
                        if self._is_static_literal_container(child.value):
                            issues.append(
                                Issue(
                                    type="PERFORMANCE",
                                    severity="LOW",
                                    file=context.file,
                                    start_line=start_line,
                                    end_line=end_line,
                                )
                            )

        # Deduplicate issues with identical (type, severity, file, start_line, end_line)
        seen = set()
        unique: List[Issue] = []
        for issue in issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    def _iter_loop_children(self, loop_node: ast.AST):
        """Yields all descendant nodes inside loop body and orelse blocks."""
        body_nodes = getattr(loop_node, "body", []) + getattr(loop_node, "orelse", [])
        for stmt in body_nodes:
            yield stmt
            for child in ast.walk(stmt):
                if child is not stmt:
                    yield child

    def _get_call_func_name(self, node: ast.Call) -> str:
        """Extracts full call string like 're.compile' or 'sorted'."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            val_str = ""
            if isinstance(node.func.value, ast.Name):
                val_str = node.func.value.id + "."
            return val_str + node.func.attr
        return ""

    def _is_re_module_call(self, node: ast.Call) -> bool:
        """Checks if call is re.compile or compile call."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return node.func.value.id == "re" and node.func.attr == "compile"
        if isinstance(node.func, ast.Name) and node.func.id == "compile":
            return True
        return False

    def _is_static_literal_container(self, container_node: ast.AST) -> bool:
        """Checks if dict or list container contains static/constant elements."""
        if isinstance(container_node, ast.Dict):
            for k in container_node.keys:
                if k is not None and not isinstance(k, ast.Constant):
                    return False
            for v in container_node.values:
                if not isinstance(v, ast.Constant):
                    return False
            return True
        elif isinstance(container_node, ast.List):
            for elt in container_node.elts:
                if not isinstance(elt, ast.Constant):
                    return False
            return True
        return False
