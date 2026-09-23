"""
JavaScript Bug Detector - Phase 11
===================================

Detects bug risks in JavaScript and TypeScript ASTs:
1. Suspicious assignment in condition (if (x = getValue()))
2. Unreachable code following return statement in function body
"""

from collections import deque
from typing import List, Optional, Set
from backend.schemas import Issue


class JavaScriptBugDetector:
    """
    Detector for bug patterns in JS/TS ESTree ASTs.
    """
    def detect(self, tree: object, file: str, changed_lines: Optional[Set[int]] = None) -> List[Issue]:
        issues: List[Issue] = []

        # 1. Unreachable Code after ReturnStatement in blocks
        issues.extend(self._detect_unreachable_code(tree, file, changed_lines))

        nodes = self._walk_tree(tree)

        for node in nodes:
            start_line = self._get_start_line(node)
            end_line = self._get_end_line(node)

            if changed_lines is not None and not self._is_line_changed(start_line, end_line, changed_lines):
                continue

            node_type = getattr(node, "type", None)

            # -------------------------------------------------------------
            # Rule 1: Assignment in condition: if (x = getValue())
            # -------------------------------------------------------------
            if node_type == "IfStatement":
                test = getattr(node, "test", None)
                if test and getattr(test, "type", None) == "AssignmentExpression":
                    issues.append(
                        Issue(
                            type="BUG",
                            severity="MEDIUM",
                            file=file,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )

        # Deduplicate issues
        seen = set()
        unique: List[Issue] = []
        for issue in issues:
            key = (issue.type, issue.severity, issue.file, issue.start_line, issue.end_line)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        return unique

    def _detect_unreachable_code(self, tree: object, file: str, changed_lines: Optional[Set[int]]) -> List[Issue]:
        issues: List[Issue] = []
        nodes = self._walk_tree(tree)

        for node in nodes:
            body = getattr(node, "body", None)
            if isinstance(body, list):
                terminated = False
                for stmt in body:
                    if terminated:
                        st_line = self._get_start_line(stmt)
                        end_line = self._get_end_line(stmt)
                        if self._is_line_changed(st_line, end_line, changed_lines):
                            issues.append(
                                Issue(
                                    type="BUG",
                                    severity="LOW",
                                    file=file,
                                    start_line=st_line,
                                    end_line=end_line,
                                )
                            )
                    elif getattr(stmt, "type", None) == "ReturnStatement":
                        terminated = True
            elif body and getattr(body, "type", None) == "BlockStatement":
                b_stmts = getattr(body, "body", None)
                if isinstance(b_stmts, list):
                    terminated = False
                    for stmt in b_stmts:
                        if terminated:
                            st_line = self._get_start_line(stmt)
                            end_line = self._get_end_line(stmt)
                            if self._is_line_changed(st_line, end_line, changed_lines):
                                issues.append(
                                    Issue(
                                        type="BUG",
                                        severity="LOW",
                                        file=file,
                                        start_line=st_line,
                                        end_line=end_line,
                                    )
                                )
                        elif getattr(stmt, "type", None) == "ReturnStatement":
                            terminated = True

        return issues

    def _walk_tree(self, root: object) -> List[object]:
        nodes: List[object] = []
        queue = deque([root])

        while queue:
            curr = queue.popleft()
            if not curr or not hasattr(curr, "__dict__"):
                continue

            nodes.append(curr)

            for attr in dir(curr):
                if attr.startswith("_") or attr in ("loc", "range"):
                    continue
                val = getattr(curr, attr, None)
                if isinstance(val, list):
                    for item in val:
                        if hasattr(item, "__dict__") and hasattr(item, "type"):
                            queue.append(item)
                elif hasattr(val, "__dict__") and hasattr(val, "type"):
                    queue.append(val)

        return nodes

    def _get_start_line(self, node: object) -> int:
        loc = getattr(node, "loc", None)
        if loc and hasattr(loc, "start"):
            return getattr(loc.start, "line", 1)
        return 1

    def _get_end_line(self, node: object) -> int:
        loc = getattr(node, "loc", None)
        if loc and hasattr(loc, "end"):
            return getattr(loc.end, "line", self._get_start_line(node))
        return self._get_start_line(node)

    def _is_line_changed(self, start_line: int, end_line: int, changed_lines: Optional[Set[int]]) -> bool:
        if changed_lines is None:
            return True
        node_range = set(range(start_line, end_line + 1))
        return bool(node_range.intersection(changed_lines))
