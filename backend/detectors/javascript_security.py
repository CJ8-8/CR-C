"""
JavaScript Security Detector - Phase 11
========================================

Detects security risks in JavaScript and TypeScript ASTs:
1. eval(...) usage (eval(userInput))
2. Command execution (child_process.exec(cmd), exec(cmd))
3. DOM / XSS innerHTML assignment (element.innerHTML = userInput)
4. Dynamic SQL concatenation ("SELECT ... WHERE id=" + userId)
"""

from collections import deque
from typing import List, Optional, Set
from backend.schemas import Issue


class JavaScriptSecurityDetector:
    """
    Detector for security vulnerabilities in JS/TS ESTree ASTs.
    """
    def detect(self, tree: object, file: str, changed_lines: Optional[Set[int]] = None) -> List[Issue]:
        issues: List[Issue] = []
        nodes = self._walk_tree(tree)

        for node in nodes:
            start_line = self._get_start_line(node)
            end_line = self._get_end_line(node)

            if changed_lines is not None and not self._is_line_changed(start_line, end_line, changed_lines):
                continue

            node_type = getattr(node, "type", None)

            # -------------------------------------------------------------
            # Rule 1: eval(userInput)
            # -------------------------------------------------------------
            if node_type == "CallExpression":
                callee_name = self._get_callee_name(getattr(node, "callee", None))
                if callee_name == "eval":
                    issues.append(
                        Issue(
                            type="SECURITY",
                            severity="HIGH",
                            file=file,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )
                # -------------------------------------------------------------
                # Rule 2: child_process.exec(cmd) or exec(cmd)
                # -------------------------------------------------------------
                elif callee_name in ("exec", "child_process.exec", "shell.exec"):
                    issues.append(
                        Issue(
                            type="SECURITY",
                            severity="HIGH",
                            file=file,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )

            # -------------------------------------------------------------
            # Rule 3: element.innerHTML = userInput (DOM XSS)
            # -------------------------------------------------------------
            elif node_type == "AssignmentExpression":
                left = getattr(node, "left", None)
                if left and getattr(left, "type", None) == "MemberExpression":
                    prop = getattr(left, "property", None)
                    if prop and getattr(prop, "name", getattr(prop, "value", None)) == "innerHTML":
                        issues.append(
                            Issue(
                                type="SECURITY",
                                severity="HIGH",
                                file=file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )

            # -------------------------------------------------------------
            # Rule 4: Dynamic SQL Construction ("SELECT ... " + userId)
            # -------------------------------------------------------------
            elif node_type == "BinaryExpression" and getattr(node, "operator", None) == "+":
                if self._is_sql_concatenation(node):
                    issues.append(
                        Issue(
                            type="SECURITY",
                            severity="HIGH",
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

    def _get_callee_name(self, callee: object) -> str:
        if not callee:
            return ""
        c_type = getattr(callee, "type", None)
        if c_type == "Identifier":
            return getattr(callee, "name", "")
        elif c_type == "MemberExpression":
            obj = getattr(callee, "object", None)
            prop = getattr(callee, "property", None)
            obj_name = getattr(obj, "name", "") if obj else ""
            prop_name = getattr(prop, "name", "") if prop else ""
            if obj_name and prop_name:
                return f"{obj_name}.{prop_name}"
            return prop_name
        return ""

    def _is_sql_concatenation(self, node: object) -> bool:
        """Returns True if binary + expression contains a SQL query string literal."""
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)

        for operand in (left, right):
            if operand and getattr(operand, "type", None) == "Literal":
                val = str(getattr(operand, "value", "")).upper()
                if any(kw in val for kw in ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM")):
                    return True
        return False

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
