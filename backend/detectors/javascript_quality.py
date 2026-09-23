"""
JavaScript Code Quality Detector - Phase 11
============================================

Detects code quality concerns in JavaScript and TypeScript ASTs:
1. Leftover console.log(...) calls
2. Duplicate module import / require(...) statements
"""

from collections import deque
from typing import List, Optional, Set
from backend.schemas import Issue


class JavaScriptQualityDetector:
    """
    Detector for code quality and leftover debug constructs in JS/TS ESTree ASTs.
    """
    def detect(self, tree: object, file: str, changed_lines: Optional[Set[int]] = None) -> List[Issue]:
        issues: List[Issue] = []
        seen_imports: Set[str] = set()
        nodes = self._walk_tree(tree)

        for node in nodes:
            start_line = self._get_start_line(node)
            end_line = self._get_end_line(node)

            if changed_lines is not None and not self._is_line_changed(start_line, end_line, changed_lines):
                continue

            node_type = getattr(node, "type", None)

            # -------------------------------------------------------------
            # Rule 1: console.log(...)
            # -------------------------------------------------------------
            if node_type == "CallExpression":
                callee_name = self._get_callee_name(getattr(node, "callee", None))
                if callee_name in ("console.log", "console.debug"):
                    issues.append(
                        Issue(
                            type="CODE_QUALITY",
                            severity="LOW",
                            file=file,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )
                # -------------------------------------------------------------
                # Rule 2: const x = require("mod") duplicate require
                # -------------------------------------------------------------
                elif callee_name == "require":
                    args = getattr(node, "arguments", [])
                    if args and getattr(args[0], "type", None) == "Literal":
                        mod_name = str(getattr(args[0], "value", ""))
                        req_key = f"require:{mod_name}"
                        if req_key in seen_imports:
                            issues.append(
                                Issue(
                                    type="CODE_QUALITY",
                                    severity="LOW",
                                    file=file,
                                    start_line=start_line,
                                    end_line=end_line,
                                )
                            )
                        else:
                            seen_imports.add(req_key)

            # -------------------------------------------------------------
            # Rule 3: import { x } from "mod" duplicate import
            # -------------------------------------------------------------
            elif node_type == "ImportDeclaration":
                source = getattr(node, "source", None)
                if source and getattr(source, "type", None) == "Literal":
                    mod_name = str(getattr(source, "value", ""))
                    imp_key = f"import:{mod_name}"
                    if imp_key in seen_imports:
                        issues.append(
                            Issue(
                                type="CODE_QUALITY",
                                severity="LOW",
                                file=file,
                                start_line=start_line,
                                end_line=end_line,
                            )
                        )
                    else:
                        seen_imports.add(imp_key)

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
