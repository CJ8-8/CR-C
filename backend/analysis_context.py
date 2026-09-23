"""
CodeJev Analysis Context & Taint Tracker - Phase 8
====================================================

Provides contextual analysis, local/cross-file variable tracking, and conservative
Taint Analysis (tracking data propagation from Sources to Sinks through Sanitizers).
"""

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from backend.analysis.control_flow import ControlFlowGraph
from backend.analysis.program_state import ProgramState, Nullability, ValueState

if TYPE_CHECKING:
    from backend.project_analyzer import ProjectAnalyzer


@dataclass
class TaintState:
    """
    Represents the taint status of a variable or expression.
    """
    is_tainted: bool
    source_file: str
    source_line: int
    source_kind: str


class AnalysisContext:
    """
    Holds AST tree, file information, changed line numbers, local variable relationships,
    CFG, ProgramState, and Taint Tracker for tracking untrusted data flow.
    """
    def __init__(
        self, 
        tree: ast.AST, 
        file: str, 
        changed_lines: Optional[Set[int]] = None,
        project_analyzer: Optional["ProjectAnalyzer"] = None
    ):
        self.tree = tree
        self.file = file
        self.changed_lines = changed_lines
        self.project_analyzer = project_analyzer
        
        # Phase 13 CFG and ProgramState
        self.cfg = ControlFlowGraph(self.file, self.tree)
        self.program_state = ProgramState()

        # Local variable assignment map: var_name -> List of assigned value AST nodes
        self.assignments: Dict[str, List[ast.AST]] = {}
        # Taint map: (file, scope_name, var_name) -> TaintState
        self.taint_map: Dict[Tuple[str, str, str], TaintState] = {}
        
        self._build_assignment_map()
        self._populate_program_state()
        self._populate_taint_map()

    def _build_assignment_map(self) -> None:
        """
        Scans AST to map local variable names to their assigned value AST nodes.
        """
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if var_name not in self.assignments:
                            self.assignments[var_name] = []
                        self.assignments[var_name].append(node.value)

    def _populate_taint_map(self) -> None:
        """
        Scans assignments and function calls to populate initial scope-aware taint states.
        """
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        scope = self._get_node_scope(node)
                        taint = self.get_node_taint(node.value, scope=scope)
                        if taint and taint.is_tainted:
                            self.taint_map[(self.file, scope, var_name)] = taint

            elif isinstance(node, ast.Call) and self.project_analyzer:
                func_def = self.project_analyzer.resolve_function(self.file, node)
                if func_def and node.args:
                    target_scope = func_def.func_name
                    target_file = func_def.file
                    if isinstance(func_def.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for idx, arg_node in enumerate(node.args):
                            if idx < len(func_def.node.args.args):
                                param_name = func_def.node.args.args[idx].arg
                                caller_scope = self._get_node_scope(node)
                                arg_taint = self.get_node_taint(arg_node, scope=caller_scope)
                                if arg_taint and arg_taint.is_tainted:
                                    self.taint_map[(target_file, target_scope, param_name)] = arg_taint

    def get_node_taint(
        self, 
        node: ast.AST, 
        scope: str = "global", 
        visited_vars: Optional[Set[str]] = None
    ) -> Optional[TaintState]:
        """
        Evaluates whether an AST node is tainted by tracing back to untrusted Sources
        while checking for explicitly recognized Sanitizers.
        """
        if visited_vars is None:
            visited_vars = set()

        if node is None:
            return None

        # 1. Check explicitly recognized Sanitizer: shlex.quote(...)
        if self._is_shlex_quote(node):
            return None  # Sanitized!

        # 2. Check direct Source: input() or request.args[...]
        source_taint = self._check_direct_source(node)
        if source_taint:
            return source_taint

        # 3. Check variable reference
        if isinstance(node, ast.Name):
            var_name = node.id
            if var_name in visited_vars:
                return None
            visited_vars.add(var_name)

            if (self.file, scope, var_name) in self.taint_map:
                return self.taint_map[(self.file, scope, var_name)]
            if (self.file, "global", var_name) in self.taint_map:
                return self.taint_map[(self.file, "global", var_name)]

            assigned_nodes = self.get_assigned_values(var_name)
            for assigned in assigned_nodes:
                taint = self.get_node_taint(assigned, scope=scope, visited_vars=visited_vars)
                if taint and taint.is_tainted:
                    return taint

        # 4. Check binary operations (e.g., "prefix" + x)
        elif isinstance(node, ast.BinOp):
            left_taint = self.get_node_taint(node.left, scope=scope, visited_vars=visited_vars)
            if left_taint and left_taint.is_tainted:
                return left_taint
            right_taint = self.get_node_taint(node.right, scope=scope, visited_vars=visited_vars)
            if right_taint and right_taint.is_tainted:
                return right_taint

        # 5. Check f-strings (JoinedStr)
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    val_taint = self.get_node_taint(value.value, scope=scope, visited_vars=visited_vars)
                    if val_taint and val_taint.is_tainted:
                        return val_taint

        # 6. Check function calls & cross-file returns (e.g. x = get_user_input())
        elif isinstance(node, ast.Call) and self.project_analyzer:
            returns = self.project_analyzer.resolve_call_returns(self.file, node)
            for ret in returns:
                ret_taint = self.get_node_taint(ret, scope=scope, visited_vars=visited_vars)
                if ret_taint and ret_taint.is_tainted:
                    return ret_taint

        return None

    def _check_direct_source(self, node: ast.AST) -> Optional[TaintState]:
        """Recognizes explicit untrusted sources like input() or request.args/form/json."""
        start_line = getattr(node, "lineno", 1)

        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node)
            if func_name == "input":
                return TaintState(
                    is_tainted=True,
                    source_file=self.file,
                    source_line=start_line,
                    source_kind="input()"
                )

        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
                if node.value.value.id == "request" and node.value.attr in ("args", "form", "json"):
                    return TaintState(
                        is_tainted=True,
                        source_file=self.file,
                        source_line=start_line,
                        source_kind=f"request.{node.value.attr}"
                    )
            elif isinstance(node.value, ast.Name) and node.value.id == "request":
                return TaintState(
                    is_tainted=True,
                    source_file=self.file,
                    source_line=start_line,
                    source_kind="request"
                )

        return None

    def _is_shlex_quote(self, node: ast.AST) -> bool:
        """Checks if a node is an explicit call to shlex.quote(...)."""
        if isinstance(node, ast.Call):
            func_name = self._get_func_name(node)
            if func_name == "quote":
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "shlex":
                        return True
                return True
        return False

    def _get_node_scope(self, node: ast.AST) -> str:
        """Determines if an AST node lives inside a function or at module (global) level."""
        return "global"

    def get_assigned_values(self, var_name: str) -> List[ast.AST]:
        """Returns list of assigned value AST nodes for a variable name."""
        return self.assignments.get(var_name, [])

    def _populate_program_state(self) -> None:
        """Populates initial program state from variable assignments."""
        for var_name, assigned_list in self.assignments.items():
            for assigned in assigned_list:
                if isinstance(assigned, ast.Constant):
                    self.program_state.set_constant(var_name, assigned.value)
                elif isinstance(assigned, ast.Call) and self.project_analyzer:
                    returns = self.project_analyzer.resolve_call_returns(self.file, assigned)
                    if returns and all(isinstance(r, ast.Constant) and r.value is None for r in returns):
                        self.program_state.set_none(var_name)

    def is_value_none(self, var_name: str, lineno: Optional[int] = None) -> bool:
        """
        Returns True ONLY if a variable is definitely None at the specified line number,
        considering path-sensitive guards ('if x is None: return' or 'if x is not None:').
        """
        assigned_nodes = self.get_assigned_values(var_name)
        if not assigned_nodes:
            return False

        # 1. Check path guards if line number is provided
        if lineno is not None:
            # Check if there is a guard before lineno
            for node in ast.walk(self.tree):
                if isinstance(node, ast.If):
                    if_start = node.lineno
                    if_end = getattr(node, "end_lineno", if_start)

                    # Guard pattern A: 'if x is None: return' (early return guard before lineno)
                    is_none_check = isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], (ast.Is, ast.Eq)) and isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value is None
                    if is_none_check and isinstance(node.test.left, ast.Name) and node.test.left.id == var_name:
                        # Check if body contains return/raise
                        has_return = any(isinstance(stmt, (ast.Return, ast.Raise)) for stmt in ast.walk(node))
                        if has_return and lineno > if_end:
                            return False  # Guarded after early return!
                        if lineno >= if_start and lineno <= if_end:
                            # Inside the if block where x is None
                            return True

                    # Guard pattern B: 'if x is not None:' (encloses lineno)
                    is_not_none_check = isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], (ast.IsNot, ast.NotEq)) and isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value is None
                    if is_not_none_check and isinstance(node.test.left, ast.Name) and node.test.left.id == var_name:
                        # If lineno is inside the body of 'if x is not None:', x is NOT None!
                        if lineno > if_start and lineno <= if_end:
                            return False  # Safe inside 'if x is not None:' block!

        # 2. Check assignments
        for node in assigned_nodes:
            if isinstance(node, ast.Constant) and node.value is None:
                return True

            if isinstance(node, ast.Call) and self.project_analyzer:
                returns = self.project_analyzer.resolve_call_returns(self.file, node)
                if returns:
                    all_none = all(isinstance(ret, ast.Constant) and ret.value is None for ret in returns)
                    if all_none:
                        return True

        return False

    def is_dynamic_sql_concatenation(self, node: ast.AST) -> bool:
        """
        Inspects an AST node to determine if it represents dynamic SQL string concatenation.
        """
        if isinstance(node, ast.Name):
            for assigned in self.get_assigned_values(node.id):
                if self.is_dynamic_sql_concatenation(assigned):
                    return True
            return False

        if isinstance(node, ast.Call) and self.project_analyzer:
            returns = self.project_analyzer.resolve_call_returns(self.file, node)
            for ret in returns:
                if self.is_dynamic_sql_concatenation(ret):
                    return True

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            sql_keywords = ("select ", "insert ", "update ", "delete ", "from ", "where ")
            left_has_sql = self._node_contains_sql_keyword(node.left, sql_keywords)
            right_has_sql = self._node_contains_sql_keyword(node.right, sql_keywords)

            if left_has_sql or right_has_sql:
                return True

        if isinstance(node, ast.JoinedStr):
            sql_keywords = ("select ", "insert ", "update ", "delete ", "from ", "where ")
            has_sql_text = False
            has_formatted_var = False

            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if any(kw in value.value.lower() for kw in sql_keywords):
                        has_sql_text = True
                elif isinstance(value, ast.FormattedValue):
                    has_formatted_var = True

            if has_sql_text and has_formatted_var:
                return True

        return False

    def _node_contains_sql_keyword(self, node: ast.AST, keywords: tuple) -> bool:
        """Checks if an AST node is a string literal containing SQL keywords."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_lower = node.value.lower()
            return any(kw in val_lower for kw in keywords)
        return False

    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        """Extracts function name for direct calls or method calls."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
