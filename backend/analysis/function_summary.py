"""
CodeJev Interprocedural Function Summaries & Cache - Phase 13
==============================================================

Computes, caches, and propagates interprocedural function summaries across files.
Captures constant return values, passthrough parameters, taint/sanitization propagation,
and potential exceptions raised. Handles recursion and cyclic calls safely.
"""

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.project_analyzer import FunctionDefinition, ProjectAnalyzer


@dataclass
class FunctionSummary:
    """
    Cached summary representation of a function's observable behavior.
    """
    func_name: str
    file: str
    returns_constant: Optional[Any] = None
    has_constant_return: bool = False
    returns_param_index: Optional[int] = None
    returns_tainted: bool = False
    returns_sanitized: bool = False
    may_raise: List[str] = field(default_factory=list)
    is_unknown: bool = False


class SummaryCache:
    """
    Memoized cache for project-level function summaries with cycle/recursion protection.
    """
    def __init__(self, project_analyzer: Optional["ProjectAnalyzer"] = None):
        self.project_analyzer = project_analyzer
        self.cache: Dict[Tuple[str, str], FunctionSummary] = {}
        self.in_progress: Set[Tuple[str, str]] = set()

    def get_summary(self, file: str, func_name: str) -> FunctionSummary:
        """
        Retrieves or computes the summary for a function in a given file.
        Returns unknown summary if function definition is missing or cyclic recursion occurs.
        """
        key = (file, func_name)

        # 1. Cycle detection: if currently being computed, return unknown summary to terminate recursion
        if key in self.in_progress:
            return FunctionSummary(func_name=func_name, file=file, is_unknown=True)

        # 2. Return memoized summary if already computed
        if key in self.cache:
            return self.cache[key]

        if not self.project_analyzer:
            return FunctionSummary(func_name=func_name, file=file, is_unknown=True)

        # Resolve function definition from project index
        mod_name = self.project_analyzer._filename_to_module(file)
        func_def = self.project_analyzer.func_index.get((mod_name, func_name))
        if not func_def:
            return FunctionSummary(func_name=func_name, file=file, is_unknown=True)

        # Mark in-progress and compute summary
        self.in_progress.add(key)
        summary = self._compute_summary(func_def)
        self.in_progress.remove(key)

        self.cache[key] = summary
        return summary

    def _compute_summary(self, func_def: "FunctionDefinition") -> FunctionSummary:
        """Analyses function AST to build a FunctionSummary."""
        func_node = func_def.node
        file = func_def.file
        func_name = func_def.func_name

        summary = FunctionSummary(func_name=func_name, file=file)

        # 1. Extract parameters
        param_names = []
        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_names = [a.arg for a in func_node.args.args]

        # 2. Extract returns and exception raises
        returns = func_def.return_values
        may_raise = []

        for n in ast.walk(func_node):
            if isinstance(n, ast.Raise):
                if isinstance(n.exc, ast.Call) and isinstance(n.exc.func, ast.Name):
                    may_raise.append(n.exc.func.id)
                elif isinstance(n.exc, ast.Name):
                    may_raise.append(n.exc.id)

        summary.may_raise = may_raise

        # 3. Analyze constant returns or parameter passthroughs
        if returns:
            # Check if all return expressions evaluate to the same constant value
            constant_vals = []
            param_returns = []

            for ret in returns:
                if isinstance(ret, ast.Constant):
                    constant_vals.append(ret.value)
                elif isinstance(ret, ast.Name) and ret.id in param_names:
                    param_returns.append(param_names.index(ret.id))

            if len(constant_vals) == len(returns) and len(set(constant_vals)) == 1:
                summary.has_constant_return = True
                summary.returns_constant = constant_vals[0]

            if len(param_returns) == len(returns) and len(set(param_returns)) == 1:
                summary.returns_param_index = param_returns[0]

        return summary
