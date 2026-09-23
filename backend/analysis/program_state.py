"""
CodeJev Program State & Lattice System - Phase 13
==================================================

Lightweight abstract program state tracking variable values, constants, nullability,
taint status, and path reachability across control flow branches.
"""

import ast
from enum import Enum
from typing import Any, Dict, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.analysis_context import TaintState


class ValueState(str, Enum):
    """
    Lattice value states for abstract variables.
    """
    UNKNOWN = "UNKNOWN"
    NONE = "NONE"
    CONSTANT = "CONSTANT"
    TAINTED = "TAINTED"
    SANITIZED = "SANITIZED"


class Nullability(str, Enum):
    """
    Nullability states for variable reasoning.
    """
    DEFINITELY_NONE = "DEFINITELY_NONE"
    POSSIBLY_NONE = "POSSIBLY_NONE"
    NOT_NONE = "NOT_NONE"
    UNKNOWN = "UNKNOWN"


class ProgramState:
    """
    Abstract program state for tracking variables at specific control-flow points.
    """
    def __init__(self, is_reachable: bool = True):
        self.is_reachable: bool = is_reachable
        self.var_values: Dict[str, Tuple[ValueState, Any]] = {}
        self.var_nullability: Dict[str, Nullability] = {}
        self.var_taint: Dict[str, Optional[Any]] = {}

    def copy(self) -> "ProgramState":
        """Creates a deep copy of the current program state."""
        new_state = ProgramState(is_reachable=self.is_reachable)
        new_state.var_values = dict(self.var_values)
        new_state.var_nullability = dict(self.var_nullability)
        new_state.var_taint = dict(self.var_taint)
        return new_state

    def set_constant(self, var: str, val: Any) -> None:
        """Sets a variable as a known constant value."""
        if val is None:
            self.set_none(var)
        else:
            self.var_values[var] = (ValueState.CONSTANT, val)
            self.var_nullability[var] = Nullability.NOT_NONE

    def set_none(self, var: str) -> None:
        """Sets a variable as definitely None."""
        self.var_values[var] = (ValueState.NONE, None)
        self.var_nullability[var] = Nullability.DEFINITELY_NONE

    def set_not_none(self, var: str) -> None:
        """Sets a variable as not None."""
        if var in self.var_nullability and self.var_nullability[var] == Nullability.DEFINITELY_NONE:
            del self.var_values[var]
        self.var_nullability[var] = Nullability.NOT_NONE

    def set_possibly_none(self, var: str) -> None:
        """Sets a variable as possibly None (e.g. branch merge)."""
        self.var_nullability[var] = Nullability.POSSIBLY_NONE

    def set_tainted(self, var: str, taint: Any) -> None:
        """Sets a variable as tainted."""
        self.var_taint[var] = taint
        if var in self.var_values:
            val_type, val = self.var_values[var]
            self.var_values[var] = (ValueState.TAINTED, val)
        else:
            self.var_values[var] = (ValueState.TAINTED, None)

    def set_sanitized(self, var: str) -> None:
        """Sets a variable as explicitly sanitized."""
        self.var_taint[var] = None
        self.var_values[var] = (ValueState.SANITIZED, None)

    def get_nullability(self, var: str) -> Nullability:
        """Returns nullability classification for a variable."""
        return self.var_nullability.get(var, Nullability.UNKNOWN)

    def is_definitely_none(self, var: str) -> bool:
        """Returns True ONLY if a variable is definitely None."""
        return self.get_nullability(var) == Nullability.DEFINITELY_NONE

    def is_not_none(self, var: str) -> bool:
        """Returns True if a variable is guaranteed not to be None."""
        return self.get_nullability(var) == Nullability.NOT_NONE

    def get_constant_value(self, var: str) -> Optional[Any]:
        """Returns constant value if known, else None."""
        if var in self.var_values:
            val_state, val = self.var_values[var]
            if val_state in (ValueState.CONSTANT, ValueState.NONE):
                return val
        return None

    def merge(self, other: "ProgramState") -> "ProgramState":
        """
        Path-sensitively merges two program states from converging control flow branches.
        """
        if not self.is_reachable:
            return other.copy()
        if not other.is_reachable:
            return self.copy()

        merged = ProgramState(is_reachable=True)

        # Merge variables across both branches
        all_vars = set(self.var_nullability.keys()) | set(other.var_nullability.keys())
        for var in all_vars:
            null_a = self.get_nullability(var)
            null_b = other.get_nullability(var)

            if null_a == null_b:
                merged.var_nullability[var] = null_a
            elif null_a == Nullability.DEFINITELY_NONE and null_b == Nullability.NOT_NONE:
                merged.var_nullability[var] = Nullability.POSSIBLY_NONE
            elif null_a == Nullability.NOT_NONE and null_b == Nullability.DEFINITELY_NONE:
                merged.var_nullability[var] = Nullability.POSSIBLY_NONE
            else:
                merged.var_nullability[var] = Nullability.UNKNOWN

        # Merge constant values: keep constant only if identical on both branches
        all_val_vars = set(self.var_values.keys()) & set(other.var_values.keys())
        for var in all_val_vars:
            state_a, val_a = self.var_values[var]
            state_b, val_b = other.var_values[var]
            if state_a == state_b and val_a == val_b:
                merged.var_values[var] = (state_a, val_a)

        # Merge taint states: IF tainted on ANY reachable branch, merged state is TAINTED!
        all_taint_vars = set(self.var_taint.keys()) | set(other.var_taint.keys())
        for var in all_taint_vars:
            taint_a = self.var_taint.get(var)
            taint_b = other.var_taint.get(var)

            if taint_a and taint_a.is_tainted:
                merged.var_taint[var] = taint_a
            elif taint_b and taint_b.is_tainted:
                merged.var_taint[var] = taint_b
            else:
                merged.var_taint[var] = None

        return merged

    def apply_guard(self, test_node: ast.AST, true_branch: bool) -> "ProgramState":
        """
        Applies path-sensitive guard information (e.g. 'if x is None:' or 'if x is not None:').
        Returns a new ProgramState with narrowed variable nullabilities.
        """
        new_state = self.copy()

        # Handle 'if x is None:' or 'if x == None:'
        if isinstance(test_node, ast.Compare):
            if len(test_node.ops) == 1 and len(test_node.comparators) == 1:
                op = test_node.ops[0]
                left = test_node.left
                right = test_node.comparators[0]

                is_none_check = isinstance(right, ast.Constant) and right.value is None
                if is_none_check and isinstance(left, ast.Name):
                    var_name = left.id
                    if isinstance(op, (ast.Is, ast.Eq)):
                        if true_branch:
                            new_state.set_none(var_name)
                        else:
                            new_state.set_not_none(var_name)
                    elif isinstance(op, (ast.IsNot, ast.NotEq)):
                        if true_branch:
                            new_state.set_not_none(var_name)
                        else:
                            new_state.set_none(var_name)

        # Handle 'if not x:' when x is checked
        elif isinstance(test_node, ast.UnaryOp) and isinstance(test_node.op, ast.Not):
            if isinstance(test_node.operand, ast.Name):
                var_name = test_node.operand.id
                if true_branch:
                    if self.get_nullability(var_name) == Nullability.POSSIBLY_NONE:
                        new_state.set_none(var_name)
                else:
                    new_state.set_not_none(var_name)

        # Handle 'if x:' (truthiness check)
        elif isinstance(test_node, ast.Name):
            var_name = test_node.id
            if true_branch:
                new_state.set_not_none(var_name)

        return new_state
