"""
CodeJev Python AST Analyzer Bridge - Phase 5
==============================================

Parses raw Python code strings into an AST tree and delegates issue detection
to the modular DetectorEngine.
"""

import ast
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.detector_engine import DetectorEngine


class ASTSyntaxError(Exception):
    """Exception raised when provided Python source code contains syntax errors."""
    pass


# Global engine instance with registered detectors
_default_engine = DetectorEngine()


def analyze_python_ast(
    file: str, 
    code: str, 
    changed_lines: Optional[Set[int]] = None
) -> List[Issue]:
    """
    Parses Python source code into an AST and runs the DetectorEngine.

    Args:
        file (str): Target filename (e.g. 'auth.py').
        code (str): Full raw Python source code string.
        changed_lines (Optional[Set[int]]): Optional set of 1-based changed line numbers.

    Returns:
        List[Issue]: Combined list of detected Issue objects.

    Raises:
        ASTSyntaxError: If the provided Python code contains invalid syntax.
    """
    if not code or not code.strip():
        return []

    # 1. Parse raw Python source into an Abstract Syntax Tree
    try:
        tree = ast.parse(code, filename=file)
    except SyntaxError as e:
        line_info = f" at line {e.lineno}" if e.lineno else ""
        raise ASTSyntaxError(f"Invalid Python syntax{line_info}: {e.msg}") from e

    # 2. Delegate detection to the modular DetectorEngine
    return _default_engine.analyze(tree=tree, file=file, changed_lines=changed_lines)
