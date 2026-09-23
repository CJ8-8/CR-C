"""
Tests for Phase 13 - Control Flow Graph (CFG) Construction
===========================================================

Tests CFG node creation, branches (if/elif/else), loops (for/while), control jumps
(return, raise, break, continue), try/except blocks, and reachable nodes.
"""

import ast
import pytest
from backend.analysis.control_flow import ControlFlowGraph, CFGNode


def test_cfg_simple_linear_flow():
    code = "x = 10\ny = 20\nz = x + y\n"
    tree = ast.parse(code, filename="linear.py")
    cfg = ControlFlowGraph("linear.py", tree)

    assert cfg.entry_node is not None
    assert cfg.exit_node is not None
    reachable = cfg.get_reachable_nodes()
    assert len(reachable) >= 4  # entry, statements, exit


def test_cfg_if_else_branches():
    code = "if x > 5:\n    y = 1\nelse:\n    y = 2\n"
    tree = ast.parse(code, filename="branch.py")
    cfg = ControlFlowGraph("branch.py", tree)

    reachable = cfg.get_reachable_nodes()
    cond_nodes = [n for n in reachable if n.node_type == "condition"]
    merge_nodes = [n for n in reachable if n.node_type == "merge"]

    assert len(cond_nodes) >= 1
    assert len(merge_nodes) >= 1


def test_cfg_while_loop_with_break_and_continue():
    code = "while True:\n    if x == 1:\n        break\n    elif x == 2:\n        continue\n"
    tree = ast.parse(code, filename="loop.py")
    cfg = ControlFlowGraph("loop.py", tree)

    reachable = cfg.get_reachable_nodes()
    assert len(reachable) >= 5


def test_cfg_try_except_finally():
    code = "try:\n    x = 10 / 0\nexcept ZeroDivisionError:\n    x = 0\nfinally:\n    cleanup()\n"
    tree = ast.parse(code, filename="try_block.py")
    cfg = ControlFlowGraph("try_block.py", tree)

    reachable = cfg.get_reachable_nodes()
    assert len(reachable) >= 4
