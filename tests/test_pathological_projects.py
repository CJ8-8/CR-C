"""
Tests for Phase 13 - Pathological Project Structures & Termination
====================================================================

Tests that analysis terminates cleanly without hanging or crashing on:
- Mutual recursion across functions
- Cyclic imports
- Deeply nested branches
- Loop-heavy code
"""

import pytest
from backend.project_analyzer import ProjectAnalyzer
from backend.detector_engine import DetectorEngine


def test_pathological_mutual_recursion():
    files = {
        "mod1.py": "from mod2 import func_b\ndef func_a(x):\n    if x > 0:\n        return func_b(x - 1)\n    return 0\n",
        "mod2.py": "from mod1 import func_a\ndef func_b(x):\n    if x > 0:\n        return func_a(x - 1)\n    return 0\n"
    }

    project = ProjectAnalyzer(files)
    engine = DetectorEngine()

    for filename, tree in project.trees.items():
        issues = engine.analyze(tree, filename, project_analyzer=project)
        # Verify analysis terminates safely
        assert isinstance(issues, list)


def test_pathological_deeply_nested_loops_and_branches():
    code = """def complex_fn(x):
    for i in range(10):
        for j in range(10):
            if i == j:
                while True:
                    if x > 0:
                        break
                    else:
                        break
    return x
"""
    files = {"deep.py": code}
    project = ProjectAnalyzer(files)
    engine = DetectorEngine()

    issues = engine.analyze(project.trees["deep.py"], "deep.py", project_analyzer=project)
    assert isinstance(issues, list)
