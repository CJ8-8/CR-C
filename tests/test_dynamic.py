"""
Tests for Phase 12 - Dynamic Test Ingestion & Result Parser
"""

import os
import tempfile
import pytest
from backend.dynamic.test_runner import TestRunner, TestResult
from backend.dynamic.result_parser import DynamicResultParser
from backend.schemas import Issue


def test_test_runner_parse_failure_traceback():
    runner = TestRunner()
    output = """
=================================== FAILURES ===================================
__________________________________ test_add ___________________________________
FAILED test_math.py::test_add - AssertionError: assert 4 == 5
  File "app/calculator.py", line 42, in add
    return a + b + 1
E   AssertionError: assert 4 == 5
    """

    results = runner._parse_test_output(output)
    assert len(results) == 1
    assert results[0].name == "test_add"
    assert results[0].status == "failed"
    assert results[0].file == "app/calculator.py"
    assert results[0].line == 42
    assert "AssertionError" in results[0].message


def test_test_runner_subprocesses_execution():
    runner = TestRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        # Write failing test and source file that raises ZeroDivisionError
        with open(os.path.join(temp_dir, "calc.py"), "w") as f:
            f.write("def add(a, b):\n    return a / 0\n")
        with open(os.path.join(temp_dir, "test_calc.py"), "w") as f:
            f.write("from calc import add\ndef test_add():\n    assert add(2, 2) == 4\n")

        results = runner.run_tests(temp_dir, timeout_seconds=3.0)
        assert len(results) >= 1
        failed = next(r for r in results if r.status == "failed")
        assert failed.file == "calc.py"
        assert failed.line == 2


def test_result_parser_conversion_and_deduplication():
    parser = DynamicResultParser()

    static_issues = [
        Issue(type="BUG", severity="MEDIUM", file="app.py", start_line=10, end_line=10)
    ]
    test_results = [
        TestResult(name="test_foo", status="failed", file="app.py", line=10, message="Assertion failed"),
        TestResult(name="test_bar", status="failed", file="app.py", line=20, message="Index error")
    ]

    dynamic_issues = parser.convert_test_results(test_results)
    combined = parser.combine_and_filter(static_issues, dynamic_issues)

    # Line 10 duplicate should be merged cleanly
    assert len(combined) == 2
    assert combined[0].file == "app.py"
    assert combined[0].start_line == 10
    assert combined[1].start_line == 20


def test_dynamic_changed_lines_filtering():
    parser = DynamicResultParser()

    dynamic_issues = [
        Issue(type="BUG", severity="HIGH", file="app.py", start_line=10, end_line=10),
        Issue(type="BUG", severity="HIGH", file="app.py", start_line=20, end_line=20)
    ]

    # Only line 20 changed
    filtered = parser.combine_and_filter([], dynamic_issues, changed_lines={"app.py": [20]})
    assert len(filtered) == 1
    assert filtered[0].start_line == 20


def test_analyze_project_endpoint_with_dynamic_options():
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)
    payload = {
        "files": {
            "calc.py": "def add(a, b):\n    return a / 0\n",
            "test_calc.py": "from calc import add\ndef test_add():\n    assert add(2, 2) == 4\n"
        },
        "changed_lines": {
            "calc.py": [2]
        },
        "dynamic": {
            "enabled": True,
            "run_tests": True,
            "entrypoints": ["calc.add"],
            "fuzz_targets": [],
            "timeout_seconds": 3.0
        }
    }

    response = client.post("/analyze-project", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "issues" in data
    # Failed test or runtime exception on calc.py line 2 should be captured
    issues = data["issues"]
    assert any(i["file"] == "calc.py" and i["start_line"] == 2 for i in issues)

