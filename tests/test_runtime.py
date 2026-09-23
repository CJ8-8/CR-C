"""
Tests for Phase 12 - Dynamic Runtime Runner
============================================

Tests controlled execution of entrypoints, exception capture (ZeroDivisionError, etc.),
timeout enforcement, missing entrypoints, and environment isolation.
"""

import os
import tempfile
import pytest
from backend.dynamic.runtime_runner import RuntimeRunner, RuntimeResult
from backend.dynamic.result_parser import DynamicResultParser


def test_runtime_runner_successful_entrypoint():
    runner = RuntimeRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        app_code = "def main():\n    x = 10\n    y = 20\n    return x + y\n"
        with open(os.path.join(temp_dir, "app.py"), "w") as f:
            f.write(app_code)

        result = runner.run_entrypoint(temp_dir, "app.main", timeout_seconds=2.0)
        assert result.status == "success"
        assert result.entrypoint == "app.main"
        assert result.file is None
        assert result.line is None
        assert result.exception_type is None


def test_runtime_runner_zero_division_error_capture():
    runner = RuntimeRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        app_code = "def start():\n    a = 5\n    b = 0\n    c = a / b\n    return c\n"
        with open(os.path.join(temp_dir, "server.py"), "w") as f:
            f.write(app_code)

        result = runner.run_entrypoint(temp_dir, "server.start", timeout_seconds=2.0)
        assert result.status == "error"
        assert result.entrypoint == "server.start"
        assert result.file == "server.py"
        assert result.line == 4
        assert result.exception_type == "ZeroDivisionError"
        assert "division by zero" in result.message


def test_runtime_runner_invalid_entrypoint_format():
    runner = RuntimeRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        result = runner.run_entrypoint(temp_dir, "invalidformat", timeout_seconds=1.0)
        assert result.status == "missing_entrypoint"
        assert result.file is None


def test_runtime_runner_timeout_enforcement():
    runner = RuntimeRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        app_code = "import time\ndef infinite_loop():\n    while True:\n        time.sleep(0.1)\n"
        with open(os.path.join(temp_dir, "loop_app.py"), "w") as f:
            f.write(app_code)

        result = runner.run_entrypoint(temp_dir, "loop_app.infinite_loop", timeout_seconds=0.3)
        assert result.status == "timeout"
        assert result.exception_type == "TimeoutError"


def test_runtime_result_parser_conversion():
    parser = DynamicResultParser()
    res = RuntimeResult(
        entrypoint="app.main",
        status="error",
        file="app.py",
        line=15,
        exception_type="ValueError",
        message="Invalid value passed"
    )
    issues = parser.convert_runtime_result(res)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == "app.py"
    assert issues[0].start_line == 15
    assert issues[0].end_line == 15
