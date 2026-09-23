"""
Tests for Phase 12 - Bounded Dynamic Fuzz Runner
================================================

Tests bounded function fuzzing, fixed seed determinism, crash localization, max cases limit, and timeout.
"""

import os
import tempfile
import pytest
from backend.dynamic.fuzz_runner import FuzzRunner, FuzzResult
from backend.dynamic.result_parser import DynamicResultParser


def test_fuzz_runner_clean_execution():
    runner = FuzzRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        code = "def safe_len(val):\n    if val is None:\n        return 0\n    return len(str(val))\n"
        with open(os.path.join(temp_dir, "util.py"), "w") as f:
            f.write(code)

        result = runner.fuzz_target(temp_dir, "util.safe_len", max_cases=20, timeout_seconds=2.0)
        assert result.status == "success"
        assert result.cases_run == 20
        assert result.file is None
        assert result.line is None


def test_fuzz_runner_crash_detection_and_localization():
    runner = FuzzRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        # Crashes on None input or empty string
        code = "def parse_age(val):\n    if val is None:\n        raise ValueError('Age cannot be None')\n    return int(val)\n"
        with open(os.path.join(temp_dir, "parser.py"), "w") as f:
            f.write(code)

        result = runner.fuzz_target(temp_dir, "parser.parse_age", max_cases=10, timeout_seconds=2.0)
        assert result.status == "crash"
        assert result.file == "parser.py"
        assert result.line == 4
        assert result.exception_type in ("ValueError", "TypeError")
        assert result.fuzz_input is not None


def test_fuzz_runner_deterministic_seed():
    runner1 = FuzzRunner()
    runner2 = FuzzRunner()

    inputs1 = runner1._generate_boundary_inputs(max_cases=30)
    inputs2 = runner2._generate_boundary_inputs(max_cases=30)

    assert inputs1 == inputs2
    assert len(inputs1) == 30


def test_fuzz_runner_invalid_target_format():
    runner = FuzzRunner()
    with tempfile.TemporaryDirectory() as temp_dir:
        result = runner.fuzz_target(temp_dir, "invalidtarget", max_cases=10)
        assert result.status == "missing_target"
        assert result.cases_run == 0


def test_fuzz_result_parser_conversion():
    parser = DynamicResultParser()
    res = FuzzResult(
        target_func="parser.parse_age",
        status="crash",
        file="parser.py",
        line=3,
        exception_type="ValueError",
        fuzz_input="None",
        cases_run=10
    )
    issues = parser.convert_fuzz_result(res)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == "parser.py"
    assert issues[0].start_line == 3
    assert issues[0].end_line == 3
