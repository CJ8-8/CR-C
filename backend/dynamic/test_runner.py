"""
CodeJev Dynamic Test Runner - Phase 12
=======================================

Executes project tests in an isolated subprocess (shell=False) with timeout enforcement.
Parses failure output and tracebacks to extract normalized TestResult objects with exact source line numbers.
"""

import re
import sys
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TestResult:
    """
    Normalized result of a single test execution or test suite run.
    """
    __test__ = False
    name: str
    status: str  # "passed", "failed", "error", "skipped"
    file: Optional[str]
    line: Optional[int]
    message: Optional[str]


class TestRunner:
    """
    Subprocess-based runner for executing project tests and parsing failure evidence.
    """
    def run_tests(self, work_dir: str, timeout_seconds: float = 3.0) -> List[TestResult]:
        """
        Executes pytest in the target project directory and returns parsed TestResults.
        """
        results: List[TestResult] = []

        cmd = [sys.executable, "-m", "pytest", "-q", "--tb=short"]

        try:
            completed = subprocess.run(
                cmd,
                cwd=work_dir,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
                shell=False
            )
            output = completed.stdout + "\n" + completed.stderr
            results = self._parse_test_output(output)

            # If pytest exited 0 with no failures detected
            if completed.returncode == 0 and not results:
                results.append(TestResult(
                    name="pytest_suite",
                    status="passed",
                    file=None,
                    line=None,
                    message="All tests passed successfully"
                ))

        except subprocess.TimeoutExpired:
            results.append(TestResult(
                name="pytest_suite",
                status="error",
                file=None,
                line=None,
                message="Test suite execution timed out"
            ))
        except Exception as e:
            results.append(TestResult(
                name="pytest_suite",
                status="error",
                file=None,
                line=None,
                message=f"Test runner error: {str(e)}"
            ))

        return results

    def _parse_test_output(self, output: str) -> List[TestResult]:
        """
        Parses pytest output to extract test failure messages and source traceback locations.
        """
        results: List[TestResult] = []
        lines = output.splitlines()

        # Match pattern: FAILED test_file.py::test_func - AssertionError: ...
        fail_header_pattern = re.compile(r"FAILED\s+([^\s:]+)(?:::([^\s]+))?\s*-\s*(.*)")
        # Match traceback line: File "app.py", line 42, in ...
        file_line_pattern = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+)')
        # Match short tb: app.py:42: in func_name
        short_tb_pattern = re.compile(r"^([a-zA-Z0-9_\-\./]+\.py):(\d+):")

        i = 0
        while i < len(lines):
            line = lines[i]
            fail_match = fail_header_pattern.search(line)
            if fail_match:
                test_file = fail_match.group(1)
                test_name = fail_match.group(2) or "test"
                msg = fail_match.group(3)

                # Look forward for source traceback line
                source_file = None
                source_line = None

                for j in range(max(0, i - 30), min(i + 30, len(lines))):
                    tb_match = file_line_pattern.search(lines[j])
                    if tb_match:
                        f = tb_match.group(1)
                        l = int(tb_match.group(2))
                        # Prefer project source file (e.g. app.py) over test harness (test_app.py)
                        if not f.startswith("test_") and "/test_" not in f and not f.endswith("_test.py"):
                            source_file = f
                            source_line = l
                            break
                        elif source_file is None:
                            source_file = f
                            source_line = l

                    short_match = short_tb_pattern.search(lines[j])
                    if short_match:
                        f = short_match.group(1)
                        l = int(short_match.group(2))
                        if not f.startswith("test_") and "/test_" not in f and not f.endswith("_test.py"):
                            source_file = f
                            source_line = l
                            break
                        elif source_file is None:
                            source_file = f
                            source_line = l

                results.append(TestResult(
                    name=test_name,
                    status="failed",
                    file=source_file or test_file,
                    line=source_line,
                    message=msg
                ))

            i += 1

        return results
