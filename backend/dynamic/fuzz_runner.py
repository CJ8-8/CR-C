"""
CodeJev Dynamic Fuzz Runner - Phase 12
=======================================

Executes bounded, deterministic fuzzing for a specified target function using fixed seeds.
Generates boundary test cases (empty strings, special chars, negative numbers, None) in an isolated subprocess.
"""

import os
import re
import sys
import subprocess
import random
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FuzzResult:
    """
    Normalized result of a bounded function fuzzing run.
    """
    target_func: str
    status: str  # "success", "crash", "timeout", "missing_target"
    file: Optional[str]
    line: Optional[int]
    exception_type: Optional[str]
    fuzz_input: Optional[str]
    cases_run: int


class FuzzRunner:
    """
    Subprocess-based runner for bounded, deterministic function fuzzing.
    """
    def fuzz_target(
        self, 
        work_dir: str, 
        fuzz_target: str, 
        max_cases: int = 50, 
        timeout_seconds: float = 3.0
    ) -> FuzzResult:
        """
        Fuzzes a specified target function (e.g. 'parser.parse_number') with generated boundary inputs.
        """
        if not fuzz_target or "." not in fuzz_target:
            return FuzzResult(
                target_func=fuzz_target or "",
                status="missing_target",
                file=None,
                line=None,
                exception_type=None,
                fuzz_input=None,
                cases_run=0
            )

        mod_name, func_name = fuzz_target.rsplit(".", 1)

        # Generate deterministic input list
        boundary_inputs = self._generate_boundary_inputs(max_cases)

        # Isolated runner script
        runner_script = f"""
import sys, reprlib
sys.path.insert(0, '.')
import {mod_name}
target = getattr({mod_name}, '{func_name}')

test_inputs = {repr(boundary_inputs)}
for idx, val in enumerate(test_inputs):
    try:
        target(val)
    except Exception as e:
        print(f"CRASH_CASE:{{idx}}")
        print(f"CRASH_INPUT:{{reprlib.repr(val)}}")
        raise e
"""

        cmd = [sys.executable, "-c", runner_script]

        clean_env = os.environ.copy()
        for k in list(clean_env.keys()):
            if "KEY" in k or "SECRET" in k or "TOKEN" in k:
                del clean_env[k]

        try:
            completed = subprocess.run(
                cmd,
                cwd=work_dir,
                env=clean_env,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
                shell=False
            )

            if completed.returncode == 0:
                return FuzzResult(
                    target_func=fuzz_target,
                    status="success",
                    file=None,
                    line=None,
                    exception_type=None,
                    fuzz_input=None,
                    cases_run=len(boundary_inputs)
                )

            # Crash detected!
            err_output = completed.stdout + "\n" + completed.stderr
            return self._parse_fuzz_crash(fuzz_target, mod_name, err_output, len(boundary_inputs))

        except subprocess.TimeoutExpired:
            return FuzzResult(
                target_func=fuzz_target,
                status="timeout",
                file=None,
                line=None,
                exception_type="TimeoutError",
                fuzz_input=None,
                cases_run=len(boundary_inputs)
            )
        except Exception as e:
            return FuzzResult(
                target_func=fuzz_target,
                status="error",
                file=None,
                line=None,
                exception_type="SubprocessError",
                fuzz_input=None,
                cases_run=0
            )

    def _generate_boundary_inputs(self, max_cases: int) -> List[object]:
        """Generates deterministic boundary inputs using a fixed random seed."""
        random.seed(42)

        base_inputs = [
            "",
            " ",
            "A" * 500,
            "0",
            "-1",
            "999999",
            "-999999",
            "0.0",
            "\0\n\r\t'\"/><;--",
            None,
            [],
            {},
            True,
            False,
        ]

        # Extend up to max_cases deterministically
        cases = list(base_inputs)
        while len(cases) < max_cases:
            val_type = random.choice(["str", "int", "float"])
            if val_type == "str":
                cases.append(f"fuzz_{random.randint(0, 10000)}")
            elif val_type == "int":
                cases.append(random.randint(-100000, 100000))
            else:
                cases.append(random.uniform(-100.0, 100.0))

        return cases[:max_cases]

    def _parse_fuzz_crash(
        self, 
        fuzz_target: str, 
        mod_name: str, 
        output: str, 
        cases_run: int
    ) -> FuzzResult:
        """Parses traceback and crash input string from fuzz output."""
        lines = output.splitlines()
        file_line_pattern = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+)')
        exc_pattern = re.compile(r"^([a-zA-Z0-9_\.]+Error|[a-zA-Z0-9_\.]+Exception):\s*(.*)")

        source_file = None
        source_line = None
        exc_type = "FuzzCrashError"
        crash_input = None

        for line in lines:
            if line.startswith("CRASH_INPUT:"):
                crash_input = line.split(":", 1)[1].strip()

            tb_match = file_line_pattern.search(line)
            if tb_match:
                f = tb_match.group(1)
                l = int(tb_match.group(2))
                if not f.startswith("<") and not f.startswith("/usr") and "site-packages" not in f:
                    source_file = os.path.basename(f)
                    source_line = l

            exc_match = exc_pattern.search(line.strip())
            if exc_match:
                exc_type = exc_match.group(1)

        return FuzzResult(
            target_func=fuzz_target,
            status="crash",
            file=source_file or f"{mod_name}.py",
            line=source_line,
            exception_type=exc_type,
            fuzz_input=crash_input,
            cases_run=cases_run
        )
