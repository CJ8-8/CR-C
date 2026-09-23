"""
CodeJev Dynamic Runtime Runner - Phase 12
=========================================

Executes declared entrypoints in an isolated subprocess (shell=False) with timeout enforcement.
Captures uncaught runtime exceptions (ZeroDivisionError, ValueError, etc.) and extracts source line numbers.
"""

import os
import re
import sys
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class RuntimeResult:
    """
    Normalized result of a runtime entrypoint execution.
    """
    entrypoint: str
    status: str  # "success", "error", "timeout", "missing_entrypoint"
    file: Optional[str]
    line: Optional[int]
    exception_type: Optional[str]
    message: Optional[str]


class RuntimeRunner:
    """
    Subprocess-based runner for executing entrypoints and capturing runtime crash evidence.
    """
    def run_entrypoint(
        self, 
        work_dir: str, 
        entrypoint: str, 
        timeout_seconds: float = 3.0
    ) -> RuntimeResult:
        """
        Executes a declared entrypoint (e.g. 'app.main') in an isolated subprocess.
        """
        if not entrypoint or "." not in entrypoint:
            return RuntimeResult(
                entrypoint=entrypoint or "",
                status="missing_entrypoint",
                file=None,
                line=None,
                exception_type=None,
                message="Invalid or missing entrypoint specification"
            )

        mod_name, func_name = entrypoint.rsplit(".", 1)
        script_code = f"import sys; sys.path.insert(0, '.'); import {mod_name}; getattr({mod_name}, '{func_name}')()"

        cmd = [sys.executable, "-c", script_code]

        # Environment isolation: remove sensitive process env variables
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
                return RuntimeResult(
                    entrypoint=entrypoint,
                    status="success",
                    file=None,
                    line=None,
                    exception_type=None,
                    message="Entrypoint executed cleanly without errors"
                )

            # Execution failed with exit code != 0
            err_output = completed.stderr or completed.stdout
            return self._parse_runtime_error(entrypoint, mod_name, err_output)

        except subprocess.TimeoutExpired:
            return RuntimeResult(
                entrypoint=entrypoint,
                status="timeout",
                file=None,
                line=None,
                exception_type="TimeoutError",
                message=f"Runtime execution exceeded timeout of {timeout_seconds}s"
            )
        except Exception as e:
            return RuntimeResult(
                entrypoint=entrypoint,
                status="error",
                file=None,
                line=None,
                exception_type="SubprocessError",
                message=str(e)
            )

    def _parse_runtime_error(self, entrypoint: str, mod_name: str, stderr: str) -> RuntimeResult:
        """
        Parses python traceback from stderr to extract exception type, message, file, and line.
        """
        lines = stderr.splitlines()
        file_line_pattern = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+)')
        exc_pattern = re.compile(r"^([a-zA-Z0-9_\.]+Error|[a-zA-Z0-9_\.]+Exception):\s*(.*)")

        source_file = None
        source_line = None
        exc_type = "RuntimeError"
        exc_msg = stderr.strip()

        for line in lines:
            tb_match = file_line_pattern.search(line)
            if tb_match:
                f = tb_match.group(1)
                l = int(tb_match.group(2))
                # Exclude <string> or python stdlib paths
                if not f.startswith("<") and not f.startswith("/usr") and "site-packages" not in f:
                    source_file = os.path.basename(f)
                    source_line = l

            exc_match = exc_pattern.search(line.strip())
            if exc_match:
                exc_type = exc_match.group(1)
                exc_msg = exc_match.group(2)

        return RuntimeResult(
            entrypoint=entrypoint,
            status="error",
            file=source_file or f"{mod_name}.py",
            line=source_line,
            exception_type=exc_type,
            message=exc_msg
        )
