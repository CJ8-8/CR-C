"""
CodeJev Dependency Analyzer - Phase 9
=======================================

Parses dependency manifest files (requirements.txt, pyproject.toml) to detect:
1. Unpinned dependencies (LOW severity)
2. Wildcard version specifications (MEDIUM severity)
3. Known vulnerable dependency versions via AdvisoryClient (HIGH/CRITICAL severity)
"""

import re
import tomllib
from typing import List, Optional, Set
from backend.schemas import Issue
from backend.advisory_client import AdvisoryClient


class DependencyAnalyzer:
    """
    Parses project dependency files and localizes dependency issues to specific line numbers.
    """
    def __init__(self, advisory_client: Optional[AdvisoryClient] = None):
        self.advisory_client = advisory_client or AdvisoryClient()

    def analyze_file(
        self, 
        filename: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Analyzes a manifest file (requirements.txt or pyproject.toml) and returns localized Issues.
        """
        base_name = filename.lower()
        if "requirements" in base_name or base_name.endswith(".txt"):
            return self.analyze_requirements_txt(filename, code, changed_lines)
        elif base_name.endswith("pyproject.toml") or base_name.endswith(".toml"):
            return self.analyze_pyproject_toml(filename, code, changed_lines)
        return []

    def analyze_requirements_txt(
        self, 
        filename: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Parses requirements.txt line by line and identifies dependency issues.
        """
        issues: List[Issue] = []
        lines = code.splitlines()

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            # Skip empty lines, comments, and flags like -r or --index-url
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            if changed_lines is not None and idx not in changed_lines:
                continue

            issue = self._evaluate_dependency_spec(filename, line, idx)
            if issue:
                issues.append(issue)

        return issues

    def analyze_pyproject_toml(
        self, 
        filename: str, 
        code: str, 
        changed_lines: Optional[Set[int]] = None
    ) -> List[Issue]:
        """
        Parses pyproject.toml dependencies and maps findings to line numbers in the raw text.
        """
        issues: List[Issue] = []
        raw_lines = code.splitlines()

        try:
            parsed = tomllib.loads(code)
        except Exception:
            # If TOML syntax is invalid, skip TOML parsing cleanly
            return []

        deps_to_check: List[str] = []

        # Standard PEP 621 dependencies: [project] dependencies = ["requests>=2.0.0", ...]
        project_sec = parsed.get("project", {})
        if isinstance(project_sec, dict) and "dependencies" in project_sec:
            req_list = project_sec.get("dependencies", [])
            if isinstance(req_list, list):
                deps_to_check.extend([str(item) for item in req_list])

        # Poetry dependencies: [tool.poetry.dependencies] requests = "^2.0.0"
        tool_sec = parsed.get("tool", {})
        if isinstance(tool_sec, dict):
            poetry_sec = tool_sec.get("poetry", {})
            if isinstance(poetry_sec, dict):
                poetry_deps = poetry_sec.get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for pkg, ver in poetry_deps.items():
                        if pkg.lower() == "python":
                            continue
                        if ver == "*":
                            deps_to_check.append(f"{pkg}==*")
                        elif isinstance(ver, str) and (ver.startswith("^") or ver.startswith("~")):
                            # Version constraint string
                            clean_v = ver.lstrip("^~=")
                            deps_to_check.append(f"{pkg}=={clean_v}")
                        else:
                            deps_to_check.append(f"{pkg}{ver}")

        # Process each dependency and locate its line number in raw pyproject.toml text
        for dep in deps_to_check:
            # Extract package name for line matching
            match = re.match(r"^([a-zA-Z0-9_\-]+)", dep.strip())
            if not match:
                continue
            pkg_name = match.group(1)

            # Find matching line in raw lines
            line_no = self._find_line_of_dep(raw_lines, pkg_name)
            if line_no is None:
                line_no = 1

            if changed_lines is not None and line_no not in changed_lines:
                continue

            issue = self._evaluate_dependency_spec(filename, dep, line_no)
            if issue:
                issues.append(issue)

        return issues

    def _find_line_of_dep(self, raw_lines: List[str], pkg_name: str) -> Optional[int]:
        """Searches raw file lines for line containing package name."""
        pattern = re.compile(rf"\b{re.escape(pkg_name)}\b", re.IGNORECASE)
        for idx, line in enumerate(raw_lines, start=1):
            if pattern.search(line):
                return idx
        return None

    def _evaluate_dependency_spec(self, filename: str, spec: str, line_no: int) -> Optional[Issue]:
        """
        Evaluates a single dependency specification string (e.g. 'requests==2.18.4', 'flask', 'django>=2.0').
        """
        spec = spec.strip()
        # Case 1: Exact version pin with == (e.g. requests==2.18.4 or flask==*)
        if "==" in spec:
            parts = spec.split("==", 1)
            pkg = parts[0].strip()
            ver = parts[1].strip().strip("\"'")

            if ver == "*":
                return Issue(
                    type="DEPENDENCY",
                    severity="MEDIUM",
                    file=filename,
                    start_line=line_no,
                    end_line=line_no,
                )

            # Check advisory database
            advisory = self.advisory_client.check_package(pkg, ver)
            if advisory:
                return Issue(
                    type="DEPENDENCY",
                    severity=advisory.severity,
                    file=filename,
                    start_line=line_no,
                    end_line=line_no,
                )
            return None

        # Case 2: Wildcard in range or version (e.g. requests>=* or flask*)
        if "*" in spec:
            return Issue(
                type="DEPENDENCY",
                severity="MEDIUM",
                file=filename,
                start_line=line_no,
                end_line=line_no,
            )

        # Case 3: Unpinned dependency with range or no version specifier (e.g. requests, requests>=2.0.0)
        match = re.match(r"^([a-zA-Z0-9_\-]+)", spec)
        if match:
            pkg_name = match.group(1)
            # If spec is just package name or uses loose relational operator like >= or ~>
            if spec == pkg_name or any(op in spec for op in [">=", ">", "~=", "<="]):
                return Issue(
                    type="DEPENDENCY",
                    severity="LOW",
                    file=filename,
                    start_line=line_no,
                    end_line=line_no,
                )

        return None
