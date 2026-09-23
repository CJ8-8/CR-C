"""
Tests for Phase 9 - Dependency Analysis (requirements.txt & pyproject.toml)
"""

import pytest
from backend.advisory_client import AdvisoryClient, Advisory
from backend.dependency_analyzer import DependencyAnalyzer


def test_requirements_unpinned():
    analyzer = DependencyAnalyzer()
    code = """
# Sample requirements.txt
requests
django>=2.0.0
flask==*
    """.strip()

    issues = analyzer.analyze_requirements_txt("requirements.txt", code)
    assert len(issues) == 3

    # line 2: requests (unpinned LOW)
    req_issue = next(i for i in issues if i.start_line == 2)
    assert req_issue.type == "DEPENDENCY"
    assert req_issue.severity == "LOW"

    # line 3: django>=2.0.0 (unpinned range LOW)
    dj_issue = next(i for i in issues if i.start_line == 3)
    assert dj_issue.type == "DEPENDENCY"
    assert dj_issue.severity == "LOW"

    # line 4: flask==* (wildcard MEDIUM)
    fl_issue = next(i for i in issues if i.start_line == 4)
    assert fl_issue.type == "DEPENDENCY"
    assert fl_issue.severity == "MEDIUM"


def test_requirements_vulnerable_advisory():
    analyzer = DependencyAnalyzer()
    code = "requests==2.18.4\n"

    issues = analyzer.analyze_requirements_txt("requirements.txt", code)
    assert len(issues) == 1
    assert issues[0].type == "DEPENDENCY"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_pyproject_toml_parsing():
    analyzer = DependencyAnalyzer()
    code = """
[project]
name = "sample-app"
version = "0.1.0"
dependencies = [
    "requests==2.18.4",
    "flask",
]
    """.strip()

    issues = analyzer.analyze_pyproject_toml("pyproject.toml", code)
    assert len(issues) == 2

    vuln_issue = next(i for i in issues if i.severity == "HIGH")
    assert vuln_issue.type == "DEPENDENCY"
    assert vuln_issue.file == "pyproject.toml"

    unpinned_issue = next(i for i in issues if i.severity == "LOW")
    assert unpinned_issue.type == "DEPENDENCY"


def test_dependency_changed_lines_filter():
    analyzer = DependencyAnalyzer()
    code = "requests==2.18.4\nflask\ndjango==2.0.0\n"

    # Only analyze line 2 (flask)
    issues = analyzer.analyze_requirements_txt("requirements.txt", code, changed_lines={2})
    assert len(issues) == 1
    assert issues[0].start_line == 2
    assert issues[0].severity == "LOW"


def test_mock_advisory_client():
    custom_advisories = {
        ("my-package", "1.0.0"): Advisory(
            package_name="my-package",
            vulnerable_version="1.0.0",
            cve_id="CVE-2026-9999",
            severity="CRITICAL",
            description="Custom mock CVE vulnerability"
        )
    }
    client = AdvisoryClient(advisories=custom_advisories)
    analyzer = DependencyAnalyzer(advisory_client=client)

    issues = analyzer.analyze_requirements_txt("requirements.txt", "my-package==1.0.0")
    assert len(issues) == 1
    assert issues[0].type == "DEPENDENCY"
    assert issues[0].severity == "CRITICAL"
