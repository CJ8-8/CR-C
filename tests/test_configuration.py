"""
Tests for Phase 9 - Configuration Analysis
"""

import ast
import pytest
from backend.analysis_context import AnalysisContext
from backend.detectors.configuration import ConfigurationDetector


def test_detect_debug_true():
    detector = ConfigurationDetector()
    code = "DEBUG = True"
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="settings.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "CONFIGURATION"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_detect_verify_false():
    detector = ConfigurationDetector()
    code = 'response = requests.get("https://api.internal.com", verify=False)'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="client.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "CONFIGURATION"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_detect_wildcard_cors():
    detector = ConfigurationDetector()
    code = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="main.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "CONFIGURATION"
    assert issues[0].severity == "MEDIUM"


def test_detect_wildcard_host():
    detector = ConfigurationDetector()
    code = 'uvicorn.run("main:app", host="0.0.0.0", port=8000)'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="server.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "CONFIGURATION"
    assert issues[0].severity == "MEDIUM"


def test_configuration_text_scanner():
    detector = ConfigurationDetector()
    code = """
# Config file
DEBUG = True
verify = False
allow_origins = ["*"]
    """.strip()

    issues = detector.scan_text("config.ini", code)
    assert len(issues) == 3
    types = [i.type for i in issues]
    assert all(t == "CONFIGURATION" for t in types)


def test_configuration_changed_lines_filter():
    detector = ConfigurationDetector()
    code = "DEBUG = True\nverify = False\n"

    issues = detector.scan_text("settings.py", code, changed_lines={1})
    assert len(issues) == 1
    assert issues[0].start_line == 1
