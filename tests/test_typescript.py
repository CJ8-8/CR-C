"""
Tests for Phase 11 - TypeScript Analysis (.ts, .tsx)
"""

import pytest
from backend.analyzers.javascript_analyzer import JavaScriptAnalyzer


def test_ts_eval_security():
    analyzer = JavaScriptAnalyzer(language="typescript")
    code = 'const result: any = eval(userInput);'

    issues = analyzer.analyze("app.ts", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == "app.ts"
    assert issues[0].start_line == 1


def test_tsx_inner_html_xss():
    analyzer = JavaScriptAnalyzer(language="typescript")
    code = 'const Component = () => {\n  element.innerHTML = userInput;\n  return <div>Test</div>;\n};'

    issues = analyzer.analyze("widget.tsx", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == "widget.tsx"
    assert issues[0].start_line == 2


def test_ts_console_log_quality():
    analyzer = JavaScriptAnalyzer(language="typescript")
    code = 'console.log("TS debug message");'

    issues = analyzer.analyze("service.ts", code)
    assert len(issues) == 1
    assert issues[0].type == "CODE_QUALITY"
    assert issues[0].severity == "LOW"
