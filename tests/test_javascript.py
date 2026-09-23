"""
Tests for Phase 11 - JavaScript Analysis (Security, Bugs, Quality, Location & Line Filtering)
"""

import pytest
from backend.analyzers.javascript_analyzer import JavaScriptAnalyzer


def test_js_eval_security():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'eval(userInput);'

    issues = analyzer.analyze("app.js", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == "app.js"
    assert issues[0].start_line == 1


def test_js_eval_in_string_literal_ignored():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'const text = "eval(userInput)";'

    issues = analyzer.analyze("app.js", code)
    assert len(issues) == 0


def test_js_child_process_exec():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'child_process.exec(cmd);'

    issues = analyzer.analyze("server.js", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_js_inner_html_xss():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'element.innerHTML = userInput;'

    issues = analyzer.analyze("dom.js", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_js_dynamic_sql_concatenation():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'const query = "SELECT * FROM users WHERE id=" + userId;'

    issues = analyzer.analyze("db.js", code)
    assert len(issues) == 1
    assert issues[0].type == "SECURITY"
    assert issues[0].severity == "HIGH"
    assert issues[0].start_line == 1


def test_js_assignment_in_condition_bug():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'if (x = getValue()) {\n    doSomething();\n}'

    issues = analyzer.analyze("logic.js", code)
    assert len(issues) == 1
    assert issues[0].type == "BUG"
    assert issues[0].severity == "MEDIUM"
    assert issues[0].start_line == 1


def test_js_unreachable_code_bug():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'function calc() {\n    return 10;\n    console.log("never");\n}'

    issues = analyzer.analyze("func.js", code)
    # Line 3 is unreachable statement
    unreachable = next(i for i in issues if i.type == "BUG")
    assert unreachable.severity == "LOW"
    assert unreachable.start_line == 3


def test_js_console_log_quality():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'console.log("debug message");'

    issues = analyzer.analyze("app.js", code)
    assert len(issues) == 1
    assert issues[0].type == "CODE_QUALITY"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 1


def test_js_duplicate_imports_quality():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'import { useState } from "react";\nimport { useEffect } from "react";'

    issues = analyzer.analyze("comp.jsx", code)
    assert len(issues) == 1
    assert issues[0].type == "CODE_QUALITY"
    assert issues[0].severity == "LOW"
    assert issues[0].start_line == 2


def test_js_changed_lines_filter():
    analyzer = JavaScriptAnalyzer(language="javascript")
    code = 'eval(userInput);\nconsole.log("debug");'

    # Only analyze line 2
    issues = analyzer.analyze("app.js", code, changed_lines={2})
    assert len(issues) == 1
    assert issues[0].start_line == 2
    assert issues[0].type == "CODE_QUALITY"
