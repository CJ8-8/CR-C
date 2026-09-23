"""
Tests for Phase 11 - Language Registry
"""

import pytest
from backend.language_registry import LanguageRegistry
from backend.analyzers.python_analyzer import PythonAnalyzer
from backend.analyzers.javascript_analyzer import JavaScriptAnalyzer


def test_extension_mapping():
    registry = LanguageRegistry()

    assert registry.get_language("main.py") == "python"
    assert registry.get_language("app.js") == "javascript"
    assert registry.get_language("component.jsx") == "javascript"
    assert registry.get_language("index.ts") == "typescript"
    assert registry.get_language("widget.tsx") == "typescript"

    # Unsupported extension returns None
    assert registry.get_language("document.pdf") is None
    assert registry.get_language("script.sh") is None


def test_analyzer_retrieval():
    registry = LanguageRegistry()

    py_analyzer = registry.get_analyzer("main.py")
    assert isinstance(py_analyzer, PythonAnalyzer)

    js_analyzer = registry.get_analyzer("app.js")
    assert isinstance(js_analyzer, JavaScriptAnalyzer)

    ts_analyzer = registry.get_analyzer("index.ts")
    assert isinstance(ts_analyzer, JavaScriptAnalyzer)

    assert registry.get_analyzer("unsupported.bin") is None
