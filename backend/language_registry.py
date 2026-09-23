"""
CodeJev Language Registry - Phase 11
=====================================

Maps file extensions to programming language categories and routes files to appropriate LanguageAnalyzers.
Supported languages:
- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
"""

import os
from typing import Dict, Optional, Type
from backend.analyzers.base import LanguageAnalyzer
from backend.analyzers.python_analyzer import PythonAnalyzer
from backend.analyzers.javascript_analyzer import JavaScriptAnalyzer

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


class LanguageRegistry:
    """
    Registry for determining language by file extension and serving LanguageAnalyzer instances.
    """
    def __init__(self):
        self._analyzers: Dict[str, LanguageAnalyzer] = {
            "python": PythonAnalyzer(),
            "javascript": JavaScriptAnalyzer(language="javascript"),
            "typescript": JavaScriptAnalyzer(language="typescript"),
        }

    def get_language(self, filename: str) -> Optional[str]:
        """
        Returns normalized language name based on file extension, or None if unsupported.
        """
        ext = os.path.splitext(filename)[1].lower()
        return EXTENSION_LANGUAGE_MAP.get(ext)

    def get_analyzer(self, filename: str) -> Optional[LanguageAnalyzer]:
        """
        Returns the appropriate LanguageAnalyzer for the given filename, or None if unsupported.
        """
        lang = self.get_language(filename)
        if lang:
            return self._analyzers.get(lang)
        return None
