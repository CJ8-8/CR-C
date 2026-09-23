"""
Tests for Phase 14 - Benchmark Loader & Integrity Validator
==============================================================

Tests loading dataset JSON files and validating dataset integrity.
"""

import os
import tempfile
import pytest
from backend.benchmark.loader import BenchmarkLoader


def test_benchmark_loader_valid_dataset():
    loader = BenchmarkLoader()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        data = [
            {
                "id": "case-01",
                "language": "python",
                "category": "SECURITY",
                "is_positive": True,
                "files": {"app.py": "eval(x)"},
                "expected_findings": [{"type": "SECURITY", "severity": "HIGH", "file": "app.py", "start_line": 1, "end_line": 1}]
            }
        ]
        import json
        json.dump(data, f)
        fpath = f.name

    try:
        cases = loader.load_from_file(fpath)
        assert len(cases) == 1
        assert cases[0].id == "case-01"
        assert cases[0].language == "python"
        assert len(cases[0].expected_findings) == 1
    finally:
        os.remove(fpath)


def test_benchmark_loader_duplicate_id_rejection():
    loader = BenchmarkLoader()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        data = [
            {"id": "dup-01", "language": "python", "category": "BUG", "is_positive": True, "files": {"a.py": "x=1"}},
            {"id": "dup-01", "language": "python", "category": "BUG", "is_positive": True, "files": {"b.py": "y=2"}}
        ]
        import json
        json.dump(data, f)
        fpath = f.name

    try:
        with pytest.raises(ValueError, match="Duplicate benchmark case ID"):
            loader.load_from_file(fpath)
    finally:
        os.remove(fpath)
