"""
Tests for Phase 14 - Benchmark Runner & Reporter
=================================================

Tests running benchmark suites offline, generating reports, and mutation testing.
"""

import os
import tempfile
import pytest
from backend.benchmark.loader import BenchmarkLoader
from backend.benchmark.runner import BenchmarkRunner
from backend.benchmark.reporter import BenchmarkReporter


def test_benchmark_runner_synthetic_suite():
    loader = BenchmarkLoader()
    cases = loader.load_from_file("benchmarks/synthetic_cases.json")
    assert len(cases) >= 10

    runner = BenchmarkRunner()
    results, summary = runner.run_suite(cases)

    assert summary.total_cases == len(cases)
    assert summary.tp >= 1
    assert summary.precision > 0.0
    assert summary.recall > 0.0
    assert summary.f1 > 0.0


def test_benchmark_reporter_json_and_md():
    loader = BenchmarkLoader()
    cases = loader.load_from_file("benchmarks/synthetic_cases.json")

    runner = BenchmarkRunner()
    results, summary = runner.run_suite(cases)

    reporter = BenchmarkReporter()
    with tempfile.TemporaryDirectory() as temp_dir:
        json_file = os.path.join(temp_dir, "evaluation.json")
        md_file = os.path.join(temp_dir, "evaluation.md")

        reporter.generate_json_report(results, summary, json_file)
        reporter.generate_markdown_report(results, summary, md_file)

        assert os.path.exists(json_file)
        assert os.path.exists(md_file)
        assert os.path.getsize(json_file) > 100
        assert os.path.getsize(md_file) > 100
