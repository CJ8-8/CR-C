"""
CodeJev Benchmark Execution Engine - Phase 14
==============================================

Executes benchmark cases through CodeJev analysis pipeline, matches predicted findings
against ground-truth, calculates metrics, and runs controlled mutation testing.
"""

import os
import tempfile
from typing import Dict, List, Optional, Tuple
from backend.benchmark.models import BenchmarkCase, CaseResult, MetricsSummary
from backend.benchmark.loader import BenchmarkLoader
from backend.benchmark.matcher import FindingMatcher
from backend.benchmark.metrics import MetricsCalculator
from backend.project_analyzer import ProjectAnalyzer
from backend.detector_engine import DetectorEngine
from backend.dependency_analyzer import DependencyAnalyzer
from backend.detectors.secrets import SecretsDetector
from backend.detectors.configuration import ConfigurationDetector
from backend.language_registry import LanguageRegistry
from backend.dynamic import TestRunner, RuntimeRunner, FuzzRunner, DynamicResultParser
from backend.schemas import Issue


class BenchmarkRunner:
    """
    Executes ground-truth benchmark suites against CodeJev internal analysis engine.
    """
    def __init__(self):
        self.matcher = FindingMatcher()
        self.metrics_calculator = MetricsCalculator()
        self.detector_engine = DetectorEngine()
        self.dependency_analyzer = DependencyAnalyzer()
        self.secrets_detector = SecretsDetector()
        self.config_detector = ConfigurationDetector()
        self.language_registry = LanguageRegistry()
        self.dynamic_parser = DynamicResultParser()

    def run_suite(self, cases: List[BenchmarkCase]) -> Tuple[List[CaseResult], MetricsSummary]:
        """
        Executes all benchmark cases in a suite and computes accuracy metrics.
        """
        results: List[CaseResult] = []

        for case in cases:
            predicted_issues = self.analyze_case(case)
            case_res = self.matcher.match_case(case, predicted_issues)
            results.append(case_res)

        summary = self.metrics_calculator.compute_summary(results)
        return results, summary

    def analyze_case(self, case: BenchmarkCase) -> List[Issue]:
        """
        Runs CodeJev analysis pipeline on a single BenchmarkCase.
        """
        static_issues: List[Issue] = []
        dynamic_issues: List[Issue] = []

        # 1. AST Analysis for Python files (preserves cross-file interprocedural analysis)
        project_analyzer = ProjectAnalyzer(files=case.files)
        for filename, tree in project_analyzer.trees.items():
            file_changed_lines = None
            if case.changed_lines and filename in case.changed_lines:
                file_changed_lines = set(case.changed_lines[filename])

            issues = self.detector_engine.analyze(
                tree=tree, 
                file=filename, 
                changed_lines=file_changed_lines, 
                project_analyzer=project_analyzer
            )
            static_issues.extend(issues)

        # 2. Multi-language (JS/TS) & manifest / text secret / config analysis
        for filename, code in case.files.items():
            file_changed_lines = None
            if case.changed_lines and filename in case.changed_lines:
                file_changed_lines = set(case.changed_lines[filename])

            lang = self.language_registry.get_language(filename)
            if lang in ("javascript", "typescript"):
                analyzer = self.language_registry.get_analyzer(filename)
                if analyzer:
                    js_issues = analyzer.analyze(filename, code, file_changed_lines)
                    static_issues.extend(js_issues)

            dep_issues = self.dependency_analyzer.analyze_file(filename, code, file_changed_lines)
            static_issues.extend(dep_issues)

            if not filename.endswith(".py"):
                sec_issues = self.secrets_detector.scan_text(filename, code, file_changed_lines)
                static_issues.extend(sec_issues)

                cfg_issues = self.config_detector.scan_text(filename, code, file_changed_lines)
                static_issues.extend(cfg_issues)

        # 3. Opt-in Dynamic Analysis (if dynamic_options enabled)
        if case.dynamic_options and case.dynamic_options.enabled:
            with tempfile.TemporaryDirectory() as temp_dir:
                for fname, content in case.files.items():
                    fpath = os.path.join(temp_dir, fname)
                    os.makedirs(os.path.dirname(fpath), exist_ok=True)
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(content)

                timeout = case.dynamic_options.timeout_seconds

                if any(k.startswith("test_") or "/test_" in k or k.endswith("_test.py") for k in case.files.keys()):
                    test_runner = TestRunner()
                    test_results = test_runner.run_tests(temp_dir, timeout_seconds=timeout)
                    dynamic_issues.extend(self.dynamic_parser.convert_test_results(test_results))

                if case.dynamic_options.entrypoint:
                    runtime_runner = RuntimeRunner()
                    rt_res = runtime_runner.run_entrypoint(temp_dir, case.dynamic_options.entrypoint, timeout_seconds=timeout)
                    dynamic_issues.extend(self.dynamic_parser.convert_runtime_result(rt_res))

                if case.dynamic_options.fuzz_target:
                    fuzz_runner = FuzzRunner()
                    fuzz_res = fuzz_runner.fuzz_target(
                        temp_dir, 
                        case.dynamic_options.fuzz_target, 
                        max_cases=case.dynamic_options.max_fuzz_cases, 
                        timeout_seconds=timeout
                    )
                    dynamic_issues.extend(self.dynamic_parser.convert_fuzz_result(fuzz_res))

        # Combine, filter by changed_lines, deduplicate, and sort
        unique_issues = self.dynamic_parser.combine_and_filter(static_issues, dynamic_issues, case.changed_lines)
        return unique_issues

    def run_mutation_test(self, case: BenchmarkCase, mutated_file: str, mutated_code: str) -> List[Issue]:
        """
        Executes a controlled mutation test on a clean benchmark case.
        """
        mutated_files = dict(case.files)
        mutated_files[mutated_file] = mutated_code

        mutated_case = BenchmarkCase(
            id=f"{case.id}-mutation",
            language=case.language,
            category=case.category,
            is_positive=True,
            files=mutated_files,
            changed_lines=case.changed_lines,
            description=f"Mutation of {case.id}"
        )

        return self.analyze_case(mutated_case)
