import os
import tempfile
from typing import List
from fastapi import FastAPI, HTTPException
from backend.schemas import (
    PRReviewRequest, 
    PRReviewResponse,
    CodeAnalysisRequest,
    CodeAnalysisResponse,
    DiffAnalysisRequest,
    PythonASTAnalysisRequest,
    ProjectAnalysisRequest,
    Issue
)
from backend.rules import evaluate_pr_review
from backend.analyzer import analyze_code, analyze_diff
from backend.ast_analyzer import analyze_python_ast, ASTSyntaxError
from backend.project_analyzer import ProjectAnalyzer
from backend.detector_engine import DetectorEngine
from backend.dependency_analyzer import DependencyAnalyzer
from backend.detectors.secrets import SecretsDetector
from backend.detectors.configuration import ConfigurationDetector
from backend.language_registry import LanguageRegistry
from backend.dynamic import TestRunner, RuntimeRunner, FuzzRunner, DynamicResultParser

# Initialize FastAPI web application
app = FastAPI(
    title="CodeJev Engine API",
    description="Multi-language static & opt-in dynamic code analysis decision engine for detecting issues in Python, JavaScript, TypeScript, dependencies, secrets, configurations, tests, runtime, and fuzzing.",
    version="0.12.0"
)


@app.get("/health", tags=["Health"])
def health_check():
    """
    Health check endpoint to verify backend server status.
    """
    return {
        "status": "ok",
        "service": "CodeJev Engine (Phase 1-12)",
        "mode": "static & opt-in dynamic analysis (tests, runtime, fuzzing)"
    }


@app.post("/review", response_model=PRReviewResponse, tags=["Phase 1 - PR Review"])
def review_pull_request(request: PRReviewRequest) -> PRReviewResponse:
    """
    Phase 1: Evaluates Pull Request summary metrics and produces a gatekeeping decision.
    """
    decision_result = evaluate_pr_review(request)
    return decision_result


@app.post("/analyze", response_model=CodeAnalysisResponse, tags=["Phase 2 - Code Analysis"])
def analyze_code_endpoint(request: CodeAnalysisRequest) -> CodeAnalysisResponse:
    """
    Phase 2: Scans a full source code string line-by-line and returns localized Issue objects.
    """
    detected_issues = analyze_code(file=request.file, code=request.code)
    return CodeAnalysisResponse(issues=detected_issues)


@app.post("/analyze-diff", response_model=CodeAnalysisResponse, tags=["Phase 3 - Diff Analysis"])
def analyze_diff_endpoint(request: DiffAnalysisRequest) -> CodeAnalysisResponse:
    """
    Phase 3: Parses a Git unified diff and scans ONLY newly added/modified lines for issues.
    """
    detected_issues = analyze_diff(file=request.file, diff_text=request.diff)
    return CodeAnalysisResponse(issues=detected_issues)


@app.post("/analyze-python", response_model=CodeAnalysisResponse, tags=["Phase 4 - Python AST Analysis"])
def analyze_python_endpoint(request: PythonASTAnalysisRequest) -> CodeAnalysisResponse:
    """
    Phase 4 & 5: Parses Python source code into an AST to detect actual executable constructs
    using modular AST detectors. Optionally filters issues to specified changed line numbers.
    """
    changed_set = set(request.changed_lines) if request.changed_lines is not None else None
    
    try:
        detected_issues = analyze_python_ast(
            file=request.file, 
            code=request.code, 
            changed_lines=changed_set
        )
    except ASTSyntaxError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return CodeAnalysisResponse(issues=detected_issues)


@app.post("/analyze-project", response_model=CodeAnalysisResponse, tags=["Phase 7-12 - Multi-file & Dynamic Analysis"])
def analyze_project_endpoint(request: ProjectAnalysisRequest) -> CodeAnalysisResponse:
    """
    Phase 7-12: Parses Python, JavaScript, TypeScript files and project manifests in a codebase.
    Optionally executes opt-in dynamic analysis (test runner, runtime runner, fuzzing) in isolated subprocesses,
    returning combined, deduplicated, localized Issues.
    """
    project_analyzer = ProjectAnalyzer(files=request.files)
    detector_engine = DetectorEngine()
    dependency_analyzer = DependencyAnalyzer()
    secrets_detector = SecretsDetector()
    config_detector = ConfigurationDetector()
    language_registry = LanguageRegistry()
    dynamic_parser = DynamicResultParser()
    static_issues: List[Issue] = []
    dynamic_issues: List[Issue] = []

    # 1. AST Analysis for Python files in project (preserves cross-file interprocedural analysis)
    for filename, tree in project_analyzer.trees.items():
        file_changed_lines = None
        if request.changed_lines and filename in request.changed_lines:
            file_changed_lines = set(request.changed_lines[filename])

        issues = detector_engine.analyze(
            tree=tree, 
            file=filename, 
            changed_lines=file_changed_lines, 
            project_analyzer=project_analyzer
        )
        static_issues.extend(issues)

    # 2. Multi-language Analysis (JS/TS) & Non-Python manifest/secret/configuration scanning
    for filename, code in request.files.items():
        file_changed_lines = None
        if request.changed_lines and filename in request.changed_lines:
            file_changed_lines = set(request.changed_lines[filename])

        # Check language via LanguageRegistry
        lang = language_registry.get_language(filename)
        if lang in ("javascript", "typescript"):
            analyzer = language_registry.get_analyzer(filename)
            if analyzer:
                js_issues = analyzer.analyze(filename, code, file_changed_lines)
                static_issues.extend(js_issues)

        # Dependency analysis for requirements.txt or pyproject.toml
        dep_issues = dependency_analyzer.analyze_file(filename, code, file_changed_lines)
        static_issues.extend(dep_issues)

        # Text secret & configuration scanning for non-Python text files
        if not filename.endswith(".py"):
            sec_issues = secrets_detector.scan_text(filename, code, file_changed_lines)
            static_issues.extend(sec_issues)

            cfg_issues = config_detector.scan_text(filename, code, file_changed_lines)
            static_issues.extend(cfg_issues)

    # 3. Opt-in Dynamic Analysis (Tests, Runtime, Fuzzing)
    if request.dynamic and request.dynamic.enabled:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write files to isolated temporary workspace
            for fname, content in request.files.items():
                fpath = os.path.join(temp_dir, fname)
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)

            timeout = request.dynamic.timeout_seconds

            # 3a. Execute Test Runner if test files exist
            if any(k.startswith("test_") or "/test_" in k or k.endswith("_test.py") for k in request.files.keys()):
                test_runner = TestRunner()
                test_results = test_runner.run_tests(temp_dir, timeout_seconds=timeout)
                dynamic_issues.extend(dynamic_parser.convert_test_results(test_results))

            # 3b. Execute Runtime Runner if entrypoint declared
            if request.dynamic.entrypoint:
                runtime_runner = RuntimeRunner()
                rt_res = runtime_runner.run_entrypoint(temp_dir, request.dynamic.entrypoint, timeout_seconds=timeout)
                dynamic_issues.extend(dynamic_parser.convert_runtime_result(rt_res))

            # 3c. Execute Fuzz Runner if fuzz_target declared
            if request.dynamic.fuzz_target:
                fuzz_runner = FuzzRunner()
                fuzz_res = fuzz_runner.fuzz_target(
                    temp_dir, 
                    request.dynamic.fuzz_target, 
                    max_cases=request.dynamic.max_fuzz_cases, 
                    timeout_seconds=timeout
                )
                dynamic_issues.extend(dynamic_parser.convert_fuzz_result(fuzz_res))

    # Combine static and dynamic issues, filter by changed_lines, deduplicate, and sort deterministically
    unique_issues = dynamic_parser.combine_and_filter(static_issues, dynamic_issues, request.changed_lines)
    return CodeAnalysisResponse(issues=unique_issues)



