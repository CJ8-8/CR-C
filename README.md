# CR-C - Phase 1 to Phase 14 Engine

Welcome to **CR-C**, an automated multi-language code analysis engine for detecting and localizing software code problems in Pull Request diffs, Python ASTs, JavaScript/TypeScript ESTrees, multi-file projects, Taint Analysis, Dependencies, Secrets, Configuration scanning, Bug detection, Performance analysis, Dynamic Signals, and Benchmark Evaluation.

---

## 1. What is CR-C?

**CR-C** is designed to inspect code modifications (e.g. Git Pull Requests) and pinpoint **EXACTLY WHERE** problems are located (filename and line numbers) along with their flaw `type` and `severity`.

- **Phase 1 (Legacy Experiment)**: PR Risk Prototype (`POST /review`) – High-level gatekeeping (`PASS`, `REVIEW`, `BLOCK`).
- **Phase 2 (Code Analysis)**: Full file issue detection (`POST /analyze`) – Line-level flaw localization in full file strings.
- **Phase 3 (Diff Analysis)**: Unified Git Diff Parsing & Changed-Line Localization (`POST /analyze-diff`) – Restricting analysis strictly to added/modified lines in code diffs.
- **Phase 4 (AST Analysis)**: Structural Python AST Analysis (`POST /analyze-python`) – Using Python's built-in `ast` module to distinguish real executable Python constructs from plain text strings.
- **Phase 5 (Detector Engine Architecture)**: Modular Detector Architecture (`backend/detector_engine.py` & `backend/detectors/`) – Decoupling rules into isolated detectors (`SecurityDetector`, `CodeQualityDetector`, `BugDetector`).
- **Phase 6 (Intelligent Detection)**: Context-Aware Analysis & Local Data-Flow (`backend/analysis_context.py`) – Tracking local variable assignments, dynamic SQL string concatenation, and definite `None` dereferences without speculative false positives.
- **Phase 7 (Multi-File / Interprocedural Analysis)**: Project-Level Cross-File Analysis (`backend/project_analyzer.py` & `POST /analyze-project`) – Indexing modules and function definitions across multiple files, resolving simple imports and cross-file function calls (`app.py` $\rightarrow$ `auth.py` $\rightarrow$ `database.py`).
- **Phase 8 (Advanced Data-Flow & Taint Analysis)**: Taint Tracking Engine (`backend/analysis_context.py` & `backend/detectors/security.py`) – Tracking untrusted data flow from **Sources** (`input()`, `request.args[...]`) through variable assignments, expressions, and function returns to dangerous **Sinks** (`eval()`, `exec()`, `subprocess.run(shell=True)`, `cursor.execute()`), respecting explicit **Sanitizers** (`shlex.quote(...)`, parameterized SQL queries).
- **Phase 9 (Dependencies, Secrets & Configuration Analysis)**: Dependency manifest parsing (`requirements.txt`, `pyproject.toml`), vulnerability advisory lookups (`advisory_client.py`), zero-exposure secret scanning (`SecretsDetector`), and configuration auditing (`ConfigurationDetector`).
- **Phase 10 (Broader Bug & Performance Detection)**: Extended bug rules (unreachable code, constant-condition branches, suspicious identity checks, duplicate dict keys, swallowed exceptions), performance heuristics (`PerformanceDetector` for `re.compile()` in loops, `+=` string accumulation in loops, repeated expensive calls/constructions), and duplicate import detection (`CodeQualityDetector`).
- **Phase 11 (Multi-Language Analysis)**: Language registry (`LanguageRegistry`), extension-based routing (`.py` $\rightarrow$ Python, `.js`/`.jsx` $\rightarrow$ JavaScript, `.ts`/`.tsx` $\rightarrow$ TypeScript), `esprima` ESTree AST parsing, and language-specific detectors (`JavaScriptSecurityDetector`, `JavaScriptBugDetector`, `JavaScriptQualityDetector`) producing unified CodeJev outputs.
- **Phase 12 (Runtime, Test & Fuzzing Signals)**: Opt-in dynamic analysis module (`backend/dynamic/`) integrating test runner (`TestRunner`), entrypoint runtime exception runner (`RuntimeRunner`), and bounded function fuzzing (`FuzzRunner`), producing merged, deduplicated `Issue` objects.
- **Phase 13 (Advanced Static Analysis & Coverage)**: Control Flow Graphs (`ControlFlowGraph`), lightweight abstract program state tracking (`ProgramState`), path-sensitive nullability & taint guards, interprocedural function summaries (`SummaryCache`), internal evidence validation (`FindingValidator`), and new bug rules (Division by Zero, Out-of-Bounds Indexing, Duplicate Branch Conditions).
- **Phase 14 (Benchmark & Accuracy Evaluation)**: Ground-truth evaluator (`backend/benchmark/`) assessing precision, recall, F1, false positive rate (FPR), exact vs range line localization, wrong-file rate, and severity agreement against ground-truth datasets without network or LLM dependencies (`python -m backend.benchmark`).

---

## 2. Project Structure

```text
codejev/
├── backend/
│   ├── __init__.py            # Python package marker
│   ├── main.py                # FastAPI endpoints
│   ├── schemas.py             # Pydantic data models
│   ├── rules.py               # Phase 1 PR risk rules
│   ├── diff_parser.py         # Phase 3 unified diff parser
│   ├── analyzer.py            # Phase 2 & 3 string scanners
│   ├── ast_analyzer.py        # AST parser bridge
│   ├── analysis_context.py    # Phase 6, 8 & 13 TaintState, AnalysisContext, CFG & ProgramState
│   ├── advisory_client.py     # Phase 9 AdvisoryClient vulnerability lookup database
│   ├── dependency_analyzer.py # Phase 9 DependencyAnalyzer for requirements.txt and pyproject.toml
│   ├── detector_engine.py     # DetectorEngine coordinator
│   ├── project_analyzer.py    # ProjectAnalyzer & interprocedural SummaryCache
│   ├── language_registry.py   # Phase 11 LanguageRegistry extension router
│   ├── benchmark/             # Phase 14 Benchmark Subsystem
│   │   ├── __init__.py        # Benchmark package marker
│   │   ├── models.py          # Ground truth case & result data structures
│   │   ├── loader.py          # Benchmark dataset loader & validator
│   │   ├── matcher.py          # Finding vs expected matcher engine
│   │   ├── metrics.py          # Precision, Recall, F1 & Localization metrics
│   │   ├── runner.py           # ProjectAnalyzer pipeline runner & mutator
│   │   ├── reporter.py         # JSON and Markdown report writer
│   │   └── __main__.py        # CLI entrypoint (python -m backend.benchmark)
│   ├── analysis/              # Phase 13 Advanced Analysis Engine
│   │   ├── __init__.py        # Analysis package marker
│   │   ├── control_flow.py    # Control Flow Graph (CFG) builder & node model
│   │   ├── program_state.py   # ProgramState lattice, nullability & guard merging
│   │   ├── function_summary.py # Interprocedural FunctionSummary & SummaryCache
│   │   └── finding_validator.py # Internal FindingEvidence & FindingValidator
│   ├── analyzers/             # Language Analyzer implementations
│   │   ├── __init__.py        # Analyzers package marker
│   │   ├── base.py            # LanguageAnalyzer abstract base class
│   │   ├── python_analyzer.py # Python AST & ProjectAnalyzer wrapper
│   │   └── javascript_analyzer.py # JS/TS esprima parser & detector orchestrator
│   ├── dynamic/               # Phase 12 Dynamic Analysis Module
│   │   ├── __init__.py        # Dynamic package marker
│   │   ├── test_runner.py     # Subprocess pytest runner & traceback parser
│   │   ├── runtime_runner.py  # Subprocess entrypoint exception runner
│   │   ├── fuzz_runner.py     # Bounded deterministic function fuzz runner
│   │   └── result_parser.py   # Dynamic evidence converter & finder integrator
│   └── detectors/             # Modular Detectors
│       ├── __init__.py        # Detectors package marker
│       ├── base.py            # BaseDetector abstract interface
│       ├── security.py        # SecurityDetector (eval, exec, shell=True, dynamic SQL, taint sinks)
│       ├── code_quality.py    # CodeQualityDetector (print debug calls, duplicate imports)
│       ├── bug.py             # BugDetector (division by zero, index out of bounds, duplicate conditions, bare excepts, mutable defaults)
│       ├── secrets.py         # Phase 9 SecretsDetector (private keys, AWS/GitHub tokens, API keys)
│       ├── configuration.py   # Phase 9 ConfigurationDetector (DEBUG=True, verify=False, wildcard CORS)
│       ├── performance.py     # Phase 10 PerformanceDetector (re.compile in loops, += string concat, etc.)
│       ├── javascript_security.py # Phase 11 JS/TS SecurityDetector (eval, child_process.exec, innerHTML, dynamic SQL)
│       ├── javascript_bug.py  # Phase 11 JS/TS BugDetector (assignment in condition, unreachable code)
│       └── javascript_quality.py # Phase 11 JS/TS QualityDetector (console.log, duplicate imports/requires)
├── benchmarks/
│   ├── synthetic_cases.json   # Ground truth test cases across languages & categories
│   └── README.md              # Dataset format specification
├── results/
│   ├── evaluation.json        # Machine-readable benchmark report
│   └── evaluation.md          # Human-readable benchmark summary
├── tests/
│   ├── __init__.py            # Python package marker
│   ├── test_review.py         # Phase 1 test suite
│   ├── test_analyze.py        # Phase 2 test suite
│   ├── test_diff.py           # Phase 3 test suite
│   ├── test_ast.py            # Phase 4 test suite
│   ├── test_detectors.py      # Phase 5 test suite
│   ├── test_context.py        # Phase 6 test suite
│   ├── test_project.py        # Phase 7, 9, 10 & 11 test suite
│   ├── test_taint.py          # Phase 8 test suite
│   ├── test_dependencies.py   # Phase 9 dependency test suite
│   ├── test_secrets.py        # Phase 9 secret scanning test suite
│   ├── test_configuration.py  # Phase 9 configuration test suite
│   ├── test_bug_extended.py   # Phase 10 extended bug test suite
│   ├── test_performance.py    # Phase 10 performance heuristics test suite
│   ├── test_language_registry.py # Phase 11 language registry test suite
│   ├── test_javascript.py     # Phase 11 JavaScript test suite
│   ├── test_typescript.py     # Phase 11 TypeScript test suite
│   ├── test_dynamic.py        # Phase 12 test runner & integrator test suite
│   ├── test_runtime.py        # Phase 12 runtime entrypoint test suite
│   ├── test_fuzzing.py        # Phase 12 bounded fuzz runner test suite
│   ├── test_control_flow.py   # Phase 13 CFG test suite
│   ├── test_program_state.py  # Phase 13 ProgramState & lattice test suite
│   ├── test_function_summaries.py # Phase 13 function summary test suite
│   ├── test_phase13_bugs.py   # Phase 13 bug rules test suite
│   ├── test_finding_validation.py # Phase 13 finding validation test suite
│   ├── test_branch_taint.py   # Phase 13 branch-sensitive taint test suite
│   ├── test_pathological_projects.py # Phase 13 recursion & termination test suite
│   ├── test_benchmark_loader.py # Phase 14 dataset loader test suite
│   ├── test_benchmark_matcher.py # Phase 14 ground-truth matcher test suite
│   ├── test_benchmark_metrics.py # Phase 14 metrics engine test suite
│   └── test_benchmark_runner.py # Phase 14 CLI & runner integration test suite
├── examples/
│   ├── sample_pr.json         # Phase 1 sample payload
│   ├── sample_code.json       # Phase 2 sample payload
│   ├── sample_diff.json       # Phase 3 sample payload
│   ├── sample_ast.json        # Phase 4 sample payload
│   ├── sample_detector.json   # Phase 5 sample payload
│   ├── sample_context.json    # Phase 6 sample payload
│   ├── sample_project.json    # Phase 7 sample payload
│   ├── sample_taint.json      # Phase 8 sample payload
│   ├── sample_security_project.json # Phase 9 sample payload
│   ├── sample_quality_performance.json # Phase 10 sample payload
│   ├── sample_multilanguage.json # Phase 11 sample payload
│   ├── sample_dynamic_project.json # Phase 12 dynamic analysis payload
│   └── sample_advanced_analysis.json # Phase 13 advanced analysis payload
├── requirements.txt           # Python project dependencies
└── README.md                  # Setup and architecture documentation
```

---

## 3. Phase 14 Architecture: Benchmark & Accuracy Evaluation

```text
       Ground-Truth Dataset (JSON)
                   │
                   ▼
         Benchmark Case Loader & Validator
                   │
                   ▼
         ProjectAnalyzer Pipeline Execution
                   │
                   ▼
          Ground-Truth Matcher Engine
        (Exact File, Line & Type Match)
                   │
                   ▼
         Metrics & Diagnostics Engine
 (Precision, Recall, F1, FPR, Line Localization)
                   │
                   ▼
      ┌──────────────────────────┐
      │  evaluation.json / .md   │
      └──────────────────────────┘
```

> [!NOTE]
> **Deterministic Evaluation**: Phase 14 measures CR-C against labeled ground truth reproducibly without non-deterministic LLM scoring or network calls.

---

## 4. How to Set Up & Run (Step-by-Step)

### Step 1: Activate Virtual Environment

```bash
source .venv/bin/activate
```

### Step 2: Run the FastAPI Server

```bash
uvicorn backend.main:app --reload --port 8000
```

- Server Address: `http://127.0.0.1:8000`
- Interactive API Docs (Swagger UI): `http://127.0.0.1:8000/docs`

### Step 3: Run the Benchmark Suite

```bash
python -m backend.benchmark
```

---

## 5. Running Automated Tests

Run the full pytest suite across all phases (153 tests):

```bash
pytest
```

---

## 6. Roadmap: Future Phases

- **Phase 15**: Multi-Repository Interprocedural Call Graphing.
- **GitHub Integration**: Real GitHub Webhook ingestion, automated PR comment posting, and cloud deployment.




