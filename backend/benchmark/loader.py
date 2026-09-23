"""
CodeJev Benchmark Case Loader & Integrity Validator - Phase 14
================================================================

Loads dataset JSON files from disk and validates dataset integrity (duplicate IDs,
invalid line numbers, unsupported languages, missing expected fields).
"""

import json
import os
from typing import Dict, List, Set
from backend.benchmark.models import BenchmarkCase, ExpectedFinding
from backend.schemas import DynamicOptions


class BenchmarkLoader:
    """
    Loads and validates ground-truth benchmark datasets.
    """
    def load_from_file(self, filepath: str) -> List[BenchmarkCase]:
        """Loads benchmark cases from a JSON file path."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Benchmark dataset file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError(f"Dataset root must be a list of case objects in {filepath}")

        cases: List[BenchmarkCase] = []
        seen_ids: Set[str] = set()

        for idx, item in enumerate(raw_data):
            case = self._parse_and_validate_case(item, idx, filepath)
            if case.id in seen_ids:
                raise ValueError(f"Duplicate benchmark case ID '{case.id}' in {filepath}")
            seen_ids.add(case.id)
            cases.append(case)

        return cases

    def _parse_and_validate_case(self, data: dict, idx: int, filepath: str) -> BenchmarkCase:
        """Parses and validates a single benchmark case dictionary."""
        case_id = data.get("id")
        if not case_id or not isinstance(case_id, str):
            raise ValueError(f"Case index {idx} in {filepath} missing string 'id'")

        language = data.get("language")
        if not language or language not in ("python", "javascript", "typescript"):
            raise ValueError(f"Case '{case_id}' has unsupported language '{language}'")

        category = data.get("category")
        if not category:
            raise ValueError(f"Case '{case_id}' missing 'category'")

        is_positive = data.get("is_positive")
        if is_positive is None or not isinstance(is_positive, bool):
            raise ValueError(f"Case '{case_id}' missing boolean 'is_positive'")

        files = data.get("files")
        if not files or not isinstance(files, dict):
            raise ValueError(f"Case '{case_id}' missing non-empty 'files' dictionary")

        changed_lines = data.get("changed_lines")

        # Parse expected findings
        raw_exp = data.get("expected_findings", [])
        expected_findings: List[ExpectedFinding] = []
        for ef in raw_exp:
            st_line = ef.get("start_line", 1)
            end_line = ef.get("end_line", st_line)
            if end_line < st_line:
                raise ValueError(f"Case '{case_id}' has invalid line range {st_line}-{end_line}")

            expected_findings.append(ExpectedFinding(
                type=ef.get("type", "BUG"),
                severity=ef.get("severity", "HIGH"),
                file=ef.get("file", list(files.keys())[0]),
                start_line=st_line,
                end_line=end_line
            ))

        # Parse dynamic options if provided
        dyn_opts = None
        raw_dyn = data.get("dynamic_options")
        if raw_dyn and isinstance(raw_dyn, dict):
            dyn_opts = DynamicOptions(**raw_dyn)

        return BenchmarkCase(
            id=case_id,
            language=language,
            category=category,
            is_positive=is_positive,
            files=files,
            changed_lines=changed_lines,
            expected_findings=expected_findings,
            dynamic_options=dyn_opts,
            description=data.get("description", "")
        )
