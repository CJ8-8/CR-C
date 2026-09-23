"""
CodeJev Benchmark Reporter - Phase 14
======================================

Generates machine-readable results/evaluation.json and human-readable results/evaluation.md
with detailed TP/FP/FN/TN breakdowns, accuracy metrics, and diagnostic false-positive / false-negative logs.
"""

import json
import os
import sys
import platform
from datetime import datetime
from typing import List, Tuple
from backend.benchmark.models import CaseResult, MetricsSummary


class BenchmarkReporter:
    """
    Generates JSON and Markdown benchmark evaluation reports.
    """
    def generate_json_report(
        self, 
        results: List[CaseResult], 
        summary: MetricsSummary, 
        output_path: str
    ) -> None:
        """Generates machine-readable evaluation.json report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "total_cases": summary.total_cases,
                "positive_cases": summary.positive_cases,
                "negative_cases": summary.negative_cases,
            },
            "metrics": {
                "tp": summary.tp,
                "fp": summary.fp,
                "fn": summary.fn,
                "tn": summary.tn,
                "precision": summary.precision,
                "recall": summary.recall,
                "f1": summary.f1,
                "false_positive_rate": summary.fpr,
                "exact_line_accuracy": summary.exact_line_accuracy,
                "overlap_accuracy": summary.overlap_accuracy,
                "wrong_file_rate": summary.wrong_file_rate,
                "severity_agreement": summary.severity_agreement,
            },
            "per_language": {
                lang: {
                    "total_cases": m.total_cases,
                    "tp": m.tp,
                    "fp": m.fp,
                    "fn": m.fn,
                    "tn": m.tn,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1,
                }
                for lang, m in summary.per_language.items()
            },
            "per_category": {
                cat: {
                    "total_cases": m.total_cases,
                    "tp": m.tp,
                    "fp": m.fp,
                    "fn": m.fn,
                    "tn": m.tn,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1,
                }
                for cat, m in summary.per_category.items()
            },
            "false_positives": [
                {
                    "case_id": r.case_id,
                    "language": r.language,
                    "category": r.category,
                    "unmatched_predicted": [
                        {
                            "type": p.type,
                            "severity": p.severity,
                            "file": p.file,
                            "start_line": p.start_line,
                            "end_line": p.end_line
                        }
                        for p in r.unmatched_predicted
                    ]
                }
                for r in results if r.unmatched_predicted
            ],
            "false_negatives": [
                {
                    "case_id": r.case_id,
                    "language": r.language,
                    "category": r.category,
                    "unmatched_expected": [
                        {
                            "type": e.type,
                            "severity": e.severity,
                            "file": e.file,
                            "start_line": e.start_line,
                            "end_line": e.end_line
                        }
                        for e in r.unmatched_expected
                    ]
                }
                for r in results if r.unmatched_expected
            ]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    def generate_markdown_report(
        self, 
        results: List[CaseResult], 
        summary: MetricsSummary, 
        output_path: str
    ) -> None:
        """Generates human-readable evaluation.md report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        md_lines = []
        md_lines.append("# CodeJev Evaluation & Accuracy Report — Phase 14")
        md_lines.append("")
        md_lines.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_lines.append(f"**Python Version**: {sys.version.split()[0]}")
        md_lines.append(f"**Platform**: {platform.platform()}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 1. Executive Summary")
        md_lines.append("")
        md_lines.append(f"- **Total Benchmark Cases**: {summary.total_cases} (Positive: {summary.positive_cases}, Clean Negative: {summary.negative_cases})")
        md_lines.append(f"- **Overall Precision**: `{summary.precision * 100:.2f}%`")
        md_lines.append(f"- **Overall Recall**: `{summary.recall * 100:.2f}%`")
        md_lines.append(f"- **Overall F1 Score**: `{summary.f1 * 100:.2f}%`")
        md_lines.append(f"- **False Positive Rate (FPR)**: `{summary.fpr * 100:.2f}%`")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 2. Localization & Quality Metrics")
        md_lines.append("")
        md_lines.append(f"- **Exact Line Accuracy**: `{summary.exact_line_accuracy * 100:.2f}%`")
        md_lines.append(f"- **Range Overlap Accuracy**: `{summary.overlap_accuracy * 100:.2f}%`")
        md_lines.append(f"- **Wrong-File Rate**: `{summary.wrong_file_rate * 100:.2f}%`")
        md_lines.append(f"- **Severity Agreement**: `{summary.severity_agreement * 100:.2f}%`")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 3. Language Breakdown")
        md_lines.append("")
        md_lines.append("| Language | Cases | TP | FP | FN | Precision | Recall | F1 |")
        md_lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for lang, m in summary.per_language.items():
            md_lines.append(f"| {lang} | {m.total_cases} | {m.tp} | {m.fp} | {m.fn} | {m.precision * 100:.1f}% | {m.recall * 100:.1f}% | {m.f1 * 100:.1f}% |")

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 4. Category Breakdown")
        md_lines.append("")
        md_lines.append("| Category | Cases | TP | FP | FN | Precision | Recall | F1 |")
        md_lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for cat, m in summary.per_category.items():
            md_lines.append(f"| {cat} | {m.total_cases} | {m.tp} | {m.fp} | {m.fn} | {m.precision * 100:.1f}% | {m.recall * 100:.1f}% | {m.f1 * 100:.1f}% |")

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 5. False Positives (Unexpected Findings)")
        md_lines.append("")
        fps = [r for r in results if r.unmatched_predicted]
        if not fps:
            md_lines.append("None. Zero false positives detected!")
        else:
            for r in fps:
                md_lines.append(f"- **Case ID**: `{r.case_id}` ({r.language} / {r.category})")
                for pred in r.unmatched_predicted:
                    md_lines.append(f"  - Unexpected `{pred.type}` ({pred.severity}) at `{pred.file}:{pred.start_line}-{pred.end_line}`")

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 6. False Negatives (Missed Known Flaws)")
        md_lines.append("")
        fns = [r for r in results if r.unmatched_expected]
        if not fns:
            md_lines.append("None. All ground-truth flaws successfully detected!")
        else:
            for r in fns:
                md_lines.append(f"- **Case ID**: `{r.case_id}` ({r.language} / {r.category})")
                for exp in r.unmatched_expected:
                    md_lines.append(f"  - Missed `{exp.type}` ({exp.severity}) at `{exp.file}:{exp.start_line}-{exp.end_line}`")

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("## 7. Limitations & Methodology Notes")
        md_lines.append("")
        md_lines.append("- Benchmark metrics represent evaluation against synthetic ground-truth cases.")
        md_lines.append("- Recall percentage on benchmark dataset does NOT guarantee finding all possible bugs in un-benchmarked production software.")
        md_lines.append("- All tests run deterministically offline without network calls or external AI APIs.")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")
