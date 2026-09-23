"""
CodeJev Benchmark CLI Entrypoint - Phase 14
============================================

Command-line interface for running CodeJev benchmark evaluations.
Supports dataset selection, language/category filtering, output report directory,
and metric threshold enforcement.

Usage:
  python -m backend.benchmark [--dataset PATH] [--output-dir PATH]
"""

import argparse
import os
import sys
from backend.benchmark.loader import BenchmarkLoader
from backend.benchmark.runner import BenchmarkRunner
from backend.benchmark.reporter import BenchmarkReporter


def main():
    parser = argparse.ArgumentParser(description="CodeJev Benchmark & Accuracy Evaluation Engine (Phase 14)")
    parser.add_argument(
        "--dataset", 
        default="benchmarks/synthetic_cases.json", 
        help="Path to benchmark ground-truth JSON dataset file"
    )
    parser.add_argument(
        "--output-dir", 
        default="results", 
        help="Output directory path for generated evaluation.json and evaluation.md"
    )
    parser.add_argument(
        "--language", 
        choices=["python", "javascript", "typescript"], 
        help="Optional language filter"
    )
    parser.add_argument(
        "--category", 
        help="Optional category filter (SECURITY, BUG, PERFORMANCE, CODE_QUALITY, SECRETS, CONFIGURATION, DEPENDENCIES)"
    )
    parser.add_argument(
        "--threshold-precision", 
        type=float, 
        help="Optional minimum precision threshold (e.g. 0.80)"
    )
    parser.add_argument(
        "--threshold-recall", 
        type=float, 
        help="Optional minimum recall threshold (e.g. 0.80)"
    )

    args = parser.parse_args()

    # Resolve paths relative to working directory
    dataset_path = os.path.abspath(args.dataset)
    output_dir = os.path.abspath(args.output_dir)

    print("==================================================================")
    print("      CodeJev Benchmark & Accuracy Evaluation Engine (Phase 14)")
    print("==================================================================")
    print(f"Loading dataset: {dataset_path}")

    loader = BenchmarkLoader()
    try:
        cases = loader.load_from_file(dataset_path)
    except Exception as e:
        print(f"ERROR loading benchmark dataset: {e}")
        sys.exit(1)

    # Filter cases if requested
    if args.language:
        cases = [c for c in cases if c.language == args.language]
    if args.category:
        cases = [c for c in cases if c.category.upper() == args.category.upper()]

    if not cases:
        print("No cases matched the specified filters.")
        sys.exit(1)

    print(f"Executing {len(cases)} benchmark cases across project analyzer...")

    runner = BenchmarkRunner()
    results, summary = runner.run_suite(cases)

    reporter = BenchmarkReporter()
    json_path = os.path.join(output_dir, "evaluation.json")
    md_path = os.path.join(output_dir, "evaluation.md")

    reporter.generate_json_report(results, summary, json_path)
    reporter.generate_markdown_report(results, summary, md_path)

    print("\n---------------------- EVALUATION METRICS ----------------------")
    print(f" Total Cases       : {summary.total_cases} (Positive: {summary.positive_cases}, Negative: {summary.negative_cases})")
    print(f" True Positives (TP): {summary.tp}")
    print(f" False Positives(FP): {summary.fp}")
    print(f" False Negatives(FN): {summary.fn}")
    print(f" True Negatives (TN): {summary.tn}")
    print("------------------------------------------------------------------")
    print(f" Precision          : {summary.precision * 100:.2f}%")
    print(f" Recall             : {summary.recall * 100:.2f}%")
    print(f" F1 Score           : {summary.f1 * 100:.2f}%")
    print(f" False Positive Rate: {summary.fpr * 100:.2f}%")
    print(f" Exact Line Accuracy: {summary.exact_line_accuracy * 100:.2f}%")
    print(f" Overlap Accuracy   : {summary.overlap_accuracy * 100:.2f}%")
    print(f" Severity Agreement : {summary.severity_agreement * 100:.2f}%")
    print("------------------------------------------------------------------")
    print(f"Reports saved to:")
    print(f"  - JSON : {json_path}")
    print(f"  - MD   : {md_path}")
    print("==================================================================\n")

    # Optional threshold checks
    failed_threshold = False
    if args.threshold_precision is not None and summary.precision < args.threshold_precision:
        print(f"FAILED Precision threshold: {summary.precision:.4f} < {args.threshold_precision:.4f}")
        failed_threshold = True
    if args.threshold_recall is not None and summary.recall < args.threshold_recall:
        print(f"FAILED Recall threshold: {summary.recall:.4f} < {args.threshold_recall:.4f}")
        failed_threshold = True

    if failed_threshold:
        sys.exit(1)


if __name__ == "__main__":
    main()
