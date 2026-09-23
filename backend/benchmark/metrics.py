"""
CodeJev Benchmark Metrics Engine - Phase 14
=============================================

Calculates multi-dimensional accuracy metrics: Precision, Recall, F1, False-Positive Rate (FPR),
Exact-Line vs Overlap Localization Accuracy, Wrong-File Rate, and Severity Agreement.
Produces breakdown metrics by programming language and issue category.
"""

from typing import Dict, List
from backend.benchmark.models import CaseResult, CategoryMetrics, MetricsSummary


class MetricsCalculator:
    """
    Computes evaluation metrics across a set of executed CaseResult objects.
    """
    def compute_summary(self, results: List[CaseResult]) -> MetricsSummary:
        """Computes global, per-language, and per-category accuracy metrics."""
        total_cases = len(results)
        positive_cases = sum(1 for r in results if r.is_positive)
        negative_cases = total_cases - positive_cases

        # Calculate TP, FP, FN, TN at finding / case level
        tp_count = 0
        fp_count = 0
        fn_count = 0
        tn_count = 0

        exact_line_matches = 0
        overlap_matches = 0
        severity_matches = 0
        total_matched_pairs = 0
        wrong_file_fps = 0

        for r in results:
            tp_count += len(r.matched_pairs)
            fn_count += len(r.unmatched_expected)
            fp_count += len(r.unmatched_predicted)

            if not r.is_positive and not r.predicted_issues:
                tn_count += 1

            for pair in r.matched_pairs:
                total_matched_pairs += 1
                if pair.is_exact_line:
                    exact_line_matches += 1
                if pair.is_overlap:
                    overlap_matches += 1
                if pair.severity_matches:
                    severity_matches += 1

            for unpred in r.unmatched_predicted:
                # Check if file didn't exist in ground truth expected
                exp_files = {e.file for e in r.unmatched_expected}
                if exp_files and unpred.file not in exp_files:
                    wrong_file_fps += 1

        precision = self._safe_divide(tp_count, tp_count + fp_count)
        recall = self._safe_divide(tp_count, tp_count + fn_count)
        f1 = self._safe_divide(2 * precision * recall, precision + recall)

        # FPR on negative clean cases
        clean_negative_fps = sum(len(r.unmatched_predicted) for r in results if not r.is_positive)
        fpr = self._safe_divide(clean_negative_fps, clean_negative_fps + tn_count)

        exact_line_acc = self._safe_divide(exact_line_matches, total_matched_pairs)
        overlap_acc = self._safe_divide(overlap_matches, total_matched_pairs)
        wrong_file_rate = self._safe_divide(wrong_file_fps, fp_count)
        sev_agreement = self._safe_divide(severity_matches, total_matched_pairs)

        # Per-language metrics
        per_language = self._compute_grouped_metrics(results, group_key=lambda r: r.language)

        # Per-category metrics
        per_category = self._compute_grouped_metrics(results, group_key=lambda r: r.category)

        return MetricsSummary(
            total_cases=total_cases,
            positive_cases=positive_cases,
            negative_cases=negative_cases,
            tp=tp_count,
            fp=fp_count,
            fn=fn_count,
            tn=tn_count,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            fpr=round(fpr, 4),
            exact_line_accuracy=round(exact_line_acc, 4),
            overlap_accuracy=round(overlap_acc, 4),
            wrong_file_rate=round(wrong_file_rate, 4),
            severity_agreement=round(sev_agreement, 4),
            per_language=per_language,
            per_category=per_category
        )

    def _compute_grouped_metrics(
        self, 
        results: List[CaseResult], 
        group_key
    ) -> Dict[str, CategoryMetrics]:
        """Computes metrics grouped by language or category."""
        groups: Dict[str, List[CaseResult]] = {}
        for r in results:
            key = group_key(r)
            if key not in groups:
                groups[key] = []
            groups[key].append(r)

        metrics_map: Dict[str, CategoryMetrics] = {}
        for key, res_list in sorted(groups.items()):
            tp = sum(len(r.matched_pairs) for r in res_list)
            fn = sum(len(r.unmatched_expected) for r in res_list)
            fp = sum(len(r.unmatched_predicted) for r in res_list)
            tn = sum(1 for r in res_list if not r.is_positive and not r.predicted_issues)

            p = self._safe_divide(tp, tp + fp)
            r = self._safe_divide(tp, tp + fn)
            f1 = self._safe_divide(2 * p * r, p + r)

            metrics_map[key] = CategoryMetrics(
                name=key,
                total_cases=len(res_list),
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
                precision=round(p, 4),
                recall=round(r, 4),
                f1=round(f1, 4)
            )

        return metrics_map

    def _safe_divide(self, num: float, den: float) -> float:
        """Safe division returning 0.0 when denominator is zero."""
        if den == 0:
            return 0.0
        return num / den
