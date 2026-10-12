#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
28-Corpus Batch Deobfuscation Benchmark Evaluation Harness.
Standardized scoring and telemetry evaluation suite across 28 real-world
batch obfuscation toolchains, malware stagers, and academic archetypes.
"""

import sys
import os
import time
import json
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add project root and src to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
src_path = str(REPO_ROOT / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from deobfuscator.core import BatchDeobfuscator
from benchmarks.corpus_data import (
    CORPUS_SUITE,
    BenchmarkCorpus,
    get_corpus_suite,
    get_corpus_by_id,
    get_corpus_by_name,
)
from benchmarks.metrics import (
    calculate_shannon_entropy,
    calculate_size_compression_ratio,
    calculate_caret_stripping_ratio,
    calculate_symbol_resolution_density,
    calculate_convergence_speed,
    calculate_readability_clarity_index,
    calculate_composite_score,
    calculate_all_metrics,
)


class BenchmarkResult:
    """Detailed telemetry and scoring record for a single corpus run."""
    def __init__(
        self,
        corpus: BenchmarkCorpus,
        clean_text: str,
        meta: Dict[str, Any],
        metrics: Dict[str, Any],
        status: str,
    ):
        self.corpus = corpus
        self.clean_text = clean_text
        self.meta = meta
        self.metrics = metrics
        self.tokens_found = metrics["tokens_found"]
        self.tokens_missing = metrics["tokens_missing"]
        self.entropy_before = metrics["entropy_before"]
        self.entropy_after = metrics["entropy_after"]
        self.entropy_delta = metrics["entropy_delta"]
        self.compression_ratio = metrics["compression_ratio"]
        self.caret_stripping_ratio = metrics["caret_stripping_ratio"]
        self.symbol_density = metrics["symbol_density"]
        self.clarity_index = metrics["clarity_index"]
        self.score = metrics["composite_score"]
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.corpus.corpus_id,
            "name": self.corpus.name,
            "archetype": self.corpus.archetype,
            "difficulty": self.corpus.difficulty,
            "detection_tags": self.corpus.detection_tags,
            "status": self.status,
            "score": self.score,
            "passes": self.meta.get("passes_executed", 0),
            "converged": self.meta.get("converged", False),
            "symbols_resolved": self.meta.get("symbols_resolved_count", 0),
            "latency_ms": self.meta.get("elapsed_ms", 0.0),
            "entropy_before": self.entropy_before,
            "entropy_after": self.entropy_after,
            "entropy_delta": self.entropy_delta,
            "compression_ratio": self.compression_ratio,
            "caret_stripping_ratio": self.caret_stripping_ratio,
            "symbol_density": self.symbol_density,
            "clarity_index": self.clarity_index,
            "tokens_found": self.tokens_found,
            "tokens_missing": self.tokens_missing,
            "ground_truth": self.corpus.ground_truth,
        }


class CorpusBenchmarkRunner:
    """Benchmark evaluation runner across the 28-corpus test suite."""

    def __init__(self, max_passes: int = 15):
        self.max_passes = max_passes
        self.engine = BatchDeobfuscator(max_passes=max_passes)

    def evaluate_single(self, corpus: BenchmarkCorpus) -> BenchmarkResult:
        """Run deobfuscation and compute telemetry metrics for one corpus."""
        # Execute deobfuscation
        engine = BatchDeobfuscator(max_passes=self.max_passes)
        clean_text, meta = engine.deobfuscate(corpus.script)

        # Calculate standardized telemetry metrics
        metrics = calculate_all_metrics(
            raw_text=corpus.script,
            clean_text=clean_text,
            meta=meta,
            expected_tokens=corpus.expected_tokens,
        )

        # PASS condition: 100% token accuracy and convergence reached
        status = "PASS" if (len(metrics["tokens_missing"]) == 0 and meta.get("converged", False)) else "FAIL"

        return BenchmarkResult(
            corpus=corpus,
            clean_text=clean_text,
            meta=meta,
            metrics=metrics,
            status=status,
        )

    def load_external_corpora(self, corpus_dir: str) -> List[BenchmarkCorpus]:
        """Load additional corpus items from a directory of .bat/.cmd or .json files."""
        dir_path = Path(corpus_dir)
        if not dir_path.is_dir():
            raise FileNotFoundError(f"Corpus directory not found: {corpus_dir}")

        external: List[BenchmarkCorpus] = []
        next_id = len(CORPUS_SUITE) + 1

        for item in sorted(dir_path.iterdir()):
            if item.is_file() and item.suffix.lower() in [".bat", ".cmd"]:
                content = item.read_text(encoding="utf-8", errors="replace")
                external.append(
                    BenchmarkCorpus(
                        corpus_id=next_id,
                        name=item.stem,
                        archetype="External Directory Sample",
                        script=content,
                        ground_truth=content,
                        expected_tokens=[],
                        difficulty="Custom",
                        detection_tags=["external-sample"],
                        description=f"Loaded from external file {item.name}",
                        reference_path=str(item),
                    )
                )
                next_id += 1
            elif item.is_file() and item.suffix.lower() == ".json":
                try:
                    data = json.loads(item.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        for entry in data:
                            external.append(
                                BenchmarkCorpus(
                                    corpus_id=entry.get("corpus_id", next_id),
                                    name=entry.get("name", item.stem),
                                    archetype=entry.get("archetype", "Custom JSON Archetype"),
                                    script=entry.get("script", ""),
                                    ground_truth=entry.get("ground_truth", ""),
                                    expected_tokens=entry.get("expected_tokens", []),
                                    difficulty=entry.get("difficulty", "Custom"),
                                    detection_tags=entry.get("detection_tags", []),
                                    description=entry.get("description", ""),
                                    reference_path=str(item),
                                )
                            )
                            next_id += 1
                except Exception:
                    pass

        return external

    def run_suite(
        self,
        corpus_filter: Optional[str] = None,
        corpus_dir: Optional[str] = None,
        min_score: float = 80.0,
    ) -> Dict[str, Any]:
        """Execute evaluation across all corpora or a filtered subset."""
        start_time = time.perf_counter()
        results: List[BenchmarkResult] = []

        suite = list(CORPUS_SUITE)
        if corpus_dir:
            suite.extend(self.load_external_corpora(corpus_dir))

        if corpus_filter:
            filt = corpus_filter.strip().lower()
            if filt.isdigit():
                matched = [c for c in suite if c.corpus_id == int(filt)]
            else:
                matched = [c for c in suite if filt in c.name.lower()]
            if not matched:
                raise ValueError(f"No corpus matched filter: {corpus_filter}")
            suite = matched

        for corpus in suite:
            res = self.evaluate_single(corpus)
            results.append(res)

        total_elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        passed_count = sum(1 for r in results if r.status == "PASS")
        failed_count = len(results) - passed_count
        pass_rate = (passed_count / len(results) * 100.0) if results else 0.0

        scores = [r.score for r in results]
        mean_score = sum(scores) / len(scores) if scores else 0.0
        mean_latency = sum(r.meta.get("elapsed_ms", 0.0) for r in results) / len(results) if results else 0.0
        total_symbols = sum(r.meta.get("symbols_resolved_count", 0) for r in results)
        mean_passes = sum(r.meta.get("passes_executed", 0) for r in results) / len(results) if results else 0.0
        mean_clarity = sum(r.clarity_index for r in results) / len(results) if results else 0.0
        mean_compression = sum(r.compression_ratio for r in results) / len(results) if results else 0.0

        # Grade calculation
        if mean_score >= 95.0 and pass_rate == 100.0:
            grade = "A+ (Excellent)"
        elif mean_score >= 90.0:
            grade = "A (Superior)"
        elif mean_score >= 80.0:
            grade = "B (Good)"
        elif mean_score >= 70.0:
            grade = "C (Fair)"
        else:
            grade = "F (Failing)"

        verdict_passed = (failed_count == 0 and mean_score >= min_score)

        summary = {
            "total_corpora": len(results),
            "passed": passed_count,
            "failed": failed_count,
            "pass_rate_pct": round(pass_rate, 1),
            "mean_score": round(mean_score, 1),
            "min_score_threshold": round(min_score, 1),
            "grade": grade,
            "verdict_passed": verdict_passed,
            "mean_latency_ms": round(mean_latency, 3),
            "total_latency_ms": round(total_elapsed_ms, 2),
            "total_symbols_resolved": total_symbols,
            "mean_passes": round(mean_passes, 2),
            "mean_clarity_index": round(mean_clarity, 1),
            "mean_compression_ratio": round(mean_compression, 1),
            "results": [r.to_dict() for r in results],
        }

        return summary


def format_text_table(summary: Dict[str, Any]) -> str:
    """Format benchmark evaluation results as a clean ASCII report table."""
    lines = []
    lines.append("=" * 96)
    lines.append("        BATCH DEOBFUSCATOR 28-CORPUS BENCHMARK EVALUATION HARNESS")
    lines.append("=" * 96)
    lines.append(f"{'ID':<4} {'Corpus Name':<30} {'Archetype':<24} {'Pass':<5} {'Latency':<9} {'Clarity':<8} {'Score':<6} {'Status':<6}")
    lines.append("-" * 96)

    for r in summary["results"]:
        lines.append(
            f"{r['id']:02d}   "
            f"{r['name']:<30} "
            f"{r['archetype'][:22]:<24} "
            f"{r['passes']:<5} "
            f"{r['latency_ms']:>6.2f}ms  "
            f"{r['clarity_index']:>6.1f}  "
            f"{r['score']:>5.1f}  "
            f"{r['status']:<6}"
        )

    lines.append("=" * 96)
    lines.append("AGGREGATE BENCHMARK METRICS SUMMARY")
    lines.append("-" * 96)
    lines.append(f"  Total Corpora Evaluated : {summary['total_corpora']} / 28")
    lines.append(f"  Passed                  : {summary['passed']} ({summary['pass_rate_pct']}%)")
    lines.append(f"  Failed                  : {summary['failed']}")
    lines.append(f"  Overall Mean Score      : {summary['mean_score']} / 100.0  [Grade: {summary['grade']}]")
    lines.append(f"  Min Score Threshold     : {summary['min_score_threshold']}")
    lines.append(f"  Mean Convergence Passes : {summary['mean_passes']} passes")
    lines.append(f"  Total Symbols Resolved  : {summary['total_symbols_resolved']}")
    lines.append(f"  Mean Clarity Index      : {summary['mean_clarity_index']} / 100.0")
    lines.append(f"  Mean Compression Ratio  : {summary['mean_compression_ratio']}%")
    lines.append(f"  Mean Execution Latency  : {summary['mean_latency_ms']} ms / corpus")
    lines.append(f"  Total Wallclock Time    : {summary['total_latency_ms']} ms")
    lines.append("=" * 96)
    if summary["verdict_passed"]:
        lines.append(f">>> VERDICT: ALL BENCHMARK CORPORA PASSED ({summary['passed']}/{summary['total_corpora']}) - ZERO REGRESSION <<<")
    else:
        lines.append(f">>> VERDICT: REGRESSION DETECTED (Failed: {summary['failed']}, Mean Score: {summary['mean_score']}) <<<")
    lines.append("=" * 96)

    return "\n".join(lines)


def format_markdown_table(summary: Dict[str, Any]) -> str:
    """Format benchmark evaluation results as a GitHub-Flavored Markdown report."""
    lines = []
    lines.append("# Batch Deobfuscator 28-Corpus Benchmark Evaluation Report")
    lines.append("")
    lines.append(f"**Verdict:** {'PASSED (Zero Regression)' if summary['verdict_passed'] else 'FAILED'}")
    lines.append(f"**Mean Score:** `{summary['mean_score']} / 100.0` ({summary['grade']}) | **Pass Rate:** `{summary['pass_rate_pct']}%` ({summary['passed']}/{summary['total_corpora']})")
    lines.append("")
    lines.append("## Benchmark Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Total Corpora** | `{summary['total_corpora']}` |")
    lines.append(f"| **Passed** | `{summary['passed']}` |")
    lines.append(f"| **Failed** | `{summary['failed']}` |")
    lines.append(f"| **Mean Score** | `{summary['mean_score']}` / 100.0 |")
    lines.append(f"| **Grade** | `{summary['grade']}` |")
    lines.append(f"| **Mean Passes** | `{summary['mean_passes']}` |")
    lines.append(f"| **Symbols Resolved** | `{summary['total_symbols_resolved']}` |")
    lines.append(f"| **Mean Clarity Index** | `{summary['mean_clarity_index']}` / 100.0 |")
    lines.append(f"| **Mean Compression** | `{summary['mean_compression_ratio']}%` |")
    lines.append(f"| **Mean Latency** | `{summary['mean_latency_ms']} ms` |")
    lines.append(f"| **Total Elapsed Time** | `{summary['total_latency_ms']} ms` |")
    lines.append("")
    lines.append("## Detailed Corpus Results")
    lines.append("")
    lines.append("| ID | Corpus Name | Archetype | Difficulty | Passes | Latency | Clarity | Score | Status |")
    lines.append("|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|")

    for r in summary["results"]:
        status_icon = "PASS" if r["status"] == "PASS" else "FAIL"
        lines.append(
            f"| `{r['id']:02d}` | **{r['name']}** | {r['archetype']} | {r['difficulty']} | "
            f"`{r['passes']}` | `{r['latency_ms']:.2f}ms` | `{r['clarity_index']:.1f}` | `{r['score']:.1f}` | **{status_icon}** |"
        )

    return "\n".join(lines)


def run_corpus_benchmark(
    corpus_filter: Optional[str] = None,
    corpus_dir: Optional[str] = None,
    min_score: float = 80.0,
) -> Dict[str, Any]:
    """Public helper function to execute benchmark suite and return summary dict."""
    runner = CorpusBenchmarkRunner()
    return runner.run_suite(corpus_filter=corpus_filter, corpus_dir=corpus_dir, min_score=min_score)


def main(args: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="28-Corpus Batch Deobfuscator Benchmark Evaluation Harness"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output report format (default: text)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional file path to write benchmark evaluation report",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=80.0,
        help="Minimum acceptable composite score threshold (default: 80.0)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose deobfuscated script snippets and token matches",
    )
    parser.add_argument(
        "--corpus-dir",
        type=str,
        default=None,
        help="Optional directory containing additional custom .bat/.cmd/.json corpora",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=None,
        help="Filter evaluation to a specific corpus by ID or name",
    )

    opts = parser.parse_args(args)

    runner = CorpusBenchmarkRunner()
    summary = runner.run_suite(
        corpus_filter=opts.corpus,
        corpus_dir=opts.corpus_dir,
        min_score=opts.min_score,
    )

    if opts.format == "json":
        output_str = json.dumps(summary, indent=2, ensure_ascii=False)
    elif opts.format == "markdown":
        output_str = format_markdown_table(summary)
    else:
        output_str = format_text_table(summary)

    if opts.verbose:
        for r in summary["results"]:
            print(f"[{r['id']:02d}] {r['name']} -> Found: {r['tokens_found']}, Missing: {r['tokens_missing']}")

    print(output_str)

    if opts.output:
        out_p = Path(opts.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(output_str, encoding="utf-8")
        print(f"\n[+] Benchmark report saved to: {opts.output}")

    # Exit code: 0 on pass, 1 on regression / failure
    return 0 if summary["verdict_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
