"""
Benchmark evaluation suite for batch-deobfuscator.
Standardized 28-corpus evaluation harness, metrics suite, and CLI runner.
"""

from .corpus_data import (
    CORPUS_SUITE,
    BenchmarkCorpus,
    get_corpus_suite,
    get_corpus_by_id,
    get_corpus_by_name,
)
from .metrics import (
    calculate_shannon_entropy,
    calculate_size_compression_ratio,
    calculate_caret_stripping_ratio,
    calculate_symbol_resolution_density,
    calculate_convergence_speed,
    calculate_readability_clarity_index,
    calculate_composite_score,
    calculate_all_metrics,
)
from .eval_corpus_runner import (
    BenchmarkResult,
    CorpusBenchmarkRunner,
    run_corpus_benchmark,
    format_text_table,
    format_markdown_table,
)

__all__ = [
    "CORPUS_SUITE",
    "BenchmarkCorpus",
    "get_corpus_suite",
    "get_corpus_by_id",
    "get_corpus_by_name",
    "calculate_shannon_entropy",
    "calculate_size_compression_ratio",
    "calculate_caret_stripping_ratio",
    "calculate_symbol_resolution_density",
    "calculate_convergence_speed",
    "calculate_readability_clarity_index",
    "calculate_composite_score",
    "calculate_all_metrics",
    "BenchmarkResult",
    "CorpusBenchmarkRunner",
    "run_corpus_benchmark",
    "format_text_table",
    "format_markdown_table",
]
