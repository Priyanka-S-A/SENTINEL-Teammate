"""
SENTINEL Phase 5: Evaluation and Benchmarking Package.
"""

from backend.evaluation.runner import evaluation_runner
from backend.evaluation.benchmark import benchmark_suite
from backend.evaluation.datasets import datasets
from backend.evaluation.metrics import summary_statistics

__all__ = ["evaluation_runner", "benchmark_suite", "datasets", "summary_statistics"]
