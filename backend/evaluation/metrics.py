"""
SENTINEL Phase 5: Evaluation Metrics Calculation Engine.
Provides rigorous mathematical calculations for precision, recall, F1, Precision@K,
Recall@K, Hit Rate, Citation Coverage, and descriptive statistics (mean, min, max, std).
All calculations are deterministic and reproducible.
"""

import math
from typing import List, Set, Any, Dict, Optional

def precision(retrieved: Set[Any], ground_truth: Set[Any]) -> float:
    """
    Calculates precision = |retrieved ∩ ground_truth| / |retrieved|
    Returns 1.0 if retrieved is empty and ground_truth is empty, else 0.0 if retrieved is empty.
    """
    if not retrieved:
        return 1.0 if not ground_truth else 0.0
    true_positives = len(retrieved.intersection(ground_truth))
    return round(true_positives / len(retrieved), 4)

def recall(retrieved: Set[Any], ground_truth: Set[Any]) -> float:
    """
    Calculates recall = |retrieved ∩ ground_truth| / |ground_truth|
    Returns 1.0 if ground_truth is empty, else 0.0 if retrieved is empty.
    """
    if not ground_truth:
        return 1.0
    true_positives = len(retrieved.intersection(ground_truth))
    return round(true_positives / len(ground_truth), 4)

def f1_score(prec: float, rec: float) -> float:
    """
    Calculates Harmonic Mean F1 = 2 * (precision * recall) / (precision + recall)
    """
    if (prec + rec) == 0.0:
        return 0.0
    return round(2 * (prec * rec) / (prec + rec), 4)

def precision_at_k(ranked_retrieved: List[Any], ground_truth: Set[Any], k: int) -> float:
    """
    Calculates Precision@K = |ranked_retrieved[:k] ∩ ground_truth| / k
    """
    if k <= 0:
        return 0.0
    top_k = ranked_retrieved[:k]
    if not top_k:
        return 0.0
    hits = len(set(top_k).intersection(ground_truth))
    return round(hits / len(top_k), 4)

def recall_at_k(ranked_retrieved: List[Any], ground_truth: Set[Any], k: int) -> float:
    """
    Calculates Recall@K = |ranked_retrieved[:k] ∩ ground_truth| / |ground_truth|
    """
    if not ground_truth:
        return 1.0
    if k <= 0:
        return 0.0
    top_k = ranked_retrieved[:k]
    hits = len(set(top_k).intersection(ground_truth))
    return round(hits / len(ground_truth), 4)

def hit_rate(ranked_retrieved: List[Any], ground_truth: Set[Any], k: Optional[int] = None) -> float:
    """
    Returns 1.0 if at least one item in ranked_retrieved[:k] is in ground_truth, else 0.0.
    """
    items = ranked_retrieved if k is None else ranked_retrieved[:k]
    if not items or not ground_truth:
        return 0.0
    return 1.0 if any(item in ground_truth for item in items) else 0.0

def summary_statistics(values: List[float]) -> Dict[str, float]:
    """
    Calculates mean, min, max, sample standard deviation, and count for a list of floats.
    """
    if not values:
        return {"count": 0, "mean": 0.0, "min": 0.0, "max": 0.0, "std": 0.0}

    n = len(values)
    mean_val = sum(values) / n
    min_val = min(values)
    max_val = max(values)

    if n > 1:
        variance = sum((x - mean_val) ** 2 for x in values) / (n - 1)
        std_val = math.sqrt(variance)
    else:
        std_val = 0.0

    return {
        "count": n,
        "mean": round(mean_val, 4),
        "min": round(min_val, 4),
        "max": round(max_val, 4),
        "std": round(std_val, 4)
    }
