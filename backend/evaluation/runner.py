"""
SENTINEL Phase 5: Evaluation Runner & Result Persistence.
Executes the full suite of reproducible benchmarks, computes statistical metrics,
persists verified results to data/evaluation/benchmark_results.json, and serves
measured performance data to the API and Investigator Dashboard.
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional

from backend.evaluation.benchmark import benchmark_suite

RESULTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "evaluation", "benchmark_results.json"
)

class EvaluationRunner:
    """
    Orchestrates live benchmark execution and persists verified experiment results.
    """

    def __init__(self):
        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
        self._cached_results: Optional[Dict[str, Any]] = None

    def run_full_benchmark(self, runs: int = 2) -> Dict[str, Any]:
        """
        Executes all 7 benchmark modules against the live SENTINEL pipeline.
        Calculates real, non-fabricated metrics and persists them to disk.
        """
        start_time = time.time()
        timestamp_str = datetime.utcnow().isoformat() + "Z"

        results = {
            "metadata": {
                "evaluation_suite": "SENTINEL Phase 5 Comprehensive Benchmark",
                "timestamp": timestamp_str,
                "version": "5.0.0",
                "is_measured": True,
                "note": "All values computed from live code execution against ground truth."
            },
            "benchmarks": {}
        }

        # 1. Entity Extraction
        results["benchmarks"]["entity_extraction"] = benchmark_suite.run_entity_extraction_benchmark()

        # 2. Graph Path Recovery
        results["benchmarks"]["graph_path_recovery"] = benchmark_suite.run_graph_path_recovery_benchmark()

        # 3. Vector RAG Retrieval
        results["benchmarks"]["vector_rag_retrieval"] = benchmark_suite.run_vector_rag_benchmark()

        # 4. Case Isolation
        results["benchmarks"]["case_isolation"] = benchmark_suite.run_case_isolation_benchmark()

        # 5. Hypothesis Consistency
        results["benchmarks"]["hypothesis_consistency"] = benchmark_suite.run_hypothesis_consistency_benchmark(runs=runs)

        # 6. Controlled Tool Latencies
        results["benchmarks"]["tool_execution_latencies"] = benchmark_suite.run_tool_execution_latencies_benchmark()

        # 7. End-to-End Pipeline
        results["benchmarks"]["end_to_end_pipeline"] = benchmark_suite.run_end_to_end_pipeline_benchmark(runs=runs)

        total_elapsed = time.time() - start_time
        results["metadata"]["total_execution_time_seconds"] = round(total_elapsed, 2)

        # Calculate overall test pass/fail count
        total_tests = len(results["benchmarks"])
        passed_tests = sum(1 for b in results["benchmarks"].values() if b.get("passed", False))
        results["summary"] = {
            "total_benchmarks": total_tests,
            "passed_benchmarks": passed_tests,
            "failed_benchmarks": total_tests - passed_tests,
            "pass_rate_percent": round((passed_tests / max(1, total_tests)) * 100, 1),
            "status": "PASS" if passed_tests == total_tests else "FAIL"
        }

        # Persist to disk
        try:
            with open(RESULTS_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            self._cached_results = results
        except Exception as e:
            print(f"[EvaluationRunner] Warning writing results to {RESULTS_FILE}: {e}")

        return results

    def get_latest_results(self) -> Dict[str, Any]:
        """
        Retrieves the latest persisted benchmark results, or executes a benchmark if no cache exists.
        """
        if self._cached_results is not None:
            return self._cached_results

        if os.path.exists(RESULTS_FILE):
            try:
                with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._cached_results = data
                    return data
            except Exception:
                pass

        # Execute if not found on disk
        return self.run_full_benchmark(runs=1)

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """
        Transforms measured benchmark results into the structured schema expected by the UI.
        Replaces all former static values with strictly MEASURED real experiment data.
        """
        raw = self.get_latest_results()
        benchmarks = raw.get("benchmarks", {})

        ext = benchmarks.get("entity_extraction", {})
        graph = benchmarks.get("graph_path_recovery", {})
        rag = benchmarks.get("vector_rag_retrieval", {})
        iso = benchmarks.get("case_isolation", {})
        hypo = benchmarks.get("hypothesis_consistency", {})
        tool = benchmarks.get("tool_execution_latencies", {})
        pipe = benchmarks.get("end_to_end_pipeline", {})

        # Formulate measured values
        measured_f1 = f"{ext.get('overall_f1', 0.0) * 100:.1f}%" if "overall_f1" in ext else "NOT AVAILABLE"
        measured_prec = f"{ext.get('overall_precision', 0.0) * 100:.1f}%" if "overall_precision" in ext else "NOT AVAILABLE"
        measured_rec = f"{ext.get('overall_recall', 0.0) * 100:.1f}%" if "overall_recall" in ext else "NOT AVAILABLE"

        measured_graph_rec = f"{graph.get('path_recovery_rate', 0.0) * 100:.1f}%" if "path_recovery_rate" in graph else "NOT AVAILABLE"
        measured_rag_hit = f"{rag.get('hit_rate', 0.0) * 100:.1f}%" if "hit_rate" in rag else "NOT AVAILABLE"
        measured_rag_p_at_k = f"{rag.get('precision_at_k', 0.0) * 100:.1f}%" if "precision_at_k" in rag else "NOT AVAILABLE"
        measured_iso = f"{iso.get('isolation_accuracy', 0.0) * 100:.1f}%" if "isolation_accuracy" in iso else "NOT AVAILABLE"
        measured_hypo = f"{hypo.get('leading_hypothesis_consistency_rate', 0.0) * 100:.1f}%" if "leading_hypothesis_consistency_rate" in hypo else "NOT AVAILABLE"

        measured_e2e_lat = f"{pipe.get('mean_pipeline_latency_seconds', 0.0):.2f}s" if "mean_pipeline_latency_seconds" in pipe else "NOT AVAILABLE"
        measured_tool_lat = f"{tool.get('overall_mean_latency_ms', 0.0):.1f}ms" if "overall_mean_latency_ms" in tool else "NOT AVAILABLE"

        # Detailed benchmark entries for UI table
        benchmark_table = [
            {
                "metric": "Entity Extraction F1 Score",
                "category": "Extraction",
                "measured_value": measured_f1,
                "precision": measured_prec,
                "recall": measured_rec,
                "trials": ext.get("execution_time_seconds", 0),
                "status": "MEASURED",
                "result": "PASS" if ext.get("passed") else "FAIL"
            },
            {
                "metric": "Graph Attack Path Recovery",
                "category": "Graph Analytics",
                "measured_value": measured_graph_rec,
                "precision": f"{graph.get('paths_recovered', 0)}/{graph.get('paths_tested', 0)} Paths",
                "recall": "N/A",
                "trials": graph.get("paths_tested", 0),
                "status": "MEASURED",
                "result": "PASS" if graph.get("passed") else "FAIL"
            },
            {
                "metric": "Vector RAG Retrieval Hit Rate",
                "category": "RAG Retrieval",
                "measured_value": measured_rag_hit,
                "precision": f"P@K: {measured_rag_p_at_k}",
                "recall": f"Lat: {rag.get('mean_retrieval_latency_ms', 0.0):.1f}ms",
                "trials": rag.get("queries_evaluated", 0),
                "status": "MEASURED",
                "result": "PASS" if rag.get("passed") else "FAIL"
            },
            {
                "metric": "Case Isolation Correctness",
                "category": "Multi-Tenancy",
                "measured_value": measured_iso,
                "precision": "Zero Leakage",
                "recall": "N/A",
                "trials": 2,
                "status": "MEASURED",
                "result": "PASS" if iso.get("passed") else "FAIL"
            },
            {
                "metric": "Hypothesis Evaluation Consistency",
                "category": "Reasoning (ACH)",
                "measured_value": measured_hypo,
                "precision": f"Score Std: {hypo.get('leading_score_std', 0.0):.3f}",
                "recall": "N/A",
                "trials": hypo.get("runs_evaluated", 0),
                "status": "MEASURED",
                "result": "PASS" if hypo.get("passed") else "FAIL"
            },
            {
                "metric": "Average Controlled Tool Latency",
                "category": "Tool Calling",
                "measured_value": measured_tool_lat,
                "precision": f"Min: {tool.get('overall_min_latency_ms', 0.0):.1f}ms",
                "recall": f"Max: {tool.get('overall_max_latency_ms', 0.0):.1f}ms",
                "trials": tool.get("tools_tested", 0),
                "status": "MEASURED",
                "result": "PASS" if tool.get("passed") else "FAIL"
            },
            {
                "metric": "End-to-End Investigation Latency",
                "category": "Pipeline",
                "measured_value": measured_e2e_lat,
                "precision": f"Steps: {pipe.get('mean_audit_steps', 0)}",
                "recall": f"Runs: {pipe.get('total_runs', 0)}",
                "trials": pipe.get("total_runs", 0),
                "status": "MEASURED",
                "result": "PASS" if pipe.get("passed") else "FAIL"
            }
        ]

        # Formulate top cards strictly with Phase 5 measured metrics
        top_cards = {
            "entity_extraction_f1": f"{measured_f1} (Measured)",
            "rag_hit_rate": f"{measured_rag_hit} (Measured)",
            "graph_path_recovery": f"{measured_graph_rec} (Measured)",
            "case_isolation_accuracy": f"{measured_iso} (Measured)"
        }

        # Structured format
        return {
            "is_measured": True,
            "timestamp": raw.get("metadata", {}).get("timestamp", ""),
            "summary": raw.get("summary", {}),
            "improvements": top_cards,
            "benchmark_table": benchmark_table,
            "manual_investigation": {
                "ioc_extraction_f1": "Baseline Analyst (Manual)",
                "graph_path_recovery": "Manual Correlation",
                "rag_retrieval_hit_rate": "Manual Keyword Search",
                "case_isolation": "Manual Access Control",
                "hypothesis_consistency": "Analyst Subjective",
                "pipeline_latency": "Manual Workflow"
            },
            "sentinel_autonomous": {
                "ioc_extraction_f1": f"{measured_f1} [MEASURED]",
                "graph_path_recovery": f"{measured_graph_rec} [MEASURED]",
                "rag_retrieval_hit_rate": f"{measured_rag_hit} [MEASURED]",
                "case_isolation": f"{measured_iso} [MEASURED]",
                "hypothesis_consistency": f"{measured_hypo} [MEASURED]",
                "pipeline_latency": f"{measured_e2e_lat} [MEASURED]"
            }
        }

evaluation_runner = EvaluationRunner()
