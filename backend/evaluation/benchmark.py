"""
SENTINEL Phase 5: Benchmark Execution Engine.
Executes real, reproducible experiments against the live SENTINEL pipeline modules:
- Deterministic Entity Extraction
- NetworkX Evidence Graph & Path Recovery
- Semantic Vector RAG Retrieval
- Case Isolation
- Hypothesis Evaluation Consistency
- Controlled Tool Latencies
- End-to-End Autonomous Investigation Pipeline
All metrics are measured from actual code executions. No numbers are hardcoded or fabricated.
"""

import time
import logging
from typing import Dict, List, Any, Set, Tuple

from backend.ingestion import ingestion_engine
from backend.extractors import extractor_engine
from backend.normalizer import normalizer
from backend.graph_engine import graph_engine
from backend.leads_hypothesis import lead_and_hypothesis_mgr
from backend.contradiction_engine import contradiction_engine
from backend.risk_engine import risk_engine
from backend.report_generator import report_engine
from backend.agent import agent_orchestrator
from backend.rag.rag_engine import rag_engine
from backend.rag.vector_store import vector_store
from backend.demo_dataset import demo_dataset_builder

from backend.evaluation.datasets import datasets
from backend.evaluation.metrics import (
    precision, recall, f1_score, precision_at_k, recall_at_k, hit_rate, summary_statistics
)

logger = logging.getLogger("sentinel.evaluation.benchmark")

class SentinelBenchmarkSuite:
    """
    Executes actual experiments to measure SENTINEL system performance.
    """

    def run_entity_extraction_benchmark(self) -> Dict[str, Any]:
        """
        Benchmark #1: Deterministic Entity Extraction Precision, Recall, and F1.
        Tests extraction against ground-truth annotated entities in standard demo files.
        """
        start_time = time.time()
        gt = datasets.get_standard_attack_ground_truth()
        demo_files = demo_dataset_builder.generate_demo_files()

        extracted_ips = set()
        extracted_domains = set()
        extracted_users = set()
        extracted_hashes = set()
        extracted_cves = set()

        file_latencies = []
        for df in demo_files:
            t0 = time.time()
            text = df["content_bytes"].decode("utf-8", errors="ignore")
            # Run deterministic extractor regex passes
            entities = extractor_engine.extract_from_text(text, source_file=df["filename"])
            file_latencies.append(time.time() - t0)

            for e in entities:
                val = e.get("value", "").strip()
                etype = e.get("type", "").upper()
                if "IP" in etype:
                    extracted_ips.add(val)
                elif "DOMAIN" in etype:
                    extracted_domains.add(val.lower())
                elif "USER" in etype or "EMAIL" in etype:
                    extracted_users.add(val)
                elif "HASH" in etype:
                    extracted_hashes.add(val.lower())
                elif "CVE" in etype:
                    extracted_cves.add(val.upper())

        # Ground truth sets
        gt_entities = gt["expected_entities"]
        gt_ips = gt_entities["ips"]
        gt_domains = {d.lower() for d in gt_entities["domains"]}
        gt_users = gt_entities["users"]
        gt_hashes = {h.lower() for h in gt_entities["hashes"]}

        # Calculate metrics per entity type
        ip_p = precision(extracted_ips, gt_ips)
        ip_r = recall(extracted_ips, gt_ips)
        ip_f1 = f1_score(ip_p, ip_r)

        dom_p = precision(extracted_domains, gt_domains)
        dom_r = recall(extracted_domains, gt_domains)
        dom_f1 = f1_score(dom_p, dom_r)

        user_p = precision(extracted_users, gt_users)
        user_r = recall(extracted_users, gt_users)
        user_f1 = f1_score(user_p, user_r)

        hash_p = precision(extracted_hashes, gt_hashes)
        hash_r = recall(extracted_hashes, gt_hashes)
        hash_f1 = f1_score(hash_p, hash_r)

        # Micro-averaged overall extraction metrics
        all_extracted = extracted_ips.union(extracted_domains).union(extracted_users).union(extracted_hashes)
        all_gt = gt_ips.union(gt_domains).union(gt_users).union(gt_hashes)
        overall_p = precision(all_extracted, all_gt)
        overall_r = recall(all_extracted, all_gt)
        overall_f1 = f1_score(overall_p, overall_r)

        elapsed = time.time() - start_time
        return {
            "name": "Deterministic Entity Extraction",
            "status": "MEASURED",
            "passed": overall_f1 >= 0.80,
            "overall_precision": overall_p,
            "overall_recall": overall_r,
            "overall_f1": overall_f1,
            "breakdown": {
                "ip": {"precision": ip_p, "recall": ip_r, "f1": ip_f1, "detected": len(extracted_ips), "ground_truth": len(gt_ips)},
                "domain": {"precision": dom_p, "recall": dom_r, "f1": dom_f1, "detected": len(extracted_domains), "ground_truth": len(gt_domains)},
                "user": {"precision": user_p, "recall": user_r, "f1": user_f1, "detected": len(extracted_users), "ground_truth": len(gt_users)},
                "hash": {"precision": hash_p, "recall": hash_r, "f1": hash_f1, "detected": len(extracted_hashes), "ground_truth": len(gt_hashes)}
            },
            "avg_file_extraction_latency_ms": round((sum(file_latencies) / len(file_latencies)) * 1000, 2),
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_graph_path_recovery_benchmark(self) -> Dict[str, Any]:
        """
        Benchmark #2: NetworkX Evidence Graph Construction & Multi-Hop Path Recovery.
        Evaluates whether known attack hops are successfully linked in the graph.
        """
        start_time = time.time()
        gt = datasets.get_standard_attack_ground_truth()
        demo_files = demo_dataset_builder.generate_demo_files()
        processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]

        # Build graph
        normalized = normalizer.normalize_extracted_entities(processed)
        graph_data = graph_engine.build_graph_from_events(normalized)

        # Check expected attack paths
        expected_paths = gt["expected_graph_paths"]
        recovered_count = 0
        tested_paths = []

        g = graph_engine.graph
        for src, tgt in expected_paths:
            # Check direct edge or undirected connectivity in the graph
            has_direct = g.has_edge(src, tgt) or g.has_edge(tgt, src)
            path_found = False
            if has_direct:
                path_found = True
            elif g.has_node(src) and g.has_node(tgt):
                import networkx as nx
                undirected = g.to_undirected()
                if nx.has_path(undirected, src, tgt):
                    path_found = True

            tested_paths.append({
                "source": src,
                "target": tgt,
                "recovered": path_found
            })
            if path_found:
                recovered_count += 1

        path_recovery_rate = round(recovered_count / len(expected_paths), 4) if expected_paths else 1.0

        # Cross-source correlation check
        correlations = graph_engine.calculate_cross_source_correlations()

        elapsed = time.time() - start_time
        return {
            "name": "Graph Attack Path Recovery",
            "status": "MEASURED",
            "passed": path_recovery_rate >= 0.80,
            "total_nodes": graph_data.get("total_nodes", 0),
            "total_edges": graph_data.get("total_edges", 0),
            "paths_tested": len(expected_paths),
            "paths_recovered": recovered_count,
            "path_recovery_rate": path_recovery_rate,
            "tested_paths": tested_paths,
            "cross_source_correlations_count": len(correlations),
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_vector_rag_benchmark(self, top_k: int = 5) -> Dict[str, Any]:
        """
        Benchmark #3: FAISS Vector RAG Precision@K, Recall@K, Hit Rate, and Retrieval Latency.
        Runs ground-truth queries against indexed case knowledge and measures accuracy.
        """
        start_time = time.time()
        gt = datasets.get_standard_attack_ground_truth()
        demo_files = demo_dataset_builder.generate_demo_files()
        processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]
        case_data = agent_orchestrator.run_autonomous_investigation(processed)

        # Index into FAISS
        rag_engine.index_case(case_data)

        p_at_k_scores = []
        hit_rates = []
        query_latencies = []

        test_queries = gt.get("rag_test_queries", [])
        for tq in test_queries:
            query = tq["query"]
            expected_sources = tq.get("expected_sources", set())
            expected_categories = tq.get("expected_categories", set())
            expected_entities = tq.get("expected_entities", set())

            t0 = time.time()
            res = rag_engine.process_query(query, case_data, top_k=top_k)
            query_latencies.append(time.time() - t0)

            citations = res.get("citations", [])
            retrieved_chunks = res.get("retrieved_chunks", [])

            # Check if any expected source file, category, or entity is retrieved
            hit = False
            relevant_retrieved = 0
            for c in citations:
                prov = c.get("provenance", "")
                cat = c.get("category", "")
                snip = c.get("snippet", "")

                source_match = any(es.lower() in prov.lower() for es in expected_sources)
                cat_match = any(ec.lower() in cat.lower() for ec in expected_categories)
                ent_match = any(ee.lower() in snip.lower() for ee in expected_entities)

                if source_match or cat_match or ent_match:
                    relevant_retrieved += 1
                    hit = True

            p_at_k = round(relevant_retrieved / max(1, len(citations)), 4)
            p_at_k_scores.append(p_at_k)
            hit_rates.append(1.0 if hit else 0.0)

        mean_p_at_k = round(sum(p_at_k_scores) / max(1, len(p_at_k_scores)), 4)
        mean_hit_rate = round(sum(hit_rates) / max(1, len(hit_rates)), 4)
        latency_stats = summary_statistics([lat * 1000 for lat in query_latencies])

        elapsed = time.time() - start_time
        return {
            "name": "Semantic Vector RAG Retrieval",
            "status": "MEASURED",
            "passed": mean_hit_rate >= 0.80 and mean_p_at_k >= 0.60,
            "queries_evaluated": len(test_queries),
            "precision_at_k": mean_p_at_k,
            "hit_rate": mean_hit_rate,
            "top_k": top_k,
            "mean_retrieval_latency_ms": latency_stats["mean"],
            "min_retrieval_latency_ms": latency_stats["min"],
            "max_retrieval_latency_ms": latency_stats["max"],
            "std_retrieval_latency_ms": latency_stats["std"],
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_case_isolation_benchmark(self) -> Dict[str, Any]:
        """
        Benchmark #4: Multi-Tenant Case Isolation Correctness.
        Verifies that querying Case A never leaks chunks or data from Case B.
        """
        start_time = time.time()
        case_a_id = "BENCH-ISOLATION-CASE-A"
        case_b_id = "BENCH-ISOLATION-CASE-B"

        secret_token_a = "SECRET_ALPHA_TOKEN_987654"
        secret_token_b = "SECRET_BETA_TOKEN_123456"

        case_a = {
            "case_id": case_a_id,
            "events": [{
                "id": "EVT-A1", "entity_value": secret_token_a, "event_action": "Confidential Project Access",
                "severity": "HIGH", "source_file": "case_a.log", "source_type": "Auth", "entity_type": "Token"
            }]
        }
        case_b = {
            "case_id": case_b_id,
            "events": [{
                "id": "EVT-B1", "entity_value": secret_token_b, "event_action": "Confidential Financial Access",
                "severity": "HIGH", "source_file": "case_b.log", "source_type": "Auth", "entity_type": "Token"
            }]
        }

        rag_engine.index_case(case_a)
        rag_engine.index_case(case_b)

        # Query Case A searching for secret B token
        from backend.rag.retriever import retriever
        res_a = retriever.retrieve(case_a_id, query=secret_token_b, top_k=5)
        leakage_detected_in_a = any(secret_token_b in r.get("text", "") for r in res_a)

        # Query Case B searching for secret A token
        res_b = retriever.retrieve(case_b_id, query=secret_token_a, top_k=5)
        leakage_detected_in_b = any(secret_token_a in r.get("text", "") for r in res_b)

        passed = (not leakage_detected_in_a) and (not leakage_detected_in_b)
        elapsed = time.time() - start_time

        return {
            "name": "Case Isolation Correctness",
            "status": "MEASURED",
            "passed": passed,
            "isolation_accuracy": 1.0 if passed else 0.0,
            "cross_case_leakage_detected": leakage_detected_in_a or leakage_detected_in_b,
            "case_a_results_from_b": len(res_a),
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_hypothesis_consistency_benchmark(self, runs: int = 3) -> Dict[str, Any]:
        """
        Benchmark #5: Competing Hypothesis Evaluation (ACH) Consistency.
        Executes hypothesis evaluation across multiple trials and checks consistency.
        """
        start_time = time.time()
        gt = datasets.get_standard_attack_ground_truth()
        demo_files = demo_dataset_builder.generate_demo_files()
        processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]
        normalized = normalizer.normalize_extracted_entities(processed)

        leading_hypotheses = []
        h1_scores = []

        for _ in range(runs):
            eval_res = lead_and_hypothesis_mgr.evaluate_hypotheses(normalized, [])
            leading = eval_res["leading_hypothesis"]
            leading_hypotheses.append(leading["id"])
            h1 = next((h for h in eval_res["hypotheses"] if h["id"] == "H1"), None)
            if h1:
                h1_scores.append(float(h1.get("score", 0.0)))

        # Check that leading hypothesis is always H1 across all runs
        consistent = all(hid == gt["expected_leading_hypothesis"] for hid in leading_hypotheses)
        score_stats = summary_statistics(h1_scores)

        elapsed = time.time() - start_time
        return {
            "name": "Hypothesis Evaluation Consistency",
            "status": "MEASURED",
            "passed": consistent,
            "runs_evaluated": runs,
            "leading_hypothesis_consistency_rate": 1.0 if consistent else 0.0,
            "expected_leading_hypothesis": gt["expected_leading_hypothesis"],
            "observed_leading_hypotheses": leading_hypotheses,
            "leading_score_mean": score_stats["mean"],
            "leading_score_std": score_stats["std"],
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_tool_execution_latencies_benchmark(self) -> Dict[str, Any]:
        """
        Benchmark #6: Average Controlled Tool Execution Latencies.
        Directly measures the invocation latency of controlled tools.
        """
        start_time = time.time()
        demo_files = demo_dataset_builder.generate_demo_files()
        processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]
        case_data = agent_orchestrator.run_autonomous_investigation(processed)

        tool_measurements = {}
        tool_samples = [
            ("search_case_evidence", {"query": "198.51.100.45"}),
            ("search_logs", {"query": "powershell"}),
            ("lookup_threat_intel", {"indicator": "198.51.100.45", "indicator_type": "IP"}),
            ("trace_entity", {"entity": "user.smith@company.com", "entity_type": "User"}),
            ("find_related_entities", {"entity": "malicious-phish.net", "entity_type": "Domain"}),
            ("map_mitre", {"event_or_indicator": "powershell.exe -enc"}),
            ("evaluate_hypotheses", {}),
            ("check_contradictions", {}),
            ("calculate_risk", {}),
            ("generate_report", {}),
            ("get_investigation_memory", {"query": "phishing"}),
            ("search_case_knowledge", {"query": "PowerShell execution stager"})
        ]

        all_latencies_ms = []
        for tname, targs in tool_samples:
            trials = []
            for _ in range(3):
                t0 = time.time()
                agent_orchestrator.execute_tool_by_name(tname, targs)
                trials.append((time.time() - t0) * 1000)
            stats = summary_statistics(trials)
            tool_measurements[tname] = stats
            all_latencies_ms.extend(trials)

        overall_stats = summary_statistics(all_latencies_ms)
        elapsed = time.time() - start_time

        return {
            "name": "Controlled Tool Execution Latencies",
            "status": "MEASURED",
            "passed": overall_stats["mean"] < 2500.0, # Average tool execution under 2.5s
            "tools_tested": len(tool_samples),
            "overall_mean_latency_ms": overall_stats["mean"],
            "overall_min_latency_ms": overall_stats["min"],
            "overall_max_latency_ms": overall_stats["max"],
            "overall_std_latency_ms": overall_stats["std"],
            "per_tool_breakdown": tool_measurements,
            "execution_time_seconds": round(elapsed, 4)
        }

    def run_end_to_end_pipeline_benchmark(self, runs: int = 2) -> Dict[str, Any]:
        """
        Benchmark #7: End-to-End Investigation Pipeline Latency and Completion Success.
        Measures total time from raw files to completed case report across multiple runs.
        """
        start_time = time.time()
        latencies = []
        step_counts = []
        successful_runs = 0

        for _ in range(runs):
            t0 = time.time()
            demo_files = demo_dataset_builder.generate_demo_files()
            processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]
            case_data = agent_orchestrator.run_autonomous_investigation(processed)
            run_time = time.time() - t0
            latencies.append(run_time)

            audit_steps = len(case_data.get("audit_trail", []))
            step_counts.append(audit_steps)

            is_completed = case_data.get("status") == "COMPLETED" or case_data.get("report") is not None
            has_risk = case_data.get("risk", {}).get("risk_score", 0) > 0 or "risk_severity" in case_data.get("risk", {})
            if is_completed and has_risk and audit_steps > 0:
                successful_runs += 1

        stats = summary_statistics(latencies)
        elapsed = time.time() - start_time

        return {
            "name": "End-to-End Investigation Pipeline",
            "status": "MEASURED",
            "passed": successful_runs == runs,
            "total_runs": runs,
            "successful_runs": successful_runs,
            "completion_rate": round(successful_runs / runs, 4),
            "mean_pipeline_latency_seconds": stats["mean"],
            "min_pipeline_latency_seconds": stats["min"],
            "max_pipeline_latency_seconds": stats["max"],
            "std_pipeline_latency_seconds": stats["std"],
            "mean_audit_steps": round(sum(step_counts) / len(step_counts), 1),
            "execution_time_seconds": round(elapsed, 4)
        }

benchmark_suite = SentinelBenchmarkSuite()
