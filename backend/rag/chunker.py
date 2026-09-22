import json
from typing import List, Dict, Any

class CaseChunker:
    """
    Converts complete Case state into structured searchable document chunks (Section 2).
    Tracks metadata and provenance for every chunk.
    """

    def chunk_case(self, case_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        case_id = case_data.get("case_id", "CASE-UNKNOWN")
        chunks = []
        chunk_idx = 1

        # 1. Chunk Evidence Events
        for ev in case_data.get("events", []):
            s_file = ev.get("source_file", "Ingested Evidence")
            s_type = ev.get("source_type", "LOG")
            action = ev.get("event_action", "")
            val = ev.get("entity_value", "")
            ts = ev.get("timestamp", "")
            raw = str(ev.get("raw_ref", ev))

            text = (
                f"Evidence Event [{s_file}] ({s_type}): {action} involving entity '{val}'. "
                f"Timestamp: {ts}. Raw Reference: {raw[:300]}"
            )

            chunks.append({
                "chunk_id": f"CHK-EV-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "events",
                "source_type": s_type,
                "source_id": s_file,
                "timestamp": ts,
                "entity": val,
                "indicator": val,
                "document_type": "EVIDENCE_EVENT",
                "provenance": f"Source File: {s_file}",
                "text": text
            })
            chunk_idx += 1

        # 2. Chunk IOC Records
        for ioc in case_data.get("iocs", []):
            ival = ioc.get("value") if isinstance(ioc, dict) else str(ioc)
            itype = ioc.get("type", "UNKNOWN") if isinstance(ioc, dict) else "UNKNOWN"
            text = f"Indicator of Compromise (IOC): '{ival}' (Type: {itype}). Extracted from normalized case evidence."

            chunks.append({
                "chunk_id": f"CHK-IOC-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "iocs",
                "source_type": "IOC",
                "source_id": ival,
                "timestamp": "",
                "entity": ival,
                "indicator": ival,
                "document_type": "IOC_RECORD",
                "provenance": "Evidence Extractor",
                "text": text
            })
            chunk_idx += 1

        # 3. Chunk Investigation Steps & Audit Trail
        for step in case_data.get("audit_trail", []):
            s_num = step.get("step", 0)
            tool = step.get("tool_called", "unknown")
            query = json.dumps(step.get("tool_args", {}))
            rationale = step.get("rationale", "")
            findings = step.get("findings", "")
            prov = step.get("llm_provider", "fallback")
            ts = step.get("timestamp", "")

            text = (
                f"Investigation Step {s_num}: Tool '{tool}' called by {prov}. Query: {query}. "
                f"Rationale: {rationale}. Findings: {findings}"
            )

            chunks.append({
                "chunk_id": f"CHK-STEP-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "audit_trail",
                "source_type": "INVESTIGATION_STEP",
                "source_id": f"Step-{s_num}",
                "timestamp": ts,
                "entity": tool,
                "indicator": "",
                "document_type": "INVESTIGATION_STEP",
                "provenance": f"Agent Replay Log Step {s_num}",
                "text": text
            })
            chunk_idx += 1

        # 4. Chunk Leads
        for l in case_data.get("leads", []):
            question = l.get("question", str(l)) if isinstance(l, dict) else str(l)
            status = l.get("status", "UNANSWERED") if isinstance(l, dict) else "UNANSWERED"
            ioc = l.get("target_ioc", "") if isinstance(l, dict) else ""

            text = f"Investigation Priority Lead: {question} Target IOC: '{ioc}'. Status: {status}."
            chunks.append({
                "chunk_id": f"CHK-LEAD-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "leads",
                "source_type": "LEAD",
                "source_id": l.get("id", "LEAD") if isinstance(l, dict) else "LEAD",
                "timestamp": "",
                "entity": ioc,
                "indicator": ioc,
                "document_type": "INVESTIGATION_LEAD",
                "provenance": "Lead Manager Queue",
                "text": text
            })
            chunk_idx += 1

        # 5. Chunk Hypotheses
        for h in case_data.get("hypotheses", []):
            title = h.get("title", str(h)) if isinstance(h, dict) else str(h)
            score = h.get("score", 0.0) if isinstance(h, dict) else 0.0
            text = f"Competing Hypothesis {h.get('id', 'H') if isinstance(h, dict) else 'H'}: '{title}'. Posterior Probability Confidence: {score}%."

            chunks.append({
                "chunk_id": f"CHK-HYPO-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "hypotheses",
                "source_type": "HYPOTHESIS",
                "source_id": h.get("id", "H") if isinstance(h, dict) else "H",
                "timestamp": "",
                "entity": title,
                "indicator": "",
                "document_type": "HYPOTHESIS",
                "provenance": "ACH Analysis Matrix",
                "text": text
            })
            chunk_idx += 1

        # 6. Chunk Graph Relationships & Hidden Paths
        graph_summary = case_data.get("graph_summary", case_data.get("graph", {}))
        for edge in graph_summary.get("edges", []):
            src = edge.get("source", "")
            rel = edge.get("relationship", edge.get("relation", "CONNECTED_TO"))
            tgt = edge.get("target", "")

            text = f"Network Graph Edge: Entity '{src}' is related via '{rel}' to Target '{tgt}'."
            chunks.append({
                "chunk_id": f"CHK-EDGE-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "graph",
                "source_type": "GRAPH_RELATIONSHIP",
                "source_id": f"{src}->{tgt}",
                "timestamp": edge.get("timestamp", ""),
                "entity": src,
                "indicator": tgt,
                "document_type": "GRAPH_EDGE",
                "provenance": "Evidence Graph Engine",
                "text": text
            })
            chunk_idx += 1

        # 7. Chunk Incident Report / Executive Summary
        if case_data.get("report"):
            rep = case_data["report"]
            exec_summary = rep.get("executive_summary", str(rep)) if isinstance(rep, dict) else str(rep)
            text = f"Executive Incident Report Summary: {exec_summary}"

            chunks.append({
                "chunk_id": f"CHK-REP-{chunk_idx:04d}",
                "case_id": case_id,
                "category": "report",
                "source_type": "REPORT",
                "source_id": "EXECUTIVE_REPORT",
                "timestamp": "",
                "entity": case_id,
                "indicator": "",
                "document_type": "INCIDENT_REPORT",
                "provenance": "Report Generator Engine",
                "text": text
            })
            chunk_idx += 1

        return chunks

chunker = CaseChunker()
