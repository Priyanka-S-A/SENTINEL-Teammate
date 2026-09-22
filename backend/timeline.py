from typing import List, Dict, Any

class TimelineAndAttackChainEngine:
    """
    Reconstructs chronological investigation timeline (Requirement #4)
    and maps observed evidence to attack-chain stages (Requirement #16).
    Explicitly marks missing steps as [UNCONFIRMED].
    """

    ATTACK_CHAIN_STAGES = [
        "Initial Access",
        "Execution",
        "Credential Access",
        "Persistence",
        "Command & Control",
        "Exfiltration & Impact"
    ]

    def build_chronological_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        timeline = []
        for idx, evt in enumerate(events, 1):
            timeline.append({
                "step_num": idx,
                "timestamp": evt.get("timestamp", "2026-09-14 10:00:00"),
                "source_file": evt.get("source_file"),
                "source_type": evt.get("source_type"),
                "event_action": evt.get("event_action"),
                "entity": f"{evt.get('entity_type')}: {evt.get('entity_value')}",
                "severity": evt.get("severity"),
                "summary": f"{evt.get('event_action')} involving {evt.get('entity_value')} recorded in {evt.get('source_file')}"
            })
        return timeline

    def reconstruct_attack_chain(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chain = {stage: {"status": "UNCONFIRMED", "evidence": []} for stage in self.ATTACK_CHAIN_STAGES}

        for evt in events:
            stype = evt.get("source_type", "")
            action = evt.get("event_action", "")
            ent_type = evt.get("entity_type", "")
            ent_val = evt.get("entity_value", "")
            src_file = evt.get("source_file", "")
            ts = evt.get("timestamp", "")

            evidence_item = f"[{ts}] {action} ({ent_type}: {ent_val}) in {src_file}"

            if "Email" in stype or "Phishing" in action:
                chain["Initial Access"]["status"] = "CONFIRMED"
                chain["Initial Access"]["evidence"].append(evidence_item)
            elif "Suspicious" in action or "Endpoint" in stype or "Execution" in action or ent_type == "FileHash":
                chain["Execution"]["status"] = "CONFIRMED"
                chain["Execution"]["evidence"].append(evidence_item)
            elif "URL" in ent_type or "Auth" in stype or "Login" in action:
                chain["Credential Access"]["status"] = "CONFIRMED"
                chain["Credential Access"]["evidence"].append(evidence_item)
            elif "Powershell" in action or "Privilege" in action:
                chain["Persistence"]["status"] = "CONFIRMED"
                chain["Persistence"]["evidence"].append(evidence_item)
            elif "Firewall" in stype or "Outbound" in action or "DNS" in stype:
                chain["Command & Control"]["status"] = "CONFIRMED"
                chain["Command & Control"]["evidence"].append(evidence_item)

        # Output structured attack chain
        output = []
        for stage in self.ATTACK_CHAIN_STAGES:
            output.append({
                "stage": stage,
                "status": chain[stage]["status"],
                "evidence_count": len(chain[stage]["evidence"]),
                "evidence_summary": chain[stage]["evidence"] if chain[stage]["evidence"] else ["No empirical evidence observed in ingested logs [UNCONFIRMED]"]
            })
        return output

timeline_engine = TimelineAndAttackChainEngine()
