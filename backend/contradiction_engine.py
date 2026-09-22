from typing import List, Dict, Any

class ContradictionAndFalsePositiveEngine:
    """
    Self-verification & Counter-Evidence Evaluator (Requirement #12).
    Actively searches for evidence against leading hypothesis to detect false positives
    and calibrate final confidence scores.
    """

    def evaluate_contradictions(self, leading_hypothesis: Dict[str, Any], events: List[Dict[str, Any]], intel_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        counter_evidence_found = []
        confidence_penalty = 0.0

        # Check for legitimate cloud infrastructure IPs (AWS, Azure, Google Cloud, O365)
        for intel in intel_data:
            interp = intel.get("interpretation", "").upper()
            if "LEGITIMATE CLOUD" in interp or "BENIGN" in interp or "MICROSOFT" in interp:
                counter_evidence_found.append({
                    "type": "Cloud Service Identification",
                    "description": f"Target infrastructure ({intel.get('type')}) was identified as benign enterprise cloud provider: {intel.get('interpretation')}",
                    "impact": "Reduces probability of malicious C2 infrastructure"
                })
                confidence_penalty += 15.0

        # Check for scheduled maintenance / internal administrative window
        for evt in events:
            raw = evt.get("raw_ref", "").lower()
            if "scheduled_task" in raw or "cron" in raw or "patch_update" in raw or "authorized_admin" in raw:
                counter_evidence_found.append({
                    "type": "Authorized Maintenance Window",
                    "description": f"Event in {evt['source_file']} matches routine system maintenance pattern: '{raw[:80]}'",
                    "impact": "Reduces anomaly confidence for endpoint execution"
                })
                confidence_penalty += 20.0

        # Check if outbound traffic was blocked by firewall instead of permitted
        blocked_connections = [e for e in events if "Blocked" in e.get("event_action", "")]
        if blocked_connections:
            counter_evidence_found.append({
                "type": "Preventative Security Control Block",
                "description": f"Firewall blocked {len(blocked_connections)} connection attempts to external IOCs. Active compromise prevented.",
                "impact": "Downgrades incident impact from Breach to Attempted Intrusion"
            })

        is_false_positive = False
        if confidence_penalty >= 35.0 or (not counter_evidence_found and len(events) < 2):
            is_false_positive = (confidence_penalty >= 35.0)

        return {
            "has_contradictions": len(counter_evidence_found) > 0,
            "counter_evidence_list": counter_evidence_found,
            "confidence_penalty": confidence_penalty,
            "is_false_positive_risk": is_false_positive,
            "verdict_summary": f"Self-verification identified {len(counter_evidence_found)} counter-evidence factors resulting in a {confidence_penalty}% confidence penalty adjustment." if counter_evidence_found else "Self-verification completed: No significant counter-evidence or false-positive indicators identified."
        }

contradiction_engine = ContradictionAndFalsePositiveEngine()
