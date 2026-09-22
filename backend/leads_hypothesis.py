from typing import List, Dict, Any

class DynamicLeadAndHypothesisManager:
    """
    Manages Dynamic Investigative Leads Queue (Requirement #7)
    and Competing Hypotheses ACH Framework (Requirement #13).
    """

    def __init__(self):
        self.leads_queue = []
        self.hypotheses = {
            "H1": {
                "id": "H1",
                "title": "Phishing-led Credential Compromise & Account Takeover",
                "description": "An attacker delivered a spear-phishing link leading to credential harvesting and subsequent unauthorized access.",
                "supporting_evidence": [],
                "counter_evidence": [],
                "score": 0.0,
                "status": "EVALUATING"
            },
            "H2": {
                "id": "H2",
                "title": "Malware Payload Execution & C2 Backdoor",
                "description": "A malicious payload executed on an endpoint, establishing encrypted C2 communication with external infrastructure.",
                "supporting_evidence": [],
                "counter_evidence": [],
                "score": 0.0,
                "status": "EVALUATING"
            },
            "H3": {
                "id": "H3",
                "title": "Compromised External Service Account / Insider",
                "description": "Authorized user credentials were used improperly or an external VPN/SaaS endpoint was accessed directly.",
                "supporting_evidence": [],
                "counter_evidence": [],
                "score": 0.0,
                "status": "EVALUATING"
            },
            "H4": {
                "id": "H4",
                "title": "False Positive / Legitimate IT Administrative Activity",
                "description": "The observed anomalies represent routine cloud sync, vulnerability scanning, or approved admin tasks.",
                "supporting_evidence": [],
                "counter_evidence": [],
                "score": 0.0,
                "status": "EVALUATING"
            }
        }

    def generate_initial_leads(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self.leads_queue = []
        lead_id = 1

        for ioc in iocs:
            val = ioc.get("value")
            itype = ioc.get("type")

            if itype == "Domain":
                self.leads_queue.append({
                    "id": f"LEAD-{lead_id:03d}",
                    "question": f"Which internal users or endpoints clicked or resolved domain '{val}'?",
                    "target_ioc": val,
                    "ioc_type": itype,
                    "priority": 95,
                    "status": "UNANSWERED",
                    "findings": None
                })
                lead_id += 1
                self.leads_queue.append({
                    "id": f"LEAD-{lead_id:03d}",
                    "question": f"Is domain '{val}' connected to other known malicious IPs or URLs?",
                    "target_ioc": val,
                    "ioc_type": itype,
                    "priority": 88,
                    "status": "UNANSWERED",
                    "findings": None
                })
                lead_id += 1

            elif itype == "IP":
                self.leads_queue.append({
                    "id": f"LEAD-{lead_id:03d}",
                    "question": f"Who communicated with IP address '{val}' in firewall or proxy logs?",
                    "target_ioc": val,
                    "ioc_type": itype,
                    "priority": 90,
                    "status": "UNANSWERED",
                    "findings": None
                })
                lead_id += 1
                self.leads_queue.append({
                    "id": f"LEAD-{lead_id:03d}",
                    "question": f"Does IP '{val}' belong to a legitimate cloud provider (AWS/Azure) or malicious hosting?",
                    "target_ioc": val,
                    "ioc_type": itype,
                    "priority": 85,
                    "status": "UNANSWERED",
                    "findings": None
                })
                lead_id += 1

            elif itype in ("FileHash", "SuspiciousKeyword"):
                self.leads_queue.append({
                    "id": f"LEAD-{lead_id:03d}",
                    "question": f"Are other machines on the network showing execution of IOC '{val}'?",
                    "target_ioc": val,
                    "ioc_type": itype,
                    "priority": 92,
                    "status": "UNANSWERED",
                    "findings": None
                })
                lead_id += 1

        # Sort by priority
        self.leads_queue.sort(key=lambda x: x["priority"], reverse=True)
        return self.leads_queue

    def update_lead_status(self, lead_id: str, status: str, findings: str):
        for lead in self.leads_queue:
            if lead["id"] == lead_id:
                lead["status"] = status
                lead["findings"] = findings
                break

    def evaluate_hypotheses(self, events: List[Dict[str, Any]], intel_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates supporting vs counter evidence for competing hypotheses (Requirement #13).
        """
        # Reset evidence lists
        for h_key in self.hypotheses:
            self.hypotheses[h_key]["supporting_evidence"] = []
            self.hypotheses[h_key]["counter_evidence"] = []

        has_phish = False
        has_url = False
        has_c2_ip = False
        has_malware_hash = False
        has_auth_anomaly = False
        has_cloud_ip = False

        for evt in events:
            action = evt.get("event_action", "")
            raw = evt.get("raw_ref", "").lower()
            stype = evt.get("source_type", "")

            if "Phishing" in action or "Email" in stype:
                has_phish = True
                self.hypotheses["H1"]["supporting_evidence"].append(f"Phishing email identified in {evt['source_file']}")
            if "URL" in evt.get("entity_type", "") or "Link" in action:
                has_url = True
                self.hypotheses["H1"]["supporting_evidence"].append(f"Suspicious URL link present in evidence")
            if "Outbound Network Traffic Allowed" in action or "Firewall" in stype:
                has_c2_ip = True
                self.hypotheses["H2"]["supporting_evidence"].append(f"Outbound connection established to external IP in {evt['source_file']}")
            if "Suspicious" in action or "File Execution" in action or "Endpoint" in stype:
                has_malware_hash = True
                self.hypotheses["H2"]["supporting_evidence"].append(f"Endpoint execution alert in {evt['source_file']}")
            if "Login" in action or "Auth" in stype:
                has_auth_anomaly = True
                self.hypotheses["H1"]["supporting_evidence"].append(f"Authentication event recorded from external source")
                self.hypotheses["H3"]["supporting_evidence"].append(f"Direct account access logged")

        # Evaluate threat intel
        for intel in intel_results:
            interp = intel.get("interpretation", "")
            if "BENIGN" in interp or "LEGITIMATE CLOUD" in interp:
                has_cloud_ip = True
                self.hypotheses["H4"]["supporting_evidence"].append(f"Threat intel confirmed legitimate infrastructure: {interp}")
                self.hypotheses["H1"]["counter_evidence"].append(f"Target IP is verified cloud infrastructure")
                self.hypotheses["H2"]["counter_evidence"].append(f"Destination host has 0 threat detections")

        # Calculate scores
        h1_supp = len(self.hypotheses["H1"]["supporting_evidence"])
        h2_supp = len(self.hypotheses["H2"]["supporting_evidence"])
        h3_supp = len(self.hypotheses["H3"]["supporting_evidence"])
        h4_supp = len(self.hypotheses["H4"]["supporting_evidence"])

        total_weight = max(1, (h1_supp * 3) + (h2_supp * 3) + (h3_supp * 2) + (h4_supp * 4))

        self.hypotheses["H1"]["score"] = round(min(98.0, ((h1_supp * 3) / total_weight) * 100), 1)
        self.hypotheses["H2"]["score"] = round(min(98.0, ((h2_supp * 3) / total_weight) * 100), 1)
        self.hypotheses["H3"]["score"] = round(min(98.0, ((h3_supp * 2) / total_weight) * 100), 1)
        self.hypotheses["H4"]["score"] = round(min(98.0, ((h4_supp * 4) / total_weight) * 100), 1)

        # Mark leading hypothesis
        leading_h = max(self.hypotheses.values(), key=lambda x: x["score"])
        for h in self.hypotheses.values():
            if h["id"] == leading_h["id"]:
                h["status"] = "LEADING_HYPOTHESIS"
            else:
                h["status"] = "EVALUATED"

        return {
            "hypotheses": list(self.hypotheses.values()),
            "leading_hypothesis": leading_h
        }

lead_and_hypothesis_mgr = DynamicLeadAndHypothesisManager()
