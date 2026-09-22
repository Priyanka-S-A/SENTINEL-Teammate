from typing import List, Dict, Any

class CampaignClusteringAndCaseComparisonEngine:
    """
    Case Comparison & Threat Campaign Clustering Engine (Requirements #30, #31).
    Compares multiple incident cases, identifies shared infrastructure (IPs, domains, hashes),
    and clusters cases into threat campaigns.
    """

    def __init__(self):
        # Synthetic historical cases database for comparison demo
        self.case_repository = [
            {
                "case_id": "CASE-2026-0801",
                "title": "Finance Dept Spear-Phishing Attempt",
                "date": "2026-08-01",
                "iocs": ["malicious-phish.net", "198.51.100.45", "user.smith@company.com"],
                "mitre_techniques": ["T1566.002", "T1071.001", "T1059.001"],
                "status": "CLOSED - CONTAINED"
            },
            {
                "case_id": "CASE-2026-0819",
                "title": "HR Department Suspicious Login & Domain Lookup",
                "date": "2026-08-19",
                "iocs": ["malicious-phish.net", "hr.helpdesk-update.info", "user.jones@company.com"],
                "mitre_techniques": ["T1566.002", "T1078"],
                "status": "CLOSED - REMEDIATED"
            },
            {
                "case_id": "CASE-2026-0902",
                "title": "Executive Spearphishing & Cobalt Strike Beacon",
                "date": "2026-09-02",
                "iocs": ["198.51.100.45", "exec-update.com", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
                "mitre_techniques": ["T1566.002", "T1071.001", "T1055"],
                "status": "CLOSED - CONTAINED"
            }
        ]

    def compare_case_with_history(self, current_case_iocs: List[str], current_techniques: List[str]) -> Dict[str, Any]:
        matched_cases = []
        campaign_iocs = set()

        for hist_case in self.case_repository:
            # Check overlap in IOCs
            shared_iocs = set(current_case_iocs).intersection(set(hist_case["iocs"]))
            shared_techs = set(current_techniques).intersection(set(hist_case["mitre_techniques"]))

            if shared_iocs or len(shared_techs) >= 2:
                similarity_score = round(min(99.0, (len(shared_iocs) * 35.0) + (len(shared_techs) * 15.0)), 1)
                matched_cases.append({
                    "case_id": hist_case["case_id"],
                    "title": hist_case["title"],
                    "date": hist_case["date"],
                    "shared_iocs": list(shared_iocs),
                    "shared_techniques": list(shared_techs),
                    "similarity_score": similarity_score
                })
                campaign_iocs.update(shared_iocs)

        campaign_name = "Operation DarkPhish Campaign" if matched_cases else "Standalone Incident"

        return {
            "campaign_identified": len(matched_cases) > 0,
            "campaign_name": campaign_name,
            "campaign_summary": f"Incident shares infrastructure and behavioral patterns with {len(matched_cases)} previous corporate cases. Identified multi-wave targeted campaign targeting credential theft and Cobalt Strike C2 persistence." if matched_cases else "No prior campaign matches detected.",
            "matched_historical_cases": matched_cases,
            "campaign_shared_infrastructure": list(campaign_iocs)
        }

campaign_engine = CampaignClusteringAndCaseComparisonEngine()
