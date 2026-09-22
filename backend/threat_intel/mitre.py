import time
from typing import Dict, Any, List
from backend.threat_intel.base import BaseThreatIntelProvider, sanitize_external_data

class MITREAttackProvider(BaseThreatIntelProvider):
    """
    Local Structured MITRE ATT&CK Mapping Provider (Section 6).
    Maps indicators, event types, and behaviors to MITRE techniques and tactics.
    """

    def __init__(self):
        super().__init__("MITRE ATT&CK")
        self.technique_db = {
            "T1566.002": {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "description": "Adversaries send spearphishing emails with malicious links to lure victims into credential harvesting or malware delivery.",
                "evidence_ref": "Email subject, embedded link URL, and phishing domain records."
            },
            "T1071.001": {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "description": "Adversaries communicate using HTTP/HTTPS web protocols to disguise C2 traffic as legitimate web browsing.",
                "evidence_ref": "Outbound firewall connections and proxy session logs."
            },
            "T1059.001": {
                "id": "T1059.001",
                "name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": "Adversaries execute encoded or obfuscated PowerShell commands to download secondary payloads into host memory.",
                "evidence_ref": "Windows Process Creation Event ID 4688 and EDR telemetry."
            },
            "T1583.001": {
                "id": "T1583.001",
                "name": "Acquire Infrastructure: Domains",
                "tactic": "Resource Development",
                "description": "Adversaries acquire typosquatted or disposable domain names for phishing campaigns.",
                "evidence_ref": "WHOIS registration records showing newly registered domains."
            },
            "T1055": {
                "id": "T1055",
                "name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "description": "Adversaries inject malicious code into legitimate processes to evade host process monitoring.",
                "evidence_ref": "Malware file hash analysis and memory injection telemetry."
            },
            "T1110": {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries use automated password spraying or brute force tools against authentication endpoints.",
                "evidence_ref": "Repeated failed login events in domain controller logs."
            }
        }

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        mapped = []
        clean = indicator.lower()

        if indicator_type == "Domain" or "phish" in clean or "login" in clean:
            mapped.append(self.technique_db["T1566.002"])
            mapped.append(self.technique_db["T1583.001"])
        elif indicator_type == "IP" or "c2" in clean:
            mapped.append(self.technique_db["T1071.001"])
        elif indicator_type == "FileHash" or "powershell" in clean:
            mapped.append(self.technique_db["T1059.001"])
            mapped.append(self.technique_db["T1055"])
        else:
            mapped.append(self.technique_db["T1566.002"])

        tech_summary = ", ".join([f"{t['id']} - {t['name']}" for t in mapped])
        raw_summary = sanitize_external_data(
            f"Mapped {len(mapped)} MITRE ATT&CK technique(s): {tech_summary}. "
            f"Primary Tactic: {mapped[0]['tactic']}."
        )

        return {
            "provider": "MITRE ATT&CK",
            "status": "LIVE",
            "malicious": True,
            "confidence": 90,
            "risk_score": 75,
            "categories": [t["tactic"] for t in mapped],
            "reputation": tech_summary,
            "techniques": mapped,
            "raw_summary": raw_summary,
            "source_url": f"https://attack.mitre.org/techniques/{mapped[0]['id'].replace('.', '/')}/",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
