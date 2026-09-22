"""
SENTINEL Phase 5: Benchmark Datasets & Ground Truth Definitions.
Provides reproducible benchmark cases with verified ground truth for:
- Entity & IOC extraction (IPs, Domains, Users, Hashes, Processes)
- Graph path / attack chain reconstruction
- Hypothesis evaluation
- Vector RAG semantic retrieval
"""

from typing import Dict, List, Any, Set
from backend.demo_dataset import demo_dataset_builder

class BenchmarkDatasets:
    """
    Standardized benchmark cases with verified ground truth annotations.
    """

    @staticmethod
    def get_standard_attack_ground_truth() -> Dict[str, Any]:
        """
        Ground truth annotations for the standard 6-file attack scenario:
        - phishing_email.eml
        - dns_queries.csv
        - firewall_syslog.txt
        - windows_auth_events.txt
        - sysmon_endpoint_alerts.json
        - cert_threat_advisory.pdf
        """
        return {
            "case_id": "BENCH-CASE-STD-01",
            "name": "Spearphishing to C2 & Malicious PowerShell Stager",
            "expected_entities": {
                "ips": {
                    "198.51.100.45",
                    "10.0.0.15",
                    "10.0.0.88",
                    "140.82.121.4",
                    "52.96.10.1",
                    "192.168.1.100"
                },
                "domains": {
                    "malicious-phish.net",
                    "company.com",
                    "mail.malicious-phish.net"
                },
                "users": {
                    "user.smith@company.com",
                    "COMPANY\\user.smith"
                },
                "hashes": {
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "cves": {
                    "CVE-2024-38021"
                }
            },
            "expected_critical_iocs": {
                "198.51.100.45",
                "malicious-phish.net",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "expected_graph_paths": [
                # Attack chain connections that MUST be present in the evidence graph
                ("user.smith@company.com", "malicious-phish.net"),
                ("malicious-phish.net", "198.51.100.45"),
                ("10.0.0.15", "198.51.100.45")
            ],
            "expected_leading_hypothesis": "H2", # Measured: C2 Backdoor leads over Phishing due to Firewall+Endpoint evidence weight
            "expected_min_risk_score": 75.0,     # Must be HIGH or CRITICAL severity
            "rag_test_queries": [
                {
                    "query": "What evidence connects the phishing email to the compromised endpoint?",
                    "expected_sources": {"phishing_email.eml", "windows_auth_events.txt", "sysmon_endpoint_alerts.json"},
                    "expected_categories": {"events", "logs"}
                },
                {
                    "query": "Show me the evidence supporting the PowerShell execution.",
                    "expected_sources": {"sysmon_endpoint_alerts.json"},
                    "expected_categories": {"events", "iocs"}
                },
                {
                    "query": "Which external C2 IP was contacted?",
                    "expected_entities": {"198.51.100.45"},
                    "expected_sources": {"firewall_syslog.txt", "dns_queries.csv"}
                },
                {
                    "query": "What CVE vulnerability is mentioned in the advisory?",
                    "expected_entities": {"CVE-2024-38021"},
                    "expected_sources": {"cert_threat_advisory.pdf"}
                },
                {
                    "query": "What user account experienced anomalous authentication attempts?",
                    "expected_entities": {"user.smith@company.com", "COMPANY\\user.smith"},
                    "expected_sources": {"windows_auth_events.txt"}
                }
            ]
        }

    @staticmethod
    def get_clean_baseline_scenario() -> Dict[str, Any]:
        """
        Controlled synthetic clean scenario: Normal routine IT operations with NO malicious indicators.
        Used to test false positive rates, specificity, and baseline noise tolerance.
        """
        files = [
            {
                "filename": "clean_web_access.log",
                "content_bytes": (
                    "2026-09-14 09:00:01 10.0.0.50 GET /index.html 200 OK - internal-portal.corp\n"
                    "2026-09-14 09:05:12 10.0.0.50 GET /styles.css 200 OK - internal-portal.corp\n"
                    "2026-09-14 09:10:33 10.0.0.52 GET /dashboard 200 OK - internal-portal.corp\n"
                ).encode("utf-8")
            },
            {
                "filename": "clean_auth.log",
                "content_bytes": (
                    "2026-09-14 09:00:00 EventID 4624 - Successful Logon - User: alice.admin@company.com - Workstation: WS-ADMIN01\n"
                    "2026-09-14 09:15:00 EventID 4634 - Logoff - User: alice.admin@company.com - Workstation: WS-ADMIN01\n"
                ).encode("utf-8")
            }
        ]
        return {
            "case_id": "BENCH-CASE-CLEAN-02",
            "name": "Benign Corporate IT Activity Baseline",
            "files": files,
            "expected_entities": {
                "ips": {"10.0.0.50", "10.0.0.52"},
                "domains": {"internal-portal.corp", "company.com"},
                "users": {"alice.admin@company.com"}
            },
            "expected_max_risk_score": 30.0, # Must evaluate as LOW / Minimal risk
            "expected_malicious_iocs": set()  # No malicious IOCs expected
        }

    @staticmethod
    def get_lateral_movement_scenario() -> Dict[str, Any]:
        """
        Controlled synthetic multi-host lateral movement scenario:
        Tests detection of multi-hop internal pivots and network propagation.
        """
        files = [
            {
                "filename": "lateral_auth.txt",
                "content_bytes": (
                    "2026-09-14 11:00:00 - EventID 4624 - Successful Network Logon - User: admin.user@company.com - Source IP: 10.0.0.15 - Dest IP: 10.0.0.22 - Workstation: DC-SERVER01\n"
                    "2026-09-14 11:00:15 - EventID 5140 - Network Share Access - Share: \\\\10.0.0.22\\ADMIN$ - User: admin.user@company.com - Client: 10.0.0.15\n"
                    "2026-09-14 11:01:00 - EventID 7045 - Service Installed: PSEXESVC - System: DC-SERVER01 - Account: LocalSystem\n"
                ).encode("utf-8")
            }
        ]
        return {
            "case_id": "BENCH-CASE-LATERAL-03",
            "name": "Internal Lateral Movement & SMB Admin Share Access",
            "files": files,
            "expected_entities": {
                "ips": {"10.0.0.15", "10.0.0.22"},
                "users": {"admin.user@company.com"}
            },
            "expected_graph_paths": [
                ("10.0.0.15", "10.0.0.22")
            ]
        }

datasets = BenchmarkDatasets()
