import os
import base64
import time
import requests
from typing import Dict, Any
from backend.threat_intel.base import BaseThreatIntelProvider, sanitize_external_data

class VirusTotalProvider(BaseThreatIntelProvider):
    """
    VirusTotal v3 REST API Threat Intelligence Integration (Section 2).
    Read-only lookups for IPs, Domains, URLs, and File Hashes.
    """

    def __init__(self):
        super().__init__("VirusTotal")

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {
                "provider": "VirusTotal",
                "status": "UNAVAILABLE",
                "reason": "VIRUSTOTAL_API_KEY environment variable not configured",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "API key unconfigured",
                "raw_summary": "VirusTotal lookup skipped (API key not provided).",
                "source_url": "https://www.virustotal.com",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        # Build VT v3 API endpoint
        if indicator_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        elif indicator_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        elif indicator_type == "URL":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif indicator_type == "FileHash":
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"

        try:
            resp = requests.get(url, headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious_cnt = stats.get("malicious", 0)
                suspicious_cnt = stats.get("suspicious", 0)
                harmless_cnt = stats.get("harmless", 0)
                total = sum(stats.values()) if stats else 70

                is_malicious = (malicious_cnt >= 3)
                risk_score = min(100, int(((malicious_cnt + suspicious_cnt * 0.5) / max(1, total)) * 100))

                categories = list(data.get("categories", {}).values())[:5]
                raw_summary = sanitize_external_data(
                    f"VirusTotal Detections: {malicious_cnt}/{total} vendors flagged as malicious. "
                    f"Reputation Score: {data.get('reputation', 0)}. Categories: {', '.join(categories)}"
                )

                return {
                    "provider": "VirusTotal",
                    "status": "LIVE",
                    "malicious": is_malicious,
                    "confidence": min(99, 50 + malicious_cnt * 2),
                    "risk_score": risk_score,
                    "categories": categories,
                    "reputation": f"{malicious_cnt}/{total} Malicious Vendors",
                    "raw_summary": raw_summary,
                    "source_url": f"https://www.virustotal.com/gui/search/{indicator}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            elif resp.status_code == 404:
                return {
                    "provider": "VirusTotal",
                    "status": "LIVE",
                    "malicious": False,
                    "confidence": 30,
                    "risk_score": 0,
                    "categories": [],
                    "reputation": "Not Found in VirusTotal Database",
                    "raw_summary": f"Indicator '{indicator}' was not found in VirusTotal repositories.",
                    "source_url": f"https://www.virustotal.com/gui/search/{indicator}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                return {
                    "provider": "VirusTotal",
                    "status": "UNAVAILABLE",
                    "reason": f"HTTP {resp.status_code}: {resp.text[:100]}",
                    "malicious": None,
                    "confidence": 0,
                    "risk_score": 0,
                    "categories": [],
                    "reputation": f"HTTP Error {resp.status_code}",
                    "raw_summary": f"VirusTotal request returned status {resp.status_code}.",
                    "source_url": "https://www.virustotal.com",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
        except Exception as e:
            return {
                "provider": "VirusTotal",
                "status": "UNAVAILABLE",
                "reason": f"Connection exception: {str(e)}",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "Connection Failed",
                "raw_summary": f"Failed to connect to VirusTotal API: {str(e)}",
                "source_url": "https://www.virustotal.com",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
