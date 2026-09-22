import os
import time
import requests
from typing import Dict, Any
from backend.threat_intel.base import BaseThreatIntelProvider, sanitize_external_data

class AbuseIPDBProvider(BaseThreatIntelProvider):
    """
    AbuseIPDB v2 REST API IP Reputation Integration (Section 3).
    Read-only IP abuse score, report counts, and ISP details.
    """

    def __init__(self):
        super().__init__("AbuseIPDB")

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type != "IP":
            return {
                "provider": "AbuseIPDB",
                "status": "UNAVAILABLE",
                "reason": f"AbuseIPDB only supports IP indicators (received {indicator_type})",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "N/A for Non-IP",
                "raw_summary": "AbuseIPDB skipped for non-IP indicator.",
                "source_url": "https://www.abuseipdb.com",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            return {
                "provider": "AbuseIPDB",
                "status": "UNAVAILABLE",
                "reason": "ABUSEIPDB_API_KEY environment variable not configured",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "API key unconfigured",
                "raw_summary": "AbuseIPDB lookup skipped (API key not provided).",
                "source_url": "https://www.abuseipdb.com",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": indicator,
            "maxAgeInDays": 90,
            "verbose": True
        }

        try:
            resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "Unknown ISP")
                domain = data.get("domain", "")

                is_malicious = abuse_score >= 50
                raw_summary = sanitize_external_data(
                    f"AbuseIPDB Confidence Score: {abuse_score}%. Total Abuse Reports: {reports}. "
                    f"Country: {country}, ISP: {isp}, Associated Domain: {domain}"
                )

                return {
                    "provider": "AbuseIPDB",
                    "status": "LIVE",
                    "malicious": is_malicious,
                    "confidence": abuse_score,
                    "risk_score": abuse_score,
                    "categories": ["IP Abuse", "Scanner/C2"] if abuse_score > 50 else [],
                    "reputation": f"Abuse Score {abuse_score}% ({reports} Reports)",
                    "raw_summary": raw_summary,
                    "source_url": f"https://www.abuseipdb.com/check/{indicator}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                return {
                    "provider": "AbuseIPDB",
                    "status": "UNAVAILABLE",
                    "reason": f"HTTP {resp.status_code}: {resp.text[:100]}",
                    "malicious": None,
                    "confidence": 0,
                    "risk_score": 0,
                    "categories": [],
                    "reputation": f"HTTP Error {resp.status_code}",
                    "raw_summary": f"AbuseIPDB request returned status {resp.status_code}.",
                    "source_url": "https://www.abuseipdb.com",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
        except Exception as e:
            return {
                "provider": "AbuseIPDB",
                "status": "UNAVAILABLE",
                "reason": f"Connection exception: {str(e)}",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "Connection Failed",
                "raw_summary": f"Failed to connect to AbuseIPDB API: {str(e)}",
                "source_url": "https://www.abuseipdb.com",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
