import os
import time
import requests
from typing import Dict, Any
from backend.threat_intel.base import BaseThreatIntelProvider, sanitize_external_data

class URLScanProvider(BaseThreatIntelProvider):
    """
    URLScan.io REST API Integration (Section 4).
    Read-only search lookup for domains and URLs.
    """

    def __init__(self):
        super().__init__("URLScan")

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in ("Domain", "URL"):
            return {
                "provider": "URLScan",
                "status": "UNAVAILABLE",
                "reason": f"URLScan search supports Domains and URLs (received {indicator_type})",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "N/A for Non-Domain/URL",
                "raw_summary": "URLScan lookup skipped.",
                "source_url": "https://urlscan.io",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        api_key = os.environ.get("URLSCAN_API_KEY")
        if not api_key:
            return {
                "provider": "URLScan",
                "status": "UNAVAILABLE",
                "reason": "URLSCAN_API_KEY environment variable not configured",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "API key unconfigured",
                "raw_summary": "URLScan lookup skipped (API key not provided).",
                "source_url": "https://urlscan.io",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json"
        }

        query = f"domain:{indicator}" if indicator_type == "Domain" else f"url:\"{indicator}\""

        try:
            resp = requests.get(f"https://urlscan.io/api/v1/search/?q={query}", headers=headers, timeout=8)
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                total = len(results)
                malicious_cnt = 0
                brands = set()

                for item in results[:10]:
                    verdicts = item.get("verdicts", {}).get("overall", {})
                    if verdicts.get("malicious", False):
                        malicious_cnt += 1
                    brand = verdicts.get("brand", "")
                    if brand:
                        brands.add(brand)

                is_malicious = (malicious_cnt > 0)
                risk_score = min(100, malicious_cnt * 30)

                raw_summary = sanitize_external_data(
                    f"URLScan Search Results: Found {total} scan record(s). "
                    f"Malicious Scans: {malicious_cnt}. Detected Target Brands: {', '.join(brands) if brands else 'None'}"
                )

                return {
                    "provider": "URLScan",
                    "status": "LIVE",
                    "malicious": is_malicious,
                    "confidence": 75 if is_malicious else 40,
                    "risk_score": risk_score,
                    "categories": list(brands),
                    "reputation": f"{malicious_cnt}/{total} Scans Flagged Malicious",
                    "raw_summary": raw_summary,
                    "source_url": f"https://urlscan.io/search/#domain:{indicator}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                return {
                    "provider": "URLScan",
                    "status": "UNAVAILABLE",
                    "reason": f"HTTP {resp.status_code}: {resp.text[:100]}",
                    "malicious": None,
                    "confidence": 0,
                    "risk_score": 0,
                    "categories": [],
                    "reputation": f"HTTP Error {resp.status_code}",
                    "raw_summary": f"URLScan API returned status {resp.status_code}.",
                    "source_url": "https://urlscan.io",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
        except Exception as e:
            return {
                "provider": "URLScan",
                "status": "UNAVAILABLE",
                "reason": f"Connection exception: {str(e)}",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "Connection Failed",
                "raw_summary": f"Failed to connect to URLScan API: {str(e)}",
                "source_url": "https://urlscan.io",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
