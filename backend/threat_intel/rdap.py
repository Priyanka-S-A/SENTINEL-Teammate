import time
import requests
from typing import Dict, Any
from backend.threat_intel.base import BaseThreatIntelProvider, sanitize_external_data

class RDAPProvider(BaseThreatIntelProvider):
    """
    Public RDAP (Registration Data Access Protocol) Integration (Section 5).
    Works WITHOUT an API key. Reads WHOIS / RDAP registration and ASN information.
    """

    def __init__(self):
        super().__init__("RDAP/WHOIS")

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        if indicator_type not in ("Domain", "IP"):
            return {
                "provider": "RDAP/WHOIS",
                "status": "UNAVAILABLE",
                "reason": f"RDAP supports Domains and IPs (received {indicator_type})",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "N/A for Non-Domain/IP",
                "raw_summary": "RDAP lookup skipped for unsupported indicator type.",
                "source_url": "https://rdap.org",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        endpoint = f"https://rdap.org/domain/{indicator}" if indicator_type == "Domain" else f"https://rdap.org/ip/{indicator}"

        try:
            resp = requests.get(endpoint, timeout=6)
            if resp.status_code == 200:
                data = resp.json()

                # Extract registrar
                registrar = "Unknown Registrar"
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break

                # Extract registration dates
                events = data.get("events", [])
                created_date = "Unknown"
                for ev in events:
                    if ev.get("eventAction") in ("registration", "transfer"):
                        created_date = ev.get("eventDate", "Unknown")[:10]
                        break

                nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if ns.get("ldhName")][:3]
                status_list = data.get("status", [])[:3]

                raw_summary = sanitize_external_data(
                    f"RDAP Registrar: {registrar}. Registration Date: {created_date}. "
                    f"Domain Status: {', '.join(status_list) if status_list else 'Active'}. "
                    f"Nameservers: {', '.join(nameservers) if nameservers else 'Standard'}"
                )

                return {
                    "provider": "RDAP/WHOIS",
                    "status": "LIVE",
                    "malicious": False,
                    "confidence": 80,
                    "risk_score": 0,
                    "categories": ["Registration Data"],
                    "reputation": f"Registrar: {registrar} (Registered: {created_date})",
                    "raw_summary": raw_summary,
                    "source_url": f"https://rdap.org/domain/{indicator}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                return {
                    "provider": "RDAP/WHOIS",
                    "status": "UNAVAILABLE",
                    "reason": f"HTTP {resp.status_code}: {resp.text[:100]}",
                    "malicious": None,
                    "confidence": 0,
                    "risk_score": 0,
                    "categories": [],
                    "reputation": f"HTTP Error {resp.status_code}",
                    "raw_summary": f"RDAP query returned status {resp.status_code}.",
                    "source_url": "https://rdap.org",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
        except Exception as e:
            return {
                "provider": "RDAP/WHOIS",
                "status": "UNAVAILABLE",
                "reason": f"Connection exception: {str(e)}",
                "malicious": None,
                "confidence": 0,
                "risk_score": 0,
                "categories": [],
                "reputation": "Connection Failed",
                "raw_summary": f"Failed to connect to RDAP service: {str(e)}",
                "source_url": "https://rdap.org",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
