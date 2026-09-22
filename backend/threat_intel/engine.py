import time
import logging
from typing import Dict, Any, List

from backend.threat_intel.base import validate_indicator, sanitize_external_data
from backend.threat_intel.virustotal import VirusTotalProvider
from backend.threat_intel.abuseipdb import AbuseIPDBProvider
from backend.threat_intel.urlscan import URLScanProvider
from backend.threat_intel.rdap import RDAPProvider
from backend.threat_intel.mitre import MITREAttackProvider
from backend.database import query_threat_intel_cache, save_threat_intel_to_db

logger = logging.getLogger("sentinel.threat_intel")

class ThreatIntelligenceEngine:
    """
    Modular Multi-Provider Threat Intelligence & IOC Enrichment Engine (Phase 3).
    Supports VirusTotal, AbuseIPDB, URLScan, RDAP/WHOIS, and MITRE ATT&CK.
    Implements multi-provider correlation, caching, DB persistence, and fallback resilience.
    """

    def __init__(self):
        self.vt_provider = VirusTotalProvider()
        self.abuse_provider = AbuseIPDBProvider()
        self.urlscan_provider = URLScanProvider()
        self.rdap_provider = RDAPProvider()
        self.mitre_provider = MITREAttackProvider()

        # Demo synthetic fallback database
        self.synthetic_db = {
            "198.51.100.45": {
                "type": "IP",
                "virustotal": {"malicious_count": 48, "total": 70, "verdict": "MALICIOUS"},
                "abuseipdb": {"score": 94, "reports": 182, "categories": ["C2 Server", "Botnet"]},
                "whois": {"registrar": "BadActor Hosting Ltd", "country": "RU", "age_days": 14},
                "mitre_attck": ["T1071.001 - Web Protocols C2", "T1571 - Non-Standard Port"],
                "interpretation": "CRITICAL RISK: Known Cobalt Strike C2 server actively hosting phishing landing payloads."
            },
            "malicious-phish.net": {
                "type": "Domain",
                "virustotal": {"malicious_count": 52, "total": 70, "verdict": "MALICIOUS"},
                "urlscan": {"verdict": "Credential Harvesting", "target": "Microsoft 365 Login Page"},
                "whois": {"registrar": "NameCheap Inc", "country": "PA", "age_days": 3},
                "mitre_attck": ["T1566.002 - Spearphishing Link", "T1583.001 - Acquire Infrastructure: Domains"],
                "interpretation": "HIGH RISK: Newly registered typosquatted domain used to host fake SSO authentication portals."
            },
            "http://malicious-phish.net/login/update-password.php": {
                "type": "URL",
                "virustotal": {"malicious_count": 41, "total": 70, "verdict": "MALICIOUS"},
                "urlscan": {"verdict": "Phishing Kit", "detected_brand": "Microsoft"},
                "mitre_attck": ["T1566.002 - Spearphishing Link"],
                "interpretation": "HIGH RISK: Direct URL path leading to credential harvesting kit."
            },
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
                "type": "FileHash",
                "virustotal": {"malicious_count": 61, "total": 70, "verdict": "MALICIOUS"},
                "family": "Trojan.PowerShell.Agent",
                "mitre_attck": ["T1059.001 - PowerShell Execution", "T1055 - Process Injection"],
                "interpretation": "CRITICAL RISK: Obfuscated PowerShell stager binary that injects shellcode into memory."
            },
            "10.0.0.15": {
                "type": "IP",
                "virustotal": {"malicious_count": 0, "total": 70, "verdict": "CLEAN"},
                "abuseipdb": {"score": 0, "reports": 0},
                "whois": {"organization": "Internal Corporate Subnet"},
                "interpretation": "BENIGN: Internal workstation IP assigned to Finance Department host."
            }
        }

    def enrich_ioc(self, ioc_value: str, ioc_type: str = "Unknown", case_id: str = "CASE-8421") -> Dict[str, Any]:
        """
        Main entrypoint for read-only threat intelligence enrichment (Tool lookup_threat_intel).
        Checks DB cache first, queries live providers, calculates overall multi-provider risk, and persists results.
        """
        valid = validate_indicator(ioc_value, ioc_type)
        indicator = valid["indicator"]
        itype = valid["type"]

        # 1. CHECK DATABASE CACHE FIRST (Section 10)
        cached_result = query_threat_intel_cache(case_id, indicator)
        if cached_result:
            logger.info(f"Threat Intel Cache Hit for indicator '{indicator}'.")
            return cached_result

        # 2. QUERY LIVE PROVIDERS (Section 1-6)
        provider_results = []
        is_live_hit = False

        # Query VirusTotal
        vt_res = self.vt_provider.lookup(indicator, itype)
        provider_results.append(vt_res)
        if vt_res.get("status") == "LIVE":
            is_live_hit = True

        # Query AbuseIPDB
        abuse_res = self.abuse_provider.lookup(indicator, itype)
        provider_results.append(abuse_res)
        if abuse_res.get("status") == "LIVE":
            is_live_hit = True

        # Query URLScan
        urlscan_res = self.urlscan_provider.lookup(indicator, itype)
        provider_results.append(urlscan_res)
        if urlscan_res.get("status") == "LIVE":
            is_live_hit = True

        # Query RDAP / WHOIS (Works without API key)
        rdap_res = self.rdap_provider.lookup(indicator, itype)
        provider_results.append(rdap_res)
        if rdap_res.get("status") == "LIVE":
            is_live_hit = True

        # Query MITRE ATT&CK
        mitre_res = self.mitre_provider.lookup(indicator, itype)
        provider_results.append(mitre_res)

        # 3. FALLBACK / SYNTHETIC DEMO HANDLING IF LIVE APIS ARE UNAVAILABLE
        overall_status = "LIVE" if is_live_hit else "FALLBACK"
        clean_key = indicator.lower()
        synthetic_match = self.synthetic_db.get(clean_key)

        if not is_live_hit and synthetic_match:
            overall_status = "FALLBACK"
            summary_text = f"FALLBACK DEMO INTELLIGENCE: {synthetic_match['interpretation']}"
            is_malicious = "MALICIOUS" in str(synthetic_match).upper()
            overall_risk = 90 if is_malicious else 10
        elif not is_live_hit:
            overall_status = "UNAVAILABLE"
            summary_text = f"UNAVAILABLE / UNKNOWN: No live API response for indicator '{indicator}'. RDAP/MITRE fallback recorded."
            is_malicious = False
            overall_risk = 30
        else:
            live_malicious = any(p.get("malicious") is True for p in provider_results if p.get("status") == "LIVE")
            is_malicious = live_malicious
            max_risk = max([p.get("risk_score", 0) for p in provider_results if p.get("status") == "LIVE"] or [0])
            overall_risk = max_risk
            summary_text = sanitize_external_data(
                f"Multi-Provider Assessment: Flagged as {'MALICIOUS' if is_malicious else 'CLEAN/INFORMATIONAL'}. "
                f"Evaluated across {len([p for p in provider_results if p.get('status') == 'LIVE'])} live providers."
            )

        # 4. MULTI-PROVIDER CORRELATION (Section 8)
        enriched = {
            "indicator": indicator,
            "indicator_type": itype,
            "status": overall_status,
            "malicious": is_malicious,
            "confidence": 85 if is_live_hit else 60,
            "risk_score": overall_risk,
            "summary": summary_text,
            "virustotal": vt_res if vt_res.get("status") == "LIVE" else (synthetic_match.get("virustotal") if synthetic_match else {"verdict": "UNAVAILABLE"}),
            "abuseipdb": abuse_res if abuse_res.get("status") == "LIVE" else (synthetic_match.get("abuseipdb") if synthetic_match else {"score": 0}),
            "whois": rdap_res if rdap_res.get("status") == "LIVE" else (synthetic_match.get("whois") if synthetic_match else {"registrar": "Unknown"}),
            "urlscan": urlscan_res if urlscan_res.get("status") == "LIVE" else (synthetic_match.get("urlscan") if synthetic_match else {"verdict": "UNAVAILABLE"}),
            "mitre_attck": [t["id"] + " - " + t["name"] for t in mitre_res.get("techniques", [])],
            "providers": provider_results,
            "interpretation": summary_text,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # 5. PERSIST TO DATABASE (Section 9)
        save_threat_intel_to_db(case_id, indicator, itype, overall_status, enriched)

        return enriched

threat_intel_engine = ThreatIntelligenceEngine()
