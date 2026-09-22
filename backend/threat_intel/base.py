import re
import html
from typing import Dict, Any, Optional

def sanitize_external_data(text: str) -> str:
    """
    Sanitizes raw external threat intelligence content to protect against Prompt Injection attacks (Section 13).
    Treats all external intelligence text strictly as data and neutralizes instruction-injection payloads.
    """
    if not isinstance(text, str):
        return str(text)

    # 1. Escape HTML/XML entities
    clean = html.escape(text)

    # 2. Defuse potential prompt-injection command phrases
    injection_patterns = [
        r"(?i)ignore\s+previous\s+instructions",
        r"(?i)disregard\s+all\s+prior",
        r"(?i)system\s+instruction[s]?\s*:",
        r"(?i)system\s+prompt\s*:",
        r"(?i)override\s+all\s+instructions",
        r"(?i)you\s+are\s+now\s+a",
        r"(?i)execute\s+command",
        r"(?i)rm\s+-rf",
        r"(?i)drop\s+table"
    ]

    for pattern in injection_patterns:
        clean = re.sub(pattern, "[DEFUSED_INJECTION_TEXT]", clean)

    return clean[:2000]

def validate_indicator(indicator: str, indicator_type: str = "Unknown") -> Dict[str, str]:
    """
    Validates and normalizes indicator values and types.
    """
    ind = indicator.strip()
    clean_ind = ind.lower()

    # Detect IP
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, ind):
        return {"indicator": ind, "type": "IP"}

    # Detect Hash (MD5, SHA1, SHA256)
    if re.match(r"^[a-fA-F0-9]{32,64}$", ind):
        return {"indicator": ind, "type": "FileHash"}

    # Detect URL
    if clean_ind.startswith("http://") or clean_ind.startswith("https://"):
        return {"indicator": ind, "type": "URL"}

    # Detect Domain
    if "." in ind and not re.match(ip_pattern, ind):
        return {"indicator": clean_ind, "type": "Domain"}

    return {"indicator": ind, "type": indicator_type if indicator_type != "Unknown" else "Domain"}

class BaseThreatIntelProvider:
    """
    Abstract Base Class for Threat Intelligence Providers (Section 1).
    """
    def __init__(self, name: str):
        self.name = name

    def lookup(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement lookup()")
