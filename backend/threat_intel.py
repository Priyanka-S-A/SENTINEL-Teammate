"""
Backward compatibility bridge module for backend/threat_intel.py.
Delegates threat intelligence enrichment calls to the modular backend.threat_intel package.
"""

from backend.threat_intel.engine import threat_intel_engine, ThreatIntelligenceEngine

__all__ = ["threat_intel_engine", "ThreatIntelligenceEngine"]
