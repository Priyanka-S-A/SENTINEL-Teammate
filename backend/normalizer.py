from typing import List, Dict, Any

class EvidenceNormalizer:
    """
    Normalizes multi-source evidence into unified common internal schema (Requirement #3):
    timestamp -> source -> entity -> event -> severity -> relationship
    """

    def normalize_extracted_entities(self, ingested_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized_events = []
        event_counter = 1

        for file_data in ingested_files:
            source_file = file_data["filename"]
            source_type = file_data["log_type"]
            raw_text = file_data.get("raw_text", "")
            entities = file_data.get("entities", [])

            for ent in entities:
                ent_type = ent["type"]
                ent_val = ent["value"]
                ts = ent.get("timestamp") or "2026-09-14 10:00:00"
                raw_line = ent.get("raw_line", "")

                # Determine Event Action, Severity, Target, Relationship based on log_type & entity
                event_action = "Observed Indicator"
                severity = "INFO"
                target_entity = None
                rel_type = "associated_with"

                if "Email" in source_type:
                    if ent_type in ("Email", "Domain"):
                        event_action = "Phishing Email Delivery"
                        severity = "HIGH"
                        rel_type = "sent_to"
                    elif ent_type == "URL":
                        event_action = "Malicious Link Embedded"
                        severity = "HIGH"
                        rel_type = "embedded_in"
                elif "DNS" in source_type:
                    event_action = "DNS Domain Resolution"
                    severity = "MEDIUM" if ent_type in ("Domain", "IP") else "INFO"
                    rel_type = "resolved_to"
                elif "Firewall" in source_type:
                    event_action = "Network Connection Attempt"
                    if "ALLOW" in raw_line.upper():
                        severity = "HIGH" if ent_type in ("IP", "Domain") else "MEDIUM"
                        event_action = "Outbound Network Traffic Allowed"
                        rel_type = "connected_to"
                    else:
                        severity = "LOW"
                        event_action = "Outbound Network Connection Blocked"
                        rel_type = "attempted_connection_to"
                elif "Authentication" in source_type:
                    if "FAILED" in raw_line.upper() or "4625" in raw_line:
                        event_action = "Failed Login Attempt"
                        severity = "HIGH"
                        rel_type = "failed_auth_from"
                    elif "ACCEPTED" in raw_line.upper() or "4624" in raw_line:
                        event_action = "Successful Login / Auth"
                        severity = "MEDIUM"
                        rel_type = "authenticated_from"
                elif "Endpoint" in source_type:
                    if "POWERSHELL" in raw_line.upper() or "CMD.EXE" in raw_line.upper():
                        event_action = "Suspicious Shell Command Executed"
                        severity = "CRITICAL"
                        rel_type = "executed_on"
                    elif ent_type == "FileHash":
                        event_action = "Suspicious File Execution"
                        severity = "HIGH"
                        rel_type = "executed_hash"
                    else:
                        event_action = "Endpoint Alert Triggered"
                        severity = "HIGH"
                elif "Intelligence" in source_type:
                    event_action = "Threat Intelligence Reference"
                    severity = "HIGH" if ent_type == "CVE" else "MEDIUM"
                    rel_type = "references_cve"

                normalized_events.append({
                    "id": f"EVT-{event_counter:04d}",
                    "timestamp": ts,
                    "source_file": source_file,
                    "source_type": source_type,
                    "entity_type": ent_type,
                    "entity_value": ent_val,
                    "event_action": event_action,
                    "severity": severity,
                    "target_entity": target_entity,
                    "relationship": rel_type,
                    "raw_ref": f"{source_file}:L{ent.get('line_num', 1)} - {raw_line[:120]}"
                })
                event_counter += 1

        # Sort chronologically
        normalized_events.sort(key=lambda x: str(x["timestamp"]))
        return normalized_events

    # Alias for convenience
    normalize_events = normalize_extracted_entities

normalizer = EvidenceNormalizer()
