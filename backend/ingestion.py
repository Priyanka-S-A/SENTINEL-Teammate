import os
import json
import csv
import io
import re
from email import message_from_string
from typing import Dict, Any, List, Tuple
from backend.extractors import extractor_engine

class EvidenceIngestionEngine:
    """
    Accepts security evidence files (CSV, JSON, TXT, EML, PDF) and automatically
    detects format & evidence log type (Requirement #1).
    """

    def auto_classify_log_type(self, filename: str, content: str) -> str:
        content_lower = content.lower()
        fn_lower = filename.lower()

        if fn_lower.endswith('.eml') or 'subject:' in content_lower and ('from:' in content_lower or 'received:' in content_lower):
            return "Phishing Email / Email Header"
        elif 'eventid' in content_lower or 'sysmon' in content_lower or 'powershell' in content_lower or 'process_name' in content_lower or 'cmd.exe' in content_lower:
            return "Endpoint Log / Alert"
        elif 'failed password' in content_lower or 'accepted password' in content_lower or '4624' in content_lower or '4625' in content_lower or 'logon_type' in content_lower or 'auth_status' in content_lower:
            return "Authentication Log"
        elif 'dns' in content_lower or 'qname' in content_lower or 'query_type' in content_lower or 'resolved_ip' in content_lower or 'rrtype' in content_lower:
            return "DNS Query Log"
        elif 'firewall' in content_lower or 'src_ip' in content_lower or 'dst_ip' in content_lower or 'action=' in content_lower or 'iptables' in content_lower:
            return "Firewall Log"
        elif fn_lower.endswith('.pdf') or 'threat intelligence' in content_lower or 'cve-' in content_lower or 'advisory' in content_lower:
            return "Security Intelligence Report"
        else:
            return "Generic Security Log"

    def parse_eml(self, content: str) -> Tuple[str, Dict[str, Any]]:
        msg = message_from_string(content)
        headers = {
            "Subject": msg.get("Subject", ""),
            "From": msg.get("From", ""),
            "To": msg.get("To", ""),
            "Date": msg.get("Date", ""),
            "Message-ID": msg.get("Message-ID", ""),
            "Received": msg.get_all("Received", [])
        }
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore') if msg.get_payload(decode=True) else msg.get_payload()

        full_text = f"Subject: {headers['Subject']}\nFrom: {headers['From']}\nTo: {headers['To']}\nDate: {headers['Date']}\nReceived: {' '.join(headers['Received'])}\n\n{body}"
        return full_text, headers

    def parse_csv(self, content: str) -> str:
        try:
            reader = csv.reader(io.StringIO(content))
            lines = []
            for idx, row in enumerate(reader):
                lines.append(f"Line {idx+1}: " + " | ".join(row))
            return "\n".join(lines)
        except Exception:
            # Fallback for malformed CSV lines
            lines = [f"Line {idx+1}: {line}" for idx, line in enumerate(content.splitlines())]
            return "\n".join(lines)

    def parse_json(self, content: str) -> str:
        try:
            data = json.loads(content)
            if isinstance(data, list):
                lines = [f"Item {idx+1}: " + json.dumps(item) for idx, item in enumerate(data)]
                return "\n".join(lines)
            elif isinstance(data, dict):
                return json.dumps(data, indent=2)
        except Exception:
            pass
        return content

    def parse_pdf_mock(self, content_bytes: bytes) -> str:
        """
        Extracts printable ASCII text from PDF bytes without requiring heavy binary dependencies.
        """
        text_parts = []
        try:
            # Extract readable text strings embedded in PDF streams
            strings = re.findall(rb'[A-Za-z0-9\s\.:;/\-_\(\)@#]{4,}', content_bytes)
            for s in strings[:200]:
                try:
                    decoded = s.decode('utf-8', errors='ignore').strip()
                    if len(decoded) > 5:
                        text_parts.append(decoded)
                except Exception:
                    continue
        except Exception:
            text_parts.append("PDF Document Content Ingested")
        return "\n".join(text_parts) if text_parts else "PDF Document Content Ingested"

    def process_file(self, filename: str, file_bytes: bytes, validate: bool = True) -> Dict[str, Any]:
        """
        Processes security evidence file with defensive security validation (Requirement Phase 6).
        Enforces size limits, extension whitelist, signature checks, path traversal neutralization,
        memory capping, and prompt injection defusing.
        """
        from backend.security import validate_upload_file, MAX_EXTRACTED_TEXT_CHARS, sanitize_prompt_injection

        if validate:
            is_valid, safe_filename, error_msg = validate_upload_file(filename, file_bytes)
            if not is_valid:
                raise ValueError(error_msg)
        else:
            from backend.security import sanitize_filename
            safe_filename = sanitize_filename(filename)

        fn_lower = safe_filename.lower()
        text_content = ""
        metadata = {}

        try:
            if fn_lower.endswith('.eml'):
                raw_str = file_bytes.decode('utf-8', errors='ignore')
                text_content, metadata = self.parse_eml(raw_str)
            elif fn_lower.endswith('.csv'):
                raw_str = file_bytes.decode('utf-8', errors='ignore')
                text_content = self.parse_csv(raw_str)
            elif fn_lower.endswith('.json'):
                raw_str = file_bytes.decode('utf-8', errors='ignore')
                text_content = self.parse_json(raw_str)
            elif fn_lower.endswith('.pdf'):
                text_content = self.parse_pdf_mock(file_bytes)
            else:
                text_content = file_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            text_content = f"[Corrupted Evidence Log] Could not parse content cleanly: {e}\nRaw preview: {file_bytes[:200].decode('utf-8', errors='ignore')}"

        # Enforce memory safety cap on text content
        if len(text_content) > MAX_EXTRACTED_TEXT_CHARS:
            text_content = text_content[:MAX_EXTRACTED_TEXT_CHARS] + "\n[TRUNCATED: Exceeded safe text ingestion size limit]"

        # Defuse prompt injection in ingested text while preserving forensic entities
        defused_text = sanitize_prompt_injection(text_content)

        log_type = self.auto_classify_log_type(safe_filename, defused_text)
        entities = extractor_engine.extract_from_text(defused_text, source_file=safe_filename)

        return {
            "filename": safe_filename,
            "log_type": log_type,
            "raw_text": defused_text,
            "metadata": metadata,
            "entities": entities,
            "entity_count": len(entities)
        }

ingestion_engine = EvidenceIngestionEngine()

