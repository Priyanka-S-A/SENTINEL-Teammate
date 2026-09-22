import re
from typing import List, Dict, Any

# Regex patterns for deterministic extraction
IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|co|xyz|info|biz|cc|tech|online|ru|cn|live|top|site|app|dev|store)\b'
URL_PATTERN = r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\']*)?'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'
TIMESTAMP_PATTERN = r'\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\b'
USER_PATTERN = r'\b(?:user|username|account|subj)=([a-zA-Z0-9_\.\\\-]+)|user:\s*([a-zA-Z0-9_\.\\\-]+)|([a-zA-Z0-9\._\-]+@(?:corp|internal|local))\b'

# Known benign domains to filter out from noise
BENIGN_DOMAINS = {'microsoft.com', 'windowsupdate.com', 'google.com', 'github.com', 'schema.org', 'w3.org', 'example.com', 'localhost'}

class EntityExtractor:
    """
    Deterministic extraction engine to parse security entities from text lines.
    Retains line number, character offsets, source file, and contextual metadata.
    """
    def __init__(self):
        self.ip_regex = re.compile(IP_PATTERN)
        self.domain_regex = re.compile(DOMAIN_PATTERN, re.IGNORECASE)
        self.url_regex = re.compile(URL_PATTERN, re.IGNORECASE)
        self.email_regex = re.compile(EMAIL_PATTERN, re.IGNORECASE)
        self.sha256_regex = re.compile(SHA256_PATTERN)
        self.md5_regex = re.compile(MD5_PATTERN)
        self.cve_regex = re.compile(CVE_PATTERN, re.IGNORECASE)
        self.timestamp_regex = re.compile(TIMESTAMP_PATTERN)

    def extract_from_text(self, text: str, source_file: str = "raw_input") -> List[Dict[str, Any]]:
        entities = []
        lines = text.splitlines()

        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue

            # Find Timestamps
            ts_matches = self.timestamp_regex.findall(line)
            ts_val = ts_matches[0] if ts_matches else None

            # Find IPs
            for match in self.ip_regex.finditer(line):
                ip = match.group(0)
                # Ignore loopback/broadcast if needed, keep internal/external
                if not (ip.startswith('127.') or ip == '0.0.0.0' or ip == '255.255.255.255'):
                    entities.append({
                        "type": "IP",
                        "value": ip,
                        "line_num": line_num,
                        "source_file": source_file,
                        "timestamp": ts_val,
                        "raw_line": line.strip()
                    })

            # Find URLs
            urls_found = set()
            for match in self.url_regex.finditer(line):
                url = match.group(0)
                urls_found.add(url)
                entities.append({
                    "type": "URL",
                    "value": url,
                    "line_num": line_num,
                    "source_file": source_file,
                    "timestamp": ts_val,
                    "raw_line": line.strip()
                })

            # Find Domains (ignoring domains already embedded inside matched URLs)
            for match in self.domain_regex.finditer(line):
                domain = match.group(0).lower()
                if domain in BENIGN_DOMAINS:
                    continue
                # Check if this domain is part of an extracted URL
                if not any(domain in u for u in urls_found):
                    entities.append({
                        "type": "Domain",
                        "value": domain,
                        "line_num": line_num,
                        "source_file": source_file,
                        "timestamp": ts_val,
                        "raw_line": line.strip()
                    })

            # Find Emails
            for match in self.email_regex.finditer(line):
                email = match.group(0).lower()
                entities.append({
                    "type": "Email",
                    "value": email,
                    "line_num": line_num,
                    "source_file": source_file,
                    "timestamp": ts_val,
                    "raw_line": line.strip()
                })

            # Find File Hashes
            for match in self.sha256_regex.finditer(line):
                entities.append({
                    "type": "FileHash",
                    "value": match.group(0).lower(),
                    "hash_type": "SHA256",
                    "line_num": line_num,
                    "source_file": source_file,
                    "timestamp": ts_val,
                    "raw_line": line.strip()
                })

            for match in self.md5_regex.finditer(line):
                # Avoid collision with sha256 substring
                val = match.group(0).lower()
                if not any(val in e['value'] for e in entities if e['type'] == 'FileHash'):
                    entities.append({
                        "type": "FileHash",
                        "value": val,
                        "hash_type": "MD5",
                        "line_num": line_num,
                        "source_file": source_file,
                        "timestamp": ts_val,
                        "raw_line": line.strip()
                    })

            # Find CVEs
            for match in self.cve_regex.finditer(line):
                entities.append({
                    "type": "CVE",
                    "value": match.group(0).upper(),
                    "line_num": line_num,
                    "source_file": source_file,
                    "timestamp": ts_val,
                    "raw_line": line.strip()
                })

            # Usernames & PowerShell/Suspicious keywords
            if 'powershell' in line.lower() or 'encodedcommand' in line.lower() or 'cmd.exe' in line.lower() or 'mimikatz' in line.lower():
                entities.append({
                    "type": "SuspiciousKeyword",
                    "value": "Powershell/Execution Keyword",
                    "line_num": line_num,
                    "source_file": source_file,
                    "timestamp": ts_val,
                    "raw_line": line.strip()
                })

        return entities

    # Alias for backward compatibility
    extract_all = extract_from_text

extractor_engine = EntityExtractor()
