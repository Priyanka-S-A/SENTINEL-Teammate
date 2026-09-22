"""
SENTINEL Phase 6: Core Security Hardening Module.
Provides defensive input validation, upload security, prompt injection defusing,
controlled tool execution guardrails, secret scrubbing, and security audit logging.
"""

import os
import re
import logging
from typing import Dict, Any, Tuple, Optional, Set, List

# Setup dedicated security audit logger
SECURITY_LOG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "security_audit.log"
)
os.makedirs(os.path.dirname(SECURITY_LOG_FILE), exist_ok=True)

sec_logger = logging.getLogger("sentinel.security")
sec_logger.setLevel(logging.INFO)
if not sec_logger.handlers:
    fh = logging.FileHandler(SECURITY_LOG_FILE, encoding="utf-8")
    fh.setFormatter(logging.Formatter("[%(asctime)s] [SECURITY] [%(levelname)s] %(message)s"))
    sec_logger.addHandler(fh)

# =============================================================================
# PART 1: UPLOAD & INGESTION SECURITY
# =============================================================================

# Maximum file size: 10 MB per file, 25 MB aggregate
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_TEXT_CHARS = 500_000  # Cap extracted text length to avoid memory exhaustion

# Whitelisted file extensions
ALLOWED_EXTENSIONS = {".eml", ".csv", ".json", ".txt", ".pdf"}

# Executable / Script signatures (Magic bytes & Shebang)
DANGEROUS_SIGNATURES = [
    (b"MZ", "Windows PE Executable / DLL"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"\xca\xfe\xba\xbe", "Java Class / Mach-O Fat Binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit Binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit Binary"),
    (b"#!", "Script Shebang"),
    (b"PK\x03\x04\x14\x00\x08\x00", "Executable Jar / APK"),
]

# Disallowed dangerous extensions even if disguised
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".bash",
    ".py", ".pyw", ".msi", ".dll", ".so", ".dylib", ".scr", ".pif",
    ".com", ".hta", ".cpl", ".jar"
}


def sanitize_filename(filename: str) -> str:
    """
    Strips directory traversal, path separators, null bytes, and control characters.
    """
    if not filename:
        return "unnamed_evidence.txt"
    
    # Strip path elements (Path traversal defense)
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes and control chars
    clean = re.sub(r"[\x00-\x1f\x7f]", "", base)
    # Remove leading dots to prevent hidden files or traversal artifacts
    clean = re.sub(r"^\.+", "", clean)
    # Allow alphanumeric, dot, hyphen, underscore, space
    clean = re.sub(r"[^\w\.\-\s]", "_", clean).strip()
    return clean if clean else "unnamed_evidence.txt"


def validate_upload_file(filename: str, file_bytes: bytes) -> Tuple[bool, str, str]:
    """
    Validates uploaded file against security constraints.
    Returns: (is_valid: bool, sanitized_filename: str, error_message: str)
    """
    # 1. Path Traversal & Safe Filename
    safe_name = sanitize_filename(filename)
    lower_name = safe_name.lower()

    # 2. Extension Whitelist Check
    ext = os.path.splitext(lower_name)[1]
    if ext in DANGEROUS_EXTENSIONS or ext not in ALLOWED_EXTENSIONS:
        msg = f"Rejected upload '{safe_name}': Extension '{ext}' is disallowed. Supported formats: .eml, .csv, .json, .txt, .pdf"
        sec_logger.warning(msg)
        return False, safe_name, msg

    # 3. File Size Limit
    if len(file_bytes) > MAX_SINGLE_FILE_BYTES:
        msg = f"Rejected upload '{safe_name}': File size ({len(file_bytes)} bytes) exceeds 10MB limit."
        sec_logger.warning(msg)
        return False, safe_name, msg

    # 4. Binary Executable & Script Signature Inspection
    header = file_bytes[:16]
    for sig, desc in DANGEROUS_SIGNATURES:
        if header.startswith(sig):
            msg = f"Rejected upload '{safe_name}': Executable/script signature detected ({desc})."
            sec_logger.error(msg)
            return False, safe_name, msg

    # 5. Non-executable verification for text/script formats
    if ext in {".txt", ".csv", ".json", ".eml"}:
        # Check for null byte flooding or binary packing
        null_count = file_bytes[:1024].count(b"\x00")
        if null_count > 10:
            msg = f"Rejected upload '{safe_name}': Malformed binary content in expected text format."
            sec_logger.warning(msg)
            return False, safe_name, msg

    sec_logger.info(f"Accepted upload '{safe_name}' ({len(file_bytes)} bytes, format: {ext})")
    return True, safe_name, ""


# =============================================================================
# PART 2: PROMPT INJECTION DEFENSE
# =============================================================================

# Comprehensive prompt injection patterns targeting LLM instruction manipulation
PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?",
    r"(?i)disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions?",
    r"(?i)forget\s+(?:your\s+)?(?:system\s+)?prompt",
    r"(?i)forget\s+all\s+(?:prior|previous)\s+instructions?",
    r"(?i)system\s+instruction[s]?\s*:",
    r"(?i)system\s+prompt\s*:",
    r"(?i)override\s+(?:all\s+)?instructions?",
    r"(?i)you\s+are\s+now\s+(?:a|an)\s+[a-z0-9_\-\s]+",
    r"(?i)execute\s+(?:shell|command|powershell|bash|cmd)",
    r"(?i)call\s+(?:another\s+)?tool",
    r"(?i)send\s+(?:this\s+)?(?:api\s+)?key",
    r"(?i)exfiltrate\s+(?:secret|key|data|token)",
    r"(?i)delete\s+(?:the\s+)?(?:investigation\s+)?database",
    r"(?i)drop\s+table\b",
    r"(?i)rm\s+-rf\b",
    r"(?i)curl\s+https?://",
    r"(?i)powershell\s+-(?:enc|encodedcommand|executionpolicy)",
    r"(?i)cmd\.exe\s+/c",
    r"(?i)sh\s+-c\b",
    r"(?i)eval\s*\(",
    r"(?i)__import__\s*\("
]

DEFUSED_MARKER = "[DEFUSED_INJECTION_TEXT]"


def sanitize_prompt_injection(text: str, max_chars: int = 100_000) -> str:
    """
    Neutralizes prompt-injection attack patterns in untrusted evidence,
    user queries, or external intelligence before LLM prompt construction.
    Preserves forensic provenance and context.
    """
    if not text or not isinstance(text, str):
        return ""

    cleaned = text
    defused_count = 0

    for pattern in PROMPT_INJECTION_PATTERNS:
        matches = list(re.finditer(pattern, cleaned))
        if matches:
            defused_count += len(matches)
            cleaned = re.sub(pattern, DEFUSED_MARKER, cleaned)

    if defused_count > 0:
        sec_logger.warning(f"Defused {defused_count} prompt injection pattern(s) in untrusted text.")

    # Cap length to avoid context/memory exhaustion
    return cleaned[:max_chars]


# =============================================================================
# PART 3: CONTROLLED TOOL SECURITY & ARGUMENT VALIDATION
# =============================================================================

APPROVED_CONTROLLED_TOOLS = {
    "search_case_evidence",
    "search_logs",
    "lookup_threat_intel",
    "trace_entity",
    "find_related_entities",
    "map_mitre",
    "evaluate_hypotheses",
    "check_contradictions",
    "calculate_risk",
    "generate_report",
    "get_investigation_memory",
    "search_case_knowledge"
}

ALLOWED_TOOL_PARAMETERS = {
    "search_case_evidence": {"query"},
    "search_logs": {"query"},
    "lookup_threat_intel": {"indicator", "indicator_type"},
    "trace_entity": {"entity", "entity_type"},
    "find_related_entities": {"entity", "entity_type"},
    "map_mitre": {"event_or_indicator"},
    "evaluate_hypotheses": set(),
    "check_contradictions": set(),
    "calculate_risk": set(),
    "generate_report": set(),
    "get_investigation_memory": {"query"},
    "search_case_knowledge": {"query"}
}


def validate_tool_call(tool_name: str, tool_args: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Strictly validates tool name and parameters against controlled sandbox rules.
    Returns: (is_valid: bool, error_message: str, cleaned_args: dict)
    """
    # 1. Whitelist tool name check
    if tool_name not in APPROVED_CONTROLLED_TOOLS:
        msg = f"Blocked unauthorized tool call '{tool_name}'. Only the 12 approved controlled tools may be executed."
        sec_logger.error(msg)
        return False, msg, {}

    # 2. Argument whitelist & type check
    allowed_params = ALLOWED_TOOL_PARAMETERS.get(tool_name, set())
    cleaned_args = {}

    if not isinstance(tool_args, dict):
        msg = f"Malformed tool arguments for '{tool_name}': Expected dict, got {type(tool_args).__name__}"
        sec_logger.warning(msg)
        return False, msg, {}

    for k, v in tool_args.items():
        if k not in allowed_params:
            msg = f"Rejected unexpected parameter '{k}' for controlled tool '{tool_name}'."
            sec_logger.warning(msg)
            return False, msg, {}
        
        # Values must be strings or primitives (no executable objects)
        if not isinstance(v, (str, int, float, bool)):
            msg = f"Invalid argument type for parameter '{k}' in tool '{tool_name}': {type(v).__name__}"
            sec_logger.warning(msg)
            return False, msg, {}

        # If string, sanitize null bytes and control chars
        if isinstance(v, str):
            clean_v = v.replace("\x00", "").strip()
            # Reject dangerous command execution flags, subshells, or system calls inside arguments
            if re.search(r"(?i)(?:powershell(?:\.exe)?\s+-(?:enc|encodedcommand|executionpolicy|command|file)|cmd(?:\.exe)?\s+/c|bash\s+-c|sh\s+-c|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.|__import__)", clean_v):
                msg = f"Rejected dangerous command invocation inside tool argument '{k}' for '{tool_name}'."
                sec_logger.error(msg)
                return False, msg, {}
            cleaned_args[k] = clean_v
        else:
            cleaned_args[k] = v

    return True, "", cleaned_args


# =============================================================================
# PART 4: SECRET PROTECTION & SCRUBBING
# =============================================================================

KNOWN_SECRET_ENV_VARS = [
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "ABUSEIPDB_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "DATABASE_URL"
]


def scrub_secrets(val: Any) -> Any:
    """
    Recursively scrubs known API keys and sensitive environment values from strings,
    dictionaries, lists, or error messages.
    """
    if val is None:
        return None

    secrets_to_mask = []
    for var in KNOWN_SECRET_ENV_VARS:
        s = os.environ.get(var)
        if s and len(s) >= 8 and not s.startswith("sqlite"):
            secrets_to_mask.append(s)

    if isinstance(val, str):
        cleaned = val
        for s in secrets_to_mask:
            cleaned = cleaned.replace(s, "[REDACTED_API_KEY]")
        # Mask generic high-entropy API key patterns
        cleaned = re.sub(r"(?i)(?:bearer\s+|key[=:\s]+|apikey[=:\s]+)[a-zA-Z0-9_\-]{20,}", "Bearer [REDACTED_API_KEY]", cleaned)
        return cleaned
    elif isinstance(val, dict):
        return {k: scrub_secrets(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [scrub_secrets(item) for item in val]
    return val


# =============================================================================
# PART 5: API PARAMETER & IDENTIFIER VALIDATION
# =============================================================================

SAFE_ID_REGEX = re.compile(r"^[A-Za-z0-9\-_]{1,64}$")


def validate_case_id(case_id: str) -> bool:
    """
    Ensures case_id conforms strictly to safe alphanumeric identifier rules.
    Rejects path traversals (../), slashes, null bytes, and malicious characters.
    """
    if not case_id or not isinstance(case_id, str):
        return False
    return bool(SAFE_ID_REGEX.match(case_id.strip()))


def validate_action_id(action_id: str) -> bool:
    """
    Ensures action_id conforms strictly to safe alphanumeric identifier rules.
    """
    if not action_id or not isinstance(action_id, str):
        return False
    return bool(SAFE_ID_REGEX.match(action_id.strip()))
