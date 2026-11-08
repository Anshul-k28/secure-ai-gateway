"""Input validation: deterministic, fast, no ML. Runs first inside input guardrails.
Each detector returns (is_violation: bool, violation_type: str | None)."""
import math
import re

from pydantic import BaseModel, field_validator
import config

# --- Schema validation ---------------------------------------------------
class ChatRequest(BaseModel):
    user_id: str
    prompt: str
    tier: str = "free"

    @field_validator("prompt")
    @classmethod
    def _len(cls, v):
        if not v or not v.strip():
            raise ValueError("empty_prompt")
        if len(v) > config.MAX_PROMPT_LEN:
            raise ValueError("prompt_too_long")
        return v


# --- Regex detectors -----------------------------------------------------
SQL_PATTERNS = [
    r"(?i)\bDROP\s+TABLE\b", r"(?i)\bUNION\s+SELECT\b",
    r"(?i)\bDELETE\s+FROM\b", r"(?i)\bINSERT\s+INTO\b",
    r"'\s*OR\s*'?1'?\s*=\s*'?1", r"(?i);\s*--",
]
CMD_PATTERNS = [
    r"rm\s+-rf", r";\s*cat\s+/etc", r"&&\s*curl", r"\|\s*sh\b",
    r"(?i)\bos\.system\b", r"(?i)\bsubprocess\b", r">\s*/dev/null",
    r"(?i)\bshutdown\b",
]
PII_REGEX = {
    "email": r"[\w.+-]+@[\w-]+\.[\w.-]+",
    "phone": r"(?:\+91[-\s]?)?[6-9]\d{9}",
    "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "pan": r"\b[A-Z]{5}\d{4}[A-Z]\b",
    "credit_card": r"\b(?:\d[ -]?){13,16}\b",
}


def detect_sql(text):
    return (any(re.search(p, text) for p in SQL_PATTERNS), "injection_sql")


def detect_cmd(text):
    return (any(re.search(p, text) for p in CMD_PATTERNS), "injection_cmd")


def detect_pii_regex(text):
    found = {lbl: re.findall(p, text) for lbl, p in PII_REGEX.items()
             if re.search(p, text)}
    return found  # dict; empty == no PII


def redact_pii(text):
    for lbl, pat in PII_REGEX.items():
        text = re.sub(pat, f"[{lbl.upper()}_REDACTED]", text)
    return text


def shannon_entropy(text):
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def detect_entropy(text):
    """High entropy on a long contiguous token => likely base64/obfuscated payload."""
    for token in text.split():
        if len(token) >= config.ENTROPY_MIN_LEN and \
           shannon_entropy(token) > config.ENTROPY_THRESHOLD:
            return (True, "suspicious_entropy")
    return (False, "suspicious_entropy")
