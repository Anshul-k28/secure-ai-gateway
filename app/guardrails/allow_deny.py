"""Allow/deny lists and safe prompt policy. Deterministic keyword/topic gate."""

DENY_KEYWORDS = {
    "bomb", "weapon", "explosive", "sudo", "passwd",
    "/etc/shadow", "ssn", "social security", "kill", "malware",
}

# Optional: zero-shot topic gate (bart-mnli) belongs HERE, not in injection.
ALLOW_TOPICS = {"billing", "account", "product", "support", "policy",
                "finance", "report", "general inquiry"}


def deny_check(text):
    """Returns (blocked: bool, violation_type)."""
    low = text.lower()
    if any(k in low for k in DENY_KEYWORDS):
        return (True, "policy")
    return (False, "policy")
