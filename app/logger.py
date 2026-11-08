"""Logging spine. Every guardrail stage writes one structured record here.
This single schema is what powers the dashboard AND the evaluation metrics."""
import json
import os
import time
from threading import Lock

import config

_lock = Lock()


def log_event(user_id, stage, decision, violation_type=None,
              latency_ms=None, scores=None, request_id=None):
    """Append one structured event. Locked for concurrent (stress-test) safety.

    decision:        "allowed" | "blocked" | "redacted"
    violation_type:  None | "injection_sql" | "injection_cmd" | "prompt_injection"
                     | "pii" | "pii_leak" | "toxicity" | "policy"
                     | "suspicious_entropy" | "rate_limit" | "schema"
    """
    record = {
        "ts": round(time.time(), 3),
        "request_id": request_id,
        "user_id": user_id,
        "stage": stage,
        "decision": decision,
        "violation_type": violation_type,
        "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
        "scores": scores,
    }
    os.makedirs(os.path.dirname(config.LOG_PATH), exist_ok=True)
    with _lock:
        with open(config.LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    return record
