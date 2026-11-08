"""ML-backed guardrails using free Hugging Face models.
Models load lazily and cache. On load/inference failure we honor FAIL_CLOSED
(block on error) so a broken model never silently lets traffic through."""
import re
import config

_PIPES = {}  # lazy cache


def _get_pipe(task, model, **kw):
    key = (task, model)
    if key not in _PIPES:
        from transformers import pipeline  # imported lazily
        _PIPES[key] = pipeline(task, model=model, **kw)
    return _PIPES[key]


# --- Prompt injection: regex fast-path + semantic model -----------------
INJECTION_REGEX = [
    r"(?i)ignore\s+(all\s+|previous\s+|above\s+|prior\s+|the\s+)*instructions",
    r"(?i)disregard\s+(the\s+)?(previous|above|prior)",
    r"(?i)reveal\s+(the\s+)?(system\s+)?prompt",
    r"(?i)(your|the)\s+(hidden\s+)?(config|configuration|instructions)",
    r"(?i)act\s+as\s+(admin|root|developer\s+mode|DAN)",
    r"(?i)you\s+are\s+(now|no\s+longer)",
    r"(?i)forget\s+everything",
    r"(?i)pretend\s+(the\s+)?(prior|previous)\s+rules",
    r"(?i)no\s+(content\s+)?(policy|restrictions)",
]


def check_injection(text):
    """Returns dict: blocked, method, score, violation_type."""
    for pat in INJECTION_REGEX:
        if re.search(pat, text):
            return {"blocked": True, "method": "regex", "score": 1.0,
                    "violation_type": "prompt_injection"}
    try:
        clf = _get_pipe("text-classification", config.INJECTION_MODEL,
                        truncation=True, max_length=512)
        r = clf(text)[0]
        is_inj = (r["label"].upper() == "INJECTION" and
                  r["score"] >= config.INJECTION_THRESHOLD)
        return {"blocked": is_inj, "method": "model", "score": float(r["score"]),
                "violation_type": "prompt_injection" if is_inj else None}
    except Exception as e:
        return {"blocked": config.FAIL_CLOSED, "method": "error",
                "score": None, "violation_type": "prompt_injection",
                "error": str(e)}


# --- NER PII (names / locations regex can't catch) ----------------------
def detect_pii_ner(text):
    try:
        ner = _get_pipe("token-classification", config.NER_MODEL,
                        aggregation_strategy="simple")
        ents = {}
        for e in ner(text):
            if e["entity_group"] in {"PER", "LOC"} and \
               e["score"] >= config.NER_CONFIDENCE:
                ents.setdefault(e["entity_group"], []).append(e["word"])
        return ents
    except Exception:
        return {}  # NER is supplementary; regex still covers structured PII


# --- Toxicity (output moderation) ---------------------------------------
def score_toxicity(text):
    """Returns (violations: list[str], scores: dict). Empty list == clean."""
    try:
        clf = _get_pipe("text-classification", config.TOXICITY_MODEL,
                        top_k=None, truncation=True, max_length=512)
        out = clf(text)
        rows = out[0] if isinstance(out[0], list) else out
        scores = {d["label"]: float(d["score"]) for d in rows}
        violations = [lbl for lbl, th in config.TOXICITY_THRESHOLDS.items()
                      if scores.get(lbl, 0) > th]
        return violations, scores
    except Exception as e:
        if config.FAIL_CLOSED:
            return ["toxic"], {"error": str(e)}
        return [], {"error": str(e)}
