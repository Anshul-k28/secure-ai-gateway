"""Core gateway pipeline. Implements the corrected ordered flow:

  auth/tier -> [1] rate limit -> [2] input guardrails (cheap->expensive)
  -> redact PII -> [3] LLM -> [4] output moderation -> response

Every stage can REJECT (short-circuit to safe fallback) and every decision
is logged. This ordering is deliberate: rate limiting and cheap regex run
before any expensive model inference (defense in depth + cost control)."""
import time
import uuid

import config
from app.logger import log_event
from app.llm_client import call_llm
from app.guardrails import input_validation as iv
from app.guardrails import ml_guardrails as ml
from app.guardrails import allow_deny as ad
from app.guardrails.rate_limit import limiter


class GatewayResult:
    def __init__(self, response, decision, violation_type=None,
                 stage=None, request_id=None, latency_ms=None, scores=None):
        self.response = response
        self.decision = decision            # allowed | blocked | redacted
        self.violation_type = violation_type
        self.stage = stage
        self.request_id = request_id
        self.latency_ms = latency_ms
        self.scores = scores

    def as_dict(self):
        return self.__dict__


def _reject(user_id, stage, vtype, rid, t0, scores=None):
    lat = (time.time() - t0) * 1000
    log_event(user_id, stage, "blocked", vtype, lat, scores, rid)
    return GatewayResult(config.SAFE_FALLBACK, "blocked", vtype, stage,
                         rid, lat, scores)


def process(user_id, prompt, tier="free", client_ip="0.0.0.0"):
    """Run a single request through the full guardrail pipeline."""
    rid = str(uuid.uuid4())[:8]
    t0 = time.time()

    # --- [0] Schema validation -----------------------------------------
    try:
        req = iv.ChatRequest(user_id=user_id, prompt=prompt, tier=tier)
    except Exception:
        return _reject(user_id, "schema", "schema", rid, t0)

    # --- [1] Rate limiting (FIRST: before any compute) -----------------
    if not limiter.allow(user_id, tier):
        return _reject(user_id, "rate_limit", "rate_limit", rid, t0)
    if not limiter.allow(f"ip:{client_ip}", tier):
        return _reject(user_id, "rate_limit", "rate_limit", rid, t0)

    text = req.prompt

    # --- [2] Input guardrails: cheap regex first -----------------------
    if iv.detect_sql(text)[0]:
        return _reject(user_id, "input", "injection_sql", rid, t0)
    if iv.detect_cmd(text)[0]:
        return _reject(user_id, "input", "injection_cmd", rid, t0)
    if iv.detect_entropy(text)[0]:
        return _reject(user_id, "input", "suspicious_entropy", rid, t0)
    if ad.deny_check(text)[0]:
        return _reject(user_id, "input", "policy", rid, t0)

    # --- [2b] Prompt injection: regex fast-path + semantic model -------
    inj = ml.check_injection(text)
    if inj["blocked"]:
        return _reject(user_id, "input", "prompt_injection", rid, t0,
                       {"injection_score": inj["score"], "method": inj["method"]})

    # --- [2c] PII: detect (regex + NER), then REDACT before LLM --------
    pii = iv.detect_pii_regex(text)
    pii_ner = ml.detect_pii_ner(text)
    safe_prompt = text
    pii_redacted = False
    if pii or pii_ner:
        safe_prompt = iv.redact_pii(text)
        pii_redacted = True
        log_event(user_id, "input", "redacted", "pii",
                  (time.time() - t0) * 1000,
                  {"regex": list(pii.keys()), "ner": list(pii_ner.keys())}, rid)

    # --- [3] LLM call ---------------------------------------------------
    try:
        raw = call_llm(config.SAFE_SYSTEM_PROMPT, safe_prompt)
    except Exception as e:
        return _reject(user_id, "llm", "llm_error", rid, t0, {"error": str(e)})

    # --- [4] Output moderation -----------------------------------------
    tox_violations, tox_scores = ml.score_toxicity(raw)
    if tox_violations:
        return _reject(user_id, "output", "toxicity", rid, t0, tox_scores)

    # PII leak re-scan: the model must not echo sensitive data back
    leak = iv.detect_pii_regex(raw)
    if leak:
        return _reject(user_id, "output", "pii_leak", rid, t0,
                       {"leaked": list(leak.keys())})

    # --- Safe response --------------------------------------------------
    lat = (time.time() - t0) * 1000
    decision = "redacted" if pii_redacted else "allowed"
    log_event(user_id, "complete", "allowed", None, lat, tox_scores, rid)
    return GatewayResult(raw, decision, None, "complete", rid, lat, tox_scores)
