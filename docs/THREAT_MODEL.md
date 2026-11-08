# Threat Model & Known Limitations

> The most important document in this project. A guardrail system that *claims*
> to be unbreakable signals inexperience. One that states precisely what it
> stops, what its measured miss rate is, and what defeats it signals security
> maturity. This is what we defend in the viva.

## 1. Security posture

The gateway uses **defense in depth**: no single control is trusted. A prompt
must clear rate limiting, schema validation, regex injection/PII checks, an
entropy check, an allow/deny gate, a semantic injection classifier, and
post-generation output moderation. Bypassing one layer still leaves the others.

Design principles:
- **Fail closed** — if a guardrail model errors, traffic is blocked, not passed.
- **Treat user text as data, not instructions** (enforced in the system prompt).
- **Cheap before expensive** — regex runs before model inference (cost + DoS resistance).
- **Redact, don't just block** — PII is stripped before reaching the LLM.
- **Re-scan output** — the model's own response is checked for toxicity and PII leakage.

## 2. Mapping to OWASP Top 10 for LLM Applications

| OWASP risk | Control in this gateway |
|---|---|
| LLM01 Prompt Injection | regex fast-path + `deberta-v3-prompt-injection-v2` + hardened system prompt |
| LLM02 Insecure Output Handling | output moderation stage (`toxic-bert`) + PII leak re-scan |
| LLM04 Model Denial of Service | rate limiting (per-user + per-IP) runs first; entropy check on payloads |
| LLM06 Sensitive Information Disclosure | regex + NER PII detection, redaction before LLM, leak re-scan after |
| LLM07 Insecure Plugin/Code Exec | SQL + command-injection regex; deny list |
| LLM09 Overreliance | dashboard + logging give human reviewers visibility into every decision |

## 3. What this system does NOT stop (honest limitations)

1. **Novel / heavily-obfuscated injection.** The classifier is strong on known
   attack families but a sufficiently novel paraphrase or multilingual attack
   can evade it. Measured recall on our paraphrased-injection rows is below 1.0
   (see eval output) — we report this number rather than hide it.
2. **Semantic PII the regex + NER miss.** "The CEO's daughter who studies at the
   downtown campus" is identifying without containing a structured identifier.
3. **Toxicity threshold trade-off.** Lowering thresholds raises recall but also
   false positives — we tune on the labelled set and report the operating point,
   not a single cherry-picked number.
4. **In-memory rate limiter is single-process.** Production needs Redis so limits
   hold across replicas. (Code is structured for a drop-in swap.)
5. **Output moderation is English-centric** (model limitation).
6. **No defense against a compromised LLM backend** — out of scope; we trust Azure.

## 4. How we'd close the gaps (next steps)

- Continuously expand the adversarial test set; retrain/fine-tune the injection
  classifier on misses (active learning loop).
- Add a canary-token / system-prompt-leak detector on output.
- Add semantic similarity to a known-attack bank for zero-day-ish coverage.
- Move rate limiting + logging to Redis; add per-tenant quotas.
- Human-in-the-loop review queue for borderline scores.

## 5. Evaluation methodology

Every prompt in `data/gateway_test_set.csv` carries an `expected_decision` and
`violation_type` label. `eval/evaluate.py` runs the detector stack over the set
and reports **per-guardrail precision, recall, F1, and false-positive rate**
plus a confusion matrix. This is the project's central evidence: we don't claim
safety, we measure it.
