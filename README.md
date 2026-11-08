# Secure AI Gateway

A FastAPI security gateway that sits between client apps and an LLM and enforces layered guardrails on every request — input validation, prompt-injection detection, PII redaction, rate limiting, and output moderation — with every decision logged and measured.

The gateway is model-agnostic: Azure OpenAI by default, or a free local Hugging Face model. All guardrail models are free Hugging Face checkpoints, so no paid API is needed for the safety layer.

```
Client ──► Auth (API key → tier)
       ──► [0] Schema validation        Pydantic, length caps
       ──► [1] Rate limiting            per-user + per-IP, runs before any compute
       ──► [2] Input guardrails         cheap → expensive, first hit short-circuits
               SQL injection regex
               OS-command injection regex
               Shannon-entropy check    catches base64 / obfuscated payloads
               Allow/deny policy gate
               Prompt injection         regex fast-path + DeBERTa-v3 classifier
               PII detect + redact      regex (email, phone, Aadhaar, PAN, card) + BERT NER
       ──► [3] LLM call                 gateway-owned system prompt, user text treated as data
       ──► [4] Output moderation        toxic-bert multi-label + PII-leak re-scan
       ──► Response  (or a fixed safe fallback — raw unsafe output is never returned)

       every stage ──► JSONL logging spine ──► Streamlit security dashboard
```

## Design principles

- **Defense in depth** — no single control is trusted; bypassing one layer still leaves the others.
- **Fail closed** — if a guardrail model errors, the request is blocked, not passed.
- **Cheap before expensive** — rate limits and regex run before any model inference (cost + DoS resistance).
- **Redact, don't just block** — PII is stripped before it reaches the LLM.
- **Re-scan output** — the model's own reply is checked for toxicity and leaked PII.
- **Measured, not claimed** — every guardrail is scored for precision / recall / F1 on a labelled set.

## Guardrail models

| Purpose | Model |
|---|---|
| Prompt-injection detection | [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) |
| Output toxicity (multi-label) | [`unitary/toxic-bert`](https://huggingface.co/unitary/toxic-bert) |
| PII names / locations | [`dslim/bert-base-NER`](https://huggingface.co/dslim/bert-base-NER) |
| Fallback LLM (local) | `Qwen/Qwen2.5-1.5B-Instruct` |

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add Azure OpenAI creds, or set LLM_BACKEND=hf for a free local model
```

**Run the API**

```bash
uvicorn app.main:app --reload --port 8000

curl -X POST localhost:8000/v1/chat \
  -H "x-api-key: demo-free-key" -H "Content-Type: application/json" \
  -d '{"prompt": "What is our refund policy?"}'
```

Response shape:

```json
{"request_id": "a1b2c3d4", "decision": "allowed | blocked | redacted",
 "violation_type": null, "stage": "complete", "latency_ms": 412.7, "response": "..."}
```

**Dashboard** — traffic, blocked vs allowed, violation mix, latency, top-risk users:

```bash
streamlit run dashboard/app.py
```

**Stress test** — mixed safe + malicious traffic; any malicious prompt that gets through is recorded as a failure:

```bash
locust -f stress/locustfile.py --host http://localhost:8000
```

**Tests and evaluation**

```bash
pytest -q                       # unit tests for every detector + rate limiter
python -m eval.evaluate         # full models
python -m eval.evaluate --mock  # regex-only, no model download
```

## Evaluation

`eval/evaluate.py` runs the labelled set in `data/gateway_test_set.csv` (22 prompts: clean queries plus SQL/command injection, prompt injection, PII, policy, entropy and toxicity cases) through the detector stack and reports per-guardrail precision, recall and F1.

Regex-only run (`--mock`):

| Guardrail | Precision | Recall | F1 |
|---|---|---|---|
| injection_cmd | 1.00 | 1.00 | 1.00 |
| injection_sql | 1.00 | 1.00 | 1.00 |
| pii | 1.00 | 1.00 | 1.00 |
| policy | 1.00 | 1.00 | 1.00 |
| prompt_injection | 1.00 | 1.00 | 1.00 |
| suspicious_entropy | 1.00 | 1.00 | 1.00 |
| toxicity | 0.00 | 0.00 | 0.00 |

Exact-match accuracy 20/22 (90.9%). The two misses are toxicity rows: toxicity is handled by the `toxic-bert` output-moderation stage, which the regex-only mode does not load. The test set is small and the numbers show the detectors behave as intended; they are not a robustness benchmark.

## Project structure

```
app/
  main.py                  FastAPI app, API-key auth → tier
  pipeline.py              ordered guardrail pipeline, short-circuit + logging
  llm_client.py            Azure OpenAI / local HF backend
  logger.py                structured JSONL logging spine
  guardrails/
    input_validation.py    schema, SQL/cmd regex, PII regex + redaction, entropy
    ml_guardrails.py       prompt-injection, NER PII, toxicity (lazy-loaded, fail-closed)
    allow_deny.py          policy deny list
    rate_limit.py          sliding-window limiter by tier
config.py                  thresholds, tiers, models, safe system prompt
dashboard/app.py           Streamlit security dashboard
eval/evaluate.py           precision / recall / F1 harness
stress/locustfile.py       load test with rejection-accuracy checks
data/                      labelled test sets (all PII synthetic)
docs/THREAT_MODEL.md       OWASP LLM Top 10 mapping + known limitations
tests/                     pytest unit tests
```

## Threat model and limitations

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the OWASP Top 10 for LLM Applications mapping and an honest list of what this does **not** stop: novel or multilingual injections, semantic PII, toxicity threshold trade-offs, and the single-process rate limiter (production would move it to Redis).

## Security note

All PII in `data/` is synthetic and test card numbers are non-functional. The API keys in `app/main.py` are demo placeholders. Never commit real credentials — `.env` is git-ignored.

## License

[MIT](LICENSE)
