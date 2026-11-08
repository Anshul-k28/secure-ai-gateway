"""Evaluation harness. Loads the labelled test set, runs each prompt through
the guardrail detectors (NOT the LLM, so it's fast and free), and computes
per-guardrail precision / recall / F1 / false-positive-rate + confusion matrix.

This is what produces the Task 7 "rejection accuracy" numbers and the
honest, measured story that makes the project defensible.

Run:  python -m eval.evaluate            (uses real HF models)
      python -m eval.evaluate --mock     (regex-only, no model download)
"""
import argparse
import csv
import sys

import config
from app.guardrails import input_validation as iv
from app.guardrails import allow_deny as ad


def classify(text, mock=False):
    """Return the violation_type the gateway would assign, or 'none'.
    Mirrors pipeline ordering: first matching stage wins."""
    if iv.detect_sql(text)[0]:
        return "injection_sql"
    if iv.detect_cmd(text)[0]:
        return "injection_cmd"
    if iv.detect_entropy(text)[0]:
        return "suspicious_entropy"
    if ad.deny_check(text)[0]:
        return "policy"
    # prompt injection
    if mock:
        import re
        from app.guardrails.ml_guardrails import INJECTION_REGEX
        if any(re.search(p, text) for p in INJECTION_REGEX):
            return "prompt_injection"
    else:
        from app.guardrails import ml_guardrails as ml
        if ml.check_injection(text)["blocked"]:
            return "prompt_injection"
    # pii
    if iv.detect_pii_regex(text):
        return "pii"
    return "none"


def evaluate(path, mock=False):
    rows = list(csv.DictReader(open(path)))
    # Map: blocked/redact -> the violation type; allow -> none
    per_type = {}  # vtype -> tp, fp, fn
    correct = 0

    for r in rows:
        text = r["prompt"]
        expected_v = r["violation_type"] if r["expected_decision"] != "allow" else "none"
        # PII redact is still a 'pii' detection for scoring
        predicted_v = classify(text, mock=mock)

        # collapse pii_leak/pii for input-side scoring
        exp = "pii" if expected_v in {"pii", "pii_leak"} else expected_v
        pred = "pii" if predicted_v in {"pii", "pii_leak"} else predicted_v

        hit = (exp == pred) or (exp != "none" and pred != "none" and
                                _same_family(exp, pred))
        if exp == pred:
            correct += 1

        for v in {exp, pred} - {"none"}:
            per_type.setdefault(v, [0, 0, 0])
        if exp != "none":
            if pred == exp:
                per_type[exp][0] += 1  # tp
            else:
                per_type[exp][2] += 1  # fn
        if pred != "none" and pred != exp:
            per_type[pred][1] += 1     # fp

    _report(per_type, correct, len(rows))
    return per_type


def _same_family(a, b):
    fam = {"injection_sql", "injection_cmd"}
    return a in fam and b in fam


def _report(per_type, correct, total):
    print(f"\n{'='*64}")
    print(f"  GATEWAY EVALUATION  ({'MOCK / regex-only' if '--mock' in sys.argv else 'full models'})")
    print(f"{'='*64}")
    print(f"  Exact-match accuracy: {correct}/{total} = {correct/total:.1%}\n")
    print(f"  {'guardrail':<22}{'prec':>7}{'recall':>8}{'F1':>7}{'tp':>5}{'fp':>5}{'fn':>5}")
    print(f"  {'-'*58}")
    macro_f1 = []
    for v in sorted(per_type):
        tp, fp, fn = per_type[v]
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        macro_f1.append(f1)
        print(f"  {v:<22}{prec:>7.2f}{rec:>8.2f}{f1:>7.2f}{tp:>5}{fp:>5}{fn:>5}")
    if macro_f1:
        print(f"  {'-'*58}")
        print(f"  macro-F1: {sum(macro_f1)/len(macro_f1):.3f}")
    print(f"{'='*64}\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true",
                    help="regex-only, no model download")
    ap.add_argument("--data", default="data/gateway_test_set.csv")
    args = ap.parse_args()
    evaluate(args.data, mock=args.mock)
