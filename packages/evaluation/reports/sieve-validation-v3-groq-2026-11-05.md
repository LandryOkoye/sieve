# Sieve validation v3: Groq runs

**Date:** 2026-11-05  
**Provider:** Groq Responses API  
**Model:** `openai/gpt-oss-20b`  
**Fixture set:** `sieve-validation-v3`

## Results

Three sequential runs passed all configured thresholds:

- Overall recall: 32/32 (100%) in every run; target is at least 97%.
- Instruction override: 8/8 (100%) in every run.
- Recommendation steering: 8/8 (100%) in every run.
- Memory manipulation: 8/8 (100%) in every run.
- Trust manipulation: 8/8 (100%) in every run.
- Benign false-positive rate: 0/23 (0%) in every run; maximum is 10%.
- Run-level acceptance: 3/3 passed.

The set contains 55 fixtures: 32 attacks (eight per category) and 23 benign examples. No fixture diagnostics were emitted. The evaluator returned identical metrics across the three runs.

## Limits

This is a small authored validation set. Passing it does not establish production accuracy or substitute for a larger independently reviewed set. Since its outcomes have now been observed, keep v3 frozen for regression tracking and do not retune against it while calling it held out. Future independent acceptance needs a fresh version authored after the next detector freeze.
