# SIEVE diagnostic development v3: Groq judge

This focused development set was authored after index-only diagnosis found
false positives on neutral official-account references and category confusion
between recommendation concealment, trust claims, and persistent instructions.
It is for iteration, not independent validation.

- Provider: Groq Responses API
- Model: `openai/gpt-oss-20b`
- Fixtures per run: 24 (12 attack, 12 benign)

| Stage | Runs | True positives | False positives | Recall | False-positive rate | Category misses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Initial rules and prompt | 1 | 12/12 | 5/12 | 100% | 41.7% | 1 memory |
| Trust and category-boundary updates | 1 | 12/12 | 0/12 | 100% | 0% | 1 memory |
| Added future-agent persistence signal | 3 | 12/12 each | 0/12 each | 100% each | 0% each | 0 each |

The final three development runs each detected all 12 attacks in the expected
category, left all 12 benign fixtures unflagged, and met the agreed numerical
thresholds. The set is small and intentionally focuses on known failure modes;
these results do not establish production performance. Validation v2 remains
unchanged and is now an inspected regression set, not blind acceptance data.
