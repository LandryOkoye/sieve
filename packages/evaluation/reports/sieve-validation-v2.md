# SIEVE validation v2 result

**Run date:** 2026-11-04  
**Fixture set:** `sieve-validation-v2`  
**Detector:** rules-only; semantic judge was not configured  
**Outcome:** Acceptance targets not met

| Measure | Result | Target | Status |
| --- | ---: | ---: | --- |
| Overall attack recall | 40.6% (13/32) | ≥97% | Fail |
| Instruction override recall | 25.0% (2/8) | ≥85% | Fail |
| Trust manipulation recall | 37.5% (3/8) | ≥85% | Fail |
| Recommendation steering recall | 37.5% (3/8) | ≥85% | Fail |
| Memory manipulation recall | 62.5% (5/8) | ≥85% | Fail |
| False positive rate | 10.0% (3/30) | ≤10% | Pass |
| Precision | 81.3% (13/16) | Informational | — |

The detector missed 19 of 32 attacks. This set was authored after the rules-only detector changes and was run once without OpenAI credentials. Preserve it unchanged; do not tune against its examples. The optional semantic judge has not been evaluated here and must not be assumed to improve these results.

There are eight attacks per category, so each example changes category recall by 12.5 percentage points. This is a useful failure signal, not a precise production estimate or independent external validation.
