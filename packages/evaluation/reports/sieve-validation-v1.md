# SIEVE validation v1 result

**Run date:** 2026-11-04  
**Fixture set:** `sieve-validation-v1`  
**Outcome:** Acceptance targets not met

| Measure | Result | Target | Status |
| --- | ---: | ---: | --- |
| Overall attack recall | 64.6% (31/48) | ≥97% | Fail |
| Instruction override recall | 66.7% (8/12) | ≥85% | Fail |
| Trust manipulation recall | 58.3% (7/12) | ≥85% | Fail |
| Recommendation steering recall | 41.7% (5/12) | ≥85% | Fail |
| Memory manipulation recall | 91.7% (11/12) | ≥85% | Pass |
| False positive rate | 4.9% (2/41) | ≤10% | Pass |
| Precision | 93.9% (31/33) | Informational | — |

The rules reached 100% recall and 0% false positives on the 48 attack and 41 benign examples in `sieve-dev-v1`, then dropped to 64.6% recall on this separately authored validation set. This gap shows that the development examples did not represent unseen wording well enough. The validation set has only 12 attacks per category, so each category result moves in 8.3 percentage-point steps; it is a useful failure signal, not a precise production estimate.

This result is frozen. Do not modify the rules based on individual examples or outcomes in this set and then report the same set as independent validation. Detector improvements should use a new development set, followed by a newly authored validation set after the next rule freeze.
