# Evaluation policy

The current acceptance targets are:

- Overall attack recall of at least 97%.
- Recall of at least 85% in each of the four threat categories.
- False-positive rate of at most 10% on benign fixtures.

The evaluator returns each threshold and a pass/fail result for every criterion. These are development targets, not a production safety certification. Small fixture sets have coarse percentage steps and cannot establish production accuracy; a release decision requires a larger, reviewed validation set kept separate from detector tuning.

`sieve-baseline-v1` is a small regression set. The examples formerly labeled `sieve-heldout-v1` were inspected and used during development; `sieve-variants-v1` is their clearer version name, while the legacy name remains accepted for existing runs. `sieve-dev-v1`, `sieve-dev-v2`, and diagnostic-guided `sieve-dev-v3` are development sets. `sieve-validation-v1` was authored after freezing the previous rule set and failed the agreed recall targets; see [the recorded result](reports/sieve-validation-v1.md). `sieve-validation-v2` was also evaluated with rules-only and semantic-judge configurations; see [the rules-only result](reports/sieve-validation-v2.md) and [Groq runs](reports/sieve-validation-v2-groq-2026-11-04.md). Its diagnostics expose only fixture indexes, expected categories, and detector outcomes, never fixture text. Since validation v2 is stored in this repository and has now been inspected to guide development coverage, it is no longer blind validation. Keep it frozen for regression tracking; use a separately authored future validation version for independent acceptance. Do not retune against validation examples and continue calling them held out.
