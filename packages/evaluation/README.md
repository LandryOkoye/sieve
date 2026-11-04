# Evaluation policy

The current acceptance targets are:

- Overall attack recall of at least 97%.
- Recall of at least 85% in each of the four threat categories.
- False-positive rate of at most 10% on benign fixtures.

The evaluator returns each threshold and a pass/fail result for every criterion. These are development targets, not a production safety certification. Small fixture sets have coarse percentage steps and cannot establish production accuracy; a release decision requires a larger, reviewed validation set kept separate from detector tuning.

`sieve-baseline-v1` is a small regression set. The examples formerly labeled `sieve-heldout-v1` were inspected and used during development; `sieve-variants-v1` is their clearer version name, while the legacy name remains accepted for existing runs. `sieve-dev-v1` and `sieve-dev-v2` are development sets. `sieve-validation-v1` was authored after freezing the previous rule set and failed the agreed recall targets; see [the recorded result](reports/sieve-validation-v1.md). `sieve-validation-v2` was also evaluated with the rules-only detector and failed; see [its recorded result](reports/sieve-validation-v2.md). The optional semantic judge has not been evaluated against either validation set because no provider credentials were configured. All fixtures are in this repository, so results are not secret or independent external validation. If a validation set fails, record the failure and create a new validation set only after the next rule-freeze; do not retune against the same examples and continue calling them held out.
