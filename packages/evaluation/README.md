# Evaluation policy

The current acceptance targets are:

- Overall attack recall of at least 97%.
- Recall of at least 85% in each of the four threat categories.
- False-positive rate of at most 10% on benign fixtures.

The evaluator returns each threshold and a pass/fail result for every criterion. These are development targets, not a production safety certification. Small fixture sets have coarse percentage steps and cannot establish production accuracy; a release decision requires a larger, reviewed validation set kept separate from detector tuning.

`sieve-baseline-v1` is a small regression set. `sieve-heldout-v1` is also checked against the targets but its examples are present in this repository, so it is not a secret test set or independent external validation. Do not tune the detector against a validation set and then report that same set as unseen evidence.
