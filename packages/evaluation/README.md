# Evaluation policy

`sieve-validation-v3` is a newly authored 55-fixture set with eight attacks per category and 23 benign examples. It is the evaluator's default validation set. See [the recorded Groq result](reports/sieve-validation-v3-groq-2026-11-05.md). Keep this set frozen for regression tracking; author a new version for independent acceptance after future detector changes.

The current acceptance targets are:

- Overall attack recall of at least 97%.
- Recall of at least 85% in each of the four threat categories.
- False-positive rate of at most 10% on benign fixtures.

The evaluator returns each threshold and a pass/fail result for every criterion. These are development targets, not a production safety certification. Small fixture sets have coarse percentage steps and cannot establish production accuracy; a release decision requires a larger, reviewed validation set kept separate from detector tuning.

`sieve-baseline-v1` is a small regression set. The examples formerly labeled `sieve-heldout-v1` were inspected and used during development; `sieve-variants-v1` is their clearer version name, while the legacy name remains accepted for existing runs. `sieve-dev-v1`, `sieve-dev-v2`, and diagnostic-guided `sieve-dev-v3` are development sets. `sieve-validation-v1` was authored after freezing the previous rule set and failed the agreed recall targets; see [the recorded result](reports/sieve-validation-v1.md). `sieve-validation-v2` was also evaluated with rules-only and semantic-judge configurations; see [the rules-only result](reports/sieve-validation-v2.md) and [Groq runs](reports/sieve-validation-v2-groq-2026-11-04.md). Its diagnostics expose only fixture indexes, expected categories, and detector outcomes, never fixture text. Since validation v2 is stored in this repository and has now been inspected to guide development coverage, it is no longer blind validation. Keep it frozen for regression tracking; use a separately authored future validation version for independent acceptance. Do not retune against validation examples and continue calling them held out.

## Persistent-memory learning evaluation

`runMemoryOnOffEvaluation` runs the same unseen fixture set twice with the same semantic classifier: once with no recalled memory and once with a supplied recall callback. It reports precision, recall, false-positive rate, hit IDs, and deltas. The evaluator rejects fixtures not explicitly labeled `unseen`; keep this set frozen and author a new version if it is used for tuning.

The live command is `pnpm --filter @sieve/api evaluate:memory`. It requires `DATABASE_URL`, Walrus Memory credentials, a configured semantic judge, and `MEMORY_EVALUATION_AGENT_CREDENTIAL` for an authorized protected agent. It recalls active Walrus records, checks each against PostgreSQL, and prints metrics without fixture text. A unit test with a mocked recall/classifier verifies the metric calculation; that test is not evidence of improvement on the real provider. Run the live command after a reviewed memory has been promoted and the API has restarted. Report improvement only if the live results show a recall gain while memory-on false-positive rate remains within 10%.
