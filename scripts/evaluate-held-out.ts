import { loadConfig } from "../apps/api/src/config.js";
import {
  fixtureSetVersions,
  freshValidationV2FixtureSetVersion,
  runEvaluationDetailed,
} from "@sieve/evaluation";
import type { EvaluationFixtureDiagnostic } from "@sieve/evaluation";
import type { EvaluationMetrics } from "@sieve/contracts";

type RunResult = {
  run: number;
  metrics: EvaluationMetrics;
  diagnosticFixtures: EvaluationFixtureDiagnostic[];
};

const maximumRuns = 10;

function parseRunCount(value: string | undefined): number {
  if (value === undefined || value === "") return 1;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > maximumRuns) {
    throw new Error("SIEVE_EVALUATION_REPEATS must be an integer from 1 to 10");
  }
  return count;
}

function numericRange(values: readonly (number | null)[]): { minimum: number; maximum: number } | null {
  const present = values.filter((value): value is number => value !== null);
  if (present.length === 0) return null;
  return { minimum: Math.min(...present), maximum: Math.max(...present) };
}

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.semanticJudge) {
    throw new Error("semantic_judge_not_configured");
  }

  const fixtureSetVersion = process.env.SIEVE_EVALUATION_FIXTURE_SET || freshValidationV2FixtureSetVersion;
  if (!fixtureSetVersions.includes(fixtureSetVersion as typeof fixtureSetVersions[number])) {
    throw new Error("unsupported_fixture_set");
  }
  const requestedRuns = parseRunCount(process.env.SIEVE_EVALUATION_REPEATS);
  const runs: RunResult[] = [];
  for (let run = 1; run <= requestedRuns; run += 1) {
    const result = await runEvaluationDetailed(fixtureSetVersion, config.semanticJudge);
    runs.push({
      run,
      metrics: result.metrics,
      diagnosticFixtures: result.diagnostics.filter(({ outcome, expectedCategoryDetected }) =>
        outcome === "false_positive" || outcome === "false_negative" || expectedCategoryDetected === false),
    });
  }
  const passedRuns = runs.filter(({ metrics }) => metrics.acceptance.passed).length;
  const recallRange = numericRange(runs.map(({ metrics }) => metrics.recall));
  const falsePositiveRateRange = numericRange(runs.map(({ metrics }) => metrics.falsePositiveRate));

  process.stdout.write(`${JSON.stringify({
    evaluatedAt: new Date().toISOString(),
    fixtureSetVersion,
    provider: config.semanticJudge.provider,
    model: config.semanticJudge.model,
    repeatCount: requestedRuns,
    passedRuns,
    allRunsPassed: passedRuns === requestedRuns,
    observedRecallRange: recallRange,
    observedFalsePositiveRateRange: falsePositiveRateRange,
    runs,
  }, null, 2)}\n`);
}

void main().catch((error: unknown) => {
  const errorCode = error instanceof Error && /^[a-z0-9_]+$/.test(error.message)
    ? error.message
    : "evaluation_failed";
  process.stderr.write(`Held-out validation evaluation failed (${errorCode}). Check provider configuration and availability.\n`);
  process.exitCode = 1;
});
