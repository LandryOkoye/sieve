import { loadConfig } from "../apps/api/src/config.js";
import {
  freshValidationV2FixtureSetVersion,
  runEvaluation,
} from "@sieve/evaluation";
import type { EvaluationMetrics } from "@sieve/contracts";

type RunResult = {
  run: number;
  metrics: EvaluationMetrics;
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

  const requestedRuns = parseRunCount(process.env.SIEVE_EVALUATION_REPEATS);
  const runs: RunResult[] = [];
  for (let run = 1; run <= requestedRuns; run += 1) {
    const metrics = await runEvaluation(freshValidationV2FixtureSetVersion, config.semanticJudge);
    runs.push({ run, metrics });
  }
  const passedRuns = runs.filter(({ metrics }) => metrics.acceptance.passed).length;
  const recallRange = numericRange(runs.map(({ metrics }) => metrics.recall));
  const falsePositiveRateRange = numericRange(runs.map(({ metrics }) => metrics.falsePositiveRate));

  process.stdout.write(`${JSON.stringify({
    evaluatedAt: new Date().toISOString(),
    fixtureSetVersion: freshValidationV2FixtureSetVersion,
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

void main().catch(() => {
  process.stderr.write("Held-out validation evaluation failed. Check provider configuration and availability.\n");
  process.exitCode = 1;
});
