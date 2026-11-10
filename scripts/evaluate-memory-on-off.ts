import { loadConfig } from "../apps/api/src/config.js";
import { Database } from "../apps/api/src/database.js";
import { hashAgentCredential } from "../apps/api/src/agent-credentials.js";
import { runMemoryOnOffEvaluation, memoryLearningEvaluationVersion } from "../packages/evaluation/src/memory.js";
import { judgeUntrustedText, type SemanticMemoryContext } from "../packages/detector/src/index.js";
import { WalrusThreatMemory } from "../packages/threat-memory/src/walrus.js";

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.databaseUrl || !config.walrusMemory || !config.semanticJudge) {
    throw new Error("memory_evaluation_requires_database_walrus_and_semantic_judge");
  }
  const credential = process.env.MEMORY_EVALUATION_AGENT_CREDENTIAL;
  const tokenHash = credential ? hashAgentCredential(credential) : null;
  if (!tokenHash) throw new Error("MEMORY_EVALUATION_AGENT_CREDENTIAL is required");

  const database = new Database(config.databaseUrl);
  try {
    await database.migrate();
    const agent = await database.authenticateAgent(tokenHash, "inspect");
    if (!agent) throw new Error("memory_evaluation_agent_not_authorized");
    const scope = { workspaceId: agent.workspaceId, agentId: agent.id, includeGlobal: agent.policy.includeGlobalMemory === true };
    const walrus = new WalrusThreatMemory(config.walrusMemory);
    await walrus.checkConnection();
    const result = await runMemoryOnOffEvaluation({
      recall: async (query) => {
        const hits = await walrus.recallLifecycleRecords(query, scope, 8);
        const memories = await database.authorizeRecalledMemories(agent, scope, hits, new Date().toISOString());
        return memories.map(({ id, category, techniqueId, summary, behavioralFeatures }): SemanticMemoryContext & { id: string } => ({
          id, category, techniqueId, summary, behavioralFeatures,
        }));
      },
      semanticReview: async (items, memories) => judgeUntrustedText(items, config.semanticJudge!, memories),
      maximumFalsePositiveRate: 0.1,
    });
    process.stdout.write(`${JSON.stringify({
      providerMode: "live-walrus-and-semantic-judge",
      fixtureSetVersion: memoryLearningEvaluationVersion,
      model: { provider: config.semanticJudge.provider, model: config.semanticJudge.model },
      metrics: result,
    }, null, 2)}\n`);
  } finally {
    await database.close();
  }
}

void main().catch(() => {
  process.stderr.write("Memory-on/off evaluation failed; check required provider configuration and availability.\n");
  process.exitCode = 1;
});
