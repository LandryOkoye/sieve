import { SieveClient } from "@sieve/sdk";

const sieve = new SieveClient({
  baseUrl: process.env.SIEVE_API_URL ?? "https://sieve.example.com",
  credential: process.env.SIEVE_AGENT_CREDENTIAL ?? "",
});

const trustedContext: string[] = [];
const quarantine: Array<{ content: string; action: string }> = [];

export async function receiveExternalContent(content: string, sourceRef?: string): Promise<void> {
  const result = await sieve.inspectBeforeContext({ content, sourceType: "retrieved_document", sourceRef }, {
    addTrusted: (text) => trustedContext.push(text),
    quarantine: (text, assessment) => quarantine.push({ content: text, action: assessment.decision.action }),
  });
  if (result.addedToTrustedContext) {
    // Continue the agent turn only after SIEVE returns an explicit allow.
    return;
  }
  // Review/block content remains outside trustedContext until an application reviewer acts.
}
