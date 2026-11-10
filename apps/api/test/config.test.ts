import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";

test("Walrus network configuration is independent of Tatum and direct inspection needs no Tatum key", () => {
  const config = loadConfig({
    TATUM_NETWORK: "mainnet",
    MEMWAL_NETWORK: "testnet",
    MEMWAL_ACCOUNT_ID: "test-account",
    MEMWAL_PRIVATE_KEY: "test-key",
  } as NodeJS.ProcessEnv);
  assert.equal(config.tatumApiKey, undefined);
  assert.equal(config.integrations.tatum, "not_configured");
  assert.equal(config.walrusMemory?.serverUrl, "https://relayer-staging.memory.walrus.xyz");
});

test("Walrus production endpoint can be selected without changing the Sui network", () => {
  const config = loadConfig({ MEMWAL_NETWORK: "mainnet" } as NodeJS.ProcessEnv);
  assert.equal(config.suiNetwork, "testnet");
  assert.equal(config.integrations.tatum, "not_configured");
});
