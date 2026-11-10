# SIEVE TypeScript SDK

`SieveClient` submits untrusted content to a SIEVE agent endpoint. Use the OIDC-provisioned `sieve_live_` credential only in your server-side agent runtime. `inspectBeforeContext` adds content to a trusted context sink only when the SIEVE policy returns `allow`; `review` and `block` go to the optional quarantine sink.

```ts
const result = await sieve.inspectBeforeContext({ content, sourceType: "retrieved_document" }, {
  addTrusted: (text) => context.add(text),
  quarantine: (text, assessment) => quarantine.add({ text, action: assessment.decision.action }),
});
```

The SDK never stores credentials in browser storage and does not log content. Configure an HTTPS API URL outside localhost. See [`examples/agent-enforcement.ts`](../../examples/agent-enforcement.ts) for the enforcement pattern.
