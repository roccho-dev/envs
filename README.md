# envs

`envs` holds public environment contracts, performs bounded provider projection, and returns a non-secret exact-SHA handoff.

- canonical branch: `proposals`
- retained compatibility mirror: `main`
- accepted handoff identity: exact commit SHA

`main` remains available, but it has no independent meaning, direct changes, pull-request base, Environment effect, or handoff identity. Compatibility refreshes copy an accepted `proposals` revision only.

## Ownership

```text
contracts  = public meaning, IDs, relationships, and forbidden dependencies
ciphertexts = versioned dev ciphertext only
adapters   = bounded envs-owned authoring/projection/readback
handoffs   = non-secret provider-effect receipts
checks     = executable repository and adapter specifications
```

`envs` does not own application runtime acceptance, independent consumer execution, generic deployment, UI meaning, live target observation, secret issuance, or target runtime state.

## Durable tree

```text
.github/workflows/
contracts/
ciphertexts/       # absent while dev is NOT_CONFIGURED
adapters/jev_api.py
handoffs/          # absent until real projection/readback PASS
checks/
LICENSES/
LICENSE_POLICY.md
THIRD_PARTY_NOTICES.md
```

## Contracts

- `contracts/environments.jsonl` — stage and secret-plane ownership
- `contracts/bindings.jsonl` — application and capability bindings
- `contracts/targets.jsonl` — desired target meaning only
- `contracts/provider-consumer.jsonl` — envs/apps/ops responsibility and normal-path exclusions
- `handoffs/dev-jev-api.json` — real projection/readback PASS after exact-SHA non-secret handoff

## Dev Jev flow

```text
public age recipient in contracts
+ dev-authoring/SOURCE_JEV_API_KEY
→ author-dev-jev-api
→ ciphertext PR
→ merge to exact proposals SHA
→ remove one-shot source secret

ciphertext
+ dev-projection decrypt/effect authority
→ project-dev-jev-api
→ provider effect + name-only readback
→ non-secret handoff PR
```

Normal apps/ops execution uses only target-native auth. It does not start or wait for envs, use envctl as a parent, decrypt SOPS, or receive an age identity.

## Checks

```text
python3 checks/repository.py
python3 checks/test_repository.py
python3 checks/test_jev_api.py
```

The repository oracle calculates accepted structure and state. Its tests deliberately create invalid states and require RED rather than repeating only happy-path execution.
