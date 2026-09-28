# Provider / consumer boundary

This document is the current source-level boundary for the clean public `roccho-dev/envs` repository.

## Authorities

```text
accepted meaning        = roccho-dev/adrs#443
historical design       = roccho-dev/envs-old#133 / #134 / #136
current provider state  = roccho-dev/envs#2
consumer application    = roccho-dev/apps#27
consumer operation      = roccho-dev/ops#435
secret-effect isolation = roccho-dev/ops#436
```

`envs-old` is historical evidence only. It is not a current authority and must never be an automatic runtime fallback.

## Ownership

```text
envs
├─ public binding / capability / source / target contract
├─ secret-source admission
├─ authoring and projection effect
├─ provider name/presence readback
└─ non-secret projection receipt

target-native auth slot
└─ revocable projection created by envs

apps
├─ exact application artifact
├─ required capability declaration
└─ secret-free application runtime acceptance

ops
├─ exact deploy/effect artifact admission
├─ deployment and target readback
├─ apps acceptance invocation
└─ independent consumer execution twice
```

`envs` does not own application behavior PASS or independent consumer PASS. A projection receipt proves a provider effect and readback only.

The provider needs a projector, but consumers do not depend on `cmd/envctl`. The current trusted workflow plus `scripts/runtime-secret-projection.sh` is the provider projector for this slice. Migrating the larger `cmd/envctl` surface is separate source-completeness work.

## Normal consumer path

Normal apps/ops execution must not use:

```text
envs checkout
envs workflow dispatch or wait
envctl parent process
envctl auth exec
auth bundle
SOPS
age identity
GitHub Environment source secret
envs-old fallback
old private artifact fallback
```

`envctl auth exec` may remain as an auxiliary local diagnosis, migration, recovery, or no-native-slot path. Its PASS is never evidence of target-native projection or autonomous consumer use.

## Handoff

The provider handoff is accepted only when all of these are present:

1. an exact 40-character envs source SHA;
2. an active `dev.projection` plane;
3. the exact current SOPS ciphertext digest;
4. provider effect PASS;
5. name/presence readback PASS;
6. a validated `envs.projectionReceipt.v1`;
7. the receipt merged into `handoffs/dev/jev-api.json`.

`main` and `proposals` are navigation/compatibility refs. Consumers use the exact SHA carried by the handoff.

The handoff does not make the consumer runtime PASS. Apps must still prove real application behavior, and ops must still prove two independent executions with envs/envctl/SOPS/age absent.

## Current states

```text
public source provider        = PASS
provider mechanism            = PASS_SOURCE
fixture SOPS/age roundtrip    = PASS_FIXTURE
physical dev projection       = derived by scripts/provider_readiness.py
provider handoff receipt      = derived by scripts/provider_readiness.py
consumer runtime readiness    = OUT_OF_SCOPE
```

Run:

```text
python3 scripts/provider_readiness.py
```

`NOT_CONFIGURED`, `NOT_RUN`, `STALE`, and `ABSENT` are not PASS.
