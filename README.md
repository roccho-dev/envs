# envs

This repository is the public clean snapshot of `envs`. Historical private Git and GitHub surfaces are intentionally not imported.

`envs` owns environment selection and binding meaning. Artifact-producing repositories remain responsible for source, version, immutable bytes, hash, runtime closure, unpacking, and package identity.

## Migration provenance

Current migration authority is `roccho-dev/envs#2`. Exact snapshot lineage and the terminal disposition of the former private GitHub surface are recorded under [`migration/`](migration/README.md).

The private historical repository is evidence only. Building, reviewing, or extending current `envs` must not require access to it.

## Provider / consumer boundary

`envs` owns secret-source admission, target-native projection, provider readback, and a non-secret projection receipt. It does not own application runtime PASS or independent consumer PASS. Consumers do not require `cmd/envctl`; the provider may use the trusted thin workflow/script projector.

Normal `apps` / `ops` execution must not use envs checkout or workflow, `envctl` as a parent process, `envctl auth exec`, auth bundles, SOPS, age identities, GitHub Environment source secrets, `envs-old`, or old private artifacts.

`envs-old` is historical evidence only. The machine-readable boundary is `contracts/provider-consumer.jsonl`; the current provider state is derived with:

```text
python3 scripts/provider_readiness.py
```

A provider handoff requires an exact envs SHA and a validated `handoffs/dev/jev-api.json`. `main` and `proposals` are navigation refs, not sufficient trust anchors. A provider handoff does not replace apps real runtime acceptance or ops independent execution twice.

See `docs/provider-consumer-boundary.md`.

## Package boundary

A package binding contains only:

- producer identity;
- exact producer revision;
- producer subflake and output;
- environment scope.

It does not contain a forge URL, credential, copied package recipe, or vendored producer tree. Nix receives the concrete resolver at execution time.

`parts` adoption is intentionally deferred. Keep new surface area minimal until the primitive shape is proven by concrete consumers.

## DuckDB OS/user bindings

The first concrete binding consumes:

```text
producer  flakes
revision  b369525b9d1ca998b7fc9ebeeec4517a6f167558
subflake  published/duckdb-cli
output    packages.x86_64-linux.duckdb-cli
scope     os | user
```

`envs` exposes the concrete entrypoints from `bindings/duckdb`:

- `os-duckdb-cli` with `scope = "os"`;
- `user-duckdb-cli` with `scope = "user"`.

Both resolve to one producer-owned derivation and one store output. DuckDB source, version, artifact URL, hash, musl/C++ runtime repair, and build logic remain exclusively in `flakes`.

The SSOT bare repository is injected through Nix, not encoded in the contract:

```text
REV=b369525b9d1ca998b7fc9ebeeec4517a6f167558
INPUT="git+file:///home/nixos/repos/flakes.git?rev=${REV}&dir=published/duckdb-cli"

nix flake check ./bindings/duckdb --no-write-lock-file \
  --override-input packagePrimitives "${INPUT}"

nix build ./bindings/duckdb#os-duckdb-cli \
  ./bindings/duckdb#user-duckdb-cli \
  --no-write-lock-file \
  --override-input packagePrimitives "${INPUT}"
```

A Nix registry may supply the same resolver. The exact revision and primitive identity are asserted by the binding flake, so a mutable or incorrect mapping fails closed.

This slice proves build-time composition only. It does not claim target-host placement, activation, convergence, rollback, or host observation.

## SSOT GitHub refs

`nixosModules.ssot-github-refs` maintains read-side GitHub mirrors for the SSOT bare repositories. Those mirrors are replaceable read adapters; package binding meaning and Nix builds do not require GitHub credentials or GitHub URLs.
