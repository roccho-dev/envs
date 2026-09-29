# envs

`envs` holds public environment contracts, performs bounded provider projection, and returns a non-secret exact-SHA handoff.

- canonical branch: `proposals`
- retained compatibility branch: `main`
- accepted handoff identity: exact commit SHA

`main` remains available, but it has no independent meaning, direct changes, pull-request base, Environment effect, or handoff identity. When `main` is refreshed, its push-time check requires that revision to equal the then-current `proposals` revision. There is no continuous synchronization claim; `main` may be stale between explicit compatibility refreshes.

## Ownership

```text
contracts  = public meaning, IDs, relationships, required input names/types/lifecycles, and forbidden dependencies; never values
ciphertexts = versioned dev ciphertext only
adapters   = bounded envs-owned authoring/projection/readback
handoffs   = non-secret provider-effect receipts
checks     = executable repository and adapter specifications
```

`envs` does not own application runtime acceptance, independent consumer execution, generic deployment, UI meaning, live target observation, secret issuance, or target runtime state.

## Durable tree

```text
.github/workflows/
flake.nix, flake.lock
contracts/
ciphertexts/       # absent while dev (Jev, rent tunnel) is NOT_CONFIGURED
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

## Environment inputs

`contracts/environments.jsonl` declares each GitHub Environment's `required_secrets` and `required_variables` by name, type, and lifecycle. The actual values live only in the GitHub Environment; the owner sets them there without a commit. Git never stores a value body: before any provider effect the adapter turns a missing or invalid required input RED, and turns RED when a live Variable value appears anywhere in the repository. The only exception is the recipient metadata that sops writes into `ciphertexts/dev-jev-api.sops.yaml` and `ciphertexts/dev-rent-tunnel.sops.yaml`.

| Environment input | Kind | Type | Lifecycle |
|---|---|---|---|
| `dev-authoring/JEV_API_KEY` | secret | opaque | one_shot_ingress |
| `dev-authoring/SOPS_AGE_RECIPIENTS` | variable | age_recipient_list | persistent |
| `dev-projection/SOPS_AGE_KEY` | secret | age_identity | persistent |
| `dev-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-tunnel/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-rent-tunnel/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-tunnel/RENT_TUNNEL_ID` | variable | cloudflare_tunnel_id | persistent |
| `dev-rent-tunnel/RENT_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `stg-projection/JEV_API_KEY` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `prd-projection/JEV_API_KEY` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |

There are no stg or prd authoring Environments.

## Dev Jev flow

```text
dev-authoring/SOPS_AGE_RECIPIENTS
+ dev-authoring/JEV_API_KEY
→ author-dev-jev-api
→ ciphertext PR
→ merge to exact proposals SHA
→ dev-authoring/JEV_API_KEY may then be deleted by the owner (one-shot ingress);
  author stays RED until it is set again

ciphertext
+ dev-projection/SOPS_AGE_KEY, CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
→ project-dev-jev-api
→ provider effect + name-only readback
→ non-secret handoff PR (no account ID)
```

`envs` never deletes an Environment input; deleting the one-shot source is a separate owner effect.

## Dev rent tunnel flow (windows #14)

The rent OCI host runs `cloudflared` from a token file. envs owns only the step from the provider-issued Named Tunnel token to a ciphertext that exactly one target can open:

```text
dev-rent-tunnel/CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, RENT_TUNNEL_ID, RENT_AGE_RECIPIENT
→ project-dev-rent-tunnel (manual dispatch on proposals only)
→ one bounded GET of the tunnel token (30 s, 64 KiB, no redirect, entry-owned CA bundle)
→ token in memory → sops stdin, SOPS_AGE_RECIPIENTS = the one target recipient
→ ciphertexts/dev-rent-tunnel.sops.yaml + dev.rent-tunnel ACTIVE
→ ciphertext handoff PR → merge to exact proposals SHA
```

- Inputs are declared, not valued: until the owner configures `dev-rent-tunnel`, the plane is `NOT_CONFIGURED` and every missing or malformed input is RED before any provider call. `RENT_AGE_RECIPIENT` is a single age recipient; a list is RED, and the ciphertext must name exactly that recipient and carry only `RENT_TUNNEL_TOKEN`.
- The token and the API token never enter argv, a log line, an error message, or the result JSON, and the adapter writes neither to Git. If either is already in a tracked file, the run is RED: the API token before the provider call, the tunnel token before SOPS or any write. The ciphertext is public and permanent in history; recovering from a leaked target identity means rotating the tunnel token, not deleting the file.
- `checks/test_rent_tunnel.py` proves the gates and failure cases with a fake provider and fake sops, and in `check` it runs the real locked sops with check-only `age-keygen` identities: the target identity decrypts, another identity and a tampered ciphertext are RED. `age` is a separate `check-age` output, and `check` proves it is absent from the provided artifact.

Not proven here, and not owned by envs: a real provider retrieval or dispatch of this workflow, the Cloudflare API token scope it needs, whether Actions may open the handoff PR (a PR opened with the workflow token does not trigger `check`), the target's age identity, applying the ciphertext on the target, the client credential, and unattended SSH.

## Effect toolchain

`flake.nix` and `flake.lock` define the only toolchain for authoring and projection: Python, SOPS, Wrangler, Git, and GitHub CLI from the locked nixpkgs input, plus the `envs-effect` entry running this source's adapter. `.#effect-artifact` is that entry's complete store closure as one tar with an `ENTRY` pointer.

```text
check (secret-free)   nix build .#effect-artifact → upload envs-effect-<source sha>  # provided artifact
clean-start / effect  obtain by source SHA → verify digest → extract to /nix/store     # no checkout build, no Nix
                      envs-effect --root <checkout> toolchain | author | project        # store paths only
```

`check` checks out, builds, and names the artifact after the exact source commit (the PR head, never a merge ref), and Nix records that commit (`self.rev`) as the artifact's `SOURCE` and manifest `source`; GitHub records its artifact id (locator) and `sha256` digest. The consumer step, identical in `check`'s effect-shape and clean-start jobs and both effect workflows, resolves the one unexpired `envs-effect-<sha>` artifact, requires its producing run to be this repository's `check.yml` for that SHA and branch and either a successful `push` run or the current run, verifies the downloaded bytes against GitHub's digest, requires `SOURCE` to equal the SHA, and only then extracts it without installing Nix. The effect-shape job runs the provided entry over a checkout of the same commit with `--root`, exactly as the effect workflows do before secrets. Effect workflows resolve by the dispatched `github.sha`, so each `proposals` commit consumes the artifact its own post-merge `check` push run provided; no SHA is copied by hand. They record `envs-effect toolchain` before the secret-bearing step and then run only provided store paths; the repository check rejects any rebuild, Nix, other executable, absolute path, command chaining, or substitution there. The runner image (recorded as `ImageOS`/`ImageVersion`), its shell/curl/jq/coreutils/tar/unzip/sudo, and SHA-pinned Actions are the platform boundary; Nix is installed only by the producer.

The entry carries a manifest of its exact tools and nixpkgs lock; before SOPS or Wrangler starts, the adapter turns RED when that manifest is absent, outside the Nix store, differs from the data root's `flake.lock` or adapter, lacks a tool, or is not running on its own Python. `check` also proves Nix regenerates the committed `flake.lock` byte-for-byte, executes each closure tool (including Wrangler's `pages secret put|list --help`), and proves missing, altered, and mismatched artifacts RED in the clean-start job.

This is source and CI evidence only. It does not claim a real authoring or projection effect.

Normal apps/ops execution uses only target-native auth. It does not start or wait for envs, use envctl as a parent, decrypt SOPS, or receive an age identity.

## Checks

```text
python3 checks/repository.py
python3 checks/test_repository.py
python3 checks/test_jev_api.py
python3 checks/test_rent_tunnel.py
nix build .#effect-toolchain .#effect-artifact --no-update-lock-file   # check workflow, toolchain job
nix build .#check-age --no-update-lock-file                             # check-only, real SOPS roundtrip
```

The repository oracle calculates accepted structure and state. Its tests deliberately create invalid states and require RED rather than repeating only happy-path execution.
