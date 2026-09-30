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
providers/         # disposable probe and state-proof declarations only; never state or lock files
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

`contracts/environments.jsonl` declares each GitHub Environment's `required_secrets` and `required_variables` by name, type, and lifecycle. The actual values live only in the GitHub Environment; the owner sets them there without a commit. Git never stores a value body: before any provider effect the adapter turns a missing or invalid required input RED, and turns RED when a live Variable value appears anywhere in the repository. The only exception is the recipient metadata that sops writes into `ciphertexts/dev-jev-api.sops.yaml`, `ciphertexts/dev-rent-tunnel.sops.yaml` and `ciphertexts/dev-jev-api.oci-dev.sops.yaml`. A binding may declare its own input on an existing Environment (`jev-api.oci-dev` declares `OCI_DEV_AGE_RECIPIENT` on `dev-authoring`); only that binding's authoring reads it.

| Environment input | Kind | Type | Lifecycle |
|---|---|---|---|
| `dev-authoring/JEV_API_KEY` | secret | opaque | one_shot_ingress |
| `dev-authoring/SOPS_AGE_RECIPIENTS` | variable | age_recipient_list | persistent |
| `dev-authoring/OCI_DEV_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-projection/SOPS_AGE_KEY` | secret | age_identity | persistent |
| `dev-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-tunnel/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-rent-tunnel/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-tunnel/RENT_TUNNEL_ID` | variable | cloudflare_tunnel_id | persistent |
| `dev-rent-tunnel/RENT_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-rent-access-probe/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-rent-access-probe/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-access-probe/CLOUDFLARE_ZONE_ID` | variable | cloudflare_zone_id | persistent |
| `dev-rent-access-probe/R2_PARENT_API_TOKEN` | secret | opaque | finite_expiry |
| `dev-rent-access-probe/R2_PARENT_ACCESS_KEY_ID` | variable | cloudflare_api_token_id | finite_expiry |
| `stg-projection/JEV_API_KEY` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `prd-projection/JEV_API_KEY` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |

There are no stg or prd authoring Environments. `dev-rent-access-probe` carries two planes: the Access probe reads `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID`, the state proof (`dev.rent-state-proof`) reads `R2_PARENT_API_TOKEN` and `R2_PARENT_ACCESS_KEY_ID`, both read `CLOUDFLARE_ACCOUNT_ID`, and neither reads the other's secret.

## Dev Jev flow

```text
dev-authoring/SOPS_AGE_RECIPIENTS
+ dev-authoring/JEV_API_KEY
→ author-dev-jev-api, target jev-api
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

`author-dev-jev-api` requires one declared target; there is no default. Each target has one literal step that receives only its own inputs, and `author --target jev-api` is the unchanged Cloudflare authoring above.

## Dev OCI Jev target (roccho-dev/adrs#460)

The trusted WSLC OCI dev target (owned by `roccho-dev/windows`) starts the apps dev server with `JEV_API_KEY` in one child process. envs owns only the target-bound ciphertext:

```text
dev-authoring/JEV_API_KEY + dev-authoring/OCI_DEV_AGE_RECIPIENT
→ author-dev-jev-api, `author --target jev-api.oci-dev` (manual dispatch on proposals only)
→ ciphertexts/dev-jev-api.oci-dev.sops.yaml, encrypted to exactly that one recipient
→ ciphertext handoff PR → merge to exact proposals SHA
```

- The binding `jev-api.oci-dev` keeps capability `jev-api` and declares `OCI_DEV_AGE_RECIPIENT`, a single age recipient; a list is RED. This target never reads `SOPS_AGE_RECIPIENTS`, and the Cloudflare target never reads `OCI_DEV_AGE_RECIPIENT`.
- OCI authoring writes only its ciphertext. It changes no plane state, no handoff, and no other target's ciphertext; its readiness is only that ciphertext validating at an exact commit (fields exactly `JEV_API_KEY` plus SOPS metadata, exactly one recipient).
- The key reaches SOPS on stdin only; a key or recipient value already in a tracked file is RED before SOPS runs.
- `checks/test_jev_api.py` proves the gates with fake sops, and in `check` it runs the real locked sops with check-only `age-keygen` identities: the target identity decrypts, and another identity or a tampered ciphertext is RED.

Not proven here, and not owned by envs: the target's identity, applying the ciphertext on the target, the launcher, application runtime acceptance, and any deployment. Source and CI PASS is not a real authoring PASS.

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

## Dev rent Access SSH probe (windows #14)

Before any rent migration, one disposable probe must show whether the exact pinned client (`cloudflared` 2026.6.1, the version windows PR #21 ships) reaches an SSH origin through Cloudflare Access with a service token and no browser. `providers/dev-rent-access-probe/main.tf` declares it with the standard Cloudflare provider (5.21.1) for OpenTofu; `flake.nix` puts OpenTofu with only that provider, `cloudflared` and OpenSSH into the same effect artifact, so a run acquires nothing from a registry.

```text
dev-rent-access-probe/CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID
→ probe-dev-rent-access-ssh (manual dispatch on proposals only; read-only repository permissions)
→ preflight lookup of the fixed names in a fresh state (create=false: no managed resource)
   any match → UNKNOWN, ownership UNPROVEN, NEEDS_AUTHORITY; nothing created, adopted or deleted
→ create: tunnel windows-rent-access-probe → ssh://localhost:2222, CNAME rent-access-probe.roccho.com,
   Access app with one Service Auth policy for exactly one 1h service token
→ localhost sshd answering a run-scoped nonce; cloudflared tunnel run with TUNNEL_TOKEN from the environment
→ ssh -o BatchMode=yes with the PR #21 ProxyCommand shape, once per case and in this order, each case and
   process with its own empty HOME (no runner or cross-case Access login cache):
   service token, no token, wrong secret, service token again
→ destroy exactly this state, then read back absence from a fresh lookup state
```

- Outcomes: `TOKEN_REACHED_NEGATIVES_REFUSED` only when both token cases return the nonce and both negative cases fail; an admitted negative is `ACCESS_NOT_ENFORCED`; both token cases failing is `UNATTENDED_PATH_FAILED`; any timeout, or a path not up on both sides of the negatives, is `UNKNOWN`. There is no retry, and cause is always `UNKNOWN`.
- A refused negative is not an Access denial: the client cannot tell Access from DNS, edge, tunnel or sshd failures. The bracketing token cases show only that the path was up around the negatives, so `access_denial_evidence` stays `NOT_OBSERVED` until a provider-side Access decision record is read for each negative attempt.
- If cleanup or its absence readback is not proven, the status is `CLEANUP_UNKNOWN` whatever the probe reached; the probe outcome stays under `probe`.
- The exact IDs of all six managed resources come from this run's OpenTofu state right after apply, even a partial one, and are emitted at once as one ID-only line: `observed_state_ids`. They record what the state holds, not that the provider has or lacks the resource. After destroy the state is read again: `remaining_in_state` is what destroy left, `unverified_after_destroy` is what the state dropped but absence was not read back for (or the state was unreadable). Only these exact IDs may be cleaned up by the owner; the state JSON is parsed in memory and never written out, since it can hold secrets.
- Credentials (API token, tunnel token, service-token secret) reach only the process that needs them, by environment; never argv, the result JSON, a log line or Git. OpenTofu state stays in the runner's temporary directory and is never committed, cached, uploaded or printed.
- Cleanup deletes only what this run's state created. If the runner loses that state, name lookup locates candidates and never proves ownership: `rent-access-locate` reports them as `UNKNOWN`/`NEEDS_AUTHORITY` and has no delete path. A deletion of name-located resources needs its own contract.
- `checks/test_rent_access_probe.py` proves the order, isolation, redaction, outcome classes and cleanup model against a fake provider and client. In `check` it also runs a real localhost sshd/ssh exchange from the closure, and `check` asserts the exact `cloudflared` version and its `--service-token-id`/`--service-token-secret` flags and initializes and validates the provider declaration with network access closed.

Not proven here: that `cloudflared` 2026.6.1 honours a service token (a reported 2026.6.0 regression, cloudflare/cloudflared#1673, is a risk), any real Cloudflare resource or Access decision, the API token scope, unattended SSH to the rent, or G6I3 credential selection. The live run needs the `dev-rent-access-probe` Environment and its own contract.

Not proven here, and not owned by envs: a real provider retrieval or dispatch of this workflow, the Cloudflare API token scope it needs, whether Actions may open the handoff PR (a PR opened with the workflow token does not trigger `check`), the target's age identity, applying the ciphertext on the target, the client credential, and unattended SSH.

## Dev rent R2 state proof (windows #8/#14)

Before any production state, one bounded run must show that the bundled OpenTofu keeps encrypted state with a native lock file in Cloudflare R2. `providers/dev-rent-state-proof/main.tf` declares exactly two per-run buckets (`windows-rent-state-proof-<run_id>-<attempt>` and its `-decoy`); `providers/dev-rent-state-proof/backend/main.tf` is an S3-backend root on the proof bucket with `use_lockfile = true`, enforced state and plan encryption, and only built-in resources.

```text
dev-rent-access-probe/R2_PARENT_API_TOKEN, R2_PARENT_ACCESS_KEY_ID, CLOUDFLARE_ACCOUNT_ID
→ probe-dev-rent-state (manual dispatch on proposals only; read-only repository permissions)
→ parent verify: ID equals R2_PARENT_ACCESS_KEY_ID, active, not_before passed, expiry covers the job bound + margin
→ both per-run names absent; first bounded create (proof bucket) is the only capability probe, then the decoy
→ one temporary credential: proof bucket, prefix state/, object-read-write, 900 s, never the parent token
→ one lock holder and one refused contender, then release; raw object is ciphertext without the canary;
   fresh-directory readback; pbkdf2 key rotation through fallback; old key, no encryption, no credential,
   outside prefix and decoy bucket refused; the same credential reads again after the negatives
→ cleanup once: credential observed refused after its TTL, exact keys deleted, owned buckets destroyed, both names 404
```

- Every OpenTofu process gets its own directory and empty HOME. The parent token reaches only the bucket root, Wrangler and the Cloudflare API; the temporary credential and the `TF_ENCRYPTION` text reach only the backend root, by environment. Neither enters argv, `-backend-config`, a log line, the result JSON, an artifact, a cache or Git; the raw state object stays in process memory.
- Right after each create the run emits one evidence line per bucket (`envs.rentStateProofCreated.v1`: bucket, provider `creation_date`, run ID, attempt, head). Cleanup deletes only a bucket whose evidence and current `creation_date` match; a bucket name alone never authorizes deletion. The same parser reads those lines from a job log as recovery input for a later exact contract.
- `STATE_BACKEND_PROVEN` needs every check and `cleanup` `ABSENT`. A remaining bucket is `LEFTOVER`, an unobserved credential expiry or unreadable evidence `UNKNOWN`; either replaces the status, with no retry. Force cancellation or runner loss can bypass cleanup.
- `checks/test_rent_state_proof.py` proves the gates, order, isolation, redaction, outcome classes, cleanup model and evidence parser against a fake provider; `check` initializes and validates both roots with network access closed and checks Wrangler's `r2 object get --pipe --remote` shape.

Not proven here: any real R2 effect, the parent token's permission (only the first bounded create proves it), R2 lock-file and prefix-scoped temporary-credential behaviour, or production state. The live run needs its own contract.

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
python3 checks/test_jev_api.py                                        # --sops/--age-keygen in check: real OCI roundtrip
python3 checks/test_rent_tunnel.py
python3 checks/test_rent_access_probe.py
python3 checks/test_rent_state_proof.py
nix build .#effect-toolchain .#effect-artifact --no-update-lock-file   # check workflow, toolchain job
nix build .#check-age --no-update-lock-file                             # check-only, real SOPS roundtrip
```

The repository oracle calculates accepted structure and state. Its tests deliberately create invalid states and require RED rather than repeating only happy-path execution.
