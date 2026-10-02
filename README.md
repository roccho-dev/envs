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
adapters/place.ps1, adapters/rent-receive.sh   # target-run placement entrance and rent receiver
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

`contracts/environments.jsonl` declares each GitHub Environment's `required_secrets` and `required_variables` by name, type, and lifecycle. The actual values live only in the GitHub Environment; the owner sets them there without a commit. Git never stores a value body: before any provider effect the adapter turns a missing or invalid required input RED, and turns RED when a live Variable value appears anywhere in the repository. The only exception is the recipient metadata that sops writes into `ciphertexts/dev-jev-api.sops.yaml`, `ciphertexts/dev-rent-tunnel.sops.yaml`, `ciphertexts/dev-rent-client.sops.yaml` and `ciphertexts/dev-jev-api.oci-dev.sops.yaml`. A binding may declare its own input on an existing Environment (`jev-api.oci-dev` declares `OCI_DEV_AGE_RECIPIENT` on `dev-authoring`); only that binding's authoring reads it.

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
| `dev-rent-client/RENT_CLIENT_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-rent-access-probe/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-rent-access-probe/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-rent-access-probe/CLOUDFLARE_ZONE_ID` | variable | cloudflare_zone_id | persistent |
| `dev-rent-access-probe/R2_PARENT_API_TOKEN` | secret | opaque | finite_expiry |
| `dev-rent-access-probe/R2_PARENT_ACCESS_KEY_ID` | secret | cloudflare_api_token_id | finite_expiry |
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

## Dev rent persistent Cloudflare root (windows #14-E)

`providers/dev-rent-cloudflare/main.tf` declares the persistent SSH path the rent will use: one named Tunnel (`config_src = "cloudflare"`) with its ingress, the DNS CNAME, a self-hosted Access application and a Service Auth (`non_identity`) policy for exactly one service token. It reuses the resource shape the disposable probe ran against the real provider, without its `create` gate, and pins the same standard provider (5.21.1). Account, zone, hostname, origin service and `service_token_duration` are required inputs with no default; nothing adopts, imports or moves an existing resource.

It is declaration only: no workflow plans or applies it. `check` initializes it without its backend and validates it with network access closed, and the repository check refuses the four things native validation accepts: a local (plaintext) backend instead of the locked native S3 backend, unenforced state or plan encryption, a credentials output that is not sensitive, and a service-token lifetime fixed in source. The output being sensitive does not keep the secrets out of state: the Tunnel token and the service-token secret will be stored there.

No plan or apply until three later gates are agreed, in no implied order:

- the persistent state: which root creates and owns the bucket (the S3 backend needs an existing one), how that ownership state itself persists encrypted and locked, and the key custody;
- the backend credential boundary (adrs#443);
- the service-token lifetime, rotation and delivery to the Windows client, and the Tunnel-token placement into the rent's token slot.

The disposable R2 proof below is design evidence only; it does not prove that production state survives. A denied connection still needs provider Access evidence, and the exact Windows client, reboot and cutover are later windows #14/#8 gates.

## Dev rent placement (windows #14-E)

One G6I3 normal-user Access service credential serves every surface of the `windows-rent` alias; the rent gets only its Tunnel token. envs owns the projection, the envelopes and the target-run entrance; windows owns each slot's format, the client slot's writer and the consumer (windows PR #37).

```text
tofu output -json credentials (the persistent root's sensitive output) → stdin of `rent-client`
→ the service token pair, each one line of the windows slot rule → sops stdin, one recipient
   (dev-rent-client/RENT_CLIENT_AGE_RECIPIENT) → ciphertexts/dev-rent-client.sops.yaml + dev.rent-client ACTIVE

on the target, from the verified envs-placement-<sha> distribution (pinned official sops.exe 3.13.2, the locked
sops version, by its release digest; adapters/place.ps1; adapters/rent-receive.sh; this source's ciphertexts):
place.ps1 -Target client -Identity <the target's own age identity> -WindowsDist <verified windows-dist>
→ sops.exe stdout into memory → '<id>LF<secret>LF' on the stdin of win.ps1 -Mode RentAccess
place.ps1 -Target rent -Identity <identity> -RentImage ghcr.io/roccho-dev/windows-rent@sha256:<digest>
→ token on the stdin of a one-shot `wslc run --rm -i` of that exact image running rent-receive.sh
```

- The plaintext exists only in `place.ps1`'s memory and its private child pipes: never printed, logged, in argv, environment or a file. The writer's exit code is the only result; a refusal is one fixed line. `rent-receive.sh` uses only the image's own bash and coreutils, holds no quote or backslash so it travels as one argument, and replaces the slot rent-start checks (regular file, 0:0, mode 600, 1-4096 bytes, not blank) only while an existing one is exactly that owned shape; any other object is refused and kept, and the same value changes nothing. `place.ps1` reads each decrypted value into one fixed buffer of its bound (1024 per client line, 4096 for the token) plus a line break, stops sops beyond it, and discards every other child stream unread.
- `rent-client` projects only the service token pair; the persistent root is still declaration only and nothing here plans or applies it. Until the owner configures `dev-rent-client`, the plane is `NOT_CONFIGURED`.
- `placement-gate` in `check` uses each platform's actual CI output from one run: `placement-artifact` builds the Windows distribution, `placement-author` seals synthetic values with the provided Linux artifact, `placement-windows` binds the exact published windows Release named in `contracts/provider-consumer.jsonl` (the tag names that commit; github-actions[bot] published it from a push run whose scope, build, Windows proof, rent image and publish jobs passed; every asset equals GitHub's digest; the ZIP equals its `.sha256`; `rent-image.json` names that source) and runs `place.ps1` in Windows PowerShell 5.1 into windows' own released `ReadRentAccessInput` and `Get-RentAccessProblem`, and `placement-rent` runs `rent-receive.sh` in the rent image that Release names, by digest, after the registry tag resolves to it. Until that Release exists the gate is RED, never assumed.

Not proven here: the production `-Mode RentAccess` glue (G6I3 normal-user caller, ledger lock, owner-only write; the windows proof covers the writer functions), WSLC (Docker stands in for the receiver), the target identities and their bootstrap, real issuance or placement, Cloudflare acceptance and denial, no-browser behaviour, and packaged Windows Codex.

## Dev rent R2 state proof (windows #8/#14)

Before any production state, one bounded run must show that the bundled OpenTofu keeps encrypted state with a native lock file in Cloudflare R2. `providers/dev-rent-state-proof/main.tf` declares exactly two per-run buckets (`windows-rent-state-proof-<run_id>-<attempt>` and its `-decoy`); `providers/dev-rent-state-proof/backend/main.tf` is an S3-backend root on the proof bucket with `use_lockfile = true`, enforced state and plan encryption, and only built-in resources.

```text
dev-rent-access-probe/R2_PARENT_API_TOKEN, R2_PARENT_ACCESS_KEY_ID, CLOUDFLARE_ACCOUNT_ID
→ probe-dev-rent-state (manual dispatch on proposals only, with the required expected_source_sha; the job and its
   Environment secrets start only when github.sha equals it and only as run attempt 1; read-only repository
   permissions)
→ parent verify: ID equals R2_PARENT_ACCESS_KEY_ID, active, not_before passed, expiry covers the job bound + margin
→ both per-run names absent; first bounded create (proof bucket) is the only capability probe, then the decoy
→ one temporary credential (attempt recorded before the one POST): proof bucket, prefix state/, object-read-write,
   900 s, never the parent token; the control writes the fixed marker state/boundary-probe and reads it back exactly
→ one lock holder and one refused contender, then release; raw object is ciphertext without the canary;
   fresh-directory readback; pbkdf2 key rotation through fallback; each negative right after its control:
   old key, no encryption, no credential (OpenTofu); the marker PUT outside the prefix and the GET of the parent's
   verified decoy marker (curl); the same credential reads again after the negatives
→ cleanup once: the same credential refused 401 reading the same marker after its TTL, the state, lock and every
   attempted marker key deleted, owned buckets destroyed, both names 404
```

- Negatives are `REFUSED` only when the adjacent control succeeds and the failure has its own cause: decryption, an encryption refusal of the encrypted state, missing credential, or, for the outside-prefix write and the decoy read, a completed HTTP 403 whose parsed S3 XML `Error` has exactly one direct `Code`, `AccessDenied`. A negative that succeeds is `ADMITTED` (RED); a 401, a 5xx, a transport error or any other cause is `UNKNOWN`, and so is a bodyless or other-coded 403, a missing object or a reply that merely contains the word.
- The object boundaries use the locked closure `curl` (`pkgs.curl`), because OpenTofu reads (HEAD) its state key before any lock write and a refused HEAD carries no error code. One path-style request each, signed `aws:amz:auto:s3` with the temporary credential, which reaches curl only through its stdin config (`-q`, the default config disabled), never argv, a file or a log; no proxy, redirect or retry, and the reply stays in process. The fixed non-secret marker `state/boundary-probe`: the credential control writes it and reads it back exactly; right before the outside-prefix write, the write control PUTs the same bytes to it again, and `outside/boundary-probe` gets an otherwise identical PUT; the parent token writes the decoy's marker and reads it back exactly, then the read control GETs the proof marker with exact bytes right before the credential reads the decoy's, so a refusal is never a missing object. Proof and decoy reads differ only in the bucket. Every PUT is recorded as attempted before it is sent, and cleanup deletes every attempted key even when the reply was a timeout. If the decoy marker cannot be verified, the decoy negative is not attempted. No raw curl read of `state/proof.tfstate` is made; the OpenTofu and Wrangler reads of it are unchanged.
- `unencrypted_read_refused` reads the state with no encryption configuration at all: a temporary copy of the backend root with its one exact enforced `encryption` block removed, without `TF_ENCRYPTION`, used for `init` and `output -raw canary` only (never plan, apply or migration). Its control and every other step keep the unchanged enforced root. A missing, differing or repeated block leaves the negative unattempted (`UNKNOWN`, diagnostics `null`). The enforced root without `TF_ENCRYPTION` is a configuration error (no method), not a read refusal, and stays `UNKNOWN`. Which phase R2 refuses at (init or read), and that this read leaves the remote state unwritten, are not observed; OpenTofu 1.12.3 `output` and S3 `StateMgr` source show only reads for an existing default workspace.
- The credential is `UNUSABLE_AFTER_TTL` only for a 401 reading the same marker after a usable control; otherwise it is `UNKNOWN`. Any issuance failure (transport, 5xx, malformed, 4xx) is `ISSUANCE_UNKNOWN`: the provider may still have issued one, so cleanup is at best `UNKNOWN` even when both buckets are gone.
- `diagnostics` records which branch produced each label, using only closed values. It explains an `UNKNOWN`; it never creates or changes a label or a check, and no value is a rejection or acceptance proof by itself. Diagnostics outside the closed sets are dropped (`null`). A `STATE_BACKEND_PROVEN` stands only with complete evidence: an entry for every negative and the post-TTL probe's status `401`; dropped, missing or `null` evidence makes it `UNKNOWN`, while an early stop may still carry `null` entries:
  - `negatives.<name>` (`null` when that negative did not run): `control` (the adjacent control succeeded), `phase` where the attempt stopped (`admitted`, or refused at `init`, `read`, `lock` or `write`, the object PUT), and the failure facts the cause is computed from.
  - `credential_probe`: `probe` (`not_run`, `admitted`, `refused` or `local_failure`), the same failure facts, `local` (`none`, `envs`, `os` or `subprocess`), and `code`: a completed failed reply's single direct S3 error code if it is one of R2's authentication and authorization codes (`Unauthorized`, `AccessDenied`, `ExpiredRequest`, `SignatureDoesNotMatch`, `NotEntitled`), `other` for any other parsed code, otherwise `none`. The code only narrows the investigation; it never changes a label, and the credential end is still only a completed 401.
  - Failure facts: `status` (`none`, `401`, `403`, `5xx`, `other`, `multiple`), `access_denied` (for OpenTofu the text named AccessDenied; for curl the parsed XML error code is AccessDenied), `transient` (timeout or connection noise; for curl any nonzero exit, such as a partial transfer, so no status or body it carried counts as a completed reply), `word` (`decrypt`, `encrypt`, `credential`, `none`). A status outranks the wording, as in the label rule.
  - A 403 with `access_denied` false is not `access_denied`. Captured output, status bodies, keys, credentials and exception text never reach the receipt; a value outside these sets drops `diagnostics` to `null`. A failure that ends the proof records `error` only as its kind (`envs`, `os` or `subprocess`), with `stage` saying where. A failure before or outside the receipt, including preflight, prints only `RENT_STATE_PROOF=RED: <kind>` (`envs`, `os`, `subprocess` or `other`) and exits non-zero: no exception text, class name or traceback reaches the job log.

- Every OpenTofu process gets its own directory and empty HOME. The parent token reaches only the bucket root, Wrangler and the Cloudflare API; the temporary credential and the `TF_ENCRYPTION` text reach only the backend root, by environment. Neither enters argv, `-backend-config`, a log line, the result JSON, an artifact, a cache or Git; the raw state object stays in process memory.
- Right after each create the run emits one evidence line per bucket (`envs.rentStateProofCreated.v1`: bucket, provider `creation_date`, run ID, attempt, head). Cleanup deletes only a bucket whose evidence and current `creation_date` match; a bucket name alone never authorizes deletion. The same parser reads those lines from a job log as recovery input for a later exact contract.
- `STATE_BACKEND_PROVEN` needs every positive check, every negative `REFUSED`, a usable control and `cleanup` `ABSENT` (buckets `ABSENT`, `owned` equal to every bucket this run's create evidence names, and the credential `UNUSABLE_AFTER_TTL`; a 404 for a created bucket never read back as owned is `UNKNOWN`, not absence). A remaining bucket is `LEFTOVER`; an unobserved credential end or unreadable evidence is `UNKNOWN`; either replaces the status, with no retry. Force cancellation or runner loss can bypass cleanup. The failure signatures above are to be confirmed by the live run.
- `checks/test_rent_state_proof.py` proves the gates, order, isolation, redaction, outcome classes, cleanup model and evidence parser against a fake provider; `check` initializes and validates both roots with network access closed and checks Wrangler's `r2 object get --pipe --remote` shape.
- `check` also runs it with `--real-tofu "$tool/tofu"`: the pinned closure OpenTofu writes, rotates and reads one synthetic state through a local backend with network access closed, using the adapter's own encryption configuration. It needs the new key to read, the old key alone to fail by decryption, and the raw state to be rewritten without the canary. Right after the new-key read, `no_config_read_refused` reads the same encrypted state from a copy of the root with no encryption block at all (init and output only, never plan or apply) and needs it refused for the adapter's own encryption or decryption cause, with the phase where it stopped; `no_config_state_unchanged` needs the raw state bytes identical afterwards. `enforced_init_refused` is a separate guard: the enforced root without `TF_ENCRYPTION` is rejected at init by its own configuration (no method) before any state is read, so it is not counted as a read refusal and its cause is not classified. This is a property of OpenTofu on a synthetic local root, not evidence for the live `unencrypted_read_refused` negative, whose backend root keeps the enforced block. It prints only the stage outcomes, fails if the tool cannot run, and leaves its fresh work directory to the ephemeral runner rather than deleting it. It proves OpenTofu's encryption metadata behaviour, not R2 or S3.
- `check` also runs it with `--real-s3 "$tool/curl"`: the closure curl sends real signed requests to a bounded in-process `127.0.0.1` HTTP fixture with synthetic credentials. It asserts the exact request order, method, path-style path, host, payload, SigV4 credential scope and `SignedHeaders` containing `x-amz-security-token` and `x-amz-content-sha256`, then keeps apart an XML 403 AccessDenied, a bodyless 403, a 401, a 404 NoSuchKey, a signature error, malformed, duplicate-code or text-only bodies, a 5xx, an unfollowed redirect, a timeout and partial transfers (exit 18) carrying an XML 403 AccessDenied, a 401 or the exact marker, all `UNKNOWN`, with no retry and no secret in argv or the environment. It also checks Wrangler's `r2 object put --pipe` shape and that curl is in the provided closure. The fixture is a transport test, not an S3 service or R2 evidence.
- `R2_PARENT_ACCESS_KEY_ID` is a secret input: as a variable its value was printed in the public step log (run 36797154456). The GitHub Environment still registers it as a variable; moving it is a later owner action. Until then the adapter's input gate rejects the missing secret before any provider call; that is source behaviour, not yet observed on a runner.

Not proven here: any real R2 effect, the parent token's permission (only the first bounded create proves it), R2 lock-file and prefix-scoped temporary-credential behaviour, whether R2 accepts curl's signature and returns XML AccessDenied for these scopes, or production state. A qualifying refusal shows only that the same credential was refused for that target, not which policy caused it. The live run needs its own contract.

## Effect toolchain

`flake.nix` and `flake.lock` define the only toolchain for authoring and projection: Python, SOPS, Wrangler, Git, GitHub CLI and curl from the locked nixpkgs input, plus the `envs-effect` entry running this source's adapter. `.#effect-artifact` is that entry's complete store closure as one tar with an `ENTRY` pointer.

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
