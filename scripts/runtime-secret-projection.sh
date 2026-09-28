#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
project="voice-ui"
secret_name="JEV_API_KEY"
cipher="secrets/jev-api-key.sops.yaml"
wrangler_version="4.112.0"
npx_bin="${NPX_BIN:-npx}"

check_contract() {
  local require_configured="${1:-false}"
  REQUIRE_CONFIGURED="$require_configured" python3 - <<'PY'
import json
import os
import re
from pathlib import Path


def rows(path: str):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

apps = rows("bindings/apps.jsonl")
voice = [row for row in apps if row.get("id") == "voice-ui"]
if voice != [{
    "id": "voice-ui",
    "kind": "envs.applicationBinding.v1",
    "application": "roccho-dev/apps/packages/voice-ui",
}]:
    raise SystemExit("voice-ui application binding mismatch")

auth = rows("bindings/auth.jsonl")
jev = [row for row in auth if row.get("id") == "jev-api"]
if jev != [{
    "id": "jev-api",
    "kind": "envs.authCapability.v1",
    "capability": "jev-api",
    "secret": "secrets/jev-api-key.sops.yaml",
    "inject": {
        "type": "env",
        "name": "JEV_API_KEY",
        "sourceKey": "JEV_API_KEY",
    },
}]:
    raise SystemExit("jev-api auth binding mismatch")

for environment in ("local", "stg", "prd"):
    matches = [
        row
        for row in rows(f"environments/{environment}.jsonl")
        if row.get("application") == "voice-ui"
        and row.get("environment") == environment
        and row.get("bindingRef") == "voice-ui"
    ]
    if len(matches) != 1:
        raise SystemExit(f"voice-ui {environment} binding must exist exactly once")

local_auth = [
    row
    for row in rows("environments/local.jsonl")
    if row.get("kind") == "envs.authEnvironment.v1"
    and row.get("environment") == "local"
]
if len(local_auth) != 1 or local_auth[0].get("availableCapabilities") != ["jev-api"]:
    raise SystemExit("local auth environment must provide exactly jev-api")

planes = {row["id"]: row for row in rows("environments/secret-planes.jsonl")}
for plane_id, desired in (
    ("dev.authoring", "dev-authoring"),
    ("dev.projection", "dev-projection"),
):
    plane = planes.get(plane_id)
    if not plane or plane.get("owner") != "envs":
        raise SystemExit(f"{plane_id}: envs-owned plane is required")
    if plane.get("github_environment") != desired:
        raise SystemExit(f"{plane_id}: desired Environment mismatch")

projection = planes["dev.projection"]
if projection.get("source_kind") != "public_sops":
    raise SystemExit("dev.projection source must be public_sops")
if projection.get("target_kind") != "target_native_auth":
    raise SystemExit("dev.projection target must be target_native_auth")

for plane_id in ("dev.runtime", "stg.runtime", "prd.runtime"):
    if planes.get(plane_id, {}).get("owner") != "target":
        raise SystemExit(f"{plane_id}: runtime must be target-owned")

for plane_id in ("stg.projection", "prd.projection"):
    plane = planes.get(plane_id, {})
    if plane.get("migration_state") != "NOT_CONFIGURED":
        raise SystemExit(f"{plane_id}: must remain NOT_CONFIGURED")

cipher_path = Path("secrets/jev-api-key.sops.yaml")
configured = cipher_path.is_file()
require_configured = os.environ["REQUIRE_CONFIGURED"] == "true"

for plane_id, environment in (
    ("dev.authoring", "dev-authoring"),
    ("dev.projection", "dev-projection"),
):
    plane = planes[plane_id]
    if configured:
        if plane.get("active_github_environment") != environment:
            raise SystemExit(f"{plane_id}: active Environment mismatch")
        if plane.get("migration_state") != "ACTIVE":
            raise SystemExit(f"{plane_id}: configured ciphertext requires ACTIVE state")
    else:
        if plane.get("active_github_environment") is not None:
            raise SystemExit(f"{plane_id}: active Environment must be absent before authoring")
        if plane.get("migration_state") != "NOT_CONFIGURED":
            raise SystemExit(f"{plane_id}: pre-authoring state must be NOT_CONFIGURED")

if require_configured and not configured:
    raise SystemExit("dev SOPS ciphertext is not configured")

if configured:
    cipher = cipher_path.read_text(encoding="utf-8")
    if "JEV_API_KEY: ENC[AES256_GCM," not in cipher or "\nsops:" not in cipher:
        raise SystemExit("exact Jev SOPS ciphertext is required")
    if "state: unprovisioned" in cipher:
        raise SystemExit("placeholder ciphertext is forbidden")
    if re.search(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}", cipher):
        raise SystemExit("private decrypt identity is forbidden")
    recipients = re.findall(r"(?m)^\s*recipient:\s*(age1[0-9a-z]+)\s*$", cipher)
    if not recipients or len(recipients) != len(set(recipients)):
        raise SystemExit("unique public age recipient is required")
else:
    secrets = Path("secrets")
    if secrets.exists() and any(secrets.iterdir()):
        raise SystemExit("unexpected secret file before authoring")

workflow_expectations = {
    ".github/workflows/secret-materialize.yml": (
        "environment: dev-authoring",
        "github.repository == 'roccho-dev/envs'",
        "github.ref_name == 'proposals'",
    ),
    ".github/workflows/runtime-secret-projection.yml": (
        "environment: dev-projection",
        "github.repository == 'roccho-dev/envs'",
        "github.ref_name == 'proposals'",
    ),
}
for path, markers in workflow_expectations.items():
    text = Path(path).read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"{path}: missing {marker}")
    for forbidden in ("pull_request_target:", "secrets: inherit", "environment: ${{"):
        if forbidden in text:
            raise SystemExit(f"{path}: forbidden marker {forbidden}")

print("DEV_SECRET_CONTRACT=PASS")
print("DEV_SOPS_STATE=" + ("ACTIVE" if configured else "NOT_CONFIGURED"))
PY
}

prepare_secret() {
  local out="$1"
  local tmp
  tmp="$(mktemp "${RUNNER_TEMP:-/tmp}/jev-decrypt.XXXXXX.json")"
  chmod 0600 "$tmp"

  if ! "$SOPS_BIN" --decrypt --output-type json "$cipher" >"$tmp"; then
    rm -f "$tmp" "$out"
    return 1
  fi
  if ! jq -e '.JEV_API_KEY | type == "string" and length > 0' "$tmp" >/dev/null; then
    rm -f "$tmp" "$out"
    return 1
  fi
  if ! jq -jer '.JEV_API_KEY' "$tmp" >"$out"; then
    rm -f "$tmp" "$out"
    return 1
  fi

  chmod 0600 "$out"
  rm -f "$tmp"
  test -s "$out" || {
    rm -f "$out"
    return 1
  }
}

case "$mode" in
  check)
    check_contract false
    ;;
  check-configured)
    check_contract true
    ;;
  project)
    check_contract true
    test "${APPLICATION:-}" = "voice-ui"
    test -n "${CLOUDFLARE_ACCOUNT_ID:-}"
    test -n "${CLOUDFLARE_API_TOKEN:-}"
    test -n "${SOPS_AGE_KEY:-}"
    test -x "${SOPS_BIN:-}"

    tmpdir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/jev-projection.XXXXXX")"
    trap 'rm -rf "$tmpdir"' EXIT
    secret_file="$tmpdir/jev-api-key"

    export SOPS_AGE_KEY
    prepare_secret "$secret_file"

    "$npx_bin" --yes "wrangler@$wrangler_version" pages secret put \
      "$secret_name" \
      --project-name "$project" \
      <"$secret_file"

    current="$(
      "$npx_bin" --yes "wrangler@$wrangler_version" pages secret list \
        --project-name "$project"
    )"
    grep -Fq "$secret_name" <<<"$current"
    ;;
  *)
    echo "usage: $0 check|check-configured|project" >&2
    exit 64
    ;;
esac
