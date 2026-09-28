#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

bash scripts/runtime-secret-projection.sh check

tmp="$(mktemp -d)"
planes="environments/secret-planes.jsonl"
planes_backup="$tmp/secret-planes.jsonl"
cp "$planes" "$planes_backup"
cleanup() {
  cp "$planes_backup" "$planes"
  rm -rf secrets "$tmp"
}
trap cleanup EXIT

mkdir -p secrets
cat > secrets/jev-api-key.sops.yaml <<'YAML'
JEV_API_KEY: ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:str]
sops:
    age:
        - enc: fixture
          recipient: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqd3p8z
    version: 3.13.2
YAML

python3 - <<'PY'
import json
from pathlib import Path

path = Path("environments/secret-planes.jsonl")
rows = []
for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    row = json.loads(line)
    if row["id"] == "dev.authoring":
        row["active_github_environment"] = "dev-authoring"
        row["migration_state"] = "ACTIVE"
    if row["id"] == "dev.projection":
        row["active_github_environment"] = "dev-projection"
        row["migration_state"] = "ACTIVE"
    rows.append(row)
path.write_text(
    "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
    encoding="utf-8",
)
PY

bash scripts/runtime-secret-projection.sh check-configured

provider_state="$tmp/provider-state"
npx_log="$tmp/npx.log"
run_log="$tmp/run.log"
printf 'before\n' >"$provider_state"

cat >"$tmp/fake-sops" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
test "${1:-}" = "--decrypt"
case "${FAKE_SOPS_MODE:-}" in
  keyed)
    if [ "${SOPS_AGE_KEY:-}" != "matching-key" ]; then
      echo "no identity matched" >&2
      exit 7
    fi
    printf '{"JEV_API_KEY":"fixture-secret"}'
    ;;
  missing)
    printf '{}'
    ;;
  empty)
    printf '{"JEV_API_KEY":""}'
    ;;
  *)
    exit 8
    ;;
esac
SH
chmod +x "$tmp/fake-sops"

cat >"$tmp/fake-npx" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_NPX_LOG"
case "$*" in
  *"pages secret put"*)
    cat >"$FAKE_PROVIDER_STATE"
    ;;
  *"pages secret list"*)
    printf 'JEV_API_KEY\n'
    ;;
  *)
    exit 9
    ;;
esac
SH
chmod +x "$tmp/fake-npx"

export APPLICATION=voice-ui
export CLOUDFLARE_ACCOUNT_ID=test-account
export CLOUDFLARE_API_TOKEN=test-token
export SOPS_BIN="$tmp/fake-sops"
export NPX_BIN="$tmp/fake-npx"
export RUNNER_TEMP="$tmp"
export FAKE_NPX_LOG="$npx_log"
export FAKE_PROVIDER_STATE="$provider_state"

assert_no_effect() {
  test "$(cat "$provider_state")" = "before"
  test ! -s "$npx_log"
}

export FAKE_SOPS_MODE=keyed
export SOPS_AGE_KEY=mismatched-key
if bash scripts/runtime-secret-projection.sh project >"$run_log" 2>&1; then
  echo "mismatched key unexpectedly projected" >&2
  exit 1
fi
assert_no_effect

export FAKE_SOPS_MODE=missing
export SOPS_AGE_KEY=matching-key
if bash scripts/runtime-secret-projection.sh project >"$run_log" 2>&1; then
  echo "missing JEV_API_KEY unexpectedly projected" >&2
  exit 1
fi
assert_no_effect

export FAKE_SOPS_MODE=empty
if bash scripts/runtime-secret-projection.sh project >"$run_log" 2>&1; then
  echo "empty JEV_API_KEY unexpectedly projected" >&2
  exit 1
fi
assert_no_effect

export FAKE_SOPS_MODE=keyed
bash scripts/runtime-secret-projection.sh project >"$run_log" 2>&1
grep -Fq 'pages secret put' "$npx_log"
grep -Fq 'pages secret list' "$npx_log"
test "$(cat "$provider_state")" = "fixture-secret"
! grep -Fq 'fixture-secret' "$run_log"

printf 'runtime-secret-projection destructive: PASS\n'
