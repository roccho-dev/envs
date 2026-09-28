#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
repo="${REPOSITORY:-roccho-dev/envs}"
ref="${REF:-proposals}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 2
  }
}

require_command gh

case "$mode" in
  configure)
    require_command age-keygen
    : "${AGE_IDENTITY_FILE:?set AGE_IDENTITY_FILE to a protected age identity file}"
    : "${JEV_API_KEY:?set the replacement JEV_API_KEY}"
    : "${CLOUDFLARE_API_TOKEN:?set the replacement CLOUDFLARE_API_TOKEN}"
    : "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
    test -f "$AGE_IDENTITY_FILE"
    test ! -L "$AGE_IDENTITY_FILE"

    recipient="$(age-keygen -y "$AGE_IDENTITY_FILE")"
    [[ "$recipient" =~ ^age1[0-9a-z]+$ ]]
    recipients="$recipient"
    if [ -n "${ADDITIONAL_AGE_RECIPIENTS:-}" ]; then
      recipients="$recipient,$ADDITIONAL_AGE_RECIPIENTS"
    fi

    gh api --method PUT "repos/$repo/environments/dev-authoring" >/dev/null
    gh api --method PUT "repos/$repo/environments/dev-projection" >/dev/null

    printf '%s' "$JEV_API_KEY" \
      | gh secret set JEV_API_KEY --repo "$repo" --env dev-authoring --body -
    gh variable set SOPS_AGE_RECIPIENTS \
      --repo "$repo" --env dev-authoring --body "$recipients"

    gh secret set SOPS_AGE_KEY \
      --repo "$repo" --env dev-projection < "$AGE_IDENTITY_FILE"
    printf '%s' "$CLOUDFLARE_API_TOKEN" \
      | gh secret set CLOUDFLARE_API_TOKEN --repo "$repo" --env dev-projection --body -
    gh variable set CLOUDFLARE_ACCOUNT_ID \
      --repo "$repo" --env dev-projection --body "$CLOUDFLARE_ACCOUNT_ID"

    gh workflow run secret-materialize.yml --repo "$repo" --ref "$ref"
    printf 'CONFIGURED=PASS\n'
    printf 'NEXT=merge the generated ciphertext PR, then run cleanup-authoring and project\n'
    ;;

  cleanup-authoring)
    gh secret delete JEV_API_KEY --repo "$repo" --env dev-authoring
    printf 'DEV_AUTHORING_INGRESS=REMOVED\n'
    ;;

  project)
    gh workflow run runtime-secret-projection.yml --repo "$repo" --ref "$ref"
    printf 'PROJECTION_DISPATCHED=PASS\n'
    ;;

  status)
    gh api "repos/$repo/environments" \
      --jq '.environments[] | [.name, .protection_rules | length] | @tsv'
    ;;

  *)
    echo "usage: $0 configure|cleanup-authoring|project|status" >&2
    exit 64
    ;;
esac
