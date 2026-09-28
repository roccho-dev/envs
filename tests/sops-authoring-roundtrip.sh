#!/usr/bin/env bash
set -euo pipefail

for command in age-keygen sops jq; do
  command -v "$command" >/dev/null
 done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

identity_a="$tmp/identity-a.txt"
identity_b="$tmp/identity-b.txt"
age-keygen -o "$identity_a" >/dev/null 2>&1
age-keygen -o "$identity_b" >/dev/null 2>&1
chmod 0600 "$identity_a" "$identity_b"
recipient_a="$(age-keygen -y "$identity_a")"
recipient_b="$(age-keygen -y "$identity_b")"
recipients="$recipient_a,$recipient_b"

plain="$tmp/plain.json"
cipher="$tmp/cipher.yaml"
printf '%s\n' '{"JEV_API_KEY":"roundtrip-fixture-secret"}' > "$plain"

sops --encrypt --input-type json --output-type yaml \
  --age "$recipients" \
  "$plain" > "$cipher"

grep -q '^JEV_API_KEY: ENC\[AES256_GCM,' "$cipher"
grep -q '^sops:' "$cipher"
! grep -Fq 'roundtrip-fixture-secret' "$cipher"
! grep -Fq 'AGE-SECRET-KEY-' "$cipher"

test "$(grep -c '^\s*recipient: age1' "$cipher")" -eq 2

for identity in "$identity_a" "$identity_b"; do
  decrypted="$(SOPS_AGE_KEY_FILE="$identity" sops --decrypt --output-type json "$cipher")"
  test "$(jq -r '.JEV_API_KEY' <<< "$decrypted")" = roundtrip-fixture-secret
done

printf 'sops-authoring-roundtrip: PASS\n'
