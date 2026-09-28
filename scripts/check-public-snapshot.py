#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519"}
FORBIDDEN_SUFFIXES = {".pem", ".p12", ".pfx"}
FORBIDDEN_PATTERNS = {
    "age private identity": re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
    "private key header": re.compile(
        rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(
        rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    ),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "npm token": re.compile(rb"\bnpm_[A-Za-z0-9]{30,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    "Stripe live key": re.compile(rb"\bsk_live_[0-9A-Za-z]{20,}\b"),
    "basic-auth URL": re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@[^\s]+"),
}
ACTION_USE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)")


def fail(message: str) -> None:
    raise SystemExit(message)


def jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            fail(f"{path.relative_to(ROOT)}:{number}: JSONL row is not an object")
        rows.append(value)
    return rows


def scan_tree() -> None:
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            fail(f"forbidden private-material filename: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(data):
                fail(f"{label} found in {path.relative_to(ROOT)}")
        if path.suffix == ".jsonl":
            jsonl(path)


def check_planes() -> bool:
    planes = {row["id"]: row for row in jsonl(ROOT / "environments/secret-planes.jsonl")}
    expected_ids = {
        "dev.authoring",
        "dev.projection",
        "dev.runtime",
        "stg.projection",
        "stg.runtime",
        "prd.projection",
        "prd.runtime",
    }
    if set(planes) != expected_ids:
        fail("secret-plane set differs")
    if any("std" in value for value in planes):
        fail("std is forbidden; use stg")

    for plane_id in ("dev.runtime", "stg.runtime", "prd.runtime"):
        if planes[plane_id]["owner"] != "target":
            fail(f"{plane_id}: runtime must be target-owned")

    for plane_id in ("stg.projection", "prd.projection"):
        row = planes[plane_id]
        if row["owner"] != "envs" or row["migration_state"] != "NOT_CONFIGURED":
            fail(f"{plane_id}: must remain envs-owned and NOT_CONFIGURED")
        if row["active_github_environment"] is not None:
            fail(f"{plane_id}: active Environment must be absent")

    cipher = ROOT / "secrets/jev-api-key.sops.yaml"
    configured = cipher.is_file()
    expected_dev = {
        "dev.authoring": "dev-authoring",
        "dev.projection": "dev-projection",
    }
    for plane_id, environment in expected_dev.items():
        row = planes[plane_id]
        if row["owner"] != "envs" or row["github_environment"] != environment:
            fail(f"{plane_id}: desired Environment contract mismatch")
        if configured:
            if (
                row["active_github_environment"] != environment
                or row["migration_state"] != "ACTIVE"
            ):
                fail(f"{plane_id}: configured ciphertext requires ACTIVE state")
        elif (
            row["active_github_environment"] is not None
            or row["migration_state"] != "NOT_CONFIGURED"
        ):
            fail(f"{plane_id}: pre-authoring state must be NOT_CONFIGURED")

    secrets_dir = ROOT / "secrets"
    if configured:
        actual = sorted(
            str(path.relative_to(ROOT)) for path in secrets_dir.rglob("*") if path.is_file()
        )
        if actual != ["secrets/jev-api-key.sops.yaml"]:
            fail(f"unexpected secret files: {actual}")
        body = cipher.read_text(encoding="utf-8")
        if "JEV_API_KEY: ENC[AES256_GCM," not in body or "\nsops:" not in body:
            fail("invalid SOPS ciphertext")
        recipients = re.findall(
            r"(?m)^\s*recipient:\s*(age1[0-9a-z]+)\s*$", body
        )
        if not recipients or len(recipients) != len(set(recipients)):
            fail("unique public age recipient is required")
    elif secrets_dir.exists() and any(secrets_dir.iterdir()):
        fail("secrets/ must be empty before new-key authoring")
    return configured


def check_workflows() -> None:
    paths = {
        "authoring": ROOT / ".github/workflows/secret-materialize.yml",
        "projection": ROOT / ".github/workflows/runtime-secret-projection.yml",
    }
    texts = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}

    for name, text in texts.items():
        for forbidden in ("pull_request_target:", "secrets: inherit", "environment: ${{"):
            if forbidden in text:
                fail(f"{name}: forbidden workflow marker {forbidden}")
        for action, ref in ACTION_USE.findall(text):
            if not action.startswith(("./", "docker://")) and not re.fullmatch(
                r"[0-9a-f]{40}", ref
            ):
                fail(f"{name}: mutable Action {action}@{ref}")

    authoring = texts["authoring"]
    for marker in (
        "github.repository == 'roccho-dev/envs'",
        "github.ref_name == 'proposals'",
        "environment: dev-authoring",
        "environment: dev-projection",
        "github.event_name == 'workflow_dispatch'",
    ):
        if marker not in authoring:
            fail(f"authoring workflow missing {marker}")

    projection = texts["projection"]
    for marker in (
        "workflow_dispatch:",
        "github.repository == 'roccho-dev/envs'",
        "github.ref_name == 'proposals'",
        "environment: dev-projection",
    ):
        if marker not in projection:
            fail(f"projection workflow missing {marker}")
    if "\n  push:" in projection or "\n  pull_request:" in projection:
        fail("projection effect must be manual-only")


def main() -> None:
    scan_tree()
    configured = check_planes()
    check_workflows()
    print("SNAPSHOT_SAFETY=PASS")
    print("SECRET_PLANES=PASS")
    print("SOPS_STATE=" + ("ACTIVE" if configured else "NOT_CONFIGURED"))


if __name__ == "__main__":
    main()
