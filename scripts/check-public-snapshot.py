#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from provider_readiness import evaluate as evaluate_provider_readiness
from projection_receipt import ReceiptError

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


def jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
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
        if (
            not path.is_file()
            or ".git" in path.parts
            or "__pycache__" in path.parts
            or path.suffix == ".pyc"
        ):
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            fail(f"forbidden private-material filename: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(data):
                fail(f"{label} found in {path.relative_to(ROOT)}")
        if path.suffix == ".jsonl":
            jsonl(path)


def check_provider_consumer_boundary() -> None:
    path = ROOT / "contracts/provider-consumer.jsonl"
    rows = {row["id"]: row for row in jsonl(path)}
    expected_ids = {
        "dev.jev-api.provider",
        "apps.voice-ui.consumer",
        "ops.voice-ui.consumer",
        "normal.consumer.path",
    }
    if set(rows) != expected_ids:
        fail("provider/consumer boundary set differs")

    provider = rows["dev.jev-api.provider"]
    expected_provider = {
        "id": "dev.jev-api.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "historical_repository": "roccho-dev/envs-old",
        "historical_repository_mode": "evidence_only",
        "stage": "dev",
        "capability": "jev-api",
        "source_kind": "public_sops",
        "target_kind": "target_native_auth",
        "owns": [
            "contract",
            "authoring",
            "projection",
            "provider_readback",
            "projection_receipt",
        ],
        "does_not_own": [
            "application_runtime_acceptance",
            "consumer_independent_execution",
        ],
        "handoff_ref_kind": "exact_commit_sha",
    }
    if provider != expected_provider:
        fail("provider boundary differs")

    apps = rows["apps.voice-ui.consumer"]
    if apps != {
        "id": "apps.voice-ui.consumer",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "consumer",
        "repository": "roccho-dev/apps",
        "stage": "dev",
        "capability": "jev-api",
        "owns": [
            "application_artifact",
            "capability_declaration",
            "application_runtime_acceptance",
        ],
        "requires": [
            "target_native_auth",
            "projection_receipt",
            "real_provider_use",
        ],
    }:
        fail("apps boundary differs")

    ops = rows["ops.voice-ui.consumer"]
    if ops != {
        "id": "ops.voice-ui.consumer",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "consumer",
        "repository": "roccho-dev/ops",
        "stage": "dev",
        "capability": "jev-api",
        "owns": [
            "exact_deploy",
            "deployment_readback",
            "apps_acceptance_invocation",
            "independent_execution_twice",
        ],
        "requires": [
            "target_native_auth",
            "projection_receipt",
            "apps_runtime_acceptance",
        ],
    }:
        fail("ops boundary differs")

    normal = rows["normal.consumer.path"]
    if normal != {
        "id": "normal.consumer.path",
        "kind": "envs.consumerExecutionBoundary.v1",
        "applies_to": ["roccho-dev/apps", "roccho-dev/ops"],
        "forbids": [
            "envs_checkout",
            "envs_workflow_dispatch",
            "envs_workflow_wait",
            "envctl_parent",
            "envctl_auth_exec",
            "auth_bundle",
            "sops",
            "age_identity",
            "github_environment_source_secret",
            "envs_old_fallback",
            "old_private_artifact_fallback",
        ],
    }:
        fail("normal consumer path differs")


def check_active_fallbacks() -> None:
    historical_repository = "roccho-dev/" + "envs-old"
    forbidden_runtime_terms = (
        historical_repository,
        "envctl auth exec",
        "auth-bundle",
    )
    roots = (
        ".github/workflows",
        "scripts",
        "cmd",
        "internal",
        "bindings",
        "environments",
        "lib",
        "modules",
    )
    for root_name in roots:
        root = ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for term in forbidden_runtime_terms:
                if term in text:
                    fail(
                        f"{path.relative_to(ROOT)}: active path contains forbidden fallback {term}"
                    )


def check_planes() -> bool:
    planes = {
        row["id"]: row for row in jsonl(ROOT / "environments/secret-planes.jsonl")
    }
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
            str(path.relative_to(ROOT))
            for path in secrets_dir.rglob("*")
            if path.is_file()
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
        "scripts/projection_receipt.py build",
        "handoffs/dev/jev-api.json",
    ):
        if marker not in projection:
            fail(f"projection workflow missing {marker}")
    if "\n  push:" in projection or "\n  pull_request:" in projection:
        fail("projection effect must be manual-only")


def check_readiness() -> dict[str, Any]:
    try:
        value = evaluate_provider_readiness()
    except (ReceiptError, ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        fail(f"provider readiness invalid: {exc}")
    if value["consumer_runtime_readiness"] != "OUT_OF_SCOPE":
        fail("envs must not claim consumer runtime readiness")
    if value["provider_handoff_ready"] and value["provider_handoff_receipt"] != "PASS":
        fail("provider handoff readiness is inconsistent")
    return value


def main() -> None:
    scan_tree()
    check_provider_consumer_boundary()
    check_active_fallbacks()
    configured = check_planes()
    check_workflows()
    readiness = check_readiness()
    print("SNAPSHOT_SAFETY=PASS")
    print("PROVIDER_CONSUMER_BOUNDARY=PASS")
    print("SECRET_PLANES=PASS")
    print("SOPS_STATE=" + ("ACTIVE" if configured else "NOT_CONFIGURED"))
    print("PROVIDER_HANDOFF=" + readiness["provider_handoff_receipt"])
    print("CONSUMER_RUNTIME_READINESS=OUT_OF_SCOPE")


if __name__ == "__main__":
    main()
