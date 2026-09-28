#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from projection_receipt import ReceiptError, load as load_receipt

ROOT = Path(__file__).resolve().parents[1]


class ReadinessError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadinessError(message)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        require(isinstance(value, dict), f"{path}:{number}: row must be an object")
        rows.append(value)
    return rows


def evaluate() -> dict[str, Any]:
    planes = {
        row["id"]: row
        for row in load_jsonl(ROOT / "environments/secret-planes.jsonl")
    }
    authoring = planes["dev.authoring"]
    projection = planes["dev.projection"]
    cipher = ROOT / "secrets/jev-api-key.sops.yaml"
    handoff = ROOT / "handoffs/dev/jev-api.json"

    configured = cipher.is_file()
    if configured:
        for plane, environment in (
            (authoring, "dev-authoring"),
            (projection, "dev-projection"),
        ):
            require(
                plane["active_github_environment"] == environment
                and plane["migration_state"] == "ACTIVE",
                "configured ciphertext requires active dev planes",
            )
    else:
        require(
            authoring["active_github_environment"] is None
            and projection["active_github_environment"] is None
            and authoring["migration_state"] == "NOT_CONFIGURED"
            and projection["migration_state"] == "NOT_CONFIGURED",
            "pre-authoring dev planes must remain NOT_CONFIGURED",
        )

    handoff_state = "ABSENT"
    physical_state = "NOT_CONFIGURED" if not configured else "NOT_RUN"
    receipt_source_sha256: str | None = None
    current_source_sha256: str | None = None

    if configured:
        current_source_sha256 = "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest()

    if handoff.is_file():
        require(configured, "projection handoff cannot exist without ciphertext")
        receipt = load_receipt(handoff)
        receipt_source_sha256 = receipt["source"]["sha256"]
        if receipt_source_sha256 == current_source_sha256:
            handoff_state = "PASS"
            physical_state = "PASS"
        else:
            handoff_state = "STALE"
            physical_state = "STALE"

    return {
        "kind": "envs.providerReadiness.v1",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "jev-api",
        "public_source_provider": "PASS",
        "small_non_secret_contracts": "PASS_SCOPED",
        "provider_mechanism": "PASS_SOURCE",
        "physical_dev_projection": physical_state,
        "provider_handoff_receipt": handoff_state,
        "provider_handoff_ready": handoff_state == "PASS",
        "consumer_runtime_readiness": "OUT_OF_SCOPE",
        "current_ciphertext_sha256": current_source_sha256,
        "receipt_ciphertext_sha256": receipt_source_sha256,
    }


def main() -> int:
    try:
        value = evaluate()
    except (ReadinessError, ReceiptError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"PROVIDER_READINESS=RED: {exc}")
        return 1
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
