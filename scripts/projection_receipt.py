#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

KIND = "envs.projectionReceipt.v1"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_KEYS = {
    "secret",
    "secret_value",
    "plaintext",
    "private_key",
    "age_identity",
    "decrypted_value",
    "secret_hash",
}
FORBIDDEN_STRING_PATTERNS = (
    re.compile(r"AGE-" + r"SECRET-" + r"KEY-1[0-9A-Z]{20,}"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
)


class ReceiptError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReceiptError(message)


def _walk(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(key not in FORBIDDEN_KEYS, f"{path}: forbidden key {key}")
            _walk(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in FORBIDDEN_STRING_PATTERNS:
            require(not pattern.search(value), f"{path}: forbidden private material")


def validate(receipt: dict[str, Any]) -> None:
    require(
        set(receipt)
        == {
            "kind",
            "status",
            "envs_sha",
            "environment",
            "capability",
            "source",
            "target",
            "projector",
            "effect",
            "readback",
            "workflow",
            "created_at",
        },
        "receipt top-level fields differ",
    )
    require(receipt["kind"] == KIND, "invalid receipt kind")
    require(receipt["status"] == "PASS", "projection receipt must represent PASS only")
    require(bool(SHA40.fullmatch(receipt["envs_sha"])), "invalid envs SHA")
    require(receipt["environment"] == "dev", "receipt environment must be dev")
    require(receipt["capability"] == "jev-api", "receipt capability must be jev-api")

    source = receipt["source"]
    require(
        source
        == {
            "kind": "public_sops",
            "ref": "secrets/jev-api-key.sops.yaml",
            "sha256": source.get("sha256"),
        },
        "source contract differs",
    )
    require(bool(SHA256.fullmatch(source["sha256"])), "invalid ciphertext digest")

    target = receipt["target"]
    require(
        set(target) == {"provider", "account_id", "project", "secret_name"},
        "target fields differ",
    )
    require(target["provider"] == "cloudflare-pages", "unexpected target provider")
    require(isinstance(target["account_id"], str) and target["account_id"], "missing account id")
    require(target["project"] == "voice-ui", "unexpected target project")
    require(target["secret_name"] == "JEV_API_KEY", "unexpected target secret name")

    require(
        receipt["projector"]
        == {
            "workflow": ".github/workflows/runtime-secret-projection.yml",
            "script": "scripts/runtime-secret-projection.sh",
        },
        "projector identity differs",
    )
    require(
        receipt["effect"]
        == {"operation": "cloudflare_pages_secret_put", "status": "PASS"},
        "provider effect is not PASS",
    )
    require(
        receipt["readback"]
        == {
            "kind": "secret_name_presence",
            "status": "PASS",
            "present": True,
        },
        "provider readback is not PASS",
    )

    workflow = receipt["workflow"]
    require(
        set(workflow) == {"repository", "ref", "run_id", "run_attempt"},
        "workflow fields differ",
    )
    require(workflow["repository"] == "roccho-dev/envs", "unexpected workflow repository")
    require(workflow["ref"] == "proposals", "workflow ref must be proposals")
    require(isinstance(workflow["run_id"], int) and workflow["run_id"] > 0, "invalid run id")
    require(
        isinstance(workflow["run_attempt"], int) and workflow["run_attempt"] > 0,
        "invalid run attempt",
    )

    created_at = receipt["created_at"]
    require(isinstance(created_at, str) and created_at.endswith("Z"), "invalid timestamp")
    try:
        datetime.fromisoformat(created_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ReceiptError("invalid timestamp") from exc

    _walk(receipt)


def build(args: argparse.Namespace) -> dict[str, Any]:
    receipt = {
        "kind": KIND,
        "status": "PASS",
        "envs_sha": args.envs_sha,
        "environment": "dev",
        "capability": "jev-api",
        "source": {
            "kind": "public_sops",
            "ref": "secrets/jev-api-key.sops.yaml",
            "sha256": f"sha256:{args.source_sha256}",
        },
        "target": {
            "provider": "cloudflare-pages",
            "account_id": args.account_id,
            "project": "voice-ui",
            "secret_name": "JEV_API_KEY",
        },
        "projector": {
            "workflow": ".github/workflows/runtime-secret-projection.yml",
            "script": "scripts/runtime-secret-projection.sh",
        },
        "effect": {
            "operation": "cloudflare_pages_secret_put",
            "status": "PASS",
        },
        "readback": {
            "kind": "secret_name_presence",
            "status": "PASS",
            "present": True,
        },
        "workflow": {
            "repository": "roccho-dev/envs",
            "ref": "proposals",
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
        },
        "created_at": args.created_at,
    }
    validate(receipt)
    return receipt


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "receipt must be an object")
    validate(value)
    return value


def write(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--envs-sha", required=True)
    build_parser.add_argument("--source-sha256", required=True)
    build_parser.add_argument("--account-id", required=True)
    build_parser.add_argument("--run-id", type=int, required=True)
    build_parser.add_argument("--run-attempt", type=int, required=True)
    build_parser.add_argument("--created-at", required=True)
    build_parser.add_argument("--output", type=Path, required=True)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("path", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "build":
            write(args.output, build(args))
            print(f"PROJECTION_RECEIPT=PASS path={args.output}")
        else:
            load(args.path)
            print(f"PROJECTION_RECEIPT=PASS path={args.path}")
    except (ReceiptError, json.JSONDecodeError, OSError) as exc:
        print(f"PROJECTION_RECEIPT=RED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
