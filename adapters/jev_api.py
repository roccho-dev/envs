#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENTS = Path("contracts/environments.jsonl")
BINDINGS = Path("contracts/bindings.jsonl")
BOUNDARY = Path("contracts/provider-consumer.jsonl")
CIPHERTEXT = Path("ciphertexts/dev-jev-api.sops.yaml")
HANDOFF = Path("handoffs/dev-jev-api.json")
FLAKE_LOCK = Path("flake.lock")
RECEIPT_KIND = "envs.projectionReceipt.v1"
TOOLCHAIN_KIND = "envs.effectToolchain.v1"
TOOLCHAIN_TOOLS = ("python3", "sops", "wrangler", "git", "gh")
STORE = Path("/nix/store")

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
AGE_RECIPIENT = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")
AGE_IDENTITY = re.compile(r"^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$")
CLOUDFLARE_ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
RECIPIENT_METADATA = re.compile(r"(?m)^[ \t]*-?[ \t]*recipient:[ \t]*(age1[0-9a-z]+)[ \t]*$")
PRIVATE_MATERIAL = (
    re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
)
FORBIDDEN_RECEIPT_KEYS = {
    "secret", "secret_value", "plaintext", "private_key", "age_identity",
    "decrypted_value", "secret_hash", "account_id",
}
SECRET_PLANE_KEYS = {
    "id", "kind", "stage_id", "plane_id", "owner", "github_environment",
    "active_github_environment", "migration_state", "source_kind", "target_kind", "desired_state",
}


class EnvsError(ValueError):
    pass


Runner = Callable[
    [Sequence[str], bytes | None, Mapping[str, str] | None],
    subprocess.CompletedProcess[bytes],
]


def require(ok: bool, message: str) -> None:
    if not ok:
        raise EnvsError(message)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EnvsError(f"{path}:{number}: invalid JSON") from exc
        require(isinstance(value, dict), f"{path}:{number}: row must be an object")
        rows.append(value)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def index(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in load_jsonl(path):
        identity = row.get("id")
        require(isinstance(identity, str) and identity, f"{path}: missing id")
        require(identity not in result, f"{path}: duplicate id {identity}")
        result[identity] = row
    return result


def expected_bindings() -> dict[str, dict[str, Any]]:
    return {
        "voice-ui": {
            "id": "voice-ui",
            "kind": "envs.applicationBinding.v1",
            "application": "roccho-dev/apps/packages/voice-ui",
        },
        "jev-api": {
            "id": "jev-api",
            "kind": "envs.authCapability.v1",
            "capability": "jev-api",
            "ciphertext": CIPHERTEXT.as_posix(),
            "source_key": "JEV_API_KEY",
            "target": {
                "provider": "cloudflare-pages",
                "project": "voice-ui",
                "secret_name": "JEV_API_KEY",
            },
        },
    }


def expected_inputs() -> dict[str, dict[str, list[dict[str, str]]]]:
    def entries(*values: tuple[str, str, str]) -> list[dict[str, str]]:
        return [{"name": name, "type": kind, "lifecycle": lifecycle} for name, kind, lifecycle in values]

    def stage_projection() -> dict[str, list[dict[str, str]]]:
        return {
            "required_secrets": entries(
                ("JEV_API_KEY", "opaque", "persistent"),
                ("CLOUDFLARE_API_TOKEN", "opaque", "persistent"),
            ),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        }

    return {
        "dev.authoring": {
            "required_secrets": entries(("JEV_API_KEY", "opaque", "one_shot_ingress")),
            "required_variables": entries(("SOPS_AGE_RECIPIENTS", "age_recipient_list", "persistent")),
        },
        "dev.projection": {
            "required_secrets": entries(
                ("SOPS_AGE_KEY", "age_identity", "persistent"),
                ("CLOUDFLARE_API_TOKEN", "opaque", "persistent"),
            ),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        },
        "stg.projection": stage_projection(),
        "prd.projection": stage_projection(),
    }


def recipient_items(value: str) -> list[str] | None:
    items = value.split(",")
    if all(AGE_RECIPIENT.fullmatch(item) for item in items) and len(items) == len(set(items)):
        return items
    return None


def is_age_identity(value: str) -> bool:
    # Native age-keygen output: comment and blank lines plus exactly one X25519 identity.
    lines = [line.strip() for line in value.splitlines()]
    identities = [line for line in lines if line and not line.startswith("#")]
    return len(identities) == 1 and AGE_IDENTITY.fullmatch(identities[0]) is not None


INPUT_TYPES: dict[str, Callable[[str], bool]] = {
    "opaque": lambda value: True,
    "age_identity": is_age_identity,
    "age_recipient_list": lambda value: recipient_items(value) is not None,
    "cloudflare_account_id": lambda value: CLOUDFLARE_ACCOUNT_ID.fullmatch(value) is not None,
}


def validate_contracts(root: Path = ROOT) -> dict[str, dict[str, dict[str, Any]]]:
    envs = index(root / ENVIRONMENTS)
    bindings = index(root / BINDINGS)
    boundary = index(root / BOUNDARY)

    require(set(envs) == {
        "dev.authoring", "dev.projection", "dev.runtime",
        "stg.projection", "stg.runtime", "prd.projection", "prd.runtime",
        "voice-ui.dev", "voice-ui.stg", "voice-ui.prd",
    }, "environment set differs")

    require(envs["dev.authoring"]["github_environment"] == "dev-authoring", "dev authoring Environment differs")
    require(envs["dev.projection"]["github_environment"] == "dev-projection", "dev projection Environment differs")
    inputs = expected_inputs()
    for identity, row in envs.items():
        if row["kind"] != "envs.secretPlane.v1":
            continue
        declared = inputs.get(identity, {})
        require(set(row) == SECRET_PLANE_KEYS | set(declared), f"{identity} fields differ")
        require((row["github_environment"] is not None) == bool(declared), f"{identity} required inputs differ")
        for group, entries in declared.items():
            require(row[group] == entries, f"{identity} {group} differ")

    for stage in ("dev", "stg", "prd"):
        runtime = envs[f"{stage}.runtime"]
        require(runtime["owner"] == "target", f"{stage}.runtime must be target-owned")
        require(runtime["github_environment"] is None, f"{stage}.runtime must not be a GitHub Environment")
        app = envs[f"voice-ui.{stage}"]
        require(app == {
            "id": f"voice-ui.{stage}", "kind": "envs.applicationEnvironment.v1",
            "application": "voice-ui", "environment": stage, "binding_ref": "voice-ui",
        }, f"voice-ui.{stage} differs")

    for stage in ("stg", "prd"):
        item = envs[f"{stage}.projection"]
        require(item["migration_state"] == "NOT_CONFIGURED", f"{stage}.projection must be NOT_CONFIGURED")
        require(item["active_github_environment"] is None, f"{stage}.projection must not be active")

    cipher = root / CIPHERTEXT
    if cipher.is_file():
        for identity, name in (("dev.authoring", "dev-authoring"), ("dev.projection", "dev-projection")):
            item = envs[identity]
            require(item["active_github_environment"] == name, f"{identity} active Environment differs")
            require(item["migration_state"] == "ACTIVE", f"{identity} must be ACTIVE")
        validate_ciphertext(cipher.read_bytes(), None, None)
    else:
        for identity in ("dev.authoring", "dev.projection"):
            item = envs[identity]
            require(item["active_github_environment"] is None, f"{identity} must not be active")
            require(item["migration_state"] == "NOT_CONFIGURED", f"{identity} must be NOT_CONFIGURED")

    require(bindings == expected_bindings(), "binding set differs")
    require(set(boundary) == {
        "repository.branch-policy", "dev.jev-api.provider",
        "apps.voice-ui.consumer", "ops.voice-ui.consumer", "normal.consumer.path",
    }, "provider-consumer boundary set differs")
    require(boundary["repository.branch-policy"] == {
        "id": "repository.branch-policy", "kind": "envs.branchPolicy.v1",
        "canonical_branch": "proposals", "default_branch": "proposals",
        "retained_compatibility_branches": ["main"],
        "direct_change_forbidden": ["main"],
        "effect_source_branches": ["proposals"],
        "handoff_ref_kind": "exact_commit_sha",
    }, "branch policy differs")
    require(boundary["dev.jev-api.provider"]["does_not_own"] == [
        "application_runtime_acceptance", "consumer_independent_execution",
    ], "provider must not own consumer readiness")
    return {"environments": envs, "bindings": bindings, "boundary": boundary}


def default_runner(argv: Sequence[str], input_data: bytes | None, env: Mapping[str, str] | None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv), input=input_data, env=None if env is None else dict(env),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False,
    )


def run_checked(argv: Sequence[str], *, label: str, input_data: bytes | None = None,
                env: Mapping[str, str] | None = None, runner: Runner = default_runner) -> subprocess.CompletedProcess[bytes]:
    result = runner(argv, input_data, env)
    require(result.returncode == 0, f"{label} failed")
    return result


def without_recipient_metadata(text: str) -> str:
    return RECIPIENT_METADATA.sub("", text)


def validate_ciphertext(data: bytes, secret: bytes | None, recipients: list[str] | None) -> None:
    text = data.decode("utf-8", errors="strict")
    require("JEV_API_KEY: ENC[AES256_GCM," in text and "\nsops:" in text, "invalid SOPS ciphertext")
    require(not any(pattern.search(text) for pattern in PRIVATE_MATERIAL), "private material found in ciphertext")
    if secret is not None:
        require(secret not in data, "plaintext survived encryption")
    actual = RECIPIENT_METADATA.findall(text)
    require(bool(actual) and len(actual) == len(set(actual)), "ciphertext recipient metadata is invalid")
    require(all(AGE_RECIPIENT.fullmatch(value) for value in actual), "ciphertext recipient metadata is invalid")
    if recipients is not None:
        require(sorted(actual) == sorted(recipients), "ciphertext recipient set differs")
    body = without_recipient_metadata(text)
    require(not any(value in body for value in actual), "ciphertext recipient outside sops metadata")


def repository_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
        and path.suffix != ".pyc"
    )


def reject_live_values(root: Path, name: str, values: list[str]) -> None:
    for path in repository_files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if relative == CIPHERTEXT.as_posix():
            data = without_recipient_metadata(data.decode("utf-8", errors="replace")).encode()
        for value in values:
            require(value.encode() not in data, f"{relative}: live {name} value is stored in Git")


def gate(root: Path, contracts: dict[str, dict[str, dict[str, Any]]], plane: str) -> dict[str, str]:
    row = contracts["environments"][plane]
    values: dict[str, str] = {}
    for entry in row["required_secrets"] + row["required_variables"]:
        name, kind = entry["name"], entry["type"]
        value = os.environ.get(name, "")
        require(value != "", f"{plane}: {name} is missing")
        require(INPUT_TYPES[kind](value), f"{plane}: {name} is not a valid {kind}")
        values[name] = value
    for entry in row["required_variables"]:
        value = values[entry["name"]]
        live = recipient_items(value) if entry["type"] == "age_recipient_list" else [value]
        reject_live_values(root, entry["name"], live or [])
    return values


def set_dev_active(root: Path, active: bool) -> None:
    rows = load_jsonl(root / ENVIRONMENTS)
    for row in rows:
        if row.get("id") in {"dev.authoring", "dev.projection"}:
            row["active_github_environment"] = row["github_environment"] if active else None
            row["migration_state"] = "ACTIVE" if active else "NOT_CONFIGURED"
    write_jsonl(root / ENVIRONMENTS, rows)


def locked_nixpkgs(root: Path) -> dict[str, str]:
    try:
        lock = json.loads((root / FLAKE_LOCK).read_text(encoding="utf-8"))
        nodes = lock["nodes"]
        locked = nodes[nodes[lock["root"]]["inputs"]["nixpkgs"]]["locked"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise EnvsError("flake.lock does not lock nixpkgs") from exc
    require(isinstance(locked, dict) and {key: locked.get(key) for key in ("type", "owner", "repo")} == {
        "type": "github", "owner": "NixOS", "repo": "nixpkgs",
    }, "flake.lock nixpkgs source differs")
    rev, nar_hash = locked.get("rev"), locked.get("narHash")
    require(isinstance(rev, str) and SHA40.fullmatch(rev) is not None, "flake.lock nixpkgs revision is not exact")
    require(isinstance(nar_hash, str) and nar_hash.startswith("sha256-"), "flake.lock nixpkgs narHash is not exact")
    return {"rev": rev, "narHash": nar_hash}


def in_store(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    path = Path(value)
    return path.is_absolute() and len(path.parts) > len(STORE.parts) and path.parts[:len(STORE.parts)] == STORE.parts


def toolchain(root: Path, environ: Mapping[str, str] | None = None, executable: str | None = None) -> dict[str, str]:
    # The flake entry exports this manifest; without it, or on any mismatch, no tool runs.
    manifest = (os.environ if environ is None else environ).get("ENVS_EFFECT_TOOLCHAIN", "")
    require(in_store(manifest), "repo-owned effect toolchain is missing")
    try:
        value = json.loads(Path(manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnvsError("repo-owned effect toolchain manifest is unreadable") from exc
    require(isinstance(value, dict) and set(value) == {"kind", "nixpkgs", "source", "tools"}
            and value["kind"] == TOOLCHAIN_KIND, "effect toolchain manifest differs")
    require(isinstance(value["source"], str) and SHA40.fullmatch(value["source"]) is not None,
            "effect toolchain source is not an exact commit")
    require(value["nixpkgs"] == locked_nixpkgs(root), "effect toolchain differs from flake.lock")
    try:
        same_adapter = (root / "adapters/jev_api.py").read_bytes() == Path(__file__).read_bytes()
    except OSError as exc:
        raise EnvsError("checkout adapter is unreadable") from exc
    require(same_adapter, "checkout adapter differs from the effect toolchain")
    tools = value["tools"]
    require(isinstance(tools, dict) and set(tools) == set(TOOLCHAIN_TOOLS), "effect toolchain tool set differs")
    for name in TOOLCHAIN_TOOLS:
        path = tools[name]
        require(in_store(path) and os.path.isfile(path) and os.access(path, os.X_OK), f"effect toolchain {name} is missing")
    current = os.path.realpath(sys.executable if executable is None else executable)
    require(current == os.path.realpath(tools["python3"]), "adapter interpreter is not the repo-owned python3")
    return dict(tools)


def clean_env(tools: Mapping[str, str], extra: Mapping[str, str]) -> dict[str, str]:
    result = {key: value for key, value in os.environ.items() if key in {"HOME", "TMPDIR", "LANG", "LC_ALL", "CI"}}
    result["PATH"] = os.pathsep.join(sorted({os.path.dirname(path) for path in tools.values()}))
    result.update(extra)
    return result


def author(root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, "dev.authoring")
    source = inputs["JEV_API_KEY"]
    recipients = recipient_items(inputs["SOPS_AGE_RECIPIENTS"]) or []

    payload = json.dumps({"JEV_API_KEY": source}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": ",".join(recipients)}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_ciphertext(result.stdout, source.encode(), recipients)
    target = root / CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(result.stdout)
    set_dev_active(root, True)
    stale = root / HANDOFF
    if stale.exists():
        stale.unlink()
    validate_contracts(root)
    return {"kind": "envs.authoringResult.v1", "status": "PASS", "ciphertext": CIPHERTEXT.as_posix()}


def walk_receipt(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            require(key not in FORBIDDEN_RECEIPT_KEYS, f"forbidden receipt key {key}")
            walk_receipt(item)
    elif isinstance(value, list):
        for item in value:
            walk_receipt(item)
    elif isinstance(value, str):
        require(not any(pattern.search(value) for pattern in PRIVATE_MATERIAL), "private material found in receipt")


def validate_receipt(receipt: dict[str, Any]) -> None:
    require(set(receipt) == {
        "kind", "status", "envs_sha", "environment", "capability", "source",
        "target", "projector", "effect", "readback", "workflow", "created_at",
    }, "receipt fields differ")
    require(receipt["kind"] == RECEIPT_KIND and receipt["status"] == "PASS", "receipt is not PASS")
    require(isinstance(receipt["envs_sha"], str) and SHA40.fullmatch(receipt["envs_sha"]), "invalid envs SHA")
    require(receipt["environment"] == "dev" and receipt["capability"] == "jev-api", "receipt identity differs")
    source = receipt["source"]
    require(source.get("kind") == "public_sops" and source.get("ref") == CIPHERTEXT.as_posix(), "receipt source differs")
    require(isinstance(source.get("sha256"), str) and SHA256.fullmatch(source["sha256"]), "invalid ciphertext digest")
    require(receipt["target"] == {
        "provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY",
    }, "receipt target differs")
    require(receipt["projector"] == {
        "workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py",
    }, "projector identity differs")
    require(receipt["effect"] == {"operation": "cloudflare_pages_secret_put", "status": "PASS"}, "provider effect is not PASS")
    require(receipt["readback"] == {"kind": "secret_name_presence", "status": "PASS", "present": True}, "provider readback is not PASS")
    workflow = receipt["workflow"]
    require(workflow.get("repository") == "roccho-dev/envs" and workflow.get("ref") == "proposals", "workflow identity differs")
    require(isinstance(workflow.get("run_id"), int) and workflow["run_id"] > 0, "invalid workflow run id")
    require(isinstance(workflow.get("run_attempt"), int) and workflow["run_attempt"] > 0, "invalid workflow run attempt")
    created_at = receipt["created_at"]
    require(isinstance(created_at, str) and created_at.endswith("Z"), "invalid timestamp")
    try:
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError as exc:
        raise EnvsError("invalid timestamp") from exc
    walk_receipt(receipt)


def build_receipt(*, envs_sha: str, ciphertext_sha256: str,
                  run_id: int, run_attempt: int, created_at: str) -> dict[str, Any]:
    receipt = {
        "kind": RECEIPT_KIND, "status": "PASS", "envs_sha": envs_sha,
        "environment": "dev", "capability": "jev-api",
        "source": {"kind": "public_sops", "ref": CIPHERTEXT.as_posix(), "sha256": "sha256:" + ciphertext_sha256},
        "target": {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"},
        "projector": {"workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py"},
        "effect": {"operation": "cloudflare_pages_secret_put", "status": "PASS"},
        "readback": {"kind": "secret_name_presence", "status": "PASS", "present": True},
        "workflow": {"repository": "roccho-dev/envs", "ref": "proposals", "run_id": run_id, "run_attempt": run_attempt},
        "created_at": created_at,
    }
    validate_receipt(receipt)
    return receipt


def project(*, envs_sha: str, run_id: int, run_attempt: int, created_at: str,
            output: Path, root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    contracts = validate_contracts(root)
    require(SHA40.fullmatch(envs_sha) is not None, "expected exact envs SHA")
    cipher = root / CIPHERTEXT
    require(cipher.is_file(), "ciphertext is not configured")
    tools = toolchain(root)
    inputs = gate(root, contracts, "dev.projection")
    age_key = inputs["SOPS_AGE_KEY"]
    account = inputs["CLOUDFLARE_ACCOUNT_ID"]
    token = inputs["CLOUDFLARE_API_TOKEN"]

    decrypted = run_checked(
        [tools["sops"], "--decrypt", "--output-type", "json", str(cipher)],
        env=clean_env(tools, {"SOPS_AGE_KEY": age_key}), runner=runner, label="SOPS decryption",
    ).stdout
    try:
        payload = json.loads(decrypted)
    except json.JSONDecodeError as exc:
        raise EnvsError("decrypted payload is not JSON") from exc
    require(isinstance(payload, dict) and set(payload) == {"JEV_API_KEY"}, "decrypted payload fields differ")
    secret = payload["JEV_API_KEY"]
    require(isinstance(secret, str) and secret, "decrypted JEV_API_KEY is empty")

    provider_env = clean_env(tools, {"CLOUDFLARE_ACCOUNT_ID": account, "CLOUDFLARE_API_TOKEN": token})
    wrangler = tools["wrangler"]
    run_checked(
        [wrangler, "pages", "secret", "put", "JEV_API_KEY", "--project-name", "voice-ui"],
        input_data=secret.encode(), env=provider_env, runner=runner, label="Cloudflare secret projection",
    )
    readback = run_checked(
        [wrangler, "pages", "secret", "list", "--project-name", "voice-ui"],
        env=provider_env, runner=runner, label="Cloudflare secret readback",
    )
    require(b"JEV_API_KEY" in readback.stdout + readback.stderr, "provider readback did not contain JEV_API_KEY")

    receipt = build_receipt(
        envs_sha=envs_sha, ciphertext_sha256=hashlib.sha256(cipher.read_bytes()).hexdigest(),
        run_id=run_id, run_attempt=run_attempt, created_at=created_at,
    )
    destination = root / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvsError("handoff receipt is invalid JSON") from exc
    require(isinstance(value, dict), "handoff receipt must be an object")
    validate_receipt(value)
    return value


def readiness(root: Path = ROOT) -> dict[str, Any]:
    validate_contracts(root)
    cipher, handoff = root / CIPHERTEXT, root / HANDOFF
    configured = cipher.is_file()
    physical, state = ("NOT_RUN", "ABSENT") if configured else ("NOT_CONFIGURED", "ABSENT")
    current = "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest() if configured else None
    receipt_digest = None
    if handoff.is_file():
        require(configured, "handoff cannot exist without ciphertext")
        receipt_digest = load_receipt(handoff)["source"]["sha256"]
        physical = state = "PASS" if receipt_digest == current else "STALE"
    return {
        "kind": "envs.providerReadiness.v1", "repository": "roccho-dev/envs",
        "canonical_branch": "proposals", "retained_compatibility_branch": "main",
        "stage": "dev", "capability": "jev-api", "public_source_provider": "PASS",
        "provider_mechanism": "PASS_SOURCE", "physical_dev_projection": physical,
        "provider_handoff_receipt": state, "provider_handoff_ready": state == "PASS",
        "consumer_runtime_readiness": "OUT_OF_SCOPE",
        "current_ciphertext_sha256": current, "receipt_ciphertext_sha256": receipt_digest,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    # Data root (contracts, ciphertext, handoff); defaults to the source carrying this adapter.
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    sub.add_parser("readiness")
    sub.add_parser("toolchain")
    sub.add_parser("author")
    project_parser = sub.add_parser("project")
    project_parser.add_argument("--envs-sha", required=True)
    project_parser.add_argument("--run-id", type=int, required=True)
    project_parser.add_argument("--run-attempt", type=int, required=True)
    project_parser.add_argument("--created-at")
    project_parser.add_argument("--output", type=Path, default=HANDOFF)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "check":
            validate_contracts(root)
            if (root / HANDOFF).is_file():
                load_receipt(root / HANDOFF)
            print("JEV_API_CONTRACT=PASS")
        elif args.command == "readiness":
            print(json.dumps(readiness(root), indent=2, sort_keys=True))
        elif args.command == "toolchain":
            tools = toolchain(root)
            print(json.dumps({
                "kind": "envs.effectToolchainCheck.v1", "status": "PASS", "root": str(root),
                "manifest": os.environ["ENVS_EFFECT_TOOLCHAIN"], "nixpkgs": locked_nixpkgs(root), "tools": tools,
                "source": json.loads(Path(os.environ["ENVS_EFFECT_TOOLCHAIN"]).read_text(encoding="utf-8"))["source"],
            }, indent=2, sort_keys=True))
        elif args.command == "author":
            print(json.dumps(author(root), indent=2, sort_keys=True))
        else:
            receipt = project(
                envs_sha=args.envs_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                created_at=args.created_at or utc_now(), output=args.output, root=root,
            )
            print(json.dumps({"kind": receipt["kind"], "status": "PASS", "output": str(args.output)}, sort_keys=True))
    except (EnvsError, OSError) as exc:
        print(f"JEV_API=RED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
