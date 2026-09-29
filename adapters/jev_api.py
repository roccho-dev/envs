#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import getpass
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
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
TOOLCHAIN_TOOLS = ("python3", "sops", "wrangler", "git", "gh", "tofu", "cloudflared", "ssh", "sshd", "ssh_keygen")
STORE = Path("/nix/store")
# Rent tunnel (windows #14): a provider-issued Named Tunnel token, encrypted to exactly one target age recipient.
RENT_PLANE = "dev.rent-tunnel"
RENT_CIPHERTEXT = Path("ciphertexts/dev-rent-tunnel.sops.yaml")
RENT_KEY = "RENT_TUNNEL_TOKEN"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
RETRIEVAL_TIMEOUT = 30.0
RESPONSE_LIMIT = 65536
# Access SSH probe (windows #14): one disposable Named Tunnel, hostname, Service Auth app and service token.
PROBE_PLANE = "dev.rent-access-probe"
PROBE_CONFIG = Path("providers/dev-rent-access-probe/main.tf")
PROBE_NAME = "windows-rent-access-probe"
PROBE_HOSTNAME = "rent-access-probe.roccho.com"
PROBE_PORT = 2222
PROBE_TIMEOUT = 60.0
PROBE_SETTLE = 20.0
PROBE_LOCATED = ("tunnels", "dns_records", "access_applications", "service_tokens")
PROBE_CREATED = ("tunnel", "dns_record", "access_application", "access_policy", "service_token")
PROBE_CREDENTIALS = ("tunnel_token", "service_token_id", "service_token_value")

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
AGE_RECIPIENT = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")
AGE_IDENTITY = re.compile(r"^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$")
CLOUDFLARE_ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
CLOUDFLARE_TUNNEL_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# The target's token file gate accepts 1-4096 non-blank bytes; the provider returns base64 text.
TUNNEL_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]{1,4096}$")
BEARER = re.compile(r"^[\x21-\x7e]+$")
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
        "rent-tunnel": {
            "id": "rent-tunnel",
            "kind": "envs.authCapability.v1",
            "capability": "rent-tunnel",
            "ciphertext": RENT_CIPHERTEXT.as_posix(),
            "source_key": RENT_KEY,
            "source": {"provider": "cloudflare", "operation": "cfd_tunnel_token"},
            "target": {"repository": "roccho-dev/windows", "host": "rent", "kind": "cloudflared_token_file"},
        },
    }


def expected_rent_boundary() -> dict[str, Any]:
    # envs ends at the target-bound ciphertext PR; apply, client access and SSH acceptance are other owners' effects.
    return {
        "id": "dev.rent-tunnel.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-tunnel",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "bounded_retrieval", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["target_apply", "target_age_identity", "client_access_credential", "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_probe_boundary() -> dict[str, Any]:
    # A disposable probe of the client path; name lookup locates, it never proves ownership or deletes.
    return {
        "id": "dev.rent-access-probe.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-access-probe",
        "source_kind": "provider_issued",
        "target_kind": "disposable_probe",
        "owns": ["disposable_probe_resources", "exact_id_cleanup", "name_lookup_locator"],
        "does_not_own": ["existing_cloudflare_resources", "name_matched_deletion", "rent_target", "client_credential_selection"],
        "handoff_ref_kind": "exact_commit_sha",
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
        RENT_PLANE: {
            "required_secrets": entries(("CLOUDFLARE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(
                ("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("RENT_TUNNEL_ID", "cloudflare_tunnel_id", "persistent"),
                ("RENT_AGE_RECIPIENT", "age_recipient", "persistent"),
            ),
        },
        PROBE_PLANE: {
            "required_secrets": entries(("CLOUDFLARE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(
                ("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("CLOUDFLARE_ZONE_ID", "cloudflare_zone_id", "persistent"),
            ),
        },
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
    "age_recipient": lambda value: AGE_RECIPIENT.fullmatch(value) is not None,
    "cloudflare_account_id": lambda value: CLOUDFLARE_ACCOUNT_ID.fullmatch(value) is not None,
    "cloudflare_tunnel_id": lambda value: CLOUDFLARE_TUNNEL_ID.fullmatch(value) is not None,
    "cloudflare_zone_id": lambda value: CLOUDFLARE_ACCOUNT_ID.fullmatch(value) is not None,
}


def validate_contracts(root: Path = ROOT) -> dict[str, dict[str, dict[str, Any]]]:
    envs = index(root / ENVIRONMENTS)
    bindings = index(root / BINDINGS)
    boundary = index(root / BOUNDARY)

    require(set(envs) == {
        "dev.authoring", "dev.projection", "dev.runtime", RENT_PLANE, PROBE_PLANE,
        "stg.projection", "stg.runtime", "prd.projection", "prd.runtime",
        "voice-ui.dev", "voice-ui.stg", "voice-ui.prd",
    }, "environment set differs")

    require(envs["dev.authoring"]["github_environment"] == "dev-authoring", "dev authoring Environment differs")
    rent = envs[RENT_PLANE]
    require(rent["github_environment"] == "dev-rent-tunnel" and rent["owner"] == "envs"
            and rent["source_kind"] == "provider_issued" and rent["target_kind"] == "public_sops",
            "dev rent tunnel plane differs")
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

    rent_cipher = root / RENT_CIPHERTEXT
    if rent_cipher.is_file():
        require(rent["active_github_environment"] == "dev-rent-tunnel" and rent["migration_state"] == "ACTIVE",
                f"{RENT_PLANE} must be ACTIVE with its ciphertext")
        validate_rent_ciphertext(rent_cipher.read_bytes(), None, None)
    else:
        require(rent["active_github_environment"] is None and rent["migration_state"] == "NOT_CONFIGURED",
                f"{RENT_PLANE} must be NOT_CONFIGURED without its ciphertext")

    probe = envs[PROBE_PLANE]
    require(probe["github_environment"] == "dev-rent-access-probe" and probe["owner"] == "envs"
            and probe["source_kind"] == "provider_issued" and probe["target_kind"] == "disposable_probe"
            and probe["active_github_environment"] is None and probe["migration_state"] == "NOT_CONFIGURED",
            f"{PROBE_PLANE} must be a NOT_CONFIGURED disposable probe plane")

    require(bindings == expected_bindings(), "binding set differs")
    require(set(boundary) == {
        "repository.branch-policy", "dev.jev-api.provider", "dev.rent-tunnel.provider", "dev.rent-access-probe.provider",
        "apps.voice-ui.consumer", "ops.voice-ui.consumer", "normal.consumer.path",
    }, "provider-consumer boundary set differs")
    require(boundary["dev.rent-tunnel.provider"] == expected_rent_boundary(), "rent tunnel provider boundary differs")
    require(boundary["dev.rent-access-probe.provider"] == expected_probe_boundary(), "access probe provider boundary differs")
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


def validate_ciphertext(data: bytes, secret: bytes | None, recipients: list[str] | None, key: str = "JEV_API_KEY") -> None:
    text = data.decode("utf-8", errors="strict")
    require(f"{key}: ENC[AES256_GCM," in text and "\nsops:" in text, "invalid SOPS ciphertext")
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


def validate_rent_ciphertext(data: bytes, token: bytes | None, recipient: str | None) -> None:
    validate_ciphertext(data, token, None if recipient is None else [recipient], key=RENT_KEY)
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "rent tunnel ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {RENT_KEY, "sops"}, "rent tunnel ciphertext fields differ")


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
        if relative in {CIPHERTEXT.as_posix(), RENT_CIPHERTEXT.as_posix()}:
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


def set_dev_active(root: Path, active: bool, planes: Iterable[str] = ("dev.authoring", "dev.projection")) -> None:
    rows = load_jsonl(root / ENVIRONMENTS)
    selected = set(planes)
    for row in rows:
        if row.get("id") in selected:
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


Fetch = Callable[[urllib.request.Request, float], bytes]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect is RED; the bearer token is never re-sent to another location.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def default_fetch(request: urllib.request.Request, timeout: float) -> bytes:
    # The entry exports the repo-owned CA bundle; errors never carry the response or the request headers.
    bundle = os.environ.get("SSL_CERT_FILE", "")
    require(in_store(bundle) and os.path.isfile(bundle), "repo-owned CA bundle is missing")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=bundle)), NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(RESPONSE_LIMIT + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise EnvsError("Cloudflare tunnel token retrieval failed") from None
    require(len(body) <= RESPONSE_LIMIT, "Cloudflare response exceeds its bound")
    return body


def retrieve_tunnel_token(account: str, tunnel: str, api_token: str, fetch: Fetch = default_fetch) -> str:
    # One GET, bounded in time and size; the token is returned in memory only.
    require(CLOUDFLARE_ACCOUNT_ID.fullmatch(account) is not None, "invalid Cloudflare account ID")
    require(CLOUDFLARE_TUNNEL_ID.fullmatch(tunnel) is not None, "invalid Cloudflare tunnel ID")
    require(BEARER.fullmatch(api_token) is not None, "invalid Cloudflare API token shape")
    request = urllib.request.Request(
        f"{CLOUDFLARE_API}/accounts/{account}/cfd_tunnel/{tunnel}/token",
        headers={"Authorization": f"Bearer {api_token}", "Accept": "application/json"},
        method="GET",
    )
    body = fetch(request, RETRIEVAL_TIMEOUT)
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError("Cloudflare response is not JSON") from None
    require(isinstance(value, dict) and value.get("success") is True, "Cloudflare did not return success")
    token = value.get("result")
    require(isinstance(token, str) and TUNNEL_TOKEN.fullmatch(token) is not None, "Cloudflare returned no valid tunnel token")
    return token


def encrypt_rent_token(token: str, recipient: str, tools: Mapping[str, str], runner: Runner = default_runner) -> bytes:
    # The token reaches SOPS on stdin only; the ciphertext must name exactly this one recipient.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "rent tunnel needs exactly one age recipient")
    require(TUNNEL_TOKEN.fullmatch(token) is not None, "invalid tunnel token")
    payload = json.dumps({RENT_KEY: token}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_rent_ciphertext(result.stdout, token.encode(), recipient)
    return result.stdout


def rent_author(root: Path = ROOT, runner: Runner = default_runner, fetch: Fetch = default_fetch) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, RENT_PLANE)
    # Secrets as well as Variables: a value already in Git is RED before the provider call, the token before SOPS.
    reject_live_values(root, "CLOUDFLARE_API_TOKEN", [inputs["CLOUDFLARE_API_TOKEN"]])
    token = retrieve_tunnel_token(
        inputs["CLOUDFLARE_ACCOUNT_ID"], inputs["RENT_TUNNEL_ID"], inputs["CLOUDFLARE_API_TOKEN"], fetch)
    reject_live_values(root, RENT_KEY, [token])
    data = encrypt_rent_token(token, inputs["RENT_AGE_RECIPIENT"], tools, runner)
    target = root / RENT_CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    set_dev_active(root, True, (RENT_PLANE,))
    validate_contracts(root)
    return {
        "kind": "envs.rentTunnelAuthoringResult.v1", "status": "PASS", "ciphertext": RENT_CIPHERTEXT.as_posix(),
        "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


# A bounded client attempt returns ("exit", code, stdout) or ("timeout", -1, b""); stderr is never kept or logged.
Bounded = Callable[[Sequence[str], Mapping[str, str], float], tuple[str, int, bytes]]
Spawn = Callable[[Sequence[str], Mapping[str, str]], Any]


def default_bounded(argv: Sequence[str], env: Mapping[str, str], timeout: float) -> tuple[str, int, bytes]:
    try:
        result = subprocess.run(list(argv), env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return ("timeout", -1, b"")
    return ("exit", result.returncode, result.stdout)


def default_spawn(argv: Sequence[str], env: Mapping[str, str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(list(argv), env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, shell=False)


def stop(process: Any) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def tofu(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner, *args: str) -> bytes:
    # Output may carry sensitive values: it is parsed, never printed, and a failure names only the command.
    return run_checked([tools["tofu"], f"-chdir={work}", *args], env=env, runner=runner,
                       label=f"OpenTofu {args[0]}").stdout


def tofu_workdir(root: Path, scratch: Path, name: str, tools: Mapping[str, str], env: Mapping[str, str],
                 runner: Runner) -> Path:
    # Each phase gets its own fresh state; a lookup directory never holds a managed resource it could delete.
    work = scratch / name
    work.mkdir()
    (work / "main.tf").write_bytes((root / PROBE_CONFIG).read_bytes())
    tofu(tools, work, env, runner, "init", "-input=false", "-no-color")
    return work


def output(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner, name: str,
           keys: Sequence[str]) -> dict[str, Any]:
    try:
        value = json.loads(tofu(tools, work, env, runner, "output", "-json", name))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError(f"OpenTofu output {name} is not JSON") from None
    require(isinstance(value, dict) and set(value) == set(keys), f"OpenTofu output {name} differs")
    return value


def locate(root: Path, scratch: Path, name: str, tools: Mapping[str, str], env: Mapping[str, str],
           runner: Runner) -> dict[str, list[str]]:
    # A locator only: create=false declares no managed resource, so this path has no create or delete.
    work = tofu_workdir(root, scratch, name, tools, env, runner)
    tofu(tools, work, env, runner, "apply", "-input=false", "-auto-approve", "-no-color", "-var", "create=false")
    found = output(tools, work, env, runner, "located", PROBE_LOCATED)
    require(all(isinstance(ids, list) and all(isinstance(item, str) for item in ids) for ids in found.values()),
            "OpenTofu located output differs")
    return found


def ssh_fixture(tools: Mapping[str, str], directory: Path, runner: Runner) -> dict[str, Any]:
    # A throwaway localhost sshd that answers every login with a run-scoped nonce, and the client files for it.
    directory.mkdir(mode=0o700)
    for key in ("host", "client"):
        run_checked([tools["ssh_keygen"], "-q", "-t", "ed25519", "-N", "", "-C", PROBE_NAME, "-f", str(directory / key)],
                    env=clean_env(tools, {}), runner=runner, label="ssh-keygen")
    nonce = secrets.token_hex(16)
    (directory / "nonce").write_text(nonce + "\n", encoding="utf-8")
    (directory / "authorized_keys").write_bytes((directory / "client.pub").read_bytes())
    host = (directory / "host.pub").read_text(encoding="utf-8").split()
    (directory / "known_hosts").write_text(f"{PROBE_NAME} {host[0]} {host[1]}\n", encoding="utf-8")
    user = getpass.getuser()
    (directory / "sshd_config").write_text("".join(f"{line}\n" for line in (
        f"Port {PROBE_PORT}", "ListenAddress 127.0.0.1", f"HostKey {directory / 'host'}",
        f"AuthorizedKeysFile {directory / 'authorized_keys'}", f"PidFile {directory / 'sshd.pid'}",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "UsePAM no", "StrictModes no", f"AllowUsers {user}", f"ForceCommand cat {directory / 'nonce'}",
    )), encoding="utf-8")
    return {"directory": directory, "nonce": nonce, "user": user}


def ssh_argv(tools: Mapping[str, str], fixture: Mapping[str, Any], target: str, proxy: bool) -> list[str]:
    directory = fixture["directory"]
    argv = [tools["ssh"], "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-i", str(directory / "client"), "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={directory / 'known_hosts'}", "-o", f"HostKeyAlias={PROBE_NAME}",
            "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=30", "-l", fixture["user"]]
    if proxy:
        # The same ProxyCommand shape windows PR #21 writes; credentials only ever come from the environment.
        argv += ["-o", f'ProxyCommand="{tools["cloudflared"]}" access ssh --hostname %h']
    else:
        argv += ["-p", str(PROBE_PORT)]
    return argv + [target]


def classify(outcomes: Mapping[str, tuple[str, int, bytes]], nonce: str) -> dict[str, Any]:
    # Timeout is UNKNOWN; a failed positive path is a failure of unknown cause; an admitted negative is a policy failure.
    def reached(outcome: tuple[str, int, bytes]) -> bool:
        return outcome[0] == "exit" and outcome[1] == 0 and outcome[2].strip() == nonce.encode()

    labels: dict[str, str] = {}
    for case, outcome in outcomes.items():
        if outcome[0] == "timeout":
            labels[case] = "UNKNOWN"
        elif case == "service_token":
            labels[case] = "REACHED" if reached(outcome) else "FAILED"
        else:
            labels[case] = "ADMITTED" if outcome[1] == 0 or nonce.encode() in outcome[2] else "DENIED"
    if any(labels[case] == "ADMITTED" for case in ("no_token", "wrong_token")):
        status = "ACCESS_NOT_ENFORCED"
    elif "UNKNOWN" in labels.values():
        status = "UNKNOWN"
    elif labels["service_token"] == "REACHED":
        status = "PASS"
    else:
        status = "UNATTENDED_PATH_FAILED"
    return {"status": status, "cases": labels, "cause": None if status == "PASS" else "UNKNOWN"}


def run_probe(tools: Mapping[str, str], credentials: Mapping[str, str], scratch: Path, runner: Runner,
              bounded: Bounded, spawn: Spawn, sleep: Callable[[float], None]) -> dict[str, Any]:
    fixture = ssh_fixture(tools, scratch / "ssh", runner)
    base = clean_env(tools, {})
    processes = [spawn([tools["sshd"], "-D", "-e", "-f", str(fixture["directory"] / "sshd_config")], base)]
    try:
        processes.append(spawn([tools["cloudflared"], "tunnel", "--no-autoupdate", "run"],
                               {**base, "TUNNEL_TOKEN": credentials["tunnel_token"]}))
        sleep(PROBE_SETTLE)
        argv = ssh_argv(tools, fixture, PROBE_HOSTNAME, proxy=True)
        cases = {
            "service_token": {"TUNNEL_SERVICE_TOKEN_ID": credentials["service_token_id"],
                              "TUNNEL_SERVICE_TOKEN_SECRET": credentials["service_token_value"]},
            "no_token": {},
            "wrong_token": {"TUNNEL_SERVICE_TOKEN_ID": credentials["service_token_id"],
                            "TUNNEL_SERVICE_TOKEN_SECRET": secrets.token_hex(32)},
        }
        # Each case runs once; there is no retry.
        outcomes = {case: bounded(argv, {**base, **extra}, PROBE_TIMEOUT) for case, extra in cases.items()}
    finally:
        for process in reversed(processes):
            stop(process)
    return classify(outcomes, fixture["nonce"])


def access_probe(root: Path = ROOT, *, locate_only: bool = False, runner: Runner = default_runner,
                 bounded: Bounded = default_bounded, spawn: Spawn = default_spawn,
                 sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, PROBE_PLANE)
    reject_live_values(root, "CLOUDFLARE_API_TOKEN", [inputs["CLOUDFLARE_API_TOKEN"]])
    env = clean_env(tools, {
        "CLOUDFLARE_API_TOKEN": inputs["CLOUDFLARE_API_TOKEN"], "TF_VAR_account_id": inputs["CLOUDFLARE_ACCOUNT_ID"],
        "TF_VAR_zone_id": inputs["CLOUDFLARE_ZONE_ID"], "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
    })
    result: dict[str, Any] = {"kind": "envs.rentAccessProbeResult.v1", "hostname": PROBE_HOSTNAME,
                              "real_ssh_acceptance": "NOT_CLAIMED", "rent_target": "UNTOUCHED"}
    with tempfile.TemporaryDirectory(prefix="envs-access-probe-") as temporary:
        scratch = Path(temporary)
        before = locate(root, scratch, "before", tools, env, runner)
        if locate_only or any(before.values()):
            # Name matches are candidates only: ownership is unproven and nothing is adopted or deleted.
            located = any(before.values())
            result.update({"stage": "locate" if locate_only else "preflight", "located": before,
                           "status": "UNKNOWN" if located else "NONE_LOCATED",
                           "ownership": "UNPROVEN" if located else None,
                           "next": "NEEDS_AUTHORITY" if located else None})
            if not locate_only:
                result["status"] = "UNKNOWN"
            return result
        work = tofu_workdir(root, scratch, "probe", tools, env, runner)
        result.update({"stage": "create", "status": "UNKNOWN", "created": None, "probe": None})
        try:
            tofu(tools, work, env, runner, "apply", "-input=false", "-auto-approve", "-no-color", "-var", "create=true")
            created = output(tools, work, env, runner, "created", PROBE_CREATED)
            require(all(isinstance(value, str) and value for value in created.values()), "created IDs differ")
            result.update({"stage": "probe", "created": created})
            credentials = output(tools, work, env, runner, "credentials", PROBE_CREDENTIALS)
            require(all(isinstance(value, str) and value for value in credentials.values()), "credentials differ")
            probe = run_probe(tools, credentials, scratch, runner, bounded, spawn, sleep)
            result.update({"probe": probe, "status": probe["status"]})
        except EnvsError as exc:
            result["error"] = str(exc)
        finally:
            # Cleanup removes only what this state created, then reads back absence from a fresh lookup state.
            try:
                tofu(tools, work, env, runner, "destroy", "-input=false", "-auto-approve", "-no-color",
                     "-var", "create=true")
                after = locate(root, scratch, "after", tools, env, runner)
                result["cleanup"] = "ABSENT" if not any(after.values()) else "CLEANUP_UNKNOWN"
                result["located_after"] = after
            except EnvsError:
                result["cleanup"] = "CLEANUP_UNKNOWN"
    return result


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
    sub.add_parser("rent-tunnel")
    sub.add_parser("rent-access-probe")
    sub.add_parser("rent-access-locate")
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
        elif args.command == "rent-tunnel":
            print(json.dumps(rent_author(root), indent=2, sort_keys=True))
        elif args.command in {"rent-access-probe", "rent-access-locate"}:
            result = access_probe(root, locate_only=args.command == "rent-access-locate")
            print(json.dumps(result, indent=2, sort_keys=True))
            passed = result["status"] == "NONE_LOCATED" if args.command == "rent-access-locate" else (
                result["status"] == "PASS" and result.get("cleanup") == "ABSENT")
            return 0 if passed else 1
        else:
            receipt = project(
                envs_sha=args.envs_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                created_at=args.created_at or utc_now(), output=args.output, root=root,
            )
            print(json.dumps({"kind": receipt["kind"], "status": "PASS", "output": str(args.output)}, sort_keys=True))
    except (EnvsError, OSError) as exc:
        label = {"rent-tunnel": "RENT_TUNNEL", "rent-access-probe": "RENT_ACCESS_PROBE",
                 "rent-access-locate": "RENT_ACCESS_PROBE"}.get(args.command, "JEV_API")
        print(f"{label}=RED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
