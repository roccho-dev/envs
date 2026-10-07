#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
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
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
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
TOOLCHAIN_TOOLS = ("python3", "sops", "wrangler", "git", "gh", "tofu", "cloudflared", "ssh", "sshd", "ssh_keygen", "curl")
STORE = Path("/nix/store")
# Rent tunnel (windows #14): a provider-issued Named Tunnel token, encrypted to exactly one target age recipient.
RENT_PLANE = "dev.rent-tunnel"
RENT_CIPHERTEXT = Path("ciphertexts/dev-rent-tunnel.sops.yaml")
RENT_KEY = "RENT_TUNNEL_TOKEN"
# Rent client (windows #14): the G6I3 normal user's Access service credential from the persistent root's sensitive
# output, encrypted to exactly one target age recipient. place.ps1 decrypts it on the target and hands windows'
# RentAccess the owner-only slot '<client id>LF<client secret>LF' through a private stdin pipe.
CLIENT_PLANE = "dev.rent-client"
CLIENT_CIPHERTEXT = Path("ciphertexts/dev-rent-client.sops.yaml")
CLIENT_KEYS = ("RENT_ACCESS_CLIENT_ID", "RENT_ACCESS_CLIENT_SECRET")
CLIENT_RECIPIENT = "RENT_CLIENT_AGE_RECIPIENT"
# Persistent rent root (windows #8/#14): the declared Cloudflare root applied with standard OpenTofu on its native
# encrypted and locked R2 backend; its sensitive credentials output is sealed in memory into the two envelopes above.
ROOT_PLANE = "dev.rent-root"
ROOT_CONFIG = Path("providers/dev-rent-cloudflare/main.tf")
ROOT_SECRETS = ("CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RENT_STATE_PASSPHRASE")
# One key provider and method name for the state's life (a rotation would add a new name with this one as fallback).
ROOT_KEY_NAME = "k0"
# The format secrets.token_hex(32) produces, placed inside an HCL string: a format check, not a strength proof.
ROOT_PASSPHRASE = re.compile(r"^[0-9a-f]{64}$")
# The windows slot rule (Get-RentAccessProblem) for each line: 1-1024 printable ASCII characters.
SLOT_LINE = re.compile(r"^[!-~]{1,1024}$")
WINDOWS_CONSUMER = "windows.rent.consumer"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
RETRIEVAL_TIMEOUT = 30.0
RESPONSE_LIMIT = 65536
# Linode/Akamai Cloud read-only connectivity probe: no create/update/delete operation exists here.
LINODE_READ_PLANE = "dev.linode-read-probe"
LINODE_API = "https://api.linode.com/v4"
LINODE_READ_ENDPOINTS = (("profile", "/profile"), ("account", "/account"), ("linodes", "/linode/instances?page_size=25"))
# Access SSH probe (windows #14): one disposable Named Tunnel, hostname, Service Auth app and service token.
PROBE_PLANE = "dev.rent-access-probe"
PROBE_CONFIG = Path("providers/dev-rent-access-probe/main.tf")
PROBE_NAME = "windows-rent-access-probe"
PROBE_HOSTNAME = "rent-access-probe.roccho.com"
PROBE_PORT = 2222
PROBE_TIMEOUT = 60.0
PROBE_SETTLE = 20.0
PROBE_LOCATED = ("tunnels", "dns_records", "access_applications", "service_tokens")
# Every managed resource in the probe declaration (six, including the tunnel configuration).
PROBE_ADDRESSES = tuple(f"cloudflare_{kind}.probe[0]" for kind in (
    "zero_trust_tunnel_cloudflared", "zero_trust_tunnel_cloudflared_config", "dns_record",
    "zero_trust_access_service_token", "zero_trust_access_policy", "zero_trust_access_application"))
PROBE_CREDENTIALS = ("tunnel_token", "service_token_id", "service_token_value")
# Durable-state proof (windows #8/#14): OpenTofu S3-backend state, lock file and encryption on two per-run R2 buckets.
# The parent token is an existing finite account token on the same Environment under its own secret name.
STATE_PLANE = "dev.rent-state-proof"
STATE_CONFIG = Path("providers/dev-rent-state-proof/main.tf")
STATE_BACKEND = Path("providers/dev-rent-state-proof/backend/main.tf")
STATE_BUCKET_PREFIX = "windows-rent-state-proof-"
STATE_RESERVED_BUCKET = "windows-rent-state"
STATE_ALLOWED_PREFIX = "state/"
STATE_KEY = "state/proof.tfstate"
# Fixed non-secret boundary objects: a known marker inside the prefix of each owned bucket, and the same bytes written
# outside it. Every key a PUT is attempted for is deleted by cleanup, even when the response is unknown.
STATE_MARKER_KEY = STATE_ALLOWED_PREFIX + "boundary-probe"
STATE_OUTSIDE_MARKER_KEY = "outside/boundary-probe"
STATE_MARKER = b"envs-r2-boundary-probe-v1"
S3_TIMEOUT = 30
S3_BODY_LIMIT = 65536
# The workflow's timeout-minutes (the repository check requires equality) bounds the whole run, including the
# temporary-credential wait; the parent token must outlive it by the margin before anything is created.
STATE_JOB_MINUTES = 45
STATE_MARGIN = 900.0
STATE_CREDENTIAL_TTL = 900
STATE_EXPIRY_GRACE = 60.0
STATE_HOLD = 60
STATE_SETTLE = 20.0
STATE_LOCK_ERROR = b"Error acquiring the state lock"
STATE_EVIDENCE_KIND = "envs.rentStateProofCreated.v1"
STATE_CHECKS = (
    "lock_holder_applied", "lock_contender_rejected", "lock_released", "raw_state_encrypted", "readback_exact",
    "rotation_rewritten", "rotated_readback", "path_up_after_negatives",
)
# Each negative is REFUSED only after an adjacent control that differs in that one input succeeds and the negative fails
# for its own cause; a negative that succeeds is ADMITTED; anything else (transport, 5xx, other cause) is UNKNOWN.
STATE_NEGATIVES = {
    "old_key_refused": {"decryption"},
    "unencrypted_read_refused": {"encryption", "decryption"},
    "no_credential_refused": {"credential"},
    "outside_prefix_write_refused": {"access_denied"},
    "decoy_refused": {"access_denied"},
}
STATE_STATUS = re.compile(rb"StatusCode: ([0-9]{3})\b")
STATE_TRANSIENT = re.compile(rb"(?<![-\w])timeout|timed out|connection (?:refused|reset)|no such host|unexpected EOF",
                             re.IGNORECASE)
# WSLC OCI dev target (roccho-dev/adrs#460): the same one-shot Jev source, encrypted to exactly one target recipient.
# It has no plane state and no handoff; the validated ciphertext at an exact commit is its whole readiness.
OCI_BINDING = "jev-api.oci-dev"
OCI_CIPHERTEXT = Path("ciphertexts/dev-jev-api.oci-dev.sops.yaml")
OCI_RECIPIENT = "OCI_DEV_AGE_RECIPIENT"
# Every binding `author --target` can select; a dispatch names exactly one of them.
AUTHOR_TARGETS = ("jev-api", OCI_BINDING)

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
AGE_RECIPIENT = re.compile(r"^age1[02-9ac-hj-np-z]{58}$")
AGE_IDENTITY = re.compile(r"^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$")
CLOUDFLARE_ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
CLOUDFLARE_WORKER_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CLOUDFLARE_TUNNEL_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CLOUDFLARE_TOKEN_ID = re.compile(r"^[0-9a-f]{32}$")
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
    "decrypted_value", "secret_hash",
}
SECRET_PLANE_KEYS = {
    "id", "kind", "stage_id", "plane_id", "owner", "github_environment",
    "active_github_environment", "migration_state", "source_kind", "target_kind", "desired_state",
}


class EnvsError(ValueError):
    pass


# State proof: provider doubt (EnvsError) and local launch or storage failures; none may bypass cleanup or become evidence.
STATE_FAILURES = (EnvsError, OSError, subprocess.SubprocessError)


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


def validate_jev_target(target: Any) -> dict[str, Any]:
    require(isinstance(target, dict), "Jev target must be an object")
    provider = target.get("provider")
    if provider == "cloudflare-pages":
        require(target == {
            "provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY",
        }, "Pages Jev target differs")
    elif provider == "cloudflare-workers":
        require(set(target) == {"provider", "account_id", "worker_name", "secret_name"},
                "Workers Jev target fields differ")
        require(isinstance(target.get("account_id"), str)
                and CLOUDFLARE_ACCOUNT_ID.fullmatch(target["account_id"]) is not None,
                "Workers account id invalid")
        require(isinstance(target.get("worker_name"), str)
                and CLOUDFLARE_WORKER_NAME.fullmatch(target["worker_name"]) is not None,
                "Workers name invalid")
        require(target.get("secret_name") == "JEV_API_KEY", "Workers secret name differs")
    else:
        raise EnvsError("Jev target provider unsupported")
    return target


def expected_bindings(jev_target: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    target = {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"} \
        if jev_target is None else validate_jev_target(jev_target)
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
            "target": dict(target),
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
        OCI_BINDING: {
            "id": OCI_BINDING,
            "kind": "envs.authCapability.v1",
            "capability": "jev-api",
            "ciphertext": OCI_CIPHERTEXT.as_posix(),
            "source_key": "JEV_API_KEY",
            "github_environment": "dev-authoring",
            "required_variables": [{"name": OCI_RECIPIENT, "type": "age_recipient", "lifecycle": "persistent"}],
            "target": {"repository": "roccho-dev/windows", "host": "oci-dev", "kind": "process_env", "secret_name": "JEV_API_KEY"},
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
        "owns": ["contract", "bounded_retrieval", "single_recipient_encryption", "ciphertext_handoff_pr",
                 "target_placement_entry"],
        "does_not_own": ["target_apply", "target_age_identity", "client_access_credential", "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_client_boundary() -> dict[str, Any]:
    # envs projects the root output and ships the entrance; the provider apply, running it on the target, the
    # target's identity and the Windows slot writer belong to others.
    return {
        "id": "dev.rent-client.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-client",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "root_output_projection", "single_recipient_encryption", "target_placement_entry"],
        "does_not_own": ["provider_apply", "target_apply", "target_age_identity", "client_slot_writer",
                         "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_root_boundary() -> dict[str, Any]:
    # envs owns the entry that applies the declared root and seals its output; the effect, its authority, the state
    # backend and key custody, the targets and their identities belong to others.
    return {
        "id": "dev.rent-root.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-root",
        "source_kind": "provider_issued",
        "target_kind": "public_sops",
        "owns": ["contract", "root_orchestration_entry", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["provider_apply_authority", "state_backend_custody", "encryption_key_custody", "target_apply",
                         "target_age_identity", "client_slot_writer", "unattended_ssh_acceptance"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_windows_consumer(source: str) -> dict[str, Any]:
    # The exact windows source whose published Release (windows-<source>) the placement gate binds.
    return {
        "id": WINDOWS_CONSUMER,
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "consumer",
        "repository": "roccho-dev/windows",
        "stage": "dev",
        "capability": "rent-client",
        "distribution_source": source,
        "owns": ["client_slot_format", "client_slot_writer", "consumer_launcher", "rent_slot_format"],
        "requires": ["exact_release", "release_publication_success", "target_native_slot"],
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


def expected_state_boundary() -> dict[str, Any]:
    # A disposable proof of the state backend; the parent credential and every existing bucket belong to others.
    return {
        "id": "dev.rent-state-proof.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "rent-state-proof",
        "source_kind": "github_environment",
        "target_kind": "disposable_state_proof",
        "owns": ["disposable_state_buckets", "run_scoped_temporary_credentials", "evidence_bound_cleanup"],
        "does_not_own": ["parent_credential", "existing_r2_buckets", "reserved_production_state_bucket",
                         "name_matched_deletion", "production_state"],
        "handoff_ref_kind": "exact_commit_sha",
    }


def expected_oci_boundary() -> dict[str, Any]:
    # envs ends at the target-bound ciphertext PR; the target applies it and apps proves its own runtime.
    return {
        "id": "dev.jev-api-oci-dev.provider",
        "kind": "envs.providerConsumerBoundary.v1",
        "role": "provider",
        "repository": "roccho-dev/envs",
        "stage": "dev",
        "capability": "jev-api",
        "binding": OCI_BINDING,
        "source_kind": "ephemeral_ingress",
        "target_kind": "public_sops",
        "owns": ["contract", "target_selected_authoring", "single_recipient_encryption", "ciphertext_handoff_pr"],
        "does_not_own": ["target_apply", "target_age_identity", "application_runtime_acceptance", "deployment"],
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
        # The credential arrives on stdin from the root's sensitive output; only its one recipient is an input.
        CLIENT_PLANE: {
            "required_secrets": entries(),
            "required_variables": entries((CLIENT_RECIPIENT, "age_recipient", "persistent")),
        },
        # The persistent root shares the rent tunnel Environment; its own plane names every input the apply reads.
        ROOT_PLANE: {
            "required_secrets": entries(*((name, "opaque", "persistent") for name in ROOT_SECRETS)),
            "required_variables": entries(
                ("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("CLOUDFLARE_ZONE_ID", "cloudflare_zone_id", "persistent"),
                ("RENT_HOSTNAME", "opaque", "persistent"),
                ("RENT_ORIGIN_SERVICE", "opaque", "persistent"),
                ("RENT_SERVICE_TOKEN_DURATION", "opaque", "persistent"),
                ("RENT_STATE_BUCKET", "opaque", "persistent"),
                ("RENT_STATE_KEY", "opaque", "persistent"),
                ("RENT_AGE_RECIPIENT", "age_recipient", "persistent"),
                (CLIENT_RECIPIENT, "age_recipient", "persistent"),
            ),
        },
        PROBE_PLANE: {
            "required_secrets": entries(("CLOUDFLARE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(
                ("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent"),
                ("CLOUDFLARE_ZONE_ID", "cloudflare_zone_id", "persistent"),
            ),
        },
        STATE_PLANE: {
            # The parent token ID is non-secret but a GitHub variable is printed in the public step log, so it is a secret.
            "required_secrets": entries(
                ("R2_PARENT_API_TOKEN", "opaque", "finite_expiry"),
                ("R2_PARENT_ACCESS_KEY_ID", "cloudflare_api_token_id", "finite_expiry"),
            ),
            "required_variables": entries(("CLOUDFLARE_ACCOUNT_ID", "cloudflare_account_id", "persistent")),
        },
        LINODE_READ_PLANE: {
            "required_secrets": entries(("LINODE_API_TOKEN", "opaque", "persistent")),
            "required_variables": entries(),
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
    "cloudflare_api_token_id": lambda value: CLOUDFLARE_TOKEN_ID.fullmatch(value) is not None,
}


def validate_contracts(root: Path = ROOT) -> dict[str, dict[str, dict[str, Any]]]:
    envs = index(root / ENVIRONMENTS)
    bindings = index(root / BINDINGS)
    boundary = index(root / BOUNDARY)

    require(set(envs) == {
        "dev.authoring", "dev.projection", "dev.runtime", RENT_PLANE, CLIENT_PLANE, ROOT_PLANE, PROBE_PLANE, STATE_PLANE,
        LINODE_READ_PLANE,
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

    client = envs[CLIENT_PLANE]
    require(client["github_environment"] == "dev-rent-client" and client["owner"] == "envs"
            and client["source_kind"] == "provider_issued" and client["target_kind"] == "public_sops",
            f"{CLIENT_PLANE} plane differs")
    client_cipher = root / CLIENT_CIPHERTEXT
    if client_cipher.is_file():
        require(client["active_github_environment"] == "dev-rent-client" and client["migration_state"] == "ACTIVE",
                f"{CLIENT_PLANE} must be ACTIVE with its ciphertext")
        validate_client_ciphertext(client_cipher.read_bytes(), None, None)
    else:
        require(client["active_github_environment"] is None and client["migration_state"] == "NOT_CONFIGURED",
                f"{CLIENT_PLANE} must be NOT_CONFIGURED without its ciphertext")

    # The persistent root has no ciphertext of its own: ACTIVE records only that it sealed both envelopes above
    # (declared plane state, not proof that the Environment, the provider or the backend is configured).
    root_plane = envs[ROOT_PLANE]
    require(root_plane["github_environment"] == rent["github_environment"] and root_plane["owner"] == "envs"
            and root_plane["source_kind"] == "provider_issued" and root_plane["target_kind"] == "public_sops",
            f"{ROOT_PLANE} plane differs")
    if root_plane["migration_state"] == "ACTIVE":
        require(root_plane["active_github_environment"] == "dev-rent-tunnel" and rent_cipher.is_file()
                and client_cipher.is_file(), f"{ROOT_PLANE} is ACTIVE only with both envelopes")
    else:
        require(root_plane["active_github_environment"] is None and root_plane["migration_state"] == "NOT_CONFIGURED",
                f"{ROOT_PLANE} must be NOT_CONFIGURED until it sealed both envelopes")

    probe = envs[PROBE_PLANE]
    require(probe["github_environment"] == "dev-rent-access-probe" and probe["owner"] == "envs"
            and probe["source_kind"] == "provider_issued" and probe["target_kind"] == "disposable_probe"
            and probe["active_github_environment"] is None and probe["migration_state"] == "NOT_CONFIGURED",
            f"{PROBE_PLANE} must be a NOT_CONFIGURED disposable probe plane")
    # The state proof shares the probe's Environment under its own secret name, so neither reads the other's token.
    state = envs[STATE_PLANE]
    require(state["github_environment"] == probe["github_environment"] and state["owner"] == "envs"
            and state["source_kind"] == "github_environment" and state["target_kind"] == "disposable_state_proof"
            and state["active_github_environment"] is None and state["migration_state"] == "NOT_CONFIGURED",
            f"{STATE_PLANE} must be a NOT_CONFIGURED disposable state plane")
    probe_secrets = {entry["name"] for entry in probe["required_secrets"]}
    require(not probe_secrets & {entry["name"] for entry in state["required_secrets"]},
            f"{STATE_PLANE} must not reuse the access probe secret")

    linode = envs[LINODE_READ_PLANE]
    require(linode["github_environment"] == "dev-projection" and linode["owner"] == "envs"
            and linode["source_kind"] == "provider_issued" and linode["target_kind"] == "read_probe"
            and linode["active_github_environment"] is None and linode["migration_state"] == "NOT_CONFIGURED",
            f"{LINODE_READ_PLANE} must be a NOT_CONFIGURED read-only probe plane")

    # The OCI target has no state of its own: its ciphertext, when present, is simply valid or RED.
    oci_cipher = root / OCI_CIPHERTEXT
    if oci_cipher.is_file():
        validate_oci_ciphertext(oci_cipher.read_bytes(), None, None)

    jev_target = validate_jev_target(bindings.get("jev-api", {}).get("target"))
    require(bindings == expected_bindings(jev_target), "binding set differs")
    require(set(boundary) == {
        "repository.branch-policy", "dev.jev-api.provider", "dev.rent-tunnel.provider", "dev.rent-access-probe.provider",
        "dev.rent-state-proof.provider", "dev.jev-api-oci-dev.provider", "apps.voice-ui.consumer", "ops.voice-ui.consumer",
        "normal.consumer.path", "dev.rent-client.provider", "dev.rent-root.provider", WINDOWS_CONSUMER,
    }, "provider-consumer boundary set differs")
    require(boundary["dev.rent-tunnel.provider"] == expected_rent_boundary(), "rent tunnel provider boundary differs")
    require(boundary["dev.rent-client.provider"] == expected_client_boundary(), "rent client provider boundary differs")
    require(boundary["dev.rent-root.provider"] == expected_root_boundary(), "rent root provider boundary differs")
    source = boundary[WINDOWS_CONSUMER].get("distribution_source")
    require(isinstance(source, str) and SHA40.fullmatch(source) is not None
            and boundary[WINDOWS_CONSUMER] == expected_windows_consumer(source), "windows rent consumer boundary differs")
    require(boundary["dev.rent-access-probe.provider"] == expected_probe_boundary(), "access probe provider boundary differs")
    require(boundary["dev.rent-state-proof.provider"] == expected_state_boundary(), "state proof provider boundary differs")
    require(boundary["dev.jev-api-oci-dev.provider"] == expected_oci_boundary(), "OCI dev provider boundary differs")
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


def validate_client_ciphertext(data: bytes, values: Sequence[bytes] | None, recipient: str | None) -> None:
    for index, key in enumerate(CLIENT_KEYS):
        validate_ciphertext(data, None if values is None else values[index], None if recipient is None else [recipient], key=key)
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "rent client ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {*CLIENT_KEYS, "sops"}, "rent client ciphertext fields differ")


def validate_oci_ciphertext(data: bytes, secret: bytes | None, recipient: str | None) -> None:
    validate_ciphertext(data, secret, None if recipient is None else [recipient])
    text = data.decode("utf-8", errors="strict")
    require(len(RECIPIENT_METADATA.findall(text)) == 1, "OCI dev ciphertext must have exactly one recipient")
    require(set(re.findall(r"(?m)^([^\s#][^:]*):", text)) == {"JEV_API_KEY", "sops"}, "OCI dev ciphertext fields differ")


def repository_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and "__pycache__" not in path.relative_to(root).parts
        and path.suffix != ".pyc"
    )


def reject_live_values(root: Path, name: str, values: list[str],
                       allowed_paths: tuple[str, ...] = ()) -> None:
    for path in repository_files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if relative in {CIPHERTEXT.as_posix(), RENT_CIPHERTEXT.as_posix(), CLIENT_CIPHERTEXT.as_posix(), OCI_CIPHERTEXT.as_posix()}:
            data = without_recipient_metadata(data.decode("utf-8", errors="replace")).encode()
        for value in values:
            if value.encode() in data:
                require(relative in allowed_paths, f"{relative}: live {name} value is stored in Git")


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
        allowed_paths: tuple[str, ...] = ()
        if entry["name"] == "CLOUDFLARE_ACCOUNT_ID":
            target = contracts["bindings"]["jev-api"]["target"]
            if target.get("provider") == "cloudflare-workers":
                require(value == target["account_id"], "Workers target account differs from projection account")
                # Account ID is a non-secret target identifier. It may occur only in the
                # closed selected binding and its non-secret handoff receipt; every other
                # repository occurrence remains rejected.
                allowed_paths = (BINDINGS.as_posix(), HANDOFF.as_posix())
        reject_live_values(root, entry["name"], live or [], allowed_paths)
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


def authoring_inputs(contracts: dict[str, dict[str, dict[str, Any]]], target: str) -> list[dict[str, str]]:
    # The Environment inputs one author target reads. The Cloudflare target reads its plane's own; the OCI target
    # reads the plane's source secret plus the recipient its binding declares. Neither reads the other's recipient.
    require(target in AUTHOR_TARGETS, f"unknown author target: {target}")
    plane = contracts["environments"]["dev.authoring"]
    if target == "jev-api":
        return plane["required_secrets"] + plane["required_variables"]
    binding = contracts["bindings"][target]
    require(binding["github_environment"] == plane["github_environment"], f"{target} Environment differs")
    source = [entry for entry in plane["required_secrets"] if entry["name"] == binding["source_key"]]
    require(len(source) == 1, f"{target} source secret is not declared")
    return source + binding["required_variables"]


def encrypt_oci_key(source: str, recipient: str, tools: Mapping[str, str], runner: Runner = default_runner) -> bytes:
    # The key reaches SOPS on stdin only; the ciphertext must name exactly this one recipient.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "OCI dev target needs exactly one age recipient")
    require(source != "", "OCI dev source key is empty")
    payload = json.dumps({"JEV_API_KEY": source}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_oci_ciphertext(result.stdout, source.encode(), recipient)
    return result.stdout


def author_oci(root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    # Writes only the OCI ciphertext: no plane state, no handoff, no other target's file.
    contracts = validate_contracts(root)
    tools = toolchain(root)
    values: dict[str, str] = {}
    for entry in authoring_inputs(contracts, OCI_BINDING):
        name, kind = entry["name"], entry["type"]
        value = os.environ.get(name, "")
        require(value != "", f"{OCI_BINDING}: {name} is missing")
        require(INPUT_TYPES[kind](value), f"{OCI_BINDING}: {name} is not a valid {kind}")
        values[name] = value
    # Secret and Variable alike: a value already in Git is RED before SOPS runs.
    reject_live_values(root, OCI_RECIPIENT, [values[OCI_RECIPIENT]])
    reject_live_values(root, "JEV_API_KEY", [values["JEV_API_KEY"]])
    data = encrypt_oci_key(values["JEV_API_KEY"], values[OCI_RECIPIENT], tools, runner)
    target = root / OCI_CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    validate_contracts(root)
    return {
        "kind": "envs.targetAuthoringResult.v1", "status": "PASS", "binding": OCI_BINDING,
        "ciphertext": OCI_CIPHERTEXT.as_posix(), "recipient_count": 1,
        "target_apply": "NOT_RUN", "application_runtime": "NOT_RUN",
    }


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


def encrypt_rent_token(token: str, recipient: str, tools: Mapping[str, str], runner: Runner = default_runner,
                       home: str | None = None) -> bytes:
    # The token reaches SOPS on stdin only; the ciphertext must name exactly this one recipient. A given home replaces
    # the inherited HOME (rent-root's fresh one); without it the standalone entries keep their existing environment.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "rent tunnel needs exactly one age recipient")
    require(TUNNEL_TOKEN.fullmatch(token) is not None, "invalid tunnel token")
    payload = json.dumps({RENT_KEY: token}, separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient, **({} if home is None else {"HOME": home})}),
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


def encrypt_client_credential(client_id: str, secret: str, recipient: str, tools: Mapping[str, str],
                              runner: Runner = default_runner, home: str | None = None) -> bytes:
    # Both values reach SOPS on stdin only; each must be one line of the windows slot rule, for exactly one recipient.
    # A given home replaces the inherited HOME, as for encrypt_rent_token.
    require(AGE_RECIPIENT.fullmatch(recipient) is not None, "rent client needs exactly one age recipient")
    require(SLOT_LINE.fullmatch(client_id) is not None and SLOT_LINE.fullmatch(secret) is not None,
            "invalid Access client credential")
    payload = json.dumps(dict(zip(CLIENT_KEYS, (client_id, secret))), separators=(",", ":")).encode() + b"\n"
    result = run_checked(
        [tools["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"],
        input_data=payload,
        env=clean_env(tools, {"SOPS_AGE_RECIPIENTS": recipient, **({} if home is None else {"HOME": home})}),
        runner=runner,
        label="SOPS encryption",
    )
    validate_client_ciphertext(result.stdout, (client_id.encode(), secret.encode()), recipient)
    return result.stdout


def client_pair(value: Any, root: Path) -> tuple[str, str]:
    # The root's credentials object: its service token pair, each one line of the windows slot rule, never in Git.
    require(isinstance(value, dict) and set(value) == set(PROBE_CREDENTIALS), "root output is not the credentials object")
    client_id, secret = value["service_token_id"], value["service_token_value"]
    require(isinstance(client_id, str) and isinstance(secret, str) and SLOT_LINE.fullmatch(client_id) is not None
            and SLOT_LINE.fullmatch(secret) is not None, "invalid Access client credential")
    reject_live_values(root, "rent client credential", [client_id, secret])
    return client_id, secret


def client_author(credentials: bytes, root: Path = ROOT, runner: Runner = default_runner) -> dict[str, Any]:
    # The persistent root's sensitive `credentials` output (tofu output -json credentials) arrives on stdin; only its
    # service token pair is projected. Nothing is printed but this result, which carries no value.
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, CLIENT_PLANE)
    require(len(credentials) <= RESPONSE_LIMIT, "root output exceeds its bound")
    try:
        value = json.loads(credentials)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise EnvsError("root output is not JSON") from None
    client_id, secret = client_pair(value, root)
    data = encrypt_client_credential(client_id, secret, inputs[CLIENT_RECIPIENT], tools, runner)
    target = root / CLIENT_CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    set_dev_active(root, True, (CLIENT_PLANE,))
    validate_contracts(root)
    return {
        "kind": "envs.rentClientAuthoringResult.v1", "status": "PASS", "ciphertext": CLIENT_CIPHERTEXT.as_posix(),
        "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


def root_env(tools: Mapping[str, str], inputs: Mapping[str, str], home: Path) -> dict[str, str]:
    # Only the OpenTofu child gets these: the API token, the backend credential and endpoint, the fixed encryption
    # (pbkdf2 key provider and aes_gcm method, both k0, for state and plan) and the root's five inputs.
    return clean_env(tools, {
        "CLOUDFLARE_API_TOKEN": inputs["CLOUDFLARE_API_TOKEN"],
        "AWS_ACCESS_KEY_ID": inputs["AWS_ACCESS_KEY_ID"], "AWS_SECRET_ACCESS_KEY": inputs["AWS_SECRET_ACCESS_KEY"],
        "AWS_ENDPOINT_URL_S3": r2_endpoint(inputs["CLOUDFLARE_ACCOUNT_ID"]), "AWS_EC2_METADATA_DISABLED": "true",
        "TF_ENCRYPTION": encryption_config(ROOT_KEY_NAME, inputs["RENT_STATE_PASSPHRASE"]),
        "TF_VAR_account_id": inputs["CLOUDFLARE_ACCOUNT_ID"], "TF_VAR_zone_id": inputs["CLOUDFLARE_ZONE_ID"],
        "TF_VAR_hostname": inputs["RENT_HOSTNAME"], "TF_VAR_origin_service": inputs["RENT_ORIGIN_SERVICE"],
        "TF_VAR_service_token_duration": inputs["RENT_SERVICE_TOKEN_DURATION"],
        "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "HOME": str(home),
    })


def seal_root_output(root: Path, tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner,
                     rent_recipient: str, client_recipient: str, progress: dict[str, str] | None = None) -> dict[str, Any]:
    # The applied root's sensitive credentials output stays in this process: both envelopes are sealed before the
    # first write. A failure before that write changes no file; one at or after it may leave an unpublished partial
    # diff that is reported, never cleaned up or claimed.
    progress = {} if progress is None else progress
    progress["stage"] = "output"
    value = output(tools, work, env, runner, "credentials", PROBE_CREDENTIALS)
    progress["stage"] = "seal"
    client_id, secret = client_pair(value, root)
    token = value["tunnel_token"]
    require(isinstance(token, str) and TUNNEL_TOKEN.fullmatch(token) is not None, "root output has no valid tunnel token")
    reject_live_values(root, RENT_KEY, [token])
    # The sops children share the run's fresh HOME, never the caller's, and get only their one recipient.
    home = env["HOME"]
    sealed = ((RENT_CIPHERTEXT, encrypt_rent_token(token, rent_recipient, tools, runner, home)),
              (CLIENT_CIPHERTEXT, encrypt_client_credential(client_id, secret, client_recipient, tools, runner, home)))
    progress["stage"] = "write"
    for relative, data in sealed:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    set_dev_active(root, True, (RENT_PLANE, CLIENT_PLANE, ROOT_PLANE))
    validate_contracts(root)
    return {
        "kind": "envs.rentRootResult.v1", "status": "PASS",
        "ciphertexts": [RENT_CIPHERTEXT.as_posix(), CLIENT_CIPHERTEXT.as_posix()],
        "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }


def rent_root(root: Path = ROOT, runner: Runner = default_runner, progress: dict[str, str] | None = None) -> dict[str, Any]:
    # Standard OpenTofu applies the declared root on its native backend; no destroy, import, adoption or retry here.
    # progress["stage"] names how far it got, so a failure is reported as a closed kind and stage only; a captured
    # non-zero init child also leaves progress["init_hint"], its closed and unverified failure facts.
    progress = {} if progress is None else progress
    progress["stage"] = "gate"
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, ROOT_PLANE)
    require(ROOT_PASSPHRASE.fullmatch(inputs["RENT_STATE_PASSPHRASE"]) is not None,
            f"{ROOT_PLANE}: RENT_STATE_PASSPHRASE is not 64 lowercase hex")
    for name in ROOT_SECRETS:
        reject_live_values(root, name, [inputs[name]])
    # A fresh owner-only scratch per run (an empty HOME and the root's working copy). It is retained, never deleted:
    # automated recursive deletion is forbidden, so it lasts as long as the runner's temporary space.
    scratch = Path(tempfile.mkdtemp(prefix="envs-rent-root-"))
    home, work = scratch / "home", scratch / "root"
    home.mkdir(mode=0o700)
    work.mkdir()
    (work / "main.tf").write_bytes((root / ROOT_CONFIG).read_bytes())
    env = root_env(tools, inputs, home)
    progress["stage"] = "init"

    def init_runner(argv: Sequence[str], input_data: bytes | None,
                    child_env: Mapping[str, str] | None) -> subprocess.CompletedProcess[bytes]:
        # Observed text patterns only, not a cause: the status enum and two booleans, never output or wording.
        result = runner(argv, input_data, child_env)
        if result.returncode != 0:
            facts = failure_facts(result)
            progress["init_hint"] = (f"status={facts['status']} access_denied={str(facts['access_denied']).lower()} "
                                     f"transient={str(facts['transient']).lower()}")
        return result

    tofu(tools, work, env, init_runner, "init", "-input=false", "-no-color",
         f"-backend-config=bucket={inputs['RENT_STATE_BUCKET']}", f"-backend-config=key={inputs['RENT_STATE_KEY']}")
    progress["stage"] = "apply"
    tofu(tools, work, env, runner, "apply", "-input=false", "-auto-approve", "-no-color")
    return seal_root_output(root, tools, work, env, runner, inputs["RENT_AGE_RECIPIENT"], inputs[CLIENT_RECIPIENT],
                            progress)


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


PROBE_CASES = ("service_token", "no_token", "wrong_token", "service_token_again")


def classify(outcomes: Mapping[str, tuple[str, int, bytes]], nonce: str) -> dict[str, Any]:
    # The client sees only its own exit and output, so a refused negative is not evidence that Access denied it: DNS,
    # edge, tunnel or sshd failures look the same. The negatives are bracketed by two token cases; only when both
    # reach the nonce was the path up around them, and even then the refusal cause stays unattributed.
    def reached(outcome: tuple[str, int, bytes]) -> bool:
        return outcome[0] == "exit" and outcome[1] == 0 and outcome[2].strip() == nonce.encode()

    require(set(outcomes) == set(PROBE_CASES), "probe cases differ")
    labels: dict[str, str] = {}
    for case, outcome in outcomes.items():
        if outcome[0] == "timeout":
            labels[case] = "UNKNOWN"
        elif case.startswith("service_token"):
            labels[case] = "REACHED" if reached(outcome) else "FAILED"
        else:
            labels[case] = "ADMITTED" if outcome[1] == 0 or nonce.encode() in outcome[2] else "REFUSED"
    if any(labels[case] == "ADMITTED" for case in ("no_token", "wrong_token")):
        status = "ACCESS_NOT_ENFORCED"
    elif "UNKNOWN" in labels.values():
        status = "UNKNOWN"
    elif labels["service_token"] == labels["service_token_again"] == "REACHED":
        status = "TOKEN_REACHED_NEGATIVES_REFUSED"
    elif labels["service_token"] == labels["service_token_again"] == "FAILED":
        status = "UNATTENDED_PATH_FAILED"
    else:
        status = "UNKNOWN"
    return {"status": status, "cases": labels, "cause": "UNKNOWN",
            "access_denial_evidence": "NOT_OBSERVED",
            "needed_for_denial_claim": "a provider-side Access decision record for each negative attempt"}


def run_probe(tools: Mapping[str, str], credentials: Mapping[str, str], scratch: Path, runner: Runner,
              bounded: Bounded, spawn: Spawn, sleep: Callable[[float], None]) -> dict[str, Any]:
    fixture = ssh_fixture(tools, scratch / "ssh", runner)

    def isolated(name: str, extra: Mapping[str, str]) -> dict[str, str]:
        # Every process and case gets its own fresh, empty HOME: no runner login cache (~/.cloudflared) and no
        # token cached by one case can reach another.
        home = scratch / f"home-{name}"
        home.mkdir(mode=0o700)
        return {**clean_env(tools, {}), "HOME": str(home), **extra}

    processes = [spawn([tools["sshd"], "-D", "-e", "-f", str(fixture["directory"] / "sshd_config")], isolated("sshd", {}))]
    try:
        processes.append(spawn([tools["cloudflared"], "tunnel", "--no-autoupdate", "run"],
                               isolated("tunnel", {"TUNNEL_TOKEN": credentials["tunnel_token"]})))
        sleep(PROBE_SETTLE)
        argv = ssh_argv(tools, fixture, PROBE_HOSTNAME, proxy=True)
        token = {"TUNNEL_SERVICE_TOKEN_ID": credentials["service_token_id"],
                 "TUNNEL_SERVICE_TOKEN_SECRET": credentials["service_token_value"]}
        cases = {
            "service_token": token,
            "no_token": {},
            "wrong_token": {"TUNNEL_SERVICE_TOKEN_ID": credentials["service_token_id"],
                            "TUNNEL_SERVICE_TOKEN_SECRET": secrets.token_hex(32)},
            "service_token_again": token,
        }
        # Each case runs once, in this order, with no retry.
        outcomes = {case: bounded(argv, isolated(case, extra), PROBE_TIMEOUT) for case, extra in cases.items()}
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
        result.update({"stage": "create", "status": "UNKNOWN", "observed_state_ids": None, "probe": None,
                       "id_claim": "IDs are as recorded in this run's OpenTofu state; provider existence or "
                                   "absence is not asserted"})
        observed: dict[str, str] | None = None
        try:
            try:
                tofu(tools, work, env, runner, "apply", "-input=false", "-auto-approve", "-no-color",
                     "-var", "create=true")
            finally:
                # Whatever apply managed to create, its exact IDs are taken from the state before anything else.
                observed = state_ids(tools, work, env, runner)
                result["observed_state_ids"] = observed if observed is not None else "STATE_UNREADABLE"
                print(json.dumps({"kind": "envs.rentAccessProbeStateIds.v1", "observed_state_ids":
                                  result["observed_state_ids"]}, sort_keys=True), file=sys.stderr, flush=True)
            require(observed is not None and set(observed) == set(PROBE_ADDRESSES), "created resource set differs")
            result["stage"] = "probe"
            credentials = output(tools, work, env, runner, "credentials", PROBE_CREDENTIALS)
            require(all(isinstance(value, str) and value for value in credentials.values()), "credentials differ")
            probe = run_probe(tools, credentials, scratch, runner, bounded, spawn, sleep)
            result.update({"probe": probe, "status": probe["status"]})
        except EnvsError as exc:
            result["error"] = str(exc)
        finally:
            # Cleanup destroys only this state, then re-reads the state and looks up absence in a fresh lookup state.
            destroyed = True
            try:
                tofu(tools, work, env, runner, "destroy", "-input=false", "-auto-approve", "-no-color",
                     "-var", "create=true")
            except EnvsError:
                destroyed = False
            remaining = state_ids(tools, work, env, runner)
            after = None
            if destroyed and remaining == {}:
                try:
                    after = locate(root, scratch, "after", tools, env, runner)
                except EnvsError:
                    after = None
            result["located_after"] = after
            if destroyed and remaining == {} and after is not None and not any(after.values()):
                result["cleanup"] = "ABSENT"
            else:
                result["cleanup"] = "CLEANUP_UNKNOWN"
                # Still in state: destroy did not remove them. Unverified: state says removed (or state unreadable),
                # but absence was not read back. Either way only these exact IDs may be cleaned up; a name match may not.
                known = observed or {}
                result["remaining_in_state"] = remaining if remaining is not None else "STATE_UNREADABLE"
                result["unverified_after_destroy"] = {
                    address: value for address, value in known.items() if remaining is None or address not in remaining}
                result["owner_cleanup"] = "exact IDs above only; name-matched deletion needs its own contract"
    if result["cleanup"] != "ABSENT":
        # The current state is what matters: resources may remain, so no probe outcome stands as the status.
        result["status"] = "CLEANUP_UNKNOWN"
    return result


def state_ids(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner) -> dict[str, str] | None:
    # The state JSON can hold secrets in plain text: it is parsed in memory and only managed addresses and IDs leave.
    try:
        state = json.loads(tofu(tools, work, env, runner, "show", "-json", "-no-color") or b"{}")
    except (EnvsError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    resources = (state.get("values") or {}).get("root_module", {}).get("resources", []) if isinstance(state, dict) else None
    if not isinstance(resources, list):
        return None
    found: dict[str, str] = {}
    for item in resources:
        if not isinstance(item, dict) or item.get("mode") != "managed":
            continue
        address, value = item.get("address"), (item.get("values") or {}).get("id")
        if address not in PROBE_ADDRESSES or not isinstance(value, str) or not value or address in found:
            return None
        found[address] = value
    return found


# A Cloudflare API call returns (HTTP status, parsed JSON or None); a transport failure is UNKNOWN, never a status.
Api = Callable[[str, str, str, Any], tuple[int, Any]]


def default_api(method: str, path: str, token: str, body: Any) -> tuple[int, Any]:
    # Same bounds as the tunnel token GET; errors never carry the response, the request headers or the token.
    bundle = os.environ.get("SSL_CERT_FILE", "")
    require(in_store(bundle) and os.path.isfile(bundle), "repo-owned CA bundle is missing")
    require(BEARER.fullmatch(token) is not None, "invalid Cloudflare API token shape")
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{CLOUDFLARE_API}{path}", data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=bundle)), NoRedirect)
    try:
        with opener.open(request, timeout=RETRIEVAL_TIMEOUT) as response:
            status, raw = response.status, response.read(RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(RESPONSE_LIMIT + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise EnvsError("Cloudflare request outcome is UNKNOWN") from None
    require(len(raw) <= RESPONSE_LIMIT, "Cloudflare response exceeds its bound")
    try:
        return status, (json.loads(raw) if raw else None)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None


def api_result(status: int, value: Any) -> Any:
    return value.get("result") if status == 200 and isinstance(value, dict) and value.get("success") is True else None


def utc_seconds(value: Any) -> float:
    require(isinstance(value, str) and value.endswith("Z"), "provider timestamp is not UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").timestamp()
    except ValueError:
        raise EnvsError("provider timestamp is invalid") from None


def state_window() -> float:
    # The job bound (which includes the temporary-credential wait and cleanup) plus the declared margin.
    return STATE_JOB_MINUTES * 60 + STATE_MARGIN


def verify_parent(api: Api, account: str, token: str, expected: str, now: float) -> dict[str, str]:
    # Verify proves identity, status and time bounds only; R2 authority is proven by the first bounded create.
    result = api_result(*api("GET", f"/accounts/{account}/tokens/verify", token, None))
    require(isinstance(result, dict), "parent token verify did not succeed")
    require(result.get("id") == expected, "parent token ID differs from R2_PARENT_ACCESS_KEY_ID")
    require(result.get("status") == "active", "parent token is not active")
    if result.get("not_before") is not None:
        require(utc_seconds(result["not_before"]) <= now, "parent token is not yet valid")
    require(result.get("expires_on") is not None, "parent token has no expiry")
    require(utc_seconds(result["expires_on"]) - now >= state_window(), "parent token expiry does not cover the proof window")
    return {"id": "MATCHED", "status": "ACTIVE", "expiry": "COVERS_WINDOW"}


def run_identity(environ: Mapping[str, str]) -> dict[str, str]:
    run_id, attempt, head = (environ.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"))
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None and re.fullmatch(r"[1-9][0-9]{0,3}", attempt) is not None
            and SHA40.fullmatch(head) is not None, "GitHub run identity is missing")
    return {"run_id": run_id, "run_attempt": attempt, "head": head, "scope": f"{run_id}-{attempt}"}


def state_bucket_names(run: Mapping[str, str]) -> dict[str, str]:
    proof = STATE_BUCKET_PREFIX + run["scope"]
    names = {"proof": proof, "decoy": proof + "-decoy"}
    require(STATE_RESERVED_BUCKET not in names.values() and all(len(name) <= 63 for name in names.values()),
            "state bucket names differ")
    return names


def bucket_creation(api: Api, account: str, token: str, name: str) -> str | None:
    # None is absent (404); a present bucket returns its provider creation_date; anything else is UNKNOWN.
    status, value = api("GET", f"/accounts/{account}/r2/buckets/{name}", token, None)
    if status == 404:
        return None
    result = api_result(status, value)
    require(isinstance(result, dict) and result.get("name") == name and isinstance(result.get("creation_date"), str),
            "bucket readback is UNKNOWN")
    return result["creation_date"]


def temporary_credentials(api: Api, account: str, token: str, parent: str, bucket: str) -> dict[str, str]:
    # One bucket-bound, prefix-bound, object-level credential that cannot exceed its parent and expires by itself.
    result = api_result(*api("POST", f"/accounts/{account}/r2/temp-access-credentials", token, {
        "bucket": bucket, "parentAccessKeyId": parent, "permission": "object-read-write",
        "ttlSeconds": STATE_CREDENTIAL_TTL, "prefixes": [STATE_ALLOWED_PREFIX]}))
    require(isinstance(result, dict), "temporary credential issuance did not succeed")
    values = {name: result.get(field) for name, field in (
        ("AWS_ACCESS_KEY_ID", "accessKeyId"), ("AWS_SECRET_ACCESS_KEY", "secretAccessKey"),
        ("AWS_SESSION_TOKEN", "sessionToken"))}
    require(all(isinstance(value, str) and BEARER.fullmatch(value) for value in values.values()),
            "temporary credential differs")
    return values


def state_buckets(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner) -> dict[str, str] | None:
    # This run's own create results: bucket name and provider creation_date from its state, parsed in memory.
    try:
        state = json.loads(tofu(tools, work, env, runner, "show", "-json", "-no-color") or b"{}")
    except (EnvsError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    resources = (state.get("values") or {}).get("root_module", {}).get("resources", []) if isinstance(state, dict) else None
    if not isinstance(resources, list):
        return None
    found: dict[str, str] = {}
    for item in resources:
        if not isinstance(item, dict) or item.get("mode") != "managed":
            continue
        values = item.get("values") or {}
        name, created = values.get("name"), values.get("creation_date")
        if item.get("type") != "cloudflare_r2_bucket" or not isinstance(name, str) or not isinstance(created, str) \
                or name in found:
            return None
        found[name] = created
    return found


def state_evidence(run: Mapping[str, str], bucket: str, created: str) -> dict[str, str]:
    return {"kind": STATE_EVIDENCE_KIND, "bucket": bucket, "creation_date": created,
            "run_id": run["run_id"], "run_attempt": run["run_attempt"], "head": run["head"]}


def record_created(tools: Mapping[str, str], work: Path, env: Mapping[str, str], runner: Runner,
                   run: Mapping[str, str], previous: dict[str, str] | None) -> dict[str, str] | None:
    # Right after each create, every new bucket is emitted once as a non-secret evidence line.
    found = state_buckets(tools, work, env, runner)
    if found is None or previous is None:
        return None
    for bucket, created in sorted(found.items()):
        if previous.get(bucket) != created:
            print(json.dumps(state_evidence(run, bucket, created), sort_keys=True), file=sys.stderr, flush=True)
    return found


def parse_state_evidence(text: str, run: Mapping[str, str]) -> dict[str, str]:
    # Recovery input: the evidence lines of one exact run, attempt and head, from a job log with any line prefix.
    names = set(state_bucket_names(run).values())
    found: dict[str, str] = {}
    for line in text.splitlines():
        start = line.find("{")
        if start == -1 or STATE_EVIDENCE_KIND not in line:
            continue
        try:
            value = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict) or value.get("kind") != STATE_EVIDENCE_KIND:
            continue
        if any(value.get(key) != run[key] for key in ("run_id", "run_attempt", "head")):
            continue
        bucket, created = value.get("bucket"), value.get("creation_date")
        if bucket not in names or not isinstance(created, str):
            continue
        require(found.get(bucket, created) == created, "conflicting bucket creation evidence")
        found[bucket] = created
    return found


def owned_buckets(evidence: Mapping[str, str], current: Mapping[str, str | None], run: Mapping[str, str]) -> list[str]:
    # Deletion needs this run's create evidence and the same provider creation_date now; a name alone never suffices.
    return sorted(name for name in state_bucket_names(run).values()
                  if name in evidence and current.get(name) is not None and current[name] == evidence[name])


def encryption_config(name: str, passphrase: str, fallback: tuple[str, str] | None = None) -> str:
    # TF_ENCRYPTION text with per-run pbkdf2 passphrases; it reaches OpenTofu only through the process environment.
    # OpenTofu binds encrypted metadata to the key provider and method names, so a key keeps its name for life: a
    # rotation adds a new name and keeps the old key under its original name as the fallback.
    blocks = [f'key_provider "pbkdf2" "{key}" {{\n  passphrase = "{value}"\n}}\n'
              f'method "aes_gcm" "{key}" {{\n  keys = key_provider.pbkdf2.{key}\n}}\n'
              for key, value in [(name, passphrase), *([fallback] if fallback else [])]]
    tail = f"  fallback {{\n    method = method.aes_gcm.{fallback[0]}\n  }}\n" if fallback else ""
    blocks += [f"{target} {{\n  method = method.aes_gcm.{name}\n{tail}}}\n" for target in ("state", "plan")]
    return "".join(blocks)


def wrangler_env(tools: Mapping[str, str], scratch: Path, account: str, token: str) -> dict[str, str]:
    home = Path(tempfile.mkdtemp(prefix="home-wrangler-", dir=scratch))
    return clean_env(tools, {"CLOUDFLARE_API_TOKEN": token, "CLOUDFLARE_ACCOUNT_ID": account,
                             "WRANGLER_SEND_METRICS": "false", "HOME": str(home)})


def raw_state(tools: Mapping[str, str], scratch: Path, account: str, token: str, bucket: str, runner: Runner) -> bytes | None:
    # The raw object bytes stay in this process: never stdout, a file, an artifact or a cache.
    result = runner([tools["wrangler"], "r2", "object", "get", f"{bucket}/{STATE_KEY}", "--remote", "--pipe"], None,
                    wrangler_env(tools, scratch, account, token))
    return result.stdout if result.returncode == 0 else None


def encrypted_raw(raw: bytes | None, canary: str) -> bool:
    if raw is None or canary.encode() in raw:
        return False
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(value, dict) and isinstance(value.get("encrypted_data"), str) and "resources" not in value


def failure_facts(result: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    # The captured output is classified in memory and never printed: only these finite facts leave this function.
    text = result.stderr + result.stdout
    statuses = set(STATE_STATUS.findall(text))
    code = next(iter(statuses)) if len(statuses) == 1 else None
    status = "none" if not statuses else "multiple" if code is None else code.decode() if code in {b"401", b"403"} \
        else "5xx" if code.startswith(b"5") else "other"
    lowered = text.lower()
    word = next((word for word in ("decrypt", "encrypt", "credential") if word.encode() in lowered), "none")
    return {"status": status, "access_denied": b"AccessDenied" in text,
            "transient": STATE_TRANSIENT.search(text) is not None, "word": word}


def failure_cause(result: subprocess.CompletedProcess[bytes]) -> str:
    # An S3 status wins over wording; 401 is the credential as a whole, 403 AccessDenied is its scope; transport
    # noise or any other status is UNKNOWN.
    facts = failure_facts(result)
    if facts["transient"] or facts["status"] in {"5xx", "multiple", "other"}:
        return "unknown"
    if facts["status"] == "401":
        return "unauthorized"
    if facts["status"] == "403":
        return "access_denied" if facts["access_denied"] else "unknown"
    return {"decrypt": "decryption", "encrypt": "encryption", "credential": "credential"}.get(facts["word"], "unknown")


def refusal(control: bool, attempt: subprocess.CompletedProcess[bytes], causes: set[str]) -> str:
    if attempt.returncode == 0:
        return "ADMITTED"
    return "REFUSED" if control and failure_cause(attempt) in causes else "UNKNOWN"


# Branch evidence for the receipt: every value comes from these closed sets, so no captured output, status body,
# key, credential or exception text can reach it. It explains an UNKNOWN; it never changes a label or PASS.
STATE_DIAGNOSTIC_VALUES: dict[str, tuple[Any, ...]] = {
    "control": (True, False),
    "phase": ("admitted", "init", "read", "lock", "write"),
    "probe": ("not_run", "admitted", "refused", "local_failure"),
    "status": ("none", "401", "403", "5xx", "other", "multiple"),
    "access_denied": (True, False),
    "transient": (True, False),
    "word": ("decrypt", "encrypt", "credential", "none"),
    "local": ("none", "envs", "os", "subprocess"),
    # The post-TTL probe's S3 error code: the R2 authentication and authorization codes, any other parsed code, or
    # none. It narrows the investigation only; no code is a credential end, which stays a completed 401.
    "code": ("Unauthorized", "AccessDenied", "ExpiredRequest", "SignatureDoesNotMatch", "NotEntitled", "other", "none"),
}
NO_FAILURE_FACTS = {"status": "none", "access_denied": False, "transient": False, "word": "none"}


def negative_evidence(control: bool, phase: str, attempt: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    # phase is where the attempt stopped: admitted, or refused at init, read (output) or lock (the lock-file write).
    facts = NO_FAILURE_FACTS if attempt.returncode == 0 else failure_facts(attempt)
    return {"control": control, "phase": "admitted" if attempt.returncode == 0 else phase, **facts}


def r2_endpoint(account: str) -> str:
    return f"https://{account}.r2.cloudflarestorage.com"


def curl_value(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def s3_error_code(body: bytes) -> str | None:
    # Only an actual S3 XML error document with exactly one direct Code names a code; a substring, a bodyless reply,
    # malformed XML or contradictory duplicate codes name none.
    if not body or len(body) > S3_BODY_LIMIT:
        return None
    try:
        document = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None
    codes = document.findall("Code") if document.tag == "Error" else []
    return codes[0].text.strip() if len(codes) == 1 and codes[0].text else None


def s3_object(tools: Mapping[str, str], runner: Runner, endpoint: str, credentials: Mapping[str, str], method: str,
              bucket: str, key: str, body: bytes | None = None, timeout: int = S3_TIMEOUT) -> dict[str, Any]:
    # One path-style request signed by the locked curl (aws:amz:auto:s3) with the temporary credential. The credential
    # and session token reach curl only through its stdin config, with its default config disabled: never argv, a
    # file or a log. No proxy, redirect or retry. The reply stays in this process and leaves only as finite facts.
    scheme = endpoint.split("://", 1)[0]
    lines = [
        f"url = {curl_value(f'{endpoint}/{bucket}/{key}')}",
        f"request = {curl_value(method)}",
        'aws-sigv4 = "aws:amz:auto:s3"',
        f"user = {curl_value(credentials['AWS_ACCESS_KEY_ID'] + ':' + credentials['AWS_SECRET_ACCESS_KEY'])}",
        f"header = {curl_value('x-amz-security-token: ' + credentials['AWS_SESSION_TOKEN'])}",
        f"proto = {curl_value('=' + scheme)}",
        'noproxy = "*"',
        "silent",
        f'connect-timeout = "{min(timeout, 10)}"',
        f'max-time = "{timeout}"',
        'write-out = "%{stderr}%{http_code}"',
    ]
    if os.environ.get("SSL_CERT_FILE") and scheme == "https":
        lines.append(f"cacert = {curl_value(os.environ['SSL_CERT_FILE'])}")
    if body is not None:
        lines += [f"data-binary = {curl_value(body.decode('ascii'))}", 'header = "Content-Type: application/octet-stream"']
    result = runner([tools["curl"], "-q", "--config", "-"], ("\n".join(lines) + "\n").encode("utf-8"), clean_env(tools, {}))
    written = result.stderr.strip()
    code = int(written) if re.fullmatch(rb"[0-9]{3}", written) else 0
    # Any nonzero curl exit is an incomplete transfer (timeout, connection, partial body...): whatever status or body
    # arrived, it is transient and never a completed reply, so it can be neither ADMITTED, REFUSED nor a 401 expiry.
    complete = result.returncode == 0
    ok = complete and 200 <= code < 300
    status = "none" if ok or code == 0 else str(code) if code in (401, 403) else "5xx" if code >= 500 else "other"
    # Only a completed failed reply's single direct Code names one, mapped into the closed set; nothing else is kept.
    parsed = s3_error_code(result.stdout) if complete and not ok else None
    known = STATE_DIAGNOSTIC_VALUES["code"][:-2]
    return {"ok": ok, "status": status,
            "access_denied": complete and status == "403" and parsed == "AccessDenied",
            "transient": not complete, "body": result.stdout if ok else None,
            "code": "none" if parsed is None else parsed if parsed in known else "other"}


def s3_facts(operation: Mapping[str, Any]) -> dict[str, Any]:
    if operation["ok"]:
        return dict(NO_FAILURE_FACTS)
    return {"status": operation["status"], "access_denied": operation["access_denied"],
            "transient": operation["transient"], "word": "none"}


def s3_cause(operation: Mapping[str, Any]) -> str:
    # The same rule as failure_cause: 401 is the credential as a whole, 403 with a parsed AccessDenied its scope.
    facts = s3_facts(operation)
    if operation["ok"] or facts["transient"] or facts["status"] not in {"401", "403"}:
        return "unknown"
    return "unauthorized" if facts["status"] == "401" else "access_denied" if facts["access_denied"] else "unknown"


def s3_refusal(control: bool, operation: Mapping[str, Any], causes: set[str]) -> str:
    if operation["ok"]:
        return "ADMITTED"
    return "REFUSED" if control and s3_cause(operation) in causes else "UNKNOWN"


def s3_evidence(control: bool, phase: str, operation: Mapping[str, Any]) -> dict[str, Any]:
    return {"control": control, "phase": "admitted" if operation["ok"] else phase, **s3_facts(operation)}


def failure_class(error: BaseException) -> str:
    # One of the state proof's handled failure kinds, never its message or class name.
    return "envs" if isinstance(error, EnvsError) else "subprocess" if isinstance(error, subprocess.SubprocessError) \
        else "os"


def probe_evidence(probe: str, operation: Mapping[str, Any] | None = None,
                   error: BaseException | None = None) -> dict[str, Any]:
    local = "none" if error is None else failure_class(error)
    facts = s3_facts(operation) if operation is not None else NO_FAILURE_FACTS
    return {"probe": probe, **facts, "local": local, "code": operation["code"] if operation is not None else "none"}


def diagnostics_finite(diagnostics: Any) -> bool:
    # Only known keys with values from their closed set; anything else is never emitted.
    def entry(value: Any, keys: set[str]) -> bool:
        return isinstance(value, dict) and set(value) == keys and all(
            any(type(item) is type(allowed) and item == allowed for allowed in STATE_DIAGNOSTIC_VALUES[key])
            for key, item in value.items())

    if not isinstance(diagnostics, dict) or set(diagnostics) != {"negatives", "credential_probe"}:
        return False
    negatives = diagnostics["negatives"]
    negative_keys = {"control", "phase", *NO_FAILURE_FACTS}
    return (negatives is None or (isinstance(negatives, dict) and set(negatives) == set(STATE_NEGATIVES) and all(
        item is None or entry(item, negative_keys) for item in negatives.values()))) and entry(
        diagnostics["credential_probe"], {"probe", "local", "code", *NO_FAILURE_FACTS})


S3 = Callable[..., dict[str, Any]]


def marker_written(s3: S3, bucket: str, attempted: dict[str, set[str]], key: str = STATE_MARKER_KEY) -> dict[str, Any]:
    # Recorded before it is sent: an ambiguous PUT may still have written the object, so cleanup deletes the key.
    attempted.setdefault(bucket, set()).add(key)
    return s3("PUT", bucket, key, STATE_MARKER)


def marker_read(s3: S3, bucket: str) -> bool:
    operation = s3("GET", bucket, STATE_MARKER_KEY)
    return operation["ok"] and operation["body"] == STATE_MARKER


def decoy_seeded(tools: Mapping[str, str], scratch: Path, account: str, token: str, bucket: str, runner: Runner,
                 attempted: dict[str, set[str]]) -> bool:
    # The parent token writes the known decoy marker and reads its exact bytes back, so a refused read cannot be a
    # missing object masked as a denial.
    attempted.setdefault(bucket, set()).add(STATE_MARKER_KEY)
    env = wrangler_env(tools, scratch, account, token)
    path = f"{bucket}/{STATE_MARKER_KEY}"
    if runner([tools["wrangler"], "r2", "object", "put", path, "--remote", "--pipe"], STATE_MARKER, env).returncode != 0:
        return False
    read = runner([tools["wrangler"], "r2", "object", "get", path, "--remote", "--pipe"], None, env)
    return read.returncode == 0 and read.stdout == STATE_MARKER


# The backend root's one enforced encryption block. Only the no-encryption negative removes it, so that OpenTofu has
# no encryption configuration at all; a method-less enforced block is a configuration error, not a ciphertext read.
STATE_ENCRYPTION_BLOCK = ("  encryption {\n    state {\n      enforced = true\n    }\n"
                          "    plan {\n      enforced = true\n    }\n  }\n")
ENCRYPTION_BLOCK_START = re.compile(r"(?m)^\s*encryption\s*\{")


def without_encryption(text: str) -> str | None:
    # Exactly one exact block is removed; a missing, differing or repeated block yields None (fail closed).
    if text.count(STATE_ENCRYPTION_BLOCK) != 1:
        return None
    plain = text.replace(STATE_ENCRYPTION_BLOCK, "")
    return None if ENCRYPTION_BLOCK_START.search(plain) else plain


def state_checks(root: Path, scratch: Path, tools: Mapping[str, str], account: str, token: str,
                 names: Mapping[str, str], credentials: Mapping[str, str], runner: Runner, spawn: Spawn,
                 sleep: Callable[[float], None], s3: S3,
                 attempted: dict[str, set[str]]) -> tuple[dict[str, bool], dict[str, str], dict[str, Any]]:
    passphrase, rotated = secrets.token_hex(32), secrets.token_hex(32)
    first, second = "canary-" + secrets.token_hex(16), "canary-" + secrets.token_hex(16)
    hold = {"TF_VAR_python": tools["python3"], "TF_VAR_hold_nonce": secrets.token_hex(8),
            "TF_VAR_hold_seconds": str(STATE_HOLD)}
    init = ("init", "-input=false", "-no-color")
    apply = ("apply", "-input=false", "-auto-approve", "-no-color")

    def backend(name: str, *, encryption: str | None, creds: Mapping[str, str] = credentials,
                bucket: str = names["proof"], key: str = STATE_KEY, canary: str = first,
                root_text: str | None = None) -> tuple[Path, dict[str, str]]:
        # Every OpenTofu process gets its own directory and empty HOME; only this run's temporary credential and
        # encryption text reach it, never the parent token. root_text replaces the backend root for that one directory.
        work, home = scratch / name, scratch / f"home-{name}"
        work.mkdir()
        home.mkdir(mode=0o700)
        (work / "main.tf").write_bytes((root / STATE_BACKEND).read_bytes() if root_text is None
                                       else root_text.encode("utf-8"))
        extra = {"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "HOME": str(home), "AWS_EC2_METADATA_DISABLED": "true",
                 "TF_VAR_account_id": account, "TF_VAR_bucket": bucket, "TF_VAR_key": key, "TF_VAR_canary": canary,
                 **hold, **creds}
        if encryption is not None:
            extra["TF_ENCRYPTION"] = encryption
        return work, clean_env(tools, extra)

    def run(work: Path, env: Mapping[str, str], *args: str) -> subprocess.CompletedProcess[bytes]:
        return runner([tools["tofu"], f"-chdir={work}", *args], None, env)

    def ok(work: Path, env: Mapping[str, str], *args: str) -> bool:
        return run(work, env, *args).returncode == 0

    def reads(work: Path, env: Mapping[str, str], expected: str) -> bool:
        if not ok(work, env, *init):
            return False
        result = run(work, env, "output", "-raw", "canary")
        return result.returncode == 0 and result.stdout == expected.encode()

    def read_attempt(name: str, **options: Any) -> tuple[str, subprocess.CompletedProcess[bytes]]:
        work, env = backend(name, **options)
        opened = run(work, env, *init)
        return ("init", opened) if opened.returncode != 0 else ("read", run(work, env, "output", "-raw", "canary"))

    def negative(name: str, control: bool, phase: str, attempt: subprocess.CompletedProcess[bytes]) -> None:
        negatives[name] = refusal(control, attempt, STATE_NEGATIVES[name])
        evidence[name] = negative_evidence(control, phase, attempt)

    checks = dict.fromkeys(STATE_CHECKS, False)
    negatives = dict.fromkeys(STATE_NEGATIVES, "UNKNOWN")
    evidence: dict[str, Any] = dict.fromkeys(STATE_NEGATIVES)
    current = encryption_config("k0", passphrase)
    holder_work, holder_env = backend("holder", encryption=current)
    contender_work, contender_env = backend("contender", encryption=current)
    if not (ok(holder_work, holder_env, *init) and ok(contender_work, contender_env, *init)):
        return checks, negatives, evidence
    holder = spawn([tools["tofu"], f"-chdir={holder_work}", *apply], holder_env)
    code = None
    try:
        sleep(STATE_SETTLE)
        contender = run(contender_work, contender_env, "plan", "-lock-timeout=0", "-input=false", "-no-color")
        checks["lock_contender_rejected"] = contender.returncode != 0 and STATE_LOCK_ERROR in contender.stderr + contender.stdout
        code = holder.wait(timeout=STATE_HOLD + 300)
    except subprocess.TimeoutExpired:
        code = None
    finally:
        if code is None:
            stop(holder)
    checks["lock_holder_applied"] = code == 0
    checks["lock_released"] = run(contender_work, contender_env, "plan", "-lock-timeout=0", "-detailed-exitcode",
                                  "-input=false", "-no-color").returncode == 0
    before = raw_state(tools, scratch, account, token, names["proof"], runner)
    checks["raw_state_encrypted"] = encrypted_raw(before, first)
    checks["readback_exact"] = reads(*backend("readback", encryption=current), first)
    rotate_work, rotate_env = backend("rotate", encryption=encryption_config("k1", rotated, ("k0", passphrase)),
                                     canary=second)
    rewritten = ok(rotate_work, rotate_env, *init) and ok(rotate_work, rotate_env, *apply)
    after = raw_state(tools, scratch, account, token, names["proof"], runner)
    checks["rotation_rewritten"] = rewritten and encrypted_raw(after, second) and after != before
    only_rotated = encryption_config("k1", rotated)
    checks["rotated_readback"] = reads(*backend("rotated", encryption=only_rotated), second)
    # Each negative runs right after a control that differs only in the input under test.
    control = reads(*backend("old-key-control", encryption=only_rotated), second)
    negative("old_key_refused", control, *read_attempt("old-key", encryption=current))
    # No encryption configuration at all: a temporary copy of the root without its enforced block, used only by
    # read_attempt (init and output). If that block cannot be removed exactly, the negative is not attempted.
    plain = without_encryption((root / STATE_BACKEND).read_text(encoding="utf-8"))
    if plain is not None:
        control = reads(*backend("no-encryption-control", encryption=only_rotated), second)
        negative("unencrypted_read_refused", control,
                 *read_attempt("no-encryption", encryption=None, root_text=plain))
    control = ok(*backend("no-credential-control", encryption=only_rotated), *init)
    work, env = backend("no-credential", encryption=only_rotated, creds={})
    negative("no_credential_refused", control, "init", run(work, env, *init))
    # Object boundaries, by the locked curl and the same temporary credential: OpenTofu reads its state key (HEAD)
    # before any write, so its init cannot isolate a prefix write or a bucket read. Each attempt follows a control
    # that differs only in the key or the bucket.
    write_control = marker_written(s3, names["proof"], attempted)["ok"]
    outside = marker_written(s3, names["proof"], attempted, STATE_OUTSIDE_MARKER_KEY)
    negatives["outside_prefix_write_refused"] = s3_refusal(write_control, outside,
                                                           STATE_NEGATIVES["outside_prefix_write_refused"])
    evidence["outside_prefix_write_refused"] = s3_evidence(write_control, "write", outside)
    # The decoy read needs a known object there; without a verified marker the negative is not attempted.
    if decoy_seeded(tools, scratch, account, token, names["decoy"], runner, attempted):
        read_control = marker_read(s3, names["proof"])
        decoy = s3("GET", names["decoy"], STATE_MARKER_KEY)
        negatives["decoy_refused"] = s3_refusal(read_control, decoy, STATE_NEGATIVES["decoy_refused"])
        evidence["decoy_refused"] = s3_evidence(read_control, "read", decoy)
    # The negatives mean something only if the same credential still reads the same state after them.
    checks["path_up_after_negatives"] = reads(*backend("bracket", encryption=only_rotated), second)
    return checks, negatives, evidence


def state_cleanup(tools: Mapping[str, str], scratch: Path, account: str, token: str,
                  run: Mapping[str, str], names: Mapping[str, str], outer: Path, outer_env: Mapping[str, str],
                  created: dict[str, str] | None, credential: str, control: bool, issued: float | None,
                  s3: S3 | None, attempted: Mapping[str, set[str]], runner: Runner, api: Api,
                  sleep: Callable[[float], None], clock: Callable[[], float]) -> dict[str, Any]:
    # Runs once: after the TTL, the same credential must be refused 401 reading the same verified marker; delete only
    # the exact expected and attempted keys and only buckets this run provably created, then read both names back.
    # Doubt is never ABSENT.
    report: dict[str, Any] = {"credential": credential, "buckets": "UNKNOWN", "owned": [], "cleanup": "UNKNOWN",
                              "credential_probe": probe_evidence("not_run")}
    if credential == "ISSUED":
        report["credential"] = "UNKNOWN"
        try:
            if control and issued is not None and s3 is not None:
                sleep(max(0.0, issued + STATE_CREDENTIAL_TTL + STATE_EXPIRY_GRACE - clock()))
                after = s3("GET", names["proof"], STATE_MARKER_KEY)
                report["credential_probe"] = probe_evidence("admitted" if after["ok"] else "refused", after)
                if after["ok"]:
                    report["credential"] = "STILL_USABLE"
                elif s3_cause(after) == "unauthorized":
                    report["credential"] = "UNUSABLE_AFTER_TTL"
        except STATE_FAILURES as exc:
            # A probe that could not run observes nothing: the credential stays UNKNOWN and cleanup still proceeds.
            report["credential"] = "UNKNOWN"
            report["credential_probe"] = probe_evidence("local_failure", error=exc)
    if created is None:
        return report
    # Phase 1: ownership needs a complete current readback; without it nothing is deleted.
    try:
        current = {name: bucket_creation(api, account, token, name) for name in names.values()}
    except STATE_FAILURES:
        return report
    owned = owned_buckets(created, current, run)
    report["owned"] = owned
    # Phase 2: delete only the exact keys (state, lock and every attempted marker), then only owned buckets; a failure
    # here is settled by the readback below. A delete is never a write retry.
    for bucket in names.values():
        if bucket not in owned:
            continue
        keys = [STATE_KEY, STATE_KEY + ".tflock"] if bucket == names["proof"] else []
        for key in keys + sorted(attempted.get(bucket, set()) - set(keys)):
            try:
                runner([tools["wrangler"], "r2", "object", "delete", f"{bucket}/{key}", "--remote"], None,
                       wrangler_env(tools, scratch, account, token))
            except STATE_FAILURES:
                pass
    try:
        present = {name for name, value in current.items() if value is not None}
        if present and present <= set(owned):
            runner([tools["tofu"], f"-chdir={outer}", "destroy", "-input=false", "-auto-approve", "-no-color",
                    "-var", "decoy=true"], None, outer_env)
    except STATE_FAILURES:
        pass
    # Phase 3: the final readback always runs after phase 1; a readback that fails is UNKNOWN, never ABSENT.
    try:
        after_buckets = [bucket_creation(api, account, token, name) for name in names.values()]
        report["buckets"] = "LEFTOVER" if any(value is not None for value in after_buckets) else "ABSENT"
    except STATE_FAILURES:
        report["buckets"] = "UNKNOWN"
    # Absence means only what this run saw: every bucket its create evidence names was read back present and owned
    # before it went; a 404 for a bucket never seen present is doubt, not ABSENT.
    if report["buckets"] == "LEFTOVER":
        report["cleanup"] = "LEFTOVER"
    elif report["buckets"] == "ABSENT" and set(owned) == set(created) \
            and report["credential"] in {"NOT_ATTEMPTED", "UNUSABLE_AFTER_TTL"}:
        report["cleanup"] = "ABSENT"
    return report


def state_proof(root: Path = ROOT, *, runner: Runner = default_runner, api: Api = default_api,
                spawn: Spawn = default_spawn, sleep: Callable[[float], None] = time.sleep,
                clock: Callable[[], float] = time.time) -> dict[str, Any]:
    contracts = validate_contracts(root)
    tools = toolchain(root)
    inputs = gate(root, contracts, STATE_PLANE)
    token, account, parent = (inputs[name] for name in ("R2_PARENT_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID",
                                                        "R2_PARENT_ACCESS_KEY_ID"))
    # Secrets are not covered by the gate's Variable check: a token or its ID already in Git is RED before any call.
    reject_live_values(root, "R2_PARENT_API_TOKEN", [token])
    reject_live_values(root, "R2_PARENT_ACCESS_KEY_ID", [parent])
    run = run_identity(os.environ)
    names = state_bucket_names(run)
    result: dict[str, Any] = {
        "kind": "envs.rentStateProofResult.v1", "status": "UNKNOWN", "stage": "preflight", "buckets": names,
        "parent": verify_parent(api, account, token, parent, clock()), "checks": None, "negatives": None,
        "credential": "NOT_ATTEMPTED", "credential_control": None, "cleanup": "NOT_STARTED",
        "production_state": "UNTOUCHED", "existing_buckets": "UNTOUCHED",
        "diagnostics": {"negatives": None, "credential_probe": probe_evidence("not_run")},
    }
    for name in names.values():
        require(bucket_creation(api, account, token, name) is None, "a per-run bucket name already exists")
    with tempfile.TemporaryDirectory(prefix="envs-state-proof-") as temporary:
        scratch = Path(temporary)
        outer, home = scratch / "outer", scratch / "home-outer"
        outer.mkdir()
        home.mkdir(mode=0o700)
        (outer / "main.tf").write_bytes((root / STATE_CONFIG).read_bytes())
        outer_env = clean_env(tools, {"CLOUDFLARE_API_TOKEN": token, "TF_VAR_account_id": account,
                                      "TF_VAR_run": run["scope"], "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
                                      "HOME": str(home)})
        created: dict[str, str] | None = {}
        issued: float | None = None
        credentials: dict[str, str] | None = None
        s3: S3 | None = None
        attempted: dict[str, set[str]] = {name: set() for name in names.values()}
        control = False
        try:
            tofu(tools, outer, outer_env, runner, "init", "-input=false", "-no-color")
            result["stage"] = "create"
            # The first bounded create is the only capability probe: no decoy, credential or state before it.
            for decoy, label in (("false", "the first bounded bucket create"), ("true", "the decoy bucket create")):
                applied = True
                try:
                    tofu(tools, outer, outer_env, runner, "apply", "-input=false", "-auto-approve", "-no-color",
                         "-var", f"decoy={decoy}")
                except EnvsError:
                    applied = False
                finally:
                    created = record_created(tools, outer, outer_env, runner, run, created)
                require(applied and created is not None and names["proof"] in created, f"{label} did not succeed")
            require(created is not None and set(created) == set(names.values()), "created bucket set differs")
            result["stage"] = "credential"
            # Recorded before the one POST: after any failure the provider may still have issued a credential.
            result["credential"] = "ATTEMPTED"
            try:
                credentials = temporary_credentials(api, account, token, parent, names["proof"])
            except STATE_FAILURES:
                result["credential"] = "ISSUANCE_UNKNOWN"
                raise
            issued = clock()
            result["credential"] = "ISSUED"
            endpoint, issued_credentials = r2_endpoint(account), credentials

            def s3(method: str, bucket: str, key: str, body: bytes | None = None) -> dict[str, Any]:
                return s3_object(tools, runner, endpoint, issued_credentials, method, bucket, key, body)

            # The credential control: the proof marker written and read back exactly; the post-TTL probe reads it again.
            control = marker_written(s3, names["proof"], attempted)["ok"] and marker_read(s3, names["proof"])
            result["credential_control"] = "USABLE" if control else "UNKNOWN"
            result["stage"] = "proof"
            checks, negatives, evidence = state_checks(root, scratch, tools, account, token, names, credentials,
                                                       runner, spawn, sleep, s3, attempted)
            result["checks"], result["negatives"] = checks, negatives
            result["diagnostics"]["negatives"] = evidence
            if not all(checks.values()) or "ADMITTED" in negatives.values():
                result["status"] = "STATE_BACKEND_RED"
            elif control and set(negatives.values()) == {"REFUSED"}:
                result["status"] = "STATE_BACKEND_PROVEN"
            else:
                result["status"] = "UNKNOWN"
        except EnvsError as exc:
            # The stage says where; the receipt carries only the closed failure kind, never exception text.
            result["error"] = failure_class(exc)
            result["status"] = "STATE_BACKEND_RED"
        except (OSError, subprocess.SubprocessError) as exc:
            # A local launch or storage failure proves nothing about R2: UNKNOWN, named by its closed kind only.
            result["error"] = failure_class(exc)
            result["status"] = "UNKNOWN"
        finally:
            report = state_cleanup(tools, scratch, account, token, run, names, outer, outer_env, created,
                                   result["credential"], control, issued, s3, attempted, runner, api, sleep, clock)
            result["diagnostics"]["credential_probe"] = report.pop("credential_probe")
            result.update(report)
    # Absent negatives or entries are fine for a run that stopped early; a proof needs every negative's evidence and
    # the observed post-TTL 401, all inside the closed sets. A proof without its evidence is not a proof.
    diagnostics = result["diagnostics"]
    finite = diagnostics_finite(diagnostics)
    complete = finite and isinstance(diagnostics["negatives"], dict) and None not in diagnostics["negatives"].values() \
        and diagnostics["credential_probe"]["status"] == "401"
    if not finite:
        # A value outside the closed sets is never emitted.
        result["diagnostics"] = None
    if result["status"] == "STATE_BACKEND_PROVEN" and not complete:
        result["status"] = "UNKNOWN"
    if result["cleanup"] != "ABSENT":
        # Resources or a usable credential may remain: no proof outcome stands as the status.
        result["status"] = result["cleanup"]
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


def _receipt_operation(target: dict[str, Any]) -> str:
    validate_jev_target(target)
    return "cloudflare_workers_secret_put" if target["provider"] == "cloudflare-workers" \
        else "cloudflare_pages_secret_put"


def parse_workers_secret_list(stdout: bytes, expected_name: str | None = None) -> list[dict[str, str]]:
    require(len(stdout) <= RESPONSE_LIMIT, "Workers secret list output too large")
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EnvsError("Workers secret list output is not JSON") from exc
    require(isinstance(value, list) and len(value) <= 10000, "Workers secret list shape differs")
    names: set[str] = set()
    rows: list[dict[str, str]] = []
    for item in value:
        require(isinstance(item, dict) and set(item) == {"name", "type"},
                "Workers secret list entry fields differ")
        name, kind = item["name"], item["type"]
        require(isinstance(name, str) and name and isinstance(kind, str) and kind,
                "Workers secret list entry differs")
        require(name not in names, "Workers secret list contains duplicate names")
        names.add(name)
        rows.append({"name": name, "type": kind})
    if expected_name is not None:
        target = next((row for row in rows if row["name"] == expected_name), None)
        require(target is not None, f"Workers secret list lacks exact {expected_name}")
        require(target["type"] == "secret_text",
                f"Workers secret list exact {expected_name} binding type differs")
    return rows


def _workers_secret_put(*, account_id: str, worker_name: str, secret_name: str,
                        secret: str, token: str, opener=None) -> None:
    # Wrangler 4.93.0 secret put may create a draft Worker on not-found. We deliberately
    # bypass that convenience branch and call the same provider secret endpoint directly.
    # A missing/deleted Worker therefore fails instead of creating infrastructure.
    require(CLOUDFLARE_ACCOUNT_ID.fullmatch(account_id) is not None, "Workers account id invalid")
    require(CLOUDFLARE_WORKER_NAME.fullmatch(worker_name) is not None, "Workers name invalid")
    require(secret_name == "JEV_API_KEY" and isinstance(secret, str) and secret, "Workers secret input invalid")
    open_request = urllib.request.urlopen if opener is None else opener
    url = (CLOUDFLARE_API + "/accounts/" + account_id + "/workers/scripts/"
           + urllib.parse.quote(worker_name, safe="") + "/secrets")
    body = json.dumps(
        {"name": secret_name, "text": secret, "type": "secret_text"},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    try:
        with open_request(request, timeout=RETRIEVAL_TIMEOUT, context=ssl.create_default_context()) as response:
            status = response.status if hasattr(response, "status") else response.getcode()
            require(200 <= status < 300, f"Cloudflare Workers secret put returned HTTP {status}")
            response_body = response.read(RESPONSE_LIMIT + 1)
            require(len(response_body) <= RESPONSE_LIMIT,
                    "Cloudflare Workers secret put response too large")
            try:
                envelope = json.loads(response_body.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise EnvsError("Cloudflare Workers secret put response is not JSON") from exc
            require(isinstance(envelope, dict), "Cloudflare Workers secret put response shape differs")
            require(envelope.get("success") is True, "Cloudflare Workers secret put did not report success")
            result = envelope.get("result")
            require(isinstance(result, dict), "Cloudflare Workers secret put result missing")
            require(result.get("name") == secret_name,
                    "Cloudflare Workers secret put result name differs")
            require(result.get("type") == "secret_text",
                    "Cloudflare Workers secret put result type differs")
    except urllib.error.HTTPError as exc:
        raise EnvsError(f"Cloudflare Workers secret put returned HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise EnvsError("Cloudflare Workers secret put transport failed") from None


def project_github_org_secret(*, target: dict[str, Any], tools: Mapping[str, str],
                              authorization: Mapping[str, str], secret_loader: Callable[[], bytes],
                              runner: Runner | None = None) -> dict[str, Any]:
    """Bound Org materialization primitive; not a grant, binding, CLI route or Jev-use receipt.

    The owning projector supplies its admitted target/toolchain, authorized GH_TOKEN and
    lazy SOPS loader. Native gh seals plaintext on stdin; the only write uses fixed repo IDs,
    not gh's name-based lookup. No Repository/Environment endpoint or automatic retry exists.
    """
    try:
        selected = json.loads(json.dumps(target, allow_nan=False))
        spec = importlib.util.spec_from_file_location("envs_org_target", Path(__file__).with_name("contract_projection.py"))
        require(spec is not None and spec.loader is not None, "Org target validator missing")
        public = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(public)
        public.public_target(selected)
        require(selected["provider"] == "github-org-secret" and selected["secret_name"] == "JEV_API_KEY",
                "Org Jev target differs")
        gh = tools["gh"]
        require(in_store(gh) and os.path.isfile(gh) and os.access(gh, os.X_OK), "fixed gh tool missing")
        require(set(authorization) == {"GH_TOKEN"} and isinstance(authorization["GH_TOKEN"], str)
                and bool(authorization["GH_TOKEN"]), "Org projection authorization missing")
    except (ValueError, TypeError, KeyError):
        raise EnvsError("Org projection input invalid") from None
    org, name = selected["organization"], selected["secret_name"]
    expected = dict(zip(selected["repositories"], selected["repository_ids"], strict=True))

    with tempfile.TemporaryDirectory(prefix="envs-org-gh-") as home:
        child_env = clean_env(tools, {"GH_TOKEN": authorization["GH_TOKEN"], "GH_HOST": "github.com",
                                      "HOME": home, "GH_CONFIG_DIR": home, "GH_PROMPT_DISABLED": "1"})

        def command(args: list[str], stdin: bytes | None = None, limit: int = RESPONSE_LIMIT) -> bytes:
            argv = [gh, *args]
            try:
                result = subprocess.run(argv, input=stdin, env=child_env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, check=False, shell=False, timeout=30) \
                    if runner is None else runner(argv, stdin, child_env)
            except Exception:
                raise EnvsError("Org gh operation unresolved") from None
            require(result.returncode == 0 and len(result.stdout) <= limit, "Org gh operation failed")
            return result.stdout

        def api(route: str) -> Any:
            try:
                return json.loads(command(["api", "-X", "GET", route]).decode("utf-8"))
            except (ValueError, UnicodeError):
                raise EnvsError("Org metadata response invalid") from None

        def identity() -> None:
            observed = api(f"orgs/{org}")
            require(isinstance(observed, dict) and observed.get("type") == "Organization"
                    and observed.get("login") == org and str(observed.get("id")) == selected["organization_id"],
                    "Org identity differs")
            for repository, repository_id in expected.items():
                observed = api(f"repos/{repository}")
                owner = observed.get("owner", {}) if isinstance(observed, dict) else {}
                require(isinstance(observed, dict) and isinstance(owner, dict)
                        and observed.get("full_name") == repository and str(observed.get("id")) == repository_id
                        and owner.get("type") == "Organization" and owner.get("login") == org
                        and str(owner.get("id")) == selected["organization_id"], "Org repository identity differs")

        def public_key() -> dict[str, str]:
            key = api(f"orgs/{org}/actions/secrets/public-key")
            require(isinstance(key, dict) and set(key) == {"key_id", "key"}
                    and isinstance(key["key_id"], str) and bool(key["key_id"])
                    and isinstance(key["key"], str), "Org public key invalid")
            try:
                require(len(base64.b64decode(key["key"], validate=True)) == 32, "Org public key invalid")
            except ValueError:
                raise EnvsError("Org public key invalid") from None
            return key

        # Read-only identity and Org API access preflight, before the owning loader reads plaintext.
        identity()
        key = public_key()
        try:
            secret = secret_loader()
        except Exception:
            raise EnvsError("Org source decryption failed") from None
        require(isinstance(secret, bytes) and 0 < len(secret) <= 48 * 1024, "Org source secret size invalid")
        encrypted = command(["secret", "set", name, "--app", "actions", "--org", org, "--no-store"],
                            secret, 2 * RESPONSE_LIMIT).strip()
        try:
            require(bool(base64.b64decode(encrypted, validate=True)), "Org sealed value invalid")
            encrypted_text = encrypted.decode("ascii")
        except (ValueError, UnicodeError):
            raise EnvsError("Org sealed value invalid") from None
        require(public_key() == key, "Org public key changed before write")
        identity()
        # The native encrypted envelope goes through stdin. Repo IDs remain bound even if a name changes.
        body = json.dumps({"encrypted_value": encrypted_text, "key_id": key["key_id"], "visibility": "selected",
                           "selected_repository_ids": [int(i) for i in selected["repository_ids"]]},
                          separators=(",", ":")).encode("utf-8")
        try:
            command(["api", "-X", "PUT", f"orgs/{org}/actions/secrets/{name}", "--input", "-"], body)
            metadata = api(f"orgs/{org}/actions/secrets/{name}")
            require(isinstance(metadata, dict) and metadata.get("name") == name
                    and metadata.get("visibility") == "selected", "Org secret metadata differs")
            access = api(f"orgs/{org}/actions/secrets/{name}/repositories?per_page=100")
            rows = access.get("repositories") if isinstance(access, dict) else None
            require(isinstance(rows, list) and access.get("total_count") == len(expected) == len(rows),
                    "Org selected repository readback incomplete")
            actual: dict[str, str] = {}
            for row in rows:
                require(isinstance(row, dict) and isinstance(row.get("full_name"), str)
                        and row["full_name"] not in actual, "Org selected repository readback invalid")
                actual[row["full_name"]] = str(row.get("id"))
            require(actual == expected, "Org selected repository readback differs")
            identity()
        except Exception:
            # A failed/unknown write or later readback is not a no-effect record. Never retry automatically.
            raise EnvsError("Org projection write/readback unresolved; do not repeat") from None
        return {"operation": "github_org_secret_put", "target": selected,
                "readback": "SECRET_NAME_AND_SELECTED_REPOSITORY_IDS", "provider_use": "NOT_RUN"}


def validate_receipt(receipt: dict[str, Any], expected_target: dict[str, Any] | None = None) -> None:
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
    target = validate_jev_target(receipt["target"])
    if expected_target is not None:
        require(target == validate_jev_target(expected_target), "receipt target differs")
    require(receipt["projector"] == {
        "workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py",
    }, "projector identity differs")
    require(receipt["effect"] == {"operation": _receipt_operation(target), "status": "PASS"},
            "provider effect is not PASS")
    require(receipt["readback"] == {"kind": "secret_name_presence", "status": "PASS", "present": True},
            "provider readback is not PASS")
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


def build_receipt(*, envs_sha: str, ciphertext_sha256: str, target: dict[str, Any],
                  run_id: int, run_attempt: int, created_at: str) -> dict[str, Any]:
    target = dict(validate_jev_target(target))
    receipt = {
        "kind": RECEIPT_KIND, "status": "PASS", "envs_sha": envs_sha,
        "environment": "dev", "capability": "jev-api",
        "source": {"kind": "public_sops", "ref": CIPHERTEXT.as_posix(), "sha256": "sha256:" + ciphertext_sha256},
        "target": target,
        "projector": {"workflow": ".github/workflows/project-dev-jev-api.yml", "adapter": "adapters/jev_api.py"},
        "effect": {"operation": _receipt_operation(target), "status": "PASS"},
        "readback": {"kind": "secret_name_presence", "status": "PASS", "present": True},
        "workflow": {"repository": "roccho-dev/envs", "ref": "proposals", "run_id": run_id, "run_attempt": run_attempt},
        "created_at": created_at,
    }
    validate_receipt(receipt, target)
    return receipt


def project(*, envs_sha: str, run_id: int, run_attempt: int, created_at: str,
            output: Path, root: Path = ROOT, runner: Runner = default_runner, opener=None) -> dict[str, Any]:
    contracts = validate_contracts(root)
    require(SHA40.fullmatch(envs_sha) is not None, "expected exact envs SHA")
    target = validate_jev_target(contracts["bindings"]["jev-api"]["target"])
    cipher = root / CIPHERTEXT
    require(cipher.is_file(), "ciphertext is not configured")
    tools = toolchain(root)
    inputs = gate(root, contracts, "dev.projection")
    age_key = inputs["SOPS_AGE_KEY"]
    account = inputs["CLOUDFLARE_ACCOUNT_ID"]
    token = inputs["CLOUDFLARE_API_TOKEN"]
    provider_env = clean_env(tools, {"CLOUDFLARE_ACCOUNT_ID": account, "CLOUDFLARE_API_TOKEN": token})
    wrangler = tools["wrangler"]

    # Workers must already exist. This read-only call fails on a missing Worker before
    # decryption or any write. Direct provider PUT below also cannot enter Wrangler's
    # createDraftWorker() fallback, closing the deletion race between preflight and put.
    if target["provider"] == "cloudflare-workers":
        require(account == target["account_id"], "Workers target account differs from projection account")
        preflight = run_checked(
            [wrangler, "secret", "list", "--name", target["worker_name"], "--format", "json"],
            env=provider_env, runner=runner, label="Cloudflare Workers existence preflight",
        )
        parse_workers_secret_list(preflight.stdout)

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

    if target["provider"] == "cloudflare-workers":
        _workers_secret_put(
            account_id=target["account_id"], worker_name=target["worker_name"],
            secret_name=target["secret_name"], secret=secret, token=token, opener=opener,
        )
        readback = run_checked(
            [wrangler, "secret", "list", "--name", target["worker_name"], "--format", "json"],
            env=provider_env, runner=runner, label="Cloudflare Workers secret readback",
        )
        # Wrangler 4.93.0 JSON stdout is the sole presence evidence. stderr may
        # contain diagnostics/warnings but is never interpreted as a positive.
        parse_workers_secret_list(readback.stdout, target["secret_name"])
    else:
        run_checked(
            [wrangler, "pages", "secret", "put", "JEV_API_KEY", "--project-name", target["project"]],
            input_data=secret.encode(), env=provider_env, runner=runner, label="Cloudflare secret projection",
        )
        readback = run_checked(
            [wrangler, "pages", "secret", "list", "--project-name", target["project"]],
            env=provider_env, runner=runner, label="Cloudflare secret readback",
        )
        # Pages stays legacy-compatible in this source slice. It is never a
        # Workers receipt and cannot satisfy #443's Workers handoff.
        require(b"JEV_API_KEY" in readback.stdout + readback.stderr,
                "provider readback did not contain JEV_API_KEY")

    receipt = build_receipt(
        envs_sha=envs_sha, ciphertext_sha256=hashlib.sha256(cipher.read_bytes()).hexdigest(),
        target=target, run_id=run_id, run_attempt=run_attempt, created_at=created_at,
    )
    destination = root / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def load_receipt(path: Path, expected_target: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvsError("handoff receipt is invalid JSON") from exc
    require(isinstance(value, dict), "handoff receipt must be an object")
    validate_receipt(value, expected_target)
    return value


def linode_read_probe(root: Path = ROOT, opener=None) -> dict[str, Any]:
    """Prove authenticated GET access only; credential scope is not narrowed by this probe."""
    contracts = validate_contracts(root)
    token = gate(root, contracts, LINODE_READ_PLANE)["LINODE_API_TOKEN"]
    require(BEARER.fullmatch(token) is not None, "Linode API token format is invalid")
    reject_live_values(root, "LINODE_API_TOKEN", [token])
    open_request = urllib.request.urlopen if opener is None else opener
    checks: dict[str, str] = {}
    context = ssl.create_default_context()
    for name, path in LINODE_READ_ENDPOINTS:
        request = urllib.request.Request(
            LINODE_API + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with open_request(request, timeout=RETRIEVAL_TIMEOUT, context=context) as response:
                status = response.status if hasattr(response, "status") else response.getcode()
                require(status == 200, f"Linode {name} read returned HTTP {status}")
                response.read(1)
        except urllib.error.HTTPError as exc:
            raise EnvsError(f"Linode {name} read returned HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise EnvsError(f"Linode {name} read transport failed") from None
        checks[name] = "PASS"
    return {"kind": "envs.linodeReadProbe.v1", "status": "PASS", "checks": checks}


def readiness(root: Path = ROOT) -> dict[str, Any]:
    contracts = validate_contracts(root)
    cipher, handoff = root / CIPHERTEXT, root / HANDOFF
    configured = cipher.is_file()
    physical, state = ("NOT_RUN", "ABSENT") if configured else ("NOT_CONFIGURED", "ABSENT")
    current = "sha256:" + hashlib.sha256(cipher.read_bytes()).hexdigest() if configured else None
    receipt_digest = None
    if handoff.is_file():
        require(configured, "handoff cannot exist without ciphertext")
        receipt_digest = load_receipt(handoff, contracts["bindings"]["jev-api"]["target"])["source"]["sha256"]
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
    # A dispatch names its one target; there is no default, and an unknown one stops before any input is read.
    author_parser = sub.add_parser("author")
    author_parser.add_argument("--target", required=True, choices=AUTHOR_TARGETS)
    sub.add_parser("rent-tunnel")
    # The root's sensitive credentials output on stdin only, never an argument, environment value or file.
    sub.add_parser("rent-client")
    # Applies the persistent root and seals both envelopes; its inputs come only from the declared environment.
    sub.add_parser("rent-root")
    sub.add_parser("rent-access-probe")
    sub.add_parser("rent-access-locate")
    sub.add_parser("rent-state-proof")
    sub.add_parser("linode-read-probe")
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
            contracts = validate_contracts(root)
            if (root / HANDOFF).is_file():
                load_receipt(root / HANDOFF, contracts["bindings"]["jev-api"]["target"])
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
            result = author(root) if args.target == "jev-api" else author_oci(root)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "rent-tunnel":
            print(json.dumps(rent_author(root), indent=2, sort_keys=True))
        elif args.command == "rent-client":
            print(json.dumps(client_author(sys.stdin.buffer.read(RESPONSE_LIMIT + 1), root), indent=2, sort_keys=True))
        elif args.command == "rent-root":
            # Only a closed kind and stage leave on failure, plus a failed init child's closed unverified hint line:
            # never a message, class name, traceback, child output or value.
            progress: dict[str, str] = {}
            try:
                result = rent_root(root, progress=progress)
            except Exception as exc:
                kind = failure_class(exc) if isinstance(exc, STATE_FAILURES) else "other"
                print(f"RENT_ROOT=RED: {kind} at {progress.get('stage', 'start')}", file=sys.stderr)
                if "init_hint" in progress:
                    print(f"RENT_ROOT_INIT_HINT_UNVERIFIED={progress['init_hint']}", file=sys.stderr)
                return 1
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command in {"rent-access-probe", "rent-access-locate"}:
            result = access_probe(root, locate_only=args.command == "rent-access-locate")
            print(json.dumps(result, indent=2, sort_keys=True))
            passed = result["status"] == "NONE_LOCATED" if args.command == "rent-access-locate" else (
                result["status"] == "TOKEN_REACHED_NEGATIVES_REFUSED" and result.get("cleanup") == "ABSENT")
            return 0 if passed else 1
        elif args.command == "linode-read-probe":
            print(json.dumps(linode_read_probe(root), indent=2, sort_keys=True))
            return 0
        elif args.command == "rent-state-proof":
            # Its failure line names only a closed kind; no exception text, class name or traceback reaches the log.
            try:
                result = state_proof(root)
            except Exception as exc:
                kind = failure_class(exc) if isinstance(exc, STATE_FAILURES) else "other"
                print(f"RENT_STATE_PROOF=RED: {kind}", file=sys.stderr)
                return 1
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "STATE_BACKEND_PROVEN" and result["cleanup"] == "ABSENT" else 1
        else:
            receipt = project(
                envs_sha=args.envs_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                created_at=args.created_at or utc_now(), output=args.output, root=root,
            )
            print(json.dumps({"kind": receipt["kind"], "status": "PASS", "output": str(args.output)}, sort_keys=True))
    except (EnvsError, OSError) as exc:
        label = {"rent-tunnel": "RENT_TUNNEL", "rent-client": "RENT_CLIENT", "rent-access-probe": "RENT_ACCESS_PROBE",
                 "rent-access-locate": "RENT_ACCESS_PROBE", "rent-state-proof": "RENT_STATE_PROOF",
                 "linode-read-probe": "LINODE_READ_PROBE"}.get(args.command, "JEV_API")
        print(f"{label}=RED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
