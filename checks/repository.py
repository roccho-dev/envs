#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    ".github/pull_request_template.md",
    ".github/workflows/check.yml",
    ".github/workflows/author-dev-jev-api.yml",
    ".github/workflows/project-dev-jev-api.yml",
    ".github/workflows/project-dev-rent-tunnel.yml",
    ".github/workflows/probe-dev-rent-access-ssh.yml",
    ".github/workflows/probe-dev-rent-state.yml",
    ".gitignore",
    "LICENSE_POLICY.md",
    "LICENSES/README.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "adapters/jev_api.py",
    "checks/repository.py",
    "checks/test_jev_api.py",
    "checks/test_rent_access_probe.py",
    "checks/test_rent_state_proof.py",
    "checks/test_rent_tunnel.py",
    "checks/test_repository.py",
    "contracts/bindings.jsonl",
    "contracts/environments.jsonl",
    "contracts/provider-consumer.jsonl",
    "contracts/targets.jsonl",
    "flake.lock",
    "flake.nix",
    "providers/dev-rent-access-probe/main.tf",
    "providers/dev-rent-cloudflare/main.tf",
    "providers/dev-rent-state-proof/main.tf",
    "providers/dev-rent-state-proof/backend/main.tf",
}
ALLOWED_ROOTS = {
    ".github",
    "LICENSES",
    "adapters",
    "checks",
    "ciphertexts",
    "contracts",
    "handoffs",
    "providers",
}
ALLOWED_ROOT_FILES = {
    ".gitignore",
    "LICENSE_POLICY.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "flake.lock",
    "flake.nix",
}
FORBIDDEN_ROOTS = {
    "appearance",
    "bindings",
    "cmd",
    "docs",
    "environments",
    "hosts",
    "internal",
    "lib",
    "migration",
    "modules",
    "scripts",
    "tests",
}
FORBIDDEN_FILENAMES = {
    ".env",
    ".mise.toml",
    "go.mod",
    "go.sum",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SUFFIXES = {".go", ".p12", ".pem", ".pfx", ".sh"}
SECRET_PATTERNS = {
    "age private identity": re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
    "private key": re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "AWS access key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "npm token": re.compile(rb"\bnpm_[A-Za-z0-9]{30,}\b"),
    "Google API key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "Slack token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    "Stripe live key": re.compile(rb"\bsk_live_[0-9A-Za-z]{20,}\b"),
    "basic-auth URL": re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@[^\s]+"),
}
ACTION_USE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)")
INPUT_REFERENCE = re.compile(r"\$\{\{\s*(secrets|vars)\.([A-Za-z0-9_]+)\s*\}\}")
EFFECT_WORKFLOWS = {
    "author-dev-jev-api.yml": "dev.authoring",
    "project-dev-jev-api.yml": "dev.projection",
    "project-dev-rent-tunnel.yml": "dev.rent-tunnel",
    "probe-dev-rent-access-ssh.yml": "dev.rent-access-probe",
    "probe-dev-rent-state.yml": "dev.rent-state-proof",
}
PROBE_CONFIG = "providers/dev-rent-access-probe/main.tf"
RENT_CONFIG = "providers/dev-rent-cloudflare/main.tf"
STATE_CONFIG = "providers/dev-rent-state-proof/main.tf"
STATE_BACKEND = "providers/dev-rent-state-proof/backend/main.tf"
# check initializes and validates both state-proof roots from the built closure with every network route closed, proves
# the Wrangler raw-read argv shape, and runs the state-proof self-test on the closure interpreter.
STATE_TOOL_CHECKS = (
    'HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$tool/tofu" -chdir="$state" init -input=false -no-color',
    '"$tool/tofu" -chdir="$state" validate -no-color',
    'HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$tool/tofu" -chdir="$state/backend" init -backend=false'
    ' -input=false -no-color',
    '"$tool/tofu" -chdir="$state/backend" validate -no-color',
    'grep -qF -- --pipe "$RUNNER_TEMP/r2-object-get.help"',
    'grep -qF -- --remote "$RUNNER_TEMP/r2-object-get.help"',
    'grep -qF -- --pipe "$RUNNER_TEMP/r2-object-put.help"',
    '"$tool/curl" --version',
    '"$tool/python3" -I checks/test_rent_state_proof.py --real-tofu "$tool/tofu" --real-s3 "$tool/curl"',
)
# check proves the probe tools from the built closure: exact client version, its token flags, and an OpenTofu
# init/validate of the provider declaration with every network route closed.
PROBE_TOOL_CHECKS = (
    '"$tool/cloudflared" --version | tee "$RUNNER_TEMP/cloudflared.version"',
    'grep -qF "cloudflared version 2026.6.1 " "$RUNNER_TEMP/cloudflared.version"',
    'grep -qF -- --service-token-id "$RUNNER_TEMP/access-ssh.help"',
    'HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$tool/tofu" -chdir="$probe" init -input=false -no-color',
    '"$tool/tofu" -chdir="$probe" validate -no-color',
    'cp providers/dev-rent-cloudflare/main.tf "$rent/"',
    'HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 "$tool/tofu" -chdir="$rent" init -backend=false -input=false'
    ' -no-color',
    '"$tool/tofu" -chdir="$rent" validate -no-color',
    '"$tool/python3" -I checks/test_rent_access_probe.py --real-ssh "$tool"',
)
CIPHERTEXTS = {
    "ciphertexts/dev-jev-api.sops.yaml", "ciphertexts/dev-rent-tunnel.sops.yaml", "ciphertexts/dev-jev-api.oci-dev.sops.yaml",
}
# The real SOPS roundtrip runs the locked sops with a check-only age that never enters the effect toolchain.
CHECK_AGE_BUILD = 'nix build .#check-age --no-update-lock-file --out-link "$RUNNER_TEMP/check-age"'
REAL_ROUNDTRIP = ('"$tool/python3" -I checks/test_rent_tunnel.py --sops "$tool/sops"'
                  ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen"')
OCI_ROUNDTRIP = ('"$tool/python3" -I checks/test_jev_api.py --sops "$tool/sops"'
                 ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen"')
# The author dispatch names one declared binding; each has exactly one literal step carrying only its own inputs.
AUTHOR_STEP = re.compile(r"(?ms)^      - name: [^\n]+\n        if: inputs\.target == '([a-z.-]+)'\n(.*?)(?=^      - name: |\Z)")
EFFECT_PACKAGES = "packages = with pkgs; [ python3 sops wrangler git gh openssh curl ] ++ [ cloudflared opentofu ];"
PROBE_PINS = (
    'cloudflared = assert pkgs.cloudflared.version == "2026.6.1"; pkgs.cloudflared;',
    "opentofu = pkgs.opentofu.withPlugins (p: [ p.cloudflare_cloudflare ]);",
)
TOOLCHAIN_BUILD = 'nix build .#effect-toolchain --no-update-lock-file'
ARTIFACT_BUILD = 'nix build .#effect-artifact --no-update-lock-file'
SOURCE_SHA = "${{ github.event.pull_request.head.sha || github.sha }}"
ARTIFACT_NAME = "name: envs-effect-${{ env.ENVS_SOURCE_SHA }}"
# The consumer binds the named commit to the producing run and to the artifact's own SOURCE.
CONSUMER_BINDING = (
    '.head_sha == $sha',
    '.repository.full_name == $repo and .head_repository.full_name == $repo',
    '((.id | tostring) == $current or (.event == "push" and .conclusion == "success"))',
    'test "$(tar -xOf "$art/content/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"',
)
EFFECT_ENV = re.compile(r"(?m)^ {10}([A-Za-z_][A-Za-z0-9_-]*):")
EFFECT_STEP_KEYS = {"ref", "fetch-depth", "persist-credentials", "GH_TOKEN", "ENVS_SOURCE_SHA"}
TOOLCHAIN_BIN = '"$RUNNER_TEMP/envs-effect/bin/'
# The one step that obtains the provided artifact; check's clean-start job holds the canonical text.
CONSUMER_STEP = "- name: Obtain provided effect artifact\n"
CONSUMER_RUN = "        run: |\n"
EFFECT_ENTRY = '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE"'
# After the consumer step, effect jobs run only store paths from the provided artifact.
AMBIENT_TOOL = re.compile(r"(?m)(?:^|[\s>|;&(])(?:python3?|git|gh|sops|wrangler|node|npx|npm|pip3?|curl|wget)\s")
RUNTIME_ACQUISITION = ("npx", "npm ", "pip ", "--yes", "nix ", "install-nix", "github:", "--impure")
TOOLCHAIN_IDENTITY = f"{EFFECT_ENTRY} toolchain"
EFFECT_ACTIONS = {"actions/checkout"}
RUN_START = re.compile(r"^(\s*)run:\s*(.*)$")
# Every other effect-step command is a provided store path or a fixed assignment.
ALLOWED_COMMAND = re.compile(
    r'^(?:set -euo pipefail'
    r'|tool="\$ENVS_EFFECT_BIN"'
    r'|branch="[a-z/-]+(?:\$\{GITHUB_RUN_(?:ID|ATTEMPT)\}-?)+"'
    r'|"\$(?:ENVS_EFFECT_BIN|tool)/[a-z0-9-]+"(?: .*)?)$'
)
COMMAND_CONTROL = re.compile(r"[;&|<>`\n]|\$\(")
STATE_DISPATCH_INPUT = ("on:\n  workflow_dispatch:\n    inputs:\n      expected_source_sha:\n"
                        "        description: The exact canonical commit authorized for this one attempt\n"
                        "        required: true\n        type: string\n")
STATE_JOB_GUARD = ("    if: github.repository == 'roccho-dev/envs' && github.ref_name == 'proposals'"
                   " && github.sha == inputs.expected_source_sha && github.run_attempt == '1'\n")
FLAKE_NIXPKGS = re.compile(r'(?m)^\s*inputs\.nixpkgs\.url = "github:NixOS/nixpkgs/([0-9a-f]{40})";$')


class RepositoryError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepositoryError(message)


def files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )


def relative_files(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in files(root)}


def load_adapter(root: Path):
    path = root / "adapters/jev_api.py"
    spec = importlib.util.spec_from_file_location("envs_jev_api", path)
    require(spec is not None and spec.loader is not None, "cannot load Jev adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_shape(root: Path) -> None:
    actual = relative_files(root)
    missing = sorted(REQUIRED_FILES - actual)
    require(not missing, f"required files missing: {missing}")

    for path in root.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            require(path.name in ALLOWED_ROOTS, f"top-level directory is not allowed: {path.name}")
        else:
            require(path.name in ALLOWED_ROOT_FILES, f"top-level file is not allowed: {path.name}")

    for name in FORBIDDEN_ROOTS:
        require(not (root / name).exists(), f"temporary or foreign root survives: {name}")

    for path in files(root):
        relative = path.relative_to(root)
        require(path.name not in FORBIDDEN_FILENAMES, f"forbidden file: {relative}")
        require(path.suffix.lower() not in FORBIDDEN_SUFFIXES, f"forbidden implementation type: {relative}")
        require("duck" + "db" not in relative.as_posix().lower(), f"database binding path survives: {relative}")

    ciphertext_dir = root / "ciphertexts"
    if ciphertext_dir.exists():
        ciphertexts = sorted(path.relative_to(root).as_posix() for path in ciphertext_dir.rglob("*") if path.is_file())
        require(bool(ciphertexts) and set(ciphertexts) <= CIPHERTEXTS, f"unexpected ciphertexts: {ciphertexts}")

    providers = sorted(path.relative_to(root).as_posix() for path in (root / "providers").rglob("*") if path.is_file())
    require(providers == sorted([PROBE_CONFIG, RENT_CONFIG, STATE_CONFIG, STATE_BACKEND]),
            f"unexpected provider files (state or lock files are never committed): {providers}")
    check_probe_config((root / PROBE_CONFIG).read_text(encoding="utf-8"))
    check_rent_config((root / RENT_CONFIG).read_text(encoding="utf-8"))
    check_state_config((root / STATE_CONFIG).read_text(encoding="utf-8"), (root / STATE_BACKEND).read_text(encoding="utf-8"))

    handoff_dir = root / "handoffs"
    if handoff_dir.exists():
        handoffs = sorted(path.relative_to(root).as_posix() for path in handoff_dir.rglob("*") if path.is_file())
        require(handoffs == ["handoffs/dev-jev-api.json"], f"unexpected handoffs: {handoffs}")


def check_probe_config(text: str) -> None:
    # Standard provider at the locked version; local ephemeral state only; every managed resource exists only when
    # create = true, so the default lookup run declares nothing it could create or delete.
    require('source  = "cloudflare/cloudflare"' in text and 'version = "5.21.1"' in text,
            "probe must pin the standard Cloudflare provider")
    for token in ("backend", "cloud {", "import {", "removed {", "moved {", "provisioner", "local-exec"):
        require(token not in text, f"probe declaration must not use {token.strip(' {')}")
    resources = re.findall(r'(?m)^resource "([a-z_]+)" "probe" \{\n  count\s+= local\.count\n', text)
    require(len(resources) == text.count('\nresource "') and len(resources) == 6,
            "every probe resource must be gated by create")
    require(re.search(r'(?m)^data "cloudflare_zero_trust_tunnel_cloudflared_token" "probe" \{\n  count\s+= local\.count\n', text)
            is not None, "the tunnel token read must be gated by create")
    require('decision   = "non_identity"' in text and "service_token = { token_id = cloudflare_zero_trust_access_service_token.probe[0].id }" in text
            and "any_valid_service_token" not in text and '"bypass"' not in text and '"allow"' not in text,
            "the Access policy must be Service Auth for exactly the probe token")
    require('name     = "windows-rent-access-probe"' in text and 'hostname = "rent-access-probe.roccho.com"' in text,
            "probe names differ")
    require(re.search(r'(?ms)^output "credentials" \{\n  sensitive = true\n', text) is not None,
            "probe credentials must be a sensitive output")


def check_rent_config(source: str) -> None:
    # Only what native validate accepts and must not: a plaintext local backend, unenforced encryption, a credentials
    # output printed in clear, and a service-token lifetime fixed in source rather than bound at deployment. Comments
    # never count: /* */ blocks and #, // line comments are dropped first (this root has no # or // inside a string).
    text = re.sub(r"(?m)[ \t]*(#|//).*$", "", re.sub(r"(?s)/\*.*?\*/", "", source))
    require(text.count('backend "') == 1 and '  backend "s3" {\n' in text and "    use_lockfile                = true\n" in text,
            "persistent root must use the locked native S3 backend")
    require("  encryption {\n    state {\n      enforced = true\n    }\n    plan {\n      enforced = true\n    }\n  }\n" in text,
            "persistent root must enforce state and plan encryption")
    require(re.search(r'(?ms)^output "credentials" \{\n  sensitive = true\n', text) is not None,
            "persistent root credentials must be a sensitive output")
    # Every remaining duration assignment line (horizontal whitespace only).
    durations = [value.strip() for value in re.findall(r"(?m)^[ \t]*duration[ \t]*=[ \t]*(.*)$", text)]
    require('variable "service_token_duration" {\n  type = string\n}\n' in text
            and durations == ["var.service_token_duration"],
            "the service-token duration must be a required input with no default")


def check_state_config(buckets: str, backend: str) -> None:
    # Buckets: the standard provider at the locked version, local ephemeral state, exactly the proof bucket and a
    # count-gated decoy, both named from the run; no existing or reserved bucket, adoption or other resource.
    require('source  = "cloudflare/cloudflare"' in buckets and 'version = "5.21.1"' in buckets,
            "state buckets must pin the standard Cloudflare provider")
    for token in ("backend", "cloud {", "import {", "removed {", "moved {", "provisioner", "local-exec", "data \""):
        require(token not in buckets, f"state buckets must not use {token.strip(' {')}")
    resources = re.findall(r'(?m)^resource "([a-z0-9_]+)" "([a-z]+)" \{$', buckets)
    require(resources == [("cloudflare_r2_bucket", "proof"), ("cloudflare_r2_bucket", "decoy")]
            and buckets.count("\nresource \"") == 2, "state buckets must be exactly proof and decoy")
    require('  name = "windows-rent-state-proof-${var.run}"\n' in buckets and '  count      = var.decoy ? 1 : 0\n' in buckets
            and '  name       = "${local.name}-decoy"\n' in buckets and '  name       = local.name\n' in buckets,
            "state bucket names must derive from the run and the decoy must be gated")
    require('"windows-rent-state"' not in buckets, "the reserved production state bucket is never declared")
    # Backend: native S3 lock file on R2 and enforced native encryption; no credential, provider or server-side flag.
    for marker in ('  backend "s3" {\n', "    bucket                      = var.bucket\n",
                   "    key                         = var.key\n", "    use_lockfile                = true\n",
                   '    endpoints                   = { s3 = "https://${var.account_id}.r2.cloudflarestorage.com" }\n',
                   "    state {\n      enforced = true\n    }\n", "    plan {\n      enforced = true\n    }\n"):
        require(marker in backend, f"state backend differs: {marker.strip()}")
    for token in ("access_key", "secret_key", "token", "encrypt ", "encrypt=", "required_providers", "passphrase",
                  "cloudflare_", "dynamodb", "profile", "shared_"):
        require(token not in backend, f"state backend must not carry {token.strip()}")
    backend_resources = re.findall(r'(?m)^resource "([a-z_]+)" "([a-z]+)" \{$', backend)
    require(backend_resources == [("terraform_data", "canary"), ("terraform_data", "hold")],
            "state backend resources must be the built-in canary and lock holder only")
    require("    interpreter = [var.python, \"-I\", \"-c\"]\n" in backend and backend.count("local-exec") == 1,
            "the lock holder must run only the closure interpreter")


def check_text(root: Path) -> None:
    database_name = "duck" + "db"
    for path in files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        for label, pattern in SECRET_PATTERNS.items():
            require(not pattern.search(data), f"{relative}: {label}")
        if relative not in {"checks/repository.py", "checks/test_repository.py"}:
            require(database_name not in data.decode("utf-8", errors="ignore").lower(), f"{relative}: removed database binding survives")

    active_roots = [root / name for name in (".github", "adapters", "checks")]
    for base in active_roots:
        for path in files(base) if base.exists() else []:
            relative = path.relative_to(root).as_posix()
            if relative == "checks/repository.py":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            historical = "roccho-dev/" + "envs-old"
            require(historical not in text, f"{relative}: historical runtime dependency")


def check_jsonl(root: Path) -> None:
    for path in sorted((root / "contracts").glob("*.jsonl")):
        ids: set[str] = set()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RepositoryError(f"{path.relative_to(root)}:{number}: invalid JSON") from exc
            require(isinstance(row, dict), f"{path.relative_to(root)}:{number}: row is not an object")
            identity = row.get("id")
            require(isinstance(identity, str) and identity, f"{path.relative_to(root)}:{number}: missing id")
            require(identity not in ids, f"{path.relative_to(root)}:{number}: duplicate id {identity}")
            ids.add(identity)


def declared_inputs(row: dict[str, Any]) -> set[tuple[str, str]]:
    return {("secrets", item["name"]) for item in row.get("required_secrets", [])} | {
        ("vars", item["name"]) for item in row.get("required_variables", [])
    }


def author_target_inputs(adapter, contracts: dict[str, dict[str, dict[str, Any]]]) -> dict[str, set[tuple[str, str]]]:
    # Each author target's Environment inputs as the adapter reads them, in (namespace, name) form.
    secrets = {item["name"] for item in contracts["environments"]["dev.authoring"]["required_secrets"]}
    return {
        target: {("secrets" if item["name"] in secrets else "vars", item["name"])
                 for item in adapter.authoring_inputs(contracts, target)}
        for target in adapter.AUTHOR_TARGETS
    }


def run_commands(text: str) -> list[str]:
    lines = text.splitlines()
    commands: list[str] = []
    index = 0
    while index < len(lines):
        match = RUN_START.match(lines[index])
        index += 1
        if match is None:
            continue
        indent, inline = len(match.group(1)), match.group(2).strip()
        if inline not in {"|", ">-"}:
            quoted = len(inline) > 1 and inline[0] == inline[-1] == "'"
            commands.append(inline[1:-1] if quoted else inline)
            continue
        block: list[str] = []
        while index < len(lines) and (not lines[index].strip() or len(lines[index]) - len(lines[index].lstrip()) > indent):
            if lines[index].strip():
                block.append(lines[index].strip())
            index += 1
        if inline == ">-":
            commands.append(" ".join(block))
            continue
        current = ""
        for line in block:
            current = f"{current} {line}" if current else line
            if current.endswith("\\"):
                current = current[:-1].rstrip()
                continue
            commands.append(current)
            current = ""
        if current:
            commands.append(current)
    return commands


def consumer_run(text: str, name: str) -> str:
    start = text.find(CONSUMER_STEP)
    require(start != -1, f"{name}: provided artifact is not obtained")
    body = text.find(CONSUMER_RUN, start)
    require(body != -1 and "- name:" not in text[start + len(CONSUMER_STEP):body], f"{name}: consumer step differs")
    end = text.find("\n\n", body)
    return text[body:] if end == -1 else text[body:end + 1]


def check_author_targets(text: str, targets: dict[str, set[tuple[str, str]]]) -> None:
    options = "".join(f"          - {target}\n" for target in targets)
    require("    inputs:\n      target:\n" in text
            and "        required: true\n        type: choice\n        options:\n" + options in text,
            "author target choice differs from the authorable bindings")
    steps = AUTHOR_STEP.findall(text)
    require([target for target, _ in steps] == list(targets), "author must have exactly one step per binding")
    for target, body in steps:
        require(f"        run: '{EFFECT_ENTRY} author --target {target}'\n" in body and body.count(" author ") == 1,
                f"author step for {target} must run exactly its literal target")
        require(set(INPUT_REFERENCE.findall(body)) == targets[target], f"author step for {target} maps other inputs")
    require(text.count(" author --target ") == len(targets) and text.count("inputs.target") == len(targets),
            "author target is selected or called outside its step")


def check_workflows(root: Path, environments: dict[str, dict[str, Any]],
                    author_targets: dict[str, set[tuple[str, str]]], adapter) -> None:
    workflow_root = root / ".github/workflows"
    names = {path.name for path in workflow_root.iterdir() if path.is_file()}
    require(
        names == {"check.yml", *EFFECT_WORKFLOWS},
        f"workflow set differs: {sorted(names)}",
    )
    texts = {path.name: path.read_text(encoding="utf-8") for path in workflow_root.iterdir() if path.is_file()}

    for name, text in texts.items():
        require("pull_request_target:" not in text, f"{name}: pull_request_target is forbidden")
        require("secrets: inherit" not in text, f"{name}: secrets inheritance is forbidden")
        require("environment: ${{" not in text, f"{name}: dynamic Environment is forbidden")
        for action, ref in ACTION_USE.findall(text):
            if not action.startswith(("./", "docker://")):
                require(re.fullmatch(r"[0-9a-f]{40}", ref) is not None, f"{name}: mutable Action {action}@{ref}")

    check = texts["check.yml"]
    require("pull_request:" in check and "proposals" in check, "check workflow must validate proposals PRs")
    require("${{ secrets." not in check, "check workflow must be secret-free")
    require("checks/repository.py" in check, "check workflow must execute repository oracle")
    require("checks/test_repository.py" in check, "check workflow must test repository oracle")
    require("checks/test_jev_api.py" in check, "check workflow must test Jev adapter")
    require("run: python3 checks/test_rent_tunnel.py\n" in check, "check workflow must test the rent tunnel adapter")
    require("run: python3 checks/test_rent_access_probe.py\n" in check, "check workflow must test the access probe adapter")
    require("run: python3 checks/test_rent_state_proof.py\n" in check, "check workflow must test the state proof adapter")
    require(TOOLCHAIN_BUILD in check, "check workflow must reconstruct the effect toolchain")
    require(f'{TOOLCHAIN_BIN}envs-effect" toolchain' in check, "check workflow must execute the effect entry")
    require(f'{TOOLCHAIN_BIN}python3" -I checks/test_jev_api.py' in check,
            "check workflow must test the adapter on the toolchain interpreter")
    require('nix flake lock "$relock"' in check and 'cmp flake.lock "$relock/flake.lock"' in check,
            "check workflow must prove Nix regenerates the committed lock")
    for tool in ("python3", "sops", "git", "gh", "wrangler"):
        require(f'"$tool/{tool}" --version' in check, f"check workflow must execute closure {tool}")
    require('"$tool/wrangler" pages secret "$command" --help' in check,
            "check workflow must execute the Wrangler argv shape")
    require(ARTIFACT_BUILD in check and ARTIFACT_NAME in check and "actions/upload-artifact@" in check,
            "check workflow must provide the effect artifact")
    require("cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in check,
            "check must not cancel the proposals run that provides an artifact")

    def job(name: str, following: str | None) -> str:
        start = check.find(f"\n  {name}:\n")
        require(start != -1, f"check workflow job missing: {name}")
        end = check.find(f"\n  {following}:\n", start) if following else -1
        return check[start:] if end == -1 else check[start:end]

    toolchain = job("toolchain", "effect-shape")
    for marker in (
        f"      ENVS_SOURCE_SHA: {SOURCE_SHA}\n",
        f"          ref: {SOURCE_SHA}\n",
        'test "$(git rev-parse HEAD)" = "$ENVS_SOURCE_SHA"',
        'test "$(tar -xOf "$RUNNER_TEMP/provide/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"',
    ):
        require(marker in toolchain, f"artifact must be built from and bound to the named commit: {marker.strip()}")
    for marker in (
        CHECK_AGE_BUILD,
        REAL_ROUNDTRIP,
        OCI_ROUNDTRIP,
        'grep -qxF "$sops" "$RUNNER_TEMP/provided.list"',
        'grep -qxF "$curl" "$RUNNER_TEMP/provided.list"',
        'if grep -qxF "$age" "$RUNNER_TEMP/provided.list"; then',
    ):
        require(marker in toolchain, f"check must run the real SOPS roundtrip with check-only age: {marker}")
    for marker in PROBE_TOOL_CHECKS:
        require(marker in toolchain, f"check must prove the probe tools from the closure: {marker}")
    for marker in STATE_TOOL_CHECKS:
        require(marker in toolchain, f"check must prove the state proof roots from the closure: {marker}")
    require(toolchain.find(REAL_ROUNDTRIP) < toolchain.find('if grep -qxF "$age"') and toolchain.find(ARTIFACT_BUILD)
            < toolchain.find('if grep -qxF "$age"'), "check-only age must be proven outside the built artifact")
    require(toolchain.find(CHECK_AGE_BUILD) < toolchain.find(OCI_ROUNDTRIP) < toolchain.find('if grep -qxF "$age"'),
            "the OCI dev roundtrip must use the check-only age built before it")
    effect_shape = job("effect-shape", "clean-start")
    clean_start = job("clean-start", None)
    require("    needs: toolchain\n" in clean_start, "check workflow must clean-start from the provided artifact")
    for token in ("actions/checkout", "nix ", "install-nix"):
        require(token not in clean_start, f"clean-start must not use {token.strip()}")
    canonical = consumer_run(clean_start, "check.yml clean-start")
    require(clean_start.count(canonical) == 2, "clean-start must run the canonical consumer and its missing case")
    for marker in CONSUMER_BINDING:
        require(marker in canonical, f"consumer must bind the named commit: {marker}")
    program = next(line.strip() for line in canonical.splitlines() if line.strip().startswith("'.path =="))
    source_check = CONSUMER_BINDING[-1]
    require(clean_start.count(program) == 3 and clean_start.count(source_check) == 3,
            "clean-start must run the canonical producer and SOURCE checks against mismatches")
    for marker in (
        'test "$MISSING" = failure',
        'if echo "${ENVS_EFFECT_DIGEST#sha256:}  $altered" | sha256sum -c -; then',
        "for case in lock adapter; do",
        '"$ENVS_EFFECT_BIN/envs-effect" --root "$copy" toolchain',
        "for change in . \\\n",
        "'.head_sha = \"0000000000000000000000000000000000000000\"'",
        "'.id = 1 | .event = \"pull_request\"'",
        "'.repository.full_name = \"fork/envs\"'",
        "'.head_repository.full_name = \"fork/envs\"'",
        'test "$accepted" = "$expected"',
        "artifact built from another commit was accepted",
    ):
        require(marker in clean_start, f"clean-start destructive case missing: {marker}")

    require(consumer_run(effect_shape, "check.yml effect-shape") == canonical, "effect-shape must run the canonical consumer")
    for token in ("nix ", "install-nix"):
        require(token not in effect_shape, f"effect-shape must not use {token.strip()}")
    for marker in (
        f"          ref: {SOURCE_SHA}\n",
        'test "$("$ENVS_EFFECT_BIN/git" -C "$GITHUB_WORKSPACE" rev-parse HEAD)" = "$ENVS_SOURCE_SHA"',
        f"{TOOLCHAIN_IDENTITY} | tee",
        ".status == \"PASS\" and .source == $sha and .root == $root",
        f"{EFFECT_ENTRY} check",
    ):
        require(marker in effect_shape, f"effect-shape must run the effect data-root shape: {marker.strip()}")

    for name, plane in EFFECT_WORKFLOWS.items():
        text = texts[name]
        row = environments[plane]
        for token in RUNTIME_ACQUISITION:
            require(token not in text, f"{name}: runtime acquisition or rebuild {token.strip()}")
        require(consumer_run(text, name) == canonical, f"{name}: consumer differs from the clean-start consumer")
        require("          ENVS_SOURCE_SHA: ${{ github.sha }}\n" in text, f"{name}: artifact must resolve by the dispatched SHA")
        rest = text.replace(canonical, "")
        require(AMBIENT_TOOL.search(rest) is None, f"{name}: ambient tool on the effect path")
        require(re.search(r"(?m)^ {0,4}env:", text) is None, f"{name}: workflow or job env is forbidden")
        # The author Environment also carries each binding's declared inputs; its steps prove which one reads which.
        declared = set().union(*author_targets.values()) if name == "author-dev-jev-api.yml" else declared_inputs(row)
        keys = set(EFFECT_ENV.findall(rest))
        allowed = EFFECT_STEP_KEYS | {input_name for _, input_name in declared}
        require(keys <= allowed, f"{name}: step env or input not allowed: {sorted(keys - allowed)}")
        require("GITHUB_ENV" not in rest and "GITHUB_PATH" not in rest, f"{name}: only the consumer may set step environment")
        consume = text.find(CONSUMER_STEP)
        identity = text.find(TOOLCHAIN_IDENTITY)
        require(-1 < consume < identity < text.find("${{ secrets."),
                f"{name}: artifact must be obtained and its identity recorded before secrets")
        require("shell:" not in text, f"{name}: custom step shell is forbidden")
        require({action for action, _ in ACTION_USE.findall(text)} == EFFECT_ACTIONS, f"{name}: effect Action set differs")
        for command in run_commands(rest):
            require(COMMAND_CONTROL.search(command) is None, f"{name}: command chaining or substitution: {command}")
            require(ALLOWED_COMMAND.fullmatch(command) is not None, f"{name}: non-closure executable: {command}")
        require("workflow_dispatch:" in text, f"{name}: manual dispatch missing")
        require("\n  push:" not in text and "\n  pull_request:" not in text, f"{name}: automatic effect trigger")
        require(f"environment: {row['github_environment']}" in text, f"{name}: static Environment differs")
        require("github.repository == 'roccho-dev/envs'" in text, f"{name}: repository guard missing")
        require("github.ref_name == 'proposals'" in text, f"{name}: canonical ref guard missing")
        require("ref: ${{ github.sha }}" in text, f"{name}: exact checkout missing")
        require("main" not in text, f"{name}: main must not be an effect source")
        require(set(INPUT_REFERENCE.findall(text)) == declared, f"{name}: Environment inputs differ from contract")
        for namespace, input_name in sorted(declared):
            mapping = "^\\s+" + re.escape(f"{input_name}: ${{{{ {namespace}.{input_name} }}}}") + "$"
            require(re.search(mapping, text, re.MULTILINE) is not None, f"{name}: {input_name} mapping differs")

    require(f"{EFFECT_ENTRY} author" in texts["author-dev-jev-api.yml"], "author workflow entry call missing")
    check_author_targets(texts["author-dev-jev-api.yml"], author_targets)
    require(f"{EFFECT_ENTRY} project" in texts["project-dev-jev-api.yml"], "project workflow entry call missing")
    rent = texts["project-dev-rent-tunnel.yml"]
    require(f"run: '{EFFECT_ENTRY} rent-tunnel'" in rent, "rent tunnel workflow entry call missing")
    require('"$tool/git" add ciphertexts/dev-rent-tunnel.sops.yaml contracts/environments.jsonl\n' in rent,
            "rent tunnel handoff must stage only its ciphertext and plane state")
    probe = texts["probe-dev-rent-access-ssh.yml"]
    require(f"run: '{EFFECT_ENTRY} rent-access-probe'" in probe, "access probe workflow entry call missing")
    require("permissions:\n  actions: read\n  contents: read\n" in probe and "write" not in probe,
            "access probe workflow must be read-only on the repository")
    require("rent-access-locate" not in probe, "live name lookup dispatch needs its own contract")
    state = texts["probe-dev-rent-state.yml"]
    require(f"run: '{EFFECT_ENTRY} rent-state-proof'" in state and state.count(" rent-state-proof'") == 1,
            "state proof workflow entry call missing")
    require("permissions:\n  actions: read\n  contents: read\n" in state and "write" not in state,
            "state proof workflow must be read-only on the repository")
    # The provider job enters only for the one authorized commit and first attempt; the SHA is a required input.
    require(STATE_DISPATCH_INPUT in state and state.count("expected_source_sha") == 2,
            "state proof dispatch must require the exact expected source SHA")
    require(state.count(STATE_JOB_GUARD) == 1 and state.count("    if: ") == 1,
            "state proof job must enter only for the expected SHA on its first attempt")
    require(f"    timeout-minutes: {adapter.STATE_JOB_MINUTES}\n" in state and state.count("timeout-minutes:") == 1,
            "state proof job bound differs from the adapter's expiry window")
    # One Environment, two meanings kept apart: neither workflow maps the other's secret.
    require("CLOUDFLARE_API_TOKEN" not in state and "R2_PARENT_" not in probe,
            "the access probe and state proof secrets must stay distinct")


def check_toolchain(root: Path, adapter) -> None:
    flake = (root / "flake.nix").read_text(encoding="utf-8")
    pinned = FLAKE_NIXPKGS.findall(flake)
    require(len(pinned) == 1 and "inputs." not in FLAKE_NIXPKGS.sub("", flake), "flake must have exactly one pinned nixpkgs input")
    require(adapter.locked_nixpkgs(root)["rev"] == pinned[0], "flake.lock differs from flake.nix")
    for tool in adapter.TOOLCHAIN_TOOLS:
        require(re.search(rf'(?m)^        {tool} = "\$\{{(pkgs\.[a-z0-9]+|cloudflared|opentofu)\}}/bin/[a-z0-9-]+";$', flake)
                is not None, f"flake does not provide {tool}")
    for pin in PROBE_PINS:
        require(pin in flake, f"flake must pin the probe tool: {pin}")
    require(flake.count("packages = with pkgs; [") == 1 and EFFECT_PACKAGES in flake,
            "effect toolchain packages differ; check-only age must stay outside them")
    require(flake.count("pkgs.age") == 1 and "        check-age = pkgs.age;\n" in flake, "check-age must be a separate check-only output")
    require("export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" in flake,
            "the entry must carry its own CA bundle for provider retrieval")
    require('exec ${tools.python3} -I ${self}/adapters/jev_api.py "$@"' in flake, "flake entry must run only the adapter")
    require("closureInfo { rootPaths = [ effect-toolchain ]; }" in flake and "echo ${effect-toolchain}/bin/envs-effect > ENTRY" in flake,
            "flake artifact must carry the whole entry closure and its ENTRY")
    require('rev = self.rev or (throw "' in flake and "echo ${rev} > SOURCE" in flake and "ENTRY SOURCE $(cat" in flake
            and "source = rev;" in flake, "flake artifact must record the exact committed source it was built from")
    source = (root / "adapters/jev_api.py").read_text(encoding="utf-8")
    for token in ("npx", "--yes", "SOPS_BIN", "NPX_BIN", "WRANGLER_PACKAGE"):
        require(token not in source, f"adapter selects an ambient or runtime tool: {token}")


def check_readme(root: Path, environments: dict[str, dict[str, Any]]) -> None:
    text = (root / "README.md").read_text(encoding="utf-8")
    for row in environments.values():
        for _, input_name in sorted(declared_inputs(row)):
            marker = f"{row['github_environment']}/{input_name}"
            require(marker in text, f"README missing {marker}")
    for marker in (
        "canonical branch: `proposals`",
        "retained compatibility branch: `main`",
        "contracts/",
        "adapters/jev_api.py",
        "handoffs/dev-jev-api.json",
        "ciphertexts/dev-rent-tunnel.sops.yaml",
        "checks/test_rent_tunnel.py",
        PROBE_CONFIG,
        RENT_CONFIG,
        "declaration only: no workflow plans or applies it",
        "checks/test_rent_access_probe.py",
        "name lookup locates candidates and never proves ownership",
        STATE_CONFIG,
        STATE_BACKEND,
        "checks/test_rent_state_proof.py",
        "a bucket name alone never authorizes deletion",
        "dev-authoring/OCI_DEV_AGE_RECIPIENT",
        "ciphertexts/dev-jev-api.oci-dev.sops.yaml",
        "`author --target jev-api.oci-dev`",
    ):
        require(marker in text, f"README missing {marker}")
    require("delete `main`" not in text.lower(), "README proposes deleting main")


def check_main_compatibility_refresh(root: Path) -> None:
    fetch = subprocess.run(
        ["git", "fetch", "--no-tags", "origin", "proposals"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(fetch.returncode == 0, "cannot fetch canonical proposals")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
    )
    canonical = subprocess.run(
        ["git", "rev-parse", "FETCH_HEAD"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True
    )
    require(head.returncode == 0 and canonical.returncode == 0, "cannot resolve branch revisions")
    require(head.stdout.strip() == canonical.stdout.strip(), "main compatibility refresh does not equal canonical proposals")


def inspect(root: Path = ROOT, *, verify_main_compatibility_refresh: bool = False) -> dict[str, Any]:
    check_shape(root)
    check_text(root)
    check_jsonl(root)
    adapter = load_adapter(root)
    contracts = adapter.validate_contracts(root)
    environments = contracts["environments"]
    if (root / adapter.HANDOFF).is_file():
        adapter.load_receipt(root / adapter.HANDOFF)
    check_workflows(root, environments, author_target_inputs(adapter, contracts), adapter)
    check_toolchain(root, adapter)
    check_readme(root, environments)
    if verify_main_compatibility_refresh:
        check_main_compatibility_refresh(root)
    readiness = adapter.readiness(root)
    require(readiness["consumer_runtime_readiness"] == "OUT_OF_SCOPE", "envs claims consumer runtime readiness")
    return {
        "kind": "envs.repositoryCheck.v1",
        "status": "PASS",
        "canonical_branch": "proposals",
        "retained_compatibility_branch": "main",
        "main_independent_authority_count": 0,
        "main_direct_change_count": 0,
        "provider_handoff": readiness["provider_handoff_receipt"],
        "consumer_runtime_readiness": "OUT_OF_SCOPE",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify-main-compatibility-refresh", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(args.root.resolve(), verify_main_compatibility_refresh=args.verify_main_compatibility_refresh)
    except (RepositoryError, ValueError, OSError) as exc:
        print(f"REPOSITORY_CHECK=RED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
