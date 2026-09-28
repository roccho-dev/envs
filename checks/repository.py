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
    ".gitignore",
    "LICENSE_POLICY.md",
    "LICENSES/README.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "adapters/jev_api.py",
    "checks/repository.py",
    "checks/test_jev_api.py",
    "checks/test_repository.py",
    "contracts/bindings.jsonl",
    "contracts/environments.jsonl",
    "contracts/provider-consumer.jsonl",
    "contracts/targets.jsonl",
}
ALLOWED_ROOTS = {
    ".github",
    "LICENSES",
    "adapters",
    "checks",
    "ciphertexts",
    "contracts",
    "handoffs",
}
ALLOWED_ROOT_FILES = {
    ".gitignore",
    "LICENSE_POLICY.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
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
    "flake.nix",
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
}


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
        require(ciphertexts == ["ciphertexts/dev-jev-api.sops.yaml"], f"unexpected ciphertexts: {ciphertexts}")

    handoff_dir = root / "handoffs"
    if handoff_dir.exists():
        handoffs = sorted(path.relative_to(root).as_posix() for path in handoff_dir.rglob("*") if path.is_file())
        require(handoffs == ["handoffs/dev-jev-api.json"], f"unexpected handoffs: {handoffs}")


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


def check_workflows(root: Path, environments: dict[str, dict[str, Any]]) -> None:
    workflow_root = root / ".github/workflows"
    names = {path.name for path in workflow_root.iterdir() if path.is_file()}
    require(
        names == {"check.yml", "author-dev-jev-api.yml", "project-dev-jev-api.yml"},
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

    for name, plane in EFFECT_WORKFLOWS.items():
        text = texts[name]
        row = environments[plane]
        require("workflow_dispatch:" in text, f"{name}: manual dispatch missing")
        require("\n  push:" not in text and "\n  pull_request:" not in text, f"{name}: automatic effect trigger")
        require(f"environment: {row['github_environment']}" in text, f"{name}: static Environment differs")
        require("github.repository == 'roccho-dev/envs'" in text, f"{name}: repository guard missing")
        require("github.ref_name == 'proposals'" in text, f"{name}: canonical ref guard missing")
        require("ref: ${{ github.sha }}" in text, f"{name}: exact checkout missing")
        require("main" not in text, f"{name}: main must not be an effect source")
        declared = declared_inputs(row)
        require(set(INPUT_REFERENCE.findall(text)) == declared, f"{name}: Environment inputs differ from contract")
        for namespace, input_name in sorted(declared):
            mapping = "^\\s+" + re.escape(f"{input_name}: ${{{{ {namespace}.{input_name} }}}}") + "$"
            require(re.search(mapping, text, re.MULTILINE) is not None, f"{name}: {input_name} mapping differs")

    require("adapters/jev_api.py author" in texts["author-dev-jev-api.yml"], "author workflow adapter call missing")
    require("adapters/jev_api.py project" in texts["project-dev-jev-api.yml"], "project workflow adapter call missing")


def check_readme(root: Path, environments: dict[str, dict[str, Any]]) -> None:
    text = (root / "README.md").read_text(encoding="utf-8")
    for row in environments.values():
        for _, input_name in sorted(declared_inputs(row)):
            marker = f"{row['github_environment']}/{input_name}"
            require(marker in text, f"README missing {marker}")
    for marker in (
        "canonical branch: `proposals`",
        "retained compatibility mirror: `main`",
        "contracts/",
        "adapters/jev_api.py",
        "handoffs/dev-jev-api.json",
    ):
        require(marker in text, f"README missing {marker}")
    require("delete `main`" not in text.lower(), "README proposes deleting main")


def check_main_mirror(root: Path) -> None:
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
    require(head.stdout.strip() == canonical.stdout.strip(), "main is not an exact proposals mirror")


def inspect(root: Path = ROOT, *, verify_main_mirror: bool = False) -> dict[str, Any]:
    check_shape(root)
    check_text(root)
    check_jsonl(root)
    adapter = load_adapter(root)
    environments = adapter.validate_contracts(root)["environments"]
    if (root / adapter.HANDOFF).is_file():
        adapter.load_receipt(root / adapter.HANDOFF)
    check_workflows(root, environments)
    check_readme(root, environments)
    if verify_main_mirror:
        check_main_mirror(root)
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
    parser.add_argument("--verify-main-mirror", action="store_true")
    args = parser.parse_args()
    try:
        result = inspect(args.root.resolve(), verify_main_mirror=args.verify_main_mirror)
    except (RepositoryError, ValueError, OSError) as exc:
        print(f"REPOSITORY_CHECK=RED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
