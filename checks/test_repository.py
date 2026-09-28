#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repository_check", ROOT / "checks/repository.py")
assert SPEC is not None and SPEC.loader is not None
repository = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repository)


def copy_root() -> Path:
    target = Path(tempfile.mkdtemp(prefix="envs-repository-test-")) / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    return target


def expect_red(mutate) -> None:
    root = copy_root()
    try:
        mutate(root)
        try:
            repository.inspect(root)
        except (repository.RepositoryError, ValueError, OSError):
            return
        raise AssertionError("invalid repository state was accepted")
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def append_branch_effect(root: Path) -> None:
    path = root / "contracts/provider-consumer.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    rows[0]["effect_source_branches"].append("main")
    path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))


def mutate_plane(identity: str, change):
    def mutate(root: Path) -> None:
        path = root / "contracts/environments.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        for row in rows:
            if row["id"] == identity:
                change(row)
        path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows))

    return mutate


def replace_text(relative: str, old: str, new: str):
    def mutate(root: Path) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        assert old in text, f"{relative} fixture anchor missing"
        path.write_text(text.replace(old, new), encoding="utf-8")

    return mutate


def main() -> None:
    baseline = repository.inspect(ROOT)
    assert baseline["status"] == "PASS"
    assert baseline["canonical_branch"] == "proposals"
    assert baseline["retained_compatibility_branch"] == "main"

    expect_red(lambda root: (root / "migration").mkdir())
    expect_red(lambda root: (root / "unexpected").mkdir())
    expect_red(lambda root: (root / "adapters/legacy.sh").write_text("exit 0\n"))
    expect_red(lambda root: (root / "adapters/legacy.go").write_text("package legacy\n"))
    expect_red(lambda root: (root / "contracts/provider-consumer.jsonl").unlink())
    expect_red(append_branch_effect)

    def add_database_path(root: Path) -> None:
        name = "duck" + "db"
        (root / f"contracts/{name}.jsonl").write_text("{}\n")

    expect_red(add_database_path)

    def add_token(root: Path) -> None:
        token = "gh" + "p_" + ("A" * 30)
        (root / "contracts/token.txt").write_text(token)

    expect_red(add_token)

    def add_historical_fallback(root: Path) -> None:
        historical = "roccho-dev/" + "envs-old"
        with (root / "adapters/jev_api.py").open("a", encoding="utf-8") as stream:
            stream.write("\n# fallback " + historical + "\n")

    expect_red(add_historical_fallback)

    def propose_main_deletion(root: Path) -> None:
        with (root / "README.md").open("a", encoding="utf-8") as stream:
            stream.write("\nDelete `main` after migration.\n")

    expect_red(propose_main_deletion)
    expect_red(replace_text("README.md", "retained compatibility branch: `main`", "retained compatibility mirror: `main`"))

    obsolete_field = "age_" + "recipients"
    obsolete_source = "SOURCE_" + "JEV_API_KEY"
    author = ".github/workflows/author-dev-jev-api.yml"
    project = ".github/workflows/project-dev-jev-api.yml"
    expect_red(mutate_plane("dev.authoring", lambda row: row.update({obsolete_field: []})))
    expect_red(mutate_plane("dev.runtime", lambda row: row.update({"required_variables": []})))
    expect_red(mutate_plane("stg.projection", lambda row: row["required_variables"].clear()))
    expect_red(mutate_plane("prd.projection", lambda row: row["required_secrets"].pop()))
    expect_red(mutate_plane("dev.projection", lambda row: row["required_variables"].append(
        {"name": "EXTRA", "type": "cloudflare_account_id", "lifecycle": "persistent"})))
    expect_red(mutate_plane("dev.authoring", lambda row: row["required_secrets"][0].update(
        {"lifecycle": "persistent"})))
    expect_red(replace_text(author, "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n", ""))
    expect_red(replace_text(author, "${{ vars.SOPS_AGE_RECIPIENTS }}", "${{ secrets.SOPS_AGE_RECIPIENTS }}"))
    expect_red(replace_text(author, "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}",
                            f"{obsolete_source}: ${{{{ secrets.{obsolete_source} }}}}"))
    expect_red(replace_text(author, "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}", "JEV_API_KEY: fixture-literal"))
    expect_red(replace_text(author, "SOPS_AGE_RECIPIENTS: ${{ vars", "AGE_RECIPIENTS: ${{ vars"))
    expect_red(replace_text(project, "          WRANGLER_PACKAGE:",
                            "          EXTRA: ${{ secrets.EXTRA }}\n          WRANGLER_PACKAGE:"))
    expect_red(replace_text("README.md", "dev-projection/SOPS_AGE_KEY", "dev-projection/REMOVED"))
    expect_red(replace_text("README.md", "prd-projection/CLOUDFLARE_ACCOUNT_ID", "prd-projection/REMOVED"))
    print("repository checker self-test: PASS")


if __name__ == "__main__":
    main()
