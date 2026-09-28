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
    print("repository checker self-test: PASS")


if __name__ == "__main__":
    main()
