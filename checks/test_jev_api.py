#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import os
import secrets
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jev_api", ROOT / "adapters/jev_api.py")
assert SPEC is not None and SPEC.loader is not None
jev = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jev)

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Live Variable values are generated per run so their bytes never appear in tracked source.
RECIPIENT = "age1" + "".join(secrets.choice(BECH32) for _ in range(58))
ACCOUNT_ID = secrets.token_hex(16)
AGE_PREFIX = "AGE-SECRET-KEY-1"
AGE_IDENTITY = AGE_PREFIX + "".join(secrets.choice(BECH32.upper()) for _ in range(58))
OBSOLETE_SOURCE = "SOURCE_" + "JEV_API_KEY"
CREATED_AT = "2026-09-28T00:00:00Z"


def age_key_file(*identities: str) -> str:
    # Native age-keygen key-file shape: comment lines, then the identity lines.
    return "".join([f"# created: {CREATED_AT}\n", f"# public key: {RECIPIENT}\n", *(f"{item}\n" for item in identities)])


AGE_KEY = age_key_file(AGE_IDENTITY)


def author_env(**overrides: str) -> dict[str, str]:
    values = {"JEV_API_KEY": "fixture-secret", "SOPS_AGE_RECIPIENTS": RECIPIENT, "SOPS_BIN": "sops-fixture"}
    values.update(overrides)
    return values


def project_env(**overrides: str) -> dict[str, str]:
    values = {
        "SOPS_BIN": "sops-fixture",
        "SOPS_AGE_KEY": AGE_KEY,
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID,
        "CLOUDFLARE_API_TOKEN": "provider-token-fixture",
        "NPX_BIN": "npx-fixture",
    }
    values.update(overrides)
    return values


@contextmanager
def environment(values: dict[str, str]):
    old = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def copy_root() -> Path:
    target = Path(tempfile.mkdtemp(prefix="envs-jev-test-")) / "repo"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
    return target


def append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(text)


def ciphertext(extra: str = "") -> bytes:
    return (
        "JEV_API_KEY: ENC[AES256_GCM,data:fixture]\n"
        f"{extra}"
        "sops:\n"
        "  age:\n"
        f"    - recipient: {RECIPIENT}\n"
    ).encode()


def expect_receipt_red(value: dict) -> None:
    try:
        jev.validate_receipt(value)
    except jev.EnvsError:
        return
    raise AssertionError("invalid receipt was accepted")


def test_author() -> None:
    root = copy_root()
    calls: list[tuple[list[str], dict[str, str]]] = []
    try:
        def runner(argv, input_data, env):
            calls.append((list(argv), dict(env)))
            return subprocess.CompletedProcess(argv, 0, stdout=ciphertext(), stderr=b"")

        with environment(author_env()):
            result = jev.author(root, runner)
        assert result["status"] == "PASS"
        assert len(calls) == 1 and calls[0][0][0] == "sops-fixture"
        assert calls[0][1]["SOPS_AGE_RECIPIENTS"] == RECIPIENT
        assert "JEV_API_KEY" not in calls[0][1]
        assert (root / jev.CIPHERTEXT).is_file()
        assert b"fixture-secret" not in (root / jev.CIPHERTEXT).read_bytes()
        contracts = jev.validate_contracts(root)
        assert contracts["environments"]["dev.authoring"]["migration_state"] == "ACTIVE"
        assert contracts["environments"]["dev.projection"]["migration_state"] == "ACTIVE"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def expect_author_red(values: dict[str, str], mutate=None, output: bytes | None = None) -> None:
    root = copy_root()
    calls: list[list[str]] = []
    try:
        if mutate is not None:
            mutate(root)

        def runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=output if output is not None else ciphertext(), stderr=b"")

        with environment(values):
            try:
                jev.author(root, runner)
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("invalid authoring input was accepted")
        assert not (root / jev.CIPHERTEXT).exists()
        assert output is not None or not calls, "sops ran before the input gate"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_author_red_inputs() -> None:
    expect_author_red(author_env(SOPS_AGE_RECIPIENTS="xxx"))
    expect_author_red(author_env(SOPS_AGE_RECIPIENTS=""))
    expect_author_red(author_env(SOPS_AGE_RECIPIENTS=f"{RECIPIENT},{RECIPIENT}"))
    expect_author_red(author_env(SOPS_AGE_RECIPIENTS=RECIPIENT.upper()))
    expect_author_red(author_env(JEV_API_KEY=""))
    expect_author_red({**author_env(JEV_API_KEY=""), OBSOLETE_SOURCE: "fixture-secret"})
    expect_author_red(author_env(), mutate=lambda root: append(root / "README.md", f"\n{RECIPIENT}\n"))
    expect_author_red(author_env(), mutate=lambda root: append(root / "checks/test_jev_api.py", f"\n# {RECIPIENT}\n"))
    expect_author_red(author_env(), output=ciphertext(f"note: {RECIPIENT}\n"))
    expect_author_red(author_env(), output=ciphertext().replace(RECIPIENT.encode(), ("age1" + "q" * 58).encode()))


def active_root() -> Path:
    root = copy_root()
    target = root / jev.CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ciphertext())
    jev.set_dev_active(root, True)
    jev.validate_contracts(root)
    return root


def test_project() -> None:
    root = active_root()
    calls: list[tuple[list[str], bytes | None]] = []
    try:
        def runner(argv, input_data, env):
            command = list(argv)
            calls.append((command, input_data))
            if command[0] == "sops-fixture":
                return subprocess.CompletedProcess(argv, 0, stdout=b'{"JEV_API_KEY":"fixture-secret"}\n', stderr=b"")
            if "put" in command:
                assert input_data == b"fixture-secret"
                assert "fixture-secret" not in " ".join(command)
                return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n", stderr=b"")
            if "list" in command:
                return subprocess.CompletedProcess(argv, 0, stdout=b"JEV_API_KEY\n", stderr=b"")
            raise AssertionError(command)

        with environment(project_env()):
            receipt = jev.project(
                envs_sha="a" * 40,
                run_id=123,
                run_attempt=1,
                created_at=CREATED_AT,
                output=jev.HANDOFF,
                root=root,
                runner=runner,
            )
        jev.validate_receipt(receipt)
        assert ["sops-fixture", "npx-fixture", "npx-fixture"] == [call[0][0] for call in calls]
        assert "account_id" not in receipt["target"]
        assert ACCOUNT_ID.encode() not in (root / jev.HANDOFF).read_bytes()
        assert jev.readiness(root)["provider_handoff_ready"] is True
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def expect_project_red(values: dict[str, str], mutate=None) -> None:
    root = active_root()
    calls: list[list[str]] = []
    try:
        if mutate is not None:
            mutate(root)

        def runner(argv, input_data, env):
            calls.append(list(argv))
            raise AssertionError("provider tool ran before the input gate")

        with environment(values):
            try:
                jev.project(
                    envs_sha="a" * 40, run_id=1, run_attempt=1, created_at=CREATED_AT,
                    output=jev.HANDOFF, root=root, runner=runner,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("invalid projection input was accepted")
        assert not calls
        assert not (root / jev.HANDOFF).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_project_red_inputs() -> None:
    expect_project_red(project_env(CLOUDFLARE_ACCOUNT_ID=""))
    expect_project_red(project_env(CLOUDFLARE_ACCOUNT_ID=ACCOUNT_ID.upper() + "G"))
    expect_project_red(project_env(CLOUDFLARE_ACCOUNT_ID=ACCOUNT_ID[:31]))
    expect_project_red(project_env(CLOUDFLARE_API_TOKEN=""))
    expect_project_red(project_env(SOPS_AGE_KEY=""))
    expect_project_red(project_env(SOPS_AGE_KEY="not-an-age-identity"))
    other = AGE_PREFIX + "".join(secrets.choice(BECH32.upper()) for _ in range(58))
    expect_project_red(project_env(SOPS_AGE_KEY=age_key_file()))
    expect_project_red(project_env(SOPS_AGE_KEY=age_key_file(AGE_IDENTITY, other)))
    expect_project_red(project_env(SOPS_AGE_KEY=age_key_file(AGE_IDENTITY[:-1])))
    expect_project_red(project_env(SOPS_AGE_KEY=age_key_file(AGE_IDENTITY[:-1] + "B")))
    expect_project_red(project_env(SOPS_AGE_KEY=age_key_file(AGE_IDENTITY + "Q")))
    expect_project_red(project_env(), mutate=lambda root: append(root / "README.md", f"\n{ACCOUNT_ID}\n"))
    expect_project_red(project_env(), mutate=lambda root: append(root / jev.CIPHERTEXT, f"# {ACCOUNT_ID}\n"))


def test_decrypt_failure_has_no_provider_effect() -> None:
    root = active_root()
    calls: list[list[str]] = []
    try:
        def runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"red")

        with environment(project_env()):
            try:
                jev.project(
                    envs_sha="a" * 40,
                    run_id=1,
                    run_attempt=1,
                    created_at=CREATED_AT,
                    output=jev.HANDOFF,
                    root=root,
                    runner=runner,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("decrypt failure was accepted")
        assert len(calls) == 1
        assert not (root / jev.HANDOFF).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_receipt_mutations() -> None:
    base = jev.build_receipt(
        envs_sha="a" * 40,
        ciphertext_sha256="b" * 64,
        run_id=123,
        run_attempt=1,
        created_at=CREATED_AT,
    )
    assert "account_id" not in base["target"]
    mutations: list[dict] = []

    value = copy.deepcopy(base)
    value["target"]["account_id"] = ACCOUNT_ID
    mutations.append(value)

    value = copy.deepcopy(base)
    value["envs_sha"] = "proposals"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["status"] = "NOT_RUN"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["readback"]["present"] = False
    mutations.append(value)

    value = copy.deepcopy(base)
    value["effect"]["status"] = "BLOCKED"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["workflow"]["ref"] = "main"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["secret_value"] = "fixture"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["source"]["sha256"] = "sha256:short"
    mutations.append(value)

    for value in mutations:
        expect_receipt_red(value)


def main() -> None:
    jev.validate_contracts(ROOT)
    state = jev.readiness(ROOT)
    assert state["physical_dev_projection"] == "NOT_CONFIGURED"
    assert state["provider_handoff_receipt"] == "ABSENT"
    assert state["consumer_runtime_readiness"] == "OUT_OF_SCOPE"
    test_author()
    test_author_red_inputs()
    test_project()
    test_project_red_inputs()
    test_decrypt_failure_has_no_provider_effect()
    test_receipt_mutations()
    print("Jev adapter self-test: PASS")


if __name__ == "__main__":
    main()
