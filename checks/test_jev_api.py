#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import os
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

RECIPIENT = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"


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


def set_recipient(root: Path) -> None:
    path = root / jev.ENVIRONMENTS
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    for row in rows:
        if row["id"] == "dev.authoring":
            row["age_recipients"] = [RECIPIENT]
    jev.write_jsonl(path, rows)


def ciphertext(secret: str = "not-the-real-secret") -> bytes:
    return (
        "JEV_API_KEY: ENC[AES256_GCM,data:fixture]\n"
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
    calls: list[list[str]] = []
    try:
        set_recipient(root)

        def runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=ciphertext(), stderr=b"")

        with environment({"SOURCE_JEV_API_KEY": "fixture-secret", "SOPS_BIN": "sops-fixture"}):
            result = jev.author(root, runner)
        assert result["status"] == "PASS"
        assert calls and calls[0][0] == "sops-fixture"
        assert (root / jev.CIPHERTEXT).is_file()
        assert b"fixture-secret" not in (root / jev.CIPHERTEXT).read_bytes()
        contracts = jev.validate_contracts(root)
        assert contracts["environments"]["dev.authoring"]["migration_state"] == "ACTIVE"
        assert contracts["environments"]["dev.projection"]["migration_state"] == "ACTIVE"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_author_missing_source() -> None:
    root = copy_root()
    try:
        set_recipient(root)
        with environment({"SOURCE_JEV_API_KEY": ""}):
            try:
                jev.author(root, lambda *_: None)
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("missing source secret was accepted")
        assert not (root / jev.CIPHERTEXT).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def active_root() -> Path:
    root = copy_root()
    set_recipient(root)
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

        with environment(
            {
                "SOPS_BIN": "sops-fixture",
                "SOPS_AGE_KEY": "fixture-age-key",
                "CLOUDFLARE_ACCOUNT_ID": "account-fixture",
                "CLOUDFLARE_API_TOKEN": "provider-token-fixture",
                "NPX_BIN": "npx-fixture",
            }
        ):
            receipt = jev.project(
                envs_sha="a" * 40,
                run_id=123,
                run_attempt=1,
                created_at="2026-09-28T00:00:00Z",
                output=jev.HANDOFF,
                root=root,
                runner=runner,
            )
        jev.validate_receipt(receipt)
        assert ["sops-fixture", "npx-fixture", "npx-fixture"] == [call[0][0] for call in calls]
        assert jev.readiness(root)["provider_handoff_ready"] is True
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_decrypt_failure_has_no_provider_effect() -> None:
    root = active_root()
    calls: list[list[str]] = []
    try:
        def runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"red")

        with environment(
            {
                "SOPS_BIN": "sops-fixture",
                "SOPS_AGE_KEY": "fixture-age-key",
                "CLOUDFLARE_ACCOUNT_ID": "account-fixture",
                "CLOUDFLARE_API_TOKEN": "provider-token-fixture",
            }
        ):
            try:
                jev.project(
                    envs_sha="a" * 40,
                    run_id=1,
                    run_attempt=1,
                    created_at="2026-09-28T00:00:00Z",
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
        account_id="account-fixture",
        run_id=123,
        run_attempt=1,
        created_at="2026-09-28T00:00:00Z",
    )
    mutations: list[dict] = []

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
    test_author_missing_source()
    test_project()
    test_decrypt_failure_has_no_provider_effect()
    test_receipt_mutations()
    print("Jev adapter self-test: PASS")


if __name__ == "__main__":
    main()
