#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

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

# A fixture store stands in for /nix/store; python3 resolves to the interpreter running these tests.
STORE = Path(tempfile.mkdtemp(prefix="envs-store-"))
jev.STORE = STORE
TOOLS: dict[str, str] = {}
for _name in jev.TOOLCHAIN_TOOLS:
    _path = STORE / f"{_name}-fixture" / "bin" / _name
    _path.parent.mkdir(parents=True)
    if _name == "python3":
        _path.symlink_to(os.path.realpath(sys.executable))
    else:
        _path.write_text("#!/bin/false\n")
        _path.chmod(0o755)
    TOOLS[_name] = str(_path)


def manifest(name: str, **changes) -> str:
    value = {"kind": jev.TOOLCHAIN_KIND, "nixpkgs": jev.locked_nixpkgs(ROOT), "source": "a" * 40, "tools": dict(TOOLS)}
    value.update(changes)
    path = STORE / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


MANIFEST = manifest("toolchain.json")


def author_env(**overrides: str) -> dict[str, str]:
    values = {"JEV_API_KEY": "fixture-secret", "SOPS_AGE_RECIPIENTS": RECIPIENT, "ENVS_EFFECT_TOOLCHAIN": MANIFEST}
    values.update(overrides)
    return values


OCI_RECIPIENT = "age1" + "".join(secrets.choice(BECH32) for _ in range(58))
OCI_OTHER = "age1" + "".join(secrets.choice(BECH32) for _ in range(58))
# Generated per run: the OCI source value never appears in tracked source.
OCI_KEY = "jev-" + secrets.token_urlsafe(24)


def oci_env(**overrides: str) -> dict[str, str]:
    values = {"JEV_API_KEY": OCI_KEY, jev.OCI_RECIPIENT: OCI_RECIPIENT, "ENVS_EFFECT_TOOLCHAIN": MANIFEST}
    values.update(overrides)
    return values


def oci_ciphertext(recipients: tuple[str, ...] = (OCI_RECIPIENT,), extra: str = "", key: str = "JEV_API_KEY") -> bytes:
    lines = "".join(f"    - recipient: {item}\n" for item in recipients)
    return f"{key}: ENC[AES256_GCM,data:fixture]\n{extra}sops:\n  age:\n{lines}".encode()


def snapshot(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in jev.repository_files(root)}


def project_env(**overrides: str) -> dict[str, str]:
    values = {
        "ENVS_EFFECT_TOOLCHAIN": MANIFEST,
        "SOPS_AGE_KEY": AGE_KEY,
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID,
        "CLOUDFLARE_API_TOKEN": "provider-token-fixture",
    }
    values.update(overrides)
    return values


PAGES_TARGET = {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"}
WORKER_NAME = "voice-ui-worker-fixture"


def worker_target(account_id: str = ACCOUNT_ID, worker_name: str = WORKER_NAME) -> dict[str, str]:
    return {
        "provider": "cloudflare-workers",
        "account_id": account_id,
        "worker_name": worker_name,
        "secret_name": "JEV_API_KEY",
    }


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
    (target / jev.OCI_CIPHERTEXT).unlink(missing_ok=True)
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
        assert len(calls) == 1 and calls[0][0][0] == TOOLS["sops"]
        assert calls[0][1]["SOPS_AGE_RECIPIENTS"] == RECIPIENT
        assert all(Path(item).parent.parent == STORE for item in calls[0][1]["PATH"].split(os.pathsep))
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


def test_author_oci() -> None:
    # SOPS_AGE_RECIPIENTS is set to an invalid value: the OCI target must not read it, only its own recipient.
    root = copy_root()
    calls: list[tuple[list[str], bytes | None, dict[str, str]]] = []
    try:
        before = snapshot(root)

        def runner(argv, input_data, env):
            calls.append((list(argv), input_data, dict(env)))
            return subprocess.CompletedProcess(argv, 0, stdout=oci_ciphertext(), stderr=b"")

        with environment(oci_env(SOPS_AGE_RECIPIENTS="not-read")):
            result = jev.author_oci(root, runner)
        assert result == {
            "kind": "envs.targetAuthoringResult.v1", "status": "PASS", "binding": jev.OCI_BINDING,
            "ciphertext": jev.OCI_CIPHERTEXT.as_posix(), "recipient_count": 1,
            "target_apply": "NOT_RUN", "application_runtime": "NOT_RUN",
        }
        assert len(calls) == 1
        argv, stdin, env = calls[0]
        assert argv == [TOOLS["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"]
        assert json.loads(stdin) == {"JEV_API_KEY": OCI_KEY}
        assert env["SOPS_AGE_RECIPIENTS"] == OCI_RECIPIENT and "JEV_API_KEY" not in env and jev.OCI_RECIPIENT not in env
        assert not any(OCI_KEY in item for item in [*argv, *env.values()])
        assert OCI_KEY not in json.dumps(result)
        # Only the declared ciphertext is new; every other byte, plane state and handoff is unchanged.
        after = snapshot(root)
        assert set(after) - set(before) == {jev.OCI_CIPHERTEXT.as_posix()}
        assert all(after[name] == data for name, data in before.items())
        assert not (root / jev.CIPHERTEXT).exists() and not (root / jev.HANDOFF).exists()
        contracts = jev.validate_contracts(root)
        for plane in ("dev.authoring", "dev.projection"):
            assert contracts["environments"][plane]["migration_state"] == "NOT_CONFIGURED"
        # A second run (rotation) over the committed ciphertext is accepted: its recipient metadata is not a leak.
        with environment(oci_env()):
            jev.author_oci(root, runner)
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_targets_are_separate() -> None:
    contracts = jev.validate_contracts(ROOT)
    names = {target: [entry["name"] for entry in jev.authoring_inputs(contracts, target)] for target in jev.AUTHOR_TARGETS}
    assert names == {"jev-api": ["JEV_API_KEY", "SOPS_AGE_RECIPIENTS"], jev.OCI_BINDING: ["JEV_API_KEY", jev.OCI_RECIPIENT]}
    try:
        jev.authoring_inputs(contracts, "rent-tunnel")
    except jev.EnvsError:
        pass
    else:
        raise AssertionError("an undeclared author target was accepted")
    # The Cloudflare target still authors with the OCI recipient absent.
    root = copy_root()
    try:
        values = author_env()
        saved = os.environ.pop(jev.OCI_RECIPIENT, None)
        try:
            with environment(values):
                jev.author(root, lambda argv, input_data, env: subprocess.CompletedProcess(argv, 0, stdout=ciphertext(), stderr=b""))
        finally:
            if saved is not None:
                os.environ[jev.OCI_RECIPIENT] = saved
        assert (root / jev.CIPHERTEXT).is_file() and not (root / jev.OCI_CIPHERTEXT).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def expect_oci_red(values: dict[str, str], *, mutate=None, output: bytes | None = None, returncode: int = 0) -> None:
    root = copy_root()
    calls: list[list[str]] = []
    try:
        if mutate is not None:
            mutate(root)
        before = snapshot(root)

        def runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, returncode, stdout=output if output is not None else oci_ciphertext(),
                                               stderr=b"")

        with environment(values):
            try:
                jev.author_oci(root, runner)
            except jev.EnvsError as exc:
                message = str(exc)
            else:
                raise AssertionError("invalid OCI authoring state was accepted")
        assert OCI_KEY not in message, message
        assert output is not None or returncode != 0 or not calls, "sops ran before the input gate"
        assert snapshot(root) == before, "a RED OCI authoring changed the repository"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_author_oci_red() -> None:
    for name in ("JEV_API_KEY", jev.OCI_RECIPIENT):
        expect_oci_red(oci_env(**{name: ""}))
    # Exactly one target recipient: lists, duplicates and malformed recipients are RED before SOPS.
    expect_oci_red(oci_env(**{jev.OCI_RECIPIENT: f"{OCI_RECIPIENT},{OCI_OTHER}"}))
    expect_oci_red(oci_env(**{jev.OCI_RECIPIENT: f"{OCI_RECIPIENT},{OCI_RECIPIENT}"}))
    expect_oci_red(oci_env(**{jev.OCI_RECIPIENT: OCI_RECIPIENT.upper()}))
    expect_oci_red(oci_env(**{jev.OCI_RECIPIENT: f" {OCI_RECIPIENT}"}))
    # The Cloudflare recipient list is not an OCI input.
    expect_oci_red({**oci_env(**{jev.OCI_RECIPIENT: ""}), "SOPS_AGE_RECIPIENTS": OCI_RECIPIENT})
    # A live recipient or source value already in Git is RED before SOPS.
    expect_oci_red(oci_env(), mutate=lambda root: append(root / "README.md", f"\n{OCI_RECIPIENT}\n"))
    expect_oci_red(oci_env(), mutate=lambda root: append(root / "README.md", f"\n{OCI_KEY}\n"))
    # SOPS output must be this one recipient's ciphertext of exactly the key.
    for output, returncode in (
        (oci_ciphertext((OCI_RECIPIENT, OCI_OTHER)), 0),
        (oci_ciphertext((OCI_OTHER,)), 0),
        (oci_ciphertext(()), 0),
        (oci_ciphertext(key=jev.RENT_KEY), 0),
        (oci_ciphertext(extra="note: plain\n"), 0),
        (oci_ciphertext(extra=f"note: {OCI_KEY}\n"), 0),
        (oci_ciphertext() + f"# {OCI_RECIPIENT}\n".encode(), 0),
        (oci_ciphertext(), 1),
    ):
        expect_oci_red(oci_env(), output=output, returncode=returncode)
    outside = Path(tempfile.mkdtemp(prefix="envs-oci-outside-"))
    try:
        for values, mutate in toolchain_red_cases(outside / "toolchain.json"):
            expect_oci_red(oci_env(**values), mutate=mutate)
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_committed_oci_state() -> None:
    def write(data: bytes):
        def mutate(root: Path) -> None:
            (root / "ciphertexts").mkdir(exist_ok=True)
            (root / jev.OCI_CIPHERTEXT).write_bytes(data)
        return mutate

    root = copy_root()
    try:
        write(oci_ciphertext())(root)
        contracts = jev.validate_contracts(root)
        assert contracts["environments"]["dev.authoring"]["migration_state"] == "NOT_CONFIGURED"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)
    for mutate in (write(oci_ciphertext((OCI_RECIPIENT, OCI_OTHER))), write(oci_ciphertext(extra="note: plain\n")),
                   write(oci_ciphertext(key=jev.RENT_KEY))):
        root = copy_root()
        try:
            mutate(root)
            try:
                jev.validate_contracts(root)
            except jev.EnvsError:
                continue
            raise AssertionError("an invalid committed OCI ciphertext was accepted")
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)


def test_author_target_cli() -> None:
    # A dispatch without a target, or with an undeclared one, stops before any input is read or anything is written.
    root = copy_root()
    try:
        before = snapshot(root)
        for argv in (["author"], ["author", "--target", "rent-tunnel"], ["author", "--target", ""]):
            with environment(oci_env()):
                try:
                    jev.main(["--root", str(root), *argv])
                except SystemExit as exc:
                    assert exc.code == 2, argv
                else:
                    raise AssertionError(f"author accepted {argv}")
        assert snapshot(root) == before
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def run_tool(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False)


def real_oci_roundtrip(sops_bin: str, keygen_bin: str) -> None:
    # The real locked sops encrypts to one throwaway target recipient; only that identity decrypts, tampering is RED.
    sops_path, keygen = os.path.realpath(sops_bin), os.path.realpath(keygen_bin)
    for path in (sops_path, keygen):
        assert path.startswith("/nix/store/") and os.access(path, os.X_OK), f"not a locked store tool: {path}"
    work = Path(tempfile.mkdtemp(prefix="envs-oci-roundtrip-"))
    base = {"PATH": os.path.dirname(sops_path), "HOME": str(work)}
    try:
        def identity(name: str) -> tuple[Path, str]:
            key = work / name
            assert run_tool([keygen, "-o", str(key)], base).returncode == 0, "age-keygen failed"
            public = run_tool([keygen, "-y", str(key)], base)
            assert public.returncode == 0, "age-keygen -y failed"
            return key, public.stdout.decode().strip()

        key, recipient = identity("target.key")
        other_key, other = identity("other.key")
        assert jev.AGE_RECIPIENT.fullmatch(recipient) and jev.AGE_RECIPIENT.fullmatch(other) and recipient != other
        calls: list[list[str]] = []

        def runner(argv, input_data, env):
            calls.append(list(argv))
            return jev.default_runner(argv, input_data, env)

        tools = {"sops": sops_path}
        data = jev.encrypt_oci_key(OCI_KEY, recipient, tools, runner)
        assert len(calls) == 1 and not any(OCI_KEY in item for item in calls[0])
        assert OCI_KEY.encode() not in data and b"AGE-SECRET-KEY-1" not in data
        jev.validate_oci_ciphertext(data, OCI_KEY.encode(), recipient)
        cipher = work / "dev-jev-api.oci-dev.sops.yaml"
        cipher.write_bytes(data)

        def decrypt(path: Path, identity_file: Path) -> subprocess.CompletedProcess[bytes]:
            return run_tool([sops_path, "--decrypt", "--input-type", "yaml", "--output-type", "json", str(path)],
                            {**base, "SOPS_AGE_KEY_FILE": str(identity_file)})

        opened = decrypt(cipher, key)
        assert opened.returncode == 0, "the target identity could not decrypt"
        assert json.loads(opened.stdout) == {"JEV_API_KEY": OCI_KEY}, "roundtrip changed the key"
        wrong = decrypt(cipher, other_key)
        assert wrong.returncode != 0 and OCI_KEY.encode() not in wrong.stdout + wrong.stderr, "another identity decrypted"
        text = data.decode()
        start = text.index("ENC[AES256_GCM,data:") + len("ENC[AES256_GCM,data:")
        tampered = work / "tampered.sops.yaml"
        tampered.write_text(text[:start] + ("A" if text[start] != "A" else "B") + text[start + 1:], encoding="utf-8")
        broken = decrypt(tampered, key)
        assert broken.returncode != 0 and OCI_KEY.encode() not in broken.stdout + broken.stderr, "tampered ciphertext decrypted"
        # A real ciphertext does not pass as another recipient's, nor with its recipient metadata swapped.
        for candidate, expected in ((data, other), (text.replace(recipient, other).encode(), recipient)):
            try:
                jev.validate_oci_ciphertext(candidate, None, expected)
            except jev.EnvsError:
                continue
            raise AssertionError("a ciphertext for another recipient was accepted")
        before = len(calls)
        try:
            jev.encrypt_oci_key(OCI_KEY, f"{recipient},{other}", tools, runner)
        except jev.EnvsError:
            pass
        else:
            raise AssertionError("two recipients were accepted")
        assert len(calls) == before, "sops ran for a recipient list"
        print(f"real OCI SOPS roundtrip: PASS (sops={sops_path}, age-keygen={keygen})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def active_root() -> Path:
    root = copy_root()
    target = root / jev.CIPHERTEXT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(ciphertext())
    jev.set_dev_active(root, True)
    jev.validate_contracts(root)
    return root


def workers_root(target: dict[str, str] | None = None) -> Path:
    root = active_root()
    rows = jev.load_jsonl(root / jev.BINDINGS)
    for row in rows:
        if row.get("id") == "jev-api":
            row["target"] = worker_target() if target is None else target
    jev.write_jsonl(root / jev.BINDINGS, rows)
    jev.validate_contracts(root)
    return root


class FakeProviderResponse:
    def __init__(
        self,
        status: int = 200,
        body: bytes = b'{"success":true,"result":{"name":"JEV_API_KEY","type":"secret_text"}}',
    ):
        self.status = status
        self._body = body

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_project() -> None:
    root = active_root()
    calls: list[tuple[list[str], bytes | None]] = []
    try:
        def runner(argv, input_data, env):
            command = list(argv)
            calls.append((command, input_data))
            assert "--yes" not in command and all(Path(item).parent.parent == STORE
                                                  for item in env["PATH"].split(os.pathsep))
            if command[0] == TOOLS["sops"]:
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
        assert [TOOLS["sops"], TOOLS["wrangler"], TOOLS["wrangler"]] == [call[0][0] for call in calls]
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


def toolchain_red_cases(outside: Path) -> list[tuple[dict[str, str], object]]:
    outside.write_text(Path(MANIFEST).read_text(encoding="utf-8"), encoding="utf-8")
    other_python = STORE / "other-python-fixture"
    other_python.write_text("#!/bin/false\n")
    other_python.chmod(0o755)
    lock = {**jev.locked_nixpkgs(ROOT)}
    lock["narHash"] = "sha256-" + "A" * 43 + "="

    def mismatch_lock(root: Path) -> None:
        path = root / jev.FLAKE_LOCK
        path.write_text(path.read_text(encoding="utf-8").replace(jev.locked_nixpkgs(ROOT)["narHash"], lock["narHash"]),
                        encoding="utf-8")

    return [
        ({"ENVS_EFFECT_TOOLCHAIN": ""}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": str(outside)}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": str(STORE / "absent.json")}, None),
        ({}, mismatch_lock),
        ({}, lambda root: (root / jev.FLAKE_LOCK).unlink()),
        ({}, lambda root: append(root / "adapters/jev_api.py", "\n# checkout differs from the artifact\n")),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("stale-lock.json", nixpkgs=lock)}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("kind.json", kind="envs.effectToolchain.v0")}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("dirty-source.json", source="dirty")}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("missing-tool.json", tools={**TOOLS, "sops": str(STORE / "absent")})}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("ambient-tool.json", tools={**TOOLS, "wrangler": "/usr/bin/wrangler"})}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("extra-tool.json", tools={**TOOLS, "npx": TOOLS["git"]})}, None),
        ({"ENVS_EFFECT_TOOLCHAIN": manifest("python.json", tools={**TOOLS, "python3": str(other_python)})}, None),
    ]


def test_toolchain_red() -> None:
    # Missing or mismatched toolchain must be RED before SOPS or the provider tool runs.
    outside = Path(tempfile.mkdtemp(prefix="envs-outside-"))
    try:
        for values, mutate in toolchain_red_cases(outside / "toolchain.json"):
            expect_author_red(author_env(**values), mutate=mutate)
            expect_project_red(project_env(**values), mutate=mutate)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
    assert jev.toolchain(ROOT, {"ENVS_EFFECT_TOOLCHAIN": MANIFEST}) == TOOLS
    try:
        jev.toolchain(ROOT, {"ENVS_EFFECT_TOOLCHAIN": MANIFEST}, executable=TOOLS["git"])
    except jev.EnvsError:
        pass
    else:
        raise AssertionError("ambient interpreter was accepted")


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



def test_workers_exact_readback_and_no_wrangler_create_path() -> None:
    root = workers_root()
    calls: list[list[str]] = []
    provider_requests = []
    list_count = 0
    try:
        def runner(argv, input_data, env):
            nonlocal list_count
            command = list(argv)
            calls.append(command)
            if command[0] == TOOLS["wrangler"]:
                assert command == [
                    TOOLS["wrangler"], "secret", "list", "--name", WORKER_NAME, "--format", "json",
                ]
                list_count += 1
                output = b'[]\n' if list_count == 1 else b'[{"name":"JEV_API_KEY","type":"secret_text"}]\n'
                # stderr is deliberately misleading; it is never positive presence evidence.
                return subprocess.CompletedProcess(argv, 0, stdout=output, stderr=b"JEV_API_KEY is missing")
            if command[0] == TOOLS["sops"]:
                return subprocess.CompletedProcess(argv, 0, stdout=b'{"JEV_API_KEY":"fixture-secret"}\n', stderr=b"")
            raise AssertionError(command)

        def opener(request, **_kwargs):
            provider_requests.append(request)
            return FakeProviderResponse()

        with environment(project_env()):
            receipt = jev.project(
                envs_sha="a" * 40, run_id=123, run_attempt=1, created_at=CREATED_AT,
                output=jev.HANDOFF, root=root, runner=runner, opener=opener,
            )
        jev.validate_receipt(receipt, worker_target())
        assert receipt["target"] == worker_target()
        assert receipt["effect"] == {"operation": "cloudflare_workers_secret_put", "status": "PASS"}
        assert list_count == 2
        assert not any(command[0] == TOOLS["wrangler"] and "put" in command for command in calls)
        assert len(provider_requests) == 1
        request = provider_requests[0]
        assert request.get_method() == "PUT"
        assert request.full_url.endswith(f"/accounts/{ACCOUNT_ID}/workers/scripts/{WORKER_NAME}/secrets")
        assert json.loads(request.data) == {"name": "JEV_API_KEY", "text": "fixture-secret", "type": "secret_text"}
        assert jev.readiness(root)["provider_handoff_ready"] is True
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_workers_missing_or_deleted_worker_never_creates_draft() -> None:
    # Preflight not-found: no decrypt, no secret write, no receipt.
    root = workers_root()
    calls: list[list[str]] = []
    writes = []
    try:
        def missing_runner(argv, input_data, env):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"Worker not found")

        def opener(request, **_kwargs):
            writes.append(request)
            return FakeProviderResponse()

        with environment(project_env()):
            try:
                jev.project(
                    envs_sha="a" * 40, run_id=1, run_attempt=1, created_at=CREATED_AT,
                    output=jev.HANDOFF, root=root, runner=missing_runner, opener=opener,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("missing Worker was accepted")
        assert calls == [[TOOLS["wrangler"], "secret", "list", "--name", WORKER_NAME, "--format", "json"]]
        assert not writes
        assert not (root / jev.HANDOFF).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)

    # Deletion after preflight: direct provider PUT returns 404. Wrangler secret put
    # is never invoked, so its createDraftWorker fallback is unreachable.
    root = workers_root()
    calls = []
    writes = []
    try:
        list_count = 0

        def race_runner(argv, input_data, env):
            nonlocal list_count
            command = list(argv)
            calls.append(command)
            if command[0] == TOOLS["wrangler"]:
                list_count += 1
                assert list_count == 1
                return subprocess.CompletedProcess(argv, 0, stdout=b'[]\n', stderr=b"")
            if command[0] == TOOLS["sops"]:
                return subprocess.CompletedProcess(argv, 0, stdout=b'{"JEV_API_KEY":"fixture-secret"}\n', stderr=b"")
            raise AssertionError(command)

        def gone_opener(request, **_kwargs):
            writes.append(request)
            return FakeProviderResponse(status=404)

        with environment(project_env()):
            try:
                jev.project(
                    envs_sha="a" * 40, run_id=1, run_attempt=1, created_at=CREATED_AT,
                    output=jev.HANDOFF, root=root, runner=race_runner, opener=gone_opener,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("deleted Worker write was accepted")
        assert len(writes) == 1
        assert not any(command[0] == TOOLS["wrangler"] and "put" in command for command in calls)
        assert not (root / jev.HANDOFF).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_workers_put_response_protocol() -> None:
    cases = [
        ("success-false", b'{"success":false,"result":{"name":"JEV_API_KEY","type":"secret_text"}}', False),
        ("malformed-json", b'not-json', False),
        ("wrong-name", b'{"success":true,"result":{"name":"NOT_JEV_API_KEY","type":"secret_text"}}', False),
        ("wrong-type", b'{"success":true,"result":{"name":"JEV_API_KEY","type":"plain_text"}}', False),
        ("missing-result", b'{"success":true}', False),
        ("exact", b'{"success":true,"result":{"name":"JEV_API_KEY","type":"secret_text"}}', True),
    ]
    for label, body, accepted in cases:
        calls = []
        def opener(request, **_kwargs):
            calls.append(request)
            return FakeProviderResponse(body=body)

        try:
            jev._workers_secret_put(
                account_id=ACCOUNT_ID,
                worker_name=WORKER_NAME,
                secret_name="JEV_API_KEY",
                secret="fixture-secret",
                token="provider-token-fixture",
                opener=opener,
            )
        except jev.EnvsError:
            if accepted:
                raise AssertionError(f"valid provider response was rejected: {label}")
        else:
            if not accepted:
                raise AssertionError(f"invalid provider response was accepted: {label}")
        assert len(calls) == 1


def test_workers_readback_exact_json_only() -> None:
    # Pure parser: exact target name succeeds; aliases, duplicates and malformed shapes do not.
    assert jev.parse_workers_secret_list(
        b'[{"name":"JEV_API_KEY","type":"secret_text"}]\n', "JEV_API_KEY"
    )[0]["name"] == "JEV_API_KEY"
    rejected = [
        b'[{"name":"NOT_JEV_API_KEY","type":"secret_text"}]\n',
        b'[{"name":"JEV_API_KEY","type":"plain_text"}]\n',
        b'[{"name":"JEV_API_KEY","type":"unknown"}]\n',
        b'[{"name":"JEV_API_KEY","type":"secret_key"}]\n',
        b'JEV_API_KEY\n',
        b'{"name":"JEV_API_KEY","type":"secret_text"}\n',
        b'[{"name":"JEV_API_KEY","type":"secret_text"},{"name":"JEV_API_KEY","type":"secret_text"}]\n',
        b'[{"name":"JEV_API_KEY","type":"secret_text","extra":"x"}]\n',
    ]
    for output in rejected:
        try:
            jev.parse_workers_secret_list(output, "JEV_API_KEY")
        except jev.EnvsError:
            pass
        else:
            raise AssertionError(f"invalid Workers list output was accepted: {output!r}")

    # A negative stderr string never compensates for stdout lacking the exact entry.
    root = workers_root()
    writes = []
    list_count = 0
    try:
        def runner(argv, input_data, env):
            nonlocal list_count
            command = list(argv)
            if command[0] == TOOLS["wrangler"]:
                list_count += 1
                return subprocess.CompletedProcess(
                    argv, 0, stdout=b'[]\n',
                    stderr=b"JEV_API_KEY is missing" if list_count == 2 else b"",
                )
            if command[0] == TOOLS["sops"]:
                return subprocess.CompletedProcess(argv, 0, stdout=b'{"JEV_API_KEY":"fixture-secret"}\n', stderr=b"")
            raise AssertionError(command)

        def opener(request, **_kwargs):
            writes.append(request)
            return FakeProviderResponse()

        with environment(project_env()):
            try:
                jev.project(
                    envs_sha="a" * 40, run_id=1, run_attempt=1, created_at=CREATED_AT,
                    output=jev.HANDOFF, root=root, runner=runner, opener=opener,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("stderr description was accepted as presence")
        assert len(writes) == 1
        assert not (root / jev.HANDOFF).exists()
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_workers_target_and_receipt_binding() -> None:
    # Environment account mismatch stops before any provider/decrypt command.
    root = workers_root()
    calls = []
    try:
        def runner(argv, input_data, env):
            calls.append(list(argv))
            raise AssertionError("tool ran before account binding")

        with environment(project_env(CLOUDFLARE_ACCOUNT_ID="f" * 32)):
            try:
                jev.project(
                    envs_sha="a" * 40, run_id=1, run_attempt=1, created_at=CREATED_AT,
                    output=jev.HANDOFF, root=root, runner=runner,
                )
            except jev.EnvsError:
                pass
            else:
                raise AssertionError("wrong Workers account was accepted")
        assert not calls
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)

    target = worker_target()
    base = jev.build_receipt(
        envs_sha="a" * 40, ciphertext_sha256="b" * 64, target=target,
        run_id=123, run_attempt=1, created_at=CREATED_AT,
    )
    jev.validate_receipt(base, target)
    mutations = []
    value = copy.deepcopy(base); value["target"]["account_id"] = "f" * 32; mutations.append(value)
    value = copy.deepcopy(base); value["target"]["worker_name"] = "other-worker"; mutations.append(value)
    value = copy.deepcopy(base); value["target"]["secret_name"] = "OTHER"; mutations.append(value)
    value = copy.deepcopy(base); value["effect"]["operation"] = "cloudflare_pages_secret_put"; mutations.append(value)
    pages = jev.build_receipt(
        envs_sha="a" * 40, ciphertext_sha256="b" * 64, target=PAGES_TARGET,
        run_id=123, run_attempt=1, created_at=CREATED_AT,
    )
    mutations.append(pages)
    for value in mutations:
        try:
            jev.validate_receipt(value, target)
        except jev.EnvsError:
            pass
        else:
            raise AssertionError("mismatched Workers receipt was accepted")


def org_world(target_override=None):
    target = target_override or {"provider": "github-org-secret", "organization": "fixture-org", "organization_id": "123",
              "secret_name": "JEV_API_KEY", "repositories": ["fixture-org/ops", "fixture-org/envs"],
              "repository_ids": ["456", "789"]}
    org, ops, envs = target["organization"], *target["repositories"]
    org_id = int(target["organization_id"])
    ops_id, envs_id = map(int, target["repository_ids"])
    secret = ("fixture-org-key-" + secrets.token_urlsafe(24)).encode()
    world = {"calls": [], "loads": 0, "writes": 0, "key_reads": 0, "fault": None}
    key = {"key_id": "fixture-key-id", "key": base64.b64encode(b"x" * 32).decode()}

    def loader():
        world["loads"] += 1
        return secret

    def runner(argv, stdin, env):
        world["calls"].append((list(argv), stdin))
        assert argv[0] == TOOLS["gh"] and env["GH_HOST"] == "github.com"
        assert env["GH_TOKEN"] == "fixture-controller-token"
        assert "JEV_API_KEY" not in env and "SOPS_AGE_KEY" not in env
        assert not any(secret.decode() in item for item in [*argv, *env.values()])
        if world["fault"] == "permission" and "public-key" in argv[-1]:
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=secret)
        if argv[1:3] == ["secret", "set"]:
            assert argv[3:] == ["JEV_API_KEY", "--app", "actions", "--org", org, "--no-store"]
            assert stdin == secret and world["loads"] == 1 and world["writes"] == 0
            stdout = b"not-base64!" if world["fault"] == "cipher" else base64.b64encode(b"synthetic-sealed-value") + b"\n"
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")
        assert argv[1:4] in (["api", "-X", "GET"], ["api", "-X", "PUT"])
        route = argv[4]
        if argv[3] == "PUT":
            world["writes"] += 1
            assert route == f"orgs/{org}/actions/secrets/JEV_API_KEY" and argv[5:] == ["--input", "-"]
            payload = json.loads(stdin)
            assert set(payload) == {"encrypted_value", "key_id", "visibility", "selected_repository_ids"}
            assert payload["visibility"] == "selected" and payload["selected_repository_ids"] == [ops_id, envs_id]
            assert payload["key_id"] == key["key_id"] and secret not in stdin
            if world["fault"] == "write":
                raise RuntimeError(secret.decode())
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        assert stdin is None
        owner = {"id": org_id, "login": org, "type": "Organization"}
        if route == f"orgs/{org}":
            value = owner
        elif route == f"orgs/{org}/actions/secrets?per_page=100":
            value = {"total_count": 0, "secrets": []}
            if world["fault"] == "already-slot":
                value = {"total_count": 1, "secrets": [{"name": "JEV_API_KEY"}]}
        elif route in (f"repos/{ops}", f"repos/{envs}"):
            value = {"id": ops_id if route.endswith("/ops") else envs_id, "full_name": route[6:], "owner": owner}
            if world["fault"] == "owner":
                value["owner"] = {**owner, "type": "User"}
            if world["fault"] == "repo-id":
                value["id"] = 999
            if world["fault"] == "metadata-json":
                return subprocess.CompletedProcess(argv, 0, stdout=b"not-json", stderr=secret)
        elif route.endswith("public-key"):
            world["key_reads"] += 1
            value = key
            if world["fault"] == "key-drift" and world["key_reads"] > 1:
                value = {**key, "key_id": "different-key"}
        elif route.endswith("/repositories?per_page=100"):
            value = {"total_count": 2, "repositories": [{"id": envs_id, "full_name": envs},
                                                        {"id": ops_id, "full_name": ops}]}
            if world["fault"] == "readback":
                value["repositories"][0]["id"] = 999
            if world["fault"] == "incomplete":
                value["repositories"].pop()
        else:
            assert route == f"orgs/{org}/actions/secrets/JEV_API_KEY"
            value = {"name": "JEV_API_KEY", "visibility": "all" if world["fault"] == "visibility" else "selected"}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(value).encode(), stderr=b"")

    return target, secret, world, loader, runner


def test_org_materialization_primitive() -> None:
    target, secret, world, loader, runner = org_world()
    plan = jev.project_github_org_secret(target=target, tools=TOOLS, authorization={"GH_TOKEN": "fixture-controller-token"},
                                       secret_loader=loader, runner=runner, apply=False)
    assert world["loads"] == 0 and world["writes"] == 0 and plan["readback"] == "NOT_RUN"
    target, secret, world, loader, runner = org_world()
    result = jev.project_github_org_secret(target=target, tools=TOOLS, authorization={"GH_TOKEN": "fixture-controller-token"},
                                         secret_loader=loader, runner=runner)
    assert world["loads"] == 1 and world["writes"] == 1
    assert result == {"operation": "github_org_secret_put", "target": target,
                      "readback": "SECRET_NAME_AND_SELECTED_REPOSITORY_IDS", "provider_use": "NOT_RUN"}
    assert secret.decode() not in json.dumps(result) and "fixture-controller-token" not in json.dumps(result)
    assert "secret_value" not in json.dumps(result) and "receipt" not in result and "status" not in result
    for fault in ("permission", "owner", "repo-id", "metadata-json", "key-drift", "cipher", "write", "readback", "incomplete", "visibility"):
        target, secret, world, loader, runner = org_world()
        world["fault"] = fault
        try:
            jev.project_github_org_secret(target=target, tools=TOOLS, authorization={"GH_TOKEN": "fixture-controller-token"},
                                         secret_loader=loader, runner=runner)
        except jev.EnvsError as error:
            assert secret.decode() not in str(error) and "fixture-controller-token" not in str(error)
            if fault in ("write", "readback", "incomplete", "visibility"):
                assert "unresolved; do not repeat" in str(error) and world["writes"] == 1
            else:
                assert world["writes"] == 0
            if fault in ("permission", "owner", "repo-id", "metadata-json"):
                assert world["loads"] == 0
        else:
            raise AssertionError("invalid Org state was accepted")
    for auth in ({}, {"GH_TOKEN": ""}, {"GITHUB_TOKEN": "fixture"}, {"GH_TOKEN": "fixture", "fallback": "x"}):
        target, secret, world, loader, runner = org_world()
        try:
            jev.project_github_org_secret(target=target, tools=TOOLS, authorization=auth, secret_loader=loader, runner=runner)
        except jev.EnvsError:
            assert world["calls"] == [] and world["loads"] == 0
        else:
            raise AssertionError("ambient or missing Org authority was accepted")
    for malformed in (b"", b"x" * (48 * 1024 + 1), "not-bytes"):
        target, secret, world, loader, runner = org_world()
        try:
            jev.project_github_org_secret(target=target, tools=TOOLS, authorization={"GH_TOKEN": "fixture-controller-token"},
                                         secret_loader=lambda: malformed, runner=runner)
        except jev.EnvsError:
            assert world["writes"] == 0 and not any(call[0][1:3] == ["secret", "set"] for call in world["calls"])
        else:
            raise AssertionError("invalid plaintext input was accepted")


def test_org_setup_route() -> None:
    def refuse(call) -> None:
        try:
            call()
        except jev.EnvsError:
            return
        raise AssertionError("invalid Org setup or receipt was accepted")

    for fault in (None, "controller", "permission", "decrypt", "duplicate-payload", "payload-field",
                  "key-mode", "auth-mode", "source", "handoff", "already-slot", "write", "readback"):
        with tempfile.TemporaryDirectory(prefix="envs-org-setup-test-") as tmp:
            private = Path(tmp)
            auth = private / "gh"
            auth.mkdir(mode=0o700)
            (auth / "hosts.yml").write_text("fixture only\n")
            (auth / "hosts.yml").chmod(0o600)
            identity = private / "oci-dev.key"
            identity.write_text("fixture identity\n")
            identity.chmod(0o600)
            root = private / "repo"
            # Setup fixtures start before materialization; retain the real public receipt in ROOT.
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "*.pyc", Path(jev.ORG_HANDOFF).name))
            target, secret, world, _, delegated = org_world(copy.deepcopy(jev.ORG_TARGET))
            private_calls = []

            def runner(argv, stdin, env):
                private_calls.append((list(argv), stdin, dict(env)))
                if argv[0] == TOOLS["sops"]:
                    world["loads"] += 1
                    assert env["SOPS_AGE_KEY_FILE"] == str(identity) and "SOPS_AGE_KEY" not in env
                    assert stdin is None
                    if fault == "decrypt":
                        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=secret)
                    body = json.dumps({"JEV_API_KEY": secret.decode()}).encode()
                    if fault == "duplicate-payload":
                        body = b'{"JEV_API_KEY":"x","JEV_API_KEY":"y"}'
                    if fault == "payload-field":
                        body = json.dumps({"JEV_API_KEY": secret.decode(), "extra": "x"}).encode()
                    return subprocess.CompletedProcess(argv, 0, stdout=body, stderr=b"")
                if list(argv[1:3]) == ["auth", "token"]:
                    assert env["GH_CONFIG_DIR"] == str(auth) and "GH_TOKEN" not in env and "GITHUB_TOKEN" not in env
                    return subprocess.CompletedProcess(argv, 0, stdout=b"fixture-controller-token\n", stderr=b"")
                if list(argv[1:]) == ["api", "-X", "GET", "user"]:
                    login = "other" if fault == "controller" else jev.ORG_CONTROLLER
                    return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"login": login, "type": "User"}).encode(), stderr=b"")
                return delegated(argv, stdin, env)

            if fault in ("permission", "already-slot", "write", "readback"):
                world["fault"] = fault
            if fault == "key-mode":
                identity.chmod(0o644)
            if fault == "auth-mode":
                (auth / "hosts.yml").chmod(0o644)
            if fault == "handoff":
                (root / jev.ORG_HANDOFF).parent.mkdir(exist_ok=True)
                (root / jev.ORG_HANDOFF).write_text("{}")
            source = "b" * 40 if fault == "source" else "a" * 40
            with environment({"ENVS_EFFECT_TOOLCHAIN": MANIFEST, "GH_TOKEN": "ambient-token-must-not-be-used"}):
                if fault is None:
                    plan = jev.org_projection(envs_sha=source, auth_config=auth, identity=identity, root=root, runner=runner)
                    assert plan["kind"] == jev.ORG_PLAN_KIND and plan["projection"] == "NOT_RUN"
                    assert world["loads"] == 0 and world["writes"] == 0 and not (root / jev.ORG_HANDOFF).exists()
                    result = jev.org_projection(envs_sha=source, auth_config=auth, identity=identity, apply=True, root=root, runner=runner)
                    jev.validate_org_receipt(result)
                    assert world["loads"] == 1 and world["writes"] == 1 and result["provider_use"] == "NOT_RUN"
                    assert json.loads((root / jev.ORG_HANDOFF).read_text()) == result
                    assert secret.decode() not in json.dumps(result) and "fixture-controller-token" not in json.dumps(result)
                    refuse(lambda: jev.org_projection(envs_sha=source, auth_config=auth, identity=identity,
                                                         apply=True, root=root, runner=runner))
                    assert world["writes"] == 1
                    mutations = [dict(result, provider_use="PASS"), dict(result, secret_value="PRIVATE-CANARY"),
                                 dict(result, source="proposals"), dict(result, created_at="not-a-time"),
                                 dict(result, kind=jev.ORG_PLAN_KIND), dict(result, target={**result["target"], "visibility": "all"})]
                    for altered in mutations:
                        refuse(lambda: jev.validate_org_receipt(altered))
                else:
                    try:
                        jev.org_projection(envs_sha=source, auth_config=auth, identity=identity, apply=True, root=root, runner=runner)
                    except jev.EnvsError as error:
                        assert secret.decode() not in str(error) and "fixture-controller-token" not in str(error)
                        assert world["writes"] == int(fault in ("write", "readback"))
                        if fault in ("controller", "permission", "key-mode", "auth-mode", "source", "handoff", "already-slot"):
                            assert world["loads"] == 0
                    else:
                        raise AssertionError("invalid Org setup state was accepted")


def test_org_setup_cli_mode() -> None:
    args = ["project-org-secret", "--envs-sha", "a" * 40,
            "--auth-config", "/work/repos/.auth/roccho-dev/gh",
            "--identity", "/work/repos/.auth/roccho-dev/age/oci-dev.key"]
    for apply in (False, True):
        calls = []
        def fake(**kwargs):
            calls.append(kwargs)
            return {"kind": jev.ORG_PLAN_KIND, "projection": "NOT_RUN"}
        with patch.object(jev, "org_projection", fake), patch("builtins.print"):
            assert jev.main(args + (["--apply"] if apply else [])) == 0
        assert len(calls) == 1 and calls[0]["apply"] is apply
        assert calls[0]["auth_config"] == Path(args[4]) and calls[0]["identity"] == Path(args[6])


def test_receipt_mutations() -> None:
    base = jev.build_receipt(
        envs_sha="a" * 40,
        ciphertext_sha256="b" * 64,
        target=PAGES_TARGET,
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--sops")
    parser.add_argument("--age-keygen")
    args = parser.parse_args()
    assert (args.sops is None) == (args.age_keygen is None), "--sops and --age-keygen go together"
    try:
        jev.validate_contracts(ROOT)
        state = jev.readiness(ROOT)
        assert state["physical_dev_projection"] == "NOT_CONFIGURED"
        assert state["provider_handoff_receipt"] == "ABSENT"
        assert state["consumer_runtime_readiness"] == "OUT_OF_SCOPE"
        test_author()
        test_author_red_inputs()
        test_author_oci()
        test_targets_are_separate()
        test_author_oci_red()
        test_committed_oci_state()
        test_author_target_cli()
        test_project()
        test_project_red_inputs()
        test_workers_exact_readback_and_no_wrangler_create_path()
        test_workers_missing_or_deleted_worker_never_creates_draft()
        test_workers_put_response_protocol()
        test_workers_readback_exact_json_only()
        test_workers_target_and_receipt_binding()
        test_toolchain_red()
        test_decrypt_failure_has_no_provider_effect()
        test_receipt_mutations()
        test_org_materialization_primitive()
        test_org_setup_route()
        test_org_setup_cli_mode()
        if args.sops is None:
            print("real OCI SOPS roundtrip: NOT RUN (the check workflow runs it with --sops and --age-keygen)")
        else:
            real_oci_roundtrip(args.sops, args.age_keygen)
    finally:
        shutil.rmtree(STORE, ignore_errors=True)
    print("Jev adapter self-test: PASS")


if __name__ == "__main__":
    main()
