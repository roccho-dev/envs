#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
        test_toolchain_red()
        test_decrypt_failure_has_no_provider_effect()
        test_receipt_mutations()
        if args.sops is None:
            print("real OCI SOPS roundtrip: NOT RUN (the check workflow runs it with --sops and --age-keygen)")
        else:
            real_oci_roundtrip(args.sops, args.age_keygen)
    finally:
        shutil.rmtree(STORE, ignore_errors=True)
    print("Jev adapter self-test: PASS")


if __name__ == "__main__":
    main()
