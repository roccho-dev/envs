#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The Jev self-test's fixture store, toolchain manifest and environment helpers are shared, not copied.
SPEC = importlib.util.spec_from_file_location("envs_jev_fixtures", ROOT / "checks/test_jev_api.py")
assert SPEC is not None and SPEC.loader is not None
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
jev = fixtures.jev

RECIPIENT = fixtures.RECIPIENT
OTHER_RECIPIENT = "age1" + "".join(secrets.choice(fixtures.BECH32) for _ in range(58))
ACCOUNT_ID = fixtures.ACCOUNT_ID
TUNNEL_ID = str(uuid.uuid4())
API_TOKEN = "cf-api-token-" + secrets.token_urlsafe(24)
# Provider-shaped token (base64 text); generated per run so it never appears in tracked source.
TOKEN = secrets.token_urlsafe(180)
SOPS_ENV_KEYS = {"HOME", "TMPDIR", "LANG", "LC_ALL", "CI", "PATH", "SOPS_AGE_RECIPIENTS"}


def rent_env(**overrides: str) -> dict[str, str]:
    values = {
        "ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST,
        "CLOUDFLARE_API_TOKEN": API_TOKEN,
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID,
        "RENT_TUNNEL_ID": TUNNEL_ID,
        "RENT_AGE_RECIPIENT": RECIPIENT,
    }
    values.update(overrides)
    return values


def ciphertext(recipients: tuple[str, ...] = (RECIPIENT,), key: str = jev.RENT_KEY, extra: str = "") -> bytes:
    lines = "".join(f"    - recipient: {item}\n" for item in recipients)
    return f"{key}: ENC[AES256_GCM,data:fixture]\n{extra}sops:\n  age:\n{lines}".encode()


def provider(body: object) -> bytes:
    return json.dumps(body).encode()


class Provider:
    def __init__(self, body: bytes | Exception) -> None:
        self.body = body
        self.calls: list[tuple[str, str, str | None, float]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> bytes:
        self.calls.append((request.full_url, request.get_method(), request.get_header("Authorization"), timeout))
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class Sops:
    def __init__(self, output: bytes, returncode: int = 0) -> None:
        self.output = output
        self.returncode = returncode
        self.calls: list[tuple[list[str], bytes | None, dict[str, str]]] = []

    def __call__(self, argv, input_data, env):
        self.calls.append((list(argv), input_data, dict(env)))
        return subprocess.CompletedProcess(argv, self.returncode, stdout=self.output, stderr=b"")


def no_secret_in_tree(root: Path) -> None:
    for path in jev.repository_files(root):
        data = path.read_bytes()
        for value in (TOKEN, API_TOKEN, ACCOUNT_ID, TUNNEL_ID):
            assert value.encode() not in data, f"{path.relative_to(root)} carries a live value"


def test_rent_author() -> None:
    root = fixtures.copy_root()
    fetch = Provider(provider({"success": True, "errors": [], "messages": [], "result": TOKEN}))
    sops = Sops(ciphertext())
    try:
        with fixtures.environment(rent_env()):
            result = jev.rent_author(root, sops, fetch)
        assert result == {
            "kind": "envs.rentTunnelAuthoringResult.v1", "status": "PASS", "ciphertext": jev.RENT_CIPHERTEXT.as_posix(),
            "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
        }
        assert fetch.calls == [(
            f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/cfd_tunnel/{TUNNEL_ID}/token",
            "GET", f"Bearer {API_TOKEN}", jev.RETRIEVAL_TIMEOUT,
        )]
        assert len(sops.calls) == 1
        argv, stdin, env = sops.calls[0]
        assert argv == [fixtures.TOOLS["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"]
        assert json.loads(stdin) == {jev.RENT_KEY: TOKEN}
        assert set(env) <= SOPS_ENV_KEYS and env["SOPS_AGE_RECIPIENTS"] == RECIPIENT
        assert not any(value in item for value in (TOKEN, API_TOKEN) for item in [*argv, *env.values()])
        assert TOKEN not in json.dumps(result)
        contracts = jev.validate_contracts(root)
        assert contracts["environments"][jev.RENT_PLANE]["migration_state"] == "ACTIVE"
        assert contracts["environments"]["dev.authoring"]["migration_state"] == "NOT_CONFIGURED"
        no_secret_in_tree(root)
        # A second run (rotation) over the committed ciphertext is accepted: its recipient metadata is not a leak.
        with fixtures.environment(rent_env()):
            jev.rent_author(root, Sops(ciphertext()), Provider(provider({"success": True, "result": TOKEN})))
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def expect_rent_red(values: dict[str, str], *, mutate=None, body: bytes | Exception | None = None,
                    output: bytes | None = None, returncode: int = 0, fetched: bool = False) -> None:
    root = fixtures.copy_root()
    fetch = Provider(provider({"success": True, "result": TOKEN}) if body is None else body)
    sops = Sops(ciphertext() if output is None else output, returncode)
    try:
        if mutate is not None:
            mutate(root)
        before = (root / jev.ENVIRONMENTS).read_bytes()
        with fixtures.environment(values):
            try:
                jev.rent_author(root, sops, fetch)
            except jev.EnvsError as exc:
                message = str(exc)
            else:
                raise AssertionError("invalid rent tunnel state was accepted")
        assert not any(value in message for value in (TOKEN, API_TOKEN, ACCOUNT_ID, TUNNEL_ID)), message
        assert len(fetch.calls) == (1 if fetched else 0), "provider was called before the input gate"
        assert output is not None or not sops.calls, "sops ran before a valid provider token"
        assert not (root / jev.RENT_CIPHERTEXT).exists()
        assert (root / jev.ENVIRONMENTS).read_bytes() == before
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_rent_red_inputs() -> None:
    for name in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "RENT_TUNNEL_ID", "RENT_AGE_RECIPIENT"):
        expect_rent_red(rent_env(**{name: ""}))
    # Exactly one target recipient: lists, duplicates and malformed recipients are RED before any effect.
    expect_rent_red(rent_env(RENT_AGE_RECIPIENT=f"{RECIPIENT},{OTHER_RECIPIENT}"))
    expect_rent_red(rent_env(RENT_AGE_RECIPIENT=f"{RECIPIENT},{RECIPIENT}"))
    expect_rent_red(rent_env(RENT_AGE_RECIPIENT=RECIPIENT.upper()))
    expect_rent_red(rent_env(RENT_AGE_RECIPIENT=f" {RECIPIENT}"))
    expect_rent_red(rent_env(RENT_TUNNEL_ID=TUNNEL_ID.upper()))
    expect_rent_red(rent_env(RENT_TUNNEL_ID=TUNNEL_ID.replace("-", "")))
    expect_rent_red(rent_env(CLOUDFLARE_ACCOUNT_ID=ACCOUNT_ID[:31]))
    expect_rent_red(rent_env(CLOUDFLARE_API_TOKEN="two words"))
    expect_rent_red(rent_env(CLOUDFLARE_API_TOKEN=API_TOKEN + "\n"))
    # Live Variable values must not be stored in Git.
    for value in (RECIPIENT, TUNNEL_ID, ACCOUNT_ID):
        expect_rent_red(rent_env(), mutate=lambda root, value=value: fixtures.append(root / "README.md", f"\n{value}\n"))
    # The API token already in Git is RED before the provider call; the fetched tunnel token in Git is RED before SOPS.
    expect_rent_red(rent_env(), mutate=lambda root: fixtures.append(root / "README.md", f"\n{API_TOKEN}\n"))
    expect_rent_red(rent_env(), mutate=lambda root: fixtures.append(root / "README.md", f"\n{TOKEN}\n"), fetched=True)
    outside = Path(tempfile.mkdtemp(prefix="envs-rent-outside-"))
    try:
        for values, mutate in fixtures.toolchain_red_cases(outside / "toolchain.json"):
            expect_rent_red(rent_env(**values), mutate=mutate)
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_rent_provider_red() -> None:
    for body in (
        provider({"success": False, "result": TOKEN}),
        provider({"success": "true", "result": TOKEN}),
        provider({"success": True}),
        provider({"success": True, "result": None}),
        provider({"success": True, "result": ""}),
        provider({"success": True, "result": "x" * 4097}),
        provider({"success": True, "result": TOKEN + "\n"}),
        provider({"success": True, "result": TOKEN[:20] + " " + TOKEN[20:]}),
        provider([TOKEN]),
        b"<html>" + TOKEN.encode(),
        b"\xff" + TOKEN.encode(),
        jev.EnvsError("Cloudflare tunnel token retrieval failed"),
    ):
        expect_rent_red(rent_env(), body=body, fetched=True)


def test_rent_ciphertext_red() -> None:
    for output, returncode in (
        (ciphertext((RECIPIENT, OTHER_RECIPIENT)), 0),
        (ciphertext((OTHER_RECIPIENT,)), 0),
        (ciphertext(()), 0),
        (ciphertext(key="JEV_API_KEY"), 0),
        (ciphertext(extra=f"note: {TOKEN}\n"), 0),
        (ciphertext(extra="note: plain\n"), 0),
        (ciphertext() + f"# {RECIPIENT}\n".encode(), 0),
        (ciphertext(), 1),
    ):
        expect_rent_red(rent_env(), body=None, output=output, returncode=returncode, fetched=True)


def test_committed_state_red() -> None:
    def ciphertext_without_state(root: Path) -> None:
        (root / "ciphertexts").mkdir(exist_ok=True)
        (root / jev.RENT_CIPHERTEXT).write_bytes(ciphertext())

    def state_without_ciphertext(root: Path) -> None:
        jev.set_dev_active(root, True, (jev.RENT_PLANE,))

    def two_recipients(root: Path) -> None:
        ciphertext_without_state(root)
        (root / jev.RENT_CIPHERTEXT).write_bytes(ciphertext((RECIPIENT, OTHER_RECIPIENT)))
        jev.set_dev_active(root, True, (jev.RENT_PLANE,))

    for mutate in (ciphertext_without_state, state_without_ciphertext, two_recipients):
        root = fixtures.copy_root()
        try:
            mutate(root)
            try:
                jev.validate_contracts(root)
            except jev.EnvsError:
                continue
            raise AssertionError("inconsistent rent tunnel state was accepted")
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)


def test_fetch_boundary() -> None:
    # No network is touched: the CA bundle gate is RED first, and a redirect is never followed.
    request = urllib.request.Request("https://api.cloudflare.com/client/v4/", method="GET")
    for bundle in ("", "/etc/ssl/certs/ca-certificates.crt", str(fixtures.STORE / "absent.crt")):
        with fixtures.environment({"SSL_CERT_FILE": bundle}):
            try:
                jev.default_fetch(request, 0.001)
            except jev.EnvsError:
                continue
            raise AssertionError("retrieval ran without the repo-owned CA bundle")
    assert jev.NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://example.invalid/") is None


# Rent client (windows #14): the root's credentials output projected to one recipient; values generated per run.
CLIENT_ID = "ci" + secrets.token_hex(16) + ".access"
CLIENT_SECRET = secrets.token_hex(32)


def credentials(**overrides: object) -> bytes:
    value: dict[str, object] = {"tunnel_token": TOKEN, "service_token_id": CLIENT_ID, "service_token_value": CLIENT_SECRET}
    value.update(overrides)
    return json.dumps({key: item for key, item in value.items() if item is not None}).encode()


def client_ciphertext(recipients: tuple[str, ...] = (RECIPIENT,), keys: tuple[str, ...] = jev.CLIENT_KEYS, extra: str = "") -> bytes:
    lines = "".join(f"    - recipient: {item}\n" for item in recipients)
    fields = "".join(f"{key}: ENC[AES256_GCM,data:fixture]\n" for key in keys)
    return f"{fields}{extra}sops:\n  age:\n{lines}".encode()


def client_env(**overrides: str) -> dict[str, str]:
    values = {"ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST, jev.CLIENT_RECIPIENT: RECIPIENT}
    values.update(overrides)
    return values


def test_client_author() -> None:
    root = fixtures.copy_root()
    sops = Sops(client_ciphertext())
    try:
        with fixtures.environment(client_env()):
            result = jev.client_author(credentials(), root, sops)
        assert result == {
            "kind": "envs.rentClientAuthoringResult.v1", "status": "PASS", "ciphertext": jev.CLIENT_CIPHERTEXT.as_posix(),
            "recipient_count": 1, "target_apply": "NOT_RUN", "client_access": "UNPROVED",
        }
        assert len(sops.calls) == 1
        argv, stdin, env = sops.calls[0]
        assert argv == [fixtures.TOOLS["sops"], "--encrypt", "--input-type", "json", "--output-type", "yaml", "/dev/stdin"]
        # Only the service token pair is projected; the tunnel token in the same output never reaches SOPS.
        assert json.loads(stdin) == {"RENT_ACCESS_CLIENT_ID": CLIENT_ID, "RENT_ACCESS_CLIENT_SECRET": CLIENT_SECRET}
        assert set(env) <= SOPS_ENV_KEYS and env["SOPS_AGE_RECIPIENTS"] == RECIPIENT
        assert not any(value in item for value in (CLIENT_ID, CLIENT_SECRET, TOKEN) for item in [*argv, *env.values()])
        assert not any(value in json.dumps(result) for value in (CLIENT_ID, CLIENT_SECRET))
        contracts = jev.validate_contracts(root)
        assert contracts["environments"][jev.CLIENT_PLANE]["migration_state"] == "ACTIVE"
        assert contracts["environments"][jev.RENT_PLANE]["migration_state"] == "NOT_CONFIGURED"
        for path in jev.repository_files(root):
            data = path.read_bytes()
            assert not any(value.encode() in data for value in (CLIENT_ID, CLIENT_SECRET, TOKEN)), path
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def expect_client_red(values: dict[str, str], body: bytes, *, mutate=None, output: bytes | None = None,
                      returncode: int = 0) -> None:
    root = fixtures.copy_root()
    sops = Sops(client_ciphertext() if output is None else output, returncode)
    try:
        if mutate is not None:
            mutate(root)
        before = (root / jev.ENVIRONMENTS).read_bytes()
        with fixtures.environment(values):
            try:
                jev.client_author(body, root, sops)
            except jev.EnvsError as exc:
                message = str(exc)
            else:
                raise AssertionError("invalid rent client state was accepted")
        assert not any(value in message for value in (CLIENT_ID, CLIENT_SECRET, TOKEN)), message
        assert output is not None or not sops.calls, "sops ran before a valid credential"
        assert not (root / jev.CLIENT_CIPHERTEXT).exists()
        assert (root / jev.ENVIRONMENTS).read_bytes() == before
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_client_red() -> None:
    expect_client_red(client_env(**{jev.CLIENT_RECIPIENT: ""}), credentials())
    expect_client_red(client_env(**{jev.CLIENT_RECIPIENT: f"{RECIPIENT},{OTHER_RECIPIENT}"}), credentials())
    for body in (
        b"not json", credentials(service_token_value=None), credentials(extra="x"), credentials(service_token_id=7),
        credentials(service_token_id=""), credentials(service_token_value="two words"), credentials(service_token_id=CLIENT_ID + "\n"),
        credentials(service_token_value="x" * 1025), credentials(service_token_value="é" + CLIENT_SECRET), b"x" * (jev.RESPONSE_LIMIT + 1),
    ):
        expect_client_red(client_env(), body)
    for value in (CLIENT_ID, CLIENT_SECRET):
        expect_client_red(client_env(), credentials(), mutate=lambda root, value=value: fixtures.append(root / "README.md", f"\n{value}\n"))
    for output, returncode in (
        (client_ciphertext((RECIPIENT, OTHER_RECIPIENT)), 0),
        (client_ciphertext((OTHER_RECIPIENT,)), 0),
        (client_ciphertext(keys=jev.CLIENT_KEYS[:1]), 0),
        (client_ciphertext(extra=f"note: {CLIENT_SECRET}\n"), 0),
        (client_ciphertext(), 1),
    ):
        expect_client_red(client_env(), credentials(), output=output, returncode=returncode)


def run(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False)


def real_roundtrip(sops_bin: str, keygen_bin: str) -> None:
    # The real locked sops encrypts to one throwaway recipient; only that identity decrypts, and tampering is RED.
    sops_path, keygen = os.path.realpath(sops_bin), os.path.realpath(keygen_bin)
    for path in (sops_path, keygen):
        assert path.startswith("/nix/store/") and os.access(path, os.X_OK), f"not a locked store tool: {path}"
    work = Path(tempfile.mkdtemp(prefix="envs-rent-roundtrip-"))
    base = {"PATH": os.path.dirname(sops_path), "HOME": str(work)}
    try:
        def identity(name: str) -> tuple[Path, str]:
            key = work / name
            assert run([keygen, "-o", str(key)], base).returncode == 0, "age-keygen failed"
            public = run([keygen, "-y", str(key)], base)
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
        data = jev.encrypt_rent_token(TOKEN, recipient, tools, runner)
        assert len(calls) == 1 and not any(TOKEN in item for item in calls[0])
        assert TOKEN.encode() not in data and b"AGE-SECRET-KEY-1" not in data
        jev.validate_rent_ciphertext(data, TOKEN.encode(), recipient)
        cipher = work / "dev-rent-tunnel.sops.yaml"
        cipher.write_bytes(data)

        def decrypt(path: Path, identity_file: Path) -> subprocess.CompletedProcess[bytes]:
            return run([sops_path, "--decrypt", "--input-type", "yaml", "--output-type", "json", str(path)],
                       {**base, "SOPS_AGE_KEY_FILE": str(identity_file)})

        opened = decrypt(cipher, key)
        assert opened.returncode == 0, "the target identity could not decrypt"
        assert json.loads(opened.stdout) == {jev.RENT_KEY: TOKEN}, "roundtrip changed the token"

        wrong = decrypt(cipher, other_key)
        assert wrong.returncode != 0 and TOKEN.encode() not in wrong.stdout + wrong.stderr, "another identity decrypted"

        text = data.decode()
        start = text.index("ENC[AES256_GCM,data:") + len("ENC[AES256_GCM,data:")
        tampered = work / "tampered.sops.yaml"
        tampered.write_text(text[:start] + ("A" if text[start] != "A" else "B") + text[start + 1:], encoding="utf-8")
        broken = decrypt(tampered, key)
        assert broken.returncode != 0 and TOKEN.encode() not in broken.stdout + broken.stderr, "tampered ciphertext decrypted"

        # A real ciphertext does not pass as another target's, nor with its recipient metadata swapped.
        for candidate, expected in ((data, other), (text.replace(recipient, other).encode(), recipient)):
            try:
                jev.validate_rent_ciphertext(candidate, None, expected)
            except jev.EnvsError:
                continue
            raise AssertionError("a ciphertext for another recipient was accepted")

        before = len(calls)
        try:
            jev.encrypt_rent_token(TOKEN, f"{recipient},{other}", tools, runner)
        except jev.EnvsError:
            pass
        else:
            raise AssertionError("two recipients were accepted")
        assert len(calls) == before, "sops ran for a recipient list"

        # The client envelope: both slot lines, one recipient; each line extracts exactly as place.ps1 reads it.
        client = jev.encrypt_client_credential(CLIENT_ID, CLIENT_SECRET, recipient, tools, runner)
        assert CLIENT_ID.encode() not in client and CLIENT_SECRET.encode() not in client
        client_file = work / "dev-rent-client.sops.yaml"
        client_file.write_bytes(client)
        for key, expected in zip(jev.CLIENT_KEYS, (CLIENT_ID, CLIENT_SECRET)):
            extracted = run([sops_path, "--decrypt", "--input-type", "yaml", "--extract", f'["{key}"]', str(client_file)],
                            {**base, "SOPS_AGE_KEY_FILE": str(key)})
            assert extracted.returncode == 0 and extracted.stdout.rstrip(b"\r\n") == expected.encode(), f"{key} extraction differs"
        refused = decrypt(client_file, other_key)
        assert refused.returncode != 0 and CLIENT_SECRET.encode() not in refused.stdout + refused.stderr, "another identity decrypted"
        print(f"real SOPS roundtrip: PASS (sops={sops_path}, age-keygen={keygen})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sops")
    parser.add_argument("--age-keygen")
    args = parser.parse_args()
    assert (args.sops is None) == (args.age_keygen is None), "--sops and --age-keygen go together"
    try:
        jev.validate_contracts(ROOT)
        test_rent_author()
        test_rent_red_inputs()
        test_rent_provider_red()
        test_rent_ciphertext_red()
        test_committed_state_red()
        test_fetch_boundary()
        test_client_author()
        test_client_red()
        if args.sops is None:
            print("real SOPS roundtrip: NOT RUN (the check workflow runs it with --sops and --age-keygen)")
        else:
            real_roundtrip(args.sops, args.age_keygen)
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("rent tunnel adapter self-test: PASS")


if __name__ == "__main__":
    main()
