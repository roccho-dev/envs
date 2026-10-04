#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
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


# Persistent root (windows #8/#14): every input generated per run; the client envelope has its own recipient.
ROOT_CLIENT_RECIPIENT = "age1" + "".join(secrets.choice(fixtures.BECH32) for _ in range(58))
ROOT_VALUES = {
    "CLOUDFLARE_API_TOKEN": API_TOKEN, "AWS_ACCESS_KEY_ID": secrets.token_hex(16),
    "AWS_SECRET_ACCESS_KEY": secrets.token_hex(32), "RENT_STATE_PASSPHRASE": secrets.token_hex(32),
    "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID, "CLOUDFLARE_ZONE_ID": secrets.token_hex(16),
    "RENT_HOSTNAME": f"rent-{secrets.token_hex(4)}.example.invalid", "RENT_ORIGIN_SERVICE": f"ssh://origin-{secrets.token_hex(4)}:2222",
    "RENT_SERVICE_TOKEN_DURATION": f"{1000 + secrets.randbelow(8000)}h", "RENT_STATE_BUCKET": f"rent-state-{secrets.token_hex(6)}",
    "RENT_STATE_KEY": f"state/{secrets.token_hex(6)}.tfstate", "RENT_AGE_RECIPIENT": RECIPIENT,
    jev.CLIENT_RECIPIENT: ROOT_CLIENT_RECIPIENT,
}
ROOT_SECRET_VALUES = [ROOT_VALUES[name] for name in jev.ROOT_SECRETS]


def root_env(**overrides: str) -> dict[str, str]:
    values = {"ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST, **ROOT_VALUES}
    values.update(overrides)
    return values


class RootRunner:
    # Fake OpenTofu and sops: fail names one step (init, apply, output, sops-rent, sops-client) to return non-zero,
    # with the synthetic (stdout, stderr) of failure.
    def __init__(self, fail: str | None = None, output: bytes | None = None,
                 failure: tuple[bytes, bytes] = (b"", b"")) -> None:
        self.fail = fail
        self.output = credentials() if output is None else output
        self.failure = failure
        self.calls: list[tuple[list[str], bytes | None, dict[str, str]]] = []

    def __call__(self, argv, input_data, env):
        self.calls.append((list(argv), input_data, dict(env or {})))
        recipient = (env or {}).get("SOPS_AGE_RECIPIENTS", "")
        step = argv[2] if argv[0] == fixtures.TOOLS["tofu"] else "sops-rent" if recipient == RECIPIENT else "sops-client"
        if step == self.fail:
            return subprocess.CompletedProcess(argv, 1, stdout=self.failure[0], stderr=self.failure[1])
        body = {"output": self.output, "sops-rent": ciphertext((recipient,)),
                "sops-client": client_ciphertext((recipient,))}.get(step, b"")
        return subprocess.CompletedProcess(argv, 0, stdout=body, stderr=b"")

    def steps(self) -> list[str]:
        return [argv[2] if argv[0] == fixtures.TOOLS["tofu"] else "sops" for argv, _, _ in self.calls]


def root_secrets() -> list[str]:
    return [*ROOT_SECRET_VALUES, TOKEN, CLIENT_ID, CLIENT_SECRET]


def prior_envelopes(root: Path) -> None:
    # A previous run's envelopes and plane state, which a failure before the first write must leave byte-identical.
    for relative, data in ((jev.RENT_CIPHERTEXT, ciphertext()), (jev.CLIENT_CIPHERTEXT, client_ciphertext())):
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_bytes(data)
    jev.set_dev_active(root, True, (jev.RENT_PLANE, jev.CLIENT_PLANE, jev.ROOT_PLANE))
    jev.validate_contracts(root)


def snapshot(root: Path) -> dict[str, bytes | None]:
    return {str(path): (root / path).read_bytes() if (root / path).is_file() else None
            for path in (jev.ENVIRONMENTS, jev.RENT_CIPHERTEXT, jev.CLIENT_CIPHERTEXT)}


# The rent-root cases delete nothing (no recursive deletion in reusable automation): each copied data root and each
# run's scratch stays in the CI runner's temporary space, which ends with the runner.
def test_root_author() -> None:
    root = fixtures.copy_root()
    runner = RootRunner()
    with fixtures.environment(root_env()):
        result = jev.rent_root(root, runner)
    assert result == {
        "kind": "envs.rentRootResult.v1", "status": "PASS",
        "ciphertexts": [jev.RENT_CIPHERTEXT.as_posix(), jev.CLIENT_CIPHERTEXT.as_posix()],
        "target_apply": "NOT_RUN", "client_access": "UNPROVED",
    }
    assert runner.steps() == ["init", "apply", "output", "sops", "sops"], runner.steps()
    init = runner.calls[0][0]
    assert init[3:] == ["-input=false", "-no-color", f"-backend-config=bucket={ROOT_VALUES['RENT_STATE_BUCKET']}",
                        f"-backend-config=key={ROOT_VALUES['RENT_STATE_KEY']}"], init
    assert runner.calls[2][0][3:] == ["-json", "credentials"]
    # Every child's argv is free of values; each OpenTofu child gets exactly the root environment.
    assert not any(value in item for value in root_secrets() for argv, _, _ in runner.calls for item in argv)
    expected = {"PATH", "HOME", "CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                "AWS_ENDPOINT_URL_S3", "AWS_EC2_METADATA_DISABLED", "TF_ENCRYPTION", "TF_VAR_account_id",
                "TF_VAR_zone_id", "TF_VAR_hostname", "TF_VAR_origin_service", "TF_VAR_service_token_duration",
                "TF_IN_AUTOMATION", "TF_INPUT"}
    home = runner.calls[0][2]["HOME"]
    assert home != os.environ.get("HOME") and Path(home).is_dir() and not any(Path(home).iterdir())
    for argv, stdin, env in runner.calls[:3]:
        assert set(env) - {"TMPDIR", "LANG", "LC_ALL", "CI"} == expected, sorted(env)
        assert stdin is None and env["HOME"] == home
        assert env["TF_ENCRYPTION"] == jev.encryption_config("k0", ROOT_VALUES["RENT_STATE_PASSPHRASE"])
        assert env["AWS_ENDPOINT_URL_S3"] == jev.r2_endpoint(ACCOUNT_ID)
        assert env["TF_VAR_service_token_duration"] == ROOT_VALUES["RENT_SERVICE_TOKEN_DURATION"]
    # Each sops child gets only its recipient and the run's fresh HOME, and only its own values on stdin.
    (rent_argv, rent_stdin, rent_env), (client_argv, client_stdin, client_env) = runner.calls[3:]
    assert set(rent_env) <= SOPS_ENV_KEYS and rent_env["SOPS_AGE_RECIPIENTS"] == RECIPIENT and rent_env["HOME"] == home
    assert set(client_env) <= SOPS_ENV_KEYS and client_env["SOPS_AGE_RECIPIENTS"] == ROOT_CLIENT_RECIPIENT \
        and client_env["HOME"] == home
    assert json.loads(rent_stdin) == {jev.RENT_KEY: TOKEN}
    assert json.loads(client_stdin) == {"RENT_ACCESS_CLIENT_ID": CLIENT_ID, "RENT_ACCESS_CLIENT_SECRET": CLIENT_SECRET}
    assert not any(value in json.dumps(result) for value in root_secrets())
    contracts = jev.validate_contracts(root)
    for plane in (jev.RENT_PLANE, jev.CLIENT_PLANE, jev.ROOT_PLANE):
        assert contracts["environments"][plane]["migration_state"] == "ACTIVE"
    for path in jev.repository_files(root):
        data = path.read_bytes()
        assert not any(value.encode() in data for value in root_secrets()), path


def expect_root_red(values: dict[str, str], runner: RootRunner, *, prior: bool = False, mutate=None,
                    children: bool = True) -> dict[str, str]:
    # A failure before the first write: RED, no destroy/import/retry, and every envelope and plane file unchanged.
    root = fixtures.copy_root()
    progress: dict[str, str] = {}
    if prior:
        prior_envelopes(root)
    if mutate is not None:
        mutate(root)
    before = snapshot(root)
    with fixtures.environment(values):
        try:
            jev.rent_root(root, runner, progress)
        except jev.EnvsError as exc:
            message = str(exc)
        else:
            raise AssertionError("invalid rent root state was accepted")
    assert not any(value in message for value in root_secrets()), message
    assert snapshot(root) == before, "a failure before the first write changed a file"
    assert progress["stage"] != "write"
    assert bool(runner.calls) == children, runner.steps()
    assert runner.steps().count("apply") <= 1 and not {"destroy", "import", "state"} & set(runner.steps())
    return progress


def test_root_red() -> None:
    # Inputs are RED before any child: each missing input, a malformed passphrase, a live value already in Git.
    for name in ROOT_VALUES:
        assert expect_root_red(root_env(**{name: ""}), RootRunner(), children=False)["stage"] == "gate"
    for passphrase in (ROOT_VALUES["RENT_STATE_PASSPHRASE"].upper(), ROOT_VALUES["RENT_STATE_PASSPHRASE"][:-1],
                       ROOT_VALUES["RENT_STATE_PASSPHRASE"] + "0", "z" * 64):
        expect_root_red(root_env(RENT_STATE_PASSPHRASE=passphrase), RootRunner(), children=False)
    for value in (ROOT_VALUES["AWS_SECRET_ACCESS_KEY"], ROOT_VALUES["RENT_STATE_BUCKET"]):
        expect_root_red(root_env(), RootRunner(), children=False,
                        mutate=lambda root, value=value: fixtures.append(root / "README.md", f"\n{value}\n"))
    # Each step failing, and a malformed root output, before the first write: new and prior envelopes alike.
    for prior in (False, True):
        for fail, stage in (("init", "init"), ("apply", "apply"), ("output", "output"), ("sops-rent", "seal"),
                            ("sops-client", "seal")):
            assert expect_root_red(root_env(), RootRunner(fail), prior=prior)["stage"] == stage
        for body in (b"not json", credentials(extra="x"), credentials(tunnel_token="two words"),
                     credentials(tunnel_token=None), credentials(service_token_id=""), credentials(service_token_value=7)):
            expect_root_red(root_env(), RootRunner(output=body), prior=prior)


def test_root_after_write() -> None:
    # A failure at or after the first write fails the entry without claiming success; the written files stay.
    root = fixtures.copy_root()
    progress: dict[str, str] = {}
    original = jev.set_dev_active

    def broken(*_args, **_kwargs) -> None:
        raise OSError("plane state not written")

    jev.set_dev_active = broken
    try:
        with fixtures.environment(root_env()):
            try:
                jev.rent_root(root, RootRunner(), progress)
            except OSError:
                pass
            else:
                raise AssertionError("a failed plane update was reported as success")
    finally:
        jev.set_dev_active = original
    assert progress["stage"] == "write"
    assert (root / jev.RENT_CIPHERTEXT).is_file() and (root / jev.CLIENT_CIPHERTEXT).is_file()


def test_root_main() -> None:
    # The production entry: a refusal and an unexpected exception print only a closed kind and stage.
    root = fixtures.copy_root()
    original = jev.rent_root

    def leaking(_root, progress):
        progress["stage"] = "apply"
        raise KeyError(API_TOKEN)

    for values, patch, expected in ((root_env(RENT_HOSTNAME=""), None, "RENT_ROOT=RED: envs at gate\n"),
                                    (root_env(), leaking, "RENT_ROOT=RED: other at apply\n")):
        out, err = io.StringIO(), io.StringIO()
        if patch is not None:
            jev.rent_root = patch
        try:
            with fixtures.environment(values), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = jev.main(["--root", str(root), "rent-root"])
        finally:
            jev.rent_root = original
        assert code == 1 and out.getvalue() == "" and err.getvalue() == expected, (code, out.getvalue(), err.getvalue())


# Synthetic init output carries this canary and every root secret, none of which may reach the CLI's output.
INIT_CANARY = "init-canary-" + secrets.token_hex(16)


def root_main(runner: RootRunner, prior: bool) -> tuple[int, str, str, bool]:
    # The production CLI with its own progress, over the fake children; returns code, stdout, stderr and whether the
    # three snapshot files are byte-identical afterwards.
    root = fixtures.copy_root()
    if prior:
        prior_envelopes(root)
    before = snapshot(root)
    original = jev.rent_root
    jev.rent_root = lambda data_root, progress: original(data_root, runner, progress)
    out, err = io.StringIO(), io.StringIO()
    try:
        with fixtures.environment(root_env()), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = jev.main(["--root", str(root), "rent-root"])
    finally:
        jev.rent_root = original
    return code, out.getvalue(), err.getvalue(), snapshot(root) == before


def test_root_init_hint() -> None:
    # A captured non-zero init child adds exactly one closed, unverified line after the unchanged first line: the
    # observed status, AccessDenied marker and transport-like text, never its output, wording or a cause.
    planted = " ".join([INIT_CANARY, *root_secrets()]).encode()
    for stdout, stderr, hint in (
        (b"", b"operation error S3: HeadObject, https response error StatusCode: 401, RequestID: r",
         "status=401 access_denied=false transient=false"),
        (b"", b"https response error StatusCode: 403, api error AccessDenied: Access Denied",
         "status=403 access_denied=true transient=false"),
        (b"", b"https response error StatusCode: 403, api error SignatureDoesNotMatch",
         "status=403 access_denied=false transient=false"),
        (b"", b"StatusCode: 403, api error AccessDenied\nStatusCode: 500, api error InternalError",
         "status=multiple access_denied=true transient=false"),
        (b"", b"https response error StatusCode: 503, api error ServiceUnavailable",
         "status=5xx access_denied=false transient=false"),
        (b"", b"https response error StatusCode: 404, api error NoSuchBucket",
         "status=other access_denied=false transient=false"),
        (b"", b"dial tcp: lookup example.invalid: no such host", "status=none access_denied=false transient=true"),
        (b"https response error StatusCode: 401", b"", "status=401 access_denied=false transient=false"),
        (b"", b"", "status=none access_denied=false transient=false"),
        # Unrelated encryption and credential wording is neither a word nor a cause: only the absent facts.
        (b"Initializing the backend...", b"Error: the encryption method is not configured; credentials are set",
         "status=none access_denied=false transient=false"),
    ):
        for prior in (False, True):
            runner = RootRunner("init", failure=(stdout + b"\n" + planted, stderr + b"\n" + planted))
            code, out, err, unchanged = root_main(runner, prior)
            expected = f"RENT_ROOT=RED: envs at init\nRENT_ROOT_INIT_HINT_UNVERIFIED={hint}\n"
            assert code == 1 and out == "" and err == expected, (code, out, err)
            assert runner.steps() == ["init"] and unchanged, runner.steps()
            assert not any(value in err for value in [INIT_CANARY, *root_secrets()])

    # No hint without a captured non-zero init: an init child that never launched, and a later child's failure.
    class Unlaunched(RootRunner):
        def __call__(self, argv, input_data, env):
            self.calls.append((list(argv), input_data, dict(env or {})))
            raise OSError(INIT_CANARY)

    status = b"https response error StatusCode: 403, api error AccessDenied\n" + planted
    for runner, expected, steps in (
        (Unlaunched(), "RENT_ROOT=RED: os at init\n", ["init"]),
        (RootRunner("apply", failure=(status, status)), "RENT_ROOT=RED: envs at apply\n", ["init", "apply"]),
    ):
        code, out, err, unchanged = root_main(runner, False)
        assert code == 1 and out == "" and err == expected, (code, out, err)
        assert runner.steps() == steps and unchanged, runner.steps()


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
        for name, expected in zip(jev.CLIENT_KEYS, (CLIENT_ID, CLIENT_SECRET)):
            extracted = run([sops_path, "--decrypt", "--input-type", "yaml", "--extract", f'["{name}"]', str(client_file)],
                            {**base, "SOPS_AGE_KEY_FILE": str(key)})
            assert extracted.returncode == 0 and extracted.stdout.rstrip(b"\r\n") == expected.encode(), f"{name} extraction differs"
        refused = decrypt(client_file, other_key)
        assert refused.returncode != 0 and CLIENT_SECRET.encode() not in refused.stdout + refused.stderr, "another identity decrypted"
        print(f"real SOPS roundtrip: PASS (sops={sops_path}, age-keygen={keygen})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# A schema-only stand-in for the persistent root: the same enforced encryption and the same sensitive credentials
# output, but no provider, resource or backend. Its values arrive only as TF_VAR_credentials in the OpenTofu child.
ROOT_FIXTURE = """terraform {
  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}

variable "credentials" {
  type      = object({ tunnel_token = string, service_token_id = string, service_token_value = string })
  sensitive = true
}

output "credentials" {
  sensitive = true
  value     = var.credentials
}
"""


def real_root_roundtrip(sops_bin: str, keygen_bin: str, tofu_bin: str) -> None:
    # The closure tofu applies the fixture on encrypted local state; the production seal_root_output then reads the
    # real `tofu output -json credentials` and the real sops seals both envelopes, each for its own throwaway identity.
    sops_path, keygen, tofu_path = (os.path.realpath(item) for item in (sops_bin, keygen_bin, tofu_bin))
    for path in (sops_path, keygen, tofu_path):
        assert path.startswith("/nix/store/") and os.access(path, os.X_OK), f"not a locked store tool: {path}"
    assert not any(value in ROOT_FIXTURE for value in (TOKEN, CLIENT_ID, CLIENT_SECRET))
    work = Path(tempfile.mkdtemp(prefix="envs-rent-root-real-"))
    root = fixtures.copy_root()
    base = {"PATH": os.path.dirname(sops_path), "HOME": str(work)}
    try:
        identities: dict[str, tuple[Path, str]] = {}
        for name in ("rent", "client"):
            key = work / f"{name}.key"
            assert run([keygen, "-o", str(key)], base).returncode == 0, "age-keygen failed"
            public = run([keygen, "-y", str(key)], base)
            assert public.returncode == 0, "age-keygen -y failed"
            identities[name] = (key, public.stdout.decode().strip())
        fixture, home = work / "root", work / "home"
        fixture.mkdir()
        home.mkdir(mode=0o700)
        (fixture / "main.tf").write_text(ROOT_FIXTURE, encoding="utf-8")
        tools = {"tofu": tofu_path, "sops": sops_path}
        env = jev.clean_env(tools, {
            "HOME": str(home), "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
            "TF_ENCRYPTION": jev.encryption_config(jev.ROOT_KEY_NAME, secrets.token_hex(32)),
            "TF_VAR_credentials": credentials().decode(),
        })
        calls: list[list[str]] = []

        def runner(argv, input_data, child_env):
            calls.append(list(argv))
            return jev.default_runner(argv, input_data, child_env)

        jev.tofu(tools, fixture, env, runner, "init", "-input=false", "-no-color")
        jev.tofu(tools, fixture, env, runner, "apply", "-input=false", "-auto-approve", "-no-color")
        state = (fixture / "terraform.tfstate").read_bytes()
        assert not any(value.encode() in state for value in (TOKEN, CLIENT_ID, CLIENT_SECRET)), "fixture state is plaintext"
        result = jev.seal_root_output(root, tools, fixture, env, runner, identities["rent"][1], identities["client"][1])
        assert [argv[2] if argv[0] == tofu_path else "sops" for argv in calls] == ["init", "apply", "output", "sops", "sops"]
        assert not any(value in item for value in (TOKEN, CLIENT_ID, CLIENT_SECRET) for argv in calls for item in argv)
        assert not any(value in json.dumps(result) for value in (TOKEN, CLIENT_ID, CLIENT_SECRET))
        contracts = jev.validate_contracts(root)
        assert all(contracts["environments"][plane]["migration_state"] == "ACTIVE"
                   for plane in (jev.RENT_PLANE, jev.CLIENT_PLANE, jev.ROOT_PLANE))

        def decrypt(relative: Path, identity: str) -> subprocess.CompletedProcess[bytes]:
            return run([sops_path, "--decrypt", "--input-type", "yaml", "--output-type", "json", str(root / relative)],
                       {**base, "SOPS_AGE_KEY_FILE": str(identities[identity][0])})

        expected = {jev.RENT_CIPHERTEXT: ({jev.RENT_KEY: TOKEN}, "rent", "client"),
                    jev.CLIENT_CIPHERTEXT: (dict(zip(jev.CLIENT_KEYS, (CLIENT_ID, CLIENT_SECRET))), "client", "rent")}
        for relative, (values, own, other) in expected.items():
            data = (root / relative).read_bytes()
            assert not any(value.encode() in data for value in (TOKEN, CLIENT_ID, CLIENT_SECRET)), relative
            opened = decrypt(relative, own)
            assert opened.returncode == 0 and json.loads(opened.stdout) == values, f"{relative} differs"
            refused = decrypt(relative, other)
            assert refused.returncode != 0 and not any(
                value.encode() in refused.stdout + refused.stderr for value in (TOKEN, CLIENT_ID, CLIENT_SECRET)), relative
    finally:
        # Only the two throwaway private identities this run created are removed, each as one exact regular file. The
        # fixture root, its encrypted state and the copied data root stay in the runner's temporary space.
        for name in ("rent", "client"):
            key = work / f"{name}.key"
            if key.is_file() and not key.is_symlink():
                key.unlink()
    assert not any(os.path.lexists(work / f"{name}.key") for name in ("rent", "client")), "a throwaway identity remains"
    print(f"real root output to both envelopes: PASS (tofu={tofu_path}, sops={sops_path}); identities removed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sops")
    parser.add_argument("--age-keygen")
    parser.add_argument("--tofu")
    args = parser.parse_args()
    assert (args.sops is None) == (args.age_keygen is None) == (args.tofu is None), \
        "--sops, --age-keygen and --tofu go together"
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
        test_root_author()
        test_root_red()
        test_root_after_write()
        test_root_main()
        test_root_init_hint()
        if args.sops is None:
            print("real SOPS roundtrip: NOT RUN (the check workflow runs it with --sops, --age-keygen and --tofu)")
        else:
            real_roundtrip(args.sops, args.age_keygen)
            real_root_roundtrip(args.sops, args.age_keygen, args.tofu)
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("rent tunnel adapter self-test: PASS")


if __name__ == "__main__":
    main()
