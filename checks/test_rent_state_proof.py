#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import re
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The Jev self-test's fixture store, toolchain manifest and environment helpers are shared, not copied.
SPEC = importlib.util.spec_from_file_location("envs_jev_fixtures", ROOT / "checks/test_jev_api.py")
assert SPEC is not None and SPEC.loader is not None
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
jev = fixtures.jev
TOOLS = fixtures.TOOLS

ACCOUNT_ID = fixtures.ACCOUNT_ID
# Values generated per run so their bytes never appear in tracked source.
PARENT_TOKEN = "r2-parent-" + secrets.token_urlsafe(24)
PARENT_ID = secrets.token_hex(16)
TEMPORARY = {"accessKeyId": secrets.token_hex(16), "secretAccessKey": secrets.token_hex(32),
             "sessionToken": secrets.token_urlsafe(48)}
RUN_ENV = {"GITHUB_RUN_ID": "36700000001", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": secrets.token_hex(20)}
RUN = jev.run_identity(RUN_ENV)
NAMES = jev.state_bucket_names(RUN)
NOW = 1_800_000_000.0
PASSPHRASE = re.compile(r'key_provider "pbkdf2" "(current|previous)" \{\n  passphrase = "([0-9a-f]+)"')
# OpenTofu/AWS SDK-shaped failures; only their class matters, and the adapter never prints them.
DENIED = b"operation error S3: ListObjectsV2, https response error StatusCode: 403, RequestID: r, api error AccessDenied: Access Denied"
LOCK_DENIED = (b"Error acquiring the state lock\n\nError message: operation error S3: PutObject, https response error "
               b"StatusCode: 403, RequestID: r, api error AccessDenied: Access Denied")
UNAUTHORIZED = b"operation error S3: ListObjectsV2, https response error StatusCode: 401, RequestID: r, api error Unauthorized"
UNAVAILABLE = b"operation error S3: GetObject, https response error StatusCode: 503, RequestID: r, api error ServiceUnavailable"
NO_METHOD = b"Error: state encryption is enforced, but no encryption method is configured"
NO_CREDENTIAL = b"Error: No valid credential sources found"
UNDECRYPTABLE = b"Error: decryption failed for all provided methods"
NEGATIVES = dict.fromkeys(jev.STATE_NEGATIVES, "REFUSED")


def iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_env(**overrides: str) -> dict[str, str]:
    values = {"ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST, "R2_PARENT_API_TOKEN": PARENT_TOKEN,
              "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID, "R2_PARENT_ACCESS_KEY_ID": PARENT_ID, **RUN_ENV}
    values.update(overrides)
    return values


class Holder:
    def __init__(self, world: "World", argv, env) -> None:
        self.world, self.argv, self.env, self.stopped = world, list(argv), dict(env), False

    def wait(self, timeout=None) -> int:
        # The holder applies while its lock stands, then releases it.
        self.world.lock_held = False
        return self.world.inner("holder", "apply", self.argv, self.env).returncode

    def terminate(self) -> None:
        self.stopped = True

    def kill(self) -> None:
        self.stopped = True


class World:
    """A fake R2/Cloudflare/OpenTofu/Wrangler world: buckets, objects, one lock file and the temporary credential."""

    def __init__(self, *, verify=None, present=(), fail=(), unknown=(), lock_ignored=False, plaintext=False,
                 never_expire=False, redated=(), issuance=None, transient=(), admit=(), outside_init_denied=False,
                 expiry=UNAUTHORIZED, decoy=DENIED) -> None:
        self.verify = {"id": PARENT_ID, "status": "active", "not_before": iso(NOW - 3600),
                       "expires_on": iso(NOW + 86400), **(verify or {})}
        self.fail, self.unknown, self.redated = set(fail), set(unknown), set(redated)
        self.lock_ignored, self.plaintext, self.never_expire = lock_ignored, plaintext, never_expire
        self.issuance, self.transient, self.admit = issuance, set(transient), set(admit)
        self.outside_init_denied, self.expiry, self.decoy = outside_init_denied, expiry, decoy
        self.issuances = 0
        self.clock = NOW
        self.buckets = {name: "2026-01-01T00:00:00.000Z" for name in present}
        self.state: dict[str, str] = {}
        self.objects: dict[tuple[str, str], dict[str, object]] = {}
        self.lock_held = False
        self.issued: float | None = None
        self.created = 0
        self.stderr = io.StringIO()
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.api_calls: list[tuple[str, str]] = []
        self.holders: list[Holder] = []
        self.slept: list[float] = []

    # --- Cloudflare API -------------------------------------------------------------------------------------------
    def api(self, method, path, token, body):
        assert token == PARENT_TOKEN, "only the parent token reaches the Cloudflare API"
        kind = "verify" if path.endswith("/tokens/verify") else "temporary" if "temp-access" in path else "bucket"
        self.api_calls.append((method, kind))
        if kind in self.unknown or (kind == "bucket" and "bucket-after" in self.unknown and self.state == {}
                                    and self.created):
            raise jev.EnvsError("Cloudflare request outcome is UNKNOWN")
        assert path.startswith(f"/accounts/{ACCOUNT_ID}/")
        if kind == "verify":
            return 200, {"success": True, "result": self.verify}
        if kind == "temporary":
            assert method == "POST" and body == {
                "bucket": NAMES["proof"], "parentAccessKeyId": PARENT_ID, "permission": "object-read-write",
                "ttlSeconds": jev.STATE_CREDENTIAL_TTL, "prefixes": ["state/"]}, body
            self.issuances += 1
            # Every failure shape: the provider may still have issued a credential the adapter never saw.
            if self.issuance == "transport":
                raise jev.EnvsError("Cloudflare request outcome is UNKNOWN")
            if self.issuance == "5xx":
                return 503, {"success": False}
            if self.issuance == "malformed":
                return 200, {"success": True, "result": {"accessKeyId": TEMPORARY["accessKeyId"]}}
            if self.issuance == "4xx":
                return 403, {"success": False, "errors": [{"code": 10000}]}
            self.issued = self.clock
            return 200, {"success": True, "result": dict(TEMPORARY)}
        name = path.rsplit("/", 1)[1]
        assert method == "GET" and not name.startswith("windows-rent-state/"), path
        if name not in self.buckets:
            return 404, {"success": False, "errors": [{"code": 10006}]}
        created = self.buckets[name] if name not in self.redated else "2026-02-02T00:00:00.000Z"
        return 200, {"success": True, "result": {"name": name, "creation_date": created}}

    # --- processes ------------------------------------------------------------------------------------------------
    def run(self, argv, input_data, env):
        argv, env = list(argv), dict(env)
        self.calls.append((argv, env))
        if argv[0] == TOOLS["wrangler"]:
            return self.wrangler(argv, env)
        assert argv[0] == TOOLS["tofu"], argv
        work = Path(argv[1].split("=", 1)[1]).name
        if work == "outer":
            return self.outer(argv, env)
        return self.inner(work, argv[2], argv, env)

    def spawn(self, argv, env):
        assert argv[0] == TOOLS["tofu"] and Path(argv[1].split("=", 1)[1]).name == "holder" and argv[2] == "apply"
        self.calls.append((list(argv), dict(env)))
        self.lock_held = True
        holder = Holder(self, argv, env)
        self.holders.append(holder)
        return holder

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.clock += seconds

    def now(self) -> float:
        return self.clock

    @staticmethod
    def done(argv, code: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)

    def outer(self, argv, env):
        assert env["CLOUDFLARE_API_TOKEN"] == PARENT_TOKEN and env["TF_VAR_run"] == RUN["scope"]
        command = argv[2]
        if command == "apply":
            decoy = argv[-1] == "decoy=true"
            if ("apply", decoy) in self.fail:
                return self.done(argv, 1, stdout=f"noise {PARENT_TOKEN}".encode())
            name = NAMES["decoy" if decoy else "proof"]
            self.created += 1
            self.buckets[name] = self.state[name] = f"2026-09-30T00:00:{self.created:02d}.000Z"
        elif command == "show":
            resources = [{"address": f"cloudflare_r2_bucket.{'decoy' if name.endswith('-decoy') else 'proof'}",
                          "mode": "managed", "type": "cloudflare_r2_bucket",
                          "values": {"name": name, "creation_date": created, "account_id": ACCOUNT_ID}}
                         for name, created in self.state.items()]
            return self.done(argv, 0, json.dumps({"values": {"root_module": {"resources": resources}}}).encode())
        elif command == "destroy":
            if "destroy" in self.fail or any(bucket in self.state for bucket, _ in self.objects):
                return self.done(argv, 1)
            for name in list(self.state):
                self.buckets.pop(name, None)
            self.state = {}
        return self.done(argv)

    def inner(self, work, command, argv, env):
        assert "CLOUDFLARE_API_TOKEN" not in env and PARENT_TOKEN not in env.values(), "the parent token reached the backend"
        keys = dict(PASSPHRASE.findall(env.get("TF_ENCRYPTION", "")))
        current, previous = keys.get("current"), keys.get("previous")
        valid = env.get("AWS_SECRET_ACCESS_KEY") == TEMPORARY["secretAccessKey"] \
            and env.get("AWS_SESSION_TOKEN") == TEMPORARY["sessionToken"]
        expired = self.issued is not None and not self.never_expire and self.clock >= self.issued + jev.STATE_CREDENTIAL_TTL
        bucket, key = env["TF_VAR_bucket"], env["TF_VAR_key"]
        inside = key.startswith("state/")
        stored = self.objects.get((bucket, key))
        readable = stored is not None and stored["key"] in {current, previous} - {None}
        if work in self.transient:
            return self.done(argv, 1, stderr=UNAVAILABLE)
        if work in self.admit:
            return self.done(argv)
        # Enforced encryption without a method, a missing credential, then S3 auth: 401 for the credential as a
        # whole (invalid or expired), 403 AccessDenied for a bucket or prefix outside its scope.
        if "TF_ENCRYPTION" not in env:
            return self.done(argv, 1, stderr=NO_METHOD)
        if "AWS_SECRET_ACCESS_KEY" not in env:
            return self.done(argv, 1, stderr=NO_CREDENTIAL)
        if not valid or expired:
            return self.done(argv, 1, stderr=self.expiry)
        if bucket != NAMES["proof"] or bucket not in self.buckets:
            return self.done(argv, 1, stderr=self.decoy)
        if command == "init":
            return self.done(argv, 1, stderr=DENIED) if not inside and self.outside_init_denied else self.done(argv)
        if not inside:
            # The first write outside the prefix is OpenTofu's own lock file.
            return self.done(argv, 1, stderr=LOCK_DENIED)
        if command == "plan":
            if self.lock_held and not self.lock_ignored:
                return self.done(argv, 1, stderr=b"Error acquiring the state lock\nLock Info: fixture")
            if "-detailed-exitcode" in argv:
                return self.done(argv, 0 if readable and stored["canary"] == env["TF_VAR_canary"] else 2)
            return self.done(argv)
        if command == "apply":
            if current is None or (stored is not None and not readable) or (self.lock_held and not self.lock_ignored):
                return self.done(argv, 1)
            version = 1 + (stored["version"] if stored else 0)
            self.objects[(bucket, key)] = {"key": current, "canary": env["TF_VAR_canary"], "version": version}
            return self.done(argv)
        if command == "output":
            return self.done(argv, 0, str(stored["canary"]).encode()) if readable else self.done(argv, 1, stderr=UNDECRYPTABLE)
        raise AssertionError(argv)

    def wrangler(self, argv, env):
        assert env["CLOUDFLARE_API_TOKEN"] == PARENT_TOKEN and argv[1:3] == ["r2", "object"] and "--remote" in argv
        bucket, key = argv[4].split("/", 1)
        assert bucket == NAMES["proof"] and key in {jev.STATE_KEY, jev.STATE_KEY + ".tflock"}, argv
        if argv[3] == "delete":
            self.objects.pop((bucket, key), None)
            return self.done(argv)
        assert argv[3] == "get" and "--pipe" in argv
        stored = self.objects.get((bucket, key))
        if stored is None:
            return self.done(argv, 1)
        sealed = hashlib.sha256(f"{stored['key']}:{stored['canary']}".encode()).hexdigest()
        body = {"serial": stored["version"], "lineage": "fixture", "encryption_version": "v0", "encrypted_data": sealed}
        if self.plaintext:
            body["canary"] = stored["canary"]
        return self.done(argv, 0, json.dumps(body).encode())

    def prove(self, root: Path) -> dict:
        with contextlib.redirect_stderr(self.stderr):
            return jev.state_proof(root, runner=self.run, api=self.api, spawn=self.spawn, sleep=self.sleep,
                                   clock=self.now)

    def tofu(self, work: str) -> list[list[str]]:
        return [argv[2:] for argv, _ in self.calls
                if argv[0] == TOOLS["tofu"] and Path(argv[1].split("=", 1)[1]).name == work]


def no_secret_escapes(world: World, result: dict) -> None:
    # The parent token reaches only the bucket root, Wrangler and the API; the temporary credential and the
    # encryption text only the backend root; the parent token ID and account only the environment and URLs.
    text = json.dumps(result) + world.stderr.getvalue()
    passphrases = {value for _, env in world.calls for _, value in PASSPHRASE.findall(env.get("TF_ENCRYPTION", ""))}
    assert len(passphrases) == 3, "state key, rotated key and credential-probe key"
    for value in (PARENT_TOKEN, PARENT_ID, ACCOUNT_ID, *TEMPORARY.values(), *passphrases):
        assert value not in text, "a secret or pinned ID reached the result or a log line"
        for argv, _ in world.calls:
            assert not any(value in item for item in argv), "a secret reached argv"
    for argv, env in world.calls:
        work = Path(argv[1].split("=", 1)[1]).name if argv[0] == TOOLS["tofu"] else None
        assert (env.get("CLOUDFLARE_API_TOKEN") == PARENT_TOKEN) == (work == "outer" or argv[0] == TOOLS["wrangler"])
        backend = argv[0] == TOOLS["tofu"] and work != "outer"
        assert ("AWS_SECRET_ACCESS_KEY" in env) <= backend and ("TF_ENCRYPTION" in env) <= backend
        assert not any(name.startswith("R2_PARENT") for name in env), "a workflow input leaked into a tool"
        assert "-backend-config" not in " ".join(argv)


def with_root(test):
    def run() -> None:
        root = fixtures.copy_root()
        try:
            with fixtures.environment(state_env()):
                test(root)
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)
    return run


@with_root
def test_state_pass(root: Path) -> None:
    world = World()
    result = world.prove(root)
    assert result["status"] == "STATE_BACKEND_PROVEN" and result["cleanup"] == "ABSENT", result
    assert result["checks"] == dict.fromkeys(jev.STATE_CHECKS, True) and len(jev.STATE_CHECKS) == 8
    assert result["negatives"] == NEGATIVES and len(NEGATIVES) == 5
    assert result["credential"] == "UNUSABLE_AFTER_TTL" and result["credential_control"] == "USABLE"
    assert result["buckets"] == "ABSENT" and result["owned"] == sorted(NAMES.values())
    # The post-TTL test runs in its own fresh directory, never the control's cached one, and after the TTL.
    assert world.tofu("usable-control") == [["init", "-input=false", "-no-color"]]
    assert world.tofu("unusable-after-ttl") == [["init", "-input=false", "-no-color"]]
    # Each negative has its adjacent control; the prefix write is OpenTofu's own lock, after an accepted init.
    for name in ("old-key", "no-encryption", "no-credential", "outside-prefix", "decoy"):
        assert world.tofu(f"{name}-control") and world.tofu(name), name
    assert [args[0] for args in world.tofu("outside-prefix")] == ["init", "plan"]
    assert "-lock-timeout=0" in world.tofu("outside-prefix")[1]
    assert result["parent"] == {"id": "MATCHED", "status": "ACTIVE", "expiry": "COVERS_WINDOW"}
    assert world.buckets == {} and world.objects == {} and not world.lock_held
    # The first bounded create comes before the decoy, the credential and any state operation.
    assert [args[0] for args in world.tofu("outer")] == ["init", "apply", "show", "apply", "show", "destroy"]
    assert world.tofu("outer")[1][-1] == "decoy=false" and world.tofu("outer")[3][-1] == "decoy=true"
    assert world.api_calls[:4] == [("GET", "verify"), ("GET", "bucket"), ("GET", "bucket"), ("POST", "temporary")]
    # Evidence lines are emitted per bucket right after its create and parse back as recovery input.
    evidence = jev.parse_state_evidence(world.stderr.getvalue(), RUN)
    assert set(evidence) == set(NAMES.values()) and world.stderr.getvalue().count(jev.STATE_EVIDENCE_KIND) == 2
    assert world.slept[0] == jev.STATE_SETTLE and world.clock >= world.issued + jev.STATE_CREDENTIAL_TTL
    assert world.tofu("contender") == [["init", "-input=false", "-no-color"],
                                       ["plan", "-lock-timeout=0", "-input=false", "-no-color"],
                                       ["plan", "-lock-timeout=0", "-detailed-exitcode", "-input=false", "-no-color"]]
    assert all(not holder.stopped for holder in world.holders) and len(world.holders) == 1
    assert "windows-rent-state" not in [name for name in NAMES.values()] and result["production_state"] == "UNTOUCHED"
    no_secret_escapes(world, result)


def expect_preflight_red(world: World, root: Path) -> None:
    try:
        world.prove(root)
    except jev.EnvsError as exc:
        assert not any(value in str(exc) for value in (PARENT_TOKEN, PARENT_ID))
    else:
        raise AssertionError("an invalid parent or occupied name was accepted")
    assert not world.calls and not world.buckets.keys() - {NAMES["proof"]} and world.issued is None


@with_root
def test_preflight_red(root: Path) -> None:
    for verify in ({"id": secrets.token_hex(16)}, {"status": "disabled"}, {"expires_on": None},
                   {"expires_on": iso(NOW + jev.state_window() - 1)}, {"not_before": iso(NOW + 60)},
                   {"expires_on": "tomorrow"}):
        expect_preflight_red(World(verify=verify), root)
    # An existing bucket under a per-run name is never adopted, created over or deleted.
    world = World(present=(NAMES["proof"],))
    expect_preflight_red(world, root)
    assert world.buckets == {NAMES["proof"]: "2026-01-01T00:00:00.000Z"}
    expect_preflight_red(World(unknown={"verify"}), root)


@with_root
def test_first_create_is_the_only_probe(root: Path) -> None:
    world = World(fail={("apply", False)})
    result = world.prove(root)
    assert result["status"] == "STATE_BACKEND_RED" and result["cleanup"] == "ABSENT", result
    assert "first bounded bucket create" in result["error"] and PARENT_TOKEN not in result["error"]
    assert [args[0] for args in world.tofu("outer")] == ["init", "apply", "show"]
    assert ("POST", "temporary") not in world.api_calls and result["credential"] == "NOT_ATTEMPTED"
    assert not world.holders and world.slept == []
    no_red_leak(world, result)


def no_red_leak(world: World, result: dict) -> None:
    text = json.dumps(result) + world.stderr.getvalue()
    for value in (PARENT_TOKEN, PARENT_ID, ACCOUNT_ID, *TEMPORARY.values()):
        assert value not in text


@with_root
def test_proof_failures(root: Path) -> None:
    for world, check in ((World(lock_ignored=True), "lock_contender_rejected"),
                         (World(plaintext=True), "raw_state_encrypted")):
        result = world.prove(root)
        assert result["status"] == "STATE_BACKEND_RED" and result["checks"][check] is False, result
        assert result["cleanup"] == "ABSENT" and world.buckets == {}
        no_secret_escapes(world, result)
    # Any issuance failure may still have issued a credential: one POST, no retry, the buckets are removed, but the
    # credential and cleanup stay UNKNOWN; nothing infers that no credential exists.
    for mode in ("transport", "5xx", "malformed", "4xx"):
        world = World(issuance=mode)
        result = world.prove(root)
        assert result["credential"] == "ISSUANCE_UNKNOWN" and result["buckets"] == "ABSENT", (mode, result)
        assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and world.issuances == 1
        assert world.buckets == {} and not world.holders and world.slept == []
        no_red_leak(world, result)


@with_root
def test_cleanup_is_evidence_bound(root: Path) -> None:
    # Destroy failed: the buckets remain and LEFTOVER replaces the proven status.
    world = World(fail={"destroy"})
    result = world.prove(root)
    assert result["status"] == "LEFTOVER" and result["cleanup"] == "LEFTOVER" and result["buckets"] == "LEFTOVER"
    assert result["negatives"]["decoy_refused"] == "REFUSED" and set(world.buckets) == set(NAMES.values())
    # A current creation_date differing from this run's evidence is not owned: no destroy at all, LEFTOVER.
    world = World(redated={NAMES["decoy"]})
    result = world.prove(root)
    assert result["cleanup"] == "LEFTOVER" and result["owned"] == [NAMES["proof"]]
    assert "destroy" not in [args[0] for args in world.tofu("outer")] and NAMES["decoy"] in world.buckets
    # The temporary credential was never observed refused: UNKNOWN, even with both names absent.
    world = World(never_expire=True)
    result = world.prove(root)
    assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and result["credential"] == "STILL_USABLE"
    # Only a 401 for the same credential in a fresh directory after the TTL, with a usable control before it, counts;
    # a 403, a 5xx or a failed control leaves the credential UNKNOWN and the buckets are still removed.
    for world in (World(expiry=DENIED), World(transient={"unusable-after-ttl"}), World(transient={"usable-control"})):
        result = world.prove(root)
        assert result["credential"] == "UNKNOWN" and result["buckets"] == "ABSENT", result
        assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and world.buckets == {}
    assert result["credential_control"] == "UNKNOWN" and not world.tofu("unusable-after-ttl")
    # A readback that cannot be completed is UNKNOWN, never ABSENT.
    world = World(unknown={"bucket-after"})
    result = world.prove(root)
    assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN"
    for item in (World(fail={"destroy"}), World(never_expire=True)):
        no_secret_escapes(item, item.prove(root))


@with_root
def test_negative_classes(root: Path) -> None:
    # A negative that succeeds is ADMITTED and RED; one failing for another cause, or behind a failed control, is
    # UNKNOWN; an outside-prefix init already refused proves no write denial.
    for world, name, label, status in (
        (World(admit={"outside-prefix"}), "outside_prefix_write_refused", "ADMITTED", "STATE_BACKEND_RED"),
        (World(admit={"old-key"}), "old_key_refused", "ADMITTED", "STATE_BACKEND_RED"),
        (World(transient={"decoy"}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(decoy=UNAUTHORIZED), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(outside_init_denied=True), "outside_prefix_write_refused", "UNKNOWN", "UNKNOWN"),
        (World(transient={"no-credential-control"}), "no_credential_refused", "UNKNOWN", "UNKNOWN"),
        (World(transient={"no-encryption"}), "unencrypted_read_refused", "UNKNOWN", "UNKNOWN"),
    ):
        result = world.prove(root)
        assert result["negatives"][name] == label and result["status"] == status, (name, result)
        assert result["cleanup"] == "ABSENT" and {key: value for key, value in result["negatives"].items()
                                                   if key != name} == {key: "REFUSED" for key in NEGATIVES if key != name}
        if world.outside_init_denied:
            assert [args[0] for args in world.tofu("outside-prefix")] == ["init"], "no write was attempted"


def test_failure_cause() -> None:
    def result(stderr: bytes, code: int = 1, stdout: bytes = b"") -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["tofu"], code, stdout=stdout, stderr=stderr)

    for stderr, cause in (
        (UNAUTHORIZED, "unauthorized"), (DENIED, "access_denied"), (LOCK_DENIED, "access_denied"),
        (b"https response error StatusCode: 403, api error SignatureDoesNotMatch", "unknown"),
        (UNAVAILABLE, "unknown"), (DENIED + b"\n" + UNAUTHORIZED, "unknown"),
        (b"dial tcp: lookup example: no such host", "unknown"), (b"i/o timeout", "unknown"),
        (DENIED + b" (retry with -lock-timeout)", "access_denied"),
        # Enforced encryption without a method is not an authentication refusal: the old expiry probe's false positive.
        (NO_METHOD, "encryption"), (UNDECRYPTABLE, "decryption"), (NO_CREDENTIAL, "credential"), (b"exit 1", "unknown"),
    ):
        assert jev.failure_cause(result(stderr)) == cause, (stderr, cause)
    assert jev.refusal(True, result(b"", 0), {"access_denied"}) == "ADMITTED"
    assert jev.refusal(False, result(DENIED), {"access_denied"}) == "UNKNOWN"
    assert jev.refusal(True, result(UNAUTHORIZED), {"access_denied"}) == "UNKNOWN"
    assert jev.refusal(True, result(DENIED), {"access_denied"}) == "REFUSED"


def expect_input_red(values: dict[str, str], mutate=None) -> None:
    root = fixtures.copy_root()
    world = World()
    try:
        if mutate is not None:
            mutate(root)
        with fixtures.environment(values):
            try:
                world.prove(root)
            except jev.EnvsError as exc:
                assert not any(value in str(exc) for value in (PARENT_TOKEN, PARENT_ID))
            else:
                raise AssertionError("invalid state proof input was accepted")
        assert not world.calls and not world.api_calls, "a tool or provider call ran before the input gate"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_state_red_inputs() -> None:
    for name in ("R2_PARENT_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "R2_PARENT_ACCESS_KEY_ID", *RUN_ENV):
        expect_input_red(state_env(**{name: ""}))
    expect_input_red(state_env(R2_PARENT_ACCESS_KEY_ID=PARENT_ID.upper()))
    expect_input_red(state_env(R2_PARENT_ACCESS_KEY_ID=PARENT_ID[:31]))
    expect_input_red(state_env(GITHUB_SHA="main"))
    for value in (PARENT_TOKEN, PARENT_ID, ACCOUNT_ID):
        expect_input_red(state_env(), mutate=lambda root, value=value: fixtures.append(root / "README.md", f"\n{value}\n"))
    # The access probe's secret is not this plane's input: holding only it is RED.
    expect_input_red({**state_env(R2_PARENT_API_TOKEN=""), "CLOUDFLARE_API_TOKEN": PARENT_TOKEN})


def test_recovery_input() -> None:
    first = jev.state_evidence(RUN, NAMES["proof"], "2026-09-30T00:00:01.000Z")
    second = jev.state_evidence(RUN, NAMES["decoy"], "2026-09-30T00:00:02.000Z")
    other = jev.state_evidence({**RUN, "run_attempt": "1"}, NAMES["proof"], "2026-09-30T00:00:09.000Z")
    log = "\n".join([
        "2026-09-30T00:00:00.1Z ##[group]Run envs-effect rent-state-proof",
        "2026-09-30T00:00:01.2Z " + json.dumps(first),
        "2026-09-30T00:00:01.3Z {not json " + jev.STATE_EVIDENCE_KIND,
        "2026-09-30T00:00:01.4Z " + json.dumps(other),
        "2026-09-30T00:00:01.5Z " + json.dumps({**second, "head": "0" * 40}),
        "2026-09-30T00:00:02.2Z " + json.dumps(second),
        "2026-09-30T00:00:02.3Z " + json.dumps({**second, "bucket": "windows-rent-state"}),
    ])
    evidence = jev.parse_state_evidence(log, RUN)
    assert evidence == {NAMES["proof"]: first["creation_date"], NAMES["decoy"]: second["creation_date"]}
    try:
        jev.parse_state_evidence(log + "\n" + json.dumps({**first, "creation_date": "2026-09-30T00:00:05.000Z"}), RUN)
    except jev.EnvsError:
        pass
    else:
        raise AssertionError("conflicting creation evidence was accepted")
    current = {NAMES["proof"]: first["creation_date"], NAMES["decoy"]: "2026-09-30T00:00:07.000Z"}
    assert jev.owned_buckets(evidence, current, RUN) == [NAMES["proof"]]
    assert jev.owned_buckets({}, current, RUN) == []
    assert jev.owned_buckets(evidence, {NAMES["proof"]: None}, RUN) == []
    assert jev.owned_buckets({"windows-rent-state": "x"}, {"windows-rent-state": "x"}, RUN) == []


def test_encryption_config() -> None:
    single = jev.encryption_config("a" * 64)
    rotated = jev.encryption_config("b" * 64, "a" * 64)
    assert dict(PASSPHRASE.findall(single)) == {"current": "a" * 64} and "fallback" not in single
    assert dict(PASSPHRASE.findall(rotated)) == {"current": "b" * 64, "previous": "a" * 64}
    assert rotated.count("fallback {\n    method = method.aes_gcm.previous\n  }") == 2
    assert jev.encrypted_raw(b'{"encrypted_data":"x","serial":1}', "canary-1")
    for raw in (None, b'{"encrypted_data":"canary-1"}', b'{"resources":[],"encrypted_data":"x"}', b"not json"):
        assert not jev.encrypted_raw(raw, "canary-1")


def main() -> None:
    try:
        jev.validate_contracts(ROOT)
        test_state_pass()
        test_preflight_red()
        test_first_create_is_the_only_probe()
        test_proof_failures()
        test_cleanup_is_evidence_bound()
        test_negative_classes()
        test_failure_cause()
        test_state_red_inputs()
        test_recovery_input()
        test_encryption_config()
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("state proof adapter self-test: PASS")


if __name__ == "__main__":
    main()
