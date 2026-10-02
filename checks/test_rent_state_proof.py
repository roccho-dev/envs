#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
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
PASSPHRASE = re.compile(r'key_provider "pbkdf2" "(\w+)" \{\n  passphrase = "([0-9a-f]+)"')
# The state method and its optional fallback, by key name: like OpenTofu, the fake binds stored state to that name.
METHODS = re.compile(r'(?m)^state \{\n  method = method\.aes_gcm\.(\w+)\n(?:  fallback \{\n    method = method\.aes_gcm\.(\w+)\n)?')
# OpenTofu/AWS SDK-shaped failures; only their class matters, and the adapter never prints them.
DENIED = b"operation error S3: ListObjectsV2, https response error StatusCode: 403, RequestID: r, api error AccessDenied: Access Denied"
LOCK_DENIED = (b"Error acquiring the state lock\n\nError message: operation error S3: PutObject, https response error "
               b"StatusCode: 403, RequestID: r, api error AccessDenied: Access Denied")
UNAUTHORIZED = b"operation error S3: ListObjectsV2, https response error StatusCode: 401, RequestID: r, api error Unauthorized"
UNAVAILABLE = b"operation error S3: GetObject, https response error StatusCode: 503, RequestID: r, api error ServiceUnavailable"
# Synthetic classifier input only (the word "encryption" classifies as encryption); not an OpenTofu message.
NO_METHOD = b"Error: state encryption is enforced, but no encryption method is configured"
# Shaped after OpenTofu 1.12.3: an enforced block without a method is an HCL configuration error naming no encryption
# word, so it never qualifies; a root with no encryption configuration refuses the encrypted state it reads.
INVALID_EXPRESSION = b"Error: Invalid expression\n\nA single static variable reference is required."
ENCRYPTED_NO_CONFIG = (b"Error: Unsupported state file format\n\nThis state file is encrypted and can not be read "
                       b"without an encryption configuration")
NO_CREDENTIAL = b"Error: No valid credential sources found"
UNDECRYPTABLE = b"Error: decryption failed for all provided methods"
NEGATIVES = dict.fromkeys(jev.STATE_NEGATIVES, "REFUSED")


def s3_error(code: str) -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>{code}</Code><Message>fixture</Message>'
            f"</Error>").encode()


# S3 object replies as (HTTP status, body), or a curl transport failure; only their class matters.
ACCESS_DENIED_XML = s3_error("AccessDenied")
NO_SUCH_KEY_XML = s3_error("NoSuchKey")
SIGNATURE_XML = s3_error("SignatureDoesNotMatch")
# Two contradictory direct codes: not one S3 Error.Code, so never a qualifying refusal.
DUPLICATE_CODE_XML = b"<Error><Code>AccessDenied</Code><Code>SignatureDoesNotMatch</Code></Error>"


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
                 never_expire=False, redated=(), issuance=None, transient=(), admit=(), expiry=UNAUTHORIZED,
                 raising=None, plain_phase="init", plain_error=ENCRYPTED_NO_CONFIG, s3=None, blind=False) -> None:
        # blind: once a create happened, every bucket GET answers 404 although the buckets exist.
        self.blind = blind
        # plain_phase/plain_error: where and how a root with no encryption configuration refuses the state; both
        # phases are exercised because which one S3 uses is not observed.
        self.plain_phase, self.plain_error, self.roots = plain_phase, plain_error, {}
        # s3: an object request label (proof-put, proof-get, outside, decoy, post-ttl) -> (status, body), "timeout"
        # (no reply) or "timeout-wrote" (no reply, yet the object was written).
        self.s3 = dict(s3 or {})
        self.markers: dict[tuple[str, str], bytes] = {}
        self.s3_calls: list[str] = []
        # raising: a work directory, "wrangler-delete", "outer-destroy" or "api-current" -> a local exception type.
        self.raising = dict(raising or {})
        self.verify = {"id": PARENT_ID, "status": "active", "not_before": iso(NOW - 3600),
                       "expires_on": iso(NOW + 86400), **(verify or {})}
        self.fail, self.unknown, self.redated = set(fail), set(unknown), set(redated)
        self.lock_ignored, self.plaintext, self.never_expire = lock_ignored, plaintext, never_expire
        self.issuance, self.transient, self.admit = issuance, set(transient), set(admit)
        self.expiry = expiry
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
        if kind == "bucket" and "api-current" in self.raising and self.state:
            raise self.raising["api-current"](f"local failure under {Path.home()}")
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
        if name not in self.buckets or (self.blind and self.created):
            return 404, {"success": False, "errors": [{"code": 10006}]}
        created = self.buckets[name] if name not in self.redated else "2026-02-02T00:00:00.000Z"
        return 200, {"success": True, "result": {"name": name, "creation_date": created}}

    # --- processes ------------------------------------------------------------------------------------------------
    def run(self, argv, input_data, env):
        argv, env = list(argv), dict(env)
        self.calls.append((argv, env))
        if argv[0] == TOOLS["wrangler"]:
            if argv[3] == "delete" and "wrangler-delete" in self.raising:
                raise self.raising["wrangler-delete"]("fixture launch failure")
            return self.wrangler(argv, input_data, env)
        if argv[0] == TOOLS["curl"]:
            return self.curl(argv, input_data, env)
        assert argv[0] == TOOLS["tofu"], argv
        work = Path(argv[1].split("=", 1)[1]).name
        if work in self.raising or (work == "outer" and argv[2] == "destroy" and "outer-destroy" in self.raising):
            raise self.raising.get(work, self.raising.get("outer-destroy"))("fixture launch failure")
        if work == "outer":
            return self.outer(argv, env)
        self.roots[work] = (Path(argv[1].split("=", 1)[1]) / "main.tf").read_text(encoding="utf-8")
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
            if "destroy" in self.fail or any(bucket in self.state for bucket, _ in [*self.objects, *self.markers]):
                return self.done(argv, 1)
            for name in list(self.state):
                self.buckets.pop(name, None)
            self.state = {}
        return self.done(argv)

    def inner(self, work, command, argv, env):
        assert "CLOUDFLARE_API_TOKEN" not in env and PARENT_TOKEN not in env.values(), "the parent token reached the backend"
        text = env.get("TF_ENCRYPTION", "")
        keys, methods = dict(PASSPHRASE.findall(text)), METHODS.search(text)
        current, previous = ((name, keys[name]) if name else None for name in (methods.groups() if methods else (None, None)))
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
        # Encryption configuration, a missing credential, then S3 auth: 401 for the credential as a whole (invalid or
        # expired), 403 AccessDenied for a bucket or prefix outside its scope.
        if "TF_ENCRYPTION" not in env:
            if jev.ENCRYPTION_BLOCK_START.search(self.roots[work]):
                # The enforced block without a method: a configuration error, not a ciphertext read refusal.
                return self.done(argv, 1, stderr=INVALID_EXPRESSION)
            assert command in {"init", "output"}, "the configuration-free root ran a mutating command"
            if command == self.plain_phase or command == "output":
                return self.done(argv, 1, stderr=self.plain_error)
            return self.done(argv)
        if "AWS_SECRET_ACCESS_KEY" not in env:
            return self.done(argv, 1, stderr=NO_CREDENTIAL)
        if not valid or expired:
            return self.done(argv, 1, stderr=self.expiry)
        # OpenTofu only ever reaches the proof bucket inside the prefix; the object boundaries are curl's.
        assert bucket == NAMES["proof"] and inside, (work, bucket, key)
        if bucket not in self.buckets:
            return self.done(argv, 1, stderr=DENIED)
        if command == "init":
            return self.done(argv)
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

    def wrangler(self, argv, input_data, env):
        assert env["CLOUDFLARE_API_TOKEN"] == PARENT_TOKEN and argv[1:3] == ["r2", "object"] and "--remote" in argv
        bucket, key = argv[4].split("/", 1)
        markers = {jev.STATE_MARKER_KEY, jev.STATE_OUTSIDE_MARKER_KEY}
        assert bucket in NAMES.values() and key in {jev.STATE_KEY, jev.STATE_KEY + ".tflock", *markers}, argv
        if argv[3] == "delete":
            self.objects.pop((bucket, key), None)
            self.markers.pop((bucket, key), None)
            return self.done(argv)
        if argv[3] == "put":
            # Only the parent's known decoy marker is written here.
            assert (bucket, key) == (NAMES["decoy"], jev.STATE_MARKER_KEY) and "--pipe" in argv, argv
            assert input_data == jev.STATE_MARKER
            if "seed" in self.fail:
                return self.done(argv, 1)
            self.markers[(bucket, key)] = input_data
            return self.done(argv)
        assert argv[3] == "get" and "--pipe" in argv
        if key == jev.STATE_MARKER_KEY:
            stored_marker = self.markers.get((bucket, key))
            return self.done(argv, 0, stored_marker) if stored_marker is not None else self.done(argv, 1)
        assert bucket == NAMES["proof"] and key == jev.STATE_KEY, argv
        stored = self.objects.get((bucket, key))
        if stored is None:
            return self.done(argv, 1)
        sealed = hashlib.sha256(f"{stored['key']}:{stored['canary']}".encode()).hexdigest()
        body = {"serial": stored["version"], "lineage": "fixture", "encryption_version": "v0", "encrypted_data": sealed}
        if self.plaintext:
            body["canary"] = stored["canary"]
        return self.done(argv, 0, json.dumps(body).encode())

    def curl(self, argv, input_data, env):
        # The temporary credential reaches curl only as stdin config; argv is fixed and the parent token never comes.
        assert argv[1:] == ["-q", "--config", "-"] and input_data is not None, argv
        assert PARENT_TOKEN.encode() not in input_data and "AWS_SECRET_ACCESS_KEY" not in env
        config = dict(re.findall(r'(?m)^([a-z0-9-]+) = "((?:[^"\\]|\\.)*)"$', input_data.decode()))
        headers = re.findall(r'(?m)^header = "((?:[^"\\]|\\.)*)"$', input_data.decode())
        assert config["aws-sigv4"] == "aws:amz:auto:s3" and config["noproxy"] == "*" and config["proto"] == "=https"
        assert "silent" in input_data.decode().splitlines() and config["write-out"] == "%{stderr}%{http_code}"
        method, url = config["request"], config["url"]
        prefix = f"https://{ACCOUNT_ID}.r2.cloudflarestorage.com/"
        assert url.startswith(prefix), url
        bucket, key = url[len(prefix):].split("/", 1)
        valid = config["user"] == f"{TEMPORARY['accessKeyId']}:{TEMPORARY['secretAccessKey']}" \
            and f"x-amz-security-token: {TEMPORARY['sessionToken']}" in headers
        expired = self.issued is not None and not self.never_expire and self.clock >= self.issued + jev.STATE_CREDENTIAL_TTL
        label = "post-ttl" if expired else "decoy" if bucket == NAMES["decoy"] else \
            "outside" if not key.startswith("state/") else f"proof-{method.lower()}"
        # Each label has exactly one method and path-style target; a misrouted request fails, whatever it is answered.
        assert (method, bucket, key) == {"proof-put": ("PUT", NAMES["proof"], jev.STATE_MARKER_KEY),
                                         "proof-get": ("GET", NAMES["proof"], jev.STATE_MARKER_KEY),
                                         "outside": ("PUT", NAMES["proof"], jev.STATE_OUTSIDE_MARKER_KEY),
                                         "decoy": ("GET", NAMES["decoy"], jev.STATE_MARKER_KEY),
                                         "post-ttl": ("GET", NAMES["proof"], jev.STATE_MARKER_KEY)}[label], \
            (label, method, bucket, key)
        body = config.get("data-binary", "").encode()
        assert (method == "PUT") == bool(body) and (not body or body == jev.STATE_MARKER)
        self.s3_calls.append(label)
        if f"curl:{label}" in self.raising:
            raise self.raising[f"curl:{label}"]("fixture launch failure")
        reply = self.s3.get(label)
        if reply in ("timeout", "timeout-wrote"):
            if reply == "timeout-wrote":
                self.markers[(bucket, key)] = body
            return self.done(argv, 28, b"", b"000")
        if reply is None:
            # The modelled R2: 401 for an invalid or expired credential, 403 AccessDenied with an XML body outside
            # its bucket or prefix, and the marker as written inside it.
            stored = self.markers.get((bucket, key))
            reply = (401, b"") if not valid or expired else (403, ACCESS_DENIED_XML) if label in {"outside", "decoy"} \
                else (200, b"") if method == "PUT" else (200, stored) if stored is not None else (404, NO_SUCH_KEY_XML)
        status, content, *rest = reply
        exit_code = rest[0] if rest else 0
        if 200 <= status < 300 and method == "PUT":
            self.markers[(bucket, key)] = body
        return self.done(argv, exit_code, content, f"{status:03d}".encode())

    def prove(self, root: Path) -> dict:
        with contextlib.redirect_stderr(self.stderr):
            result = jev.state_proof(root, runner=self.run, api=self.api, spawn=self.spawn, sleep=self.sleep,
                                     clock=self.now)
        # Every scenario's branch evidence is finite and agrees with its unchanged labels; an error is only its kind.
        assert jev.diagnostics_finite(result["diagnostics"]), result["diagnostics"]
        assert result.get("error", "envs") in {"envs", "os", "subprocess"} and type(result.get("error", "")) is str, result
        if result["negatives"] is not None:
            assert result["negatives"] == {name: label_from(name, entry)
                                           for name, entry in result["diagnostics"]["negatives"].items()}, result
        return result

    def tofu(self, work: str) -> list[list[str]]:
        return [argv[2:] for argv, _ in self.calls
                if argv[0] == TOOLS["tofu"] and Path(argv[1].split("=", 1)[1]).name == work]


def no_secret_escapes(world: World, result: dict) -> None:
    # The parent token reaches only the bucket root, Wrangler and the API; the temporary credential and the
    # encryption text only the backend root; the parent token ID and account only the environment and URLs.
    text = json.dumps(result) + world.stderr.getvalue()
    passphrases = {value for _, env in world.calls for _, value in PASSPHRASE.findall(env.get("TF_ENCRYPTION", ""))}
    assert len(passphrases) == 2, "state key and rotated key"
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
    # Object requests in order: the credential control writes and reads the proof marker; the prefix write follows its
    # write control, the decoy read its read control after the parent seeded and verified the decoy marker; after
    # the TTL the same credential reads the same marker.
    assert world.s3_calls == ["proof-put", "proof-get", "proof-put", "outside", "proof-get", "decoy", "post-ttl"]
    seed = [i for i, (argv, _) in enumerate(world.calls) if argv[0] == TOOLS["wrangler"] and argv[3] == "put"]
    decoy = [i for i, (argv, _) in enumerate(world.calls) if argv[0] == TOOLS["curl"]][5]
    assert len(seed) == 1 and seed[0] < decoy
    # Each OpenTofu negative keeps its adjacent control; OpenTofu no longer runs the object boundaries.
    for name in ("old-key", "no-encryption", "no-credential"):
        assert world.tofu(f"{name}-control") and world.tofu(name), name
    assert not world.tofu("outside-prefix") and not world.tofu("decoy") and not world.tofu("usable-control")
    # Every attempted marker key is deleted before the owned buckets are destroyed.
    deleted = {argv[4] for argv, _ in world.calls if argv[0] == TOOLS["wrangler"] and argv[3] == "delete"}
    assert deleted == {f"{NAMES['proof']}/{jev.STATE_KEY}", f"{NAMES['proof']}/{jev.STATE_KEY}.tflock",
                       f"{NAMES['proof']}/{jev.STATE_MARKER_KEY}", f"{NAMES['proof']}/{jev.STATE_OUTSIDE_MARKER_KEY}",
                       f"{NAMES['decoy']}/{jev.STATE_MARKER_KEY}"}, deleted
    assert result["parent"] == {"id": "MATCHED", "status": "ACTIVE", "expiry": "COVERS_WINDOW"}
    assert world.buckets == {} and world.objects == {} and world.markers == {} and not world.lock_held
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
    # The same proven run whose branch evidence leaves the closed sets: the evidence is dropped and so is the proof.
    original = jev.s3_evidence
    jev.s3_evidence = lambda control, phase, operation: {**original(control, phase, operation), "phase": "unrecorded"}
    try:
        world = World()
        with contextlib.redirect_stderr(world.stderr):
            dropped = jev.state_proof(root, runner=world.run, api=world.api, spawn=world.spawn, sleep=world.sleep,
                                      clock=world.now)
    finally:
        jev.s3_evidence = original
    assert dropped["diagnostics"] is None and dropped["status"] == "UNKNOWN", dropped
    assert dropped["checks"] == result["checks"] and dropped["negatives"] == NEGATIVES and dropped["cleanup"] == "ABSENT"
    # Finite yet incomplete: shapes a run that stopped early may carry (no entry for a negative, no negatives at all,
    # no post-TTL probe) leave the labels proven but cannot leave the status proven.
    checks_of, probe_of = jev.state_checks, jev.probe_evidence
    for name, attribute, replacement in (
        ("entry", "s3_evidence", lambda control, phase, operation: None),
        ("negatives", "state_checks", lambda *args: (*checks_of(*args)[:2], None)),
        ("probe", "probe_evidence", lambda probe, operation=None, error=None: probe_of("not_run")),
    ):
        original = getattr(jev, attribute)
        setattr(jev, attribute, replacement)
        try:
            world = World()
            with contextlib.redirect_stderr(world.stderr):
                missing = jev.state_proof(root, runner=world.run, api=world.api, spawn=world.spawn, sleep=world.sleep,
                                          clock=world.now)
        finally:
            setattr(jev, attribute, original)
        assert jev.diagnostics_finite(missing["diagnostics"]) and missing["negatives"] == NEGATIVES, (name, missing)
        assert missing["status"] == "UNKNOWN" and missing["cleanup"] == "ABSENT", (name, missing)


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
    # The stage names where it failed; the receipt carries only the closed failure kind, no exception text.
    assert result["stage"] == "create" and result["error"] == "envs", result
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
    # Only a 401 for the same credential reading the same marker after the TTL, with a usable control before it,
    # counts; a 403 (even AccessDenied), a timeout or a failed control leaves the credential UNKNOWN and the buckets
    # are still removed.
    for world in (World(s3={"post-ttl": (403, ACCESS_DENIED_XML)}), World(s3={"post-ttl": "timeout"}),
                  World(s3={"post-ttl": (401, b"", 18)}), World(s3={"proof-get": (503, b"")})):
        result = world.prove(root)
        assert result["credential"] == "UNKNOWN" and result["buckets"] == "ABSENT", result
        assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and world.buckets == {}
    assert result["credential_control"] == "UNKNOWN" and "post-ttl" not in world.s3_calls
    # A write whose reply never came may still have landed: its exact key is deleted anyway, and nothing is retried.
    for label in ("outside", "proof-put"):
        world = World(s3={label: "timeout-wrote"})
        result = world.prove(root)
        assert result["buckets"] == "ABSENT" and world.markers == {} and world.buckets == {}, (label, result)
        assert world.s3_calls.count(label) == (1 if label == "outside" else 2), world.s3_calls
    # Without a verified decoy marker the decoy read is not attempted at all.
    world = World(fail={"seed"})
    result = world.prove(root)
    assert result["negatives"]["decoy_refused"] == "UNKNOWN" and "decoy" not in world.s3_calls
    assert result["diagnostics"]["negatives"]["decoy_refused"] is None and result["buckets"] == "ABSENT"
    # A readback that cannot be completed is UNKNOWN, never ABSENT.
    world = World(unknown={"bucket-after"})
    result = world.prove(root)
    assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN"
    # A readback that 404s buckets this run created is not their absence: nothing is owned or deleted, both names read
    # back 404, yet without ownership of every created bucket the run is UNKNOWN, never ABSENT or PROVEN.
    world = World(blind=True)
    result = world.prove(root)
    assert result["owned"] == [] and result["buckets"] == "ABSENT" and result["credential"] == "UNUSABLE_AFTER_TTL"
    assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN", result
    assert set(world.buckets) == set(NAMES.values()) and "destroy" not in [args[0] for args in world.tofu("outer")]
    # Only the proof bucket was created: owning exactly it is complete ownership, so its absence stays ABSENT.
    world = World(fail={("apply", True)})
    result = world.prove(root)
    assert result["owned"] == [NAMES["proof"]] and result["cleanup"] == "ABSENT" and result["status"] == "STATE_BACKEND_RED"
    for item in (World(fail={"destroy"}), World(never_expire=True)):
        no_secret_escapes(item, item.prove(root))


@with_root
def test_cleanup_survives_local_failures(root: Path) -> None:
    readback = [("GET", "bucket"), ("GET", "bucket")]

    def outer_commands(world: World) -> list[str]:
        return [args[0] for args in world.tofu("outer")]

    # The post-TTL probe cannot launch (either local failure class): the credential is UNKNOWN, yet the owned
    # buckets are still deleted and read back once.
    for error in (OSError, subprocess.SubprocessError):
        world = World(raising={"curl:post-ttl": error})
        result = world.prove(root)
        assert result["credential"] == "UNKNOWN" and result["buckets"] == "ABSENT", result
        assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and world.buckets == {}
        assert outer_commands(world).count("destroy") == 1 and world.api_calls[-2:] == readback
        no_red_leak(world, result)
    # A key delete or the destroy cannot launch: the final readback still runs and finds the buckets.
    for raising in ({"wrangler-delete": OSError}, {"outer-destroy": OSError}):
        world = World(raising=raising)
        result = world.prove(root)
        assert result["buckets"] == "LEFTOVER" and result["cleanup"] == "LEFTOVER" and result["status"] == "LEFTOVER"
        assert outer_commands(world)[-1] == "destroy" and world.api_calls[-2:] == readback, raising
        assert set(world.buckets) == set(NAMES.values())
        no_red_leak(world, result)
    # No complete ownership readback: nothing is deleted, no final readback claims anything, UNKNOWN.
    world = World(raising={"api-current": OSError})
    result = world.prove(root)
    assert result["buckets"] == "UNKNOWN" and result["cleanup"] == "UNKNOWN" and result["owned"] == []
    assert "destroy" not in outer_commands(world) and set(world.buckets) == set(NAMES.values())
    assert not [argv for argv, _ in world.calls if argv[0] == TOOLS["wrangler"] and argv[3] == "delete"]
    # A local failure inside the proof is UNKNOWN (closed kind only), the result is still returned after cleanup.
    for error, kind in ((OSError, "os"), (subprocess.SubprocessError, "subprocess"), (PermissionError, "os")):
        world = World(raising={"readback": error})
        result = world.prove(root)
        assert result["status"] == "UNKNOWN" and result["error"] == kind and result["checks"] is None, result
        assert result["cleanup"] == "ABSENT" and result["credential"] == "UNUSABLE_AFTER_TTL" and world.buckets == {}
        assert str(Path.home()) not in json.dumps(result)
        no_red_leak(world, result)


@with_root
def test_negative_classes(root: Path) -> None:
    # A negative that succeeds is ADMITTED and RED; one failing for another cause, or behind a failed control, is
    # UNKNOWN; an outside-prefix init already refused proves no write denial.
    for world, name, label, status in (
        (World(s3={"outside": (200, b"")}), "outside_prefix_write_refused", "ADMITTED", "STATE_BACKEND_RED"),
        (World(admit={"old-key"}), "old_key_refused", "ADMITTED", "STATE_BACKEND_RED"),
        (World(s3={"decoy": (200, jev.STATE_MARKER)}), "decoy_refused", "ADMITTED", "STATE_BACKEND_RED"),
        (World(s3={"decoy": "timeout"}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(s3={"decoy": (401, b"")}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        # A bodyless or other-coded 403, or a missing object, is not the scope refusal.
        (World(s3={"decoy": (403, b"")}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(s3={"outside": (403, SIGNATURE_XML)}), "outside_prefix_write_refused", "UNKNOWN", "UNKNOWN"),
        (World(s3={"decoy": (404, NO_SUCH_KEY_XML)}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(s3={"decoy": (403, DUPLICATE_CODE_XML)}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        # A nonzero curl exit (18: partial transfer) is never a completed reply, whatever status or body arrived.
        (World(s3={"outside": (403, ACCESS_DENIED_XML, 18)}), "outside_prefix_write_refused", "UNKNOWN", "UNKNOWN"),
        (World(s3={"decoy": (200, jev.STATE_MARKER, 18)}), "decoy_refused", "UNKNOWN", "UNKNOWN"),
        (World(transient={"no-credential-control"}), "no_credential_refused", "UNKNOWN", "UNKNOWN"),
        (World(transient={"no-encryption"}), "unencrypted_read_refused", "UNKNOWN", "UNKNOWN"),
    ):
        result = world.prove(root)
        assert result["negatives"][name] == label and result["status"] == status, (name, result)
        assert result["cleanup"] == "ABSENT" and {key: value for key, value in result["negatives"].items()
                                                   if key != name} == {key: "REFUSED" for key in NEGATIVES if key != name}


def test_without_encryption() -> None:
    # Exactly the one enforced block goes; anything else is refused rather than rewritten.
    text = (ROOT / jev.STATE_BACKEND).read_text(encoding="utf-8")
    plain = jev.without_encryption(text)
    assert plain is not None and plain == text.replace(jev.STATE_ENCRYPTION_BLOCK, "")
    assert not jev.ENCRYPTION_BLOCK_START.search(plain) and 'backend "s3"' in plain and "use_lockfile" in plain
    block = jev.STATE_ENCRYPTION_BLOCK
    for bad in (text.replace(block, ""), text.replace(block, block.replace("enforced = true", "enforced = false", 1)),
                text.replace(block, block + block), text.replace(block, block + "  encryption {\n  }\n")):
        assert jev.without_encryption(bad) is None, bad


@with_root
def test_no_encryption_root(root: Path) -> None:
    backend = (root / jev.STATE_BACKEND).read_text(encoding="utf-8")
    # The configuration-free root is the exact transform, only for that negative, and only init/output run in it;
    # its control and every other directory keep the unchanged enforced root.
    for phase, commands, diagnostic in (("init", ["init"], "init"), ("output", ["init", "output"], "read")):
        world = World(plain_phase=phase)
        result = world.prove(root)
        assert result["status"] == "STATE_BACKEND_PROVEN" and result["negatives"] == NEGATIVES, result
        assert world.roots["no-encryption"] == jev.without_encryption(backend)
        assert all(text == backend for work, text in world.roots.items() if work != "no-encryption")
        assert [args[0] for args in world.tofu("no-encryption")] == commands
        entry = result["diagnostics"]["negatives"]["unencrypted_read_refused"]
        assert entry["phase"] == diagnostic and entry["word"] == "encrypt" and entry["control"] is True, entry
    # A configuration error, a failed paired control or an admitted read never counts as a refusal.
    for world, label, status in ((World(plain_error=INVALID_EXPRESSION), "UNKNOWN", "UNKNOWN"),
                                 (World(transient={"no-encryption-control"}), "UNKNOWN", "UNKNOWN"),
                                 (World(admit={"no-encryption"}), "ADMITTED", "STATE_BACKEND_RED")):
        result = world.prove(root)
        assert result["negatives"]["unencrypted_read_refused"] == label and result["status"] == status, result
    # The old shape, the enforced root without TF_ENCRYPTION, is a configuration error and stays UNKNOWN.
    assert jev.refusal(True, World.done(["tofu"], 1, stderr=INVALID_EXPRESSION),
                       jev.STATE_NEGATIVES["unencrypted_read_refused"]) == "UNKNOWN"
    # A missing, differing or repeated block: the negative is not attempted (UNKNOWN, no evidence); nothing else moves.
    block = jev.STATE_ENCRYPTION_BLOCK
    for bad in (backend.replace(block, ""), backend.replace(block, block.replace("enforced = true", "enforced = false", 1)),
                backend.replace(block, block + block)):
        (root / jev.STATE_BACKEND).write_text(bad, encoding="utf-8")
        world = World()
        result = world.prove(root)
        assert result["negatives"]["unencrypted_read_refused"] == "UNKNOWN" and result["status"] == "UNKNOWN", result
        assert result["diagnostics"]["negatives"]["unencrypted_read_refused"] is None
        assert not world.tofu("no-encryption") and not world.tofu("no-encryption-control")
        assert {key: value for key, value in result["negatives"].items() if key != "unencrypted_read_refused"} == \
            {key: "REFUSED" for key in NEGATIVES if key != "unencrypted_read_refused"}
        assert result["cleanup"] == "ABSENT" and all(result["checks"].values())
    (root / jev.STATE_BACKEND).write_text(backend, encoding="utf-8")


MARKER = "fixture-marker-" + secrets.token_hex(8)
# A reply body carrying a marker and the AccessDenied word, but not as an S3 XML error: it must neither qualify nor
# escape into the receipt.
LEAKY = f"AccessDenied {MARKER} <Error><Code>AccessDenied".encode()
PHASES = {"old_key_refused": "read", "unencrypted_read_refused": "init", "no_credential_refused": "init",
          "outside_prefix_write_refused": "write", "decoy_refused": "read"}


def label_from(name: str, entry: dict | None) -> str:
    # The pre-registered reading: each label follows from its evidence by the unchanged refusal rule.
    if entry is None:
        return "UNKNOWN"
    if entry["phase"] == "admitted":
        return "ADMITTED"
    facts = {key: entry[key] for key in jev.NO_FAILURE_FACTS}
    cause = "unknown" if facts["transient"] or facts["status"] in {"5xx", "multiple", "other"} else \
        "unauthorized" if facts["status"] == "401" else \
        ("access_denied" if facts["access_denied"] else "unknown") if facts["status"] == "403" else \
        {"decrypt": "decryption", "encrypt": "encryption", "credential": "credential"}.get(facts["word"], "unknown")
    return "REFUSED" if entry["control"] and cause in jev.STATE_NEGATIVES[name] else "UNKNOWN"


def diagnostics_hold(world: World, result: dict) -> dict:
    # Finite values only, consistent with the unchanged labels, and no captured output in the receipt.
    diagnostics = result["diagnostics"]
    assert jev.diagnostics_finite(diagnostics), diagnostics
    if result["negatives"] is not None:
        for name, entry in diagnostics["negatives"].items():
            assert result["negatives"][name] == label_from(name, entry), (name, entry, result["negatives"])
    probe = diagnostics["credential_probe"]
    if result["credential"] == "STILL_USABLE":
        assert probe["probe"] == "admitted"
    if result["credential"] == "UNUSABLE_AFTER_TTL":
        assert probe["probe"] == "refused" and probe["status"] == "401"
    text = json.dumps(result)
    assert MARKER not in text and "StatusCode" not in text and "operation error" not in text
    no_red_leak(world, result)
    return diagnostics


@with_root
def test_branch_evidence(root: Path) -> None:
    # A proven run: every negative refused at its own phase with its own cause, after a successful control.
    world = World()
    result = world.prove(root)
    diagnostics = diagnostics_hold(world, result)
    negatives = diagnostics["negatives"]
    assert {name: entry["phase"] for name, entry in negatives.items()} == PHASES
    assert all(entry["control"] for entry in negatives.values())
    assert negatives["old_key_refused"]["word"] == "decrypt" and negatives["unencrypted_read_refused"]["word"] == "encrypt"
    assert negatives["no_credential_refused"]["word"] == "credential"
    for name in ("outside_prefix_write_refused", "decoy_refused"):
        assert negatives[name]["status"] == "403" and negatives[name]["access_denied"] is True
    assert diagnostics["credential_probe"] == {"probe": "refused", "status": "401", "access_denied": False,
                                               "transient": False, "word": "none", "local": "none", "code": "none"}
    # Each UNKNOWN or ADMITTED branch is told apart by finite evidence, with the label unchanged.
    for world, name, expected in (
        (World(s3={"outside": (200, b"")}), "outside_prefix_write_refused", {"phase": "admitted", "status": "none"}),
        (World(s3={"proof-put": (503, b"")}), "outside_prefix_write_refused",
         {"control": False, "phase": "write", "status": "403", "access_denied": True}),
        (World(s3={"proof-get": (503, b"")}), "decoy_refused",
         {"control": False, "phase": "read", "status": "403", "access_denied": True}),
        (World(transient={"no-credential-control"}), "no_credential_refused", {"control": False, "phase": "init"}),
        (World(transient={"no-encryption"}), "unencrypted_read_refused", {"phase": "init", "status": "5xx"}),
        (World(s3={"decoy": (401, b"")}), "decoy_refused", {"control": True, "status": "401"}),
        (World(s3={"decoy": (403, b"")}), "decoy_refused", {"control": True, "status": "403", "access_denied": False}),
        (World(s3={"decoy": (403, LEAKY)}), "decoy_refused", {"status": "403", "access_denied": False}),
        (World(s3={"outside": (403, SIGNATURE_XML)}), "outside_prefix_write_refused",
         {"status": "403", "access_denied": False}),
        (World(s3={"decoy": (404, NO_SUCH_KEY_XML)}), "decoy_refused", {"status": "other", "access_denied": False}),
        (World(s3={"decoy": "timeout"}), "decoy_refused", {"status": "none", "transient": True}),
    ):
        result = world.prove(root)
        entry = diagnostics_hold(world, result)["negatives"][name]
        assert {key: entry[key] for key in expected} == expected, (name, entry)
        assert result["negatives"][name] in {"UNKNOWN", "ADMITTED"}, (name, result["negatives"])
    # The post-TTL probe: admitted, refused for another cause, not run behind a failed control, or a local failure
    # named only by its closed class.
    for world, credential, expected in (
        (World(never_expire=True), "STILL_USABLE", {"probe": "admitted", "status": "none", "local": "none", "code": "none"}),
        (World(s3={"post-ttl": (403, ACCESS_DENIED_XML)}), "UNKNOWN",
         {"probe": "refused", "status": "403", "access_denied": True, "code": "AccessDenied"}),
        (World(s3={"post-ttl": (503, b"")}), "UNKNOWN", {"probe": "refused", "status": "5xx", "code": "none"}),
        (World(s3={"post-ttl": "timeout"}), "UNKNOWN",
         {"probe": "refused", "status": "none", "transient": True, "code": "none"}),
        (World(s3={"proof-get": (503, b"")}), "UNKNOWN", {"probe": "not_run", "local": "none", "code": "none"}),
        (World(raising={"curl:post-ttl": OSError}), "UNKNOWN", {"probe": "local_failure", "local": "os", "code": "none"}),
        (World(raising={"curl:post-ttl": subprocess.SubprocessError}), "UNKNOWN",
         {"probe": "local_failure", "local": "subprocess", "code": "none"}),
        (World(issuance="5xx"), "ISSUANCE_UNKNOWN", {"probe": "not_run", "code": "none"}),
    ):
        result = world.prove(root)
        probe = diagnostics_hold(world, result)["credential_probe"]
        assert result["credential"] == credential and {key: probe[key] for key in expected} == expected, (probe, result)
    # A completed post-TTL 403 names its code for the investigation only: whatever the code, the credential and the
    # cleanup stay UNKNOWN and nothing is proven; only the 401 path proves, and its code changes nothing.
    for reply, code in (((403, s3_error("ExpiredRequest")), "ExpiredRequest"), ((403, SIGNATURE_XML), "SignatureDoesNotMatch"),
                        ((403, s3_error("NotEntitled")), "NotEntitled"), ((403, s3_error("ExpiredToken")), "other"),
                        ((403, b""), "none"), ((403, DUPLICATE_CODE_XML), "none")):
        world = World(s3={"post-ttl": reply})
        result = world.prove(root)
        probe = diagnostics_hold(world, result)["credential_probe"]
        assert probe["code"] == code and probe["status"] == "403" and result["credential"] == "UNKNOWN", (code, probe)
        assert result["cleanup"] == "UNKNOWN" and result["status"] == "UNKNOWN" and result["buckets"] == "ABSENT", result
    world = World(s3={"post-ttl": (401, s3_error("Unauthorized"))})
    result = world.prove(root)
    assert diagnostics_hold(world, result)["credential_probe"]["code"] == "Unauthorized"
    assert result["status"] == "STATE_BACKEND_PROVEN" and result["credential"] == "UNUSABLE_AFTER_TTL", result
    # No negative ran: the evidence says so instead of inventing a branch.
    world = World(issuance="transport")
    assert diagnostics_hold(world, result := world.prove(root))["negatives"] is None and result["negatives"] is None


def test_diagnostics_closed() -> None:
    good = {"negatives": None, "credential_probe": jev.probe_evidence("not_run")}
    assert jev.diagnostics_finite(good)
    entry = {"control": True, "phase": "init", **jev.NO_FAILURE_FACTS}
    assert jev.diagnostics_finite({**good, "negatives": {name: entry for name in jev.STATE_NEGATIVES}})
    for bad in (
        {**good, "extra": 1},
        {**good, "credential_probe": {**good["credential_probe"], "local": "KeyError"}},
        {**good, "credential_probe": {**good["credential_probe"], "status": "403 AccessDenied: denied"}},
        {**good, "credential_probe": {**good["credential_probe"], "word": TEMPORARY["sessionToken"]}},
        {**good, "credential_probe": {**good["credential_probe"], "detail": "x"}},
        {**good, "credential_probe": {**good["credential_probe"], "code": "ExpiredToken"}},
        {**good, "credential_probe": {key: value for key, value in good["credential_probe"].items() if key != "code"}},
        {**good, "negatives": {name: {**entry, "code": "none"} for name in jev.STATE_NEGATIVES}},
        {**good, "negatives": {name: {**entry, "control": 1} for name in jev.STATE_NEGATIVES}},
        {**good, "negatives": {name: {**entry, "phase": "plan"} for name in jev.STATE_NEGATIVES}},
        {**good, "negatives": {"old_key_refused": entry}},
        None,
    ):
        assert not jev.diagnostics_finite(bad), bad


class MarkerFailure(Exception):
    pass


def state_command(root: Path) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = jev.main(["--root", str(root), "rent-state-proof"])
    return code, out.getvalue() + err.getvalue()


def test_state_command_red_line() -> None:
    # The state command's failure line carries only a closed kind: never exception text, a class name or a
    # traceback, even for an unexpected exception; it still fails closed.
    secret = f"{MARKER}-{TEMPORARY['secretAccessKey']}"
    original = jev.state_proof
    try:
        for error, kind in ((jev.EnvsError(secret), "envs"), (OSError(secret), "os"),
                            (subprocess.SubprocessError(secret), "subprocess"), (MarkerFailure(secret), "other"),
                            (KeyError(secret), "other")):
            def failing(root: Path, error: Exception = error) -> dict:
                raise error
            jev.state_proof = failing
            code, text = state_command(ROOT)
            assert code == 1 and text == f"RENT_STATE_PROOF=RED: {kind}\n", (kind, text)
            assert MARKER not in text and type(error).__name__ not in text and "Traceback" not in text
    finally:
        jev.state_proof = original
    # A real preflight refusal (a missing secret input) reads the same way.
    root = fixtures.copy_root()
    try:
        with fixtures.environment(state_env(R2_PARENT_API_TOKEN="")):
            code, text = state_command(root)
        assert code == 1 and text == "RENT_STATE_PROOF=RED: envs\n", text
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


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
        (INVALID_EXPRESSION, "unknown"), (ENCRYPTED_NO_CONFIG, "encryption"),
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
    single = jev.encryption_config("k0", "a" * 64)
    rotated = jev.encryption_config("k1", "b" * 64, ("k0", "a" * 64))
    assert dict(PASSPHRASE.findall(single)) == {"k0": "a" * 64} and "fallback" not in single
    assert METHODS.search(single).groups() == ("k0", None)
    # The old key keeps the name it was written under; the new key gets its own.
    assert dict(PASSPHRASE.findall(rotated)) == {"k1": "b" * 64, "k0": "a" * 64}
    assert METHODS.search(rotated).groups() == ("k1", "k0")
    assert rotated.count("fallback {\n    method = method.aes_gcm.k0\n  }") == 2
    assert jev.encrypted_raw(b'{"encrypted_data":"x","serial":1}', "canary-1")
    for raw in (None, b'{"encrypted_data":"canary-1"}', b'{"resources":[],"encrypted_data":"x"}', b"not json"):
        assert not jev.encrypted_raw(raw, "canary-1")


# The backend root's encryption and canary on a local backend: OpenTofu's own encryption metadata, without S3 or R2.
NATIVE_ENCRYPTION = jev.STATE_ENCRYPTION_BLOCK
NATIVE_ROOT = """terraform {
  backend "local" {
    path = "%s"
  }
""" + NATIVE_ENCRYPTION + """}

variable "canary" {
  type    = string
  default = ""
}

resource "terraform_data" "canary" {
  input = var.canary
}

output "canary" {
  value = terraform_data.canary.output
}
"""
# The same root with no encryption block at all: OpenTofu then has no encryption configuration. It is only ever
# initialized and read, never planned or applied, so it cannot write the state.
# It is made by the adapter's own transform, the one the live no-encryption negative uses.
NATIVE_PLAIN_ROOT = jev.without_encryption(NATIVE_ROOT)
assert NATIVE_PLAIN_ROOT is not None and NATIVE_PLAIN_ROOT != NATIVE_ROOT and "encryption" not in NATIVE_PLAIN_ROOT


def real_tofu(tofu: str) -> None:
    # The pinned closure OpenTofu writes, rotates and reads one synthetic state with the adapter's own encryption text,
    # each step from a fresh directory, network closed. Only stage outcomes are printed, never a canary or a key.
    # The work directory is a fresh empty path that is never deleted here: recursive deletion is not allowed in an
    # automated check, and its synthetic, encrypted state is left to the ephemeral runner.
    assert os.path.isfile(tofu) and os.access(tofu, os.X_OK), "native OpenTofu cannot run"
    work = Path(tempfile.mkdtemp(prefix="envs-native-tofu-"))
    assert not any(work.iterdir()), "native OpenTofu work directory is not empty"
    state = work / "state.tfstate"
    first, second = secrets.token_hex(32), secrets.token_hex(32)
    old, new = "canary-" + secrets.token_hex(16), "canary-" + secrets.token_hex(16)

    def run(name: str, encryption: str | None, canary: str, *args: str,
            root: str = NATIVE_ROOT) -> subprocess.CompletedProcess[bytes]:
        directory, home = work / name, work / f"home-{name}"
        if not directory.exists():
            directory.mkdir()
            home.mkdir()
            (directory / "main.tf").write_text(root % state.as_posix(), encoding="utf-8")
        env = {"PATH": os.path.dirname(tofu), "HOME": str(home), "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
               "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "CHECKPOINT_DISABLE": "1",
               "TF_VAR_canary": canary}
        if encryption is not None:
            env["TF_ENCRYPTION"] = encryption
        return subprocess.run([tofu, f"-chdir={directory}", *args], env=env, capture_output=True, timeout=300,
                              check=False)

    def step(name: str, encryption: str, canary: str, *args: str) -> tuple[bool, str]:
        for command in (("init", "-input=false", "-no-color"), args):
            result = run(name, encryption, canary, *command)
            if result.returncode != 0:
                return False, jev.failure_cause(result)
        return True, "ok"

    def reads(name: str, encryption: str, expected: str) -> tuple[bool, str]:
        ok, cause = step(name, encryption, "", "output", "-raw", "canary")
        if not ok:
            return False, cause
        return run(name, encryption, "", "output", "-raw", "canary").stdout == expected.encode(), "ok"

    apply = ("apply", "-input=false", "-auto-approve", "-no-color")
    outcome: dict[str, object] = {}
    outcome["write"] = step("write", jev.encryption_config("k0", first), old, *apply)
    before = state.read_bytes() if state.is_file() else None
    outcome["raw_encrypted"] = jev.encrypted_raw(before, old)
    outcome["rotate"] = step("rotate", jev.encryption_config("k1", second, ("k0", first)), new, *apply)
    after = state.read_bytes() if state.is_file() else None
    outcome["raw_rewritten"] = jev.encrypted_raw(after, new) and after != before
    outcome["new_key_read"] = reads("new-key", jev.encryption_config("k1", second), new)
    # Right after that control, only the encryption configuration differs: a root with no encryption block reads the
    # same encrypted state (init and output only) and must be refused for the adapter's own qualifying cause.
    held = state.read_bytes() if state.is_file() else None
    phase, cause = "admitted", "ok"
    for name, command in (("init", ("init", "-input=false", "-no-color")), ("read", ("output", "-raw", "canary"))):
        result = run("no-config", None, "", *command, root=NATIVE_PLAIN_ROOT)
        if result.returncode != 0:
            phase, cause = name, jev.failure_cause(result)
            break
    qualifying = jev.STATE_NEGATIVES["unencrypted_read_refused"]
    outcome["no_config_read_refused"] = (phase != "admitted" and cause in qualifying, cause, phase)
    # A guard, not a read refusal: the enforced root without TF_ENCRYPTION is rejected at init by its own
    # configuration (no method), before any state is read; only that refusal is recorded, not its cause.
    guard = run("enforced-no-key", None, "", "init", "-input=false", "-no-color")
    outcome["enforced_init_refused"] = guard.returncode != 0
    outcome["no_config_state_unchanged"] = held is not None and state.read_bytes() == held
    refused, cause = reads("old-key", jev.encryption_config("k0", first), new)
    outcome["old_key_refused"] = (not refused and cause == "decryption", cause)
    passed = all(value[0] if isinstance(value, tuple) else value for value in outcome.values())
    print("native OpenTofu rotation:", json.dumps(outcome, sort_keys=True), "PASS" if passed else "RED")
    assert passed, "native OpenTofu rotation regression failed"


class FixtureS3(http.server.BaseHTTPRequestHandler):
    # A bounded loopback HTTP responder: it records each request and answers the next scripted (status, body, delay,
    # headers). It is a transport fixture for the real curl, not an S3 service and not R2 evidence.
    def serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.server.seen.append({"method": self.command, "path": self.path, "body": self.rfile.read(length) if length else b"",
                                 "headers": {name.lower(): value for name, value in self.headers.items()}})
        status, content, delay, extra = self.server.replies.pop(0)
        time.sleep(delay)
        try:
            self.send_response(status)
            # An extra Content-Length larger than the body delivered makes the transfer partial (curl exit 18).
            for name, value in extra.items():
                self.send_header(name, value)
            if "Content-Length" not in extra:
                self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except OSError:
            pass

    do_GET = do_PUT = serve

    def log_message(self, *args) -> None:
        pass


SIGNED = re.compile(r"^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/auto/s3/aws4_request, ?SignedHeaders=([a-z0-9;-]+), ?"
                    r"Signature=[0-9a-f]{64}$")


def real_s3(curl: str) -> None:
    # The locked closure curl signs real HTTP requests to the loopback fixture with synthetic credentials: exact request
    # order, method, path-style path, host, payload, SigV4 scope and signed session token, then every reply class the
    # adapter must keep apart. Only finite classes are printed; network and every proxy stay closed.
    assert os.path.isfile(curl) and os.access(curl, os.X_OK), "native curl cannot run"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureS3)
    server.daemon_threads, server.seen, server.replies = True, [], []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint, host = f"http://127.0.0.1:{server.server_port}", f"127.0.0.1:{server.server_port}"
    credentials = {"AWS_ACCESS_KEY_ID": "AKIA" + secrets.token_hex(8).upper(), "AWS_SECRET_ACCESS_KEY": secrets.token_hex(20),
                   "AWS_SESSION_TOKEN": secrets.token_urlsafe(48)}
    launched: list[tuple[list[str], dict[str, str]]] = []
    exits: list[int] = []

    def runner(argv, input_data, env):
        # A dead proxy in the environment proves the request goes direct.
        env = {**env, "http_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9"}
        launched.append((list(argv), dict(env)))
        result = jev.default_runner(argv, input_data, env)
        exits.append(result.returncode)
        return result

    proof, decoy = "proof-bucket", "proof-bucket-decoy"
    expected: list[tuple[str, str, str, bytes | None]] = []

    def mismatch(sent, method, bucket, key, body):
        # Every field the fixture observed against the one request the test expects; the scripted reply plays no part.
        headers = sent["headers"]
        signed = SIGNED.fullmatch(headers.get("authorization", ""))
        payload = body or b""
        fields = {
            "method": sent["method"] == method,
            "target": sent["path"] == f"/{bucket}/{key}",
            "host": headers.get("host") == host,
            "payload": sent["body"] == payload,
            "content_type": (headers.get("content-type") == "application/octet-stream") == (method == "PUT"),
            "scope": signed is not None and signed.group(1) == credentials["AWS_ACCESS_KEY_ID"]
            and signed.group(2) == headers.get("x-amz-date", "")[:8],
            "signed_headers": signed is not None and {"host", "x-amz-date", "x-amz-security-token",
                                                      "x-amz-content-sha256"} <= set(signed.group(3).split(";")),
            "token": headers.get("x-amz-security-token") == credentials["AWS_SESSION_TOKEN"],
            "payload_hash": headers.get("x-amz-content-sha256") in {hashlib.sha256(payload).hexdigest(),
                                                                    "UNSIGNED-PAYLOAD"},
        }
        return sorted(name for name, good in fields.items() if not good)

    def script(reply, method, bucket, key, body=None):
        status, content, *rest = reply
        server.replies.append((status, content, rest[0] if rest else 0, rest[1] if len(rest) > 1 else {}))
        expected.append((method, bucket, key, body))

    def send(method, bucket, key, body=None, timeout=jev.S3_TIMEOUT):
        before = len(server.seen)
        operation = jev.s3_object({"curl": curl}, runner, endpoint, credentials, method, bucket, key, body, timeout)
        seen = server.seen[before:]
        assert len(seen) == 1, (method, bucket, key, "a request was retried, a redirect followed or none was sent")
        return operation, seen[0], expected.pop(0)

    def s3(method, bucket, key, body=None, timeout=jev.S3_TIMEOUT):
        # The adapter's S3 callable: each request must be exactly the scripted one before its reply is used.
        operation, sent, want = send(method, bucket, key, body, timeout)
        wrong = mismatch(sent, *want)
        assert not wrong, (want[:3], wrong)
        return operation

    outcome: dict[str, object] = {}
    attempted: dict[str, set[str]] = {}
    try:
        # The credential control, the adapter's own marker write and exact read.
        script((200, b""), "PUT", proof, jev.STATE_MARKER_KEY, jev.STATE_MARKER)
        assert jev.marker_written(s3, proof, attempted)["ok"]
        payload = server.seen[-1]["headers"].get("x-amz-content-sha256")
        outcome["payload_hash"] = "sha256" if payload == hashlib.sha256(jev.STATE_MARKER).hexdigest() else \
            "unsigned" if payload == "UNSIGNED-PAYLOAD" else "other"
        assert outcome["payload_hash"] in {"sha256", "unsigned"}
        script((200, jev.STATE_MARKER), "GET", proof, jev.STATE_MARKER_KEY)
        assert jev.marker_read(s3, proof)
        outcome["control"] = True
        causes = jev.STATE_NEGATIVES["outside_prefix_write_refused"]
        # Only a 403 whose XML error document says AccessDenied is the scope refusal; 401 is the credential itself.
        # Each outside attempt follows its write control, both by the adapter's marker write.
        for name, reply, cause, status in (
            ("xml_access_denied", (403, ACCESS_DENIED_XML), "access_denied", "403"),
            ("bodyless_403", (403, b""), "unknown", "403"),
            ("unauthorized", (401, b""), "unauthorized", "401"),
            ("no_such_key", (404, NO_SUCH_KEY_XML), "unknown", "other"),
            ("signature", (403, SIGNATURE_XML), "unknown", "403"),
            ("malformed", (403, b"<Error><Code>AccessDenied"), "unknown", "403"),
            ("duplicate_code", (403, DUPLICATE_CODE_XML), "unknown", "403"),
            ("text_only", (403, b"AccessDenied"), "unknown", "403"),
            ("server_error", (500, s3_error("InternalError")), "unknown", "5xx"),
            ("redirect", (301, b"", 0, {"Location": f"{endpoint}/elsewhere"}), "unknown", "other"),
        ):
            script((200, b""), "PUT", proof, jev.STATE_MARKER_KEY, jev.STATE_MARKER)
            control = jev.marker_written(s3, proof, attempted)["ok"]
            script(reply, "PUT", proof, jev.STATE_OUTSIDE_MARKER_KEY, jev.STATE_MARKER)
            operation = jev.marker_written(s3, proof, attempted, jev.STATE_OUTSIDE_MARKER_KEY)
            assert not operation["ok"] and operation["status"] == status and jev.s3_cause(operation) == cause, (name, operation)
            assert operation["body"] is None
            outcome[name] = jev.s3_refusal(control, operation, causes)
        assert attempted == {proof: {jev.STATE_MARKER_KEY, jev.STATE_OUTSIDE_MARKER_KEY}}, attempted
        # The decoy read follows its read control (the proof marker's exact bytes) and is a real GET of the decoy bucket.
        decoy_causes = jev.STATE_NEGATIVES["decoy_refused"]
        for name, reply, verdict in (("decoy_access_denied", (403, ACCESS_DENIED_XML), "REFUSED"),
                                     ("decoy_bodyless_403", (403, b""), "UNKNOWN")):
            script((200, jev.STATE_MARKER), "GET", proof, jev.STATE_MARKER_KEY)
            control = jev.marker_read(s3, proof)
            script(reply, "GET", decoy, jev.STATE_MARKER_KEY)
            operation = s3("GET", decoy, jev.STATE_MARKER_KEY)
            outcome[name] = jev.s3_refusal(control, operation, decoy_causes)
            assert control and outcome[name] == verdict and operation["body"] is None, (name, operation)
        script((403, ACCESS_DENIED_XML), "GET", proof, jev.STATE_MARKER_KEY)
        refused = s3("GET", proof, jev.STATE_MARKER_KEY)
        assert outcome["xml_access_denied"] == "REFUSED" and refused["access_denied"] and \
            jev.s3_refusal(False, refused, causes) == "UNKNOWN", "a failed control qualified"
        # The post-TTL probe is the same exact GET of the proof marker; only a completed 401 is expiry.
        script((401, b""), "GET", proof, jev.STATE_MARKER_KEY)
        after = s3("GET", proof, jev.STATE_MARKER_KEY)
        assert not after["ok"] and after["status"] == "401" and jev.s3_cause(after) == "unauthorized", after
        outcome["post_ttl"] = jev.s3_cause(after)
        # The probe's closed code: a completed failed reply's single direct Code if listed, other if not, none for a
        # bodyless, malformed or contradictory reply. No code changes the cause: only the 401 is unauthorized.
        codes = {}
        for name, reply, code, cause in (
            ("unauthorized_xml", (401, s3_error("Unauthorized")), "Unauthorized", "unauthorized"),
            ("access_denied", (403, ACCESS_DENIED_XML), "AccessDenied", "access_denied"),
            ("expired_request", (403, s3_error("ExpiredRequest")), "ExpiredRequest", "unknown"),
            ("signature", (403, SIGNATURE_XML), "SignatureDoesNotMatch", "unknown"),
            ("not_entitled", (403, s3_error("NotEntitled")), "NotEntitled", "unknown"),
            ("unlisted", (403, s3_error("ExpiredToken")), "other", "unknown"),
            ("bodyless", (403, b""), "none", "unknown"),
            ("malformed", (403, b"<Error><Code>ExpiredRequest"), "none", "unknown"),
            ("duplicate", (403, DUPLICATE_CODE_XML), "none", "unknown"),
        ):
            script(reply, "GET", proof, jev.STATE_MARKER_KEY)
            operation = s3("GET", proof, jev.STATE_MARKER_KEY)
            evidence = jev.probe_evidence("refused", operation)
            assert operation["code"] == code and evidence["code"] == code and jev.s3_cause(operation) == cause, \
                (name, operation["code"], jev.s3_cause(operation))
            codes[name] = evidence["code"]
        outcome["post_ttl_codes"] = codes
        # No reply within the bound: transient, never retried, never a refusal.
        script((200, jev.STATE_MARKER, 4), "GET", proof, jev.STATE_MARKER_KEY)
        operation = s3("GET", proof, jev.STATE_MARKER_KEY, timeout=2)
        assert not operation["ok"] and operation["transient"] and operation["status"] == "none" and operation["code"] == "none"
        outcome["timeout"] = jev.s3_refusal(True, operation, causes)
        # A partial transfer (more Content-Length than delivered) with a parsable reply: curl exits nonzero, so neither
        # the XML 403 AccessDenied, the 401 nor the exact marker bytes count as a completed reply.
        for name, (status, content) in (("partial_access_denied", (403, ACCESS_DENIED_XML)),
                                        ("partial_unauthorized", (401, b"")),
                                        ("partial_marker", (200, jev.STATE_MARKER))):
            script((status, content, 0, {"Content-Length": str(len(content) + 64)}), "GET", proof, jev.STATE_MARKER_KEY)
            operation = s3("GET", proof, jev.STATE_MARKER_KEY, timeout=5)
            assert exits[-1] == 18, (name, "the transfer was not partial")
            assert not operation["ok"] and operation["transient"] and not operation["access_denied"]
            assert jev.s3_cause(operation) == "unknown" and operation["body"] is None, (name, jev.s3_facts(operation))
            assert operation["code"] == "none", (name, "an incomplete reply named a code")
            outcome[name] = jev.s3_refusal(True, operation, causes)
        # A misrouted request answered with the qualifying XML 403 would classify as REFUSED, so only the observed
        # method, target and payload keep it out: each wrong request differs from the expected one in those fields.
        caught = {}
        for name, want, sent in (
            ("decoy_as_put", ("GET", decoy, jev.STATE_MARKER_KEY, None), ("PUT", decoy, jev.STATE_MARKER_KEY, jev.STATE_MARKER)),
            ("decoy_in_proof", ("GET", decoy, jev.STATE_MARKER_KEY, None), ("GET", proof, jev.STATE_MARKER_KEY, None)),
            ("outside_in_prefix", ("PUT", proof, jev.STATE_OUTSIDE_MARKER_KEY, jev.STATE_MARKER),
             ("PUT", proof, jev.STATE_MARKER_KEY, jev.STATE_MARKER)),
            ("outside_as_get", ("PUT", proof, jev.STATE_OUTSIDE_MARKER_KEY, jev.STATE_MARKER),
             ("GET", proof, jev.STATE_OUTSIDE_MARKER_KEY, None)),
        ):
            script((403, ACCESS_DENIED_XML), *want)
            operation, seen, expect = send(*sent)
            assert expect == want and jev.s3_refusal(True, operation, causes) == "REFUSED", (name, operation)
            caught[name] = mismatch(seen, *want)
            assert caught[name], (name, "a misrouted request matched the expected one")
        outcome["misroute"] = caught
        assert all(value == "UNKNOWN" for name, value in outcome.items() if name not in {
            "payload_hash", "control", "xml_access_denied", "decoy_access_denied", "post_ttl", "post_ttl_codes",
            "misroute"}), outcome
        assert expected == [] and attempted == {proof: {jev.STATE_MARKER_KEY, jev.STATE_OUTSIDE_MARKER_KEY}}, attempted
        # The credential and session token never reach argv or the environment; only finite facts leave.
        assert len(server.seen) == len(launched) and server.replies == []
        for argv, env in launched:
            assert argv == [curl, "-q", "--config", "-"], argv
            for value in credentials.values():
                assert all(value not in item for item in argv) and value not in json.dumps(env)
    finally:
        server.shutdown()
        server.server_close()
    print("native S3 transport:", json.dumps(outcome, sort_keys=True), "PASS")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-tofu", metavar="TOFU")
    parser.add_argument("--real-s3", metavar="CURL")
    args = parser.parse_args()
    try:
        jev.validate_contracts(ROOT)
        test_state_pass()
        test_preflight_red()
        test_first_create_is_the_only_probe()
        test_proof_failures()
        test_cleanup_is_evidence_bound()
        test_cleanup_survives_local_failures()
        test_negative_classes()
        test_without_encryption()
        test_no_encryption_root()
        test_branch_evidence()
        test_diagnostics_closed()
        test_state_command_red_line()
        test_failure_cause()
        test_state_red_inputs()
        test_recovery_input()
        test_encryption_config()
        if args.real_tofu is None:
            print("native OpenTofu rotation: NOT RUN (the check workflow runs it with --real-tofu)")
        else:
            real_tofu(args.real_tofu)
        if args.real_s3 is None:
            print("native S3 transport: NOT RUN (the check workflow runs it with --real-s3)")
        else:
            real_s3(args.real_s3)
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("state proof adapter self-test: PASS")


if __name__ == "__main__":
    main()
