#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
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
ZONE_ID = secrets.token_hex(16)
# Values generated per run so their bytes never appear in tracked source.
API_TOKEN = "cf-api-" + secrets.token_urlsafe(24)
TUNNEL_TOKEN = secrets.token_urlsafe(120)
SERVICE_ID = secrets.token_hex(16) + ".access"
SERVICE_VALUE = secrets.token_hex(32)
SECRETS = (API_TOKEN, TUNNEL_TOKEN, SERVICE_VALUE)
CREATED = {name: secrets.token_hex(16) for name in jev.PROBE_CREATED}
EMPTY = {name: [] for name in jev.PROBE_LOCATED}
PROXY = f'ProxyCommand="{TOOLS["cloudflared"]}" access ssh --hostname %h'


def probe_env(**overrides: str) -> dict[str, str]:
    values = {
        "ENVS_EFFECT_TOOLCHAIN": fixtures.MANIFEST, "CLOUDFLARE_API_TOKEN": API_TOKEN,
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT_ID, "CLOUDFLARE_ZONE_ID": ZONE_ID,
    }
    values.update(overrides)
    return values


class Process:
    def __init__(self, argv, env) -> None:
        self.argv, self.env, self.stopped = list(argv), dict(env), False

    def terminate(self) -> None:
        self.stopped = True

    def wait(self, timeout=None) -> int:
        return 0

    def kill(self) -> None:
        self.stopped = True


class Cloud:
    """A fake provider/client world: tofu, ssh-keygen, the long-running processes and the bounded ssh cases."""

    def __init__(self, *, before=None, after=None, fail=(), outcomes=None) -> None:
        self.located = {"before": before or EMPTY, "after": after or EMPTY}
        self.fail = set(fail)
        self.outcomes = outcomes or {}
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.processes: list[Process] = []
        self.cases: list[tuple[list[str], dict[str, str]]] = []
        self.slept: list[float] = []

    def run(self, argv, input_data, env):
        argv = list(argv)
        self.calls.append((argv, dict(env)))
        if argv[0] == TOOLS["ssh_keygen"]:
            key = Path(argv[argv.index("-f") + 1])
            key.write_text("private\n")
            key.with_name(key.name + ".pub").write_text(f"ssh-ed25519 AAAA{secrets.token_hex(8)} {jev.PROBE_NAME}\n")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        assert argv[0] == TOOLS["tofu"], argv
        phase, command = Path(argv[1].split("=", 1)[1]).name, argv[2]
        if (phase, command) in self.fail:
            return subprocess.CompletedProcess(argv, 1, stdout=f"noise {API_TOKEN}".encode(), stderr=b"")
        stdout = b""
        if command == "output":
            stdout = json.dumps({"located": self.located.get(phase), "created": CREATED, "credentials": {
                "tunnel_token": TUNNEL_TOKEN, "service_token_id": SERVICE_ID, "service_token_value": SERVICE_VALUE,
            }}[argv[4]]).encode()
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

    def spawn(self, argv, env):
        process = Process(argv, env)
        self.processes.append(process)
        return process

    def bounded(self, argv, env, timeout):
        argv = list(argv)
        self.cases.append((argv, dict(env)))
        nonce = (Path(argv[argv.index("-i") + 1]).parent / "nonce").read_text().strip().encode()
        # Each case starts from its own empty HOME, never the runner's (no cached Access login can leak in).
        home = Path(env["HOME"])
        assert home.is_dir() and not any(home.iterdir()) and home.name.startswith("home-"), env["HOME"]
        (home / ".cloudflared").mkdir()
        if env.get("TUNNEL_SERVICE_TOKEN_SECRET") == SERVICE_VALUE:
            case = "service_token_again" if any(e.get("TUNNEL_SERVICE_TOKEN_SECRET") == SERVICE_VALUE
                                                for _, e in self.cases[:-1]) else "service_token"
        elif "TUNNEL_SERVICE_TOKEN_SECRET" in env:
            case = "wrong_token"
        else:
            case = "no_token"
        default = ("exit", 0, nonce + b"\n") if case.startswith("service_token") else ("exit", 255, b"")
        outcome = self.outcomes.get(case, default)
        return outcome if outcome != "nonce" else ("exit", 0, nonce + b"\n")

    def probe(self, root: Path, **kwargs):
        return jev.access_probe(root, runner=self.run, bounded=self.bounded, spawn=self.spawn,
                                sleep=self.slept.append, **kwargs)

    def tofu_calls(self) -> list[tuple[str, list[str]]]:
        return [(Path(argv[1].split("=", 1)[1]).name, argv[2:]) for argv, _ in self.calls if argv[0] == TOOLS["tofu"]]


def no_secret_escapes(cloud: Cloud, result: dict) -> None:
    text = json.dumps(result)
    for value in SECRETS:
        assert value not in text, "a secret reached the result"
        for argv, _ in cloud.calls + cloud.cases:
            assert not any(value in item for item in argv), "a secret reached argv"
        for process in cloud.processes:
            assert not any(value in item for item in process.argv), "a secret reached a process argv"
    for argv, env in cloud.calls:
        assert ("CLOUDFLARE_API_TOKEN" in env) == (argv[0] == TOOLS["tofu"]), "the API token left OpenTofu"
    for process in cloud.processes:
        assert ("TUNNEL_TOKEN" in process.env) == (process.argv[0] == TOOLS["cloudflared"])
        assert "CLOUDFLARE_API_TOKEN" not in process.env and "TUNNEL_SERVICE_TOKEN_SECRET" not in process.env
    for _, env in cloud.cases:
        assert "TUNNEL_TOKEN" not in env and "CLOUDFLARE_API_TOKEN" not in env


def lookups_never_mutate(cloud: Cloud) -> None:
    # Name lookup runs in its own fresh state with create=false; destroy happens only in the probe's own state.
    for phase, args in cloud.tofu_calls():
        if phase in {"before", "after"}:
            assert args[0] != "destroy" and "create=true" not in args, (phase, args)
        if args[0] == "destroy":
            assert phase == "probe" and args[-1] == "create=true"
        if args[0] == "apply" and phase == "probe":
            assert args[-1] == "create=true"


def with_root(test):
    def run() -> None:
        root = fixtures.copy_root()
        try:
            with fixtures.environment(probe_env()):
                test(root)
        finally:
            shutil.rmtree(root.parent, ignore_errors=True)
    return run


@with_root
def test_probe_pass(root: Path) -> None:
    cloud = Cloud()
    result = cloud.probe(root)
    assert result["status"] == "TOKEN_REACHED_NEGATIVES_REFUSED" and result["cleanup"] == "ABSENT", result
    assert result["created"] == CREATED and result["probe"]["cases"] == {
        "service_token": "REACHED", "no_token": "REFUSED", "wrong_token": "REFUSED", "service_token_again": "REACHED"}
    # A refused negative is never reported as an Access denial.
    assert result["probe"]["access_denial_evidence"] == "NOT_OBSERVED" and result["probe"]["cause"] == "UNKNOWN"
    assert "PASS" not in json.dumps(result) and "DENIED" not in json.dumps(result)
    homes = [env["HOME"] for _, env in cloud.cases] + [process.env["HOME"] for process in cloud.processes]
    assert len(set(homes)) == 6 and os.environ.get("HOME", "\0") not in homes
    assert [(phase, args[0]) for phase, args in cloud.tofu_calls()] == [
        ("before", "init"), ("before", "apply"), ("before", "output"),
        ("probe", "init"), ("probe", "apply"), ("probe", "output"), ("probe", "output"),
        ("probe", "destroy"), ("after", "init"), ("after", "apply"), ("after", "output")]
    assert [process.argv[0] for process in cloud.processes] == [TOOLS["sshd"], TOOLS["cloudflared"]]
    assert cloud.processes[1].argv == [TOOLS["cloudflared"], "tunnel", "--no-autoupdate", "run"]
    assert cloud.processes[1].env["TUNNEL_TOKEN"] == TUNNEL_TOKEN
    assert all(process.stopped for process in cloud.processes)
    assert cloud.slept == [jev.PROBE_SETTLE] and len(cloud.cases) == 4
    for argv, env in cloud.cases:
        assert PROXY in argv and "BatchMode=yes" in argv and argv[-1] == jev.PROBE_HOSTNAME
    pair = {"TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET"}
    assert [set(env) & pair for _, env in cloud.cases] == [pair, set(), pair, pair]
    assert cloud.cases[3][1]["TUNNEL_SERVICE_TOKEN_SECRET"] == SERVICE_VALUE
    assert cloud.cases[2][1]["TUNNEL_SERVICE_TOKEN_SECRET"] != SERVICE_VALUE
    no_secret_escapes(cloud, result)
    lookups_never_mutate(cloud)


def only_lookup(cloud: Cloud) -> None:
    assert {phase for phase, _ in cloud.tofu_calls()} == {"before"} and not cloud.processes and not cloud.cases
    lookups_never_mutate(cloud)


@with_root
def test_preflight_match_stops(root: Path) -> None:
    # Even one fixed-name match is a candidate of unproven ownership: stop before create, adopt or delete nothing.
    for located in ({**EMPTY, "tunnels": ["t"]}, {**EMPTY, "service_tokens": ["a", "b"]}):
        cloud = Cloud(before=located)
        result = cloud.probe(root)
        assert result["status"] == "UNKNOWN" and result["stage"] == "preflight" and result["located"] == located
        assert result["ownership"] == "UNPROVEN" and result["next"] == "NEEDS_AUTHORITY"
        only_lookup(cloud)


@with_root
def test_locate_only(root: Path) -> None:
    cloud = Cloud()
    assert cloud.probe(root, locate_only=True)["status"] == "NONE_LOCATED"
    only_lookup(cloud)
    single = {**EMPTY, "dns_records": ["d"]}
    cloud = Cloud(before=single)
    result = cloud.probe(root, locate_only=True)
    assert (result["status"], result["ownership"], result["next"]) == ("UNKNOWN", "UNPROVEN", "NEEDS_AUTHORITY")
    only_lookup(cloud)


@with_root
def test_probe_outcomes(root: Path) -> None:
    timeout = ("timeout", -1, b"")
    for outcomes, status in (
        ({"service_token": timeout}, "UNKNOWN"),
        ({"service_token": ("exit", 255, b""), "service_token_again": ("exit", 255, b"")}, "UNATTENDED_PATH_FAILED"),
        ({"service_token": ("exit", 0, b"login page"), "service_token_again": ("exit", 1, b"")},
         "UNATTENDED_PATH_FAILED"),
        # The path was not up on both sides of the negatives: their refusal says nothing, so UNKNOWN.
        ({"service_token_again": ("exit", 255, b"")}, "UNKNOWN"),
        ({"service_token": ("exit", 255, b"")}, "UNKNOWN"),
        ({"no_token": "nonce"}, "ACCESS_NOT_ENFORCED"),
        ({"wrong_token": "nonce"}, "ACCESS_NOT_ENFORCED"),
        ({"wrong_token": timeout}, "UNKNOWN"),
        ({"service_token": ("exit", 255, b""), "no_token": timeout}, "UNKNOWN"),
    ):
        cloud = Cloud(outcomes=outcomes)
        result = cloud.probe(root)
        assert result["status"] == status, (outcomes, result)
        assert result["probe"]["cause"] == "UNKNOWN" and result["cleanup"] == "ABSENT"
        assert result["probe"]["access_denial_evidence"] == "NOT_OBSERVED"
        assert all(process.stopped for process in cloud.processes) and len(cloud.cases) == 4
        no_secret_escapes(cloud, result)
        lookups_never_mutate(cloud)


@with_root
def test_failures_fail_closed(root: Path) -> None:
    # A failed create still destroys exactly this state; any cleanup doubt is CLEANUP_UNKNOWN, never retried.
    cloud = Cloud(fail={("probe", "apply")})
    result = cloud.probe(root)
    assert result["status"] == "UNKNOWN" and result["cleanup"] == "ABSENT" and not cloud.processes
    assert [args[0] for phase, args in cloud.tofu_calls() if phase == "probe"] == ["init", "apply", "destroy"]
    assert API_TOKEN not in result["error"]
    no_secret_escapes(cloud, result)
    for world in (Cloud(fail={("probe", "destroy")}), Cloud(after={**EMPTY, "tunnels": ["t"]}),
                  Cloud(fail={("after", "apply")})):
        result = world.probe(root)
        # A reached probe never stands as the status while resources may remain.
        assert result["status"] == "CLEANUP_UNKNOWN" and result["cleanup"] == "CLEANUP_UNKNOWN", result
        assert result["probe"]["status"] == "TOKEN_REACHED_NEGATIVES_REFUSED"
        assert sum(1 for _, args in world.tofu_calls() if args[0] == "destroy") == 1
        no_secret_escapes(world, result)
        lookups_never_mutate(world)


def expect_probe_red(values: dict[str, str], mutate=None) -> None:
    root = fixtures.copy_root()
    cloud = Cloud()
    try:
        if mutate is not None:
            mutate(root)
        with fixtures.environment(values):
            try:
                cloud.probe(root)
            except jev.EnvsError as exc:
                assert not any(value in str(exc) for value in SECRETS)
            else:
                raise AssertionError("invalid probe input was accepted")
        assert not cloud.calls and not cloud.processes, "a tool ran before the input gate"
    finally:
        shutil.rmtree(root.parent, ignore_errors=True)


def test_probe_red_inputs() -> None:
    for name in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ZONE_ID"):
        expect_probe_red(probe_env(**{name: ""}))
    expect_probe_red(probe_env(CLOUDFLARE_ZONE_ID=ZONE_ID[:31]))
    expect_probe_red(probe_env(CLOUDFLARE_ZONE_ID=ZONE_ID.upper()))
    for value in (API_TOKEN, ZONE_ID, ACCOUNT_ID):
        expect_probe_red(probe_env(), mutate=lambda root, value=value: fixtures.append(root / "README.md", f"\n{value}\n"))
    outside = Path(tempfile.mkdtemp(prefix="envs-probe-outside-"))
    try:
        for values, mutate in fixtures.toolchain_red_cases(outside / "toolchain.json"):
            expect_probe_red(probe_env(**values), mutate=mutate)
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def real_ssh(bin_dir: str) -> None:
    # The locked sshd/ssh/ssh-keygen: the probe's sshd answers the authorized key with the nonce and refuses another.
    tools = {name: os.path.realpath(os.path.join(bin_dir, file)) for name, file in (
        ("ssh", "ssh"), ("sshd", "sshd"), ("ssh_keygen", "ssh-keygen"))}
    for path in tools.values():
        assert path.startswith("/nix/store/") and os.access(path, os.X_OK), path
    work = Path(tempfile.mkdtemp(prefix="envs-probe-ssh-"))
    try:
        fixture = jev.ssh_fixture(tools, work / "ssh", jev.default_runner)
        env = {"PATH": os.pathsep.join(sorted({os.path.dirname(path) for path in tools.values()}) + ["/usr/bin", "/bin"]),
               "HOME": str(work)}
        sshd = jev.default_spawn([tools["sshd"], "-D", "-e", "-f", str(fixture["directory"] / "sshd_config")], env)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    socket.create_connection(("127.0.0.1", jev.PROBE_PORT), timeout=1).close()
                    break
                except OSError:
                    assert time.monotonic() < deadline and sshd.poll() is None, "sshd did not listen"
                    time.sleep(0.2)
            argv = jev.ssh_argv(tools, fixture, "127.0.0.1", proxy=False)
            outcome = jev.default_bounded(argv, env, 30)
            assert jev.classify({"service_token": outcome, "no_token": ("exit", 255, b""), "wrong_token": ("exit", 255, b""),
                                 "service_token_again": outcome}, fixture["nonce"])["cases"]["service_token"] == "REACHED", \
                outcome[:2]
            other = list(argv)
            other[other.index("-i") + 1] = str(fixture["directory"] / "host")
            refused = jev.default_bounded(other, env, 30)
            assert refused[0] == "exit" and refused[1] != 0 and fixture["nonce"].encode() not in refused[2]
        finally:
            jev.stop(sshd)
        print(f"real localhost ssh: PASS (sshd={tools['sshd']})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-ssh", metavar="BIN")
    args = parser.parse_args()
    try:
        jev.validate_contracts(ROOT)
        test_probe_pass()
        test_preflight_match_stops()
        test_locate_only()
        test_probe_outcomes()
        test_failures_fail_closed()
        test_probe_red_inputs()
        if args.real_ssh is None:
            print("real localhost ssh: NOT RUN (the check workflow runs it with --real-ssh)")
        else:
            real_ssh(args.real_ssh)
    finally:
        shutil.rmtree(fixtures.STORE, ignore_errors=True)
    print("access probe adapter self-test: PASS")


if __name__ == "__main__":
    main()
