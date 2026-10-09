#!/usr/bin/env python3
"""Offline security regressions for the M0 Mail GET-only client."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import urllib.response
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mail_probe", ROOT / "adapters/mail_routing_read.py")
assert SPEC is not None and SPEC.loader is not None
mail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mail)

DOMAIN = "hidden.example.invalid"
SELECTOR = hashlib.sha256(DOMAIN.encode()).hexdigest()
ACCOUNT = "a" * 32
ZONE = "b" * 32
TOKEN = "private_cf_fixture_token"
GITHUB_TOKEN = "private_github_fixture_token"
RECIPIENT = "very.private@example.invalid"
ENV = {"CLOUDFLARE_API_TOKEN": TOKEN, "GH_TOKEN": GITHUB_TOKEN}


def wrap(value: object) -> bytes:
    payload: dict = {"success": True, "errors": [], "result": value}
    if isinstance(value, list):
        payload["result_info"] = {
            "page": 1, "per_page": 50, "total_pages": 1, "total_count": len(value),
        }
    return json.dumps(payload).encode()


class Response:
    status = 200

    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, *_args: object) -> bytes:
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class Fake:
    """Every mocked call asserts pinned origin, GET and correct bearer."""
    def __init__(self, deny: str = "", bad: str = "", wrong_account: bool = False,
                 duplicate: bool = False, overrides: dict[str, object] | None = None) -> None:
        self.calls: list[str] = []
        self.deny = deny
        self.bad = bad
        self.wrong_account = wrong_account
        self.duplicate = duplicate
        self.overrides = overrides or {}

    def __call__(self, req: urllib.request.Request, **kwargs: object):
        assert req.get_method() == "GET"
        assert kwargs == {"timeout": 12}
        url = urllib.parse.urlsplit(req.full_url)
        assert url.scheme == "https"
        if url.netloc == "api.github.com":
            assert req.full_url == mail.GITHUB_ACCOUNT_URL
            assert req.get_header("Authorization") == "Bearer " + GITHUB_TOKEN
            path = "github-account"
        else:
            assert url.netloc == "api.cloudflare.com"
            assert req.get_header("Authorization") == "Bearer " + TOKEN
            path = url.path.removeprefix("/client/v4")
        self.calls.append(path)
        if path == self.deny:
            raise urllib.error.HTTPError(req.full_url, 403, TOKEN, {}, None)
        if path == self.bad:
            return Response(b'{"result":{"contains":"SECRET_RESPONSE"}}')
        if path in self.overrides:
            return Response(wrap(self.overrides[path]))
        if path == "github-account":
            return Response(json.dumps({
                "name": "CLOUDFLARE_ACCOUNT_ID",
                "value": "f" * 32 if self.wrong_account else ACCOUNT,
            }).encode())
        if path == "/user/tokens/verify":
            return Response(wrap({"status": "active"}))
        if path == "/zones":
            query = urllib.parse.parse_qs(url.query)
            assert query == {"account.id": [ACCOUNT], "match": ["all"], "page": ["1"], "per_page": ["50"]}
            wanted = {"name": DOMAIN, "id": ZONE, "account": {"id": ACCOUNT}}
            return Response(wrap([wanted, wanted] if self.duplicate else [wanted]))
        if path == f"/zones/{ZONE}/dns_records":
            return Response(wrap([
                {"type": "MX", "name": DOMAIN, "content": "private-mx.invalid"},
                {"type": "TXT", "name": DOMAIN, "content": TOKEN},
            ]))
        if path == f"/zones/{ZONE}/email/routing":
            return Response(wrap({"enabled": True, "status": "ready"}))
        if path == f"/zones/{ZONE}/email/routing/dns":
            return Response(wrap([{"type": "MX", "name": DOMAIN}]))
        if path == f"/zones/{ZONE}/email/routing/rules":
            return Response(wrap([{"source": "wrangler", "enabled": True, "actions": [{"value": [RECIPIENT]}]}]))
        if path == f"/zones/{ZONE}/email/routing/rules/catch_all":
            return Response(wrap({"enabled": False}))
        if path == f"/accounts/{ACCOUNT}/email/routing/addresses":
            return Response(wrap([{"email": RECIPIENT, "verified": "2026-10-09T00:00:00Z"}]))
        raise AssertionError("unexpected provider path / fallback")


def event(path: Path, value: object = SELECTOR) -> str:
    path.write_text(json.dumps({"inputs": {"domain_sha256": value}}), encoding="utf-8")
    return str(path)


def safe(result: dict) -> None:
    text = json.dumps(result)
    for private in (DOMAIN, ACCOUNT, ZONE, TOKEN, GITHUB_TOKEN, RECIPIENT, SELECTOR,
                    "private-mx.invalid", "SECRET_RESPONSE"):
        assert private not in text, "private value leaked"
    assert "traceback" not in text.lower()


def test_transport_no_redirect_no_proxy() -> None:
    class Redirect(urllib.request.HTTPSHandler):
        def __init__(self, code: int, location: str) -> None:
            super().__init__()
            self.calls: list[str] = []
            self.code = code
            self.location = location

        def https_open(self, req: urllib.request.Request):
            self.calls.append(req.full_url)
            return urllib.response.addinfourl(
                io.BytesIO(b""), {"Location": self.location}, req.full_url, code=self.code,
            )

    prior = {key: os.environ.get(key) for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
    try:
        os.environ.update({"HTTP_PROXY": "http://proxy.invalid:8888",
                           "HTTPS_PROXY": "http://proxy.invalid:8888",
                           "http_proxy": "http://proxy.invalid:8888",
                           "https_proxy": "http://proxy.invalid:8888"})
        for code in (302, 307):
            for location in ("https://evil.invalid/steal", "https://api.cloudflare.com/client/v4/else"):
                handler = Redirect(code, location)
                opener = mail.safe_opener(handler)
                try:
                    mail._request(opener, TOKEN, "/user/tokens/verify")
                    raise AssertionError("redirect accepted")
                except mail.ReadFailure as failure:
                    assert failure.state == "UNKNOWN"
                assert handler.calls == ["https://api.cloudflare.com/client/v4/user/tokens/verify"]
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "event.json"
        selected = event(path)
        success = Fake()
        answer = mail.observe(selected, ENV, success)
        assert answer["status"] == "READ_OBSERVED", answer
        assert all(s == "OBSERVED" for s in answer["read"].values())
        assert len(success.calls) == len(mail.STEPS)
        assert answer["write_authority"] == answer["mail_arrival"] == "NOT_PROVEN"
        assert answer["facts"]["token_active"] is True
        assert answer["facts"]["routing_ready"] is True and answer["facts"]["catch_all_enabled"] is False
        assert answer["counts"]["verified_destinations"] == 1
        safe(answer)

        # Raw domain/zone/account never supplied by workflow metadata or step env.
        for wrong in (DOMAIN, "", "xyz", "Z" * 64, 3, None, {"name": DOMAIN}):
            fixture = Fake()
            result = mail.observe(event(path, wrong), ENV, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)
        selected = event(path)
        for missing in ({}, {"CLOUDFLARE_API_TOKEN": TOKEN},
                        {"GH_TOKEN": GITHUB_TOKEN}):
            fixture = Fake()
            result = mail.observe(selected, missing, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)

        for fixture in (Fake(wrong_account=True), Fake(duplicate=True)):
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert "addresses" not in result["counts"]
            safe(result)

        # HTTP refusal is per-operation, not proof of missing Write access.
        for endpoint in ("github-account", "/user/tokens/verify", "/zones",
                         f"/zones/{ZONE}/email/routing/rules",
                         f"/accounts/{ACCOUNT}/email/routing/addresses"):
            fixture = Fake(deny=endpoint)
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            if endpoint == "github-account":
                assert result["read"]["account"] == "UNKNOWN"
                assert fixture.calls == ["github-account"]
            else:
                assert "DENIED" in result["read"].values()
            assert len(fixture.calls) == len(set(fixture.calls))
            safe(result)

        bad_objects = (
            ("/user/tokens/verify", {}, "token"),
            ("/zones", [], "zone"),
            (f"/zones/{ZONE}/email/routing", {}, "routing"),
            (f"/zones/{ZONE}/email/routing", {"enabled": "false", "status": "ready"}, "routing"),
            (f"/zones/{ZONE}/email/routing", {"enabled": False}, "routing"),
            (f"/zones/{ZONE}/email/routing/rules/catch_all", {}, "catch_all"),
            (f"/zones/{ZONE}/email/routing/rules/catch_all", {"enabled": "false"}, "catch_all"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT}], "addresses"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT, "verified": True}], "addresses"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", [{"email": RECIPIENT, "verified": "false"}], "addresses"),
        )
        for path_name, response, step in bad_objects:
            fixture = Fake(overrides={path_name: response})
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE" and result["read"][step] == "UNKNOWN", (step, result)
            safe(result)
        for status in ("disabled", "expired", "inactive"):
            result = mail.observe(selected, ENV, Fake(overrides={"/user/tokens/verify": {"status": status}}))
            assert result["status"] == "INCOMPLETE"
            assert result["read"]["token"] == "OBSERVED" and result["facts"]["token_active"] is False
            safe(result)

        result = mail.observe(selected, ENV, Fake(bad=f"/zones/{ZONE}/dns_records"))
        assert result["status"] == "INCOMPLETE" and result["read"]["dns"] == "UNKNOWN"
        safe(result)

        # Main entry only with INVALID input; never execute a real network call
        # from the synthetic CI test (no provider, no GitHub API).
        preserved = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            os.environ["GH_TOKEN"] = ""
            stream = io.StringIO()
            with redirect_stdout(stream):
                assert mail.main() == 2
            safe(json.loads(stream.getvalue()))
        finally:
            os.environ.clear()
            os.environ.update(preserved)

    workflow = (ROOT / ".github/workflows/probe-dev-mail-routing.yml").read_text(encoding="utf-8")
    assert "domain_sha256:" in workflow and "domain:\n" not in workflow
    assert "CLOUDFLARE_ACCOUNT_ID: " not in workflow
    assert "${{ vars.CLOUDFLARE_ACCOUNT_ID }}" not in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert "github.actor_id == '40359643'" in workflow
    assert "github.triggering_actor == 'roccho-dev'" in workflow
    assert "GITHUB_EVENT_PATH" not in workflow or "domain_sha256" in workflow
    test_transport_no_redirect_no_proxy()
    print("mail routing read selftest: PASS; GET-only, safe transport/schema/metadata")


if __name__ == "__main__":
    main()
