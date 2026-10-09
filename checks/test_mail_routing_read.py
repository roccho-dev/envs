#!/usr/bin/env python3
"""Offline security regressions for the M0 Mail GET-only client."""
from __future__ import annotations

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
ACCOUNT = "a" * 32
ZONE = "b" * 32
TOKEN = "private_cf_fixture_token"
RECIPIENT = "very.private@example.invalid"
ENV = {"CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ACCOUNT_ID": ACCOUNT}


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
                 duplicate: bool = False, overrides: dict[str, object] | None = None,
                 zone_reply: bytes | None = None, zone_http: int | None = None,
                 zone_transport: bool = False, zone_id: str = ZONE,
                 wrong_name: bool = False, zone_unexpected: bool = False) -> None:
        self.calls: list[str] = []
        self.deny = deny
        self.bad = bad
        self.wrong_account = wrong_account
        self.duplicate = duplicate
        self.overrides = overrides or {}
        self.zone_reply = zone_reply
        self.zone_http = zone_http
        self.zone_transport = zone_transport
        self.zone_id = zone_id
        self.wrong_name = wrong_name
        self.zone_unexpected = zone_unexpected

    def __call__(self, req: urllib.request.Request, **kwargs: object):
        assert req.get_method() == "GET"
        assert kwargs == {"timeout": 12}
        url = urllib.parse.urlsplit(req.full_url)
        assert url.scheme == "https"
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
        if path == "/user/tokens/verify":
            return Response(wrap({"status": "active"}))
        if path == "/zones":
            query = urllib.parse.parse_qs(url.query)
            assert query == {
                "name": [DOMAIN], "account.id": [ACCOUNT], "match": ["all"],
                "page": ["1"], "per_page": ["50"],
            }
            if self.zone_http is not None:
                raise urllib.error.HTTPError(req.full_url, self.zone_http, TOKEN, {}, None)
            if self.zone_transport:
                raise urllib.error.URLError("private transport " + TOKEN)
            if self.zone_unexpected:
                raise RuntimeError("private internal " + TOKEN)
            if self.zone_reply is not None:
                return Response(self.zone_reply)
            wanted = {"name": DOMAIN + ".other" if self.wrong_name else DOMAIN,
                      "id": self.zone_id,
                      "account": {"id": "f" * 32 if self.wrong_account else ACCOUNT}}
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
            return Response(wrap([{
                "source": "wrangler", "enabled": True,
                "actions": [{"value": [RECIPIENT]}],
                "matchers": [{"type": "literal", "field": "to", "value": "m0@" + DOMAIN}],
            }]))
        if path == f"/zones/{ZONE}/email/routing/rules/catch_all":
            return Response(wrap({"enabled": False}))
        if path == f"/accounts/{ACCOUNT}/email/routing/addresses":
            return Response(wrap([{"email": RECIPIENT, "verified": "2026-10-09T00:00:00Z"}]))
        raise AssertionError("unexpected provider path / fallback")


def event(path: Path, value: object = DOMAIN) -> str:
    path.write_text(json.dumps({"inputs": {"domain": value}}), encoding="utf-8")
    return str(path)


def safe(result: dict) -> None:
    text = json.dumps(result)
    for private in (DOMAIN, ACCOUNT, ZONE, TOKEN, RECIPIENT,
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
            response = Response(b"")
            response.code = self.code
            response.status = self.code
            response.msg = "synthetic redirect"
            response.info = lambda: {"Location": self.location}
            response.geturl = lambda: req.full_url
            response.close = lambda: None
            return response

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
        assert "zone_unknown_reason" not in answer
        assert answer["write_authority"] == answer["mail_arrival"] == "NOT_PROVEN"
        assert answer["facts"]["token_active"] is True
        assert answer["facts"]["routing_ready"] is True and answer["facts"]["catch_all_enabled"] is False
        assert answer["counts"]["verified_destinations"] == 1
        safe(answer)

        # Domain is an explicit non-secret native workflow selector; it
        # remains excluded from adapter stdout, provider identities and logs.
        for wrong in ("", "xyz", "Z" * 64, 3, None, {"name": DOMAIN},
                      "https://" + DOMAIN, "*.example.invalid", DOMAIN + " "):
            fixture = Fake()
            result = mail.observe(event(path, wrong), ENV, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)
        selected = event(path)
        for missing in ({}, {"CLOUDFLARE_API_TOKEN": TOKEN},
                        {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT},
                        {"CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ACCOUNT_ID": "f" * 31}):
            fixture = Fake()
            result = mail.observe(selected, missing, fixture)
            assert result["status"] == "INCOMPLETE" and fixture.calls == []
            safe(result)

        for fixture in (Fake(wrong_account=True), Fake(duplicate=True)):
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert result["zone_unknown_reason"] in ("owner_or_id_mismatch", "multiple_match")
            assert "addresses" not in result["counts"]
            safe(result)

        # HTTP refusal is per-operation, not proof of missing Write access.
        for endpoint in ("/user/tokens/verify", "/zones",
                         f"/zones/{ZONE}/email/routing/rules",
                         f"/accounts/{ACCOUNT}/email/routing/addresses"):
            fixture = Fake(deny=endpoint)
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert "DENIED" in result["read"].values()
            assert len(fixture.calls) == len(set(fixture.calls))
            safe(result)

        bad_objects = (
            ("/user/tokens/verify", {}, "token"),
            ("/zones", [], "zone"),
            (f"/zones/{ZONE}/dns_records", [{}], "dns"),
            (f"/zones/{ZONE}/dns_records", [{"type": None}], "dns"),
            (f"/zones/{ZONE}/email/routing/dns", [{}], "routing_dns"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [],
            }], "rules"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [], "matchers": "literal",
            }], "rules"),
            (f"/zones/{ZONE}/email/routing/rules", [{
                "source": "api", "enabled": True, "actions": [], "matchers": [{}],
            }], "rules"),
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

        # Zone diagnostic is a single closed non-secret reason code for
        # UNKNOWN *only*: these are fully synthetic original decision paths,
        # never a second Cloudflare dispatch or a guessed scope diagnosis.
        def zone_case(fixture: Fake, expected: str) -> None:
            result = mail.observe(selected, ENV, fixture)
            assert result["status"] == "INCOMPLETE"
            assert result["read"]["token"] == "OBSERVED"
            assert result["read"]["zone"] == "UNKNOWN"
            assert result["zone_unknown_reason"] == expected, (result, expected)
            assert expected in mail.ZONE_UNKNOWN_REASONS
            assert result["facts"] == {"token_active": True}
            assert result["counts"] == {}
            assert all(result["read"][step] == "UNKNOWN"
                       for step in mail.STEPS if step not in ("token", "zone"))
            assert fixture.calls == ["/user/tokens/verify", "/zones"], fixture.calls
            safe(result)

        zone_case(Fake(overrides={"/zones": []}), "zero_match")
        zero_pages = json.loads(wrap([]))
        zero_pages["result_info"]["total_pages"] = 0
        zone_case(Fake(zone_reply=json.dumps(zero_pages).encode()), "zero_match")
        zone_case(Fake(duplicate=True), "multiple_match")
        zone_case(Fake(wrong_account=True), "owner_or_id_mismatch")
        zone_case(Fake(wrong_name=True), "owner_or_id_mismatch")
        zone_case(Fake(zone_id="not-an-id"), "owner_or_id_mismatch")
        for http_status in (302, 429, 500):
            zone_case(Fake(zone_http=http_status), "http_other")
        zone_case(Fake(zone_transport=True), "transport")
        zone_case(Fake(zone_unexpected=True), "unclassified")
        zone_case(Fake(bad="/zones"), "invalid_payload_or_pagination")
        zone_case(Fake(zone_reply=b'{not-json-private-body'), "invalid_payload_or_pagination")
        for broken in (
            {"result_info": {"page": 1, "per_page": 50, "total_pages": 1, "total_count": 1},
             "success": True, "result": []},
            {"result_info": {"page": 2, "per_page": 50, "total_pages": 1, "total_count": 0},
             "success": True, "result": []},
            {"result_info": {"page": 1, "per_page": 50, "total_pages": 0, "total_count": 1},
             "success": True, "result": [{"name": DOMAIN, "id": ZONE, "account": {"id": ACCOUNT}}]},
            {"result_info": {"page": 1, "per_page": 50, "total_pages": "1", "total_count": 0},
             "success": True, "result": []},
        ):
            zone_case(Fake(zone_reply=json.dumps(broken).encode()), "invalid_payload_or_pagination")

        # An explicit 401/403 is DENIED, not UNKNOWN; a valid empty rules
        # or account-destinations list is OBSERVED with an actual zero count.
        for http_status in (401, 403):
            fixture = Fake(zone_http=http_status)
            denied = mail.observe(selected, ENV, fixture)
            assert denied["read"]["zone"] == "DENIED"
            assert "zone_unknown_reason" not in denied
            safe(denied)
        for path_name, count_key in (
            (f"/zones/{ZONE}/email/routing/rules", "rules"),
            (f"/accounts/{ACCOUNT}/email/routing/addresses", "account_destinations"),
        ):
            passed = mail.observe(selected, ENV, Fake(overrides={path_name: []}))
            assert passed["status"] == "READ_OBSERVED"
            assert passed["counts"][count_key] == 0
            assert "zone_unknown_reason" not in passed
            safe(passed)

        # Exercise main() with synthetic *valid* account and mocked opener
        # to establish that its actual public JSON retains only the enum.
        prior_opener = mail.safe_opener
        saved_env = dict(os.environ)
        try:
            mail.safe_opener = lambda: Fake(zone_transport=True)
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            output = io.StringIO()
            with redirect_stdout(output):
                assert mail.main() == 2
            exposed = json.loads(output.getvalue())
            assert exposed["zone_unknown_reason"] == "transport"
            safe(exposed)
        finally:
            mail.safe_opener = prior_opener
            os.environ.clear()
            os.environ.update(saved_env)

        result = mail.observe(selected, ENV, Fake(bad=f"/zones/{ZONE}/dns_records"))
        assert result["status"] == "INCOMPLETE" and result["read"]["dns"] == "UNKNOWN"
        safe(result)

        # Main entry only with INVALID input; never execute a live network
        # call from this synthetic CI test.
        preserved = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            os.environ["CLOUDFLARE_ACCOUNT_ID"] = "invalid"
            stream = io.StringIO()
            with redirect_stdout(stream):
                assert mail.main() == 2
            safe(json.loads(stream.getvalue()))
        finally:
            os.environ.clear()
            os.environ.update(preserved)

    workflow = (ROOT / ".github/workflows/probe-dev-mail-routing.yml").read_text(encoding="utf-8")
    assert "      domain:\n" in workflow and "domain_sha256:" not in workflow
    assert "CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}" in workflow
    assert "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in workflow
    assert "GH_TOKEN: ${{ github.token }}\n          CLOUDFLARE_API_TOKEN" not in workflow
    assert "github.actor_id == '40359643'" in workflow
    assert "github.triggering_actor == 'roccho-dev'" in workflow
    assert "inputs.domain" not in workflow
    assert "environment: dev-projection" in workflow
    test_transport_no_redirect_no_proxy()
    print("mail routing read selftest: PASS; GET-only, safe transport/schema/metadata")


if __name__ == "__main__":
    main()
