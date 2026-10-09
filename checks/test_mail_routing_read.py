#!/usr/bin/env python3
"""Read-only Mail M0 preflight: synthetic input and negative security cases."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import urllib.error
import urllib.parse
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
TOKEN = "private_fixture_token_opaque"
RECIPIENT = "very.private@example.invalid"
ENV = {"CLOUDFLARE_API_TOKEN": TOKEN, "CLOUDFLARE_ACCOUNT_ID": ACCOUNT}


def wrapped(value: object, total: int | None = None) -> bytes:
    response = {"success": True, "errors": [], "result": value}
    if isinstance(value, list):
        response["result_info"] = {
            "page": 1, "per_page": 50, "total_pages": 1,
            "total_count": len(value) if total is None else total,
        }
    return json.dumps(response).encode()


class Response:
    status = 200

    def __init__(self, value: object) -> None:
        self.data = value

    def read(self, *_args: object) -> bytes:
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class Fake:
    def __init__(self, denied: str = "", bad: str = "", wrong_account: bool = False,
                 second_zone: bool = False) -> None:
        self.calls: list[str] = []
        self.denied = denied
        self.bad = bad
        self.wrong_account = wrong_account
        self.second_zone = second_zone

    def __call__(self, req, **kwargs):
        assert req.get_method() == "GET"
        assert kwargs == {"timeout": 12}
        assert req.get_header("Authorization") == "Bearer " + TOKEN
        url = urllib.parse.urlsplit(req.full_url)
        assert url.scheme == "https" and url.netloc == "api.cloudflare.com"
        path = url.path.removeprefix("/client/v4")
        self.calls.append(path)
        if path == self.denied:
            raise urllib.error.HTTPError(req.full_url, 403, "ContainsSecret:" + TOKEN, {}, None)
        if path == self.bad:
            return Response(b'{"result": [{"private": "MALFORMED"}]}')
        if path == "/user/tokens/verify":
            return Response(wrapped({"status": "active"}))
        if path == "/zones":
            query = urllib.parse.parse_qs(url.query)
            assert query["name"] == [DOMAIN]
            assert query["account.id"] == [ACCOUNT]
            assert query["match"] == ["all"]
            assert query["page"] == ["1"]
            base = {"id": ZONE, "name": DOMAIN,
                    "account": {"id": "f" * 32 if self.wrong_account else ACCOUNT}}
            return Response(wrapped([base, base] if self.second_zone else [base]))
        if path == f"/zones/{ZONE}/dns_records":
            return Response(wrapped([
                {"type": "MX", "name": DOMAIN, "content": "private-mx.invalid"},
                {"type": "TXT", "name": DOMAIN, "content": TOKEN},
            ]))
        if path == f"/zones/{ZONE}/email/routing":
            return Response(wrapped({"enabled": True, "status": "ready"}))
        if path == f"/zones/{ZONE}/email/routing/dns":
            return Response(wrapped([{"type": "MX", "name": DOMAIN, "content": "private-mx.invalid"}]))
        if path == f"/zones/{ZONE}/email/routing/rules":
            return Response(wrapped([{"id": "private", "source": "wrangler", "enabled": True, "actions": [{"value": [RECIPIENT]}]}]))
        if path == f"/zones/{ZONE}/email/routing/rules/catch_all":
            return Response(wrapped({"enabled": False, "actions": [{"value": [RECIPIENT]}]}))
        if path == f"/accounts/{ACCOUNT}/email/routing/addresses":
            return Response(wrapped([{"email": RECIPIENT, "verified": "2026-10-09T00:00:00Z"}]))
        raise AssertionError("Unapproved URL or fallback path was called")


def event(path: Path, domain: object = DOMAIN) -> str:
    path.write_text(json.dumps({"inputs": {"domain": domain}}), encoding="utf-8")
    return str(path)


def no_values_leak(result: dict) -> None:
    public = json.dumps(result)
    for secret in (DOMAIN, ACCOUNT, ZONE, TOKEN, RECIPIENT, "private-mx.invalid",
                   "MALFORMED", "ContainsSecret"):
        assert secret not in public, secret
    assert "traceback" not in public.lower()


def main() -> None:
    with tempfile.TemporaryDirectory() as home:
        selected = event(Path(home) / "event.json")
        opener = Fake()
        result = mail.observe(selected, ENV, opener)
        assert result["status"] == "READ_OBSERVED", result
        assert all(x == "OBSERVED" for x in result["read"].values())
        assert result["write_authority"] == result["mail_arrival"] == "NOT_PROVEN"
        assert result["facts"]["routing_ready"] is True
        assert result["counts"] == {
            "dns": 2, "mx": 1, "txt": 1, "routing_dns_records": 1,
            "rules": 1, "enabled_rules": 1, "wrangler_rules": 1,
            "account_destinations": 1, "verified_destinations": 1,
        }
        assert len(opener.calls) == len(mail.STEPS)
        no_values_leak(result)

        # Reject invalid target before *any* provider request.
        for invalid in ("other.invalid/", "*.invalid", "https://example.invalid", "example.invalid ",
                        "two@example.invalid", "example.invalid/path", "", 21, "例子.invalid"):
            op = Fake()
            got = mail.observe(event(Path(home) / "event.json", invalid), ENV, op)
            assert got["status"] == "INCOMPLETE" and op.calls == []
            no_values_leak(got)
        selected = event(Path(home) / "event.json")
        for bad in (
            {"CLOUDFLARE_API_TOKEN": TOKEN},
            {"CLOUDFLARE_ACCOUNT_ID": ACCOUNT},
            {"CLOUDFLARE_ACCOUNT_ID": "f" * 31, "CLOUDFLARE_API_TOKEN": TOKEN},
        ):
            op = Fake()
            assert mail.observe(selected, bad, op)["status"] == "INCOMPLETE"
            assert op.calls == []

        for option in ({"wrong_account": True}, {"second_zone": True}):
            op = Fake(**option)
            got = mail.observe(selected, ENV, op)
            assert got["status"] == "INCOMPLETE"
            assert op.calls == ["/user/tokens/verify", "/zones"]
            no_values_leak(got)

        # 403 says only that one operation was denied. No guessed root cause
        # and no automatic retry/other account/token/scope selection.
        for denial in (
            "/user/tokens/verify",
            "/zones",
            f"/zones/{ZONE}/email/routing/rules",
            f"/accounts/{ACCOUNT}/email/routing/addresses",
        ):
            op = Fake(denied=denial)
            result = mail.observe(selected, ENV, op)
            assert result["status"] == "INCOMPLETE"
            assert "DENIED" in result["read"].values()
            assert len(op.calls) == len(set(op.calls))
            no_values_leak(result)

        malformed = Fake(bad=f"/zones/{ZONE}/dns_records")
        result = mail.observe(selected, ENV, malformed)
        assert result["status"] == "INCOMPLETE" and result["read"]["dns"] == "UNKNOWN"
        assert "dns" not in result["counts"]
        no_values_leak(result)

        saved = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update({**ENV, "GITHUB_EVENT_PATH": selected})
            # main is exercised only with invalid inputs: never contact a
            # real provider from a source test, even with fixture credentials.
            os.environ["CLOUDFLARE_ACCOUNT_ID"] = "wrong"
            out = io.StringIO()
            with redirect_stdout(out):
                code = mail.main()
            assert code == 2
            no_values_leak(json.loads(out.getvalue()))
        finally:
            os.environ.clear()
            os.environ.update(saved)

    print("mail routing read selftest: PASS; synthetic GET only / closed outputs")


if __name__ == "__main__":
    main()
