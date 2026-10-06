#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("envs_jev_api", ROOT / "adapters/jev_api.py")
assert SPEC is not None and SPEC.loader is not None
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class Response:
    def __init__(self, scopes: str) -> None:
        self.status = 200
        self.headers = {"X-OAuth-Scopes": scopes}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int = -1) -> bytes:
        return b"{"


class Opener:
    def __init__(self, scopes: str) -> None:
        self.scopes = scopes
        self.urls: list[str] = []

    def __call__(self, request, **_kwargs):
        assert request.get_method() == "GET"
        assert request.headers["Authorization"].startswith("Bearer ")
        self.urls.append(request.full_url)
        return Response(self.scopes)


def expect_red(callable_) -> str:
    try:
        callable_()
    except adapter.EnvsError as exc:
        return str(exc)
    raise AssertionError("invalid Linode probe state was accepted")


def main() -> None:
    previous = os.environ.get("LINODE_API_TOKEN")
    token = "".join(("linode-", "read-", "fixture"))
    try:
        os.environ["LINODE_API_TOKEN"] = token
        opener = Opener("account:read_only, linodes:read_only")
        result = adapter.linode_read_probe(ROOT, opener=opener)
        assert result == {
            "kind": "envs.linodeReadProbe.v1",
            "status": "PASS",
            "checks": {"profile": "PASS", "account": "PASS", "linodes": "PASS"},
        }
        assert opener.urls == [
            "https://api.linode.com/v4/profile",
            "https://api.linode.com/v4/account",
            "https://api.linode.com/v4/linode/instances?page_size=25",
        ]

        broad = Opener("account:read_write, linodes:read_write, events:read_only")
        assert adapter.linode_read_probe(ROOT, opener=broad)["status"] == "PASS"

        def denied(request, **_kwargs):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

        message = expect_red(lambda: adapter.linode_read_probe(ROOT, opener=denied))
        assert "HTTP 403" in message
        assert token not in message

        os.environ.pop("LINODE_API_TOKEN")
        assert "LINODE_API_TOKEN is missing" in expect_red(lambda: adapter.linode_read_probe(ROOT, opener=opener))
    finally:
        if previous is None:
            os.environ.pop("LINODE_API_TOKEN", None)
        else:
            os.environ["LINODE_API_TOKEN"] = previous


if __name__ == "__main__":
    main()
