#!/usr/bin/env python3
"""One bounded, read-only Mail M0 Cloudflare preflight; no provider effects.

Dispatch domain is read from GITHUB_EVENT_PATH, never argv or a logged env.
Only dev-projection's existing token/account inputs are consumed. The result is
a closed non-secret summary: no API response body, domain, token, account or
zone identifier, email, request URL, exception message or traceback escapes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

API = "https://api.cloudflare.com/client/v4"
# Existing dev-projection Environment Variable, read directly in memory with
# the already provided Actions token; never expand its raw value into step env,
# argv, GitHub log/script or run metadata.
GITHUB_ACCOUNT_URL = (
    "https://api.github.com/repos/roccho-org/envs/environments/"
    "dev-projection/variables/CLOUDFLARE_ACCOUNT_ID"
)
ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
SELECTOR = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
STEPS = ("account", "token", "zone", "dns", "routing", "routing_dns", "rules", "catch_all", "addresses")
MAX_RESPONSE = 1_000_000
MAX_PAGES = 100
PAGE_SIZE = 50
Opener = Callable[..., Any]


class ReadFailure(Exception):
    def __init__(self, state: str = "UNKNOWN") -> None:
        self.state = state


class DenyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        # Refuse both same-origin and cross-origin 30x; no Bearer forwarding.
        return None


def safe_opener(https_handler: urllib.request.BaseHandler | None = None) -> Opener:
    # An explicit empty ProxyHandler suppresses the OS/ambient HTTPS_PROXY,
    # HTTP_PROXY and no_proxy lookup used by urllib's default urlopen.
    # The test-only handler exercises the real urllib redirect/proxy chain
    # without a socket or a provider request.
    handler = https_handler or urllib.request.HTTPSHandler(context=ssl.create_default_context())
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), DenyRedirect(), handler).open


def selector_from_event(path: str) -> str:
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        value = event["inputs"]["domain_sha256"]
        if not isinstance(value, str) or not SELECTOR.fullmatch(value):
            raise ValueError()
        return value
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise ReadFailure() from None


def private_inputs(event_path: str, environ: Mapping[str, str]) -> tuple[str, str, str]:
    # The dispatch metadata contains only a non-secret fingerprint, not the
    # raw target. This is an opaque SELECTOR, not encryption or a secrecy proof
    # against dictionary attacks on publicly known DNS names.
    selector = selector_from_event(event_path)
    token = environ.get("CLOUDFLARE_API_TOKEN", "")
    github = environ.get("GH_TOKEN", "")
    if (not token or len(token) > 4096 or token != token.strip()
            or not github or len(github) > 4096 or github != github.strip()):
        raise ReadFailure()
    return selector, token, github


def configured_account(opener: Opener, github_token: str) -> str:
    request = urllib.request.Request(
        GITHUB_ACCOUNT_URL,
        headers={"Authorization": "Bearer " + github_token, "Accept": "application/vnd.github+json"},
        method="GET",
    )
    try:
        with opener(request, timeout=12) as response:
            if getattr(response, "status", None) != 200:
                raise ReadFailure()
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ReadFailure()
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("name") != "CLOUDFLARE_ACCOUNT_ID"
                or not isinstance(data.get("value"), str) or not ACCOUNT.fullmatch(data["value"])):
            raise ReadFailure()
        return data["value"]
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError,
            ValueError, TypeError, UnicodeError):
        # GitHub 403 means lack of access to this Variable, NOT a Cloudflare
        # permission result. Do not fall back to a different Environment.
        raise ReadFailure() from None


def _request(opener: Opener, token: str, path: str, params: Mapping[str, object] | None = None) -> Any:
    query = urllib.parse.urlencode(params or {})
    url = API + path + ("?" + query if query else "")
    req = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        method="GET",
    )
    try:
        with opener(req, timeout=12) as response:
            if getattr(response, "status", 200) != 200:
                raise ReadFailure("DENIED" if response.status in (401, 403) else "UNKNOWN")
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ReadFailure()
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ReadFailure()
        if not isinstance(payload.get("result"), (dict, list)):
            raise ReadFailure()
        return payload
    except urllib.error.HTTPError as error:
        raise ReadFailure("DENIED" if error.code in (401, 403) else "UNKNOWN") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, UnicodeError):
        raise ReadFailure() from None


def _list(opener: Opener, token: str, path: str,
          params: Mapping[str, object] | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        args = {**(params or {}), "page": page, "per_page": PAGE_SIZE}
        payload = _request(opener, token, path, args)
        info = payload.get("result_info")
        batch = payload["result"]
        if (not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch)
                or not isinstance(info, dict)):
            raise ReadFailure()
        total_pages = info.get("total_pages")
        total_count = info.get("total_count")
        if (type(total_pages) is not int or type(total_count) is not int
                or total_pages < 1 or total_pages > MAX_PAGES or total_count < 0
                or total_count > MAX_PAGES * PAGE_SIZE):
            raise ReadFailure()
        if expected_total is not None and total_count != expected_total:
            raise ReadFailure()
        expected_total = total_count
        results.extend(batch)
        if page == total_pages:
            if len(results) != total_count:
                raise ReadFailure()
            return results
        if page > total_pages:
            raise ReadFailure()
    raise ReadFailure()


def _single(opener: Opener, token: str, path: str) -> dict[str, Any]:
    value = _request(opener, token, path)["result"]
    if not isinstance(value, dict):
        raise ReadFailure()
    return value


def _empty() -> dict[str, Any]:
    return {
        "kind": "envs.mailRoutingRead.v1",
        "status": "INCOMPLETE",
        "read": {step: "UNKNOWN" for step in STEPS},
        "facts": {},
        "counts": {},
        "write_authority": "NOT_PROVEN",
        "mail_arrival": "NOT_PROVEN",
    }


def observe(event_path: str, environ: Mapping[str, str], opener: Opener | None = None) -> dict[str, Any]:
    output = _empty()
    try:
        selector, token, github_token = private_inputs(event_path, environ)
    except ReadFailure:
        return output

    if opener is None:
        opener = safe_opener()

    def check(step: str, fetch: Callable[[], Any]) -> Any | None:
        try:
            result = fetch()
        except ReadFailure as failure:
            output["read"][step] = failure.state
            return None
        except Exception:
            # Fail closed even for malformed provider/opener implementations.
            output["read"][step] = "UNKNOWN"
            return None
        output["read"][step] = "OBSERVED"
        return result

    account = check("account", lambda: configured_account(opener, github_token))
    if account is None:
        return output

    def read_token() -> dict[str, Any]:
        data = _single(opener, token, "/user/tokens/verify")
        if data.get("status") not in ("active", "disabled", "expired", "inactive"):
            raise ReadFailure()
        return data

    verification = check("token", read_token)
    if verification is None:
        return output
    output["facts"]["token_active"] = verification["status"] == "active"
    if not output["facts"]["token_active"]:
        return output

    # Do not put the domain into workflow_dispatch metadata or a step env.
    # Enumerate only the configured account; one matching SHA-256 selector
    # must resolve, otherwise STOP with no fallback to another account/zone.
    zones = check("zone", lambda: _list(opener, token, "/zones", {
        "account.id": account, "match": "all",
    }))
    if zones is None:
        # Preserve an exact HTTP DENIED rather than rewriting it UNKNOWN.
        return output
    matching = []
    for candidate in zones:
        name = candidate.get("name")
        if isinstance(name, str) and hashlib.sha256(name.lower().encode()).hexdigest() == selector:
            matching.append(candidate)
    if len(matching) != 1:
        output["read"]["zone"] = "UNKNOWN"
        return output
    zone = matching[0]
    owner = zone.get("account")
    if (not isinstance(zone.get("name"), str) or not isinstance(owner, dict)
            or owner.get("id") != account or not ACCOUNT.fullmatch(str(zone.get("id", "")))):
        output["read"]["zone"] = "UNKNOWN"
        return output

    zone_id = zone["id"]
    # Each capability is independently observed. Failure/403 is not absence or
    # evidence of missing Write permission; never switch account/zone/token.
    dns = check("dns", lambda: _list(opener, token, f"/zones/{zone_id}/dns_records"))
    if dns is not None:
        output["counts"]["dns"] = len(dns)
        output["facts"]["mx_present"] = any(x.get("type") == "MX" for x in dns)
        output["counts"]["mx"] = sum(x.get("type") == "MX" for x in dns)
        output["counts"]["txt"] = sum(x.get("type") == "TXT" for x in dns)

    def read_routing() -> dict[str, Any]:
        data = _single(opener, token, f"/zones/{zone_id}/email/routing")
        if (type(data.get("enabled")) is not bool
                or data.get("status") not in (
                    "ready", "unconfigured", "misconfigured", "misconfigured/locked", "unlocked",
                )):
            raise ReadFailure()
        return data

    routing = check("routing", read_routing)
    if routing is not None:
        output["facts"]["routing_ready"] = routing["status"] == "ready"
        output["facts"]["routing_enabled"] = routing["enabled"]

    def routing_dns_read() -> list[dict[str, Any]]:
        payload = _request(opener, token, f"/zones/{zone_id}/email/routing/dns")
        records = payload["result"]
        info = payload.get("result_info")
        if (not isinstance(records, list) or any(not isinstance(item, dict) for item in records)
                or (isinstance(info, dict) and info.get("total_count", len(records)) != len(records))):
            raise ReadFailure()
        return records

    routing_dns = check("routing_dns", routing_dns_read)
    if routing_dns is not None:
        output["counts"]["routing_dns_records"] = len(routing_dns)

    def read_rules() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/zones/{zone_id}/email/routing/rules")
        if any(type(row.get("enabled")) is not bool or not isinstance(row.get("source"), str)
               or not isinstance(row.get("actions"), list) for row in rows):
            raise ReadFailure()
        return rows

    rules = check("rules", read_rules)
    if rules is not None:
        output["counts"]["rules"] = len(rules)
        output["counts"]["enabled_rules"] = sum(x.get("enabled") is True for x in rules)
        output["counts"]["wrangler_rules"] = sum(x.get("source") == "wrangler" for x in rules)

    def read_catch() -> dict[str, Any]:
        data = _single(opener, token, f"/zones/{zone_id}/email/routing/rules/catch_all")
        if type(data.get("enabled")) is not bool:
            raise ReadFailure()
        return data

    catch = check("catch_all", read_catch)
    if catch is not None:
        output["facts"]["catch_all_enabled"] = catch["enabled"]

    def read_addresses() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/accounts/{account}/email/routing/addresses")
        for row in rows:
            value = row.get("verified", ...)
            if (not isinstance(row.get("email"), str) or not row["email"]
                    or (value is not None and (
                        not isinstance(value, str)
                        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T[^\s]+", value) is None
                    ))):
                raise ReadFailure()
        return rows

    addresses = check("addresses", read_addresses)
    if addresses is not None:
        output["counts"]["account_destinations"] = len(addresses)
        output["counts"]["verified_destinations"] = sum(x["verified"] is not None for x in addresses)

    if all(output["read"][key] == "OBSERVED" for key in STEPS):
        output["status"] = "READ_OBSERVED"
    return output


def main() -> int:
    # No traceback, provider response, identifier, domain, or exception details.
    try:
        result = observe(os.environ.get("GITHUB_EVENT_PATH", ""), os.environ)
    except Exception:
        result = _empty()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["status"] == "READ_OBSERVED" else 2


if __name__ == "__main__":
    sys.exit(main())
