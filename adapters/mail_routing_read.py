#!/usr/bin/env python3
"""One bounded, read-only Mail M0 Cloudflare preflight; no provider effects.

Dispatch domain is read from GITHUB_EVENT_PATH, never argv or a logged env.
Only dev-projection's existing token/account inputs are consumed. The result is
a closed non-secret summary: no API response body, domain, token, account or
zone identifier, email, request URL, exception message or traceback escapes.
"""
from __future__ import annotations

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
ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
STEPS = ("token", "zone", "dns", "routing", "routing_dns", "rules", "catch_all", "addresses")
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


def domain_from_event(path: str) -> str:
    # This is an explicitly non-secret selected-domain locator in native
    # workflow_dispatch metadata. It is NEVER used as a credential, emitted
    # in stdout/stderr, or expanded by an Actions run-step environment.
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        value = event["inputs"]["domain"]
        if not isinstance(value, str):
            raise ValueError()
        domain = value.lower()
        if (len(domain) > 253 or len(domain) < 4 or domain != value.strip().lower()
                or "." not in domain or any(not LABEL.fullmatch(part) for part in domain.split("."))):
            raise ValueError()
        return domain
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise ReadFailure() from None


def private_inputs(event_path: str, environ: Mapping[str, str]) -> tuple[str, str, str]:
    # Both Cloudflare inputs use EXISTING dev-projection native GitHub slots.
    # GitHub Variables are not Secret-masked; account is allowed here only as
    # a NON-SECRET operational locator under the bounded P v2 exception.
    domain = domain_from_event(event_path)
    account = environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = environ.get("CLOUDFLARE_API_TOKEN", "")
    if not ACCOUNT.fullmatch(account) or not token or len(token) > 4096 or token != token.strip():
        raise ReadFailure()
    return domain, account, token


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
        domain, account, token = private_inputs(event_path, environ)
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

    # Native Cloudflare account and selected domain filters are sent together.
    # Do not enumerate other zones just to hide an ordinary non-secret selector.
    zones = check("zone", lambda: _list(opener, token, "/zones", {
        "name": domain, "account.id": account, "match": "all",
    }))
    if zones is None:
        # Preserve HTTP DENIED, do not silently demote it to UNKNOWN.
        return output
    if len(zones) != 1:
        output["read"]["zone"] = "UNKNOWN"
        return output
    zone = zones[0]
    owner = zone.get("account")
    if (zone.get("name") != domain or not isinstance(owner, dict)
            or owner.get("id") != account or not ACCOUNT.fullmatch(str(zone.get("id", "")))):
        output["read"]["zone"] = "UNKNOWN"
        return output

    zone_id = zone["id"]
    # Each capability is independently observed. Failure/403 is not absence or
    # evidence of missing Write permission; never switch account/zone/token.
    def read_dns() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/zones/{zone_id}/dns_records")
        if any(not isinstance(row.get("type"), str) or not row["type"].strip() for row in rows):
            raise ReadFailure()
        return rows

    dns = check("dns", read_dns)
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
        if (not isinstance(records, list)
                or any(not isinstance(item, dict) or not isinstance(item.get("type"), str)
                       or not item["type"].strip() for item in records)
                or (isinstance(info, dict) and info.get("total_count", len(records)) != len(records))):
            raise ReadFailure()
        return records

    routing_dns = check("routing_dns", routing_dns_read)
    if routing_dns is not None:
        output["counts"]["routing_dns_records"] = len(routing_dns)

    def read_rules() -> list[dict[str, Any]]:
        rows = _list(opener, token, f"/zones/{zone_id}/email/routing/rules")
        for row in rows:
            matchers = row.get("matchers")
            if (type(row.get("enabled")) is not bool
                    or not isinstance(row.get("source"), str)
                    or not isinstance(row.get("actions"), list)
                    or not isinstance(matchers, list) or not matchers
                    or any(not isinstance(m, dict) or not all(
                        isinstance(m.get(key), str) and m[key] for key in ("type", "field", "value")
                    ) for m in matchers)):
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
