#!/usr/bin/env python3
"""Project public binding facts, never credential bytes or provider success.

The caller supplies authority-derived obligation selectors. This adapter does
not mint those identities or authenticate that authority. The consumer must
admit the exact source/selection independently before treating a diff as trusted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

LIMIT = 2 * 1024 * 1024
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}\Z")
PRIVATE = re.compile(r"AGE-SECRET-KEY-|BEGIN.*PRIVATE KEY|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}")


def token(value):
    if not isinstance(value, str) or not TOKEN.fullmatch(value) or PRIVATE.search(value):
        raise ValueError("public identifier required")


def validate_selection(selection):
    if not isinstance(selection, dict) or set(selection) != {"consumer", "stage", "obligations"}:
        raise ValueError("selection schema")
    token(selection["consumer"]); token(selection["stage"])
    if not isinstance(selection["obligations"], list) or len(selection["obligations"]) > 10000:
        raise ValueError("selection schema")
    for row in selection["obligations"]:
        if not isinstance(row, dict) or set(row) != {"id", "obligation_digest", "binding", "profile"}:
            raise ValueError("obligation schema")
        token(row["id"]); token(row["binding"])
        if not isinstance(row["obligation_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["obligation_digest"]):
            raise ValueError("semantic digest")
        if not isinstance(row["profile"], list) or len(row["profile"]) > 32:
            raise ValueError("profile schema")
        roles = set()
        for item in row["profile"]:
            if not isinstance(item, dict) or set(item) != {"role", "operation", "readback", "grade"}:
                raise ValueError("profile schema")
            token(item["role"])
            if item["role"] in roles:
                raise ValueError("duplicate evidence role")
            roles.add(item["role"])
            if item["operation"] is not None:
                token(item["operation"])
            if type(item["readback"]) is not bool or item["grade"] not in ("fixture", "source", "real"):
                raise ValueError("profile schema")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def object_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate property")
        out[key] = value
    return out


def read_json(text):
    return json.loads(text, object_pairs_hook=object_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))


def keyed(text):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        row = read_json(line)
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in result:
            raise ValueError("invalid or duplicate row")
        result[row["id"]] = row
    return result


def project(bindings_text, consumers_text, selection, revision):
    """No receipt is fabricated; absence of a selected binding yields no P row."""
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("exact revision required")
    validate_selection(selection)
    bindings, consumers = keyed(bindings_text), keyed(consumers_text)
    output, seen = [], set()
    for requirement in selection["obligations"]:
        if not isinstance(requirement, dict) or set(requirement) != {"id", "obligation_digest", "binding", "profile"}:
            raise ValueError("obligation schema")
        if not isinstance(requirement["id"], str) or requirement["id"] in seen:
            raise ValueError("duplicate obligation")
        seen.add(requirement["id"])
        binding = bindings.get(requirement["binding"])
        if binding is None:
            continue
        if binding.get("kind") != "envs.authCapability.v1":
            raise ValueError("binding kind")
        matches = [r for r in consumers.values() if r.get("role") == "consumer"
                   and r.get("repository") == selection["consumer"] and r.get("stage") == selection["stage"]
                   and r.get("capability") == binding.get("capability")]
        if not matches:
            continue
        if len(matches) != 1:
            raise ValueError("consumer binding ambiguous")
        target = binding["target"]
        if target.get("provider") in ("cloudflare-pages", "cloudflare-workers"):
            provider = target["provider"]
            resource_key = "project" if provider == "cloudflare-pages" else "worker_name"
            if not {"provider", resource_key, "secret_name"} <= target.keys() <= {"provider", resource_key, "secret_name", "account_id"}:
                raise ValueError("target projection unsupported")
            resource, slot = target[resource_key], target["secret_name"]
        elif target.get("kind") == "process_env" and set(target) == {"repository", "host", "kind", "secret_name"}:
            provider, resource, slot = target["kind"], target["host"], target["secret_name"]
        else:
            raise ValueError("target projection unsupported")
        for value in (provider, resource, slot, binding["capability"], binding["id"]):
            token(value)
        if target.get("account_id") is not None:
            token(target["account_id"])
        # Read only a closed set of public fields. source_key/ciphertext are not opened.
        output.append({"id": requirement["id"], "contract": {
            "obligation_digest": requirement["obligation_digest"], "profile": requirement["profile"],
            "consumer": matches[0]["repository"], "stage": matches[0]["stage"],
            "capability": binding["capability"], "binding": binding["id"], "slot": slot,
            "target": {"provider": provider, "resource": resource, "account": target.get("account_id")}}})
    return {"source": {"repository": "roccho-dev/envs", "revision": revision, "path": "contracts",
                       "digest": digest({"bindings": bindings, "consumers": consumers})},
            "rows": sorted(output, key=lambda row: row["id"])}


def read_file(path):
    if path.is_symlink():
        raise ValueError("symlink input")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("input size")
    return raw.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        paths = [root / "contracts" / name for name in ("bindings.jsonl", "provider-consumer.jsonl")]
        if any(not path.resolve().is_relative_to(root) for path in paths):
            raise ValueError("path escape")
        result = project(*(read_file(path) for path in paths), read_json(read_file(args.selection)), args.revision)
        sys.stdout.buffer.write(canonical(result) + b"\n")
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        # Do not print input bytes, keys, path contents, or raw parser exceptions.
        sys.stderr.write("contract_projection: invalid or unavailable public inputs\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
