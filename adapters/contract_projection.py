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


def closed(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() <= set(required) | set(optional):
        raise ValueError("closed public schema required")


def tokens(value):
    if not isinstance(value, list) or len(value) > 10000:
        raise ValueError("public identifier list required")
    for item in value:
        token(item)
    if len(set(value)) != len(value):
        raise ValueError("duplicate public identifier")


def public_target(value):
    if not isinstance(value, dict):
        raise ValueError("target schema")
    provider = value.get("provider")
    if provider == "github-org-secret":
        closed(value, ("provider", "organization", "organization_id", "secret_name",
                       "repositories", "repository_ids"))
        for key in ("provider", "organization", "organization_id", "secret_name"):
            token(value[key])
        org = value["organization"]
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org):
            raise ValueError("organization identifier")
        if not re.fullmatch(r"[1-9][0-9]*", value["organization_id"]):
            raise ValueError("organization identity")
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value["secret_name"]) or value["secret_name"].startswith("GITHUB_"):
            raise ValueError("secret slot identifier")
        repos, ids = value["repositories"], value["repository_ids"]
        tokens(repos); tokens(ids)
        if not 1 <= len(repos) <= 100 or len(repos) != len(ids):
            raise ValueError("selected repository identities")
        if not all(re.fullmatch(re.escape(org) + r"/[A-Za-z0-9_.-]+", repo) for repo in repos):
            raise ValueError("selected repository organization")
        if not all(re.fullmatch(r"[1-9][0-9]*", repo_id) for repo_id in ids):
            raise ValueError("selected repository identity")
        return
    if provider in ("cloudflare-pages", "cloudflare-workers"):
        resource = "project" if provider == "cloudflare-pages" else "worker_name"
        closed(value, ("provider", resource, "secret_name"), ("account_id",))
    elif value.get("kind") == "pi_auth_command":
        # Source metadata only. This is not parent-process secret injection or an executable projection port.
        closed(value, ("repository", "host", "kind"))
        if value != {"repository": "roccho-dev/windows", "host": "oci-dev", "kind": "pi_auth_command"}:
            raise ValueError("Pi target identity differs")
    elif value.get("kind") == "process_env":
        closed(value, ("repository", "host", "kind", "secret_name"))
    elif value.get("kind") == "cloudflared_token_file":
        closed(value, ("repository", "host", "kind"))
    else:
        raise ValueError("target projection unsupported")
    for item in value.values():
        token(item)


def public_row(row, family):
    """Validate the whole digest domain, including unselected rows, before hashing.

    These are public transport shapes, not a second binding/obligation authority.
    Unknown kinds/fields require explicit support; never hash an ignored extension.
    """
    kind = row.get("kind")
    if family == "bindings" and kind == "envs.applicationBinding.v1":
        closed(row, ("id", "kind", "application"))
    elif family == "bindings" and kind == "envs.authCapability.v1":
        closed(row, ("id", "kind", "capability", "ciphertext", "source_key", "target"),
               ("source", "github_environment", "required_variables"))
    elif family == "consumers" and kind == "envs.branchPolicy.v1":
        closed(row, ("id", "kind", "canonical_branch", "default_branch", "retained_compatibility_branches",
                     "direct_change_forbidden", "effect_source_branches", "handoff_ref_kind"))
    elif family == "consumers" and kind == "envs.consumerExecutionBoundary.v1":
        closed(row, ("id", "kind", "applies_to", "forbids"))
    elif family == "consumers" and kind == "envs.providerConsumerBoundary.v1":
        common = ("id", "kind", "role", "repository", "stage", "capability", "owns")
        if row.get("role") == "consumer":
            closed(row, (*common, "requires"), ("distribution_source",))
        elif row.get("role") == "provider":
            closed(row, (*common, "source_kind", "target_kind", "does_not_own", "handoff_ref_kind"),
                   ("binding", "historical_repository", "historical_repository_mode"))
        else:
            raise ValueError("boundary role")
    else:
        raise ValueError("public row kind")
    lists = {"owns", "requires", "does_not_own", "applies_to", "forbids", "retained_compatibility_branches",
             "direct_change_forbidden", "effect_source_branches"}
    for key, value in row.items():
        if key in lists:
            tokens(value)
        elif key == "target":
            public_target(value)
        elif key == "source":
            closed(value, ("provider", "operation"))
            for item in value.values():
                token(item)
        elif key == "required_variables":
            if not isinstance(value, list) or len(value) > 32:
                raise ValueError("variable schema")
            names = []
            for item in value:
                closed(item, ("name", "type", "lifecycle"))
                for field in item.values():
                    token(field)
                names.append(item["name"])
            tokens(names)
        else:
            token(value)
            if key == "distribution_source" and not re.fullmatch(r"[0-9a-f]{40}", value):
                raise ValueError("exact distribution source required")


def validate_selection(selection):
    closed(selection, ("obligations",))
    if not isinstance(selection["obligations"], list) or len(selection["obligations"]) > 10000:
        raise ValueError("selection schema")
    for row in selection["obligations"]:
        if not isinstance(row, dict) or set(row) != {"id", "obligation_digest", "binding", "consumer_boundary", "profile"}:
            raise ValueError("obligation schema")
        token(row["id"]); token(row["binding"]); token(row["consumer_boundary"])
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


def keyed(text, family):
    if not isinstance(text, str) or len(text.encode("utf-8")) > LIMIT:
        raise ValueError("input size")
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        row = read_json(line)
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in result:
            raise ValueError("invalid or duplicate row")
        public_row(row, family)
        result[row["id"]] = row
        if len(result) > 10000:
            raise ValueError("row limit")
    return result


def project(bindings_text, consumers_text, selection, revision):
    """No receipt is fabricated; absence of a selected binding yields no P row."""
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("exact revision required")
    validate_selection(selection)
    bindings, consumers = keyed(bindings_text, "bindings"), keyed(consumers_text, "consumers")
    output, seen = [], set()
    for requirement in selection["obligations"]:
        if not isinstance(requirement["id"], str) or requirement["id"] in seen:
            raise ValueError("duplicate obligation")
        seen.add(requirement["id"])
        binding = bindings.get(requirement["binding"])
        if binding is None:
            continue
        if binding.get("kind") != "envs.authCapability.v1":
            raise ValueError("binding kind")
        # Both locators are stable source-row IDs, not values under comparison.
        consumer = consumers.get(requirement["consumer_boundary"])
        if consumer is None:
            continue
        if consumer["kind"] != "envs.providerConsumerBoundary.v1" or consumer.get("role") != "consumer":
            raise ValueError("selected consumer boundary kind")
        if consumer["capability"] != binding["capability"]:
            raise ValueError("selected capability relation inconsistent")
        target = binding["target"]
        if target.get("provider") == "github-org-secret":
            if consumer["repository"] not in target["repositories"]:
                raise ValueError("selected consumer not covered by Org target")
            provider, resource, slot = target["provider"], target["organization"], target["secret_name"]
            account = target["organization_id"]
        elif target.get("provider") in ("cloudflare-pages", "cloudflare-workers"):
            provider = target["provider"]
            resource_key = "project" if provider == "cloudflare-pages" else "worker_name"
            resource, slot = target[resource_key], target["secret_name"]
            account = target.get("account_id")
        elif target.get("kind") == "process_env":
            provider, resource, slot = target["kind"], target["host"], target["secret_name"]
            account = None
        else:
            raise ValueError("target projection unsupported")
        # Read only a closed set of public fields. source_key/ciphertext are not opened.
        output.append({"id": requirement["id"], "contract": {
            "obligation_digest": requirement["obligation_digest"], "profile": requirement["profile"],
            "consumer": consumer["repository"], "stage": consumer["stage"],
            "capability": binding["capability"], "binding": binding["id"], "slot": slot,
            "target": {"provider": provider, "resource": resource, "account": account}}})
    return {"source": {"repository": "roccho-org/envs", "revision": revision, "path": "contracts",
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
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        # Do not print input bytes, keys, path contents, or raw parser exceptions.
        sys.stderr.write("contract_projection: invalid or unavailable public inputs\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
