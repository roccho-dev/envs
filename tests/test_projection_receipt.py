#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "projection_receipt", ROOT / "scripts/projection_receipt.py"
)
assert SPEC is not None and SPEC.loader is not None
projection_receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection_receipt)


def expect_red(value: dict) -> None:
    try:
        projection_receipt.validate(value)
    except projection_receipt.ReceiptError:
        return
    raise AssertionError("unsafe projection receipt was accepted")


def main() -> None:
    args = argparse.Namespace(
        envs_sha="a" * 40,
        source_sha256="b" * 64,
        account_id="account-fixture",
        run_id=123,
        run_attempt=1,
        created_at="2026-09-28T00:00:00Z",
    )
    base = projection_receipt.build(args)
    projection_receipt.validate(base)

    mutations: list[dict] = []

    value = copy.deepcopy(base)
    value["envs_sha"] = "main"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["status"] = "NOT_RUN"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["readback"]["present"] = False
    mutations.append(value)

    value = copy.deepcopy(base)
    value["effect"]["status"] = "BLOCKED"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["target"]["project"] = "other-project"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["source"]["sha256"] = "sha256:short"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["secret_value"] = "fixture"
    mutations.append(value)

    value = copy.deepcopy(base)
    value["target"]["account_id"] = (
        "AGE-" + "SECRET-" + "KEY-1" + ("A" * 32)
    )
    mutations.append(value)

    for value in mutations:
        expect_red(value)

    print("projection-receipt self-test: PASS")


if __name__ == "__main__":
    main()
