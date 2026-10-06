#!/usr/bin/env python3
"""Public source projection tests; no SOPS, identity, provider call or receipt."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("envs_contract_projection", ROOT / "adapters/contract_projection.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def fixture():
    binding = {"id": "jev-api", "kind": "envs.authCapability.v1", "capability": "jev-api",
               "ciphertext": "ciphertexts/do-not-read", "source_key": "JEV_API_KEY",
               "target": {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"}}
    consumer = {"id": "ops.voice-ui.consumer", "kind": "envs.providerConsumerBoundary.v1", "role": "consumer",
                "repository": "roccho-dev/ops", "stage": "dev", "capability": "jev-api"}
    selection = {"consumer": consumer["repository"], "stage": "dev", "obligations": [
        {"id": "fixture.jev", "obligation_digest": "sha256:" + "b" * 64, "binding": "jev-api", "profile": []}]}
    return [binding], [consumer], selection


def run(bindings, consumers, selection):
    text = lambda rows: "".join(json.dumps(r) + "\n" for r in rows)
    return module.project(text(bindings), text(consumers), selection, "a" * 40)


class ProjectionTests(unittest.TestCase):
    def test_actual_public_binding_is_projected_not_repaired(self):
        bindings = (ROOT / "contracts/bindings.jsonl").read_text()
        consumers = (ROOT / "contracts/provider-consumer.jsonl").read_text()
        _, _, selection = fixture()
        result = module.project(bindings, consumers, selection, "a" * 40)
        actual = module.keyed(bindings)["jev-api"]["target"]
        self.assertEqual(result["rows"][0]["contract"]["target"]["provider"], actual["provider"])
        self.assertNotIn("receipt", result)
        self.assertNotIn("verified", result)

    def test_pages_is_not_workers_and_no_plaintext_read(self):
        b, c, s = fixture()
        result = run(b, c, s)
        self.assertEqual(result["rows"][0]["contract"]["target"],
                         {"provider": "cloudflare-pages", "resource": "voice-ui", "account": None})
        self.assertNotIn("ciphertext", json.dumps(result))
        self.assertNotIn("source_key", json.dumps(result))

    def test_workers_requires_its_actual_shape(self):
        b, c, s = fixture(); b[0]["target"] = {"provider": "cloudflare-workers", "worker_name": "voice-ui", "secret_name": "JEV_API_KEY", "account_id": "a" * 32}
        self.assertEqual(run(b, c, s)["rows"][0]["contract"]["target"]["provider"], "cloudflare-workers")
        b[0]["target"]["project"] = b[0]["target"].pop("worker_name")
        with self.assertRaises(ValueError): run(b, c, s)

    def test_missing_binding_or_consumer_stays_missing(self):
        b, c, s = fixture()
        self.assertEqual(run([], c, s)["rows"], [])
        self.assertEqual(run(b, [], s)["rows"], [])
        s["stage"] = "prod"
        self.assertEqual(run(b, c, s)["rows"], [])

    def test_duplicate_and_ambiguous_inputs_are_refused(self):
        b, c, s = fixture()
        with self.assertRaises(ValueError): run(b + b, c, s)
        c.append({**c[0], "id": "another-consumer"})
        with self.assertRaises(ValueError): run(b, c, s)
        b, c, s = fixture(); s["obligations"] *= 2
        with self.assertRaises(ValueError): run(b, c, s)

    def test_unknown_profile_or_secret_property_is_not_echoed(self):
        b, c, s = fixture(); s["obligations"][0]["profile"] = [{"secret_value": "PRIVATE-CANARY"}]
        with self.assertRaises(ValueError): run(b, c, s)
        b, c, s = fixture(); b[0]["target"]["api_key"] = "PRIVATE-CANARY"
        with self.assertRaises(ValueError): run(b, c, s)

    def test_order_is_not_meaning(self):
        b, c, s = fixture(); before = module.canonical(run(b, c, s))
        b[0] = dict(reversed(list(b[0].items())))
        self.assertEqual(before, module.canonical(run(b, c, s)))

    def test_no_identity_minting(self):
        b, c, s = fixture(); s["obligations"][0]["id"] = "authority.other"
        result = run(b, c, s)
        self.assertEqual(result["rows"][0]["id"], "authority.other")
        del s["obligations"][0]["id"]
        with self.assertRaises(ValueError): run(b, c, s)

    def test_mutable_revision_and_duplicate_json_properties_refused(self):
        with self.assertRaises(ValueError): module.project("", "", fixture()[2], "proposals")
        with self.assertRaises(ValueError): module.read_json('{"id":"a","id":"b"}')

    def test_cli_independent_runs_and_missing_input(self):
        b, c, s = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "contracts").mkdir()
            for filename, value in (("bindings.jsonl", b), ("provider-consumer.jsonl", c)):
                (root / "contracts" / filename).write_text("".join(json.dumps(r) + "\n" for r in value))
            selection = root / "selection.json"; selection.write_text(json.dumps(s))
            cmd = [sys.executable, str(ROOT / "adapters/contract_projection.py"), "--root", str(root), "--selection", str(selection), "--revision", "a" * 40]
            one = subprocess.run(cmd, capture_output=True, check=True)
            two = subprocess.run(cmd, capture_output=True, check=True)
            self.assertEqual(one.stdout, two.stdout)
            (root / "contracts/bindings.jsonl").unlink()
            failed = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(failed.stdout, b"")


if __name__ == "__main__":
    unittest.main()
