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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("envs_contract_projection", ROOT / "adapters/contract_projection.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def fixture():
    binding = {"id": "jev-api", "kind": "envs.authCapability.v1", "capability": "jev-api",
               "ciphertext": "ciphertexts/do-not-read", "source_key": "JEV_API_KEY",
               "target": {"provider": "cloudflare-pages", "project": "voice-ui", "secret_name": "JEV_API_KEY"}}
    consumer = {"id": "ops.voice-ui.consumer", "kind": "envs.providerConsumerBoundary.v1", "role": "consumer",
                "repository": "roccho-dev/ops", "stage": "dev", "capability": "jev-api", "owns": [], "requires": []}
    selection = {"obligations": [{"id": "fixture.jev", "obligation_digest": "sha256:" + "b" * 64,
                 "binding": "jev-api", "consumer_boundary": consumer["id"], "profile": []}]}
    return [binding], [consumer], selection


def lines(rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


def run(bindings, consumers, selection):
    return module.project(lines(bindings), lines(consumers), selection, "a" * 40)


class ProjectionTests(unittest.TestCase):
    def test_actual_public_binding_is_projected_not_repaired(self):
        bindings = (ROOT / "contracts/bindings.jsonl").read_text()
        consumers = (ROOT / "contracts/provider-consumer.jsonl").read_text()
        result = module.project(bindings, consumers, fixture()[2], "a" * 40)
        actual = module.keyed(bindings, "bindings")["jev-api"]["target"]
        self.assertEqual(result["rows"][0]["contract"]["target"]["provider"], actual["provider"])
        self.assertNotIn("receipt", result)
        self.assertNotIn("verified", result)

    def test_pages_is_not_workers_and_no_plaintext_read(self):
        result = run(*fixture())
        self.assertEqual(result["rows"][0]["contract"]["target"],
                         {"provider": "cloudflare-pages", "resource": "voice-ui", "account": None})
        self.assertNotIn("ciphertext", json.dumps(result))
        self.assertNotIn("source_key", json.dumps(result))

    def test_workers_requires_its_actual_shape(self):
        b, c, s = fixture()
        b[0]["target"] = {"provider": "cloudflare-workers", "worker_name": "voice-ui", "secret_name": "JEV_API_KEY", "account_id": "a" * 32}
        self.assertEqual(run(b, c, s)["rows"][0]["contract"]["target"]["provider"], "cloudflare-workers")
        b[0]["target"]["project"] = b[0]["target"].pop("worker_name")
        with self.assertRaises(ValueError):
            run(b, c, s)

    def test_missing_stable_binding_or_boundary_stays_missing(self):
        b, c, s = fixture()
        self.assertEqual(run([], c, s)["rows"], [])
        self.assertEqual(run(b, [], s)["rows"], [])
        c[0]["id"] = "different.boundary"
        self.assertEqual(run(b, c, s)["rows"], [])

    def test_stage_and_consumer_drift_preserve_the_row(self):
        for field, actual in (("stage", "prod"), ("repository", "roccho-dev/another")):
            with self.subTest(field=field):
                b, c, s = fixture()
                c[0][field] = actual
                rows = run(b, c, s)["rows"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["id"], s["obligations"][0]["id"])
                self.assertEqual(rows[0]["contract"]["consumer" if field == "repository" else field], actual)

    def test_capability_drift_is_emitted_or_internal_conflict_rejected(self):
        b, c, s = fixture()
        b[0]["capability"] = "different"
        with self.assertRaises(ValueError):
            run(b, c, s)
        c[0]["capability"] = "different"
        self.assertEqual(run(b, c, s)["rows"][0]["contract"]["capability"], "different")

    def test_identity_not_first_last_or_value_match(self):
        b, c, s = fixture()
        c.append({**c[0], "id": "another-consumer", "stage": "prod"})
        expected = run(b, c, s)
        self.assertEqual(expected, run(b, list(reversed(c)), s))
        self.assertEqual(expected["rows"][0]["contract"]["stage"], "dev")
        s["obligations"][0]["consumer_boundary"] = "another-consumer"
        self.assertEqual(run(b, c, s)["rows"][0]["contract"]["stage"], "prod")

    def test_duplicate_and_ambiguous_inputs_are_refused(self):
        b, c, s = fixture()
        with self.assertRaises(ValueError):
            run(b + b, c, s)
        with self.assertRaises(ValueError):
            run(b, c + c, s)
        s["obligations"] *= 2
        with self.assertRaises(ValueError):
            run(b, c, s)

    def test_wrong_selected_kind_is_not_a_missing_supply(self):
        b, c, s = fixture()
        c[0] = {"id": c[0]["id"], "kind": "envs.consumerExecutionBoundary.v1", "applies_to": [], "forbids": []}
        with self.assertRaises(ValueError):
            run(b, c, s)

    def test_unknown_profile_or_secret_property_is_not_echoed(self):
        b, c, s = fixture()
        s["obligations"][0]["profile"] = [{"secret_value": "PRIVATE-CANARY"}]
        with self.assertRaises(ValueError):
            run(b, c, s)
        b, c, s = fixture()
        b[0]["target"]["api_key"] = "PRIVATE-CANARY"
        with self.assertRaises(ValueError):
            run(b, c, s)

    def test_every_current_source_row_is_closed_before_digest(self):
        # Every kind, selected and unselected, is in the same public digest domain.
        bindings = [json.loads(line) for line in (ROOT / "contracts/bindings.jsonl").read_text().splitlines() if line]
        consumers = [json.loads(line) for line in (ROOT / "contracts/provider-consumer.jsonl").read_text().splitlines() if line]
        for collection, rows in enumerate((bindings, consumers)):
            for index in range(len(rows)):
                for key in ("secret_value", "unexpected"):
                    for canary in ("PRIVATE-CANARY-A", "PRIVATE-CANARY-B"):
                        with self.subTest(collection=collection, row=index, key=key, canary=canary[-1]):
                            inputs = copy.deepcopy([bindings, consumers])
                            inputs[collection][index][key] = canary
                            with patch.object(module, "digest") as hash_call:
                                with self.assertRaises(ValueError) as error:
                                    run(*inputs, fixture()[2])
                                hash_call.assert_not_called()
                            self.assertNotIn(canary, str(error.exception))

    def test_nested_unknowns_wrong_types_and_kinds_rejected_before_hash(self):
        b, c, s = fixture()
        b[0]["source"] = {"provider": "provider", "operation": "read"}
        b[0]["required_variables"] = [{"name": "PUBLIC_NAME", "type": "identifier", "lifecycle": "persistent"}]
        mutations = [
            lambda b, c: b[0]["source"].update(unknown="CANARY"),
            lambda b, c: b[0]["required_variables"][0].update(unknown="CANARY"),
            lambda b, c: c[0].update(owns=[{"secret_value": "CANARY"}]),
            lambda b, c: b[0].update(capability={"secret_value": "CANARY"}),
            lambda b, c: b[0].update(kind="unknown-kind"),
            lambda b, c: b[0].update(target=[]),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(case=i):
                bb, cc = copy.deepcopy([b, c])
                mutate(bb, cc)
                with patch.object(module, "digest") as hash_call:
                    with self.assertRaises(ValueError):
                        run(bb, cc, s)
                    hash_call.assert_not_called()

    def test_order_is_not_meaning_and_input_is_unchanged(self):
        b, c, s = fixture()
        original = copy.deepcopy([b, c, s])
        before = module.canonical(run(b, c, s))
        self.assertEqual([b, c, s], original)
        b[0] = dict(reversed(list(b[0].items())))
        self.assertEqual(before, module.canonical(run(b, c, s)))

    def test_no_identity_minting_or_legacy_value_selection(self):
        b, c, s = fixture()
        s["obligations"][0]["id"] = "authority.other"
        self.assertEqual(run(b, c, s)["rows"][0]["id"], "authority.other")
        del s["obligations"][0]["consumer_boundary"]
        with self.assertRaises(ValueError):
            run(b, c, s)
        b, c, s = fixture()
        s.update(consumer="roccho-dev/ops", stage="dev")
        with self.assertRaises(ValueError):
            run(b, c, s)

    def test_mutable_revision_and_duplicate_json_properties_refused(self):
        with self.assertRaises(ValueError):
            module.project("", "", fixture()[2], "proposals")
        with self.assertRaises(ValueError):
            module.read_json('{"id":"a","id":"b"}')

    def test_cli_independent_runs_missing_input_and_private_input_output(self):
        b, c, s = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "contracts").mkdir()
            binding_path = root / "contracts/bindings.jsonl"
            binding_path.write_text(lines(b))
            (root / "contracts/provider-consumer.jsonl").write_text(lines(c))
            selection = root / "selection.json"
            selection.write_text(json.dumps(s))
            cmd = [sys.executable, str(ROOT / "adapters/contract_projection.py"), "--root", str(root), "--selection", str(selection), "--revision", "a" * 40]
            one = subprocess.run(cmd, capture_output=True, check=True)
            two = subprocess.run(cmd, capture_output=True, check=True)
            self.assertEqual(one.stdout, two.stdout)
            errors = []
            for canary in ("PRIVATE-CANARY-A", "PRIVATE-CANARY-B"):
                binding_path.write_text(lines([{**b[0], "secret_value": canary}]))
                failed = subprocess.run(cmd, capture_output=True)
                self.assertEqual(failed.returncode, 2)
                self.assertEqual(failed.stdout, b"")
                self.assertNotIn(canary.encode(), failed.stderr)
                errors.append(failed.stderr)
            self.assertEqual(errors[0], errors[1])
            binding_path.unlink()
            failed = subprocess.run(cmd, capture_output=True)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, b"")


if __name__ == "__main__":
    unittest.main()
