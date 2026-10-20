"""Validate editor semantics with a standard JSON Schema implementation.

Run: uv run --with jsonschema --with PyYAML schema/test_schema.py
These are development-only verification dependencies, not Helios dependencies.
"""

import copy
import json
from pathlib import Path
import unittest

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/helios.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


class ManifestSchemaTests(unittest.TestCase):
    def assert_valid(self, manifest: dict) -> None:
        errors = list(VALIDATOR.iter_errors(manifest))
        self.assertFalse(errors, "\n".join(error.message for error in errors))

    def assert_invalid(self, manifest: dict) -> None:
        self.assertTrue(list(VALIDATOR.iter_errors(manifest)), manifest)

    def test_schema_is_a_valid_draft_2020_12_document(self) -> None:
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    def test_every_workload_kind_and_lane_fixture_is_supported(self) -> None:
        workloads = {
            "web": {"kind": "web", "image": "example/api:1", "port": 8080,
                    "routes": [{"host": "api.example.com"}]},
            "static": {"kind": "static", "dir": "public",
                       "routes": [{"host": "site.example.com"}]},
            "worker": {"kind": "worker", "build": {}},
            "cron": {"kind": "cron", "image": "example/worker:1",
                     "schedule": "0 3 * * *", "command": ["echo", True, 1]},
            "release": {"kind": "release", "build": {"target": "release"},
                        "order": 1, "timeout": "10m"},
        }
        for name, workload in workloads.items():
            with self.subTest(kind=name):
                self.assert_valid({"app": "demo", "workloads": {name: workload}})
        for name in ("hello", "site", "notes"):
            with self.subTest(fixture=name):
                manifest = yaml.safe_load((ROOT / f"lane/fixtures/{name}/helios.yaml").read_text())
                self.assert_valid(manifest)

    def test_scalar_configuration_and_defaults_are_accepted(self) -> None:
        self.assert_valid({
            "app": "api", "workloads": {"worker": {
                "kind": "worker", "image": "example/api:1", "build": None,
                "env": {"PORT": 8080, "ENABLED": True},
                "resources": {"pids": 0, "cpus": 0}, "port": 0,
                "user": "", "order": 0, "schedule": "", "timeout": "",
            }}, "data": {"postgres": {"version": 16, "database_url": False}},
        })

    def test_unknown_fields_are_rejected_at_nested_boundaries(self) -> None:
        self.assert_invalid({"app": "demo", "workloads": {
            "worker": {"kind": "worker", "image": "example/app:1", "colour": "blue"}}})
        self.assert_invalid({"app": "demo", "workloads": {
            "worker": {"kind": "worker", "build": {"docker_file": "Dockerfile"}}}})
        self.assert_invalid({"app": "demo", "workloads": {
            "worker": {"kind": "worker", "image": "example/app:1"}},
            "data": {"postgres": {"versoin": "16"}}})

    def test_workload_shape_and_isolation_errors_are_rejected(self) -> None:
        invalid = [
            {"kind": "web", "image": "app", "port": 0, "routes": [{"host": "app.example.com"}]},
            {"kind": "web", "image": "app", "port": 8080},
            {"kind": "worker", "image": "app", "build": {}},
            {"kind": "worker"},
            {"kind": "worker", "image": "app", "schedule": "0 3 * * *"},
            {"kind": "static", "dir": "public", "image": "app", "routes": [{"host": "app.example.com"}]},
            {"kind": "cron", "image": "app"},
            {"kind": "release", "image": "app", "routes": [{"host": "app.example.com"}]},
            {"kind": "worker", "image": "app", "ports": [{"port": 3478}]},
            {"kind": "worker", "image": "app", "resources": {"cpus": 65}},
            {"kind": "worker", "image": "app", "resources": {"pids": 15}},
            {"kind": "worker", "image": "app", "privileged": True, "capabilities": ["SYS_ADMIN"]},
            {"kind": "worker", "image": "app", "health": {"path": "/", "command": ["true"]}},
        ]
        for workload in invalid:
            with self.subTest(workload=workload):
                self.assert_invalid({"app": "demo", "workloads": {"work": workload}})

    def test_release_data_policy_requires_a_release_workload_and_known_contract(self) -> None:
        manifest = {"app": "demo", "workloads": {"release": {"kind": "release", "image": "app"}},
                    "release": {"data_compatibility": "restore-required"}}
        self.assert_valid(manifest)
        manifest["release"]["data_compatibility"] = "backward-compatible"
        self.assert_valid(manifest)
        manifest["release"]["data_compatibility"] = "unknown"
        self.assert_invalid(manifest)
        manifest["release"]["data_compatibility"] = "backward-compatible"
        manifest["workloads"]["release"]["kind"] = "worker"
        self.assert_invalid(manifest)

    def test_a_volume_may_be_left_out_of_backups(self) -> None:
        manifest = {"app": "notes", "workloads": {"worker": {"kind": "worker", "image": "example/notes:1"}},
                    "data": {"volumes": {"state": {}, "scratch": {"backup": False}}}}
        self.assert_valid(manifest)
        manifest["data"]["volumes"]["scratch"]["backup"] = True
        self.assert_valid(manifest)
        manifest["data"]["volumes"]["scratch"]["backup"] = "no"
        self.assert_invalid(manifest)

    def test_preview_routes_require_sign_in(self) -> None:
        manifest = {"app": "demo-pr-nav", "preview": {"of": "demo", "branch": "nav", "pinned": True},
                    "workloads": {"web": {"kind": "web", "image": "app", "port": 8080,
                                          "routes": [{"host": "nav.demo.example.com"}]}}}
        self.assert_invalid(manifest)
        manifest["workloads"]["web"]["routes"][0]["auth"] = "loom"
        self.assert_valid(manifest)

    def test_credential_checks_require_explicit_edge_and_https(self) -> None:
        manifest = {"app": "api", "workloads": {"worker": {"kind": "worker", "image": "app"}},
                    "checks": [{"url": "https://api.example.com/", "context": "edge",
                                "headers_from_secrets": {"Authorization": "CHECK_TOKEN"}}]}
        self.assert_valid(manifest)
        for changes in ({"context": "application"}, {"context": ""},
                        {"url": "http://api.example.com/"},
                        {"url": "https://user:password@api.example.com/"},
                        {"headers_from_secrets": {"hOsT": "CHECK_TOKEN"}},
                        {"headers_from_secrets": {"X-Forwarded-For": "CHECK_TOKEN"}},
                        {"headers_from_secrets": {"Bad Header": "CHECK_TOKEN"}},
                        {"headers_from_secrets": {"Authorization": "lower"}}):
            with self.subTest(changes=changes):
                bad = copy.deepcopy(manifest)
                bad["checks"][0].update(changes)
                self.assert_invalid(bad)


if __name__ == "__main__":
    unittest.main()
