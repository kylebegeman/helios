#!/usr/bin/env python3
"""Proof reports distinguish missing infrastructure from a successful run."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("lane_proof", HERE / "proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


class ProofReports(unittest.TestCase):
    def test_missing_target_configuration_writes_a_blocked_unrun_report(self):
        with tempfile.TemporaryDirectory(prefix="bedrock-proof-test-") as directory:
            artifacts = Path(directory) / "artifacts"
            result = subprocess.run([str(HERE / "prove.sh"), "--config", str(Path(directory) / "missing.env"),
                                     "--artifacts", str(artifacts), "m1"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            report = json.loads((artifacts / "report.json").read_text())
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["results"], [{"proof": "m1", "status": "not run"}])
            self.assertEqual(len(report["commit"]), 40)
            self.assertTrue(report["problems"])
            self.assertEqual(artifacts.stat().st_mode & 0o777, 0o700)

    def test_credentials_are_masked_in_legacy_transcripts(self):
        values = "token=throwaway-token\npassword: throwaway-password\nAGE-SECRET-KEY-1ABCDEF\n  " + "a" * 48 + "\n"
        text = PROOF.redact(values)
        for secret in ("throwaway-token", "throwaway-password", "AGE-SECRET-KEY-1ABCDEF", "a" * 48):
            self.assertNotIn(secret, text)
        self.assertIn("redacted", text)

    def test_structured_credentials_and_url_passwords_are_masked(self):
        values = '\n'.join([
            '{"password": "json secret with spaces", "api_token":"json-token"}',
            'DATABASE_URL=postgres://bedrock:url-password@postgres:5432/app',
            'API_SECRET="quoted secret with spaces"',
        ])
        text = PROOF.redact(values)
        for secret in ("json secret with spaces", "json-token", "url-password", "quoted secret with spaces"):
            self.assertNotIn(secret, text)
        self.assertIn("redacted", text)

    def test_source_fingerprint_tracks_untracked_source_and_excludes_python_cache(self):
        with tempfile.TemporaryDirectory(prefix="bedrock-fingerprint-test-") as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            source = root / "new-feature.go"
            source.write_text("package fixture\n")
            with mock.patch.object(PROOF, "ROOT", root):
                initial = PROOF.source_tree_digest()
                source.write_text("package improved\n")
                changed = PROOF.source_tree_digest()
                self.assertNotEqual(initial, changed)
                cache = root / "__pycache__"
                cache.mkdir()
                (cache / "generated.pyc").write_bytes(b"cache")
                self.assertEqual(changed, PROOF.source_tree_digest())

    def test_transfer_requires_an_explicit_second_disposable_target(self):
        args = SimpleNamespace(proofs=["transfer"], target_config=None)
        self.assertTrue(any("--target-config" in item for item in PROOF.prerequisites(args, {})))

    def test_every_listed_proof_has_an_executable_script(self):
        for name in PROOF.PROOFS:
            script = HERE / f"prove-{name}.sh"
            self.assertTrue(script.is_file(), script)
            self.assertTrue(script.stat().st_mode & 0o111, f"{script} is not executable")

    def test_origin_pull_proof_runs_on_the_loopback_guest(self):
        # It brings its own records and certificates, so it needs no public
        # DNS and is not refused on the QEMU guest the way m3 is.
        args = SimpleNamespace(proofs=["originpull"])
        self.assertEqual(PROOF.prerequisites(args, {"LANE_PROVIDER": "qemu-docker"}), [])
        self.assertTrue(PROOF.prerequisites(SimpleNamespace(proofs=["m3"]), {"LANE_PROVIDER": "qemu-docker"}))

    def test_real_cloudflare_requires_explicit_mutation_opt_in(self):
        args = SimpleNamespace(proofs=["cloudflare"], real_cloudflare=False)
        settings = {"LANE_DOMAIN": "lane.example.com", "LANE_ZONE": "example.com"}
        self.assertTrue(any("--real-cloudflare" in item for item in PROOF.prerequisites(args, settings)))

    def test_private_restore_sources_with_env_files_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="bedrock-stage-test-") as directory:
            stage = Path(directory)
            for filename in ("src/begamin/Dockerfile", "src/dragon-writer/Dockerfile", "archives/begamin-data.tar.gz",
                             "archives/dragon_writer_fixture.dump", "archives/uploads_fixture.tar.gz", "src/begamin/.env"):
                path = stage / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            args = SimpleNamespace(proofs=["m4"], staging=str(stage))
            settings = {"LANE_DOMAIN": "lane.example.com", "LANE_ZONE": "example.com", "LANE_SITE_URL": "https://example.com", "LANE_DW_CHAPTERS": "1"}
            self.assertTrue(any(".env" in item for item in PROOF.prerequisites(args, settings)))


class MemoryPreflight(unittest.TestCase):
    def run_proof(self, proof, source_memory="MemTotal: 3145728 kB\n",
                  destination_memory="MemTotal: 3145728 kB\n", check=False, memory_probe_seconds=0):
        with tempfile.TemporaryDirectory(prefix="bedrock-memory-preflight-") as directory:
            artifacts = Path(directory) / "report"
            source = "/source.env"
            destination = "/destination.env"
            settings = {"LANE_PROVIDER": "qemu-docker", "LANE_ID": "a" * 32, "LANE_ARCH": "arm64",
                        "LANE_VM_IMAGE": "sha256:" + "c" * 64, "LANE_OS_IMAGE_SHA256": "d" * 64,
                        "LANE_VM_MEMORY_MIB": "3072"}
            other = {**settings, "LANE_ID": "b" * 32}
            argv = ["proof.py", "--config", source, "--artifacts", str(artifacts),
                    "--setup", "storage", proof]
            if proof == "transfer":
                argv[1:1] = ["--target-config", destination]
            if check:
                argv.insert(1, "--check")
            probes = []

            def remote(config, script, timeout=60):
                probes.append((config, script))
                if script == "cat /proc/meminfo":
                    if memory_probe_seconds > timeout:
                        raise subprocess.TimeoutExpired("guarded memory probe", timeout)
                    result = source_memory if config == source else destination_memory
                    if isinstance(result, BaseException):
                        raise result
                    if isinstance(result, subprocess.CompletedProcess):
                        return result
                    return subprocess.CompletedProcess([], 0, stdout=result, stderr="")
                return subprocess.CompletedProcess([], 0, stdout="Ubuntu 24.04\n", stderr="")

            process = mock.Mock(returncode=0)
            process.communicate.return_value = ("fixture proof completed\n", None)
            with (
                mock.patch.object(PROOF.sys, "argv", argv),
                mock.patch.object(PROOF, "local", side_effect=lambda *args: "e" * 40 if args == ("git", "rev-parse", "HEAD") else ""),
                mock.patch.object(PROOF, "source_tree_digest", return_value="f" * 64),
                mock.patch.object(PROOF.shutil, "which", return_value="/fixture/tool"),
                mock.patch.object(PROOF, "configuration", side_effect=lambda config: settings if config == source else other),
                mock.patch.object(PROOF, "remote", side_effect=remote),
                mock.patch.object(PROOF.subprocess, "Popen", return_value=process) as popen,
                mock.patch.object(PROOF.subprocess, "run") as setup,
                mock.patch.object(PROOF.sys, "stdout", io.StringIO()),
                mock.patch.object(PROOF.sys, "stderr", io.StringIO()),
            ):
                result = PROOF.main()
            report = json.loads((artifacts / "report.json").read_text())
            markdown = (artifacts / "report.md").read_text()
            return result, report, markdown, popen, setup, probes

    def assert_blocked_before_mutation(self, result):
        code, report, _, popen, setup, _ = result
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["results"][0]["status"], "not run")
        self.assertTrue(report["problems"])
        popen.assert_not_called()
        setup.assert_not_called()

    def test_guarded_memory_probe_can_use_existing_remote_budget(self):
        # Model guard plus probe taking 45s without sleeping or connecting.
        for proof in ("product", "transfer"):
            with self.subTest(proof=proof):
                result = self.run_proof(proof, check=True, memory_probe_seconds=45)
                self.assertEqual(result[0], 0)
                self.assertEqual(result[1]["status"], "ready")
                self.assertEqual(result[1]["target"]["memory_total_bytes"], 3 * 1024**3)
                result[3].assert_not_called()
                result[4].assert_not_called()

    def test_guarded_memory_probe_still_blocks_when_remote_budget_is_exhausted(self):
        for proof in ("product", "transfer"):
            with self.subTest(proof=proof):
                result = self.run_proof(proof, memory_probe_seconds=65)
                self.assert_blocked_before_mutation(result)

    def test_low_destination_blocks_transfer_before_setup_or_process_launch(self):
        result = self.run_proof("transfer", source_memory="MemTotal: 1572864 kB\n",
                                destination_memory="MemTotal: 1048576 kB\n")
        self.assert_blocked_before_mutation(result)
        self.assertEqual(result[1]["secondary_target"]["memory_total_bytes"], 1024 * 1024**2)
        self.assertTrue(any("destination" in problem and "MemTotal" in problem for problem in result[1]["problems"]))

    def test_low_source_blocks_m2_and_product_before_setup_or_process_launch(self):
        for proof in ("m2", "product"):
            with self.subTest(proof=proof):
                result = self.run_proof(proof, source_memory="MemTotal: 1572864 kB\n")
                self.assert_blocked_before_mutation(result)
                self.assertEqual(result[1]["target"]["memory_total_bytes"], 1536 * 1024**2)
                self.assertTrue(any("source" in problem and "MemTotal" in problem for problem in result[1]["problems"]))

    def test_exact_two_gib_is_accepted_for_each_required_guest(self):
        for proof in ("m2", "product", "transfer"):
            with self.subTest(proof=proof):
                result = self.run_proof(proof, source_memory="MemTotal: 2097152 kB\n",
                                       destination_memory="MemTotal: 2097152 kB\n", check=True)
                self.assertEqual(result[0], 0)
                self.assertEqual(result[1]["status"], "ready")
                key = "secondary_target" if proof == "transfer" else "target"
                self.assertEqual(result[1][key]["memory_total_bytes"], 2 * 1024**3)
                result[3].assert_not_called()
                result[4].assert_not_called()

    def test_malformed_memtotal_blocks_without_serializing_probe_output(self):
        invalid = ("MemFree: 3145728 kB\n", "MemTotal: unknown kB\n", "MemTotal: -3145728 kB\n",
                   "MemTotal: 3145728 MB\n", "MemTotal: 0 kB\n",
                   "MemTotal: 3145728 kB\nMemTotal: 3145728 kB\n",
                   "MemTotal: 3145728 kB token=probe-secret\n")
        for payload in invalid:
            for proof in ("product", "transfer"):
                with self.subTest(proof=proof, payload=payload):
                    values = {"destination_memory": payload} if proof == "transfer" else {"source_memory": payload}
                    result = self.run_proof(proof, **values)
                    self.assert_blocked_before_mutation(result)
                    self.assertNotIn("probe-secret", json.dumps(result[1]) + result[2])

    def test_failed_memtotal_probe_blocks_before_mutation(self):
        failures = (subprocess.CompletedProcess([], 1, stdout="MemTotal: 3145728 kB\n", stderr="token=probe-secret"),
                    subprocess.TimeoutExpired("memory probe", 30),
                    OSError("token=probe-secret"))
        for failure in failures:
            for proof in ("m2", "transfer"):
                with self.subTest(proof=proof, failure=type(failure).__name__):
                    values = {"destination_memory": failure} if proof == "transfer" else {"source_memory": failure}
                    result = self.run_proof(proof, **values)
                    self.assert_blocked_before_mutation(result)
                    self.assertNotIn("probe-secret", json.dumps(result[1]) + result[2])

    def test_m1_does_not_add_a_memory_requirement_or_probe(self):
        result = self.run_proof("m1", source_memory=OSError("memory unavailable"), check=True)
        self.assertEqual(result[0], 0)
        self.assertEqual(result[1]["status"], "ready")
        self.assertFalse(any(script == "cat /proc/meminfo" for _, script in result[5]))
        self.assertNotIn("memory_total_bytes", result[1]["target"])

    def test_transfer_allows_prepared_small_source_and_larger_clean_destination(self):
        result = self.run_proof("transfer", source_memory="MemTotal: 1572864 kB\n",
                               destination_memory="MemTotal: 2621440 kB\n", check=True)
        self.assertEqual(result[0], 0)
        self.assertEqual(result[1]["status"], "ready")
        self.assertEqual(result[1]["target"]["memory_total_bytes"], 1536 * 1024**2)
        self.assertEqual(result[1]["secondary_target"]["memory_total_bytes"], 2560 * 1024**2)
        self.assertIn("MemTotal", result[2])
        self.assertFalse(result[1]["problems"])


if __name__ == "__main__":
    unittest.main()
