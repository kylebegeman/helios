#!/usr/bin/env python3
"""Run M1/M2 proofs against controlled command/event/receipt fixtures, offline."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

# This transport never runs its command. It models the public CLI contracts and
# persists state across invocations, including a command still planning while
# unrelated successful history exists.
TRANSPORT = r'''#!/usr/bin/env python3
import json, os, shlex, sys
from pathlib import Path
root = Path(os.environ["M2_TEST_ROOT"])
path = root / "state.json"
s = json.loads(path.read_text())
command = sys.argv[-1]
s["commands"].append(command)
scenario = os.environ.get("M2_TEST_SCENARIO", "normal")
phase = s.get("phase", "setup")
ids = {"setup": "op-20261021-120000-aaaaa", "maintain": "op-20261021-120001-bbbbb",
       "broken-upgrade": "op-20261021-120002-ccccc", "good-upgrade": "op-20261021-120003-ddddd"}
kind = "host.maintain" if phase == "maintain" else "host.upgrade" if "upgrade" in phase else "host.setup"
code = 0
out = ""
if command.startswith("mktemp -d "):
    out = "/var/lib/bedrock/m2-proof.abcdef"
elif command.startswith("nohup "):
    if s.get("active"):
        s["overlap"] = True
    if "host setup" in command: phase = "setup"
    elif "host maintain" in command: phase = "maintain"
    elif "/tmp/bedrock-broken" in command: phase = "broken-upgrade"
    elif "/tmp/bedrock-lane" in command: phase = "good-upgrade"
    else: raise SystemExit("unexpected detached command: " + command)
    s.update(phase=phase, active=True, reads=0)
    s["started"].append(phase)
elif command.startswith("cat ") and command.endswith(".events"):
    s["reads"] += 1
    if scenario == "no-admission" or (scenario == "admission-exit-race" and s["reads"] == 1):
        pass
    elif scenario == "delayed" and phase == "maintain" and s["reads"] < 3:
        pass
    elif scenario == "rejected" and phase == "broken-upgrade":
        pass
    else:
        out = json.dumps({"type": "planned", "operation": ids[phase],
                          "plan": {"kind": kind, "target": "/usr/local/bin/bedrock" if "upgrade" in phase else "bedrock-lane",
                                   "digest": "d" * 24}}) + "\n"
        if scenario == "wrong-event" and phase == "maintain":
            out += json.dumps({"type": "step-started", "operation": ids["setup"]}) + "\n"
elif command.startswith("cat ") and command.endswith(".exit"):
    if scenario == "rejected" and phase == "broken-upgrade": out = "1\n"
    elif scenario == "admission-exit-race": out = "0\n"
    else: code = 1
elif command.startswith("bedrock history ") and "--limit" not in command:
    requested = shlex.split(command)[2]
    s["queried"].append(requested)
    status = "failed" if phase == "broken-upgrade" else "succeeded"
    if scenario == "failed-good" and phase == "good-upgrade": status = "failed"
    if scenario == "no-terminal": status = "applying"
    names = ["updates", "reboot", "verify"] if phase == "maintain" else ["stage", "switch", "restart", "verify"] if "upgrade" in phase else ["packages", "profile"]
    steps = [{"name": name, "status": "succeeded", "attempts": 1} for name in names]
    if phase == "maintain": steps[1]["attempts"] = 2
    interruptions = 1 if phase == "maintain" or "upgrade" in phase else 0
    error = ""
    if phase == "broken-upgrade":
        steps[2].update(status="failed", attempts=2,
                        error="the new build 0.7.0-broken (unknown) didn't start; systemd put 0.7.0-dev (unknown) back")
        steps[3].update(status="pending", attempts=0)
        error = "restart: " + steps[2]["error"]
    if scenario == "never-switched" and phase == "broken-upgrade":
        steps[1].update(status="failed", error="candidate could not be installed")
    receipt = {"id": ids[phase], "kind": kind, "target": "/usr/local/bin/bedrock" if "upgrade" in phase else "bedrock-lane",
               "plan_digest": "d" * 24, "status": status, "interruptions": interruptions,
               "steps": steps, "error": error}
    if scenario == "unrelated" and phase == "maintain": receipt.update(id=ids["setup"], kind="host.setup")
    if scenario == "wrong-digest" and phase == "good-upgrade": receipt["plan_digest"] = "e" * 24
    if scenario == "no-recovery" and phase == "maintain": receipt["interruptions"] = 0
    out = json.dumps(receipt)
    s["active"] = False
    if phase == "maintain" and scenario != "missing-reboot": s["rebooted"] = True
elif command.startswith("bedrock history "):
    # The bug: a newer phase is still planning, so latest history is old setup.
    out = json.dumps([{"id": ids["setup"], "kind": "host.setup", "status": "succeeded"}])
elif command == "cat /proc/sys/kernel/random/boot_id":
    out = "22222222-2222-4222-8222-222222222222" if s.get("rebooted") else "11111111-1111-4111-8111-111111111111"
elif command == "bedrock version --json":
    out = json.dumps({"version": "0.7.0-lane" if phase == "good-upgrade" else "0.7.0-dev"})
elif command == "bedrock version":
    out = "helios " + ("0.7.0-lane" if phase == "good-upgrade" else "0.7.0-dev")
elif command == "bedrock daemon status":
    out = "daemon " + ("0.7.0-lane" if phase == "good-upgrade" else "0.7.0-dev") + " answering on /run/bedrock/daemon.sock"
elif command.startswith("bedrock version;"):
    out = "helios 0.7.0-dev\ndaemon 0.7.0-dev answering"
elif command == "bedrock host reconcile --plan":
    out = "host.setup on bedrock-lane"
elif command.startswith("test ! -e /var/run/reboot-required"):
    code = 0 if s.get("rebooted") else 1
elif command.startswith("sha256sum "):
    out = "f" * 64 + "  /usr/local/bin/bedrock\n" + ("e" if scenario == "wrong-binary" and phase == "good-upgrade" else "f") * 64 + "  /tmp/bedrock-lane\n"
elif command in ("bedrock doctor", "bedrock host setup --hostname bedrock-lane --swap 4 --yes", "true", "uptime -p"):
    pass
elif command.startswith(("chmod 755 ", "touch /var/run/reboot-required", "tail -n ")):
    pass
else:
    raise SystemExit("unexpected fixture command: " + command)
path.write_text(json.dumps(s))
if out: print(out, end="" if out.endswith("\n") else "\n")
raise SystemExit(code)
'''


class ProofFixture:
    script = "prove-m2.sh"
    transport = TRANSPORT

    def run_proof(self, scenario="normal", operation=None):
        with tempfile.TemporaryDirectory(prefix="helios-m2-test-") as directory:
            root = Path(directory)
            lane = root / "lane"
            lane.mkdir()
            (root / "bin").mkdir()
            shutil.copy(HERE / self.script, lane)
            if (HERE / "proof_operation.py").exists():
                shutil.copy(HERE / "proof_operation.py", lane)
            (lane / "common.sh").write_text("LANE_ARCH=amd64\nssh_opts=(fixture)\nscp_opts=(fixture)\nbox=fixture\n")
            tools = root / "tools"
            tools.mkdir()
            for name, body in {"ssh": self.transport, "go": "#!/bin/sh\nexit 0\n",
                               "scp": "#!/bin/sh\nexit 0\n",
                               "systemctl": "#!/bin/sh\necho 424242\n",
                               "bedrock": '#!/bin/sh\ncat "$M2_TEST_ROOT/kill-receipt.json"\n',
                               "sleep": "#!/bin/sh\nexit 0\n"}.items():
                executable = tools / name
                executable.write_text(body)
                executable.chmod(0o755)
            (root / "state.json").write_text(json.dumps({"commands": [], "started": [], "queried": []}))
            command = ["bash", str(lane / self.script)]
            if operation:
                phase, seconds = operation
                command = ["python3", str(lane / "proof_operation.py"), "--phase", phase,
                           "--directory", "/var/lib/bedrock/m2-proof.abcdef", "--timeout", str(seconds),
                           "--", str(tools / "ssh"), "fixture"]
            result = subprocess.run(command, text=True, capture_output=True,
                                    env={**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                                         "M2_TEST_ROOT": str(root), "M2_TEST_SCENARIO": scenario}, timeout=30)
            return result, json.loads((root / "state.json").read_text())


class M2Proof(ProofFixture, unittest.TestCase):
    def test_delayed_admission_ignores_stale_history_and_never_overlaps(self):
        result, state = self.run_proof("delayed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(state.get("overlap"), state)
        self.assertEqual(state["started"], ["setup", "maintain", "broken-upgrade", "good-upgrade"])
        self.assertEqual(len(set(state["queried"])), 4)
        self.assertIn("M2 proven", result.stdout)

    def assert_unproven(self, scenario, later_phase):
        result, state = self.run_proof(scenario)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("M2 proven", result.stdout)
        expected = {"unrelated": "receipt does not belong", "missing-reboot": "without a boot ID change",
                    "rejected": "without admission", "never-switched": "did not stage and switch",
                    "failed-good": "good-upgrade did not succeed", "wrong-event": "unrelated operation",
                    "wrong-digest": "does not match the admitted kind and plan",
                    "wrong-binary": "differs from the expected build", "no-recovery": "did not recover its reboot step"}
        self.assertIn(expected[scenario], result.stderr)
        if later_phase:
            self.assertNotIn(later_phase, state["started"], state)

    def test_admission_wait_is_bounded_without_history_fallback(self):
        result, state = self.run_proof("no-admission", operation=("good-upgrade", 0.25))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("command admission", result.stderr)
        self.assertFalse(state["queried"])

    def test_own_terminal_wait_is_bounded(self):
        result, state = self.run_proof("no-terminal", operation=("good-upgrade", 0.5))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("terminal receipt", result.stderr)
        self.assertEqual(set(state["queried"]), {"op-20261021-120003-ddddd"})

    def test_exit_marker_race_rereads_completed_admission(self):
        result, state = self.run_proof("admission-exit-race", operation=("good-upgrade", 3))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(state["queried"]), {"op-20261021-120003-ddddd"})

    def test_maintenance_must_resume_through_reboot(self):
        self.assert_unproven("no-recovery", "broken-upgrade")

    def test_good_upgrade_must_install_the_candidate_bytes(self):
        self.assert_unproven("wrong-binary", None)

    def test_unrelated_successful_receipt_cannot_complete_maintenance(self):
        self.assert_unproven("unrelated", "broken-upgrade")

    def test_success_without_real_reboot_cannot_pass(self):
        self.assert_unproven("missing-reboot", "broken-upgrade")

    def test_preflight_rejection_is_not_a_proven_rollback(self):
        self.assert_unproven("rejected", "good-upgrade")

    def test_failed_switch_is_not_a_proven_daemon_rollback(self):
        self.assert_unproven("never-switched", "good-upgrade")

    def test_failed_own_good_upgrade_cannot_use_old_success(self):
        self.assert_unproven("failed-good", None)

    def test_events_from_another_operation_fail_the_phase(self):
        self.assert_unproven("wrong-event", "broken-upgrade")

    def test_receipt_must_match_admitted_plan(self):
        self.assert_unproven("wrong-digest", None)


EXERCISE_TRANSPORT = r"""#!/usr/bin/env python3
import json, os, shlex, subprocess, sys, threading, time
from pathlib import Path
root = Path(os.environ["M2_TEST_ROOT"])
path = root / "state.json"
s = json.loads(path.read_text())
command = sys.argv[-1]
s["commands"].append(command)
scenario = os.environ["M2_TEST_SCENARIO"]
operation = "op-20261021-130000-aaaaa"
old = "op-20261020-130000-bbbbb"
code, out = 0, ""
if command.startswith("mktemp -d "):
    out = "/var/lib/bedrock/m1-proof.abcdef"
elif "nohup " in command:
    s.update(reads=0, active=True)
    s["started"].append("exercise")
    if "python3 -c " in command:
        steps = [{"name": "step-" + str(n), "status": "succeeded" if n < 3 else "running" if n == 3 else "pending",
                  "attempts": 1 if n <= 3 else 0} for n in range(1, 7)]
        receipt = {"id": old if scenario == "unrelated" else operation, "kind": "kernel.exercise", "plan_digest": "d" * 24,
                   "target": "/var/lib/bedrock/m1-proof.abcdef/markers", "steps": steps,
                   "status": "applying", "interruptions": 0}
        if scenario in ("no-step3", "moved-before-kill"): steps[2]["status"] = "succeeded"
        (root / "kill-receipt.json").write_text(json.dumps(receipt))
        args = shlex.split(command)
        index = args.index("python3")
        events, crash = root / "watcher.events", root / "watcher.crash"
        events.write_text("")
        def admit():
            time.sleep(0.05)
            events.write_text(json.dumps({"type": "planned", "operation": operation,
                                         "plan": {"kind": "kernel.exercise", "digest": "d" * 24}}) + "\n")
        thread = threading.Thread(target=admit)
        thread.start()
        # Execute the actual guest watcher against fixture CLI responses. Record
        # its signal request, without sending any operating-system signal.
        recorder = ('import os, json; from pathlib import Path; '
                    'os.kill = lambda pid, sig: Path(os.environ["M2_TEST_ROOT"], "signal.json").write_text(json.dumps([pid, sig]))\n')
        result = subprocess.run([sys.executable, "-c", recorder + args[index + 2], str(events), str(crash),
                                 str(time.time() + 2), "2"], text=True, capture_output=True)
        thread.join()
        code, out = result.returncode, result.stdout
        sys.stderr.write(result.stderr)
        s["crash"] = json.loads(crash.read_text())
        s["killed"] = (root / "signal.json").exists()
        s["killed_before_admission"] = s["killed"] and not events.read_text()
        s["killed_step"] = 3 if s["killed"] else None
elif command.startswith("cat ") and command.endswith(".events"):
    s["reads"] += 1
    # The host sees admission late, after the watcher already performed the
    # exact crash. This models transport latency longer than the step window.
    if s["reads"] >= 3:
        out = json.dumps({"type": "planned", "operation": operation,
                          "plan": {"kind": "kernel.exercise", "digest": "d" * 24}}) + "\n"
elif command.startswith("cat ") and command.endswith(".exit"):
    code = 1
elif command.startswith("cat ") and command.endswith(".crash"):
    out = json.dumps(s["crash"])
elif command.startswith("bedrock history ") and "--limit" not in command:
    s["queried"].append(shlex.split(command)[2])
    receipt = {"id": operation, "kind": "kernel.exercise", "plan_digest": "d" * 24,
               "target": "/var/lib/bedrock/m1-proof.abcdef/markers",
               "steps": [{"name": "step-" + str(n), "status": "succeeded", "attempts": 2 if n == 3 else 1} for n in range(1, 7)],
               "status": "succeeded", "interruptions": 1}
    if scenario == "unrelated": receipt["id"] = old
    out = json.dumps(receipt)
elif command.startswith("bedrock history "):
    out = json.dumps([{"id": old, "status": "succeeded", "interruptions": 1}])
elif 'kill -9 "$pid"' in command:
    s["killed_before_admission"] = True
    s["killed"] = True
elif command.startswith("python3 -c ") and "markers" in command:
    markers = root / "markers"
    markers.mkdir(exist_ok=True)
    for n in range(1, 6 if scenario == "missing-marker" else 7):
        (markers / ("step-" + str(n))).write_text("2026-10-21T12:00:00Z\n")
    args = shlex.split(command)
    result = subprocess.run([sys.executable, "-c", args[2], str(markers)], text=True, capture_output=True)
    code, out = result.returncode, result.stdout
    sys.stderr.write(result.stderr)
elif command.startswith(("chmod ", "bedrock daemon install", "tail -n ", "journalctl ", "ls ")):
    pass
else:
    raise SystemExit("unexpected fixture command: " + command)
path.write_text(json.dumps(s))
if out: print(out, end="" if out.endswith("\n") else "\n")
raise SystemExit(code)
"""


class M1Proof(ProofFixture, unittest.TestCase):
    script = "prove-m1.sh"
    transport = EXERCISE_TRANSPORT

    def test_delayed_exercise_admission_kills_only_its_running_third_step(self):
        result, state = self.run_proof("delayed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(state.get("killed_before_admission"), state)
        self.assertEqual(state.get("killed_step"), 3, state)
        self.assertEqual(set(state["queried"]), {"op-20261021-130000-aaaaa"})
        self.assertIn("M1 proven", result.stdout)

    def test_missing_marker_cannot_pass_a_successful_receipt(self):
        result, state = self.run_proof("missing-marker")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(state.get("killed"), state)
        self.assertIn("exercise must have all six marker files", result.stderr)
        self.assertNotIn("M1 proven", result.stdout)

    def test_unrelated_receipt_cannot_trigger_kill(self):
        result, state = self.run_proof("unrelated")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(state.get("killed"), state)

    def test_remote_recheck_refuses_signal_if_third_step_finished(self):
        result, state = self.run_proof("moved-before-kill")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("step-3 no longer running; no signal sent", result.stderr)
        self.assertFalse(state.get("killed"), state)
        self.assertNotIn("M1 proven", result.stdout)

    def test_passing_the_intended_step_without_kill_fails(self):
        result, state = self.run_proof("no-step3")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(state.get("killed"), state)


if __name__ == "__main__":
    unittest.main()
