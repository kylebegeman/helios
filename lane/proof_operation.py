#!/usr/bin/env python3
"""Bind a lane proof command to its admitted operation and verify its own outcome."""
import argparse
import json
from pathlib import PurePosixPath
import re
import shlex
import subprocess
import sys
import time
import uuid


PHASES = {
    "exercise": ("kernel.exercise", ""),
    "setup": ("host.setup", "bedrock host setup --hostname bedrock-lane --swap 4 --yes --json"),
    "maintain": ("host.maintain", "bedrock host maintain --reboot --yes --json"),
    "broken-upgrade": ("host.upgrade", "bedrock upgrade /tmp/bedrock-broken --yes --json"),
    "good-upgrade": ("host.upgrade", "bedrock upgrade /tmp/bedrock-lane --yes --json"),
}
FINAL = {"succeeded", "failed", "compensated"}


class ProofError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofError(message)


class Remote:
    def __init__(self, transport: list[str], deadline: float):
        self.transport = transport
        self.deadline = deadline
        self.last_error = ""

    def read(self, command: str) -> str | None:
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "phase timed out before its own terminal receipt")
        try:
            result = subprocess.run([*self.transport, command], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=min(15, remaining))
        except subprocess.TimeoutExpired:
            self.last_error = "remote command timed out"
            return None
        self.last_error = result.stderr.strip()[-2000:] if result.returncode else ""
        return result.stdout if result.returncode == 0 else None

    def checked(self, command: str) -> str:
        result = self.read(command)
        require(result is not None, f"command failed: {self.last_error or command}")
        return result


def admission(output: str, kind: str) -> tuple[str, str] | None:
    events = []
    # A concurrent cat can end in the middle of the last event. Only complete
    # lines are evidence; malformed complete lines must fail closed.
    for line in output.splitlines(keepends=True):
        if line.endswith("\n"):
            event = json.loads(line)
            require(isinstance(event, dict), "invalid command event")
            events.append(event)
    planned = [event for event in events if event.get("type") == "planned"]
    if not planned:
        require(not events, "command emitted events without an admitted plan")
        return None
    require(len(planned) == 1, "command admitted more than one operation")
    event = planned[0]
    operation = event.get("operation", "")
    plan = event.get("plan")
    require(isinstance(operation, str) and re.fullmatch(r"op-\d{8}-\d{6}-[a-z2-7]{5}", operation),
            "invalid admitted operation ID")
    require(isinstance(plan, dict) and plan.get("kind") == kind, "command admitted the wrong operation kind")
    digest = plan.get("digest", "")
    require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{24}", digest), "invalid admitted plan digest")
    require(all(event.get("operation") == operation for event in events),
            "command events refer to an unrelated operation")
    return operation, digest


def receipt_status(receipt: dict, operation: str, kind: str, digest: str) -> str:
    require(isinstance(receipt, dict) and receipt.get("id") == operation,
            "receipt does not belong to this command's admitted operation")
    require(receipt.get("kind") == kind and receipt.get("plan_digest") == digest,
            "receipt does not match the admitted kind and plan")
    status = receipt.get("status")
    require(status in FINAL | {"planned", "applying"}, "unknown operation status")
    return status


def verify_receipt(receipt: dict, phase: str) -> None:
    rows = receipt.get("steps")
    require(isinstance(rows, list) and rows and all(isinstance(step, dict) for step in rows),
            "receipt has no valid steps")
    steps = {step.get("name"): step for step in rows}
    require(len(steps) == len(rows), "receipt has duplicate steps")
    if phase != "broken-upgrade":
        require(receipt["status"] == "succeeded" and all(step.get("status") == "succeeded" for step in rows),
                f"{phase} did not succeed: {receipt.get('error', receipt['status'])}")
    if phase == "exercise":
        require(set(steps) == {f"step-{n}" for n in range(1, 7)}, "exercise did not finish six steps")
        require(receipt.get("interruptions") == 1 and steps["step-3"].get("attempts") == 2,
                "exercise did not resume the killed third step exactly once")
    elif phase == "maintain":
        require(set(steps) == {"updates", "reboot", "verify"}, "maintenance did not complete its intended steps")
        require(receipt.get("interruptions", 0) >= 1 and steps["reboot"].get("attempts", 0) >= 2,
                "maintenance did not recover its reboot step")
    elif "upgrade" in phase:
        require(receipt.get("target") == "/usr/local/bin/bedrock", "upgrade targeted another binary")
        require(set(steps) == {"stage", "switch", "restart", "verify"}, "upgrade has unexpected steps")
        if phase == "broken-upgrade":
            require(receipt["status"] == "failed" and steps["stage"].get("status") == "succeeded"
                    and steps["switch"].get("status") == "succeeded", "broken upgrade did not stage and switch the candidate")
            restart = steps["restart"]
            require(restart.get("status") == "failed" and restart.get("attempts", 0) >= 2
                    and receipt.get("interruptions", 0) >= 1, "broken upgrade did not fail after daemon recovery")
            require("the new build 0.7.0-broken " in restart.get("error", "")
                    and "didn't start; systemd put 0.7.0-dev " in restart.get("error", ""),
                    "broken upgrade did not report failed daemon startup and rollback")
            require(steps["verify"].get("status") == "pending", "broken upgrade unexpectedly reached verification")


def verify_binary(remote: Remote, phase: str) -> None:
    expected = "0.7.0-lane" if phase == "good-upgrade" else "0.7.0-dev"
    info = json.loads(remote.checked("bedrock version --json"))
    require(isinstance(info, dict) and info.get("version") == expected, f"installed binary is not {expected}")
    status = remote.checked("bedrock daemon status")
    require(any(line.startswith(f"daemon {expected} answering on ") for line in status.splitlines()),
            f"daemon is not answering on {expected}")
    candidate = "/tmp/bedrock-lane" if phase == "good-upgrade" else "/usr/local/lib/bedrock/previous"
    sums = remote.checked(f"sha256sum /usr/local/bin/bedrock {candidate}").splitlines()
    require(len(sums) == 2 and all(re.match(r"^[a-f0-9]{64}  ", line) for line in sums)
            and sums[0].split()[0] == sums[1].split()[0], "installed binary differs from the expected build")


# Watch locally beside the exercise: a pinned SSH connection can take longer
# than the entire intended step. The signal must not depend on host poll timing.
EXERCISE_WATCHER = r"""
import json, os, re, signal, subprocess, sys, time
from pathlib import Path
events, destination, cutoff, budget = sys.argv[1:]
deadline = time.monotonic() + min(float(budget), max(0, float(cutoff) - time.time()))
result = Path(destination)
bound = None
try:
    while time.monotonic() < deadline:
        if bound is None and Path(events).exists():
            for line in Path(events).read_text().splitlines(keepends=True):
                if not line.endswith("\n"):
                    continue
                event = json.loads(line)
                if event.get("type") == "planned":
                    operation = event.get("operation", "")
                    plan = event.get("plan", {})
                    digest = plan.get("digest", "")
                    if not (re.fullmatch(r"op-\d{8}-\d{6}-[a-z2-7]{5}", operation)
                            and plan.get("kind") == "kernel.exercise" and re.fullmatch(r"[a-f0-9]{24}", digest)):
                        raise ValueError("invalid exercise admission; no signal sent")
                    bound = operation, digest
                    break
        if bound:
            operation, digest = bound
            pid = int(subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", "bedrock"], text=True, timeout=3).strip())
            receipt = json.loads(subprocess.check_output(["bedrock", "history", operation, "--json"], text=True, timeout=3))
            if not (receipt["id"] == operation and receipt["kind"] == "kernel.exercise" and receipt["plan_digest"] == digest):
                raise ValueError("unrelated exercise receipt; no signal sent")
            steps = {step["name"]: step for step in receipt["steps"]}
            if receipt["status"] == "applying" and steps["step-3"]["status"] == "running":
                if not (pid > 1 and receipt["interruptions"] == 0 and steps["step-1"]["status"] == "succeeded"
                        and steps["step-2"]["status"] == "succeeded" and steps["step-3"]["attempts"] == 1
                        and time.monotonic() < deadline):
                    raise ValueError("exercise no longer ready for its crash; no signal sent")
                os.kill(pid, signal.SIGKILL)
                proof = {"pid": pid, "receipt": receipt}
                break
            if receipt["status"] not in {"planned", "applying"} or steps["step-3"]["status"] not in {"pending", "running"}:
                raise ValueError("exercise step-3 no longer running; no signal sent")
        time.sleep(0.1)
    else:
        raise ValueError("timed out waiting for exercise step-3; no signal sent")
except Exception as error:
    proof = {"error": str(error)}
# Publish evidence atomically so a host read never sees a partial JSON object.
temporary = result.with_suffix(".tmp")
temporary.write_text(json.dumps(proof) + "\n")
temporary.replace(result)
"""


def verify_crash(proof: dict, operation: str, digest: str, markers: str) -> None:
    require(isinstance(proof, dict), "invalid exercise crash evidence")
    require("error" not in proof, str(proof.get("error")))
    receipt = proof.get("receipt", {})
    require(receipt_status(receipt, operation, "kernel.exercise", digest) == "applying"
            and receipt.get("target") == markers, "exercise crash evidence belongs to another operation")
    steps = {step["name"]: step for step in receipt["steps"]}
    require(type(proof.get("pid")) is int and proof["pid"] > 1 and receipt.get("interruptions") == 0
            and steps["step-1"]["status"] == "succeeded" and steps["step-2"]["status"] == "succeeded"
            and steps["step-3"]["status"] == "running" and steps["step-3"]["attempts"] == 1,
            "exercise was not killed during its intended third step")
    print(f"killed daemon pid {proof['pid']} during {operation} step-3", flush=True)
    print(json.dumps(receipt), flush=True)


def verify_markers(remote: Remote, directory: str) -> None:
    script = """
from datetime import datetime
from pathlib import Path
import sys
markers = Path(sys.argv[1])
expected = {f"step-{n}" for n in range(1, 7)}
if {path.name for path in markers.iterdir()} != expected:
    raise SystemExit("exercise must have all six marker files")
for name in sorted(expected):
    path = markers / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit("invalid exercise marker: " + name)
    datetime.fromisoformat(path.read_text().strip().replace("Z", "+00:00"))
print("verified six exercise marker files:", ", ".join(sorted(expected)))
"""
    print(remote.checked(shlex.join(["python3", "-c", script, directory])), end="", flush=True)

def prove(args: argparse.Namespace) -> None:
    kind, command = PHASES[args.phase]
    if args.phase == "maintain":
        uuid.UUID(args.boot_before)
    markers = str(PurePosixPath(args.directory) / "markers")
    if args.phase == "exercise":
        command = shlex.join(["bedrock", "kernel", "exercise", "--dir", markers, "--steps", "6",
                              "--step-duration", "3s", "--yes", "--json"])
    remote = Remote(args.transport, time.monotonic() + args.timeout)
    base = str(PurePosixPath(args.directory) / args.phase)
    events, exited, log = (shlex.quote(base + suffix) for suffix in (".events", ".exit", ".log"))
    # Each invocation uses the caller's newly created directory. A wrapper's
    # exit marker detects pre-admission rejection; reboot may kill the wrapper,
    # so that marker is never required to prove a recovered terminal receipt.
    script = f'{command}; result=$?; printf "%s\\n" "$result" > {exited}'
    launch = f"nohup sh -c {shlex.quote(script)} > {events} 2> {log} < /dev/null &"
    crash_file = shlex.quote(base + ".crash")
    if args.phase == "exercise":
        # Share the host's wall-clock cutoff so delayed transport never permits
        # a signal after the phase deadline. Disposable VMs use the host clock.
        cutoff = time.time() + max(0, remote.deadline - time.monotonic())
        watcher = shlex.join(["python3", "-c", EXERCISE_WATCHER, base + ".events", base + ".crash", str(cutoff), str(args.timeout)])
        launch += f" nohup {watcher} > {shlex.quote(base + '.watch.log')} 2>&1 < /dev/null &"
    remote.checked(launch)
    bound = None
    killed = False
    while time.monotonic() < remote.deadline:
        output = remote.read(f"cat {events}")
        if output is not None:
            observed = admission(output, kind)
            if observed:
                require(bound is None or bound == observed, "admitted operation changed during the phase")
                if bound is None:
                    print(f"{args.phase} admitted {observed[0]}", flush=True)
                bound = observed
        if bound:
            operation, digest = bound
            output = remote.read(f"bedrock history {shlex.quote(operation)} --json")
            if output is not None:
                receipt = json.loads(output)
                status = receipt_status(receipt, operation, kind, digest)
                if args.phase == "exercise":
                    require(receipt.get("target") == markers, "exercise targeted a different marker directory")
                    if not killed:
                        evidence = remote.read(f"cat {crash_file}")
                        if evidence is not None:
                            verify_crash(json.loads(evidence), operation, digest, markers)
                            killed = True
                        else:
                            require(status not in FINAL, "exercise ended before its intended crash")
                if status in FINAL:
                    print(json.dumps(receipt), flush=True)
                    verify_receipt(receipt, args.phase)
                    if args.phase == "exercise":
                        verify_markers(remote, markers)
                    if args.phase == "maintain":
                        before = str(uuid.UUID(args.boot_before))
                        after = str(uuid.UUID(remote.checked("cat /proc/sys/kernel/random/boot_id").strip()))
                        require(before != after, "maintenance succeeded without a boot ID change")
                        remote.checked("test ! -e /var/run/reboot-required")
                        print(f"reboot recovered: {before} -> {after}", flush=True)
                    if "upgrade" in args.phase:
                        verify_binary(remote, args.phase)
                    print(f"{args.phase} ended: {operation} {receipt['status']}", flush=True)
                    return
        elif remote.read(f"cat {exited}") is not None:
            # The first event read can race the final write. Once exit is
            # recorded, reread the completed stream before rejecting it.
            output = remote.read(f"cat {events}")
            observed = admission(output, kind) if output is not None else None
            require(observed is not None, f"command exited without admission; inspect {base}.log")
            bound = observed
            print(f"{args.phase} admitted {observed[0]}", flush=True)
            continue
        time.sleep(min(1, max(0, remote.deadline - time.monotonic())))
    raise ProofError(f"timed out waiting for {'terminal receipt of ' + bound[0] if bound else 'command admission'}; inspect {base}.log")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--boot-before", default="")
    parser.add_argument("transport", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.transport[:1] == ["--"]:
        args.transport.pop(0)
    try:
        require(args.transport and args.timeout > 0, "transport and positive timeout required")
        prove(args)
    except (ProofError, ValueError, TypeError, KeyError, OSError) as error:
        print(f"{'M1' if args.phase == 'exercise' else 'M2'} NOT proven: {args.phase}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
