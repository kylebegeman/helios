#!/usr/bin/env python3
"""Own one disposable QEMU guest; never adopt or delete another container."""
import argparse
import json
import os
import re
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("LANE_VM_STATE", str(Path(os.environ.get("TMPDIR", "/tmp")) / f"bedrock-lane-{os.getuid()}")))
IMAGE = "bedrock-lane-qemu:ubuntu-24.04"
LABEL = "io.bedrock.lane.id"
DEFAULT_MEMORY_MIB = 3072
MIN_MEMORY_MIB = 512
MAX_MEMORY_MIB = 65536
TCG_CACHE_MIB = 128
# Docker hands a published port's connections to the container from its
# network's gateway, and QEMU's user network passes that address on to the
# guest. On the default bridge it is 172.17.0.1, the address the guest's own
# Docker gives docker0, so once host setup installs Docker the guest drops
# every new SSH connection as coming from itself. Each VM gets a network of
# its own in a range Docker never picks by default.
NETWORK_SUBNETS = tuple(f"10.213.{n}.0/24" for n in range(1, 255))


def requested_memory() -> int:
    value = os.environ.get("LANE_VM_MEMORY_MIB", str(DEFAULT_MEMORY_MIB))
    if (len(value) > len(str(MAX_MEMORY_MIB)) or
            re.fullmatch(r"[1-9][0-9]*", value) is None or
            not MIN_MEMORY_MIB <= int(value) <= MAX_MEMORY_MIB):
        raise RuntimeError(f"LANE_VM_MEMORY_MIB must be an integer from {MIN_MEMORY_MIB} through {MAX_MEMORY_MIB}.")
    return int(value)


def write_config(data: dict, port: str) -> None:
    values = {"LANE_PROVIDER": "qemu-docker", "LANE_DISPOSABLE": "true", "LANE_ID": data["id"],
              "LANE_VM_IMAGE": data["provider_image"], "LANE_OS_IMAGE_SHA256": data["guest_image_sha256"],
              "HOST": "127.0.0.1", "PORT": port,
              "KEY": str(STATE / "ssh-key"), "KNOWN_HOSTS": str(STATE / "known_hosts")}
    # Unknown legacy resources must not become an explicit empty RAM request
    # when callers export the generated configuration before reusing the VM.
    for field, key in (("guest_memory_mib", "LANE_VM_MEMORY_MIB"),
                       ("tcg_cache_mib", "LANE_VM_TCG_CACHE_MIB")):
        if data.get(field) is not None:
            values[key] = str(data[field])
    (STATE / "lane.env").write_text("\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()) + "\n")
    (STATE / "lane.env").chmod(0o600)


def command(*args: str, capture: bool = False, timeout: int = 900) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=capture, timeout=timeout)
    return result.stdout.strip() if capture else ""


def saved() -> dict:
    path = STATE / "machine.json"
    if not path.is_file():
        raise RuntimeError("No managed lane VM. Run lane/vm.sh up.")
    data = json.loads(path.read_text())
    if not isinstance(data.get("id"), str) or len(data["id"]) != 32 or any(c not in "0123456789abcdef" for c in data["id"]):
        raise RuntimeError("Invalid saved VM identity; refusing to act.")
    if data.get("container") != "bedrock-lane-" + data["id"]:
        raise RuntimeError("Saved container is not a managed lane name; refusing to act.")
    if data.get("network", data["container"]) != data["container"]:
        raise RuntimeError("Saved network is not the managed lane network; refusing to act.")
    info = json.loads(command("docker", "inspect", data["container"], capture=True))[0]
    if info.get("Config", {}).get("Labels", {}).get(LABEL) != data["id"]:
        raise RuntimeError("Container identity does not match; refusing to act.")
    return data


def destroy() -> None:
    data = saved()
    if data.get("ready"):
        # An owned VM can later acquire a production marker or foreign apps.
        # Once it has booted, deletion must pass the same remote refusal guard.
        subprocess.run(["bash", "-c", '. "$1/common.sh"', "lane", str(HERE.parent)],
                       env={**os.environ, "LANE_CONFIG": str(STATE / "lane.env")}, check=True, timeout=60)
    command("docker", "rm", "-f", data["container"])
    if data.get("network"):
        remove_network(data["network"], data["id"])
    # These are exactly the generated files owned by this provisioner.
    for name in ("machine.json", "lane.env", "ssh-key", "ssh-key.pub", "host-key", "host-key.pub", "known_hosts", "user-data", "meta-data"):
        (STATE / name).unlink(missing_ok=True)
    print("Disposable VM removed.")


def create_network(name: str, identity: str) -> str:
    for subnet in NETWORK_SUBNETS:
        try:
            command("docker", "network", "create", "--label", f"{LABEL}={identity}", "--subnet", subnet, name, capture=True)
            return name
        except subprocess.CalledProcessError as error:
            if "overlaps" not in (error.stderr or ""):
                raise
    raise RuntimeError(f"Every lane network range {NETWORK_SUBNETS[0]} through {NETWORK_SUBNETS[-1]} is taken.")


def remove_network(name: str, identity: str) -> None:
    # Only the exact network carrying this VM's label; one already gone is fine.
    owned = command("docker", "network", "ls", "--filter", f"label={LABEL}={identity}", "--format", "{{.Name}}", capture=True)
    if name in owned.split():
        command("docker", "network", "rm", name)


def wait_ready(data: dict) -> None:
    port = command("docker", "port", data["container"], "2222/tcp", capture=True).rsplit(":", 1)[1]
    # Docker may allocate a different loopback port after a container restart.
    host_public = (STATE / "host-key.pub").read_text().strip()
    (STATE / "known_hosts").write_text(f"[127.0.0.1]:{port} {host_public}\n")
    image_id = command("docker", "inspect", "--format", "{{.Image}}", data["container"], capture=True)
    image_sha = command("docker", "exec", data["container"], "/bin/cat", "/opt/ubuntu.sha256", capture=True).split()[0]
    data["provider_image"], data["guest_image_sha256"] = image_id, image_sha
    write_config(data, port)
    print("Waiting for the disposable Ubuntu guest (software virtualization can take several minutes)...", flush=True)
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(["ssh", "-i", str(STATE / "ssh-key"), "-p", port, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                                 "-o", "IdentityAgent=none", "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}", "-o", "StrictHostKeyChecking=yes",
                                 "-o", "ConnectTimeout=5", "root@127.0.0.1", "cloud-init status --wait >/dev/null && test -f /etc/bedrock-lane-id"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        except subprocess.TimeoutExpired:
            time.sleep(5)
            continue
        if result.returncode == 0:
            data["ready"] = True
            (STATE / "machine.json").write_text(json.dumps(data) + "\n")
            print(f"Ready. Configuration: {STATE / 'lane.env'}")
            return
        time.sleep(5)
    raise RuntimeError(f"VM did not become ready in 15 minutes. Inspect: docker logs {data['container']}. lane/vm.sh down removes only this VM.")


def prepare_provider(memory_mib: int) -> tuple[str | None, dict]:
    """Validate a creation policy before reset deletes the current provider."""
    command("docker", "info", "--format", "{{.OSType}}", capture=True)
    provider_image = os.environ.get("LANE_VM_PROVIDER_IMAGE")
    resources = {"guest_memory_mib": memory_mib, "tcg_cache_mib": TCG_CACHE_MIB}
    if provider_image:
        info = json.loads(command("docker", "image", "inspect", provider_image, capture=True))[0]
        if info.get("Config", {}).get("Labels", {}).get("io.bedrock.lane.provider") != "qemu-ubuntu-24.04":
            raise RuntimeError("LANE_VM_PROVIDER_IMAGE is not a previously built lane provider image.")
        provider_image = info["Id"]
        boot = command("docker", "run", "--rm", "--network", "none", "--read-only",
                       "--entrypoint", "/bin/cat", provider_image, "/opt/boot.sh", capture=True, timeout=30)
        if boot != (HERE / "boot.sh").read_text().strip():
            if "LANE_VM_MEMORY_MIB" in os.environ:
                raise RuntimeError("The retained provider image has a different boot policy and cannot apply "
                                   "LANE_VM_MEMORY_MIB. Rebuild the current provider image for a RAM override.")
            resources = {"guest_memory_mib": None, "tcg_cache_mib": None}
    return provider_image, resources


def up(prepared: tuple[str | None, dict] | None = None) -> None:
    memory_mib = requested_memory()
    if (STATE / "machine.json").exists():
        data = saved()
        if "LANE_VM_MEMORY_MIB" in os.environ and data.get("guest_memory_mib") != memory_mib:
            raise RuntimeError("An existing VM keeps its recorded resources; RAM cannot be changed by up. "
                               "Use a fresh LANE_VM_STATE directory with a current provider image.")
        print(f"Existing managed VM: {data['container']}", flush=True)
        if not data.get("network"):
            print("This VM runs on Docker's default bridge, so SSH stops answering once host setup installs "
                  "Docker in the guest. Recreate it with make lane-reset before proving m2.", flush=True)
        command("docker", "start", data["container"])
        wait_ready(data)
        return
    provider_image, resources = prepared if prepared is not None else prepare_provider(memory_mib)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    STATE.chmod(0o700)
    identity = secrets.token_hex(16)
    name = "bedrock-lane-" + identity
    for key in ("ssh-key", "host-key"):
        key_path = STATE / key
        if key_path.exists():
            raise RuntimeError(f"Unowned key exists: {key_path}. Use a fresh LANE_VM_STATE directory.")
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "bedrock disposable lane", "-f", str(key_path))
    authorized = (STATE / "ssh-key.pub").read_text().strip()
    host_private = (STATE / "host-key").read_text().rstrip()
    host_public = (STATE / "host-key.pub").read_text().strip()
    private_block = "\n".join("    " + line for line in host_private.splitlines())
    user_data = f"""#cloud-config
hostname: bedrock-lane
disable_root: false
ssh_pwauth: false
ssh_authorized_keys:
  - {authorized}
ssh_keys:
  ed25519_private: |
{private_block}
  ed25519_public: {host_public}
write_files:
  - path: /etc/bedrock-lane-id
    owner: root:root
    permissions: '0600'
    content: '{identity}'
runcmd:
  - [sh, -c, "systemctl enable ssh; systemctl restart ssh"]
"""
    (STATE / "user-data").write_text(user_data)
    (STATE / "user-data").chmod(0o600)
    (STATE / "meta-data").write_text(f"instance-id: {identity}\nlocal-hostname: bedrock-lane\n")
    if not provider_image:
        command("docker", "build", "--tag", IMAGE, str(HERE), timeout=1800)
        provider_image = IMAGE
    network = create_network(name, identity)
    create_args = ["docker", "create", "--name", name, "--label", f"{LABEL}={identity}",
                   "--network", network, "--publish", "127.0.0.1::2222"]
    if resources["guest_memory_mib"] is not None:
        create_args += ["--env", f"LANE_VM_MEMORY_MIB={resources['guest_memory_mib']}"]
    try:
        command(*create_args, provider_image)
    except (subprocess.SubprocessError, OSError):
        remove_network(network, identity)
        raise
    # Record ownership before any further Docker probe can fail. This receipt
    # is sufficient to identify and clean up the exact never-booted container.
    data = {"id": identity, "container": name, "network": network, "ready": False, **resources}
    (STATE / "machine.json").write_text(json.dumps(data) + "\n")
    image_id = command("docker", "inspect", "--format", "{{.Image}}", name, capture=True)
    image_sha = command("docker", "run", "--rm", "--entrypoint", "/bin/cat", image_id, "/opt/ubuntu.sha256", capture=True).split()[0]
    data.update(provider_image=image_id, guest_image_sha256=image_sha)
    (STATE / "machine.json").write_text(json.dumps(data) + "\n")
    command("docker", "cp", str(STATE / "user-data"), f"{name}:/work/user-data")
    command("docker", "cp", str(STATE / "meta-data"), f"{name}:/work/meta-data")
    command("docker", "start", name)
    wait_ready(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "status", "down", "reset"))
    args = parser.parse_args()
    try:
        if args.action == "up":
            up()
        elif args.action == "down":
            destroy()
        elif args.action == "reset":
            prepared = prepare_provider(requested_memory())
            destroy()
            up(prepared)
        else:
            data = saved()
            print(command("docker", "inspect", "--format", "{{.State.Status}}", data["container"], capture=True))
            print(f"Configuration: {STATE / 'lane.env'}")
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"Lane VM: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
