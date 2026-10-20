#!/usr/bin/env python3
"""Ensure cleanup cannot adopt a container by name or malformed saved data."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lane_vm", Path(__file__).parent / "vm/manage.py")
VM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VM)
IDENTITY = "1234567890abcdef1234567890abcdef"


class OwnedVM(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bedrock-lane-vm-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.state_patch = patch.object(VM, "STATE", self.work)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.data = {"id": IDENTITY, "container": "bedrock-lane-" + IDENTITY}
        self.save()

    def save(self):
        (self.work / "machine.json").write_text(json.dumps(self.data))

    def test_foreign_container_name_is_refused_before_docker(self):
        self.data["container"] = "production-database"
        self.save()
        with patch.object(VM, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "not a managed lane name"):
                VM.destroy()
            command.assert_not_called()

    def test_corrupted_identity_is_refused_before_docker(self):
        self.data["id"] = "not-an-identity"
        self.save()
        with patch.object(VM, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "Invalid saved VM identity"):
                VM.destroy()
            command.assert_not_called()

    def test_similarly_named_container_without_ownership_label_is_refused(self):
        with patch.object(VM, "command", return_value='[{"Config":{"Labels":{}}}]') as command:
            with self.assertRaisesRegex(RuntimeError, "identity does not match"):
                VM.destroy()
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[:2], ("docker", "inspect"))

    def test_exact_owned_never_booted_vm_can_be_cleaned_up(self):
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with patch.object(VM, "command", return_value=json.dumps(info)) as command:
            VM.destroy()
            self.assertEqual(command.call_args.args, ("docker", "rm", "-f", self.data["container"]))
            self.assertFalse((self.work / "machine.json").exists())

    def test_booted_vm_refusal_prevents_deletion(self):
        self.data["ready"] = True
        self.save()
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with (
            patch.object(VM, "command", return_value=json.dumps(info)) as command,
            patch.object(VM.subprocess, "run", side_effect=VM.subprocess.CalledProcessError(2, "guard")),
        ):
            with self.assertRaises(VM.subprocess.CalledProcessError):
                VM.destroy()
            self.assertEqual(command.call_count, 1)
            self.assertTrue((self.work / "machine.json").exists())

    def test_foreign_network_name_is_refused_before_docker(self):
        self.data["network"] = "bridge"
        self.save()
        with patch.object(VM, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "not the managed lane network"):
                VM.destroy()
            command.assert_not_called()

    def test_owned_network_is_removed_after_its_container(self):
        self.data["network"] = self.data["container"]
        self.save()
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]

        def fake_command(*args, **kwargs):
            if args[:3] == ("docker", "network", "ls"):
                self.assertIn(f"label={VM.LABEL}={IDENTITY}", args)
                return self.data["network"] + "\n"
            return json.dumps(info)

        with patch.object(VM, "command", side_effect=fake_command) as command:
            VM.destroy()
        calls = [call.args[:3] for call in command.call_args_list]
        self.assertEqual(calls[-3:], [("docker", "rm", "-f"), ("docker", "network", "ls"), ("docker", "network", "rm")])
        self.assertEqual(command.call_args.args[-1], self.data["network"])
        self.assertFalse((self.work / "machine.json").exists())

    def test_network_without_the_vm_label_is_left_alone(self):
        self.data["network"] = self.data["container"]
        self.save()
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]

        def fake_command(*args, **kwargs):
            return "" if args[:3] == ("docker", "network", "ls") else json.dumps(info)

        with patch.object(VM, "command", side_effect=fake_command) as command:
            VM.destroy()
        self.assertNotIn(("docker", "network", "rm"), [call.args[:3] for call in command.call_args_list])


    def test_invalid_memory_is_refused_before_docker_for_new_and_existing_vm(self):
        invalid = ("", "0", "0512", "001024", "511", "65537", "-1", "1g", "1024.0", " 1536", "1536\n",
                   "１０２４", "1; touch injected", "9" * 40)
        for existing in (False, True):
            for value in invalid:
                with self.subTest(existing=existing, value=value):
                    if existing:
                        self.save()
                    else:
                        (self.work / "machine.json").unlink(missing_ok=True)
                    with (
                        patch.dict(VM.os.environ, {"LANE_VM_MEMORY_MIB": value}, clear=True),
                        patch.object(VM, "command") as command,
                    ):
                        with self.assertRaisesRegex(RuntimeError, "LANE_VM_MEMORY_MIB must be an integer"):
                            VM.up()
                        command.assert_not_called()

    def test_invalid_reset_memory_does_not_destroy_existing_provider(self):
        with (
            patch.dict(VM.os.environ, {"LANE_VM_MEMORY_MIB": "invalid"}, clear=True),
            patch.object(VM.sys, "argv", ["manage.py", "reset"]),
            patch.object(VM, "destroy") as destroy,
            patch.object(VM, "command") as command,
            patch.object(VM.sys, "stderr", io.StringIO()),
        ):
            self.assertEqual(VM.main(), 2)
            destroy.assert_not_called()
            command.assert_not_called()

    def test_reset_incompatible_retained_provider_refuses_before_destroy(self):
        before = (self.work / "machine.json").read_bytes()
        info = [{"Id": "sha256:" + "a" * 64,
                 "Config": {"Labels": {"io.bedrock.lane.provider": "qemu-ubuntu-24.04"}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "legacy", "LANE_VM_MEMORY_MIB": "1024"}, clear=True),
            patch.object(VM.sys, "argv", ["manage.py", "reset"]),
            patch.object(VM, "destroy") as destroy,
            patch.object(VM, "command", side_effect=["linux", json.dumps(info), "legacy boot"]) as command,
            patch.object(VM.sys, "stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(VM.main(), 2)
            destroy.assert_not_called()
            self.assertIn("different boot policy", stderr.getvalue())
            self.assertEqual(command.call_count, 3)
            self.assertEqual((self.work / "machine.json").read_bytes(), before)

    def test_reset_unlabeled_retained_provider_refuses_before_destroy(self):
        before = (self.work / "machine.json").read_bytes()
        info = [{"Id": "sha256:" + "a" * 64, "Config": {"Labels": {}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "foreign", "LANE_VM_MEMORY_MIB": "1024"}, clear=True),
            patch.object(VM.sys, "argv", ["manage.py", "reset"]),
            patch.object(VM, "destroy") as destroy,
            patch.object(VM, "command", side_effect=["linux", json.dumps(info)]) as command,
            patch.object(VM.sys, "stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(VM.main(), 2)
            destroy.assert_not_called()
            self.assertIn("not a previously built lane provider image", stderr.getvalue())
            self.assertEqual(command.call_count, 2)
            self.assertEqual((self.work / "machine.json").read_bytes(), before)

    def test_reset_binds_retained_mutable_tag_once_before_destroy(self):
        self.data.update(guest_memory_mib=1536, tcg_cache_mib=128)
        self.save()
        image_id = "sha256:" + "a" * 64
        later_image_id = "sha256:" + "c" * 64
        created_image = []
        events = []

        def fake_command(*args, **kwargs):
            if args[:3] == ("docker", "image", "inspect"):
                # The tag points elsewhere once the old provider is deleted.
                resolved = later_image_id if any(event[0] == "destroy" for event in events) else image_id
                events.append(("image-inspected", resolved))
                return json.dumps([{"Id": resolved,
                                    "Config": {"Labels": {"io.bedrock.lane.provider": "qemu-ubuntu-24.04"}}}])
            if args[:2] == ("docker", "inspect"):
                if args[2] == "--format":
                    return created_image[0]
                return json.dumps([{"Config": {"Labels": {VM.LABEL: IDENTITY}}}])
            if args[:2] == ("docker", "run"):
                if args[-1] == "/opt/boot.sh":
                    events.append(("boot-inspected", args[-2]))
                    return (VM.HERE / "boot.sh").read_text().strip()
                return "b" * 64 + "  /opt/ubuntu.img"
            if args[:2] == ("docker", "rm"):
                events.append(("destroy", args[-1]))
            elif args[:2] == ("docker", "create"):
                created_image.append(args[-1])
                events.append(("create", args[-1]))
            elif args[0] == "ssh-keygen":
                key = Path(args[-1])
                key.write_text("test-only-key")
                key.with_suffix(".pub").write_text("ssh-ed25519 test-only-public")
            return ""

        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "mutable-provider-tag",
                                      "LANE_VM_MEMORY_MIB": "1024"}, clear=True),
            patch.object(VM.sys, "argv", ["manage.py", "reset"]),
            patch.object(VM.secrets, "token_hex", return_value="fedcba09876543210fedcba09876543210"),
            patch.object(VM, "command", side_effect=fake_command) as command,
            patch.object(VM, "wait_ready", side_effect=lambda data: VM.write_config(data, "5555")),
        ):
            self.assertEqual(VM.main(), 0)
        self.assertEqual(events, [("image-inspected", image_id), ("boot-inspected", image_id),
                                  ("destroy", self.data["container"]), ("create", image_id)])
        image_inspections = [call for call in command.call_args_list if call.args[:3] == ("docker", "image", "inspect")]
        self.assertEqual(len(image_inspections), 1)
        self.assertEqual(image_inspections[0].args[-1], "mutable-provider-tag")
        creates = [call.args for call in command.call_args_list if call.args[:2] == ("docker", "create")]
        self.assertEqual(creates[0][-3:], ("--env", "LANE_VM_MEMORY_MIB=1024", image_id))
        data = json.loads((self.work / "machine.json").read_text())
        self.assertNotEqual(data["id"], IDENTITY)
        self.assertEqual(data["provider_image"], image_id)
        self.assertEqual(data["guest_memory_mib"], 1024)
        self.assertEqual(data["tcg_cache_mib"], 128)
        self.assertEqual(self.config_values()["LANE_VM_MEMORY_MIB"], "1024")

    def test_existing_stopped_vm_starts_only_after_ownership_validation(self):
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}, "State": {"Status": "exited"}}]
        events = []

        def fake_command(*args, **kwargs):
            events.append(args)
            return json.dumps(info)

        with (
            patch.dict(VM.os.environ, {}, clear=True),
            patch.object(VM, "command", side_effect=fake_command),
            patch.object(VM, "wait_ready", side_effect=lambda data: events.append(("ready", data["container"]))),
        ):
            VM.up()
        self.assertEqual(events, [
            ("docker", "inspect", self.data["container"]),
            ("docker", "start", self.data["container"]),
            ("ready", self.data["container"]),
        ])

    def test_existing_vm_ignores_new_defaults_and_preserves_recorded_resources(self):
        self.data.update(guest_memory_mib=1536, tcg_cache_mib=128)
        self.save()
        before = (self.work / "machine.json").read_bytes()
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "unrelated-foreign-image"}, clear=True),
            patch.object(VM, "command", return_value=json.dumps(info)) as command,
            patch.object(VM, "wait_ready") as ready,
        ):
            VM.up()
            self.assertEqual([call.args for call in command.call_args_list], [
                ("docker", "inspect", self.data["container"]),
                ("docker", "start", self.data["container"]),
            ])
            ready.assert_called_once_with(self.data)
            self.assertEqual((self.work / "machine.json").read_bytes(), before)

    def test_existing_vm_accepts_same_explicit_memory_without_reconfiguration(self):
        self.data.update(guest_memory_mib=1536, tcg_cache_mib=128)
        self.save()
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_MEMORY_MIB": "1536"}, clear=True),
            patch.object(VM, "command", return_value=json.dumps(info)) as command,
            patch.object(VM, "wait_ready") as ready,
        ):
            VM.up()
            self.assertEqual(command.call_count, 2)
            ready.assert_called_once_with(self.data)

    def test_existing_vm_refuses_different_or_unrecorded_memory(self):
        for recorded in (1536, None):
            with self.subTest(recorded=recorded):
                self.data["guest_memory_mib"] = recorded
                self.save()
                info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
                with (
                    patch.dict(VM.os.environ, {"LANE_VM_MEMORY_MIB": "1024"}, clear=True),
                    patch.object(VM, "command", return_value=json.dumps(info)) as command,
                    patch.object(VM, "wait_ready") as ready,
                ):
                    with self.assertRaisesRegex(RuntimeError, "existing VM keeps its recorded resources"):
                        VM.up()
                    command.assert_called_once_with("docker", "inspect", self.data["container"], capture=True)
                    ready.assert_not_called()

    def test_legacy_existing_vm_keeps_identity_and_unknown_resource_fields(self):
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with (
            patch.dict(VM.os.environ, {}, clear=True),
            patch.object(VM, "command", return_value=json.dumps(info)),
            patch.object(VM, "wait_ready") as ready,
        ):
            VM.up()
            ready.assert_called_once_with(self.data)
        self.data.update(provider_image="sha256:" + "a" * 64, guest_image_sha256="b" * 64)
        VM.write_config(self.data, "5555")
        values = self.config_values()
        self.assertEqual(values["LANE_ID"], IDENTITY)
        self.assertNotIn("LANE_VM_MEMORY_MIB", values)
        self.assertNotIn("LANE_VM_TCG_CACHE_MIB", values)

    def test_exported_legacy_config_can_reuse_existing_provider(self):
        self.data.update(provider_image="sha256:" + "a" * 64, guest_image_sha256="b" * 64)
        self.save()
        VM.write_config(self.data, "5555")
        info = [{"Config": {"Labels": {VM.LABEL: IDENTITY}}}]
        with (
            patch.dict(VM.os.environ, self.config_values(), clear=True),
            patch.object(VM, "command", return_value=json.dumps(info)) as command,
            patch.object(VM, "wait_ready") as ready,
        ):
            VM.up()
            self.assertEqual([call.args for call in command.call_args_list], [
                ("docker", "inspect", self.data["container"]),
                ("docker", "start", self.data["container"]),
            ])
            ready.assert_called_once_with(self.data)

    def test_created_provider_keeps_ownership_if_image_probe_fails(self):
        (self.work / "machine.json").unlink()

        def fake_command(*args, **kwargs):
            if args[0] == "ssh-keygen":
                key = Path(args[-1])
                key.write_text("test-only-key")
                key.with_suffix(".pub").write_text("ssh-ed25519 test-only-public")
            elif args[:2] == ("docker", "inspect"):
                raise VM.subprocess.CalledProcessError(1, args)
            return ""

        with (
            patch.dict(VM.os.environ, {}, clear=True),
            patch.object(VM.secrets, "token_hex", return_value=IDENTITY),
            patch.object(VM, "command", side_effect=fake_command),
        ):
            with self.assertRaises(VM.subprocess.CalledProcessError):
                VM.up(prepared=(VM.IMAGE, {"guest_memory_mib": 3072, "tcg_cache_mib": 128}))
        self.assertTrue((self.work / "machine.json").is_file(), "created provider lost its cleanup ownership receipt")
        data = json.loads((self.work / "machine.json").read_text())
        self.assertEqual(data["id"], IDENTITY)
        self.assertEqual(data["container"], "bedrock-lane-" + IDENTITY)
        self.assertFalse(data["ready"])

    def test_new_provider_runs_on_its_own_labelled_network_past_taken_ranges(self):
        (self.work / "machine.json").unlink()
        name = "bedrock-lane-" + IDENTITY
        tried = []

        def fake_command(*args, **kwargs):
            if args[0] == "ssh-keygen":
                key = Path(args[-1])
                key.write_text("test-only-key")
                key.with_suffix(".pub").write_text("ssh-ed25519 test-only-public")
            elif args[:3] == ("docker", "network", "create"):
                tried.append(args[args.index("--subnet") + 1])
                if len(tried) == 1:
                    raise VM.subprocess.CalledProcessError(
                        1, args, stderr="Error response from daemon: invalid pool request: Pool overlaps with other one on this address space")
            elif args[:2] == ("docker", "inspect"):
                return "sha256:" + "a" * 64
            elif args[:2] == ("docker", "run"):
                return "b" * 64 + "  /opt/ubuntu.img"
            return ""

        with (
            patch.dict(VM.os.environ, {}, clear=True),
            patch.object(VM.secrets, "token_hex", return_value=IDENTITY),
            patch.object(VM, "command", side_effect=fake_command) as command,
            patch.object(VM, "wait_ready", side_effect=lambda data: VM.write_config(data, "5555")),
        ):
            VM.up(prepared=(VM.IMAGE, {"guest_memory_mib": 3072, "tcg_cache_mib": 128}))
        self.assertEqual(tried, ["10.213.1.0/24", "10.213.2.0/24"])
        create_network = [call.args for call in command.call_args_list if call.args[:3] == ("docker", "network", "create")][-1]
        self.assertEqual(create_network[-1], name)
        self.assertIn(f"{VM.LABEL}={IDENTITY}", create_network)
        create = next(call.args for call in command.call_args_list if call.args[:2] == ("docker", "create"))
        self.assertEqual(create[create.index("--network") + 1], name)
        # The guest's own Docker takes 172.17.0.0/16 and 192.168.0.0/16 by
        # default, and QEMU's user network 10.0.2.0/24.
        for subnet in VM.NETWORK_SUBNETS:
            self.assertTrue(subnet.startswith("10.213."), subnet)
        self.assertEqual(json.loads((self.work / "machine.json").read_text())["network"], name)

    def test_failed_create_removes_the_network_it_made(self):
        (self.work / "machine.json").unlink()

        def fake_command(*args, **kwargs):
            if args[0] == "ssh-keygen":
                key = Path(args[-1])
                key.write_text("test-only-key")
                key.with_suffix(".pub").write_text("ssh-ed25519 test-only-public")
            elif args[:2] == ("docker", "create"):
                raise VM.subprocess.CalledProcessError(1, args)
            elif args[:3] == ("docker", "network", "ls"):
                return "bedrock-lane-" + IDENTITY
            return ""

        with (
            patch.dict(VM.os.environ, {}, clear=True),
            patch.object(VM.secrets, "token_hex", return_value=IDENTITY),
            patch.object(VM, "command", side_effect=fake_command) as command,
        ):
            with self.assertRaises(VM.subprocess.CalledProcessError):
                VM.up(prepared=(VM.IMAGE, {"guest_memory_mib": 3072, "tcg_cache_mib": 128}))
        self.assertEqual(command.call_args.args, ("docker", "network", "rm", "bedrock-lane-" + IDENTITY))
        self.assertFalse((self.work / "machine.json").exists())

    def config_values(self):
        return {line.split("=", 1)[0]: shlex.split(line.split("=", 1)[1])[0]
                for line in (self.work / "lane.env").read_text().splitlines()}

    def provision(self, environment, retained_boot=None):
        (self.work / "machine.json").unlink()
        image_id = "sha256:" + "a" * 64

        def fake_command(*args, **kwargs):
            if args[0] == "ssh-keygen":
                key = Path(args[-1])
                key.write_text("test-only-key")
                key.with_suffix(".pub").write_text("ssh-ed25519 test-only-public")
            elif args[:3] == ("docker", "image", "inspect"):
                return json.dumps([{"Id": image_id, "Config": {"Labels": {"io.bedrock.lane.provider": "qemu-ubuntu-24.04"}}}])
            elif args[:2] == ("docker", "inspect"):
                return image_id
            elif args[:2] == ("docker", "run"):
                if args[-1] == "/opt/boot.sh":
                    return retained_boot
                return "b" * 64 + "  /opt/ubuntu.img"
            return ""

        with (
            patch.dict(VM.os.environ, environment, clear=True),
            patch.object(VM.secrets, "token_hex", return_value=IDENTITY),
            patch.object(VM, "command", side_effect=fake_command) as command,
            patch.object(VM, "wait_ready", side_effect=lambda data: VM.write_config(data, "5555")),
        ):
            VM.up()
        return command, json.loads((self.work / "machine.json").read_text())

    def test_new_provider_flags_and_recorded_resource_values_are_consistent(self):
        for chosen in (None, "1536", "512", "65536"):
            with self.subTest(chosen=chosen):
                environment = {} if chosen is None else {"LANE_VM_MEMORY_MIB": chosen}
                command, data = self.provision(environment)
                expected = 3072 if chosen is None else int(chosen)
                create = next(call.args for call in command.call_args_list if call.args[:2] == ("docker", "create"))
                self.assertEqual(create[-3:], ("--env", f"LANE_VM_MEMORY_MIB={expected}", VM.IMAGE))
                self.assertEqual(data["guest_memory_mib"], expected)
                self.assertEqual(data["tcg_cache_mib"], 128)
                values = self.config_values()
                self.assertEqual(values["LANE_VM_MEMORY_MIB"], str(expected))
                self.assertEqual(values["LANE_VM_TCG_CACHE_MIB"], "128")
                self.assertEqual(values["LANE_ID"], data["id"])
                self.assertEqual(values["LANE_VM_IMAGE"], data["provider_image"])
                self.assertEqual((self.work / "lane.env").stat().st_mode & 0o777, 0o600)
                for key in ("ssh-key", "ssh-key.pub", "host-key", "host-key.pub", "user-data", "meta-data", "lane.env"):
                    (self.work / key).unlink()

    def test_retained_current_provider_is_inspected_by_id_and_accepts_ram_override(self):
        command, data = self.provision({"LANE_VM_PROVIDER_IMAGE": "mutable-provider-tag", "LANE_VM_MEMORY_MIB": "1024"},
                                       (VM.HERE / "boot.sh").read_text().strip())
        image_id = "sha256:" + "a" * 64
        command.assert_any_call("docker", "run", "--rm", "--network", "none", "--read-only",
                                "--entrypoint", "/bin/cat", image_id, "/opt/boot.sh", capture=True, timeout=30)
        create = next(call.args for call in command.call_args_list if call.args[:2] == ("docker", "create"))
        self.assertEqual(create[-3:], ("--env", "LANE_VM_MEMORY_MIB=1024", image_id))
        self.assertEqual(data["guest_memory_mib"], 1024)
        self.assertEqual(data["tcg_cache_mib"], 128)
        self.assertFalse(any(call.args[:2] == ("docker", "build") for call in command.call_args_list))

    def test_retained_legacy_provider_without_override_keeps_unknown_resources(self):
        command, data = self.provision({"LANE_VM_PROVIDER_IMAGE": "legacy-provider"}, "#!/bin/sh\nexec qemu -m 3072")
        create = next(call.args for call in command.call_args_list if call.args[:2] == ("docker", "create"))
        self.assertNotIn("--env", create)
        self.assertEqual(create[-1], "sha256:" + "a" * 64)
        self.assertIsNone(data["guest_memory_mib"])
        self.assertIsNone(data["tcg_cache_mib"])
        self.assertNotIn("LANE_VM_MEMORY_MIB", self.config_values())
        self.assertNotIn("LANE_VM_TCG_CACHE_MIB", self.config_values())

    def test_unlabeled_retained_provider_is_refused_before_boot_inspection(self):
        (self.work / "machine.json").unlink()
        info = [{"Id": "sha256:" + "a" * 64, "Config": {"Labels": {}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "foreign-provider"}, clear=True),
            patch.object(VM, "command", side_effect=["linux", json.dumps(info)]) as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "not a previously built lane provider image"):
                VM.up()
            self.assertEqual(command.call_count, 2)
            self.assertFalse((self.work / "ssh-key").exists())
            self.assertFalse((self.work / "machine.json").exists())

    def test_retained_legacy_provider_refuses_override_before_create_or_key_generation(self):
        (self.work / "machine.json").unlink()
        info = [{"Id": "sha256:" + "a" * 64, "Config": {"Labels": {"io.bedrock.lane.provider": "qemu-ubuntu-24.04"}}}]
        with (
            patch.dict(VM.os.environ, {"LANE_VM_PROVIDER_IMAGE": "legacy", "LANE_VM_MEMORY_MIB": "1024"}, clear=True),
            patch.object(VM, "command", side_effect=["linux", json.dumps(info), "legacy boot"]) as command,
        ):
            with self.assertRaisesRegex(RuntimeError, "different boot policy"):
                VM.up()
            self.assertEqual(command.call_count, 3)
            self.assertFalse((self.work / "ssh-key").exists())
            self.assertFalse((self.work / "machine.json").exists())


class BootResources(unittest.TestCase):
    """Run the staged boot script with fake QEMU and real argument parsing."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bedrock-lane-boot-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.disk = self.work / "work"
        self.disk.mkdir()
        (self.disk / "disk.qcow2").touch()
        self.arch = self.work / "guest-arch"
        self.args = self.work / "qemu-args.json"
        self.bin = self.work / "bin"
        self.bin.mkdir()
        for name in ("qemu-system-aarch64", "qemu-system-x86_64"):
            executable = self.bin / name
            executable.write_text("#!/usr/bin/env python3\n"
                                  "import json, os, pathlib, sys\n"
                                  "pathlib.Path(os.environ['LANE_TEST_QEMU_ARGS']).write_text(json.dumps(sys.argv))\n")
            executable.chmod(0o755)
        self.boot = self.work / "boot.sh"
        # Only fixture filesystem paths change; the actual QEMU invocation stays intact.
        source = (Path(__file__).parent / "vm/boot.sh").read_text()
        self.boot.write_text(source.replace("/work", str(self.disk)).replace("/opt/guest-arch", str(self.arch)))

    def run_boot(self, architecture, memory=None, include_memory=True):
        self.arch.write_text(architecture)
        self.args.unlink(missing_ok=True)
        environment = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                       "LANE_TEST_QEMU_ARGS": str(self.args)}
        environment.pop("LANE_VM_MEMORY_MIB", None)
        if include_memory:
            environment["LANE_VM_MEMORY_MIB"] = memory
        return subprocess.run(["sh", str(self.boot)], env=environment, capture_output=True, text=True, timeout=10)

    def test_actual_boot_arguments_use_configured_or_default_memory_and_cache_cap(self):
        for architecture in ("amd64", "arm64"):
            for memory in (None, "1536", "1024", "512", "65536"):
                with self.subTest(architecture=architecture, memory=memory):
                    result = self.run_boot(architecture, memory, include_memory=memory is not None)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = json.loads(self.args.read_text())
                    expected = "3072" if memory is None else memory
                    self.assertEqual(args[args.index("-m") + 1], expected)
                    self.assertEqual(args[args.index("-accel") + 1], "tcg,thread=multi,tb-size=128")
                    expected_binary = "qemu-system-x86_64" if architecture == "amd64" else "qemu-system-aarch64"
                    self.assertEqual(Path(args[0]).name, expected_binary)

    def test_invalid_memory_never_starts_qemu(self):
        for memory in ("", "0", "0512", "001024", "511", "65537", "-1", "1g", "1024.0", " 1024", "1024\n",
                       "１０２４", "1; touch injected", "9" * 40):
            with self.subTest(memory=memory):
                result = self.run_boot("amd64", memory)
                self.assertEqual(result.returncode, 2)
                self.assertIn("LANE_VM_MEMORY_MIB", result.stderr)
                self.assertFalse(self.args.exists())


if __name__ == "__main__":
    unittest.main()
