"""Real predecessor inputs and acknowledged-copy interruption, without host mutation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from molecule.config import Config

from scripts import qualification_production_predecessor as predecessor
from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV, resource_names
from scripts.qualification_group_case import case_configuration
from scripts.qualification_minio import image_reference

ROOT = Path(__file__).resolve().parents[2]
CALLBACKS = ROOT / "config/ansible/molecule/m3_8/callback_plugins"


def test_actual_m3_10_source_does_not_preinstall_either_bootstrap_dependency(
    tmp_path: Path,
) -> None:
    previous, variables = predecessor.prepare(tmp_path)
    assert predecessor.PREDECESSOR == "22147a64e9b39e7965201cf2d96e07aeaa6d3ca1"
    assert (previous / "config/ansible/molecule/m3_8/converge.yml").is_file()
    assert not (previous / "config/ansible/roles/base/files/configure-static-python").exists()
    assert not (previous / "config/ansible/roles/host_recovery/files/host-restore-gate").exists()
    assert json.loads(variables.read_text())["backup_repository"] == predecessor.REPOSITORY
    # Only fixture plumbing may differ. In particular every historical site
    # role, build script, dependency lock and artifact package stays exact.
    adapted = {predecessor.SCENARIO / name for name in predecessor.HARNESS_COPIES}
    adapted.add(predecessor.SCENARIO / "converge.yml")
    with tarfile.open(tmp_path / "production-predecessor.tar") as source:
        for member in source.getmembers():
            if member.isfile() and Path(member.name) not in adapted:
                original = source.extractfile(member)
                assert original is not None
                assert (previous / member.name).read_bytes() == original.read()
    scenario = yaml.safe_load((previous / predecessor.SCENARIO / "molecule.yml").read_text())
    host, archive = scenario["platforms"]
    assert "LDP_QUALIFICATION_HOST" in host["name"]
    assert "LDP_QUALIFICATION_ARCHIVE" in archive["name"]
    assert "LDP_QUALIFICATION_SSH_PORT" in host["published_ports"][0]
    assert "lowerduckpond.qualification.run" in host["labels"]
    assert "lowerduckpond.qualification.run" in archive["labels"]
    converge = yaml.safe_load((previous / predecessor.SCENARIO / "converge.yml").read_text())
    calls = {
        t["name"]: t.get("ansible.builtin.command", {}).get("argv", [])
        for t in converge[0]["tasks"]
    }
    assert (
        calls["Resolve the exact controller address used for operator transport"][-1]
        == "{{ groups['hosting_nodes'] | first }}"
    )
    assert (
        calls["Prepare the pinned private TLS archive fixture without removing objects"][-2]
        == "{{ groups['archive_fixture'] | first }}"
    )
    for name in predecessor.HARNESS_COPIES:
        assert (previous / predecessor.SCENARIO / name).read_bytes() == (
            ROOT / predecessor.SCENARIO / name
        ).read_bytes()
    # Preparation is exclusive: partial evidence cannot silently be replaced.
    with pytest.raises(FileExistsError):
        predecessor.prepare(tmp_path)


def test_bootstrap_admission_precedes_dependency_installation_and_existing_probe() -> None:
    role = ROOT / "config/ansible/roles/static_host_agent/tasks"
    tasks = yaml.safe_load((role / "main.yml").read_text())
    assert tasks[0]["ansible.builtin.import_tasks"].endswith("m3-11-production-guard.yml")
    assert tasks[1]["ansible.builtin.import_tasks"] == "bootstrap_dependencies.yml"
    assert "bootstrap" in tasks[1]["when"]
    dependencies = yaml.safe_load((role / "bootstrap_dependencies.yml").read_text())
    gate, admit, interpreter = dependencies[1:]
    assert gate["ansible.builtin.copy"]["dest"].endswith("/host-restore-gate")
    assert gate["ansible.builtin.copy"]["mode"] == "0755"
    assert admit["ansible.builtin.command"]["argv"][-1] == "--ordinary"
    assert "failed_when" not in admit  # Pending/unknown recovery cannot be relabelled successful.
    assert interpreter["ansible.builtin.copy"]["dest"].endswith("/configure-static-python")
    assert interpreter["ansible.builtin.copy"]["mode"] == "0700"
    assert all(task["ansible.builtin.copy"]["owner"] == "root" for task in [gate, interpreter])


@pytest.mark.parametrize("interrupt", [True, False])
def test_actual_ansible_callback_preserves_acknowledged_copy_before_resume(
    tmp_path: Path, interrupt: bool
) -> None:
    destination, marker = tmp_path / "copied", tmp_path / "departure"
    playbook = tmp_path / "play.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "name": "Install bootstrap-independent root recovery admission",
                            "ansible.builtin.copy": {
                                "content": "retained dependency\n",
                                "dest": str(destination),
                                "mode": "0600",
                            },
                        },
                        {
                            "name": "Assert the next boundary",
                            "ansible.builtin.assert": {"that": [True]},
                        },
                    ],
                }
            ]
        )
    )
    environment = {
        **os.environ,
        "ANSIBLE_CONFIG": str(ROOT / "config/ansible/ansible.cfg"),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-local"),
        "ANSIBLE_REMOTE_TEMP": str(tmp_path / "ansible-remote"),
        "ANSIBLE_CALLBACK_PLUGINS": str(CALLBACKS),
        "ANSIBLE_CALLBACKS_ENABLED": "ldp_bootstrap_departure",
    }
    if interrupt:
        environment["LDP_M3_11_TEST_DEPARTURE"] = str(marker)
    arguments = [
        str(Path(sys.executable).with_name("ansible-playbook")),
        "-i",
        "localhost,",
        str(playbook),
    ]
    first = subprocess.run(  # noqa: S603 - real local Ansible, only this temporary file
        arguments, env=environment, capture_output=True, text=True, check=False, timeout=30
    )
    assert first.returncode == (86 if interrupt else 0), first.stdout + first.stderr
    assert destination.read_text() == "retained dependency\n"
    inode = destination.stat().st_ino
    if interrupt:
        assert marker.read_text() == "acknowledged-first-dependency\n"
    environment.pop("LDP_M3_11_TEST_DEPARTURE", None)
    resumed = subprocess.run(  # noqa: S603 - same local copy, no original evidence replaced
        arguments, env=environment, capture_output=True, text=True, check=False, timeout=30
    )
    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert "changed=0" in resumed.stdout
    assert destination.stat().st_ino == inode


def test_only_rollout_baseline_uses_archived_source(tmp_path: Path) -> None:
    configuration, previous = case_configuration(
        tmp_path, tmp_path / "verify.yml", "production-rollout"
    )
    assert previous == tmp_path / "production-predecessor"
    assert configuration["provisioner"] == {
        "ansible_args": [
            "--extra-vars",
            "@" + str(tmp_path / "production-predecessor-variables.json"),
        ]
    }
    configuration, previous = case_configuration(tmp_path, tmp_path / "verify.yml", "core")
    assert previous is None
    assert "provisioner" not in configuration


def test_historical_harness_adapter_rejects_unexpected_arguments(tmp_path: Path) -> None:
    previous, _ = predecessor.prepare(tmp_path)
    # Re-applying an adapter to already changed harness bytes is not a fresh baseline.
    with pytest.raises(ValueError, match="argument changed"):
        predecessor.adapt_harness(previous)


def test_adapted_molecule_inventory_targets_the_exact_owned_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous, _ = predecessor.prepare(tmp_path)
    environment = resource_names(uuid.uuid7().hex)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("MOLECULE_EPHEMERAL_DIRECTORY", str(tmp_path / "molecule"))
    # Match phase(project=previous), including the historical Ansible roles root.
    monkeypatch.chdir(previous / "config/ansible")
    selected = Config(str(previous / predecessor.SCENARIO / "molecule.yml"))
    host, archive = selected.config_data["platforms"]
    assert host["name"] == environment[HOST_ENV]
    assert archive["name"] == environment[ARCHIVE_ENV]
    assert archive["image"] == image_reference()
    assert host["published_ports"] == ["0:22"]
    for platform in [host, archive]:
        assert platform["labels"]["lowerduckpond.qualification.run"] == environment[RUN_ENV]
    assert selected.config_data["ansible"]["cfg"]["defaults"]["roles_path"] == str(
        previous / "config/ansible/roles"
    )
