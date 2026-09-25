"""Read-only production migration gates observe real private files and bounded children."""

from __future__ import annotations

import copy
import json
import os
import shlex
import sys
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity
from lowerduckpond_static_host_agent.capacity import HostCapacityLimits

from scripts import m3_11_production_preflight as preflight
from scripts import m3_11_production_probe as probe
from scripts.check_m3_10_provider import GateError, PolicyClient
from scripts.check_m3_11_backup_policy import REVIEWED_RULE
from scripts.check_m3_11_backup_policy import check as check_backup_policy

from .test_m3_10_production_gate import Storage

REGION = "nyc3"
BUCKET = "fixture-backup"
LOCATOR = f"s3:https://{REGION}.digitaloceanspaces.com/{BUCKET}/backups/{probe.NODE}"
ARTIFACT = "a" * 64
SOURCE = "b" * 40
TARGET = "c" * 64
CONFIG_ID = "d" * 64
CANARY = "fixture-credential-never-printed-7c16ee9f"
ORIGINAL = f"{ARTIFACT} {SOURCE} {TARGET}\n"
CONFIG = {"version": 2, "id": CONFIG_ID}
PRIVATE_FILE_MODE = 0o600


def write(path: Path, raw: bytes, mode: int = 0o400) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(mode)


def backup_environment() -> bytes:
    return (
        "\n".join(
            name + "=" + shlex.quote(value)
            for name, value in {
                "AWS_ACCESS_KEY_ID": "fixture-access",
                "AWS_SECRET_ACCESS_KEY": CANARY,
                "AWS_DEFAULT_REGION": REGION,
                "RESTIC_PASSWORD": CANARY,
                "RESTIC_REPOSITORY": LOCATOR,
                "LOWERDUCKPOND_BACKUP_NODE_NAME": probe.NODE,
            }.items()
        ).encode()
        + b"\n"
    )


def child(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(probe, "RESTIC", (sys.executable, "-I", "-c", code))


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "host"
    root.mkdir(mode=0o700)
    for name in ("completion", "config", "artifact", "static", "sites", "cache"):
        (root / name).mkdir(mode=0o700)
    (root / "artifact" / ARTIFACT).mkdir(mode=0o555)
    for constant, path in {
        "COMPLETION": root / "completion/m3-10",
        "TRANSACTION": root / "completion/m3-11",
        "SELECTION": root / "artifact/current",
        "BACKUP": root / "config/backup.env",
        "PUBLICATION": root / "config/static-publication.json",
    }.items():
        monkeypatch.setattr(probe, constant, path)
    monkeypatch.setattr(
        probe,
        "CAPACITY_PATHS",
        tuple(root / name for name in ("static", "sites", "cache", "artifact")),
    )
    monkeypatch.setattr(
        os,
        "fstatvfs",
        lambda _: os.statvfs_result(
            (
                4096,
                4096,
                20_000_000,
                10_000_000,
                10_000_000,
                2_000_000,
                1_000_000,
                1_000_000,
                0,
                255,
            )
        ),
    )
    write(probe.COMPLETION, ORIGINAL.encode())
    write(probe.BACKUP, backup_environment(), 0o600)
    write(
        probe.PUBLICATION,
        b'{"format":"lowerduckpond-static-publication-gate-v1","static_publication_enabled":false}\n',
    )
    probe.SELECTION.symlink_to(probe.SELECTION.parent / ARTIFACT, target_is_directory=True)
    child(
        monkeypatch,
        "import json, os; assert 'UNRELATED_SECRET' not in os.environ; "
        + f"print({json.dumps(CONFIG)!r})",
    )
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-reach-restic")
    return root


def snapshot(root: Path) -> dict[str, tuple[int, int, int, bytes | str | None]]:
    return {
        str(path.relative_to(root)): (
            path.lstat().st_ino,
            path.lstat().st_mtime_ns,
            path.lstat().st_mode,
            str(path.readlink())
            if path.is_symlink()
            else path.read_bytes()
            if path.is_file()
            else None,
        )
        for path in root.rglob("*")
    }


def observe() -> dict[str, object]:
    return probe.observe(REGION, BUCKET, owner=os.geteuid())


def test_predecessor_probe_is_readonly_and_contains_no_credential_values(host: Path) -> None:
    before = snapshot(host)
    result = observe()
    assert result["predecessor"] == ORIGINAL
    assert result["repository_config_id"] == CONFIG_ID
    assert result["repository_locator"] == LOCATOR
    assert result["repository_node"] == probe.NODE
    assert CANARY not in json.dumps(result)
    assert snapshot(host) == before
    assert not probe.TRANSACTION.exists()


def test_free_space_gate_preserves_existing_capacity_contract() -> None:
    limits = HostCapacityLimits()
    assert (
        limits.minimum_available_bytes,
        limits.minimum_available_inodes,
        limits.minimum_available_percent,
    ) == (probe.MINIMUM_BYTES, probe.MINIMUM_INODES, probe.MINIMUM_PERCENT)
    assert probe.RESTIC == ("/usr/bin/restic", "--no-cache", "--no-lock", "cat", "config")


@pytest.mark.parametrize(
    "fault", ["missing", "truncated", "mode", "hardlink", "symlink", "fifo", "parent-mode"]
)
def test_completion_requires_original_safe_bytes(host: Path, fault: str) -> None:
    if fault == "mode":
        probe.COMPLETION.chmod(0o600)
    elif fault == "parent-mode":
        probe.COMPLETION.parent.chmod(0o755)
    elif fault == "truncated":
        write(probe.COMPLETION, ORIGINAL.rstrip().encode())
    elif fault == "hardlink":
        os.link(probe.COMPLETION, host / "original-copy")
    else:
        probe.COMPLETION.unlink()
        if fault == "symlink":
            target = host / "original-copy"
            write(target, ORIGINAL.encode())
            probe.COMPLETION.symlink_to(target)
        elif fault == "fifo":
            os.mkfifo(probe.COMPLETION, 0o400)
    before = snapshot(host)
    with pytest.raises((ValueError, OSError)):
        observe()
    assert snapshot(host) == before


@pytest.mark.parametrize("kind", ["directory", "file", "dangling-link"])
def test_pending_or_completed_migration_is_never_a_fresh_predecessor(host: Path, kind: str) -> None:
    if kind == "directory":
        probe.TRANSACTION.mkdir(mode=0o700)
    elif kind == "file":
        write(probe.TRANSACTION, b"original authority")
    else:
        probe.TRANSACTION.symlink_to(host / "missing")
    before = snapshot(host)
    with pytest.raises(ValueError, match="original resume"):
        observe()
    assert snapshot(host) == before


@pytest.mark.parametrize("value", [True, 0, "false", None])
def test_only_boolean_false_means_disabled_publication(host: Path, value: object) -> None:
    write(
        probe.PUBLICATION,
        json.dumps(
            {
                "format": "lowerduckpond-static-publication-gate-v1",
                "static_publication_enabled": value,
            }
        ).encode(),
    )
    before = snapshot(host)
    with pytest.raises(ValueError, match="disabled"):
        observe()
    assert snapshot(host) == before


@pytest.mark.parametrize(
    "replacement",
    [
        b"RESTIC_REPOSITORY=s3:https://other.example/backup\n",
        b"AWS_DEFAULT_REGION=us-east-1\n",
        b"LOWERDUCKPOND_BACKUP_NODE_NAME=other\n",
        b"LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED=true\n",
        b"LOWERDUCKPOND_AUDIT_ROTATION_ENABLED=true\n",
        b"RESTIC_PASSWORD=second\n",
        b"UNKNOWN=unreviewed\n",
        b"export OTHER=value\n",
    ],
)
def test_ambiguous_or_unexpected_backup_environment_is_not_executed(
    host: Path, replacement: bytes
) -> None:
    write(probe.BACKUP, backup_environment() + replacement, 0o600)
    before = snapshot(host)
    with pytest.raises(ValueError):
        observe()
    assert snapshot(host) == before


def test_shell_substitutions_remain_literal_data(tmp_path: Path) -> None:
    marker = tmp_path / "not-executed"
    raw = backup_environment().replace(CANARY.encode(), f"'$(touch {marker})'".encode())
    env = probe.environment(raw, region=REGION, locator=LOCATOR)
    assert env["RESTIC_PASSWORD"] == f"$(touch {marker})"
    assert not marker.exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"version":2,"id":"short"}',
        b'{"version":true,"id":"' + CONFIG_ID.encode() + b'"}',
        b'{"version":2,"id":"a","id":"b"}',
        b"x" * (probe.MAX_BYTES + 1),
    ],
)
def test_invalid_or_unbounded_repository_output_is_not_a_binding(
    host: Path, monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    child(monkeypatch, f"import sys; sys.stdout.buffer.write({raw!r})")
    before = snapshot(host)
    with pytest.raises(ValueError):
        observe()
    assert snapshot(host) == before


def test_failed_repository_child_does_not_emit_credentials(
    host: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    child(
        monkeypatch,
        "import os,sys; print(os.environ['RESTIC_PASSWORD'],file=sys.stderr); sys.exit(1)",
    )
    with pytest.raises(ValueError, match="observation failed"):
        observe()
    output = capfd.readouterr()
    assert CANARY not in output.out + output.err


def test_repository_child_is_killed_at_original_deadline(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child(monkeypatch, "import time; time.sleep(60)")
    monkeypatch.setattr(probe, "METADATA_SECONDS", 0.05)
    with pytest.raises(ValueError, match="deadline"):
        observe()


@pytest.mark.parametrize("field,value", [(4, 1), (7, 1), (2, 200_000_000), (5, 20_000_000)])
def test_capacity_rejects_either_absolute_or_percentage_reserve(
    host: Path, monkeypatch: pytest.MonkeyPatch, field: int, value: int
) -> None:
    values = [
        4096,
        4096,
        20_000_000,
        10_000_000,
        10_000_000,
        2_000_000,
        1_000_000,
        1_000_000,
        0,
        255,
    ]
    values[field] = value
    monkeypatch.setattr(os, "fstatvfs", lambda _: os.statvfs_result(values))
    before = snapshot(host)
    with pytest.raises(ValueError, match="reserve"):
        observe()
    assert snapshot(host) == before


def test_configuration_change_during_remote_read_invalidates_preflight(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = probe.repository_config

    def changed(environment: dict[str, str]) -> bytes:
        raw = original(environment)
        write(probe.BACKUP, backup_environment().replace(CANARY.encode(), b"changed-key"), 0o600)
        return raw

    monkeypatch.setattr(probe, "repository_config", changed)
    with pytest.raises(ValueError, match="changed during"):
        observe()


@pytest.fixture
def controller(
    host: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, list[tuple[str, list[str], bytes]]]:
    observed = observe()
    directory = tmp_path / "controller"
    directory.mkdir(mode=0o700)
    for key, value in {
        "SPACES_REGION": REGION,
        "SPACES_BACKUP_BUCKET": BUCKET,
        "ANSIBLE_PRIVATE_KEY_FILE": "/private/key",
        "PRODUCTION_ORIGIN_IPV4": "203.0.113.10",
    }.items():
        monkeypatch.setenv(key, value)
    calls: list[tuple[str, list[str], bytes]] = []

    def run(_directory: Path, name: str, command: list[str], *, program: bytes = b"") -> bytes:
        calls.append((name, command, program))
        if name.startswith("predecessor-"):
            return json.dumps(observed).encode()
        if name == "archive-authority":
            return b'{"archives":[]}\n'
        return b""

    monkeypatch.setattr(preflight, "run", run)
    monkeypatch.setattr(
        preflight,
        "git",
        lambda _root, *args: ("e" * 40 + "\n").encode() if args == ("rev-parse", "HEAD") else b"",
    )
    monkeypatch.setattr(preflight, "storage_target_digest", lambda: TARGET)
    return directory, calls


def test_controller_composes_existing_predecessor_and_provider_gates(
    controller: tuple[Path, list[tuple[str, list[str], bytes]]],
) -> None:
    directory, calls = controller
    receipt = preflight.preflight(directory)
    assert (
        receipt["repository_binding"]
        == RepositoryIdentity(CONFIG_ID, probe.NODE, LOCATOR).binding()["value"]
    )
    assert cast(dict[str, object], receipt["observation"])["predecessor"] == ORIGINAL
    assert [call[0] for call in calls] == [
        "operator",
        "dark-host",
        "predecessor-before",
        "archive-authority",
        "provider",
        "firewall",
        "backup-policy",
        "predecessor-after",
    ]
    assert f"{ARTIFACT} upgrade-host {SOURCE}" in calls[3][1][-1]
    assert calls[3][2] == (preflight.ROOT / "scripts/m3-10-completed-host-preflight").read_bytes()
    assert "--allow-existing-archives" in calls[4][1]
    assert json.loads((directory / "preflight.json").read_bytes()) == receipt
    assert (directory / "preflight.json").stat().st_mode & 0o777 == PRIVATE_FILE_MODE
    assert not any(
        "convergence-state" in item or "ansible-playbook" in item
        for _, command, _ in calls
        for item in command
    )


def test_controller_checks_original_storage_target_before_host_or_provider_steps(
    controller: tuple[Path, list[tuple[str, list[str], bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, calls = controller
    monkeypatch.setattr(preflight, "storage_target_digest", lambda: "f" * 64)
    with pytest.raises(ValueError, match="storage target"):
        preflight.preflight(directory)
    assert [call[0] for call in calls] == ["operator", "dark-host", "predecessor-before"]
    assert not (directory / "preflight.json").exists()


def test_failed_step_retains_private_output_without_printing_it(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ValueError, match="step failed"):
        preflight.run(
            tmp_path,
            "fixture",
            [
                sys.executable,
                "-I",
                "-c",
                f"import sys; print({CANARY!r}); print({CANARY!r},file=sys.stderr); sys.exit(1)",
            ],
        )
    assert CANARY.encode() in (tmp_path / "fixture.stderr").read_bytes()
    assert (tmp_path / "fixture.stdout").stat().st_mode & 0o777 == PRIVATE_FILE_MODE
    output = capfd.readouterr()
    assert CANARY not in output.out + output.err


def test_provider_failure_cannot_leave_a_passed_receipt(
    controller: tuple[Path, list[tuple[str, list[str], bytes]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, calls = controller
    original = preflight.run

    def fail(directory: Path, name: str, command: list[str], *, program: bytes = b"") -> bytes:
        if name == "provider":
            raise ValueError("provider unavailable")
        return original(directory, name, command, program=program)

    monkeypatch.setattr(preflight, "run", fail)
    with pytest.raises(ValueError, match="provider"):
        preflight.preflight(directory)
    assert not (directory / "preflight.json").exists()
    assert "predecessor-after" not in [call[0] for call in calls]


def test_backup_policy_reads_do_not_require_or_modify_an_empty_repository() -> None:
    storage = Storage()
    storage.responses["get_bucket_lifecycle_configuration"] = {
        "Rules": [copy.deepcopy(REVIEWED_RULE)]
    }
    storage.responses["list_objects_v2"] = {"Contents": [{"Key": "backups/node/config"}]}
    check_backup_policy(cast(PolicyClient, storage), bucket="archive-fixture")
    assert storage.calls == [
        "get_bucket_acl",
        "get_bucket_policy",
        "get_bucket_lifecycle_configuration",
        "get_bucket_versioning",
    ]


@pytest.mark.parametrize(
    ("operation", "response"),
    [
        ("get_bucket_acl", {"Owner": {"ID": "owner"}, "Grants": []}),
        ("get_bucket_policy", {"Policy": "{}"}),
        ("get_bucket_policy", "AccessDenied"),
        ("get_bucket_lifecycle_configuration", {"Rules": [{"Status": "Enabled"}]}),
        ("get_bucket_versioning", {"Status": "Suspended"}),
        ("get_bucket_versioning", {}),
    ],
)
def test_backup_policy_rejects_loss_of_privacy_or_indefinite_retention(
    operation: str, response: object
) -> None:
    storage = Storage()
    storage.responses["get_bucket_lifecycle_configuration"] = {
        "Rules": [copy.deepcopy(REVIEWED_RULE)]
    }
    storage.responses[operation] = response
    with pytest.raises(GateError):
        check_backup_policy(cast(PolicyClient, storage), bucket="archive-fixture")


@pytest.mark.parametrize("filter_prefix", [False, True])
def test_reviewed_backup_lifecycle_never_expires_current_repository_objects(
    *, filter_prefix: bool
) -> None:
    rule = copy.deepcopy(REVIEWED_RULE)
    if filter_prefix:
        rule["Filter"] = {"Prefix": rule.pop("Prefix")}
    storage = Storage()
    storage.responses["get_bucket_lifecycle_configuration"] = {"Rules": [rule]}
    check_backup_policy(cast(PolicyClient, storage), bucket="archive-fixture")
    rule["Expiration"] = {"Days": 365}
    with pytest.raises(GateError, match="lifecycle"):
        check_backup_policy(cast(PolicyClient, storage), bucket="archive-fixture")


def test_backup_policy_matches_existing_production_infrastructure() -> None:
    module = preflight.ROOT / "infra/opentofu/modules/digitalocean-spaces"
    source = (module / "main.tf").read_text()
    variables = (module / "variables.tf").read_text()
    production = (preflight.ROOT / "infra/opentofu/environments/production/main.tf").read_text()
    assert 'id      = "backups-retention"' in source
    assert 'prefix  = "backups/"' in source
    assert "abort_incomplete_multipart_upload_days = 7" in source
    assert "days = var.noncurrent_version_retention_days" in source
    assert "default     = 30" in variables
    assert "noncurrent_version_retention_days" not in production
