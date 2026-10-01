"""A finished debugging session disposes of exactly its local and remote fixture."""

from __future__ import annotations

import json
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_debug_closeout as cleanup
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_combined_inputs import FORMAT, _environment
from scripts.m3_11_private_inputs import write_private
from scripts.qualification_context import RUN_ENV, run_lease

RUN = "0198d17f-6f4a-7000-8000-000000000001"
NONCE = "0198d17f-6f4a-7000-8000-000000000002"
TARGET = Target(RUN, "ams3", "example-backups", "example-archives")
ENDPOINT = "unix:///var/run/docker.sock"
IMAGE = "sha256:" + "e" * 64


@dataclass
class Fixture:
    run: Path
    environment: dict[str, str]
    rows: dict[str, dict[str, object]] = field(default_factory=dict)
    events: list[tuple[str, str]] = field(default_factory=list)
    versions: dict[tuple[str, str], str] = field(default_factory=dict)
    fail_after: str | None = None
    dirty_archive: bool = False
    image_busy: bool = False
    image_present: bool = True
    cloud_unavailable: bool = False

    def objects(self, **request: object) -> dict[str, object]:
        if self.cloud_unavailable:
            raise OSError("provider unavailable")
        if request["Bucket"] == TARGET.archive_bucket:
            keys = ["unknown/archive"] if self.dirty_archive else []
        else:
            assert request["Bucket"] == TARGET.backup_bucket and request["Prefix"] == TARGET.prefix
            keys = [key for (key, _identity), kind in self.versions.items() if kind == "version"]
        return {"IsTruncated": False, "Contents": [{"Key": key} for key in keys]}

    def version_list(self, **request: object) -> dict[str, object]:
        values = self.versions if request["Bucket"] == TARGET.backup_bucket else {}
        return {
            "IsTruncated": False,
            "Versions": [{"Key": key, "VersionId": identity} for key, identity in values],
        }

    def delete(self, **request: object) -> dict[str, object]:
        assert request["Bucket"] == TARGET.backup_bucket
        key, version = str(request["Key"]), str(request["VersionId"])
        del self.versions[key, version]
        self.changed("remote", key)
        return {"VersionId": version}

    def client(self) -> Mock:
        client = Mock(spec=S3Client)
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        client.list_objects_v2.side_effect = self.objects
        client.list_object_versions.side_effect = self.version_list
        client.list_multipart_uploads.return_value = {"IsTruncated": False}
        client.delete_object.side_effect = self.delete
        client.abort_multipart_upload.side_effect = AssertionError("no uploads in this fixture")
        return client

    def changed(self, kind: str, identity: str) -> None:
        self.events.append((kind, identity))
        if self.fail_after == kind:
            self.fail_after = None
            raise OSError("response lost after commit")

    def command(
        self, environment: dict[str, str], *arguments: str, timeout: int = 60, stdin: bytes = b""
    ) -> bytes:
        assert environment["DOCKER_HOST"] == ENDPOINT
        assert "DOCKER_CONTEXT" not in environment
        assert arguments[0] == "docker"
        if arguments[1:3] == ("container", "ls"):
            assert f"label={cleanup.LABEL}={environment[RUN_ENV]}" in arguments
            return "\n".join(self.rows).encode()
        if arguments[1] == "inspect":
            return json.dumps(self.rows[arguments[-1]]).encode()
        if arguments[1] == "stop":
            assert arguments[2:4] == ("--time", "60")
            self.rows[arguments[-1]]["running"] = False
            self.changed("stop", arguments[-1])
        elif arguments[1:3] == ("container", "rm"):
            assert arguments[3] == "--volumes"
            row = self.rows.pop(arguments[-1])
            assert row["running"] is False
            assert not self.versions
            self.changed("container", arguments[-1])
        else:
            raise AssertionError(arguments)
        return b""

    def image(self, environment: dict[str, str]) -> None:
        assert not self.rows and not self.versions
        assert (
            environment["LDP_QUALIFICATION_IMAGE"]
            == f"ldp-m3-{evidence.uuid7(RUN).hex}:ubuntu-2604"
        )
        if not self.image_present:
            return
        if self.image_busy:
            raise ValueError("image still referenced")
        self.image_present = False
        self.changed("image", IMAGE)


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    run = tmp_path / "failed-run"
    run.mkdir(mode=0o700)
    write_private(
        run / "fixture.json",
        {"format": FORMAT, "run_id": RUN, "environment": _environment(run, RUN, ENDPOINT)},
    )
    write_private(
        run / "qualification-inputs.json", {"storage_target_sha256": TARGET.storage_target_sha256}
    )
    write_private(run / "failure-exit.json", {"exit_status": 124, "phase": "verify"})
    environment = {
        "SPACES_REGION": TARGET.region,
        "SPACES_BACKUP_BUCKET": TARGET.backup_bucket,
        "SPACES_ARCHIVE_BUCKET": TARGET.archive_bucket,
        "SPACES_ACCESS_KEY_ID": "example-key",
        "SPACES_SECRET_ACCESS_KEY": "example-credential",
        "CLOUDFLARE_API_TOKEN": "example-token",
        "CLOUDFLARE_ZONE_ID": "a" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "b" * 32,
        "DOCKER_CONTEXT": "an-unrelated-ambient-context",
    }
    value = Fixture(run, environment)
    for index, role in enumerate(cleanup.ROLES, start=1):
        identity = str(index) * 64
        value.rows[identity] = {
            "id": identity,
            "name": f"/ldp-m3-{evidence.uuid7(RUN).hex}-{role}",
            "owner": evidence.uuid7(RUN).hex,
            "image": IMAGE,
            "running": role != "archive",
        }
    value.versions = {
        (TARGET.owner_key, "owner-version"): "version",
        (TARGET.prefix + "restic/data/fixture", "data-version"): "version",
    }
    monkeypatch.setattr(owned, "command", value.command)
    monkeypatch.setattr(cleanup, "create_client", Mock(return_value=value.client()))
    monkeypatch.setattr(cleanup, "storage_lease", lambda environment: nullcontext())
    monkeypatch.setattr(cleanup, "remove_owned_image", value.image)
    return value


def test_preview_retains_every_resource_and_original_failure(fixture: Fixture) -> None:
    original = (fixture.run / "failure-exit.json").read_bytes()
    cleanup.closeout(fixture.run, fixture.environment, apply=False)
    assert not fixture.events
    assert fixture.rows and fixture.versions
    assert (fixture.run / "failure-exit.json").read_bytes() == original
    assert not (fixture.run / "run.lock").exists()


def test_completed_inner_case_without_full_qualification_can_be_closed_out(
    fixture: Fixture,
) -> None:
    write_private(fixture.run / "combined.json", {"status": "passed"})
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.run.exists()


def test_closeout_stops_writers_then_purges_remote_before_local_and_removes_all_disk_copies(
    fixture: Fixture,
) -> None:
    retired = fixture.run / "failed-archive-retirement"
    retired.mkdir(mode=0o700)
    (retired / "source.ext4").write_bytes(b"discardable previous diagnostic copy")
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    kinds = [kind for kind, _identity in fixture.events]
    assert max(index for index, kind in enumerate(kinds) if kind == "stop") < kinds.index("remote")
    assert max(index for index, kind in enumerate(kinds) if kind == "remote") < kinds.index(
        "container"
    )
    assert kinds[-1] == "image"
    assert not fixture.rows and not fixture.versions and not fixture.run.exists()


@pytest.mark.parametrize("phase", ["create", "crash", "already-stopped"])
def test_closeout_does_not_require_passing_diagnostics_or_an_exit_record(
    fixture: Fixture, phase: str
) -> None:
    (fixture.run / "failure-exit.json").unlink()
    if phase == "create":
        fixture.rows = {
            key: row
            for key, row in fixture.rows.items()
            if str(row["name"]).endswith(("-host", "-archive"))
        }
        fixture.versions.clear()
        (fixture.run / "qualification-inputs.json").unlink()
    elif phase == "already-stopped":
        for row in fixture.rows.values():
            row["running"] = False
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.run.exists()


@pytest.mark.parametrize("stage", ["stop", "remote", "container", "image"])
def test_interrupted_closeout_can_be_repeated_without_recreating_or_preserving_resources(
    fixture: Fixture, stage: str
) -> None:
    original = (fixture.run / "failure-exit.json").read_bytes()
    fixture.fail_after = stage
    with pytest.raises(OSError, match="response lost"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert (fixture.run / "failure-exit.json").read_bytes() == original
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.run.exists()
    assert len(fixture.events) == len(set(fixture.events))


@pytest.mark.parametrize(
    "fault", ["unavailable", "archives", "target", "foreign-container", "passing", "live-target"]
)
def test_uncertain_provider_or_ownership_prevents_local_and_remote_mutations(
    fixture: Fixture, fault: str
) -> None:
    if fault == "unavailable":
        fixture.cloud_unavailable = True
    elif fault == "archives":
        fixture.dirty_archive = True
    elif fault == "target":
        fixture.environment["SPACES_BACKUP_BUCKET"] = "another-bucket"
    elif fault == "foreign-container":
        fixture.rows["1" * 64]["name"] = "/production-host"
    elif fault == "live-target":
        write_private(fixture.run / "live-storage.json", {"run_id": RUN, "region": "nyc3"})
    else:
        write_private(fixture.run / "qualification.json", {"status": "passed"})
    with pytest.raises((cleanup.CloseoutError, OSError)):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.events
    assert fixture.run.exists()


def test_foreign_or_changed_original_container_receipt_prevents_cleanup(fixture: Fixture) -> None:
    (fixture.run / "restore").mkdir(mode=0o700)
    saved = {**fixture.rows["1" * 64], "id": "f" * 64}
    write_private(fixture.run / "restore/destination.json", saved)
    with pytest.raises(cleanup.CloseoutError, match="replaced"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.events


def test_active_debugger_run_lock_prevents_cleanup(fixture: Fixture) -> None:
    with run_lease(fixture.run, create=True), pytest.raises(BlockingIOError):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.events


def test_active_qualification_storage_lease_prevents_cleanup(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cleanup, "storage_lease", Mock(side_effect=BlockingIOError("busy")))
    with pytest.raises(BlockingIOError):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.events


def test_writer_restart_after_stopping_prevents_remote_and_local_deletion(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def command(environment: dict[str, str], *arguments: str, **options: object) -> bytes:
        result = fixture.command(environment, *arguments)
        if arguments[1] == "stop":
            fixture.rows[arguments[-1]]["running"] = True
        return result

    monkeypatch.setattr(owned, "command", command)
    with pytest.raises(cleanup.CloseoutError, match="writer restarted"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert all(kind == "stop" for kind, _identity in fixture.events)
    assert fixture.run.exists() and fixture.versions


def test_provider_failure_after_fencing_retains_stopped_local_resources(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def command(environment: dict[str, str], *arguments: str, **options: object) -> bytes:
        result = fixture.command(environment, *arguments)
        if arguments[1] == "stop":
            fixture.cloud_unavailable = True
        return result

    monkeypatch.setattr(owned, "command", command)
    with pytest.raises(OSError, match="provider unavailable"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert fixture.rows and all(row["running"] is False for row in fixture.rows.values())
    assert fixture.run.exists() and fixture.versions


def test_image_failure_leaves_manifest_for_resuming_last_step(fixture: Fixture) -> None:
    fixture.image_busy = True
    with pytest.raises(ValueError, match="image still"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.rows and not fixture.versions
    assert (fixture.run / "fixture.json").exists()
    fixture.image_busy = False
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.run.exists()


def test_redirected_run_directory_is_rejected(fixture: Fixture) -> None:
    link = fixture.run.parent / "redirected"
    link.symlink_to(fixture.run, target_is_directory=True)
    with pytest.raises(ValueError):
        cleanup.closeout(link, fixture.environment, apply=True)
    assert not fixture.events


def test_manifest_change_after_image_removal_prevents_directory_deletion(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def image(environment: dict[str, str]) -> None:
        fixture.image(environment)
        (fixture.run / "fixture.json").unlink()
        write_private(fixture.run / "fixture.json", {"format": "changed"})

    monkeypatch.setattr(cleanup, "remove_owned_image", image)
    with pytest.raises(cleanup.CloseoutError, match="manifest changed"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert fixture.run.exists()


@pytest.mark.parametrize("complete_context", [True, False])
@pytest.mark.parametrize("records", [[], [{"id": "c" * 32, "type": "TXT", "content": "d" * 43}]])
def test_bound_dns_challenges_must_be_absent(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    records: list[dict[str, str]],
    complete_context: bool,
) -> None:
    write_private(
        fixture.run / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": RUN,
            "nonce": NONCE,
            "subjects": list(evidence.subjects(NONCE)),
        },
    )
    if complete_context:
        write_private(
            fixture.run / "combined-context.json",
            {"run_id": RUN, "subject_set_sha256": evidence.subject_digest(NONCE)},
        )
    client = Mock()
    client.get_collection.side_effect = lambda path, query: [
        {**record, "name": query["name"]} for record in records
    ]
    monkeypatch.setattr(cleanup, "CloudflareClient", Mock(return_value=client))
    monkeypatch.setattr(cleanup, "_require_zone_identity", Mock(return_value="one-account"))
    if records:
        with pytest.raises(cleanup.CloseoutError, match="DNS challenges"):
            cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.events
    else:
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.run.exists()


def test_cli_failure_redacts_provider_response(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["closeout", str(fixture.run), "--discard"])
    monkeypatch.setattr(
        cleanup, "closeout", Mock(side_effect=RuntimeError("sensitive-provider-credential"))
    )
    assert cleanup.main() == 1
    assert "sensitive-provider-credential" not in capsys.readouterr().err
