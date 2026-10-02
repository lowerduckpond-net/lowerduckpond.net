"""A finished debugging session disposes of exactly its local and remote fixture."""

from __future__ import annotations

import fcntl
import io
import json
import os
import re
import shutil
import subprocess
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_backup_fixture as backup_fixture
from scripts import m3_11_debug_closeout as cleanup
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_case
from scripts import qualification_restore as owned
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_combined_inputs import FORMAT, _environment
from scripts.m3_11_live_storage import FORMAT as STORAGE_FORMAT
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.production_qualification_inputs import POLICY
from scripts.qualification_context import RUN_ENV, run_lease

RUN = "0198d17f-6f4a-7000-8000-000000000001"
NONCE = "0198d17f-6f4a-7000-8000-000000000002"
TARGET = Target(RUN, "ams3", "example-backups", "example-archives")
ENDPOINT = "unix:///var/run/docker.sock"
IMAGE = "sha256:" + "e" * 64
BINDING: dict[str, object] = {
    "source_revision": "a" * 40,
    "artifact_sha256": "b" * 64,
    "input_policy": POLICY,
    "qualification_inputs_sha256": "c" * 64,
    "storage_target_sha256": TARGET.storage_target_sha256,
    "storage_run_id": NONCE,
    "storage_report_sha256": "d" * 64,
}


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
    image_id: str = IMAGE
    manifest: bytes = evidence.canonical_bytes(TARGET.manifest(BINDING))
    cloud_unavailable: bool = False

    def objects(self, **request: object) -> dict[str, object]:
        if self.cloud_unavailable:
            raise OSError("provider unavailable")
        if request["Bucket"] == TARGET.archive_bucket:
            keys = ["unknown/archive"] if self.dirty_archive else []
        else:
            assert request["Bucket"] == TARGET.backup_bucket and request["Prefix"] == TARGET.prefix
            latest = {key: kind for (key, _), kind in self.versions.items()}
            keys = [key for key, kind in latest.items() if kind == "version"]
        return {"IsTruncated": False, "Contents": [{"Key": key} for key in keys]}

    def version_list(self, **request: object) -> dict[str, object]:
        values = self.versions if request["Bucket"] == TARGET.backup_bucket else {}
        return {
            "IsTruncated": False,
            **{
                output: [
                    {"Key": key, "VersionId": identity}
                    for (key, identity), kind in values.items()
                    if key.startswith(str(request["Prefix"])) and kind == selected
                ]
                for selected, output in (
                    ("version", "Versions"),
                    ("delete-marker", "DeleteMarkers"),
                )
            },
        }

    def owner(self, **request: object) -> dict[str, object]:
        assert request["Bucket"] == TARGET.backup_bucket
        assert request["Key"] == TARGET.owner_key
        assert (TARGET.owner_key, str(request["VersionId"])) in self.versions
        return {
            "VersionId": request["VersionId"],
            "ContentLength": len(self.manifest),
            "Body": io.BytesIO(self.manifest),
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
        client.get_object.side_effect = self.owner
        client.delete_object.side_effect = self.delete
        client.abort_multipart_upload.side_effect = AssertionError("no uploads in this fixture")
        return client

    def changed(self, kind: str, identity: str) -> None:
        self.events.append((kind, identity))
        if self.fail_after in {kind, identity}:
            self.fail_after = None
            raise OSError("response lost after commit")

    def command(
        self, environment: dict[str, str], *arguments: str, timeout: int = 60, stdin: bytes = b""
    ) -> bytes:
        assert environment["DOCKER_HOST"] == ENDPOINT
        assert "DOCKER_CONTEXT" not in environment
        assert arguments[0] == "docker"
        if arguments[1:3] == ("container", "ls"):
            selector = arguments[arguments.index("--filter") + 1]
            if selector.startswith("label="):
                assert selector == f"label={cleanup.LABEL}={environment[RUN_ENV]}"
                ids = [
                    key for key, row in self.rows.items() if row["owner"] == environment[RUN_ENV]
                ]
            else:
                assert selector.startswith("name=")
                ids = [
                    key
                    for key, row in self.rows.items()
                    if re.search(selector[5:], str(row["name"]))
                ]
            return "\n".join(ids).encode()
        if arguments[1:3] == ("image", "ls"):
            assert f"reference=molecule_local/{environment['LDP_QUALIFICATION_IMAGE']}" in arguments
            return self.image_id.encode() if self.image_present else b""
        if arguments[1:3] == ("image", "rm"):
            assert arguments[3:] == (f"molecule_local/{environment['LDP_QUALIFICATION_IMAGE']}",)
            self.image(environment)
            return b""
        if arguments[1] == "inspect":
            row = next(
                row
                for row in self.rows.values()
                if arguments[-1] in {row["id"], str(row["name"]).removeprefix("/")}
            )
            return json.dumps(row).encode()
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
        self.changed("image", self.image_id)

    def bounded(
        self, arguments: list[str], *, environment: dict[str, str], **options: object
    ) -> bytes:
        return self.command(environment, *arguments)


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
    write_private(
        run / "live-storage.json",
        {
            "format": STORAGE_FORMAT,
            "run_id": RUN,
            "region": TARGET.region,
            "backup_bucket": TARGET.backup_bucket,
            "archive_bucket": TARGET.archive_bucket,
            "binding": BINDING,
            "owner_version": "owner-version",
            "restic_password": "f" * 64,
        },
    )
    write_private(run / "failure-exit.json", {"exit_status": 124, "phase": "verify"})
    environment = {
        "SPACES_REGION": TARGET.region,
        "SPACES_BACKUP_BUCKET": TARGET.backup_bucket,
        "SPACES_ARCHIVE_BUCKET": TARGET.archive_bucket,
        "SPACES_ACCESS_KEY_ID": "example-key",
        "SPACES_SECRET_ACCESS_KEY": "example-credential",
        "SPACES_BACKUP_ACCESS_KEY_ID": "runtime-key",
        "SPACES_BACKUP_SECRET_ACCESS_KEY": "runtime-credential",
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
    monkeypatch.setattr(backup_fixture, "create_client", lambda **options: value.client())
    monkeypatch.setattr(qualification_case, "bounded_command", value.bounded)
    return value


def test_preview_retains_every_resource_and_original_failure(fixture: Fixture) -> None:
    original = (fixture.run / "failure-exit.json").read_bytes()
    cleanup.closeout(fixture.run, fixture.environment, apply=False)
    assert not fixture.events
    assert fixture.rows and fixture.versions
    assert (fixture.run / "failure-exit.json").read_bytes() == original
    assert not (fixture.run / "run.lock").exists()
    assert not (fixture.run / "debug-closeout-local.json").exists()
    assert not (fixture.run / "debug-closeout-backup").exists()


@pytest.mark.parametrize("apply", [False, True])
@pytest.mark.parametrize("fault", ["version", "body", "binding", "missing"])
def test_original_remote_ownership_is_required_before_any_mutation(
    fixture: Fixture, fault: str, apply: bool
) -> None:
    if fault in {"version", "missing"}:
        del fixture.versions[TARGET.owner_key, "owner-version"]
        if fault == "version":
            fixture.versions[TARGET.owner_key, "replacement-version"] = "version"
    elif fault == "body":
        fixture.manifest = evidence.canonical_bytes(
            TARGET.manifest({**BINDING, "artifact_sha256": "f" * 64})
        )
    else:
        path = fixture.run / "live-storage.json"
        storage = read_private(path)
        storage["binding"] = {**BINDING, "artifact_sha256": "f" * 64}
        path.unlink()
        write_private(path, storage)
    before = dict(fixture.versions)
    with pytest.raises(ValueError, match="ownership"):
        cleanup.closeout(fixture.run, fixture.environment, apply=apply)
    assert not fixture.events
    assert fixture.versions == before and fixture.rows and fixture.image_present


@pytest.mark.parametrize("role", cleanup.ROLES)
@pytest.mark.parametrize("owner", [None, "another-run"])
def test_expected_name_with_replacement_label_is_rejected_before_mutation(
    fixture: Fixture, role: str, owner: str | None
) -> None:
    replacement = next(
        row for row in fixture.rows.values() if str(row["name"]).endswith("-" + role)
    )
    replacement["owner"] = owner
    environment = _environment(fixture.run, RUN, ENDPOINT)
    # Docker's label filter really does omit the replacement in this reproduction.
    listed = fixture.command(
        environment,
        "docker",
        "container",
        "ls",
        "--filter",
        f"label={cleanup.LABEL}={environment[RUN_ENV]}",
    )
    assert str(replacement["id"]).encode() not in listed
    with pytest.raises(ValueError, match="ownership"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.events
    assert fixture.versions and fixture.image_present and fixture.run.exists()


@pytest.mark.parametrize("interruption", [None, "container", "image"])
def test_reassigned_image_tag_is_retained_before_cleanup_and_on_retry(
    fixture: Fixture, interruption: str | None
) -> None:
    if interruption is not None:
        fixture.fail_after = interruption
        with pytest.raises(OSError, match="response lost"):
            cleanup.closeout(fixture.run, fixture.environment, apply=True)
    fixture.image_present = True
    fixture.image_id = "sha256:" + "f" * 64
    events = list(fixture.events)
    with pytest.raises(cleanup.CloseoutError, match="tag was replaced"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert fixture.events == events
    assert fixture.image_present and fixture.run.exists()
    assert not cleanup.disposal_receipt(fixture.run).exists()


def test_real_image_removal_helper_rechecks_tag_identity(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def command(arguments: list[str], *, environment: dict[str, str], **options: object) -> bytes:
        if arguments[1:3] == ["image", "ls"]:
            fixture.image_id = "sha256:" + "f" * 64
        return fixture.command(environment, *arguments)

    monkeypatch.setattr(qualification_case, "bounded_command", command)
    with pytest.raises(ValueError, match="tag was replaced"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert fixture.image_present and fixture.run.exists()
    assert all(kind != "image" for kind, _ in fixture.events)


@pytest.mark.parametrize("image", [IMAGE, "sha256:" + "f" * 64])
def test_retained_source_receipt_binds_image_after_original_host_is_gone(
    fixture: Fixture, image: str
) -> None:
    identity, source = next(
        (identity, row)
        for identity, row in fixture.rows.items()
        if str(row["name"]).endswith("-host")
    )
    (fixture.run / "restore").mkdir(mode=0o700)
    write_private(fixture.run / "restore/source.json", source)
    del fixture.rows[identity]
    fixture.image_id = image
    if image == IMAGE:
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.run.exists()
    else:
        with pytest.raises(cleanup.CloseoutError, match="tag was replaced"):
            cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.events and fixture.image_present


@pytest.mark.parametrize("authorization", ["original", "missing", "changed"])
def test_lost_owner_deletion_response_requires_original_authorization_to_resume(
    fixture: Fixture, authorization: str
) -> None:
    fixture.fail_after = TARGET.owner_key
    with pytest.raises(OSError, match="response lost"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.versions and fixture.rows
    path = fixture.run / "debug-closeout-backup/owner-delete.started.json"
    if authorization != "original":
        path.unlink()
        if authorization == "changed":
            write_private(path, {"intent_sha256": "f" * 64})
        events = list(fixture.events)
        with pytest.raises(ValueError, match=r"ownership|authorization"):
            cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert fixture.events == events and fixture.run.exists()
    else:
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.run.exists()
        assert len(fixture.events) == len(set(fixture.events))


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
        (fixture.run / "live-storage.json").unlink()
    elif phase == "already-stopped":
        for row in fixture.rows.values():
            row["running"] = False
    cleanup.closeout(fixture.run, fixture.environment, apply=True)
    assert not fixture.run.exists()


@pytest.mark.parametrize("captured_inputs", [False, True])
@pytest.mark.parametrize("contents", ["unowned", "owner-only", "empty"])
def test_failed_storage_setup_requires_an_empty_prefix_before_any_cleanup(
    fixture: Fixture, captured_inputs: bool, contents: str
) -> None:
    (fixture.run / "live-storage.json").unlink()
    if not captured_inputs:
        (fixture.run / "qualification-inputs.json").unlink()
    if contents == "empty":
        fixture.versions.clear()
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.run.exists()
    else:
        fixture.versions = {
            (
                TARGET.owner_key if contents == "owner-only" else TARGET.prefix + "unowned",
                "v",
            ): "version"
        }
        with pytest.raises(RuntimeError, match="required empty boundary"):
            cleanup.closeout(fixture.run, fixture.environment, apply=True)
        assert not fixture.events
        assert fixture.rows and fixture.versions and fixture.run.exists()


@pytest.mark.parametrize("removed", ["manifest", "root"])
def test_interrupted_directory_removal_resumes_without_manifest_providers_or_preservation(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, removed: str
) -> None:
    original = shutil.rmtree

    def interrupt(path: Path) -> None:
        assert path == fixture.run
        assert not fixture.rows and not fixture.versions and not fixture.image_present
        if removed == "manifest":
            (path / "fixture.json").unlink()
        else:
            original(path)
        raise OSError("interrupted directory removal")

    monkeypatch.setattr(shutil, "rmtree", interrupt)
    with pytest.raises(OSError, match="interrupted directory"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    receipt = cleanup.disposal_receipt(fixture.run)
    raw = receipt.read_bytes()
    events = list(fixture.events)
    fixture.cloud_unavailable = True
    cleanup.closeout(fixture.run, {}, apply=False)
    assert receipt.read_bytes() == raw and fixture.events == events
    monkeypatch.setattr(shutil, "rmtree", original)
    cleanup.closeout(fixture.run, {}, apply=True)
    assert not fixture.run.exists() and not receipt.exists()
    assert fixture.events == events


def test_final_disposal_wrapper_skips_state_loading_after_manifest_deletion(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = shutil.rmtree

    def interrupt(path: Path) -> None:
        (path / "fixture.json").unlink()
        raise OSError("interrupted")

    monkeypatch.setattr(shutil, "rmtree", interrupt)
    with pytest.raises(OSError, match="interrupted"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    monkeypatch.setattr(shutil, "rmtree", original)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("SPACES_", "OPENTOFU_", "CLOUDFLARE_", "M3_10_", "AWS_"))
    }
    script = Path(__file__).resolve().parents[2] / "scripts/m3-11-debug-closeout"
    result = subprocess.run(  # noqa: S603 - exact owned local-only disposal fixture
        [str(script), str(fixture.run), "--discard"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not fixture.run.exists() and not cleanup.disposal_receipt(fixture.run).exists()


@pytest.mark.parametrize("fault", ["directory", "receipt", "fixture", "busy"])
def test_final_disposal_refuses_changed_identity_or_concurrent_deletion(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    original = shutil.rmtree
    monkeypatch.setattr(shutil, "rmtree", Mock(side_effect=OSError("interrupted")))
    with pytest.raises(OSError, match="interrupted"):
        cleanup.closeout(fixture.run, fixture.environment, apply=True)
    monkeypatch.setattr(shutil, "rmtree", original)
    receipt = cleanup.disposal_receipt(fixture.run)
    if fault == "directory":
        fixture.run.rename(fixture.run.with_name("original-leftover"))
        fixture.run.mkdir(mode=0o700)
        (fixture.run / "canary").write_bytes(b"unrelated recreated directory")
    elif fault == "receipt":
        saved = read_private(receipt)
        saved["directory"] = str(fixture.run.parent / "unrelated")
        receipt.unlink()
        write_private(receipt, saved)
    elif fault == "fixture":
        (fixture.run / "fixture.json").unlink()
        write_private(fixture.run / "fixture.json", {"format": "unrelated"})
    else:
        descriptor = os.open(receipt, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(cleanup.CloseoutError, match="already running"):
                cleanup.closeout(fixture.run, {}, apply=True)
        finally:
            os.close(descriptor)
        assert fixture.run.exists() and receipt.exists()
        return
    with pytest.raises(cleanup.CloseoutError, match=r"identity|replaced|manifest changed"):
        cleanup.closeout(fixture.run, {}, apply=True)
    assert fixture.run.exists() and receipt.exists()
    if fault == "directory":
        assert (fixture.run / "canary").read_bytes() == b"unrelated recreated directory"


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
        (fixture.run / "live-storage.json").unlink()
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
    def command(arguments: list[str], *, environment: dict[str, str], **options: object) -> bytes:
        result = fixture.command(environment, *arguments)
        if arguments[1:3] == ["image", "rm"]:
            (fixture.run / "fixture.json").unlink()
            write_private(fixture.run / "fixture.json", {"format": "changed"})
        return result

    monkeypatch.setattr(qualification_case, "bounded_command", command)
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
