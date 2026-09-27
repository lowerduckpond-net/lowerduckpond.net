"""Native adapter for the installed case; unavailable from the live operator CLI."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_contracts import canonical_json_bytes
from restore_fixture import Fixture, checked
from retirement_storage import clients

from scripts import qualification_restore as owned
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_archive import Archives
from scripts.m3_11_retirement_context import Context
from scripts.m3_11_retirement_docker import Containers, Stream
from scripts.m3_11_retirement_ext4 import Ext4
from scripts.m3_11_retirement_files import CHUNK, digest, fingerprint, legacy
from scripts.m3_11_retirement_live import SpacesFixture
from scripts.m3_11_retirement_minio import observe
from scripts.m3_11_retirement_state import ownership
from scripts.m3_11_retirement_transaction import Retirement
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, RUN_ENV, resource_names
from scripts.qualification_minio import image_reference


class NativeContext:
    def __init__(self, fixture: Fixture, root: Path) -> None:
        self.run, self.environment = root, fixture.environment
        self.context = {
            kind + "_fixture_sha256": digest(
                {
                    key: legacy(root / f"restore/{kind}.json")[key]
                    for key in ("id", "name", "owner", "image")
                }
            )
            for kind in ("source", "destination")
        }
        self.context["source_revision"] = (
            fixture.command("git", "rev-parse", "HEAD").decode().strip()
        )

    def original(self) -> dict[str, object]:
        return {
            name: fingerprint(self.run / name, 1024 * 1024)
            for name in (
                "retirement-original-failure.json",
                "restore/source.json",
                "restore/destination.json",
                "restore/acme.json",
                "source-idempotence.json",
            )
        }


class NativeContainers(Containers):
    def __init__(self, context: NativeContext) -> None:
        super().__init__(cast(Context, context))
        names = resource_names(uuid.uuid7().hex)
        environment = {
            **context.environment,
            **names,
            "M3_10_ARCHIVE_BACKEND": "spaces",
            "M3_11_COMBINED_BACKEND": "spaces",
        }
        self.unused = cast(
            Context, SimpleNamespace(environment=environment, context=context.context)
        )
        owned.command(
            environment,
            "docker",
            "run",
            "--detach",
            "--name",
            names[ARCHIVE_ENV],
            "--label",
            "lowerduckpond.qualification.run=" + names[RUN_ENV],
            "--env",
            "MINIO_ROOT_USER=molecule-m3-10-root",
            "--env",
            "MINIO_ROOT_PASSWORD=molecule-m3-10-disposable-root-secret",  # gitleaks:allow
            "--env",
            "MINIO_REGION_NAME=ams3",
            image_reference(),
            "server",
            "/data",
            "--address",
            ":443",
            "--certs-dir",
            "/certs",
        )

    def unused_minio(self) -> dict[str, object]:
        return observe(self.unused, self.api)

    def backup_digest(self, identity: str) -> str:
        stream, _metadata = self.api.get_archive(
            identity, "/mnt/lowerduckpond-restic-test", chunk_size=CHUNK
        )
        rows = {}
        size = 0
        with Stream(iter(stream)) as source, tarfile.open(fileobj=source, mode="r|") as archive:
            for member in archive:
                if member.isdir():
                    continue
                assert member.isfile() and len(rows) < 10000  # noqa: PLR2004 - fixed inventory bound
                size += member.size
                assert size < 1024 * 1024 * 1024
                body = archive.extractfile(member)
                assert body is not None
                with body:
                    rows[member.name] = hashlib.file_digest(body, "sha256").hexdigest()
        assert rows
        return digest(rows)


class NativeFixture(SpacesFixture):
    containers: NativeContainers

    def __init__(self, fixture: Fixture, root: Path, writer: S3Client, observer: S3Client) -> None:
        context = NativeContext(fixture, root)
        self.context = cast(Context, context)
        self.environment = context.environment
        self.containers = NativeContainers(context)
        self.archives = Archives(writer, observer, "molecule-tenant-archives")
        self.fixture = fixture
        self.original_backup = self.containers.backup_digest(fixture.source_id)
        self.storage = SimpleNamespace(  # type: ignore[assignment]  # Fixed native test backend only.
            binding={
                "artifact_sha256": hashlib.sha256(
                    Path(self.environment[ARTIFACT_ENV]).read_bytes()
                ).hexdigest()
            },
            target=SimpleNamespace(
                archive_bucket="molecule-tenant-archives",
                repository="/mnt/lowerduckpond-restic-test",
            ),
        )
        owned.acme_accounting(self.environment, fixture.acme_id, negative=True)

    def owner(self) -> None:
        assert self.containers.backup_digest(self.fixture.source_id) == self.original_backup

    def dns(self) -> dict[str, object]:
        # No public provider exists in native qualification. The live DNS boundary
        # has separate component cases and remains mandatory in the operator CLI.
        return {"backend": "controlled-acme", "public_provider_authority": "none"}


def state_digests(fixture: Fixture, root: str, *, destination: bool) -> dict[str, str]:
    host = fixture.destination if destination else fixture.source
    return json.loads(
        checked(
            host,
            f"""
import hashlib, json
from pathlib import Path
root = Path({root!r})
rows = {{}}
for name in ('authorization', 'audit', 'tenants', 'intake', 'exports'):
    base = root / name
    if base.exists():
        for path in sorted(base.rglob('*')):
            assert not path.is_symlink()
            if path.is_file():
                rows[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
assert rows
print(json.dumps(rows, sort_keys=True))
""",
        )
    )


def preserved(root: Path, image: str, prefix: str, expected: dict[str, str]) -> None:
    # Test-only extraction to compare every original job/result/audit byte. The
    # production reader remains bounded to canonical authority records.
    output = root / "retirement-test-extract"
    for index, (name, expected_digest) in enumerate(expected.items()):
        assert all(part not in {"", ".", ".."} for part in name.split("/"))
        destination = output.with_name(output.name + f"-{index}")
        subprocess.run(  # noqa: S603 - fixed debugfs dump of private native fixture
            ["/usr/sbin/debugfs", "-R", f"dump {prefix}/{name} {destination}", str(root / image)],
            check=True,
            capture_output=True,
            timeout=20,
        )
        with destination.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == expected_digest
        destination.unlink()


class ChangedManifest(Ext4):
    """Read-only fault: both views agree, but contradict the captured descriptor."""

    def read(self, path: str) -> bytes:
        raw = super().read(path)
        value = json.loads(raw)
        if value.get("kind") == "Site":
            value["metadata"]["slug"] = "changed-after-capture"
            return canonical_json_bytes(value)
        return raw


def retire_failed_fixture(fixture: Fixture, root: Path, failure: dict[str, object]) -> None:
    before = (root / "retirement-original-failure.json").read_bytes()
    original_source = state_digests(fixture, "/var/lib/lowerduckpond/static", destination=False)
    candidate = f"/var/lib/lowerduckpond/.restore-{fixture.restore_id}-state/candidate"
    original_destination = state_digests(fixture, candidate, destination=True)
    archive = owned.inspect(fixture.environment, fixture.environment[ARCHIVE_ENV])
    # This fixed case additionally inventories current objects through the
    # archive principal. Keep its object permissions unchanged; grant only the
    # same bucket listing already visible through its version inventory.
    fixture.command(
        "docker",
        "exec",
        str(archive["id"]),
        "python3",
        "-c",
        """
import json
from pathlib import Path
path = Path('/fixtures/m310archive.json')
policy = json.loads(path.read_bytes())
assert policy['Statement'][0]['Action'] == [
    's3:GetBucketVersioning', 's3:ListBucketVersions', 's3:ListBucketMultipartUploads'
]
policy['Statement'][0]['Action'].append('s3:ListBucket')
path.write_text(json.dumps(policy))
""",
    )
    fixture.command(
        "docker",
        "exec",
        str(archive["id"]),
        "mc",
        "--config-dir",
        "/root/.mc",
        "admin",
        "policy",
        "create",
        "m310",
        "m310archive",
        "/fixtures/m310archive.json",
    )
    ca = Path(fixture.environment["MOLECULE_EPHEMERAL_DIRECTORY"]) / "archive-tls/ca.crt"
    with clients(fixture.address(str(archive["id"])), ca) as (writer, observer):
        native = NativeFixture(fixture, root, writer, observer)
        transaction = Retirement(root, native)
        foreign = observer.put_object(
            Bucket=native.archives.bucket,
            Key="foreign-test-object",
            Body=b"foreign",
            ContentLength=7,
        )
        with pytest.raises(ValueError):
            transaction.prepare()
        assert observer.get_object(
            Bucket=native.archives.bucket,
            Key="foreign-test-object",
            VersionId=foreign["VersionId"],
        )["ContentLength"] == len(b"foreign")
        assert all(
            row["running"] for row in native.containers.state(native.containers.expected()).values()
        )
        observer.delete_object(
            Bucket=native.archives.bucket, Key="foreign-test-object", VersionId=foreign["VersionId"]
        )
        plan = transaction.prepare()
        for reader, repository in (
            (Ext4, "/mnt/foreign-repository"),
            (ChangedManifest, native.storage.target.repository),
        ):
            with pytest.raises(ValueError):
                ownership(
                    reader(transaction.root / "source.ext4"),
                    reader(transaction.root / "destination.ext4"),
                    "/static",
                    "/lowerduckpond",
                    artifact=str(native.storage.binding["artifact_sha256"]),
                    bucket=native.archives.bucket,
                    repository=repository,
                )
        with pytest.raises(ValueError):
            transaction.retire("f" * 64, acknowledge=True)
        assert native.archives.observed()
        result = transaction.retire(str(plan["plan_sha256"]), acknowledge=True)
        assert transaction.retire(str(plan["plan_sha256"]), acknowledge=True) == result
        assert not native.archives.observed()
        native.owner()
        assert read_private(root / "retirement-original-failure.json") == failure
        assert (root / "retirement-original-failure.json").read_bytes() == before
        assert not (root / "combined.json").exists() and not (root / "qualification.json").exists()
        for kind in ("source", "destination", "acme"):
            assert (
                owned.inspect(
                    fixture.environment, str(legacy(root / f"restore/{kind}.json")["id"])
                )["running"]
                is False
            )
        preserved(transaction.root, "source.ext4", "/static", original_source)
        preserved(
            transaction.root,
            "destination.ext4",
            f"/lowerduckpond/.restore-{fixture.restore_id}-state/candidate",
            original_destination,
        )
        assert (
            native.containers.unused_minio()
            == read_private(transaction.root / "preparation.json")["untouched_minio"]
        )
        owned.require_source_idempotence(fixture.environment, archived_prefix=True)
        write_private(
            root / "case-retirement.json",
            {
                "run_id": os.environ[RUN_ENV],
                "artifact_sha256": native.storage.binding["artifact_sha256"],
                "receipt": result,
                "protected_backup_sha256": native.original_backup,
                "source_state_sha256": digest(original_source),
                "destination_state_sha256": digest(original_destination),
            },
        )
