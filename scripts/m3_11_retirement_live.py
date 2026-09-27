"""Fixed Spaces/Docker boundary for the failed disposable archive transaction."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import botocore.session  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.check_m3_7_production_edge import CloudflareClient, _require_zone_identity
from scripts.m3_11_dns_witness import ZONES, DnsWitness
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_archive import Archives
from scripts.m3_11_retirement_context import Context
from scripts.m3_11_retirement_docker import IMAGE_BYTES, Containers, LiveReader
from scripts.m3_11_retirement_ext4 import Ext4
from scripts.m3_11_retirement_files import (
    RetirementError,
    capacity,
    digest,
    fingerprint,
    legacy,
    record,
)
from scripts.m3_11_retirement_state import ownership


def client(environment: Mapping[str, str], prefix: str, region: str) -> S3Client:
    result = botocore.session.get_session().create_client(
        "s3",
        aws_access_key_id=environment[prefix + "ACCESS_KEY_ID"],
        aws_secret_access_key=environment[prefix + "SECRET_ACCESS_KEY"],
        region_name=region,
        endpoint_url=f"https://{region}.digitaloceanspaces.com",
        config=Config(
            connect_timeout=5,
            read_timeout=15,
            retries={"total_max_attempts": 1},
            s3={"addressing_style": "path"},
        ),
    )
    return cast(S3Client, result)


class SpacesFixture:
    def __init__(self, context: Context) -> None:
        self.context = context
        self.storage = context.storage
        self.environment = context.environment
        target = self.storage.target
        if any(
            self.environment.get(key) != expected
            for key, expected in {
                "SPACES_REGION": target.region,
                "SPACES_ARCHIVE_BUCKET": target.archive_bucket,
                "SPACES_BACKUP_BUCKET": target.backup_bucket,
            }.items()
        ):
            raise RetirementError("retirement storage target changed")
        prefixes = ("SPACES_", "SPACES_ARCHIVE_", "SPACES_BACKUP_")
        if any(
            not self.environment.get(prefix + name)
            for prefix in prefixes
            for name in ("ACCESS_KEY_ID", "SECRET_ACCESS_KEY")
        ) or len({self.environment[prefix + "ACCESS_KEY_ID"] for prefix in prefixes}) != len(
            prefixes
        ):
            raise RetirementError("retirement requires distinct explicit storage principals")
        self.observer, self.writer, self.backup = (
            client(self.environment, prefix, target.region) for prefix in prefixes
        )
        self.archives = Archives(self.writer, self.observer, target.archive_bucket)
        self.containers = Containers(context)

    def owner(self) -> None:
        self.storage._require_inputs(self.environment)
        for principal in (self.backup, self.observer):
            self.storage.target.require_owner(
                principal, self.storage.binding, version=self.storage.owner_version
            )

    def dns(self) -> dict[str, object]:
        names = read_private(self.context.run / "combined-names.json")
        evidence.validate_names(self.context.run / "combined-names.json", self.context.context)
        nonce = evidence.uuid7(names["nonce"]).hex
        client = CloudflareClient(self.environment["CLOUDFLARE_API_TOKEN"])
        coordinates = tuple(
            (domain, self.environment[variable], f"_acme-challenge.m3-11-{nonce}.{domain}")
            for domain, variable in ZONES
        )
        if (
            len({zone for _, zone, _ in coordinates}) != len(ZONES)
            or len(
                {_require_zone_identity(client, zone, domain) for domain, zone, _ in coordinates}
            )
            != 1
        ):
            raise RetirementError("retirement DNS zone identity is ambiguous")
        witness = DnsWitness(
            self.context.run, client, digest(self.context.context), digest(names), coordinates
        )
        for domain, zone, challenge in coordinates:
            # A subject CNAME or wildcard would also be a foreign dependency.
            for name in (f"m3-11-{nonce}.{domain}", f"*.m3-11-{nonce}.{domain}", challenge):
                if witness._records(zone, name):
                    raise RetirementError("retirement DNS subject or challenge is not absent")
        return {
            "coordinates": [list(item) for item in coordinates],
            "subjects_sha256": self.context.context["subject_set_sha256"],
            "records": 0,
        }

    def initial(self) -> dict[str, object]:
        original = self.context.original()
        self.owner()
        containers = self.containers.expected()
        states = self.containers.state(containers)
        if any(row["running"] is not True for row in states.values()):
            raise RetirementError("retirement preparation requires original running fixtures")
        observations = owned.observations(self.environment)
        for kind in ("source", "destination"):
            row = cast(dict[str, object], observations[kind])
            units = cast(dict[str, dict[str, object]], row["units"])
            if (
                row.get("gate_present") is not True
                or units["caddy.service"]["state"] != "inactive"
                or units["lowerduckpond-host-restore.service"]["state"]
                != ("failed" if kind == "destination" else "inactive")
            ):
                raise RetirementError("retirement requires failed gated reconstruction")
        proof = ownership(
            LiveReader(self.environment, str(containers["source"]["id"])),
            LiveReader(self.environment, str(containers["destination"]["id"])),
            "/var/lib/lowerduckpond/static",
            "/var/lib/lowerduckpond",
            artifact=str(self.storage.binding["artifact_sha256"]),
            bucket=self.storage.target.archive_bucket,
            repository=self.storage.target.repository,
        )
        if (
            cast(list[str], proof["gates_sha256"])[0]
            != legacy(self.context.run / "restore/source.json")["gateSha256"]
        ):
            raise RetirementError("source gate changed from original fencing")
        selected = cast(list[dict[str, object]], proof["archives"])
        if self.archives.observed() != [(str(row["key"]), str(row["version"])) for row in selected]:
            raise RetirementError("retirement remote inventory differs from original ownership")
        capacity(
            self.context.run, 2 * IMAGE_BYTES + sum(cast(int, row["size"]) for row in selected)
        )
        result = {
            "original": original,
            "containers": containers,
            "states": states,
            "backing_images": self.containers.image_metadata(containers),
            "untouched_minio": self.containers.unused_minio(),
            "ownership": proof,
            "dns": self.dns(),
            "observed_at": datetime.now(UTC).isoformat(),
        }
        if self.context.original() != original or self.containers.state(containers) != states:
            raise RetirementError("retirement fixture changed before preparation")
        return result

    def freeze(self, root: Path, intent: dict[str, object]) -> None:
        if self.context.original() != intent["original"] or self.dns() != intent["dns"]:
            raise RetirementError("retirement preparation inputs changed")
        self.owner()
        if self.containers.unused_minio() != intent["untouched_minio"]:
            raise RetirementError("unused local MinIO changed")
        self.containers.freeze(root, intent)

    def capture(self, root: Path, intent: dict[str, object]) -> dict[str, object]:
        images = {
            kind: self.containers.copy(root, intent, kind) for kind in ("source", "destination")
        }
        proof = ownership(
            Ext4(root / "source.ext4"),
            Ext4(root / "destination.ext4"),
            "/static",
            "/lowerduckpond",
            artifact=str(self.storage.binding["artifact_sha256"]),
            bucket=self.storage.target.archive_bucket,
            repository=self.storage.target.repository,
        )
        if proof != intent["ownership"]:
            raise RetirementError("stopped state differs from pre-stop archive authority")
        result = {**proof, "images": images}
        record(root / "capture.json", result)
        return result

    def guard(self, root: Path, intent: dict[str, object], capture: dict[str, object]) -> None:
        if self.context.original() != intent["original"] or self.dns() != intent["dns"]:
            raise RetirementError("retirement original authority changed")
        self.owner()
        self.containers.stopped(intent)
        if self.containers.unused_minio() != intent["untouched_minio"]:
            raise RetirementError("unused local MinIO changed")
        if read_private(root / "capture.json") != capture:
            raise RetirementError("retirement frozen capture changed")
        images = cast(dict[str, dict[str, object]], capture["images"])
        if set(images) != {"source", "destination"}:
            raise RetirementError("retirement lacks both frozen filesystems")
        for kind, expected in images.items():
            if (
                kind not in {"source", "destination"}
                or fingerprint(root / (kind + ".ext4"), IMAGE_BYTES) != expected["bytes"]
                or read_private(root / (kind + "-image.json")) != expected
            ):
                raise RetirementError("retirement frozen filesystem evidence changed")
