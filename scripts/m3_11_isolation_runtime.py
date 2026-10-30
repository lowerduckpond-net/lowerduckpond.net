"""Native admission and verified evidence-volume ownership for isolation only."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_files import directory, record, sync
from scripts.m3_11_unattended.docker import (
    ADMISSION,
    EVIDENCE_VOLUME,
    OWNER,
    Docker,
    reserve_admission,
)
from scripts.m3_11_unattended.model import digest, fingerprint, identity
from scripts.production_qualification_inputs import revision

LABEL = OWNER + ".public-ca"
FORMAT = "lowerduckpond-isolated-public-ca-admission-v1"


def volume_identity(docker: Docker) -> dict[str, object]:
    rows = json.loads(docker.command("volume", "inspect", EVIDENCE_VOLUME))
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("isolated native evidence volume identity is unavailable")
    volume = rows[0]
    labels = volume.get("Labels")
    if (
        volume.get("Name") != EVIDENCE_VOLUME
        or volume.get("Driver") != "local"
        or not isinstance(labels, dict)
        or labels.get(OWNER) != "true"
        or not isinstance(volume.get("CreatedAt"), str)
        or not isinstance(volume.get("Mountpoint"), str)
    ):
        raise ValueError("isolated native evidence volume ownership differs")
    return {key: volume[key] for key in ("Name", "Driver", "CreatedAt", "Mountpoint", "Labels")}


@dataclass(frozen=True)
class Fence:
    docker: Docker
    ticket: dict[str, object]

    @classmethod
    def acquire(cls, docker: Docker, *, run_id: str, source: str, image_sha256: str) -> Fence:
        identity(run_id)
        revision(source)
        image = "sha256:" + fingerprint(image_sha256)
        daemon = docker.info()
        volume = volume_identity(docker)
        selected = reserve_admission(
            docker, image=image, labels=(LABEL + "=" + run_id, OWNER + ".source=" + source)
        )
        ticket: dict[str, object] = {
            "format": FORMAT,
            "run_id": run_id,
            "source_revision": source,
            "image": image,
            "daemon": daemon,
            "evidence_volume": volume,
            "container_id": fingerprint(selected),
        }
        result = cls(docker, ticket)
        result.require()
        return result

    def require(self, manifest: Manifest | None = None) -> None:
        value = self.ticket
        if (
            value.get("format") != FORMAT
            or self.docker.info() != value["daemon"]
            or volume_identity(self.docker) != value["evidence_volume"]
        ):
            raise ValueError("isolated admission daemon changed")
        actor = self.docker.owned(str(value["container_id"]))
        config, host, state = actor.get("Config"), actor.get("HostConfig"), actor.get("State")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(state, dict)
        ):
            raise ValueError("isolated admission metadata is unavailable")
        labels = config.get("Labels")
        restart = host.get("RestartPolicy")
        if (
            actor.get("Id") != value["container_id"]
            or actor.get("Name") != "/" + ADMISSION
            or actor.get("Image") != value["image"]
            or config.get("Cmd") != ["true"]
            or not isinstance(labels, dict)
            or labels.get(LABEL) != value["run_id"]
            or labels.get(OWNER + ".source") != value["source_revision"]
            or host.get("NetworkMode") != "none"
            or not isinstance(restart, dict)
            or restart.get("Name") != "no"
            or state.get("Running") is not False
            or state.get("Pid") != 0
        ):
            raise ValueError("isolated global admission is no longer its inert owned fence")
        if manifest is not None and (
            manifest.plan.run_id != value["run_id"]
            or manifest.plan.source_revision != value["source_revision"]
            or "sha256:" + manifest.plan.controller_sha256 != value["image"]
            or manifest.plan.daemon_sha256 != digest(value["daemon"])
        ):
            raise ValueError("isolated manifest differs from its native admission")

    def release(
        self, manifest: Manifest, *, evidence: Evidence, journal: object, run_id: int
    ) -> dict[str, object]:
        from scripts.m3_11_isolation_host import Host  # noqa: PLC0415
        from scripts.m3_11_isolation_journal import Journal  # noqa: PLC0415
        from scripts.m3_11_isolation_seal import seal  # noqa: PLC0415

        self.require(manifest)
        if evidence.fence != self or not isinstance(journal, Journal):
            raise ValueError("isolated admission requires its real native evidence/journal")
        host = Host(
            manifest,
            evidence,
            directory_path=evidence.root / "runs" / manifest.plan.run_id,
            docker=self.docker,
        )
        result = seal(host, journal, run_id=run_id)
        # Stock qualification uses authoritative prechecks. A recursive-mode
        # diagnostic records its result but cannot silently authorize different
        # full-run semantics.
        if manifest.plan.network.mode != "authoritative":
            raise ValueError("isolated network proof does not match stock qualification")
        host.require(consumed=True)
        self.docker.remove_controller(str(self.ticket["container_id"]))
        return result


class Evidence:
    """A concrete native-volume adapter, not an arbitrary output directory."""

    def __init__(self, docker: Docker, fence: Fence, *, actor_id: str, root: Path) -> None:
        self.docker, self.fence, self.actor_id, self.root = (
            docker,
            fence,
            fingerprint(actor_id),
            root,
        )
        self.require()
        root.mkdir(mode=0o700, exist_ok=True)
        directory(root)
        self.reservations = root / "reservations"
        self.reservations.mkdir(mode=0o700, exist_ok=True)
        directory(self.reservations)
        sync(root)

    def require(self) -> None:
        self.fence.require()
        actor = self.docker.owned(self.actor_id)
        mounts = actor.get("Mounts")
        if actor.get("Image") != self.fence.ticket["image"] or not isinstance(mounts, list):
            raise ValueError("isolated evidence actor image or mounts differ")
        selected = [
            item
            for item in mounts
            if isinstance(item, dict)
            and item.get("Type") == "volume"
            and item.get("Name") == EVIDENCE_VOLUME
        ]
        if (
            len(selected) != 1
            or selected[0].get("RW") is not True
            or self.root != Path(str(selected[0].get("Destination"))) / "public-ca"
        ):
            raise ValueError("isolated evidence is not the native writable shared volume")
        protected = Path(str(selected[0]["Destination"]))
        for mount in mounts:
            if not isinstance(mount, dict) or not isinstance(mount.get("Destination"), str):
                raise ValueError("isolated evidence mount metadata is invalid")
            target = Path(mount["Destination"])
            if (
                not target.is_absolute()
                or ".." in target.parts
                or str(target) != mount["Destination"]
            ):
                raise ValueError("isolated evidence mount destination is not canonical")
            if mount is not selected[0] and (
                target == protected or target.is_relative_to(protected)
            ):
                raise ValueError("isolated native evidence is shadowed by another mount")
        volumes = json.loads(self.docker.command("volume", "inspect", EVIDENCE_VOLUME))
        if not isinstance(volumes, list) or len(volumes) != 1:
            raise ValueError("isolated evidence volume identity is unavailable")
        volume = volumes[0]
        labels = volume.get("Labels")
        if (
            volume.get("Name") != EVIDENCE_VOLUME
            or volume.get("Driver") != "local"
            or not isinstance(labels, dict)
            or labels.get(OWNER) != "true"
            or volume.get("Mountpoint") != selected[0].get("Source")
        ):
            raise ValueError("isolated evidence volume owner or source differs")
        # Prove that this process sees the actual actor's mount, rather than a
        # same-named local directory. The probe only stats the mount root.
        mount = self.root.parent
        directory(mount)
        if self.root.exists() or self.root.is_symlink():
            directory(self.root)
        reserved = self.root / "reservations"
        if reserved.exists() or reserved.is_symlink():
            directory(reserved)
        probe = (
            "import json,os,sys;s=os.stat(sys.argv[1],follow_symlinks=False);"
            "print(json.dumps([s.st_dev,s.st_ino,s.st_uid]))"
        )
        observed = json.loads(
            self.docker.command(
                "exec",
                self.actor_id,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                probe,
                str(mount),
                timeout=30,
            )
        )
        local = mount.stat(follow_symlinks=False)
        if observed != [local.st_dev, local.st_ino, os.geteuid()] or local.st_uid != os.geteuid():
            raise ValueError("isolated evidence path is not the actor's actual mount")

    def consume(self, manifest: Manifest, value: dict[str, object]) -> None:
        self.require()
        self.fence.require(manifest)
        # O_EXCL and fsync are on the verified persistent volume, under the
        # still-held daemon-wide fence. Never use Connect titles as a CAS.
        payload = {
            "manifest_sha256": manifest.sha256,
            "admission": self.fence.ticket,
            "reservation": value,
            "actor_id": self.actor_id,
        }
        from scripts.m3_11_qualification_evidence import canonical_bytes  # noqa: PLC0415

        descriptor = os.open(self.reservations, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            named = self.reservations.stat(follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ValueError("isolated persistent reservation directory changed")
            fd = os.open(
                manifest.plan.run_id + ".json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=descriptor,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical_bytes(payload))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(descriptor)
            current = self.reservations.stat(follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("isolated persistent reservation directory changed after write")
        finally:
            os.close(descriptor)

    def require_consumed(self, manifest: Manifest) -> dict[str, object]:
        self.require()
        self.fence.require(manifest)
        value = read_private(self.reservations / (manifest.plan.run_id + ".json"))
        if (
            value.get("manifest_sha256") != manifest.sha256
            or value.get("admission") != self.fence.ticket
        ):
            raise ValueError("isolated persistent reservation differs")
        return value

    def retain_ticket(self) -> None:
        self.require()
        record(
            self.root / (str(self.fence.ticket["run_id"]) + ".admission.json"), self.fence.ticket
        )
