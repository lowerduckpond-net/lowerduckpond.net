"""Original local container fencing and bounded copies of stopped ext4 images."""

from __future__ import annotations

import io
import json
import tarfile
import time
from collections.abc import Buffer, Iterator
from pathlib import Path
from typing import cast

import docker  # type: ignore[import-untyped]

from scripts import qualification_restore as owned
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_context import Context
from scripts.m3_11_retirement_files import (
    CHUNK,
    RetirementError,
    digest,
    fingerprint,
    preserve,
    record,
)
from scripts.m3_11_retirement_minio import observe as observe_minio
from scripts.qualification_context import HOST_ENV, RUN_ENV
from scripts.qualification_probe import bounded_command, document
from scripts.qualification_retirement import incarnation, snapshot

IMAGE_BYTES = 8 * 1024 * 1024 * 1024
IMAGE_PATHS = {
    "source": "/var/lib/lowerduckpond-m3-8-disks/state.ext4",
    "destination": "/root/restore-disks/var-lib.ext4",
}
IDENTITY = ("id", "name", "owner", "image")


class Stream(io.RawIOBase):
    def __init__(self, values: Iterator[bytes]) -> None:
        self.values = values
        self.pending = bytearray()
        self.deadline = time.monotonic() + 900

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Buffer) -> int:
        target = memoryview(buffer)
        if time.monotonic() > self.deadline:
            raise TimeoutError("state image copy exceeded its deadline")
        if not self.pending:
            self.pending.extend(next(self.values, b""))
        size = min(len(target), len(self.pending))
        target[:size] = self.pending[:size]
        del self.pending[:size]
        return size


class LiveReader:
    def __init__(self, environment: dict[str, str], identity: str) -> None:
        self.environment, self.identity = environment, identity

    def _command(self, action: str, path: str) -> bytes:
        raw = bounded_command(
            [
                "docker",
                "exec",
                "-i",
                self.identity,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-",
                action,
                path,
            ],
            environment=self.environment,
            timeout=20,
            maximum=1024 * 1024,
            stdin=Path(__file__).with_name("m3_11_retirement_probe.py").read_bytes(),
        )
        if raw is None:
            raise RetirementError("retirement private state observation failed")
        return raw

    def read(self, path: str) -> bytes:
        return self._command("read", path)

    def names(self, path: str) -> dict[str, str]:
        value = json.loads(self._command("names", path))
        if not isinstance(value, dict) or any(
            not isinstance(key, str) or kind not in {"directory", "regular", "unsafe"}
            for key, kind in value.items()
        ):
            raise RetirementError("invalid retirement state inventory")
        return value


class Containers:
    def __init__(self, context: Context) -> None:
        self.context = context
        self.environment = context.environment
        self.api = docker.APIClient(base_url=self.environment["DOCKER_HOST"], timeout=20)

    def expected(self) -> dict[str, dict[str, object]]:
        result = {
            kind: {
                key: document(self.context.run / f"restore/{kind}.json")[key] for key in IDENTITY
            }
            for kind in ("source", "destination", "acme")
        }
        for kind in ("source", "destination"):
            if digest(result[kind]) != self.context.context[kind + "_fixture_sha256"]:
                raise RetirementError("retirement host identity differs from the original capture")
        names = {
            "source": self.environment[HOST_ENV],
            "destination": f"ldp-m3-{self.environment[RUN_ENV]}-destination",
            "acme": f"ldp-m3-{self.environment[RUN_ENV]}-acme",
        }
        if len({row["id"] for row in result.values()}) != len(names) or any(
            row["name"] != "/" + names[kind] or row["owner"] != self.environment[RUN_ENV]
            for kind, row in result.items()
        ):
            raise RetirementError("retirement container identities are mixed")
        return result

    def state(self, expected: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
        result = {}
        for kind, row in expected.items():
            identity = str(row["id"])
            current = owned.inspect(self.environment, identity)
            if any(current[key] != row[key] for key in IDENTITY):
                raise RetirementError("retirement container ownership changed")
            value = self.api.inspect_container(identity)
            if value["HostConfig"]["RestartPolicy"].get("Name") not in {"", "no"}:
                raise RetirementError("retirement writer has an automatic restart policy")
            result[kind] = snapshot(self.environment, identity)
        return result

    def image_metadata(self, expected: dict[str, dict[str, object]]) -> dict[str, object]:
        return {
            kind: json.loads(
                LiveReader(self.environment, str(expected[kind]["id"]))._command("image", path)
            )
            for kind, path in IMAGE_PATHS.items()
        }

    def freeze(self, root: Path, intent: dict[str, object]) -> None:
        expected = cast(dict[str, dict[str, object]], intent["containers"])
        before = cast(dict[str, dict[str, object]], intent["states"])
        for kind in ("destination", "source", "acme"):
            current = self.state(expected)
            if any(incarnation(current[name]) != incarnation(before[name]) for name in expected):
                raise RetirementError("retirement container restarted")
            step: dict[str, object] = {
                "identity": expected[kind],
                "incarnation": incarnation(before[kind]),
            }
            path = root / ("stop-" + kind + ".json")
            if not current[kind]["running"]:
                if read_private(path) != step:
                    raise RetirementError("container stopped without retirement authorization")
                continue
            if kind in IMAGE_PATHS:
                image = json.loads(
                    LiveReader(self.environment, str(expected[kind]["id"]))._command(
                        "image", IMAGE_PATHS[kind]
                    )
                )
                if image != cast(dict[str, object], intent["backing_images"])[kind]:
                    raise RetirementError("state backing image changed before stopping")
            record(path, step)
            owned.command(
                self.environment,
                "docker",
                "stop",
                "--time",
                "60",
                str(expected[kind]["id"]),
                timeout=75,
            )
            after = self.state(expected)
            if after[kind]["running"] or incarnation(after[kind]) != incarnation(before[kind]):
                raise RetirementError("retirement writer did not stop unchanged")

    def stopped(self, intent: dict[str, object]) -> None:
        expected = cast(dict[str, dict[str, object]], intent["containers"])
        current = self.state(expected)
        before = cast(dict[str, dict[str, object]], intent["states"])
        if any(
            row["running"] or incarnation(row) != incarnation(before[kind])
            for kind, row in current.items()
        ):
            raise RetirementError("retirement writer restarted or is running")

    def copy(self, root: Path, intent: dict[str, object], kind: str) -> dict[str, object]:
        self.stopped(intent)
        expected = cast(dict[str, dict[str, object]], intent["containers"])
        original = cast(dict[str, dict[str, object]], intent["backing_images"])[kind]
        path = root / (kind + ".ext4")
        receipt = root / (kind + "-image.json")
        if receipt.exists():
            value = read_private(receipt)
            if value.get("bytes") != fingerprint(path, IMAGE_BYTES):
                raise RetirementError("frozen state image changed")
            return value
        stream, metadata = self.api.get_archive(
            expected[kind]["id"], IMAGE_PATHS[kind], chunk_size=CHUNK
        )
        if (
            metadata.get("size") != IMAGE_BYTES
            or metadata.get("linkTarget")
            or metadata.get("name") != Path(IMAGE_PATHS[kind]).name
        ):
            raise RetirementError("state backing image metadata is invalid")
        with (
            Stream(iter(stream)) as source,
            tarfile.open(fileobj=source, mode="r|") as archive,
        ):
            member = archive.next()
            if (
                member is None
                or not member.isfile()
                or member.size != IMAGE_BYTES
                or member.uid != 0
                or member.name != metadata["name"]
                or member.mode != original["mode"]
            ):
                raise RetirementError("state backing image is not one root-owned regular file")
            body = archive.extractfile(member)
            if body is None:
                raise RetirementError("state backing image content is unavailable")
            with body:

                def chunks() -> Iterator[bytes]:
                    while data := body.read(CHUNK):
                        yield data

                saved = preserve(path, chunks(), IMAGE_BYTES)
            if archive.next() is not None:
                raise RetirementError("state image copy contains unrelated entries")
        self.stopped(intent)
        value = {"container": expected[kind], "source_metadata": metadata, "bytes": saved}
        record(receipt, value)
        return value

    def unused_minio(self) -> dict[str, object]:
        return observe_minio(self.context, self.api)
