"""Full-size deployment fixture built through the supported operator lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
import zipfile
from io import BytesIO
from pathlib import Path

import test_lifecycle as support
from lowerduckpond_static_contracts import MAX_DEPLOY_ARTIFACT_BYTES
from testinfra.host import Host

CONTENT_BYTES = 100 * 1024 * 1024
ENTRY_COUNT = 5_000
FILE_BYTES = 4 * 1024 * 1024
INDEX = b"full-size installed M3.9 content\n"
WORKER_MEMORY_BYTES = 256 * 1024 * 1024


def deployment() -> bytes:
    stream = BytesIO()
    remaining = CONTENT_BYTES - len(INDEX)
    with zipfile.ZipFile(stream, mode="w") as archive:
        for index in range(ENTRY_COUNT):
            name = "index.html" if index == 0 else f"file-{index:04d}.bin"
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            if index == 0:
                content = INDEX
            else:
                size = min(remaining, FILE_BYTES)
                # Moderate compression fills the complete content quota while
                # leaving room for ZIP metadata in the bounded upload envelope.
                random_bytes = size // 2
                content = os.urandom(random_bytes) + bytes(size - random_bytes)
            archive.writestr(member, content)
            if index != 0:
                remaining -= len(content)
    assert remaining == 0
    payload = stream.getvalue()
    assert len(payload) <= MAX_DEPLOY_ARTIFACT_BYTES
    return payload


def assert_worker_budget(host: Host, result: dict[str, object]) -> None:
    provenance = result["provenance"]
    assert isinstance(provenance, dict)
    job_id = str(provenance["jobId"])
    unit = f"lowerduckpond-static-worker@{job_id}.service"
    checked = host.run(
        "/usr/bin/systemctl show --property=Result --property=MemoryMax "
        "--property=MemorySwapMax --property=LimitCPU --property=CPUQuotaPerSecUSec %s",
        unit,
    )
    assert checked.rc == 0, checked.stderr
    properties = dict(line.split("=", 1) for line in checked.stdout.splitlines())
    assert properties["Result"] == "success"
    assert int(properties["MemoryMax"]) == WORKER_MEMORY_BYTES
    assert properties["MemorySwapMax"] == "0"
    assert properties["LimitCPU"] == "120"
    assert properties["CPUQuotaPerSecUSec"] == "1s"


def _digest_rows(rows: list[tuple[str, int, str]]) -> str:
    encoded = json.dumps(sorted(rows), separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def content_digest(payload: bytes) -> str:
    with zipfile.ZipFile(BytesIO(payload)) as archive:
        rows = [
            (item.filename, item.file_size, hashlib.sha256(archive.read(item)).hexdigest())
            for item in archive.infolist()
        ]
    return _digest_rows(rows)


def installed_digest(host: Host, tenant: str, deployment_id: str) -> str:
    root = f"{support.RELEASE_ROOT}/{tenant}/releases/{deployment_id}"
    outcome = host.run(
        "/usr/bin/python3 -I -B -c %s",
        f"""
import hashlib, json
from pathlib import Path
root = Path({root!r})
rows = []
for path in root.rglob('*'):
    assert not path.is_symlink()
    if path.is_file():
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        rows.append((path.relative_to(root).as_posix(), path.stat().st_size, digest))
assert len(rows) == {ENTRY_COUNT}
assert sum(row[1] for row in rows) == {CONTENT_BYTES}
encoded = json.dumps(sorted(rows), separators=(',', ':')).encode('ascii')
print(hashlib.sha256(encoded).hexdigest())
""",
    )
    assert outcome.rc == 0, outcome.stderr
    return outcome.stdout.strip()


def create(
    host: Host, tmp_path: Path, connection: tuple[str, Path, Path], *, slug: str
) -> tuple[dict[str, object], str]:
    operator, identity, ssh = connection
    created = support._submit(
        tmp_path,
        operator,
        identity,
        ssh,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=slug,
            quotas={"storageMiB": 100, "entries": ENTRY_COUNT},
        ),
    )
    assert created["status"] == "succeeded"
    tenant = str(created["tenantId"])
    payload = deployment()
    expected = content_digest(payload)
    deployed = support._submit(
        tmp_path,
        operator,
        identity,
        ssh,
        support._request("deploy", str(uuid.uuid7()), tenantId=tenant),
        artifact=payload,
    )
    assert deployed["status"] == "succeeded"
    support._assert_route(host, str(deployed["canonicalOrigin"]), status=200, body=INDEX)
    assert_worker_budget(host, deployed)
    assert installed_digest(host, tenant, support._desired_deployment(deployed)) == expected
    return deployed, expected
