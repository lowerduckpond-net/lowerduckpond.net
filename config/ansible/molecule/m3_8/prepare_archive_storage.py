"""Configure only the pinned disposable MinIO fixture, preserving existing object bytes."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import time
from pathlib import Path

_IMAGE = (
    "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
)
_ROOT_USER = "molecule-m3-10-root"
_ROOT_SECRET = "molecule-m3-10-disposable-root-secret"  # noqa: S105 - gitleaks:allow - disposable fixture
_ARCHIVE_USER = "molecule-m3-10-archive"
_ARCHIVE_SECRET = "molecule-m3-10-disposable-archive-secret"  # noqa: S105 - disposable fixture
_BACKUP_USER = "molecule-m3-10-backup"
_BACKUP_SECRET = "molecule-m3-10-disposable-backup-secret"  # noqa: S105 - disposable fixture
_ARCHIVE_BUCKET = "molecule-tenant-archives"
_BACKUP_BUCKET = "molecule-platform-backup"
_ARGUMENT_COUNT = 2
_READY_ATTEMPTS = 100


def _run(arguments: list[str]) -> str:
    return subprocess.run(  # noqa: S603 - fixed commands and fixture paths
        arguments, check=True, capture_output=True, text=True, timeout=60
    ).stdout.strip()


def _certificates(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (root / "public.crt").is_file():
        _run(["openssl", "x509", "-in", str(root / "public.crt"), "-checkend", "3600", "-noout"])
        return
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "7",
            "-subj",
            "/CN=M3.10 disposable archive CA",
            "-keyout",
            str(root / "ca.key"),
            "-out",
            str(root / "ca.crt"),
        ]
    )
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=ams3.digitaloceanspaces.com",
            "-addext",
            "subjectAltName=DNS:ams3.digitaloceanspaces.com,IP:127.0.0.1",
            "-keyout",
            str(root / "private.key"),
            "-out",
            str(root / "server.csr"),
        ]
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(root / "server.csr"),
            "-CA",
            str(root / "ca.crt"),
            "-CAkey",
            str(root / "ca.key"),
            "-CAcreateserial",
            "-copy_extensions",
            "copy",
            "-days",
            "7",
            "-out",
            str(root / "public.crt"),
        ]
    )
    for name in ("ca.key", "private.key"):
        (root / name).chmod(0o600)


def prepare(container: str, root: Path) -> dict[str, str]:
    inspection = json.loads(_run(["docker", "inspect", container]))[0]
    if (
        inspection["Config"]["Image"] != _IMAGE
        or f"MINIO_ROOT_USER={_ROOT_USER}" not in inspection["Config"]["Env"]
    ):
        raise RuntimeError("archive fixture is not the expected disposable MinIO instance")
    addresses = {
        network["IPAddress"]
        for network in inspection["NetworkSettings"]["Networks"].values()
        if network["IPAddress"]
    }
    if len(addresses) != 1:
        raise RuntimeError("disposable archive endpoint is ambiguous")
    address = ipaddress.ip_address(addresses.pop()).compressed
    _certificates(root)
    exec_prefix = ["docker", "exec", container]
    _run([*exec_prefix, "mkdir", "-p", "/certs", "/root/.mc/certs/CAs", "/fixtures"])
    certificate = subprocess.run(  # noqa: S603 - fixed fixture command
        [*exec_prefix, "cat", "/certs/public.crt"], check=False, capture_output=True, timeout=30
    ).stdout
    if certificate != (root / "public.crt").read_bytes():
        for name in ("public.crt", "private.key"):
            _run(["docker", "cp", str(root / name), f"{container}:/certs/{name}"])
        _run(["docker", "restart", "--timeout", "10", container])
    _run(["docker", "cp", str(root / "ca.crt"), f"{container}:/root/.mc/certs/CAs/m3-10.crt"])
    client = [*exec_prefix, "mc", "--config-dir", "/root/.mc", "--quiet", "--no-color"]
    for _ in range(_READY_ATTEMPTS):
        probe = subprocess.run(  # noqa: S603 - dedicated disposable credentials only
            [*client, "alias", "set", "m310", "https://127.0.0.1", _ROOT_USER, _ROOT_SECRET],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if probe.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("TLS archive fixture did not become ready")
    archive_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:ListBucketVersions",
                    "s3:ListBucketMultipartUploads",
                ],
                "Resource": [f"arn:aws:s3:::{_ARCHIVE_BUCKET}"],
            },
            {
                "Effect": "Allow",
                # This pinned MinIO authorizes version deletion through DeleteObject
                # as well (cmd/auth-handler.go:authorizeRequest). This fixture-only
                # permission does not change the production Spaces credential policy.
                "Action": [
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                ],
                "Resource": [f"arn:aws:s3:::{_ARCHIVE_BUCKET}/archives/*"],
            },
        ],
    }
    backup_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*"],
                "Resource": [f"arn:aws:s3:::{_BACKUP_BUCKET}", f"arn:aws:s3:::{_BACKUP_BUCKET}/*"],
            }
        ],
    }
    for bucket in (_ARCHIVE_BUCKET, _BACKUP_BUCKET):
        _run([*client, "mb", "--ignore-existing", f"m310/{bucket}"])
        _run([*client, "version", "enable", f"m310/{bucket}"])
    for name, user, secret, policy in (
        ("m310archive", _ARCHIVE_USER, _ARCHIVE_SECRET, archive_policy),
        ("m310backup", _BACKUP_USER, _BACKUP_SECRET, backup_policy),
    ):
        policy_path = root / f"{name}.json"
        policy_path.write_text(json.dumps(policy), encoding="ascii")
        _run(["docker", "cp", str(policy_path), f"{container}:/fixtures/{name}.json"])
        _run([*client, "admin", "user", "add", "m310", user, secret])
        _run([*client, "admin", "policy", "create", "m310", name, f"/fixtures/{name}.json"])
        _run([*client, "admin", "policy", "attach", "m310", name, "--user", user])
    return {"address": address, "caCertificate": str((root / "ca.crt").resolve())}


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != _ARGUMENT_COUNT:
        raise SystemExit(
            "usage: prepare_archive_storage.py MINIO_CONTAINER PRIVATE_CERTIFICATE_DIRECTORY"
        )
    print(json.dumps(prepare(values[0], Path(values[1])), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
