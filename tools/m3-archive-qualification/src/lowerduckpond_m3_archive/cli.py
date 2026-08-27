"""Command-line entry point for the M3.1 archive storage gates."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from lowerduckpond_m3_archive.report import (
    ArchiveQualificationReport,
    UnsafeArchiveReportError,
)
from lowerduckpond_m3_archive.storage import (
    ArchiveQualificationError,
    assert_storage_empty,
    create_client,
    run_acceptance,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser(
        "preflight", help="prove an existing bucket prefix has no S3 accounting state"
    )
    preflight.add_argument("--bucket", required=True)
    preflight.add_argument("--prefix", default="archives/")
    _add_endpoint_arguments(preflight)

    acceptance = subparsers.add_parser(
        "acceptance", help="run mutual-denial and version-lifecycle acceptance"
    )
    acceptance.add_argument("--backup-bucket", required=True)
    acceptance.add_argument("--archive-bucket", required=True)
    acceptance.add_argument("--source-revision", required=True)
    acceptance.add_argument("--output", required=True, type=Path)
    _add_endpoint_arguments(acceptance)

    verify = subparsers.add_parser("verify-report", help="validate a sanitized report")
    verify.add_argument("report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "verify-report":
            ArchiveQualificationReport.from_json(arguments.report.read_text(encoding="utf-8"))
            print("Sanitized M3.1 archive qualification report is valid.")
            return 0
        endpoint_url = arguments.endpoint_url or (
            f"https://{arguments.region}.digitaloceanspaces.com"
        )
        if arguments.command == "preflight":
            client = create_client(
                access_key_id=_required_environment("SPACES_ACCESS_KEY_ID"),
                secret_access_key=_required_environment("SPACES_SECRET_ACCESS_KEY"),
                region=arguments.region,
                endpoint_url=endpoint_url,
            )
            assert_storage_empty(client, bucket=arguments.bucket, prefix=arguments.prefix)
            print("Archive-prefix preflight proved version-aware and multipart-aware absence.")
            return 0
        backup_client = create_client(
            access_key_id=_required_environment("SPACES_BACKUP_ACCESS_KEY_ID"),
            secret_access_key=_required_environment("SPACES_BACKUP_SECRET_ACCESS_KEY"),
            region=arguments.region,
            endpoint_url=endpoint_url,
        )
        archive_client = create_client(
            access_key_id=_required_environment("SPACES_ARCHIVE_ACCESS_KEY_ID"),
            secret_access_key=_required_environment("SPACES_ARCHIVE_SECRET_ACCESS_KEY"),
            region=arguments.region,
            endpoint_url=endpoint_url,
        )
        evidence = run_acceptance(
            backup_client=backup_client,
            archive_client=archive_client,
            backup_bucket=arguments.backup_bucket,
            archive_bucket=arguments.archive_bucket,
        )
        report = ArchiveQualificationReport.create(
            evidence, source_revision=arguments.source_revision
        )
        report.write(arguments.output)
        print("M3.1 archive storage acceptance passed and wrote sanitized evidence.")
        return 0
    except (ArchiveQualificationError, UnsafeArchiveReportError) as error:
        print(f"M3.1 archive storage gate failed closed: {error}", file=sys.stderr)
        return 1
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "unknown")
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown")
        print(
            f"M3.1 archive storage gate failed closed: remote S3 error {code}/{status}.",
            file=sys.stderr,
        )
        return 1
    except (BotoCoreError, OSError, ValueError) as error:
        print(f"M3.1 archive storage gate failed closed ({type(error).__name__}).", file=sys.stderr)
        return 1


def _add_endpoint_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--region", default="nyc3")
    parser.add_argument("--endpoint-url")


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ArchiveQualificationError(f"required environment variable {name} is missing")
    return value
