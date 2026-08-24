"""Command-line entry point for M3.0 qualification."""

from __future__ import annotations

import argparse
import asyncio
import os
from collections.abc import Sequence
from pathlib import Path

from lowerduckpond_m3_qualification.report import (
    QualificationReport,
    UnsafeReportError,
    combine_reports,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    libraries = subparsers.add_parser("libraries", help="qualify pinned Python libraries")
    libraries.add_argument("--output", required=True, type=Path)

    filesystem = subparsers.add_parser("filesystem", help="qualify real filesystem behavior")
    filesystem.add_argument("--work-root", required=True, type=Path)
    filesystem.add_argument("--expected-filesystem", default="ext4")
    filesystem.add_argument("--output", required=True, type=Path)

    browser = subparsers.add_parser("browser", help="run mandatory live browser checks")
    browser.add_argument("--platform-origin", required=True)
    browser.add_argument("--tenant-alias-origin", required=True)
    browser.add_argument("--tenant-immutable-origin", required=True)
    browser.add_argument("--tenant-unknown-origin", required=True)
    browser.add_argument("--output", required=True, type=Path)

    host = subparsers.add_parser("host", help="run privileged disposable-host checks")
    host.add_argument("--work-root", default=Path("/var/lib/lowerduckpond-m3"), type=Path)
    host.add_argument("--output", required=True, type=Path)

    domains = subparsers.add_parser("domains", help="qualify domain control and delegation")
    domains.add_argument("--attestation", required=True, type=Path)
    domains.add_argument("--net-zone-id", required=True)
    domains.add_argument("--com-zone-id", required=True)
    domains.add_argument("--output", required=True, type=Path)

    assemble = subparsers.add_parser("assemble", help="assemble exact report fragments")
    assemble.add_argument("--fragment", action="append", required=True, type=Path)
    assemble.add_argument("--required-check", action="append")
    assemble.add_argument("--require-m3", action="store_true")
    assemble.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "libraries":
        from lowerduckpond_m3_qualification.libraries import run_library_checks

        report = QualificationReport.create(environment="hermetic-ci", checks=run_library_checks())
    elif arguments.command == "filesystem":
        from lowerduckpond_m3_qualification.filesystem import run_filesystem_checks

        report = QualificationReport.create(
            environment="ubuntu-26.04-disposable",
            checks=run_filesystem_checks(
                work_root=arguments.work_root,
                expected_filesystem=arguments.expected_filesystem,
            ),
        )
    elif arguments.command == "browser":
        from lowerduckpond_m3_qualification.browser import BrowserOrigins, run_browser_checks

        try:
            origins = BrowserOrigins(
                platform=arguments.platform_origin,
                tenant_alias=arguments.tenant_alias_origin,
                tenant_immutable=arguments.tenant_immutable_origin,
                tenant_unknown=arguments.tenant_unknown_origin,
            )
        except ValueError:
            return 2
        report = QualificationReport.create(
            environment="live-dual-domain",
            checks=asyncio.run(run_browser_checks(origins)),
        )
    elif arguments.command == "host":
        from lowerduckpond_m3_qualification.host import run_host_checks

        if not hasattr(arguments, "work_root"):
            return 2
        report = QualificationReport.create(
            environment="ubuntu-26.04-disposable",
            checks=run_host_checks(work_root=arguments.work_root),
        )
    elif arguments.command == "domains":
        from lowerduckpond_m3_qualification.domains import run_domain_checks

        report = QualificationReport.create(
            environment="operator-and-cloudflare",
            checks=run_domain_checks(
                attestation_path=arguments.attestation,
                zone_ids={
                    "lowerduckpond.net": arguments.net_zone_id,
                    "lowerduckpond.com": arguments.com_zone_id,
                },
                api_token=os.environ.get("M3_QUALIFICATION_CLOUDFLARE_API_TOKEN", ""),
            ),
        )
    else:
        from lowerduckpond_m3_qualification.checks import M3_REQUIRED_CHECK_IDS

        try:
            fragments = tuple(
                QualificationReport.from_json(path.read_text(encoding="utf-8"))
                for path in arguments.fragment
            )
            report = combine_reports(
                fragments,
                required_check_ids=(
                    M3_REQUIRED_CHECK_IDS
                    if arguments.require_m3
                    else frozenset(arguments.required_check or ())
                ),
            )
        except OSError, ValueError, UnsafeReportError:
            return 2
    report.write(arguments.output)
    return 0 if report.passed else 1
