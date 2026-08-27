"""Command-line entry point for M3.0 qualification."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.report import (
    CheckResult,
    QualificationReport,
    UnsafeReportError,
    combine_reports,
)

FRAGMENT_LABELS: Final = frozenset(
    {
        "libraries",
        "host",
        "domains",
        "browser",
        "edge-primary",
        "edge-replacement",
        "edge-rollback",
        "edge-forward",
        "edge-retired-primary",
        "edge-final",
        "assembled",
    }
)
FRAGMENT_ARGUMENT_PATTERN: Final = re.compile(r"^([a-z-]+)=(.+)$")


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    begin_session = subparsers.add_parser("begin-session", help="bind a new live run to stdin")
    begin_session.add_argument("--source-revision", required=True)
    begin_session.add_argument("--output", required=True, type=Path)

    verify_session = subparsers.add_parser("verify-session", help="verify a live run against stdin")
    verify_session.add_argument("--session", required=True, type=Path)
    verify_session.add_argument("--source-revision", required=True)

    verify_convergence = subparsers.add_parser(
        "verify-convergence", help="verify host convergence from stdin"
    )
    verify_convergence.add_argument("--session", required=True, type=Path)
    verify_convergence.add_argument("--trust-stage", required=True, choices=("dual", "replacement"))

    session_value = subparsers.add_parser("session-value", help="read one validated session value")
    session_value.add_argument("--session", required=True, type=Path)
    session_value.add_argument(
        "--field",
        required=True,
        choices=("run_id", "source_revision", "droplet_id", "droplet_urn", "ipv4_address"),
    )

    report_status = subparsers.add_parser(
        "report-status", help="summarize validated local evidence without mutation"
    )
    report_status.add_argument("--session", required=True, type=Path)
    report_status.add_argument("--source-revision", required=True)
    report_status.add_argument("--fragment", action="append", default=[])

    libraries = subparsers.add_parser("libraries", help="qualify pinned Python libraries")
    _add_run_arguments(libraries)
    libraries.add_argument("--output", required=True, type=Path)

    filesystem = subparsers.add_parser("filesystem", help="qualify real filesystem behavior")
    _add_run_arguments(filesystem)
    filesystem.add_argument("--work-root", required=True, type=Path)
    filesystem.add_argument("--expected-filesystem", default="ext4")
    filesystem.add_argument("--output", required=True, type=Path)

    browser = subparsers.add_parser("browser", help="run mandatory live browser checks")
    _add_run_arguments(browser)
    browser.add_argument("--platform-origin", required=True)
    browser.add_argument("--tenant-alias-origin", required=True)
    browser.add_argument("--tenant-immutable-origin", required=True)
    browser.add_argument("--tenant-unknown-origin", required=True)
    browser.add_argument("--ws-endpoint")
    browser.add_argument("--ignore-https-errors", action="store_true")
    browser.add_argument("--output", required=True, type=Path)

    host = subparsers.add_parser("host", help="run privileged disposable-host checks")
    _add_run_arguments(host)
    host.add_argument("--work-root", default=Path("/var/lib/lowerduckpond-m3"), type=Path)
    host.add_argument("--trust-stage", required=True, choices=("dual", "replacement"))
    host.add_argument("--output", required=True, type=Path)

    domains = subparsers.add_parser("domains", help="qualify domain control and delegation")
    _add_run_arguments(domains)
    domains.add_argument("--attestation", required=True, type=Path)
    domains.add_argument("--net-zone-id", required=True)
    domains.add_argument("--com-zone-id", required=True)
    domains.add_argument("--output", required=True, type=Path)

    edge_preflight = subparsers.add_parser(
        "edge-preflight", help="qualify Cloudflare account capabilities before provisioning"
    )
    edge_preflight.add_argument("--certificate-ids", required=True, type=Path)
    edge_preflight.add_argument("--net-zone-id", required=True)
    edge_preflight.add_argument("--com-zone-id", required=True)
    edge_preflight.add_argument("--primary-ca", required=True, type=Path)
    edge_preflight.add_argument("--replacement-ca", required=True, type=Path)

    edge = subparsers.add_parser("edge", help="run one reviewed Cloudflare edge stage")
    _add_run_arguments(edge)
    edge.add_argument(
        "--stage",
        required=True,
        choices=("primary", "replacement", "rollback", "forward", "retired-primary", "final"),
    )
    edge.add_argument("--origin-ipv4", required=True)
    edge.add_argument("--certificate-ids", required=True, type=Path)
    edge.add_argument("--net-zone-id", required=True)
    edge.add_argument("--com-zone-id", required=True)
    edge.add_argument("--output", required=True, type=Path)

    assemble = subparsers.add_parser("assemble", help="assemble exact report fragments")
    assemble.add_argument("--fragment", action="append", required=True, type=Path)
    assemble.add_argument("--required-check", action="append")
    assemble.add_argument("--require-m3", action="store_true")
    assemble.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911,PLR0912
    arguments = build_parser().parse_args(argv)
    if arguments.command == "edge-preflight":
        from lowerduckpond_m3_qualification.edge import (
            EdgeQualificationError,
            load_certificate_ids,
            run_preflight,
        )

        try:
            run_preflight(
                zone_ids={
                    "lowerduckpond_net": arguments.net_zone_id,
                    "lowerduckpond_com": arguments.com_zone_id,
                },
                certificate_ids=load_certificate_ids(arguments.certificate_ids),
                ca_paths={
                    "primary": arguments.primary_ca,
                    "replacement": arguments.replacement_ca,
                },
                api_token=os.environ.get("M3_QUALIFICATION_CLOUDFLARE_API_TOKEN", ""),
            )
        except OSError, ValueError, EdgeQualificationError:
            print("M3.0 edge preflight failed closed.", file=sys.stderr)
            return 1
        print("M3.0 edge preflight passed without changing Cloudflare state.")
        return 0
    if arguments.command in {
        "begin-session",
        "verify-session",
        "verify-convergence",
        "session-value",
    }:
        return _handle_session_command(arguments)
    if arguments.command == "report-status":
        return _report_status(
            session_path=arguments.session,
            source_revision=arguments.source_revision,
            fragments=tuple(arguments.fragment),
        )
    if arguments.command == "libraries":
        from lowerduckpond_m3_qualification.libraries import run_library_checks

        report = _create_report(arguments, environment="hermetic-ci", checks=run_library_checks())
    elif arguments.command == "filesystem":
        from lowerduckpond_m3_qualification.filesystem import run_filesystem_checks

        report = _create_report(
            arguments,
            environment="ubuntu-26.04-disposable",
            checks=run_filesystem_checks(
                work_root=arguments.work_root,
                expected_filesystem=arguments.expected_filesystem,
            ),
        )
    elif arguments.command == "browser":
        from lowerduckpond_m3_qualification.browser import (
            BrowserOrigins,
            run_browser_checks,
            validate_browser_endpoint,
        )

        try:
            origins = BrowserOrigins(
                platform=arguments.platform_origin,
                tenant_alias=arguments.tenant_alias_origin,
                tenant_immutable=arguments.tenant_immutable_origin,
                tenant_unknown=arguments.tenant_unknown_origin,
            )
            ws_endpoint = (
                validate_browser_endpoint(arguments.ws_endpoint)
                if arguments.ws_endpoint is not None
                else None
            )
        except ValueError:
            return 2
        report = _create_report(
            arguments,
            environment="live-dual-domain",
            checks=asyncio.run(
                run_browser_checks(
                    origins,
                    ws_endpoint=ws_endpoint,
                    ignore_https_errors=arguments.ignore_https_errors,
                )
            ),
        )
    elif arguments.command == "host":
        from lowerduckpond_m3_qualification.host import run_host_checks

        if not hasattr(arguments, "work_root"):
            return 2
        report = _create_report(
            arguments,
            environment="ubuntu-26.04-disposable",
            checks=run_host_checks(
                work_root=arguments.work_root,
                expected_generation=f"{arguments.run_id}-{arguments.trust_stage}",
            ),
        )
    elif arguments.command == "domains":
        from lowerduckpond_m3_qualification.domains import run_domain_checks

        report = _create_report(
            arguments,
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
    elif arguments.command == "edge":
        from lowerduckpond_m3_qualification.edge import (
            FINAL_EDGE_SUFFIXES,
            EdgeInputs,
            EdgeQualificationError,
            load_certificate_ids,
            run_rollover_stage,
        )

        try:
            edge_inputs = EdgeInputs(
                origin_ipv4=arguments.origin_ipv4,
                zone_ids={
                    "lowerduckpond_net": arguments.net_zone_id,
                    "lowerduckpond_com": arguments.com_zone_id,
                },
                certificate_ids=load_certificate_ids(arguments.certificate_ids),
                api_token=os.environ.get("M3_QUALIFICATION_CLOUDFLARE_API_TOKEN", ""),
                ssh_target=f"ldp-admin@{arguments.origin_ipv4}",
            )
            checks = run_rollover_stage(edge_inputs, stage=arguments.stage)
        except OSError, ValueError, EdgeQualificationError, subprocess.SubprocessError:
            identifiers = [f"m3.0.edge.aop-{arguments.stage}"]
            if arguments.stage == "final":
                identifiers.extend(f"m3.0.edge.{suffix}" for suffix in FINAL_EDGE_SUFFIXES)
            checks = tuple(
                CheckResult(
                    check_id=check_id,
                    status="failed",
                    evidence={},
                    error_code="probe_failed",
                )
                for check_id in identifiers
            )
        report = _create_report(
            arguments,
            environment="live-cloudflare-edge",
            checks=checks,
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


def _handle_session_command(arguments: argparse.Namespace) -> int:
    from lowerduckpond_m3_qualification.session import QualificationSession

    try:
        if arguments.command == "begin-session":
            session = QualificationSession.create(
                identity=json.load(sys.stdin),
                source_revision=arguments.source_revision,
            )
            session.write(arguments.output)
        else:
            session = QualificationSession.read(arguments.session)
            if arguments.command == "verify-session":
                session.verify(
                    identity=json.load(sys.stdin),
                    source_revision=arguments.source_revision,
                )
            elif arguments.command == "verify-convergence":
                session.verify_convergence_marker(
                    sys.stdin.read(), trust_stage=arguments.trust_stage
                )
            else:
                print(getattr(session, arguments.field))
    except OSError, ValueError, json.JSONDecodeError:
        return 2
    return 0


def _report_status(*, session_path: Path, source_revision: str, fragments: tuple[str, ...]) -> int:
    """Print only validated identities, labels, check IDs, and status words."""
    from lowerduckpond_m3_qualification.session import (
        QualificationSession,
        UnsafeSessionError,
    )

    try:
        session = QualificationSession.read(session_path)
        if session.source_revision != source_revision:
            raise UnsafeSessionError("source revision changed")
    except OSError, ValueError, UnsafeSessionError:
        print("session: invalid-or-stale")
        return 2
    print(f"session: active {session.run_id} {session.source_revision}")

    next_action: str | None = None
    for raw in fragments:
        match = FRAGMENT_ARGUMENT_PATTERN.fullmatch(raw)
        if match is None or match.group(1) not in FRAGMENT_LABELS:
            print("evidence: invalid-argument")
            return 2
        label, raw_path = match.groups()
        path = Path(raw_path)
        if not path.is_file():
            print(f"{label}: absent")
            next_action = next_action or label
            continue
        try:
            report = QualificationReport.from_json(path.read_text(encoding="utf-8"))
        except OSError, ValueError, UnsafeReportError:
            print(f"{label}: invalid")
            next_action = next_action or label
            continue
        if report.run_id != session.run_id or report.source_revision != session.source_revision:
            print(f"{label}: stale")
            next_action = next_action or label
            continue
        if not report.checks:
            print(f"{label}: invalid")
            next_action = next_action or label
            continue
        failures = tuple(check.check_id for check in report.checks if check.status == "failed")
        if failures:
            print(f"{label}: failed {','.join(failures)}")
            next_action = next_action or label
        else:
            print(f"{label}: passed")
    print(f"next: {next_action or 'complete'}")
    return 0


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-revision", required=True)


def _create_report(
    arguments: argparse.Namespace,
    *,
    environment: str,
    checks: Sequence[CheckResult],
) -> QualificationReport:
    return QualificationReport.create(
        run_id=arguments.run_id,
        source_revision=arguments.source_revision,
        environment=environment,
        checks=checks,
    )
