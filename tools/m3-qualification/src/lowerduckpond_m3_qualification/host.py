"""Privileged production-equivalent host qualification probes."""

from __future__ import annotations

import grp
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from pathlib import Path
from typing import Final

from lowerduckpond_m3_qualification.filesystem import run_filesystem_checks
from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue, run_check

HOST_OS_RELEASE: Final = "26.04"
QUALIFICATION_ROOT: Final = Path("/run/lowerduckpond-m3-qualification")
CADDY_GENERATION_ROOT: Final = Path("/etc/caddy/qualification/generations")
CADDY_ACTIVE_PATH: Final = Path("/etc/caddy/qualification/active")
CADDY_LOG_PATH: Final = Path("/var/log/caddy/m3-qualification.json")
CADDY_ADMIN_SOCKET: Final = Path("/run/caddy/admin.sock")
UUID_COMMAND: Final = Path("/usr/local/libexec/lowerduckpond/m3-qualification-uuid")
VALID_UUIDV7: Final = "0198d17f-6f4a-7000-8000-000000000001"
CANARY_VALUE: Final = "ldp-m3-canary-not-sensitive"
LOG_PROOF_PATH: Final = "/m3-log-proof"
ROUTE_HOSTS: Final = (
    "lowerduckpond.com",
    "m3-a.lowerduckpond.com",
    "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
    "m3-unknown.lowerduckpond.com",
)
CERTIFICATE_PROBES: Final = (
    ("lowerduckpond.net", "lowerduckpond.net"),
    ("m3-qualification.lowerduckpond.net", "*.lowerduckpond.net"),
    ("lowerduckpond.com", "lowerduckpond.com"),
    ("m3-a.lowerduckpond.com", "*.lowerduckpond.com"),
)
UUID_REJECTION_ARGUMENTS: Final = (
    (),
    (VALID_UUIDV7.upper(),),
    ("0198d17f-6f4a-4000-8000-000000000001",),
    (f"{VALID_UUIDV7};id",),
    (f"{VALID_UUIDV7}/suffix",),
    (VALID_UUIDV7, "additional"),
    (VALID_UUIDV7.replace("-", "_"),),
    (f"{VALID_UUIDV7}\nlookalike",),
)
POLL_ATTEMPTS: Final = 100
POLL_DELAY_SECONDS: Final = 0.1
CADDY_RUNTIME_MODE: Final = 0o700
MAXIMUM_HANDOFF_MILLISECONDS: Final = 1000
MINIMUM_HTTP_STATUS_FIELDS: Final = 2
TLS_TIMEOUT_SECONDS: Final = 5.0
ROUTE_CLASS_COUNT: Final = 5
GENERATION_DIRECTORY_MODE: Final = 0o550
GENERATION_FILE_MODE: Final = 0o440
ROOT_UID: Final = 0
GENERATION_PATTERN: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"-(?:dual|replacement)$"
)


def run_host_checks(*, work_root: Path, expected_generation: str) -> tuple[CheckResult, ...]:
    """Run all checks that require the disposable Ubuntu host."""
    checks: list[CheckResult] = [
        run_check("m3.0.host.ubuntu", _check_ubuntu),
        run_check("m3.0.host.sudo-uuid", _check_sudo_uuid),
        run_check("m3.0.host.tmpfs-limits", _check_tmpfs_limits),
        run_check(
            "m3.0.host.caddy-descriptor",
            lambda: _check_caddy_descriptor(expected_generation),
        ),
        run_check("m3.0.host.caddy-admin", _check_caddy_admin),
        run_check("m3.0.host.caddy-hooks", lambda: _check_caddy_hooks(expected_generation)),
        run_check("m3.0.host.caddy-routes", _check_caddy_routes),
        run_check("m3.0.host.caddy-certificates", _check_caddy_certificates),
        run_check("m3.0.host.caddy-log-safety", _check_caddy_log_safety),
        run_check("m3.0.host.systemd-recovery", _check_systemd_recovery),
    ]
    checks.extend(run_filesystem_checks(work_root=work_root, expected_filesystem="ext4"))
    return tuple(checks)


def _check_ubuntu() -> dict[str, EvidenceValue]:
    values = _parse_key_values(Path("/etc/os-release").read_text(encoding="utf-8"))
    if values.get("ID") != "ubuntu" or values.get("VERSION_ID") != HOST_OS_RELEASE:
        raise RuntimeError
    return {"distribution": "ubuntu", "release": HOST_OS_RELEASE}


def _check_sudo_uuid() -> dict[str, EvidenceValue]:
    command = ("runuser", "--user", "ldp-qualification", "--", "sudo", "-n", str(UUID_COMMAND))
    if _quiet_run((*command, VALID_UUIDV7)).returncode != 0:
        raise RuntimeError
    for arguments in UUID_REJECTION_ARGUMENTS:
        if _quiet_run((*command, *arguments)).returncode == 0:
            raise RuntimeError
    unauthorized = ("runuser", "--user", "ldp-qualification", "--", "sudo", "-n", "/usr/bin/true")
    if _quiet_run(unauthorized).returncode == 0:
        raise RuntimeError
    return {"accepted": 1, "rejected": len(UUID_REJECTION_ARGUMENTS) + 1}


def _check_tmpfs_limits() -> dict[str, EvidenceValue]:
    result_path = QUALIFICATION_ROOT / "tmpfs-result.json"
    result_path.unlink(missing_ok=True)
    _checked_run(("systemctl", "start", "ldp-m3-tmpfs.service"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result != {"inodes_enforced": True, "space_enforced": True}:
        raise RuntimeError
    properties = _systemd_properties("ldp-m3-tmpfs.service", ("PrivateTmp", "TemporaryFileSystem"))
    if properties.get("PrivateTmp") != "yes":
        raise RuntimeError
    if "/var/lib/lowerduckpond-m3-tmpfs" not in properties.get("TemporaryFileSystem", ""):
        raise RuntimeError
    return {"inodes": 4096, "private": True, "size_mib": 64}


def _check_caddy_descriptor(expected_generation: str) -> dict[str, EvidenceValue]:
    properties = _systemd_properties("caddy.service", ("MainPID",))
    process_id = int(properties["MainPID"])
    if process_id <= 1:
        raise RuntimeError
    descriptor_targets: list[Path] = []
    for descriptor in Path(f"/proc/{process_id}/fd").iterdir():
        try:
            target = descriptor.resolve(strict=True)
        except OSError:
            continue
        if target.is_dir():
            descriptor_targets.append(target)
    start_generation = _recorded_generation("caddy-start-generation", expected_generation)
    if start_generation not in descriptor_targets:
        raise RuntimeError
    if CADDY_ACTIVE_PATH.resolve(strict=True) != start_generation:
        raise RuntimeError
    generation_stat = start_generation.stat()
    caddyfile_stat = (start_generation / "Caddyfile").stat()
    caddy_group = grp.getgrnam("caddy")
    if (
        generation_stat.st_uid != ROOT_UID
        or generation_stat.st_gid != caddy_group.gr_gid
        or stat.S_IMODE(generation_stat.st_mode) != GENERATION_DIRECTORY_MODE
        or caddyfile_stat.st_uid != ROOT_UID
        or caddyfile_stat.st_gid != caddy_group.gr_gid
        or stat.S_IMODE(caddyfile_stat.st_mode) != GENERATION_FILE_MODE
    ):
        raise RuntimeError
    return {"generation_pinned": True}


def _check_caddy_admin() -> dict[str, EvidenceValue]:
    if not CADDY_ADMIN_SOCKET.is_socket():
        raise RuntimeError
    runtime_stat = CADDY_ADMIN_SOCKET.parent.stat()
    caddy_user = pwd.getpwnam("caddy")
    if (
        runtime_stat.st_uid != caddy_user.pw_uid
        or stat.S_IMODE(runtime_stat.st_mode) != CADDY_RUNTIME_MODE
    ):
        raise RuntimeError
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.25)
        if connection.connect_ex(("127.0.0.1", 2019)) == 0:
            raise RuntimeError
    _checked_run(
        (
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--unix-socket",
            str(CADDY_ADMIN_SOCKET),
            "http://localhost/config/",
        )
    )
    denied = _quiet_run(
        (
            "runuser",
            "--user",
            "ldp-qualification",
            "--",
            "curl",
            "--fail",
            "--silent",
            "--unix-socket",
            str(CADDY_ADMIN_SOCKET),
            "http://localhost/config/",
        )
    )
    if denied.returncode == 0:
        raise RuntimeError
    return {"access_limited": True, "tcp_disabled": True, "unix_socket": True}


def _check_caddy_hooks(expected_generation: str) -> dict[str, EvidenceValue]:
    invocation = _systemd_properties("caddy.service", ("InvocationID",))["InvocationID"]
    if not re.fullmatch(r"[0-9a-f]{32}", invocation):
        raise RuntimeError
    for phase in ("start-pre", "start-post"):
        recorded = (
            (QUALIFICATION_ROOT / f"caddy-{phase}-invocation").read_text(encoding="utf-8").strip()
        )
        if recorded != invocation:
            raise RuntimeError
    _checked_run(("systemctl", "reload", "caddy.service"))
    for phase in ("reload-pre", "reload-post"):
        recorded = (
            (QUALIFICATION_ROOT / f"caddy-{phase}-invocation").read_text(encoding="utf-8").strip()
        )
        if recorded != invocation:
            raise RuntimeError
    reload_generation = _recorded_generation("caddy-reload-generation", expected_generation)
    if reload_generation != _recorded_generation("caddy-start-generation", expected_generation):
        raise RuntimeError
    properties = _systemd_properties(
        "caddy.service", ("Restart", "StartLimitBurst", "StartLimitIntervalUSec")
    )
    if properties.get("Restart") != "on-failure" or properties.get("StartLimitBurst") != "3":
        raise RuntimeError
    if properties.get("StartLimitIntervalUSec") in {None, "0"}:
        raise RuntimeError
    return {"bounded_attempts": 3, "invocation_hooks": True, "reload_pinned": True}


def _check_caddy_routes() -> dict[str, EvidenceValue]:
    apex_status, apex_headers, apex_body = _curl_route(ROUTE_HOSTS[0], "/", include_state=True)
    apex_clear_status, apex_clear_headers, apex_clear_body = _curl_route(
        ROUTE_HOSTS[0], "/", include_state=False
    )
    if (
        apex_status != HTTPStatus.NOT_FOUND
        or apex_clear_status != HTTPStatus.NOT_FOUND
        or apex_body != apex_clear_body
        or not _headers_are_stateless(apex_headers)
        or not _headers_are_stateless(apex_clear_headers)
    ):
        raise RuntimeError

    alias_status, alias_headers, alias_body = _curl_route(ROUTE_HOSTS[1], "/", include_state=True)
    alias_clear_status, alias_clear_headers, alias_clear_body = _curl_route(
        ROUTE_HOSTS[1], "/", include_state=False
    )
    expected_location = f"https://{ROUTE_HOSTS[2]}/"
    if (
        alias_status != HTTPStatus.FOUND
        or alias_clear_status != HTTPStatus.FOUND
        or alias_body != alias_clear_body
        or alias_headers.get("location") != expected_location
        or alias_clear_headers.get("location") != expected_location
        or not _headers_are_stateless(alias_headers)
        or not _headers_are_stateless(alias_clear_headers)
    ):
        raise RuntimeError

    alias_non_root_status, alias_non_root_headers, alias_non_root_body = _curl_route(
        ROUTE_HOSTS[1], "/static", include_state=True
    )
    alias_non_root_clear_status, alias_non_root_clear_headers, alias_non_root_clear_body = (
        _curl_route(ROUTE_HOSTS[1], "/static", include_state=False)
    )
    if (
        alias_non_root_status != HTTPStatus.NOT_FOUND
        or alias_non_root_clear_status != HTTPStatus.NOT_FOUND
        or alias_non_root_body != alias_non_root_clear_body
        or not _headers_are_stateless(alias_non_root_headers)
        or not _headers_are_stateless(alias_non_root_clear_headers)
    ):
        raise RuntimeError

    canonical_status, canonical_headers, canonical_body = _curl_route(
        ROUTE_HOSTS[2], "/probe", include_state=True
    )
    canonical_clear_status, canonical_clear_headers, canonical_clear_body = _curl_route(
        ROUTE_HOSTS[2], "/probe", include_state=False
    )
    if (
        canonical_status != HTTPStatus.OK
        or canonical_clear_status != HTTPStatus.OK
        or canonical_body != canonical_clear_body
        or canonical_headers.get("x-m3-upstream-saw-state") != "false"
        or canonical_clear_headers.get("x-m3-upstream-saw-state") != "false"
        or not _headers_are_stateless(canonical_headers)
        or not _headers_are_stateless(canonical_clear_headers)
    ):
        raise RuntimeError
    static_status, static_headers, _ = _curl_route(ROUTE_HOSTS[2], "/static", include_state=True)
    if static_status != HTTPStatus.OK or not _headers_are_stateless(static_headers):
        raise RuntimeError

    unknown_status, unknown_headers, unknown_body = _curl_route(
        ROUTE_HOSTS[3], "/", include_state=True
    )
    unknown_clear_status, unknown_clear_headers, unknown_clear_body = _curl_route(
        ROUTE_HOSTS[3], "/", include_state=False
    )
    if (
        unknown_status != HTTPStatus.NOT_FOUND
        or unknown_clear_status != HTTPStatus.NOT_FOUND
        or unknown_body != unknown_clear_body
        or not _headers_are_stateless(unknown_headers)
        or not _headers_are_stateless(unknown_clear_headers)
    ):
        raise RuntimeError
    return {"route_classes": ROUTE_CLASS_COUNT, "state_independent": True}


def _headers_are_stateless(headers: Mapping[str, str]) -> bool:
    return (
        "set-cookie" not in headers
        and not headers.get("x-m3-incoming-state", "")
        and headers.get("cache-control") == "no-store, no-transform"
    )


def _recorded_generation(name: str, expected_generation: str) -> Path:
    generation = Path((QUALIFICATION_ROOT / name).read_text(encoding="utf-8").strip())
    if not _is_generation_path(generation) or generation.name != expected_generation:
        raise RuntimeError
    return generation


def _is_generation_path(path: Path) -> bool:
    return (
        path.parent == CADDY_GENERATION_ROOT and GENERATION_PATTERN.fullmatch(path.name) is not None
    )


def _check_caddy_certificates() -> dict[str, EvidenceValue]:
    address = _route_addresses()
    for server_name, required_dns_name in CERTIFICATE_PROBES:
        if required_dns_name not in _certificate_dns_names(address, server_name):
            raise RuntimeError
    return {"certificate_paths": len(CERTIFICATE_PROBES)}


def _certificate_dns_names(address: str, server_name: str) -> frozenset[str]:
    handshake = subprocess.run(  # noqa: S603
        (
            "/usr/bin/openssl",
            "s_client",
            "-connect",
            f"{address}:443",
            "-servername",
            server_name,
            "-showcerts",
            "-verify_return_error",
        ),
        input=b"",
        capture_output=True,
        check=False,
        timeout=TLS_TIMEOUT_SECONDS,
    )
    match = re.search(
        rb"-----BEGIN CERTIFICATE-----\r?\n.+?-----END CERTIFICATE-----\r?\n?",
        handshake.stdout,
        re.DOTALL,
    )
    if match is None:
        raise RuntimeError
    decoded = subprocess.run(
        ("/usr/bin/openssl", "x509", "-noout", "-ext", "subjectAltName"),
        input=match.group(0),
        capture_output=True,
        check=True,
        text=False,
    ).stdout.decode("ascii")
    return frozenset(re.findall(r"DNS:([^,\s]+)", decoded))


def _check_caddy_log_safety() -> dict[str, EvidenceValue]:
    initial_log = CADDY_LOG_PATH.stat()
    initial_identity = (initial_log.st_dev, initial_log.st_ino)
    initial_size = initial_log.st_size
    status, headers, _ = _curl_route(ROUTE_HOSTS[3], LOG_PROOF_PATH, include_state=True)
    if status != HTTPStatus.NOT_FOUND or not _headers_are_stateless(headers):
        raise RuntimeError
    for _ in range(POLL_ATTEMPTS):
        with CADDY_LOG_PATH.open("rb") as log_file:
            current_log = os.fstat(log_file.fileno())
            if (
                current_log.st_dev,
                current_log.st_ino,
            ) != initial_identity or current_log.st_size < initial_size:
                raise RuntimeError
            log_file.seek(initial_size)
            log_bytes = log_file.read()
        if CANARY_VALUE.encode() in log_bytes or b'"Cookie"' in log_bytes:
            raise RuntimeError
        proof_observed = False
        for line in log_bytes.splitlines():
            if not line:
                continue
            entry = json.loads(line)
            request = entry.get("request", {}) if isinstance(entry, dict) else {}
            if isinstance(request, dict) and request.get("uri") == LOG_PROOF_PATH:
                proof_observed = True
        if proof_observed:
            return {"structured": True, "values_omitted": True}
        time.sleep(POLL_DELAY_SECONDS)
    raise RuntimeError


def _check_systemd_recovery() -> dict[str, EvidenceValue]:
    success_marker = QUALIFICATION_ROOT / "recovery-allowed"
    success_marker.unlink(missing_ok=True)
    _quiet_run(("systemctl", "stop", "ldp-m3-recovery.service"))
    # A newly installed unit may not have been loaded yet. Only the reset that
    # transitions the exhausted service back to healthy is a required action.
    _quiet_run(("systemctl", "reset-failed", "ldp-m3-recovery.service"))
    started_at = time.monotonic()
    _checked_run(("systemctl", "--no-block", "start", "ldp-m3-recovery.service"))
    handoff_milliseconds = int((time.monotonic() - started_at) * 1000)
    if handoff_milliseconds >= MAXIMUM_HANDOFF_MILLISECONDS:
        raise RuntimeError
    _poll_systemd_state("ldp-m3-recovery.service", "failed")
    failed_properties = _systemd_properties(
        "ldp-m3-recovery.service", ("NRestarts", "StartLimitBurst")
    )
    if int(failed_properties["NRestarts"]) != int(failed_properties["StartLimitBurst"]):
        raise RuntimeError

    success_marker.touch(mode=0o600)
    _checked_run(("systemctl", "reset-failed", "ldp-m3-recovery.service"))
    _checked_run(("systemctl", "--no-block", "start", "ldp-m3-recovery.service"))
    _poll_systemd_state("ldp-m3-recovery.service", "active")
    recovered = _systemd_properties("ldp-m3-recovery.service", ("NRestarts", "Result"))
    if recovered.get("NRestarts") != "0" or recovered.get("Result") != "success":
        raise RuntimeError
    return {"nonblocking": True, "reset_recovered": True, "handoff_ms": handoff_milliseconds}


def _route_addresses() -> str:
    addresses = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    for address in addresses:
        candidate = str(address[4][0])
        if not candidate.startswith("127."):
            return candidate
    return "127.0.0.1"


def _curl_route(host: str, path: str, *, include_state: bool) -> tuple[int, dict[str, str], bytes]:
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--dump-header",
        "-",
        "--noproxy",
        "*",
        "--header",
        f"Host: {host}",
    ]
    if include_state:
        command.extend(("--header", f"Cookie: ldp_m3_parent={CANARY_VALUE}"))
    command.append(f"http://127.0.0.1:18081{path}")
    completed = subprocess.run(command, check=True, capture_output=True)  # noqa: S603
    header_bytes, separator, body = completed.stdout.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError
    header_lines = header_bytes.split(b"\r\n")
    status_fields = header_lines[0].split()
    if len(status_fields) < MINIMUM_HTTP_STATUS_FIELDS:
        raise RuntimeError
    status = int(status_fields[1])
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        key, marker, value = line.partition(b":")
        if marker:
            headers[key.decode("ascii").lower()] = value.decode("ascii").strip()
    return status, headers, body


def _poll_systemd_state(unit: str, expected: str) -> None:
    for _ in range(POLL_ATTEMPTS):
        state = _systemd_properties(unit, ("ActiveState",)).get("ActiveState")
        if state == expected:
            return
        time.sleep(POLL_DELAY_SECONDS)
    raise RuntimeError


def _systemd_properties(unit: str, names: Sequence[str]) -> dict[str, str]:
    command = ["systemctl", "show", unit]
    for name in names:
        command.extend(("--property", name))
    completed = subprocess.run(  # noqa: S603
        command, check=True, capture_output=True, text=True
    )
    return _parse_key_values(completed.stdout)


def _parse_key_values(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip('"')
    return values


def _checked_run(command: Sequence[str]) -> None:
    subprocess.run(  # noqa: S603
        command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def _quiet_run(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
