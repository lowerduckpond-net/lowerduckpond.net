from __future__ import annotations

import shlex

from testinfra.host import Host

BACKUP_ENVIRONMENT_MODE = 0o600
CONTENT_ROOT_MODE = 0o711
ROUTE_DIRECTORY_MODE = 0o750
DATABASE_BACKUP_PRIVILEGES = {
    "EVENT:NO",
    "LOCK TABLES:NO",
    "PROCESS:NO",
    "RELOAD:NO",
    "SELECT:NO",
    "SHOW VIEW:NO",
    "TRIGGER:NO",
}
BACKUP_SCOPE_PATH = "/etc/lowerduckpond/backup-scope"
BACKUP_SCOPE_LENGTH = 64
STATUS_FIELD_COUNT = 2
LOCAL_BACKUP_REPOSITORY = "/mnt/lowerduckpond-restic-test"
LOCAL_BACKUP_REPOSITORY_MODE = 0o700
BACKUP_SOURCE_PATHS = (
    "/srv/lowerduckpond",
    "/var/lib/caddy",
    "/var/lib/lowerduckpond/manifests",
    "/var/lib/lowerduckpond/audit",
)
SYSTEMD_SYSTEM_UNIT_PATHS = (
    "/etc/systemd/system/caddy.service",
    "/etc/systemd/system/ldp-m3-fixture.service",
    "/etc/systemd/system/lowerduckpond-backup.service",
    "/etc/systemd/system/lowerduckpond-backup.timer",
    "/etc/systemd/system/lowerduckpond-backup-maintenance.service",
    "/etc/systemd/system/lowerduckpond-backup-maintenance.timer",
    "/etc/systemd/system/lowerduckpond-health.service",
    "/etc/systemd/system/lowerduckpond-health.timer",
)
SYSTEMD_USER_UNIT_PATH = (
    "/var/lib/lowerduckpond/runtime/.config/systemd/user/lowerduckpond-podman-ready.service"
)
QUALIFICATION_UUID_COMMAND = "/usr/local/libexec/lowerduckpond/m3-qualification-uuid"
QUALIFICATION_UUID_COMMAND_MODE = 0o755
QUALIFICATION_LOG_MODE = 0o600
QUALIFICATION_LOG_PATH = "/tmp/lowerduckpond-m3-qualification.json"  # noqa: S108
QUALIFICATION_MARKER = "/tmp/lowerduckpond-m3-converged-session"  # noqa: S108
QUALIFICATION_CADDYFILE = "/tmp/lowerduckpond-m3-Caddyfile"  # noqa: S108
QUALIFICATION_MARKER_MODE = 0o400
QUALIFICATION_PACKAGE_DIRECTORY_MODE = 0o755
QUALIFICATION_PACKAGE_FILE_MODE = 0o644
QUALIFICATION_PACKAGE_ROOT = "/opt/lowerduckpond/m3-qualification/lowerduckpond_m3_qualification"
QUALIFICATION_PYTHON_MODULES = (
    "__init__.py",
    "__main__.py",
    "browser.py",
    "checks.py",
    "cli.py",
    "domains.py",
    "edge.py",
    "filesystem.py",
    "fixture_server.py",
    "host.py",
    "libraries.py",
    "report.py",
    "session.py",
)
QUALIFICATION_REPAIRED_LOG_PATH = "/tmp/lowerduckpond-m3-qualification-repair.json"  # noqa: S108
QUALIFICATION_SUDOERS_MODE = 0o440
VALID_UUIDV7 = "0198d17f-6f4a-7000-8000-000000000001"
UUID_REJECTION_ARGUMENTS = (
    (VALID_UUIDV7.upper(),),
    ("0198d17f-6f4a-4000-8000-000000000001",),
    (f"{VALID_UUIDV7};id",),
    (f"{VALID_UUIDV7}/suffix",),
    (VALID_UUIDV7, "additional"),
    (VALID_UUIDV7.replace("-", "_"),),
    (f"{VALID_UUIDV7}\nlookalike",),
    (),
)


def read_status_scope(host: Host, variable_name: str) -> str:
    result = host.run(
        "/bin/bash -c %s",
        f'source /etc/lowerduckpond/backup.env; printf "%s" "${{{variable_name}}}"',
    )
    assert result.rc == 0
    scope = result.stdout.strip()
    assert len(scope) == BACKUP_SCOPE_LENGTH
    assert all(character in "0123456789abcdef" for character in scope)
    return scope


def read_backup_scope(host: Host) -> str:
    return read_status_scope(host, "LOWERDUCKPOND_BACKUP_STATUS_SCOPE")


def read_maintenance_scope(host: Host) -> str:
    return read_status_scope(host, "LOWERDUCKPOND_BACKUP_MAINTENANCE_STATUS_SCOPE")


def read_status_record(host: Host, path: str) -> tuple[int, str]:
    fields = host.file(path).content_string.split()
    assert len(fields) == STATUS_FIELD_COUNT
    timestamp, scope = fields
    assert timestamp.isdigit()
    return int(timestamp), scope


def write_status_record(host: Host, path: str, timestamp: int, scope: str) -> None:
    result = host.run(f"printf '%s %s\\n' {timestamp} {scope} > {path}")
    assert result.rc == 0


def test_supported_operating_system(host: Host) -> None:
    release = host.file("/etc/os-release")
    assert release.contains('VERSION_ID="26.04"')


def test_distribution_packages_are_within_supported_bounds(host: Host) -> None:
    supported_packages = {
        "mariadb-server": ("1:11.8", "1:11.9"),
        "podman": ("5.7", "6"),
        "restic": ("0.18.1", "0.19"),
    }
    for package, (minimum, maximum) in supported_packages.items():
        result = host.run(
            f"/usr/local/libexec/lowerduckpond/assert-package-version {package} {minimum} {maximum}"
        )
        assert result.rc == 0


def test_qualification_sudo_boundary_uses_the_root_owned_parser(host: Host) -> None:
    account = host.user("ldp-qualification")
    assert account.exists
    assert account.shell == "/usr/sbin/nologin"

    parser = host.file(QUALIFICATION_UUID_COMMAND)
    assert parser.is_file
    assert parser.user == "root"
    assert parser.group == "root"
    assert parser.mode == QUALIFICATION_UUID_COMMAND_MODE
    assert parser.content_string.startswith("#!/usr/bin/python3 -I\n")

    sudoers = host.file("/etc/sudoers.d/lowerduckpond-m3-qualification")
    assert sudoers.is_file
    assert sudoers.user == "root"
    assert sudoers.group == "root"
    assert sudoers.mode == QUALIFICATION_SUDOERS_MODE
    assert sudoers.content_string == (
        f"ldp-qualification ALL=(root) NOPASSWD: {QUALIFICATION_UUID_COMMAND}\n"
    )

    command = ("runuser", "--user", "ldp-qualification", "--", "sudo", "-n")

    valid = host.run(shlex.join((*command, QUALIFICATION_UUID_COMMAND, VALID_UUIDV7)))
    assert valid.rc == 0

    for arguments in UUID_REJECTION_ARGUMENTS:
        rejected = host.run(shlex.join((*command, QUALIFICATION_UUID_COMMAND, *arguments)))
        assert rejected.rc != 0

    other_command = host.run(shlex.join((*command, "/usr/bin/true")))
    assert other_command.rc != 0


def test_qualification_fixture_ignores_restrictive_controller_modes(host: Host) -> None:
    package = host.file(QUALIFICATION_PACKAGE_ROOT)
    assert package.is_directory
    assert package.user == "root"
    assert package.group == "root"
    assert package.mode == QUALIFICATION_PACKAGE_DIRECTORY_MODE

    for module_name in QUALIFICATION_PYTHON_MODULES:
        module = host.file(f"{QUALIFICATION_PACKAGE_ROOT}/{module_name}")
        assert module.is_file
        assert module.user == "root"
        assert module.group == "root"
        assert module.mode == QUALIFICATION_PACKAGE_FILE_MODE

    assert not host.file(f"{QUALIFICATION_PACKAGE_ROOT}/__pycache__").exists
    fixture = host.service("ldp-m3-fixture")
    assert fixture.is_enabled
    assert fixture.is_running
    response = host.run("curl --fail --silent http://127.0.0.1:18080/probe")
    assert response.rc == 0
    assert response.stdout == "lowerduckpond-m3-cookie-independent-body\n"


def test_qualification_convergence_marker_is_byte_exact(host: Host) -> None:
    marker = host.file(QUALIFICATION_MARKER)
    assert marker.is_file
    assert marker.user == "root"
    assert marker.group == "root"
    assert marker.mode == QUALIFICATION_MARKER_MODE
    assert marker.content_string == f"{VALID_UUIDV7} {'0' * 40} dual\n"


def test_only_expected_ports_listen_publicly(host: Host) -> None:
    listeners = host.run("/usr/local/libexec/lowerduckpond/public-tcp-listeners")
    assert listeners.rc == 0
    ports = {listener.rsplit(":", 1)[1] for listener in listeners.stdout.splitlines()}
    assert {"80", "443"}.issubset(ports)
    assert ports.issubset({"22", "80", "443"})


def test_public_listener_classifier_handles_concrete_addresses(host: Host) -> None:
    fixture = "\n".join(
        [
            "LISTEN 0 4096 127.0.0.1:9100 0.0.0.0:*",
            "LISTEN 0 4096 [::1]:3306 [::]:*",
            "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
            "LISTEN 0 4096 192.0.2.10:8443 0.0.0.0:*",
            "LISTEN 0 4096 [2001:db8::10]:9443 [::]:*",
        ]
    )
    result = host.run(
        f"printf '%b' {fixture!r} | /usr/local/libexec/lowerduckpond/public-tcp-listeners --stdin"
    )
    assert result.rc == 0
    assert set(result.stdout.splitlines()) == {
        "0.0.0.0:22",
        "192.0.2.10:8443",
        "[2001:db8::10]:9443",
    }


def test_caddy_custom_build_and_https_fixture(host: Host) -> None:
    selected_binary = host.run("readlink --canonicalize /usr/local/bin/caddy")
    assert selected_binary.rc == 0
    assert selected_binary.stdout.strip().endswith("/caddy-2.11.4-xcaddy-0.4.7-cloudflare-0.2.4")

    modules = host.run("/usr/local/bin/caddy list-modules")
    assert modules.rc == 0
    assert "dns.providers.cloudflare" in modules.stdout.splitlines()

    response = host.run(
        "curl --fail --silent --show-error --insecure "
        "--resolve lowerduckpond.test:443:127.0.0.1 https://lowerduckpond.test/"
    )
    assert response.rc == 0
    assert "Lower Duck Pond Hosting" in response.stdout

    service = host.service("caddy")
    assert service.is_enabled
    assert service.is_running


def test_qualification_component_listener_accepts_reviewed_hosts_only_on_loopback(
    host: Host,
) -> None:
    configuration = host.file(QUALIFICATION_CADDYFILE).content_string
    assert "http://:18081 {" in configuration
    assert "\tbind 127.0.0.1" in configuration
    assert "http://127.0.0.1:18081 {" not in configuration
    assert "@platform host lowerduckpond.net m3-qualification.lowerduckpond.net" in configuration
    assert "@canonical host t-0198d17f6f4a70008000000000000001.lowerduckpond.com" in configuration


def test_caddy_reload_always_validates_first(host: Host) -> None:
    unit = host.file("/etc/systemd/system/caddy.service")
    validate_index = unit.content_string.index("ExecReload=/usr/local/bin/caddy validate")
    reload_index = unit.content_string.index("ExecReload=/usr/local/bin/caddy reload")
    assert validate_index < reload_index
    assert "--address unix//run/caddy/admin.sock" in unit.content_string
    assert "Restart=on-failure" in unit.content_string


def test_caddy_admin_api_is_caddy_only(host: Host) -> None:
    configuration = host.file("/etc/caddy/Caddyfile")
    assert configuration.contains("admin unix//run/caddy/admin.sock")

    socket = host.file("/run/caddy/admin.sock")
    assert socket.exists
    assert socket.user == "caddy"
    assert not host.socket("tcp://127.0.0.1:2019").is_listening

    denied = host.run(
        "runuser --user ldp-provisioner -- "
        "curl --fail --silent --unix-socket /run/caddy/admin.sock "
        "http://localhost/config/"
    )
    assert denied.rc != 0


def test_rootless_podman_non_login_account(host: Host) -> None:
    account = host.user("ldp-runtime")
    assert account.exists
    assert account.shell == "/usr/sbin/nologin"

    podman = host.run(
        "runuser --user ldp-runtime -- env HOME=/var/lib/lowerduckpond/runtime "
        "XDG_RUNTIME_DIR=/run/user/21000 podman info --format json"
    )
    assert podman.rc == 0
    assert host.file("/var/lib/systemd/linger/ldp-runtime").exists


def test_subordinate_ids_are_unique_and_overlap_is_rejected(host: Host) -> None:
    for path in ("/etc/subuid", "/etc/subgid"):
        allocations = [
            line
            for line in host.file(path).content_string.splitlines()
            if line.startswith("ldp-runtime:")
        ]
        assert allocations == ["ldp-runtime:200000:65536"]

    fixture_result = host.run("mktemp")
    assert fixture_result.rc == 0
    fixture = fixture_result.stdout.strip()
    seed = host.run(
        f"printf '%s\\n' 'another-user:190000:20000' > {fixture} && chmod 0644 {fixture}"
    )
    assert seed.rc == 0
    overlap = host.run(
        "/usr/local/libexec/lowerduckpond/ensure-subid-allocation "
        f"{fixture} ldp-runtime 200000 65536 --check"
    )
    assert overlap.rc != 0
    assert "overlaps another-user:190000:20000" in overlap.stderr
    assert host.file(fixture).content_string == "another-user:190000:20000\n"


def test_database_is_loopback_only(host: Host) -> None:
    query = host.run("mariadb --batch --skip-column-names --execute 'SELECT @@bind_address'")
    assert query.rc == 0
    assert query.stdout.strip() == "127.0.0.1"
    assert host.service("mariadb").is_running
    assert host.service("mariadb").is_enabled

    privileges = host.run(
        'mariadb --batch --skip-column-names --execute "'
        "SELECT CONCAT(PRIVILEGE_TYPE, ':', IS_GRANTABLE) "
        "FROM information_schema.USER_PRIVILEGES "
        "WHERE GRANTEE=\\\"'ldp-backup'@'localhost'\\\"\""
    )
    assert privileges.rc == 0
    assert set(privileges.stdout.splitlines()) == DATABASE_BACKUP_PRIVILEGES

    scoped_or_role_privileges = host.run(
        'mariadb --batch --skip-column-names --execute "'
        "SELECT "
        "(SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES "
        "WHERE GRANTEE=\\\"'ldp-backup'@'localhost'\\\") + "
        "(SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES "
        "WHERE GRANTEE=\\\"'ldp-backup'@'localhost'\\\") + "
        "(SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES "
        "WHERE GRANTEE=\\\"'ldp-backup'@'localhost'\\\") + "
        "(SELECT COUNT(*) FROM mysql.procs_priv "
        "WHERE User='ldp-backup' AND Host='localhost') + "
        "(SELECT COUNT(*) FROM mysql.roles_mapping "
        "WHERE User='ldp-backup' AND Host='localhost')\""
    )
    assert scoped_or_role_privileges.rc == 0
    assert scoped_or_role_privileges.stdout.strip() == "0"


def test_nftables_policy_compiles_and_blocks_metadata(host: Host) -> None:
    validation = host.run("nft --check --file /etc/nftables.conf")
    assert validation.rc == 0
    policy = host.file("/etc/nftables.conf")
    assert policy.contains("169.254.169.254")
    assert policy.contains("policy drop")


def test_project_systemd_units_pass_static_verification(host: Host) -> None:
    for unit_path in SYSTEMD_SYSTEM_UNIT_PATHS:
        system_unit = host.run(
            "systemd-analyze verify --recursive-errors=no %s",
            unit_path,
        )
        assert system_unit.rc == 0, f"{unit_path}: {system_unit.stderr}"

    user_unit = host.run(
        "runuser --user ldp-runtime -- env "
        "HOME=/var/lib/lowerduckpond/runtime "
        "XDG_RUNTIME_DIR=/run/user/21000 "
        "systemd-analyze --user verify --recursive-errors=no %s",
        SYSTEMD_USER_UNIT_PATH,
    )
    assert user_unit.rc == 0, f"{SYSTEMD_USER_UNIT_PATH}: {user_unit.stderr}"


def test_backup_configuration_is_atomic_and_sandboxed(host: Host) -> None:
    assert host.file("/etc/lowerduckpond/backup.env").mode == BACKUP_ENVIRONMENT_MODE
    assert not host.file(BACKUP_SCOPE_PATH).exists
    backup_script = host.file("/usr/local/libexec/lowerduckpond/backup")
    maintenance_script = host.file("/usr/local/libexec/lowerduckpond/backup-maintenance")
    lock_path = "/var/cache/lowerduckpond-backup/repository.lock"
    source_index = backup_script.content_string.index("source /etc/lowerduckpond/backup.env")
    backup_lock_index = backup_script.content_string.index("flock --exclusive 9")
    maintenance_source_index = maintenance_script.content_string.index(
        "source /etc/lowerduckpond/backup.env"
    )
    maintenance_lock_index = maintenance_script.content_string.index("flock --exclusive 9")
    dump_index = backup_script.content_string.index("mariadb-dump")
    credential_export_index = backup_script.content_string.index("export AWS_ACCESS_KEY_ID")
    assert backup_lock_index < source_index < dump_index < credential_export_index
    assert maintenance_lock_index < maintenance_source_index
    assert backup_script.contains("/usr/bin/env --ignore-environment")
    assert backup_script.contains(f"lock_path={lock_path}")
    assert maintenance_script.contains(f"lock_path={lock_path}")
    assert backup_script.contains("LOWERDUCKPOND_BACKUP_STATUS_SCOPE")
    assert maintenance_script.contains("LOWERDUCKPOND_BACKUP_MAINTENANCE_STATUS_SCOPE")
    assert read_backup_scope(host) != read_maintenance_scope(host)
    assert not backup_script.contains(BACKUP_SCOPE_PATH)
    assert not maintenance_script.contains(BACKUP_SCOPE_PATH)
    restic_index = maintenance_script.content_string.index("restic forget")
    assert maintenance_lock_index < restic_index
    assert maintenance_script.contains("--tag scheduled")
    for helper_name, restic_command in (
        ("restic-check", "restic check"),
        ("latest-backup-snapshot", "restic snapshots"),
        ("restore-smoke-test", "restic restore"),
    ):
        helper = host.file(f"/usr/local/libexec/lowerduckpond/{helper_name}")
        assert helper.content_string.index("flock --exclusive 9") < (
            helper.content_string.index(restic_command)
        )
    assert host.file(LOCAL_BACKUP_REPOSITORY).is_directory
    assert host.file(LOCAL_BACKUP_REPOSITORY).user == "root"
    assert host.file(LOCAL_BACKUP_REPOSITORY).group == "root"
    assert host.file(LOCAL_BACKUP_REPOSITORY).mode == LOCAL_BACKUP_REPOSITORY_MODE
    canonical_repository = host.run(f"realpath {LOCAL_BACKUP_REPOSITORY}")
    assert canonical_repository.rc == 0
    assert not canonical_repository.stdout.startswith(("/home/", "/root/", "/run/user/"))
    for source_path in BACKUP_SOURCE_PATHS:
        canonical_source = host.run(f"realpath {source_path}")
        assert canonical_source.rc == 0
        source = canonical_source.stdout.strip()
        repository = canonical_repository.stdout.strip()
        assert repository != source
        assert not repository.startswith(f"{source}/")
        assert not source.startswith(f"{repository}/")
        assert backup_script.contains(source_path)
    backup_unit = host.file("/etc/systemd/system/lowerduckpond-backup.service")
    maintenance_unit = host.file("/etc/systemd/system/lowerduckpond-backup-maintenance.service")
    assert backup_unit.contains(LOCAL_BACKUP_REPOSITORY)
    assert maintenance_unit.contains(LOCAL_BACKUP_REPOSITORY)
    assert backup_unit.contains("ProtectHome=true")
    assert maintenance_unit.contains("ProtectHome=true")


def test_backup_repository_and_restore(host: Host) -> None:
    lock_path = "/var/cache/lowerduckpond-backup/repository.lock"
    backup = host.run("systemctl start lowerduckpond-backup.service")
    backup_journal = host.run(
        "journalctl --unit lowerduckpond-backup.service --no-pager --lines 50"
    )
    assert backup.rc == 0, backup_journal.stdout

    check = host.run("/usr/local/libexec/lowerduckpond/restic-check")
    assert check.rc == 0
    latest = host.run("/usr/local/libexec/lowerduckpond/latest-backup-snapshot")
    assert latest.rc == 0
    assert latest.stdout.strip().isdigit()

    diagnostic_root = "/var/cache/lowerduckpond-backup/diagnostic"
    diagnostic_fixture = host.run(
        f"install -d -m 0700 {diagnostic_root} && "
        f"printf '%s\\n' diagnostic > {diagnostic_root}/not-a-host-backup"
    )
    assert diagnostic_fixture.rc == 0
    diagnostic_backup = host.run(
        "/bin/bash -c 'set -a; source /etc/lowerduckpond/backup.env; set +a; "
        f"restic backup --host molecule --tag diagnostic {diagnostic_root}'"
    )
    assert diagnostic_backup.rc == 0

    restore_script = host.file("/usr/local/libexec/lowerduckpond/restore-smoke-test")
    assert restore_script.contains("--tag scheduled")
    restore = host.run("/usr/local/libexec/lowerduckpond/restore-smoke-test")
    assert restore.rc == 0

    lock_probe_script = f"""
set -euo pipefail
exec 8>{lock_path}
flock --exclusive 8
cleanup() {{ flock --unlock 8 || true; }}
trap cleanup EXIT
systemctl start --no-block lowerduckpond-backup-maintenance.service
for _ in {{1..50}}; do
    state=$(systemctl show --property ActiveState --value \
        lowerduckpond-backup-maintenance.service)
    [[ $state == activating ]] && break
    [[ $state == failed ]] && exit 1
    sleep 0.1
done
[[ $state == activating ]]
flock --unlock 8
trap - EXIT
for _ in {{1..300}}; do
    state=$(systemctl show --property ActiveState --value \
        lowerduckpond-backup-maintenance.service)
    [[ $state == inactive ]] && break
    [[ $state == failed ]] && exit 1
    sleep 0.1
done
[[ $state == inactive ]]
[[ $(systemctl show --property Result --value \
    lowerduckpond-backup-maintenance.service) == success ]]
"""
    maintenance = host.run("/bin/bash -c %s", lock_probe_script)
    maintenance_journal = host.run(
        "journalctl --unit lowerduckpond-backup-maintenance.service --no-pager --lines 50"
    )
    assert maintenance.rc == 0, maintenance_journal.stdout
    active_backup_scope = read_backup_scope(host)
    active_maintenance_scope = read_maintenance_scope(host)
    backup_status_path = "/var/lib/lowerduckpond/backup-status/backup-last-success"
    maintenance_status_path = "/var/lib/lowerduckpond/backup-status/maintenance-last-success"
    assert read_status_record(host, backup_status_path)[1] == active_backup_scope
    assert read_status_record(host, maintenance_status_path)[1] == active_maintenance_scope
    assert host.service("lowerduckpond-backup.timer").is_enabled
    assert host.service("lowerduckpond-backup-maintenance.timer").is_enabled


def test_monitoring_is_local_and_healthy(host: Host) -> None:
    exporter = host.socket("tcp://127.0.0.1:9100")
    assert exporter.is_listening
    assert not host.socket("tcp://0.0.0.0:9100").is_listening

    health_unit = host.file("/etc/systemd/system/lowerduckpond-health.service")
    assert not health_unit.contains("ReadWritePaths=/var/lib/lowerduckpond/runtime")
    assert not health_unit.contains("BindReadOnlyPaths=/run/user/21000")
    readiness_unit = host.file(
        "/var/lib/lowerduckpond/runtime/.config/systemd/user/lowerduckpond-podman-ready.service"
    )
    assert not readiness_unit.contains("RemainAfterExit=yes")
    assert not readiness_unit.contains("After=default.target")
    assert readiness_unit.contains("StartLimitIntervalSec=0")
    assert readiness_unit.contains("WantedBy=default.target")
    health_script = host.file("/usr/local/libexec/lowerduckpond/health-check")
    assert health_script.contains("start lowerduckpond-podman-ready.service")
    assert not health_script.contains("restart lowerduckpond-podman-ready.service")
    assert health_script.contains("source /etc/lowerduckpond/backup.env")
    assert not health_script.contains(BACKUP_SCOPE_PATH)
    caddy_validator = host.file("/usr/local/libexec/lowerduckpond/caddy-validate")
    assert caddy_validator.contains("lowerduckpond-caddy-validate")
    for qualification_log_path in (QUALIFICATION_LOG_PATH, QUALIFICATION_REPAIRED_LOG_PATH):
        qualification_log = host.file(qualification_log_path)
        assert qualification_log.exists
        assert qualification_log.is_file
        assert qualification_log.user == "caddy"
        assert qualification_log.group == "caddy"
        assert qualification_log.mode == QUALIFICATION_LOG_MODE
    scheduled_health = host.run("systemctl start lowerduckpond-health.service")
    health_journal = host.run(
        "journalctl --unit lowerduckpond-health.service --no-pager --lines 50"
    )
    assert scheduled_health.rc == 0, health_journal.stdout

    metrics = host.file("/var/lib/prometheus/node-exporter/lowerduckpond.prom")
    assert metrics.contains("lowerduckpond_health_failures 0")
    assert host.service("lowerduckpond-health.timer").is_enabled


def test_monitoring_reports_newer_backup_failures(host: Host) -> None:
    status_root = "/var/lib/lowerduckpond/backup-status"
    backup_success_path = f"{status_root}/backup-last-success"
    original_failure = host.file(f"{status_root}/backup-last-failure")
    original_failure_value = original_failure.content_string if original_failure.exists else None
    backup_success_timestamp, active_scope = read_status_record(host, backup_success_path)
    future_failure = backup_success_timestamp + 1

    try:
        write_status_record(
            host,
            f"{status_root}/backup-last-failure",
            future_failure,
            active_scope,
        )
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest scheduled backup failed" in unhealthy.stderr
    finally:
        if original_failure_value is None:
            host.run(f"rm -f {status_root}/backup-last-failure")
        else:
            restored_timestamp, restored_scope = original_failure_value.split()
            write_status_record(
                host,
                f"{status_root}/backup-last-failure",
                int(restored_timestamp),
                restored_scope,
            )

    restored = host.run("/usr/local/libexec/lowerduckpond/health-check")
    assert restored.rc == 0, restored.stderr


def test_monitoring_reports_newer_maintenance_failures(host: Host) -> None:
    status_root = "/var/lib/lowerduckpond/backup-status"
    status_names = ("maintenance-last-success", "maintenance-last-failure")
    original_values = {}
    for status_name in status_names:
        status = host.file(f"{status_root}/{status_name}")
        original_values[status_name] = status.content_string if status.exists else None

    now = int(host.run("date +%s").stdout.strip())
    active_scope = read_maintenance_scope(host)
    try:
        write_status_record(host, f"{status_root}/maintenance-last-success", now, active_scope)
        write_status_record(host, f"{status_root}/maintenance-last-failure", now + 1, active_scope)
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest backup maintenance failed" in unhealthy.stderr
    finally:
        for status_name, original_value in original_values.items():
            status_path = f"{status_root}/{status_name}"
            if original_value is None:
                host.run(f"rm -f {status_path}")
            else:
                restored_timestamp, restored_scope = original_value.split()
                write_status_record(host, status_path, int(restored_timestamp), restored_scope)

    restored = host.run("/usr/local/libexec/lowerduckpond/health-check")
    assert restored.rc == 0, restored.stderr


def test_monitoring_reports_stale_maintenance(host: Host) -> None:
    status_path = "/var/lib/lowerduckpond/backup-status/maintenance-last-success"
    original_success, active_scope = read_status_record(host, status_path)
    assert active_scope == read_maintenance_scope(host)
    stale_success = int(host.run("date +%s").stdout.strip()) - 691201

    try:
        write_status_record(host, status_path, stale_success, active_scope)
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest backup maintenance is too old" in unhealthy.stderr
    finally:
        write_status_record(host, status_path, original_success, active_scope)

    restored = host.run("/usr/local/libexec/lowerduckpond/health-check")
    assert restored.rc == 0, restored.stderr


def test_monitoring_ignores_status_from_another_maintenance_scope(host: Host) -> None:
    status_path = "/var/lib/lowerduckpond/backup-status/maintenance-last-success"
    original_success, active_scope = read_status_record(host, status_path)
    assert active_scope == read_maintenance_scope(host)
    zero_scope = "0" * BACKUP_SCOPE_LENGTH
    inactive_scope = zero_scope if active_scope != zero_scope else "1" * BACKUP_SCOPE_LENGTH

    try:
        write_status_record(host, status_path, original_success, inactive_scope)
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "no successful backup maintenance is recorded" in unhealthy.stderr
    finally:
        write_status_record(host, status_path, original_success, active_scope)

    restored = host.run("/usr/local/libexec/lowerduckpond/health-check")
    assert restored.rc == 0, restored.stderr


def test_provisioner_privilege_is_narrow(host: Host) -> None:
    account = host.user("ldp-provisioner")
    assert account.exists
    assert account.shell == "/usr/sbin/nologin"

    content_root = host.file("/srv/lowerduckpond")
    assert content_root.user == "root"
    assert content_root.group == "root"
    assert content_root.mode == CONTENT_ROOT_MODE
    traversal = host.run("runuser --user ldp-provisioner -- test -x /srv/lowerduckpond")
    assert traversal.rc == 0

    active_routes = host.file("/etc/caddy/routes.d")
    assert active_routes.is_directory
    assert active_routes.user == "root"
    assert active_routes.group == "caddy"
    assert active_routes.mode == ROUTE_DIRECTORY_MODE

    live_write = host.run("runuser --user ldp-provisioner -- test -w /etc/caddy/routes.d")
    assert live_write.rc != 0
    content_write = host.run("runuser --user ldp-provisioner -- mkdir /srv/lowerduckpond/sites")
    assert content_write.rc != 0

    assert not host.file("/usr/local/libexec/lowerduckpond/publish-caddy-routes").exists
    assert not host.file("/etc/sudoers.d/lowerduckpond-provisioner").exists
