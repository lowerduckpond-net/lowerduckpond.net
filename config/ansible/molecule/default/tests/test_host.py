from __future__ import annotations

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


def test_backup_repository_and_restore(host: Host) -> None:
    assert host.file("/etc/lowerduckpond/backup.env").mode == BACKUP_ENVIRONMENT_MODE
    backup_script = host.file("/usr/local/libexec/lowerduckpond/backup")
    maintenance_script = host.file("/usr/local/libexec/lowerduckpond/backup-maintenance")
    lock_path = "/var/cache/lowerduckpond-backup/repository.lock"
    assert backup_script.content_string.index("mariadb-dump") < (
        backup_script.content_string.index("source /etc/lowerduckpond/backup.env")
    )
    assert backup_script.contains("/usr/bin/env --ignore-environment")
    assert backup_script.contains(f"lock_path={lock_path}")
    assert maintenance_script.contains(f"lock_path={lock_path}")

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

    lock_index = maintenance_script.content_string.index("flock --exclusive 9")
    restic_index = maintenance_script.content_string.index("restic forget")
    assert lock_index < restic_index
    assert maintenance_script.contains("--tag scheduled")
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
    assert host.file("/var/lib/lowerduckpond/backup-status/maintenance-last-success").exists
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
    health_script = host.file("/usr/local/libexec/lowerduckpond/health-check")
    assert health_script.contains("start lowerduckpond-podman-ready.service")
    assert not health_script.contains("restart lowerduckpond-podman-ready.service")
    caddy_validator = host.file("/usr/local/libexec/lowerduckpond/caddy-validate")
    assert caddy_validator.contains("lowerduckpond-caddy-validate")
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
    backup_success = host.file(f"{status_root}/backup-last-success")
    original_failure = host.file(f"{status_root}/backup-last-failure")
    original_failure_value = original_failure.content_string if original_failure.exists else None
    future_failure = int(backup_success.content_string.strip()) + 1

    try:
        write_failure = host.run(
            f"printf '%s\\n' {future_failure} > {status_root}/backup-last-failure"
        )
        assert write_failure.rc == 0
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest scheduled backup failed" in unhealthy.stderr
    finally:
        if original_failure_value is None:
            host.run(f"rm -f {status_root}/backup-last-failure")
        else:
            restored_value = int(original_failure_value.strip())
            host.run(f"printf '%s\\n' {restored_value} > {status_root}/backup-last-failure")

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
    try:
        host.run(f"printf '%s\\n' {now} > {status_root}/maintenance-last-success")
        host.run(f"printf '%s\\n' {now + 1} > {status_root}/maintenance-last-failure")
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest backup maintenance failed" in unhealthy.stderr
    finally:
        for status_name, original_value in original_values.items():
            status_path = f"{status_root}/{status_name}"
            if original_value is None:
                host.run(f"rm -f {status_path}")
            else:
                restored_value = int(original_value.strip())
                host.run(f"printf '%s\\n' {restored_value} > {status_path}")

    restored = host.run("/usr/local/libexec/lowerduckpond/health-check")
    assert restored.rc == 0, restored.stderr


def test_monitoring_reports_stale_maintenance(host: Host) -> None:
    status_path = "/var/lib/lowerduckpond/backup-status/maintenance-last-success"
    original_success = int(host.file(status_path).content_string.strip())
    stale_success = int(host.run("date +%s").stdout.strip()) - 691201

    try:
        host.run(f"printf '%s\\n' {stale_success} > {status_path}")
        unhealthy = host.run("/usr/local/libexec/lowerduckpond/health-check")
        assert unhealthy.rc != 0
        assert "latest backup maintenance is too old" in unhealthy.stderr
    finally:
        host.run(f"printf '%s\\n' {original_success} > {status_path}")

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
