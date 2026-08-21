from __future__ import annotations

from testinfra.host import Host

BACKUP_ENVIRONMENT_MODE = 0o600
CONTENT_ROOT_MODE = 0o711
ROUTE_FILE_MODE = 0o640
SUDOERS_MODE = 0o440
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


def test_only_expected_ports_listen_publicly(host: Host) -> None:
    listeners = host.run(
        "ss --listening --numeric --tcp | "
        "awk 'NR > 1 && ($4 ~ /^0.0.0.0:/ || $4 ~ /^\\[::\\]:/ || $4 ~ /^\\*:/) "
        '{sub(/^.*:/, "", $4); print $4}\''
    )
    assert listeners.rc == 0
    ports = set(listeners.stdout.splitlines())
    assert {"80", "443"}.issubset(ports)
    assert ports.issubset({"22", "80", "443"})


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
    check = host.run("/usr/local/libexec/lowerduckpond/restic-check")
    assert check.rc == 0
    restore = host.run("/usr/local/libexec/lowerduckpond/restore-smoke-test")
    assert restore.rc == 0
    assert host.service("lowerduckpond-backup.timer").is_enabled
    assert host.service("lowerduckpond-backup-maintenance.timer").is_enabled


def test_monitoring_is_local_and_healthy(host: Host) -> None:
    exporter = host.socket("tcp://127.0.0.1:9100")
    assert exporter.is_listening
    assert not host.socket("tcp://0.0.0.0:9100").is_listening

    health_unit = host.file("/etc/systemd/system/lowerduckpond-health.service")
    assert not health_unit.contains("ReadWritePaths=/var/lib/lowerduckpond/runtime")
    assert not health_unit.contains("BindReadOnlyPaths=/run/user/21000")
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

    active_routes = host.file("/etc/caddy/sites-enabled")
    assert active_routes.is_symlink
    live_write = host.run("runuser --user ldp-provisioner -- test -w /etc/caddy/sites-enabled")
    assert live_write.rc != 0

    site_id = "01JMOLECULE00000000000000"
    stage_route = host.run(
        "runuser --user ldp-provisioner -- sh -c "
        '\'printf "molecule\\n" > '
        f"/var/lib/lowerduckpond/caddy-routes-staging/{site_id}.route'"
    )
    assert stage_route.rc == 0
    publish = host.run(
        "runuser --user ldp-provisioner -- "
        "sudo /usr/local/libexec/lowerduckpond/publish-caddy-routes"
    )
    assert publish.rc == 0

    active_release = host.run("readlink --canonicalize /etc/caddy/sites-enabled")
    assert active_release.rc == 0
    published_route = host.file(f"{active_release.stdout.strip()}/{site_id}.caddy")
    assert published_route.user == "root"
    assert published_route.group == "ldp-caddy-routes"
    assert published_route.mode == ROUTE_FILE_MODE
    assert published_route.contains("host molecule.lowerduckpond.test")
    assert published_route.contains(rf"root \* /srv/lowerduckpond/sites/{site_id}/current")
    assert published_route.contains("file_server")
    assert not published_route.contains("CLOUDFLARE_API_TOKEN")

    malicious_stage = host.run(
        "runuser --user ldp-provisioner -- sh -c "
        '\'printf "{\\$CLOUDFLARE_API_TOKEN}\\n" > '
        "/var/lib/lowerduckpond/caddy-routes-staging/attacker.route'"
    )
    assert malicious_stage.rc == 0
    rejected = host.run(
        "runuser --user ldp-provisioner -- "
        "sudo /usr/local/libexec/lowerduckpond/publish-caddy-routes"
    )
    assert rejected.rc != 0
    unchanged_release = host.run("readlink --canonicalize /etc/caddy/sites-enabled")
    assert unchanged_release.stdout == active_release.stdout

    remove_malicious = host.run(
        "runuser --user ldp-provisioner -- "
        "rm /var/lib/lowerduckpond/caddy-routes-staging/attacker.route"
    )
    assert remove_malicious.rc == 0
    unsafe_stage = host.run(
        "runuser --user ldp-provisioner -- "
        "ln --symbolic /etc/shadow "
        "/var/lib/lowerduckpond/caddy-routes-staging/unsafe.route"
    )
    assert unsafe_stage.rc == 0
    rejected_symlink = host.run(
        "runuser --user ldp-provisioner -- "
        "sudo /usr/local/libexec/lowerduckpond/publish-caddy-routes"
    )
    assert rejected_symlink.rc != 0
    unchanged_after_symlink = host.run("readlink --canonicalize /etc/caddy/sites-enabled")
    assert unchanged_after_symlink.stdout == active_release.stdout

    sudoers = host.file("/etc/sudoers.d/lowerduckpond-provisioner")
    assert sudoers.mode == SUDOERS_MODE
    assert sudoers.contains("/usr/local/libexec/lowerduckpond/publish-caddy-routes")
    assert not sudoers.contains(" ALL=(ALL)")
