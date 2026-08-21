from __future__ import annotations

from testinfra.host import Host

BACKUP_ENVIRONMENT_MODE = 0o600
CONTENT_ROOT_MODE = 0o711
SUDOERS_MODE = 0o440


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

    sudoers = host.file("/etc/sudoers.d/lowerduckpond-provisioner")
    assert sudoers.mode == SUDOERS_MODE
    assert sudoers.contains("/usr/local/libexec/lowerduckpond/reload-caddy")
    assert not sudoers.contains(" ALL=(ALL)")
