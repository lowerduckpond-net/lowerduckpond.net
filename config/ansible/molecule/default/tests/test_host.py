from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import result_digest
from testinfra.host import Host

BACKUP_ENVIRONMENT_MODE = 0o600
BACKUP_COMMAND_MODE = 0o755
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
    "/var/lib/lowerduckpond/static",
)
BACKUP_EXCLUDE_PATHS = (
    "/var/lib/lowerduckpond/static/intake",
    "/srv/lowerduckpond/sites/.staging",
    "/var/lib/lowerduckpond/static/exports",
    "/etc/caddy/generations",
    "/etc/caddy/environment",
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
    "/etc/systemd/system/lowerduckpond-static-reconcile.service",
    "/etc/systemd/system/lowerduckpond-static-reconcile.timer",
    "/etc/systemd/system/lowerduckpond-static-worker@.service",
    "/etc/systemd/system/lowerduckpond-static-workers.slice",
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
    "reserved_namespace.py",
    "session.py",
)
QUALIFICATION_REPAIRED_LOG_PATH = "/tmp/lowerduckpond-m3-qualification-repair.json"  # noqa: S108
QUALIFICATION_SUDOERS_MODE = 0o440
QUALIFICATION_STATIC_FILE_MODE = 0o640
QUALIFICATION_STATIC_ROOT = "/tmp/lowerduckpond-m3-static"  # noqa: S108
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
STATIC_HOST_AGENT_ROOT = "/opt/lowerduckpond/static-host-agent"
STATIC_STATE_ROOT = "/var/lib/lowerduckpond/static"
STATIC_RELEASE_ROOT = "/srv/lowerduckpond/sites"
STATIC_RELEASE_STAGING_ROOT = f"{STATIC_RELEASE_ROOT}/.staging"
STATIC_RELEASE_ROOT_MODE = 0o710
STATIC_RELEASE_STAGING_ROOT_MODE = 0o700
STATIC_HOST_AGENT_DIRECTORY_MODE = 0o555
STATIC_HOST_AGENT_FILE_MODE = 0o444
STATIC_STATE_DIRECTORY_MODE = 0o700
STATIC_STATE_LOCK_MODE = 0o600
STATIC_SELECTION_LOCK_MODE = 0o600
STATIC_CONFIGURATION_MODE = 0o400
STATIC_PUBLICATION_DISABLED_STATUS = 78
STATIC_OPERATOR_DISABLED_STATUS = 78
STATIC_OPERATOR_INVALID_REQUEST_STATUS = 65
STATIC_OPERATOR_KEY_PATH = "/run/lowerduckpond-molecule/operator-key"
STATIC_OPERATOR_AUTHORIZED_KEYS_PATH = "/etc/ssh/lowerduckpond/authorized_keys/ldp-operator"
STATIC_OPERATOR_COMMAND = "/usr/local/libexec/lowerduckpond/static-operator-adapter"
STATIC_JOB_EXECUTOR = "/usr/local/libexec/lowerduckpond/execute-authorized-job"
STATIC_JOB_RECONCILER = "/usr/local/libexec/lowerduckpond/reconcile-authorized-jobs"
STATIC_OPERATOR_REQUEST_DECODER = "/usr/local/libexec/lowerduckpond/static-request-decoder"
STATIC_OPERATOR_COMMAND_MODE = 0o755
STATIC_OPERATOR_KEY_DIRECTORY_MODE = 0o755
STATIC_OPERATOR_KEY_FILE_MODE = 0o640
STATIC_OPERATOR_HOME_MODE = 0o555
STATIC_CADDY_RUNTIME_MODE = 0o750
STATIC_CADDY_ADMIN_SOCKET_MODE = 0o620
SSHD_SETTING_FIELD_COUNT = 2
STATIC_STATE_DIRECTORIES = (
    "platform",
    "tenants",
    "authorization",
    "authorization/jobs",
    "authorization/results",
    "authorization/correlations",
    "intents",
    "intake",
    "exports",
    "audit",
    "locks",
)
STATIC_STATE_LOCKS = (
    "intake.lock",
    "export.lock",
    "publication.lock",
    "tenant-state.lock",
)
STATIC_ACCEPTED_FIXTURES = (
    Path(__file__).resolve().parents[5] / "tests/static-publication/fixtures/accepted"
)


def static_operator_ssh_command(
    *arguments: str,
    options: tuple[str, ...] = (),
) -> str:
    base = (
        "/usr/bin/ssh -F /dev/null "
        f"-i {shlex.quote(STATIC_OPERATOR_KEY_PATH)} "
        "-o BatchMode=yes -o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR -o ConnectTimeout=5"
    )
    if options:
        base = f"{base} {shlex.join(options)}"
    base = f"{base} ldp-operator@127.0.0.1"
    if not arguments:
        return base
    return f"{base} {shlex.join(arguments)}"


def seed_static_authorization(host: Host, selected_root: str) -> str:
    """Seed one accepted job/result pair without opening publication."""

    job = json.loads(
        (STATIC_ACCEPTED_FIXTURES / "authorization-job.json").read_text(encoding="utf-8")
    )
    result = json.loads(
        (STATIC_ACCEPTED_FIXTURES / "operation-result.json").read_text(encoding="utf-8")
    )
    audit = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "AuditEntry",
        "sequence": 0,
        "previousEntryDigest": None,
        "timestamp": job["acceptedAt"],
        "operatorPrincipal": job["operatorPrincipal"],
        "operation": result["operation"],
        "tenantId": result["tenantId"],
        "correlationId": result["correlationId"],
        "resultDigest": result_digest(result).to_dict(),
        "resultStatus": result["status"],
    }
    job_id = job["jobId"]
    correlation_id = job["request"]["correlationId"]
    documents = json.dumps(
        {"job": job, "result": result, "audit": audit},
        separators=(",", ":"),
    )

    seed = host.run(
        "/usr/bin/python3 -I -B -c %s",
        "from pathlib import Path; "
        "import json, sys; "
        f"sys.path.insert(0, {selected_root!r} + '/site-packages'); "
        "from lowerduckpond_static_host_agent import StateRecordPath, StateRepository; "
        f"documents = json.loads({documents!r}); "
        f"repository = StateRepository(Path({STATIC_STATE_ROOT!r}), expected_owner=0); "
        "job = documents['job']; "
        "repository.create_immutable("
        f"StateRecordPath.authorization_correlation({correlation_id!r}), job); "
        "repository.create_immutable("
        f"StateRecordPath.authorization_job({job_id!r}), job); "
        "repository.create_immutable("
        f"StateRecordPath.authorization_result({job_id!r}), documents['result']); "
        "repository.append_audit(documents['audit']); "
        "repository.close()",
    )
    assert seed.rc == 0, seed.stderr
    assert host.file(f"{STATIC_STATE_ROOT}/authorization/jobs/{job_id}.json").exists
    return job_id


def assert_static_worker_sudo_compatibility(host: Host) -> None:
    """Require only the sandbox operations needed by sudo and PAM."""

    unit = host.file("/etc/systemd/system/lowerduckpond-static-worker@.service")
    assert unit.contains("RestrictAddressFamilies=AF_UNIX")
    assert all(
        not unit.contains(required_sudo_operation)
        for required_sudo_operation in (
            "SystemCallFilter=~@network-io",
            "SystemCallFilter=~@resources",
            "SystemCallFilter=~prlimit64",
            "SystemCallFilter=~pipe pipe2",
        )
    )
    assert unit.contains("SystemCallFilter=~mknod mknodat")


def assert_static_worker_caddy_runtime_access(host: Host) -> None:
    """Require only the host paths used by root-owned Caddy transactions."""

    unit = host.file("/etc/systemd/system/lowerduckpond-static-worker@.service")
    assert unit.contains(f"ConditionPathIsReadWrite={STATIC_STATE_ROOT}")
    assert unit.contains(f"ConditionPathIsReadWrite={STATIC_RELEASE_ROOT}")
    assert unit.contains(f"BindPaths={STATIC_STATE_ROOT}")
    assert unit.contains(f"BindPaths={STATIC_RELEASE_ROOT}")
    assert unit.contains("BindPaths=/etc/caddy")
    assert unit.contains("BindPaths=/run/caddy")
    assert unit.contains("BindReadOnlyPaths=/run/systemd")
    assert not unit.contains("InaccessiblePaths=/proc")
    assert unit.contains(
        f"ExecStart=/usr/bin/sudo --non-interactive --user=root --group=caddy "
        f"{STATIC_JOB_EXECUTOR} %i"
    )

    selected = host.run(f"readlink --canonicalize {STATIC_HOST_AGENT_ROOT}/current")
    assert selected.rc == 0
    probe = (
        "import os,pwd,shutil,sys;"
        f"sys.path.insert(0,{(selected.stdout.strip() + '/site-packages')!r});"
        "import lowerduckpond_static_host_agent.caddy_admin as admin;"
        "import lowerduckpond_static_host_agent.caddy_runtime as runtime;"
        "pid,invocation=admin._running_caddy_service_identity();"
        "assert pid>1 and len(invocation)==32;"
        "assert admin._read_caddy_admin_configuration();"
        "admin._normalize_admin_socket();"
        "assert os.access('/usr/bin/bash',os.X_OK);"
        "caddy=pwd.getpwnam('caddy');"
        "validation_root,environment=runtime._create_validation_environment({},"
        "validation_uid=caddy.pw_uid,validation_gid=caddy.pw_gid);"
        "os.seteuid(caddy.pw_uid);"
        "open(environment['TMPDIR']+'/candidate-output','w').close();"
        "os.seteuid(0);"
        "shutil.rmtree(validation_root);"
        "validator_fd=os.open('/usr/bin/true',os.O_RDONLY|os.O_CLOEXEC);"
        "validation=runtime._run_validation_command(validator_fd,[],environment={},"
        "inherited_descriptors=(),validation_uid=caddy.pw_uid,"
        "validation_gid=caddy.pw_gid);"
        "os.close(validator_fd);"
        "assert validation.returncode==0;"
        "fd=os.open('/workspace/chown-probe',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
        "os.fchown(fd,0,pwd.getpwnam('caddy').pw_gid);"
        "os.close(fd)"
    )
    command = shlex.join(
        (
            "systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--unit=lowerduckpond-static-worker-access-probe",
            "--property=User=root",
            "--property=Group=caddy",
            "--property=TemporaryFileSystem=/:ro",
            "--property=TemporaryFileSystem=/workspace:rw,size=64M,nr_inodes=4096,mode=0700",
            "--property=BindReadOnlyPaths=/usr",
            "--property=BindReadOnlyPaths=/lib",
            "--property=BindReadOnlyPaths=/lib64",
            "--property=BindReadOnlyPaths=/etc/group",
            "--property=BindReadOnlyPaths=/etc/nsswitch.conf",
            "--property=BindReadOnlyPaths=/etc/passwd",
            f"--property=BindReadOnlyPaths={STATIC_HOST_AGENT_ROOT}",
            "--property=BindPaths=/run/caddy",
            "--property=BindReadOnlyPaths=/run/systemd",
            "--property=ProtectProc=invisible",
            "--property=ProcSubset=pid",
            "--property=CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID",
            "--property=NoNewPrivileges=no",
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            probe,
        )
    )
    result = host.run(command)
    assert result.rc == 0, result.stderr


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


def test_qualification_static_fixtures_include_a_canonical_root(host: Host) -> None:
    root = host.file(QUALIFICATION_STATIC_ROOT)
    assert root.is_directory
    assert root.user == "root"
    assert root.group == "caddy"
    assert root.mode == ROUTE_DIRECTORY_MODE

    canonical = host.file(f"{QUALIFICATION_STATIC_ROOT}/index.html")
    assert canonical.is_file
    assert canonical.user == "root"
    assert canonical.group == "caddy"
    assert canonical.mode == QUALIFICATION_STATIC_FILE_MODE
    assert canonical.content_string == "lowerduckpond-m3-canonical-root"


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
    mode_index = unit.content_string.index("ExecReload=/usr/bin/chmod 0620 /run/caddy/admin.sock")
    assert validate_index < reload_index
    assert reload_index < mode_index
    assert "--address unix//run/caddy/admin.sock" in unit.content_string
    assert "Restart=on-failure" in unit.content_string


def test_caddy_admin_api_is_caddy_only(host: Host) -> None:
    configuration = host.file("/etc/caddy/Caddyfile")
    assert configuration.contains("admin unix//run/caddy/admin.sock")

    socket = host.file("/run/caddy/admin.sock")
    assert socket.exists
    assert socket.user == "caddy"
    assert socket.group == "caddy"
    assert socket.mode == STATIC_CADDY_ADMIN_SOCKET_MODE
    runtime = host.file("/run/caddy")
    assert runtime.user == "caddy"
    assert runtime.group == "caddy"
    assert runtime.mode == STATIC_CADDY_RUNTIME_MODE
    assert not host.socket("tcp://127.0.0.1:2019").is_listening

    denied = host.run(
        "runuser --user ldp-provisioner -- "
        "curl --fail --silent --unix-socket /run/caddy/admin.sock "
        "http://localhost/config/"
    )
    assert denied.rc != 0

    root_worker = host.run(
        "setpriv --reuid=0 --regid=caddy --clear-groups "
        "--bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "
        "curl --fail --silent --unix-socket /run/caddy/admin.sock "
        "http://localhost/config/"
    )
    assert root_worker.rc == 0


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


def test_backup_serializes_the_static_snapshot_boundary(host: Host) -> None:
    backup_script = host.file("/usr/local/libexec/lowerduckpond/backup")
    content = backup_script.content_string
    credential_export_index = content.index("export AWS_ACCESS_KEY_ID")
    snapshot_index = content.index("backup-static-snapshot")
    backup_index = content.index("/usr/bin/restic backup")

    assert credential_export_index < snapshot_index < backup_index
    snapshot = host.file("/usr/local/libexec/lowerduckpond/backup-static-snapshot")
    snapshot_content = snapshot.content_string
    assert snapshot.user == "root"
    assert snapshot.group == "root"
    assert snapshot.mode == BACKUP_COMMAND_MODE
    assert '"/var/lib/lowerduckpond/static/locks/publication.lock"' in snapshot_content
    assert '"/var/lib/lowerduckpond/static/locks/tenant-state.lock"' in snapshot_content
    assert 'sys.argv[1:3] != ["/usr/bin/restic", "backup"]' in snapshot_content
    assert "os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC" in snapshot_content
    assert "os.O_CREAT" not in snapshot_content
    assert "metadata.st_nlink != 1" in snapshot_content
    assert "fcntl.flock(descriptor, fcntl.LOCK_SH)" in snapshot_content
    assert "_require_quiescent_staging()" in snapshot_content


def test_backup_refuses_missing_or_linked_static_locks(host: Host) -> None:
    lock_path = "/var/lib/lowerduckpond/static/locks/publication.lock"
    saved_path = "/var/lib/lowerduckpond/static/locks/publication.lock.acceptance"
    tenant_lock_path = "/var/lib/lowerduckpond/static/locks/tenant-state.lock"
    moved = host.run("mv -- %s %s", lock_path, saved_path)
    assert moved.rc == 0
    try:
        missing = host.run("/usr/local/libexec/lowerduckpond/backup")
        assert missing.rc != 0
        assert "lock could not be opened safely" in missing.stderr

        linked = host.run("ln -s -- %s %s", tenant_lock_path, lock_path)
        assert linked.rc == 0
        rejected = host.run("/usr/local/libexec/lowerduckpond/backup")
        assert rejected.rc != 0
        assert "lock could not be opened safely" in rejected.stderr
    finally:
        host.run("rm -f -- %s", lock_path)
        restored = host.run("mv -- %s %s", saved_path, lock_path)
        assert restored.rc == 0


def test_backup_rejects_nonempty_release_staging(host: Host) -> None:
    staging_entry = (
        "/srv/lowerduckpond/sites/.staging/"
        "0198d17f-6f4a-7000-8000-000000000001--"
        "0198d17f-6f4a-7000-8000-000000000002"
    )
    created = host.run("install -d -m 0700 %s", staging_entry)
    assert created.rc == 0
    try:
        blocked = host.run("/usr/local/libexec/lowerduckpond/backup")
        assert blocked.rc != 0
        assert "release staging is nonempty" in blocked.stderr
    finally:
        removed = host.run("rmdir %s", staging_entry)
        assert removed.rc == 0

    recovered = host.run("/usr/local/libexec/lowerduckpond/backup")
    assert recovered.rc == 0, recovered.stderr


def test_backup_scope_excludes_ephemeral_static_state(host: Host) -> None:
    backup_script = host.file("/usr/local/libexec/lowerduckpond/backup")
    for exclude_path in BACKUP_EXCLUDE_PATHS:
        assert backup_script.contains(f"--exclude {exclude_path}")
    assert backup_script.contains('--tag "scope-${status_scope}"')
    scoped_filter = '--tag "scheduled,scope-${LOWERDUCKPOND_BACKUP_STATUS_SCOPE}"'
    assert host.file("/usr/local/libexec/lowerduckpond/latest-backup-snapshot").contains(
        scoped_filter
    )
    assert host.file("/usr/local/libexec/lowerduckpond/restore-smoke-test").contains(scoped_filter)


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
    assert restore_script.contains('--tag "scheduled,scope-${LOWERDUCKPOND_BACKUP_STATUS_SCOPE}"')
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
    assert health_unit.contains(
        "ReadWritePaths=/var/lib/prometheus/node-exporter "
        "/var/lib/lowerduckpond/static/locks/publication.lock"
    )
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
    for qualification_log_path in (
        QUALIFICATION_LOG_PATH,
        QUALIFICATION_REPAIRED_LOG_PATH,
    ):
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
    assert account.home == "/nonexistent"

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
    content_write = host.run(
        "runuser --user ldp-provisioner -- mkdir /srv/lowerduckpond/sites/denied"
    )
    assert content_write.rc != 0

    assert not host.file("/usr/local/libexec/lowerduckpond/publish-caddy-routes").exists
    assert not host.file("/etc/sudoers.d/lowerduckpond-provisioner").exists


def test_static_host_agent_is_hash_pinned_and_immutable(host: Host) -> None:
    selected = host.run(f"readlink --canonicalize {STATIC_HOST_AGENT_ROOT}/current")
    assert selected.rc == 0
    selected_root = selected.stdout.strip()
    digest = selected_root.rsplit("/", 1)[-1]
    assert len(digest) == BACKUP_SCOPE_LENGTH
    assert all(character in "0123456789abcdef" for character in digest)

    root = host.file(selected_root)
    assert root.is_directory
    assert root.user == "root"
    assert root.group == "root"
    assert root.mode == STATIC_HOST_AGENT_DIRECTORY_MODE
    verification = host.run(
        "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact %s",
        selected_root,
    )
    assert verification.rc == 0

    ownership_victim = f"{selected_root}/site-packages/lowerduckpond_static_host_agent/__init__.py"
    try:
        assert host.run(f"chown ldp-provisioner:ldp-provisioner {ownership_victim}").rc == 0
        refused = host.run(
            "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact %s",
            selected_root,
        )
        assert refused.rc != 0
        assert "unexpected owner" in refused.stderr
    finally:
        assert host.run(f"chown root:root {ownership_victim}").rc == 0
    assert (
        host.run(
            "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact %s",
            selected_root,
        ).rc
        == 0
    )
    assert (
        host.run(rf"find {selected_root} \( ! -user root -o ! -group root \) -print -quit").stdout
        == ""
    )
    assert host.run(f"find {selected_root} -type d ! -perm 0555 -print -quit").stdout == ""
    assert host.run(f"find {selected_root} -type f ! -perm 0444 -print -quit").stdout == ""
    assert host.file(f"{selected_root}/artifact-manifest.json").mode == STATIC_HOST_AGENT_FILE_MODE
    imports = host.run(
        "PYTHONPATH=%s/site-packages /usr/bin/python3 -I -B -c %s",
        selected_root,
        "import sys; "
        f"sys.path.insert(0, {selected_root!r} + '/site-packages'); "
        "import lowerduckpond_static_contracts, lowerduckpond_static_domain, "
        "lowerduckpond_static_host_agent",
    )
    assert imports.rc == 0
    assert host.run(f"find {STATIC_HOST_AGENT_ROOT} -maxdepth 1 -name '.install-*'").stdout == ""


def test_static_host_agent_selection_is_locked(host: Host) -> None:
    selection_lock = host.file(f"{STATIC_HOST_AGENT_ROOT}/selection.lock")
    assert selection_lock.is_file
    assert selection_lock.user == "root"
    assert selection_lock.group == "root"
    assert selection_lock.mode == STATIC_SELECTION_LOCK_MODE
    assert selection_lock.size == 0
    for command in (
        STATIC_JOB_EXECUTOR,
        STATIC_JOB_RECONCILER,
        STATIC_OPERATOR_COMMAND,
        STATIC_OPERATOR_REQUEST_DECODER,
    ):
        wrapper = host.file(command)
        assert wrapper.contains(
            f'SELECTION_LOCK = pathlib.Path("{STATIC_HOST_AGENT_ROOT}/selection.lock")'
        )
        assert wrapper.contains("fcntl.LOCK_SH")


def test_static_state_migration_is_empty_root_owned_and_private(host: Host) -> None:
    for legacy in ("provisioner", "jobs", "manifests", "audit"):
        assert not host.file(f"/var/lib/lowerduckpond/{legacy}").exists
    root = host.file(STATIC_STATE_ROOT)
    assert root.is_directory
    assert root.user == "root"
    assert root.group == "root"
    assert root.mode == STATIC_STATE_DIRECTORY_MODE
    for relative in STATIC_STATE_DIRECTORIES:
        directory = host.file(f"{STATIC_STATE_ROOT}/{relative}")
        assert directory.is_directory
        assert directory.user == "root"
        assert directory.group == "root"
        assert directory.mode == STATIC_STATE_DIRECTORY_MODE
    for filename in STATIC_STATE_LOCKS:
        lock = host.file(f"{STATIC_STATE_ROOT}/locks/{filename}")
        assert lock.is_file
        assert lock.user == "root"
        assert lock.group == "root"
        assert lock.mode == STATIC_STATE_LOCK_MODE
        assert lock.size == 0
    files = host.run(f"find {STATIC_STATE_ROOT} -type f -printf '%P\\n' | sort")
    assert files.rc == 0
    assert files.stdout.splitlines() == [f"locks/{name}" for name in sorted(STATIC_STATE_LOCKS)]
    denied = host.run(f"runuser --user ldp-provisioner -- test -x {STATIC_STATE_ROOT}")
    assert denied.rc != 0

    release_root = host.file(STATIC_RELEASE_ROOT)
    assert release_root.is_directory
    assert release_root.user == "root"
    assert release_root.group == "caddy"
    assert release_root.mode == STATIC_RELEASE_ROOT_MODE
    staging_root = host.file(STATIC_RELEASE_STAGING_ROOT)
    assert staging_root.is_directory
    assert staging_root.user == "root"
    assert staging_root.group == "root"
    assert staging_root.mode == STATIC_RELEASE_STAGING_ROOT_MODE


def test_static_publication_gate_rejects_before_allocation(host: Host) -> None:
    configuration = host.file("/etc/lowerduckpond/static-publication.json")
    assert configuration.user == "root"
    assert configuration.group == "root"
    assert configuration.mode == STATIC_CONFIGURATION_MODE
    assert configuration.content_string == (
        '{"format":"lowerduckpond-static-publication-gate-v1","static_publication_enabled":false}\n'
    )
    before = host.run(f"find {STATIC_STATE_ROOT} -printf '%P %y %m %u %g\\n'")
    rejected = host.run("/usr/local/libexec/lowerduckpond/static-publication-gate job-issuance")
    after = host.run(f"find {STATIC_STATE_ROOT} -printf '%P %y %m %u %g\\n'")
    assert rejected.rc == STATIC_PUBLICATION_DISABLED_STATUS
    assert rejected.stderr.strip() == "publication_disabled"
    assert before.stdout == after.stdout
    empty_candidate = host.run(
        "/usr/local/libexec/lowerduckpond/static-publication-gate caddy-generation 0"
    )
    tenant_candidate = host.run(
        "/usr/local/libexec/lowerduckpond/static-publication-gate caddy-generation 1"
    )
    assert empty_candidate.rc == 0
    assert tenant_candidate.rc == STATIC_PUBLICATION_DISABLED_STATUS
    assert tenant_candidate.stderr.strip() == "publication_disabled"


def test_static_operator_identity_is_root_bound_and_has_no_writable_home(
    host: Host,
) -> None:
    account = host.user("ldp-operator")
    assert account.exists
    assert account.group == "ldp-operator"
    assert account.home == "/var/empty/lowerduckpond-static-operator"
    assert account.shell == "/bin/sh"
    assert host.run("id -Gn ldp-operator").stdout.strip() == "ldp-operator"

    home = host.file(account.home)
    assert home.is_directory
    assert home.user == "root"
    assert home.group == "root"
    assert home.mode == STATIC_OPERATOR_HOME_MODE
    assert host.run(f"find {account.home} -mindepth 1 -print -quit").stdout == ""
    assert host.run(f"runuser -u ldp-operator -- touch {account.home}/escape").rc != 0

    shadow = host.run("getent shadow ldp-operator")
    assert shadow.rc == 0
    password_field = shadow.stdout.split(":", maxsplit=2)[1]
    assert password_field.startswith("$6$LdPM3Op20260830$")
    assert not password_field.startswith(("!", "*"))

    command = host.file(STATIC_OPERATOR_COMMAND)
    assert command.is_file
    assert command.user == "root"
    assert command.group == "root"
    assert command.mode == STATIC_OPERATOR_COMMAND_MODE

    key_directory = host.file("/etc/ssh/lowerduckpond/authorized_keys")
    assert key_directory.is_directory
    assert key_directory.user == "root"
    assert key_directory.group == "root"
    assert key_directory.mode == STATIC_OPERATOR_KEY_DIRECTORY_MODE
    authorized_keys = host.file(STATIC_OPERATOR_AUTHORIZED_KEYS_PATH)
    assert authorized_keys.is_file
    assert authorized_keys.user == "root"
    assert authorized_keys.group == "ldp-operator"
    assert authorized_keys.mode == STATIC_OPERATOR_KEY_FILE_MODE
    key_lines = [
        line
        for line in authorized_keys.content_string.splitlines()
        if line and not line.startswith("#")
    ]
    assert len(key_lines) == 1
    assert key_lines[0].startswith(
        'command="/usr/bin/env -i LANG=C.UTF-8 /usr/bin/sudo -n '
        f'{STATIC_OPERATOR_COMMAND} --principal molecule-operator-v1",restrict ssh-ed25519 '
    )
    assert "environment=" not in key_lines[0]
    assert "permitopen=" not in key_lines[0]
    assert host.run(f"ssh-keygen -l -f {STATIC_OPERATOR_AUTHORIZED_KEYS_PATH}").rc == 0


def test_static_operator_effective_sshd_policy_denies_side_channels(host: Host) -> None:
    result = host.run("/usr/sbin/sshd -T -C user=ldp-operator,host=localhost,addr=127.0.0.1")
    assert result.rc == 0
    settings = {
        fields[0]: fields[1]
        for line in result.stdout.splitlines()
        if len(fields := line.split(maxsplit=1)) == SSHD_SETTING_FIELD_COUNT
    }
    expected = {
        "allowagentforwarding": "no",
        "allowstreamlocalforwarding": "no",
        "allowtcpforwarding": "no",
        "authenticationmethods": "publickey",
        "authorizedkeysfile": STATIC_OPERATOR_AUTHORIZED_KEYS_PATH,
        "disableforwarding": "yes",
        "gatewayports": "no",
        "kbdinteractiveauthentication": "no",
        "maxsessions": "1",
        "passwordauthentication": "no",
        "permitlisten": "none",
        "permitopen": "none",
        "permittty": "no",
        "permituserenvironment": "no",
        "permituserrc": "no",
        "pubkeyauthentication": "yes",
        "x11forwarding": "no",
    }
    for name, value in expected.items():
        assert settings[name] == value


def test_static_operator_request_decoder_is_isolated_and_strict(host: Host) -> None:
    decoder = host.file(STATIC_OPERATOR_REQUEST_DECODER)
    assert decoder.is_file
    assert decoder.user == "root"
    assert decoder.group == "root"
    assert decoder.mode == STATIC_OPERATOR_COMMAND_MODE
    request = (
        '{"apiVersion":"hosting.lowerduckpond.net/v1alpha1",'
        '"correlationId":"0198d17f-6f4a-7000-8000-000000000001",'
        '"kind":"OperationRequest","operation":"create",'
        '"quotas":{"entries":5000,"storageMiB":100},"slug":"duck-repair"}'
    )
    accepted = host.run(
        "printf %%s %s | %s",
        request,
        STATIC_OPERATOR_REQUEST_DECODER,
    )
    duplicate = host.run(
        "printf %%s %s | %s",
        request.replace('"slug":"duck-repair"', '"slug":"duck-repair","slug":"other"'),
        STATIC_OPERATOR_REQUEST_DECODER,
    )
    assert accepted.rc == 0
    assert accepted.stdout == f"{request}\n"
    assert duplicate.rc == STATIC_OPERATOR_INVALID_REQUEST_STATUS
    assert duplicate.stderr.strip() == "request_invalid"


def test_static_operator_real_ssh_is_forced_and_allocation_free(host: Host) -> None:
    before = host.run(f"find {STATIC_STATE_ROOT} -printf '%P %y %m %u %g\\n' | sort")
    shell = host.run(static_operator_ssh_command())
    assert shell.rc == STATIC_OPERATOR_DISABLED_STATUS
    assert shell.stderr.strip() == "publication_disabled"

    sentinel = "/tmp/lowerduckpond-static-operator-command-escape"  # noqa: S108
    arbitrary = host.run(static_operator_ssh_command("/usr/bin/touch", sentinel))
    assert arbitrary.rc == STATIC_OPERATOR_DISABLED_STATUS
    assert arbitrary.stderr.strip() == "publication_disabled"
    assert not host.file(sentinel).exists

    environment = host.run(
        static_operator_ssh_command(
            "/usr/bin/env",
            options=("-o", "SetEnv=M3_OPERATOR_SENTINEL=attacker"),
        )
    )
    assert environment.rc == STATIC_OPERATOR_DISABLED_STATUS
    assert environment.stderr.strip() == "publication_disabled"
    assert "M3_OPERATOR_SENTINEL" not in environment.stdout

    pty = host.run(static_operator_ssh_command("/usr/bin/id", options=("-tt",)))
    assert pty.rc != 0
    assert not host.file(sentinel).exists

    forwarding = host.run(
        "timeout 8s "
        + static_operator_ssh_command(
            options=(
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                "127.0.0.1:45876:127.0.0.1:22",
            )
        )
    )
    assert forwarding.rc != 0

    after = host.run(f"find {STATIC_STATE_ROOT} -printf '%P %y %m %u %g\\n' | sort")
    assert before.stdout == after.stdout


def test_static_operator_real_ssh_denies_sftp_and_scp(host: Host) -> None:
    common = (
        f"-F /dev/null -i {STATIC_OPERATOR_KEY_PATH} "
        "-o BatchMode=yes -o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR -o ConnectTimeout=5"
    )
    sftp = host.run(f"/usr/bin/sftp {common} -b /dev/null ldp-operator@127.0.0.1")
    assert sftp.rc != 0

    destination = "/tmp/lowerduckpond-static-operator-scp-escape"  # noqa: S108
    scp = host.run(f"/usr/bin/scp {common} /etc/hostname ldp-operator@127.0.0.1:{destination}")
    assert scp.rc != 0
    assert not host.file(destination).exists


def test_static_job_commands_are_root_owned_and_uuid_only(host: Host) -> None:
    for command_path in (STATIC_JOB_EXECUTOR, STATIC_JOB_RECONCILER):
        command = host.file(command_path)
        assert command.is_file
        assert command.user == "root"
        assert command.group == "root"
        assert command.mode == STATIC_OPERATOR_COMMAND_MODE

    sudoers = host.file("/etc/sudoers.d/lowerduckpond-static-jobs")
    assert sudoers.is_file
    assert sudoers.user == "root"
    assert sudoers.group == "root"
    assert sudoers.mode == QUALIFICATION_SUDOERS_MODE
    assert sudoers.content_string == (
        f"Defaults!{STATIC_JOB_EXECUTOR} !use_pty\n"
        f"ldp-provisioner ALL=(root:caddy) NOPASSWD: {STATIC_JOB_EXECUTOR}\n"
    )
    prefix = ("runuser", "--user", "ldp-provisioner", "--", "sudo", "-n")
    unknown = host.run(shlex.join((*prefix, STATIC_JOB_EXECUTOR, VALID_UUIDV7)))
    assert unknown.rc != 0
    assert unknown.stderr.strip() == "authorized_job_failed:FileNotFoundError"
    for arguments in UUID_REJECTION_ARGUMENTS:
        rejected = host.run(shlex.join((*prefix, STATIC_JOB_EXECUTOR, *arguments)))
        assert rejected.rc != 0
    assert host.run(shlex.join((*prefix, STATIC_JOB_RECONCILER))).rc != 0


def assert_static_worker_execution(host: Host) -> None:
    assert host.run("systemctl is-enabled lowerduckpond-static-worker@.service").stdout.strip() == (
        "static"
    )
    instance = "lowerduckpond-static-worker@0198d17f-6f4a-7000-8000-000000000001.service"
    host.run_expect([0], f"systemctl start {instance}")
    host.run_expect(
        [0],
        f"timeout 5s bash -c 'until systemctl is-failed --quiet {instance}; do sleep 0.05; done'",
    )
    status = host.run(f"systemctl show --property=ExecMainStatus --value {instance}")
    assert status.stdout.strip() == "1"
    host.run_expect([0], f"systemctl reset-failed {instance}")

    reconciler = host.file("/etc/systemd/system/lowerduckpond-static-reconcile.service")
    assert reconciler.contains(f"ExecStart={STATIC_JOB_RECONCILER}")
    assert reconciler.contains(f"ReadWritePaths={STATIC_STATE_ROOT} {STATIC_RELEASE_ROOT}")
    assert reconciler.contains("PrivateNetwork=true")
    assert reconciler.contains("RestrictAddressFamilies=AF_UNIX")
    assert not reconciler.contains("SystemCallFilter=~@network-io")
    assert host.run(
        "systemctl is-enabled lowerduckpond-static-reconcile.service"
    ).stdout.strip() == ("enabled")
    host.run_expect([0], "systemctl start lowerduckpond-static-reconcile.service")
    assert host.run("systemctl is-enabled lowerduckpond-static-reconcile.timer").stdout.strip() == (
        "enabled"
    )
    assert host.run("systemctl is-active lowerduckpond-static-reconcile.timer").stdout.strip() == (
        "active"
    )

    selected = host.run(f"readlink --canonicalize {STATIC_HOST_AGENT_ROOT}/current")
    assert selected.rc == 0
    selected_root = selected.stdout.strip()
    job_id = seed_static_authorization(host, selected_root)
    host.run_expect([0], "systemctl start lowerduckpond-static-reconcile.service")
    job_path = f"{STATIC_STATE_ROOT}/authorization/jobs/{job_id}.json"
    result_path = f"{STATIC_STATE_ROOT}/authorization/results/{job_id}.json"
    completion = host.run(
        f"timeout 10s bash -c 'until grep --fixed-strings --quiet completed {job_path}; "
        "do sleep 0.05; done'",
    )
    if completion.rc != 0:
        worker = f"lowerduckpond-static-worker@{job_id}.service"
        state = host.run(
            f"systemctl show --no-pager --property=ActiveState --property=SubState "
            f"--property=Result --property=ExecMainStatus {worker}"
        )
        journal = host.run(f"journalctl --unit={worker} --no-pager --output=cat")
        pytest.fail(
            "installed static create did not complete\n"
            f"job={host.file(job_path).content_string}\n"
            f"result={host.file(result_path).content_string}\n"
            f"state={state.stdout}\n"
            f"journal={journal.stdout}{journal.stderr}"
        )
    assert '"phase":"completed"' in host.file(job_path).content_string
    assert '"status":"succeeded"' in host.file(result_path).content_string
    cursor = host.file(f"{STATIC_STATE_ROOT}/locks/authorization-recovery.cursor")
    assert cursor.user == "root"
    assert cursor.group == "root"
    assert cursor.mode == STATIC_STATE_LOCK_MODE
    assert cursor.content_string == job_id


def test_static_worker_boundary_is_opaque_and_hardened(host: Host) -> None:
    unit = host.file("/etc/systemd/system/lowerduckpond-static-worker@.service")
    assert unit.contains("TemporaryFileSystem=/:ro")
    assert unit.contains("User=ldp-provisioner")
    assert unit.contains("Group=ldp-provisioner")
    assert unit.contains(
        f"ExecStart=/usr/bin/sudo --non-interactive --user=root --group=caddy "
        f"{STATIC_JOB_EXECUTOR} %i"
    )
    assert unit.contains("Slice=lowerduckpond-static-workers.slice")
    assert unit.contains("OnSuccess=lowerduckpond-static-reconcile.service")
    assert not unit.contains("OnFailure=")
    assert not unit.contains("SystemCallFilter=~clone clone3 fork vfork")
    assert unit.contains("TemporaryFileSystem=/workspace:rw,size=64M,nr_inodes=4096,mode=0700")
    for bound_path in (
        "/usr",
        "/lib",
        "/lib64",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/sudoers.d",
        STATIC_HOST_AGENT_ROOT,
        "/etc/lowerduckpond/static-publication.json",
    ):
        assert unit.contains(f"BindReadOnlyPaths={bound_path}")
    for property_line in (
        "MemoryMax=256M",
        "MemorySwapMax=0",
        "TasksMax=32",
        "PrivateNetwork=true",
        "NoNewPrivileges=false",
        "CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID",
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "DevicePolicy=closed",
        "IPAddressDeny=any",
        "ProtectProc=invisible",
    ):
        assert unit.contains(property_line)
    assert_static_worker_sudo_compatibility(host)
    assert_static_worker_caddy_runtime_access(host)
    assert_static_worker_execution(host)

    timer = host.file("/etc/systemd/system/lowerduckpond-static-reconcile.timer")
    assert timer.contains("OnUnitInactiveSec=1min")
    worker_slice = host.file("/etc/systemd/system/lowerduckpond-static-workers.slice")
    for property_line in ("MemoryMax=512M", "MemorySwapMax=0", "TasksMax=64"):
        assert worker_slice.contains(property_line)
    assert host.run(f"find {STATIC_HOST_AGENT_ROOT} -name __pycache__ -print -quit").stdout == ""


def test_caddy_has_no_tenant_routes_while_publication_is_dark(host: Host) -> None:
    routes = host.run("find /etc/caddy/routes.d -mindepth 1 -print -quit")
    assert routes.rc == 0
    assert routes.stdout == ""
    configuration = host.file("/etc/caddy/Caddyfile")
    assert not configuration.contains("import {$CADDY_ROUTES_GLOB}")
    unknown = host.run(
        "curl --silent --output /dev/null --write-out '%{http_code}' --insecure "
        "--resolve unknown.lowerduckpond.test:443:127.0.0.1 "
        "https://unknown.lowerduckpond.test/"
    )
    assert unknown.rc == 0
    assert unknown.stdout == "404"
