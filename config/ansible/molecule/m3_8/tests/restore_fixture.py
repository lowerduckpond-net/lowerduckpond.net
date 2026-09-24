"""A distinct empty Ubuntu/ext4 destination and real DNS-01 ACME fixture."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from urllib.request import urlopen

import test_backup_identity as identity
import test_lifecycle as support
import testinfra
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_inputs import INPUT_SCHEMA, ISSUER, SUBJECTS
from testinfra.host import Host

from config.ansible.molecule.m3_8 import restore_convergence
from scripts import qualification_restore as owned
from scripts.qualification_case import private_document
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV

SCENARIO = Path(__file__).resolve().parents[1]
REPO = SCENARIO.parents[3]
UNIT = "lowerduckpond-host-restore.service"
RECOVERY = "/var/lib/lowerduckpond/recovery"
PINNED = {
    "pebble": "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed",
    "pebble-challtestsrv": "e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92",
}


def checked(host: Host, code: str) -> str:
    return identity._run(host, code)


def private(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def wait_systemd(host: Host) -> None:
    # Do not publish fstab entries while the initial generator is still
    # discovering mounts. Docker start only proves that PID 1 was launched.
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if host.run("systemctl is-system-running").stdout.strip() in {"running", "degraded"}:
            return
        time.sleep(0.5)
    raise AssertionError("fresh destination systemd did not finish booting")


class Fixture:
    def __init__(self, source: Host, snapshot: str) -> None:
        self.environment = dict(os.environ)
        self.source = source
        self.snapshot = snapshot
        self.restore_id = str(uuid.uuid7())
        self.root = owned.directory(self.environment)
        self.root.mkdir(mode=0o700)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.ephemeral = Path(os.environ["MOLECULE_EPHEMERAL_DIRECTORY"])
        result = source.run(
            "/usr/local/sbin/fence-static-host --snapshot %s --restore-id %s",
            snapshot,
            self.restore_id,
        )
        assert result.rc == 0, result.stderr
        receipt = owned.inspect(self.environment, self.environment[HOST_ENV])
        receipt["gateSha256"] = hashlib.sha256(source.file(owned.GATE).content).hexdigest()
        receipt["snapshot"] = snapshot
        private_document(self.root, "source.json", receipt)
        self.source_id = str(receipt["id"])
        self.fence = source.file(f"{RECOVERY}/source-fence-{self.restore_id}.json").content
        private(self.inputs / f"source-fence-{self.restore_id}.json", self.fence)
        self.acme_id = owned.create(self.environment, "acme")
        self.acme = testinfra.get_host(f"docker://{self.acme_id}")
        self._prepare_acme()
        self.destination_id = owned.create(self.environment, "destination")
        self.destination = testinfra.get_host(f"docker://{self.destination_id}")
        wait_systemd(self.destination)
        self._prepare_destination()
        self.target = self._target()
        private(self.inputs / "target.json", canonical_json_bytes(self.target))
        self._bootstrap()

    def command(self, *args: str, timeout: int = 60, stdin: bytes = b"") -> bytes:
        return owned.command(self.environment, *args, timeout=timeout, stdin=stdin)

    def copy_in(self, source: Path, identity: str, destination: str) -> None:
        self.command("docker", "cp", str(source), f"{identity}:{destination}")

    def copy_root_between(self, source: str, destination: str) -> None:
        local = self.root / f"transfer-{uuid.uuid7().hex}"
        self.command("docker", "cp", f"{self.source_id}:{source}", str(local), timeout=120)
        self.copy_in(local, self.destination_id, destination)
        # Staging through the controller replaces numeric ownership with its
        # user. These two inputs (Restic repository and Caddy binary) are owned
        # by root on both hosts; restore that ownership before bootstrap checks.
        self.command(
            "docker",
            "exec",
            self.destination_id,
            "chown",
            "--recursive",
            "--no-dereference",
            "0:0",
            "--",
            destination,
        )

    def copy_operator_inputs(self) -> None:
        # systemd's /run mount is visible to exec, but not necessarily to the
        # Docker copy API. Transfer only these fixed disposable fixture inputs
        # through stdin into the running destination's mount namespace.
        names = (
            "operator-key",
            "operator-key.pub",
            "origin-pull-client.key",
            "origin-pull-client.pem",
        )
        values = {
            name: self.source.file(f"/run/lowerduckpond-molecule/{name}").content.hex()
            for name in names
        }
        data = canonical_json_bytes(values)
        assert len(data) <= 65536  # noqa: PLR2004 - fixed fixture input transfer bound
        self.command(
            "docker",
            "exec",
            "--interactive",
            self.destination_id,
            "python3",
            "-I",
            "-B",
            "-c",
            """
import json, sys
from pathlib import Path
root = Path('/run/lowerduckpond-molecule')
root.mkdir(mode=0o700, exist_ok=True)
values = json.load(sys.stdin)
names = ('operator-key', 'operator-key.pub', 'origin-pull-client.key', 'origin-pull-client.pem')
assert set(values) == set(names)
for name in names:
    path = root / name
    path.write_bytes(bytes.fromhex(values[name]))
    path.chmod(0o644 if name.endswith('.pub') else 0o600)
""",
            stdin=data,
        )

    def address(self, identity: str) -> str:
        return (
            self.command(
                "docker",
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                identity,
            )
            .decode()
            .strip()
        )

    def _prepare_acme(self) -> None:
        root = self.root / "acme-inputs"
        root.mkdir(mode=0o700)
        for name, digest in PINNED.items():
            archive = root / f"{name}.tgz"
            url = (
                "https://github.com/letsencrypt/pebble/releases/download/v2.10.1/"
                f"{name}-linux-amd64.tar.gz"
            )
            with urlopen(url, timeout=30) as response:  # noqa: S310 - fixed HTTPS release
                data = response.read(32 * 1024 * 1024 + 1)
            assert hashlib.sha256(data).hexdigest() == digest
            private(archive, data)
            with tarfile.open(archive) as bundle:
                members = [
                    value for value in bundle if value.isfile() and Path(value.name).name == name
                ]
                assert len(members) == 1
                stream = bundle.extractfile(members[0])
                assert stream is not None
                private(root / name, stream.read(32 * 1024 * 1024 + 1))
                (root / name).chmod(0o700)
        # Generate unique private CA/key material; never install a public test key.
        for args in (
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=Run-owned ACME proxy",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                "proxy-ca.key",
                "-out",
                "proxy-ca.crt",
            ],
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,DNS:acme-v02.api.letsencrypt.org,"
                "DNS:acme-staging-v02.api.letsencrypt.org,DNS:api.cloudflare.com",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
                "proxy.key",
                "-out",
                "proxy.csr",
            ],
            [
                "x509",
                "-req",
                "-in",
                "proxy.csr",
                "-CA",
                "proxy-ca.crt",
                "-CAkey",
                "proxy-ca.key",
                "-CAcreateserial",
                "-days",
                "2",
                "-copy_extensions",
                "copy",
                "-out",
                "proxy.crt",
            ],
        ):
            subprocess.run(  # noqa: S603 - fixed generated fixture keys
                ["/usr/bin/openssl", *args], cwd=root, check=True, capture_output=True, timeout=30
            )
        for path in root.iterdir():
            if path.name not in PINNED:
                path.chmod(0o600)
        private(
            root / "pebble.json",
            json.dumps(
                {
                    "pebble": {
                        "listenAddress": "127.0.0.1:14000",
                        "managementListenAddress": "127.0.0.1:15000",
                        "certificate": "/root/restore-acme/proxy.crt",
                        "privateKey": "/root/restore-acme/proxy.key",
                        "httpPort": 5002,
                        "tlsPort": 5001,
                    }
                }
            ).encode(),
        )
        private(root / "server.py", (SCENARIO / "restore_acme_server.py").read_bytes())
        private(root / "restore_dns_server.py", (SCENARIO / "restore_dns_server.py").read_bytes())
        self.copy_in(root, self.acme_id, "/root/restore-acme")
        self.command("docker", "start", self.acme_id)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.acme.run(
                "/usr/bin/python3 -I -B -c %s",
                """
import json, socket, ssl, struct, urllib.request
ctx = ssl.create_default_context(cafile='/root/restore-acme/proxy-ca.crt')
for host in ('acme-v02.api.letsencrypt.org', 'acme-staging-v02.api.letsencrypt.org'):
    request = urllib.request.Request('https://localhost/directory', headers={'Host': host})
    with urllib.request.urlopen(request, context=ctx, timeout=2) as response:
        directory = json.load(response)
    for field in ('newAccount', 'newNonce', 'newOrder'):
        assert directory[field].startswith('https://' + host + '/')
# Exercise forwarding to the actual challenge responder, not a synthesized
# SOA answer or the independently healthy Pebble management listener.
name = b''.join(bytes([len(label)]) + label
                for label in b'_acme-challenge.lowerduckpond.net'.split(b'.')) + bytes(1)
packet = struct.pack('!6H', 123, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', 16, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
    connection.settimeout(2)
    connection.connect(('127.0.0.1', 8054))
    connection.send(packet)
    reply = connection.recv(65535)
assert len(reply) >= 12 and reply[:2] == packet[:2]
flags = struct.unpack('!H', reply[2:4])[0]
assert flags & 0x8000 and flags & 0x000f == 0
with urllib.request.urlopen('https://localhost:15000/roots/0', context=ctx, timeout=5) as response:
    print(response.read().decode(), end='')
""",
            )
            if result.rc == 0:
                private(root / "issuer-root.crt", result.stdout.encode())
                return
            time.sleep(0.25)
        raise AssertionError("controlled ACME fixture did not start")

    def _prepare_destination(self) -> None:
        # Mount parents, not install roots: the actual recovery uses same-FS
        # rename. A mount at /etc/caddy would incorrectly make rename impossible.
        # Workspaces also require real inode capacity; some Docker backing
        # filesystems report zero inodes for the unmounted overlay cache.
        result = self.destination.run(
            "/bin/bash -c %s",
            """
set -euo pipefail
install -d -m 0700 /root/restore-disks
for name in etc srv var-lib var-cache; do
    target=/${name//-/\\/}
    truncate --size=8G /root/restore-disks/$name.ext4
    mkfs.ext4 -F -q -m 0 /root/restore-disks/$name.ext4
    printf '%s %s ext4 loop,nodev,nosuid 0 0\n' \
        /root/restore-disks/$name.ext4 "$target" >> /etc/fstab
done
for name in etc srv var-lib var-cache; do
    target=/${name//-/\\/}
    install -d /mnt/restore-copy
    mount -o loop,nodev,nosuid /root/restore-disks/$name.ext4 /mnt/restore-copy
    cp -a "$target/." /mnt/restore-copy/
    mount --move /mnt/restore-copy "$target"
done
""",
        )
        assert result.rc == 0, result.stderr
        # Restic preserves numeric content ownership in the descriptor. Reserve
        # the original Caddy GID before other baseline packages allocate users.
        group = int(self.source.run("getent group caddy").stdout.split(":")[2])
        assert 0 < group < 65536  # noqa: PLR2004 - Linux service group identity
        assert self.destination.run("groupadd --system --gid %s caddy", str(group)).rc == 0
        assert (
            self.destination.run(
                "useradd --system --gid caddy --home-dir /var/lib/caddy "
                "--shell /usr/sbin/nologin --no-create-home caddy"
            ).rc
            == 0
        )
        for name in ("proxy-ca.crt", "issuer-root.crt"):
            self.copy_in(
                self.root / "acme-inputs" / name,
                self.destination_id,
                f"/usr/local/share/ca-certificates/restore-{name}",
            )
        self.copy_in(
            self.ephemeral / "archive-tls/ca.crt",
            self.destination_id,
            "/usr/local/share/ca-certificates/restore-archive.crt",
        )
        archive_address = self.source.run(
            "getent hosts ams3.digitaloceanspaces.com"
        ).stdout.split()[0]
        self.acme_address = self.address(self.acme_id)
        hosts = (
            f"{self.acme_address} acme-v02.api.letsencrypt.org "
            "acme-staging-v02.api.letsencrypt.org api.cloudflare.com\n"
            f"{archive_address} ams3.digitaloceanspaces.com\n"
        )
        checked(
            self.destination,
            f"""
from pathlib import Path
with Path('/etc/hosts').open('a') as stream:
    stream.write({hosts!r})
""",
        )
        assert self.destination.run("update-ca-certificates").rc == 0
        # Keep this destination-only DNS redirection across its reboot. No host
        # or workstation resolver/CA configuration is changed.
        nft = (
            "table ip restore_fixture_dns {\n chain output {\n"
            "  type nat hook output priority -110;\n"
            f"  udp dport 53 dnat to {self.acme_address}:8054;\n"
            f"  tcp dport 53 dnat to {self.acme_address}:8054;\n" + " }\n}\n"
        )
        checked(
            self.destination,
            f"""
from pathlib import Path
Path('/root/restore-dns.nft').write_text({nft!r})
Path('/root/restore-hosts.py').write_text(
    "from pathlib import Path\\n"
    "path = Path('/etc/hosts')\\n"
    "with path.open('a') as stream:\\n"
    "    stream.write(" + repr({hosts!r}) + ")\\n")
Path('/etc/systemd/system/restore-fixture-dns.service').write_text('''[Unit]
Before=caddy.service lowerduckpond-host-restore.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /root/restore-hosts.py
ExecStart=/usr/sbin/nft -f /root/restore-dns.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
""",
        )
        assert self.destination.run("systemctl daemon-reload").rc == 0
        started = self.destination.run("systemctl enable --now restore-fixture-dns.service")
        assert started.rc == 0, self.destination.run(
            "journalctl --unit=restore-fixture-dns.service --no-pager --output=cat -n 30"
        ).stdout
        # Copy the fenced local Restic repository intact. Neither source history
        # nor its snapshots are pruned. Live-provider reconstruction remains P6.
        self.copy_root_between("/mnt/lowerduckpond-restic-test", "/mnt/lowerduckpond-restic-test")
        self.copy_operator_inputs()
        self.binary = self.source.run("readlink -f /usr/local/bin/caddy").stdout.strip()
        assert self.binary.startswith("/usr/local/lib/lowerduckpond/caddy-")
        assert self.destination.run("install -d -m 0755 /usr/local/lib/lowerduckpond").rc == 0
        self.copy_root_between(self.binary, self.binary)
        for index in (0,):
            private(
                self.inputs / f"original-origin-pull-ca-{index}.pem",
                self.source.file(f"/etc/caddy/origin-pull-ca-{index}.pem").content,
            )

    def _target(self) -> dict[str, object]:
        fence = json.loads(self.fence)
        ca_digest = self.source.run(
            "openssl x509 -in /etc/caddy/origin-pull-ca-0.pem -outform DER"
        ).stdout_bytes
        namespace = json.loads(
            self.source.file(f"{support.STATE_ROOT}/platform/namespace.json").content
        )
        launch_path = self.source.file(f"{support.STATE_ROOT}/platform/launch.json")
        return {
            "schema": INPUT_SCHEMA,
            "restoreId": self.restore_id,
            "snapshotId": self.snapshot,
            "repositoryBinding": fence["repositoryBinding"],
            "originalArtifactSha256": fence["artifactDigest"]["value"],
            "sourceMachineId": fence["sourceMachineId"],
            "destinationMachineId": self.destination.file("/etc/machine-id").content_string.strip(),
            "sourceFenceDigest": framed_digest(
                "lowerduckpond-host-restore-source-fence-v1", self.fence
            ),
            "namespace": namespace,
            "launch": json.loads(launch_path.content) if launch_path.exists else None,
            "archiveTarget": {"region": "ams3", "bucket": "molecule-tenant-archives"},
            "caddy": {
                "binaryPath": self.binary,
                "binarySha256": self.source.run("sha256sum %s", self.binary).stdout.split()[0],
                "environmentSha256": hashlib.sha256(
                    self.source.file("/etc/caddy/environment").content
                ).hexdigest(),
                "originPullCaSha256": [hashlib.sha256(ca_digest).hexdigest()],
                "originalOriginPullCaSha256": [hashlib.sha256(ca_digest).hexdigest()],
                "originPullRequired": True,
                "issuer": ISSUER,
                "subjects": list(SUBJECTS),
                "trustBundleSha256": hashlib.sha256(
                    self.destination.file("/etc/ssl/certs/ca-certificates.crt").content
                ).hexdigest(),
            },
            "publicationEnabled": True,
            "auditRotationEnabled": False,
        }

    def _bootstrap(self) -> None:
        transport = self.command(
            "python3",
            str(SCENARIO / "resolve_operator_transport.py"),
            self.environment.get("DOCKER_HOST", ""),
            self.destination_id,
        )
        self.transport = self.root / "operator-transport.json"
        private(self.transport, transport)
        variables = {
            "firewall_admin_source_cidrs": [json.loads(transport)["sourceCidr"]],
            "base_start_time_synchronization": False,
            "firewall_enable_service": True,
            "caddy_cloudflare_api_token": "0" * 40,
            "caddy_generation_enabled": True,
            "caddy_origin_pull_enforcement_enabled": True,
            "caddy_origin_pull_ca_paths": [str(self.ephemeral / "origin-pull-ca.pem")],
            "static_publication_enabled": False,
            "podman_cgroup_manager": "cgroupfs",
            "backup_repository": "/mnt/lowerduckpond-restic-test",
            "backup_restic_password": "molecule-restic-password-0000000000",
            "backup_spaces_access_key_id": "molecule-spaces-access-key",
            "backup_spaces_secret_access_key": "molecule-spaces-secret-key",
            "backup_spaces_region": "us-east-1",
            "backup_node_name": "molecule",
            "backup_static_recovery_enabled": True,
            "backup_audit_rotation_enabled": False,
            "static_operator_public_key": self.source.file(
                "/run/lowerduckpond-molecule/operator-key.pub"
            ).content_string.strip(),
            "static_operator_principal": "molecule-m3-8-operator-v1",
            "static_host_agent_artifact_path": os.environ[ARTIFACT_ENV],
            "static_host_agent_artifact_sha256": self.target["originalArtifactSha256"],
            "static_host_agent_archive_configuration": {
                "format": "lowerduckpond-archive-configuration-v1",
                "region": "ams3",
                "bucket": "molecule-tenant-archives",
                "accessKeyId": "molecule-m3-10-archive",
                "secretAccessKey": "molecule-m3-10-disposable-archive-secret",
            },
            "host_recovery_bootstrap_enabled": True,
            "host_recovery_restore_id": self.restore_id,
            "host_recovery_input_directory": str(self.inputs),
        }
        inventory = {
            "all": {
                "children": {
                    "hosting_nodes": {
                        "hosts": {
                            self.destination_id: {
                                "ansible_connection": "community.docker.docker",
                                "ansible_user": "root",
                                **variables,
                            }
                        }
                    }
                }
            }
        }
        self.inventory = self.root / "inventory.json"
        private(self.inventory, json.dumps(inventory).encode())
        self.converge(succeeds=True)
        assert not self.destination.file("/var/lib/caddy/caddy/certificates").exists
        assert not self.destination.service("caddy").is_running

    def converge(self, *, succeeds: bool) -> None:
        uv = shutil.which("uv")
        assert uv is not None
        with (self.root / f"converge-{uuid.uuid7().hex}.log").open("xb") as log:
            status = restore_convergence.run(
                [
                    uv,
                    "run",
                    "ansible-playbook",
                    "-i",
                    str(self.inventory),
                    str(REPO / "config/ansible/playbooks/site.yml"),
                ],
                cwd=REPO,
                environment={
                    **self.environment,
                    "ANSIBLE_CONFIG": str(REPO / "config/ansible/ansible.cfg"),
                },
                log=log,
            )
        assert (status == 0) is succeeds, "destination converge: see retained private log"

    def status(self) -> dict[str, object]:
        result = self.destination.run("/usr/local/sbin/restore-static-host --status")
        assert result.rc == 0, result.stderr
        return json.loads(result.stdout)

    def start(self) -> None:
        assert self.destination.run("systemctl start --no-block %s", UNIT).rc == 0

    def wait(self, phases: set[str], *, seconds: int = 180) -> dict[str, object]:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            status = self.status()
            if status["phase"] in phases and (
                status["phase"] != "complete" or not status["activationPending"]
            ):
                return status
            state = self.destination.run(
                "systemctl show --value --property=ActiveState %s", UNIT
            ).stdout.strip()
            assert state != "failed", "restore failed: retain destination unit journal"
            time.sleep(0.5)
        raise AssertionError("restore did not reach its expected phase")

    def fault(self, fault: str) -> None:
        checked(
            self.acme,
            f"""
import json, urllib.request
request = urllib.request.Request('http://127.0.0.1:8056/fault',
    data=json.dumps({{'fault': {fault!r}}}).encode(),
    headers={{'Content-Type': 'application/json'}})
with urllib.request.urlopen(request, timeout=10) as response:
    assert response.status == 200
""",
        )

    def reboot(self) -> None:
        # Container restart restarts systemd with persistent ext4 and empty /run.
        # Prove a new PID 1 start time without claiming a separate kernel boot.
        before_pid = self.destination.file("/proc/1/stat").content_string.split()[21]
        self.command("docker", "restart", "--time", "20", self.destination_id, timeout=40)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            result = self.destination.run("systemctl is-system-running")
            if result.stdout.strip() in {"running", "degraded"}:
                assert (
                    self.destination.file("/proc/1/stat").content_string.split()[21] != before_pid
                )
                for path in ("/etc", "/srv", "/var/lib", "/var/cache"):
                    assert (
                        self.destination.run(
                            "findmnt -n -o FSTYPE --target %s", path
                        ).stdout.strip()
                        == "ext4"
                    )
                return
            time.sleep(0.5)
        raise AssertionError("restored destination systemd did not return")

    def connection(self, path: Path) -> tuple[str, Path, Path]:
        path.mkdir(mode=0o700)
        if not self.destination.file(support.OPERATOR_KEY).exists:
            self.copy_operator_inputs()
        support._initialize_admission_pacing(self.destination)
        return support._operator_inputs(
            path, container=self.destination_id, transport_path=self.transport
        )

    def fault_observed(self, name: str) -> None:
        assert name in {"deniedDns", "deniedAcme"}
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            value = json.loads(
                checked(
                    self.acme,
                    """
import urllib.request
with urllib.request.urlopen('http://127.0.0.1:8056/status', timeout=5) as response:
    print(response.read().decode())
""",
                )
            )
            if value[name] > 0:
                assert self.destination.service("caddy").is_running
                return
            time.sleep(0.5)
        raise AssertionError("native Caddy did not observe the injected provider failure")
