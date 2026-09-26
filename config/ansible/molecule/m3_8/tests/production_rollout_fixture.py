"""Actual dark-host phase engine on an owned MinIO/systemd fixture.

Provider qualification is deliberately absent. The diagnostic original binds
real source/artifact/repository inputs but cannot pass the public report gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import tarfile
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from independent_fixture import require_owned_fixture
from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity

from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_workflow as workflow
from scripts import production_qualification_inputs as inputs
from scripts.m3_11_production_proposals import Proposals
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import Logs, controller
from scripts.qualification_case import owned_containers
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV

ROOT = Path(__file__).resolve().parents[5]
# Last main before the production controller; its real site config has recovery
# and rotation disabled and retains the completed empty M3.10 layout.
PREDECESSOR = "69859cbb949d95c1aae6959363773cbf1d8e126b"
REPOSITORY = "/var/cache/lowerduckpond-backup/rollout-fixture-repository"
INSTALL = "/opt/lowerduckpond/static-host-agent"


class ControllerDepartureError(Exception):
    """A deliberate departure after retaining actual installed evidence."""


class Fixture:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        require_owned_fixture()
        self.environment = dict(os.environ)
        self.identities = owned_containers(self.environment)
        self.host = self.identities[HOST_ENV]
        self.source_artifact = Path(os.environ[ARTIFACT_ENV])
        self.directory = self.source_artifact.parent.parent / "production-rollout"
        self.directory.mkdir(mode=0o700)
        self.logs = Logs(self.directory)
        self.artifact = self.directory / "candidate.tar"
        shutil.copyfile(self.source_artifact, self.artifact)
        self.artifact.chmod(0o400)
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.patch = monkeypatch
        self.predecessor()
        self.ssh = self.transport()
        self.configure()
        self.original = self.proposal()
        for name in ("journal", "proposals"):
            (self.directory / name).mkdir(mode=0o700)

    def command(self, name: str, arguments: list[str], data: bytes = b"") -> bytes:
        assert owned_containers(self.environment) == self.identities
        result = self.logs.run(name, arguments, data=data, environment=self.environment)
        assert result.status == 0, f"{name}: see {result.stdout} and {result.stderr}"
        return result.read(256 * 1024)

    def remote(self, name: str, arguments: list[str], data: bytes = b"") -> bytes:
        return self.command(name, ["docker", "exec", "-i", self.host, *arguments], data)

    def predecessor(self) -> None:
        previous = self.directory / "predecessor"
        previous.mkdir(mode=0o700)
        archive = self.logs.run("previous-source", ["git", "-C", str(ROOT), "archive", PREDECESSOR])
        assert archive.status == 0
        with tarfile.open(archive.stdout) as source:
            source.extractall(previous, filter="data")
        variables = self.directory / "predecessor-variables.json"
        variables.write_bytes(
            journal.canonical({"backup_node_name": probe.NODE, "backup_repository": REPOSITORY})
        )
        base = self.directory / "predecessor-base.yml"
        base.write_bytes(
            journal.canonical(
                {"provisioner": {"ansible_args": ["--extra-vars", "@" + str(variables)]}}
            )
        )
        environment = {
            key: value for key, value in self.environment.items() if not key.startswith("MOLECULE_")
        }
        environment["MOLECULE_EPHEMERAL_DIRECTORY"] = self.environment[
            "MOLECULE_EPHEMERAL_DIRECTORY"
        ]
        result = self.logs.run(
            "previous-converge",
            [
                "uv",
                "run",
                "--directory",
                str(previous / "config/ansible"),
                "--frozen",
                "molecule",
                "--base-config",
                str(base),
                "converge",
                "--scenario-name",
                "m3_8",
            ],
            environment=environment,
        )
        assert result.status == 0, f"preceding site convergence failed: {result.stdout}"
        shutil.copyfile(self.artifact, self.source_artifact)
        self.source_artifact.with_suffix(".tar.sha256").write_text(self.digest + "\n")
        selected = (
            self.remote("previous-selection", ["readlink", INSTALL + "/current"])
            .decode()
            .strip()
            .rsplit("/", 1)[-1]
        )
        assert selected != self.digest
        self.remote(
            "previous-completion",
            ["bash", "-s", "--", "record", selected, PREDECESSOR],
            (ROOT / "scripts/m3-10-convergence-state").read_bytes(),
        )
        self.predecessor_integrity(selected)

    def predecessor_integrity(self, selected: str) -> None:
        # The real read-only gate rejects queued/running lifecycle work. Pause
        # this empty owned fixture's periodic producers before draining them,
        # then restore them for the actual controller's drain/recovery proof.
        services = [
            "lowerduckpond-static-reconcile.service",
            "lowerduckpond-static-emergency-reconcile.service",
        ]
        timers = [unit.removesuffix(".service") + ".timer" for unit in services]
        for unit in timers:
            self.remote("previous-timer-active", ["systemctl", "is-active", "--quiet", unit])
        try:
            self.remote("previous-timers-pause", ["systemctl", "stop", *timers])
            self.remote("previous-reconcilers-drain", ["systemctl", "stop", *services])
            self.remote(
                "previous-integrity",
                ["bash", "-s", "--", selected, "upgrade-host", PREDECESSOR],
                (ROOT / "scripts/m3-10-completed-host-preflight").read_bytes(),
            )
        finally:
            self.remote("previous-timers-resume", ["systemctl", "start", *timers])
        for unit in timers:
            self.remote("previous-timer-active", ["systemctl", "is-active", "--quiet", unit])

    def transport(self) -> list[str]:
        self.endpoint = json.loads(
            (
                Path(self.environment["MOLECULE_EPHEMERAL_DIRECTORY"]) / "operator-transport.json"
            ).read_text()
        )
        self.key = self.directory / "admin-key"
        self.command(
            "admin-key", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)]
        )
        self.remote(
            "admin-identity",
            [
                "python3",
                "-c",
                "import os,pwd,sys;from pathlib import Path;u=pwd.getpwnam('ldp-admin');"
                "d=Path(u.pw_dir)/'.ssh';d.mkdir(mode=0o700);os.chown(d,u.pw_uid,u.pw_gid);"
                "p=d/'authorized_keys';p.write_bytes(sys.stdin.buffer.read());"
                "p.chmod(0o600);os.chown(p,u.pw_uid,u.pw_gid)",
            ],
            self.key.with_suffix(".pub").read_bytes(),
        )
        known = self.directory / "known-hosts"
        public = (
            self.remote("host-key", ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
            .decode()
            .split()[:2]
        )
        known.write_text("lowerduckpond.net " + " ".join(public) + "\n")
        known.chmod(0o600)
        self.common = [
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(known),
            "-o",
            "HostKeyAlias=lowerduckpond.net",
            "-o",
            "ConnectTimeout=10",
        ]
        ssh = [
            "ssh",
            "-p",
            self.endpoint["sshPort"],
            *self.common,
            "-i",
            str(self.key),
            "ldp-admin@" + self.endpoint["peerAddress"],
        ]
        self.command("admin-transport", [*ssh, "true"])
        return ssh

    def configure(self) -> None:
        self.config = probe.configuration(
            self.remote("backup-configuration", ["cat", "/etc/lowerduckpond/backup.env"])
        )
        operator = (
            self.remote(
                "operator-public-key", ["cat", "/run/lowerduckpond-molecule/operator-key.pub"]
            )
            .decode()
            .strip()
        )
        values = {
            "PRODUCTION_ORIGIN_IPV4": self.endpoint["peerAddress"],
            "ADMIN_SOURCE_CIDRS_JSON": json.dumps([self.endpoint["sourceCidr"]]),
            "CADDY_CLOUDFLARE_API_TOKEN": "0" * 40,
            "CADDY_ORIGIN_PULL_CA_PATHS_JSON": json.dumps(
                [str(Path(self.environment["MOLECULE_EPHEMERAL_DIRECTORY"]) / "origin-pull-ca.pem")]
            ),
            "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED": "true",
            "BACKUP_REPOSITORY": self.config["RESTIC_REPOSITORY"],
            "RESTIC_PASSWORD": self.config["RESTIC_PASSWORD"],
            "SPACES_BACKUP_ACCESS_KEY_ID": self.config["AWS_ACCESS_KEY_ID"],
            "SPACES_BACKUP_SECRET_ACCESS_KEY": self.config["AWS_SECRET_ACCESS_KEY"],
            "SPACES_REGION": "ams3",
            "SPACES_ARCHIVE_BUCKET": "molecule-tenant-archives",
            "SPACES_ARCHIVE_ACCESS_KEY_ID": "molecule-m3-10-archive",
            "SPACES_ARCHIVE_SECRET_ACCESS_KEY": "molecule-m3-10-disposable-archive-secret",
            "STATIC_OPERATOR_PUBLIC_KEY": operator,
            "STATIC_OPERATOR_PRINCIPAL": "molecule-m3-8-operator-v1",
        }
        for name, value in values.items():
            self.patch.setenv(name, value)
        variables = converge._variables

        def fixture_variables(stage: str, artifact: Path, digest: str) -> dict[str, object]:
            return {
                **variables(stage, artifact, digest),
                "ansible_port": int(self.endpoint["sshPort"]),
                "ansible_private_key_file": str(self.key),
                "ansible_ssh_common_args": shlex.join(self.common),
                "base_start_time_synchronization": False,
                "podman_cgroup_manager": "cgroupfs",
                "caddy_tls_mode": "internal",
                "backup_spaces_region": self.config["AWS_DEFAULT_REGION"],
            }

        self.patch.setattr(converge, "_variables", fixture_variables)

    def proposal(self) -> bytes:
        repository = json.loads(
            self.remote(
                "repository-config",
                [
                    "bash",
                    "-c",
                    "set -a; source /etc/lowerduckpond/backup.env; "
                    "exec restic --no-cache --no-lock cat config",
                ],
            )
        )
        predecessor = self.remote(
            "original-predecessor",
            ["bash", "-s", "--", "inspect"],
            (ROOT / "scripts/m3-10-convergence-state").read_bytes(),
        ).decode()
        revision = (
            self.command("source-revision", ["git", "-C", str(ROOT), "rev-parse", "HEAD"])
            .decode()
            .strip()
        )
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        original: dict[str, object] = {
            "format": journal.FORMAT,
            "transaction_id": str(uuid.uuid7()),
            "started_at": now,
            "candidate": {
                "source_revision": revision,
                "artifact_sha256": self.digest,
                "input_policy": inputs.POLICY,
                "qualification_inputs_sha256": inputs.candidate_inputs(ROOT, revision, self.digest),
                "storage_target_sha256": journal.digest(b"local-fixture-storage-not-live-provider"),
                "report_sha256": journal.digest(b"diagnostic-only-not-a-qualification-report"),
            },
            "predecessor": predecessor,
            "repository_binding": RepositoryIdentity(
                repository["id"], probe.NODE, REPOSITORY
            ).binding()["value"],
            "namespace": {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "PlatformNamespace",
                "tenantOriginSuffix": "lowerduckpond.com",
                "initializedAt": now,
            },
        }
        raw = journal.canonical(original)
        journal.validate([("original", raw)])
        with (self.directory / "original.json").open("xb") as output:
            output.write(raw)
        return raw

    def retained_capture(self) -> bytes:
        transaction = cast(str, json.loads(self.original)["transaction_id"])
        path = "/var/cache/lowerduckpond-backup/m3-11/" + transaction
        return self.remote(
            "retained-capture",
            [
                "python3",
                "-c",
                "import hashlib,json,sys;from pathlib import Path;root=Path(sys.argv[1]);"
                "rows={str(p.relative_to(root)):[p.stat().st_ino,p.stat().st_mtime_ns,"
                "hashlib.sha256(p.read_bytes()).hexdigest()] for p in root.rglob('*') "
                "if p.is_file() and 'protection' not in p.relative_to(root).parts};"
                "assert rows;print(json.dumps(rows,sort_keys=True))",
                path,
            ],
        )

    def run(self, stop: str | None = None) -> list[tuple[str, bytes]]:
        attempt = Path(tempfile.mkdtemp(prefix="controller-", dir=self.directory))
        fixture = self

        class RetainedProposals(Proposals):
            def publish(self, pair: Replica, name: str, raw: bytes) -> None:
                if stop == "backup" and name == "backup-verified":
                    self.recover(pair)
                    self.retain(name, raw)
                    raise ControllerDepartureError(
                        "original verified backup retained before acknowledgement"
                    )
                super().publish(pair, name, raw)

        with (
            journal.locked(self.directory / "journal", owner=os.geteuid(), create=True) as local,
            journal.locked(
                self.directory / "proposals", owner=os.geteuid(), create=True
            ) as retained,
            controller(self.ssh, attempt) as session,
        ):
            pair = Replica(local, session)
            proposals = RetainedProposals(retained, attempt)
            if not retained.records():
                proposals.publish(pair, "original", self.original)

            def guard() -> None:
                assert owned_containers(fixture.environment) == fixture.identities
                assert hashlib.sha256(fixture.artifact.read_bytes()).hexdigest() == fixture.digest
                records = local.records()
                assert records[0][1] == fixture.original
                if stop == "namespace" and journal.validate(records)["phase"] == "namespace":
                    raise ControllerDepartureError(
                        "original namespace committed before controller departure"
                    )

            if stop:
                with pytest.raises(ControllerDepartureError):
                    workflow.run(pair, self.artifact, proposals, guard)
            else:
                workflow.run(pair, self.artifact, proposals, guard)
                assert journal.validate(pair.synchronize())["phase"] == "complete"
            return local.records()
