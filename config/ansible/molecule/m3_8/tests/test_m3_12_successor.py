"""The native M3.12 launch following an actual accepted M3.11 installed rollout."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import backup_capture_support as captures
import pytest
import test_backup_identity as backup
import test_reboot as reboot
import yaml
from production_rollout_fixture import ROOT, Fixture
from testinfra.host import Host

from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_journal as previous_journal
from scripts import m3_11_production_records as previous_records
from scripts import production_qualification_inputs as inputs
from scripts.m3_11_production_session import Session, controller
from scripts.m3_12_contracts import COMMON_SLOTS, Document, digest, encode
from scripts.m3_12_diagnostic_store import publish, read
from scripts.m3_12_installed import (
    APPLY_STAGE_ENV,
    PROGRESS_ROOT_ENV,
    installed_archive_hosts_line,
    predecessor_progress,
    recheck_installed,
    successor_stage,
)
from scripts.m3_12_installed_root import PUBLICATION
from scripts.qualification_context import ARTIFACT_ENV
from scripts.qualification_production_predecessor import ACCEPTED_M3_11

AUTHORITY = Path("/var/lib/lowerduckpond/convergence/m3-12")
GATE = "/usr/local/libexec/lowerduckpond/static-publication-gate"
VERIFY = "/usr/local/libexec/lowerduckpond/check-caddy-publication-open"
PYTHON = "/usr/bin/python3"
INSTALLED_HOST = "installed-m3-12-successor"
ARCHIVE_ENDPOINT = "m3-12-successor-archive-endpoint.json"


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def record(name: str, **fields: object) -> Document:
    return {"format": f"lowerduckpond-m3-12-{name}-v1", **fields}


class Rollout:
    def __init__(
        self,
        fixture: Fixture,
        session: Session,
        directory: Path,
        original: list[tuple[str, bytes]],
    ) -> None:
        self.fixture = fixture
        self.session = session
        self.directory = directory
        self.origin = fixture.source_artifact.parent.parent
        self.allocation = recheck_installed(self.origin, fixture.environment)
        self.predecessor = sha(previous_records.encode(original))
        self.invocation = str(uuid.uuid7())
        self.artifact = directory / "successor.tar"
        self.inventory = directory / "installed-inventory.json"
        self.measurements: dict[str, tuple[str, str, str]] = {}

    def remote(self, step: str, command: list[str], *, data: bytes = b"", expect: int = 0) -> bytes:
        assert recheck_installed(self.origin, self.fixture.environment) == self.allocation
        result = self.session.run(step, command, data=data)
        if result.status != expect:
            raise AssertionError(
                f"Leased installed successor step failed ({step}, {result.status})"
            )
        return result.read(256 * 1024)

    def seal(self, file: str, document: Document) -> None:
        self.remote(
            "seal-installed-evidence",
            [
                PYTHON,
                "-I",
                "-B",
                "-c",
                "import os,sys;from pathlib import Path;"
                "sys.path.insert(0,'/opt/lowerduckpond/static-host-agent/current/site-packages');"
                "from lowerduckpond_static_host_agent.durable import DurableDirectory;"
                "p=Path(sys.argv[1]);p.parent.mkdir(mode=0o700,exist_ok=True);"
                "d=os.open(p.parent.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);"
                "os.fsync(d);os.close(d);"
                "r=DurableDirectory.open(p.parent,expected_owner=0,expected_directory_mode=0o700);"
                "r.create_immutable((p.name,),sys.stdin.buffer.read(262145));r.close()",
                str(AUTHORITY / file),
            ],
            data=encode(document),
        )

    def observe(self, slot: str, action: Callable[[], str]) -> None:
        start = timestamp()
        result = action()
        self.measurements[slot] = (start, timestamp(), result)

    def build(self) -> str:
        commands = (
            [str(ROOT / "scripts/build-static-host-agent"), str(self.artifact)],
            [
                os.sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/infrastructure/test_m3_12_contracts.py",
            ],
        )
        for command in commands:
            result = subprocess.run(  # noqa: S603 - fixed candidate tests and artifact build
                command,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            assert result.returncode == 0, "Reviewed candidate component prerequisites failed."
        return sha(self.artifact.read_bytes())

    def active_generation(self) -> Document:
        raw = self.remote(
            "read-verified-platform-generation",
            [
                PYTHON,
                "-I",
                "-B",
                "-c",
                "import hashlib,json,sys;sys.path.insert(0,"
                "'/opt/lowerduckpond/static-host-agent/current/site-packages');"
                "from lowerduckpond_static_host_agent import entrypoints;"
                "r=entrypoints._open_caddy_control_runtime();c=r.locked();c.__enter__();"
                "g=r.open_verified_generation(r.read_active());m=g.manifest;"
                "print(json.dumps({'generation':m.generation_id,"
                "'manifestSha256':hashlib.sha256(m.to_bytes()).hexdigest()},sort_keys=True));"
                "g.close();c.__exit__(None,None,None);r.close()",
            ],
        )
        return json.loads(raw)  # type: ignore[no-any-return]

    def stage_distinct_platform_generation(self) -> Document:
        source = Path(__file__).with_name("m3_12_caddy_witness.py").read_bytes()
        self.remote(
            "stage-distinct-platform-generation",
            [
                PYTHON,
                "-I",
                "-B",
                "-c",
                "import sys;sys.path.insert(0,"
                "'/opt/lowerduckpond/static-host-agent/current/site-packages');"
                "exec(compile(sys.stdin.buffer.read(),'m3_12_caddy_witness.py','exec'))",
                self.session.token,
            ],
            data=source,
        )
        self.health(enabled=False)
        generation = self.active_generation()
        assert generation["generation"] != self.preceding_generation["generation"]
        return generation

    def setup(self) -> None:
        self.observe("component", self.build)
        self.preceding_generation = self.active_generation()
        self.seal("preceding-generation.json", self.preceding_generation)
        revision = inputs.git(ROOT, "rev-parse", "HEAD").decode("ascii").strip()
        revocations = inputs.current_candidate(ROOT, revision)
        artifact = self.measurements["component"][2]
        fingerprint = inputs.candidate_inputs(ROOT, revision, artifact)
        inputs.assert_not_revoked(
            revocations, source=revision, artifact=artifact, inputs=fingerprint
        )
        self.candidate = {
            "revision": revision,
            "inputPolicySha256": sha(inputs.POLICY.encode()),
            "inputFingerprintSha256": fingerprint,
            "hostAgentSha256": artifact,
            "toolchainSha256": sha((ROOT / "uv.lock").read_bytes()),
            "requirementsSha256": sha((ROOT / "schemas/m3-12/v1/requirements.json").read_bytes()),
        }
        namespace = json.loads(
            self.remote(
                "namespace", ["cat", "/var/lib/lowerduckpond/static/platform/namespace.json"]
            )
        )
        self.platform = {
            "namespaceSha256": digest(namespace),
            "storageTargetSha256": digest(
                {"repository": self.fixture.config["RESTIC_REPOSITORY"], "backend": "minio"}
            ),
            "storageBackend": "minio",
            "cloudflareNetworkSetSha256": sha(
                (ROOT / "platform/cloudflare-networks.json").read_bytes()
            ),
            "trustedPlatformDomain": "lowerduckpond.net",
            "aliasSuffix": "lowerduckpond.com",
            "tenantOriginSuffix": namespace["tenantOriginSuffix"],
            "cookiePolicyVersion": "lowerduckpond-cookie-policy-v1",
            "edgePolicyVersion": "lowerduckpond-edge-policy-v1",
        }
        hostname = self.remote("guest-hostname", ["hostname"]).decode("ascii").strip()
        self.enrollment = record(
            "installed-enrollment",
            hostname=hostname,
            artifact=artifact,
            predecessor=self.predecessor,
            allocation=digest(self.allocation),
            invocation=self.invocation,
            candidate=digest(self.candidate),
            platform=digest(self.platform),
        )
        variables = yaml.safe_load(
            (
                ROOT / "config/ansible/inventories/production/group_vars/hosting_nodes.yml"
            ).read_bytes()
        )
        self.inventory.write_bytes(
            encode(
                {
                    "all": {
                        "children": {
                            "hosting_nodes": {
                                "vars": variables,
                                "hosts": {
                                    INSTALLED_HOST: {
                                        "ansible_host": self.fixture.endpoint["peerAddress"],
                                        "ansible_user": "ldp-admin",
                                        "ansible_connection": "ldp_m3_11",
                                        "ansible_ssh_transfer_method": "piped",
                                        "ansible_ssh_use_tty": False,
                                        "ansible_ssh_retries": 0,
                                        "caddy_domain": "lowerduckpond.net",
                                        # This is the original synthetic repository's lineage name.
                                        "backup_node_name": self.fixture.config[
                                            "LOWERDUCKPOND_BACKUP_NODE_NAME"
                                        ],
                                    }
                                },
                            }
                        }
                    }
                }
            )
        )
        inode = (self.origin / "run.lock").stat()
        self.lease_digest = sha(self.session.token.encode())
        self.target = {
            "targetKind": "installed-fixture",
            "purpose": "installed-test",
            "enrollmentSha256": digest(self.enrollment),
            "allocationSha256": digest(self.allocation),
            "leaseDomainSha256": digest({"inode": inode.st_ino, "device": inode.st_dev}),
            "inventorySha256": sha(self.inventory.read_bytes()),
            "stateSha256": digest(namespace),
            "addressSetSha256": digest({"peer": self.fixture.endpoint["peerAddress"]}),
            "transactionNamespaceSha256": digest(
                {"path": str(AUTHORITY), "run": self.allocation["runId"]}
            ),
            "transport": {
                "kind": "ssh",
                "identitySha256": sha((self.fixture.directory / "known-hosts").read_bytes()),
            },
            "docker": self.allocation["docker"],
        }

        def transport() -> str:
            assert self.remote(
                "accepted-original-read",
                [PYTHON, "-I", "-B", self.session.helper, "journal", self.session.token, "read"],
            )
            self.seal("installed-allocation.json", self.allocation)
            self.seal("installed-target.json", self.target)
            self.seal("installed-enrollment.json", self.enrollment)
            return digest(self.target)

        self.observe("transportBootstrap", transport)

    def start(self, name: str) -> None:
        self.seal(name + ".started", {"lease": self.lease_digest, "stage": name})

    def complete(self, name: str, observation: str) -> None:
        self.seal(name + ".complete", {"stage": name, "observationSha256": observation})

    def converge(self, stage: str, *, enabled: bool, repeated: bool = False) -> str:
        self.start(stage)
        variables = converge._variables(
            "rotation-enabled", self.artifact, self.candidate["hostAgentSha256"]
        )
        variables.update(
            static_host_agent_verified_completed_candidate=False,
            static_publication_enabled=enabled,
        )
        override = self.directory / (stage + "-vars.json")
        override.write_bytes(encode(variables))
        recap = self.directory / (stage + "-recap.json")
        context = digest(
            {
                "stage": stage,
                "configuration": variables,
                "inventory": sha(self.inventory.read_bytes()),
            }
        )
        environment = self.session.ansible_environment(os.environ)
        environment.update(
            ANSIBLE_CONFIG=str(ROOT / "config/ansible/ansible.cfg"),
            ANSIBLE_CALLBACK_PLUGINS=str(ROOT / "config/ansible/plugins/callback"),
            ANSIBLE_CALLBACKS_ENABLED="ldp_m3_11_receipt,ldp_m3_12_successor",
            LDP_M3_11_PLAYBOOK_CONTEXT=context,
            LDP_M3_11_PLAYBOOK_RECEIPT=str(recap),
        )
        environment.update({APPLY_STAGE_ENV: stage, PROGRESS_ROOT_ENV: str(self.origin)})
        self.session.require_owner()
        assert recheck_installed(self.origin, self.fixture.environment) == self.allocation
        executable = shutil.which("uv")
        assert executable is not None
        result = subprocess.run(  # noqa: S603 - fixed playbook and leased owned target
            [
                executable,
                "run",
                "--frozen",
                "ansible-playbook",
                "-i",
                str(self.inventory),
                str(ROOT / "config/ansible/playbooks/site.yml"),
                "--extra-vars",
                "@" + str(override),
            ],
            env=environment,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        assert result.returncode == 0, f"Leased successor convergence failed at {stage}"
        observed, _ = converge.recap(
            recap, context, idempotent=repeated, expected_host=INSTALLED_HOST
        )
        self.health(enabled=enabled)
        observed_sha = sha(observed)
        self.complete(stage, observed_sha)
        return observed_sha

    def health(self, *, enabled: bool) -> str:
        assert self.remote("authoritative-generation", [VERIFY]) == b"current\n"
        self.remote("job-issuance", [GATE, "job-issuance"], expect=0 if enabled else 78)
        policy = json.loads(self.remote("gate-configuration", ["cat", str(PUBLICATION)]))
        assert policy["static_publication_enabled"] is enabled
        return digest(policy)

    def admission(self) -> bytes:
        binding = {
            "targetKind": "installed-fixture",
            "purpose": "installed-test",
            "runId": self.allocation["runId"],
            "targetSha256": digest(self.target),
            "candidateSha256": digest(self.candidate),
            "platformSha256": digest(self.platform),
        }
        receipts = {}
        for slot, kind in COMMON_SLOTS.items():
            start, end, observed = self.measurements[slot]
            receipt = record(
                "receipt",
                binding=binding,
                invocationId=self.invocation,
                kind=kind,
                startedAt=start,
                finishedAt=end,
                oldestSupportingAt=start,
                observationSha256=observed,
                outcome="passed",
            )
            receipts[slot] = digest(receipt)
            self.seal("prerequisite-" + receipts[slot] + ".json", receipt)
        return encode(
            record(
                "admission",
                binding=binding,
                target=self.target,
                candidate=self.candidate,
                platform=self.platform,
                invocationId=self.invocation,
                authoritySha256=digest(self.enrollment),
                leaseSha256=self.lease_digest,
                prerequisites=receipts,
                preparedAt=timestamp(),
            )
        )

    def launch(self) -> bytes:
        self.start("durable-launch")
        raw = self.admission()
        command = [
            PYTHON,
            "-I",
            "-B",
            "-c",
            "import sys;"
            "sys.path.insert(0,'/opt/lowerduckpond/static-host-agent/current/site-packages');"
            "from scripts.m3_12_installed_root import launch;"
            "sys.stdout.buffer.write(launch(sys.argv[1],sys.stdin.buffer.read(262145)))",
            self.session.token,
        ]
        original = self.remote("durable-launch", command, data=raw)
        assert json.loads(original)["binding"]["targetKind"] == "installed-fixture"
        assert self.remote("exact-launch-retry", command, data=raw) == original
        self.complete("durable-launch", sha(original))
        return original

    def physical(self, action: str, *, interrupt: bool = False) -> Document:
        command = [
            PYTHON,
            "-I",
            "-B",
            "-c",
            "import sys;"
            "sys.path.insert(0,'/opt/lowerduckpond/static-host-agent/current/site-packages');"
            "from scripts.m3_12_installed_root import physical;"
            "sys.stdout.buffer.write(physical(sys.argv[1],sys.argv[2],"
            "stop_after_selection=sys.argv[3]=='interrupt'))",
            self.session.token,
            action,
            "interrupt" if interrupt else "reconcile",
        ]
        if interrupt:
            assert not self.remote("interrupt-installed-rollback", command, expect=75)
            return {}
        return json.loads(self.remote("installed-" + action, command))  # type: ignore[no-any-return]


def test_installed_m3_12_successor_from_accepted_m3_11(  # noqa: PLR0915 - one installed proof
    host: Host,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = Path(os.environ[ARTIFACT_ENV]).parent.parent
    with successor_stage(origin, "predecessor-preparation"):
        assert host.run("systemctl is-active caddy.service").rc == 0
        fixture = Fixture(monkeypatch, source_revision=ACCEPTED_M3_11)
    with successor_stage(origin, "predecessor-rollout"):
        original = fixture.run(on_receipt=lambda name: predecessor_progress(origin, name))
    state = previous_journal.validate(original)
    assert state["phase"] == "complete"
    assert json.loads(original[0][1])["candidate"]["source_revision"] == ACCEPTED_M3_11
    assert host.run("test ! -e /var/lib/lowerduckpond/static/platform/launch.json").rc == 0
    directory = fixture.directory / "successor"
    directory.mkdir(mode=0o700)
    with controller(fixture.ssh, directory) as session:
        with successor_stage(origin, "candidate-preparation"):
            rollout = Rollout(fixture, session, directory, original)
            rollout.setup()
        with successor_stage(origin, "dark-staging"):
            rollout.observe("darkStage", lambda: rollout.converge("dark-staging", enabled=False))
            successor_generation = rollout.stage_distinct_platform_generation()
        with successor_stage(origin, "dark-repeat"):
            rollout.observe(
                "darkRepeat", lambda: rollout.converge("dark-repeat", enabled=False, repeated=True)
            )
        with successor_stage(origin, "durable-launch"):
            rollout.observe("targetSafety", lambda: rollout.health(enabled=False))
            launch = rollout.launch()
        with successor_stage(origin, "enabled-convergence"):
            rollout.converge("enabled-convergence", enabled=True)
        with successor_stage(origin, "enabled-repeat"):
            rollout.converge("enabled-repeat", enabled=True, repeated=True)
        with successor_stage(origin, "rollback-handoff"):
            assert rollout.active_generation() == successor_generation
            rollout.physical("restore-platform-only", interrupt=True)
            assert rollout.active_generation() == rollout.preceding_generation
            rollout.remote("interrupted-issuance-fenced", [GATE, "job-issuance"], expect=78)
        original_lease = sha(session.token.encode())

    recovery = directory / "rollback-recovery"
    recovery.mkdir(mode=0o700)
    with controller(fixture.ssh, recovery) as session:
        with successor_stage(origin, "rollback-resume"):
            assert sha(session.token.encode()) != original_lease
            rollout.session = session
            restored = rollout.physical("restore-platform-only")
            assert restored["source"] == successor_generation
            assert restored["desired"] == rollout.preceding_generation
            assert rollout.active_generation() == rollout.preceding_generation
            rollout.health(enabled=False)
        with successor_stage(origin, "same-policy-reactivation"):
            reactivated = rollout.physical("reactivate-same-policy")
            assert reactivated["source"] == rollout.preceding_generation
            assert reactivated["desired"] == successor_generation
            assert rollout.active_generation() == successor_generation
            rollout.health(enabled=True)
        assert rollout.remote(
            "verify-accepted-predecessor-unchanged",
            [PYTHON, "-I", "-B", session.helper, "journal", session.token, "read"],
        ) == previous_records.encode(original)
        assert (
            rollout.remote(
                "verify-original-launch-retained", ["cat", str(AUTHORITY / "launch-receipt.json")]
            )
            == launch
        )

        archive_line = installed_archive_hosts_line(origin, fixture.environment)
        assert reboot._archive_hosts_line(host) == archive_line, "Owned archive mapping changed."
        publish(origin, ARCHIVE_ENDPOINT, {"line": archive_line})
        publish(
            rollout.origin,
            "m3-12-successor-before-reboot.json",
            {
                "predecessorSource": ACCEPTED_M3_11,
                "predecessorSha256": rollout.predecessor,
                "launchReceiptSha256": sha(launch),
                "launchRecordSha256": json.loads(launch)["launchRecordSha256"],
                "rollbackEffectSha256": digest(restored),
                "reactivationEffectSha256": digest(reactivated),
                "rollbackResumedAfterHandoff": True,
                "rollbackSelectorChanged": True,
                "reactivatedSelectorSha256": sha(
                    (successor_generation["generation"] + "\n").encode("ascii")
                ),
            },
        )


def test_installed_m3_12_successor_survives_reboot_and_backup(host: Host) -> None:
    fixture = Path(os.environ[ARTIFACT_ENV]).parent.parent
    launch_path = "/var/lib/lowerduckpond/static/platform/launch.json"
    with successor_stage(fixture, "post-reboot"):
        # The Docker restart can recreate /etc/hosts. Recheck the original
        # sidecar and saved route before the successor or accounting use it.
        archive_line = installed_archive_hosts_line(fixture, dict(os.environ))
        assert read(fixture, ARCHIVE_ENDPOINT) == {"line": archive_line}, (
            "Owned archive endpoint changed."
        )
        reboot._restore_archive_hosts_line(host, archive_line)
        proof = read(fixture, "m3-12-successor-before-reboot.json")
        assert sha(host.file("/etc/caddy/active").content) == proof["reactivatedSelectorSha256"]
        result = host.run("%s job-issuance", GATE)
        assert result.rc == 0, "Publication authority was not restored after reboot."
        assert sha(host.file(launch_path).content) == proof["launchRecordSha256"]
        assert (
            sha(host.file(str(AUTHORITY / "launch-receipt.json")).content)
            == proof["launchReceiptSha256"]
        )
    with successor_stage(fixture, "backup-readback"):
        listing = "snapshots --json --tag lowerduckpond-static-backup"
        before = {item["id"] for item in json.loads(backup._restic(host, listing))}
        status = host.run("systemctl start %s", captures.BACKUP_UNIT)
        assert status.rc == 0, "Installed successor backup did not complete."
        after = {item["id"] for item in json.loads(backup._restic(host, listing))}
        (snapshot,) = after - before
        assert len(snapshot) == 64 and all(c in "0123456789abcdef" for c in snapshot)  # noqa: PLR2004
        assert (
            sha(backup._restic(host, f"dump {snapshot} {launch_path}").encode())
            == proof["launchRecordSha256"]
        )
    publish(
        fixture,
        "m3-12-successor-proof.json",
        {
            **proof,
            "format": "lowerduckpond-m3-12-installed-successor-proof-v1",
            "authority": "installed-diagnostic",
            "admissionPurpose": "installed-test",
            "enabledAfterReboot": True,
            "originalLaunchInBackup": True,
        },
    )
