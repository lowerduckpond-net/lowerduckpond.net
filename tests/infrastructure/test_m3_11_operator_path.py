"""Connected synthetic operator workflow through actual producers and validators.

All remote/native/provider responses are modeled, never captured live evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import time
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import m3_11_finalization_access as finalization_access
from scripts import m3_11_functional_completion as functional
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import __main__ as launcher
from scripts.m3_11_unattended import (
    connect_action,
    connect_activate,
    connect_delivery,
    operator_publish,
    operator_records,
)
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import controller_name
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp
from scripts.m3_11_unattended.watchdog import quiesce_runtime
from scripts.m3_11_unattended.worker import Worker

from .operator_flow_support import SOURCE
from .operator_process_support import Processes
from .operator_provider_support import Cloud
from .test_m3_11_cleanup_workflow import select
from .test_m3_11_lease_configuration import mapping
from .test_m3_11_operator_migration import MigrationCase, complete_history
from .test_m3_11_operator_records import command

LEGACY_KNOWN_IDS = 43
LEGACY_ABORTED = 7


class ConnectedCase(MigrationCase):
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        super().__init__(tmp_path, monkeypatch)
        self.monkeypatch = monkeypatch
        self.cloud = Cloud(self.services, monkeypatch)
        complete_history(self, monkeypatch)
        for name, value in (
            ("prepared", self.prepared),
            ("historical", self.historical),
            ("declarations", self.declarations),
        ):
            write_private(self.studio / (name + ".json"), value)
        self.host.isolated = True

    def deliver_cli(self, operation: str, output: Path, *extra: str) -> None:
        self.monkeypatch.setattr(
            sys,
            "argv",
            [
                "delivery",
                "--operation",
                operation,
                "--output",
                str(output),
                "--destination",
                "coder@synthetic.test",
                "--workspace",
                "synthetic-workspace",
                "--workspace-id",
                "11111111-1111-1111-1111-111111111111",
                *extra,
            ],
        )
        assert connect_delivery.main() == 0

    def collect(self) -> dict[str, object]:
        output = self.studio / "collected.json"
        self.deliver_cli(
            "inspect-import",
            output,
            "--prepared",
            str(self.studio / "prepared.json"),
            "--daemon-socket",
            "/var/run/docker.sock",
            "--historical-reader",
            str(self.studio / "historical.json"),
            "--journal-vault",
            str(mapping(self.services.manifest["vaults"])["journal"]),
            "--declarations",
            str(self.studio / "declarations.json"),
        )
        return read_private(output)

    def publish(self) -> None:
        staged = self.studio / "staged"
        args = [
            "publisher",
            "publish-attestations",
            "--manifest",
            str(self.studio / "bound-inputs.json"),
            "--staged",
            str(staged),
            "--expected-controller-sha256",
            hashlib.sha256((staged / "controller-connect.json").read_bytes()).hexdigest(),
            "--state",
            str(self.studio / "publication"),
        ]
        self.monkeypatch.setattr(sys, "argv", args)
        assert operator_publish.main() == 0
        proposal, _config = operator_publish.staged(
            self.studio / "bound-inputs.json", staged, args[7]
        )
        self.monkeypatch.setattr(
            sys, "argv", [*args, "--apply", "--expected-proposal-sha256", digest(proposal)]
        )
        assert operator_publish.main() == 0

    def approve_attempt(self, *, retry: Path | None = None) -> Path:
        suffix = "retry" if retry else "initial"
        proposal = self.studio / (suffix + "-proposal.json")
        command(
            self.monkeypatch,
            "attempt-proposal",
            "--inputs",
            str(self.studio / "bound-inputs.json"),
            "--prepared",
            str(self.studio / "prepared.json"),
            "--source",
            SOURCE,
            "--mode",
            "qualification",
            "--expires-at",
            stamp(datetime.now(UTC) + timedelta(hours=2)),
            "--output",
            str(proposal),
            *(["--reuse-status", str(retry)] if retry else []),
        )
        output = self.studio / (suffix + "-approval")
        command(
            self.monkeypatch,
            "record-attempt",
            "--proposal",
            str(proposal),
            "--expected-proposal-sha256",
            digest(read_private(proposal)),
            "--approved-at",
            stamp(datetime.now(UTC) - timedelta(seconds=1)),
            "--approval-reference",
            "SYNTHETIC external attempt consent",
            "--output",
            str(output),
        )
        return output / "live-approval.json"

    def schedule(self, *, expected: int = 0) -> Path:
        runner = self.studio / ("runner-" + str(len(list(self.studio.glob("runner-*")))))
        runner.mkdir(mode=0o700)
        for key, value in {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": connect_action.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": (
                f"{connect_action.REPOSITORY}/.github/workflows/"
                f"{connect_action.WORKFLOW}@refs/heads/main"
            ),
            "M3_11_HELPER_REVISION": SOURCE,
            "RUNNER_TEMP": str(runner),
            "GITHUB_RUN_ID": str(100 + len(list(self.studio.glob("runner-*")))),
            "GITHUB_RUN_ATTEMPT": "1",
        }.items():
            self.monkeypatch.setenv(key, value)
        bundle = read_private(self.studio / "staged/github-connect.json")
        with self.monkeypatch.context() as external:
            external.setattr(subprocess, "run", self.services.local_run)
            external.setattr(subprocess, "Popen", self.services.local_popen)
            result, selected = select(runner, BOOTSTRAP=json.dumps(bundle))
        assert result.returncode == 0
        stream = io.TextIOWrapper(
            io.BytesIO(canonical_bytes({"bootstrap": bundle, "operation": selected["operation"]}))
        )
        self.monkeypatch.setattr(sys, "stdin", stream)
        assert connect_action.main() == expected, read_private(
            runner / "m3-11-connect/receipt.json"
        )
        return runner


@pytest.mark.parametrize("ordinary_success", [False, True])
def test_connected_operator_approval_existing_import_activation_launch_and_seven_creates(  # noqa: PLR0915 - one connected producer-to-consumer scenario
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ordinary_success: bool
) -> None:
    case = ConnectedCase(tmp_path, monkeypatch)
    config = case.approve_and_stage(monkeypatch)
    obligations = mapping(read_private(case.studio / "migration/legacy-import.json")["obligations"])
    assert (
        sum(mapping(row)["provider_id"] is not None for row in obligations.values())
        == LEGACY_KNOWN_IDS
    )
    assert (
        sum(mapping(row)["original_status"] == "not-submitted" for row in obligations.values())
        == LEGACY_ABORTED
    )
    assert (
        sum(
            mapping(row)["original_status"] == "operator-accepted-uncertainty"
            for row in obligations.values()
        )
        == 1
    )
    case.publish()
    case.seed_historical_import(config)
    before_import = len(case.services.exchanges)
    case.deliver_cli(
        "import",
        case.studio / "staged",
        "--prepared",
        str(case.studio / "prepared.json"),
        "--daemon-socket",
        "/var/run/docker.sock",
        "--approved-import",
        str(case.studio / "migration/legacy-import.json"),
        "--apply",
    )
    assert all(row["method"] == "GET" for row in case.services.exchanges[before_import:])
    with pytest.raises(FileNotFoundError):
        read_private(next(case.directory.glob("credential-cleanup/*.json")))
    monkeypatch.setattr(
        sys, "argv", ["activate", "preflight", "--output", str(case.studio / "staged")]
    )
    assert connect_activate.main() == 0
    case.deliver_cli("deliver", case.studio / "staged", "--apply")
    approved = case.approve_attempt()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "launcher",
            "start",
            SOURCE,
            "--approval",
            str(approved),
            "--config",
            str(case.host.controller),
            "--mode",
            "qualification",
            "--daemon-socket",
            "/var/run/docker.sock",
        ],
    )
    with case.host.inside():
        assert launcher.main() == 0
        directory = case.host.evidence / "runs" / case.host.launched[-1]
        worker = Worker(directory, LeaseConfiguration.load(case.host.controller), Path.cwd())
        assert worker.request["approval_sha256"] == digest(read_private(approved))
        worker.state.begin(worker.binding)
        for name in (
            "credential-intents",
            "credential-cleanup",
            "qualification",
            "docker-config",
            "supervisor",
        ):
            (directory / name).mkdir(mode=0o700)
        worker._verify_daemon()
        worker._verify_source()
        original_sleep = time.sleep

        def tick(seconds: float) -> None:
            if seconds == 5:  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
                assert not case.cloud.creates
                # The independent runner has no host filesystem even while
                # its controller waits inside the synthetic daemon boundary.
                old_depth = case.host.depth
                case.host.depth = 0
                try:
                    case.services.lose_post = "-confirmed"
                    runner = case.schedule(expected=1)
                    posted = sum(row["method"] == "POST" for row in case.services.exchanges)
                    # A retry using the durable pending directory cannot replay.
                    bundle = read_private(case.studio / "staged/github-connect.json")

                    with pytest.raises(LifecycleError):
                        connect_action.execute(
                            {"bootstrap": bundle, "operation": "confirm"},
                            directory=runner / "m3-11-connect",
                            helper=SOURCE,
                        )
                    assert sum(row["method"] == "POST" for row in case.services.exchanges) == posted
                    # A fresh scheduled runner can independently observe and confirm.
                    case.schedule()
                    case.services.hidden.clear()

                    before = sum(row["method"] == "POST" for row in case.services.exchanges)
                    case.schedule()
                    assert sum(row["method"] == "POST" for row in case.services.exchanges) == before
                    confirmations = [
                        json.loads(str(cast(list[dict[str, object]], row["fields"])[0]["value"]))
                        for row in case.services.items.values()
                        if str(row["title"]).endswith("-confirmed")
                    ]
                    assert len(confirmations) == 2  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
                    assert len({row["payload"]["github_run_id"] for row in confirmations}) == 2  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
                    assert not case.cloud.creates
                finally:
                    case.host.depth = old_depth
            else:
                original_sleep(seconds)

        monkeypatch.setattr(time, "sleep", tick)
        credentials, fixture = worker._provision()
        assert len(case.cloud.creates) == 7  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
        assert set(credentials) == {
            "archive",
            "backup",
            "operator",
            "caddy",
            "observer",
            "audit",
            "page-rules",
        }
        assert fixture["helper_revision"] == fixture["source_revision"] == SOURCE
        assert worker.lifecycle is not None
        assert worker.lifecycle.manifest.helper_revision == SOURCE
        processes = Processes(case.host, case.cloud, monkeypatch)
        processes.reserved = not ordinary_success
        production = worker._production(credentials, fixture)
        environment = worker._deliver(credentials, {"production": production, "fixture": fixture})
        assert worker._journey(environment) == 1
        worker.state.finish_journey("failed", 1)
        original_failure = (directory / "journey-result.json").read_bytes()
        worker._terminal()
        assert worker.state.status()["credential_cleanup"] == "pending"
        case.host.command(["stop", controller_name(worker.run_id)])
        proof = quiesce_runtime(directory, case.docker)
        assert len(cast(list[object], proof["containers"])) == (0 if ordinary_success else 4)
        status = json.loads(launcher.operate(case.docker, worker.run_id, "status"))
        for fault in ("binding", "progress", "released", "deadline"):
            altered = deepcopy(status)
            if fault == "binding":
                altered["binding"] = {}
                altered["retry_basis"]["attempt_binding_sha256"] = digest({})
            elif fault == "progress":
                altered["status"]["qualification"] = "passed"
            elif fault == "released":
                altered["lease"]["use_released"] = False
            else:
                altered["retry_basis"]["deadline"] = stamp(datetime.now(UTC) + timedelta(days=100))
            with pytest.raises((ValueError, LifecycleError)):
                operator_records.retry_basis(
                    altered,
                    policy=worker.config.policy,
                    targets=worker.config.targets,
                    now=datetime.now(UTC),
                )
        later = datetime.now(UTC) + timedelta(days=3)
        proposal = operator_records.attempt_body(
            {
                "inputs": read_private(case.studio / "bound-inputs.json"),
                "prepared": case.prepared,
                "reuse_status": status,
            },
            {
                "source": SOURCE,
                "mode": "qualification",
                "expires_at": stamp(later + timedelta(hours=1)),
            },
            now=later,
        )
        assert proposal["lease_id"] == worker.lifecycle.manifest.lease_id
        retry_status = case.studio / "retry-status.json"
        write_private(retry_status, status)
        retry_approval = case.approve_attempt(retry=retry_status)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "launcher",
                "start",
                SOURCE,
                "--approval",
                str(retry_approval),
                "--config",
                str(case.host.controller),
                "--mode",
                "qualification",
                "--daemon-socket",
                "/var/run/docker.sock",
            ],
        )
        assert launcher.main() == 0
        retry_directory = case.host.evidence / "runs" / case.host.launched[-1]
        retry = Worker(retry_directory, LeaseConfiguration.load(case.host.controller), Path.cwd())
        processes.success = ordinary_success
        assert retry.run() == (0 if ordinary_success else 1)
        assert retry.lifecycle is not None
        observed = processes.observations[-1]
        pairs = mapping(read_private(observed.directory / "managed-credentials.json")["receipts"])
        fresh_fixture = mapping(pairs["fixture"])
        fresh_production = mapping(pairs["production"])
        assert fresh_fixture["identities_sha256"] == fixture["identities_sha256"]
        assert fresh_fixture["deadline"] == fixture["deadline"]
        assert fresh_fixture["managed_run_id"] != fixture["managed_run_id"]
        assert fresh_production["managed_run_id"] == retry.run_id
        if not ordinary_success:
            retained_result = (retry_directory / "journey-result.json").read_bytes()
            deadline = instant(fresh_fixture["deadline"])
            for moment in (
                datetime.now(UTC),
                datetime.now(UTC) + timedelta(days=3),
                deadline - timedelta(seconds=1),
            ):
                with monkeypatch.context() as clock:
                    clock.setattr(
                        finalization_access,
                        "datetime",
                        SimpleNamespace(now=lambda _zone, value=moment: value),
                    )
                    with finalization_access.access(observed.directory):
                        finalization_access.require_live(observed.directory)
                        assert functional.load(observed.directory, observed.environment)[0].passed(
                            0
                        )
            with monkeypatch.context() as clock:
                clock.setattr(
                    finalization_access, "datetime", SimpleNamespace(now=lambda _zone: deadline)
                )
                with pytest.raises(ValueError), finalization_access.access(observed.directory):
                    pytest.fail("access crossed original expiry")
            with finalization_access.access(observed.directory):
                observed.finish(recovery=True)
            assert (retry_directory / "journey-result.json").read_bytes() == retained_result
            retry.state.cancel()
            assert retry.revoke()
        assert retry.state.status()["credential_cleanup"] == "verified"
        assert len(case.cloud.creates) == 7  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
        assert not case.cloud.keys
        assert not any(
            str(item["name"]).startswith("ldp-m311-") for item in case.cloud.tokens.values()
        )
        assert (directory / "journey-result.json").read_bytes() == original_failure
        case.schedule()
        assert case.host.original_files().items() >= case.baseline.items()


def test_host_import_lost_response_reuses_persistent_mapping_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_m3_11_legacy_discovery import DiscoveryCase  # noqa: PLC0415 - shared v2 fixture
    from .test_m3_11_legacy_import_reader import attach_bridge  # noqa: PLC0415 - Docker boundary

    case = DiscoveryCase(tmp_path, monkeypatch)
    original_files = case.host.original_files()
    case.approve_and_stage(monkeypatch)
    attach_bridge(case, monkeypatch)
    write_private(case.studio / "prepared.json", case.prepared)
    case.host.isolated = True
    arguments = [
        "delivery",
        "--operation",
        "import",
        "--output",
        str(case.studio / "staged"),
        "--destination",
        "coder@synthetic.test",
        "--workspace",
        "synthetic-workspace",
        "--workspace-id",
        "11111111-1111-1111-1111-111111111111",
        "--prepared",
        str(case.studio / "prepared.json"),
        "--daemon-socket",
        "/var/run/docker.sock",
        "--approved-import",
        str(case.studio / "migration/legacy-import.json"),
        "--apply",
    ]
    monkeypatch.setattr(sys, "argv", arguments)
    case.services.lose_post = "m3-11-import-"
    before_post = sum(row["method"] == "POST" for row in case.services.exchanges)
    with pytest.raises(SystemExit) as refused:
        connect_delivery.main()
    assert refused.value.code == 1
    posted = sum(row["method"] == "POST" for row in case.services.exchanges)
    assert posted == before_post + 1
    with case.host.inside():
        pending = {str(path): path.read_bytes() for path in case.host.spool.rglob("*.json")}
    assert pending
    assert sum(Path(path).name.startswith("import-") for path in pending) == 1
    with pytest.raises(SystemExit) as refused:
        connect_delivery.main()
    assert refused.value.code == 1
    assert sum(row["method"] == "POST" for row in case.services.exchanges) == posted
    case.services.hidden.clear()
    assert connect_delivery.main() == 0
    assert sum(row["method"] == "POST" for row in case.services.exchanges) == posted
    with case.host.inside():
        assert {str(path): path.read_bytes() for path in case.host.spool.rglob("*.json")} == pending
        assert case.host.original_files() == original_files
