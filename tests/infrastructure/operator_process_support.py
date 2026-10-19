"""Private process boundaries used by the connected synthetic attempt.

Production bootstrap and validation execute their real entry functions. The
external state loader/probe and journey process supply disposable observations.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_combined_inputs as combined
from scripts import qualification_restore
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_restore_reservation import reserve
from scripts.m3_11_unattended import inputs, production
from scripts.production_qualification_inputs import POLICY
from scripts.qualification_context import ARTIFACT_ENV

from .operator_completion_support import Observations
from .operator_flow_support import ARTIFACT
from .operator_host_support import Host
from .operator_provider_support import Cloud


class Child:
    pid = 2_000_000_000
    returncode = 0
    stdout = None

    def __init__(
        self, communicate: Callable[[bytes], int], *, status: int = 0, stdout: bytes | None = None
    ) -> None:
        self.execute = communicate
        self.returncode = status
        if stdout is not None:
            read, write = os.pipe()
            os.write(write, stdout)
            os.close(write)
            self.stdout = os.fdopen(read, "rb")

    def communicate(
        self,
        input: bytes | None = None,  # noqa: A002 - matches subprocess.Popen interface
        timeout: float | None = None,
    ) -> tuple[bytes, bytes]:
        self.returncode = self.execute(input or b"")
        return b"", b""

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


class Processes:
    def __init__(self, host: Host, cloud: Cloud, monkeypatch: pytest.MonkeyPatch) -> None:
        self.host, self.cloud, self.monkeypatch = host, cloud, monkeypatch
        # The simulated original journey acquires the same persistent target lock.
        target = {"region": cloud.targets.region, "archive_bucket": cloud.targets.archive_bucket}
        lock = host.storage_leases / (hashlib.sha256(canonical_bytes(target)).hexdigest() + ".lock")
        lock.touch(mode=0o600)
        self.fixtures: list[Path] = []
        self.environments: list[dict[str, str]] = []
        self.observations: list[Observations] = []
        self.success = False
        self.reserved = False
        self.previous_transport = host.services.transport_handler
        host.services.transport_handler = self.transport
        monkeypatch.setattr(subprocess, "Popen", self.spawn)

    def transport(
        self, program: str, arguments: list[str], stdin: bytes | None, kwargs: dict[str, object]
    ) -> bytes:

        if program == "bash" and any("production validate" in argument for argument in arguments):
            assert stdin is not None
            environment = cast(dict[str, str], kwargs["env"])
            assert "OP_CONNECT_TOKEN" not in environment
            environment.update(
                SPACES_ARCHIVE_ACCESS_KEY_ID="SYNTHETIC-PRODUCTION-ARCHIVE",
                SPACES_ARCHIVE_SECRET_ACCESS_KEY="SYNTHETIC-PRODUCTION-ARCHIVE-SECRET",  # noqa: S106 - synthetic test value only
                SPACES_BACKUP_ACCESS_KEY_ID="SYNTHETIC-PRODUCTION-BACKUP",
                SPACES_BACKUP_SECRET_ACCESS_KEY="SYNTHETIC-PRODUCTION-BACKUP-SECRET",  # noqa: S106 - synthetic test value only
            )
            with self.monkeypatch.context() as external:
                for key in list(os.environ):
                    external.delenv(key)
                for key, value in environment.items():
                    external.setenv(key, value)
                production.validate(json.loads(stdin), Path.cwd())
            return b""
        if program == "uv" and "credential-check" in arguments:
            assert "ldp-m3-archive" in arguments and "--probe-record" in arguments
            environment = cast(dict[str, str], kwargs["env"])
            assert not any(key.startswith(("OP_", "OPENTOFU_")) for key in environment)
            return b""
        assert self.previous_transport is not None
        return self.previous_transport(program, arguments, stdin, kwargs)

    def spawn(self, arguments: list[str], **kwargs: object) -> Child:

        if arguments[1:] == ["-m", "scripts.m3_11_unattended.production", "bootstrap"]:
            return Child(lambda raw: production.bootstrap(json.loads(raw), Path.cwd()))
        if Path(arguments[0]).name == "docker":
            output = self.host.command(arguments[1:])
            return Child(lambda _raw: 0, stdout=output)
        if "molecule" in arguments:
            assert arguments[1:] == [
                "run",
                "--frozen",
                "molecule",
                "create",
                "--scenario-name",
                "m3_8",
            ]
            environment = cast(dict[str, str], kwargs["env"])
            for role in ("host", "archive"):
                self.host.command(
                    [
                        "create",
                        "--name",
                        f"ldp-m3-{environment['LDP_QUALIFICATION_RUN_ID']}-{role}",
                        "--label",
                        "lowerduckpond.qualification.run="
                        + environment["LDP_QUALIFICATION_RUN_ID"],
                        "sha256:" + "9" * 64,
                    ]
                )
            return Child(lambda _raw: 0)
        assert Path(arguments[0]).name == "just" and arguments[1:] == ["m3-11-spaces-qualification"]
        environment = cast(dict[str, str], kwargs["env"])
        self.environments.append(environment)
        fixture = Path(environment["M3_11_EVIDENCE_ROOT"]) / "synthetic-fixture"
        fixture.mkdir(mode=0o700)
        selected = combined.allocate(fixture, environment)
        with self.monkeypatch.context() as external:
            for key in list(os.environ):
                external.delenv(key)
            for key, value in selected.items():
                external.setenv(key, value)
            inputs.capture(
                Path(environment[inputs.MANAGED_ENV]),
                fixture,
                repository=Path.cwd(),
                now=datetime.now(UTC),
            )
        self.fixtures.append(fixture)
        # The first attempt fails before fixture CREATE. Later attempts expose
        # modeled functional observations for the separate completion validators.
        if len(self.fixtures) == 1 and self.reserved:
            combined.begin_create(fixture, Path.cwd(), selected)
            assert combined.execute_create(fixture, Path.cwd(), selected) == 0
            self.reserve(fixture, selected)
        if len(self.fixtures) > 1:
            observed = Observations(fixture, selected)
            self.observations.append(observed)
            if self.success:
                observed.finish()
        return Child(lambda _raw: 0 if self.success else 1, status=0 if self.success else 1)

    def reserve(self, fixture: Path, environment: dict[str, str]) -> None:

        target = combined._target(environment)
        bound = read_private(fixture / "managed-credentials.json")
        binding = {
            key: bound[key]
            for key in (
                "source_revision",
                "artifact_sha256",
                "qualification_inputs_sha256",
                "storage_target_sha256",
            )
        }
        binding.update(
            input_policy=POLICY, storage_run_id=str(uuid.uuid7()), storage_report_sha256="a" * 64
        )
        Path(environment[ARTIFACT_ENV]).write_bytes(ARTIFACT)
        self.cloud.objects[target.backup_bucket, target.owner_key] = (
            "synthetic-original-version",
            canonical_bytes(target.manifest(binding)),
        )
        storage = LiveStorage(target, binding, "synthetic-original-version", environment, "a" * 64)
        reserve(storage)
        qualification_restore.create_stopped(environment, "acme")
