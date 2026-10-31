"""Separate diagnostic on a fresh, genuine local-MinIO reconstructed fixture.

Not a pytest test or qualification entry point. The isolated controller calls
this adapter only after fresh native local reconstruction, prearmed host cleanup
and independently confirmed three-role issuance. Preparation remains a separate
native phase so no child lifetime is consumed by fixture convergence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import restore_scenarios as restore
from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS
from public_ca_recovery import PublicRecovery, observation, program
from restore_fixture import Fixture
from testinfra.host import Host

from scripts import m3_11_isolation_preparation as preparation
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_errors as errors
from scripts import qualification_restore as owned
from scripts.m3_11_isolation_contract import (
    CONTEXT_FORMAT,
    RESULT_FORMAT,
    Intent,
    Plan,
    require_public_admission,
)
from scripts.m3_11_isolation_dns import IsolationWitness, Readers, authenticate
from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_public_inputs import FORMAT as INPUT_FORMAT
from scripts.m3_11_public_inputs import _copy, _fingerprints, require_original
from scripts.m3_11_public_inputs_probe import FILES
from scripts.m3_11_public_sequence import exercise
from scripts.m3_11_unattended.model import digest
from scripts.production_qualification_inputs import current_candidate
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, HOST_ENV, RUN_ENV
from scripts.qualification_retirement import artifact_digest

ROOT = Path(__file__).resolve().parents[5]


@dataclass(frozen=True)
class Setup:
    plan: Plan
    intents: tuple[Intent, ...]
    readers: Readers = field(repr=False)
    expected_ids: dict[str, str]
    controller_id: str
    require_cleanup_armed: Callable[[], None] = field(repr=False)
    observe: Callable[[str, object], None] = field(repr=False)


def reconstruct(source: Host, directory: Path) -> tuple[Fixture, list[str], dict[str, object]]:
    """Build the actual local prerequisite journal, never a synthetic COMPLETE."""
    fixture, tenants, replay = restore.source(
        source, directory, full_history=True, live_storage=None
    )
    fixture.fault("none")
    fixture.start()
    restore.verify_reconstruction(fixture, replay)
    return fixture, tenants, replay


def observe_preparation(
    fixture: Fixture, directory: Path, *, source: str, controller_id: str
) -> dict[str, object]:
    """Produce nonsecret bindings by observing the actual native fixture."""
    current_candidate(ROOT, source)
    if (
        fixture.live_storage is not None
        or fixture.environment.get("M3_10_ARCHIVE_BACKEND") != "minio"
    ):
        raise ValueError("isolated preparation cannot use live Spaces")
    identities = {
        "source": owned.inspect(fixture.environment, fixture.source_id),
        "destination": owned.inspect(fixture.environment, fixture.destination_id),
        "acme": owned.inspect(fixture.environment, fixture.acme_id),
        "archive": owned.inspect(fixture.environment, fixture.environment[ARCHIVE_ENV]),
        "controller": owned.inspect(fixture.environment, controller_id),
    }
    if any(item.get("running") is not True for item in identities.values()):
        raise ValueError("isolated preparation needs the fresh running resource graph")
    binary_sha = hashlib.sha256(fixture.source.file(fixture.binary).content).hexdigest()
    guest = program(fixture, isolated=True)
    raw = fixture.command(
        "docker",
        "exec",
        "--interactive",
        fixture.destination_id,
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        guest,
        stdin=policy.canonical(
            {
                "action": "observe_prepared",
                "failure_protocol": errors.FORMAT,
                "binary": fixture.binary,
                "binary_sha256": binary_sha,
                "restore_id": fixture.restore_id,
            }
        ),
        timeout=60,
    )
    daemon = json.loads(
        fixture.command(
            "docker",
            "info",
            "--format",
            '{"ID":{{json .ID}},"Name":{{json .Name}},'
            '"ServerVersion":{{json .ServerVersion}},"DockerRootDir":{{json .DockerRootDir}}}',
        )
    )
    modes = {
        name: fixture.command(
            "docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", str(actor["id"])
        )
        .decode()
        .strip()
        for name, actor in identities.items()
    }
    captured = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    run_id = str(uuid.UUID(fixture.environment[RUN_ENV]))
    require_original(
        directory,
        {
            "run_id": run_id,
            "captured_at": captured,
            "source_fixture_sha256": digest(
                {key: identities["source"][key] for key in ("id", "name", "owner", "image")}
            ),
        },
    )
    owned.source_fenced(fixture.environment)
    result = preparation.parse(
        {
            "format": preparation.FORMAT,
            "run_id": run_id,
            "source_revision": source,
            "artifact_sha256": artifact_digest(Path(fixture.environment[ARTIFACT_ENV])),
            "caddy_binary_sha256": binary_sha,
            "daemon_sha256": digest(daemon),
            "original_inputs_sha256": hashlib.sha256(
                read_private_bytes(directory / "public-inputs/original.json")
            ).hexdigest(),
            "source_fence_sha256": hashlib.sha256(fixture.fence).hexdigest(),
            "guest_program_sha256": hashlib.sha256(guest.encode()).hexdigest(),
            "restore": observation(raw, action="observe_prepared", directory=directory),
            "captured_at": captured,
            "actors": {
                name: {key: item[key] for key in ("id", "name", "owner", "image")}
                for name, item in identities.items()
            },
            "topology": {
                "docker_endpoint": fixture.environment["DOCKER_HOST"],
                "daemon": daemon,
                "network_modes": modes,
            },
        }
    )
    write_private(directory / "isolation-guest-program.json", {"program": guest})
    write_private(directory / "isolation-prepared.json", result)
    return result


def daemon_identity(fixture: Fixture, plan: Plan) -> dict[str, object]:
    if fixture.environment.get("DOCKER_HOST") != plan.docker_endpoint:
        raise ValueError("isolated Docker endpoint changed")
    daemon = json.loads(
        fixture.command(
            "docker",
            "info",
            "--format",
            '{"ID":{{json .ID}},"Name":{{json .Name}},'
            '"ServerVersion":{{json .ServerVersion}},"DockerRootDir":{{json .DockerRootDir}}}',
        )
    )
    if not isinstance(daemon, dict) or digest(daemon) != plan.daemon_sha256:
        raise ValueError("isolated Docker daemon identity changed")
    return daemon


def topology(
    fixture: Fixture, identities: dict[str, dict[str, object]], plan: Plan
) -> dict[str, object]:
    daemon = daemon_identity(fixture, plan)
    networks = {}
    for name, actor in identities.items():
        mode = (
            fixture.command(
                "docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", str(actor["id"])
            )
            .decode()
            .strip()
        )
        if mode != ("host" if name == "controller" else "bridge"):
            raise ValueError("isolated actor left the native network path")
        networks[name] = mode
    return {"docker_endpoint": plan.docker_endpoint, "daemon": daemon, "network_modes": networks}


def capture(directory: Path, environment: dict[str, str]) -> None:
    """Use the genuine fresh-input probe, before any controlled CA is installed."""
    if environment.get("M3_10_ARCHIVE_BACKEND") != "minio" or environment.get(
        "M3_10_INSTALLED_REPORT"
    ):
        raise ValueError("isolated public inputs require an owned local-MinIO fixture")
    source = owned.inspect(environment, environment[HOST_ENV])
    if source.get("running") is not True:
        raise ValueError("isolated public inputs require the fresh running source")
    destination = directory / "public-inputs"
    destination.mkdir(mode=0o700)
    started = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    fingerprints = _fingerprints(environment, str(source["id"]))
    for name in FILES:
        _copy(environment, str(source["id"]), destination / name, fingerprints[name])
    if fingerprints != _fingerprints(environment, str(source["id"])) or source != owned.inspect(
        environment, str(source["id"])
    ):
        raise ValueError("isolated public input source changed during capture")
    write_private(
        destination / "original.json",
        {
            "format": INPUT_FORMAT,
            "run_id": environment[RUN_ENV],
            "source": {key: source[key] for key in ("id", "name", "owner", "image")},
            "started_at": started,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "files": fingerprints,
        },
    )


class IsolatedRecovery(PublicRecovery):
    """Own diagnostic guards around the unchanged shared recovery sequence."""

    def __init__(
        self,
        fixture: Fixture,
        directory: Path,
        setup: Setup,
    ) -> None:
        plan, intents, readers = setup.plan, setup.intents, setup.readers
        prepared = preparation.require(read_private(directory / "isolation-prepared.json"), plan)
        plan.network.document()  # No choice or fallback is supplied here.
        self.plan = plan
        self.intents = intents
        self.plan_sha256 = plan.sha256
        self.require_cleanup_armed = setup.require_cleanup_armed
        self.observe = setup.observe
        self.fixture, self.directory = fixture, directory
        self.controller_id = setup.controller_id
        environment = fixture.environment
        if (
            fixture.live_storage is not None
            or environment.get("M3_10_ARCHIVE_BACKEND") != "minio"
            or environment.get("M3_10_INSTALLED_REPORT")
            or environment[RUN_ENV] != plan.run_id.replace("-", "")
            or any(
                key.startswith("SPACES_") or key == "M3_10_PAGE_RULES_TOKEN" for key in environment
            )
        ):
            raise ValueError(
                "isolated public recovery cannot use live storage or qualification inputs"
            )
        current_candidate(ROOT, plan.source_revision)
        if artifact_digest(Path(environment[ARTIFACT_ENV])) != plan.artifact_sha256:
            raise ValueError("isolated selected installed artifact changed")
        identities = {
            "source": owned.inspect(environment, fixture.source_id),
            "destination": owned.inspect(environment, fixture.destination_id),
            "acme": owned.inspect(environment, fixture.acme_id),
            "archive": owned.inspect(environment, environment[ARCHIVE_ENV]),
            "controller": owned.inspect(environment, setup.controller_id),
        }
        if len({item["id"] for item in identities.values()}) != len(identities) or any(
            item.get("running") is not True for item in identities.values()
        ):
            raise ValueError("isolated actors must be distinct and running")
        if (
            identities["controller"]["image"] != "sha256:" + plan.controller_sha256
            or identities["archive"]["image"] != "sha256:" + plan.archive_image_sha256
        ) or any(
            identities[key]["image"] != "sha256:" + plan.fixture_image_sha256
            for key in ("source", "destination", "acme")
        ):
            raise ValueError("isolated runtime image differs from the bound plan")
        if (
            hashlib.sha256(fixture.source.file(fixture.binary).content).hexdigest()
            != plan.caddy_binary_sha256
        ):
            raise ValueError("isolated Caddy binary differs from the bound plan")
        self.program = program(fixture, isolated=True)
        if hashlib.sha256(self.program.encode()).hexdigest() != prepared["guest_program_sha256"]:
            raise ValueError("isolated selected guest program changed after preparation")
        original_restore = observation(
            fixture.command(
                "docker",
                "exec",
                "--interactive",
                fixture.destination_id,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                self.program,
                stdin=policy.canonical(
                    {
                        "action": "observe_prepared",
                        "failure_protocol": errors.FORMAT,
                        "binary": fixture.binary,
                        "binary_sha256": plan.caddy_binary_sha256,
                        "restore_id": fixture.restore_id,
                    }
                ),
                timeout=60,
            ),
            action="observe_prepared",
            directory=directory,
        )
        if original_restore != prepared["restore"]:
            raise ValueError("isolated genuine reconstruction changed after preparation")
        self.context = {
            "format": CONTEXT_FORMAT,
            "plan_sha256": plan.sha256,
            "run_id": plan.run_id,
            "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "source_fixture_sha256": digest(
                {key: identities["source"][key] for key in ("id", "name", "owner", "image")}
            ),
            "actors": {
                name: {key: item[key] for key in ("id", "name", "owner", "image")}
                for name, item in identities.items()
            },
            "topology": topology(fixture, identities, plan),
            "guest_program_sha256": hashlib.sha256(self.program.encode()).hexdigest(),
            "preparation_sha256": plan.preparation_sha256,
        }
        self.original = require_original(directory, self.context)
        self.context_sha256 = digest(self.context)
        self.names = {"nonce": plan.nonce}
        self.token = readers.caddy
        self.require_cleanup_armed()
        self.identifiers = authenticate(
            plan, intents, readers, expected_ids=setup.expected_ids, now=datetime.now(UTC)
        )
        require_public_admission(intents, now=datetime.now(UTC))
        self.context["credentials"] = {
            "ids": self.identifiers,
            "intents": {intent.role: intent.sha256 for intent in intents},
            "expires_at": intents[0].expires_at,
        }
        preparation.context(
            self.context,
            prepared,
            plan,
            intents={intent.role: intent.sha256 for intent in intents},
            ids=self.identifiers,
            expires_at=intents[0].expires_at,
        )
        self.context_sha256 = digest(self.context)
        write_private(directory / "isolation-context.json", self.context)
        self.observe("context", self.context)
        write_private(
            directory / "isolation-names.json",
            {
                "format": "lowerduckpond-isolated-public-ca-names-v1",
                "plan_sha256": plan.sha256,
                "nonce": plan.nonce,
            },
        )
        self.deadline = time.monotonic() + COORDINATOR_SECONDS
        self._identity()
        self.witness = IsolationWitness.open(directory, plan, readers)

    def _identity(self) -> None:
        if (
            self.plan.sha256 != self.plan_sha256
            or read_private(self.directory / "isolation-context.json") != self.context
        ):
            raise ValueError("isolated public context changed")
        current_candidate(ROOT, self.plan.source_revision)
        if (
            artifact_digest(Path(self.fixture.environment[ARTIFACT_ENV]))
            != self.plan.artifact_sha256
        ):
            raise ValueError("isolated installed artifact changed")
        actors = self.context["actors"]
        assert isinstance(actors, dict)
        for original in actors.values():
            assert isinstance(original, dict)
            actual = owned.inspect(self.fixture.environment, str(original["id"]))
            if actual.get("running") is not True or any(
                actual[key] != value for key, value in original.items()
            ):
                raise ValueError("isolated fixture/runtime identity changed")
        require_original(self.directory, self.context)
        if topology(self.fixture, actors, self.plan) != self.context["topology"]:
            raise ValueError("isolated network path changed")
        if hashlib.sha256(self.program.encode()).hexdigest() != self.context[
            "guest_program_sha256"
        ] or self.context["credentials"] != {
            "ids": self.identifiers,
            "intents": {intent.role: intent.sha256 for intent in self.intents},
            "expires_at": self.intents[0].expires_at,
        }:
            raise ValueError("isolated code or credential binding changed")
        owned.source_fenced(self.fixture.environment)

    def _stop_identity(self) -> None:
        # Cleanup must not depend on MinIO/peer/source remaining healthy or a
        # clean source checkout. The unchanged guest stop guard proves journal,
        # unit and context ownership before quiescing the exact public issuer.
        if read_private(self.directory / "isolation-context.json") != self.context:
            raise ValueError("isolated failure-stop context changed")
        daemon_identity(self.fixture, self.plan)
        actors = self.context["actors"]
        assert isinstance(actors, dict)
        original = actors["destination"]
        assert isinstance(original, dict)
        actual = owned.inspect(self.fixture.environment, str(original["id"]))
        if actual.get("running") is not True or any(
            actual[key] != value for key, value in original.items()
        ):
            raise ValueError("isolated failure-stop destination ownership changed")
        if (
            hashlib.sha256(self.program.encode()).hexdigest()
            != self.context["guest_program_sha256"]
        ):
            raise ValueError("isolated failure-stop program changed")

    def call(self, action: str, **arguments: object) -> dict[str, object]:
        if action not in {
            "install",
            "start",
            "ready",
            "suspend",
            "interrupt",
            "rebooted",
            "open_verified",
            "restore_native",
            "stop_failed",
        }:
            raise ValueError("isolated public action is outside the recovery sequence")
        if action != "stop_failed":
            self.require_cleanup_armed()
        else:
            self._stop_identity()
            return self._dispatch(action, **arguments)
        if action == "install" or (action == "start" and arguments.get("resume") is not True):
            require_public_admission(self.intents, now=datetime.now(UTC))
        if action == "install":
            value = arguments["value"]
            if not isinstance(value, dict):
                raise ValueError("isolated guest request is invalid")
            arguments["value"] = {**value, "isolation_network": self.plan.network.document()}
            # The base dispatcher adds context to non-install actions; this
            # separate install still receives its context inside its value.
            self._identity()
            self.require_cleanup_armed()
            require_public_admission(self.intents, now=datetime.now(UTC))
            raw = self.fixture.command(
                "docker",
                "exec",
                "--interactive",
                self.fixture.destination_id,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                self.program,
                stdin=policy.canonical(
                    {"failure_protocol": errors.FORMAT, "action": "install_isolated", **arguments}
                ),
                timeout=min(180, self._remaining()),
            )
            result = observation(
                raw,
                action="install_isolated",
                directory=self.directory,
                context_sha256=self.context_sha256,
            )
            self._remaining()
            return result
        return super().call(action, **arguments)

    def _dispatch(self, action: str, **arguments: object) -> dict[str, object]:
        if action == "start" and arguments.get("resume") is not True:
            self.require_cleanup_armed()
            require_public_admission(self.intents, now=datetime.now(UTC))
        return super()._dispatch(action, **arguments)

    def _run(self) -> tuple[dict[str, object], dict[str, object]]:
        value: dict[str, object] = {
            "context_sha256": self.context_sha256,
            "binary": self.fixture.binary,
            "binary_sha256": self.plan.caddy_binary_sha256,
            "nonce": self.plan.nonce,
            "files": {
                name: base64.b64encode(
                    read_private_bytes(path, maximum=policy.MAXIMUM_BYTES)
                ).decode("ascii")
                for name, path in self.original.items()
            },
            "token": self.token,
        }
        started = datetime.now(UTC)
        phase = {
            "context_sha256": self.context_sha256,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "deadline_at": (started + timedelta(seconds=max(0, self.deadline - time.monotonic())))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        write_private(self.directory / "isolation-phase-started.json", phase)
        self.observe("phase-started", phase)
        observations = exercise(self, value)
        result: dict[str, object] = {
            "format": RESULT_FORMAT,
            "qualification_authority": "none",
            "plan_sha256": self.plan_sha256,
            "context_sha256": self.context_sha256,
            "observations_sha256": digest(observations),
            "network": self.plan.network.document(),
            "functional_recovery": "passed",
            "cleanup": "pending-independent-closure",
        }
        write_private(self.directory / "isolation-observations.json", observations)
        write_private(self.directory / "isolation-functional.json", result)
        self.observe("functional", result)
        absence = self.witness.require_absent("teardown")
        cleanup = {
            "context_sha256": self.context_sha256,
            "basis": "observed-absent",
            "observation": read_private(absence.path),
            "observation_sha256": absence.sha256,
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        write_private(self.directory / "isolation-dns-clean.json", cleanup)
        self.observe("dns-clean", cleanup)
        return result, observations
