"""Actual public-CA dependency proof on the owned reconstructed destination."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from pathlib import Path
from typing import cast

import restore_peer
from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS
from restore_fixture import Fixture
from restore_scenarios import gate_closed
from test_export_import import _selected_python

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_dns_witness import POLL_INTERVAL_SECONDS, DnsWitness
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_public_inputs import require_original
from scripts.m3_11_public_sequence import exercise


def _digest(value: object) -> str:
    return hashlib.sha256(evidence.canonical_bytes(value)).hexdigest()


def run(
    fixture: Fixture, storage: LiveStorage, directory: Path, recorder: Recorder
) -> tuple[PublicRecovery, dict[str, object]]:
    """Append phase five only after its actual public assertions complete."""
    with recorder.phase("public-ca-cold-recovery") as observations:
        recovery = PublicRecovery(fixture, storage, directory)
        public_ca, details = recovery.run()
        observations.update(details)
    # The live controller retains the same read-only DNS witness for the fresh
    # teardown absence check; it cannot initialize a replacement baseline.
    return recovery, public_ca


def program(fixture: Fixture, *, diagnostic: bool = False, isolated: bool = False) -> str:
    """Assemble exact selected helpers; credentials remain in private stdin."""
    script_root = Path(policy.__file__).parent
    return _selected_python(
        fixture.destination,
        """
import json, sys, types
package = types.ModuleType('scripts')
package.__path__ = []
sys.modules['scripts'] = package
"""
        + "\n".join(
            f"module = types.ModuleType({name!r})\n"
            f"sys.modules[{name!r}] = module\n"
            f"exec(compile({(script_root / filename).read_bytes()!r}, "
            f"{filename!r}, 'exec'), module.__dict__)\n"
            for name, filename in (
                ("scripts.m3_11_public_caddy", "m3_11_public_caddy.py"),
                ("scripts.m3_11_public_probe", "m3_11_public_probe.py"),
            )
        )
        + (
            "helper = types.ModuleType('scripts.m3_11_debug_dns_probe')\n"
            "sys.modules[helper.__name__] = helper\n"
            f"exec(compile({(script_root / 'm3_11_debug_dns_probe.py').read_bytes()!r}, "
            "'m3_11_debug_dns_probe.py', 'exec'), helper.__dict__)\n"
            f"exec(compile({(script_root / 'm3_11_debug_public.py').read_bytes()!r}, "
            "'m3_11_debug_public.py', 'exec'), module.__dict__)\n"
            if diagnostic
            else ""
        )
        + """
request = json.load(sys.stdin)
action = request.pop('action')
actions = {name: getattr(module, name) for name in (
    'install', 'start', 'ready', 'suspend', 'interrupt', 'rebooted',
    'open_verified', 'restore_native',
    'stop_failed', 'diagnostic_prepare', 'diagnostic_start', 'diagnostic_interrupt',
    'diagnostic_open', 'diagnostic_finish', 'diagnostic_retire_dns',
    'diagnostic_stop_failed', 'diagnostic_suspend') if hasattr(module, name)}
"""
        + (
            "actions.update(install_isolated=module.install_isolated, "
            "observe_prepared=module.observe_prepared)\n"
            if isolated
            else ""
        )
        + "print(json.dumps(actions[action](**request), sort_keys=True))\n",
    )


class PublicRecovery:
    def __init__(
        self, fixture: Fixture, storage: LiveStorage, directory: Path, *, diagnostic: bool = False
    ) -> None:
        self.deadline = time.monotonic() + COORDINATOR_SECONDS
        self.fixture = fixture
        self.directory = directory
        self.context = read_private(directory / "combined-context.json")
        evidence.validate_names(directory / "combined-names.json", self.context)
        self.names = read_private(directory / "combined-names.json")
        self.original = (
            require_original(directory, self.context, diagnostic=True)
            if diagnostic
            else require_original(directory, self.context)
        )
        if fixture.live_storage is not storage or self.context["run_id"] != storage.target.run_id:
            raise ValueError("public recovery requires the original live fixture and storage")
        self.context_sha256 = _digest(self.context)
        self._identity()
        self.witness = (
            DnsWitness.begin(directory, storage, diagnostic=True)
            if diagnostic
            else DnsWitness.begin(directory, storage)
        )
        self.token = storage.environment["CADDY_CLOUDFLARE_API_TOKEN"]
        # Execute the exact checked-out fixture helpers through the destination's
        # selected installed artifact. Credentials and captured roots use stdin;
        # neither command arguments nor controller diagnostics contain the token.
        self.program = program(fixture, diagnostic=diagnostic)

    def _remaining(self) -> int:
        remaining = math.floor(self.deadline - time.monotonic())
        if remaining < 1:
            raise TimeoutError("public recovery exceeded its original coordinator deadline")
        return remaining

    def _identity(self) -> None:
        for identity, key in (
            (self.fixture.source_id, "source_fixture_sha256"),
            (self.fixture.destination_id, "destination_fixture_sha256"),
        ):
            actual = owned.inspect(self.fixture.environment, identity)
            if (
                actual.get("running") is not True
                or _digest({field: actual[field] for field in ("id", "name", "owner", "image")})
                != self.context[key]
            ):
                raise ValueError("public recovery fixture differs from its original capture")
        if _digest(read_private(self.directory / "combined-context.json")) != self.context_sha256:
            raise ValueError("public recovery original context changed")
        owned.source_fenced(self.fixture.environment)

    def call(self, action: str, **arguments: object) -> dict[str, object]:
        self._identity()
        return self._dispatch(action, **arguments)

    def _dispatch(self, action: str, **arguments: object) -> dict[str, object]:
        if action not in {"install", "diagnostic_prepare"}:
            arguments["context_sha256"] = self.context_sha256
        raw = self.fixture.command(
            "docker",
            "exec",
            "--interactive",
            self.fixture.destination_id,
            *(
                ("/usr/bin/unshare", "--mount", "--propagation", "private", "--")
                if action == "diagnostic_retire_dns"
                else ()
            ),
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            self.program,
            stdin=evidence.canonical_bytes({"action": action, **arguments}),
            # Failure handling stops issuance; it cannot resume or produce a
            # passing receipt after the original qualification deadline.
            timeout=30
            if action in {"stop_failed", "diagnostic_stop_failed"}
            else min(180, self._remaining()),
        )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("public recovery probe did not return an observation")
        if action not in {"stop_failed", "diagnostic_stop_failed"}:
            self._remaining()
        return cast("dict[str, object]", result)

    def peer(self, *, opened: bool) -> None:
        self._identity()
        restore_peer.check(self.fixture, opened=opened)
        self._remaining()

    def _wait(self) -> None:
        time.sleep(min(POLL_INTERVAL_SECONDS, self._remaining()))

    def drain_issuance(self, *, diagnostic: bool = False) -> dict[str, object]:
        self.call("diagnostic_suspend" if diagnostic else "suspend")
        observations = []
        while True:
            self._remaining()
            observation = self.witness.sample("activity")
            observations.append(observation.sha256)
            if not observation.record_count:
                break
            self._wait()
        absence = self.witness.require_absent("cleanup")
        return {"activity_sha256": observations, "absence_sha256": absence.sha256}

    def run(self) -> tuple[dict[str, object], dict[str, object]]:
        self.installed = False
        try:
            return self._run()
        except BaseException as failure:
            if self.installed:
                try:
                    self.call("stop_failed")
                except Exception as error:
                    failure.add_note(
                        "Public issuer failure handling failed: " + type(error).__name__
                    )
                    try:
                        write_private(
                            self.directory / "public-ca-stop-failed.json",
                            {
                                "context_sha256": self.context_sha256,
                                "error_type": type(error).__name__,
                            },
                        )
                    except Exception as recording:
                        failure.add_note(
                            "Public failure observation could not be written: "
                            + type(recording).__name__
                        )
            raise

    @property
    def audit_rotation(self) -> bool:
        return cast("bool", self.fixture.target["auditRotationEnabled"])

    def gate_closed(self) -> None:
        gate_closed(self.fixture)

    def reboot(self) -> None:
        self.fixture.reboot()

    def _run(self) -> tuple[dict[str, object], dict[str, object]]:
        value = {
            "context_sha256": self.context_sha256,
            "binary": self.fixture.binary,
            "binary_sha256": self.context["caddy_binary_sha256"],
            "nonce": self.names["nonce"],
            "files": {
                name: base64.b64encode(
                    read_private_bytes(path, maximum=policy.MAXIMUM_BYTES)
                ).decode("ascii")
                for name, path in self.original.items()
            },
            "token": self.token,
        }
        observations = exercise(self, value)
        tls = observations["tls"]
        public_ca = {
            "issuer": policy.ISSUER,
            "trust": "system-public-roots",
            "subject_count": len(policy.disposable_subjects(str(self.names["nonce"]))),
            "zone_count": 2,
            "certificates_sha256": _digest(tls),
        }
        details: dict[str, object] = {
            "context_sha256": self.context_sha256,
            "original_public_inputs_sha256": hashlib.sha256(
                read_private_bytes(self.directory / "public-inputs" / "original.json")
            ).hexdigest(),
            **observations,
            "public_ca": public_ca,
        }
        write_private(self.directory / "public-ca.json", details)
        return public_ca, details
