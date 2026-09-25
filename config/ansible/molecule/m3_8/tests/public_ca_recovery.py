"""Actual public-CA dependency proof on the owned reconstructed destination."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS
from restore_fixture import Fixture, checked
from restore_scenarios import gate_closed
from test_export_import import _selected_python

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_dns_witness import DnsWitness
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_public_inputs import require_original


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


class PublicRecovery:
    def __init__(self, fixture: Fixture, storage: LiveStorage, directory: Path) -> None:
        self.deadline = time.monotonic() + COORDINATOR_SECONDS
        self.fixture = fixture
        self.directory = directory
        self.context = read_private(directory / "combined-context.json")
        evidence.validate_names(directory / "combined-names.json", self.context)
        self.names = read_private(directory / "combined-names.json")
        self.original = require_original(directory, self.context)
        if fixture.live_storage is not storage or self.context["run_id"] != storage.target.run_id:
            raise ValueError("public recovery requires the original live fixture and storage")
        self.context_sha256 = _digest(self.context)
        self._identity()
        self.witness = DnsWitness.begin(directory, storage)
        self.token = storage.environment["CADDY_CLOUDFLARE_API_TOKEN"]
        # Execute the exact checked-out fixture helpers through the destination's
        # selected installed artifact. Credentials and captured roots use stdin;
        # neither command arguments nor controller diagnostics contain the token.
        script_root = Path(policy.__file__).parent
        self.program = _selected_python(
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
            + """
request = json.load(sys.stdin)
action = request.pop('action')
actions = {name: getattr(module, name) for name in (
    'install', 'start', 'ready', 'interrupt', 'rebooted', 'open_verified', 'restore_native',
    'stop_failed')}
print(json.dumps(actions[action](**request), sort_keys=True))
""",
        )

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
        if action != "install":
            arguments["context_sha256"] = self.context_sha256
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
            stdin=evidence.canonical_bytes({"action": action, **arguments}),
            # Failure handling stops issuance; it cannot resume or produce a
            # passing receipt after the original qualification deadline.
            timeout=30 if action == "stop_failed" else min(180, self._remaining()),
        )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("public recovery probe did not return an observation")
        if action != "stop_failed":
            self._remaining()
        return cast("dict[str, object]", result)

    def peer(self, *, opened: bool) -> None:
        self._identity()
        # The base firewall still requires a Cloudflare source even when the
        # restore gate opens. Use the existing fixture's reviewed probe address
        # on the owned peer, with no published origin port or policy change.
        peer_address = self.fixture.address(self.fixture.acme_id)
        for host, arguments in (
            (self.fixture.acme, "address replace 173.245.48.1/32 dev lo"),
            (self.fixture.destination, f"route replace 173.245.48.1/32 via {peer_address}"),
        ):
            result = host.run("/usr/sbin/ip " + arguments)
            assert result.rc == 0, result.stderr
        address = self.fixture.address(self.fixture.destination_id)
        checked(
            self.fixture.acme,
            f"""
import socket
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.settimeout(2)
connection.bind(('173.245.48.1', 0))
try:
    connection.connect(({address!r}, 443))
except OSError:
    assert not {opened!r}, 'verified public probe did not open ingress'
else:
    assert {opened!r}, 'public probe exposed ingress before verification'
finally:
    connection.close()
""",
        )
        self._remaining()

    def _wait(self) -> None:
        time.sleep(min(5, self._remaining()))

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
        original = self.call("install", value=value)
        self.installed = True
        self.call("start")
        gate_closed(self.fixture)
        self.peer(opened=False)
        observations = []
        while True:
            self._remaining()
            observation = self.witness.sample("activity")
            observations.append(observation.sha256)
            if observation.record_count:
                interrupted = self.call("interrupt")
                break
            if self.call("ready")["ready"]:
                raise ValueError("public issuance finished without an observed interruption")
            self._wait()
        gate_closed(self.fixture)
        self.fixture.reboot()
        reboot = self.call("rebooted")
        gate_closed(self.fixture)
        self.peer(opened=False)
        self.call("start", resume=True)
        while True:
            self._remaining()
            observations.append(self.witness.sample("activity").sha256)
            result = self.call("ready")
            if result["ready"]:
                tls = evidence.fields(result["tls"], {"issuer", "certificates"})
                break
            self._wait()
        self.witness.require_both_zones_observed()
        cleanup = self.witness.require_absent("cleanup")
        self.peer(opened=False)
        opened = self.call("open_verified", expected=tls)
        self.peer(opened=True)
        restored = self.call(
            "restore_native", audit_rotation=self.fixture.target["auditRotationEnabled"]
        )
        self._identity()
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
            "original": original,
            "interrupted": interrupted,
            "rebooted": reboot,
            "tls": tls,
            "opened": opened,
            "restored": restored,
            "dns_activity_sha256": observations,
            "dns_cleanup_sha256": cleanup.sha256,
            "public_ca": public_ca,
        }
        write_private(self.directory / "public-ca.json", details)
        return public_ca, details
