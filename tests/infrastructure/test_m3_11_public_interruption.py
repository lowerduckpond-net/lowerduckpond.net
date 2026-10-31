"""Offline interruption protocol over the real private Unix HTTP transport.

The issuer is a configuration-driven synthetic model, not Caddy or a CA. Its
virtual clock makes the fast-issuer counterexample reproducible without sleeps.
Systemd, boot identity, restore admission, TLS and provider responses are test
boundaries; probe activation/suspension, private file I/O, stopped inventory,
reboot checks, DNS witness accounting and the shared transition sequence execute
their actual implementations. No daemon, public network or real credential is
available to these tests.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

from scripts import m3_11_dns_witness as dns
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts import m3_11_public_sequence as sequence
from scripts.check_m3_7_production_edge import CloudflareClient
from scripts.m3_11_private_inputs import write_private

from .test_m3_11_public_control import control as control  # noqa: PLC0414 - fixture export

NONCE = "0198d17f-6f4a-7000-8000-000000000001"
CONTEXT = "a" * 64
BINARY = "/usr/local/lib/lowerduckpond/caddy-2.11.4-xcaddy-0.4.7-cloudflare-0.2.4"
ZONES = ("lowerduckpond.net", "lowerduckpond.com")
PRIVATE = "synthetic-private-admin-value-never-a-real-credential"


def _dns(configuration: bytes) -> dict[str, Any]:
    value = json.loads(configuration)
    return cast(
        "dict[str, Any]",
        value["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"],
    )


@dataclass
class Issuer:
    control: dict[str, object]
    inputs: Path
    storage: Path
    events: list[str] = field(default_factory=list)
    running: bool = False
    boot: int = 1
    completed: bool = False
    elapsed: int = 0
    validation_requests: int = 0
    boot_configuration: bytes | None = None
    active_zones: set[str] = field(default_factory=set)
    tls_reads: int = 0
    tls_failure: bool = False

    def systemctl(self, *arguments: str) -> bytes:
        if arguments == ("start", policy.UNIT):
            assert not self.running
            self.events.append("boot:inert")
            self.running = True
            self.elapsed = 0
            self.control["config"] = json.loads(
                self.boot_configuration or (self.inputs / "bootstrap.json").read_bytes()
            )
        elif arguments == ("stop", policy.UNIT):
            self.events.append("stop")
            self.running = False
        else:
            raise AssertionError("synthetic systemd received an unexpected operation")
        return b""

    def advance(self, seconds: int, *, zones: tuple[str, ...] = ZONES) -> None:
        """Model only the pinned source's configuration contract, not Go execution."""
        configuration = cast("dict[str, Any]", self.control["config"])
        if not self.running or self.completed or "apps" not in configuration:
            return
        self.elapsed += seconds
        self.active_zones.update(zones)
        account = self.storage / "acme" / "synthetic-account.key"
        account.parent.mkdir(mode=0o700, exist_ok=True)
        if not account.exists():
            account.write_bytes(b"synthetic-account-key")
            account.chmod(0o600)
        delay = _dns(policy.canonical(configuration)).get("propagation_delay", "0s")
        if self.elapsed >= int(str(delay).removesuffix("s")):
            self.validation_requests += 1
            self.completed = True
            # The synthetic normal issuer finishes and removes its TXT records
            # before a slow observer can see any of them.
            self.active_zones.clear()

    def tls(self, marker: dict[str, object]) -> dict[str, object]:
        assert marker["nonce"] == NONCE
        self.tls_reads += 1
        if self.tls_failure:
            raise HostRestoreError("restore_tls_key_mismatch")
        if not self.completed:
            raise FileNotFoundError
        return {"issuer": policy.ISSUER, "certificates": ["synthetic-public-TLS-proof"]}

    def inactive(self, unit: str) -> None:
        assert unit == policy.UNIT and not self.running


@pytest.fixture
def issuer(control: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Issuer:
    inputs = tmp_path / "inputs"
    inputs.mkdir(mode=0o700)
    monkeypatch.setattr(policy, "INPUTS", inputs)
    value = Issuer(control, inputs, policy.STORAGE)
    marker: dict[str, object] = {"nonce": NONCE, "context_sha256": CONTEXT}
    for name, raw in {
        "bootstrap.json": policy.suspended_configuration(),
        "interruption.json": policy.interruption_configuration(NONCE),
        "caddy.json": policy.configuration(NONCE),
    }.items():
        (inputs / name).write_bytes(raw)
        (inputs / name).chmod(0o440)

    original_read = probe._read

    def read(path: Path, *, owner: int | None = None, maximum: int = policy.MAXIMUM_BYTES) -> bytes:
        assert path.is_relative_to(inputs) or path.is_relative_to(value.storage)
        return original_read(path, owner=os.getuid() if owner is None else owner, maximum=maximum)

    def write(path: Path, raw: bytes, *, mode: int = 0o400, group: int = 0) -> None:
        # Ownership is the sole substituted part of private record publication:
        # unprivileged tests keep the actual exclusive create/fsync/read path.
        assert path.is_relative_to(inputs) and group == 0
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def guard(context: str) -> dict[str, object]:
        assert context == CONTEXT
        return marker

    def fixture_path(path: str | os.PathLike[str]) -> Path:
        if str(path) == "/proc/1/stat":
            return cast("Path", Mock(read_text=lambda: " ".join(["0"] * 21 + [str(value.boot)])))
        return Path(path)

    monkeypatch.setattr(probe, "_read", read)
    monkeypatch.setattr(probe, "_write", write)
    monkeypatch.setattr(probe, "_guard", guard)
    monkeypatch.setattr(probe, "_closed", lambda: value.events.append("gate:closed"))
    monkeypatch.setattr(probe, "_systemctl", value.systemctl)
    monkeypatch.setattr(probe, "_inactive", value.inactive)
    monkeypatch.setattr(probe, "_tls", value.tls)
    monkeypatch.setattr(probe, "Path", fixture_path)
    monkeypatch.setattr(
        socket,
        "create_connection",
        Mock(side_effect=AssertionError("public-network transport is unavailable in this test")),
    )
    return value


@pytest.mark.parametrize(
    "network",
    [
        None,
        {"mode": "authoritative", "resolvers": []},
        {"mode": "recursive-precheck", "resolvers": ["192.0.2.53"]},
    ],
)
def test_hold_changes_only_delay_and_boot_is_inert(network: object) -> None:
    normal = (
        policy.configuration(NONCE)
        if network is None
        else policy.isolation_configuration(NONCE, network)
    )
    held = json.loads(policy.interruption_configuration(NONCE, network))
    selected = held["apps"]["tls"]["automation"]["policies"][0]
    assert selected["subjects"] == list(policy.disposable_subjects(NONCE))
    assert len(selected["subjects"]) == 4  # noqa: PLR2004 - apex and wildcard in both zones
    acme = selected["issuers"][0]
    assert acme["ca"] == acme["test_ca"] == policy.ISSUER
    assert acme["challenges"]["dns"].pop("propagation_delay") == f"{COORDINATOR_SECONDS}s"
    assert policy.canonical(held) == normal
    assert "apps" not in json.loads(policy.suspended_configuration())
    assert f"run --config {policy.INPUTS}/bootstrap.json" in policy.service(BINARY).decode()
    assert f"run --config {policy.INPUTS}/caddy.json" not in policy.service(BINARY).decode()


def test_without_hold_fast_issuer_completes_before_first_observation(
    issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Remove only the configured hold to reproduce the original timing race.
    # All actual probe methods and Unix requests still execute.
    monkeypatch.setattr(
        policy,
        "interruption_configuration",
        lambda nonce, network=None: policy.configuration(nonce),
    )
    selected = issuer.inputs / "interruption.json"
    selected.chmod(0o600)
    selected.write_bytes(policy.configuration(NONCE))
    selected.chmod(0o440)
    probe.start(CONTEXT)
    issuer.advance(1)
    assert probe.ready(CONTEXT)["ready"] is True
    assert issuer.validation_requests == 1 and not issuer.active_zones
    before = list(cast("list[tuple[str, str]]", issuer.control["calls"]))
    with pytest.raises(ValueError, match="already completed"):
        probe.suspend(CONTEXT)
    assert issuer.control["calls"] == before
    assert not (issuer.inputs / "interrupted.json").exists()


def test_initial_hold_survives_delayed_observer_and_resume_uses_normal_issuer(
    issuer: Issuer,
) -> None:
    assert probe.start(CONTEXT) == {"started": True}
    assert issuer.control["calls"] == [("GET", "/config/"), ("POST", "/load"), ("GET", "/config/")]
    assert issuer.control["config"] == json.loads(policy.interruption_configuration(NONCE))
    issuer.advance(COORDINATOR_SECONDS - 1)
    assert probe.ready(CONTEXT) == {"ready": False}
    assert issuer.validation_requests == 0 and issuer.active_zones == set(ZONES)
    assert probe.suspend(CONTEXT) == {"issuance_suspended": True}
    assert issuer.control["config"] == json.loads(policy.suspended_configuration())
    # Control acknowledgement deliberately leaves the provider model unchanged.
    assert issuer.active_zones == set(ZONES)
    assert not (issuer.inputs / "interrupted.json").exists()
    issuer.active_zones.clear()  # Synthetic provider completion, checked by drain below.
    interrupted = probe.interrupt(CONTEXT)
    assert set(cast("dict[str, Any]", interrupted["value"])["storage"]) == {
        "acme/synthetic-account.key"
    }
    issuer.boot += 1
    probe.rebooted(CONTEXT)
    before = list(cast("list[tuple[str, str]]", issuer.control["calls"]))
    assert probe.start(CONTEXT, resume=True) == {"started": True}
    assert issuer.control["calls"] == [
        *before,
        ("GET", "/config/"),
        ("POST", "/load"),
        ("GET", "/config/"),
    ]
    assert issuer.control["config"] == json.loads(policy.configuration(NONCE))
    issuer.advance(1)
    assert probe.ready(CONTEXT)["ready"] is True
    assert issuer.validation_requests == 1


@pytest.mark.parametrize("name", ["bootstrap.json", "interruption.json", "caddy.json"])
def test_tampered_selected_inputs_fail_before_boot_or_activation(issuer: Issuer, name: str) -> None:
    resume = name == "caddy.json"
    if resume:
        probe._record("rebooted", {"storage": probe._inventory()})
    selected = issuer.inputs / name
    selected.chmod(0o600)
    selected.write_bytes(policy.canonical({"untrusted": PRIVATE}))
    selected.chmod(0o440)
    with pytest.raises(ValueError, match="interruption barrier changed") as caught:
        probe.start(CONTEXT, resume=resume)
    assert PRIVATE not in str(caught.value)
    assert issuer.control["calls"] == []
    assert not issuer.running and issuer.validation_requests == 0


def test_unexpected_boot_apps_fail_before_activation_post(issuer: Issuer) -> None:
    issuer.boot_configuration = policy.canonical({"apps": {"untrusted": PRIVATE}})
    with pytest.raises(ValueError, match="still has active issuance") as caught:
        probe.start(CONTEXT)
    assert PRIVATE not in str(caught.value)
    assert issuer.control["calls"] == [("GET", "/config/")]
    assert issuer.validation_requests == 0


def test_activation_acknowledgement_without_exact_readback_is_not_started(issuer: Issuer) -> None:
    issuer.control["ignore_load"] = True
    with pytest.raises(ValueError, match="configuration was not confirmed"):
        probe.start(CONTEXT)
    assert issuer.control["calls"] == [("GET", "/config/"), ("POST", "/load"), ("GET", "/config/")]
    assert issuer.control["config"] == json.loads(policy.suspended_configuration())
    issuer.advance(COORDINATOR_SECONDS - 1)
    assert issuer.validation_requests == 0 and not issuer.completed


def test_suspension_requires_exact_live_hold_before_cancellation(
    issuer: Issuer,
) -> None:
    probe.start(CONTEXT)
    issuer.control["config"] = {"apps": {"untrusted": PRIVATE}}
    before = list(cast("list[tuple[str, str]]", issuer.control["calls"]))
    with pytest.raises(ValueError, match="configuration was not confirmed") as caught:
        probe.suspend(CONTEXT)
    assert PRIVATE not in str(caught.value)
    assert issuer.control["calls"] == [*before, ("GET", "/config/")]
    assert issuer.tls_reads == 1 and not (issuer.inputs / "interrupted.json").exists()


@pytest.mark.parametrize("suffix", ["crt", "key", "json"])
def test_partial_certificate_material_cannot_be_interruption_evidence(
    issuer: Issuer, suffix: str
) -> None:
    probe.start(CONTEXT)
    issuer.advance(1)
    probe.suspend(CONTEXT)
    certificate = issuer.storage / "certificates" / "synthetic" / ("site." + suffix)
    certificate.parent.mkdir(mode=0o700, parents=True)
    certificate.write_bytes(b"synthetic-partial-certificate-material")
    certificate.chmod(0o600)
    with pytest.raises(ValueError, match="already has certificate material"):
        probe.interrupt(CONTEXT)
    assert not issuer.running
    assert not (issuer.inputs / "interrupted.json").exists()


@dataclass
class Recovery:
    issuer: Issuer
    witness: dns.DnsWitness
    native_drain: Callable[[object], dict[str, object]]
    failure: str | None = None
    installed: bool = False
    audit_rotation: bool = False
    opened: bool = False
    interrupted: bool = False
    reboot_verified: bool = False
    sample_count: int = 0
    cancel_samples: int = 0

    def records(self, path: str, *, query: dict[str, str]) -> list[dict[str, str]]:
        zone = ZONES[0] if path == "/zones/" + "1" * 32 + "/dns_records" else ZONES[1]
        assert path in {"/zones/" + digit * 32 + "/dns_records" for digit in ("1", "2")}
        if zone == ZONES[0]:
            self.sample_count += 1
            if "apps" in cast("dict[str, object]", self.issuer.control["config"]):
                self.issuer.advance(1, zones=ZONES[:1] if self.sample_count == 1 else ZONES)
            else:
                self.cancel_samples += 1
                if self.cancel_samples >= 2:  # noqa: PLR2004 - first post-cancel read remains active
                    self.issuer.active_zones.clear()
            self.issuer.events.append("dns:" + str(self.sample_count))
        return (
            []
            if zone not in self.issuer.active_zones
            else [{"id": "c" * 32, "name": query["name"], "type": "TXT", "content": "x" * 43}]
        )

    def call(self, action: str, **arguments: object) -> dict[str, object]:  # noqa: PLR0911 - closed synthetic boundary dispatcher
        self.issuer.events.append("call:" + action)
        if self.failure == action:
            raise ValueError("synthetic transition failure")
        if action == "install":
            return {"installed": "synthetic-restored-fixture-boundary"}
        if action == "start":
            return probe.start(CONTEXT, resume=arguments.get("resume") is True)
        if action == "suspend":
            return probe.suspend(CONTEXT)
        if action == "interrupt":
            assert self.cancel_samples >= 3 and not self.issuer.active_zones  # noqa: PLR2004 - active read, empty read, final absence proof
            assert self.witness.both_zones_observed
            result = probe.interrupt(CONTEXT)
            self.interrupted = True
            return result
        if action == "rebooted":
            result = probe.rebooted(CONTEXT)
            self.reboot_verified = True
            return result
        if action == "ready":
            if self.reboot_verified:
                if self.failure == "normal-ready":
                    self.issuer.tls_failure = True
                self.issuer.advance(1)
            return probe.ready(CONTEXT)
        if action == "open_verified":
            assert self.interrupted and self.reboot_verified and self.issuer.completed
            assert self.issuer.control["config"] == json.loads(policy.configuration(NONCE))
            assert arguments["expected"] == self.issuer.tls({"nonce": NONCE})
            self.opened = True
            return {"opened": True}
        assert action == "restore_native" and self.opened
        return {"restored": True}

    def peer(self, *, opened: bool) -> None:
        assert opened == self.opened

    def gate_closed(self) -> None:
        assert not self.opened

    def reboot(self) -> None:
        self.issuer.events.append("reboot")
        assert self.interrupted and not self.issuer.running
        if self.failure == "reboot":
            raise ValueError("synthetic reboot failed")
        self.issuer.boot += 1

    def drain_issuance(self, *, diagnostic: bool = False) -> dict[str, object]:
        assert not diagnostic and self.sample_count == len(ZONES)
        return self.native_drain(self)

    def _remaining(self) -> int:
        assert self.sample_count < 20  # noqa: PLR2004 - broken transitions cannot spin indefinitely
        return COORDINATOR_SECONDS - self.sample_count

    def _wait(self) -> None:
        self.issuer.events.append("wait")

    def _identity(self) -> None:
        assert self.opened


@pytest.fixture
def recovery(
    issuer: Issuer, tmp_path: Path, installed_module: Callable[[str], ModuleType]
) -> Recovery:
    # The actual native witness parses, validates and writes these synthetic
    # provider responses. Only get_collection is replaced; it has no live client.
    directory = tmp_path / "witness"
    directory.mkdir(mode=0o700)
    context: dict[str, object] = {"synthetic": "context"}
    names: dict[str, object] = {"synthetic": "names"}
    write_private(directory / "combined-context.json", context)
    write_private(directory / "combined-names.json", names)
    client = Mock(spec=CloudflareClient)
    witness = dns.DnsWitness(
        directory,
        client,
        dns._digest(context),
        dns._digest(names),
        tuple(
            (zone, digit * 32, "_acme-challenge.synthetic." + zone)
            for zone, digit in zip(ZONES, ("1", "2"), strict=True)
        ),
    )
    witness.output_directory = directory / "observations"
    witness.output_directory.mkdir(mode=0o700)
    module = installed_module("public_ca_recovery")
    value = Recovery(
        issuer,
        witness,
        cast("Callable[[object], dict[str, object]]", module.PublicRecovery.drain_issuance),
    )
    client.get_collection.side_effect = value.records
    return value


def test_shared_sequence_waits_for_both_zones_and_actual_cleanup_before_reboot(
    recovery: Recovery,
) -> None:
    result = sequence.exercise(recovery, {})
    assert recovery.installed and recovery.opened
    events = recovery.issuer.events
    assert events.index("dns:1") < events.index("wait") < events.index("dns:2")
    assert events.index("dns:2") < events.index("call:suspend") < events.index("dns:3")
    assert events.index("dns:5") < events.index("call:interrupt") < events.index("reboot")
    assert events.index("call:rebooted") < events.index("call:open_verified")
    assert recovery.issuer.validation_requests == 1  # Only the normal resumed leg.
    assert recovery.witness.both_zones_observed
    first = json.loads((cast("Path", recovery.witness.output_directory) / "0000.json").read_bytes())
    assert first["zones"][ZONES[0]]["records"] and not first["zones"][ZONES[1]]["records"]
    assert len(cast("dict[str, Any]", result["interruption_cleanup"])["activity_sha256"]) == 2  # noqa: PLR2004 - active then empty provider observation


@pytest.mark.parametrize("failure", ["interrupt", "reboot", "normal-ready"])
def test_failed_sequence_never_opens_ingress(recovery: Recovery, failure: str) -> None:
    recovery.failure = failure
    with pytest.raises((ValueError, HostRestoreError)):
        sequence.exercise(recovery, {})
    assert not recovery.opened
    assert "call:open_verified" not in recovery.issuer.events
    assert "call:restore_native" not in recovery.issuer.events


def test_control_failures_do_not_emit_private_admin_values(
    issuer: Issuer, capsys: pytest.CaptureFixture[str]
) -> None:
    issuer.boot_configuration = policy.canonical({"apps": {"untrusted": PRIVATE}})
    with pytest.raises(ValueError) as caught:
        probe.start(CONTEXT)
    assert PRIVATE not in str(caught.value)
    output = capsys.readouterr()
    assert output.out == output.err == ""
