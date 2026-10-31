"""Real guest subprocess through native command, terminal failure and cleanup.

Docker exec is a local Python forwarder, providers/actor metadata are synthetic,
and guest bootstrap/disk/TLS inputs are substituted. No daemon, DNS provider or
CA is contacted. The command wrappers, private Unix HTTP error, guest suspension,
decoder, recovery/terminal handling, journal and lease cleanup are real code.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import traceback
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_isolation_controller as controller
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_errors as errors
from scripts.check_m3_7_production_edge import CloudflareClient
from scripts.m3_11_isolation_contract import CONTEXT_FORMAT
from scripts.m3_11_isolation_dns import IsolationWitness
from scripts.m3_11_isolation_host import Host
from scripts.m3_11_isolation_journal import Journal
from scripts.m3_11_isolation_lease import Lease, Provider
from scripts.m3_11_isolation_seal import functional
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.model import digest
from scripts.qualification_context import ARTIFACT_ENV, resource_names

from .test_m3_11_isolation_integration import graph as graph  # noqa: PLC0414 - fixture export
from .test_m3_11_isolation_integration import manifest as manifest  # noqa: PLC0414
from .test_m3_11_isolation_integration import (
    no_live_transports as no_live_transports,  # noqa: PLC0414
)
from .test_m3_11_isolation_integration import (
    prepared as original_prepared,  # noqa: F401 - pytest dependency
)
from .test_m3_11_public_control import control as control  # noqa: PLC0414
from .test_m3_11_public_isolation import NOW, SECRET, START, FakeProvider
from .test_m3_11_public_isolation import intents as intents  # noqa: PLC0414
from .test_m3_11_public_isolation import plan as plan  # noqa: PLC0414

PRIVATE = "synthetic-exception-payload-never-a-credential"


@dataclass(frozen=True)
class Guest:
    program: str
    started: Path
    stopped: Path


@pytest.fixture
def guest(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    control: dict[str, object],
    tmp_path: Path,
) -> Guest:
    module = installed_module("public_ca_recovery")
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    control["status"] = 500
    started, stopped = tmp_path / "guest-started", tmp_path / "guest-stopped"
    patch = f"""
module.policy.STORAGE = module.Path({str(policy.STORAGE)!r})
module.pwd.getpwnam = lambda name: types.SimpleNamespace(pw_uid=module.os.geteuid())
module._guard = lambda context: {{'nonce': '0198d17f-6f4a-7000-8000-000000000001'}}
module._closed = lambda: None
module._document = lambda name: {{}}
module._record = lambda name, value: value
module._read = lambda path: module.policy.configuration('0198d17f-6f4a-7000-8000-000000000001')
def missing_tls(marker):
    raise FileNotFoundError()
module._tls = missing_tls
original_admin = module._admin
def private_admin(*args, **kwargs):
    try:
        return original_admin(*args, **kwargs)
    except ValueError as error:
        error.add_note({PRIVATE!r})
        raise error from OSError({PRIVATE!r})
module._admin = private_admin
def start(**kwargs):
    module.Path({str(started)!r}).touch()
    return {{'started': True}}
def stop_failed(**kwargs):
    module.Path({str(stopped)!r}).touch()
    raise OSError({PRIVATE!r})
actions['install_isolated'] = lambda **kwargs: {{'installed': True}}
actions['start'] = start
actions['stop_failed'] = stop_failed
sys.stderr.write({PRIVATE!r})
"""
    program = module.program(Mock(), isolated=True).replace(
        "action = None\n", patch + "action = None\n"
    )
    return Guest(program, started, stopped)


@pytest.fixture
def prepared(original_prepared: dict[str, Any], guest: Guest) -> dict[str, Any]:  # noqa: F811 - pytest dependency
    value = deepcopy(original_prepared)
    value["guest_program_sha256"] = hashlib.sha256(guest.program.encode()).hexdigest()
    return value


def test_real_fixture_subprocess_failure_survives_terminal_and_native_cleanup(  # noqa: PLR0915
    graph: tuple[Host, Journal, Mock],
    guest: Guest,
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    host, journal, _ = graph
    assert SECRET not in guest.program  # Synthetic child credentials travel only in stdin.
    prepared_graph = cast("dict[str, Any]", host.prepared)
    write_private(host.root / "manifest.json", host.manifest.document())
    adapter = installed_module("isolated_public_ca_recovery")
    native_recovery = adapter.IsolatedRecovery
    fixture = object.__new__(adapter.Fixture)
    fixture.destination_id = prepared_graph["actors"]["destination"]["id"]
    fixture.binary, fixture.target, fixture.reboot = (
        "synthetic-caddy",
        {"auditRotationEnabled": False},
        Mock(),
    )
    # Forward only the exact Docker exec shape to a real isolated Python child.
    # Fixture.command, ownership locks, qualification_restore.command and
    # bounded_command are neither replaced nor mocked.
    transport = host.root / "transport"
    transport.mkdir(mode=0o700)
    forwarder = transport / "docker"
    forwarder.write_text(f"""#!{sys.executable}
import os,sys
assert sys.argv[1:4] == ['exec','--interactive',{fixture.destination_id!r}]
assert sys.argv[4:8] == ['/usr/bin/python3','-I','-B','-c']
os.execv(sys.executable,[sys.executable,*sys.argv[5:]])
""")
    forwarder.chmod(0o700)
    monkeypatch.setenv("PATH", str(transport) + os.pathsep + os.environ["PATH"])
    fixture.environment = {
        **resource_names(host.manifest.plan.run_id.replace("-", "")),
        ARTIFACT_ENV: str(host.phase / "fixture/static-host-agent.tar"),
        "PATH": os.environ["PATH"],
    }
    # Reproduce the original information-loss boundary first: a real nonzero
    # guest command becomes the generic native error while stderr is discarded.
    with pytest.raises(ValueError, match="owned reconstruction fixture command failed"):
        fixture.command(
            "docker",
            "exec",
            "--interactive",
            fixture.destination_id,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            guest.program,
            stdin=json.dumps({"action": "suspend", "context_sha256": "a" * 64}).encode(),
            timeout=10,
        )
    monkeypatch.setattr(controller, "datetime", Mock(now=lambda zone: NOW))
    monkeypatch.setattr(adapter, "datetime", Mock(now=lambda zone: NOW))
    monkeypatch.setattr(controller, "require_armed", lambda selected: selected.require())
    monkeypatch.setattr(controller, "installed_adapter", lambda: adapter)
    confirmation = next(
        row["payload"] for row in journal.all_records() if row["kind"] == "confirmed"
    )
    monkeypatch.setattr(
        controller,
        "capture",
        Mock(return_value=Mock(receipt={"github": confirmation}, provenance={"run_id": 1})),
    )
    provider = FakeProvider(host.manifest.plan)
    provider.authority_sha256 = "e" * 64
    access = Mock()
    access.client.return_value, access.provider.return_value = journal.client, provider

    def records(client: object, path: str, *, query: dict[str, str]) -> list[dict[str, str]]:
        if not guest.started.exists() or guest.stopped.exists():
            return []
        return [
            {
                "id": hashlib.sha256(query["name"].encode()).hexdigest()[:32],
                "name": query["name"],
                "type": "TXT",
                "content": "x" * 43,
            }
        ]

    monkeypatch.setattr(CloudflareClient, "get_collection", records)

    def recovery(selected: object, directory: Path, setup: object) -> object:
        details = cast(Any, setup)
        value = object.__new__(native_recovery)
        value.fixture, value.directory, value.program = selected, directory, guest.program
        value.plan, value.plan_sha256, value.intents = (
            details.plan,
            details.plan.sha256,
            details.intents,
        )
        value.context = {
            "format": CONTEXT_FORMAT,
            "plan_sha256": details.plan.sha256,
            "run_id": details.plan.run_id,
            "captured_at": START,
            "source_fixture_sha256": digest(prepared_graph["actors"]["source"]),
            "actors": prepared_graph["actors"],
            "topology": prepared_graph["topology"],
            "guest_program_sha256": prepared_graph["guest_program_sha256"],
            "preparation_sha256": details.plan.preparation_sha256,
            "credentials": {
                "ids": details.expected_ids,
                "intents": {item.role: item.sha256 for item in details.intents},
                "expires_at": details.intents[0].expires_at,
            },
        }
        value.context_sha256 = digest(value.context)
        value.names, value.token, value.original = (
            {"nonce": details.plan.nonce},
            details.readers.caddy,
            {},
        )
        for name in ("roots.pem", "hosts", "resolv.conf"):
            path = directory / name
            path.write_bytes(b"synthetic guest input")
            path.chmod(0o600)
            value.original[name] = path
        write_private(directory / "isolation-context.json", value.context)
        write_private(
            directory / "isolation-names.json",
            {
                "format": "lowerduckpond-isolated-public-ca-names-v1",
                "plan_sha256": details.plan.sha256,
                "nonce": details.plan.nonce,
            },
        )
        write_private(directory / "isolation-guest-program.json", {"program": guest.program})
        journal.put("context", value.context)
        value.observe = journal.put
        value.require_cleanup_armed, value._identity, value._stop_identity = (host.require,) * 3
        value.gate_closed, value.peer = Mock(), Mock()
        value.deadline = time.monotonic() + 60
        value.witness = IsolationWitness.open(directory, details.plan, details.readers)
        return value

    monkeypatch.setattr(adapter, "IsolatedRecovery", recovery)
    with pytest.raises(errors.ProbeError) as caught:
        controller.execute(host, access, fixture, confirmation_run=1)
    assert caught.value.receipt["code"] == "admin-response-unverified"
    source = Path(policy.__file__).with_name("m3_11_public_probe.py")
    assertion_line = next(
        index
        for index, line in enumerate(source.read_text().splitlines(), 1)
        if 'raise ValueError("public probe issuance suspension was not confirmed")' in line
    )
    assert {"module": source.name, "line": assertion_line} in cast(
        "list[dict[str, object]]", caught.value.receipt["frames"]
    )
    assert guest.started.exists() and guest.stopped.exists()
    assert read_private(host.root / "functional-terminal.json") == {
        "status": "failed",
        "qualification_authority": "none",
    }
    fixture.reboot.assert_not_called()
    assert not (host.phase / "isolation-functional.json").exists()
    primary = host.phase / "public-probe-failure-suspend.json"
    before = primary.read_bytes()
    assert read_private(primary) == caught.value.receipt
    assert (
        read_private(host.phase / "public-probe-failure-stop_failed.json")["error_type"]
        == "OSError"
    )
    provider.authority_sha256 = "d" * 64
    closed = host.cleanup(access)
    assert closed["status"] == "verified" and closed["failures"] == []
    remote = Lease(None, host.manifest.intents, Journal(journal.client, host.manifest))
    readback = remote.independent_readback(
        cast(Provider, provider),
        expected=cast(str, closed["closure_sha256"]),
        require_issuer_stopped=host.controller_stopped,
    )
    assert readback["provider_absent"] is True
    assert primary.read_bytes() == before
    assert read_private(host.root / "functional-terminal.json")["status"] == "failed"
    with pytest.raises(FileNotFoundError):
        functional(host)  # Cleanup cannot manufacture an isolated recovery prerequisite.
    assert not provider.items and len(provider.deleted) == len(host.manifest.intents)
    assert all(host.actor(role)["running"] is False for role in prepared_graph["actors"])
    diagnostics = before + json.dumps(closed).encode() + json.dumps(readback).encode()
    for path in (
        host.root / "functional-terminal.json",
        host.phase / "public-probe-failure-stop_failed.json",
        host.phase / "public-ca-stop-failed.json",
    ):
        diagnostics += path.read_bytes()
    captured = capfd.readouterr()
    rendered_failure = "".join(traceback.format_exception(caught.value))
    for private in (PRIVATE, SECRET):
        assert private.encode() not in diagnostics
        assert private not in captured.out + captured.err
        assert private not in rendered_failure
