"""Hermetic source/restore transport tests. No test opens an SSH connection."""

from __future__ import annotations

import base64
import os
import shlex
import stat
import subprocess
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from scripts import m3_12_droplet_observe as guest
from scripts import m3_12_droplet_ssh as ssh
from scripts.m3_12_contracts import Document, ValidationError, decode, encode
from scripts.m3_12_diagnostic_store import PRIVATE_FILE, Attempt, clock, read
from scripts.m3_12_droplet_controller import inspect_boot, prepare
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_ssh import Endpoint

FORBIDDEN_FIXTURE_VALUE = "fake-fixture-secret-excluded"


def proof(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def public_key(symbol: bytes) -> bytes:
    return b"ssh-ed25519 " + base64.b64encode(guest.ED25519_WIRE_HEADER + symbol * 32)


@pytest.fixture
def endpoints(tmp_path: Path) -> tuple[Attempt, Endpoint, Endpoint, Document]:
    attempt = Attempt.allocate(tmp_path / "attempts")
    key = tmp_path / "synthetic-client-identity"
    key.touch(mode=0o600)
    pair = []
    for target, address, symbol in ((101, "11.1.2.10", b"A"), (102, "11.1.2.11", b"B")):
        identity = ProviderIdentity(proof("reviewed-project"), target, address)
        allocation = ApprovedAllocation(
            run_id=attempt.directory.parent.name,
            state_sha256=proof(f"reviewed-state-{target}"),
            allocation_sha256=proof(f"allocation-{target}"),
            inventory_sha256=proof(f"inventory-{target}"),
            transaction_namespace_sha256=proof(f"namespace-{target}"),
            identity=identity,
        )
        pair.append(Endpoint(allocation, identity, public_key(symbol), key))
    exclusions = {
        "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
        "dropletIds": [900],
        "addresses": ["11.1.2.20"],
        "identityDigests": [proof("enrolled-production-identity")],
    }
    return attempt, pair[0], pair[1], exclusions


def observation(endpoint: Endpoint) -> Document:
    role = str(endpoint.provider.droplet_id)
    _, fingerprint = endpoint.validate()
    return {
        "format": guest.FORMAT,
        "metadata": {"dropletId": endpoint.provider.droplet_id, "ipv4": endpoint.provider.ipv4},
        "hostIdentity": {
            "hostKeySha256": fingerprint,
            "machineSha256": proof("machine-" + role),
            "systemUuidSha256": proof("host-" + role),
        },
        "bootSha256": proof("boot-" + role),
        "state": {"artifactSelected": False, "launchPresent": False, "publication": "absent"},
    }


def test_cold_restore_probe_reads_the_guest_without_an_installed_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = {
        "MACHINE_ID": b"1" * 32 + b"\n",
        "SYSTEM_UUID": b"10000000-2000-3000-4000-500000000000\n",
        "HOST_KEY": public_key(b"A") + b" fixture\n",
        "BOOT_ID": b"01000000-0000-4000-8000-000000000000\n",
    }
    for name, body in values.items():
        path = tmp_path / name
        path.write_bytes(body)
        path.chmod(0o600)
        monkeypatch.setattr(guest, name, path)
    for name in ("PUBLICATION", "SELECTION", "LAUNCH"):
        monkeypatch.setattr(guest, name, tmp_path / name)
    monkeypatch.setattr(guest, "metadata_identity", lambda: (101, "11.1.2.10"))
    received = decode(encode(guest.observe(os.geteuid())), "droplet-observation")
    assert received["state"] == {
        "artifactSelected": False,
        "launchPresent": False,
        "publication": "absent",
    }
    assert received["hostIdentity"]["hostKeySha256"] == guest.ed25519_key(public_key(b"A"))[1]
    guest.BOOT_ID.write_text("02000000-0000-4000-8000-000000000000\n")
    original = guest.observe(os.geteuid())
    assert original["bootSha256"] != received["bootSha256"]
    assert original["hostIdentity"] == received["hostIdentity"]


def test_ssh_options_are_accepted_by_the_actual_local_client(
    tmp_path: Path, endpoints: tuple[Attempt, Endpoint, Endpoint, Document]
) -> None:
    _, endpoint, _, _ = endpoints
    # -G evaluates the local client configuration and exits before connecting.
    known_hosts = tmp_path / "known hosts"
    flags = ssh._arguments(endpoint, known_hosts)
    query = subprocess.run(  # noqa: S603 - fixed OpenSSH config evaluation, no network
        [flags[0], "-G", *flags[1:]], capture_output=True, text=True, check=True
    )
    expected = {
        f"hostname {endpoint.provider.ipv4}",
        "user ldp-admin",
        "stricthostkeychecking true",
        "hostkeyalgorithms ssh-ed25519",
        "identitiesonly yes",
        "clearallforwardings yes",
        "forwardagent no",
        f"userknownhostsfile {known_hosts}",
        "globalknownhostsfile /dev/null",
    }
    assert expected <= set(query.stdout.splitlines())


def _expected_connection(
    attempt: Attempt, endpoint: Endpoint, args: list[str], source: bytes
) -> None:
    assert args[-2:] == [f"ldp-admin@{endpoint.provider.ipv4}", ssh.REMOTE_PROBE]
    assert source == ssh.PROBE.read_bytes()
    base, _, _ = args[0].rpartition("/")
    assert base == "/usr/bin"
    host_file_option = next(word for word in args if word.startswith("UserKnownHostsFile="))
    value = shlex.split(host_file_option.removeprefix("UserKnownHostsFile="))
    assert len(value) == 1
    host_file = Path(value[0])
    assert stat.S_IMODE(host_file.stat().st_mode) == PRIVATE_FILE
    assert host_file.read_bytes() == (
        endpoint.provider.ipv4.encode() + b" " + endpoint.host_public_key + b"\n"
    )
    assert (
        read(attempt.directory, "droplet-preparation.json")["runId"]
        == attempt.directory.parent.name
    )


def test_preparation_pins_both_roles_before_ssh_and_reopens_original_receipts(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints
    choices = {endpoint.provider.ipv4: endpoint for endpoint in (source, restore)}
    connected = []

    def wire(args: list[str], *, stdin: bytes, **kwargs: object) -> bytes:
        endpoint = choices[args[-2].partition("@")[2]]
        _expected_connection(attempt, endpoint, args, stdin)
        assert kwargs["timeout"] is None and kwargs["check"] is True
        connected.append(endpoint)
        return encode(observation(endpoint))

    monkeypatch.setattr(ssh, "bounded_command", wire)
    original = prepare(attempt, source, restore, encode(exclusions))
    record_path = attempt.directory / "droplet-preparation-result.json"
    retained = record_path.read_bytes()
    assert original["source"][0]["droplet"]["dropletId"] == source.provider.droplet_id
    assert original["restore"][0]["droplet"]["dropletId"] == restore.provider.droplet_id
    assert prepare(attempt, source, restore, encode(exclusions)) == original
    assert record_path.read_bytes() == retained
    assert connected == [source, restore, source, restore]

    with pytest.raises(ValidationError, match="droplet-preparation-original-changed"):
        prepare(attempt, restore, source, encode(exclusions))
    assert connected == [source, restore, source, restore]


def test_preparation_refuses_production_or_foreign_target_before_connecting(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        pytest.fail("SSH ran before the provider scope was verified")

    monkeypatch.setattr(ssh, "bounded_command", forbidden)
    changed = replace(restore, provider=replace(restore.provider, droplet_id=999))
    with pytest.raises(ValidationError, match="droplet-ssh-scope-changed"):
        prepare(attempt, source, changed, encode(exclusions))
    exclusions["addresses"].append(restore.provider.ipv4)
    with pytest.raises(ValidationError, match="production-crossover"):
        prepare(attempt, source, restore, encode(exclusions))


@pytest.mark.parametrize("invalid", ["foreign-host", "extra-output", "preinstalled"])
def test_preparation_declines_invalid_or_precooked_restore(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document],
    invalid: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt, source, restore, exclusions = endpoints

    def wire(args: list[str], **_kwargs: object) -> bytes:
        if args[-2].endswith(source.provider.ipv4):
            return encode(observation(source))
        report = observation(restore)
        if invalid == "foreign-host":
            report["hostIdentity"]["hostKeySha256"] = proof("different ssh key")
        elif invalid == "extra-output":
            report["forbidden"] = FORBIDDEN_FIXTURE_VALUE
        else:
            report["state"]["artifactSelected"] = True
        return encode(report)

    monkeypatch.setattr(ssh, "bounded_command", wire)
    expected = {
        "foreign-host": "droplet-ssh-observation-changed",
        "extra-output": "invalid-record",
        "preinstalled": "droplet-restore-target-is-not-cold",
    }
    with pytest.raises(ValidationError, match=expected[invalid]):
        prepare(attempt, source, restore, encode(exclusions))
    assert not (attempt.directory / "droplet-preparation-result.json").exists()
    assert all(
        FORBIDDEN_FIXTURE_VALUE not in path.read_text() for path in attempt.directory.glob("*.json")
    )


def test_transport_loss_retains_first_role_and_never_replaces_the_original(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints

    def wire(args: list[str], **_kwargs: object) -> bytes:
        if args[-2].endswith(source.provider.ipv4):
            return encode(observation(source))
        raise subprocess.CalledProcessError(255, args, stderr=FORBIDDEN_FIXTURE_VALUE)

    monkeypatch.setattr(ssh, "bounded_command", wire)
    started = clock()
    attempt.append("allocation", "controller", started, status=9, original=True)
    original = (attempt.directory / "original.json").read_bytes()
    with pytest.raises(ConnectionError, match=r"^droplet-ssh-transport-failed$"):
        prepare(attempt, source, restore, encode(exclusions))
    source_receipt = attempt.directory / "droplet-source-observation.json"
    assert source_receipt.is_file()
    assert not (attempt.directory / "droplet-restore-observation.json").exists()
    assert (attempt.directory / "original.json").read_bytes() == original
    assert all(
        FORBIDDEN_FIXTURE_VALUE not in path.read_text() for path in attempt.directory.glob("*.json")
    )


def test_boot_observation_reopens_only_the_original_host(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints
    source_observation = observation(source)
    restore_observation = observation(restore)
    observed = []

    def wire(args: list[str], **_kwargs: object) -> bytes:
        address = args[-2].partition("@")[2]
        observed.append(address)
        return encode(
            source_observation if address == source.provider.ipv4 else restore_observation
        )

    monkeypatch.setattr(ssh, "bounded_command", wire)
    prepare(attempt, source, restore, encode(exclusions))
    path = attempt.directory / "droplet-source-observation.json"
    before = path.read_bytes()

    no_change = inspect_boot(attempt, "source", source, encode(exclusions))
    assert no_change["bootChanged"] is False
    source_observation["bootSha256"] = proof("later boot")
    later = inspect_boot(attempt, "source", source, encode(exclusions))
    assert later["bootChanged"] is True
    assert later["observedBootSha256"] == proof("later boot")
    assert inspect_boot(attempt, "source", source, encode(exclusions)) == later
    assert path.read_bytes() == before

    source_observation["hostIdentity"]["machineSha256"] = proof("different machine")
    with pytest.raises(ValidationError, match="droplet-inspection-host-changed"):
        inspect_boot(attempt, "source", source, encode(exclusions))
    observed.clear()
    with pytest.raises(ValidationError, match="droplet-inspection-scope-changed"):
        inspect_boot(attempt, "source", restore, encode(exclusions))
    assert observed == []
