"""Hermetic source/restore transport tests. No test opens an SSH connection."""

from __future__ import annotations

import base64
import os
import shlex
import ssl
import stat
import subprocess
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_fence import FENCE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_inputs import (
    INPUT_SCHEMA,
    ISSUER,
    SUBJECTS,
    RestoreInputs,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
)

from scripts import m3_12_droplet_observe as guest
from scripts import m3_12_droplet_ssh as ssh
from scripts.m3_12_contracts import Document, ValidationError, decode, digest, encode
from scripts.m3_12_diagnostic_store import PRIVATE_FILE, Attempt, clock, read
from scripts.m3_12_droplet_controller import (
    inspect_boot,
    inspect_fresh_dark,
    prepare,
    prepare_cold_restore,
    prepare_fresh,
)
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_ssh import Endpoint

ORIGINAL_CA = b"synthetic original origin-pull CA"
CANDIDATE_SHA256 = "1" * 64

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
            role="source" if not pair else "restore",
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
        "state": {"artifactSha256": None, "launchPresent": False, "publication": "absent"},
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
        "artifactSha256": None,
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

    with pytest.raises(ValidationError, match="droplet-preparation-role-conflict"):
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
            report["state"]["artifactSha256"] = CANDIDATE_SHA256
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


def test_boot_readback_rederives_the_original_target_from_the_pinned_observation(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints
    selected = {endpoint.provider.ipv4: observation(endpoint) for endpoint in (source, restore)}
    connections = []

    def wire(args: list[str], **_kwargs: object) -> bytes:
        address = args[-2].partition("@")[2]
        connections.append(address)
        return encode(selected[address])

    monkeypatch.setattr(ssh, "bounded_command", wire)
    excluded = encode(exclusions)
    prepare(attempt, source, restore, excluded)
    path = attempt.directory / "droplet-preparation-result.json"
    result = read(attempt.directory, path.name)
    result["restore"]["target"]["stateSha256"] = proof("substituted state")
    path.write_bytes(encode(result))
    connections.clear()
    with pytest.raises(ValidationError, match="droplet-inspection-enrollment-changed"):
        inspect_boot(attempt, "restore", restore, excluded)
    assert connections == []


def test_fresh_install_preparation_cannot_reuse_the_paired_attempt(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, restore, exclusions = endpoints
    report = observation(source)
    connections = []

    def wire(args: list[str], **_kwargs: object) -> bytes:
        assert args[-2].partition("@")[2] == source.provider.ipv4
        prepared = read(attempt.directory, "droplet-preparation.json")
        assert set(prepared).isdisjoint({"source", "restore"})
        assert prepared["fresh"]["provider"] == source.provider.document()
        connections.append(source.provider.ipv4)
        return encode(report)

    monkeypatch.setattr(ssh, "bounded_command", wire)
    with pytest.raises(ValidationError, match="droplet-preparation-role-conflict"):
        prepare_fresh(attempt, source, encode(exclusions), artifact_sha256=CANDIDATE_SHA256)
    fresh = replace(source, allocation=replace(source.allocation, role="fresh"))
    target, enrollment = prepare_fresh(
        attempt, fresh, encode(exclusions), artifact_sha256=CANDIDATE_SHA256
    )
    assert target["droplet"]["dropletId"] == source.provider.droplet_id
    assert enrollment["machineSha256"] == report["hostIdentity"]["machineSha256"]
    with pytest.raises(ValidationError, match="droplet-preparation-original-changed"):
        prepare(attempt, source, restore, encode(exclusions))
    with pytest.raises(ValidationError, match="droplet-inspection-scope-changed"):
        inspect_boot(attempt, "source", source, encode(exclusions))
    assert len(connections) == 1
    report["bootSha256"] = proof("fresh reboot")
    assert inspect_boot(attempt, "fresh", fresh, encode(exclusions))["bootChanged"]


@pytest.mark.parametrize(
    ("field", "value"),
    [("artifactSha256", CANDIDATE_SHA256), ("launchPresent", True), ("publication", "dark")],
)
def test_fresh_install_rejects_preexisting_candidate_state(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    attempt, source, _, exclusions = endpoints
    report = observation(source)
    report["state"][field] = value
    monkeypatch.setattr(ssh, "bounded_command", lambda *_args, **_kwargs: encode(report))
    fresh = replace(source, allocation=replace(source.allocation, role="fresh"))
    with pytest.raises(ValidationError, match="droplet-fresh-target-is-not-pristine"):
        prepare_fresh(attempt, fresh, encode(exclusions), artifact_sha256=CANDIDATE_SHA256)
    assert not (attempt.directory / "droplet-preparation-result.json").exists()


def test_fresh_dark_readback_requires_the_pinned_candidate_after_reboot(
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt, source, _, exclusions = endpoints
    fresh = replace(source, allocation=replace(source.allocation, role="fresh"))
    report = observation(fresh)
    monkeypatch.setattr(ssh, "bounded_command", lambda *_args, **_kwargs: encode(report))
    excluded = encode(exclusions)
    prepare_fresh(attempt, fresh, excluded, artifact_sha256=CANDIDATE_SHA256)
    with pytest.raises(ValidationError, match="droplet-preparation-original-changed"):
        prepare_fresh(attempt, fresh, excluded, artifact_sha256="2" * 64)
    dark = {"artifactSha256": CANDIDATE_SHA256, "publication": "dark", "launchPresent": False}
    for changes in (
        {"artifactSha256": "2" * 64},
        {"publication": "enabled"},
        {"launchPresent": True},
    ):
        report["state"] = {**dark, **changes}
        with pytest.raises(ValidationError, match="droplet-fresh-dark-state-changed"):
            inspect_fresh_dark(attempt, fresh, excluded)
    assert not list(attempt.directory.glob("droplet-fresh-dark-*.json"))

    report["state"] = dark
    first = inspect_fresh_dark(attempt, fresh, excluded)
    assert inspect_fresh_dark(attempt, fresh, excluded) == first
    report["bootSha256"] = proof("fresh reboot after dark install")
    after = inspect_fresh_dark(attempt, fresh, excluded)
    assert after == {**first, "bootSha256": report["bootSha256"]}
    first_path = f"droplet-fresh-dark-{first['bootSha256']}.json"
    assert read(attempt.directory, first_path) == first


def test_guest_selection_is_an_owned_content_address_not_a_link_to_unreviewed_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selector = tmp_path / "current"
    monkeypatch.setattr(guest, "SELECTION", selector)
    owner = os.geteuid()
    assert guest.selected_artifact(owner) is None
    artifact = tmp_path / CANDIDATE_SHA256
    artifact.mkdir(mode=0o700)
    selector.symlink_to(artifact)
    assert guest.selected_artifact(owner) == CANDIDATE_SHA256
    artifact.chmod(0o770)
    with pytest.raises(ValueError, match="droplet-artifact-selector-invalid"):
        guest.selected_artifact(owner)
    artifact.chmod(0o700)
    selector.unlink()
    selector.symlink_to(artifact.name)
    with pytest.raises(ValueError, match="droplet-artifact-selector-invalid"):
        guest.selected_artifact(owner)


def recovery_policy(
    attempt: Attempt, *, snapshot: str = "c" * 64, source_machine: str = "a" * 32
) -> tuple[Document, bytes]:
    restore_id = attempt.directory.name
    artifact = "d" * 64
    repository = framed_digest("lowerduckpond-backup-repository-binding-v1", b"owned repository")
    fence = encode(
        {
            "schema": FENCE_SCHEMA,
            "restoreId": restore_id,
            "snapshotId": snapshot,
            "captureId": "00000000-0000-7000-8000-000000000001",
            "lineageId": "00000000-0000-7000-8000-000000000002",
            "repositoryBinding": repository,
            "artifactDigest": {
                "format": "lowerduckpond-static-host-agent-artifact-v1",
                "algorithm": "sha256",
                "value": artifact,
            },
            "sourceMachineId": source_machine,
            "sourceGateDigest": framed_digest(
                GATE_SCHEMA, encode({"schema": GATE_SCHEMA, "restoreId": restore_id})
            ),
            "maskedUnits": sorted(
                (*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service")
            ),
        }
    )
    return {
        "schema": INPUT_SCHEMA,
        "restoreId": restore_id,
        "snapshotId": snapshot,
        "repositoryBinding": repository,
        "originalArtifactSha256": artifact,
        "sourceMachineId": source_machine,
        "destinationMachineId": "b" * 32,
        "sourceFenceDigest": framed_digest(FENCE_SCHEMA, fence),
        "namespace": {
            "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
            "kind": "PlatformNamespace",
            "tenantOriginSuffix": "lowerduckpond.com",
            "initializedAt": "2026-01-01T00:00:00Z",
        },
        "launch": None,
        "archiveTarget": {"region": "sfo3", "bucket": "owned-test-archive"},
        "caddy": {
            "binaryPath": "/usr/local/lib/lowerduckpond/caddy-owned-pinned-binary",
            "binarySha256": proof("caddy"),
            "environmentSha256": proof("test environment"),
            "originPullCaSha256": [proof("restore CA")],
            "originalOriginPullCaSha256": [sha256(ORIGINAL_CA).hexdigest()],
            "originPullRequired": True,
            "issuer": ISSUER,
            "subjects": list(SUBJECTS),
            "trustBundleSha256": proof("trust bundle"),
        },
        "publicationEnabled": False,
        "auditRotationEnabled": False,
    }, fence


def recovery_files(root: Path, policy: Document, fence: bytes) -> Path:
    root.mkdir(mode=0o700)
    for name, raw in (
        ("target.json", encode(policy)),
        (f"source-fence-{policy['restoreId']}.json", fence),
        ("original-origin-pull-ca-0.pem", ssl.DER_cert_to_PEM_cert(ORIGINAL_CA).encode()),
    ):
        path = root / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return root


def test_cold_restore_preflight_binds_the_original_policy_to_the_two_owned_hosts(  # noqa: PLR0915 - exercise the full retained original and transfer boundary
    endpoints: tuple[Attempt, Endpoint, Endpoint, Document],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt, source, restore, exclusions = endpoints
    reports = {endpoint.provider.ipv4: observation(endpoint) for endpoint in (source, restore)}
    reports[source.provider.ipv4]["hostIdentity"]["machineSha256"] = proof("a" * 32)
    reports[restore.provider.ipv4]["hostIdentity"]["machineSha256"] = proof("b" * 32)
    connections = []

    def wire(args: list[str], **_kwargs: object) -> bytes:
        address = args[-2].partition("@")[2]
        connections.append(address)
        return encode(reports[address])

    excluded = encode(exclusions)
    monkeypatch.setattr(ssh, "bounded_command", wire)
    targets = prepare(attempt, source, restore, excluded)
    connections.clear()
    policy, fence = recovery_policy(attempt)

    def preflight(directory: Path) -> Document:
        return prepare_cold_restore(attempt, source, restore, excluded, inputs_directory=directory)

    with pytest.raises(HostRestoreError, match="restore_source_fence_mismatch"):
        preflight(recovery_files(tmp_path / "mismatch", {**policy, "snapshotId": "e" * 64}, fence))
    switched, switched_fence = recovery_policy(attempt, source_machine="f" * 32)
    with pytest.raises(ValidationError, match="droplet-restore-policy-host-changed"):
        preflight(recovery_files(tmp_path / "other-machine", switched, switched_fence))
    invalid = recovery_files(tmp_path / "invalid-ca", policy, fence)
    (invalid / "original-origin-pull-ca-0.pem").write_text(
        ssl.DER_cert_to_PEM_cert(b"wrong synthetic CA")
    )
    with pytest.raises(HostRestoreError, match="restore_archive_original_trust_changed"):
        preflight(invalid)
    assert connections == []
    assert not list(attempt.directory.glob("droplet-cold-restore-readback-*.json"))

    trusted = recovery_files(tmp_path / "original", policy, fence)
    original = preflight(trusted)
    retained = read(attempt.directory, "droplet-cold-restore-inputs.json")
    assert original == retained
    assert original["snapshotId"] == policy["snapshotId"]
    assert original["sourceFence"] == policy["sourceFenceDigest"]
    assert original["originalCaCount"] == 1
    assert original["sourceTargetSha256"] == digest(targets["source"][0])
    assert original["destinationTargetSha256"] == digest(targets["restore"][0])
    assert original["sourceLaunch"] is None
    scoped = RestoreInputs.from_bytes(
        (attempt.directory / "droplet-restore-target.json").read_bytes()
    )
    assert scoped.digest == original["trustedInputs"]
    assert scoped.droplet_scope_digest == original["activationScope"]
    assert scoped.droplet_scope is not None
    assert scoped.droplet_scope["runId"] == attempt.directory.parent.name
    assert scoped.droplet_scope["destinationTargetSha256"] == digest(targets["restore"][0])
    assert not {"sourceMachineId", "destinationMachineId"}.intersection(retained)
    assert connections == [restore.provider.ipv4]
    observed = reports[restore.provider.ipv4]
    accepted_readback = f"droplet-cold-restore-readback-{digest(observed)}.json"
    assert read(attempt.directory, accepted_readback)["inputsSha256"] == digest(original)

    replacement, replacement_fence = recovery_policy(attempt, snapshot="e" * 64)
    with pytest.raises(ValidationError, match="droplet-preparation-original-changed"):
        preflight(recovery_files(tmp_path / "other-snapshot", replacement, replacement_fence))
    observed["state"]["artifactSha256"] = CANDIDATE_SHA256
    with pytest.raises(ValidationError, match="droplet-restore-target-is-not-cold"):
        preflight(trusted)
    assert read(attempt.directory, "droplet-cold-restore-inputs.json") == original
    assert list(attempt.directory.glob("droplet-cold-restore-readback-*.json")) == [
        attempt.directory / accepted_readback
    ]
