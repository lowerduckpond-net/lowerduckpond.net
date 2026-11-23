"""Exercise the P4 native orchestration without a daemon, external SSH or provider APIs."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import droplet_enrollment
from lowerduckpond_static_host_agent.host_restore_inputs import ROUTING_INPUT
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    DROPLET_SCOPE_FORMAT,
    HostRestoreError,
)
from lowerduckpond_static_host_agent.installed_routing import (
    ROLE,
    CutoverReceiver,
    cutover_filename,
)

from infrastructure.test_m3_12_droplet_adapters import endpoint
from infrastructure.test_m3_12_droplet_controller import recovery_files, recovery_policy
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import proof
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from scripts import m3_12_droplet_observe as guest
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import PRIVATE_FILE, Attempt, read
from scripts.m3_12_disposable_routing import POLICY_FORMAT, reviewed_routing_policy
from scripts.m3_12_droplet_cleanup import InitialRetirement
from scripts.m3_12_droplet_driver import (
    REBOOT,
    RESUME,
    CleanupCapture,
    FixtureObservation,
    FixturePhase,
    NativePhaseDriver,
    ReviewedDestroy,
)
from scripts.m3_12_droplet_journey import PHASES
from scripts.m3_12_droplet_plan import CONFIGURATION_FIELDS, PROVIDER
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import REMOTE_PROBE, REMOTE_RESTORE, Endpoint
from scripts.m3_12_droplet_teardown import HostAbsence, _host_authority

INITIAL_BOOT = "11111111-1111-4111-8111-111111111111"
SECOND_BOOT = "22222222-2222-4222-8222-222222222222"


def _private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _cleanup_plans(
    scope: Document, endpoints: dict[str, Endpoint]
) -> tuple[dict[str, ReviewedDestroy], Document]:
    plans = {}
    for role, endpoint_binding in endpoints.items():
        values = {address: {"id": f"{role}-{address}"} for address in CONFIGURATION_FIELDS}
        original = InitialRetirement(
            endpoint_binding.allocation,
            scope["resources"]["hosts"][role]["stateKey"],
            f"firewall-{role}",
            f"do:droplet:{endpoint_binding.provider.droplet_id}",
            tuple((address, encode(row)) for address, row in values.items()),
        )
        resources = [
            {
                "address": address,
                "provider_name": PROVIDER,
                "mode": "managed",
                "type": address.split(".")[0],
                "name": address.split(".")[1],
                "values": value,
            }
            for address, value in values.items()
        ]
        plan = {
            "errored": False,
            "planned_values": {},
            "prior_state": {"values": {"root_module": {"resources": resources}}},
            "resource_changes": [
                {
                    **{key: value for key, value in row.items() if key != "values"},
                    "change": {"actions": ["delete"], "before": row["values"], "after": None},
                }
                for row in resources
            ],
        }
        plans[role] = ReviewedDestroy(original, encode(plan), digest(plan))
    authority = {
        "format": "lowerduckpond-m3-12-teardown-authority-v1",
        "allocationSha256": digest(scope),
        "hosts": {
            role: _host_authority(scope, role, plan.original) for role, plan in plans.items()
        },
        "grants": [proof("fixture grant")],
        "archiveRetentions": {},
    }
    return plans, authority


class SimulatedNative:
    def __init__(  # noqa: PLR0913, PLR0917 - distinct fixture custody and boot inputs
        self,
        scope: Document,
        policy: Document,
        fence: Document,
        boot: Path,
        receiver: CutoverReceiver,
        plans: dict[str, ReviewedDestroy],
        cleanup_authority: Document,
    ) -> None:
        self.scope = scope
        self.policy = policy
        self.fence = fence
        self.boot = boot
        self.receiver = receiver
        self.plans = plans
        self.cleanup_authority = cleanup_authority
        self.actions: list[str] = []
        self.phase_results: set[str] = set()
        self.source_closed = False
        self.fence_effect = True
        self.restore_closed = True
        self.local_gate_valid = True
        self.visible_grant_closed = False
        self.unsafe_state = False
        self.cleanup_reads = 0
        self.interrupt_restore = False
        self.interrupt_cleanup = False
        self.hide_reboot_result = False

    def observation(self, role: str) -> Document:
        host = self.scope["resources"]["hosts"][role]
        return {
            "format": guest.FORMAT,
            "metadata": {
                "dropletId": host["target"]["droplet"]["dropletId"],
                "ipv4": host["enrollment"]["ipv4"],
            },
            "hostIdentity": {
                name: host["enrollment"][name]
                for name in ("machineSha256", "systemUuidSha256", "hostKeySha256")
            },
            "bootSha256": guest.boot_sha256(os.geteuid()) if role == "restore" else proof(role),
            "state": {
                "artifactSha256": self.policy["originalArtifactSha256"],
                "launchPresent": False,
                "publication": "dark",
            },
        }

    def gate(self, role: str) -> Document:
        return {
            "format": guest.FENCE_FORMAT,
            "observation": self.observation(role),
            "gateSha256": self.fence["sourceGateDigest"]["value"],
            "ingressClosed": self.source_closed if role == "source" else self.restore_closed,
            "caddyInactive": role == "source" and self.source_closed,
        }

    def local_gate(self, restore_id: str) -> Document:
        assert restore_id == self.policy["restoreId"]
        gate = self.gate("restore")
        return gate if self.local_gate_valid else {**gate, "ingressClosed": False}

    def wire(self, arguments: list[str], **_options: object) -> bytes:
        assert "StrictHostKeyChecking=yes" in arguments
        address = arguments[-2].removeprefix("ldp-admin@")
        role = next(
            name
            for name, host in self.scope["resources"]["hosts"].items()
            if host["enrollment"]["ipv4"] == address
        )
        command = arguments[-1]
        if command == REMOTE_PROBE:
            return encode(self.observation(role))
        if command.startswith(f"{REMOTE_PROBE} --restore-fence"):
            return encode(self.gate(role))
        assert command == f"{REMOTE_RESTORE} --status"
        return encode(
            {
                "restoreId": self.policy["restoreId"],
                "snapshotId": self.policy["snapshotId"],
                "phase": "complete",
                "activationPending": self.restore_closed,
            }
        )

    def submit(self, work: FixturePhase) -> None:
        phase = work.phase.name
        assert phase not in self.actions
        self.actions.append(phase)
        if phase == "backup-fence":
            self.source_closed = self.fence_effect
        if phase in {"restore", RESUME}:
            assert self.source_closed and self.restore_closed
            received = self.receiver.authority / cutover_filename(guest.boot_sha256(os.geteuid()))
            self.receiver.require_installed(received.read_bytes())
            assert received.stat().st_mode & 0o777 == PRIVATE_FILE
            self.restore_closed = False
        if phase == REBOOT:
            self.restore_closed = True
            self.boot.write_text(SECOND_BOOT + "\n")
        self.phase_results.add(phase)
        if (phase == "restore" and self.interrupt_restore) or (
            phase == "teardown" and self.interrupt_cleanup
        ):
            raise ConnectionError("discarded synthetic transport output")

    def inspect(self, work: FixturePhase) -> FixtureObservation:
        name = work.phase.name
        if name not in self.phase_results or (name == REBOOT and self.hide_reboot_result):
            return FixtureObservation("unknown", {})
        evidence = {
            field: {"phase": name, "kind": field}
            for field in work.phase.evidence - {"nativeIngress", "closedBoot"}
        }
        if name == "backup-fence":
            evidence["sourceFence"] = self.fence
        if name == "retain-originals":
            evidence["cleanupAuthority"] = self.cleanup_authority
        return FixtureObservation("committed", evidence)

    def inspect_cleanup(self, work: FixturePhase) -> CleanupCapture:
        assert work.phase.name == "teardown"
        self.cleanup_reads += 1
        state = encode(
            {
                "format_version": "1.0",
                "terraform_version": "1.12.6",
                **(
                    {"checks": [{"unreviewed": "synthetic-secret-canary"}]}
                    if self.unsafe_state
                    else {}
                ),
            }
        )
        hosts = {}
        for role, plan in self.plans.items():
            original = plan.original
            allocation = original.allocation
            hosts[role] = HostAbsence(
                original,
                state,
                {
                    "stateKey": original.state_key,
                    "allocationSha256": allocation.allocation_sha256,
                    "stateSha256": proof(state.decode()),
                    "projectIdSha256": allocation.identity.project_id_sha256,
                    "dropletId": allocation.identity.droplet_id,
                    "firewallId": original.firewall_id,
                    "projectUrn": original.urn,
                    "droplet": "absent",
                    "firewall": "absent",
                    "projectMembership": "absent",
                },
            )

        def status(identity: str, result: str = "absent") -> Document:
            return {"identitySha256": identity, "evidenceSha256": proof(identity), "status": result}

        external = {
            "dns": {
                f"{zone}-{role}": status(
                    digest(
                        {"zoneId": row["zoneId"], "zoneName": row["zoneName"], "scope": row[role]}
                    )
                )
                for zone, row in self.scope["resources"]["edge"].items()
                for role in ("source", "fresh")
            },
            "storage": {
                f"{role}-{kind}": status(digest({"role": role, "kind": kind, **storage}))
                for role, locations in self.scope["resources"]["storage"].items()
                for kind, storage in locations.items()
            },
            "grants": {
                key: status(key, "revoked" if self.visible_grant_closed else "active")
                for key in self.cleanup_authority["grants"]
            },
        }
        return CleanupCapture(hosts, external, digest(external))


@pytest.fixture
def native(
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[NativePhaseDriver, SimulatedNative]:
    attempt, scope, review = fixture
    site = {
        "format": POLICY_FORMAT,
        "runId": scope["runId"],
        "invocationId": scope["invocationId"],
        "platform": "source.platform.example",
        "tenantScope": "source.tenant.example",
        "tenants": [],
    }
    scope["sitePolicySha256"] = digest(site)
    hosts = scope["resources"]["hosts"]
    for role, machine in (("source", "a" * 32), ("restore", "b" * 32)):
        host = hosts[role]
        host["enrollment"]["machineSha256"] = proof(machine)
        host["target"]["enrollmentSha256"] = digest(host["enrollment"])
    review = replace(
        review,
        manifest_sha256=digest(scope),
        site_policy_sha256=digest(site),
        observed_resources=encode(scope["resources"]),
    )
    routing = reviewed_routing_policy(scope, encode(site))
    policy, fence = recovery_policy(attempt)
    policy[ROUTING_INPUT] = routing.document()
    policy[DROPLET_BINDING] = {
        "format": DROPLET_SCOPE_FORMAT,
        "runId": routing.run_id,
        "sourceTargetSha256": routing.source_target,
        "destinationTargetSha256": routing.restore_target,
        "sourceLaunchReceiptSha256": None,
    }
    inputs = recovery_files(tmp_path / "controller-restore", policy, fence)
    guest_inputs = recovery_files(tmp_path / "guest-restore", policy, fence)
    authority = tmp_path / droplet_enrollment.PUBLICATION_VIEW
    authority.mkdir(mode=0o700)
    recovery = tmp_path / "guest-recovery"
    recovery.mkdir(mode=0o700)
    owner = os.geteuid()
    receiver = CutoverReceiver(guest_inputs, recovery, authority, owner)
    restore = hosts["restore"]
    for name, record in (
        (droplet_enrollment.TARGET, restore["target"]),
        (droplet_enrollment.ENROLLMENT, restore["enrollment"]),
        (droplet_enrollment.EXCLUSIONS, json.loads(review.production_exclusions)["hosts"]),
        (ROLE, routing.role_document("restore")),
    ):
        _private(authority / name, encode(record))
    boot = tmp_path / "boot-id"
    _private(boot, (INITIAL_BOOT + "\n").encode())
    monkeypatch.setattr(guest, "BOOT_ID", boot)
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", tmp_path / "fixture-only-marker")
    monkeypatch.setattr(
        droplet_enrollment,
        "host_identity",
        lambda _owner: {
            name: restore["enrollment"][name]
            for name in ("machineSha256", "systemUuidSha256", "hostKeySha256")
        },
    )
    endpoints = {
        "source": endpoint(tmp_path, scope, "source"),
        "restore": endpoint(tmp_path, scope, "restore"),
        "fresh": endpoint(tmp_path, scope, "fresh"),
    }
    plans, cleanup_authority = _cleanup_plans(scope, endpoints)
    sim = SimulatedNative(
        scope, policy, json.loads(fence), boot, receiver, plans, cleanup_authority
    )
    driver = NativePhaseDriver(
        attempt,
        encode(scope),
        review,
        endpoints,
        encode(site),
        inputs,
        receiver,
        sim.local_gate,
        sim.wire,
        sim,
        plans,
    )
    return driver, sim


def test_native_driver_recovers_cutover_and_cleanup_without_replaying_actions(  # noqa: PLR0915 - complete interruption and retained-evidence sequence
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    sim.interrupt_restore = sim.interrupt_cleanup = sim.hide_reboot_result = True
    first = driver.run()
    assert first["phases"]["restore"] == "uncertain"
    assert first["phases"][REBOOT] == "blocked"
    assert first["phases"]["fresh-reboot"] == "committed"
    submitted = (driver.attempt.directory / "journey-restore-intent.json").read_bytes()
    with pytest.raises(ValidationError, match="droplet-native-dispatch-already-submitted"):
        driver.submit(submitted, driver.allocation)
    original_boot_file = next(driver.receiver.authority.glob("routing-cutover-*.json"))
    original_bytes = original_boot_file.read_bytes()

    second = replace(driver).run()
    assert second["phases"][REBOOT] == "uncertain"
    assert second["phases"][RESUME] == "blocked"
    assert sim.gate("restore")["ingressClosed"] is True
    assert len(list(driver.receiver.authority.glob("routing-cutover-*.json"))) == 1

    sim.hide_reboot_result = False
    third = replace(driver).run()
    assert third["phases"][RESUME] == "committed"
    assert third["phases"]["teardown"] == "uncertain"
    assert sim.gate("restore")["ingressClosed"] is False
    assert original_boot_file.read_bytes() == original_bytes

    fourth = replace(driver).run()
    assert fourth["phases"]["teardown"] == "uncertain"
    assert not (driver.attempt.directory / "journey-teardown-result.json").exists()
    sim.visible_grant_closed = True
    assert replace(driver).run()["sequenceComplete"]
    assert set(sim.actions) == {phase.name for phase in PHASES}
    assert len(sim.actions) == len(PHASES)
    assert (
        sim.actions.index("backup-fence") < sim.actions.index("restore") < sim.actions.index(REBOOT)
    )
    assert sim.actions.index(REBOOT) < sim.actions.index(RESUME) < sim.actions.index("teardown")
    assert not any(
        b"discarded synthetic transport output" in path.read_bytes()
        for path in driver.attempt.directory.glob("*.json")
    )
    completed_actions = list(sim.actions)
    completed_reads = sim.cleanup_reads
    assert replace(driver).run()["sequenceComplete"]
    assert sim.cleanup_reads == completed_reads
    original = read(driver.attempt.directory, "journey-teardown-result.json")
    captured_key = original["evidence"]["cleanupCapture"]
    captured_name = f"native-evidence-{captured_key}.json"
    captured = read(driver.attempt.directory, captured_name)
    assert captured["externalSha256"] == digest(captured["external"])
    for domain in ("dns", "storage", "grants"):
        assert captured["external"][domain]
        for row in captured["external"][domain].values():
            assert row["evidenceSha256"] == proof(row["identitySha256"])
    hosts = read(
        driver.attempt.directory, f"native-evidence-{original['evidence']['hostAbsence']}.json"
    )
    for role, row in captured["hosts"].items():
        assert hosts[role]["stateSha256"] == proof(row["stateJson"])
        assert hosts[role]["readbackSha256"] == digest(row["providerReadback"])
    captured_file = driver.attempt.directory / captured_name
    captured_file.write_bytes(encode({**captured, "externalSha256": proof("substituted")}))
    with pytest.raises(ValidationError, match="original-observation-changed"):
        replace(driver).run()
    captured_file.unlink()
    with pytest.raises(FileNotFoundError):
        replace(driver).run()
    assert sim.actions == completed_actions
    assert sim.cleanup_reads == completed_reads


def test_native_driver_excludes_unreviewed_teardown_state(
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    sim.visible_grant_closed = True
    sim.unsafe_state = True
    with pytest.raises(ValidationError, match="droplet-cleanup-unsafe-state-evidence"):
        driver.run()
    assert not (driver.attempt.directory / "journey-teardown-result.json").exists()
    assert not any(
        b"synthetic-secret-canary" in path.read_bytes()
        for path in driver.attempt.directory.glob("*.json")
    )


def test_native_driver_never_delivers_when_source_ingress_stays_open(
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    sim.fence_effect = False
    with pytest.raises(ValidationError, match="droplet-routing-fence-unproven"):
        driver.run()
    assert sim.gate("restore")["ingressClosed"] is True
    assert "restore" not in sim.actions and "teardown" not in sim.actions
    assert not list(driver.receiver.authority.glob("routing-cutover-*.json"))


def test_receiver_requires_independent_local_fence_before_writing(
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    sim.local_gate_valid = False
    result = driver.run()
    assert result["phases"]["restore"] == "uncertain"
    assert "restore" not in sim.actions
    assert not list(driver.receiver.authority.glob("routing-cutover-*.json"))

    cutover = next(driver.attempt.directory.glob("native-cutover-*.json")).read_bytes()
    sim.local_gate_valid = True
    bad_record = {**json.loads(cutover), "restoreBootSha256": proof("other boot")}
    with pytest.raises(HostRestoreError, match="cutover_changed"):
        driver.receiver.install(encode(bad_record), sim.local_gate)
    role_path = driver.receiver.authority / ROLE
    original_role = role_path.read_bytes()
    _private(role_path, encode({**json.loads(original_role), "role": "source"}))
    with pytest.raises(HostRestoreError, match="role_changed"):
        driver.receiver.install(cutover, sim.local_gate)
    assert not list(driver.receiver.authority.glob("routing-cutover-*.json"))
    _private(role_path, original_role)
    gate = sim.local_gate(sim.policy["restoreId"])
    gate["observation"]["hostIdentity"]["machineSha256"] = proof("foreign receiver")
    with pytest.raises(HostRestoreError, match="local_fence_unproven"):
        driver.receiver.install(cutover, lambda _restore_id: gate)
    assert not list(driver.receiver.authority.glob("routing-cutover-*.json"))
    driver.receiver.install(cutover, sim.local_gate)
    driver.receiver.install(cutover, sim.local_gate)
    installed = driver.receiver.authority / cutover_filename(guest.boot_sha256(os.geteuid()))
    changed_source = {**json.loads(cutover), "sourceBootSha256": proof("new source readback")}
    with pytest.raises(HostRestoreError, match="cutover_conflict"):
        driver.receiver.install(encode(changed_source), sim.local_gate)
    assert installed.read_bytes() == cutover


def test_native_closeout_refuses_missing_original_observation(
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    sim.hide_reboot_result = True
    assert driver.run()["phases"][RESUME] == "blocked"
    row = read(driver.attempt.directory, "journey-predecessor-result.json")
    key = row["evidence"]["bootstrap"]
    (driver.attempt.directory / f"native-evidence-{key}.json").unlink()
    sim.hide_reboot_result = False
    result = driver.run()
    assert result["phases"]["retain-originals"] == "uncertain"
    assert result["phases"]["teardown"] == "blocked"
    assert "retain-originals" not in sim.actions and "teardown" not in sim.actions


def test_driver_checks_all_destroy_plans_before_teardown(
    native: tuple[NativePhaseDriver, SimulatedNative],
) -> None:
    driver, sim = native
    original = driver.destroy_plans["restore"]
    bad = replace(original, reviewed_sha256=proof("other provider plan"))
    with pytest.raises(ValidationError, match="droplet-cleanup-plan-changed"):
        replace(driver, destroy_plans={**driver.destroy_plans, "restore": bad}).run()
    assert "retain-originals" in sim.actions and "teardown" not in sim.actions
