"""Run native P4 admission and receipt delivery on an explicitly supplied disposable fixture."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.installed_routing import CutoverReceiver

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import Attempt, publish, read
from scripts.m3_12_disposable_routing import (
    RoutingEndpoint,
    prepare_routing,
    require_prepared_cutover,
    verify_cutover,
)
from scripts.m3_12_droplet_cleanup import InitialRetirement, retain_empty_state
from scripts.m3_12_droplet_journey import PHASES, Phase, committed_dispatches, run_journey
from scripts.m3_12_droplet_native import AdapterInputs, inspect_host, require_endpoint
from scripts.m3_12_droplet_scope import ReviewedJourney, approved_scope
from scripts.m3_12_droplet_ssh import Endpoint, ReadExecutor, restore_status
from scripts.m3_12_droplet_teardown import HostAbsence, reconcile_teardown, review_destroy_plan

PHASE_BY_NAME = {phase.name: phase for phase in PHASES}
HEX_DIGEST_LENGTH = 64
RESUME = "restore-reboot"
REBOOT = "restore-reboot-closed"
INGRESS_PHASES = frozenset({"restore", RESUME})
CLOSEOUT_PHASES = frozenset({"retain-originals", "teardown"})


@dataclass(frozen=True)
class FixturePhase:
    inputs: AdapterInputs
    phase: Phase
    endpoint: Endpoint | None
    intent: Document


@dataclass(frozen=True)
class FixtureObservation:
    outcome: str
    evidence: Mapping[str, Document]


@dataclass(frozen=True)
class ReviewedDestroy:
    original: InitialRetirement
    saved_plan: bytes = field(repr=False)
    reviewed_sha256: str


@dataclass(frozen=True)
class CleanupCapture:
    hosts: Mapping[str, HostAbsence]
    external: Document
    independently_observed_sha256: str


class FixtureOperations(Protocol):
    def submit(self, work: FixturePhase) -> None:
        """Perform the fixed phase on an isolated fixture."""

    def inspect(self, work: FixturePhase) -> FixtureObservation:
        """Read the independent native fixture state without replaying the action."""

    def inspect_cleanup(self, work: FixturePhase) -> CleanupCapture:
        """Return independent host and external resource readbacks."""


@dataclass(frozen=True)
class NativePhaseDriver:
    """No provider clients, accounts, or default command execution are configured."""

    attempt: Attempt
    allocation: bytes = field(repr=False)
    reviewed: ReviewedJourney = field(repr=False)
    endpoints: Mapping[str, Endpoint] = field(repr=False)
    site_policy: bytes = field(repr=False)
    restore_inputs_directory: Path
    receiver: CutoverReceiver
    observe_local_fence: Callable[[str], dict[str, object]]
    read_ssh: ReadExecutor
    fixture: FixtureOperations
    destroy_plans: Mapping[str, ReviewedDestroy] = field(repr=False)

    def run(self, *, retry_not_applied: str | None = None) -> Document:
        result = run_journey(
            self.attempt,
            self.allocation,
            self.reviewed,
            self,
            retry_not_applied=retry_not_applied,
        )

        if result["sequenceComplete"]:
            scope = approved_scope(self.attempt, self.allocation, self.reviewed)
            self._reopen_originals(scope, None)
        return result

    def _bound(self, intent: bytes, allocation: bytes) -> tuple[Document, FixturePhase]:
        require(allocation == self.allocation, "droplet-native-driver-allocation-changed")
        inputs = AdapterInputs(self.attempt, allocation, self.reviewed, intent)
        scope, action = inputs.open(frozenset(PHASE_BY_NAME))
        phase = PHASE_BY_NAME[action["phase"]]
        require(
            self.endpoints.keys() == scope["resources"]["hosts"].keys(),
            "droplet-native-driver-endpoints-changed",
        )
        for role in action["targets"]:
            target = self.endpoints[role]
            require(target.allocation.role == role, "droplet-native-driver-endpoints-changed")
            require_endpoint(target, scope, action)
        endpoint = None if phase.role == "all" else self.endpoints[phase.role]
        return scope, FixturePhase(inputs, phase, endpoint, action)

    def _retain(self, prefix: str, key: str, document: Document) -> None:
        name = f"native-{prefix}-{key}.json"
        try:
            publish(self.attempt.directory, name, document)
        except FileExistsError:
            require(
                read(self.attempt.directory, name) == document,
                "droplet-native-original-observation-changed",
            )

    def _original(self, key: str) -> Document:
        require(
            len(key) == HEX_DIGEST_LENGTH and all(c in "0123456789abcdef" for c in key),
            "droplet-native-evidence-id-invalid",
        )
        row = read(self.attempt.directory, f"native-evidence-{key}.json")
        require(digest(row) == key, "droplet-native-original-observation-changed")
        return row

    def _prior(self, work: FixturePhase, phase: str, label: str) -> Document:
        reference = work.intent["prerequisites"][phase]
        original = read(self.attempt.directory, reference["file"])
        require(
            digest(original) == reference["sha256"] and original["outcome"] == "committed",
            "droplet-native-prerequisite-changed",
        )
        return self._original(original["evidence"][label])

    def _reopen_originals(self, scope: Document, phase: str | None) -> None:
        dispatches = committed_dispatches(self.attempt, scope)
        for predecessor in PHASES:
            if predecessor.name == phase:
                return
            require(predecessor.name in dispatches, "droplet-native-original-observation-missing")
            dispatch = dispatches[predecessor.name]
            assert dispatch.receipt is not None  # noqa: S101 - only committed dispatches
            evidence = {
                name: self._original(key) for name, key in dispatch.receipt["evidence"].items()
            }
            if predecessor.name == "teardown":
                _, work = self._bound(encode(dispatch.intent), self.allocation)
                self._require_cleanup_capture(work, evidence)

    def _restore_inputs(self) -> RestoreInputs:
        return RestoreInputs.load(self.restore_inputs_directory, owner=self.receiver.owner)

    def _cutover(self, work: FixturePhase) -> Document:
        source_reference = work.intent["prerequisites"]["backup-fence"]
        source_record = self._prior(work, "backup-fence", "sourceFence")
        # The runner verifies the prerequisite file name and content before this is read.
        source_name = source_reference["file"].removesuffix("-result.json") + "-intent.json"
        source_inputs = AdapterInputs(
            self.attempt,
            self.allocation,
            self.reviewed,
            encode(read(self.attempt.directory, source_name)),
        )
        source = self.endpoints["source"]
        destination = self.endpoints["restore"]
        restore = self._restore_inputs()
        with DurableDirectory.open(
            self.restore_inputs_directory,
            expected_owner=self.receiver.owner,
            expected_directory_mode=0o700,
        ) as protected:
            fence = protected.read_regular(
                (f"source-fence-{restore.restore_id}.json",),
                expected_owner=self.receiver.owner,
                expected_mode=0o600,
                maximum_bytes=MAX_RECORD_BYTES,
            )
        require(fence == encode(source_record), "droplet-native-original-fence-changed")
        return verify_cutover(
            RoutingEndpoint(
                source_inputs,
                source,
                prepare_routing(source_inputs, source, self.site_policy, self.read_ssh),
            ),
            RoutingEndpoint(
                work.inputs,
                destination,
                prepare_routing(work.inputs, destination, self.site_policy, self.read_ssh),
            ),
            policy_raw=self.site_policy,
            restore=restore,
            fence=fence,
            execute=self.read_ssh,
        )

    def _deliver(self, work: FixturePhase) -> None:
        cutover = self._cutover(work)
        if work.phase.name == RESUME:
            require(
                cutover == self._prior(work, REBOOT, "closedBoot"),
                "droplet-native-closed-boot-changed",
            )
        self._retain("cutover", digest(work.intent), cutover)
        self.receiver.install(encode(cutover), self.observe_local_fence)

    def _ingress(self, work: FixturePhase) -> Document:
        cutover = read(self.attempt.directory, f"native-cutover-{digest(work.intent)}.json")
        endpoint = self.endpoints["restore"]
        prepared = prepare_routing(work.inputs, endpoint, self.site_policy, self.read_ssh)
        require_prepared_cutover(work.inputs, prepared, cutover)
        self.receiver.require_installed(encode(cutover))
        inputs = self._restore_inputs()
        status = restore_status(endpoint, executor=self.read_ssh)
        require(
            status
            == {
                "restoreId": inputs.restore_id,
                "snapshotId": inputs.snapshot_id,
                "phase": "complete",
                "activationPending": False,
            }
            and inspect_host(work.inputs, endpoint, self.read_ssh)["bootSha256"]
            == prepared.boot_sha256,
            "droplet-native-ingress-unproven",
        )
        return {
            "cutoverSha256": digest(cutover),
            "bootSha256": prepared.boot_sha256,
            "status": status,
        }

    def _review_cleanup(self, work: FixturePhase) -> None:
        require(
            self.destroy_plans.keys() == work.intent["targets"].keys(),
            "droplet-native-teardown-plan-set-changed",
        )
        original = encode(self._prior(work, "retain-originals", "cleanupAuthority"))
        for role, plan in self.destroy_plans.items():
            review_destroy_plan(
                work.inputs,
                original,
                role,
                plan.original,
                plan.saved_plan,
                reviewed_sha256=plan.reviewed_sha256,
            )

    def _reconcile_cleanup(self, work: FixturePhase, capture: CleanupCapture) -> Document:
        original = self._prior(work, "retain-originals", "cleanupAuthority")
        return reconcile_teardown(
            work.inputs,
            encode(original),
            capture.hosts,
            capture.external,
            independently_observed_sha256=capture.independently_observed_sha256,
        )

    def _cleanup(self, work: FixturePhase) -> FixtureObservation:
        capture = self.fixture.inspect_cleanup(work)
        report = self._reconcile_cleanup(work, capture)
        if report["outcome"] != "reconciled":
            return FixtureObservation("unknown", {"observation": report})
        return FixtureObservation("committed", self._cleanup_evidence(capture, report))

    def _cleanup_evidence(self, capture: CleanupCapture, report: Document) -> dict[str, Document]:
        return {
            "hostAbsence": report["hosts"],
            "dnsAbsence": report["dns"],
            "archiveDisposition": report["storage"],
            "credentialClosure": report["grants"],
            "cleanupCapture": {
                "external": capture.external,
                "externalSha256": capture.independently_observed_sha256,
                "hosts": {
                    role: {
                        "stateJson": retain_empty_state(host.state_json),
                        "providerReadback": host.readback,
                    }
                    for role, host in capture.hosts.items()
                },
            },
        }

    def _require_cleanup_capture(self, work: FixturePhase, evidence: dict[str, Document]) -> None:
        original = evidence["cleanupCapture"]
        hosts = {
            role: HostAbsence(
                self.destroy_plans[role].original,
                row["stateJson"].encode("utf-8"),
                row["providerReadback"],
            )
            for role, row in original["hosts"].items()
        }
        capture = CleanupCapture(hosts, original["external"], original["externalSha256"])
        report = self._reconcile_cleanup(work, capture)
        require(
            report["outcome"] == "reconciled"
            and self._cleanup_evidence(capture, report) == evidence,
            "droplet-native-cleanup-evidence-changed",
        )

    def submit(self, intent: bytes, allocation: bytes) -> None:
        scope, work = self._bound(intent, allocation)
        phase = work.phase.name
        require(
            phase not in committed_dispatches(self.attempt, scope),
            "droplet-native-dispatch-already-committed",
        )
        key = digest(work.intent)
        try:
            publish(self.attempt.directory, f"native-submitted-{key}.json", {"intentSha256": key})
        except FileExistsError:
            raise ValidationError("droplet-native-dispatch-already-submitted") from None
        if phase in CLOSEOUT_PHASES:
            self._reopen_originals(scope, phase)
        if phase == "teardown":
            self._review_cleanup(work)
        if phase in INGRESS_PHASES:
            self._deliver(work)
        self.fixture.submit(work)

    def readback(self, intent: bytes, allocation: bytes) -> bytes:
        scope, work = self._bound(intent, allocation)
        phase = work.phase.name
        if phase in CLOSEOUT_PHASES:
            self._reopen_originals(scope, phase)
        observed = self._cleanup(work) if phase == "teardown" else self.fixture.inspect(work)
        evidence = dict(observed.evidence)
        if observed.outcome == "committed":
            if phase in INGRESS_PHASES:
                require("nativeIngress" not in evidence, "droplet-native-evidence-injected")
                evidence["nativeIngress"] = self._ingress(work)
            if phase == REBOOT:
                require("closedBoot" not in evidence, "droplet-native-evidence-injected")
                cutover = self._cutover(work)
                old = self._prior(work, "restore", "nativeIngress")
                require(
                    cutover["restoreBootSha256"] != old["bootSha256"],
                    "droplet-native-reboot-unproven",
                )
                evidence["closedBoot"] = cutover
        names = set(evidence)
        require(
            (observed.outcome == "committed" and names == work.phase.evidence)
            or (observed.outcome in {"not-applied", "failed"} and names == {"observation"})
            or (observed.outcome == "unknown" and names <= {"observation"}),
            "droplet-native-observation-invalid",
        )
        evidence_digests = {}
        for name, document in evidence.items():
            key = digest(document)
            self._retain("evidence", key, document)
            evidence_digests[name] = key
        return encode(
            {
                "format": "lowerduckpond-m3-12-droplet-journey-observation-v1",
                "intentSha256": digest(work.intent),
                "outcome": observed.outcome,
                "evidence": evidence_digests,
            }
        )
