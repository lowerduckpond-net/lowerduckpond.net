"""Fail-closed native operations on the independently enrolled production successor."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.entrypoints import _open_caddy_control_runtime
from lowerduckpond_static_host_agent.first_canary import fence_worker_view
from lowerduckpond_static_host_agent.host_restore_gate import require_restore_admission
from lowerduckpond_static_host_agent.platform_launch import initialize_launch, verify_launch
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from lowerduckpond_static_host_agent.successor_rollback import PhysicalRollback

from scripts import m3_11_production_lease as lease
from scripts import m3_11_production_records as predecessor_records
from scripts.m3_12_contracts import (
    CANARY_DROPLET,
    CANARY_TRANSACTION,
    FIRST_CANARY,
    MAX_RECORD_BYTES,
    AdmissionContext,
    Document,
    Evidence,
    decode,
    decode_launch_admission,
    digest,
    encode,
    instant,
    require,
    require_canary_decision,
)
from scripts.m3_12_successor import (
    CONFIGURATION_PHASES,
    accepted_predecessor,
    guard_configuration,
    stage_configuration,
)
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import Reconciliation, RollbackReadback

RUNTIME = Path("/run/lowerduckpond-m3-12")
LEASE = RUNTIME / "lease"
UNIT = "lowerduckpond-m3-12-action.service"
ROOT = Path("/var/lib/lowerduckpond/convergence/m3-12")
STATE = Path("/var/lib/lowerduckpond/static")
MACHINE_ID = Path("/etc/machine-id")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")
PREDECESSOR = ROOT.parent / "m3-11"
CANDIDATE = Path("/opt/lowerduckpond/static-host-agent")
PUBLICATION = Path("/etc/lowerduckpond/static-publication.json")
REQUIRE_CGROUP = Path("/proc/self/cgroup")
CGROUP_EVENTS = Path("/sys/fs/cgroup/system.slice") / UNIT / "cgroup.events"
HEX_SHA = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class NativeAuthority:
    context: AdmissionContext
    predecessor: str
    candidate: Document
    platform: Document
    preflight: Document


def read_enrollment(journal: SuccessorJournal, target: Document) -> Document:
    """Match root-enrolled host identity, not hostname or transport arguments."""
    require(not os.path.lexists("/.dockerenv"), "production-enrollment-is-disposable")
    raw = journal.read("enrollment.json")
    record = decode_json_object(raw)
    machine = MACHINE_ID.read_bytes()
    require(
        raw == encode(record)
        and record
        == {
            "format": "lowerduckpond-m3-12-production-enrollment-v1",
            "machineSha256": sha256(machine).hexdigest(),
            "inventorySha256": target["inventorySha256"],
            "leaseDomainSha256": target["leaseDomainSha256"],
        }
        and digest(record) == target["enrollmentSha256"],
        "native-production-host-changed",
    )
    return record


def decode_json_object(raw: bytes) -> Document:
    from lowerduckpond_static_contracts import decode_json_object as decode_object  # noqa: PLC0415

    return decode_object(raw)


def read_authority(journal: SuccessorJournal, token: str) -> NativeAuthority:
    """Read P4/P5 evidence from protected custody and reobserve the actual host."""
    lease.require_action(LEASE, owner=0, token=token)
    snapshot = journal.snapshot()
    original = decode(snapshot.original, "transaction")
    target = decode(journal.read("target.json"), "target")
    candidate = decode(journal.read("candidate.json"), "candidate")
    platform = decode(journal.read("platform.json"), "platform")
    require(
        target["targetKind"] == "production-host" and target["purpose"] == "production",
        "native-production-purpose-required",
    )
    read_enrollment(journal, target)
    predecessor_raw = predecessor_records.operate(PREDECESSOR, ["read"], b"", owner=0)
    predecessor_chain = predecessor_records.decode(predecessor_raw)
    prior, previous = accepted_predecessor(predecessor_chain)
    canary = original["transactionId"] == CANARY_TRANSACTION
    invoked_raw = journal.read("invocation.json")
    invocation = decode_json_object(invoked_raw)
    lease_sha = sha256(token.encode()).hexdigest()
    require(
        invoked_raw == encode(invocation)
        and set(invocation)
        == {
            "format",
            "transactionSha256",
            "invocationId",
            "leaseSha256",
            "preflightSha256",
        }
        | (set() if canary else {"qualifiedDisposablePlatformSha256"})
        and invocation["format"]
        == (
            "lowerduckpond-m3-12-first-canary-invocation-v1"
            if canary
            else "lowerduckpond-m3-12-native-invocation-v1"
        )
        and invocation["transactionSha256"] == snapshot.history.transaction_sha256
        and invocation["leaseSha256"] == lease_sha
        and not os.path.lexists(ROOT / "revoked"),
        "native-successor-invocation-changed",
    )
    binding = original["binding"]
    require(
        binding["targetSha256"] == digest(target)
        and binding["candidateSha256"] == digest(candidate)
        and binding["platformSha256"] == digest(platform)
        and target["predecessorSha256"] == original["predecessorSha256"] == prior
        and target["successorProposalSha256"] == original["originalProposalSha256"]
        and target["leaseDomainSha256"] == original["leaseDomainSha256"],
        "native-successor-original-changed",
    )
    selected = SELECTION.resolve(strict=True)
    require(
        SELECTION.is_symlink()
        and selected
        in {
            CANDIDATE / previous["candidate"]["artifact_sha256"],
            CANDIDATE / candidate["hostAgentSha256"],
        },
        "native-successor-artifact-changed",
    )
    with StateRepository(STATE, expected_owner=0) as repository:
        namespace = repository.read(StateRecordPath.platform_namespace()).document
    require(digest(namespace) == platform["namespaceSha256"], "native-successor-namespace-changed")

    key = invocation["preflightSha256"]
    preflight = Evidence({key: evidence_bytes(journal, key)}).read(key, "receipt")
    now = datetime.now(UTC)
    completed = instant(preflight["finishedAt"])
    require(
        preflight["kind"] == "live-preflight"
        and preflight["binding"] == binding
        and preflight["invocationId"] == invocation["invocationId"]
        and instant(preflight["oldestSupportingAt"])
        <= instant(preflight["startedAt"])
        <= completed
        <= now
        and (
            not snapshot.history.pending
            or snapshot.phases[-1]["invocationId"] != invocation["invocationId"]
            or completed <= snapshot.history.recorded_at
        ),
        "native-current-preflight-required",
    )
    context = AdmissionContext(
        now=now,
        invocation_id=invocation["invocationId"],
        enrolled_target=target,
        candidate_sha256=digest(candidate),
        platform_sha256=digest(platform),
        authority_sha256=original["authorizationSha256"],
        lease_sha256=lease_sha,
        run_id=binding["runId"],
        active_authority=True,
        revoked=False,
        tenant_history=False,
        tenant_generation=False,
        unfinished_lifecycle=False,
        production_identifiers=frozenset(),
        qualified_disposable_platform_sha256=invocation.get("qualifiedDisposablePlatformSha256"),
        transaction_id=original["transactionId"],
        predecessor_transaction=previous["transaction_id"],
        predecessor_head=sha256(predecessor_chain[-1][1]).hexdigest(),
    )
    if canary:
        decision = Evidence(
            {context.authority_sha256: evidence_bytes(journal, context.authority_sha256)}
        ).read(context.authority_sha256, "first-canary-decision")
        require_canary_decision(decision, target, binding, context)
        from scripts.m3_12_droplet_observe import host_identity, metadata_identity  # noqa: PLC0415

        require(
            metadata_identity()[0] == CANARY_DROPLET
            and host_identity() == decision["hostIdentity"],
            "first-canary-wrong-guest",
        )
    return NativeAuthority(context, prior, candidate, platform, preflight)


def evidence_bytes(journal: SuccessorJournal, key: str) -> bytes:
    require(
        isinstance(key, str) and HEX_SHA.fullmatch(key) is not None,
        "native-successor-evidence-key-invalid",
    )
    raw = journal.read("evidence-" + key + ".json")
    require(sha256(raw).hexdigest() == key, "native-successor-evidence-changed")
    return raw


def gate(journal: SuccessorJournal, raw: bytes, token: str) -> str:
    trusted = read_authority(journal, token)
    return guard_configuration(
        journal,
        decode_json_object(raw),
        trusted.context,
        predecessor_sha256=trusted.predecessor,
        candidate=trusted.candidate,
        state=STATE,
        directory=ROOT,
    )


def launch(journal: SuccessorJournal, token: str) -> Document:
    snapshot = journal.snapshot()
    require(
        snapshot.history.phase == "durable-launch"
        and snapshot.history.pending
        and len(snapshot.rollbacks) % 2 == 0,
        "native-successor-launch-not-pending",
    )
    trusted = read_authority(journal, token)
    require(
        SELECTION.resolve(strict=True) == CANDIDATE / trusted.candidate["hostAgentSha256"]
        and (
            (
                snapshot.phases[-1]["leaseSha256"] == trusted.context.lease_sha256
                and snapshot.phases[-1]["invocationId"] == trusted.context.invocation_id
            )
            or os.path.lexists(ROOT / "launch-intent.json")
        ),
        "native-successor-activation-not-current",
    )
    raw = journal.read("prepared-admission.json")
    admission = decode_launch_admission(raw)

    direct = admission["prerequisites"]
    require(
        direct["livePreflight"] == digest(trusted.preflight),
        "native-successor-admission-preflight-changed",
    )
    require_dark_health()
    evidence = admission_evidence(journal, admission)
    backup = evidence.read(direct["backupRestore"], "receipt")
    completed = [
        row
        for row in snapshot.phases
        if row["phase"] == "final-backup-verification" and row["transition"] == "committed"
    ]
    require(
        len(completed) == 1 and completed[0]["evidenceSha256"] == backup["observationSha256"],
        "native-successor-final-backup-changed",
    )

    def reopen_lease() -> AdmissionContext:
        # The native initializer already owns tenant-state; avoid nested access.
        lease.require_action(LEASE, owner=0, token=token)
        require(not os.path.lexists(ROOT / "revoked"), "native-successor-invocation-revoked")
        return trusted.context

    receipt = initialize_launch(STATE, ROOT, raw, evidence, reopen_lease)
    if admission["format"] == FIRST_CANARY:
        from lowerduckpond_static_host_agent.first_canary import project_launch  # noqa: PLC0415

        project_launch(journal.root, journal.owner)
    return receipt


def admission_evidence(journal: SuccessorJournal, admission: Document) -> Evidence:
    records = {key: evidence_bytes(journal, key) for key in admission["prerequisites"].values()}
    if admission["format"] == FIRST_CANARY:
        key = admission["authoritySha256"]
        records[key] = evidence_bytes(journal, key)
        return Evidence(records)
    report_key = admission["prerequisites"]["completeDisposable"]
    report = Evidence(records).read(report_key, "report")
    require(report["completion"]["kind"] == "complete-disposable", "wrong-disposable-proof")
    keys = {report["sealSha256"], *report["completion"]["receipts"].values()}
    records.update({key: evidence_bytes(journal, key) for key in keys})
    seal = Evidence(records).read(report["sealSha256"], "seal")
    keys = {seal["admissionSha256"], seal["launchReceiptSha256"]}
    records.update({key: evidence_bytes(journal, key) for key in keys})
    prior = Evidence(records).read(seal["admissionSha256"], "admission")
    receipt = Evidence(records).read(seal["launchReceiptSha256"], "launch-receipt")
    keys = {
        receipt["launchRecordSha256"],
        receipt["intentSha256"],
        *prior["prerequisites"].values(),
    }
    records.update({key: evidence_bytes(journal, key) for key in keys})
    return Evidence(records)


def _systemctl(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - fixed native unit and operations
        ["/usr/bin/systemctl", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def require_dark_health() -> None:
    require_restore_admission()
    with DurableDirectory.open(
        PUBLICATION.parent, expected_owner=0, expected_directory_mode=0o700
    ) as config:
        current = decode_json_object(
            config.read_regular(
                (PUBLICATION.name,), expected_owner=0, expected_mode=0o400, maximum_bytes=4096
            )
        )
    require(
        current
        == {
            "format": "lowerduckpond-static-publication-gate-v1",
            "static_publication_enabled": False,
        },
        "native-successor-launch-requires-dark-state",
    )
    health = subprocess.run(
        ["/usr/local/libexec/lowerduckpond/check-caddy-publication-open"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    require(health.returncode == 0 and health.stdout == b"current\n", "native-successor-unhealthy")


def phase(journal: SuccessorJournal, operation: str, token: str) -> Document:
    trusted = read_authority(journal, token)
    current = journal.snapshot()
    require(
        trusted.context.transaction_id != CANARY_TRANSACTION
        or current.history.phase != "acceptance",
        "first-canary-customer-acceptance-closed",
    )
    record = decode_json_object(journal.read("phase-readback.json"))
    require(
        set(record)
        == {
            "format",
            "transactionSha256",
            "priorHeadSha256",
            "phase",
            "invocationId",
            "leaseSha256",
            "readbackSha256",
            "outcome",
            "processDrained",
            "originalPreconditions",
            "configurationSha256",
        }
        and record["format"] == "lowerduckpond-m3-12-native-phase-readback-v1"
        and record["transactionSha256"] == current.history.transaction_sha256
        and record["priorHeadSha256"] == current.history.head_sha256
        and record["phase"] == current.history.phase
        and record["invocationId"] == trusted.context.invocation_id
        and record["leaseSha256"] == trusted.context.lease_sha256
        and record["processDrained"] is True
        and type(record["originalPreconditions"]) is bool,
        "native-successor-readback-changed",
    )
    raw = evidence_bytes(journal, record["readbackSha256"])
    if operation == "reconcile" and current.history.phase == "durable-launch":
        if record["outcome"] == "committed":
            require(
                raw == encode(verify_launch(STATE, ROOT)),
                "native-successor-launch-readback-changed",
            )
        else:
            require(
                not os.path.lexists(ROOT / "launch-intent.json"),
                "native-successor-launch-resume-required",
            )
    if operation == "start":
        transition = "started"
    else:
        transition = "committed" if record["outcome"] == "committed" else "not-applied"
    return journal.advance(
        transition,
        trusted.context,
        Reconciliation(
            evidence_sha256=record["readbackSha256"],
            outcome=record["outcome"],
            drained=True,
            preconditions_hold=record["originalPreconditions"],
            stage_configuration_sha256=record["configurationSha256"],
        ),
    )


def physical(journal: SuccessorJournal, token: str, operation: str) -> Document:
    trusted = read_authority(journal, token)
    with (
        _open_caddy_control_runtime() as runtime,
        CaddyStartupStore.open(Path("/etc/caddy/intents"), expected_owner=0) as startup,
    ):
        engine = PhysicalRollback(
            STATE,
            ROOT,
            PUBLICATION,
            runtime,
            require_lease=lambda: lease.require_action(LEASE, owner=0, token=token),
            restart=lambda: _systemctl("restart", "caddy.service"),
            startup=startup,
        )
        if operation == "pin-predecessor":
            require(
                journal.snapshot().history.phase == "preparation", "native-successor-not-preparing"
            )
            return engine.pin_predecessor()
        current = journal.snapshot()
        raw = journal.read("rollback-request.json")
        decision = decode(raw, "rollback")
        require(
            decision["transactionSha256"] == current.history.transaction_sha256
            and decision["priorHeadSha256"] == current.history.head_sha256,
            "native-successor-rollback-head-changed",
        )

        def authorize() -> None:
            if operation == "resume-rollback":
                require(
                    bool(current.rollbacks) and current.rollbacks[-1] == decision,
                    "native-successor-original-rollback-missing",
                )
                if trusted.context.transaction_id == CANARY_TRANSACTION:
                    fence_worker_view(journal.root, journal.owner, closed=True)
                return
            require(
                not current.rollbacks or current.rollbacks[-1] != decision,
                "native-successor-use-rollback-resume",
            )
            authority = decode_json_object(journal.read("rollback-readback.json"))
            require(
                authority
                == {
                    "format": "lowerduckpond-m3-12-native-rollback-readback-v1",
                    "invocationId": trusted.context.invocation_id,
                    "authorizationSha256": decision["authorizationSha256"],
                    "readbackSha256": decision["readbackSha256"],
                    "samePolicy": True,
                },
                "native-successor-rollback-authorization-changed",
            )
            evidence_bytes(journal, decision["readbackSha256"])
            journal.rollback(
                raw,
                trusted.context,
                RollbackReadback(
                    invocation_id=trusted.context.invocation_id,
                    authorization_sha256=authority["authorizationSha256"],
                    evidence_sha256=authority["readbackSha256"],
                    preceding_generation_sha256=decision["precedingGenerationSha256"],
                    retained_launch_sha256=decision["retainedLaunchSha256"],
                    retained_intent_sha256=decision["retainedIntentSha256"],
                    drained=True,
                    platform_only_compatible=True,
                    irreversible_history=False,
                    policy_unchanged=True,
                    rollback_active=len(current.rollbacks) % 2 == 1,
                ),
            )
            if trusted.context.transaction_id == CANARY_TRANSACTION:
                fence_worker_view(journal.root, journal.owner, closed=True)

        result = engine.reconcile(decision, authorize=authorize)
        if (
            trusted.context.transaction_id == CANARY_TRANSACTION
            and decision["action"] == "reactivate-same-policy"
        ):
            require(
                journal.snapshot().rollbacks[-1] == decision
                and len(journal.snapshot().rollbacks) % 2 == 0
                and not os.path.lexists(ROOT / "publication-fence.json"),
                "first-canary-rollback-pending",
            )
            fence_worker_view(journal.root, journal.owner, closed=False)
        return result


def drain_unit(unit: str, events_file: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed successor unit
        ["/usr/bin/systemctl", "stop", unit], capture_output=True, check=False
    )
    if result.returncode:
        state = subprocess.run(  # noqa: S603 - fixed successor unit and field
            ["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"],
            capture_output=True,
            check=False,
        )
        require(state.stdout == b"not-found\n", "native-successor-action-not-drained")
    try:
        events = events_file.read_text(encoding="ascii")
    except FileNotFoundError:
        return
    require("populated 0" in events.splitlines(), "native-successor-action-still-running")


def drain() -> None:
    drain_unit(UNIT, CGROUP_EVENTS)


def dispatch(journal: SuccessorJournal, arguments: list[str]) -> int:
    if arguments == ["owner"]:
        target = decode(journal.read("target.json"), "target")
        require(target["targetKind"] == "production-host", "native-production-purpose-required")
        read_enrollment(journal, target)
        RUNTIME.mkdir(mode=0o700, exist_ok=True)
        LEASE.mkdir(mode=0o700, exist_ok=True)
        with lease.controller(LEASE, owner=0, drain=drain) as token:
            print(token, flush=True)
            require(
                sys.stdin.buffer.read(8) in {b"", b"release\n"}, "native-successor-control-invalid"
            )
        return 0
    require(
        REQUIRE_CGROUP.read_text(encoding="ascii") == f"0::/system.slice/{UNIT}\n",
        "native-successor-outside-action",
    )
    operation, token, *extra = arguments
    if operation == "gate":
        require(not extra, "native-successor-command-invalid")
        raw = sys.stdin.buffer.read(MAX_RECORD_BYTES + 1)
        require(len(raw) <= MAX_RECORD_BYTES, "native-successor-command-invalid")
        print(gate(journal, raw, token))
        return 0
    with lease.action(LEASE, owner=0, token=token):
        return _under_action(journal, operation, token, extra)


def _under_action(journal: SuccessorJournal, operation: str, token: str, extra: list[str]) -> int:
    if operation == "action" and len(extra) == 1:
        trusted = read_authority(journal, token)
        phase_name = journal.snapshot().history.phase
        if phase_name not in CONFIGURATION_PHASES or phase_name is None:
            raise ValueError("native-successor-no-configuration-stage")
        guard_configuration(
            journal,
            stage_configuration(phase_name, trusted.candidate["hostAgentSha256"]),
            trusted.context,
            predecessor_sha256=trusted.predecessor,
            candidate=trusted.candidate,
            state=STATE,
            directory=ROOT,
        )
        return subprocess.call(["/bin/sh", "-c", extra[0]])  # noqa: S603 - leased Ansible channel
    require(not extra, "native-successor-command-invalid")
    if operation == "launch":
        result = launch(journal, token)
    elif operation in {"start", "reconcile"}:
        result = phase(journal, operation, token)
    elif operation in {"pin-predecessor", "rollback", "resume-rollback"}:
        result = physical(journal, token, operation)
    else:
        raise ValueError("native-successor-command-invalid")
    sys.stdout.buffer.write(encode(result))
    return 0


def main() -> int:
    try:
        require(os.geteuid() == 0, "native-successor-root-required")
        with DurableDirectory.open(ROOT, expected_owner=0, expected_directory_mode=0o700) as root:
            return dispatch(SuccessorJournal(root, 0), sys.argv[1:])
    except Exception:
        print("m3_12_successor_action_refused", file=sys.stderr)
        return 2
