"""Resume the scoped P4 journey through explicitly supplied execution adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from scripts.m3_12_contracts import Document, decode, digest, encode, require
from scripts.m3_12_diagnostic_store import Attempt, clock, failure, publish, read
from scripts.m3_12_droplet_scope import ReviewedJourney, approved_scope


@dataclass(frozen=True)
class Phase:
    name: str
    role: str
    needs: tuple[str, ...]
    evidence: frozenset[str]


def _phase(name: str, role: str, needs: tuple[str, ...], *evidence: str) -> Phase:
    return Phase(name, role, needs, frozenset(evidence))


PHASES = (
    _phase("predecessor", "source", (), "pristine", "acceptedPredecessor", "bootstrap"),
    _phase("dark-stage", "source", ("predecessor",), "convergence", "darkHealth"),
    _phase("dark-repeat", "source", ("dark-stage",), "zeroChange"),
    _phase("launch", "source", ("dark-repeat",), "launchReceipt"),
    _phase("enabled-converge", "source", ("launch",), "convergence", "publication"),
    _phase("enabled-repeat", "source", ("enabled-converge",), "zeroChange"),
    _phase(
        "rollback-resume", "source", ("enabled-repeat",), "selector", "rollback", "reactivation"
    ),
    _phase("source-reboot", "source", ("rollback-resume",), "bootTransition", "nativeReadback"),
    _phase(
        "functional",
        "source",
        ("source-reboot",),
        "installedMatrix",
        "forcedSsh",
        "lifecycle",
        "archiveSdk",
        "failureRecovery",
    ),
    _phase("edge", "source", ("functional",), "edge", "browser", "acme", "originPull"),
    _phase("capacity", "source", ("functional",), "overlap", "originalSamples", "reserves"),
    _phase(
        "backup-fence",
        "source",
        ("edge", "capacity"),
        "originalBackup",
        "sourceFence",
        "archiveInventory",
    ),
    _phase(
        "cold-install",
        "restore",
        ("backup-fence",),
        "emptyCertificateStore",
        "closedIngress",
        "protectedDelivery",
    ),
    _phase(
        "restore",
        "restore",
        ("cold-install",),
        "exactSnapshot",
        "archiveVersions",
        "excludedState",
    ),
    _phase(
        "restore-reboot",
        "restore",
        ("restore",),
        "bootTransition",
        "statusReadback",
        "ingress",
    ),
    _phase("fresh-install", "fresh", (), "pristine", "darkReadback", "freshAcceptance"),
    _phase("fresh-reboot", "fresh", ("fresh-install",), "bootTransition", "nativeReadback"),
    _phase(
        "retain-originals",
        "all",
        ("restore-reboot", "fresh-reboot"),
        "originalEvidence",
        "independentReopen",
    ),
    _phase(
        "teardown",
        "all",
        ("retain-originals",),
        "hostAbsence",
        "dnsAbsence",
        "archiveDisposition",
        "credentialClosure",
    ),
)


class Driver(Protocol):
    """Trusted adapters use their existing leases, native commands and independent readback."""

    def submit(self, intent: bytes, allocation: bytes) -> None:
        """Perform only the named phase under the allocation and native authority."""

    def readback(self, intent: bytes, allocation: bytes) -> bytes:
        """Return an allowlisted observation from native state, with original evidence digests."""


def _load(attempt: Attempt, name: str) -> Document | None:
    try:
        return read(attempt.directory, name)
    except FileNotFoundError:
        return None


def _receipt(raw: bytes, phase: Phase, intent: Document, *, stored: bool = False) -> Document:
    record = decode(raw, "droplet-journey-observation")
    outcome = record["outcome"]
    evidence = set(record["evidence"])
    require(
        record["intentSha256"] == digest(intent)
        and (
            (outcome == "committed" and evidence == phase.evidence)
            or (outcome in {"failed", "not-applied"} and evidence == {"observation"})
            or (outcome == "unknown" and not stored and evidence <= {"observation"})
        ),
        "droplet-journey-evidence-changed",
    )
    return record


@dataclass(frozen=True)
class Dispatch:
    key: str
    intent: Document
    receipt: Document | None = None


def _outcome(dispatch: Dispatch | None) -> str | None:
    if dispatch is None or dispatch.receipt is None:
        return None
    outcome: str = dispatch.receipt["outcome"]
    return outcome


def _intent(
    scope: Document,
    phase: Phase,
    entries: dict[str, Dispatch],
    previous_no_effect: Document | None,
) -> Document:
    roles = scope["resources"]["hosts"]
    subjects = {
        role: digest(host["target"]) for role, host in roles.items() if phase.role in (role, "all")
    }
    return {
        "format": "lowerduckpond-m3-12-droplet-journey-intent-v1",
        "allocationSha256": digest(scope),
        "phase": phase.name,
        "targets": subjects,
        "prerequisites": {
            name: {
                "file": f"{entries[name].key}-result.json",
                "sha256": digest(entries[name].receipt),
            }
            for name in phase.needs
        },
        "priorNoEffectSha256": None if previous_no_effect is None else digest(previous_no_effect),
    }


def _key(phase: Phase, previous_no_effect: Document | None) -> str:
    base = f"journey-{phase.name}"
    return base if previous_no_effect is None else f"{base}-{digest(previous_no_effect)}"


def _originals(attempt: Attempt, scope: Document) -> dict[str, Dispatch]:
    entries: dict[str, Dispatch] = {}
    # Reopen the original dependency chain and any verified no-effect retries.
    for phase in PHASES:
        previous = None
        while True:
            key = _key(phase, previous)
            intent = _load(attempt, f"{key}-intent.json")
            receipt = _load(attempt, f"{key}-result.json")
            if intent is None:
                require(receipt is None, "droplet-journey-intent-missing")
                break
            require(
                all(_outcome(entries.get(name)) == "committed" for name in phase.needs)
                and intent == _intent(scope, phase, entries, previous),
                "droplet-journey-intent-changed",
            )
            if receipt is not None:
                receipt = _receipt(encode(receipt), phase, intent, stored=True)
            entries[phase.name] = Dispatch(key, intent, receipt)
            if receipt is None or receipt["outcome"] != "not-applied":
                break
            previous = receipt
    return entries


def _retain_readback(attempt: Attempt, dispatch: Dispatch, record: Document) -> None:
    name = f"{dispatch.key}-observation-{digest(record)}.json"
    earlier = _load(attempt, name)
    if earlier is None:
        publish(attempt.directory, name, record)
    else:
        require(earlier == record, "droplet-journey-observation-changed")


def _advance(  # noqa: PLR0913 - one fixed phase and its independent dispatch/readback inputs
    attempt: Attempt,
    phase: Phase,
    dispatch: Dispatch,
    raw: bytes,
    driver: Driver,
    *,
    pending: bool,
) -> Document | None:
    started = clock()
    witness = encode(dispatch.intent)
    try:
        if not pending:
            driver.submit(witness, raw)
        record = _receipt(driver.readback(witness, raw), phase, dispatch.intent)
    except (OSError, RuntimeError) as error:
        # The persisted intent is still pending. The exception is not evidence
        # about whether the action ran. Store only the existing safe projection.
        attempt.append(
            "inspection",
            "controller",
            started,
            outcome="uncertain",
            incident=failure("primary", "controller", "controller", error),
        )
        return None
    if record["outcome"] == "unknown":
        _retain_readback(attempt, dispatch, record)
        return None
    publish(attempt.directory, f"{dispatch.key}-result.json", record)
    return record


def run_journey(
    attempt: Attempt,
    raw: bytes,
    reviewed: ReviewedJourney,
    driver: Driver,
    *,
    retry_not_applied: str | None = None,
) -> Document:
    """Run eligible phases. A persisted intent permits readback only on reentry."""
    scope = approved_scope(attempt, raw, reviewed)
    with attempt.lock("droplet-journey.lock", blocking=False):
        retained = _load(attempt, "journey-allocation.json")
        if retained is None:
            # Other files can only have been written after the original allocation.
            require(
                not any(attempt.directory.glob("journey-*.json")),
                "droplet-journey-original-missing",
            )
            publish(attempt.directory, "journey-allocation.json", scope)
        else:
            require(retained == scope, "droplet-journey-original-changed")
        entries = _originals(attempt, scope)
        if retry_not_applied is not None:
            require(
                _outcome(entries.get(retry_not_applied)) == "not-applied",
                "droplet-journey-retry-not-proven",
            )
        states: dict[str, str] = {}
        for phase in PHASES:
            name = phase.name
            prior = entries.get(name)
            receipt = None if prior is None else prior.receipt
            if all(states.get(key) == "committed" for key in phase.needs) and (
                receipt is None or name == retry_not_applied
            ):
                if receipt is not None and prior is not None:
                    # Preserve the original no-effect result and require a new
                    # independent no-effect read before any further submission.
                    current = _receipt(
                        driver.readback(encode(prior.intent), raw), phase, prior.intent
                    )
                    _retain_readback(attempt, prior, current)
                    require(current["outcome"] == "not-applied", "droplet-journey-retry-not-proven")
                    prior = None
                if prior is None:
                    dispatch = Dispatch(
                        _key(phase, receipt), _intent(scope, phase, entries, receipt)
                    )
                    publish(attempt.directory, f"{dispatch.key}-intent.json", dispatch.intent)
                else:
                    dispatch = prior
                result = _advance(attempt, phase, dispatch, raw, driver, pending=prior is not None)
                entries[name] = Dispatch(dispatch.key, dispatch.intent, result)
                states[name] = "uncertain" if result is None else result["outcome"]
            else:
                states[name] = "blocked" if receipt is None else receipt["outcome"]
        return {
            "format": "lowerduckpond-m3-12-droplet-journey-progress-v1",
            "allocationSha256": digest(scope),
            "phases": states,
            "sequenceComplete": all(state == "committed" for state in states.values()),
        }
