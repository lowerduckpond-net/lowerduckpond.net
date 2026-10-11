"""Separate original functional history, lease-bounded recovery, and fresh final proof."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_unattended import inputs
from scripts.m3_11_unattended.model import LeasePolicy, digest, instant

HISTORICAL_SPAN = timedelta(hours=24)
SUMMARY_FIELDS = {
    "functional_completed_at",
    "completed_at",
    "original_outcome",
    "original_result_sha256",
    "checkpoint_sha256",
}
OBSERVATION_FIELDS = {
    "started_at",
    "cleanup_completed_at",
    "storage_started_at",
    "storage_completed_at",
    "completed_at",
    "checks",
    "combined_sha256",
    "context_sha256",
    "checkpoint_sha256",
    "dns_sha256",
}
CHECKS = dict.fromkeys(("owned_resources_absent", "dns_absent", "storage_private_empty"), "passed")


@dataclass(frozen=True)
class Window:
    functional_at: datetime
    deadline: datetime

    @property
    def maximum_age(self) -> timedelta:
        # This bounds historical validation at the ORIGINAL packaging time.
        # It is not the consumer freshness window for final observations.
        return self.deadline - self.functional_at + HISTORICAL_SPAN

    @classmethod
    def from_evidence(cls, managed: dict[str, object], summary: dict[str, object]) -> Window:
        pair = evidence.fields(managed["receipts"], {"production", "fixture"})
        fixture = pair["fixture"]
        if not isinstance(fixture, dict) or fixture.get("format") != inputs.LEASE_FIXTURE_FORMAT:
            raise ValueError("recovery requires the original approved managed lease")
        policy = LeasePolicy.parse(fixture["lease_policy"])
        issued = instant(fixture["lease_issued_at"])
        deadline = instant(fixture["deadline"])
        completed = evidence.parse_timestamp(summary["functional_completed_at"])
        if (
            not policy.retain_after_failure
            or deadline != policy.deadline(issued)
            or not issued <= completed < deadline
        ):
            raise ValueError("functional recovery is outside its approved retained lease")
        return cls(completed, deadline)

    def validate(self, report: dict[str, object], *, now: datetime, freshness: timedelta) -> None:
        recovery = evidence.fields(
            report["finalization_recovery"], SUMMARY_FIELDS | {"final_observation"}
        )
        observation = evidence.fields(recovery["final_observation"], OBSERVATION_FIELDS)
        proof = report["combined"]
        if not isinstance(proof, dict):
            raise ValueError("recovery combined evidence is invalid")
        context = proof["context"]
        phases = evidence.fields(proof["phases"], set(evidence.PHASE_CHECKS))
        legacy = evidence.fields(
            report["legacy_observations"], {"storage_at", "installed_at", "phases"}
        )
        legacy_phases = evidence.fields(
            legacy["phases"], {"create", "prepare", "converge", "idempotence", "verify", "destroy"}
        )
        if not isinstance(context, dict):
            raise ValueError("recovery context is invalid")
        historical = [
            context["captured_at"],
            report["oldest_evidence_at"],
            legacy["storage_at"],
            legacy["installed_at"],
        ]
        historical.extend(
            legacy_phases[name] for name in ("create", "prepare", "converge", "idempotence")
        )
        for name, phase in phases.items():
            value = evidence.fields(
                phase, {"started_at", "completed_at", "checks", "evidence_sha256"}
            )
            if name != "owned-teardown":
                historical.extend((value["started_at"], value["completed_at"]))
        for value in historical:
            evidence.timestamp(value, now=self.functional_at, maximum_age=HISTORICAL_SPAN)
        teardown = evidence.fields(
            phases["owned-teardown"], {"started_at", "completed_at", "checks", "evidence_sha256"}
        )
        observed = [
            evidence.parse_timestamp(observation[key])
            for key in (
                "started_at",
                "cleanup_completed_at",
                "storage_started_at",
                "storage_completed_at",
                "completed_at",
            )
        ]
        packaged = evidence.parse_timestamp(report["packaged_at"])
        original_completed = evidence.parse_timestamp(recovery["completed_at"])
        if (
            recovery["original_outcome"] not in {"failed", "interrupted"}
            or not self.functional_at <= evidence.parse_timestamp(teardown["started_at"])
            or not evidence.parse_timestamp(teardown["completed_at"]) <= observed[1]
            or observed != sorted(observed)
            or not self.functional_at <= observed[0] <= observed[-1] <= packaged < self.deadline
            or not evidence.parse_timestamp(report["completed_at"])
            <= original_completed
            <= packaged
            or observation["checks"] != CHECKS
            or observation["combined_sha256"] != digest(proof)
            or observation["context_sha256"] != digest(context)
            or observation["checkpoint_sha256"] != recovery["checkpoint_sha256"]
        ):
            raise ValueError("recovery final observations or lease chronology are invalid")
        for key in ("original_result_sha256", "checkpoint_sha256"):
            evidence.digest(recovery[key])
        evidence.digest(observation["dns_sha256"])
        # Publication and consumption each use this actual observation time;
        # the original functional/teardown timestamps are never refreshed.
        evidence.timestamp(observation["started_at"], now=packaged, maximum_age=HISTORICAL_SPAN)
        evidence.timestamp(observation["started_at"], now=now, maximum_age=freshness)
