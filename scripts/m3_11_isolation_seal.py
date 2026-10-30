"""Seal only a genuine isolated recovery and independently closed obligations.

This is a separate prerequisite, never a combined qualification result. The live
entry captures GitHub evidence through authenticated fixed GETs; accepting a
caller-provided status dictionary cannot release native admission.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from scripts import m3_11_public_caddy as policy
from scripts.m3_11_isolation_github import Proof, capture
from scripts.m3_11_isolation_host import Host
from scripts.m3_11_isolation_journal import Journal, collect
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import record
from scripts.m3_11_unattended.model import digest, fingerprint, instant, stamp

FORMAT = "lowerduckpond-isolated-public-ca-prerequisite-v1"


def native(raw: object) -> dict[str, object]:
    envelope = fields(raw, {"sha256", "value"})
    if not isinstance(envelope["value"], dict) or digest(envelope["value"]) != envelope["sha256"]:
        raise ValueError("isolated native original record digest differs")
    return envelope["value"]


def functional(host: Host) -> dict[str, object]:  # noqa: PLR0912 - complete native observation graph
    """Validate the native producer's complete original observation graph."""
    phase = host.phase
    result = read_private(phase / "isolation-functional.json")
    observations = fields(
        read_private(phase / "isolation-observations.json"),
        {
            "original",
            "interrupted",
            "interruption_cleanup",
            "rebooted",
            "tls",
            "opened",
            "restored",
            "dns_activity_sha256",
            "dns_cleanup_sha256",
        },
    )
    context = read_private(phase / "isolation-context.json")
    if result.get("observations_sha256") != digest(observations):
        raise ValueError("isolated functional observations changed")
    original = native(observations["original"])
    if (
        original.get("context_sha256") != digest(context)
        or original.get("binary_sha256") != host.manifest.plan.caddy_binary_sha256
        or original.get("nonce") != host.manifest.plan.nonce
        or original.get("journal_sha256")
        != cast(dict[str, object], host.prepared["restore"])["journal_sha256"]
        or original.get("isolation_network") != host.manifest.plan.network.document()
    ):
        raise ValueError("isolated original native public inputs differ")
    interrupted = fields(native(observations["interrupted"]), {"storage", "pid_one"})
    rebooted = fields(native(observations["rebooted"]), {"storage", "pid_one"})
    if (
        not isinstance(interrupted["storage"], dict)
        or not interrupted["storage"]
        or interrupted["storage"] != rebooted["storage"]
        or interrupted["pid_one"] == rebooted["pid_one"]
    ):
        raise ValueError("isolated actual interrupted account/reboot continuity is absent")
    tls = fields(observations["tls"], {"issuer", "certificates"})
    certificates = tls["certificates"]
    if tls["issuer"] != policy.ISSUER_STORAGE or not isinstance(certificates, list):
        raise ValueError("isolated TLS issuer is not the pinned production CA")
    subjects = []
    for certificate in certificates:
        item = fields(certificate, {"subject", "leafSha256"})
        subjects.append(item["subject"])
        fingerprint(item["leafSha256"])
    if subjects != list(policy.disposable_subjects(host.manifest.plan.nonce)):
        raise ValueError("isolated native TLS subjects differ")
    if native(observations["opened"]) != {"tls_sha256": digest(tls)} or native(
        observations["restored"]
    ) != {"journal_sha256": original["journal_sha256"]}:
        raise ValueError("isolated native readiness/restoration proof differs")
    activity = observations["dns_activity_sha256"]
    if not isinstance(activity, list) or not activity:
        raise ValueError("isolated DNS publication has no original observations")
    host._observed_records()  # Validate native record coordinates, identities and bounds.
    files = {
        digest(read_private(path)): read_private(path)
        for path in (phase / "isolation-dns").glob("*.json")
    }
    seen: set[str] = set()
    for activity_digest in activity:
        fingerprint(activity_digest)
        observation = files.get(str(activity_digest))
        if (
            observation is None
            or observation.get("kind") != "activity"
            or observation.get("context_sha256") != digest(context)
        ):
            raise ValueError("isolated DNS activity hash has no original native observation")
        zones = fields(observation["zones"], set(host.manifest.plan.zones))
        for domain, zone in zones.items():
            selected = cast(dict[str, object], zone)
            if selected.get("records"):
                seen.add(domain)
    interruption = fields(
        observations["interruption_cleanup"], {"activity_sha256", "absence_sha256"}
    )
    for cleanup_digest in (interruption["absence_sha256"], observations["dns_cleanup_sha256"]):
        observation = files.get(fingerprint(cleanup_digest))
        if (
            observation is None
            or observation.get("kind") != "cleanup"
            or observation.get("context_sha256") != digest(context)
            or any(
                cast(dict[str, object], zone).get("records") != []
                for zone in cast(dict[str, object], observation["zones"]).values()
            )
        ):
            raise ValueError("isolated native challenge cleanup was not observed")
    if seen != set(host.manifest.plan.zones):
        raise ValueError("isolated actual publication did not cover both zones")
    return result


def seal(
    host: Host, journal: Journal, *, run_id: int, api: Callable[[str], bytes] | None = None
) -> dict[str, object]:
    """Capture a current independent proof, preserve the exact prerequisite."""
    host.require(consumed=True)
    host.controller_stopped()
    for name in ("source", "destination", "archive", "acme"):
        actor = host.actor(name)
        if actor["running"] is not False or actor["pid"] != 0 or actor["restart_policy"] != "no":
            raise ValueError("isolated prerequisite consumers are not stopped")
    manifest = host.manifest
    records = collect(journal.all_records(), manifest)
    facts = {row["kind"]: row["payload"] for row in records}
    required = {
        "prepared",
        "context",
        "issued",
        "phase-started",
        "functional",
        "quiesced",
        "dns-clean",
        "closed",
        "readback",
    }
    if not required <= set(facts):
        raise ValueError("isolated prerequisite lacks required native closure facts")
    result = functional(host)
    if (
        facts["functional"] != result
        or facts["closed"] != read_private(host.credentials / "closed.json")
        or facts["dns-clean"] != read_private(host.phase / "isolation-dns-clean.json")
    ):
        raise ValueError("isolated original and independently published evidence differ")
    closure = cast(dict[str, object], facts["closed"])
    roles = fields(closure["roles"], {"audit", "caddy", "observer"})
    issued = fields(cast(dict[str, object], facts["issued"])["ids"], set(roles))
    if any(
        value
        != {"credential_id": issued[role], "provider_absent": True, "authentication": "denied"}
        for role, value in roles.items()
    ):
        raise ValueError("isolated passing prerequisite requires all three actual children closed")
    proof: Proof = capture(manifest, run_id, operation="reconcile", api=api)
    readbacks = [
        cast(dict[str, object], row["payload"]) for row in records if row["kind"] == "readback"
    ]
    if proof.receipt.get("closure_sha256") != digest(closure) or not any(
        value.get("closure_sha256") == digest(closure)
        and value.get("github") == proof.receipt["github"]
        for value in readbacks
    ):
        raise ValueError(
            "isolated independent final readback differs from its authenticated artifact"
        )
    if instant(proof.receipt["observed_at"]) < instant(
        cast(dict[str, object], facts["quiesced"])["observed_at"]
    ):
        raise ValueError("isolated final independent proof predates consumer stop")
    value: dict[str, object] = {
        "format": FORMAT,
        "status": "passed",
        "qualification_authority": "none",
        "manifest_sha256": manifest.sha256,
        "plan_sha256": manifest.plan.sha256,
        "source_revision": manifest.plan.source_revision,
        "caddy_binary_sha256": manifest.plan.caddy_binary_sha256,
        "network": manifest.plan.network.document(),
        "prepared_sha256": manifest.plan.preparation_sha256,
        "context_sha256": digest(facts["context"]),
        "functional_sha256": digest(result),
        "closure_sha256": digest(closure),
        "independent": proof.provenance,
        "observed_at": stamp(datetime.now(UTC)),
    }
    # Recheck native state after the bounded external proof collection.
    host.require(consumed=True)
    for name in ("controller", "source", "destination", "archive", "acme"):
        actor = host.actor(name)
        if actor["running"] is not False or actor["pid"] != 0 or actor["restart_policy"] != "no":
            raise ValueError("isolated consumers changed during final proof capture")
    record(host.root / "prerequisite.json", value)
    return value
