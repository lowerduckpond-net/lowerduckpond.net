"""Root-side launch on an enrolled, leased disposable Droplet."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_host_agent.droplet_enrollment import (
    PUBLICATION_VIEW,
    DropletEnrollment,
    protected_record,
    read_enrollment,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.platform_launch import initialize_launch

from scripts import m3_11_production_lease as lease
from scripts.m3_12_contracts import (
    AdmissionContext,
    Document,
    Evidence,
    decode,
    digest,
    require,
)
from scripts.m3_12_droplet_observe import metadata_identity
from scripts.m3_12_native import require_dark_health

ROOT = Path("/var/lib/lowerduckpond/convergence/m3-12")
STATE = Path("/var/lib/lowerduckpond/static")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")
LEASE = Path("/run/lowerduckpond-m3-12-droplet/lease")


def require_metadata(enrolled: DropletEnrollment, observed: tuple[int, str]) -> None:
    droplet_id, ipv4 = observed
    target = enrolled.target["droplet"]
    require(
        droplet_id == target["dropletId"]
        and ipv4 == enrolled.registration["ipv4"]
        and digest({"dropletId": droplet_id, "ipv4": ipv4}) == target["metadataIdentitySha256"],
        "droplet-metadata-changed",
    )


def _selected_candidate(candidate: Document) -> bool:
    return SELECTION.is_symlink() and (
        SELECTION.resolve(strict=True) == SELECTION.parent / candidate["hostAgentSha256"]
    )


def launch(token: str, raw: bytes, *, owner: int = 0) -> Document:
    """Use the original protected enrollment and current action lease for the common writer."""
    admission = decode(raw, "admission")
    with (
        DurableDirectory.open(ROOT, expected_owner=owner, expected_directory_mode=0o700) as root,
        root.open_descendant((PUBLICATION_VIEW,)) as publication,
    ):
        enrolled = read_enrollment(ROOT / PUBLICATION_VIEW, publication, owner=owner)
        enrolled.require_binding(admission["binding"])
        # This read can be interrupted before any action or publication lock is held.
        observed = metadata_identity()
        require_metadata(enrolled, observed)
        with lease.action(LEASE, owner=owner, token=token):
            return _launch_locked(
                root, publication, enrolled, admission, raw=raw, token=token, owner=owner
            )


def _launch_locked(  # noqa: PLR0913 - bind protected files, original admission and active lease
    root: DurableDirectory,
    publication: DurableDirectory,
    enrolled: DropletEnrollment,
    admission: Document,
    *,
    raw: bytes,
    token: str,
    owner: int,
) -> Document:
    lease_digest = sha256(token.encode()).hexdigest()
    attempt = decode(
        protected_record(root, f"droplet-attempt-{lease_digest}.json", owner),
        "droplet-launch-attempt",
    )
    require(
        attempt["binding"] == admission["binding"]
        and attempt["invocationId"] == admission["invocationId"]
        and attempt["leaseSha256"] == lease_digest == admission["leaseSha256"]
        and _selected_candidate(admission["candidate"]),
        "droplet-launch-attempt-changed",
    )
    evidence = Evidence(
        {
            key: protected_record(root, f"evidence-{key}.json", owner)
            for key in admission["prerequisites"].values()
        }
    )
    require_dark_health()

    def observe() -> AdmissionContext:
        lease.require_action(LEASE, owner=owner, token=token)
        require(
            read_enrollment(ROOT / PUBLICATION_VIEW, publication, owner=owner) == enrolled
            and _selected_candidate(admission["candidate"]),
            "droplet-enrollment-changed",
        )
        binding = attempt["binding"]
        return AdmissionContext(
            now=datetime.now(UTC),
            invocation_id=attempt["invocationId"],
            enrolled_target=enrolled.target,
            candidate_sha256=binding["candidateSha256"],
            platform_sha256=binding["platformSha256"],
            authority_sha256=enrolled.target["enrollmentSha256"],
            lease_sha256=lease_digest,
            run_id=enrolled.registration["runId"],
            active_authority=True,
            revoked=False,
            tenant_history=False,
            tenant_generation=False,
            unfinished_lifecycle=False,
            production_identifiers=enrolled.production_identifiers,
            observed_disposable_identifiers=enrolled.observed_identifiers,
        )

    return initialize_launch(STATE, ROOT / PUBLICATION_VIEW, raw, evidence, observe, owner=owner)
