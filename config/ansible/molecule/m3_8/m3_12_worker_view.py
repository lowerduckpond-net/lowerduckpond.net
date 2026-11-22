"""Run the real worker sandbox and publication gate in the owned local test guest."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

# The controller installs and independently verifies the fixture artifact first.
if __name__ == "__main__":
    sys.path.insert(0, "/opt/lowerduckpond/static-host-agent/current/site-packages")

from lowerduckpond_static_host_agent.droplet_enrollment import (
    ENROLLMENT,
    EXCLUSIONS,
    PUBLICATION_VIEW,
    TARGET,
    lease_domain,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.platform_launch import initialize_launch

from scripts.m3_12_contracts import (
    COMMON_SLOTS,
    DISPOSABLE,
    AdmissionContext,
    Document,
    Evidence,
    digest,
    encode,
    require,
)
from scripts.m3_12_droplet_observe import ED25519_WIRE_HEADER, HOST_KEY, host_identity

ROOT = Path("/var/lib/lowerduckpond/convergence/m3-12")
STATE = Path("/var/lib/lowerduckpond/static")
VIEW = ROOT / PUBLICATION_VIEW
RUN_ID = "00000000-0000-7000-8000-000000000001"
ATTEMPT_ID = "00000000-0000-7000-8000-000000000002"
JOB = "00000000-0000-7000-8000-000000000003"
UNIT = f"lowerduckpond-static-worker@{JOB}.service"
NOW = "2026-01-01T00:00:00Z"
FIXTURE_PUBLIC_KEY = b"ssh-ed25519 " + base64.b64encode(ED25519_WIRE_HEADER + b"A" * 32) + b"\n"


def record(record_type: str, **fields: object) -> Document:
    return {"format": f"lowerduckpond-m3-12-{record_type}-v1", **fields}


def proof(subject: str) -> str:
    return sha256(subject.encode()).hexdigest()


def create_launch(artifact: str, *, owner: int = 0) -> None:
    """Create synthetic local authority via the common initializer for this witness only."""
    ROOT.mkdir(mode=0o700, parents=True)
    VIEW.mkdir(mode=0o700)
    # These sentinels must remain outside the actual worker sandbox.
    (ROOT / "controller-only-witness").touch(mode=0o600)
    (HOST_KEY.parent / "ssh_host_ed25519_key").touch(mode=0o600, exist_ok=False)
    HOST_KEY.write_bytes(FIXTURE_PUBLIC_KEY)
    local = host_identity(owner)
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": NOW,
    }
    for name in (
        "platform",
        "locks",
        "audit",
        "tenants",
        "intents",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
    ):
        directory = STATE / name
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.mkdir(mode=0o700)
    for name in ("tenant-state.lock", "publication.lock"):
        (STATE / "locks" / name).touch(mode=0o600)
    with DurableDirectory.open(STATE, expected_owner=owner, expected_directory_mode=0o700) as fd:
        fd.create_immutable(("platform", "namespace.json"), encode(namespace))

    exclusions = record(
        "droplet-production-exclusions",
        dropletIds=[21],
        addresses=["192.0.2.21"],
        identityDigests=[proof("fixture-production-only")],
    )
    enrollment = record(
        "droplet-enrollment",
        runId=RUN_ID,
        ipv4="192.0.2.22",
        allocationSha256=proof("fixture-allocation"),
        productionExclusionsSha256=digest(exclusions),
        **local,
    )
    target = {
        "targetKind": DISPOSABLE,
        "purpose": "disposable-qualification",
        "enrollmentSha256": digest(enrollment),
        "allocationSha256": enrollment["allocationSha256"],
        "addressSetSha256": digest({"ipv4": enrollment["ipv4"]}),
        "inventorySha256": proof("fixture-inventory"),
        "stateSha256": proof("fixture-open-tofu-state"),
        "transactionNamespaceSha256": proof("fixture-transaction"),
        "leaseDomainSha256": lease_domain(RUN_ID, local["systemUuidSha256"]),
        "transport": {"kind": "ssh", "identitySha256": local["hostKeySha256"]},
        "droplet": {
            "projectIdSha256": proof("fixture-project"),
            "dropletId": 22,
            "providerIdentitySha256": proof("fixture-provider"),
            "metadataIdentitySha256": proof("fixture-metadata"),
        },
    }
    with DurableDirectory.open(VIEW, expected_owner=owner, expected_directory_mode=0o700) as fd:
        for name, document in (
            (TARGET, target),
            (ENROLLMENT, enrollment),
            (EXCLUSIONS, exclusions),
        ):
            fd.create_immutable((name,), encode(document))

    candidate = {
        "revision": "a" * 40,
        "hostAgentSha256": artifact,
        "inputPolicySha256": proof("fixture-input-policy"),
        "inputFingerprintSha256": proof("fixture-inputs"),
        "toolchainSha256": proof("fixture-toolchain"),
        "requirementsSha256": proof("fixture-requirements"),
    }
    platform = {
        "namespaceSha256": digest(namespace),
        "storageTargetSha256": proof("unreachable-fixture-storage"),
        "storageBackend": "spaces",
        "cloudflareNetworkSetSha256": proof("fixture-networks"),
        "trustedPlatformDomain": "lowerduckpond.net",
        "aliasSuffix": "lowerduckpond.com",
        "tenantOriginSuffix": "lowerduckpond.com",
        "cookiePolicyVersion": "lowerduckpond-cookie-policy-v1",
        "edgePolicyVersion": "lowerduckpond-edge-policy-v1",
    }
    binding = {
        "targetKind": DISPOSABLE,
        "purpose": target["purpose"],
        "runId": RUN_ID,
        "targetSha256": digest(target),
        "candidateSha256": digest(candidate),
        "platformSha256": digest(platform),
    }
    receipts = {
        slot: record(
            "receipt",
            binding=binding,
            invocationId=ATTEMPT_ID,
            kind=kind,
            startedAt=NOW,
            finishedAt=NOW,
            oldestSupportingAt=NOW,
            observationSha256=proof(slot),
            outcome="passed",
        )
        for slot, kind in COMMON_SLOTS.items()
    }
    admission = record(
        "admission",
        binding=binding,
        target=target,
        candidate=candidate,
        platform=platform,
        invocationId=ATTEMPT_ID,
        authoritySha256=digest(enrollment),
        leaseSha256=proof("fixture-lease"),
        prerequisites={slot: digest(receipt) for slot, receipt in receipts.items()},
        preparedAt=NOW,
    )
    context = AdmissionContext(
        now=datetime.now(UTC),
        invocation_id=ATTEMPT_ID,
        enrolled_target=target,
        candidate_sha256=digest(candidate),
        platform_sha256=digest(platform),
        authority_sha256=digest(enrollment),
        lease_sha256=admission["leaseSha256"],
        run_id=RUN_ID,
        active_authority=True,
        revoked=False,
        tenant_history=False,
        tenant_generation=False,
        unfinished_lifecycle=False,
        production_identifiers=frozenset({21, "192.0.2.21", proof("fixture-production-only")}),
    )
    initialize_launch(
        STATE,
        VIEW,
        encode(admission),
        Evidence({digest(receipt): encode(receipt) for receipt in receipts.values()}),
        lambda: context,
        owner=owner,
    )


def run_worker(expected: int) -> None:
    argv = ["/usr/bin/systemctl"]
    result = subprocess.run(  # noqa: S603 - fixed owned worker unit
        [*argv, "start", "--wait", UNIT], check=False
    )
    observed = subprocess.check_output(  # noqa: S603 - fixed service status query
        [*argv, "show", UNIT, "--property=ExecMainStatus", "--value"], text=True
    ).strip()
    require(
        (result.returncode == 0) == (expected == 0) and observed == str(expected),
        f"worker exit {observed}, expected {expected}",
    )


def main() -> None:
    require(Path("/.dockerenv").is_file() and os.geteuid() == 0, "fixture root required")
    create_launch(sys.argv[1])
    run_worker(0)
    print(
        "worker publication: valid identity passed; authority and identities read-only", flush=True
    )
    HOST_KEY.unlink()
    run_worker(78)
    print("worker publication: missing identity denied by gate", flush=True)
    HOST_KEY.write_bytes(
        b"ssh-ed25519 " + base64.b64encode(ED25519_WIRE_HEADER + b"B" * 32) + b"\n"
    )
    run_worker(78)
    print("worker publication: mismatched identity denied by gate", flush=True)
    HOST_KEY.write_bytes(FIXTURE_PUBLIC_KEY)
    (VIEW / "revoked").touch(mode=0o600)
    run_worker(78)
    print("worker publication: revocation denied by gate", flush=True)


if __name__ == "__main__":
    main()
