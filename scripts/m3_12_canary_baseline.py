"""Read the original accepted production baseline, without preparing or launching a canary."""

from __future__ import annotations

import fcntl
import os
import subprocess
from collections.abc import Callable
from hashlib import sha256

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_observe as predecessor_state
from scripts import m3_11_production_records as records
from scripts import m3_12_droplet_observe as guest
from scripts.m3_12_contracts import (
    CANARY_DROPLET,
    CANARY_PREDECESSOR,
    CANARY_PREDECESSOR_HEAD,
    Document,
    digest,
    require,
)
from scripts.m3_12_successor import accepted_predecessor


def _accepted(owner: int) -> tuple[bytes, str, Document]:
    raw = records.operate(records.ROOT, ["read"], b"", owner=owner)
    chain = records.decode(raw)
    authority, original = accepted_predecessor(chain)
    require(
        original["transaction_id"] == CANARY_PREDECESSOR
        and sha256(chain[-1][1]).hexdigest() == CANARY_PREDECESSOR_HEAD,
        "canary-baseline-predecessor-changed",
    )
    return raw, authority, original


def _checked_state(observed: Document, expected_identity: Document, artifact: str) -> None:
    require(
        observed.get("metadata", {}).get("dropletId") == CANARY_DROPLET
        and observed.get("hostIdentity") == expected_identity,
        "canary-baseline-host-changed",
    )
    require(
        observed.get("state")
        == {
            "artifactSha256": artifact,
            "launchPresent": False,
            "publication": "dark",
        },
        "canary-baseline-not-original-dark-state",
    )


def _verify_artifact(artifact: str) -> None:
    verifier = "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact"
    result = subprocess.run(  # noqa: S603 - fixed installed verifier and validated artifact digest
        [verifier, str(guest.SELECTION.parent / artifact)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    require(result.returncode == 0, "canary-baseline-selected-artifact-invalid")


def observe(
    expected_identity: Document, *, _sample: Callable[[int], Document] = guest.observe
) -> Document:
    """Measure the live guest side; provider/storage approval is still external.

    The caller must use pinned SSH on the already identified target. No state,
    customer admission or launch evidence files are written here.
    """
    owner = os.geteuid()
    require(owner == 0 and not os.path.lexists("/.dockerenv"), "canary-baseline-native-root-only")
    with locks._lock(locks.SELECTION_LOCK, fcntl.LOCK_SH, owner):
        raw, original_sha, original = _accepted(owner)
        artifact: str = original["candidate"]["artifact_sha256"]
        enrollment_machine = guest.production_enrollment_machine_sha256(owner)
        first = _sample(owner)
        _checked_state(first, expected_identity, artifact)
        _verify_artifact(artifact)
        predecessor_state._empty(owner)
        last = _sample(owner)
        require(
            first == last
            and _accepted(owner)[0] == raw
            and guest.production_enrollment_machine_sha256(owner) == enrollment_machine,
            "canary-baseline-readback-changed",
        )
    return {
        "format": "lowerduckpond-m3-12-canary-guest-baseline-v1",
        "guest": last,
        "enrollmentMachineSha256": enrollment_machine,
        "predecessorSha256": original_sha,
        "predecessorHeadSha256": CANARY_PREDECESSOR_HEAD,
        "namespaceSha256": digest(original["namespace"]),
        "repositoryBinding": original["repository_binding"],
    }
