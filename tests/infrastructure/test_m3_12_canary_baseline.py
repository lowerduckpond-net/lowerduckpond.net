"""Read-only native baseline fixtures; these do not create launch evidence."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_observe as predecessor_state
from scripts import m3_12_canary_baseline as baseline
from scripts import m3_12_droplet_observe as guest
from scripts.m3_12_contracts import CANARY_DROPLET, Document, ValidationError, digest

from .test_m3_12_contracts import proof


@pytest.mark.parametrize(
    "fault", ["none", "not-root", "wrong-host", "live", "boot", "journal", "enrollment"]
)
def test_baseline_reads_only_exact_accepted_dark_guest(
    fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = proof("accepted artifact")
    identity = {"machineSha256": proof("machine")}
    namespace = {"synthetic": "namespace"}
    original = {
        "candidate": {"artifact_sha256": artifact},
        "namespace": namespace,
        "repository_binding": proof("repository"),
    }
    calls: list[str] = []

    @contextmanager
    def selection(*_args: object) -> Iterator[int]:
        calls.append("held")
        yield 1
        calls.append("released")

    def accepted(owner: int) -> tuple[bytes, str, Document]:
        assert owner == 0
        bracketing = "accepted" in calls
        calls.append("accepted")
        raw = b"changed" if bracketing and fault == "journal" else b"original"
        return raw, proof("predecessor"), original

    def sample(owner: int) -> Document:
        assert owner == 0
        bracketing = "sample" in calls
        calls.append("sample")
        return {
            "metadata": {"dropletId": 7 if fault == "wrong-host" else CANARY_DROPLET},
            "hostIdentity": identity,
            "bootSha256": proof("reboot" if bracketing and fault == "boot" else "boot"),
            "state": {
                "artifactSha256": artifact,
                "launchPresent": fault == "live",
                "publication": "dark",
            },
        }

    monkeypatch.setattr(
        baseline,
        "os",
        SimpleNamespace(
            geteuid=lambda: 1000 if fault == "not-root" else 0,
            path=SimpleNamespace(lexists=lambda _: False),
        ),
    )
    enrollment_reads = iter(
        [proof("raw machine"), proof("changed" if fault == "enrollment" else "raw machine")]
    )
    monkeypatch.setattr(
        guest, "production_enrollment_machine_sha256", lambda _: next(enrollment_reads)
    )
    monkeypatch.setattr(locks, "_lock", selection)
    monkeypatch.setattr(baseline, "_accepted", accepted)
    monkeypatch.setattr(baseline, "_verify_artifact", lambda _: calls.append("verify"))
    monkeypatch.setattr(predecessor_state, "_empty", lambda _: calls.append("empty"))
    if fault != "none":
        with pytest.raises(ValidationError, match="canary-baseline-"):
            baseline.observe(identity, _sample=sample)
        return
    result = baseline.observe(identity, _sample=sample)
    assert result["enrollmentMachineSha256"] == proof("raw machine")
    assert result["namespaceSha256"] == digest(namespace)
    assert result["predecessorSha256"] == proof("predecessor")
    assert result["repositoryBinding"] == proof("repository")
    assert calls == [
        "held",
        "accepted",
        "sample",
        "verify",
        "empty",
        "sample",
        "accepted",
        "released",
    ]


def test_production_enrollment_does_not_hash_the_trimmed_guest_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine = tmp_path / "machine-id"
    raw = b"a" * 32 + b"\n"
    machine.write_bytes(raw)
    monkeypatch.setattr(guest, "MACHINE_ID", machine)
    owner = machine.stat().st_uid
    observed = guest.production_enrollment_machine_sha256(owner)
    assert observed == sha256(raw).hexdigest()
    assert observed != sha256(raw.strip()).hexdigest()
