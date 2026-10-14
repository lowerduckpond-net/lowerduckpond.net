"""Explicit synthetic consent crosses real proposal, record and binding producers."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import operator_records as records
from scripts.m3_11_unattended.model import LeasePolicy, LifecycleError, digest, stamp
from scripts.m3_11_unattended.state import replace_private

from .operator_flow_support import DAEMON, SOURCE, Services
from .test_m3_11_lease_configuration import mapping


def command(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
    monkeypatch.setattr(sys, "argv", ["operator_records", *arguments])
    assert records.main() == 0


def policy_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    services = Services(monkeypatch)
    tmp_path.chmod(0o700)
    draft = tmp_path / "policy-draft.json"
    write_private(draft, services.manifest)
    proposal = tmp_path / "policy-proposal.json"
    command(monkeypatch, "policy-proposal", "--inputs", str(draft), "--output", str(proposal))
    return proposal


def record_policy(proposal: Path, output: Path) -> dict[str, object]:
    return records.record(
        "policy",
        proposal=proposal,
        expected=digest(read_private(proposal)),
        approved_at=stamp(datetime.now(UTC) - timedelta(seconds=1)),
        approval_reference="SYNTHETIC external consent only",
        output=output,
        now=datetime.now(UTC),
    )


def test_policy_cli_retains_reviewed_sources_and_publishes_final_record_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proposal = policy_proposal(tmp_path, monkeypatch)
    output = tmp_path / "approved-policy"
    approved_at = stamp(datetime.now(UTC) - timedelta(seconds=1))
    arguments = (
        "record-policy",
        "--proposal",
        str(proposal),
        "--expected-proposal-sha256",
        digest(read_private(proposal)),
        "--approved-at",
        approved_at,
        "--approval-reference",
        "SYNTHETIC external consent only",
        "--output",
        str(output),
    )
    command(monkeypatch, *arguments)
    policy = LeasePolicy.parse(read_private(output / "policy.json"))
    assert policy.approval_reference == "SYNTHETIC external consent only"
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    command(monkeypatch, *arguments)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert read_private(output / "receipt.json")["record_sha256"] == policy.sha256


@pytest.mark.parametrize(
    "fault",
    [
        "changed-source",
        "changed-proposal",
        "missing-source",
        "partial-output",
        "future-consent",
        "empty-consent",
    ],
)
def test_consent_cannot_accept_changed_facts_or_incomplete_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    proposal = policy_proposal(tmp_path, monkeypatch)
    expected = digest(read_private(proposal))
    output = tmp_path / "approved-policy"
    if fault == "changed-source":
        path = tmp_path / "policy-draft.json"
        value = read_private(path)
        mapping(value["policy"])["retain_after_failure"] = False
        replace_private(path, value)
    elif fault == "changed-proposal":
        value = read_private(proposal)
        cast(dict[str, object], value["proposed"])["retain_after_failure"] = False
        replace_private(proposal, value)
    elif fault == "missing-source":
        (tmp_path / "policy-draft.json").unlink()
    elif fault == "partial-output":
        output.mkdir(mode=0o700)
        write_private(output / "proposal.json", read_private(proposal))
    with pytest.raises((LifecycleError, OSError, ValueError)):
        records.record(
            "policy",
            proposal=proposal,
            expected=expected,
            output=output,
            now=datetime.now(UTC),
            approved_at=stamp(
                datetime.now(UTC) + timedelta(days=1)
                if fault == "future-consent"
                else datetime.now(UTC) - timedelta(seconds=1)
            ),
            approval_reference=""
            if fault == "empty-consent"
            else "SYNTHETIC external consent only",
        )
    assert not (output / "policy.json").exists()


@pytest.mark.parametrize("failed_write", [1, 2, 3, 4])
def test_companion_write_failure_never_exposes_a_consumable_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_write: int
) -> None:
    proposal = policy_proposal(tmp_path, monkeypatch)
    original = write_private
    count = 0

    def fail(path: Path, value: dict[str, object], *, maximum: int) -> None:
        nonlocal count
        count += 1
        if count == failed_write:
            raise OSError("synthetic durable write failure")
        original(path, value, maximum=maximum)

    monkeypatch.setattr(records, "write_private", fail)
    output = tmp_path / "approved-policy"
    with pytest.raises(OSError):
        record_policy(proposal, output)
    assert not (output / "policy.json").exists()


@pytest.mark.parametrize("complete", [True, False])
def test_identical_record_retry_after_cutoff_preserves_only_a_complete_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, complete: bool
) -> None:
    proposal = policy_proposal(tmp_path, monkeypatch)
    output = tmp_path / "approved-policy"
    original = record_policy(proposal, output)
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    if not complete:
        (output / "policy.json").unlink()
    again = partial(
        records.record,
        "policy",
        proposal=proposal,
        expected=digest(read_private(proposal)),
        output=output,
        approved_at=str(original["approved_at"]),
        approval_reference=str(original["approval_reference"]),
        now=datetime.now(UTC) + timedelta(days=100),
    )
    if complete:
        assert again() == original
        assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    else:
        with pytest.raises(LifecycleError, match="incomplete"):
            again()
        assert not (output / "policy.json").exists()


@pytest.mark.parametrize("fault", ["helper", "image", "daemon", "inputs", "unknown", "dirty"])
def test_attempt_proposal_refuses_invalid_preparation_and_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:

    services = Services(monkeypatch)
    prepared: dict[str, object] = {
        "source_revision": SOURCE,
        "helper_revision": SOURCE,
        "controller_image": "sha256:" + "a" * 64,
        "artifact_sha256": "b" * 64,
        "daemon": DAEMON,
    }
    if fault == "helper":
        prepared["helper_revision"] = "a" * 40
    elif fault == "image":
        prepared["controller_image"] = "sha256:short"
    elif fault == "daemon":
        prepared["daemon"] = {**DAEMON, "ID": ""}
    elif fault == "inputs":
        del services.manifest["providers"]
    services.dirty, services.unknown_source = fault == "dirty", fault == "unknown"
    with pytest.raises((LifecycleError, ValueError)):
        records.attempt_body(
            {"inputs": services.manifest, "prepared": prepared},
            {
                "source": SOURCE,
                "mode": "qualification",
                "expires_at": stamp(datetime.now(UTC) + timedelta(hours=1)),
            },
            now=datetime.now(UTC),
        )
    assert all(Path(call[0]).name == "git" for call in services.calls)
