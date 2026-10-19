"""Real private publication boundaries with a synthetic source-fact builder.

The connected operator-path tests independently cover the complete real builder,
CLI, lock-held admission and worker boundaries without this isolated double.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import approval, operator_readiness, operator_records
from scripts.m3_11_unattended.model import LifecycleError, digest
from scripts.m3_11_unattended.state import replace_private

from .standing_authority_support import execution
from .test_m3_11_lease_inventory import NOW
from .test_m3_11_reuse_admission import request_for
from .test_m3_11_storage_admission import prepared


def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    _old, lease, _daemon, config, _inventory = prepared(tmp_path, monkeypatch)
    _request, legacy = request_for(lease, config)
    now = NOW + timedelta(minutes=1)
    ready = execution(legacy, now)
    root = tmp_path / "record-source"
    root.mkdir(mode=0o700)
    body = {
        key: value
        for key, value in legacy.items()
        if key not in {"approved_at", "approval_reference"}
    }
    sources = {}
    for name in ("inputs", "prepared", "reuse_status"):
        value: dict[str, object] = {"synthetic": name}
        path = root / (name + ".json")
        write_private(path, value)
        sources[name] = {"path": str(path), "sha256": digest(value)}
    proposed: dict[str, object] = {
        "format": operator_records.FORMAT,
        "kind": "attempt",
        "sources": sources,
        "parameters": {
            "source": config.helper_revision,
            "mode": "qualification",
            "expires_at": body["expires_at"],
        },
        "proposed": body,
    }
    proposal = root / "proposal.json"
    write_private(proposal, proposed)
    for name in ("authority", "assessment"):
        write_private(root / (name + ".json"), cast(dict[str, object], ready[name]))
    monkeypatch.setattr(operator_records, "build", lambda *_args, **_kwargs: deepcopy(body))
    return {
        "proposal": proposal,
        "expected": digest(proposed),
        "authority": root / "authority.json",
        "assessment": root / "assessment.json",
        "learning_reference": "SYNTHETIC learning",
        "review_reference": "SYNTHETIC review",
        "output": tmp_path / "record-output",
        "now": now,
    }


def record(arguments: dict[str, object]) -> dict[str, object]:
    return operator_readiness.record(**arguments)  # type: ignore[arg-type] # heterogeneous exact API inputs


def test_refresh_preserves_original_consent_action_and_old_expired_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = inputs(tmp_path, monkeypatch)
    first = record(arguments)
    original = {p.name: p.read_bytes() for p in cast(Path, arguments["output"]).iterdir()}
    late = {**arguments, "now": cast(datetime, arguments["now"]) + timedelta(days=3)}
    assert record(late) == first
    assert {p.name: p.read_bytes() for p in cast(Path, arguments["output"]).iterdir()} == original
    with pytest.raises(LifecycleError):
        approval.validate(first, mode="qualification", now=cast(datetime, late["now"]))
    fresh = record(
        {
            **arguments,
            "output": tmp_path / "separate-refreshed-record",
            "now": cast(datetime, arguments["now"]) + timedelta(minutes=1),
        }
    )
    assert fresh["authority"] == first["authority"]
    assert fresh["assessment"] == first["assessment"]
    assert fresh["readiness"] != first["readiness"]
    assert "approved_at" not in fresh


@pytest.mark.parametrize("fault", ["source", "issuance", "withdrawn", "during-build", "partial"])
def test_bad_or_changed_facts_never_publish_execution_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    arguments = inputs(tmp_path, monkeypatch)
    proposal = cast(Path, arguments["proposal"])
    output = cast(Path, arguments["output"])
    if fault == "source":
        replace_private(proposal.parent / "prepared.json", {"changed": True})
    elif fault == "issuance":
        document = read_private(proposal)
        del cast(dict[str, object], document["sources"])["reuse_status"]
        replace_private(proposal, document)
        arguments["expected"] = digest(document)
    elif fault == "withdrawn":
        assessment = cast(Path, arguments["assessment"])
        replace_private(assessment, {**read_private(assessment), "status": "withdrawn"})
    elif fault == "partial":
        output.mkdir(mode=0o700)
        write_private(output / "inputs.json", {"partial": True})
    else:
        original = operator_records.build

        def changed(*args: object, **kwargs: object) -> dict[str, object]:
            result = original(*args, **kwargs)  # type: ignore[arg-type] # preserve actual synthetic builder
            assessment = cast(Path, arguments["assessment"])
            replace_private(assessment, {**read_private(assessment), "status": "withdrawn"})
            return result

        monkeypatch.setattr(operator_records, "build", changed)
    with pytest.raises(LifecycleError):
        record(arguments)
    assert not (output / "live-approval.json").exists()


@pytest.mark.parametrize("write_number", [1, 2])
def test_companion_failure_never_exposes_consumable_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_number: int,
) -> None:
    arguments = inputs(tmp_path, monkeypatch)
    calls = 0

    def interrupted(path: Path, value: dict[str, object], *, maximum: int) -> None:
        nonlocal calls
        calls += 1
        if calls == write_number:
            raise OSError("synthetic private companion write failure")
        write_private(path, value, maximum=maximum)

    monkeypatch.setattr(operator_readiness, "write_private", interrupted)
    with pytest.raises(OSError, match="companion"):
        record(arguments)
    assert not (cast(Path, arguments["output"]) / "live-approval.json").exists()
    with pytest.raises(LifecycleError, match="incomplete"):
        record(arguments)


@pytest.mark.parametrize("field", ["source", "consent", "assessment", "assessment_path"])
def test_matching_receipt_digest_cannot_rebind_completed_record_away_from_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    arguments = inputs(tmp_path, monkeypatch)
    result = record(arguments)
    output = cast(Path, arguments["output"])
    changed = deepcopy(result)
    if field == "source":
        cast(dict[str, object], changed["prepared"])["controller_image"] = "sha256:" + "f" * 64
    elif field == "consent":
        authority = cast(dict[str, object], changed["authority"])
        cast(dict[str, object], authority["consent"])["approved_at"] = None
        cast(dict[str, object], changed["assessment"])["authority_sha256"] = digest(authority)
    elif field == "assessment_path":
        changed["assessment_path"] = "/synthetic/different-current-authority.json"
    else:
        cast(dict[str, object], changed["assessment"])["check_reference"] = (
            "SYNTHETIC changed assessment"
        )
    replace_private(output / "live-approval.json", changed)
    receipt = read_private(output / "receipt.json")
    replace_private(output / "receipt.json", {**receipt, "record_sha256": digest(changed)})
    with pytest.raises(LifecycleError, match="original proposal and consent"):
        record(arguments)
