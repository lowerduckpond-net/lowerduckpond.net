"""Only a complete bound Ansible recap can attest to an idempotent pass."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from ansible.executor.stats import AggregateStats  # type: ignore[import-untyped]
from ansible.plugins.loader import callback_loader  # type: ignore[import-untyped]

from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_journal as journal

CONTEXT = "a" * 64


def write_recap(stats: AggregateStats) -> None:
    callback_loader.add_directory(str(converge.ROOT / "config/ansible/plugins/callback"))
    callback = callback_loader.get("ldp_m3_11_receipt")
    assert callback is not None
    callback.v2_playbook_on_stats(stats)


@pytest.fixture
def receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "recap.json"
    monkeypatch.setenv("LDP_M3_11_PLAYBOOK_RECEIPT", str(path))
    monkeypatch.setenv("LDP_M3_11_PLAYBOOK_CONTEXT", CONTEXT)
    stats = AggregateStats()
    stats.increment("ok", converge.HOST)
    write_recap(stats)
    return path


def test_actual_ansible_aggregate_stats_produce_an_exact_success_receipt(receipt: Path) -> None:
    raw, counters = converge.recap(receipt, CONTEXT, idempotent=True)
    assert raw == receipt.read_bytes()
    assert counters == {key: int(key == "ok") for key in converge.COUNTERS}


@pytest.mark.parametrize(
    "fault",
    [
        "failures",
        "unreachable",
        "ignored",
        "rescued",
        "changed",
        "boolean",
        "empty",
        "extra-host",
        "context",
        "duplicate",
    ],
)
def test_zero_exit_or_forged_stdout_cannot_hide_an_incomplete_playbook(
    receipt: Path, fault: str
) -> None:
    value = json.loads(receipt.read_bytes())
    counters = value["hosts"][converge.HOST]
    if fault in converge.COUNTERS:
        counters[fault] = 1
    elif fault == "boolean":
        counters["changed"] = False
    elif fault == "empty":
        counters["ok"] = 0
    elif fault == "extra-host":
        value["hosts"]["localhost"] = dict(counters)
    elif fault == "context":
        value["context_sha256"] = "b" * 64
    raw = journal.canonical(value)
    if fault == "duplicate":
        raw = raw.replace(b'"changed":0', b'"changed":1,"changed":0')
    receipt.write_bytes(raw)
    with pytest.raises(ValueError):
        converge.recap(receipt, CONTEXT, idempotent=True)


def test_first_converge_can_change_while_second_must_be_idempotent(receipt: Path) -> None:
    value = json.loads(receipt.read_bytes())
    value["hosts"][converge.HOST]["changed"] = 1
    receipt.write_bytes(journal.canonical(value))
    _, counters = converge.recap(receipt, CONTEXT, idempotent=False)
    assert counters["changed"] == 1
    with pytest.raises(ValueError, match="idempotent"):
        converge.recap(receipt, CONTEXT, idempotent=True)


@pytest.mark.parametrize("fault", ["mode", "link", "symlink", "fifo", "oversize"])
def test_recap_requires_bounded_private_original_file(receipt: Path, fault: str) -> None:
    if fault == "mode":
        receipt.chmod(0o644)
    elif fault == "link":
        receipt.with_name("other").hardlink_to(receipt)
    elif fault == "symlink":
        original = receipt.with_name("original")
        receipt.rename(original)
        receipt.symlink_to(original)
    elif fault == "fifo":
        import os  # noqa: PLC0415 - this test creates only its owned FIFO

        receipt.unlink()
        os.mkfifo(receipt, 0o600)
    else:
        receipt.write_bytes(receipt.read_bytes() + b" " * converge.MAX_RECEIPT_BYTES)
    with pytest.raises((OSError, ValueError)):
        converge.recap(receipt, CONTEXT, idempotent=True)


def test_callback_never_overwrites_a_prior_outcome(receipt: Path) -> None:
    original = receipt.read_bytes()
    stats = AggregateStats()
    stats.increment("failures", converge.HOST)
    with pytest.raises(FileExistsError):
        write_recap(stats)
    assert receipt.read_bytes() == original


@pytest.mark.parametrize(
    ("stage", "recovery", "rotation"),
    [
        ("bootstrap", False, False),
        ("converged", True, False),
        ("rotation-enabled", True, True),
        ("accepted", True, True),
    ],
)
def test_real_playbook_configuration_matches_only_the_committed_phase(
    stage: str, recovery: bool, rotation: bool
) -> None:
    values = converge._variables(stage, Path("/private/artifact.tar"), "b" * 64)
    assert values["backup_static_recovery_enabled"] is recovery
    assert values["backup_audit_rotation_enabled"] is rotation
    assert values["static_publication_enabled"] is False
    assert values["host_recovery_bootstrap_enabled"] is False
    assert values["static_host_agent_verified_completed_candidate"] is (stage != "bootstrap")
