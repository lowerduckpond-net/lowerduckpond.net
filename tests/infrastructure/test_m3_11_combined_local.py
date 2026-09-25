"""Complete local integration must prove all assertions before paired teardown."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_combined_local as local
from scripts import qualification_restore as restore
from scripts.m3_11_private_inputs import read_private
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, HOST_ENV, resource_names
from scripts.qualification_group_runner import SCENARIO, Completion


@pytest.fixture
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    values = {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
        "M3_10_ARCHIVE_BACKEND": "minio",
    }
    Path(values[ARTIFACT_ENV]).parent.mkdir()
    Path(values[ARTIFACT_ENV]).write_bytes(b"selected immutable artifact")
    for key in (*values, "M3_10_INSTALLED_REPORT", "M3_11_COMBINED_BACKEND"):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        local, "owned_containers", Mock(return_value={HOST_ENV: "source", ARCHIVE_ENV: "archive"})
    )
    return values


def completion(status: str) -> object:
    def execute(arguments: list[str], *, plugins: list[Completion]) -> int:
        plugin = plugins[0]
        assert len(plugin.expected) == 2  # noqa: PLR2004 - combined assertions + paired accounting
        assert "complete_journey_combined_reconstruction" in plugin.expected[0]
        assert "installed_restore_paired_accounting" in plugin.expected[1]
        assert all(f"{SCENARIO}/{node}" in arguments for node in plugin.expected)
        plugin.collected = list(plugin.expected) if status != "omitted" else []
        plugin.reports = {
            node: [
                (
                    phase,
                    "skipped" if status == "skipped" and phase == "call" else "passed",
                    status == "xfail",
                )
                for phase in ("setup", "call", "teardown")
            ]
            for node in plugin.collected
        }
        return 1 if status == "failed" else 0

    return execute


@pytest.mark.parametrize("status", ["omitted", "skipped", "xfail", "failed", "passed"])
def test_only_exact_complete_run_and_fresh_proofs_authorize_removal(
    environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    monkeypatch.setattr(pytest, "main", completion(status))
    pair = {"destination": "destination", "acme": "acme"}
    observed: list[str] = []
    monkeypatch.setattr(
        restore,
        "require_source_idempotence",
        lambda *args, **kwargs: observed.append("idempotence"),
    )

    def paired(_environment: dict[str, str]) -> dict[str, str]:
        observed.append("pair")
        return pair

    monkeypatch.setattr(restore, "paired_proof", paired)
    monkeypatch.setattr(
        local, "independent_storage_absence", lambda *args: observed.append("storage")
    )
    monkeypatch.setattr(restore, "remove_pair", lambda *args: observed.append("remove"))
    assert local.run() == (0 if status == "passed" else 1 if status == "failed" else 2)
    if status == "passed":
        assert observed == ["idempotence", "pair", "storage", "pair", "remove"]
        receipt = read_private(tmp_path / "complete-combined.json")
        assert receipt["format"] == local.FORMAT
        assert receipt["identities"] == {HOST_ENV: "source", ARCHIVE_ENV: "archive"}
    else:
        assert not observed
        assert not (tmp_path / "complete-combined.json").exists()
    assert (tmp_path / "complete-combined.started.json").exists()
    with pytest.raises(FileExistsError):
        local.run()


@pytest.mark.parametrize("fault", ["source", "storage", "changed-pair"])
def test_failed_or_changed_final_accounting_retains_the_recovery_pair(
    environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(pytest, "main", completion("passed"))
    monkeypatch.setattr(
        restore,
        "require_source_idempotence",
        Mock(side_effect=ValueError("source changed") if fault == "source" else None),
    )
    pairs = [
        {"destination": "original", "acme": "original"},
        {"destination": "changed" if fault == "changed-pair" else "original", "acme": "original"},
    ]
    monkeypatch.setattr(restore, "paired_proof", Mock(side_effect=pairs))
    monkeypatch.setattr(
        local,
        "independent_storage_absence",
        Mock(side_effect=ValueError("storage not empty") if fault == "storage" else None),
    )
    remove = Mock()
    monkeypatch.setattr(restore, "remove_pair", remove)
    with pytest.raises(ValueError):
        local.run()
    remove.assert_not_called()
    assert not (tmp_path / "complete-combined.json").exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("M3_10_ARCHIVE_BACKEND", "spaces"),
        ("M3_10_INSTALLED_REPORT", "live-report.json"),
        ("M3_11_COMBINED_BACKEND", "spaces"),
    ],
)
def test_live_inputs_cannot_enter_the_local_diagnostic_controller(
    environment: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: str,
) -> None:
    monkeypatch.setenv(key, value)
    execute = Mock()
    monkeypatch.setattr(pytest, "main", execute)
    with pytest.raises(ValueError, match="owned MinIO"):
        local.run()
    execute.assert_not_called()
    assert not (tmp_path / "complete-combined.started.json").exists()
