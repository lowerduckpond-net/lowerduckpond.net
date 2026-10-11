"""Recovery consumes original completion, never runs the functional tests again."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_combined_live as live
from scripts import m3_11_finalization as finalization
from scripts import m3_11_functional_completion as functional
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.state import replace_private

from .test_m3_11_combined_live import execute, retirement
from .test_m3_11_combined_live import inputs as inputs  # noqa: PLC0414 - shared pytest fixture
from .test_m3_11_finalization_report import managed


@pytest.mark.parametrize("fault", ["authorize", "cleanup"])
def test_new_process_finishes_without_replaying_tests_or_refreshing_originals(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    managed(tmp_path, inputs.binding)
    tests = Mock(side_effect=execute("passed"))
    monkeypatch.setattr(pytest, "main", tests)
    removal = retirement(monkeypatch)
    getattr(removal, "authorize" if fault == "authorize" else "run").side_effect = OSError(
        "transient"
    )
    with pytest.raises(OSError, match="transient"):
        live.run()
    completion, checkpoint = functional.load(tmp_path, dict(inputs.environment))
    assert completion.passed(0)
    originals = {
        p: functional.snapshot(tmp_path / p) for p in cast(dict[str, object], checkpoint["files"])
    }
    opening = (tmp_path / "combined-phases/owned-teardown.started.json").read_bytes()
    removal.authorize.side_effect = None
    removal.run.side_effect = None
    removal.root = tmp_path / "owned-teardown"

    def resume(_directory: Path, _storage: object, dns: object, **kwargs: object) -> Mock:
        assert callable(dns)
        removal.run.side_effect = lambda: (dns(), removal.run.return_value)[1]
        return removal

    monkeypatch.setattr(finalization, "Teardown", resume)
    monkeypatch.setattr(
        finalization, "removal_absence", Mock(return_value=SimpleNamespace(sha256="a" * 64))
    )
    monkeypatch.setattr(finalization, "require_live", lambda _: None)
    finalization.combined(tmp_path, inputs)
    envelope = (tmp_path / "combined.json").read_bytes()
    assert originals == {p: functional.snapshot(tmp_path / p) for p in originals}
    assert (tmp_path / "combined-phases/owned-teardown.started.json").read_bytes() == opening
    assert (tmp_path / "functional-completion.json").read_bytes().find(b"+00:00") == -1
    finalization.combined(tmp_path, inputs)
    assert (tmp_path / "combined.json").read_bytes() == envelope
    tests.assert_called_once()


@pytest.mark.parametrize(
    "fault", ["teardown", "collection", "exit", "mtime", "input", "diagnostic", "missing"]
)
def test_changed_or_incomplete_completion_cannot_authorize_recovery(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(pytest, "main", execute("passed"))
    removal = retirement(monkeypatch)
    removal.authorize.side_effect = OSError("transient")
    with pytest.raises(OSError):
        live.run()
    path = tmp_path / "functional-completion.json"
    checkpoint = read_private(path)
    if fault in {"teardown", "collection", "exit"}:
        result = cast(dict[str, object], checkpoint["tests"])
        if fault == "exit":
            result["exit_status"] = 1
        elif fault == "collection":
            result["collected"] = []
        else:
            cast(dict[str, list[object]], result["reports"])[
                cast(list[str], result["nodes"])[0]
            ].pop()
        replace_private(path, checkpoint)
    elif fault == "mtime":
        changed = tmp_path / "installed.json"
        os.utime(changed, ns=(changed.stat().st_atime_ns, changed.stat().st_mtime_ns + 1))
    elif fault == "input":
        replace_private(tmp_path / "qualification-inputs.json", {"changed": True})
    elif fault == "diagnostic":
        replace_private(tmp_path / "diagnostic-origin.json", {"qualification_authority": "none"})
    else:
        path.unlink()
    constructor = Mock()
    monkeypatch.setattr(finalization, "Teardown", constructor)
    with pytest.raises((ValueError, FileNotFoundError)):
        finalization.combined(tmp_path, inputs)
    constructor.assert_not_called()


def test_access_loss_after_cleanup_cannot_publish_combined_pass(
    inputs: Mock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    managed(tmp_path, inputs.binding)
    monkeypatch.setattr(pytest, "main", execute("passed"))
    removal = retirement(monkeypatch)
    removal.run.side_effect = OSError("transient")
    with pytest.raises(OSError):
        live.run()
    removal.run.side_effect = None
    removal.root = tmp_path / "owned-teardown"
    monkeypatch.setattr(finalization, "Teardown", Mock(return_value=removal))
    monkeypatch.setattr(finalization, "require_live", Mock(side_effect=ValueError("expired")))
    with pytest.raises(ValueError, match="expired"):
        finalization.combined(tmp_path, inputs)
    assert not (tmp_path / "combined.json").exists()
