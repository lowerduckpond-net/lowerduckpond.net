"""Real publication producer over explicitly synthetic native CLI/Connect exchanges."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import operator_publish as publisher
from scripts.m3_11_unattended.model import LifecycleError, digest
from scripts.m3_11_unattended.state import replace_private

from .operator_flow_support import Services
from .test_m3_11_lease_configuration import mapping


def test_publication_preserves_full_items_and_exact_runtime_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    original = deepcopy(services.items)
    state = tmp_path / "publication"
    before = len(services.calls)
    proposal = publisher.run(
        manifest=manifest, directory=staged, expected=expected, state=state, apply=False
    )
    assert len(services.calls) == before and not state.exists()
    for _ in range(2):
        assert (
            publisher.run(
                manifest=manifest,
                directory=staged,
                expected=expected,
                state=state,
                apply=True,
                expected_proposal=digest(proposal),
            )
            == proposal
        )
    assert len(services.edits) == 2  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
    for raw in mapping(proposal["destinations"]).values():
        destination = mapping(raw)
        key = str(destination["vault"]), str(destination["item"])
        after = services.items[key]
        assert publisher.protected(after, destination) == publisher.protected(
            original[key], destination
        )
        assert read_private(
            state
            / (
                digest({"account": proposal["account"], "destination": destination})
                + ".complete.json"
            )
        ) == read_private(
            state
            / (
                digest({"account": proposal["account"], "destination": destination})
                + ".pending.json"
            )
        )
    assert all(exchange["method"] == "GET" for exchange in services.exchanges)


@pytest.mark.parametrize(
    "fault",
    [
        "concurrent",
        "password",
        "conflicting-field",
        "duplicate-field",
        "files",
        "unknown-template",
        "wrong-version",
        "wrong-proposal",
    ],
)
def test_publication_refuses_changed_or_unsupported_inputs_before_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    state = tmp_path / "publication"
    proposal = publisher.run(
        manifest=manifest, directory=staged, expected=expected, state=state, apply=False
    )
    for item in services.items.values():
        fields = item["fields"]
        assert isinstance(fields, list)
        if fault == "password":
            fields[0]["value"] = "DIFFERENT-SYNTHETIC-PASSWORD"
        elif fault in {"conflicting-field", "duplicate-field"}:
            fields.append(
                {
                    "id": "digitalocean_metadata",
                    "label": "digitalocean_metadata",
                    "type": "STRING",
                    "value": "conflict",
                }
            )
            if fault == "duplicate-field":
                fields.append(
                    {
                        "id": "other",
                        "label": "digitalocean_metadata",
                        "type": "STRING",
                        "value": "conflict",
                    }
                )
        elif fault == "files":
            item["files"] = [{"id": "synthetic-file"}]
        elif fault == "unknown-template":
            item["unsupported_template"] = True
    services.change_before_edit = fault == "concurrent"
    services.op_version = "9.0.0" if fault == "wrong-version" else "2.33.0"
    with pytest.raises(LifecycleError):
        publisher.run(
            manifest=manifest,
            directory=staged,
            expected=expected,
            state=state,
            apply=True,
            expected_proposal="0" * 64 if fault == "wrong-proposal" else digest(proposal),
        )
    assert not services.edits


def test_lost_edit_and_partial_progress_reconcile_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    state = tmp_path / "publication"
    proposal = publisher.run(
        manifest=manifest, directory=staged, expected=expected, state=state, apply=False
    )
    services.lost_edit = True
    with pytest.raises(LifecycleError):
        publisher.run(
            manifest=manifest,
            directory=staged,
            expected=expected,
            state=state,
            apply=True,
            expected_proposal=digest(proposal),
        )
    assert len(services.edits) == 1 and len(list(state.glob("*.pending.json"))) == 1
    services.lost_edit, services.hide_metadata = False, True
    with pytest.raises(LifecycleError):
        publisher.run(
            manifest=manifest,
            directory=staged,
            expected=expected,
            state=state,
            apply=True,
            expected_proposal=digest(proposal),
        )
    assert len(services.edits) == 1
    services.hide_metadata = False
    publisher.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=state,
        apply=True,
        expected_proposal=digest(proposal),
    )
    assert len(services.edits) == 2 and len(list(state.glob("*.complete.json"))) == 2  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value


@pytest.mark.parametrize(
    "fault",
    [
        "url-extra",
        "section-extra",
        "field-object",
        "field-section",
        "duplicate-section",
        "favorite",
        "tags",
    ],
)
def test_nested_native_template_is_closed_before_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    proposal = publisher.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=tmp_path / "publication",
        apply=False,
    )
    for item in services.items.values():
        if fault == "url-extra":
            cast(list[dict[str, object]], item["urls"])[0]["unknown"] = "unsupported"
        elif fault == "section-extra":
            cast(list[dict[str, object]], item["sections"])[0]["unknown"] = "unsupported"
        elif fault == "duplicate-section":
            cast(list[dict[str, object]], item["sections"]).append(
                deepcopy(cast(list[dict[str, object]], item["sections"])[0])
            )
        elif fault == "field-object":
            cast(list[dict[str, object]], item["fields"])[-1]["value"] = {"nested": "unsupported"}
        elif fault == "field-section":
            mapping(cast(list[dict[str, object]], item["fields"])[-1]["section"])["id"] = "missing"
        else:
            item[fault] = {"unsupported": True}
    with pytest.raises((LifecycleError, ValueError)):
        publisher.run(
            manifest=manifest,
            directory=staged,
            expected=expected,
            state=tmp_path / "publication",
            apply=True,
            expected_proposal=digest(proposal),
        )
    assert services.edits == []


@pytest.mark.parametrize(
    "fault", ["attested_by", "principal_context", "verified_at", "observation"]
)
def test_publication_cannot_adopt_attestation_provenance_changed_after_assembly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:

    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    path = staged / "provision-digitalocean-attestation.json"
    value = read_private(path)
    if fault == "observation":
        path = staged / "assembly-receipt.json"
        value = read_private(path)
        mapping(mapping(value["observations"])["provision"])["assembled_at"] = (
            "2020-01-01T00:00:00Z"
        )
    else:
        value[fault] = (
            "2020-01-01T00:00:00Z" if fault == "verified_at" else "changed synthetic provenance"
        )
    replace_private(path, value)
    calls = len(services.calls)
    with pytest.raises((LifecycleError, ValueError)):
        publisher.run(
            manifest=manifest,
            directory=staged,
            expected=expected,
            state=tmp_path / "publication",
            apply=False,
        )
    assert len(services.calls) == calls
