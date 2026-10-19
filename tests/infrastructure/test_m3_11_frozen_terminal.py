"""Terminal facts retain all seven exact obligations after credential expiry."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts.m3_11_frozen_terminal import retained, terminal_facts
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.inventory import fact
from scripts.m3_11_unattended.model import LeaseManifest, LifecycleError
from scripts.m3_11_unattended.state import LeaseState

from .test_m3_11_lease_inventory import manifest


def closed(
    selected: LeaseManifest | None = None,
) -> tuple[LeaseManifest, list[dict[str, object]], dict[str, object], dict[str, object]]:
    selected = manifest() if selected is None else selected
    issuer: dict[str, object] = {
        "writer_sha256": "b" * 64,
        "stopped_at": selected.created_at,
        "retained_roles": sorted(intent.role for intent in selected.intents),
    }
    created: dict[str, object] = {
        intent.role: {"intent_sha256": intent.sha256, "credential_id": "synthetic-" + intent.role}
        for intent in selected.intents
    }
    rows = [
        fact(selected, "manifest", selected.document()),
        fact(selected, "issuer-stopped", issuer),
    ]
    for intent in selected.intents:
        for kind in ("created", "removed", "denied"):
            payload = created[intent.role]
            assert isinstance(payload, dict)
            rows.append(fact(selected, kind + ":" + intent.role, payload))
    rows.append(
        fact(
            selected,
            "closed",
            {
                "results": [
                    {
                        "intent_sha256": intent.sha256,
                        "status": "verified",
                        "negative_authentication": "denied",
                    }
                    for intent in selected.intents
                ]
            },
        )
    )
    return selected, rows, issuer, created


def test_all_original_identities_are_required_without_a_freshness_deadline() -> None:
    selected, rows, issuer, created = closed()
    found = terminal_facts(rows, selected, issuer=issuer, created=created)
    assert {row["slot"] for row in found} == {row["slot"] for row in rows}
    # Identical immutable duplicates can arise after a lost publication response.
    assert terminal_facts([*rows, *rows], selected, issuer=issuer, created=created) == found


@pytest.mark.parametrize(
    "slot",
    [
        "manifest",
        "issuer-stopped",
        "closed",
        *[
            kind + ":" + role
            for role in (
                "archive",
                "audit",
                "backup",
                "caddy",
                "observer",
                "operator",
                "page-rules",
            )
            for kind in ("created", "removed", "denied")
        ],
    ],
)
def test_missing_terminal_fact_never_substitutes_zero_overdue(slot: str) -> None:
    selected, rows, issuer, created = closed()
    with pytest.raises((ValueError, LifecycleError)):
        terminal_facts(
            [row for row in rows if row["slot"] != slot], selected, issuer=issuer, created=created
        )


@pytest.mark.parametrize(
    "change",
    [
        "credential",
        "intent",
        "manifest",
        "issuer",
        "not-submitted",
        "unavailable",
        "not-tested",
        "conflict",
    ],
)
def test_rejects_imprecise_or_conflicting_terminal_proof(change: str) -> None:
    selected, rows, issuer, created = closed()
    target = next(row for row in rows if row["slot"] == "denied:archive")
    payload = target["payload"]
    assert isinstance(payload, dict)
    if change == "credential":
        payload["credential_id"] = "another-credential"
    elif change == "intent":
        payload["intent_sha256"] = "e" * 64
    elif change == "manifest":
        target["manifest_sha256"] = "e" * 64
    elif change == "issuer":
        issuer["retained_roles"] = ["archive"]
    elif change == "not-submitted":
        rows.append(
            fact(
                selected,
                "not-submitted:archive",
                {"intent_sha256": payload["intent_sha256"], "writer_sha256": "b" * 64},
            )
        )
    elif change in {"unavailable", "not-tested"}:
        closure = rows[-1]["payload"]
        assert isinstance(closure, dict) and isinstance(closure["results"], list)
        closure["results"][0]["negative_authentication"] = change
    else:
        duplicate = deepcopy(target)
        payload["credential_id"] = "another-credential"
        rows.append(duplicate)
    with pytest.raises((ValueError, LifecycleError)):
        terminal_facts(rows, selected, issuer=issuer, created=created)


def test_read_only_original_binding_survives_secret_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, rows, issuer, created = closed()
    lease = LeaseState(tmp_path)
    write_private(tmp_path / "manifest.json", selected.document())
    write_private(
        tmp_path / "issuer.json",
        {"manifest_sha256": selected.sha256, "writer_sha256": issuer["writer_sha256"]},
    )
    write_private(tmp_path / "issuer-stopped.json", issuer)
    for role, value in created.items():
        assert isinstance(value, dict)
        write_private(tmp_path / ("created-" + role + ".json"), value)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("terminal verification opened child credentials")

    monkeypatch.setattr(LeaseState, "credential", forbidden)
    before = {path: path.read_bytes() for path in tmp_path.iterdir()}
    assert retained(lease, rows)["created"] == created
    assert before == {path: path.read_bytes() for path in tmp_path.iterdir()}
