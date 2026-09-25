"""The orchestration cannot skip phases, renew receipts, or redeploy completion."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from infrastructure.test_m3_11_production_replica import (
    OWNER,
    Peer,
    replica,
    snapshot,
)
from infrastructure.test_m3_11_production_replica import (
    roots as roots,  # noqa: PLC0414 - shared filesystem fixture
)
from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_records as wire
from scripts import m3_11_production_workflow as workflow
from scripts.m3_11_production_proposals import Proposals
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import Result


class Actions(Peer):
    def __init__(self, root: Path, logs: Path, observations: dict[str, object]) -> None:
        super().__init__(root, logs)
        self.observations = observations
        self.actions: list[str] = []
        self.after: Callable[[], None] = lambda: None

    def run(
        self, name: str, arguments: Sequence[str], *, data: bytes = b"", backup: bool = False
    ) -> Result:
        if name == "journal-sync":
            return super().run(name, arguments, data=data)
        chain = wire.decode(wire.operate(self.root, ["read"], b"", owner=OWNER))
        state = journal.validate(chain)
        original = cast(dict[str, object], state["original"])
        predecessor = cast(str, original["predecessor"])
        self.actions.append(name)
        value: object
        if name == "drain":
            assert state["phase"] == "drained.started"
            value = {
                "format": "lowerduckpond-m3-11-predecessor-drain-v1",
                "original_sha256": state["original_sha256"],
                "predecessor_sha256": journal.digest(predecessor.encode()),
                "fences": {
                    unit: journal.digest(fence.content(chain[0][1], phase))
                    for unit, phase in fence.FENCES.items()
                },
                "active_units": [],
                "external_commands": [],
                "populated_groups": [],
            }
        elif name == "drained-host-authority":
            artifact, source, *_ = predecessor.split()
            assert list(arguments) == ["/bin/bash", "-s", "--", artifact, "upgrade-host", source]
            assert data == (workflow.ROOT / "scripts/m3-10-completed-host-preflight").read_bytes()
            value = {
                "format": "lowerduckpond-m3-10-archive-authority-v1",
                "artifactSha256": artifact,
                "sourceRevision": source,
                "archives": [],
            }
        elif name == "inspect":
            assert backup and state["phase"] in {"accepted.started", "complete"}
            value = {
                "format": "lowerduckpond-m3-11-production-inspection-v1",
                "original_sha256": state["original_sha256"],
                "last_sha256": state["last_sha256"],
                "recovery_enabled": True,
                "rotation_enabled": True,
                "publication_enabled": False,
            }
        else:
            phase = str(state["phase"]).removesuffix(".started")
            assert name in {"initialize", "backup"}
            assert str(state["phase"]).endswith(".started")
            assert (name == "backup") == backup
            value = dict(cast(dict[str, object], self.observations[phase]))
            candidate = cast(dict[str, object], original["candidate"])
            if phase == "namespace":
                value.update(
                    artifact_sha256=candidate["artifact_sha256"],
                    namespace_sha256=journal.digest(
                        journal.canonical(cast(dict[str, object], original["namespace"]))
                    ),
                )
            elif phase == "lineage":
                value["repository_binding"] = original["repository_binding"]
            elif phase == "backup-verified":
                value["report_sha256"] = candidate["report_sha256"]
        self.after()
        out, err = (
            self.logs / f"action-{len(self.actions)}.out",
            self.logs / f"action-{len(self.actions)}.err",
        )
        out.write_bytes(journal.canonical(cast(dict[str, object], value)))
        err.write_bytes(b"")
        return Result(0, out, err)


@pytest.fixture
def actions(
    roots: tuple[Path, Path],
    tmp_path: Path,
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> Actions:
    peer = Actions(
        roots[1],
        tmp_path / "logs",
        {name: json.loads(raw)["observations"] for name, raw in records[2::2]},
    )

    def playbook(pair: Replica, stage: str, artifact: Path, *, idempotent: bool = False) -> str:
        assert journal.validate(pair.synchronize())["phase"] == converge.PHASES[stage][0]
        peer.actions.append(stage + ("-idempotent" if idempotent else ""))
        peer.after()
        return "a" * 64

    monkeypatch.setattr(converge, "playbook", playbook)
    monkeypatch.setattr(converge, "_digest", lambda _: "b" * 64)
    return peer


def test_all_phases_follow_original_order_and_completion_is_inspection_only(
    roots: tuple[Path, Path], tmp_path: Path, records: list[tuple[str, bytes]], actions: Actions
) -> None:
    cache, attempt = tmp_path / "proposals", tmp_path / "attempt"
    for path in (cache, attempt):
        path.mkdir(mode=0o700)
    with (
        journal.locked(roots[0], owner=OWNER, create=True) as local,
        journal.locked(cache, owner=OWNER, create=True) as saved,
    ):
        pair, proposals = replica(local, actions), Proposals(saved, attempt)
        proposals.publish(pair, *records[0])
        workflow.run(pair, tmp_path / "artifact", proposals, lambda: None)
        assert actions.actions == [
            "drain",
            "drained-host-authority",
            "bootstrap",
            "initialize",
            "initialize",
            "converged",
            "converged-idempotent",
            "backup",
            "rotation-enabled",
            "rotation-enabled-idempotent",
            "accepted",
            "inspect",
            "inspect",
        ]
        assert local.inspect()["phase"] == "complete"
        assert local.records() == saved.records()
        before = snapshot(roots[0]), snapshot(roots[1]), snapshot(cache)
        actions.actions.clear()
        workflow.run(pair, tmp_path / "artifact", proposals, lambda: None)
        assert actions.actions == ["inspect"]
        assert (snapshot(roots[0]), snapshot(roots[1]), snapshot(cache)) == before


def test_changed_inputs_after_action_do_not_publish_a_completion_receipt(
    roots: tuple[Path, Path], tmp_path: Path, records: list[tuple[str, bytes]], actions: Actions
) -> None:
    cache, attempt = tmp_path / "proposals", tmp_path / "attempt"
    for path in (cache, attempt):
        path.mkdir(mode=0o700)
    changed = False

    def change() -> None:
        nonlocal changed
        changed = True

    def guard() -> None:
        if changed:
            raise ValueError("inputs changed")

    with (
        journal.locked(roots[0], owner=OWNER, create=True) as local,
        journal.locked(cache, owner=OWNER, create=True) as saved,
    ):
        pair, proposals = replica(local, actions), Proposals(saved, attempt)
        proposals.publish(pair, *records[0])
        actions.after = change
        with pytest.raises(ValueError, match="inputs changed"):
            workflow.run(pair, tmp_path / "artifact", proposals, guard)
        assert local.inspect()["phase"] == "drained.started"
        assert local.records() == saved.records()
