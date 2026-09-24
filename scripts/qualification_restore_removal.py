"""Journal exact paired fixture retirement before stopping or deleting resources."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from scripts import qualification_restore as restore
from scripts.qualification_case import private_document
from scripts.qualification_context import ARTIFACT_ENV, run_lease
from scripts.qualification_probe import document
from scripts.qualification_retirement import (
    artifact_digest,
    environment_for,
    incarnation,
    snapshot,
    valid_incarnation,
)

FORMAT = "lowerduckpond-restore-fixture-removal-v1"
STEPS = ("stop-destination", "stop-acme", "remove-destination", "remove-acme", "complete")


def present(environment: dict[str, str], receipts: dict[str, object]) -> dict[str, str]:
    result = {}
    for kind in restore.KINDS:
        receipt = receipts[kind]
        if not isinstance(receipt, dict):
            raise ValueError("invalid restore removal receipt")
        found = (
            restore.command(
                environment,
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^{receipt['name']}$",
                "--format",
                "{{.ID}}",
            )
            .decode("ascii")
            .strip()
        )
        if not found:
            continue
        if found != receipt["id"]:
            raise ValueError("restore removal resource was replaced")
        current = restore.inspect(environment, found)
        if any(current[key] != receipt[key] for key in ("id", "name", "owner", "image")):
            raise ValueError("restore removal ownership changed")
        result[kind] = found
    return result


def remove_pair(  # noqa: PLR0912 - explicit stop/remove recovery states
    environment: dict[str, str], expected: dict[str, str]
) -> None:
    root = restore.directory(environment)
    receipts = {kind: document(root / f"{kind}.json") for kind in restore.KINDS}
    if set(expected) != set(restore.KINDS) or any(
        receipts[kind].get("id") != expected[kind] for kind in restore.KINDS
    ):
        raise ValueError("restore removal identities changed")
    path = root / "removal.json"
    digest = artifact_digest(Path(environment[ARTIFACT_ENV]))
    if path.exists():
        intent = document(path)
        starts = intent.get("incarnations")
        if (
            set(intent) != {"format", "receipts", "artifact", "incarnations", "step"}
            or intent["format"] != FORMAT
            or intent["receipts"] != receipts
            or intent["artifact"] != digest
            or intent["step"] not in STEPS
            or not isinstance(starts, dict)
            or set(starts) != set(restore.KINDS)
            or any(not valid_incarnation(value) for value in starts.values())
        ):
            raise ValueError("invalid restore removal transaction")
    else:
        before = {kind: snapshot(environment, expected[kind]) for kind in restore.KINDS}
        if restore.paired_proof(environment) != expected or any(
            snapshot(environment, expected[kind]) != before[kind] for kind in restore.KINDS
        ):
            raise ValueError("restore resources changed before retirement")
        starts = {kind: incarnation(before[kind]) for kind in restore.KINDS}
        intent = {
            "format": FORMAT,
            "receipts": receipts,
            "artifact": digest,
            "incarnations": starts,
            "step": STEPS[0],
        }
        private_document(root, path.name, intent)
    assert isinstance(starts, dict)  # noqa: S101 - validated or constructed above
    for step in STEPS[STEPS.index(str(intent["step"])) :]:
        current = present(environment, cast(dict[str, object], receipts))
        index = STEPS.index(step)
        required = (
            set(restore.KINDS)
            if step.startswith("stop-")
            else {"acme"}
            if step == "remove-destination"
            else set()
        )
        allowed = (
            set(restore.KINDS)
            if step in (*STEPS[:2], "remove-destination")
            else {"acme"}
            if step == "remove-acme"
            else set()
        )
        if not required <= set(current) <= allowed:
            raise ValueError("restore resource disappeared before removal authorization")
        for kind, identity in current.items():
            value = snapshot(environment, identity)
            if incarnation(value) != starts[kind]:
                raise ValueError("restore resource restarted after retirement proof")
            if value["running"] and (
                step.startswith("remove-") or (step == "stop-acme" and kind == "destination")
            ):
                raise ValueError("restore resource restarted after shutdown")
        if step == "complete":
            break
        restore.source_fenced(environment)
        action, kind = step.split("-", 1)
        identity = expected[kind]
        if action == "stop":
            if kind == "acme" and snapshot(environment, identity)["running"]:
                completed = document(root / "completed.json")
                restore.acme_accounting(
                    environment,
                    identity,
                    negative=completed.get("outcome") == "blocked-as-expected",
                )
            restore.command(environment, "docker", "stop", "--time", "20", identity, timeout=30)
            stopped = snapshot(environment, identity)
            if stopped["running"] or incarnation(stopped) != starts[kind]:
                raise ValueError("restore fixture did not stop unchanged")
        elif kind in current:
            restore.command(environment, "docker", "rm", "--volumes", identity)
            if kind in present(environment, cast(dict[str, object], receipts)):
                raise ValueError("restore fixture removal is incomplete")
        intent["step"] = STEPS[index + 1]
        private_document(root, path.name, intent)
    private_document(root, "removed.json", {"identities": expected})


def resume(directory: Path) -> Path:
    """Finish an already authorized pair removal without rerunning the scenario."""
    directory = directory.resolve(strict=True)
    with run_lease(directory):
        environment = environment_for(directory)
        root = restore.directory(environment)
        if not (root / "removal.json").is_file():
            raise ValueError("paired retirement has no prior authorization")
        expected = {kind: str(document(root / f"{kind}.json")["id"]) for kind in restore.KINDS}
        remove_pair(environment, expected)
    return root / "removed.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(resume(parser.parse_args().directory))
