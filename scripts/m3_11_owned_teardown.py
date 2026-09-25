"""Retire the exact live combined fixture after installed-test completion.

The durable authorization can resume cleanup after a lost response. It cannot
resume a failed qualification or write a combined qualification envelope.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import assert_storage_empty

from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as restore
from scripts.m3_11_backup_removal import Removal, _once
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_dns_witness import removal_absence
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_case import owned_containers, remove_owned_image
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    IMAGE_ENV,
    host_name,
    run_lease,
)
from scripts.qualification_group_runner import Completion
from scripts.qualification_groups import node
from scripts.qualification_probe import document
from scripts.qualification_restore_removal import present
from scripts.qualification_retirement import (
    artifact_digest,
    incarnation,
    snapshot,
    uninstalled_storage_absence,
    valid_incarnation,
)

FORMAT = "lowerduckpond-m3-11-owned-teardown-v1"
STEPS = (
    "pair",
    "backup",
    "stop-source",
    "stop-archive",
    "remove-source",
    "remove-archive",
    "image",
)
KEYS = {"source": HOST_ENV, "archive": ARCHIVE_ENV}
EMPTY: dict[str, object] = {"current": [], "versions": [], "uploads": []}


def _digest(value: object) -> str:
    return hashlib.sha256(evidence.canonical_bytes(value)).hexdigest()


def nodes(environment: dict[str, str]) -> tuple[str, ...]:
    return (
        node("combined_live", "live_combined_recovery").format(
            host=f"docker://{host_name(environment)}"
        ),
    )


class Teardown:
    def __init__(
        self, directory: Path, storage: LiveStorage, dns_absence: Callable[[], str]
    ) -> None:
        self.directory = directory
        self.storage = storage
        self.environment = environment_for(directory, storage.environment)
        self.context = read_private(directory / "combined-context.json")
        if self.context["run_id"] != storage.target.run_id or any(
            self.context[key] != storage.binding[key] for key in evidence.BINDING_FIELDS
        ):
            raise ValueError("owned teardown storage differs from the original context")
        self.dns_absence = dns_absence
        self.root = directory / "owned-teardown"
        self.intent: dict[str, object] = {}

    def _archive_absent(self) -> None:
        _, observer = self.storage.target.clients(self.storage.environment)
        assert_storage_empty(observer, bucket=self.storage.target.archive_bucket)

    def _dns_absent(self) -> str:
        value = self.dns_absence()
        evidence.digest(value)
        return value

    def _image(self) -> str:
        result = (
            restore.command(
                self.environment,
                "docker",
                "image",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"reference=molecule_local/{self.environment[IMAGE_ENV]}",
                "--format",
                "{{.ID}}",
            )
            .decode("ascii")
            .strip()
        )
        if result and re.fullmatch(r"sha256:[0-9a-f]{64}", result) is None:
            raise ValueError("owned teardown image inventory is ambiguous")
        return result

    def _pair_receipts(self) -> dict[str, object]:
        return {
            kind: document(restore.directory(self.environment) / f"{kind}.json")
            for kind in restore.KINDS
        }

    def authorize(self, completion: Completion, status: int) -> None:
        """Only the fixed, entirely passing pytest node can authorize deletion."""
        if completion.expected != nodes(self.environment) or not completion.passed(status):
            raise ValueError("owned teardown requires exact installed-test completion")
        if self.root.exists() or self.root.is_symlink():
            raise ValueError("owned teardown cannot replace its original authorization")
        self.storage.require_source(self.environment)
        bound = owned_containers(self.environment)
        before = {key: snapshot(self.environment, value) for key, value in bound.items()}
        pair = restore.paired_proof(self.environment)
        receipts = self._pair_receipts()
        source = restore.inspect(self.environment, bound[HOST_ENV])
        source_identity = {key: source[key] for key in ("id", "name", "owner", "image")}
        destination = cast("dict[str, object]", receipts["destination"])
        if (
            _digest(source_identity) != self.context["source_fixture_sha256"]
            or _digest({key: destination[key] for key in source_identity})
            != self.context["destination_fixture_sha256"]
            or self._image() != source["image"]
            or any(value["running"] is not True for value in before.values())
        ):
            raise ValueError("owned teardown does not own the original running resources")
        accounting = read_private(self.directory / "paired-accounting.json")
        if accounting.get("context_sha256") != _digest(self.context):
            raise ValueError("owned teardown lacks original paired accounting")
        # Spaces convergence deliberately never configures the unused local
        # MinIO fixture. Prove that it still contains no buckets before removing it.
        uninstalled_storage_absence(self.environment, bound[ARCHIVE_ENV])
        self._archive_absent()
        dns = self._dns_absent()
        if (
            owned_containers(self.environment) != bound
            or restore.paired_proof(self.environment) != pair
            or any(
                snapshot(self.environment, identity) != before[key]
                for key, identity in bound.items()
            )
        ):
            raise ValueError("owned resources changed during teardown authorization")
        tests = {
            "nodes": list(completion.expected),
            "collected": completion.collected,
            "reports": {
                key: [list(item) for item in values] for key, values in completion.reports.items()
            },
            "exit_status": status,
        }
        write_private(self.directory / "combined-tests.json", tests)
        self.intent = {
            "format": FORMAT,
            "context_sha256": _digest(self.context),
            "storage": self.storage.target.manifest(self.storage.binding),
            "owner_version": self.storage.owner_version,
            "tests_sha256": _digest(tests),
            "accounting_sha256": _digest(accounting),
            "containers": bound,
            "incarnations": {key: incarnation(value) for key, value in before.items()},
            "pair": pair,
            "pair_receipts": receipts,
            "image": source["image"],
            "dns_sha256": dns,
        }
        self.root.mkdir(mode=0o700)
        write_private(self.root / "intent.json", self.intent)

    def _load(self) -> None:
        metadata = self.root.lstat()
        if (
            self.root.resolve() != self.root
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - private journal
            or metadata.st_uid != os.geteuid()
            or read_private(self.directory / "combined-context.json") != self.context
        ):
            raise ValueError("owned teardown journal or context changed")
        self.intent = evidence.fields(
            read_private(self.root / "intent.json"),
            {
                "format",
                "context_sha256",
                "storage",
                "owner_version",
                "tests_sha256",
                "accounting_sha256",
                "containers",
                "incarnations",
                "pair",
                "pair_receipts",
                "image",
                "dns_sha256",
            },
        )
        starts = evidence.fields(self.intent["incarnations"], {HOST_ENV, ARCHIVE_ENV})
        evidence.fields(self.intent["containers"], {HOST_ENV, ARCHIVE_ENV})
        evidence.fields(self.intent["pair"], set(restore.KINDS))
        if (
            self.intent["format"] != FORMAT
            or self.intent["context_sha256"] != _digest(self.context)
            or self.intent["storage"] != self.storage.target.manifest(self.storage.binding)
            or self.intent["owner_version"] != self.storage.owner_version
            or self.intent["tests_sha256"]
            != _digest(read_private(self.directory / "combined-tests.json"))
            or self.intent["accounting_sha256"]
            != _digest(read_private(self.directory / "paired-accounting.json"))
            or self.intent["pair_receipts"] != self._pair_receipts()
            or any(not valid_incarnation(value) for value in starts.values())
            or artifact_digest(Path(self.environment[ARTIFACT_ENV]))
            != self.context["artifact_sha256"]
        ):
            raise ValueError("owned teardown original authorization changed")

    def _core(self, step: str, *, started: bool) -> dict[str, dict[str, object]]:
        bound = cast("dict[str, str]", self.intent["containers"])
        starts = cast("dict[str, dict[str, object]]", self.intent["incarnations"])
        current = owned_containers(self.environment, allow_missing=True)
        index = STEPS.index(step)
        result = {}
        for kind, key in KEYS.items():
            removed = STEPS.index(f"remove-{kind}")
            stopped = STEPS.index(f"stop-{kind}")
            may_be_absent = index > removed or (index == removed and started)
            if key not in current:
                if not may_be_absent:
                    raise ValueError("owned container disappeared before removal authorization")
                continue
            if index > removed or current[key] != bound[key]:
                raise ValueError("owned container reappeared or was replaced")
            value = snapshot(self.environment, current[key])
            if incarnation(value) != starts[key]:
                raise ValueError("owned container restarted after teardown authorization")
            if index > stopped and value["running"] is not False:
                raise ValueError("owned container restarted after its authorized shutdown")
            if (index < stopped or (index == stopped and not started)) and value[
                "running"
            ] is not True:
                raise ValueError("owned container stopped before shutdown authorization")
            result[kind] = value
        return result

    def _pair_absent(self) -> None:
        receipts = cast("dict[str, object]", self.intent["pair_receipts"])
        if present(self.environment, receipts) or document(
            restore.directory(self.environment) / "removed.json"
        ) != {"identities": self.intent["pair"]}:
            raise ValueError("owned restore pair removal is incomplete")

    def _quiet(self) -> str:
        self._core("backup", started=True)
        self._pair_absent()
        restore.source_fenced(self.environment)
        bound = cast("dict[str, str]", self.intent["containers"])
        uninstalled_storage_absence(self.environment, bound[ARCHIVE_ENV])
        return _digest(self.intent)

    def _backup(self) -> Removal:
        writer, observer = self.storage.target.clients(self.storage.environment)
        return Removal(
            self.storage.target,
            self.storage.binding,
            self.storage.owner_version,
            writer,
            observer,
            self.root / "backup",
            self._quiet,
        )

    def _backup_absent(self) -> None:
        removal = self._backup()
        intent = read_private(removal.directory / "intent.json")
        if (
            intent.get("ownership") != self.intent["storage"]
            or intent.get("owner_version") != self.storage.owner_version
            or intent.get("quiescent_sha256") != _digest(self.intent)
            or read_private(removal.directory / "removed.json")
            != {
                "intent_sha256": _digest(intent),
                "remaining_backup_objects": 0,
            }
            or removal._observed() != EMPTY
        ):
            raise ValueError("owned backup removal is incomplete or bytes reappeared")

    def _action(self, step: str, current: dict[str, dict[str, object]]) -> None:
        if step == "pair":
            restore.remove_pair(self.environment, cast("dict[str, str]", self.intent["pair"]))
            self._pair_absent()
        elif step == "backup":
            self._backup().run()
        elif step == "image":
            if self._image() not in {"", self.intent["image"]}:
                raise ValueError("owned image tag was replaced")
            remove_owned_image(self.environment)
        else:
            self._container_action(step, current)

    def _container_action(self, step: str, current: dict[str, dict[str, object]]) -> None:
        action, kind = step.split("-", 1)
        if kind not in current:
            return  # Only a previously authorized remove can observe absence.
        bound = cast("dict[str, str]", self.intent["containers"])
        identity = bound[KEYS[kind]]
        if action == "stop":
            if current[kind]["running"] is False:
                return  # Lost stop response; the original incarnation is still stopped.
            if kind == "source":
                restore.source_fenced(self.environment)
            else:
                uninstalled_storage_absence(self.environment, identity)
            restore.command(
                self.environment, "docker", "stop", "--time", "20", identity, timeout=30
            )
            value = snapshot(self.environment, identity)
            if value["running"] or incarnation(value) != incarnation(current[kind]):
                raise ValueError("owned container did not stop unchanged")
        else:
            restore.command(self.environment, "docker", "rm", "--volumes", identity)
            if KEYS[kind] in owned_containers(self.environment, allow_missing=True):
                raise ValueError("owned container removal did not finish")

    def run(self) -> dict[str, object]:
        self._load()
        authorization: dict[str, object] = {"intent_sha256": _digest(self.intent)}
        for step in STEPS:
            done = self.root / f"{step}.completed.json"
            started = self.root / f"{step}.started.json"
            if done.exists():
                if read_private(done) != authorization or read_private(started) != authorization:
                    raise ValueError("owned teardown step lost its original authorization")
                continue
            current = self._core(step, started=started.exists())
            if step != "pair":
                self._pair_absent()
            if step not in {"pair", "backup"}:
                self._backup_absent()
                self._archive_absent()
            if step == "image" and not started.exists() and self._image() != self.intent["image"]:
                raise ValueError("owned image disappeared before removal authorization")
            _once(started, authorization)
            self._action(step, current)
            _once(done, authorization)
        if owned_containers(self.environment, allow_missing=True) or self._image():
            raise ValueError("owned fixture resources remain after teardown")
        self._pair_absent()
        self._backup_absent()
        self._archive_absent()
        result: dict[str, object] = {
            **authorization,
            "dns_sha256": self._dns_absent(),
            "teardown": dict.fromkeys(evidence.ZERO_TEARDOWN, 0),
        }
        # A resumed cleanup must not replace original final observations.
        if (self.root / "removed.json").exists():
            original = read_private(self.root / "removed.json")
            if any(original[key] != result[key] for key in ("intent_sha256", "teardown")):
                raise ValueError("owned teardown completion changed")
            return original
        write_private(self.root / "removed.json", result)
        return result


def resume(directory: Path, ambient: Mapping[str, str]) -> Path:
    """Finish only a previously authorized deletion, under its original run lease."""
    environment = environment_for(directory, ambient)
    with run_lease(directory):
        storage = LiveStorage._retained(environment)
        retirement = Teardown(
            directory, storage, lambda: removal_absence(directory, storage).sha256
        )
        retirement.run()  # _load rejects a missing/changed original authorization first.
    return directory / "owned-teardown/removed.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(resume(parser.parse_args().directory, os.environ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
