"""Exact per-entry disposal with durable identities and read-only reconciliation.

The caller holds exclusive immutable fixture ownership throughout. A previous
submission is never sent again, even if its entry remains present. An explicit
continuation may remove only original exported entries never submitted before.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from typing import cast

from scripts import m3_11_frozen_export as export
from scripts.m3_11_frozen_stage import Effects
from scripts.m3_11_retirement_files import RetirementError, digest


class Residual:
    def __init__(
        self, root: Path, manifest: dict[str, object], effects: Effects, guard: Callable[[], None]
    ) -> None:
        if manifest.get("root") != str(root):
            raise RetirementError("residual disposal original root differs")
        self.root, self.manifest, self.effects, self.guard = root, manifest, effects, guard
        self.rows = cast(list[dict[str, object]], manifest["entries"])
        self.groups: dict[str, list[dict[str, object]]] = {}
        self.changed_directories: set[str] = set()
        for row in self.rows:
            self.groups.setdefault(str(Path(str(row["path"])).parent), []).append(row)
            if self.submitted(row):
                self.changed(row)
        original = cast(dict[str, object], manifest["metadata"])
        self.root_identity = {
            "path": str(root),
            "device": original["device"],
            "inode": original["inode"],
            "export_sha256": digest(manifest),
        }

    def slot(self, row: dict[str, object]) -> tuple[str, dict[str, object]]:
        return "remove-entry-" + digest(row["path"]), row

    def submitted(self, row: dict[str, object]) -> bool:
        return self.effects.submitted(*self.slot(row))

    def changed(self, row: dict[str, object]) -> None:
        self.changed_directories.update(str(path) for path in Path(str(row["path"])).parents)

    def _absent(self, row: dict[str, object], state: dict[str, list[str]]) -> None:
        path = str(row["path"])
        if not self.submitted(row):
            raise RetirementError("residual entry disappeared without an exact submission")
        state["absent"].append(path)
        for nested in self.groups.get(path, []):
            self._absent(nested, state)

    def _metadata(self, current: os.stat_result, saved: object, path: str) -> None:
        actual = export.metadata(current)
        expected = cast(dict[str, object], saved)
        changed_by_removal = path in self.changed_directories
        keys = {"device", "inode", "mode", "uid", "gid"} if changed_by_removal else set(actual)
        if any(actual[key] != expected[key] for key in keys):
            raise RetirementError("residual original directory metadata changed")

    def _file(self, descriptor: int, name: str, row: dict[str, object]) -> None:
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if export.metadata(before) != row["metadata"]:
            raise RetirementError("residual source entry changed after export")
        if row["type"] == "symlink":
            if os.readlink(name, dir_fd=descriptor) != row["target"]:
                raise RetirementError("residual symbolic link changed")
        else:
            with export.child(descriptor, name, is_directory=False) as source:
                export._same(before, os.fstat(source))
                export._plain(source)
                hasher = hashlib.sha256()
                for block in export.chunks(source, before.st_size, self.guard):
                    hasher.update(block)
                if hasher.hexdigest() != row["sha256"]:
                    raise RetirementError("residual original file bytes changed")
                export._same(before, os.fstat(source))
        export._same(before, os.stat(name, dir_fd=descriptor, follow_symlinks=False))

    def observe(self) -> dict[str, list[str]]:
        """Classify original identities; no mutation, ACK or receipt publication."""
        self.guard()
        self.changed_directories.clear()
        for row in self.rows:
            if self.submitted(row):
                self.changed(row)
        state: dict[str, list[str]] = {"absent": [], "unsubmitted": [], "pending": []}
        if not self.root.exists() and not self.root.is_symlink():
            if not self.effects.submitted("remove-directory", self.root_identity):
                raise RetirementError("residual root absence lacks its original submission")
            for row in self.groups.get(".", []):
                self._absent(row, state)
            state["absent"].append(".")
            return state
        parent = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            export._parent_linked(self.root.parent, parent)
            with export.child(parent, self.root.name, is_directory=True) as source:
                export._plain(source)
                self._metadata(os.fstat(source), self.manifest["metadata"], ".")

                def scan(descriptor: int, path: str) -> None:
                    self.guard()
                    export._parent_linked(self.root.parent, parent)
                    export._linked(parent, self.root.name, source)
                    rows = self.groups.get(path, [])
                    present = set(export._names(descriptor))
                    if not present <= {Path(str(row["path"])).name for row in rows}:
                        raise RetirementError("residual disposal found unexported entries")
                    for row in rows:
                        name, relative = Path(str(row["path"])).name, str(row["path"])
                        if name not in present:
                            self._absent(row, state)
                            continue
                        state["pending" if self.submitted(row) else "unsubmitted"].append(relative)
                        if row["type"] == "directory":
                            with export.child(descriptor, name, is_directory=True) as nested:
                                self._metadata(os.fstat(nested), row["metadata"], relative)
                                export._plain(nested)
                                scan(nested, relative)
                                export._linked(descriptor, name, nested)
                        else:
                            self._file(descriptor, name, row)

                scan(source, ".")
                state[
                    "pending"
                    if self.effects.submitted("remove-directory", self.root_identity)
                    else "unsubmitted"
                ].append(".")
                return state
        finally:
            os.close(parent)

    def remove_unsubmitted(self) -> dict[str, list[str]]:  # noqa: PLR0915 - one pinned transaction
        state = self.observe()
        if state["pending"]:
            raise RetirementError(
                "residual submitted entries remain; read-only reconciliation required"
            )
        if "." in state["absent"]:
            return state
        parent = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            export._parent_linked(self.root.parent, parent)
            with export.child(parent, self.root.name, is_directory=True) as source:
                export._plain(source)
                self._metadata(os.fstat(source), self.manifest["metadata"], ".")

                def current() -> None:
                    self.guard()
                    export._parent_linked(self.root.parent, parent)
                    export._linked(parent, self.root.name, source)

                def remove(descriptor: int, path: str) -> None:
                    for row in self.groups.get(path, []):
                        current()
                        relative, name = str(row["path"]), Path(str(row["path"])).name
                        if relative in state["absent"]:
                            if name in export._names(descriptor):
                                raise RetirementError("residual removed entry reappeared")
                            continue
                        if row["type"] == "directory":
                            with export.child(descriptor, name, is_directory=True) as nested:
                                self._metadata(os.fstat(nested), row["metadata"], relative)
                                remove(nested, relative)

                                def unlink_directory(name: str = name) -> None:
                                    current()
                                    export._linked(descriptor, name, nested)
                                    if export._names(nested):
                                        raise RetirementError(
                                            "residual directory contains new bytes"
                                        )
                                    os.rmdir(name, dir_fd=descriptor)
                                    os.fsync(descriptor)

                                self.effects.submit(*self.slot(row), unlink_directory)
                                self.changed(row)
                        else:
                            self._file(descriptor, name, row)

                            def unlink_file(name: str = name, row: dict[str, object] = row) -> None:
                                current()
                                self._file(descriptor, name, row)
                                os.unlink(name, dir_fd=descriptor)
                                os.fsync(descriptor)

                            self.effects.submit(*self.slot(row), unlink_file)
                            self.changed(row)

                remove(source, ".")

                def unlink_root() -> None:
                    current()
                    export._plain(source)
                    if export._names(source):
                        raise RetirementError("residual root contains new bytes")
                    os.rmdir(self.root.name, dir_fd=parent)
                    os.fsync(parent)

                self.effects.submit("remove-directory", self.root_identity, unlink_root)
        finally:
            os.close(parent)
        return self.observe()
