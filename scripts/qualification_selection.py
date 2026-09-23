"""Conservative change-to-group policy, initially usable in comparison mode."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import PurePosixPath

from scripts.qualification_groups import GROUPS

FORMAT = "lowerduckpond-installed-selection-v1"
ALL = tuple(GROUPS)
_TESTS = "config/ansible/molecule/m3_8/tests/"
_EMERGENCY = (
    "backup-mutation-overlap",
    "deletion-quarantine",
    "credentials",
    "reboot-journey",
    "restore-reconstruction",
    "restore-negative",
    "restore-tls-bootstrap",
)
# Only leaf modules with reviewed consumers are narrowed. Everything else,
# including shared fixtures, schemas, authorization and deployment policy, is full.
DEPENDENCIES = {
    "packages/static-host-agent/src/lowerduckpond_static_host_agent/emergency_plan.py": _EMERGENCY,
    "packages/static-host-agent/tests/test_emergency_delete.py": _EMERGENCY,
    _TESTS + "test_core_independent.py": ("core", "reboot-journey"),
    _TESTS + "test_configuration_independent.py": (
        "configuration-publication",
        "configuration-generation",
        "reboot-journey",
    ),
    _TESTS + "test_recovery_independent.py": (
        "transport-recovery",
        "overlap-deployment",
        "overlap-routing",
        "reboot-journey",
    ),
    _TESTS + "test_archive_independent.py": ("archive-cycles", "reboot-journey"),
    _TESTS + "test_archive_full_size.py": ("full-size-archive", "reboot-journey"),
    _TESTS + "test_quarantine_recovery.py": ("deletion-quarantine", "reboot-journey"),
    _TESTS + "test_archive_credentials.py": ("credentials", "reboot-journey"),
    _TESTS + "test_cross_feature.py": ("reboot-journey",),
}
MAX_DIFF_BYTES = 1024 * 1024
MAX_CHANGES = 4096
FIRST_PRINTABLE = 32
_RAW = re.compile(rb":([0-7]{6}) ([0-7]{6}) [0-9a-f]{40} [0-9a-f]{40} ([AMDT]|R[0-9]{1,3})")


@dataclass(frozen=True)
class Change:
    paths: tuple[str, ...]
    modes: tuple[str, str]
    status: str


def parse_changes(raw: bytes) -> list[Change]:
    if len(raw) > MAX_DIFF_BYTES:
        raise ValueError("diff exceeds selection bounds")
    if not raw:
        return []
    fields = raw.split(b"\0")
    if fields.pop() != b"":
        raise ValueError("incomplete diff")
    changes: list[Change] = []
    index = 0
    while index < len(fields):
        match = _RAW.fullmatch(fields[index])
        if match is None or len(changes) >= MAX_CHANGES:
            raise ValueError("unsupported diff metadata")
        old, new, status = (value.decode("ascii") for value in match.groups())
        count = 2 if status.startswith("R") else 1
        selected = fields[index + 1 : index + 1 + count]
        if len(selected) != count:
            raise ValueError("missing diff path")
        paths = tuple(value.decode("utf-8") for value in selected)
        if any(
            not path
            or PurePosixPath(path).is_absolute()
            or any(part in {".", ".."} for part in path.split("/"))
            or any(ord(char) < FIRST_PRINTABLE for char in path)
            for path in paths
        ):
            raise ValueError("unsupported diff path")
        changes.append(Change(paths, (old, new), status))
        index += 1 + count
    return changes


def documentation(path: str) -> bool:
    if path in {"README.md", "CONTRIBUTING.md"}:
        return True
    if path.startswith("docs/") and path.endswith(".md"):
        return True
    return path.startswith(("docs/records/", "docs/threat-model/evidence/")) and path.endswith(
        (".json", ".sha256")
    )


def selection(cases: tuple[str, ...], reason: str) -> dict[str, object]:
    return {
        "format": FORMAT,
        "mode": "all" if cases == ALL else "affected" if cases else "none",
        "reason": reason,
        "cases": list(cases),
    }


def select_changes(changes: list[Change]) -> dict[str, object]:
    if not changes:
        return selection(ALL, "empty-diff")
    affected: set[str] = set()
    for change in changes:
        if any(mode not in {"000000", "100644"} for mode in change.modes):
            return selection(ALL, "nonregular-or-executable-input")
        for path in change.paths:  # Both sides of a rename are obligations.
            if documentation(path):
                continue
            if path not in DEPENDENCIES:
                return selection(ALL, "unmapped-input")
            if change.status != "M":
                return selection(ALL, "added-removed-or-renamed-code")
            affected.update(DEPENDENCIES[path])
    return selection(
        tuple(name for name in ALL if name in affected),
        "reviewed-map" if affected else "documentation-only",
    )


def git(*arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("git is unavailable")
    result = subprocess.run(  # noqa: S603 - fixed git executable and commands, revisions validated
        [executable, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=15,
    )
    if len(result.stdout) > MAX_DIFF_BYTES:
        raise ValueError("git metadata exceeds selection bounds")
    return result.stdout


def select_revisions(base: str, head: str) -> dict[str, object]:
    try:
        if any(re.fullmatch(r"[0-9a-f]{40}", revision) is None for revision in (base, head)):
            raise ValueError("missing revision")
        if git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise ValueError("incomplete history")
        for revision in (base, head):
            git("cat-file", "-e", revision + "^{commit}")
        return select_changes(
            parse_changes(
                git("diff", "--raw", "-z", "--no-abbrev", "--find-renames", base, head, "--")
            )
        )
    except OSError, ValueError, subprocess.SubprocessError:
        return selection(ALL, "unavailable-diff")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    result = (
        selection(ALL, "scheduled-manual-or-release")
        if args.full
        else select_revisions(args.base, args.head)
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
