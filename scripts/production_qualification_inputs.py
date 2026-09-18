"""Bind production qualification to reviewed Git inputs, preserving original provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
POLICY = "lowerduckpond-production-inputs-v1"
REVOCATIONS = "scripts/qualification-revocations.json"
# These namespaces contain records, never executable inputs or requirements.
# Every other tracked path (including new/unknown files) participates by default.
RECORD_PREFIXES = (b"docs/records/", b"docs/threat-model/evidence/")
RECORD_SUFFIXES = (b".md", b".json", b".sha256")


def git(repository: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git is unavailable")
    result = subprocess.run(  # noqa: S603 - fixed git subcommands; revisions validated before use
        [executable, "--no-replace-objects", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("qualification Git inputs are unavailable")
    return result.stdout


def revision(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("qualification source revision is invalid")
    return value


def fingerprint(repository: Path, source: str) -> str:
    """Hash names, modes and contents from the committed tree, never the worktree."""
    source = revision(source)
    git(repository, "cat-file", "-e", f"{source}^{{commit}}")
    tree = git(repository, "ls-tree", "-rz", "--full-tree", source)
    digest = hashlib.sha256(POLICY.encode("ascii") + b"\0")
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ValueError("qualification tree contains an unsupported Git object")
        if (
            mode == b"100644"
            and name.startswith(RECORD_PREFIXES)
            and name.endswith(RECORD_SUFFIXES)
        ):
            continue
        content = git(repository, "cat-file", "blob", oid.decode("ascii"))
        digest.update(mode + b"\0" + name + b"\0" + hashlib.sha256(content).digest())
    return digest.hexdigest()


def current_candidate(repository: Path, source: str) -> dict[str, list[str]]:
    source = revision(source)
    if (
        git(repository, "rev-parse", "HEAD").decode("ascii").strip() != source
        or git(repository, "status", "--porcelain", "--untracked-files=all")
        or git(repository, "rev-parse", "--is-shallow-repository").strip() != b"false"
    ):
        raise ValueError("qualification requires the clean, complete candidate checkout")
    raw = git(repository, "show", f"{source}:{REVOCATIONS}")
    policy = json.loads(raw)
    fields = {"format", "sources", "artifacts", "reports", "input_digests"}
    if (
        not isinstance(policy, dict)
        or set(policy) != fields
        or policy["format"] != "lowerduckpond-qualification-revocations-v1"
    ):
        raise ValueError("qualification revocation policy is invalid")
    for field in fields - {"format"}:
        entries = policy[field]
        length = 40 if field == "sources" else 64
        if not isinstance(entries, list) or any(
            not isinstance(item, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", item) is None
            for item in entries
        ):
            raise ValueError("qualification revocation entry is invalid")
    return cast(dict[str, list[str]], {key: policy[key] for key in fields - {"format"}})


def assert_not_revoked(
    revocations: dict[str, list[str]],
    *,
    source: str,
    artifact: str,
    inputs: str,
    report: bytes = b"",
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", artifact) is None:
        raise ValueError("qualification artifact digest is invalid")
    if (
        source in revocations["sources"]
        or artifact in revocations["artifacts"]
        or inputs in revocations["input_digests"]
        or (report and hashlib.sha256(report).hexdigest() in revocations["reports"])
    ):
        raise ValueError("qualification evidence has been revoked")


def candidate_inputs(repository: Path, source: str, artifact: str) -> str:
    revocations = current_candidate(repository, source)
    inputs = fingerprint(repository, source)
    assert_not_revoked(revocations, source=source, artifact=artifact, inputs=inputs)
    return inputs


def equivalent_completion(repository: Path, *, source: str, completed: str, artifact: str) -> bool:
    inputs = candidate_inputs(repository, source, artifact)
    completed = revision(completed)
    git(repository, "merge-base", "--is-ancestor", completed, source)
    revocations = current_candidate(repository, source)
    if completed in revocations["sources"]:
        return False
    return fingerprint(repository, completed) == inputs


def storage_target_digest() -> str:
    values = {
        key: os.environ.get(key, "")
        for key in ("SPACES_REGION", "SPACES_ARCHIVE_BUCKET", "SPACES_BACKUP_BUCKET")
    }
    if any(not value or re.fullmatch(r"[a-z0-9.-]+", value) is None for value in values.values()):
        raise ValueError("qualification storage target is unavailable")
    raw = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def capture_run(directory: Path, *, repository: Path, source: str) -> None:
    """Capture identity before any provider proof; never bind it at packaging time."""
    policy = current_candidate(repository, source)
    inputs = fingerprint(repository, source)
    if source in policy["sources"] or inputs in policy["input_digests"]:
        raise ValueError("qualification evidence has been revoked")
    document = {
        "source_revision": source,
        "input_policy": POLICY,
        "qualification_inputs_sha256": inputs,
        "storage_target_sha256": storage_target_digest(),
    }
    with (directory / "qualification-inputs.json").open("x", encoding="ascii") as stream:
        stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--artifact")
    parser.add_argument("--capture-run", type=Path)
    parser.add_argument("--completed-source")
    parser.add_argument("--completed-storage-target")
    arguments = parser.parse_args()
    try:
        if arguments.capture_run:
            if (
                arguments.artifact
                or arguments.completed_source
                or arguments.completed_storage_target
            ):
                raise ValueError("unexpected qualification capture options")
            capture_run(arguments.capture_run, repository=ROOT, source=arguments.source)
            return 0
        if not arguments.artifact:
            raise ValueError("qualification artifact is required")
        target = storage_target_digest()
        if arguments.completed_source and arguments.completed_storage_target == target:
            completed = equivalent_completion(
                ROOT,
                source=arguments.source,
                completed=arguments.completed_source,
                artifact=arguments.artifact,
            )
        else:
            candidate_inputs(ROOT, arguments.source, arguments.artifact)
            completed = False
    except ValueError, OSError, TypeError, UnicodeError:
        parser.exit(1, "Production qualification inputs could not be verified.\n")
    print(("completed" if completed else "changed") + " " + target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
