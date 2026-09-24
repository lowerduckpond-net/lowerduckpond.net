"""Original public trust is captured before fixture setup and never refreshed."""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_public_inputs as public
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_public_inputs_probe import CHUNK_BYTES, FILES
from scripts.qualification_context import HOST_ENV, RUN_ENV


@dataclass
class Run:
    directory: Path
    environment: dict[str, str]
    source: dict[str, object]
    fingerprints: Mock
    content: dict[str, bytes]

    def capture(self) -> None:
        public.capture(self.directory, self.environment)

    def context(self) -> dict[str, object]:
        return {
            "run_id": str(uuid.UUID(self.environment[RUN_ENV])),
            "source_fixture_sha256": hashlib.sha256(
                evidence.canonical_bytes(
                    {key: value for key, value in self.source.items() if key != "running"}
                )
            ).hexdigest(),
            "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Run:
    environment = allocate(tmp_path, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    source: dict[str, object] = {
        "id": "a" * 64,
        "name": "/" + environment[HOST_ENV],
        "image": "sha256:" + "b" * 64,
        "owner": environment[RUN_ENV],
        "running": True,
    }
    content = {name: ("original " + name + "\n").encode() for name in FILES}
    fingerprints = Mock(
        return_value={
            name: {"sha256": hashlib.sha256(raw).hexdigest(), "identity": [1, 2, len(raw), 3, 4]}
            for name, raw in content.items()
        }
    )
    monkeypatch.setattr(public, "_fingerprints", fingerprints)
    monkeypatch.setattr(owned, "inspect", Mock(return_value=source))

    def probe(environment: dict[str, str], identity: str, name: str, offset: str) -> object:
        assert identity == source["id"]
        raw = content[name]
        return {
            "fingerprint": {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "identity": [1, 2, len(raw), 3, 4],
            },
            "content": base64.b64encode(raw[int(offset) : int(offset) + CHUNK_BYTES]).decode(
                "ascii"
            ),
        }

    monkeypatch.setattr(public, "_probe", probe)
    return Run(tmp_path, environment, source, fingerprints, content)


def test_capture_preserves_original_bytes_and_source_identity(run: Run) -> None:
    run.capture()
    files = public.require_original(run.directory, run.context())
    original = (run.directory / "public-inputs/original.json").read_bytes()
    for name, path in files.items():
        assert path.read_bytes() == run.content[name]
        assert path.stat().st_uid == os.getuid()
    with pytest.raises(FileExistsError):
        run.capture()
    assert (run.directory / "public-inputs/original.json").read_bytes() == original


@pytest.mark.parametrize("fault", ["truncated", "base64", "fingerprint", "final-hash"])
def test_a_bad_chunk_cannot_publish_original_public_inputs(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    raw = run.content["roots.pem"]
    if fault == "truncated":
        raw = raw[:-1]
    elif fault == "final-hash":
        raw = b"X" * len(raw)
    fingerprint = dict(run.fingerprints.return_value["roots.pem"])
    if fault == "fingerprint":
        fingerprint["identity"] = [1, 2, len(raw), 4, 5]
    monkeypatch.setattr(
        public,
        "_probe",
        Mock(
            return_value={
                "fingerprint": fingerprint,
                "content": "not-base64"
                if fault == "base64"
                else base64.b64encode(raw).decode("ascii"),
            }
        ),
    )
    with pytest.raises(ValueError):
        run.capture()
    assert not (run.directory / "public-inputs/original.json").exists()
    assert (run.directory / "public-inputs/roots.pem").exists()


@pytest.mark.parametrize("fault", ["copy", "source-fingerprint", "source-image", "unprepared"])
def test_partial_capture_retains_bytes_without_completed_manifest(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    if fault == "copy":
        run.content["hosts"] = b"changed copy"
    elif fault == "source-fingerprint":
        run.fingerprints.side_effect = [run.fingerprints.return_value, {}]
    elif fault == "source-image":
        changed = {**run.source, "image": "sha256:" + "c" * 64}
        monkeypatch.setattr(
            owned,
            "inspect",
            Mock(side_effect=[run.source, changed, changed]),
        )
    else:
        run.fingerprints.side_effect = ValueError("source already has controlled fixture trust")
    with pytest.raises(ValueError):
        run.capture()
    assert (run.directory / "public-inputs").is_dir()
    assert not (run.directory / "public-inputs/original.json").exists()
    with pytest.raises(FileExistsError):
        run.capture()


@pytest.mark.parametrize(
    "fault", ["bytes", "source", "run", "late", "stale", "symlink", "public-mode"]
)
def test_later_verification_cannot_replace_trust_or_refresh_its_provenance(
    run: Run, fault: str
) -> None:
    run.capture()
    context = run.context()
    roots = run.directory / "public-inputs/roots.pem"
    original = run.directory / "public-inputs/original.json"
    if fault == "bytes":
        roots.write_bytes(b"restored controlled CA bundle")
    elif fault == "source":
        context["source_fixture_sha256"] = "0" * 64
    elif fault == "run":
        context["run_id"] = "01900000-0000-7000-8000-000000000000"
    elif fault in {"late", "stale"}:
        value = read_private(original)
        if fault == "late":
            value["completed_at"] = (
                (datetime.now(UTC) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            )
        else:
            value["started_at"] = (
                (datetime.now(UTC) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
            )
        original.write_bytes(evidence.canonical_bytes(value))
    elif fault == "symlink":
        replacement = roots.with_suffix(".saved")
        roots.rename(replacement)
        roots.symlink_to(replacement)
    else:
        roots.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        public.require_original(run.directory, context)
