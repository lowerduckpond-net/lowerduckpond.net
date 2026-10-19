"""Concrete selector/caller, exact native origins, complete verifier sequence."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import m3_11_frozen_local as local
from scripts import m3_11_frozen_refresh as refresh
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended.model import instant, stamp

from .test_m3_11_frozen_local import selection as selection  # noqa: PLC0414 - pytest fixture


@pytest.fixture
def case(selection: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:  # noqa: PLR0915 - concrete four-command fixture
    root = selection.root
    readiness = root / "readiness"
    readiness.mkdir(mode=0o700)
    environment = root / "venv"
    (environment / "bin").mkdir(parents=True)
    python = environment / "bin/python"
    python.write_bytes(b"synthetic interpreter boundary")
    (environment / "pyvenv.cfg").write_bytes(b"synthetic virtual environment")
    paths = {}
    for name in ("collector", "host_observer", "local_validator"):
        path = root / (name + ".py")
        path.write_bytes(b"independently reviewed synthetic native boundary\n")
        paths[name] = str(path)
    evidence = root / "evidence.json"
    record(evidence, selection.evidence)
    config: dict[str, object] = {
        "format": "lowerduckpond-m3-11-staged-proof-refresh-v1",
        "python": str(python),
        "python_realpath": str(python),
        "python_configuration": str(environment / "pyvenv.cfg"),
        **paths,
        "evidence": str(evidence),
        "evidence_sha256": digest(selection.evidence),
        "readiness_directory": str(readiness),
        "output_parent": str(root),
    }
    config["pins"] = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            python,
            environment / "pyvenv.cfg",
            evidence,
            *(Path(path) for path in paths.values()),
        )
    }
    now = datetime.now(UTC)
    clocks = [now - timedelta(minutes=40), now - timedelta(minutes=1)]
    native_clock = [clocks[0]]
    calls: list[str] = []
    current: dict[str, object] = {}
    monkeypatch.setattr(
        local, "verify", lambda *_args, **_kwargs: {"result": {"result": "native-bound-result"}}
    )

    def command(args: list[str], **kwargs: Any) -> bytes:  # noqa: ANN401 - command boundary
        assert kwargs["deadline"] > time.monotonic()
        if args[0] == "gh":
            assert args[1:] == [
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                refresh.ENDPOINT,
            ]
            calls.append("inventory")
            return json.dumps(
                {
                    "workflow_runs": [
                        {
                            "id": 123,
                            "run_attempt": 1,
                            "event": "schedule",
                            "head_sha": selection.contract["native_workflow"],
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": stamp(native_clock[0]),
                        }
                    ]
                }
            ).encode()
        assert args[:3] == [str(python), "-I", "-B"]
        if args[3] == paths["collector"]:
            assert args[4:] == ["123"]
            calls.append("independent")
            directory = readiness / ("fresh-independent-" + str(uuid.uuid4()))
            directory.mkdir(mode=0o700)
            proof = read_private(Path(selection.chosen["independent"]["path"]))
            proof["native_created_at"] = stamp(native_clock[0])
            record(directory / "verified.json", proof)
            sha = hashlib.sha256((directory / "verified.json").read_bytes()).hexdigest()
            record(
                directory / "collection-result.json",
                {
                    "status": "passed",
                    "verified_sha256": sha,
                    "provider_calls": 0,
                    "new_dispatches": 0,
                    "live_mutations": 0,
                },
            )
            current.update(directory=str(directory), sha=sha)
            return json.dumps(
                {
                    "status": proof["status"],
                    "run_id": 123,
                    "run_attempt": 1,
                    "review_directory": str(directory),
                    "verified_sha256": sha,
                }
            ).encode()
        if args[3] == paths["host_observer"]:
            calls.append("host")
            assert args[4:] == [
                "observe",
                str(Path(str(current["directory"])) / "verified.json"),
                current["sha"],
            ]
            directory = readiness / ("host-handoff-read-" + uuid.uuid4().hex)
            directory.mkdir(mode=0o700)
            proof = read_private(Path(selection.chosen["host"]["path"]))
            cast(dict[str, object], proof["receipt"])["observed_at"] = stamp(native_clock[0])
            record(directory / "host-verified.json", proof)
            return json.dumps(
                {"status": proof["status"], "evidence_directory": str(directory)}
            ).encode()
        assert args[3] == paths["local_validator"] and args[4] == str(evidence)
        calls.append("local")
        proof = local.verify_local(
            selection.evidence, read_private(Path(args[5])), scratch=Path(args[6])
        )
        return json.dumps(proof).encode()

    monkeypatch.setattr(refresh, "read_command", command)
    return SimpleNamespace(
        callback=refresh.Refresh(config, environment={}),
        calls=calls,
        clock=native_clock,
        clocks=clocks,
        config=config,
        root=root,
    )


def test_each_refresh_runs_complete_verifiers_and_keeps_actual_new_native_origin(
    case: SimpleNamespace,
) -> None:
    first = case.callback()
    case.clock[0] = case.clocks[1]
    second = case.callback()
    assert instant(second["proof_valid_until"]) - instant(first["proof_valid_until"]) == timedelta(
        minutes=39
    )
    assert case.calls == ["inventory", "independent", "host", "local"] * 2
    assert len(list(case.root.glob("refresh-*/verified.json"))) == 2  # noqa: PLR2004
    assert second["evidence_sha256"] == first["evidence_sha256"]


def test_rereading_same_native_proof_never_renews_it(case: SimpleNamespace) -> None:
    first, second = case.callback(), case.callback()
    assert first["proof_valid_until"] == second["proof_valid_until"]


def test_no_suitable_schedule_stops_without_dispatch_or_polling(case: SimpleNamespace) -> None:
    case.clock[0] = datetime.now(UTC) - timedelta(hours=2)
    with pytest.raises(ValueError, match="no eligible"):
        case.callback()
    assert case.calls == ["inventory"]
    assert list(case.root.glob("refresh-*/failure.json"))


def test_changed_full_verifier_stops_before_native_requests(case: SimpleNamespace) -> None:
    Path(case.config["collector"]).write_bytes(b"unreviewed")
    with pytest.raises(ValueError, match="changed"):
        case.callback()
    assert case.calls == [] and not list(case.root.glob("refresh-*"))
