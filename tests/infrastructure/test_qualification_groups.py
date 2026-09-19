from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts import qualification_case as primitives
from scripts import qualification_group_case as case
from scripts import qualification_group_runner as runner
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RUN_ENV,
    resource_names,
)
from scripts.qualification_groups import GROUPS

ROOT = Path(__file__).resolve().parents[2]
FAILURE_STATUS = 17


@pytest.mark.parametrize(
    "outcome", ["pass", "skip", "xfail", "setup", "call", "teardown", "extra", "missing"]
)
def test_receipt_tracks_real_pytest_stages(tmp_path: Path, outcome: str) -> None:
    body = {
        "pass": "assert True",
        "skip": "pytest.skip('skip')",
        "xfail": "pytest.xfail('xfail')",
        "setup": "assert True",
        "call": "assert False",
        "teardown": "assert True",
        "extra": "assert True",
        "missing": "assert True",
    }[outcome]
    fixture = "assert False" if outcome == "setup" else "yield\n    assert False"
    text = f"import pytest\ndef test_case():\n    {body}\n"
    if outcome in {"setup", "teardown"}:
        text += f"\n@pytest.fixture(autouse=True)\ndef broken():\n    {fixture}\n"
    if outcome == "extra":
        text += "\ndef test_extra():\n    assert True\n"
    (tmp_path / "test_receipt.py").write_text(text)
    code = """
import sys, pytest
from scripts.qualification_group_runner import Completion
expected = ('test_receipt.py::test_case',)
if sys.argv[1] == 'missing':
    expected += ('test_receipt.py::test_missing',)
proof = Completion(expected)
status = pytest.main(['-q', '--rootdir=.', '-c', '/dev/null', 'test_receipt.py'], plugins=[proof])
assert proof.passed(int(status)) is (sys.argv[1] == 'pass')
"""
    result = subprocess.run(  # noqa: S603 - generated fixed test, no remote inputs
        [sys.executable, "-c", code, outcome],
        cwd=tmp_path,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("name", "stage"),
    [(name, stage) for name, group in GROUPS.items() for stage in group.stages],
)
def test_every_declared_node_exists_in_order_including_each_parameter(
    name: str, stage: str
) -> None:
    host = "ldp-collection-only"
    expected = list(GROUPS[name].nodes(stage, host))
    result = subprocess.run(  # noqa: S603 - collection only; no host is accessed
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            f"--hosts=docker://{host}",
            *(f"{runner.SCENARIO}/{node}" for node in expected),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    collected = [
        runner.Completion.relative(line) for line in result.stdout.splitlines() if "::test_" in line
    ]
    assert collected == expected


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    return {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/static-host-agent.tar"),
    }


def receipts(directory: Path, env: dict[str, str], name: str) -> None:
    for stage in GROUPS[name].stages:
        (directory / f"group-{stage}.json").write_text(
            json.dumps(
                {
                    "format": runner.FORMAT,
                    "run_id": env[RUN_ENV],
                    "case": name,
                    "stage": stage,
                    "nodes": GROUPS[name].nodes(stage, env[HOST_ENV]),
                }
            )
        )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing-stage",
        "other-run",
        "skipped-test",
        "local",
        "remote",
        "changed-host",
        "destroy",
        "image-cleanup",
    ],
)
def test_group_teardown_requires_all_stages_and_fresh_accounting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    fault: str | None,
) -> None:
    phases: list[str] = []
    monkeypatch.setenv("LDP_QUALIFICATION_TIMING_EVENTS", str(tmp_path / "timing-events.jsonl"))
    checks: list[str] = []
    name = "reboot-journey"

    def phase(directory: Path, env: dict[str, str], uv: str, current: str) -> int:
        phases.append(current)
        if current == "verify":
            receipts(directory, env, name)
            path = directory / "group-after.json"
            data = json.loads(path.read_text())
            if fault == "missing-stage":
                path.unlink()
            elif fault in {"other-run", "skipped-test"}:
                data["run_id" if fault == "other-run" else "nodes"] = "invalid"
                path.write_text(json.dumps(data))
        return 9 if fault == "destroy" and current == "destroy" else 0

    def owned(env: dict[str, str], **kwargs: object) -> dict[str, str]:
        checks.append("owner")
        return {
            HOST_ENV: "c" * 64 if fault == "changed-host" and phases[-1] == "verify" else "a" * 64,
            ARCHIVE_ENV: "b" * 64,
        }

    def local(env: dict[str, str], identity: str) -> str:
        checks.append("local")
        if fault == "local":
            raise ValueError("pending obligations")
        return "quiescent-installed"

    def remote(env: dict[str, str], identity: str) -> None:
        checks.append("remote")
        if fault == "remote":
            raise ValueError("remote inventory unavailable")

    def image_cleanup(env: dict[str, str]) -> None:
        assert phases[-1] == "destroy"
        if fault == "image-cleanup":
            raise ValueError("owned image cleanup unavailable")
        checks.append("image")

    monkeypatch.setattr(case, "phase", phase)
    monkeypatch.setattr(case, "owned_containers", owned)
    monkeypatch.setattr(primitives, "owned_containers", owned)
    monkeypatch.setattr(case, "local_proof", local)
    monkeypatch.setattr(case, "independent_storage_absence", remote)
    monkeypatch.setattr(case, "remove_owned_image", image_cleanup)
    if fault in {None, "destroy"}:
        assert case.run_group(tmp_path, environment, "uv", name) == (9 if fault else 0)
        assert checks == ["owner", "owner", "local", "remote", "owner", "local"] + (
            ["image"] if fault is None else []
        )
        assert phases[-1] == "destroy"
    else:
        with pytest.raises((ValueError, FileNotFoundError)):
            case.run_group(tmp_path, environment, "uv", name)
        assert ("destroy" in phases) is (fault == "image-cleanup")
    assert (tmp_path / "case.json").exists() is (fault is None)
    assert not (tmp_path / "qualification.json").exists()
    if fault not in {None, "destroy"}:
        assert json.loads((tmp_path / "failure-phase.json").read_text())["phase"] == (
            "final-storage-proof" if fault == "remote" else "final-accounting"
        )


@pytest.mark.parametrize("failed", ["create", "prepare", "converge", "idempotence", "verify"])
def test_failed_phase_cannot_reach_a_later_phase_or_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment: dict[str, str], failed: str
) -> None:
    observed: list[str] = []

    def phase(directory: Path, env: dict[str, str], uv: str, name: str) -> int:
        observed.append(name)
        return FAILURE_STATUS if name == failed else 0

    monkeypatch.setattr(case, "phase", phase)
    for module in (case, primitives):
        monkeypatch.setattr(
            module,
            "owned_containers",
            lambda env, **kwargs: {HOST_ENV: "a" * 64, ARCHIVE_ENV: "b" * 64},
        )
    assert case.run_group(tmp_path, environment, "uv", "core") == FAILURE_STATUS
    sequence = ["create", "prepare", "converge", "idempotence", "verify"]
    assert observed == sequence[: sequence.index(failed) + 1]
    assert not (tmp_path / "case.json").exists()


def test_partial_group_report_is_never_production_qualification(tmp_path: Path) -> None:
    from scripts.m3_10_qualification_report import verify_report  # noqa: PLC0415

    report = tmp_path / "case.json"
    report.write_text(
        json.dumps({"format": case.FORMAT, "authority": "diagnostic-only", "status": "passed"})
    )
    with pytest.raises(ValueError):
        verify_report(report, source="a" * 40, artifact="a" * 64)


def test_ci_runs_every_group_alongside_the_complete_journey() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    matrix = workflow["jobs"]["ansible-m3-8"]["strategy"]["matrix"]["include"]
    recipes = {row["recipe"] for row in matrix}
    assert recipes == {
        "check-ansible-m3-8",
        "check-archive-full-size",
        *(f"check-installed-group {name}" for name in GROUPS if name != "full-size-archive"),
    }
    assert len({row["artifact"] for row in matrix}) == len(matrix)
    assert workflow["jobs"]["ansible-m3-8"]["strategy"]["fail-fast"] is False
