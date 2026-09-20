from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from scripts import qualification_ci as ci
from scripts.qualification_case import CONTENT_BYTES, ENTRY_COUNT, INSTALLED_FORMAT
from scripts.qualification_groups import GROUP_REPORT_FORMAT
from scripts.qualification_selection import ALL, selection


def receipt(directory: Path, case: str) -> Path:
    destination = directory / f"installed-result-{case}" / "case.json"
    destination.parent.mkdir(parents=True)
    destination.write_text(
        json.dumps(
            {
                "format": GROUP_REPORT_FORMAT,
                "authority": "diagnostic-only",
                "case": case,
                "run_id": uuid.uuid7().hex,
                "backend": "minio",
                "status": "passed",
                "local_accounting": "passed",
                "independent_storage_absence": "passed",
                "destroy": "passed",
            }
        )
    )
    if case == "full-size-archive":
        report = json.loads(destination.read_text())
        report["installed"] = {
            "format": INSTALLED_FORMAT,
            "run_id": report["run_id"],
            "artifact_sha256": "a" * 64,
            "content_sha256": "b" * 64,
            "entries": ENTRY_COUNT,
            "bytes": CONTENT_BYTES,
        }
        destination.write_text(json.dumps(report))
    return destination


@pytest.mark.parametrize("fault", [None, "missing", "other-run", "size", "hash", "extra"])
def test_full_size_result_requires_the_retained_installed_evidence(
    tmp_path: Path, fault: str | None
) -> None:
    path = receipt(tmp_path, "full-size-archive")
    report = json.loads(path.read_text())
    if fault == "missing":
        del report["installed"]
    elif fault:
        field = {
            "other-run": "run_id",
            "size": "bytes",
            "hash": "content_sha256",
            "extra": "private",
        }[fault]
        report["installed"][field] = "invalid-private-canary"
    path.write_text(json.dumps(report))

    def verify() -> None:
        ci.verify(
            selection(("full-size-archive",), "reviewed-map"),
            tmp_path,
            event="pull_request",
            matrix_result="success",
            complete_result="skipped",
            static_result="success",
        )

    if fault:
        with pytest.raises(ValueError):
            verify()
    else:
        verify()


def test_docs_require_no_matrix_but_still_require_fast_baseline(tmp_path: Path) -> None:
    plan = selection((), "documentation-only")
    ci.verify(
        plan,
        tmp_path,
        event="pull_request",
        matrix_result="skipped",
        complete_result="skipped",
        static_result="success",
    )
    with pytest.raises(ValueError):
        ci.verify(
            plan,
            tmp_path,
            event="pull_request",
            matrix_result="skipped",
            complete_result="skipped",
            static_result="failure",
        )
    assert ci.matrix([]) == {"include": [{"case": "none"}]}


@pytest.mark.parametrize("fault", [None, "extra", "wrong-case", "multiple-selected"])
def test_single_pattern_match_download_is_flat_and_still_must_match_selection(
    tmp_path: Path, fault: str | None
) -> None:
    # Pinned download-artifact v8 extracts one pattern match directly into path,
    # even when merge-multiple is false. Multiple matches get named directories.
    path = receipt(tmp_path, "credentials" if fault == "wrong-case" else "reboot-journey")
    path.rename(tmp_path / "case.json")
    path.parent.rmdir()
    if fault == "extra":
        (tmp_path / "unexpected.json").write_text("{}")
    cases = ("core", "reboot-journey") if fault == "multiple-selected" else ("reboot-journey",)

    def verify() -> None:
        ci.verify(
            selection(cases, "reviewed-map"),
            tmp_path,
            event="pull_request",
            matrix_result="success",
            complete_result="skipped",
            static_result="success",
        )

    if fault:
        with pytest.raises(ValueError):
            verify()
    else:
        verify()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "extra",
        "wrong-case",
        "failed",
        "wrong-owner",
        "incomplete-accounting",
        "wrong-format",
        "duplicate-owner",
        "job-failed",
        "job-skipped",
        "missing-job",
        "cancelled-job",
        "complete-unexpected",
    ],
)
def test_missing_failed_or_incomplete_selected_results_cannot_pass(
    tmp_path: Path, fault: str | None
) -> None:
    plan = selection(("core", "reboot-journey"), "reviewed-map")
    first = receipt(tmp_path, "core")
    second = receipt(tmp_path, "reboot-journey")
    if fault == "missing":
        second.unlink()
    elif fault == "extra":
        receipt(tmp_path, "credentials")
    elif fault in {
        "wrong-case",
        "failed",
        "wrong-owner",
        "incomplete-accounting",
        "wrong-format",
        "duplicate-owner",
    }:
        data = json.loads(first.read_text())
        key, value = {
            "wrong-case": ("case", "credentials"),
            "failed": ("status", "failed"),
            "wrong-owner": ("run_id", "legacy"),
            "incomplete-accounting": ("independent_storage_absence", "unknown"),
            "wrong-format": ("format", "lowerduckpond-m3-10-installed-spaces-v2"),
            "duplicate-owner": ("run_id", json.loads(second.read_text())["run_id"]),
        }[fault]
        data[key] = value
        first.write_text(json.dumps(data))
    status = {
        "job-failed": "failure",
        "job-skipped": "skipped",
        "missing-job": "",
        "cancelled-job": "cancelled",
    }.get(str(fault), "success")

    def verify() -> None:
        ci.verify(
            plan,
            tmp_path,
            event="pull_request",
            matrix_result=status,
            complete_result="success" if fault == "complete-unexpected" else "skipped",
            static_result="success",
        )

    if fault:
        with pytest.raises((ValueError, FileNotFoundError)):
            verify()
    else:
        verify()


@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch", "unknown-event"])
def test_complete_events_always_require_all_groups_and_the_complete_journey(
    tmp_path: Path, event: str
) -> None:
    plan = ci.plan(event, "", "")
    assert plan["cases"] == list(ALL)
    for case in ALL:
        receipt(tmp_path, case)
    ci.verify(
        plan,
        tmp_path,
        event=event,
        matrix_result="success",
        complete_result="success",
        static_result="success",
    )
    with pytest.raises(ValueError):
        ci.verify(
            plan,
            tmp_path,
            event=event,
            matrix_result="success",
            complete_result="skipped",
            static_result="success",
        )


@pytest.mark.parametrize("change", ["mode", "duplicate", "unknown", "extra", "format", "missing"])
def test_malformed_selection_never_exempts_a_required_job(change: str) -> None:
    plan = selection(("core",), "reviewed-map")
    if change == "missing":
        del plan["cases"]
    else:
        key, value = {
            "mode": ("mode", "none"),
            "duplicate": ("cases", ["core", "core"]),
            "unknown": ("cases", ["unknown"]),
            "extra": ("untrusted", True),
            "format": ("format", "unknown"),
        }[change]
        plan[key] = value
    with pytest.raises(ValueError):
        ci.selected_cases(plan)
